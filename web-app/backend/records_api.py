import json
import secrets
import time
import uuid
from typing import Literal

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from hybrid_v4 import remove, unwrap, wrap
from key_binding import key_for_account
from vault_api import database, require_records, session
from security_runtime import audit

router = APIRouter(prefix="/api/vault/records")
AAD = b"PicoVault/v5/records/"


class RecordInput(BaseModel):
    kind: Literal["note", "credential"]
    title: str = Field(min_length=1, max_length=160)
    secret: str = Field(min_length=1, max_length=8192)
    username: str = Field(default="", max_length=180)
    url: str = Field(default="", max_length=1000)


def setup(db):
    db.execute("CREATE TABLE IF NOT EXISTS vault_records (id TEXT PRIMARY KEY, account_id TEXT NOT NULL, kind TEXT NOT NULL, nonce BLOB NOT NULL, ciphertext BLOB NOT NULL, created_at INTEGER NOT NULL)")
    db.execute("CREATE INDEX IF NOT EXISTS vault_records_owner ON vault_records(account_id, created_at)")


def read_record(db, account_id, bound_key, record):
    record_id, kind, nonce, ciphertext, created_at = record
    try:
        record_key = unwrap(db, account_id, record_id, bound_key)
        plaintext = AESGCM(record_key).decrypt(nonce, ciphertext, AAD + account_id.encode() + record_id.encode() + kind.encode())
        content = json.loads(plaintext)
    except (ValueError, InvalidTag, KeyError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HTTPException(422, "Encrypted record could not be authenticated") from exc
    return {"id": record_id, "kind": kind, "created_at": created_at, **content}


def no_store(data, status_code=200):
    return JSONResponse(data, status_code=status_code, headers={"Cache-Control": "no-store"})


@router.post("", status_code=201)
def create_record(payload: RecordInput, user=Depends(session)):
    require_records(user)
    account_id = user["account_id"]
    record_id = uuid.uuid4().hex
    data = payload.model_dump()
    raw = json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode()
    nonce = secrets.token_bytes(12)
    record_key = secrets.token_bytes(32)
    encrypted = AESGCM(record_key).encrypt(nonce, raw, AAD + account_id.encode() + record_id.encode() + payload.kind.encode())
    with database() as db:
        setup(db)
        bound_key = key_for_account(db, account_id, user["key"], migrate=True)
        wrap(db, account_id, record_id, bound_key, record_key)
        db.execute("INSERT INTO vault_records VALUES (?,?,?,?,?,?)", (record_id, account_id, payload.kind, nonce, encrypted, int(time.time())))
        audit(db, account_id, 'record.create')
        db.commit()
    return no_store({"id": record_id, "kind": payload.kind, "created": True, "key_protection": "ML-KEM-768 + X25519 + Pico"}, 201)


@router.get("")
def list_records(user=Depends(session)):
    require_records(user)
    account_id = user["account_id"]
    with database() as db:
        setup(db)
        rows = db.execute("SELECT id,kind,nonce,ciphertext,created_at FROM vault_records WHERE account_id=? ORDER BY created_at DESC, id DESC", (account_id,)).fetchall()
        if not rows:
            return no_store({"records": []})
        bound_key = key_for_account(db, account_id, user["key"])
        summaries = []
        for row in rows:
            record = read_record(db, account_id, bound_key, row)
            summaries.append({"id": record["id"], "kind": record["kind"], "title": record["title"], "created_at": record["created_at"]})
    return no_store({"records": summaries})


@router.get("/{record_id}")
def get_record(record_id: str, user=Depends(session)):
    require_records(user)
    account_id = user["account_id"]
    with database() as db:
        setup(db)
        row = db.execute("SELECT id,kind,nonce,ciphertext,created_at FROM vault_records WHERE account_id=? AND id=?", (account_id, record_id)).fetchone()
        if row is None:
            raise HTTPException(404, "Record not found")
        bound_key = key_for_account(db, account_id, user["key"])
        content = read_record(db, account_id, bound_key, row)
        audit(db, account_id, 'record.reveal')
        db.commit()
    return no_store(content)


@router.delete("/{record_id}")
def delete_record(record_id: str, user=Depends(session)):
    require_records(user)
    account_id = user["account_id"]
    with database() as db:
        setup(db)
        row = db.execute("SELECT 1 FROM vault_records WHERE account_id=? AND id=?", (account_id, record_id)).fetchone()
        if row is None:
            raise HTTPException(404, "Record not found")
        db.execute("DELETE FROM vault_records WHERE account_id=? AND id=?", (account_id, record_id))
        remove(db, record_id)
        db.execute("DELETE FROM file_pqc WHERE file_id=?", (record_id,))
        audit(db, account_id, 'record.delete')
        db.commit()
    return no_store({"deleted": True})
