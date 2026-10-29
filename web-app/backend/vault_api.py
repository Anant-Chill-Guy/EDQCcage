import hashlib
import hmac
import os
import secrets
import sqlite3
import threading
import time
import uuid
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from fastapi import APIRouter, Depends, File, Header, HTTPException, UploadFile
from fastapi.responses import Response
from pydantic import BaseModel, Field

from hardware_auth import authenticate_device
from pqc_storage import setup, initialize_account, wrap_file_key, unwrap_file_key, uses_pqc

router = APIRouter(prefix="/api/vault")
BASE = Path(__file__).resolve().parent / ".vault_data"
BLOBS = BASE / "blobs"
DB = BASE / "vault.sqlite3"
MAX_FILE = 16 * 1024 * 1024
SESSIONS = {}
LOCK = threading.RLock()


def database():
    BASE.mkdir(parents=True, exist_ok=True, mode=0o700)
    BLOBS.mkdir(parents=True, exist_ok=True, mode=0o700)
    conn = sqlite3.connect(DB, timeout=10)
    conn.execute("PRAGMA foreign_keys=ON")
    setup(conn)
    conn.execute("CREATE TABLE IF NOT EXISTS accounts (id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL, salt BLOB NOT NULL, password_hash BLOB NOT NULL, vault_salt BLOB NOT NULL)")
    conn.execute("CREATE TABLE IF NOT EXISTS files (id TEXT PRIMARY KEY, account_id TEXT NOT NULL, filename TEXT NOT NULL, byte_size INTEGER NOT NULL, created_at INTEGER NOT NULL, nonce BLOB NOT NULL, FOREIGN KEY(account_id) REFERENCES accounts(id))")
    conn.commit()
    return conn


def derive(password, salt):
    return hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=32)


def require_pico():
    try:
        result = authenticate_device()
    except (RuntimeError, ValueError, OSError):
        raise HTTPException(423, "Enrolled Pico required and must authenticate")
    if not result.get("authenticated"):
        raise HTTPException(423, "Pico challenge-response failed")


class Credentials(BaseModel):
    username: str = Field(min_length=3, max_length=48, pattern=r"^[a-zA-Z0-9_.-]+$")
    password: str = Field(min_length=12, max_length=256)


def session(authorization: str | None = Header(default=None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Authentication required")
    token = authorization[7:]
    with LOCK:
        entry = SESSIONS.get(hashlib.sha256(token.encode()).digest())
        if entry is None or entry["expires"] <= time.time():
            raise HTTPException(401, "Invalid or expired session")
        return dict(entry)


@router.post("/register", status_code=201)
def register(payload: Credentials):
    require_pico()
    salt = secrets.token_bytes(16)
    vault_salt = secrets.token_bytes(16)
    with database() as db:
        try:
            db.execute("INSERT INTO accounts VALUES (?,?,?,?,?)", (uuid.uuid4().hex, payload.username, salt, derive(payload.password, salt), vault_salt))
            db.commit()
        except sqlite3.IntegrityError:
            raise HTTPException(409, "Username unavailable")
    return {"created": True, "username": payload.username}


@router.post("/login")
def login(payload: Credentials):
    require_pico()
    with database() as db:
        row = db.execute("SELECT id, salt, password_hash, vault_salt FROM accounts WHERE username=?", (payload.username,)).fetchone()
    candidate_salt = row[1] if row else b"\x00" * 16
    candidate = derive(payload.password, candidate_salt)
    if row is None or not hmac.compare_digest(candidate, row[2]):
        raise HTTPException(401, "Invalid credentials")
    account_key = derive(payload.password, row[3])
    with database() as db:
        initialize_account(db, row[0], account_key)
        db.commit()
    token = secrets.token_urlsafe(32)
    with LOCK:
        SESSIONS[hashlib.sha256(token.encode()).digest()] = {"account_id": row[0], "key": account_key, "expires": time.time() + 1800}
    return {"access_token": token, "token_type": "bearer", "expires_in": 1800}


@router.post("/logout")
def logout(authorization: str | None = Header(default=None), user=Depends(session)):
    with LOCK:
        SESSIONS.pop(hashlib.sha256(authorization[7:].encode()).digest(), None)
    return {"logged_out": True}


@router.get("/files")
def list_files(user=Depends(session)):
    require_pico()
    with database() as db:
        rows = db.execute("SELECT id,filename,byte_size,created_at FROM files WHERE account_id=? ORDER BY created_at DESC", (user["account_id"],)).fetchall()
    return {"files": [{"id": r[0], "name": r[1], "size": r[2], "created_at": r[3]} for r in rows]}


@router.post("/files", status_code=201)
async def upload(file: UploadFile = File(...), user=Depends(session)):
    require_pico()
    data = await file.read(MAX_FILE + 1)
    await file.close()
    if len(data) > MAX_FILE:
        raise HTTPException(413, "Phase 4 file limit is 16 MiB")
    name = Path((file.filename or "unnamed").replace("\\", "/")).name[:255]
    file_id = uuid.uuid4().hex
    nonce = secrets.token_bytes(12)
    file_key = secrets.token_bytes(32)
    blob = AESGCM(file_key).encrypt(nonce, data, (user["account_id"] + ":" + file_id).encode())
    path = BLOBS / (file_id + ".bin")
    with path.open("xb") as handle:
        os.chmod(path, 0o600)
        handle.write(blob)
    try:
        with database() as db:
            db.execute("INSERT INTO files VALUES (?,?,?,?,?,?)", (file_id, user["account_id"], name, len(data), int(time.time()), nonce))
            wrap_file_key(db, user["account_id"], file_id, user["key"], file_key)
            db.commit()
    except Exception:
        path.unlink(missing_ok=True)
        raise
    return {"id": file_id, "name": name, "size": len(data), "encrypted_at_rest": True, "key_protection": "ML-KEM-768"}


@router.get("/files/{file_id}")
def download(file_id: str, user=Depends(session)):
    require_pico()
    with database() as db:
        row = db.execute("SELECT filename,nonce FROM files WHERE id=? AND account_id=?", (file_id, user["account_id"])).fetchone()
    if row is None:
        raise HTTPException(404, "File not found")
    try:
        blob = (BLOBS / (file_id + ".bin")).read_bytes()
        with database() as db:
            file_key = unwrap_file_key(db, user["account_id"], file_id, user["key"]) if uses_pqc(db, file_id) else user["key"]
        data = AESGCM(file_key).decrypt(row[1], blob, (user["account_id"] + ":" + file_id).encode())
    except (OSError, ValueError, InvalidTag):
        raise HTTPException(422, "Encrypted file is unavailable or invalid")
    return Response(content=data, media_type="application/octet-stream", headers={"Content-Disposition": "attachment; filename*=UTF-8''" + __import__("urllib.parse", fromlist=["quote"]).quote(row[0])})


@router.delete("/files/{file_id}")
def delete(file_id: str, user=Depends(session)):
    require_pico()
    with database() as db:
        found = db.execute("SELECT id FROM files WHERE id=? AND account_id=?", (file_id, user["account_id"])).fetchone()
        if found is None:
            raise HTTPException(404, "File not found")
        db.execute("DELETE FROM file_pqc WHERE file_id=?", (file_id,))
        db.execute("DELETE FROM files WHERE id=? AND account_id=?", (file_id, user["account_id"]))
        db.commit()
    (BLOBS / (file_id + ".bin")).unlink(missing_ok=True)
    return {"deleted": True}
