import hashlib
import math
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
from security_runtime import audit, setup as setup_security, login_allowed, login_failure, login_success, password_hash, verify_password
from key_binding import key_for_account, setup as setup_hardware
from pqc_storage import setup, unwrap_file_key, uses_pqc
from hybrid_v4 import setup as setup_hybrid, wrap as wrap_hybrid, unwrap as unwrap_hybrid, is_hybrid, remove as remove_hybrid

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
    BASE.chmod(0o700)
    BLOBS.chmod(0o700)
    conn = sqlite3.connect(DB, timeout=10)
    DB.chmod(0o600)
    conn.execute("PRAGMA foreign_keys=ON")
    setup(conn)
    setup_hardware(conn)
    setup_security(conn)
    setup_hybrid(conn)
    conn.execute("CREATE TABLE IF NOT EXISTS accounts (id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL, salt BLOB NOT NULL, password_hash BLOB NOT NULL, vault_salt BLOB NOT NULL)")
    conn.execute("CREATE TABLE IF NOT EXISTS account_locks (account_id TEXT PRIMARY KEY REFERENCES accounts(id), salt BLOB NOT NULL, verifier BLOB NOT NULL)")
    conn.execute("CREATE TABLE IF NOT EXISTS hardware_passwords (account_id TEXT PRIMARY KEY REFERENCES accounts(id), salt BLOB NOT NULL, verifier BLOB NOT NULL)")
    conn.execute("CREATE TABLE IF NOT EXISTS files (id TEXT PRIMARY KEY, account_id TEXT NOT NULL, filename TEXT NOT NULL, byte_size INTEGER NOT NULL, created_at INTEGER NOT NULL, nonce BLOB NOT NULL, storage_mode TEXT NOT NULL DEFAULT 'encrypted', FOREIGN KEY(account_id) REFERENCES accounts(id))")
    columns = {row[1] for row in conn.execute("PRAGMA table_info(files)")}
    if 'storage_mode' not in columns:
        conn.execute("ALTER TABLE files ADD COLUMN storage_mode TEXT NOT NULL DEFAULT 'encrypted'")
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
        key = hashlib.sha256(token.encode()).digest()
        entry = SESSIONS.get(key)
        now = time.time()
        if entry is None or entry["expires"] <= now or now - entry.get("seen", now) > 900:
            SESSIONS.pop(key, None)
            raise HTTPException(401, "Invalid or expired session")
        entry["seen"] = now
        return {**entry, "session_id": key}


@router.post("/register", status_code=201)
def register(payload: Credentials):
    salt = secrets.token_bytes(16)
    vault_salt = secrets.token_bytes(16)
    with database() as db:
        try:
            account_id = uuid.uuid4().hex
            db.execute("INSERT INTO accounts VALUES (?,?,?,?,?)", (account_id, payload.username, salt, password_hash(payload.password, salt), vault_salt))
            audit(db, account_id, 'account.register')
            db.commit()
        except sqlite3.IntegrityError:
            raise HTTPException(409, "Username unavailable")
    return {"created": True, "username": payload.username}


@router.post("/login")
def login(payload: Credentials):
    with database() as db:
        if not login_allowed(db, payload.username):
            raise HTTPException(429, "Too many attempts. Try again later.")
        row = db.execute("SELECT id, salt, password_hash, vault_salt FROM accounts WHERE username=?", (payload.username,)).fetchone()
        salt = row[1] if row else bytes(16)
        stored = row[2] if row else bytes(32)
        valid, legacy = verify_password(payload.password, salt, stored, derive)
        if row is None or not valid:
            if row is not None:
                audit(db, row[0], 'account.login_failed')
            login_failure(db, payload.username)
            raise HTTPException(401, "Invalid credentials")
        login_success(db, payload.username)
        if legacy:
            db.execute("UPDATE accounts SET password_hash=? WHERE id=?", (password_hash(payload.password, row[1]), row[0]))
            db.commit()
    account_key = derive(payload.password, row[3])
    token = secrets.token_urlsafe(32)
    with LOCK:
        now = time.time()
        SESSIONS[hashlib.sha256(token.encode()).digest()] = {"account_id": row[0], "key": account_key, "expires": now + 1800, "seen": now, "hardware_until": 0, "records_until": 0}
    with database() as db:
        audit(db, row[0], 'account.login')
        db.commit()
    return {"access_token": token, "token_type": "bearer", "expires_in": 1800}



class AccountPasswordChange(BaseModel):
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=12, max_length=256)


@router.post("/account/password/change")
def change_account_password(payload: AccountPasswordChange, user=Depends(session)):
    require_hardware(user)
    account_id = user["account_id"]
    with database() as db:
        identity = "account-change:" + account_id
        if not login_allowed(db, identity):
            raise HTTPException(429, "Too many password attempts. Try again later")
        row = db.execute("SELECT salt,password_hash,vault_salt FROM accounts WHERE id=?", (account_id,)).fetchone()
        if row is None:
            raise HTTPException(401, "Account not found")
        valid, _ = verify_password(payload.current_password, row[0], row[1], derive)
        if not valid:
            login_failure(db, identity)
            raise HTTPException(403, "Incorrect current account password")
        if hmac.compare_digest(payload.current_password, payload.new_password):
            raise HTTPException(400, "Choose a different account password")
        old_password_key = derive(payload.current_password, row[2])
        new_login_salt = secrets.token_bytes(16)
        new_vault_salt = secrets.token_bytes(16)
        new_password_key = derive(payload.new_password, new_vault_salt)
        binding = db.execute("SELECT device_id,salt FROM account_hardware WHERE account_id=?", (account_id,)).fetchone()
        if binding:
            from hardware_key import factor
            from key_binding import _combine
            device_id, device_factor = factor(account_id)
            if not hmac.compare_digest(device_id, binding[0]):
                raise HTTPException(423, "The registered Pico is required to change this account password")
            old_wrap_key = key_for_account(db, account_id, old_password_key)
            new_wrap_key = _combine(new_password_key, device_factor, binding[1], account_id)
        else:
            old_wrap_key = old_password_key
            new_wrap_key = new_password_key
        from pqc_storage import DOMAIN
        from hybrid_v4 import HYBRID
        for table, domain in (
            ("account_pqc", DOMAIN + account_id.encode()),
            ("account_hybrid", HYBRID + b"account/" + account_id.encode()),
        ):
            wrapped = db.execute("SELECT secret_nonce,secret_blob FROM " + table + " WHERE account_id=?", (account_id,)).fetchone()
            if wrapped:
                try:
                    plaintext = AESGCM(old_wrap_key).decrypt(wrapped[0], wrapped[1], domain)
                except InvalidTag as exc:
                    raise HTTPException(422, "Existing account keys could not be verified; password not changed") from exc
                nonce = secrets.token_bytes(12)
                protected = AESGCM(new_wrap_key).encrypt(nonce, plaintext, domain)
                db.execute("UPDATE " + table + " SET secret_nonce=?,secret_blob=? WHERE account_id=?", (nonce, protected, account_id))
        db.execute(
            "UPDATE accounts SET salt=?,password_hash=?,vault_salt=? WHERE id=?",
            (new_login_salt, password_hash(payload.new_password, new_login_salt), new_vault_salt, account_id),
        )
        login_success(db, identity)
        audit(db, account_id, "account.password_change")
        db.commit()
    with LOCK:
        for session_id, entry in list(SESSIONS.items()):
            if entry["account_id"] == account_id:
                SESSIONS.pop(session_id, None)
    return {"changed": True, "signed_out": True}


@router.post("/logout")
def logout(authorization: str | None = Header(default=None), user=Depends(session)):
    with LOCK:
        SESSIONS.pop(hashlib.sha256(authorization[7:].encode()).digest(), None)
    with database() as db:
        audit(db, user["account_id"], 'account.logout')
        db.commit()
    return {"logged_out": True}


class LockInput(BaseModel):
    password: str = Field(min_length=12, max_length=256)


class UnlockInput(BaseModel):
    lock_password: str = Field(min_length=1, max_length=256)


def lock_configured(db, account_id):
    return db.execute("SELECT 1 FROM account_locks WHERE account_id=?", (account_id,)).fetchone() is not None


def verify_lock(db, account_id, password):
    identity = "lock:" + account_id
    if not login_allowed(db, identity):
        raise HTTPException(429, "Too many lock-password attempts. Try again later.")
    row = db.execute("SELECT salt, verifier FROM account_locks WHERE account_id=?", (account_id,)).fetchone()
    if row is None:
        raise HTTPException(409, "Set your file lock password before decrypting")
    if not hmac.compare_digest(row[1], password_hash(password, row[0])):
        login_failure(db, identity)
        raise HTTPException(403, "Incorrect lock password")
    login_success(db, identity)


@router.get("/lock/status")
def lock_status(user=Depends(session)):
    with database() as db:
        return {"configured": lock_configured(db, user["account_id"])}


@router.post("/lock", status_code=201)
def set_lock(payload: LockInput, user=Depends(session)):
    with database() as db:
        try:
            salt = secrets.token_bytes(16)
            db.execute("INSERT INTO account_locks (account_id,salt,verifier) VALUES (?,?,?)", (user["account_id"], salt, password_hash(payload.password, salt)))
            audit(db, user["account_id"], 'lock.set')
            db.commit()
        except sqlite3.IntegrityError as exc:
            raise HTTPException(409, "Lock password already set") from exc
    return {"configured": True}


class ChangeLockInput(BaseModel):
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=12, max_length=256)


@router.post("/lock/change")
def change_lock(payload: ChangeLockInput, user=Depends(session)):
    account_id = user["account_id"]
    with database() as db:
        verify_lock(db, account_id, payload.current_password)
        if hmac.compare_digest(payload.current_password, payload.new_password):
            raise HTTPException(400, "Choose a different lock password")
        require_hardware(user)
        salt = secrets.token_bytes(16)
        verifier = password_hash(payload.new_password, salt)
        db.execute("UPDATE account_locks SET salt=?,verifier=? WHERE account_id=?", (salt, verifier, account_id))
        audit(db, account_id, 'lock.change')
        db.commit()
    return {"changed": True}


class HardwarePasswordInput(BaseModel):
    password: str = Field(min_length=12, max_length=256)


class HardwareChangeInput(BaseModel):
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=12, max_length=256)


def _grant(user, field, seconds):
    with LOCK:
        active = SESSIONS.get(user["session_id"])
        if active is None or active["account_id"] != user["account_id"]:
            raise HTTPException(401, "Sign in again")
        now = time.time()
        active[field] = now + seconds
        if field == "hardware_until":
            active["expires"] = max(active["expires"], now + seconds + 10)


def _revoke(user):
    with LOCK:
        active = SESSIONS.get(user["session_id"])
        if active:
            active["hardware_until"] = 0
            active["records_until"] = 0


def require_hardware(user):
    with LOCK:
        active = SESSIONS.get(user["session_id"])
        if not active or active.get("hardware_until", 0) <= time.time():
            raise HTTPException(423, "Unlock your Pico with the hardware password in USB Device first")
    try:
        require_pico()
    except HTTPException:
        _revoke(user)
        raise


def require_records(user):
    require_hardware(user)
    with LOCK:
        active = SESSIONS.get(user["session_id"])
        if not active or active.get("records_until", 0) <= time.time():
            raise HTTPException(423, "Unlock Credentials & Notes with the file lock password")


def _hardware_verified(db, user, password):
    identity = "pico-password:" + user["account_id"]
    if not login_allowed(db, identity):
        raise HTTPException(429, "Too many hardware password attempts")
    row = db.execute("SELECT salt, verifier FROM hardware_passwords WHERE account_id=?", (user["account_id"],)).fetchone()
    if not row:
        raise HTTPException(409, "Set a hardware password first")
    if not hmac.compare_digest(row[1], password_hash(password, row[0])):
        login_failure(db, identity)
        raise HTTPException(403, "Incorrect hardware password")
    login_success(db, identity)


@router.get("/hardware/status")
def hardware_status(user=Depends(session)):
    with database() as db:
        configured = db.execute("SELECT 1 FROM hardware_passwords WHERE account_id=?", (user["account_id"],)).fetchone() is not None
    with LOCK:
        active = SESSIONS.get(user["session_id"], {})
        expires = max(0, math.ceil(active.get("hardware_until", 0) - time.time()))
    return {"configured": configured, "unlocked": expires > 0, "seconds_left": expires}


@router.post("/hardware/password", status_code=201)
def set_hardware_password(payload: HardwarePasswordInput, user=Depends(session)):
    require_pico()
    with database() as db:
        try:
            salt = secrets.token_bytes(16)
            db.execute("INSERT INTO hardware_passwords VALUES (?,?,?)", (user["account_id"], salt, password_hash(payload.password, salt)))
            audit(db, user["account_id"], "hardware.password_set")
            db.commit()
        except sqlite3.IntegrityError as exc:
            raise HTTPException(409, "Hardware password already configured") from exc
    return {"configured": True}


@router.post("/hardware/unlock")
def hardware_unlock(payload: HardwarePasswordInput, user=Depends(session)):
    with database() as db:
        _hardware_verified(db, user, payload.password)
    require_pico()
    _grant(user, "hardware_until", 900)
    return {"unlocked": True, "expires_in": 900}


@router.post("/hardware/change")
def hardware_change(payload: HardwareChangeInput, user=Depends(session)):
    require_hardware(user)
    with database() as db:
        _hardware_verified(db, user, payload.current_password)
        if hmac.compare_digest(payload.current_password, payload.new_password):
            raise HTTPException(400, "Choose a different hardware password")
        salt = secrets.token_bytes(16)
        db.execute("UPDATE hardware_passwords SET salt=?,verifier=? WHERE account_id=?", (salt, password_hash(payload.new_password, salt), user["account_id"]))
        audit(db, user["account_id"], "hardware.password_change")
        db.commit()
    _revoke(user)
    return {"changed": True}


@router.post("/hardware/lock")
def hardware_lock(user=Depends(session)):
    _revoke(user)
    return {"locked": True}


@router.post("/records/unlock")
def records_unlock(payload: UnlockInput, user=Depends(session)):
    require_hardware(user)
    with database() as db:
        verify_lock(db, user["account_id"], payload.lock_password)
    _grant(user, "records_until", 300)
    return {"unlocked": True, "expires_in": 300}


@router.post("/records/lock")
def records_lock(user=Depends(session)):
    with LOCK:
        active = SESSIONS.get(user["session_id"])
        if active:
            active["records_until"] = 0
    return {"locked": True}


class DeletePasswordInput(BaseModel):
    current_password: str = Field(min_length=1, max_length=256)


def _revoke_all_for_account(account_id, records_only=False):
    with LOCK:
        for active in SESSIONS.values():
            if active["account_id"] == account_id:
                active["records_until"] = 0
                if not records_only:
                    active["hardware_until"] = 0


@router.post("/hardware/delete")
def delete_hardware_password(payload: DeletePasswordInput, user=Depends(session)):
    require_hardware(user)
    with database() as db:
        _hardware_verified(db, user, payload.current_password)
        db.execute("DELETE FROM hardware_passwords WHERE account_id=?", (user["account_id"],))
        audit(db, user["account_id"], "hardware.password_delete")
        db.commit()
    _revoke_all_for_account(user["account_id"])
    return {"deleted": True, "requires_new_password": True}


@router.get("/files")
def list_files(user=Depends(session)):
    with database() as db:
        rows = db.execute("SELECT id,filename,byte_size,created_at,storage_mode FROM files WHERE account_id=? ORDER BY created_at DESC", (user["account_id"],)).fetchall()
    return {"files": [{"id": r[0], "name": r[1], "size": r[2], "created_at": r[3], "storage_mode": r[4], "key_protection": "AES-256-GCM · Pico · ML-KEM-768/X25519" if r[4] == 'encrypted' else "Legacy unencrypted · migration needed"} for r in rows]}


@router.post("/files", status_code=201)
async def upload(file: UploadFile = File(...), user=Depends(session)):
    require_hardware(user)
    with database() as db:
        if not lock_configured(db, user["account_id"]):
            raise HTTPException(423, "Configure a file lock password before encrypting files")
    data = await file.read(MAX_FILE + 1)
    await file.close()
    if len(data) > MAX_FILE:
        raise HTTPException(413, "File size limit is 16 MiB")
    name = Path((file.filename or "unnamed").replace("\\", "/")).name[:255]
    file_id = uuid.uuid4().hex
    nonce = secrets.token_bytes(12)
    with database() as db:
        bound_key = key_for_account(db, user["account_id"], user["key"], migrate=True)
        db.commit()
    file_key = secrets.token_bytes(32)
    blob = AESGCM(file_key).encrypt(nonce, data, (user["account_id"] + ":" + file_id).encode())
    path = BLOBS / (file_id + ".bin")
    with path.open("xb") as handle:
        os.chmod(path, 0o600)
        handle.write(blob)
    try:
        with database() as db:
            db.execute("INSERT INTO files (id,account_id,filename,byte_size,created_at,nonce,storage_mode) VALUES (?,?,?,?,?,?,?)", (file_id, user["account_id"], name, len(data), int(time.time()), nonce, 'encrypted'))
            wrap_hybrid(db, user["account_id"], file_id, bound_key, file_key)
            audit(db, user["account_id"], 'file.upload_encrypted')
            db.commit()
    except Exception:
        path.unlink(missing_ok=True)
        raise
    return {"id": file_id, "name": name, "size": len(data), "storage_mode": "encrypted", "encrypted_at_rest": True}


@router.post("/files/migrate")
def migrate_plain_files(user=Depends(session)):
    require_hardware(user)
    with database() as db:
        if not lock_configured(db, user["account_id"]):
            raise HTTPException(409, "Set your lock password before migration")
        rows = db.execute("SELECT id,nonce FROM files WHERE account_id=? AND storage_mode='plain'", (user["account_id"],)).fetchall()
        if not rows:
            return {"migrated": 0}
        bound_key = key_for_account(db, user["account_id"], user["key"], migrate=True)
        db.commit()
    migrated = 0
    for file_id, _ in rows:
        path = BLOBS / (file_id + ".bin")
        try:
            cleartext = path.read_bytes()
        except OSError:
            continue
        nonce = secrets.token_bytes(12)
        file_key = secrets.token_bytes(32)
        ciphertext = AESGCM(file_key).encrypt(nonce, cleartext, (user["account_id"] + ":" + file_id).encode())
        temp = BLOBS / (file_id + ".pending")
        with temp.open("xb") as handle:
            os.chmod(temp, 0o600)
            handle.write(ciphertext)
        try:
            with database() as db:
                db.execute("BEGIN IMMEDIATE")
                current = db.execute("SELECT storage_mode FROM files WHERE id=? AND account_id=?", (file_id,user["account_id"])).fetchone()
                if not current or current[0] != 'plain':
                    continue
                wrap_hybrid(db, user["account_id"], file_id, bound_key, file_key)
                os.replace(temp, path)
                db.execute("UPDATE files SET nonce=?,storage_mode='encrypted' WHERE id=? AND account_id=?", (nonce,file_id,user["account_id"]))
                audit(db, user["account_id"], 'file.migrate')
                db.commit()
                migrated += 1
        finally:
            temp.unlink(missing_ok=True)
    return {"migrated": migrated}


@router.post("/files/{file_id}/decrypt")
def decrypt_file(file_id: str, payload: UnlockInput, user=Depends(session)):
    with database() as db:
        row = db.execute("SELECT filename,nonce,storage_mode FROM files WHERE id=? AND account_id=?", (file_id, user["account_id"])).fetchone()
        if row is None:
            raise HTTPException(404, "File not found")
        if row[2] != 'encrypted':
            raise HTTPException(409, "Migrate this legacy file to encrypted storage first")
        verify_lock(db, user["account_id"], payload.lock_password)
    require_hardware(user)
    name, nonce, _ = row
    try:
        blob = (BLOBS / (file_id + ".bin")).read_bytes()
        with database() as db:
            bound_key = key_for_account(db, user["account_id"], user["key"])
            if uses_pqc(db, file_id):
                file_key = unwrap_hybrid(db, user["account_id"], file_id, bound_key) if is_hybrid(db, file_id) else unwrap_file_key(db, user["account_id"], file_id, bound_key)
            else:
                file_key = user["key"]
        content = AESGCM(file_key).decrypt(nonce, blob, (user["account_id"] + ":" + file_id).encode())
    except (OSError, ValueError, InvalidTag):
        raise HTTPException(422, "File could not be verified or opened")
    with database() as db:
        audit(db, user["account_id"], 'file.decrypt')
        db.commit()
    from urllib.parse import quote
    return Response(content=content, media_type="application/octet-stream", headers={"Content-Disposition": "attachment; filename*=UTF-8''" + quote(name), "X-Storage-Mode": "encrypted", "Cache-Control": "no-store"})


@router.delete("/files/{file_id}")
def delete(file_id: str, user=Depends(session)):
    with database() as db:
        found = db.execute("SELECT storage_mode FROM files WHERE id=? AND account_id=?", (file_id, user["account_id"])).fetchone()
        if found is None:
            raise HTTPException(404, "File not found")
        if found[0] == 'encrypted':
            remove_hybrid(db, file_id)
            db.execute("DELETE FROM file_pqc WHERE file_id=?", (file_id,))
        db.execute("DELETE FROM files WHERE id=? AND account_id=?", (file_id, user["account_id"]))
        audit(db, user["account_id"], 'file.delete')
        db.commit()
    (BLOBS / (file_id + ".bin")).unlink(missing_ok=True)
    return {"deleted": True}


@router.get("/me")
def current_account(user=Depends(session)):
    with database() as db:
        row = db.execute("SELECT username FROM accounts WHERE id=?", (user["account_id"],)).fetchone()
    if row is None:
        raise HTTPException(401, "Account not found")
    return {"username": row[0], "authenticated": True, "hardware_required_for_decryption": True}
