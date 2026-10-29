import hmac
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from fastapi import HTTPException

from hardware_key import factor
from pqc_storage import DOMAIN, initialize_account

BIND_DOMAIN = b'PicoVault/v3/account-key-binding/'


def setup(db):
    db.execute('CREATE TABLE IF NOT EXISTS account_hardware (account_id TEXT PRIMARY KEY, device_id TEXT NOT NULL, salt BLOB NOT NULL)')


def _combine(password_key, device_factor, salt, account_id):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=BIND_DOMAIN + account_id.encode()).derive(password_key + device_factor)


def key_for_account(db, account_id, password_key, migrate=False):
    setup(db)
    try:
        device_id, device_factor = factor(account_id)
    except (OSError, RuntimeError, ValueError) as exc:
        raise HTTPException(423, detail=str(exc) or 'No Device Detected') from exc
    row = db.execute('SELECT device_id,salt FROM account_hardware WHERE account_id=?', (account_id,)).fetchone()
    if row is not None:
        if not hmac.compare_digest(row[0], device_id):
            raise HTTPException(423, 'This account is bound to a different Pico')
        key = _combine(password_key, device_factor, row[1], account_id)
        stored = db.execute('SELECT secret_nonce,secret_blob FROM account_pqc WHERE account_id=?', (account_id,)).fetchone()
        if not stored:
            raise HTTPException(422, 'PQC account key missing')
        try:
            AESGCM(key).decrypt(stored[0], stored[1], DOMAIN + account_id.encode())
        except InvalidTag as exc:
            raise HTTPException(423, 'Hardware-bound key recovery failed') from exc
        return key
    if not migrate:
        raise HTTPException(423, 'Account device binding required. Sign in again.')
    initialize_account(db, account_id, password_key)
    stored = db.execute('SELECT secret_nonce,secret_blob FROM account_pqc WHERE account_id=?', (account_id,)).fetchone()
    if not stored:
        raise HTTPException(422, 'PQC account key missing')
    secret = AESGCM(password_key).decrypt(stored[0], stored[1], DOMAIN + account_id.encode())
    salt = os.urandom(32)
    key = _combine(password_key, device_factor, salt, account_id)
    nonce = os.urandom(12)
    protected = AESGCM(key).encrypt(nonce, secret, DOMAIN + account_id.encode())
    db.execute('UPDATE account_pqc SET secret_nonce=?,secret_blob=? WHERE account_id=?', (nonce, protected, account_id))
    db.execute('INSERT INTO account_hardware VALUES (?,?,?)', (account_id, device_id, salt))
    return key
