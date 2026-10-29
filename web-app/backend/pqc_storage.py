import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from pqcrypto.kem.ml_kem_768 import generate_keypair, encrypt, decrypt

DOMAIN = b"PicoVault/v2/ML-KEM-768/"


def setup(db):
    db.execute("CREATE TABLE IF NOT EXISTS account_pqc (account_id TEXT PRIMARY KEY, public_key BLOB NOT NULL, secret_nonce BLOB NOT NULL, secret_blob BLOB NOT NULL)")
    db.execute("CREATE TABLE IF NOT EXISTS file_pqc (file_id TEXT PRIMARY KEY, ciphertext BLOB NOT NULL, nonce BLOB NOT NULL, wrapped_key BLOB NOT NULL)")


def initialize_account(db, account_id, password_key):
    setup(db)
    if db.execute("SELECT 1 FROM account_pqc WHERE account_id=?", (account_id,)).fetchone():
        return
    public, private = generate_keypair()
    nonce = os.urandom(12)
    blob = AESGCM(password_key).encrypt(nonce, private, DOMAIN + account_id.encode())
    db.execute("INSERT INTO account_pqc VALUES (?,?,?,?)", (account_id, public, nonce, blob))


def _keys(db, account_id, password_key):
    row = db.execute("SELECT public_key,secret_nonce,secret_blob FROM account_pqc WHERE account_id=?", (account_id,)).fetchone()
    if not row:
        raise ValueError("Account PQC key missing")
    private = AESGCM(password_key).decrypt(row[1], row[2], DOMAIN + account_id.encode())
    return row[0], private


def _kek(shared, account_id, file_id):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=DOMAIN + account_id.encode() + file_id.encode()).derive(shared)


def wrap_file_key(db, account_id, file_id, password_key, file_key):
    public, _ = _keys(db, account_id, password_key)
    kem_ciphertext, shared = encrypt(public)
    nonce = os.urandom(12)
    wrapped = AESGCM(_kek(shared, account_id, file_id)).encrypt(nonce, file_key, DOMAIN + file_id.encode())
    db.execute("INSERT INTO file_pqc VALUES (?,?,?,?)", (file_id, kem_ciphertext, nonce, wrapped))


def unwrap_file_key(db, account_id, file_id, password_key):
    _, private = _keys(db, account_id, password_key)
    row = db.execute("SELECT ciphertext,nonce,wrapped_key FROM file_pqc WHERE file_id=?", (file_id,)).fetchone()
    if row is None:
        raise ValueError("PQC envelope missing")
    shared = decrypt(private, row[0])
    return AESGCM(_kek(shared, account_id, file_id)).decrypt(row[1], row[2], DOMAIN + file_id.encode())


def uses_pqc(db, file_id):
    return db.execute("SELECT 1 FROM file_pqc WHERE file_id=?", (file_id,)).fetchone() is not None
