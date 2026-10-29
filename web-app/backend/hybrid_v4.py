import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from pqcrypto.kem.ml_kem_768 import encrypt, decrypt

from pqc_storage import DOMAIN

HYBRID = b"PicoVault/v4/ML-KEM-768+X25519/"


def setup(db):
    db.execute("CREATE TABLE IF NOT EXISTS account_hybrid (account_id TEXT PRIMARY KEY, public_key BLOB NOT NULL, secret_nonce BLOB NOT NULL, secret_blob BLOB NOT NULL)")
    db.execute("CREATE TABLE IF NOT EXISTS file_hybrid (file_id TEXT PRIMARY KEY, ephemeral_key BLOB NOT NULL, salt BLOB NOT NULL)")


def initialize_account(db, account_id, bound_key):
    setup(db)
    if db.execute("SELECT 1 FROM account_hybrid WHERE account_id=?", (account_id,)).fetchone():
        return
    private = x25519.X25519PrivateKey.generate()
    public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    secret = private.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    nonce = os.urandom(12)
    blob = AESGCM(bound_key).encrypt(nonce, secret, HYBRID + b"account/" + account_id.encode())
    db.execute("INSERT INTO account_hybrid VALUES (?,?,?,?)", (account_id, public, nonce, blob))


def _derive(pq_shared, classical_shared, salt, account_id, file_id):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=HYBRID + account_id.encode() + b"/" + file_id.encode()).derive(pq_shared + classical_shared)


def wrap(db, account_id, file_id, bound_key, file_key):
    if len(file_key) != 32:
        raise ValueError("Invalid file key")
    setup(db)
    initialize_account(db, account_id, bound_key)
    pq_row = db.execute("SELECT public_key FROM account_pqc WHERE account_id=?", (account_id,)).fetchone()
    classical_row = db.execute("SELECT public_key FROM account_hybrid WHERE account_id=?", (account_id,)).fetchone()
    if not pq_row or not classical_row:
        raise ValueError("Recipient keys missing")
    kem_ciphertext, pq_shared = encrypt(pq_row[0])
    ephemeral = x25519.X25519PrivateKey.generate()
    ephemeral_public = ephemeral.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    classical_shared = ephemeral.exchange(x25519.X25519PublicKey.from_public_bytes(classical_row[0]))
    salt = os.urandom(32)
    nonce = os.urandom(12)
    key = _derive(pq_shared, classical_shared, salt, account_id, file_id)
    wrapped = AESGCM(key).encrypt(nonce, file_key, HYBRID + account_id.encode() + b"/" + file_id.encode())
    db.execute("INSERT INTO file_pqc VALUES (?,?,?,?)", (file_id, kem_ciphertext, nonce, wrapped))
    db.execute("INSERT INTO file_hybrid VALUES (?,?,?)", (file_id, ephemeral_public, salt))


def is_hybrid(db, file_id):
    setup(db)
    return db.execute("SELECT 1 FROM file_hybrid WHERE file_id=?", (file_id,)).fetchone() is not None


def unwrap(db, account_id, file_id, bound_key):
    pq = db.execute("SELECT ciphertext,nonce,wrapped_key FROM file_pqc WHERE file_id=?", (file_id,)).fetchone()
    envelope = db.execute("SELECT ephemeral_key,salt FROM file_hybrid WHERE file_id=?", (file_id,)).fetchone()
    pq_account = db.execute("SELECT secret_nonce,secret_blob FROM account_pqc WHERE account_id=?", (account_id,)).fetchone()
    classical_account = db.execute("SELECT secret_nonce,secret_blob FROM account_hybrid WHERE account_id=?", (account_id,)).fetchone()
    if not all((pq, envelope, pq_account, classical_account)):
        raise ValueError("Hybrid key information missing")
    pq_private = AESGCM(bound_key).decrypt(pq_account[0], pq_account[1], DOMAIN + account_id.encode())
    classical_private = AESGCM(bound_key).decrypt(classical_account[0], classical_account[1], HYBRID + b"account/" + account_id.encode())
    pq_shared = decrypt(pq_private, pq[0])
    classical_shared = x25519.X25519PrivateKey.from_private_bytes(classical_private).exchange(x25519.X25519PublicKey.from_public_bytes(envelope[0]))
    key = _derive(pq_shared, classical_shared, envelope[1], account_id, file_id)
    return AESGCM(key).decrypt(pq[1], pq[2], HYBRID + account_id.encode() + b"/" + file_id.encode())


def remove(db, file_id):
    db.execute("DELETE FROM file_hybrid WHERE file_id=?", (file_id,))
