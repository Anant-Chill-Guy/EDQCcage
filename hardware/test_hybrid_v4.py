import os
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "web-app/backend"))

from cryptography.exceptions import InvalidTag
from pqc_storage import initialize_account as initialize_pqc, setup as setup_pqc, wrap_file_key, unwrap_file_key
from hybrid_v4 import setup, wrap, unwrap, is_hybrid


def rejected(action):
    try:
        action()
    except (ValueError, InvalidTag):
        return True
    return False


db = sqlite3.connect(":memory:")
setup_pqc(db)
setup(db)
account = os.urandom(16).hex()
key = os.urandom(32)
file_key = os.urandom(32)
initialize_pqc(db, account, key)

legacy_id = os.urandom(16).hex()
wrap_file_key(db, account, legacy_id, key, file_key)
assert not is_hybrid(db, legacy_id)
assert unwrap_file_key(db, account, legacy_id, key) == file_key
print("Legacy ML-KEM-768 keys remain readable: PASS")

file_id = os.urandom(16).hex()
wrap(db, account, file_id, key, file_key)
assert is_hybrid(db, file_id)
assert unwrap(db, account, file_id, key) == file_key
print("ML-KEM-768 + X25519 hybrid recovery: PASS")

assert rejected(lambda: unwrap(db, account, file_id, os.urandom(32)))
print("Incorrect account-bound key rejected: PASS")

original = db.execute("SELECT wrapped_key FROM file_pqc WHERE file_id=?", (file_id,)).fetchone()[0]
mutated = original[:-1] + bytes([original[-1] ^ 1])
db.execute("UPDATE file_pqc SET wrapped_key=? WHERE file_id=?", (mutated, file_id))
assert rejected(lambda: unwrap(db, account, file_id, key))
db.execute("UPDATE file_pqc SET wrapped_key=? WHERE file_id=?", (original, file_id))
print("Wrapped key tampering rejected: PASS")

original_ephemeral = db.execute("SELECT ephemeral_key FROM file_hybrid WHERE file_id=?", (file_id,)).fetchone()[0]
db.execute("UPDATE file_hybrid SET ephemeral_key=? WHERE file_id=?", (os.urandom(32), file_id))
assert rejected(lambda: unwrap(db, account, file_id, key))
db.execute("UPDATE file_hybrid SET ephemeral_key=? WHERE file_id=?", (original_ephemeral, file_id))
print("Classical ephemeral key tampering rejected: PASS")

original_kem = db.execute("SELECT ciphertext FROM file_pqc WHERE file_id=?", (file_id,)).fetchone()[0]
mutated_kem = original_kem[:-1] + bytes([original_kem[-1] ^ 1])
db.execute("UPDATE file_pqc SET ciphertext=? WHERE file_id=?", (mutated_kem, file_id))
assert rejected(lambda: unwrap(db, account, file_id, key))
db.execute("UPDATE file_pqc SET ciphertext=? WHERE file_id=?", (original_kem, file_id))
print("ML-KEM ciphertext tampering rejected: PASS")

assert unwrap(db, account, file_id, key) == file_key
print("Original hybrid envelope still decrypts: PASS")
print("Hybrid v4 tests PASSED")
