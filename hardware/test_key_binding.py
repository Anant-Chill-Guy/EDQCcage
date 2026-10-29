import os
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'web-app/backend'))

from cryptography.exceptions import InvalidTag
from fastapi import HTTPException
import key_binding
from pqc_storage import DOMAIN, _keys, initialize_account, setup, wrap_file_key, unwrap_file_key

account = os.urandom(16).hex()
password_key = os.urandom(32)
original_file_key = os.urandom(32)
fixed_device = os.urandom(32).hex()
fixed_factor = os.urandom(32)
db = sqlite3.connect(':memory:')
setup(db)
initialize_account(db, account, password_key)
legacy_secret = _keys(db, account, password_key)[1]

key_binding.factor = lambda account_id: (fixed_device, fixed_factor)
bound_key = key_binding.key_for_account(db, account, password_key, migrate=True)
assert _keys(db, account, bound_key)[1] == legacy_secret
print('Existing ML-KEM private key migrated without changing it: PASS')

try:
    _keys(db, account, password_key)
except InvalidTag:
    print('Password alone cannot decrypt migrated ML-KEM private key: PASS')
else:
    raise AssertionError('Device factor not required')

file_id = os.urandom(16).hex()
wrap_file_key(db, account, file_id, bound_key, original_file_key)
assert unwrap_file_key(db, account, file_id, bound_key) == original_file_key
print('Pico-bound ML-KEM file key round-trip: PASS')

key_binding.factor = lambda account_id: (os.urandom(32).hex(), os.urandom(32))
try:
    key_binding.key_for_account(db, account, password_key, migrate=True)
except HTTPException as e:
    assert e.status_code == 423
    print('Different Pico identity rejected: PASS')
else:
    raise AssertionError('Wrong device identity accepted')

key_binding.factor = lambda account_id: (fixed_device, os.urandom(32))
try:
    key_binding.key_for_account(db, account, password_key, migrate=True)
except HTTPException as e:
    assert e.status_code == 423
    print('Cloned identity without original secret rejected: PASS')
else:
    raise AssertionError('Wrong Pico factor accepted')

print('Hardware-bound ML-KEM key migration tests PASSED')
