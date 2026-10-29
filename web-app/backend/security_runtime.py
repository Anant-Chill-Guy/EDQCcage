import hashlib
import os
import sqlite3
import time

from argon2.low_level import Type, hash_secret_raw

PASSWORD_PREFIX = b'PV-ARGON2ID-v1:'
WINDOW = 900
LIMIT = 5
LOCK_DURATION = 300


def password_hash(password, salt):
    raw = hash_secret_raw(password.encode('utf-8'), salt, time_cost=3, memory_cost=65536, parallelism=1, hash_len=32, type=Type.ID)
    return PASSWORD_PREFIX + raw


def verify_password(password, salt, stored, legacy_deriver):
    import hmac
    if stored.startswith(PASSWORD_PREFIX):
        return hmac.compare_digest(stored, password_hash(password, salt)), False
    return hmac.compare_digest(stored, legacy_deriver(password, salt)), True


def setup(db):
    db.execute('CREATE TABLE IF NOT EXISTS login_limits (username_hash TEXT PRIMARY KEY, failures INTEGER NOT NULL, started_at INTEGER NOT NULL, locked_until INTEGER NOT NULL)')
    db.execute('CREATE TABLE IF NOT EXISTS security_audit (id INTEGER PRIMARY KEY AUTOINCREMENT, account_id TEXT NOT NULL, event TEXT NOT NULL, created_at INTEGER NOT NULL)')
    db.execute('CREATE INDEX IF NOT EXISTS security_audit_owner ON security_audit(account_id, created_at DESC)')


def _identity(username):
    return hashlib.sha256(username.encode('utf-8')).hexdigest()


def login_allowed(db, username, now=None):
    setup(db)
    now = int(time.time()) if now is None else int(now)
    row = db.execute('SELECT failures,started_at,locked_until FROM login_limits WHERE username_hash=?', (_identity(username),)).fetchone()
    if row is None:
        return True
    return row[2] <= now


def login_failure(db, username, now=None):
    setup(db)
    now = int(time.time()) if now is None else int(now)
    key = _identity(username)
    row = db.execute('SELECT failures,started_at,locked_until FROM login_limits WHERE username_hash=?', (key,)).fetchone()
    if row and now - row[1] < WINDOW and not (row[2] and row[2] <= now):
        failures = row[0] + 1
        started = row[1]
    else:
        failures = 1
        started = now
    locked = now + LOCK_DURATION if failures >= LIMIT else 0
    db.execute('INSERT INTO login_limits VALUES (?,?,?,?) ON CONFLICT(username_hash) DO UPDATE SET failures=excluded.failures,started_at=excluded.started_at,locked_until=excluded.locked_until', (key, failures, started, locked))
    db.commit()
    return locked > now


def login_success(db, username):
    db.execute('DELETE FROM login_limits WHERE username_hash=?', (_identity(username),))
    db.commit()


def audit(db, account_id, event, now=None):
    setup(db)
    allowed = {'account.register', 'account.login', 'account.login_failed', 'account.logout', 'file.upload', 'file.download', 'file.delete', 'file.upload_encrypted', 'file.upload_plain', 'file.decrypt', 'file.open_plain', 'record.create', 'record.reveal', 'record.delete'}
    if event not in allowed:
        raise ValueError('Unrecognized audit event')
    now = int(time.time()) if now is None else int(now)
    db.execute('INSERT INTO security_audit (account_id,event,created_at) VALUES (?,?,?)', (account_id, event, now))
    db.execute('DELETE FROM security_audit WHERE created_at<?', (now - 7 * 86400,))
