import os
import hashlib
import binascii

SECRET_FILE = 'pv_secret.bin'

def _hex(value):
    return binascii.hexlify(value).decode()

def _unhex(value):
    return binascii.unhexlify(value)

def _hmac(key, msg):
    if len(key) > 64:
        key = hashlib.sha256(key).digest()
    key = key + b'\x00' * (64 - len(key))
    outer = bytes((b ^ 0x5c) for b in key)
    inner = bytes((b ^ 0x36) for b in key)
    return hashlib.sha256(outer + hashlib.sha256(inner + msg).digest()).digest()

def enrolled():
    try:
        with open(SECRET_FILE, 'rb') as handle:
            return len(handle.read()) == 32
    except OSError:
        return False

def enroll():
    if enrolled():
        print('PV_ERROR:already_enrolled')
        return
    secret = os.urandom(32)
    with open(SECRET_FILE, 'wb') as handle:
        handle.write(secret)
    print('PV_ENROLL:' + _hex(secret))

def respond(challenge_hex):
    if len(challenge_hex) != 64:
        print('PV_ERROR:invalid_challenge')
        return
    try:
        challenge = _unhex(challenge_hex)
        with open(SECRET_FILE, 'rb') as handle:
            secret = handle.read()
        if len(secret) != 32:
            raise ValueError('invalid device secret')
        print('PV_RESPONSE:' + _hex(_hmac(secret, b'PicoVault/v1/auth/' + challenge)))
    except (OSError, ValueError):
        print('PV_ERROR:not_enrolled')
