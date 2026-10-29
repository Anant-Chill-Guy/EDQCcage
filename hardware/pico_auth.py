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

DEVICE_KEY_FILE = 'pv_keyshare.bin'
KEY_DOMAIN = b'PicoVault/v3/physical-key/'


def _device_key():
    try:
        with open(DEVICE_KEY_FILE, 'rb') as handle:
            secret = handle.read()
    except OSError:
        raise ValueError('device_key_not_provisioned')
    if len(secret) != 32:
        raise ValueError('device_key_invalid')
    return secret


def provision(seed_hex):
    try:
        existing = _device_key()
        print('PV_DEVICE_ID:' + _hex(hashlib.sha256(KEY_DOMAIN + existing).digest()))
        return
    except ValueError as exc:
        if str(exc) != 'device_key_not_provisioned':
            raise
    if len(seed_hex) != 64:
        raise ValueError('invalid_seed')
    seed = _unhex(seed_hex)
    secret = hashlib.sha256(KEY_DOMAIN + os.urandom(32) + seed).digest()
    with open(DEVICE_KEY_FILE, 'wb') as handle:
        handle.write(secret)
    print('PV_DEVICE_ID:' + _hex(hashlib.sha256(KEY_DOMAIN + secret).digest()))


def key_identify():
    secret = _device_key()
    print('PV_DEVICE_ID:' + _hex(hashlib.sha256(KEY_DOMAIN + secret).digest()))


def key_derive(account_hex):
    if len(account_hex) != 32:
        raise ValueError('invalid_account_id')
    account = _unhex(account_hex)
    if len(account) != 16:
        raise ValueError('invalid_account_id')
    print('PV_FACTOR:' + _hex(_hmac(_device_key(), KEY_DOMAIN + b'account/' + account)))


def menu():
    print('PV_MENU:1 DEVICE STATUS')
    print('PV_MENU:2 AUTHENTICATE')
    print('PV_MENU:3 KEY STATUS')
    print('PV_MENU:4 SELF TEST')
    print('PV_MENU:5 EXIT')

def device_status():
    print('PV_STATUS:ENROLLED' if enrolled() else 'PV_STATUS:UNENROLLED')
    try:
        key_identify()
        print('PV_STATUS:KEY_READY')
    except ValueError:
        print('PV_STATUS:KEY_MISSING')

def self_test():
    try:
        known = _hmac(b'\x0b' * 20, b'Hi There')
        result = enrolled() and len(_device_key()) == 32 and _hex(known) == 'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7'
    except (OSError, ValueError):
        result = False
    print('PV_SELFTEST:PASS' if result else 'PV_SELFTEST:FAIL')
