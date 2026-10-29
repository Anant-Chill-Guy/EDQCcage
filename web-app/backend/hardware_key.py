import secrets
import threading

from hardware_auth import authenticate_device, get_port, marker, run_device

DEVICE_LOCK = threading.RLock()


def _verified_port():
    result = authenticate_device()
    if not result.get('authenticated'):
        raise RuntimeError('Device authentication failed')
    return get_port()


def provision():
    with DEVICE_LOCK:
        port = _verified_port()
        command = "import pico_auth; pico_auth.provision('" + secrets.token_hex(32) + "')"
        output = run_device(port, command)
        return {'port': port, 'device_id': marker(output, 'PV_DEVICE_ID:')}


def factor(account_id):
    if len(account_id) != 32 or any(c not in '0123456789abcdef' for c in account_id):
        raise ValueError('Invalid account identifier')
    with DEVICE_LOCK:
        port = _verified_port()
        command = "import pico_auth; pico_auth.key_identify(); pico_auth.key_derive('" + account_id + "')"
        output = run_device(port, command)
        return marker(output, 'PV_DEVICE_ID:'), bytes.fromhex(marker(output, 'PV_FACTOR:'))
