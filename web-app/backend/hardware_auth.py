import hashlib
import hmac
import json
import os
import re
import secrets
import subprocess
import sys
from pathlib import Path
from serial.tools import list_ports

STORE = Path(__file__).resolve().parent / '.device_enrollment.json'
PREFIX = b'PicoVault/v1/auth/'

def get_port():
    devices = [port.device for port in list_ports.comports() if port.vid == 0x2E8A and port.pid == 0x0005]
    if not devices:
        raise RuntimeError('No Device Detected')
    if len(devices) != 1:
        raise RuntimeError('Connect exactly one MicroPython Pico to enroll or authenticate')
    return devices[0]

def run_device(port, statement):
    try:
        proc = subprocess.run(
            [sys.executable, '-m', 'mpremote', 'connect', port, 'exec', statement],
            capture_output=True, text=True, timeout=18, check=False
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(f'Device communication failed: {exc}') from exc
    if proc.returncode:
        raise RuntimeError('Could not communicate with Pico. Check serial permissions and MicroPython firmware.')
    return proc.stdout

def marker(output, label):
    result = re.search(r'(?:^|\n)' + re.escape(label) + r'([0-9a-f]{64})(?:\r?\n|$)', output)
    if not result:
        raise RuntimeError('Device did not return the expected response. Confirm pico_auth.py is installed.')
    return result.group(1)

def enroll_device():
    if STORE.exists():
        raise RuntimeError('A device is already enrolled. Re-enrollment requires an explicit reset procedure.')
    port = get_port()
    result = run_device(port, 'import pico_auth; pico_auth.enroll()')
    if 'PV_ERROR:already_enrolled' in result:
        raise RuntimeError('Pico already enrolled. Enrollment data is absent on host; do not overwrite secrets blindly.')
    secret_hex = marker(result, 'PV_ENROLL:')
    data = {'version': 1, 'secret': secret_hex, 'device': 'rp2040-micropython'}
    fd = os.open(STORE, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(data, stream)
    return {'enrolled': True, 'port': port, 'message': 'Device enrollment completed'}

def status():
    try:
        port = get_port()
    except RuntimeError:
        port = None
    return {'connected': bool(port), 'port': port, 'enrolled_on_host': STORE.exists(), 'authenticated': False}

def authenticate_device():
    if not STORE.exists():
        raise RuntimeError('Enroll the Pico first')
    port = get_port()
    with STORE.open() as stream:
        record = json.load(stream)
    challenge = secrets.token_bytes(32)
    output = run_device(port, "import pico_auth; pico_auth.respond('" + challenge.hex() + "')")
    returned_hex = marker(output, 'PV_RESPONSE:')
    expected = hmac.new(bytes.fromhex(record['secret']), PREFIX + challenge, hashlib.sha256).digest()
    authenticated = hmac.compare_digest(bytes.fromhex(returned_hex), expected)
    return {'authenticated': authenticated, 'port': port, 'method': 'HMAC-SHA256 challenge-response', 'nonce_bytes': 32}
