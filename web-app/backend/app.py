from vault_api import router as vault_router
from hardware_auth import authenticate_device, enroll_device, status
from fastapi import HTTPException
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from serial.tools import list_ports

app = FastAPI(title="EDQCcage Hardware Service", docs_url=None, redoc_url=None)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:5173", "http://localhost:5173"],
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Content-Type", "Authorization"],
)

@app.get("/api/health")
def health():
    return {"service": "edqccage-hardware", "status": "running", "mode": "local development"}

@app.get("/api/device")
def device():
    ports = list(list_ports.comports())
    matches = [p for p in ports if p.vid == 0x2E8A and p.pid in (0x0005, 0x000A, 0x0003)]
    serial_ports = [p for p in matches if p.device.startswith("/dev/tty")]
    selected = serial_ports[0] if serial_ports else None
    return {
        "connected": selected is not None,
        "port": selected.device if selected else None,
        "description": selected.description if selected else None,
        "vid": selected.vid if selected else None,
        "pid": selected.pid if selected else None,
        "protocol": "HMAC-SHA256 challenge-response via /api/device/authenticate",
    }

@app.get('/api/device/auth-status')
def device_auth_status():
    return status()

@app.post('/api/device/enroll')
def device_enroll():
    try:
        return enroll_device()
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

@app.post('/api/device/authenticate')
def device_authenticate():
    try:
        return authenticate_device()
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc



@app.post('/api/device/setup')
def device_setup():
    from hardware_auth import STORE
    from hardware_key import provision
    try:
        if not STORE.exists():
            enroll_device()
        result = authenticate_device()
        if not result.get('authenticated'):
            raise RuntimeError('Wrong USB device')
        device_info = provision()
        return {'enrolled': True, 'device_id': device_info['device_id']}
    except (OSError, RuntimeError, ValueError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

@app.get('/api/device/inspect')
def device_inspect():
    from hardware_auth import STORE, get_port, run_device
    try:
        port = get_port()
        output = run_device(port, 'import pico_auth; pico_auth.device_status()')
        states = {line.strip() for line in output.splitlines() if line.startswith('PV_STATUS:')}
        identities = [line.split(':', 1)[1].strip() for line in output.splitlines() if line.startswith('PV_DEVICE_ID:')]
        return {
            'connected': True,
            'port': port,
            'host_enrolled': STORE.exists(),
            'device_enrolled': 'PV_STATUS:ENROLLED' in states,
            'key_ready': 'PV_STATUS:KEY_READY' in states,
            'device_id': identities[0][:16] if identities else None,
        }
    except (OSError, RuntimeError, ValueError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

@app.post('/api/device/self-test')
def device_selftest():
    from hardware_auth import get_port, run_device
    try:
        output = run_device(get_port(), 'import pico_auth; pico_auth.self_test()')
        authenticated = authenticate_device().get('authenticated', False)
        return {'pass': 'PV_SELFTEST:PASS' in output and authenticated, 'device_authenticated': authenticated}
    except (OSError, RuntimeError, ValueError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

from records_api import router as records_router
app.include_router(records_router)
app.include_router(vault_router)
from audit_api import router as audit_router
app.include_router(audit_router)

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.trustedhost import TrustedHostMiddleware

app.add_middleware(TrustedHostMiddleware, allowed_hosts=['127.0.0.1', 'localhost'])


@app.middleware('http')
async def protect_local_requests(request: Request, call_next):
    origin = request.headers.get('origin')
    if origin and origin not in ('http://127.0.0.1:5173', 'http://localhost:5173', 'http://127.0.0.1:8765', 'http://localhost:8765'):
        return JSONResponse({'detail': 'Untrusted origin'}, status_code=403)
    response = await call_next(request)
    response.headers['Cache-Control'] = 'no-store'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['X-Frame-Options'] = 'DENY'
    return response

from pathlib import Path
from fastapi.staticfiles import StaticFiles

FRONTEND_DIST = Path(__file__).resolve().parent.parent / 'frontend' / 'dist'
if FRONTEND_DIST.is_dir():
    app.mount('/', StaticFiles(directory=str(FRONTEND_DIST), html=True), name='edqccage-ui')
