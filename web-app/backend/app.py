from vault_api import router as vault_router
from hardware_auth import authenticate_device, enroll_device, status
from fastapi import HTTPException
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from serial.tools import list_ports

app = FastAPI(title="PicoVault Hardware Service", docs_url=None, redoc_url=None)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:5173", "http://localhost:5173"],
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Content-Type", "Authorization"],
)

@app.get("/api/health")
def health():
    return {"service": "picovault-hardware", "status": "running", "mode": "local development"}

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
    if origin and origin not in ('http://127.0.0.1:5173', 'http://localhost:5173'):
        return JSONResponse({'detail': 'Untrusted origin'}, status_code=403)
    response = await call_next(request)
    response.headers['Cache-Control'] = 'no-store'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['X-Frame-Options'] = 'DENY'
    return response
