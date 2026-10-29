from hardware_auth import authenticate_device, enroll_device, status
from fastapi import HTTPException
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from serial.tools import list_ports

app = FastAPI(title="PicoVault Hardware Service", docs_url=None, redoc_url=None)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:5173", "http://localhost:5173"],
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)

@app.get("/api/health")
def health():
    return {"service": "picovault-hardware", "status": "running", "mode": "read-only"}

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
        "protocol": "USB enumeration only; device authentication not implemented",
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
