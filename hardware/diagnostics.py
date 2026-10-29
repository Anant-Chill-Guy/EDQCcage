import subprocess
import sys
from serial.tools import list_ports

ports = [port for port in list_ports.comports() if port.vid == 0x2E8A]
if not ports:
    raise SystemExit("No Raspberry Pi USB device detected")
for port in ports:
    print(f"USB: {port.device} VID={port.vid:04x} PID={port.pid:04x} {port.description}")
    if port.device.startswith("/dev/tty"):
        code = "import sys,machine,os;print('PV_DIAG',sys.platform,machine.freq(),os.statvfs('/')[3])"
        result = subprocess.run([sys.executable, "-m", "mpremote", "connect", port.device, "exec", code], capture_output=True, text=True, timeout=12)
        print(result.stdout if result.returncode == 0 else result.stderr)
        if result.returncode:
            raise SystemExit(result.returncode)
