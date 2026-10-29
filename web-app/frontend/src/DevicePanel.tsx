import { useEffect, useState } from 'react'
import { Activity, CheckCircle2, Cpu, Fingerprint, KeyRound, RefreshCcw, ShieldAlert, Usb, XCircle } from 'lucide-react'

type DeviceInfo = { connected: boolean; port: string | null; description: string | null; vid: number | null; pid: number | null; protocol: string }
type Inspection = { connected: boolean; port: string; host_enrolled: boolean; device_enrolled: boolean; key_ready: boolean; device_id: string | null }
type Props = { device: DeviceInfo | null; deviceError: string; deviceBusy: boolean; onScan: () => Promise<void> }
const API = 'http://127.0.0.1:8765/api/device'

export default function DevicePanel({ device, deviceError, deviceBusy, onScan }: Props) {
  const [inspection, setInspection] = useState<Inspection | null>(null)
  const [verified, setVerified] = useState(false)
  const [testResult, setTestResult] = useState<boolean | null>(null)
  const [working, setWorking] = useState('')
  const [error, setError] = useState('')
  const [lastCheck, setLastCheck] = useState('Not checked')
  useEffect(() => { if (!device?.connected) { setInspection(null); setVerified(false); setTestResult(null) } }, [device?.connected])

  const execute = async (operation: 'inspect' | 'authenticate' | 'self-test') => {
    setWorking(operation)
    setError('')
    try {
      const response = await fetch(`${API}/${operation}`, {method: operation === 'inspect' ? 'GET' : 'POST', signal: AbortSignal.timeout(20000)})
      const data = await response.json()
      if (!response.ok) throw Error(data.detail || 'The device operation failed')
      if (operation === 'inspect') setInspection(data as Inspection)
      if (operation === 'authenticate') {
        setVerified(Boolean(data.authenticated))
        if (!data.authenticated) throw Error('The connected Pico does not match the enrolled device')
      }
      if (operation === 'self-test') setTestResult(Boolean(data.pass))
      setLastCheck(new Date().toLocaleTimeString())
    } catch (reason) {
      if (operation === 'authenticate') setVerified(false)
      if (operation === 'self-test') setTestResult(false)
      setError(reason instanceof Error ? reason.message : 'Hardware operation failed')
    } finally { setWorking('') }
  }

  return <div className="edqc-device-layout">
    <section className="panel edqc-device-identity">
      <div className="edqc-device-topline"><span className="edqc-device-label"><Usb size={17}/> CONNECTED DEVICE</span><span className={`edqc-device-state ${device?.connected ? 'connected' : ''}`}>{device?.connected ? 'USB connected' : 'Not connected'}</span></div>
      <div className="edqc-device-mark"><Cpu size={44} strokeWidth={1.5}/></div>
      <h2>{device?.connected ? 'Raspberry Pi Pico' : 'Connect your Pico'}</h2>
      <p>{device?.connected ? 'MicroPython USB serial interface' : 'Connect your enrolled RP2040 device to enable protected vault operations.'}</p>
      <div className="edqc-device-facts"><div><span>Interface</span><strong>{device?.port || '—'}</strong></div><div><span>Board</span><strong>{device?.connected ? 'RP2040' : '—'}</strong></div><div><span>Last check</span><strong>{lastCheck}</strong></div></div>
      <button className="button secondary edqc-wide" disabled={deviceBusy || !!working} onClick={() => { setVerified(false); void onScan() }}><RefreshCcw size={16}/>{deviceBusy ? 'Scanning…' : 'Refresh connection'}</button>
      {deviceError && <p className="edqc-device-error">{deviceError}</p>}
    </section>
    <section className="panel edqc-device-operations">
      <div className="panel-title"><div><h3>Security controls</h3><p>Run operations on the physically connected device</p></div><Fingerprint size={20}/></div>
      <div className="edqc-device-verification"><span className={`edqc-device-indicator ${verified ? 'verified' : ''}`}>{verified ? <CheckCircle2 size={18}/> : <ShieldAlert size={18}/>}</span><div><strong>{verified ? 'Enrolled device verified' : 'Verification required'}</strong><p>{verified ? 'Fresh HMAC challenge-response completed' : 'USB connection alone does not establish device identity'}</p></div></div>
      <div className="edqc-device-actions">
        <button disabled={!device?.connected || !!working} className="edqc-device-action" onClick={() => void execute('authenticate')}><Fingerprint size={20}/><strong>01 · Authenticate</strong><small>Verify the enrolled Pico</small></button>
        <button disabled={!device?.connected || !!working} className="edqc-device-action" onClick={() => void execute('inspect')}><KeyRound size={20}/><strong>02 · Key status</strong><small>Read enrollment and key readiness</small></button>
        <button disabled={!device?.connected || !!working} className="edqc-device-action" onClick={() => void execute('self-test')}><Activity size={20}/><strong>03 · Self-check</strong><small>Verify firmware crypto routine and Pico auth</small></button>
      </div>
      {working && <p className="edqc-device-muted" role="status">Communicating with Pico…</p>}
      {error && <p className="edqc-device-error" role="alert"><XCircle size={15}/>{error}</p>}
      <div className="edqc-device-readout">
        <div className="edqc-device-readout-head"><strong>Device diagnostics</strong><span>LIVE STATUS</span></div>
        <div><span>Host enrollment</span><strong>{inspection ? (inspection.host_enrolled ? 'Present' : 'Missing') : 'Run key status'}</strong></div>
        <div><span>Pico enrollment</span><strong>{inspection ? (inspection.device_enrolled ? 'Present' : 'Not enrolled') : '—'}</strong></div>
        <div><span>Protected key</span><strong>{inspection ? (inspection.key_ready ? 'Ready' : 'Unavailable') : '—'}</strong></div>
        <div><span>Device ID</span><strong className="edqc-mono">{inspection?.device_id || '—'}</strong></div>
        <div><span>Self-check</span><strong>{testResult === null ? 'Not run' : testResult ? 'Passed' : 'Failed'}</strong></div>
      </div>
    </section>
  </div>
}
