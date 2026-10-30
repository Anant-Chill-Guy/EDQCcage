import { useEffect, useState } from 'react'
import type { FormEvent } from 'react'
import { CheckCircle2, Cpu, Fingerprint, KeyRound, Lock, RefreshCcw, ShieldCheck, Usb } from 'lucide-react'

type DeviceInfo = { connected: boolean; port: string | null; description: string | null; vid: number | null; pid: number | null; protocol: string }
type Inspection = { connected: boolean; port: string; host_enrolled: boolean; device_enrolled: boolean; key_ready: boolean; device_id: string | null }
type Props = { device: DeviceInfo | null; deviceError: string; deviceBusy: boolean; onScan: () => Promise<void>; token: string }
const API = 'http://127.0.0.1:8765'

export default function DevicePanel({ device, deviceError, deviceBusy, onScan, token }: Props) {
  const [configured, setConfigured] = useState(false)
  const [unlocked, setUnlocked] = useState(false)
  const [remaining, setRemaining] = useState(0)
  const [inspection, setInspection] = useState<Inspection | null>(null)
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [current, setCurrent] = useState('')
  const [changing, setChanging] = useState(false)
  const [removing, setRemoving] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [message, setMessage] = useState('')
  const request = async (path: string, method = 'GET', body?: object) => {
    const response = await fetch(API + path, { method, headers: { Authorization: `Bearer ${token}`, ...(body ? { 'Content-Type': 'application/json' } : {}) }, ...(body ? { body: JSON.stringify(body) } : {}), cache: 'no-store', signal: AbortSignal.timeout(20000) })
    const data = await response.json()
    if (!response.ok) throw Error(data.detail || `Request failed (${response.status})`)
    return data
  }
  const refresh = async () => {
    if (!token) return
    try {
      const status = await request('/api/vault/hardware/status')
      setConfigured(Boolean(status.configured))
      setUnlocked(Boolean(status.unlocked && device?.connected))
      setRemaining(Number(status.seconds_left) || 0)
    } catch { setUnlocked(false) }
  }
  useEffect(() => {
    if (!device?.connected) { setUnlocked(false); setRemaining(0); setInspection(null) }
    if (device?.connected) {
      void fetch(API + '/api/device/inspect').then(async r => { if (r.ok) setInspection(await r.json() as Inspection) }).catch(() => setInspection(null))
    }
  }, [device?.connected])
  useEffect(() => { void refresh(); const timer = window.setInterval(() => void refresh(), 15000); return () => window.clearInterval(timer) }, [token, device?.connected])
  useEffect(() => {
    const ticker = window.setInterval(() => setRemaining(value => Math.max(0, value - 1)), 1000)
    return () => window.clearInterval(ticker)
  }, [])
  const countdown = `${String(Math.floor(remaining / 60)).padStart(2, '0')}:${String(remaining % 60).padStart(2, '0')}`

  const perform = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    setError(''); setMessage(''); setBusy(true)
    try {
      if (!configured && password !== confirm) throw Error('Hardware passwords do not match')
      if (changing && password !== confirm) throw Error('New hardware passwords do not match')
      if (changing) {
        await request('/api/vault/hardware/change', 'POST', {current_password: current, new_password: password})
        setChanging(false); setUnlocked(false); setMessage('Hardware password changed. Authenticate again.')
      } else if (!configured) {
        await request('/api/vault/hardware/password', 'POST', { password })
        setConfigured(true); setMessage('Hardware password created. Enter it again to authorize your Pico.')
      } else {
        await request('/api/vault/hardware/unlock', 'POST', { password })
        setUnlocked(true); setRemaining(900); setMessage('Hardware authorization successful.')
      }
      setPassword(''); setConfirm(''); setCurrent('')
      await refresh()
    } catch (reason) { setError(reason instanceof Error ? reason.message : 'Device authentication failed') }
    finally { setBusy(false) }
  }
  const deletePassword = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (!window.confirm('Remove hardware password? Protected operations will lock until you create and authenticate a new one.')) return
    setBusy(true); setError(''); setMessage('')
    try {
      await request('/api/vault/hardware/delete', 'POST', {current_password: current})
      setConfigured(false); setUnlocked(false); setRemaining(0); setRemoving(false)
      setCurrent(''); setPassword(''); setConfirm('')
      setMessage('Hardware password removed. Set a new password to authorize the Pico.')
    } catch (reason) { setError(reason instanceof Error ? reason.message : 'Unable to remove hardware password') }
    finally { setBusy(false) }
  }
  const lockNow = async () => {
    setBusy(true); setError('')
    try { await request('/api/vault/hardware/lock', 'POST'); setUnlocked(false); setRemaining(0); setMessage('Hardware authorization cleared') }
    catch (reason) { setError(reason instanceof Error ? reason.message : 'Unable to lock device') }
    finally { setBusy(false) }
  }
  return <div className="edqc-device-layout">
    <section className="panel edqc-device-identity">
      <div className="edqc-device-topline"><span className="edqc-device-label"><Usb size={17}/> USB DEVICE</span><span className={`edqc-device-state ${device?.connected ? 'connected' : ''}`}>{device?.connected ? 'Connected' : 'Disconnected'}</span></div>
      <div className="edqc-device-mark"><Cpu size={44} strokeWidth={1.5}/></div>
      <h2>Raspberry Pi Pico</h2><p>RP2040 · MicroPython</p>
      <div className="edqc-device-facts"><div><span>USB port</span><strong>{device?.port || '—'}</strong></div><div><span>Interface</span><strong>USB serial (CDC)</strong></div><div><span>Hardware identity</span><strong>{device?.connected ? 'RP2040' : 'Not detected'}</strong></div></div>
      <button className="button secondary edqc-wide" disabled={deviceBusy || busy} onClick={() => { setUnlocked(false); void onScan() }}><RefreshCcw size={16}/>{deviceBusy ? 'Scanning…' : 'Refresh connection'}</button>
      {deviceError && <p className="edqc-device-error">{deviceError}</p>}
    </section>
    <section className="panel edqc-device-operations">
      <div className="panel-title"><div><h3>Hardware authorization</h3></div></div>
      <div className={`edqc-device-verification ${unlocked ? 'edqc-authorized' : ''}`}><span>{unlocked ? <CheckCircle2 size={23}/> : <Lock size={23}/>}</span><div><strong>{unlocked ? 'Pico authorized' : 'Protected operations locked'}</strong><p>{unlocked ? `Session expires in ${countdown}` : 'Enter the hardware password and authenticate the enrolled device'}</p></div></div>
      {!removing && <form className="edqc-device-auth-form" onSubmit={e => void perform(e)}>
        <label>{changing ? 'New hardware password' : configured ? 'Hardware password' : 'Create a hardware password'}<input type="password" minLength={changing || !configured ? 12 : 1} maxLength={256} autoComplete="off" value={password} onChange={e => setPassword(e.target.value)} required/></label>
        {changing && <label>Current hardware password<input type="password" autoComplete="off" value={current} onChange={e => setCurrent(e.target.value)} required/></label>}
        {(!configured || changing) && <label>Confirm new password<input type="password" minLength={12} maxLength={256} autoComplete="off" value={confirm} onChange={e => setConfirm(e.target.value)} required/></label>}
        <button className="button primary edqc-wide" type="submit" disabled={!device?.connected || busy || !token}><Fingerprint size={17}/>{busy ? 'Verifying…' : changing ? 'Change hardware password' : configured ? 'Authenticate Pico & unlock' : 'Set hardware password'}</button>
      </form>}
      {removing && <form className="edqc-device-auth-form" onSubmit={e => void deletePassword(e)}><label>Current hardware password<input type="password" value={current} onChange={e => setCurrent(e.target.value)} autoComplete="off" required/></label><button type="submit" className="button danger edqc-wide" disabled={busy || !device?.connected}>Remove hardware password</button></form>}
      <div className="edqc-device-secondary-actions">
        {configured && !removing && <button className="button secondary" type="button" onClick={() => {setChanging(v => !v);setPassword('');setCurrent('');setConfirm('');setError('')}} disabled={busy}>{changing ? 'Cancel password change' : 'Change hardware password'}</button>}
        {configured && <button className="button secondary" type="button" onClick={() => {setRemoving(v => !v);setChanging(false);setPassword('');setCurrent('');setConfirm('');setError('')}} disabled={busy}>{removing ? 'Cancel removal' : 'Remove hardware password'}</button>}
        {unlocked && <button className="button secondary" type="button" onClick={() => void lockNow()} disabled={busy}>Lock device access</button>}
      </div>
      {message && <p className="edqc-device-muted"><ShieldCheck size={16}/>{message}</p>}
      {error && <p className="edqc-device-error" role="alert">{error}</p>}
      <div className="edqc-hardware-details"><div className="edqc-hardware-details-title"><Cpu size={18}/><h3>Device information</h3></div><div className="edqc-hardware-details-grid">
        <div><small>Board</small><strong>Raspberry Pi Pico (RP2040)</strong></div>
        <div><small>Firmware</small><strong>MicroPython</strong></div>
        <div><small>USB port</small><strong>{device?.port || '—'}</strong></div>
        <div><small>Device enrollment</small><strong>{inspection ? inspection.device_enrolled ? 'Present' : 'Missing' : '—'}</strong></div>
        <div><small>Protected key</small><strong>{inspection ? inspection.key_ready ? 'Ready' : 'Unavailable' : '—'}</strong></div>
        <div><small>Authentication</small><strong>HMAC-SHA256 challenge-response</strong></div>
        <div><small>Account authorization</small><strong>{unlocked ? 'Unlocked' : 'Locked'}</strong></div>
      </div><p className="edqc-hardware-note">The RP2040 uses MicroPython flash storage; it is not a tamper-resistant secure element.</p></div>
    </section>
  </div>
}
