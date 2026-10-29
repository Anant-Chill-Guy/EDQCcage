import { useEffect, useMemo, useRef, useState } from 'react'
import type { ChangeEvent, FormEvent, ReactNode } from 'react'
import { Activity, ArrowDownLeft, ArrowDownToLine, ArrowLeft, ArrowRight, ArrowUpRight, Bell, BookOpen, Check, CheckCheck, ChevronDown, ChevronLeft, ChevronRight, ChevronUp, CircleHelp, Clock3, CloudOff, Command, Copy, Cpu, Download, Ellipsis, Eye, EyeOff, FileArchive, FileCode2, FileImage, FileKey2, FileLock2, FilePlus2, FileText, Fingerprint, FolderClosed, FolderPlus, HardDrive, HardDriveDownload, History, House, Info, KeyRound, LayoutGrid, Link2, List, Lock, LockKeyhole, Menu, MoreHorizontal, Plus, Search, Settings2, Shield, ShieldAlert, ShieldCheck, ShieldOff, SlidersHorizontal, Sparkles, Trash2, UploadCloud, Usb, Users, Vault, WifiOff, X } from 'lucide-react'

type DeviceReport = { connected: boolean; port: string | null; description: string | null; vid: number | null; pid: number | null; protocol: string }
type Page = 'Overview' | 'My vault' | 'USB device' | 'Passwords' | 'Activity' | 'Settings'
type Kind = 'pdf' | 'image' | 'archive' | 'code' | 'text' | 'key'
type VaultFile = { id: string; name: string; kind: Kind; size: string; modified: string; tag: string; local?: boolean }
type Event = { id: number; title: string; desc: string; time: string; icon: 'success' | 'warning' | 'neutral' }
const initialFiles: VaultFile[] = [
  { id: '1', name: 'Acquisition agreement.pdf', kind: 'pdf', size: '2.4 MB', modified: 'Today, 10:42 AM', tag: 'Legal' },
  { id: '2', name: 'Financial model Q4.xlsx', kind: 'archive', size: '8.1 MB', modified: 'Yesterday', tag: 'Finance' },
  { id: '3', name: 'Identity documents.zip', kind: 'archive', size: '14.7 MB', modified: 'Oct 26, 2026', tag: 'Personal' },
  { id: '4', name: 'Infrastructure credentials.txt', kind: 'key', size: '4 KB', modified: 'Oct 24, 2026', tag: 'Credentials' },
  { id: '5', name: 'Prototype drawings.png', kind: 'image', size: '6.8 MB', modified: 'Oct 21, 2026', tag: 'Research' },
  { id: '6', name: 'Project notes.md', kind: 'text', size: '72 KB', modified: 'Oct 19, 2026', tag: 'Personal' }
]
const initialEvents: Event[] = [
  { id: 1, title: 'Workspace opened', desc: 'Local demo session', time: 'Just now', icon: 'success' },
  { id: 2, title: 'Device not connected', desc: 'Waiting for a hardware integration', time: 'Today', icon: 'warning' },
  { id: 3, title: 'Demo data loaded', desc: 'Sample records for UI preview', time: 'Today', icon: 'neutral' }
]
const navigation: { title: string; items: { page: Page; icon: typeof House }[] }[] = [
  { title: 'WORKSPACE', items: [{ page: 'Overview', icon: House }, { page: 'My vault', icon: FolderClosed }, { page: 'Passwords', icon: KeyRound }] },
  { title: 'SECURITY', items: [{ page: 'USB device', icon: Usb }, { page: 'Activity', icon: History }, { page: 'Settings', icon: Settings2 }] }
]
const iconFor = (kind: Kind) => ({ pdf: FileText, image: FileImage, archive: FileArchive, code: FileCode2, text: FileText, key: FileKey2 })[kind]
const iconClass = (kind: Kind) => ({ pdf: 'rose', image: 'indigo', archive: 'amber', code: 'indigo', text: 'sky', key: 'mint' })[kind]
const headings: Record<Page, { eyebrow: string; title: string; subtitle: string }> = {
  Overview: { eyebrow: '', title: 'Welcome to PicoVault.', subtitle: '' },
  'My vault': { eyebrow: '', title: 'Private Vault', subtitle: '' },
  'USB device': { eyebrow: '', title: 'Hardware Device', subtitle: 'Status' },
  Passwords: { eyebrow: '', title: 'Credentials & Notes', subtitle: '' },
  Activity: { eyebrow: '', title: 'History', subtitle: '' },
  Settings: { eyebrow: '', title: 'Settings', subtitle: '' }
}
type StoredFile = { id: string; name: string; size: number; created_at: number; key_protection: string }
const VAULT_API = 'http://127.0.0.1:8765/api/vault'

async function vaultRequest(path: string, init: RequestInit = {}, token?: string) {
  const headers = new Headers(init.headers)
  if (token) headers.set('Authorization', `Bearer ${token}`)
  const response = await fetch(VAULT_API + path, { ...init, headers })
  const type = response.headers.get('content-type') || ''
  const data = type.includes('application/json') ? await response.json() : null
  if (!response.ok) throw new Error(data?.detail || `Request failed (${response.status})`)
  return data
}

function toVaultFile(f: StoredFile): VaultFile {
  const name = f.name
  const kind: Kind = /\.pdf$/i.test(name) ? 'pdf' : /\.(png|jpg|jpeg|webp)$/i.test(name) ? 'image' : /\.(zip|xlsx|docx)$/i.test(name) ? 'archive' : /\.(key|pem)$/i.test(name) ? 'key' : 'text'
  const size = f.size >= 1048576 ? `${(f.size / 1048576).toFixed(1)} MB` : `${Math.max(1, Math.ceil(f.size / 1024))} KB`
  return { id: f.id, name, kind, size, modified: new Date(f.created_at * 1000).toLocaleString(), tag: f.key_protection }
}

function App() {
  const [device, setDevice] = useState<DeviceReport | null>(null)
  const [deviceError, setDeviceError] = useState('')
  const [deviceBusy, setDeviceBusy] = useState(false)
  const scanDevice = async () => {
    setDeviceBusy(true)
    setDeviceError('')
    try {
      const response = await fetch('http://127.0.0.1:8765/api/device', { signal: AbortSignal.timeout(5000) })
      if (!response.ok) throw new Error('Hardware service unavailable')
      setDevice(await response.json() as DeviceReport)
    } catch {
      setDevice(null)
      setDeviceError('Start the PicoVault hardware service to detect your board.')
    } finally {
      setDeviceBusy(false)
    }
  }
  useEffect(() => { void scanDevice(); const timer = window.setInterval(() => void scanDevice(), 10000); return () => window.clearInterval(timer) }, [])
  const [page, setPage] = useState<Page>('Overview')
  const [files, setFiles] = useState<VaultFile[]>([])
  const [events, setEvents] = useState<Event[]>([])
  const [search, setSearch] = useState('')
  const [view, setView] = useState<'list' | 'grid'>('list')
  const [filter, setFilter] = useState('All files')
  const [modal, setModal] = useState<'import' | 'device' | 'info' | null>(null)
  const [selected, setSelected] = useState<VaultFile | null>(null)
  const [toast, setToast] = useState('')
  const [sidebar, setSidebar] = useState(false)
  const [notifications, setNotifications] = useState(false)
  const [compact, setCompact] = useState(false)
  const [noteVisible, setNoteVisible] = useState(false)
  const [theme, setTheme] = useState<'light' | 'dark'>(() => localStorage.getItem('pv-theme') === 'dark' ? 'dark' : 'light')
  const [shortcut, setShortcut] = useState(() => localStorage.getItem('pv-shortcut') || 'k')
  const [retention, setRetention] = useState(() => localStorage.getItem('pv-retention') || '7')
  const [accountName, setAccountName] = useState('')
  const [vaultToken, setVaultToken] = useState('')
  const [accountPassword, setAccountPassword] = useState('')
  const [accountMode, setAccountMode] = useState<'login' | 'register'>('login')
  const [accountBusy, setAccountBusy] = useState(false)
  const [accountError, setAccountError] = useState('')
  const [accountDraft, setAccountDraft] = useState('')
  const [accountOpen, setAccountOpen] = useState(false)
  useEffect(() => { localStorage.setItem('pv-theme', theme) }, [theme])
  useEffect(() => { localStorage.setItem('pv-shortcut', shortcut) }, [shortcut])
  useEffect(() => { localStorage.setItem('pv-retention', retention) }, [retention])

  const [sampleNotes, setSampleNotes] = useState<string[]>([])
  const [newNote, setNewNote] = useState('')
  const inputRef = useRef<HTMLInputElement>(null)
  const showToast = (message: string) => { setToast(message); window.setTimeout(() => setToast(''), 3500) }
  const logEvent = (title: string, desc: string, icon: Event['icon'] = 'neutral') => setEvents(p => [{ id: Date.now(), title, desc, time: 'Just now', icon }, ...p])
  const navigate = (destination: Page) => { setPage(destination); setSidebar(false); setSearch(''); setFilter('All files') }
  useEffect(() => { const handler = (e: KeyboardEvent) => { if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === shortcut.toLowerCase()) { e.preventDefault(); document.getElementById('global-search')?.focus() } }; window.addEventListener('keydown', handler); return () => window.removeEventListener('keydown', handler) }, [shortcut])
  const visibleFiles = useMemo(() => files.filter(f => `${f.name} ${f.tag}`.toLowerCase().includes(search.toLowerCase())), [files, search, filter])
  const refreshFiles = async (token: string) => {
    const data = await vaultRequest('/files', {}, token) as { files: StoredFile[] }
    setFiles(data.files.map(toVaultFile))
  }
  const submitAccount = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault()
    const username = accountDraft.trim()
    if (!username || !accountPassword) return
    setAccountBusy(true)
    setAccountError('')
    try {
      const body = JSON.stringify({ username, password: accountPassword })
      if (accountMode === 'register') await vaultRequest('/register', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body })
      const result = await vaultRequest('/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body }) as { access_token: string }
      await refreshFiles(result.access_token)
      setVaultToken(result.access_token)
      setAccountName(username)
      setAccountPassword('')
      setAccountOpen(false)
      logEvent('Secure sign-in', `${username} authenticated with Pico`, 'success')
      showToast('Signed in · hardware authentication verified')
    } catch (error) {
      setAccountError(error instanceof Error ? error.message : 'Authentication failed')
    } finally {
      setAccountBusy(false)
    }
  }
  const logoutAccount = async () => {
    try { await vaultRequest('/logout', { method: 'POST' }, vaultToken) } catch { }
    setVaultToken('')
    setAccountName('')
    setFiles([])
    setSelected(null)
    setAccountOpen(false)
    showToast('Signed out')
  }
  const downloadVaultFile = async (file: VaultFile) => {
    if (!vaultToken) { setAccountOpen(true); return }
    try {
      const response = await fetch(`${VAULT_API}/files/${encodeURIComponent(file.id)}`, { headers: { Authorization: `Bearer ${vaultToken}` } })
      if (!response.ok) {
        const data = await response.json()
        throw new Error(data?.detail || 'Download unavailable')
      }
      const url = URL.createObjectURL(await response.blob())
      const link = document.createElement('a')
      link.href = url
      link.download = file.name
      document.body.appendChild(link)
      link.click()
      link.remove()
      window.setTimeout(() => URL.revokeObjectURL(url), 1000)
      logEvent('File decrypted', file.name, 'success')
      showToast('File decrypted and downloaded')
    } catch (error) { showToast(error instanceof Error ? error.message : 'Download failed') }
  }
  const deleteVaultFile = async (file: VaultFile) => {
    if (!window.confirm(`Permanently delete ${file.name}?`)) return
    try {
      await vaultRequest(`/files/${encodeURIComponent(file.id)}`, { method: 'DELETE' }, vaultToken)
      setFiles(p => p.filter(f => f.id !== file.id))
      setSelected(null)
      setModal(null)
      logEvent('Encrypted file deleted', file.name)
      showToast('Encrypted file deleted')
    } catch (error) { showToast(error instanceof Error ? error.message : 'Delete failed') }
  }
  const onFiles = async (e: ChangeEvent<HTMLInputElement>) => {
    const picks = Array.from(e.target.files || [])
    if (inputRef.current) inputRef.current.value = ''
    if (!picks.length) return
    if (!vaultToken) { setModal(null); setAccountOpen(true); return }
    try {
      for (const file of picks) {
        const form = new FormData()
        form.append('file', file)
        await vaultRequest('/files', { method: 'POST', body: form }, vaultToken)
      }
      await refreshFiles(vaultToken)
      logEvent('Files encrypted', `${picks.length} file(s) · AES-256-GCM + ML-KEM-768`, 'success')
      showToast(`${picks.length} file(s) encrypted and stored`)
      setModal(null)
    } catch (error) { showToast(error instanceof Error ? error.message : 'Upload failed'); await refreshFiles(vaultToken).catch(() => {}) }
  }
  const openFile = (f: VaultFile) => { setSelected(f); setModal('info') }
  const openImport = () => { if (!vaultToken) { setAccountOpen(true); showToast('Sign in to access your encrypted vault'); return }; setModal('import') }
  const header = headings[page]
  return <div className={`app-shell ${compact ? 'compact' : ''} pv-${theme}`}>
    <aside className={`sidebar ${sidebar ? 'sidebar-open' : ''}`}>
      <div className="brand" onClick={() => navigate('Overview')} role="button" tabIndex={0}><div className="brand-mark"><Shield size={22} strokeWidth={2.2}/><span className="brand-dot"/></div><span>Pico<span className="brand-bold">Vault</span></span></div>
      <div className="workspace-switch"><div className="avatar-small">P</div><div className="workspace-name"><strong>{accountName || 'Account not signed in'}</strong><small>{accountName ? 'Local UI profile' : 'Select an account'}</small></div><ChevronDown size={15}/></div>
      <div className="nav-groups">{navigation.map(group => <div className="nav-group" key={group.title}><div className="nav-label">{group.title}</div>{group.items.map(item => <button type="button" onClick={() => navigate(item.page)} key={item.page} className={`nav-link ${page === item.page ? 'active' : ''}`}><item.icon size={18} strokeWidth={page === item.page ? 2.2 : 1.8}/><span>{item.page}</span>{item.page === 'USB device' && <span className="nav-indicator"/>}</button>)}</div>)}</div>
      <div className="sidebar-bottom"><div className="sidebar-info"><div className="tiny-ribbon"><span/> SECURITY STATUS</div><strong>Hardware-backed vault</strong><p>The enrolled Pico is required for protected operations.</p><button onClick={() => navigate('USB device')}>View device setup <ArrowRight size={14}/></button></div><div className="sidebar-account" onClick={() => setAccountOpen(true)} role="button" tabIndex={0}><span className="account-icon">PV</span><div><strong>{accountName || 'Guest'}</strong><small>Account controls</small></div><MoreHorizontal size={17}/></div></div>
    </aside>
    {sidebar && <div className="mobile-scrim" onClick={() => setSidebar(false)}/>}
    <div className="main-column"><header className="topbar"><div className="top-left"><button className="mobile-menu icon-button" onClick={() => setSidebar(true)} aria-label="Open navigation"><Menu size={20}/></button><span className="crumb">Workspace</span><ChevronRight size={14} className="crumb-arrow"/><strong>{page}</strong></div><div className="top-actions"><div className="top-search"><Search size={17}/><input id="global-search" value={search} onChange={e => { setSearch(e.target.value); if (e.target.value) setPage('My vault') }} placeholder="Find something..."/><kbd>Ctrl + {shortcut.toUpperCase()}</kbd></div><button className="icon-button notice-button" aria-label="Notifications" onClick={() => setNotifications(p => !p)}><Bell size={19}/><span/></button><div className="top-divider"/><button className="top-avatar" onClick={() => setAccountOpen(true)} aria-label="Account">{accountName ? accountName.slice(0,2).toUpperCase() : 'PV'}</button></div>{notifications && <div className="notifications"><strong>You're all caught up</strong><p>Real security notifications will appear after device integration.</p><button onClick={() => setNotifications(false)}>Dismiss</button></div>}</header>
    <main className="content"><div className="page-head"><div>{header.eyebrow && <div className="eyebrow"><span className="eyebrow-bar"/>{header.eyebrow}</div>}<h1>{header.title}</h1><p>{header.subtitle}</p></div><div className="page-head-action">{(page === 'Overview' || page === 'My vault') && <button className="button primary" onClick={openImport}><Plus size={18}/> Add files</button>}</div></div>
    {page === 'Overview' && <><div className="hero"><div className="hero-copy"><h2>Welcome to<br/><em>PicoVault.</em></h2><p>Hardware-assisted protection for your confidential files and credentials. Designed around a physical security device.</p><div className="hero-actions"><button className="button white" onClick={() => navigate('My vault')}>Access Vault <ArrowUpRight size={17}/></button><button className="hero-link" onClick={() => navigate('USB device')}>USB device <ArrowRight size={17}/></button></div></div><div className="hero-visual"><div className="orbit orbit-one"/><div className="orbit orbit-two"/><div className="orbit orbit-three"/><div className="center-crest"><Shield size={100} strokeWidth={1.05}/><div className="crest-center"><LockKeyhole size={37} strokeWidth={1.5}/></div></div><div className="float-tag tag-left"><span className="tag-icon"><KeyRound size={15}/></span>Private by design</div><div className="float-tag tag-right"><span className="tag-icon"><Lock size={15}/></span>Your keys, your rules</div></div></div>
      <div className="section-row"><div><h3>Security overview</h3><p>Account and hardware status</p></div><button className="subtle-action" onClick={() => setAccountOpen(true)}>{accountName || 'Sign in'} <ArrowRight size={15}/></button></div><div className="stats-grid"><Stat icon={<FolderClosed size={20}/>} tone="blue" label="Encrypted files" value={String(files.length).padStart(2, '0')} footer={vaultToken ? "Stored in your private vault" : "Sign in to see your files"}/><Stat icon={<Usb size={20}/>} tone="red" label="Hardware device" value={device?.connected ? 'Detected' : 'Offline'} footer={device?.port || 'No Device Detected'}/><Stat icon={<KeyRound size={20}/>} tone="purple" label="Account" value={accountName || 'Guest'} footer={vaultToken ? "Password + Pico verified" : "Sign in to unlock"}/><Stat icon={<ShieldCheck size={20}/>} tone="green" label="Encryption" value={vaultToken ? "Active" : "Locked"} footer="AES-256-GCM · ML-KEM-768 key protection"/></div>
      <div className="overview-columns"><div className="panel files-panel"><div className="panel-title"><div><h3>Recent files</h3><p>Encrypted files in your account</p></div><button className="subtle-action" onClick={() => navigate('My vault')}>View all <ArrowRight size={16}/></button></div><div className="recent-list">{files.length ? files.slice(0,4).map(f => <FileRow key={f.id} file={f} onClick={() => openFile(f)} simple/>) : <p className="empty-line">No encrypted files yet</p>}</div></div><div className="panel activity-panel"><div className="panel-title"><div><h3>Recent activity</h3><p>Recent workspace events</p></div><button className="icon-button" onClick={() => navigate('Activity')} aria-label="View activity"><ArrowUpRight size={18}/></button></div><div className="timeline">{events.length ? events.slice(0,3).map(e => <EventRow key={e.id} event={e}/>) : <p className="empty-line">No recent actions</p>}</div><button className="activity-footer" onClick={() => navigate('Activity')}>View activity history <ArrowRight size={15}/></button></div></div></>}
    {page === 'My vault' && <><div className="toolbar"><div className="toolbar-left"><span className="item-count">{visibleFiles.length} items</span></div><div className="toolbar-right"><div className="view-toggle"><button aria-label="List view" className={view === 'list' ? 'picked' : ''} onClick={() => setView('list')}><List size={18}/></button><button aria-label="Grid view" className={view === 'grid' ? 'picked' : ''} onClick={() => setView('grid')}><LayoutGrid size={18}/></button></div><button className="button secondary" onClick={openImport}><UploadCloud size={17}/> Import files</button></div></div>{view === 'list' ? <div className="file-table"><div className="file-table-header"><span>NAME</span><span>TYPE</span><span>SIZE</span><span>MODIFIED</span><span/></div>{visibleFiles.map(f => <div className="file-table-row" key={f.id} onClick={() => openFile(f)} role="button" tabIndex={0}><div className="file-name"><FileTile kind={f.kind}/><div><strong>{f.name}</strong>{f.local && <small className="warning-text">Not encrypted</small>}</div></div><span><span className="tag">{f.tag}</span></span><span className="table-muted">{f.size}</span><span className="table-muted">{f.modified}</span><MoreHorizontal size={18} className="more"/></div>)}</div> : <div className="file-grid">{visibleFiles.map(f => <button className="file-card" key={f.id} onClick={() => openFile(f)}><FileTile kind={f.kind}/><strong>{f.name}</strong><span>{f.size} · {f.tag}</span></button>)}</div>}{visibleFiles.length === 0 && <EmptyState title="Nothing here yet" desc="Sign in and upload a file to encrypt it." action="Add files" onAction={openImport}/>}</>}
    {page === 'USB device' && <><div className="device-layout"><div className="device-primary panel"><div className="device-heading"><span className="device-pill"><span/> {device?.connected ? 'USB DETECTED' : 'NO DEVICE DETECTED'}</span><span className="device-id">RP2040 · USB SERIAL</span></div><div className="usb-illustration"><div className="usb-body"><span className="usb-cut"/><div className="usb-chip"><Cpu size={36} strokeWidth={1.3}/></div><div className="usb-mark"><Shield size={18}/> PicoVault</div></div><div className="usb-stem"/><div className="usb-connector"><span/><span/></div></div><div className="device-description"><h2>Hardware Device</h2><p>Connected USB hardware and communication status.</p></div><div className="device-btn-row"><button className="button secondary" onClick={() => void scanDevice()}><Activity size={17}/> {deviceBusy ? 'Scanning...' : 'Scan for devices'}</button></div></div><div className="device-secondary"><div className="panel device-info"><div className="panel-title"><div><h3>Device status</h3><p>Connection and security diagnostics</p></div><span className="status-grey">{device?.connected ? 'USB PRESENT' : 'NOT CONNECTED'}</span></div><InfoRow label="Device model" value="RP2040 (confirmed)"/><InfoRow label="Firmware" value="MicroPython 1.29.0"/><InfoRow label="USB port" value={device?.port || "Not detected"}/><InfoRow label="Hardware bridge" value={device ? "Running" : "Offline"} warn={!device}/><InfoRow label="Authentication" value={device?.connected ? "HMAC-SHA256 available" : "No Device Detected"} warn={!device?.connected}/><InfoRow label="Protected key" value="Per-device secret in Pico flash"/></div>{deviceError && <p className="device-message">{deviceError}</p>}<div className="panel device-info"><div className="panel-title"><h3>USB devices</h3></div>{device?.connected ? <div className="usb-device-entry"><Usb size={18}/><span>{device.description || 'RP2040 USB Serial'}</span><strong>{device.port}</strong></div> : <p className="device-message">No supported device detected</p>}<p className="device-message">Full USB inventory and registered-device enrollment will be available after backend integration.</p></div></div></div></>}
    {page === 'Passwords' && <><div className="panel password-panel"><div className="panel-title"><div><h3>Secure notes</h3></div><button className="button secondary" onClick={() => setNoteVisible(p => !p)}>{noteVisible ? <EyeOff size={16}/> : <Eye size={16}/>} {noteVisible ? 'Hide names' : 'Show names'}</button></div>{sampleNotes.map((n,i) => <div className="note-row" key={i}><div className="note-icon"><FileKey2 size={20}/></div><div><strong>{noteVisible ? n : '••••••••••••••••••'}</strong><small>Not stored securely</small></div><Lock size={16}/></div>)}<form className="note-form" onSubmit={e => { e.preventDefault(); if (!newNote.trim()) return; setSampleNotes(p => [newNote.trim(), ...p]); setNewNote(''); showToast('Demo note added · not encrypted') }}><input value={newNote} onChange={e => setNewNote(e.target.value)} placeholder="Add a demo note name..."/><button className="button primary" type="submit">Add note</button></form></div></>}

    {page === 'Activity' && <div className="panel full-activity"><div className="panel-title"><div><h3>Workspace journal</h3><p>Retention: {retention === '0' ? 'Current session' : `${retention} days`} · backend audit storage pending</p></div></div><div className="activity-date">TODAY</div>{events.map(e => <EventRow key={e.id} event={e} expanded/>)}</div>}
    {page === 'Settings' && <div className="settings-layout"><div className="panel"><div className="panel-title"><div><h3>Interface</h3></div><Settings2 size={19}/></div><div className="setting-row"><div><strong>Comfortable spacing</strong><p>A little more room for everything</p></div><button role="switch" aria-checked={!compact} className={`toggle ${!compact ? 'on' : ''}`} onClick={() => setCompact(p => !p)}><span/></button></div><div className="setting-row"><div><strong>Appearance</strong><p>Choose an interface theme</p></div><select aria-label="Appearance" value={theme} onChange={e => setTheme(e.target.value as 'light' | 'dark')}><option value="light">Light</option><option value="dark">Dark navy</option></select></div><div className="setting-row"><div><strong>History retention</strong><p>Preference for future server-side audit storage</p></div><select aria-label="History retention" value={retention} onChange={e => setRetention(e.target.value)}><option value="7">7 days</option><option value="30">30 days</option><option value="90">90 days</option><option value="0">Current session</option></select></div></div><div className="panel"><div className="panel-title"><div><h3>Security configuration</h3><p>Pending backend integration</p></div><LockKeyhole size={19}/></div><InfoRow label="Encryption engine" value="AES-256-GCM"/><InfoRow label="RP2040 binding" value={vaultToken ? "Account-bound" : "Sign in to verify"} warn={!vaultToken}/><InfoRow label="Offline recovery" value="Not configured" warn/><InfoRow label="Post-quantum key exchange" value="ML-KEM-768 file-key encapsulation"/></div></div>}
    </main><footer className="footer"><span>© 2026 PicoVault</span><span>Local-development encrypted vault · hardware required</span></footer></div>
    <input type="file" multiple ref={inputRef} hidden onChange={onFiles}/>
    {modal && <div className="modal-overlay" onMouseDown={e => { if (e.target === e.currentTarget) setModal(null) }}><div className="modal" role="dialog" aria-modal="true" aria-label={modal === 'info' ? 'File details' : 'Information'}><div className="modal-head"><span>{modal === 'import' ? 'Import files' : modal === 'device' ? 'Hardware integration' : 'File details'}</span><button onClick={() => setModal(null)} aria-label="Close"><X size={19}/></button></div>{modal === 'import' && <div className="modal-body"><div className="drop-zone" onClick={() => inputRef.current?.click()}><div><UploadCloud size={30}/></div><strong>Choose files</strong><p>Any file type is supported for selection.</p><button className="button primary" onClick={e => { e.stopPropagation(); inputRef.current?.click() }}>Browse files</button></div><div className="modal-warning"><ShieldAlert size={18}/> Your files are encrypted locally by the development backend with AES-256-GCM and ML-KEM-768 key protection. Maximum 16 MiB per file.</div></div>}{modal === 'device' && <div className="modal-body"><div className="modal-feature"><Usb size={25}/><h3>The USB bridge comes next.</h3><p>The local hardware service can detect connected boards. Device enrollment and cryptographic authentication are not yet available.</p></div><div className="modal-checklist"><div><Check size={17}/> RP2040 board and firmware verified</div><div><Clock3 size={17}/> Local hardware companion service</div><div><Clock3 size={17}/> Challenge-response enrollment</div><div><Clock3 size={17}/> Authenticated encryption operations</div></div><button className="button primary full" onClick={() => setModal(null)}>Understood</button></div>}{modal === 'info' && selected && <div className="modal-body"><div className="file-modal-title"><FileTile kind={selected.kind}/><div><strong>{selected.name}</strong><small>{selected.tag} · {selected.size}</small></div></div><InfoRow label="Modified" value={selected.modified}/><InfoRow label="Protection" value={selected.tag}/><InfoRow label="Device binding" value={selected.tag.includes("Pico-bound") ? "Bound to enrolled hardware" : "Legacy format"} warn={!selected.tag.includes("Pico-bound")}/><div className="file-modal-actions"><button className="button primary" onClick={() => void downloadVaultFile(selected)}><Download size={16}/> Download</button><button className="button secondary" onClick={() => { navigator.clipboard?.writeText(selected.name); showToast('Filename copied') }}><Copy size={16}/> Copy name</button><button className="button danger" onClick={() => void deleteVaultFile(selected)}><Trash2 size={16}/> Delete file</button></div></div>}</div></div>}
    {accountOpen && <div className="modal-overlay" onMouseDown={e => { if (e.target === e.currentTarget) { setAccountPassword(''); setAccountOpen(false) } }}><div className="modal" role="dialog" aria-modal="true" aria-label="Account"><div className="modal-head"><span>{vaultToken ? 'Account' : accountMode === 'login' ? 'Sign in' : 'Create account'}</span><button onClick={() => { setAccountPassword(''); setAccountOpen(false) }} aria-label="Close"><X size={18}/></button></div><div className="modal-body">{vaultToken ? <><p>Signed in as <strong>{accountName}</strong>. Vault operations require your enrolled Pico.</p><button className="button secondary" onClick={() => void logoutAccount()}>Sign out</button></> : <><p>Use your account password and connected Pico to unlock the vault.</p><form className="account-form" onSubmit={e => void submitAccount(e)}><label htmlFor="vault-username">Username</label><input id="vault-username" value={accountDraft} autoComplete="username" minLength={3} maxLength={48} pattern="[A-Za-z0-9_.-]+" onChange={e => setAccountDraft(e.target.value)} required/><label htmlFor="vault-password">Password</label><input id="vault-password" type="password" autoComplete={accountMode === 'login' ? 'current-password' : 'new-password'} minLength={12} maxLength={256} value={accountPassword} onChange={e => setAccountPassword(e.target.value)} required/>{accountError && <p role="alert" className="warning-text">{accountError}</p>}<button className="button primary" disabled={accountBusy} type="submit">{accountBusy ? 'Verifying hardware...' : accountMode === 'login' ? 'Sign in securely' : 'Create account'}</button></form><button className="button secondary" onClick={() => { setAccountMode(p => p === 'login' ? 'register' : 'login'); setAccountError('') }}>{accountMode === 'login' ? 'Create a new account' : 'Already have an account? Sign in'}</button></>}</div></div></div>}

    {toast && <div className="toast"><Info size={17}/>{toast}<button onClick={() => setToast('')} aria-label="Close notification"><X size={14}/></button></div>}
  </div>
}
function FileTile({ kind }: { kind: Kind }) { const Icon = iconFor(kind); return <div className={`file-tile ${iconClass(kind)}`}><Icon size={21} strokeWidth={1.8}/></div> }
function FileRow({ file, onClick, simple = false }: { file: VaultFile; onClick: () => void; simple?: boolean }) { return <button className="recent-file" onClick={onClick}><FileTile kind={file.kind}/><div className="recent-info"><strong>{file.name}</strong><small>{file.size} <span>·</span> {file.modified}</small></div>{simple && <ArrowUpRight size={17} className="recent-arrow"/>}</button> }
function Stat({ icon, tone, label, value, footer }: { icon: ReactNode; tone: string; label: string; value: string; footer: string }) { return <div className="stat-card"><div className={`stat-icon ${tone}`}>{icon}</div><span>{label}</span><strong>{value}</strong><small>{footer}</small></div> }
function EventRow({ event, expanded = false }: { event: Event; expanded?: boolean }) { return <div className={`event-row ${expanded ? 'expanded' : ''}`}><div className={`event-icon ${event.icon}`}>{event.icon === 'success' ? <Check size={17}/> : event.icon === 'warning' ? <ShieldAlert size={17}/> : <Activity size={17}/>}</div><div><strong>{event.title}</strong><p>{event.desc}</p></div><time>{event.time}</time></div> }
function EmptyState({ title, desc, action, onAction }: { title: string; desc: string; action: string; onAction: () => void }) { return <div className="empty-state"><FolderClosed size={34}/><h3>{title}</h3><p>{desc}</p><button className="button primary" onClick={onAction}>{action}</button></div> }
function InfoRow({ label, value, warn = false }: { label: string; value: string; warn?: boolean }) { return <div className="info-row"><span>{label}</span><strong className={warn ? 'warn-text' : ''}>{value}</strong></div> }
function FeatureCard({ number, icon, title, desc }: { number: string; icon: ReactNode; title: string; desc: string }) { return <div className="feature-card"><span>{number}</span><div>{icon}</div><h3>{title}</h3><p>{desc}</p></div> }
export default App
