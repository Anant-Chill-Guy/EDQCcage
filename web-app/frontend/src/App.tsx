import DevicePanel from './DevicePanel'
import { useEffect, useMemo, useRef, useState } from 'react'
import type { ChangeEvent, FormEvent, ReactNode } from 'react'
import { Activity, ArrowDownLeft, ArrowDownToLine, ArrowLeft, ArrowRight, ArrowUpRight, Bell, BookOpen, Check, CheckCheck, ChevronDown, ChevronLeft, ChevronRight, ChevronUp, CircleHelp, Clock3, CloudOff, Command, Copy, Cpu, Download, Ellipsis, Eye, EyeOff, FileArchive, FileCode2, FileImage, FileKey2, FileLock2, FilePlus2, FileText, Fingerprint, FolderClosed, FolderPlus, HardDrive, HardDriveDownload, History, House, Info, KeyRound, LayoutGrid, Link2, List, Lock, LockKeyhole, Menu, MoreHorizontal, Plus, Search, Settings2, Shield, ShieldAlert, ShieldCheck, ShieldOff, SlidersHorizontal, Sparkles, Trash2, UploadCloud, Usb, Users, Vault, WifiOff, X } from 'lucide-react'

type DeviceReport = { connected: boolean; port: string | null; description: string | null; vid: number | null; pid: number | null; protocol: string }
type Page = 'Overview' | 'My vault' | 'USB device' | 'Passwords' | 'Activity' | 'Settings'
type Kind = 'pdf' | 'image' | 'archive' | 'code' | 'text' | 'key'
type VaultFile = { id: string; name: string; kind: Kind; size: string; modified: string; tag: string; mode: 'encrypted' | 'plain' }
type Event = { id: number; title: string; desc: string; time: string; icon: 'success' | 'warning' | 'neutral' }
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
  Overview: { eyebrow: '', title: 'Welcome to EDQCcage.', subtitle: '' },
  'My vault': { eyebrow: '', title: 'Private Vault', subtitle: '' },
  'USB device': { eyebrow: '', title: 'Hardware Device', subtitle: 'Manage your connected Pico and verify its identity.' },
  Passwords: { eyebrow: '', title: 'Credentials & Notes', subtitle: '' },
  Activity: { eyebrow: '', title: 'History', subtitle: '' },
  Settings: { eyebrow: '', title: 'Settings', subtitle: '' }
}
type StoredFile = { id: string; name: string; size: number; created_at: number; key_protection: string; storage_mode: 'encrypted' | 'plain' }
type SecretSummary = { id: string; kind: 'note' | 'credential'; title: string; created_at: number }
type SecretDetail = SecretSummary & { secret: string; username: string; url: string }
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
  return { id: f.id, name, kind, size, modified: new Date(f.created_at * 1000).toLocaleString(), tag: f.key_protection, mode: f.storage_mode }
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
      setDeviceError('Start the EDQCcage hardware service to detect your board.')
    } finally {
      setDeviceBusy(false)
    }
  }
  useEffect(() => { void scanDevice(); const timer = window.setInterval(() => void scanDevice(), 10000); return () => window.clearInterval(timer) }, [])
  const setupDevice = async () => {
    try {
      const response = await fetch('http://127.0.0.1:8765/api/device/setup', { method: 'POST' })
      const result = await response.json()
      if (!response.ok) throw new Error(result.detail || 'Enrollment failed')
      await scanDevice()
      setAccountError('USB registered. Sign in to continue.')
    } catch (error) {
      setAccountError(error instanceof Error ? error.message : 'Enrollment failed')
    }
  }
  const [page, setPage] = useState<Page>('Overview')
  const [serverAudit, setServerAudit] = useState<Event[]>([])
  const [files, setFiles] = useState<VaultFile[]>([])
  const [events, setEvents] = useState<Event[]>([])
  const [search, setSearch] = useState('')
  const [view, setView] = useState<'list' | 'grid'>('list')
  const [filter, setFilter] = useState('All files')
  const [uploadMode, setUploadMode] = useState<'encrypted' | 'plain'>('encrypted')
  const [fileBusy, setFileBusy] = useState(false)
  const [previewUrl, setPreviewUrl] = useState('')
  const [previewType, setPreviewType] = useState<'image' | 'document'>('document')
  const previewRef = useRef('')
  const [modal, setModal] = useState<'import' | 'device' | 'info' | 'preview' | null>(null)
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

  const [records, setRecords] = useState<SecretSummary[]>([])
  const [recordKind, setRecordKind] = useState<'note' | 'credential'>('note')
  const [newNote, setNewNote] = useState('')
  const [recordSecret, setRecordSecret] = useState('')
  const [recordUsername, setRecordUsername] = useState('')
  const [recordUrl, setRecordUrl] = useState('')
  const [revealedRecord, setRevealedRecord] = useState<SecretDetail | null>(null)
  const [recordBusy, setRecordBusy] = useState(false)
  const inputRef = useRef<HTMLInputElement>(null)

  const showToast = (message: string) => { setToast(message); window.setTimeout(() => setToast(''), 3500) }
  const logEvent = (title: string, desc: string, icon: Event['icon'] = 'neutral') => setEvents(p => [{ id: Date.now(), title, desc, time: 'Just now', icon }, ...p])
  const navigate = (destination: Page) => { setPage(destination); setSidebar(false); setSearch(''); setFilter('All files') }
  useEffect(() => { const handler = (e: KeyboardEvent) => { if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === shortcut.toLowerCase()) { e.preventDefault(); document.getElementById('global-search')?.focus() } }; window.addEventListener('keydown', handler); return () => window.removeEventListener('keydown', handler) }, [shortcut])
  const visibleFiles = useMemo(() => files.filter(f => (filter === 'All files' || (filter === 'Encrypted' ? f.mode === 'encrypted' : f.mode === 'plain')) && `${f.name} ${f.tag}`.toLowerCase().includes(search.toLowerCase())), [files, search, filter])
  const closePreview = () => { if (previewRef.current) URL.revokeObjectURL(previewRef.current); previewRef.current = ''; setPreviewUrl(''); setModal(null) }
  useEffect(() => () => { if (previewRef.current) URL.revokeObjectURL(previewRef.current) }, [])
  const refreshRecords = async (token: string) => {
    const data = await vaultRequest('/records', {}, token) as { records: SecretSummary[] }
    setRecords(data.records)
  }
  const saveRecord = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (!vaultToken) { setAccountOpen(true); return }
    if (!newNote.trim() || !recordSecret) return
    setRecordBusy(true)
    try {
      await vaultRequest('/records', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ kind: recordKind, title: newNote.trim(), secret: recordSecret, username: recordUsername, url: recordUrl }) }, vaultToken)
      await refreshRecords(vaultToken)
      setNewNote('')
      setRecordSecret('')
      setRecordUsername('')
      setRecordUrl('')
      setRevealedRecord(null)
      logEvent('Encrypted record saved', recordKind === 'note' ? 'Secure note' : 'Credential', 'success')
      showToast('Saved with hybrid encryption and Pico binding')
    } catch (error) { showToast(error instanceof Error ? error.message : 'Save failed') }
    finally { setRecordBusy(false) }
  }
  const toggleRecord = async (item: SecretSummary) => {
    if (revealedRecord?.id === item.id) { setRevealedRecord(null); return }
    try {
      const data = await vaultRequest(`/records/${encodeURIComponent(item.id)}`, {}, vaultToken) as SecretDetail

      setRevealedRecord(data)
    } catch (error) { setRevealedRecord(null); showToast(error instanceof Error ? error.message : 'Unable to reveal record') }
  }
  const removeRecord = async (item: SecretSummary) => {
    if (!window.confirm(`Delete ${item.title}?`)) return
    try {
      await vaultRequest(`/records/${encodeURIComponent(item.id)}`, { method: 'DELETE' }, vaultToken)
      setRevealedRecord(null)
      await refreshRecords(vaultToken)
      logEvent('Encrypted record deleted', item.kind)
      showToast('Record deleted')
    } catch (error) { showToast(error instanceof Error ? error.message : 'Delete failed') }
  }
  const refreshAudit = async (token: string) => {
    const data = await vaultRequest('/audit', {}, token) as { events: { event: string; created_at: number }[] }
    setServerAudit(data.events.map((item, index) => ({ id: item.created_at * 1000 + index, title: item.event.replaceAll('.', ' · '), desc: 'Account security event', time: new Date(item.created_at * 1000).toLocaleString(), icon: 'success' })))
  }
  useEffect(() => { if (vaultToken && page === 'Activity') void refreshAudit(vaultToken).catch(() => {}) }, [vaultToken, page])
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
      await refreshRecords(result.access_token)
      try { await refreshAudit(result.access_token) } catch { }

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
    setRecords([])
    setServerAudit([])
    setRevealedRecord(null)
    setSelected(null)
    setAccountOpen(false)
    showToast('Signed out')
  }
  const fetchFile = async (file: VaultFile) => {
    if (!vaultToken) throw Error('Sign in to access files')
    const encrypted = file.mode === 'encrypted'
    const response = await fetch(`${VAULT_API}/files/${encodeURIComponent(file.id)}${encrypted ? '/decrypt' : ''}`, { method: encrypted ? 'POST' : 'GET', headers: { Authorization: `Bearer ${vaultToken}` }, cache: 'no-store' })
    if (!response.ok) {
      const data = await response.json().catch(() => ({}))
      throw Error(data.detail || `File access failed (${response.status})`)
    }
    return response.blob()
  }
  const downloadVaultFile = async (file: VaultFile) => {
    setFileBusy(true)
    try {
      const blob = await fetchFile(file)
      const url = URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = url
      link.download = file.name
      document.body.appendChild(link)
      link.click()
      link.remove()
      window.setTimeout(() => URL.revokeObjectURL(url), 15000)
      logEvent(file.mode === 'encrypted' ? 'File decrypted' : 'File downloaded', file.name, 'success')
      showToast(file.mode === 'encrypted' ? 'Decrypted using your enrolled Pico' : 'Normal file downloaded')
    } catch (error) { showToast(error instanceof Error ? error.message : 'Download failed') }
    finally { setFileBusy(false) }
  }
  const openVaultFile = async (file: VaultFile) => {
    const extension = file.name.split('.').pop()?.toLowerCase()
    const formats: Record<string, string> = { pdf: 'application/pdf', png: 'image/png', jpg: 'image/jpeg', jpeg: 'image/jpeg', webp: 'image/webp', gif: 'image/gif', txt: 'text/plain', md: 'text/plain', csv: 'text/plain', json: 'text/plain', py: 'text/plain', js: 'text/plain', ts: 'text/plain' }
    if (!extension || !formats[extension]) { await downloadVaultFile(file); return }
    setFileBusy(true)
    try {
      const data = await fetchFile(file)
      if (previewRef.current) URL.revokeObjectURL(previewRef.current)
      const url = URL.createObjectURL(new Blob([data], { type: formats[extension] }))
      previewRef.current = url
      setPreviewUrl(url)
      setPreviewType(formats[extension].startsWith('image/') ? 'image' : 'document')
      setModal('preview')
      logEvent(file.mode === 'encrypted' ? 'File decrypted for preview' : 'Normal file opened', file.name, 'success')
    } catch (error) { showToast(error instanceof Error ? error.message : 'Could not open file') }
    finally { setFileBusy(false) }
  }
  const deleteVaultFile = async (file: VaultFile) => {
    if (!window.confirm(`Permanently delete ${file.name}?`)) return
    try {
      await vaultRequest(`/files/${encodeURIComponent(file.id)}`, { method: 'DELETE' }, vaultToken)
      setFiles(p => p.filter(f => f.id !== file.id))
      setSelected(null)
      setModal(null)
      logEvent('File deleted', file.name)
      showToast('File deleted')
    } catch (error) { showToast(error instanceof Error ? error.message : 'Delete failed') }
  }
  const onFiles = async (e: ChangeEvent<HTMLInputElement>) => {
    const picks = Array.from(e.target.files || [])
    if (inputRef.current) inputRef.current.value = ''
    if (!picks.length) return
    if (!vaultToken) { setModal(null); setAccountOpen(true); return }
    setFileBusy(true)
    let stored = 0
    try {
      for (const file of picks) {
        const form = new FormData()
        form.append('file', file)
        form.append('mode', uploadMode)
        await vaultRequest('/files', { method: 'POST', body: form }, vaultToken)
        stored++
      }
      await refreshFiles(vaultToken)
      logEvent(uploadMode === 'encrypted' ? 'Files encrypted' : 'Normal files stored', `${stored} file(s)`, 'success')
      showToast(`${stored} file(s) stored ${uploadMode === 'encrypted' ? 'with encryption' : 'without encryption'}`)
      setModal(null)
    } catch (error) {
      showToast(`${stored} stored. ${error instanceof Error ? error.message : 'Upload failed'}`)
      await refreshFiles(vaultToken).catch(() => {})
    } finally { setFileBusy(false) }
  }
  const openFile = (f: VaultFile) => { setSelected(f); setModal('info') }
  const openImport = () => { if (!vaultToken) { setAccountOpen(true); showToast('Sign in to access your cage'); return }; setUploadMode('encrypted'); setModal('import') }
  const header = headings[page]
  if (!vaultToken) return <div className={`pv-entry pv-${theme}`}>
    <section className="pv-entry-cover"><div className="pv-entry-logo">EDQC<span>cage</span></div><div><h1>Post-Quantum Encryption. Hardware-Backed Security.</h1></div></section>
    <section className="pv-entry-formside"><form className="pv-entry-form" onSubmit={e => void submitAccount(e)}>
      <h2>{accountMode === 'login' ? 'Welcome back' : 'Create your account'}</h2>

      <div className="pv-entry-device"><span className={`pv-entry-dot ${device?.connected ? 'online' : ''}`}/>{device?.connected ? 'Device connected' : 'No Device Detected'}</div>
      <button type="button" className="pv-switch" onClick={() => void setupDevice()}>Register USB device</button>
      <label htmlFor="pv-login-name">Username</label>
      <input id="pv-login-name" value={accountDraft} onChange={e => setAccountDraft(e.target.value)} autoComplete="username" minLength={3} maxLength={48} pattern="[a-zA-Z0-9_.-]+" placeholder="Username" required/>
      <label htmlFor="pv-login-password">Password</label>
      <input id="pv-login-password" type="password" value={accountPassword} onChange={e => setAccountPassword(e.target.value)} minLength={12} maxLength={256} autoComplete={accountMode === 'register' ? 'new-password' : 'current-password'} placeholder="At least 12 characters" required/>
      {accountError && <div className="pv-entry-error" role="alert">{accountError}</div>}
      <button type="submit" disabled={accountBusy || !device?.connected}>{accountBusy ? 'Authenticating…' : accountMode === 'login' ? 'Unlock Cage' : 'Create Account'}</button>
      <button type="button" className="pv-switch" onClick={() => {setAccountMode(p => p === 'login' ? 'register' : 'login'); setAccountError('')}}>{accountMode === 'login' ? 'New to EDQCcage? Create an account' : 'Already registered? Sign in'}</button>

    </form></section>
  </div>
  return <div className={`app-shell ${compact ? 'compact' : ''} pv-${theme}`}>
    <aside className={`sidebar ${sidebar ? 'sidebar-open' : ''}`}>
      <div className="brand" onClick={() => navigate('Overview')} role="button" tabIndex={0}><div className="brand-mark"><Shield size={22} strokeWidth={2.2}/><span className="brand-dot"/></div><span>EDQC<span className="brand-bold">cage</span></span></div>
      <div className="workspace-switch"><div className="avatar-small">P</div><div className="workspace-name"><strong>{accountName || 'Account not signed in'}</strong><small>{accountName ? 'Local UI profile' : 'Select an account'}</small></div><ChevronDown size={15}/></div>
      <div className="nav-groups">{navigation.map(group => <div className="nav-group" key={group.title}><div className="nav-label">{group.title}</div>{group.items.map(item => <button type="button" onClick={() => navigate(item.page)} key={item.page} className={`nav-link ${page === item.page ? 'active' : ''}`}><item.icon size={18} strokeWidth={page === item.page ? 2.2 : 1.8}/><span>{item.page}</span>{item.page === 'USB device' && <span className="nav-indicator"/>}</button>)}</div>)}</div>
      <div className="sidebar-bottom"><div className="sidebar-info"><div className="tiny-ribbon"><span/> SECURITY STATUS</div><strong>Hardware-backed vault</strong><p>The enrolled Pico is required for protected operations.</p><button onClick={() => navigate('USB device')}>View device setup <ArrowRight size={14}/></button></div><div className="sidebar-account" onClick={() => setAccountOpen(true)} role="button" tabIndex={0}><span className="account-icon">PV</span><div><strong>{accountName || 'Guest'}</strong><small>Account controls</small></div><MoreHorizontal size={17}/></div></div>
    </aside>
    {sidebar && <div className="mobile-scrim" onClick={() => setSidebar(false)}/>}
    <div className="main-column"><header className="topbar"><div className="top-left"><button className="mobile-menu icon-button" onClick={() => setSidebar(true)} aria-label="Open navigation"><Menu size={20}/></button><span className="crumb">Workspace</span><ChevronRight size={14} className="crumb-arrow"/><strong>{page}</strong></div><div className="top-actions"><div className="top-search"><Search size={17}/><input id="global-search" value={search} onChange={e => { setSearch(e.target.value); if (e.target.value) setPage('My vault') }} placeholder="Find something..."/><kbd>Ctrl + {shortcut.toUpperCase()}</kbd></div><button className="icon-button notice-button" aria-label="Notifications" onClick={() => setNotifications(p => !p)}><Bell size={19}/><span/></button><div className="top-divider"/><button className="top-avatar" onClick={() => setAccountOpen(true)} aria-label="Account">{accountName ? accountName.slice(0,2).toUpperCase() : 'PV'}</button></div>{notifications && <div className="notifications"><strong>You're all caught up</strong><p>Real security notifications will appear after device integration.</p><button onClick={() => setNotifications(false)}>Dismiss</button></div>}</header>
    <main className="content"><div className="page-head"><div>{header.eyebrow && <div className="eyebrow"><span className="eyebrow-bar"/>{header.eyebrow}</div>}<h1>{header.title}</h1><p>{header.subtitle}</p></div><div className="page-head-action">{(page === 'Overview' || page === 'My vault') && <button className="button primary" onClick={openImport}><Plus size={18}/> Add files</button>}</div></div>
    {page === 'Overview' && <><div className="hero"><div className="hero-copy"><h2>Welcome to<br/><em>EDQCcage.</em></h2><p>Hardware-assisted protection for your confidential files and credentials. Designed around a physical security device.</p><div className="hero-actions"><button className="button white" onClick={() => navigate('My vault')}>Access Vault <ArrowUpRight size={17}/></button><button className="hero-link" onClick={() => navigate('USB device')}>USB device <ArrowRight size={17}/></button></div></div><div className="hero-visual"><div className="orbit orbit-one"/><div className="orbit orbit-two"/><div className="orbit orbit-three"/><div className="center-crest"><Shield size={100} strokeWidth={1.05}/><div className="crest-center"><LockKeyhole size={37} strokeWidth={1.5}/></div></div><div className="float-tag tag-left"><span className="tag-icon"><KeyRound size={15}/></span>Private by design</div><div className="float-tag tag-right"><span className="tag-icon"><Lock size={15}/></span>Your keys, your rules</div></div></div>
      <div className="section-row"><div><h3>Security overview</h3><p>Account and hardware status</p></div><button className="subtle-action" onClick={() => setAccountOpen(true)}>{accountName || 'Sign in'} <ArrowRight size={15}/></button></div><div className="stats-grid"><Stat icon={<FolderClosed size={20}/>} tone="blue" label="Encrypted files" value={String(files.filter(f => f.mode === 'encrypted').length).padStart(2, '0')} footer={vaultToken ? 'Encrypted and normal storage' : 'Sign in to view your files'}/><Stat icon={<Usb size={20}/>} tone="red" label="Hardware device" value={device?.connected ? 'Detected' : 'Offline'} footer={device?.port || 'No Device Detected'}/><Stat icon={<KeyRound size={20}/>} tone="purple" label="Account" value={accountName || 'Guest'} footer={vaultToken ? "Password + Pico verified" : "Sign in to unlock"}/><Stat icon={<ShieldCheck size={20}/>} tone="green" label="Encryption" value={vaultToken ? "Active" : "Locked"} footer="AES-256-GCM · ML-KEM-768 key protection"/></div>
      <div className="overview-columns"><div className="panel files-panel"><div className="panel-title"><div><h3>Recent files</h3><p>Your most recent files</p></div><button className="subtle-action" onClick={() => navigate('My vault')}>View all <ArrowRight size={16}/></button></div><div className="recent-list">{files.length ? files.slice(0,4).map(f => <FileRow key={f.id} file={f} onClick={() => openFile(f)} simple/>) : <p className="empty-line">No files yet</p>}</div></div><div className="panel activity-panel"><div className="panel-title"><div><h3>Recent activity</h3><p>Recent workspace events</p></div><button className="icon-button" onClick={() => navigate('Activity')} aria-label="View activity"><ArrowUpRight size={18}/></button></div><div className="timeline">{events.length ? events.slice(0,3).map(e => <EventRow key={e.id} event={e}/>) : <p className="empty-line">No recent actions</p>}</div><button className="activity-footer" onClick={() => navigate('Activity')}>View activity history <ArrowRight size={15}/></button></div></div></>}
    {page === 'My vault' && <>
      <div className="toolbar"><div className="toolbar-left"><span className="item-count">{visibleFiles.length} files</span><div className="edqc-file-filter">{(['All files','Encrypted','Normal'] as const).map(item => <button key={item} className={filter === item ? 'active' : ''} onClick={() => setFilter(item)}>{item}</button>)}</div></div><div className="toolbar-right"><div className="view-toggle"><button aria-label="List view" className={view === 'list' ? 'picked' : ''} onClick={() => setView('list')}><List size={18}/></button><button aria-label="Grid view" className={view === 'grid' ? 'picked' : ''} onClick={() => setView('grid')}><LayoutGrid size={18}/></button></div><button className="button secondary" onClick={openImport}><UploadCloud size={17}/> Add files</button></div></div>
      {view === 'list' ? <div className="file-table"><div className="file-table-header"><span>NAME</span><span>PROTECTION</span><span>SIZE</span><span>MODIFIED</span><span/></div>{visibleFiles.map(f => <div className="file-table-row" key={f.id} onClick={() => openFile(f)} role="button" tabIndex={0} onKeyDown={e => { if (e.key === 'Enter') openFile(f) }}><div className="file-name"><FileTile kind={f.kind}/><div><strong>{f.name}</strong><small className={`edqc-file-mode ${f.mode}`}>{f.mode === 'encrypted' ? 'Encrypted · Pico required' : 'Normal · Unencrypted on disk'}</small></div></div><span><span className="tag">{f.mode === 'encrypted' ? 'Encrypted' : 'Normal'}</span></span><span className="table-muted">{f.size}</span><span className="table-muted">{f.modified}</span><MoreHorizontal size={18} className="more"/></div>)}</div> : <div className="file-grid">{visibleFiles.map(f => <button className="file-card" key={f.id} onClick={() => openFile(f)}><FileTile kind={f.kind}/><strong>{f.name}</strong><span>{f.size} · {f.mode === 'encrypted' ? 'Encrypted' : 'Normal'}</span></button>)}</div>}
      {visibleFiles.length === 0 && <EmptyState title="No matching files" desc="Store a file encrypted or leave it as a normal local file." action="Add files" onAction={openImport}/>}
    </>}
    {page === 'USB device' && <DevicePanel device={device} deviceError={deviceError} deviceBusy={deviceBusy} onScan={scanDevice}/>}
    {page === 'Passwords' && <div className="panel password-panel"><div className="panel-title"><div><h3>Credentials & Notes</h3><p>ML-KEM-768 + X25519 · Pico-bound protection</p></div><button className="button secondary" onClick={() => vaultToken ? void refreshRecords(vaultToken).catch(e => showToast(e.message)) : setAccountOpen(true)}>Refresh</button></div>
      {!vaultToken ? <div className="modal-body"><p>Sign in with your account and enrolled Pico to access encrypted records.</p><button className="button primary" onClick={() => setAccountOpen(true)}>Sign in</button></div> : <>
      {records.map(item => <div className="note-row" key={item.id}><div className="note-icon"><FileKey2 size={20}/></div><div style={{flex:1,minWidth:0}}><strong>{item.title}</strong><small>{item.kind === 'note' ? 'Encrypted note' : 'Encrypted credential'}</small>{revealedRecord?.id === item.id && <div style={{whiteSpace:'pre-wrap',overflowWrap:'anywhere',marginTop:10}}>{revealedRecord.username && <p>Username: {revealedRecord.username}</p>}{revealedRecord.url && <p>URL: {revealedRecord.url}</p>}<strong>{item.kind === 'note' ? 'Note' : 'Password'}</strong><p>{revealedRecord.secret}</p></div>}</div><button className="button secondary" onClick={() => void toggleRecord(item)}>{revealedRecord?.id === item.id ? 'Hide' : 'Reveal'}</button><button className="icon-button" aria-label={`Delete ${item.title}`} onClick={() => void removeRecord(item)}><Trash2 size={16}/></button></div>)}
      {!records.length && <p className="empty-line">No encrypted records yet</p>}
      <form className="note-form" style={{display:'flex',flexWrap:'wrap',gap:10}} onSubmit={e => void saveRecord(e)}><select value={recordKind} onChange={e => setRecordKind(e.target.value as 'note' | 'credential')} aria-label="Record type"><option value="note">Secure note</option><option value="credential">Credential</option></select><input value={newNote} onChange={e => setNewNote(e.target.value)} placeholder="Title" required maxLength={160}/>{recordKind === 'credential' && <><input value={recordUsername} onChange={e => setRecordUsername(e.target.value)} placeholder="Username (optional)" maxLength={180}/><input value={recordUrl} onChange={e => setRecordUrl(e.target.value)} placeholder="URL (optional)" maxLength={1000}/></>}<input type={recordKind === 'credential' ? 'password' : 'text'} value={recordSecret} onChange={e => setRecordSecret(e.target.value)} placeholder={recordKind === 'note' ? 'Note contents' : 'Password / secret'} required maxLength={8192}/><button className="button primary" type="submit" disabled={recordBusy}>{recordBusy ? 'Encrypting...' : 'Save encrypted'}</button></form>
      </>}
    </div>}

    {page === 'Activity' && <div className="panel full-activity"><div className="panel-title"><div><h3>Workspace journal</h3><p>Backend audit events · most recent 7 days</p></div></div><div className="activity-date">TODAY</div>{(vaultToken ? serverAudit : events).map(e => <EventRow key={e.id} event={e} expanded/>)}</div>}
    {page === 'Settings' && <div className="settings-layout"><div className="panel"><div className="panel-title"><div><h3>Interface</h3></div><Settings2 size={19}/></div><div className="setting-row"><div><strong>Comfortable spacing</strong><p>A little more room for everything</p></div><button role="switch" aria-checked={!compact} className={`toggle ${!compact ? 'on' : ''}`} onClick={() => setCompact(p => !p)}><span/></button></div><div className="setting-row"><div><strong>Appearance</strong><p>Choose an interface theme</p></div><select aria-label="Appearance" value={theme} onChange={e => setTheme(e.target.value as 'light' | 'dark')}><option value="light">Light</option><option value="dark">Dark navy</option></select></div><div className="setting-row"><div><strong>History retention</strong><p>Preference for future server-side audit storage</p></div><select aria-label="History retention" value={retention} onChange={e => setRetention(e.target.value)}><option value="7">7 days</option><option value="30">30 days</option><option value="90">90 days</option><option value="0">Current session</option></select></div></div><div className="panel"><div className="panel-title"><div><h3>Security configuration</h3><p>Local development security status</p></div><LockKeyhole size={19}/></div><InfoRow label="Encryption engine" value="AES-256-GCM"/><InfoRow label="RP2040 binding" value={vaultToken ? "Account-bound" : "Sign in to verify"} warn={!vaultToken}/><InfoRow label="Post-quantum key exchange" value="ML-KEM-768 + X25519"/></div></div>}
    </main><footer className="footer"><span>© 2026 EDQCcage</span><span>Local development · hardware verification required</span></footer></div>
    <input type="file" multiple ref={inputRef} hidden onChange={onFiles} disabled={fileBusy}/>
    {modal && <div className="modal-overlay" onMouseDown={e => { if (e.target === e.currentTarget) closePreview() }}><div className="modal" role="dialog" aria-modal="true" aria-label={modal === 'info' ? 'File details' : modal === 'preview' ? 'File preview' : 'Import files'} style={modal === 'preview' ? {maxWidth:950,width:'min(95vw,950px)'} : undefined}>
      <div className="modal-head"><span>{modal === 'import' ? 'Store files' : modal === 'info' ? 'File details' : modal === 'preview' ? selected?.name || 'Preview' : 'Hardware'}</span><button onClick={closePreview} aria-label="Close"><X size={19}/></button></div>
      {modal === 'import' && <div className="modal-body"><h3>Choose how to store your files</h3><div className="edqc-mode-picker"><label className={`edqc-mode-card ${uploadMode === 'encrypted' ? 'selected' : ''}`}><input type="radio" name="storageMode" checked={uploadMode === 'encrypted'} onChange={() => setUploadMode('encrypted')}/><div><strong>Encrypted storage</strong><small>AES-256-GCM and hybrid key wrapping. Enrolled Pico required to decrypt.</small></div></label><label className={`edqc-mode-card ${uploadMode === 'plain' ? 'selected' : ''}`}><input type="radio" name="storageMode" checked={uploadMode === 'plain'} onChange={() => setUploadMode('plain')}/><div><strong>Normal storage</strong><small>Stored as readable bytes on local disk. No file encryption.</small></div></label></div><div className="drop-zone" onClick={() => { if (!fileBusy) inputRef.current?.click() }}><div><UploadCloud size={30}/></div><strong>{fileBusy ? 'Uploading files…' : 'Choose files to store'}</strong><p>{uploadMode === 'encrypted' ? 'Encryption is applied by the backend with the connected Pico.' : 'Files will be stored without encryption.'}</p><button className="button primary" disabled={fileBusy} onClick={e => { e.stopPropagation(); inputRef.current?.click() }}>Browse files</button></div><p className="edqc-upload-note">Maximum 16 MiB per file. Files are restricted to your signed-in account. Normal files remain readable to anyone with access to server storage.</p></div>}
      {modal === 'preview' && previewUrl && <div className="modal-body">{previewType === 'image' ? <img src={previewUrl} alt={selected?.name || 'File preview'} className="edqc-preview edqc-preview-img"/> : <iframe src={previewUrl} title={selected?.name || 'File preview'} sandbox="allow-downloads" className="edqc-preview"/>}<div className="file-modal-actions"><button className="button primary" onClick={() => selected && void downloadVaultFile(selected)} disabled={fileBusy}><Download size={16}/> Save copy</button><button className="button secondary" onClick={closePreview}>Close preview</button></div></div>}
      {modal === 'info' && selected && <div className="modal-body"><div className="file-modal-title"><FileTile kind={selected.kind}/><div><strong>{selected.name}</strong><small>{selected.mode === 'encrypted' ? 'Encrypted' : 'Normal · Unencrypted'} · {selected.size}</small></div></div><InfoRow label="Stored" value={selected.modified}/><InfoRow label="Protection" value={selected.mode === 'encrypted' ? 'AES-256-GCM · Pico-bound key' : 'None · local plaintext'}/><InfoRow label="Device check" value="Required for every file access"/><div className="file-modal-actions"><button className="button primary" disabled={fileBusy} onClick={() => void openVaultFile(selected)}><Eye size={16}/> {selected.mode === 'encrypted' ? 'Decrypt & open' : 'Open file'}</button><button className="button secondary" disabled={fileBusy} onClick={() => void downloadVaultFile(selected)}><Download size={16}/> {selected.mode === 'encrypted' ? 'Decrypt & download' : 'Download'}</button><button className="button danger" disabled={fileBusy} onClick={() => void deleteVaultFile(selected)}><Trash2 size={16}/> Delete</button></div></div>}
    </div></div>}
    {accountOpen && <div className="modal-overlay" onMouseDown={e => { if (e.target === e.currentTarget) { setAccountPassword(''); setAccountOpen(false) } }}><div className="modal" role="dialog" aria-modal="true" aria-label="Account"><div className="modal-head"><span>{vaultToken ? 'Account' : accountMode === 'login' ? 'Sign in' : 'Create account'}</span><button onClick={() => { setAccountPassword(''); setAccountOpen(false) }} aria-label="Close"><X size={18}/></button></div><div className="modal-body">{vaultToken ? <><p>Signed in as <strong>{accountName}</strong>. Vault operations require your enrolled Pico.</p><button className="button secondary" onClick={() => void logoutAccount()}>Sign out</button></> : <><p>Use your account password and connected Pico to unlock the cage.</p><form className="account-form" onSubmit={e => void submitAccount(e)}><label htmlFor="vault-username">Username</label><input id="vault-username" value={accountDraft} autoComplete="username" minLength={3} maxLength={48} pattern="[A-Za-z0-9_.-]+" onChange={e => setAccountDraft(e.target.value)} required/><label htmlFor="vault-password">Password</label><input id="vault-password" type="password" autoComplete={accountMode === 'login' ? 'current-password' : 'new-password'} minLength={12} maxLength={256} value={accountPassword} onChange={e => setAccountPassword(e.target.value)} required/>{accountError && <p role="alert" className="warning-text">{accountError}</p>}<button className="button primary" disabled={accountBusy} type="submit">{accountBusy ? 'Verifying hardware...' : accountMode === 'login' ? 'Sign in securely' : 'Create account'}</button></form><button className="button secondary" onClick={() => { setAccountMode(p => p === 'login' ? 'register' : 'login'); setAccountError('') }}>{accountMode === 'login' ? 'Create a new account' : 'Already have an account? Sign in'}</button></>}</div></div></div>}

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
