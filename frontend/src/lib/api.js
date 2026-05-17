const BASE = '/api'

function getToken() {
  return (localStorage.getItem('arbor_token') || '').trim()
}

function headers() {
  return {
    'Authorization': `Bearer ${getToken()}`,
    'Content-Type': 'application/json',
  }
}

async function get(path) {
  const res = await fetch(BASE + path, { headers: headers() })
  if (res.status === 401) throw new Error('Unauthorized')
  if (!res.ok) throw new Error(`HTTP ${res.status}`)
  return res.json()
}

export const api = {
  setToken(token) {
    localStorage.setItem('arbor_token', token)
  },
  status: () => get('/status'),
  packages: (search = '') => get(`/packages?search=${encodeURIComponent(search)}`),
  packageInfo: (atom) => get(`/package?atom=${encodeURIComponent(atom)}`),
  search: (q) => get(`/search?q=${encodeURIComponent(q)}`),
  useFlags: (atom) => get(`/package/use-flags?atom=${encodeURIComponent(atom)}`),
  deps: (atom) => get(`/package/deps?atom=${encodeURIComponent(atom)}`),
  depGraph: (atom, depth = 2) => get(`/package/dep-graph?atom=${encodeURIComponent(atom)}&depth=${depth}`),
}

export function wsUpdates(onLine, onDone) {
  const proto = location.protocol === 'https:' ? 'wss' : 'ws'
  const token = getToken()
  const ws = new WebSocket(`${proto}://${location.host}/ws/updates?token=${encodeURIComponent(token)}`)

  ws.onmessage = (e) => {
    const data = JSON.parse(e.data)
    if (data.done) onDone(data.returncode)
    else if (data.line) onLine(data.line)
  }

  ws.onerror = () => onDone(-1)
  return ws
}

// Returns a WebSocket that emits parsed JSON messages; call .close() to abort.
export function wsEmerge(cmd, atom, onMsg, extra = {}) {
  const proto = location.protocol === 'https:' ? 'wss' : 'ws'
  const token = getToken()
  const params = new URLSearchParams({ token, atom, ...extra })
  const url = `${proto}://${location.host}/ws/emerge/${cmd}?${params}`
  const ws = new WebSocket(url)
  let done = false
  ws.onmessage = (e) => { const msg = JSON.parse(e.data); if (msg.done) done = true; onMsg(msg) }
  ws.onerror = () => { if (!done) { done = true; onMsg({ done: true, returncode: -1, error: 'WebSocket error' }) } }
  ws.onclose = () => { if (!done) { done = true; onMsg({ done: true, returncode: -1, error: 'connection closed' }) } }
  return ws
}

// Like wsEmerge but for commands that have no atom (sync, world-update, etc.).
export function wsGlobalEmerge(cmd, onMsg, extra = {}) {
  const proto = location.protocol === 'https:' ? 'wss' : 'ws'
  const token = getToken()
  const params = new URLSearchParams({ token, ...extra })
  const url = `${proto}://${location.host}/ws/emerge/${cmd}?${params}`
  const ws = new WebSocket(url)
  let done = false
  ws.onmessage = (e) => { const msg = JSON.parse(e.data); if (msg.done) done = true; onMsg(msg) }
  ws.onerror = () => { if (!done) { done = true; onMsg({ done: true, returncode: -1, error: 'WebSocket error' }) } }
  ws.onclose = () => { if (!done) { done = true; onMsg({ done: true, returncode: -1, error: 'connection closed' }) } }
  return ws
}

// Close a WebSocket without firing the synthetic {done, returncode:-1}
// onclose/onerror callbacks added by wsEmerge/wsGlobalEmerge/wsJobAttach.
// Use this when the caller intentionally detaches (component unmount,
// user navigated away) and a background job should keep running on the
// server. Without this, the synthetic "done" would mark the local view
// as failed and wipe its persisted job id from localStorage.
export function detachWs(ws) {
  if (!ws) return
  try {
    ws.onmessage = null
    ws.onclose = null
    ws.onerror = null
    ws.close()
  } catch (_) {}
}

// Attach to a background job by ID and stream its output (buffered + live).
export function wsJobAttach(jobId, onMsg) {
  const proto = location.protocol === 'https:' ? 'wss' : 'ws'
  const token = getToken()
  const url = `${proto}://${location.host}/ws/jobs/${encodeURIComponent(jobId)}?token=${encodeURIComponent(token)}`
  const ws = new WebSocket(url)
  let done = false
  ws.onmessage = (e) => { const msg = JSON.parse(e.data); if (msg.done) done = true; onMsg(msg) }
  ws.onerror = () => { if (!done) { done = true; onMsg({ done: true, returncode: -1, error: 'WebSocket error' }) } }
  ws.onclose = () => { if (!done) { done = true; onMsg({ done: true, returncode: -1, error: 'connection closed' }) } }
  return ws
}

async function post(path, body) {
  const res = await fetch(BASE + path, { method: 'POST', headers: headers(), body: JSON.stringify(body) })
  if (res.status === 401) throw new Error('Unauthorized')
  if (!res.ok) throw new Error(`HTTP ${res.status}`)
  return res.json()
}

export const emerge = {
  etcUpdateCheck: () => get('/emerge/etc-update'),
  etcUpdateResolve: (cfg_file, action) => post('/emerge/etc-update/resolve', { cfg_file, action }),
}

export const jobs = {
  status:     (jobId) => get(`/jobs/${encodeURIComponent(jobId)}`),
  listByAtom: (atom)  => get(`/jobs?atom=${encodeURIComponent(atom)}`),
  list:       ()      => get('/jobs'),
  cancel:     (jobId) => post(`/jobs/${encodeURIComponent(jobId)}/cancel`, {}),
}
