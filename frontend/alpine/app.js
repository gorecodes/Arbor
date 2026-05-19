// Arbor — Alpine.js frontend
// Load order: app.js (defer) → alpine.min.js (defer)
// All component factories are exposed on window for Alpine x-data evaluation.
;(function () {
  'use strict'

  // ── API CLIENT ────────────────────────────────────────────────────────────

  const BASE = '/api'

  function _getToken() {
    return (localStorage.getItem('arbor_token') || '').trim()
  }

  function _hdr() {
    return { 'Authorization': 'Bearer ' + _getToken(), 'Content-Type': 'application/json' }
  }

  async function _get(path) {
    const res = await fetch(BASE + path, { headers: _hdr() })
    if (res.status === 401) throw new Error('Unauthorized')
    if (!res.ok) throw new Error('HTTP ' + res.status)
    return res.json()
  }

  async function _post(path, body) {
    const res = await fetch(BASE + path, { method: 'POST', headers: _hdr(), body: JSON.stringify(body) })
    if (res.status === 401) throw new Error('Unauthorized')
    if (!res.ok) throw new Error('HTTP ' + res.status)
    return res.json()
  }

  async function _del(path) {
    const res = await fetch(BASE + path, { method: 'DELETE', headers: _hdr() })
    if (res.status === 401) throw new Error('Unauthorized')
    if (!res.ok) throw new Error('HTTP ' + res.status)
    return res.json()
  }

  const api = {
    setToken(t) { localStorage.setItem('arbor_token', t) },
    status:      ()          => _get('/status'),
    packages:    (q = '')    => _get('/packages?search=' + encodeURIComponent(q)),
    packageInfo: (atom)      => _get('/package?atom=' + encodeURIComponent(atom)),
    search:      (q)         => _get('/search?q=' + encodeURIComponent(q)),
    useFlags:    (atom)      => _get('/package/use-flags?atom=' + encodeURIComponent(atom)),
    deps:        (atom)      => _get('/package/deps?atom=' + encodeURIComponent(atom)),
    depGraph:    (atom, d=2) => _get('/package/dep-graph?atom=' + encodeURIComponent(atom) + '&depth=' + d),
  }

  const emerge = {
    etcUpdateCheck:   ()                 => _get('/emerge/etc-update'),
    etcUpdateResolve: (cfg_file, action) => _post('/emerge/etc-update/resolve', { cfg_file, action }),
  }

  const jobs = {
    status:     (id)   => _get('/jobs/' + encodeURIComponent(id)),
    listByAtom: (atom) => _get('/jobs?atom=' + encodeURIComponent(atom)),
    list:       ()     => _get('/jobs'),
    cancel:     (id)   => _post('/jobs/' + encodeURIComponent(id) + '/cancel', {}),
  }

  const jobHistory = {
    list:   (limit = 50, offset = 0, kind = '') =>
      _get('/history?limit=' + limit + '&offset=' + offset + (kind ? '&kind=' + encodeURIComponent(kind) : '')),
    log:    (id)   => _get('/history/' + encodeURIComponent(id) + '/log'),
    delete: (id)   => _del('/history/' + encodeURIComponent(id)),
    purge:  (days) => _post('/history/purge', { days }),
  }

  const overlays = {
    list:   ()                             => _get('/overlays'),
    add:    (name, sync_type, sync_uri)    => _post('/overlays', { name, sync_type, sync_uri }),
    remove: (name, purge = false)          => _del('/overlays/' + encodeURIComponent(name) + (purge ? '?purge=1' : '')),
  }

  function _wsProto() { return location.protocol === 'https:' ? 'wss' : 'ws' }

  function wsEmerge(cmd, atom, onMsg, extra = {}) {
    const p = new URLSearchParams({ token: _getToken(), atom, ...extra })
    const ws = new WebSocket(_wsProto() + '://' + location.host + '/ws/emerge/' + cmd + '?' + p)
    let done = false
    ws.onmessage = e => { const m = JSON.parse(e.data); if (m.done) done = true; onMsg(m) }
    ws.onerror   = () => { if (!done) { done = true; onMsg({ done: true, returncode: -1, error: 'WebSocket error' }) } }
    ws.onclose   = () => { if (!done) { done = true; onMsg({ done: true, returncode: -1, error: 'connection closed' }) } }
    return ws
  }

  function wsGlobalEmerge(cmd, onMsg, extra = {}) {
    const p = new URLSearchParams({ token: _getToken(), ...extra })
    const ws = new WebSocket(_wsProto() + '://' + location.host + '/ws/emerge/' + cmd + '?' + p)
    let done = false
    ws.onmessage = e => { const m = JSON.parse(e.data); if (m.done) done = true; onMsg(m) }
    ws.onerror   = () => { if (!done) { done = true; onMsg({ done: true, returncode: -1, error: 'WebSocket error' }) } }
    ws.onclose   = () => { if (!done) { done = true; onMsg({ done: true, returncode: -1, error: 'connection closed' }) } }
    return ws
  }

  function wsJobAttach(jobId, onMsg) {
    const p = new URLSearchParams({ token: _getToken() })
    const ws = new WebSocket(_wsProto() + '://' + location.host + '/ws/jobs/' + encodeURIComponent(jobId) + '?' + p)
    let done = false
    ws.onmessage = e => { const m = JSON.parse(e.data); if (m.done) done = true; onMsg(m) }
    ws.onerror   = () => { if (!done) { done = true; onMsg({ done: true, returncode: -1, error: 'WebSocket error' }) } }
    ws.onclose   = () => { if (!done) { done = true; onMsg({ done: true, returncode: -1, error: 'connection closed' }) } }
    return ws
  }

  function wsOverlaySync(name, onMsg) {
    const p = new URLSearchParams({ token: _getToken() })
    const ws = new WebSocket(_wsProto() + '://' + location.host + '/ws/overlays/sync/' + encodeURIComponent(name) + '?' + p)
    let done = false
    ws.onmessage = e => { const m = JSON.parse(e.data); if (m.done) done = true; onMsg(m) }
    ws.onerror   = () => { if (!done) { done = true; onMsg({ done: true, returncode: -1, error: 'WebSocket error' }) } }
    ws.onclose   = () => { if (!done) { done = true; onMsg({ done: true, returncode: -1, error: 'connection closed' }) } }
    return ws
  }

  function detachWs(ws) {
    if (!ws) return
    try { ws.onmessage = null; ws.onclose = null; ws.onerror = null; ws.close() } catch (_) {}
  }

  // ── ROUTER ────────────────────────────────────────────────────────────────

  function navigate(view, param) {
    location.hash = param != null
      ? '/' + view + '/' + encodeURIComponent(param)
      : '/' + view
  }

  function navigateTo(cpv) { navigate('packages', cpv) }
  function navigateBack()  { history.back() }

  function _applyRoute() {
    const hash = location.hash.replace(/^#/, '')
    const r    = Alpine.store('router')
    const pkg  = hash.match(/^\/packages\/(.+)$/)
    const inst = hash.match(/^\/install\/(.+)$/)
    const uni  = hash.match(/^\/uninstall\/(.+)$/)
    const sim  = hash.match(/^\/([^/]+)$/)
    if      (pkg)  { r.selectedPackage = decodeURIComponent(pkg[1]);  r.view = 'packages'  }
    else if (inst) { r.installAtom     = decodeURIComponent(inst[1]); r.view = 'install'   }
    else if (uni)  { r.uninstallAtom   = decodeURIComponent(uni[1]);  r.view = 'uninstall' }
    else if (sim)  { r.view = sim[1]; r.selectedPackage = null }
    else           { r.view = 'dashboard'; r.selectedPackage = null }
  }

  function _initRouter() {
    window.addEventListener('hashchange', _applyRoute)
    if (!location.hash || location.hash === '#' || location.hash === '#/') location.hash = '/dashboard'
    _applyRoute()
  }

  // ── COMPONENT FACTORIES ───────────────────────────────────────────────────

  function loginComponent() {
    return {
      token: '', error: '', loading: false,
      async submit() {
        this.loading = true; this.error = ''
        const t = this.token.trim()
        api.setToken(t)
        try {
          await api.status()
          Alpine.store('auth').set(t)
        } catch {
          this.error = 'Invalid token'; api.setToken('')
        } finally {
          this.loading = false
        }
      }
    }
  }

  function navComponent() {
    return {
      items: [
        { id: 'dashboard', label: 'Dashboard'    },
        { id: 'packages',  label: 'Installed'    },
        { id: 'search',    label: 'Search'        },
        { id: 'updates',   label: 'Maintenance'  },
        { id: 'overlays',  label: 'Overlays'     },
        { id: 'jobs',      label: 'Jobs'          },
      ],
      isActive(id) {
        const r = Alpine.store('router')
        return r.view === id && !r.selectedPackage
      },
      nav(id) { navigate(id) },
      logout() { Alpine.store('auth').logout() }
    }
  }

  function dashboardComponent() {
    return {
      status: null,
      error: null,
      _timer: null,
      init() {
        this._load()
        this.$watch('$store.router.view', v => {
          if (v === 'dashboard') { this._load(); this._scheduleRefresh() }
          else { clearInterval(this._timer); this._timer = null }
        })
        this._scheduleRefresh()
      },
      _scheduleRefresh() {
        clearInterval(this._timer)
        this._timer = setInterval(() => { if (Alpine.store('router').view === 'dashboard') this._load() }, 5000)
      },
      async _load() {
        try { this.status = await api.status() }
        catch(e) { this.error = e.message }
      },
      fmtBytes(b) {
        if (!b) return '0 B'
        const gb = b / 1024 ** 3
        return gb >= 1 ? gb.toFixed(1) + ' GB' : (b / 1024 ** 2).toFixed(0) + ' MB'
      },
      _safePct(used, total) {
        if (!total || isNaN(used) || isNaN(total)) return 0
        return Math.min(100, Math.max(0, Math.round((used / total) * 100)))
      },
      diskPct() { return this.status ? this._safePct(this.status.disk_used, this.status.disk_total) : 0 },
      memPct()  { return this.status ? this._safePct(this.status.mem_used,  this.status.mem_total)  : 0 },
      cpuPct()  { return this.status ? Math.round(this.status.cpu_pct || 0) : 0 },
      // Returns :style string for the conic-gradient ring gauge.
      // Semi-circle: starts at left (270deg), fills clockwise over the top to right.
      // Outer div (150x75 overflow:hidden) clips to show only the top half of the 150x150 circle.
      gaugeStyle(pct) {
        const p = isNaN(pct) || !isFinite(pct) ? 0 : Math.max(0, Math.min(100, pct))
        const color = p >= 85 ? '#f85149' : p >= 60 ? '#d29922' : '#3fb950'
        const deg = (p / 100) * 180
        return `background:conic-gradient(from 270deg,${color} 0deg ${deg}deg,#21262d ${deg}deg 180deg,transparent 180deg 360deg)`
      }
    }
  }

  function packageListComponent() {
    return {
      packages: [], loading: true, _timer: null,
      search: Alpine.store('router').packageListSearch,
      init() {
        this._load()
        // reload when navigating (back) to the packages list
        this.$watch('$store.router.view', v => {
          if (v === 'packages' && !Alpine.store('router').selectedPackage) this._load()
        })
        this.$watch('$store.router.selectedPackage', v => {
          if (!v && Alpine.store('router').view === 'packages') this._load()
        })
      },
      async _load() {
        this.loading = true
        try { this.packages = await api.packages(this.search) }
        finally { this.loading = false }
      },
      onInput() {
        Alpine.store('router').packageListSearch = this.search
        clearTimeout(this._timer)
        this._timer = setTimeout(() => this._load(), 300)
      },
      fmtDate(ts) {
        if (!ts) return '—'
        return new Date(parseInt(ts) * 1000).toLocaleDateString()
      }
    }
  }

  function searchComponent() {
    return {
      query: Alpine.store('router').searchViewQuery,
      results: [], loading: false, searched: false, _timer: null,
      init() {
        if (this.query.length >= 2) this._search()
        this.$watch('$store.router.view', v => {
          if (v === 'search' && this.query.length >= 2 && !this.searched) this._search()
        })
      },
      onInput() {
        Alpine.store('router').searchViewQuery = this.query
        clearTimeout(this._timer)
        if (this.query.length < 2) { this.results = []; this.searched = false; return }
        this._timer = setTimeout(() => this._search(), 350)
      },
      async _search() {
        this.loading = true; this.searched = true
        try { this.results = await api.search(this.query) }
        finally { this.loading = false }
      }
    }
  }

  // ── EmergeOptions mixin ────────────────────────────────────────────────────
  // Returns a plain object to be spread-merged into a parent x-data factory.
  // All properties are prefixed `eo` to avoid conflicts with parent state.
  // The parent calls this.eoLoad() in its own init() and reads this.eoOpts()
  // when building WebSocket params.
  function makeEmergeOptions(storageKey, schema, command, baseFlags) {
    return {
      _eoStorageKey: storageKey,
      _eoSchema: schema || [],
      _eoCommand: command || 'emerge',
      _eoBaseFlags: baseFlags || [],
      eoChecked: {}, eoValues: {}, eoOpen: false,
      eoLoad() {
        try {
          const saved = JSON.parse(localStorage.getItem(this._eoStorageKey) || '{}') || {}
          this.eoChecked = saved.checked || {}
          this.eoValues  = saved.values  || {}
        } catch (_) { this.eoChecked = {}; this.eoValues = {} }
      },
      eoSave() {
        try { localStorage.setItem(this._eoStorageKey, JSON.stringify({ checked: this.eoChecked, values: this.eoValues })) } catch (_) {}
      },
      eoToggle(key) {
        this.eoChecked = { ...this.eoChecked, [key]: !this.eoChecked[key] }
        this.eoSave()
      },
      _eoValueFor(item) {
        const v = this.eoValues[item.key]
        return v === undefined || v === null || v === '' ? item.default : v
      },
      eoSetValue(item, raw) {
        this.eoValues = { ...this.eoValues, [item.key]: raw }
        this.eoSave()
      },
      _eoClamped(item) {
        let n = parseInt(this._eoValueFor(item), 10)
        if (!Number.isFinite(n)) n = item.default
        if (n < item.min) n = item.min
        if (n > item.max) n = item.max
        return n
      },
      _eoFlagFor(item) {
        return item.type === 'int'
          ? item.label.replace('N', this._eoClamped(item))
          : item.label
      },
      eoOpts() {
        return this._eoSchema
          .filter(s => this.eoChecked[s.key])
          .map(s => s.type === 'int' ? `${s.key}:${this._eoClamped(s)}` : s.key)
          .join(',')
      },
      eoUserFlags() {
        return this._eoSchema
          .filter(s => this.eoChecked[s.key])
          .map(s => this._eoFlagFor(s))
      },
      eoActiveCount() { return this.eoUserFlags().length }
    }
  }

  // ── DepGraph ────────────────────────────────────────────────────────────────
  // Recursive tree via imperative DOM building (_render) instead of Svelte
  // {#snippet} recursion. The tree data model is identical to the Svelte version.
  function depGraphComponent() {
    return {
      root: null, error: null, loading: true,
      init() {
        const atom = Alpine.store('router').selectedPackage
        if (atom) this._load(atom)
        this.$watch('$store.router.selectedPackage', atom => {
          if (atom && Alpine.store('router').view === 'packages') this._load(atom)
        })
      },
      async _load(atom) {
        this.root = null; this.error = null; this.loading = true
        try {
          const data = await api.depGraph(atom, 1)
          if (data?.error) { this.error = data.error; return }
          const byId = {}
          data.nodes.forEach(n => { byId[n.id] = n })
          const rootInfo = byId[data.root] || { id: data.root, cpv: data.root, installed: false }
          const directCps = data.edges
            .filter(e => e.source === data.root && byId[e.target])
            .map(e => e.target)
          this.root = {
            cp: data.root, cpv: rootInfo.cpv, installed: rootInfo.installed,
            expanded: true, loading: false, error: null, circular: false,
            children: directCps.map(cp => this._mknode(byId[cp], new Set([data.root])))
          }
          this.$nextTick(() => this._render())
        } catch(e) {
          this.error = e.message
        } finally {
          this.loading = false
        }
      },
      _mknode(n, selfAndAncestors) {
        return {
          cp: n.id, cpv: n.cpv, installed: n.installed,
          expanded: false, loading: false, error: null,
          circular: selfAndAncestors.has(n.id), children: null
        }
      },
      async _toggle(node, ancestors) {
        if (node.circular) return
        if (node.expanded) { node.expanded = false; this._render(); return }
        node.expanded = true
        this._render()
        if (node.children !== null) return
        node.loading = true
        this._render()
        const selfAndAncestors = new Set([...ancestors, node.cp])
        try {
          const data = await api.depGraph(node.cpv, 1)
          if (data?.error) { node.error = data.error; node.children = []; return }
          const byId = {}
          data.nodes.forEach(n => { byId[n.id] = n })
          const childCps = data.edges
            .filter(e => e.source === data.root && byId[e.target])
            .map(e => e.target)
          node.children = childCps.map(cp => this._mknode(byId[cp], selfAndAncestors))
        } catch(e) {
          node.error = e.message; node.children = []
        } finally {
          node.loading = false
          this._render()
        }
      },
      _render() {
        const container = this.$refs.treeRoot
        if (!container) return
        container.innerHTML = ''
        if (!this.root) return
        const ul = document.createElement('ul')
        ul.className = 'dg-tree-root'
        ul.appendChild(this._buildNode(this.root, new Set(), true))
        container.appendChild(ul)
      },
      _buildNode(n, ancestors, isRoot) {
        const li = document.createElement('li')
        li.className = 'dg-item'
        const row = document.createElement('div')
        row.className = 'dg-row' + (isRoot ? ' is-root' : '')
        if (n.circular) {
          const circ = document.createElement('span')
          circ.className = 'dg-tog dg-circ'
          circ.title = 'circular dependency'
          circ.textContent = '↺'
          row.appendChild(circ)
        } else {
          const tog = document.createElement('button')
          tog.className = 'dg-tog'
          tog.textContent = n.loading ? '…' : n.expanded ? '▾' : '▸'
          tog.addEventListener('click', () => this._toggle(n, ancestors))
          row.appendChild(tog)
        }
        const dot = document.createElement('span')
        dot.className = 'dg-dot' + (n.installed ? ' inst' : '')
        dot.addEventListener('click', () => navigateTo(n.cpv))
        row.appendChild(dot)
        const pkg = document.createElement('button')
        pkg.className = 'dg-pkg'
        pkg.textContent = n.cp.split('/')[1] || n.cp
        pkg.addEventListener('click', () => navigateTo(n.cpv))
        row.appendChild(pkg)
        const cat = document.createElement('span')
        cat.className = 'dg-cat'
        cat.textContent = n.cp.split('/')[0]
        row.appendChild(cat)
        if (!n.installed) {
          const b = document.createElement('span')
          b.className = 'dg-badge dg-miss'; b.textContent = 'not installed'
          row.appendChild(b)
        }
        if (n.error) {
          const b = document.createElement('span')
          b.className = 'dg-badge dg-err-badge'; b.textContent = n.error
          row.appendChild(b)
        }
        li.appendChild(row)
        if (n.expanded) {
          const ul = document.createElement('ul')
          ul.className = 'dg-list'
          if (n.children === null) {
            const li2 = document.createElement('li'); li2.className = 'dg-msg dg-indent'; li2.textContent = 'Loading…'
            ul.appendChild(li2)
          } else if (n.children.length === 0) {
            const li2 = document.createElement('li'); li2.className = 'dg-msg dg-indent dg-muted'; li2.textContent = 'no runtime deps'
            ul.appendChild(li2)
          } else {
            const next = new Set([...ancestors, n.cp])
            for (const child of n.children) ul.appendChild(this._buildNode(child, next, false))
          }
          li.appendChild(ul)
        }
        return li
      }
    }
  }

  function packageDetailComponent() {
    return {
      info: null, flags: null, deps: null,
      tab: 'info',
      error: null, flagsError: null, depsError: null,
      init() {
        const atom = Alpine.store('router').selectedPackage
        if (atom) this._load(atom)
        this.$watch('$store.router.selectedPackage', atom => {
          if (atom && Alpine.store('router').view === 'packages') this._load(atom)
        })
      },
      async _load(atom) {
        this.info = null; this.flags = null; this.deps = null
        this.error = null; this.flagsError = null; this.depsError = null
        this.tab = 'info'
        const [infoRes, flagsRes, depsRes] = await Promise.allSettled([
          api.packageInfo(atom),
          api.useFlags(atom),
          api.deps(atom),
        ])
        if (infoRes.status === 'fulfilled') {
          this.info = Array.isArray(infoRes.value) ? infoRes.value[0] : infoRes.value
        } else {
          this.error = infoRes.reason?.message ?? 'Failed to load package info'
        }
        this.flags = flagsRes.status === 'fulfilled' ? flagsRes.value : null
        if (flagsRes.status === 'rejected') this.flagsError = flagsRes.reason?.message ?? 'Failed to load use flags'
        this.deps = depsRes.status === 'fulfilled' ? depsRes.value : null
        if (depsRes.status === 'rejected') this.depsError = depsRes.reason?.message ?? 'Failed to load deps'
      },
      validHomepage() { return this.info?.HOMEPAGE && /^https?:\/\//.test(this.info.HOMEPAGE) },
      fmtSize(b) {
        if (!b) return '—'
        const kb = parseInt(b) / 1024
        return kb > 1024 ? (kb / 1024).toFixed(1) + ' MB' : kb.toFixed(0) + ' KB'
      },
      fmtDate(ts) {
        if (!ts) return '—'
        return new Date(parseInt(ts) * 1000).toLocaleString()
      }
    }
  }

  function jobsViewComponent() {
    const MAX_LINES = 5000
    const FLUSH_MS = 80
    const PAGE_SIZE = 50
    return {
      // active tab
      tab: 'active',
      // active jobs
      jobList: [], loading: true, error: null,
      expanded: null, activeLines: [], termWs: null,
      _refreshTimer: null, _pending: [], _flushTimer: null,
      // history tab
      histList: [], histTotal: 0, histOffset: 0, histLoading: false, histError: null,
      histKind: '',
      histExpanded: null, histLines: [], histLinesLoading: false,
      // purge
      purgeDays: 30, purgeMsg: null,
      init() {
        this._load().then(() => this._scheduleRefresh())
        this.$watch('$store.router.view', v => { if (v === 'jobs') { this._load(); if (this.tab === 'history') this._loadHistory(0) } })
      },
      switchTab(t) {
        this.tab = t
        if (t === 'history' && this.histList.length === 0) this._loadHistory(0)
      },
      // ── Active ────────────────────────────────────────────────────────────
      async _load() {
        const prevIds = new Set(this.jobList.map(j => j.job_id))
        try { this.jobList = await jobs.list(); this.error = null }
        catch(e) { this.error = e.message }
        finally { this.loading = false }
        // if any previously-running job has disappeared (finished → archived), refresh history
        const anyFinished = [...prevIds].some(id => !this.jobList.find(j => j.job_id === id))
        if (anyFinished) this._loadHistory(0)
      },
      _scheduleRefresh() {
        clearTimeout(this._refreshTimer)
        const delay = this.jobList.some(j => j.status === 'running') ? 3000 : 15000
        this._refreshTimer = setTimeout(async () => { await this._load(); this._scheduleRefresh() }, delay)
      },
      _pushLine(l) {
        this._pending.push(l)
        if (this._flushTimer === null) this._flushTimer = setTimeout(() => this._flushLines(), FLUSH_MS)
      },
      _flushLines() {
        this._flushTimer = null
        if (this._pending.length === 0) return
        const next = this.activeLines.concat(this._pending)
        this._pending = []
        this.activeLines = next.length > MAX_LINES ? next.slice(next.length - MAX_LINES) : next
        this.$nextTick(() => {
          const el = document.getElementById('jv-terminal-' + this.expanded)
          if (el) el.scrollTop = el.scrollHeight
        })
      },
      _resetLines() {
        if (this._flushTimer !== null) { clearTimeout(this._flushTimer); this._flushTimer = null }
        this._pending = []; this.activeLines = []
      },
      _closeStream() {
        detachWs(this.termWs); this.termWs = null
        if (this._flushTimer !== null) { clearTimeout(this._flushTimer); this._flushTimer = null }
      },
      toggle(jobId) {
        if (this.expanded === jobId) { this._closeStream(); this.expanded = null; this._resetLines(); return }
        this._closeStream(); this.expanded = jobId; this._resetLines()
        this.termWs = wsJobAttach(jobId, (msg) => {
          if (msg.line !== undefined) this._pushLine(msg.line)
          if (msg.done) { this._flushLines(); this.termWs = null; this._load() }
        })
      },
      async kill(jobId, e) {
        e.stopPropagation()
        if (!confirm('Kill this job?')) return
        try { await jobs.cancel(jobId); await this._load() }
        catch(e) { alert('Kill failed: ' + e.message) }
      },
      openPanel(job, e) {
        e.stopPropagation()
        const kind = job.kind || '', atom = job.atom || ''
        const maint = new Set(['world','world-pretend','depclean','depclean-pretend','preserved-rebuild','sync'])
        if (maint.has(kind) || atom.startsWith('@')) navigate('updates')
        else if (kind === 'uninstall' || atom.startsWith('uninstall:')) navigate('uninstall', atom.replace(/^uninstall:/, ''))
        else navigate('install', atom)
      },
      // ── History ───────────────────────────────────────────────────────────
      async _loadHistory(offset) {
        this.histLoading = true; this.histError = null
        try {
          const res = await jobHistory.list(PAGE_SIZE, offset, this.histKind)
          if (offset === 0) this.histList = res.items
          else this.histList = this.histList.concat(res.items)
          this.histTotal = res.total
          this.histOffset = offset + res.items.length
        } catch(e) { this.histError = e.message }
        finally { this.histLoading = false }
      },
      filterHistory() { this._loadHistory(0) },
      loadMore() { this._loadHistory(this.histOffset) },
      async toggleHist(jobId) {
        if (this.histExpanded === jobId) { this.histExpanded = null; this.histLines = []; return }
        this.histExpanded = jobId; this.histLines = []; this.histLinesLoading = true
        try {
          const res = await jobHistory.log(jobId)
          this.histLines = (res.log || '').split('\n')
        } catch(e) { this.histLines = ['Error: ' + e.message] }
        finally { this.histLinesLoading = false }
        this.$nextTick(() => {
          const el = document.getElementById('hv-terminal-' + jobId)
          if (el) el.scrollTop = el.scrollHeight
        })
      },
      async deleteEntry(jobId, e) {
        e.stopPropagation()
        if (!confirm('Delete this history entry?')) return
        try {
          await jobHistory.delete(jobId)
          this.histList = this.histList.filter(j => j.job_id !== jobId)
          this.histTotal = Math.max(0, this.histTotal - 1)
          if (this.histExpanded === jobId) { this.histExpanded = null; this.histLines = [] }
        } catch(e) { alert('Delete failed: ' + e.message) }
      },
      async purge() {
        if (!confirm('Delete all history older than ' + this.purgeDays + ' days?')) return
        try {
          const res = await jobHistory.purge(this.purgeDays)
          this.purgeMsg = 'Deleted ' + res.deleted + ' entries.'
          this._loadHistory(0)
          setTimeout(() => { this.purgeMsg = null }, 3000)
        } catch(e) { alert('Purge failed: ' + e.message) }
      },
      histHasMore() { return this.histOffset < this.histTotal },
      histRemaining() { return this.histTotal - this.histOffset },
      // ── Shared helpers ────────────────────────────────────────────────────
      statusLabel(j) {
        if (j.status === 'running') return 'running'
        if (j.status === 'done' && j.returncode === 0) return 'done'
        if (j.status === 'done') return 'exit ' + j.returncode
        return j.status
      },
      statusClass(j) {
        if (j.status === 'running') return 'run'
        if (j.status === 'done' && j.returncode === 0) return 'ok'
        return 'err'
      },
      ago(ts) {
        if (!ts) return ''
        const s = Math.floor(Date.now() / 1000 - ts)
        if (s < 60) return s + 's ago'
        if (s < 3600) return Math.floor(s / 60) + 'm ago'
        if (s < 86400) return Math.floor(s / 3600) + 'h ago'
        return Math.floor(s / 86400) + 'd ago'
      },
      duration(j) {
        if (!j.finished_at || !j.created_at) return ''
        const s = Math.round(j.finished_at - j.created_at)
        if (s < 60) return s + 's'
        if (s < 3600) return Math.floor(s / 60) + 'm ' + (s % 60) + 's'
        return Math.floor(s / 3600) + 'h ' + Math.floor((s % 3600) / 60) + 'm'
      },
      lineClass(l) {
        if (/^\[ebuild/.test(l) || /^>>> /.test(l) || /Completed/.test(l)) return 'hi-ok'
        if (/^!!!/.test(l) || /[Ee]rror/.test(l)) return 'hi-err'
        if (/^ \* /.test(l) || /^NOTE:/.test(l)) return 'hi-warn'
        return ''
      }
    }
  }

  function uninstallComponent() {
    const MAX_LINES = 5000
    const FLUSH_MS = 80
    return {
      step: 'pretend', lines: [], running: false, returncode: null, ws: null,
      _pending: [], _flushTimer: null,
      init() {
        const atom = Alpine.store('router').uninstallAtom
        if (atom) this._setupForAtom(atom)
        this.$watch('$store.router.uninstallAtom', atom => { if (atom) this._setupForAtom(atom) })
      },
      async _setupForAtom(atom) {
        detachWs(this.ws); this.ws = null
        this._resetLines()
        this.step = 'pretend'; this.running = false; this.returncode = null
        const savedId = localStorage.getItem('arbor_uninstall_' + atom)
        if (savedId) {
          try {
            const st = await jobs.status(savedId)
            if (st.status === 'running') { this._attachToJob(atom, savedId); return }
            if (st.status === 'done' && st.returncode === 0) {
              localStorage.removeItem('arbor_uninstall_' + atom); this.step = 'done'; return
            }
          } catch (_) {}
          localStorage.removeItem('arbor_uninstall_' + atom)
        }
        try {
          const active = await jobs.listByAtom(atom)
          const running = active.find(j => j.status === 'running' && j.kind === 'uninstall')
          if (running) { localStorage.setItem('arbor_uninstall_' + atom, running.job_id); this._attachToJob(atom, running.job_id); return }
        } catch (_) {}
      },
      _pushLine(l) {
        this._pending.push(l)
        if (this._flushTimer === null) this._flushTimer = setTimeout(() => this._flushLines(), FLUSH_MS)
      },
      _flushLines() {
        this._flushTimer = null
        if (this._pending.length === 0) return
        const next = this.lines.concat(this._pending)
        this._pending = []
        this.lines = next.length > MAX_LINES ? next.slice(next.length - MAX_LINES) : next
        this.$nextTick(() => {
          if (this.$refs.uninstallTerm) this.$refs.uninstallTerm.scrollTop = this.$refs.uninstallTerm.scrollHeight
        })
      },
      _resetLines() {
        if (this._flushTimer !== null) { clearTimeout(this._flushTimer); this._flushTimer = null }
        this._pending = []; this.lines = []
      },
      runPretend() {
        const atom = Alpine.store('router').uninstallAtom
        this.step = 'pretend'; this.returncode = null; this._resetLines(); this.running = true
        this.ws = wsEmerge('uninstall-pretend', atom, (msg) => {
          if (msg.line !== undefined) this._pushLine(msg.line)
          if (msg.done) { this._flushLines(); this.running = false; this.returncode = msg.returncode ?? null; this.ws = null }
        })
      },
      runUninstall() {
        const atom = Alpine.store('router').uninstallAtom
        this.step = 'uninstall'; this.returncode = null; this._resetLines(); this.running = true
        this.ws = wsEmerge('uninstall', atom, (msg) => {
          if (msg.job_id) { localStorage.setItem('arbor_uninstall_' + atom, msg.job_id); return }
          if (msg.line !== undefined) this._pushLine(msg.line)
          if (msg.done) {
            this._flushLines(); this.running = false; this.returncode = msg.returncode ?? null; this.ws = null
            localStorage.removeItem('arbor_uninstall_' + atom)
            if (this.returncode === 0) this.step = 'done'
          }
        })
      },
      retry() { this.step === 'pretend' ? this.runPretend() : this.runUninstall() },
      _attachToJob(atom, id) {
        this.step = 'uninstall'; this.running = true; this._resetLines()
        let gotLines = false
        this.ws = wsJobAttach(id, (msg) => {
          if (msg.line !== undefined) { this._pushLine(msg.line); gotLines = true }
          if (msg.done) {
            this._flushLines(); this.running = false; this.returncode = msg.returncode ?? -1; this.ws = null
            localStorage.removeItem('arbor_uninstall_' + atom)
            if (msg.connectionLost || (this.returncode !== 0 && !gotLines)) {
              this.returncode = null; this.runUninstall()
            } else if (this.returncode === 0) {
              this.step = 'done'
            }
          }
        })
      },
      goBack() {
        detachWs(this.ws); this.ws = null
        navigate('packages', Alpine.store('router').uninstallAtom)
      },
      stepTitle() {
        const atom = Alpine.store('router').uninstallAtom || ''
        if (this.step === 'pretend')   return 'Pretend uninstall — ' + atom
        if (this.step === 'uninstall') return 'Uninstalling — ' + atom
        return 'Done — ' + atom
      },
      statusClass() { return this.returncode === 0 ? 'ok' : this.returncode !== null ? 'err' : '' },
      statusText()  {
        return this.returncode === 0
          ? 'removed successfully'
          : this.returncode !== null ? 'failed (exit ' + this.returncode + ')' : ''
      },
      lineClass(l) {
        if (/^>>> /.test(l) || /Completed/.test(l) || /^--- /.test(l)) return 'hi-ok'
        if (/^!!!/.test(l) || /[Ee]rror/.test(l)) return 'hi-err'
        if (/^ \* /.test(l) || /^NOTE:/.test(l)) return 'hi-warn'
        return ''
      }
    }
  }

  // ── InstallView ─────────────────────────────────────────────────────────────
  const INSTALL_OPTS_SCHEMA = [
    { type: 'bool', key: 'keep-going',  label: '--keep-going',  desc: "Don't bail on the first failure: skip the broken package and keep building the rest." },
    { type: 'bool', key: 'usepkg',      label: '--usepkg',      desc: 'Use a matching binary package if one is available instead of compiling (much faster).' },
    { type: 'bool', key: 'buildpkg',    label: '--buildpkg',    desc: 'Save a binary package for every installed atom into /var/cache/binpkgs (useful for backups or reuse).' },
    { type: 'bool', key: 'oneshot',     label: '--oneshot',     desc: "Install without adding the atom to @world — it won't be pulled by future updates." },
    { type: 'bool', key: 'quiet-build', label: '--quiet-build', desc: 'Show only major phases and hide the verbose compile output.' },
    { type: 'int',  key: 'jobs',        label: '--jobs=N',      desc: 'Build up to N packages in parallel. Helps when dependencies are independent; uses much more RAM/CPU.', min: 1,  max: 64,   default: 4  },
    { type: 'int',  key: 'backtrack',   label: '--backtrack=N', desc: 'How many alternative resolutions portage may try when it hits a conflict. Raise if you see "backtrack limit exceeded".',     min: 0,  max: 1000, default: 30 },
  ]

  function installComponent() {
    const MAX_LINES = 5000
    const FLUSH_MS = 80
    return {
      ...makeEmergeOptions('arbor_opts_install', INSTALL_OPTS_SCHEMA, 'emerge', ['--verbose', '--color=n']),
      step: 'pretend', lines: [], running: false, returncode: null, ws: null,
      needsUnmask: false, etcFiles: [],
      _pending: [], _flushTimer: null, _attachRetries: 0,
      init() {
        this.eoLoad()
        const atom = Alpine.store('router').installAtom
        if (atom) this._setupForAtom(atom)
        this.$watch('$store.router.installAtom', atom => { if (atom) this._setupForAtom(atom) })
      },
      async _setupForAtom(atom) {
        detachWs(this.ws); this.ws = null
        this._resetLines()
        this.step = 'pretend'; this.running = false; this.returncode = null
        this.needsUnmask = false; this.etcFiles = []; this._attachRetries = 0
        const savedId = localStorage.getItem('arbor_job_' + atom)
        if (savedId) {
          try {
            const st = await jobs.status(savedId)
            if (st.status === 'running') { this._attachToJob(atom, savedId); return }
            if (st.status === 'done' && st.returncode === 0) {
              localStorage.removeItem('arbor_job_' + atom)
              await this._afterInstallDone(0); return
            }
          } catch (_) {}
          localStorage.removeItem('arbor_job_' + atom)
        }
        try {
          const active = await jobs.listByAtom(atom)
          const running = active.find(j => j.status === 'running')
          if (running) { localStorage.setItem('arbor_job_' + atom, running.job_id); this._attachToJob(atom, running.job_id); return }
        } catch (_) {}
      },
      _pushLine(l) {
        this._pending.push(l)
        if (this._flushTimer === null) this._flushTimer = setTimeout(() => this._flushLines(), FLUSH_MS)
      },
      _flushLines() {
        this._flushTimer = null
        if (this._pending.length === 0) return
        const next = this.lines.concat(this._pending)
        this._pending = []
        this.lines = next.length > MAX_LINES ? next.slice(next.length - MAX_LINES) : next
        this.$nextTick(() => {
          if (this.$refs.installTerm) this.$refs.installTerm.scrollTop = this.$refs.installTerm.scrollHeight
        })
      },
      _resetLines() {
        if (this._flushTimer !== null) { clearTimeout(this._flushTimer); this._flushTimer = null }
        this._pending = []; this.lines = []
      },
      runPretend(clean) {
        const atom = Alpine.store('router').installAtom
        this.step = 'pretend'; this.returncode = null; this.needsUnmask = false
        this._resetLines(); this.running = true
        const extra = { opts: this.eoOpts() }
        if (clean) extra.clean = '1'
        this.ws = wsEmerge('pretend', atom, (msg) => {
          if (msg.line !== undefined) this._pushLine(msg.line)
          if (msg.done) {
            this._flushLines(); this.running = false
            this.returncode = msg.returncode ?? null; this.ws = null
            this.needsUnmask = !!msg.needs_unmask
          }
        }, extra)
      },
      runAutounmask() {
        const atom = Alpine.store('router').installAtom
        this.step = 'autounmask'; this.returncode = null
        this._resetLines(); this.running = true
        this.ws = wsEmerge('autounmask', atom, (msg) => {
          if (msg.line !== undefined) this._pushLine(msg.line)
          if (msg.done) {
            this._flushLines(); this.running = false
            this.returncode = msg.returncode ?? null; this.ws = null
            setTimeout(() => this.runPretend(true), 600)
          }
        })
      },
      async _afterInstallDone(rc) {
        if (rc === 0) {
          try {
            const pending = await emerge.etcUpdateCheck()
            if (pending.length > 0) {
              this.etcFiles = pending.map(f => ({ ...f, resolved: false }))
              this.step = 'etcupdate'; return
            }
          } catch (_) {}
          this.step = 'done'
        }
      },
      _attachToJob(atom, id) {
        this.step = 'install'; this.running = true; this._resetLines()
        let gotLines = false
        this.ws = wsJobAttach(id, async (msg) => {
          if (msg.line !== undefined) { this._pushLine(msg.line); gotLines = true }
          if (msg.done) {
            this._flushLines(); this.running = false
            this.returncode = msg.returncode ?? -1; this.ws = null
            localStorage.removeItem('arbor_job_' + atom)
            if (this.returncode !== 0 && !gotLines && this._attachRetries < 1) {
              this._attachRetries++; this.returncode = null; this.runInstall()
            } else {
              this._attachRetries = 0
              await this._afterInstallDone(this.returncode)
            }
          }
        })
      },
      runInstall() {
        const atom = Alpine.store('router').installAtom
        this.step = 'install'; this.returncode = null
        this._resetLines(); this.running = true
        this.ws = wsEmerge('install', atom, async (msg) => {
          if (msg.job_id) { localStorage.setItem('arbor_job_' + atom, msg.job_id); return }
          if (msg.line !== undefined) this._pushLine(msg.line)
          if (msg.done) {
            this._flushLines(); this.running = false
            this.returncode = msg.returncode ?? null; this.ws = null
            localStorage.removeItem('arbor_job_' + atom)
            await this._afterInstallDone(msg.returncode ?? -1)
          }
        }, { opts: this.eoOpts() })
      },
      async resolveFile(file, action) {
        try {
          await emerge.etcUpdateResolve(file.cfg_file, action)
          this.etcFiles = this.etcFiles.map(f => f.cfg_file === file.cfg_file ? { ...f, resolved: true, action } : f)
          if (this.etcFiles.every(f => f.resolved)) this.step = 'done'
        } catch(e) { alert('etc-update error: ' + e.message) }
      },
      retry() { this.step === 'install' ? this.runInstall() : this.runAutounmask() },
      goBack() { detachWs(this.ws); this.ws = null; navigate('packages', Alpine.store('router').installAtom) },
      stepTitle() {
        const atom = Alpine.store('router').installAtom || ''
        if (this.step === 'pretend')    return 'Pretend — ' + atom
        if (this.step === 'autounmask') return 'Accepting keywords — ' + atom
        if (this.step === 'install')    return 'Installing — ' + atom
        if (this.step === 'etcupdate')  return 'Config updates'
        return 'Done — ' + atom
      },
      statusClass() { return this.returncode === 0 ? 'ok' : this.returncode !== null ? 'err' : '' },
      statusText() {
        return this.returncode === 0
          ? 'completed successfully'
          : this.returncode !== null ? 'failed (exit ' + this.returncode + ')' : ''
      },
      lineClass(l) {
        if (/^\[ebuild/.test(l) || /^>>> /.test(l) || /Completed/.test(l)) return 'hi-ok'
        if (/^!!!/.test(l) || /[Ee]rror/.test(l)) return 'hi-err'
        if (/^ \* /.test(l) || /^NOTE:/.test(l) || /autounmask/.test(l)) return 'hi-warn'
        return ''
      }
    }
  }

  // ── UpdatesView (Maintenance) ────────────────────────────────────────────────
  const UPDATE_OPTS_SCHEMA = [
    { type: 'bool', key: 'keep-going',  label: '--keep-going',  desc: "Don't bail on the first failure: skip the broken package and keep building the rest." },
    { type: 'bool', key: 'usepkg',      label: '--usepkg',      desc: 'Use a matching binary package if one is available instead of compiling (much faster).' },
    { type: 'bool', key: 'buildpkg',    label: '--buildpkg',    desc: 'Save a binary package for every installed atom into /var/cache/binpkgs (useful for backups or reuse).' },
    { type: 'bool', key: 'quiet-build', label: '--quiet-build', desc: 'Show only major phases and hide the verbose compile output.' },
    { type: 'int',  key: 'jobs',        label: '--jobs=N',      desc: 'Build up to N packages in parallel. Helps when dependencies are independent; uses much more RAM/CPU.', min: 1, max: 64,   default: 4  },
    { type: 'int',  key: 'backtrack',   label: '--backtrack=N', desc: 'How many alternative resolutions portage may try when it hits a conflict. Raise if you see "backtrack limit exceeded".',     min: 0, max: 1000, default: 30 },
  ]

  const _JOB_META = {
    worldUpdate:     { storage: 'arbor_job_@world',             atom: '@world',             attachOnDone: false },
    depclean:        { storage: 'arbor_job_@depclean',          atom: '@depclean',          attachOnDone: false },
    preserved:       { storage: 'arbor_job_@preserved-rebuild', atom: '@preserved-rebuild', attachOnDone: false },
    sync:            { storage: 'arbor_job_@sync',              atom: '@sync',              attachOnDone: true  },
    worldPretend:    { storage: 'arbor_job_@world-pretend',     atom: '@world-pretend',     attachOnDone: true  },
    depcleanPretend: { storage: 'arbor_job_@depclean-pretend',  atom: '@depclean-pretend',  attachOnDone: true  },
  }

  function updatesComponent() {
    const MAX_LINES = 5000
    const mkOp = (expanded) => ({ lines: [], running: false, rc: null, ws: null, expanded })
    return {
      ...makeEmergeOptions('arbor_opts_world', UPDATE_OPTS_SCHEMA, 'emerge', ['--update', '--deep', '--newuse', '--with-bdeps=y', '--color=n']),
      sync:         mkOp(true),
      worldPretend: mkOp(false),
      worldUpdate:  mkOp(false),
      depclean:     { ...mkOp(false), dcStep: 'idle' },
      preserved:    mkOp(false),
      init() {
        this.eoLoad()
        this.$watch('$store.router.view', v => { if (v === 'updates') this._resumeAll() })
        this._resumeAll()
      },
      async _resumeAll() {
        await Promise.all([
          this._resumeIfRunning('worldUpdate',  id => this._attachWorldUpdate(id)),
          this._resumeIfRunning('depclean',     id => this._attachDepclean(id)).then(() => {
            if (!this.depclean.ws && !localStorage.getItem('arbor_depclean_ran')) return this._resumeIfRunning('depcleanPretend', id => this._attachDepcleanPretend(id))
          }),
          this._resumeIfRunning('preserved',    id => this._attachPreserved(id)),
          this._resumeIfRunning('sync',         id => this._attachSync(id)),
          this._resumeIfRunning('worldPretend', id => this._attachWorldPretend(id)),
        ])
      },
      async _resumeIfRunning(name, attach) {
        const meta = _JOB_META[name]
        let candidate = localStorage.getItem(meta.storage)
        if (!candidate) {
          try {
            const active = await jobs.listByAtom(meta.atom)
            const running = active.find(j => j.status === 'running')
            if (running) { candidate = running.job_id }
            else if (meta.attachOnDone) {
              const done = [...active].sort((a, b) => (b.created_at || 0) - (a.created_at || 0)).find(j => j.status === 'done')
              if (done) candidate = done.job_id
            }
          } catch (_) {}
        }
        if (!candidate) return
        try {
          const st = await jobs.status(candidate)
          if (st.status === 'running' || (meta.attachOnDone && st.status === 'done')) {
            if (st.status === 'running') localStorage.setItem(meta.storage, candidate)
            else localStorage.removeItem(meta.storage)
            attach(candidate)
          } else {
            localStorage.removeItem(meta.storage)
          }
        } catch (_) { localStorage.removeItem(meta.storage) }
      },
      _appendLine(op, refName, line) {
        op.lines.push(line)
        if (op.lines.length > MAX_LINES) op.lines.splice(0, op.lines.length - MAX_LINES)
        this.$nextTick(() => { const el = this.$refs[refName]; if (el) el.scrollTop = el.scrollHeight })
      },
      lineClass(l) {
        if (/^\[ebuild/.test(l) || /^>>> /.test(l) || /Completed/.test(l)) return 'hi-ok'
        if (/^!!!/.test(l) || /[Ee]rror/.test(l)) return 'hi-err'
        if (/^ \* /.test(l) || /^NOTE:/.test(l)) return 'hi-warn'
        return ''
      },
      statusClass(rc) { return rc === null ? '' : rc === 0 ? 'ok' : 'err' },
      startSync() {
        this.sync.lines = []; this.sync.rc = null; this.sync.running = true; this.sync.expanded = true
        this.sync.ws = wsGlobalEmerge('sync', (msg) => {
          if (msg.job_id) { localStorage.setItem(_JOB_META.sync.storage, msg.job_id); return }
          if (msg.line !== undefined) this._appendLine(this.sync, 'syncTerm', msg.line)
          if (msg.done) { this.sync.running = false; this.sync.rc = msg.returncode ?? null; this.sync.ws = null; localStorage.removeItem(_JOB_META.sync.storage) }
        })
      },
      _attachSync(id) {
        this.sync.running = true; this.sync.expanded = true; this.sync.lines = []; this.sync.rc = null
        this.sync.ws = wsJobAttach(id, (msg) => {
          if (msg.line !== undefined) this._appendLine(this.sync, 'syncTerm', msg.line)
          if (msg.done) { this.sync.running = false; this.sync.rc = msg.returncode ?? null; this.sync.ws = null; localStorage.removeItem(_JOB_META.sync.storage) }
        })
      },
      startWorldPretend() {
        this.worldPretend.lines = []; this.worldPretend.rc = null; this.worldPretend.running = true; this.worldPretend.expanded = true
        this.worldPretend.ws = wsGlobalEmerge('world-pretend', (msg) => {
          if (msg.job_id) { localStorage.setItem(_JOB_META.worldPretend.storage, msg.job_id); return }
          if (msg.line !== undefined) this._appendLine(this.worldPretend, 'wpTerm', msg.line)
          if (msg.done) { this.worldPretend.running = false; this.worldPretend.rc = msg.returncode ?? null; this.worldPretend.ws = null; localStorage.removeItem(_JOB_META.worldPretend.storage) }
        })
      },
      _attachWorldPretend(id) {
        this.worldPretend.running = true; this.worldPretend.expanded = true; this.worldPretend.lines = []; this.worldPretend.rc = null
        this.worldPretend.ws = wsJobAttach(id, (msg) => {
          if (msg.line !== undefined) this._appendLine(this.worldPretend, 'wpTerm', msg.line)
          if (msg.done) { this.worldPretend.running = false; this.worldPretend.rc = msg.returncode ?? null; this.worldPretend.ws = null; localStorage.removeItem(_JOB_META.worldPretend.storage) }
        })
      },
      startWorldUpdate() {
        this.worldUpdate.lines = []; this.worldUpdate.rc = null; this.worldUpdate.running = true; this.worldUpdate.expanded = true
        this.worldUpdate.ws = wsGlobalEmerge('world-update', (msg) => {
          if (msg.job_id) { localStorage.setItem(_JOB_META.worldUpdate.storage, msg.job_id); return }
          if (msg.line !== undefined) this._appendLine(this.worldUpdate, 'wuTerm', msg.line)
          if (msg.done) { this.worldUpdate.running = false; this.worldUpdate.rc = msg.returncode ?? null; this.worldUpdate.ws = null; localStorage.removeItem(_JOB_META.worldUpdate.storage) }
        }, { opts: this.eoOpts() })
      },
      _attachWorldUpdate(id) {
        this.worldUpdate.running = true; this.worldUpdate.expanded = true; this.worldUpdate.lines = []; this.worldUpdate.rc = null
        this.worldUpdate.ws = wsJobAttach(id, (msg) => {
          if (msg.line !== undefined) this._appendLine(this.worldUpdate, 'wuTerm', msg.line)
          if (msg.done) { this.worldUpdate.running = false; this.worldUpdate.rc = msg.returncode ?? null; this.worldUpdate.ws = null; localStorage.removeItem(_JOB_META.worldUpdate.storage) }
        })
      },
      startDepcleanPretend() {
        localStorage.removeItem('arbor_depclean_ran')
        this.depclean.lines = []; this.depclean.rc = null; this.depclean.running = true; this.depclean.expanded = true; this.depclean.dcStep = 'pretend'
        this.depclean.ws = wsGlobalEmerge('depclean-pretend', (msg) => {
          if (msg.job_id) { localStorage.setItem(_JOB_META.depcleanPretend.storage, msg.job_id); return }
          if (msg.line !== undefined) this._appendLine(this.depclean, 'dcTerm', msg.line)
          if (msg.done) {
            this.depclean.running = false; this.depclean.rc = msg.returncode ?? null; this.depclean.ws = null
            if (this.depclean.rc === 0) this.depclean.dcStep = 'confirm'
            localStorage.removeItem(_JOB_META.depcleanPretend.storage)
          }
        })
      },
      _attachDepcleanPretend(id) {
        this.depclean.running = true; this.depclean.expanded = true; this.depclean.dcStep = 'pretend'; this.depclean.lines = []; this.depclean.rc = null
        this.depclean.ws = wsJobAttach(id, (msg) => {
          if (msg.line !== undefined) this._appendLine(this.depclean, 'dcTerm', msg.line)
          if (msg.done) {
            this.depclean.running = false; this.depclean.rc = msg.returncode ?? null; this.depclean.ws = null
            if (this.depclean.rc === 0) this.depclean.dcStep = 'confirm'
            localStorage.removeItem(_JOB_META.depcleanPretend.storage)
          }
        })
      },
      startDepclean() {
        localStorage.setItem('arbor_depclean_ran', '1')
        this.depclean.lines = []; this.depclean.rc = null; this.depclean.running = true; this.depclean.expanded = true; this.depclean.dcStep = 'running'
        this.depclean.ws = wsGlobalEmerge('depclean', (msg) => {
          if (msg.job_id) { localStorage.setItem(_JOB_META.depclean.storage, msg.job_id); return }
          if (msg.line !== undefined) this._appendLine(this.depclean, 'dcTerm', msg.line)
          if (msg.done) { this.depclean.running = false; this.depclean.rc = msg.returncode ?? null; this.depclean.ws = null; localStorage.removeItem(_JOB_META.depclean.storage) }
        })
      },
      _attachDepclean(id) {
        this.depclean.running = true; this.depclean.expanded = true; this.depclean.dcStep = 'running'; this.depclean.lines = []; this.depclean.rc = null
        this.depclean.ws = wsJobAttach(id, (msg) => {
          if (msg.line !== undefined) this._appendLine(this.depclean, 'dcTerm', msg.line)
          if (msg.done) { this.depclean.running = false; this.depclean.rc = msg.returncode ?? null; this.depclean.ws = null; localStorage.removeItem(_JOB_META.depclean.storage) }
        })
      },
      startPreserved() {
        this.preserved.lines = []; this.preserved.rc = null; this.preserved.running = true; this.preserved.expanded = true
        this.preserved.ws = wsGlobalEmerge('preserved-rebuild', (msg) => {
          if (msg.job_id) { localStorage.setItem(_JOB_META.preserved.storage, msg.job_id); return }
          if (msg.line !== undefined) this._appendLine(this.preserved, 'psTerm', msg.line)
          if (msg.done) { this.preserved.running = false; this.preserved.rc = msg.returncode ?? null; this.preserved.ws = null; localStorage.removeItem(_JOB_META.preserved.storage) }
        })
      },
      _attachPreserved(id) {
        this.preserved.running = true; this.preserved.expanded = true; this.preserved.lines = []; this.preserved.rc = null
        this.preserved.ws = wsJobAttach(id, (msg) => {
          if (msg.line !== undefined) this._appendLine(this.preserved, 'psTerm', msg.line)
          if (msg.done) { this.preserved.running = false; this.preserved.rc = msg.returncode ?? null; this.preserved.ws = null; localStorage.removeItem(_JOB_META.preserved.storage) }
        })
      },
    }
  }

  // ── ALPINE STORES + INIT ──────────────────────────────────────────────────

  document.addEventListener('alpine:init', () => {
    Alpine.store('auth', {
      token: localStorage.getItem('arbor_token') || '',
      get isLoggedIn() { return !!this.token },
      set(t) {
        this.token = t.trim()
        t.trim() ? localStorage.setItem('arbor_token', t.trim())
                 : localStorage.removeItem('arbor_token')
      },
      logout() { this.set('') }
    })

    Alpine.store('router', {
      view: 'dashboard',
      selectedPackage: null,
      installAtom:     null,
      uninstallAtom:   null,
      packageListSearch: '',
      searchViewQuery:   '',
    })
  })

  // ---------------------------------------------------------------------------
  // Overlays view
  // ---------------------------------------------------------------------------
  function overlayViewComponent() {
    const MAX_LINES = 2000
    let _ws = null
    return {
      list: [], loading: true, error: null,
      // add form
      addShow: false, addName: '', addSyncType: 'git', addSyncUri: '', addBusy: false, addError: null,
      expanded: null,
      // flat top-level sync state (one active sync at a time)
      syncName: null, syncRunning: false, syncLines: [], syncRc: null,

      init() {
        this._load()
        this.$watch('$store.router.view', v => { if (v === 'overlays') this._load() })
      },
      async _load() {
        this.loading = true; this.error = null
        try { this.list = await overlays.list() }
        catch(e) { this.error = e.message }
        finally { this.loading = false }
      },
      toggleAdd() { this.addShow = !this.addShow; this.addError = null },
      async add() {
        this.addError = null
        if (!this.addName.trim()) { this.addError = 'Name is required'; return }
        if (!this.addSyncUri.trim()) { this.addError = 'Sync URI is required'; return }
        this.addBusy = true
        try {
          const name = this.addName.trim()
          await overlays.add(name, this.addSyncType, this.addSyncUri.trim())
          this.addShow = false
          this.addName = ''; this.addSyncUri = ''
          await this._load()
          this._startSync(name)
        } catch(e) { this.addError = e.message }
        finally { this.addBusy = false }
      },
      async remove(name, purge) {
        if (!confirm('Remove overlay "' + name + '"?' + (purge ? '\n\nThis will also delete the local files.' : ''))) return
        try {
          await overlays.remove(name, purge)
          if (this.expanded === name) this.expanded = null
          if (this.syncName === name) {
            if (_ws) { try { _ws.close() } catch(_) {} _ws = null }
            this.syncRunning = false
          }
          await this._load()
        } catch(e) { alert('Remove failed: ' + e.message) }
      },
      toggleExpand(name) {
        this.expanded = this.expanded === name ? null : name
      },
      sync(name) {
        if (this.syncRunning) return
        if (_ws) { try { _ws.close() } catch(_) {} _ws = null }
        this.syncName    = name
        this.syncRunning = true
        this.syncLines   = []
        this.syncRc      = null
        this.expanded    = name
        _ws = wsOverlaySync(name, (msg) => {
          if (msg.line !== undefined) {
            this.syncLines = this.syncLines.length >= MAX_LINES
              ? this.syncLines.slice(1).concat([msg.line])
              : this.syncLines.concat([msg.line])
            this.$nextTick(() => {
              const el = document.getElementById('ov-term')
              if (el) el.scrollTop = el.scrollHeight
            })
          }
          if (msg.done) {
            this.syncRunning = false
            this.syncRc = msg.returncode ?? -1
            _ws = null
            this._load()
          }
        })
      },
      lineClass(l) {
        if (/^\[ebuild/.test(l) || /^>>> /.test(l) || /Completed/.test(l)) return 'hi-ok'
        if (/^!!!/.test(l) || /[Ee]rror/.test(l)) return 'hi-err'
        if (/^ \* /.test(l) || /^NOTE:/.test(l)) return 'hi-warn'
        return ''
      },
      fmtLastSync(ts) {
        if (!ts) return '—'
        try { return new Date(ts).toLocaleDateString() } catch(_) { return ts }
      },
    }
  }

  document.addEventListener('DOMContentLoaded', _initRouter)

  // Expose to window for Alpine x-data expressions and inline event handlers.
  // Component factories must be on window so Alpine can resolve them by name.
  Object.assign(window, {
    navigate, navigateTo, navigateBack,
    api, emerge, jobs, jobHistory, overlays,
    wsEmerge, wsGlobalEmerge, wsJobAttach, wsOverlaySync, detachWs,
    loginComponent,
    navComponent,
    dashboardComponent,
    packageListComponent,
    searchComponent,
    packageDetailComponent,
    depGraphComponent,
    jobsViewComponent,
    uninstallComponent,
    installComponent,
    updatesComponent,
    overlayViewComponent,
  })

}())
