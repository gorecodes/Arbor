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
    useFlagOrigins: (atom)   => _get('/package/use-flag-origins?atom=' + encodeURIComponent(atom)),
    globalUseFlagsAudit: ()  => _get('/use-flags-audit'),
    deps:        (atom)      => _get('/package/deps?atom=' + encodeURIComponent(atom)),
    depGraph:    (atom, d=2) => _get('/package/dep-graph?atom=' + encodeURIComponent(atom) + '&depth=' + d),
    stats:       ()          => _get('/stats'),
    pkgStats:    ()          => _get('/pkg-stats'),
    compileCats: ()          => _get('/analytics/compile-time-by-category'),
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
    config: ()                             => _get('/overlays/config'),
    add:    (name, sync_type, sync_uri, approve_danger, approval_text) =>
      _post('/overlays', { name, sync_type, sync_uri, approve_danger, approval_text }),
    remove: (name, purge = false)          => _del('/overlays/' + encodeURIComponent(name) + (purge ? '?purge=1' : '')),
  }

  function _wsProto() { return location.protocol === 'https:' ? 'wss' : 'ws' }

  function _withQuery(path, params) {
    const qs = new URLSearchParams(params).toString()
    return qs ? path + '?' + qs : path
  }

  function _openAuthedWebSocket(path, onMsg) {
    const ws = new WebSocket(_wsProto() + '://' + location.host + path)
    let done = false
    ws.onopen = () => {
      // Send auth in the first frame so the token never appears in the URL.
      ws.send(JSON.stringify({ type: 'auth', token: _getToken() }))
    }
    ws.onmessage = e => { const m = JSON.parse(e.data); if (m.done) done = true; onMsg(m) }
    ws.onerror   = () => { if (!done) { done = true; onMsg({ done: true, returncode: -1, error: 'WebSocket error' }) } }
    ws.onclose   = () => { if (!done) { done = true; onMsg({ done: true, returncode: -1, error: 'connection closed' }) } }
    return ws
  }

  function wsEmerge(cmd, atom, onMsg, extra = {}) {
    return _openAuthedWebSocket(_withQuery('/ws/emerge/' + cmd, { atom, ...extra }), onMsg)
  }

  function wsGlobalEmerge(cmd, onMsg, extra = {}) {
    return _openAuthedWebSocket(_withQuery('/ws/emerge/' + cmd, extra), onMsg)
  }

  function wsJobAttach(jobId, onMsg) {
    return _openAuthedWebSocket('/ws/jobs/' + encodeURIComponent(jobId), onMsg)
  }

  function wsOverlaySync(name, onMsg) {
    return _openAuthedWebSocket('/ws/overlays/sync/' + encodeURIComponent(name), onMsg)
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

  function scrollMainToTop() {
    const apply = () => {
      const el = document.querySelector('.app-main') || document.querySelector('main')
      if (el) {
        el.scrollTop = 0
        el.scrollTo({ top: 0, behavior: 'auto' })
      }
      document.documentElement.scrollTop = 0
      document.body.scrollTop = 0
    }
    requestAnimationFrame(() => {
      apply()
      requestAnimationFrame(apply)
    })
  }

  function navigateTo(cpv) { navigate('packages', cpv) }
  function navigateToUse(cpv) { navigate('use-flags', cpv) }
  function navigateBack()  { history.back() }
  function invalidatePackageState(atom = null) {
    const router = Alpine.store('router')
    router.packageStateVersion = (router.packageStateVersion || 0) + 1
    router.lastChangedPackage = atom
  }

  function _applyRoute() {
    const hash = location.hash.replace(/^#/, '')
    const r    = Alpine.store('router')
    const pkg  = hash.match(/^\/packages\/(.+)$/)
    const use  = hash.match(/^\/use-flags\/(.+)$/)
    const inst = hash.match(/^\/install\/(.+)$/)
    const uni  = hash.match(/^\/uninstall\/(.+)$/)
    const sim  = hash.match(/^\/([^/]+)$/)
    if      (pkg)  { r.selectedPackage = decodeURIComponent(pkg[1]);  r.selectedUseFlag = null; r.view = 'packages'  }
    else if (use)  { r.selectedPackage = null; r.selectedUseFlag = decodeURIComponent(use[1]); r.view = 'use-flags' }
    else if (inst) { r.installAtom     = decodeURIComponent(inst[1]); r.view = 'install'   }
    else if (uni)  { r.uninstallAtom   = decodeURIComponent(uni[1]);  r.view = 'uninstall' }
    else if (sim)  { r.view = sim[1]; r.selectedPackage = null; r.selectedUseFlag = null }
    else           {
      r.view = 'dashboard'
      r.selectedPackage = null
      r.selectedUseFlag = null
    }
  }

  function _initRouter() {
    window.addEventListener('hashchange', _applyRoute)
    if (!location.hash || location.hash === '#' || location.hash === '#/') location.hash = '/dashboard'
    _applyRoute()
  }

  function normalizePayload(payload) {
    if (!payload) return null
    if (Array.isArray(payload)) return payload[0] || null
    return payload
  }

  function useFlagDescription(flag) {
    return flag?.description || 'No description available.'
  }

  function useFlagSourceLabel(flag) {
    const source = flag?.source ?? flag?.configured_source
    if (source === 'forced') return 'forced'
    if (source === 'masked') return 'masked'
    if (source === 'package.use') return 'package.use'
    if (source === 'make.conf') return 'make.conf'
    if (source === 'default') return 'IUSE default'
    if (source === 'profile') return 'profile'

    const origin = flag?.origin_type ?? flag?.configured_origin_type
    if (origin === 'profile_package.use' || origin === 'user_package.use') return 'package.use'
    if (origin === 'make_conf') return 'make.conf'
    if (origin === 'profile_defaults') return 'profile'
    return 'unknown'
  }

  function useFlagSourceTone(flag) {
    const source = flag?.source ?? flag?.configured_source
    if (source === 'forced') return 'forced'
    if (source === 'masked') return 'masked'
    if (source === 'package.use') return 'package-use'
    if (source === 'make.conf') return 'make-conf'
    if (source === 'default') return 'profile'

    const origin = flag?.origin_type ?? flag?.configured_origin_type
    if (origin === 'profile_package.use' || origin === 'user_package.use') return 'package-use'
    if (origin === 'make_conf') return 'make-conf'
    return 'profile'
  }

  function useFlagOriginDetail(flag) {
    const source = flag?.source ?? flag?.configured_source
    const originFile = flag?.origin_file ?? flag?.configured_origin_file
    if (source === 'forced') return 'Active profile or repository forces this flag on; no direct file path is available.'
    if (source === 'masked') return 'Active profile or repository masks this flag off; no direct file path is available.'
    if (source === 'default') return flag?.default_on ? 'Enabled by the ebuild IUSE default.' : 'Disabled by the ebuild IUSE default.'
    if (originFile) return originFile
    return flag?.default_on ? 'Enabled by the package defaults.' : 'Disabled by the package defaults.'
  }

  const CHART_COLORS = {
    grid: 'var(--chart-grid, #303944)',
    track: 'var(--chart-track, #28303a)',
    text: 'var(--text, #d7dde4)',
    textMuted: 'var(--text-muted, #98a4af)',
    primary: 'var(--chart-1, #88a784)',
    success: 'var(--success, #92af84)',
    warning: 'var(--warning, #b59a67)',
    danger: 'var(--danger, #ba7f7d)',
    info: 'var(--chart-2, #708da8)',
    muted: 'var(--chart-4, #8794a1)',
    accent: 'var(--chart-5, #8f7c73)',
  }

  const CHART_PALETTES = {
    primary: ['var(--chart-1, #88a784)', '#809d7b', '#779272', '#6d8769', '#647c61', 'var(--chart-4, #8794a1)'],
    info: ['var(--chart-2, #708da8)', '#69849d', '#617b92', '#597187', '#51687d', 'var(--chart-4, #8794a1)'],
    warm: ['var(--chart-3, #b59a67)', '#aa9165', '#9c8761', '#8f7d5d', '#82745a', 'var(--chart-4, #8794a1)'],
  }

  function paletteColor(name, index) {
    const palette = CHART_PALETTES[name] || CHART_PALETTES.primary
    return palette[Math.min(index, palette.length - 1)]
  }

  function fmtIecParts(b) {
    if (!b) return { value: '0', unit: 'B' }
    if (b >= 1024 ** 3) return { value: (b / 1024 ** 3).toFixed(1), unit: 'GiB' }
    if (b >= 1024 ** 2) return { value: (b / 1024 ** 2).toFixed(0), unit: 'MiB' }
    if (b >= 1024) return { value: (b / 1024).toFixed(0), unit: 'KiB' }
    return { value: String(Math.round(b)), unit: 'B' }
  }

  function buildPortageDiskRows(pkgStats) {
    const disk = pkgStats?.portage_disk
    if (!disk) return []
    const order = ['repos', 'distfiles', 'binpkgs', 'vartree']
    const LABELS = {
      repos: '/var/db/repos',
      distfiles: '/var/cache/distfiles',
      binpkgs: '/var/cache/binpkgs',
      vartree: '/var/db/pkg',
    }
    const TONES = {
      repos: 'tone-blue',
      distfiles: 'tone-amber',
      binpkgs: 'tone-green',
      vartree: 'tone-purple',
    }
    const entries = order
      .map(key => [key, disk[key]])
      .filter(([, bytes]) => typeof bytes === 'number' && bytes >= 0)
    const total = entries.reduce((sum, [, bytes]) => sum + bytes, 0)
    return entries.map(([key, bytes]) => {
      const size = fmtIecParts(bytes)
      return {
        key,
        bytes,
        label: LABELS[key] || key,
        sizeValue: size.value,
        sizeUnit: size.unit,
        pct: total ? Math.round((bytes / total) * 100) : 0,
        tone: TONES[key] || 'tone-blue',
      }
    })
  }

  function portageDiskHint(pkgStats) {
    const distfiles = pkgStats?.portage_disk?.distfiles || 0
    return distfiles > 5 * 1024 ** 3 ? 'Large distfiles cache' : ''
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

  const PRIMARY_NAV_ITEMS = [
    { id: 'dashboard', label: 'Dashboard'   },
    { id: 'packages',  label: 'Installed packages'   },
    { id: 'search',    label: 'Search Packages' },
    { id: 'use-flags', label: 'USE Flags'   },
    { id: 'updates',   label: 'Maintenance' },
    { id: 'overlays',  label: 'Overlays'    },
    { id: 'jobs',      label: 'Jobs'        },
  ]

  function isPrimaryRouteActive(id) {
    const view = Alpine.store('router').view
    if (id === 'packages') return ['packages', 'install', 'uninstall'].includes(view)
    return view === id
  }

  function navComponent() {
    return {
      items: PRIMARY_NAV_ITEMS,
      isActive(id) { return isPrimaryRouteActive(id) },
      nav(id) { navigate(id) },
      logout() { Alpine.store('auth').logout() }
    }
  }

  function appShellComponent() {
    return {
      items: PRIMARY_NAV_ITEMS,
      status: null,
      activeJobs: [],
      _timer: null,
      init() {
        this._loadSummary()
        this._timer = setInterval(() => {
          if (!Alpine.store('auth').isLoggedIn) return
          this._loadSummary()
        }, 15000)
        this.$watch('$store.auth.token', token => {
          if (token) this._loadSummary()
        })
      },
      isActive(id) { return isPrimaryRouteActive(id) },
      nav(id) { navigate(id) },
      logout() { Alpine.store('auth').logout() },
      async _loadSummary() {
        try {
          const [status, activeJobs] = await Promise.all([
            api.status(),
            jobs.list().catch(() => []),
          ])
          this.status = status
          this.activeJobs = Array.isArray(activeJobs) ? activeJobs : []
        } catch (_) {}
      },
      runningJobCount() {
        return this.activeJobs.filter(job => job?.status === 'running').length
      },
      memoryPct() {
        const used = this.status?.mem_used
        const total = this.status?.mem_total
        if (!total || isNaN(used) || isNaN(total)) return null
        return Math.max(0, Math.min(100, Math.round((used / total) * 100)))
      },
      syncLabel() {
        const stamp = this.status?.last_sync
        if (!stamp) return 'sync —'
        const text = String(stamp).trim()
        return 'sync ' + (text.length > 10 ? text.slice(0, 10) : text)
      },
      statusPills() {
        const pills = [
          { key: 'jobs', text: this.runningJobCount() > 0 ? this.runningJobCount() + ' job' + (this.runningJobCount() === 1 ? '' : 's') : 'jobs idle', tone: this.runningJobCount() > 0 ? 'info' : 'muted' },
        ]
        if (this.status) {
          pills.push({ key: 'cpu', text: 'cpu ' + Math.round(this.status?.cpu_pct || 0) + '%', tone: 'muted' })
          if (this.memoryPct() !== null) pills.push({ key: 'mem', text: 'mem ' + this.memoryPct() + '%', tone: 'muted' })
          pills.push({ key: 'sync', text: this.syncLabel(), tone: 'muted' })
        }
        return pills
      },
      currentMeta() {
        const r = Alpine.store('router')
        if (r.view === 'dashboard') {
          return {
            section: 'Overview',
            title: 'Dashboard',
            detail: '',
          }
        }
        if (r.view === 'packages' && r.selectedPackage) {
          return {
            section: 'Packages',
            title: r.selectedPackage,
            detail: 'Installed package metadata, USE state, and dependency inspection.',
          }
        }
        if (r.view === 'packages') {
          return {
            section: 'Packages',
            title: 'Installed packages',
            detail: 'Browse the current system set and open package details quickly.',
          }
        }
        if (r.view === 'use-flags') {
          return {
            section: 'Configuration',
            title: r.selectedUseFlag || 'USE flags',
            detail: 'Inspect global state, package overrides, and installed package usage for each USE flag.',
          }
        }
        if (r.view === 'search') {
          return {
            section: 'Portage tree',
            title: 'Search packages',
            detail: 'Query package names across the tree and jump straight to the best match.',
          }
        }
        if (r.view === 'updates') {
          return {
            section: 'Maintenance',
            title: 'System maintenance',
            detail: 'Sync the tree, check @world, rebuild preserved libs, and run depclean.',
          }
        }
        if (r.view === 'jobs') {
          return {
            section: 'Operations',
            title: 'Jobs',
            detail: 'Follow active work, reopen output, and review retained job history.',
          }
        }
        if (r.view === 'overlays') {
          return {
            section: 'Repositories',
            title: 'Overlays',
            detail: 'Inspect configured overlays and sync additional repositories.',
          }
        }
        if (r.view === 'install') {
          return {
            section: 'Packages',
            title: 'Install ' + (r.installAtom || 'package'),
            detail: 'Run pretend, resolve autounmask steps, and execute the install flow.',
          }
        }
        if (r.view === 'uninstall') {
          return {
            section: 'Packages',
            title: 'Uninstall ' + (r.uninstallAtom || 'package'),
            detail: 'Preview removals before starting the uninstall job.',
          }
        }
        return { section: 'Arbor', title: 'Dashboard', detail: '' }
      },
      contextItems() {
        const view = Alpine.store('router').view
        if (view === 'dashboard') return []
        if (view === 'updates') {
          return [
            { id: 'updates-sync', label: 'Sync' },
            { id: 'updates-check', label: 'Check' },
            { id: 'updates-world', label: '@world' },
            { id: 'updates-preserved', label: 'Preserved' },
            { id: 'updates-depclean', label: 'Depclean' },
          ]
        }
        return []
      },
      scrollToSection(id) {
        const section = document.getElementById(id)
        if (!section) return
        section.scrollIntoView({ behavior: 'smooth', block: 'start' })
      },
    }
  }

  function dashboardComponent() {
    return {
      status: null,
      stats: null,
      pkgStats: null,
      compileCats: null,
      runningJobs: [],
      recentHistory: [],
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
        try {
          this.error = null
          const [statusRes, statsRes, pkgStatsRes, compileCatsRes, jobsRes, historyRes] = await Promise.allSettled([
            api.status(),
            api.stats(),
            api.pkgStats(),
            api.compileCats(),
            jobs.list(),
            jobHistory.list(12, 0, ''),
          ])
          if (statusRes.status !== 'fulfilled') throw statusRes.reason
          this.status = statusRes.value
          this.stats = statsRes.status === 'fulfilled' ? statsRes.value : null
          this.pkgStats = pkgStatsRes.status === 'fulfilled' ? pkgStatsRes.value : null
          this.compileCats = compileCatsRes.status === 'fulfilled' ? compileCatsRes.value : null
          this.runningJobs = jobsRes.status === 'fulfilled' && Array.isArray(jobsRes.value) ? jobsRes.value : []
          this.recentHistory = historyRes.status === 'fulfilled' && Array.isArray(historyRes.value?.items) ? historyRes.value.items : []
        } catch(e) { this.error = e.message }
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
      maxSystemPct() {
        return Math.max(this.cpuPct(), this.memPct(), this.diskPct())
      },
      activeJobCount() {
        return this.runningJobs.length
      },
      hasActiveJobs() {
        return this.activeJobCount() > 0
      },
      hasStats() {
        return !!(this.stats && this.stats.total > 0)
      },
      hasActivity() {
        return this.hasStats() || this.recentHistory.length > 0
      },
      hasComposition() {
        return !!(this.compileCats || (this.pkgStats && (
          this.pkgStats?.top_use_flags?.length ||
          this.pkgStats?.keyword_dist ||
          this.pkgStats?.src_vs_bin ||
          this.pkgStats?.slotted?.length
        )))
      },
      hasPortageDisk() {
        return !!this.pkgStats?.portage_disk
      },
      hasPkgStats() {
        return !!(this.pkgStats && (
          this.pkgStats?.top_use_flags?.length ||
          this.pkgStats?.keyword_dist ||
          this.pkgStats?.src_vs_bin ||
          this.pkgStats?.slotted?.length
        ))
      },
      meterFillCount(pct, total = 24) {
        const p = isNaN(pct) || !isFinite(pct) ? 0 : Math.max(0, Math.min(100, pct))
        if (p === 0) return 0
        return Math.max(1, Math.round((p / 100) * total))
      },
      meterTone(pct) {
        if (pct >= 85) return 'is-hot'
        if (pct >= 60) return 'is-warn'
        return 'is-ok'
      },
      systemMeters() {
        if (!this.status) return []
        return [
          {
            key: 'cpu',
            label: 'CPU',
            pct: this.cpuPct(),
            detail: 'load ' + (this.status?.cpu_load1 ?? 0),
          },
          {
            key: 'ram',
            label: 'RAM',
            pct: this.memPct(),
            detail: this.fmtBytes(this.status?.mem_used ?? 0) + ' / ' + this.fmtBytes(this.status?.mem_total ?? 0),
          },
          {
            key: 'disk',
            label: 'DISK /',
            pct: this.diskPct(),
            detail: this.fmtBytes(this.status?.disk_used ?? 0) + ' / ' + this.fmtBytes(this.status?.disk_total ?? 0),
          },
        ].map(metric => ({ ...metric, tone: this.meterTone(metric.pct) }))
      },
      _plural(n, word) {
        return n + ' ' + word + (n === 1 ? '' : 's')
      },
      _shortAtom(atom) {
        if (!atom) return 'system task'
        return String(atom).replace(/^=/, '').replace(/^uninstall:/, '')
      },
      _kindLabel(kind) {
        return String(kind || 'job').replace(/_/g, ' ')
      },
      _fmtRelativeMs(ms) {
        if (!Number.isFinite(ms) || ms < 0) return 'unknown'
        const s = Math.round(ms / 1000)
        if (s < 60) return s + 's ago'
        if (s < 3600) return Math.floor(s / 60) + 'm ago'
        if (s < 86400) return Math.floor(s / 3600) + 'h ago'
        return Math.floor(s / 86400) + 'd ago'
      },
      _timestampMs(value) {
        if (!value || value === 'unknown') return null
        const ms = Date.parse(value)
        return Number.isFinite(ms) ? ms : null
      },
      syncAgeMs() {
        const ts = this._timestampMs(this.status?.last_sync)
        return ts === null ? null : Math.max(0, Date.now() - ts)
      },
      syncFreshnessLabel() {
        const age = this.syncAgeMs()
        return age === null ? 'unknown' : this._fmtRelativeMs(age)
      },
      syncFreshnessTone() {
        const age = this.syncAgeMs()
        if (age === null) return 'muted'
        if (age > 14 * 86400000) return 'danger'
        if (age > 7 * 86400000) return 'warning'
        return 'success'
      },
      syncFreshnessNote() {
        const age = this.syncAgeMs()
        if (age === null) return 'No Gentoo sync timestamp was available.'
        if (age > 14 * 86400000) return 'The tree looks stale for a Portage UI.'
        if (age > 7 * 86400000) return 'A fresh sync is probably worth scheduling.'
        return 'The Gentoo tree timestamp looks recent.'
      },
      recentWindow(limit = 12) {
        return this.recentHistory.slice(0, limit)
      },
      recentFailureCount(limit = 12) {
        return this.recentWindow(limit).filter(job => job.status !== 'done').length
      },
      lastFailure() {
        return this.recentHistory.find(job => job.status !== 'done') || null
      },
      recentHistoryStatusLabel(job) {
        if (!job) return 'unknown'
        if (job.status === 'done') return 'done'
        if (job.status === 'cancelled') return 'cancelled'
        return 'failed'
      },
      recentHistoryTone(job) {
        if (!job) return 'muted'
        if (job.status === 'done') return 'success'
        if (job.status === 'cancelled') return 'warning'
        return 'danger'
      },
      recentHistoryDuration(job) {
        if (!job?.created_at || !job?.finished_at) return '—'
        const seconds = Math.max(0, Math.round(job.finished_at - job.created_at))
        return this._fmtDur(seconds)
      },
      runningKindsText() {
        if (!this.runningJobs.length) return 'no active emerge jobs'
        const counts = {}
        this.runningJobs.forEach(job => {
          const key = this._kindLabel(job.kind)
          counts[key] = (counts[key] || 0) + 1
        })
        return Object.entries(counts)
          .map(([kind, count]) => count > 1 ? `${kind} x${count}` : kind)
          .slice(0, 3)
          .join(' · ')
      },
      systemLoadState() {
        const maxPct = this.maxSystemPct()
        if (maxPct >= 85) return 'high'
        if (maxPct >= 60) return 'normal'
        return 'low'
      },
      portageOverviewCards() {
        const source = this.pkgStats?.src_vs_bin?.source || 0
        const binary = this.pkgStats?.src_vs_bin?.binary || 0
        const totalMix = source + binary
        const sourcePct = totalMix ? Math.round((source / totalMix) * 100) : null
        const keywords = this.pkgStats?.keyword_dist || {}
        const keywordTotal = (keywords.stable || 0) + (keywords.testing || 0) + (keywords.live || 0) + (keywords.unknown || 0)
        const stablePct = keywordTotal ? Math.round(((keywords.stable || 0) / keywordTotal) * 100) : null
        return [
          {
            key: 'packages',
            label: 'installed packages',
            value: this.status?.pkg_count ?? '—',
            detail: 'currently in /var/db/pkg',
          },
          {
            key: 'mix',
            label: 'source-built mix',
            value: sourcePct === null ? '—' : sourcePct + '%',
            detail: totalMix ? `${source} source / ${binary} binary` : 'package mix unavailable',
          },
          {
            key: 'keywords',
            label: 'keyword posture',
            value: stablePct === null ? '—' : stablePct + '% stable',
            detail: keywordTotal ? `${keywords.testing || 0} testing / ${keywords.live || 0} live / ${keywords.unknown || 0} other` : 'keyword mix unavailable',
          },
        ]
      },
      portageFootprintSummary() {
        const rows = this.portageDiskRows()
        if (!rows.length) {
          return {
            value: '—',
            detail: 'tracked Portage storage unavailable',
            tone: 'muted',
          }
        }
        const total = rows.reduce((sum, row) => sum + row.bytes, 0)
        const largest = rows.reduce((current, row) => row.bytes > current.bytes ? row : current, rows[0])
        const totalSize = this._fmtIecParts(total)
        return {
          value: totalSize.value + ' ' + totalSize.unit,
          detail: `${largest.label} is ${largest.pct}% of tracked Portage storage`,
          tone: this.portageHint() ? 'warning' : 'info',
        }
      },
      topSummaryCards() {
        const recentFailures = this.recentFailureCount()
        const recentCount = this.recentWindow().length
        return [
          {
            key: 'jobs',
            label: 'job state',
            value: this.hasActiveJobs() ? this._plural(this.activeJobCount(), 'active') : 'idle',
            detail: this.runningKindsText(),
            tone: this.hasActiveJobs() ? 'info' : 'success',
          },
          {
            key: 'sync',
            label: 'last sync',
            value: this.syncFreshnessLabel(),
            detail: this.status?.last_sync || 'sync timestamp unavailable',
            tone: this.syncFreshnessTone(),
          },
          {
            key: 'issues',
            label: 'recent job issues',
            value: recentCount ? (recentFailures ? String(recentFailures) : 'none') : '—',
            detail: recentCount ? `failed or cancelled in last ${recentCount} jobs` : 'no recent job history',
            tone: !recentCount ? 'muted' : recentFailures > 0 ? 'danger' : 'success',
          },
          {
            key: 'packages',
            label: 'installed packages',
            value: this.status?.pkg_count ?? '—',
            detail: 'current package count in /var/db/pkg',
            tone: 'muted',
          },
        ]
      },
      activitySummaryCards() {
        const counts = this.stats?.status_counts || {}
        const done = counts.done || 0
        const failed = counts.failed || 0
        const cancelled = counts.cancelled || 0
        const total = done + failed + cancelled
        const successPct = total ? Math.round((done / total) * 100) : null
        return [
          {
            key: 'running',
            label: 'current state',
            value: this.hasActiveJobs() ? this._plural(this.activeJobCount(), 'job') : 'idle',
            detail: this.hasActiveJobs() ? this.runningKindsText() : 'No emerge work is running right now.',
            tone: this.hasActiveJobs() ? 'info' : 'success',
          },
          {
            key: 'outcomes',
            label: 'job outcomes',
            value: successPct === null ? '—' : successPct + '% done',
            detail: total ? `${done} done · ${failed} failed · ${cancelled} cancelled` : 'No completed job history yet.',
            tone: !total ? 'muted' : failed > 0 ? 'danger' : cancelled > 0 ? 'warning' : 'success',
          },
        ]
      },
      sourceBinaryMeter() {
        const svb = this.pkgStats?.src_vs_bin
        const source = svb?.source || 0
        const binary = svb?.binary || 0
        const total = source + binary
        if (!total) {
          return {
            value: '—',
            detail: 'Current source/binary mix is unavailable.',
            segments: [],
          }
        }
        const sourcePct = Math.round((source / total) * 100)
        const binaryPct = Math.max(0, 100 - sourcePct)
        return {
          value: `${sourcePct}% source`,
          detail: `${source} source · ${binary} binary`,
          segments: [
            { key: 'source', pct: sourcePct, tone: 'tone-green' },
            { key: 'binary', pct: binaryPct, tone: 'tone-blue' },
          ].filter(segment => segment.pct > 0),
        }
      },
      keywordPostureMeter() {
        const keywords = this.pkgStats?.keyword_dist || {}
        const stable = keywords.stable || 0
        const testing = keywords.testing || 0
        const live = keywords.live || 0
        const unknown = keywords.unknown || 0
        const total = stable + testing + live + unknown
        if (!total) {
          return {
            value: '—',
            detail: 'Installed keyword mix is unavailable.',
            segments: [],
          }
        }
        const stablePct = Math.round((stable / total) * 100)
        return {
          value: `${stablePct}% stable`,
          detail: `${testing} testing · ${live} live · ${unknown} other`,
          segments: [
            { key: 'stable', pct: Math.round((stable / total) * 100), tone: 'tone-green' },
            { key: 'testing', pct: Math.round((testing / total) * 100), tone: 'tone-amber' },
            { key: 'live', pct: Math.round((live / total) * 100), tone: 'tone-blue' },
            { key: 'other', pct: Math.max(0, 100 - Math.round((stable / total) * 100) - Math.round((testing / total) * 100) - Math.round((live / total) * 100)), tone: 'tone-muted' },
          ].filter(segment => segment.pct > 0),
        }
      },
      compositionSummaryCard(key) {
        return this.compositionSummaryCards().find(card => card.key === key) || {
          key,
          label: '',
          value: '—',
          detail: 'Unavailable',
        }
      },
      compositionSummaryCards() {
        const svb = this.pkgStats?.src_vs_bin
        const source = svb?.source || 0
        const binary = svb?.binary || 0
        const mixTotal = source + binary
        const sourcePct = mixTotal ? Math.round((source / mixTotal) * 100) : null
        const keywords = this.pkgStats?.keyword_dist || {}
        const keywordTotal = (keywords.stable || 0) + (keywords.testing || 0) + (keywords.live || 0) + (keywords.unknown || 0)
        const stablePct = keywordTotal ? Math.round(((keywords.stable || 0) / keywordTotal) * 100) : null
        return [
          {
            key: 'source-binary',
            label: 'source / binary mix',
            value: sourcePct === null ? '—' : sourcePct + '% source',
            detail: mixTotal ? `${source} source · ${binary} binary` : 'Current source/binary mix is unavailable.',
          },
          {
            key: 'keywords',
            label: 'keyword posture',
            value: stablePct === null ? '—' : stablePct + '% stable',
            detail: keywordTotal ? `${keywords.testing || 0} testing · ${keywords.live || 0} live · ${keywords.unknown || 0} other` : 'Installed keyword mix is unavailable.',
          },
        ]
      },
      longestBuildRows(limit = 4) {
        if (!this.stats?.top_slow?.length) return []
        return this.stats.top_slow.slice(0, limit).map(item => ({
          key: item.atom,
          label: this._shortAtom(item.atom),
          value: this._fmtDur(item.duration),
        }))
      },
      recentJobRows(limit = 5) {
        return this.recentHistory.slice(0, limit).map(job => ({
          key: job.job_id,
          label: this._shortAtom(job.atom),
          value: this.recentHistoryStatusLabel(job),
          meta: `${this._kindLabel(job.kind)} · ${this._fmtRelativeMs(Math.max(0, Date.now() - (job.created_at * 1000)))}`,
          tone: this.recentHistoryTone(job),
        }))
      },
      topUseFlagRows(limit = 5) {
        if (!this.pkgStats?.top_use_flags?.length) return []
        return this.pkgStats.top_use_flags.slice(0, limit).map(item => ({
          key: item.flag,
          label: item.flag,
          value: String(item.cnt),
        }))
      },
      slottedRows(limit = 5) {
        if (!this.pkgStats?.slotted?.length) return []
        return this.pkgStats.slotted.slice(0, limit).map(item => ({
          key: item.cp,
          label: item.cp,
          value: item.count + ' slots',
        }))
      },
      attentionItems() {
        const items = []
        if (this.hasActiveJobs()) {
          items.push({
            key: 'running',
            title: this._plural(this.activeJobCount(), 'active job'),
            detail: this.runningKindsText(),
            tone: 'info',
          })
        }
        const recentFailures = this.recentFailureCount()
        if (recentFailures > 0) {
          const lastFailure = this.lastFailure()
          items.push({
            key: 'failures',
            title: this._plural(recentFailures, 'recent failed or cancelled job'),
            detail: lastFailure ? `${this._shortAtom(lastFailure.atom)} ${this._fmtRelativeMs(Math.max(0, Date.now() - (lastFailure.created_at * 1000)))}` : 'Recent history contains non-successful jobs.',
            tone: 'danger',
          })
        }
        const syncTone = this.syncFreshnessTone()
        if (syncTone === 'warning' || syncTone === 'danger') {
          items.push({
            key: 'sync',
            title: 'Portage tree sync is aging',
            detail: this.syncFreshnessNote(),
            tone: syncTone,
          })
        }
        const maxPct = this.maxSystemPct()
        if (maxPct >= 85) {
          const resource = this.cpuPct() >= maxPct ? 'CPU' : (this.memPct() >= maxPct ? 'RAM' : 'disk')
          items.push({
            key: 'load',
            title: `${resource} utilization is high`,
            detail: `cpu ${this.cpuPct()} · ram ${this.memPct()} · disk ${this.diskPct()}`,
            tone: 'danger',
          })
        } else if (maxPct >= 60) {
          items.push({
            key: 'load-watch',
            title: 'System resources are worth watching',
            detail: `cpu ${this.cpuPct()} · ram ${this.memPct()} · disk ${this.diskPct()}`,
            tone: 'warning',
          })
        }
        if (this.portageHint()) {
          items.push({
            key: 'distfiles',
            title: 'Distfiles cache is large',
            detail: this.portageHint().replace(/^hint:\s*/, ''),
            tone: 'warning',
          })
        }
        return items
      },
      heroTone() {
        if (this.attentionItems().some(item => item.tone === 'danger')) return 'danger'
        if (this.attentionItems().some(item => item.tone === 'warning')) return 'warning'
        if (this.hasActiveJobs()) return 'info'
        return 'success'
      },
      heroHeadline() {
        if (this.hasActiveJobs()) return `${this._plural(this.activeJobCount(), 'job')} running`
        if (this.attentionItems().length) return 'Attention recommended'
        return 'No immediate issues seen'
      },
      heroCopy() {
        const recentCount = this.recentWindow().length
        const failureText = recentCount ? `${this.recentFailureCount()} failed or cancelled in the last ${recentCount} jobs` : 'job history is still empty'
        if (this.hasActiveJobs()) {
          return `Portage work is active. Last sync is ${this.syncFreshnessLabel()}, and ${failureText}.`
        }
        if (this.attentionItems().length) {
          return `The system is idle, but current metrics suggest a quick review. Last sync is ${this.syncFreshnessLabel()}, and ${failureText}.`
        }
        return `The system is idle, the tree sync looks ${this.syncFreshnessLabel()}, and CPU, memory, and root disk usage are within normal operating range.`
      },
      _esc(s) {
        return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;')
      },
      _fmtDur(s) {
        s = Math.round(s)
        if (s < 60) return s + 's'
        const m = Math.floor(s / 60), sec = s % 60
        return m + 'm ' + (sec ? sec + 's' : '')
      },
      activitySvg() {
        if (!this.stats) return ''
        const data = this.stats.activity_30d || []
        const days = []
        for (let i = 29; i >= 0; i--) {
          const d = new Date(Date.now() - i * 86400000)
          const key = d.toISOString().slice(0, 10)
          const found = data.find(r => r.day === key)
          days.push({ day: key, cnt: found ? found.cnt : 0 })
        }
        const max = Math.max(1, ...days.map(d => d.cnt))
        const Y_LABEL_W = 28, BAR_W = 11, GAP = 3, CHART_H = 60, LABEL_H = 16, TOP_PAD = 12, AXIS_LABEL_H = 9
        const barsW = days.length * (BAR_W + GAP) - GAP
        const totalW = Y_LABEL_W + barsW
        const chartTop = AXIS_LABEL_H + TOP_PAD
        const totalH = chartTop + CHART_H + LABEL_H

        const yTicks = [0, Math.round(max / 2), max].filter((v, i, a) => a.indexOf(v) === i)
        const grid = yTicks.map(v => {
          const y = chartTop + CHART_H - Math.round((v / max) * CHART_H)
          return `<line x1="${Y_LABEL_W}" y1="${y}" x2="${totalW}" y2="${y}" stroke="${CHART_COLORS.grid}" stroke-width="0.75" stroke-dasharray="2 3"/>
<text x="${Y_LABEL_W - 4}" y="${y + 3}" fill="${CHART_COLORS.textMuted}" font-size="8" text-anchor="end">${v}</text>`
        }).join('')

        const bars = days.map((d, i) => {
          const h = d.cnt === 0 ? 2 : Math.max(4, Math.round((d.cnt / max) * CHART_H))
          const x = Y_LABEL_W + i * (BAR_W + GAP)
          const y = chartTop + CHART_H - h
          const color = d.cnt === 0 ? CHART_COLORS.track : CHART_COLORS.primary
          const label = d.day.slice(5)
          const tick = (i === 0 || i === 6 || i === 13 || i === 20 || i === 29)
            ? `<text x="${x + BAR_W / 2}" y="${chartTop + CHART_H + LABEL_H - 1}" fill="${CHART_COLORS.textMuted}" font-size="8" text-anchor="middle">${this._esc(label)}</text>` : ''
          return `<rect x="${x}" y="${y}" width="${BAR_W}" height="${h}" fill="${color}"><title>${this._esc(d.day)}: ${d.cnt} job${d.cnt !== 1 ? 's' : ''}</title></rect>${tick}`
        }).join('')

        const yTitle = `<text x="0" y="8" fill="${CHART_COLORS.textMuted}" font-size="8">jobs/day</text>`

        return `<svg viewBox="0 0 ${totalW} ${totalH}" width="100%" xmlns="http://www.w3.org/2000/svg" font-family="JetBrains Mono, Fira Code, monospace" style="display:block;overflow:visible">${yTitle}${grid}${bars}</svg>`
      },
      donutSvg() {
        if (!this.stats) return ''
        const sc = this.stats.status_counts || {}
        const done = sc.done || 0
        const failed = sc.failed || 0
        const cancelled = sc.cancelled || 0
        const total = done + failed + cancelled
        if (total === 0) return `<p class="dash-chart-empty">No data yet</p>`
        return this._percentBarSvg([
          { val: done,      color: CHART_COLORS.success, label: 'Done' },
          { val: failed,    color: CHART_COLORS.danger, label: 'Failed' },
          { val: cancelled, color: CHART_COLORS.warning, label: 'Cancelled' },
        ].filter(s => s.val > 0), total, 120, 126, 62, 312)
      },
      kindSvg() {
        if (!this.stats?.kind_counts?.length) return ''
        const COLORS = {
          install: CHART_COLORS.primary,
          uninstall: CHART_COLORS.danger,
          world_update: CHART_COLORS.info,
          depclean: CHART_COLORS.accent,
          sync: CHART_COLORS.warning,
          preserved_rebuild: CHART_COLORS.muted,
        }
        const rows = this.stats.kind_counts.slice(0, 8).map(it => ({
          label: it.kind.replace(/_/g, ' '), val: it.cnt, color: COLORS[it.kind] || CHART_COLORS.muted
        }))
        return this._hBarSvg(rows, v => String(v), 120, 126, 62, 312)
      },
      topSlowSvg() {
        if (!this.stats?.top_slow?.length) return `<p class="dash-chart-empty">No completed builds yet</p>`
        const rows = this.stats.top_slow.slice(0, 6).map(item => ({
          label: (item.atom.replace(/^=/, '').split('/').pop() || item.atom).slice(0, 26),
          val: item.duration,
          color: CHART_COLORS.info,
        }))
        return this._hBarSvg(rows, v => this._fmtDur(v), 150, 108, 84, 346)
      },
      compileTrendSvg() {
        if (!this.stats?.compile_by_day?.length) return `<p class="dash-chart-empty">No data yet — future compilations will be tracked here</p>`
        const data = this.stats.compile_by_day
        const max = Math.max(1, ...data.map(d => d.secs))
        const W = 360, H = 124, PAD_L = 34, PAD_R = 8, PAD_T = 12, PAD_B = 20
        const innerW = W - PAD_L - PAD_R
        const innerH = H - PAD_T - PAD_B
        const fmtAxis = secs => {
          const mins = Math.round(secs / 60)
          if (mins >= 60) return Math.floor(mins / 60) + 'h' + (mins % 60 ? (mins % 60) + 'm' : '')
          return mins + 'm'
        }
        const points = data.map((d, i) => {
          const x = PAD_L + (data.length === 1 ? innerW / 2 : (i / (data.length - 1)) * innerW)
          const y = PAD_T + innerH - Math.round((d.secs / max) * innerH)
          return { ...d, x, y }
        })
        const line = points.map((p, i) => `${i === 0 ? 'M' : 'L'} ${p.x} ${p.y}`).join(' ')
        const area = `${line} L ${points[points.length - 1].x} ${PAD_T + innerH} L ${points[0].x} ${PAD_T + innerH} Z`
        const yTicks = [0, max / 2, max]
        const grid = yTicks.map(v => {
          const y = PAD_T + innerH - Math.round((v / max) * innerH)
          return `<line x1="${PAD_L}" y1="${y}" x2="${W - PAD_R}" y2="${y}" stroke="${CHART_COLORS.grid}" stroke-width="0.75" stroke-dasharray="2 3"/>
<text x="${PAD_L - 4}" y="${y + 3}" fill="${CHART_COLORS.textMuted}" font-size="8" text-anchor="end">${this._esc(fmtAxis(v))}</text>`
        }).join('')
        const labels = points.map((p, i) => {
          const show = i === 0 || i === points.length - 1 || i % Math.max(1, Math.ceil(points.length / 5)) === 0
          if (!show) return ''
          return `<text x="${p.x}" y="${H - 4}" fill="${CHART_COLORS.textMuted}" font-size="8" text-anchor="middle">${this._esc(p.day.slice(5))}</text>`
        }).join('')
        const markers = points.map(p => {
          const dur = fmtAxis(p.secs)
          return `<circle cx="${p.x}" cy="${p.y}" r="2.5" fill="${CHART_COLORS.warning}"><title>${this._esc(p.day)}: ${dur}</title></circle>`
        }).join('')
        return `<svg viewBox="0 0 ${W} ${H}" width="100%" xmlns="http://www.w3.org/2000/svg" font-family="JetBrains Mono, Fira Code, monospace" style="display:block;overflow:visible">
<text x="0" y="8" fill="${CHART_COLORS.textMuted}" font-size="8">build time</text>
${grid}
<path d="${area}" fill="rgba(181, 154, 103, 0.14)" stroke="none"/>
<path d="${line}" fill="none" stroke="${CHART_COLORS.warning}" stroke-width="2"/>
${markers}
${labels}
</svg>`
      },
      _fmtIecParts(b) {
        return fmtIecParts(b)
      },
      portageDiskRows() {
        return buildPortageDiskRows(this.pkgStats)
      },
      portageHint() {
        return portageDiskHint(this.pkgStats)
      },
      useFlagsSvg() {
        if (!this.pkgStats?.top_use_flags?.length) return ''
        const all = this.pkgStats.top_use_flags.map(it => [it.flag, it.cnt])
        const colorFn = i => paletteColor('primary', i)
        return this._hBarSvg(this._topNOther(all, 10, colorFn), v => String(v), 90, 152, 56, 304)
      },
      compileCatsSvg() {
        if (!this.compileCats) return `<p class="dash-chart-empty">Loading from emerge.log…</p>`
        const all = Object.entries(this.compileCats)
        if (!all.length) return `<p class="dash-chart-empty">No emerge history found in /var/log/emerge.log</p>`
        const fmtH = s => {
          const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60)
          return h ? `${h}h ${m}m` : `${m}m`
        }
        const rows = this._topNOther(all, 10, i => paletteColor('info', i))
        const maxVal = Math.max(1, ...rows.map(row => row.val))
        const items = rows.map(row => {
          const width = Math.max(4, Math.round((row.val / maxVal) * 100))
          return `<div class="dash-compile-row">
  <div class="dash-compile-row-head">
    <span class="dash-compile-label">${this._esc(row.label)}</span>
    <span class="dash-compile-value">${this._esc(fmtH(row.val))}</span>
  </div>
  <div class="dash-compile-bar">
    <span class="dash-compile-bar-fill" style="width:${width}%;background:${row.color}"></span>
  </div>
</div>`
        }).join('')
        return `<div class="dash-compile-list">${items}</div>`
      },
      keywordDistSvg() {
        if (!this.pkgStats?.keyword_dist) return ''
        const kd = this.pkgStats.keyword_dist
        const total = (kd.stable || 0) + (kd.testing || 0) + (kd.live || 0) + (kd.unknown || 0)
        if (total === 0) return `<p class="dash-chart-empty">No data</p>`
        return this._percentBarSvg([
          { val: kd.stable,  color: CHART_COLORS.success, label: 'Stable' },
          { val: kd.testing, color: CHART_COLORS.warning, label: 'Testing' },
          { val: kd.live,    color: CHART_COLORS.info, label: 'Live' },
          { val: kd.unknown, color: CHART_COLORS.muted, label: 'Other' },
        ].filter(s => s.val > 0), total, 68, 72, 50, 190)
      },
      _hBarSvg(rows, fmtVal = v => String(v), labelW = 105, barW = 160, valueW = 52, viewW = 320) {
        const maxVal = Math.max(1, ...rows.map(r => r.val))
        const ROW_H = 22, PAD_T = 2
        const items = rows.map((r, i) => {
          const fillW = r.val === 0 ? 0 : Math.max(1, Math.round((r.val / maxVal) * barW))
          const y = PAD_T + i * ROW_H
          return `<text x="0" y="${y + 11}" fill="${CHART_COLORS.text}" font-size="11" dominant-baseline="middle">${this._esc(r.label)}</text>` +
                 `<rect x="${labelW}" y="${y + 4}" width="${barW}" height="12" fill="${CHART_COLORS.track}"/>` +
                 (fillW > 0 ? `<rect x="${labelW}" y="${y + 4}" width="${fillW}" height="12" fill="${r.color}"/>` : '') +
                 `<text x="${labelW + barW + valueW - 4}" y="${y + 11}" fill="${CHART_COLORS.textMuted}" font-size="10" text-anchor="end" dominant-baseline="middle">${this._esc(fmtVal(r.val))}</text>`
        }).join('')
        const h = PAD_T + rows.length * ROW_H
        return `<svg viewBox="0 0 ${viewW} ${h}" width="100%" height="${h}" xmlns="http://www.w3.org/2000/svg" font-family="JetBrains Mono, Fira Code, monospace" style="display:block">${items}</svg>`
      },
      _topNOther(entries, n, colorFn, otherColor = CHART_COLORS.muted) {
        const top = entries.slice(0, n)
        const rest = entries.slice(n)
        const rows = top.map(([label, val], i) => ({ label, val, color: colorFn(i, top.length) }))
        if (rest.length > 0) {
          const otherVal = rest.reduce((s, [, v]) => s + v, 0)
          if (otherVal > 0) rows.push({ label: 'Other', val: otherVal, color: otherColor })
        }
        return rows
      },
      _percentBarSvg(rows, total, labelW = 150, barW = 110, valueW = 78, viewW = 340) {
        const ROW_H = 22, PAD_T = 2
        const items = rows.map((row, i) => {
          const pct = total ? Math.round((row.val / total) * 100) : 0
          const fillW = pct === 0 ? 0 : Math.max(1, Math.round((pct / 100) * barW))
          const y = PAD_T + i * ROW_H
          return `<text x="0" y="${y + 11}" fill="${CHART_COLORS.text}" font-size="11" dominant-baseline="middle">${this._esc(row.label)}</text>` +
                 `<rect x="${labelW}" y="${y + 4}" width="${barW}" height="12" fill="${CHART_COLORS.track}"/>` +
                 (fillW > 0 ? `<rect x="${labelW}" y="${y + 4}" width="${fillW}" height="12" fill="${row.color}"/>` : '') +
                 `<text x="${labelW + barW + valueW - 4}" y="${y + 11}" fill="${CHART_COLORS.textMuted}" font-size="10" text-anchor="end" dominant-baseline="middle">${pct}% ${this._esc(String(row.val))}</text>`
        }).join('')
        const h = PAD_T + rows.length * ROW_H
        return `<svg viewBox="0 0 ${viewW} ${h}" width="100%" height="${h}" xmlns="http://www.w3.org/2000/svg" font-family="JetBrains Mono, Fira Code, monospace" style="display:block">${items}</svg>`
      },
      slottedSvg() {
        if (!this.pkgStats?.slotted?.length) return `<p class="dash-chart-empty">No multi-version packages found — clean system!</p>`
        const all = this.pkgStats.slotted.map(it => [it.cp.split('/')[1] || it.cp, it.count])
        const colorFn = i => paletteColor('warm', i)
        return this._hBarSvg(this._topNOther(all, 10, colorFn), v => `${v} slots`, 120, 142, 64, 326)
      },
      srcVsBinSvg() {
        const svb = this.pkgStats?.src_vs_bin
        if (!svb) return ''
        const total = (svb.source || 0) + (svb.binary || 0)
        if (total === 0) return `<p class="dash-chart-empty">No data</p>`
        return this._percentBarSvg([
          { val: svb.source || 0, color: CHART_COLORS.primary, label: 'Source' },
          { val: svb.binary || 0, color: CHART_COLORS.info, label: 'Binary' },
        ].filter(s => s.val > 0), total, 64, 78, 46, 188)
      },
      licenseSvg() {
        const ld = this.pkgStats?.license_dist
        if (!ld) return ''
        const total = Object.values(ld).reduce((a, b) => a + b, 0)
        if (total === 0) return `<p class="dash-chart-empty">No data</p>`
        const segments = [
          { key: 'copyleft',    color: CHART_COLORS.primary, label: 'Copyleft (GPL…)' },
          { key: 'permissive',  color: CHART_COLORS.info, label: 'Permissive (MIT, Apache…)' },
          { key: 'proprietary', color: CHART_COLORS.danger, label: 'Proprietary' },
          { key: 'other',       color: CHART_COLORS.muted, label: 'Other / Unknown' },
        ].filter(s => ld[s.key] > 0).map(s => ({ ...s, val: ld[s.key] }))
        return this._percentBarSvg(segments, total, 156, 108, 88, 352)
      },
    }
  }

  function packageListComponent(mode = 'packages') {
    return {
      packages: [], loading: true, _timer: null,
      search: Alpine.store('router').packageListSearch,
      mode,
      init() {
        this._load()
        // reload when navigating (back) to the packages list
        this.$watch('$store.router.view', v => {
          if (v === this.mode && !Alpine.store('router').selectedPackage) this._load()
        })
        this.$watch('$store.router.selectedPackage', v => {
          if (!v && Alpine.store('router').view === this.mode) this._load()
        })
        this.$watch('$store.router.packageStateVersion', () => {
          if (Alpine.store('router').view === this.mode) this._load()
        })
      },
      async _load() {
        this.loading = true
        try { this.packages = await api.packages(this.search) }
        finally { this.loading = false }
      },
      openPackage(cpv) {
        if (this.mode === 'use-flags') navigateToUse(cpv)
        else navigateTo(cpv)
      },
      title() {
        return this.mode === 'use-flags' ? 'USE Flags' : 'Installed Packages'
      },
      placeholder() {
        return this.mode === 'use-flags' ? 'Filter packages for USE inspection…' : 'Filter…'
      },
      visibleCountText() {
        if (this.loading) return 'Loading packages…'
        const count = this.packages.length
        return count + ' package' + (count === 1 ? '' : 's')
      },
      searchStateText() {
        const query = this.search.trim()
        return query
          ? 'Filtered by "' + query + '". Select a package to inspect metadata, USE state, and dependencies.'
          : 'Select a package to inspect metadata, USE state, and dependencies.'
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

  function useFlagsExplorerComponent() {
    return {
      search: Alpine.store('router').useFlagsQuery,
      activeFilters: [],
      audit: null,
      loading: true,
      error: null,
      _timer: null,
      _sectionLimit: 8,
      _expandedSections: {},
      init() {
        if (Alpine.store('router').view === 'use-flags') {
          this._load()
        }
        this.$watch('$store.router.view', view => {
          if (view !== 'use-flags') return
          this._load()
        })
        this.$watch('$store.router.selectedUseFlag', flag => {
          if (!flag || Alpine.store('router').view !== 'use-flags') return
          this.$nextTick(() => scrollMainToTop())
        })
      },
      async _load() {
        this.loading = true
        this.error = null
        try {
          this.audit = await api.globalUseFlagsAudit()
          this._ensureSelection()
        } catch (e) {
          this.audit = null
          this.error = e.message
        } finally {
          this.loading = false
        }
      },
      _allFlags() {
        return Array.isArray(this.audit?.flags) ? this.audit.flags : []
      },
      _ensureSelection() {
        const selected = Alpine.store('router').selectedUseFlag
        if (!selected) return
        if (this._allFlags().some(flag => flag.name === selected)) return
        Alpine.store('router').selectedUseFlag = null
      },
      selectedFlagName() {
        return Alpine.store('router').selectedUseFlag
      },
      selectedFlag() {
        const name = this.selectedFlagName()
        return this._allFlags().find(flag => flag.name === name) || null
      },
      onSearchInput() {
        Alpine.store('router').useFlagsQuery = this.search
        clearTimeout(this._timer)
        this._timer = setTimeout(() => this._ensureSelection(), 120)
      },
      toggleStateFilter(value) {
        if (value === 'all') {
          this.activeFilters = []
          this._ensureSelection()
          return
        }
        const active = new Set(this.activeFilters)
        if (active.has(value)) active.delete(value)
        else active.add(value)
        this.activeFilters = [...active]
        this._ensureSelection()
      },
      stateFilters() {
        return [
          { value: 'all', label: 'All' },
          { value: 'has-overrides', label: 'Has overrides' },
          { value: 'mismatch', label: 'Mismatch' },
          { value: 'installed-only', label: 'Installed only' },
          { value: 'forced', label: 'Forced' },
          { value: 'masked', label: 'Masked' },
          { value: 'global-on', label: 'Global on' },
          { value: 'global-off', label: 'Global off' },
        ]
      },
      isFilterActive(value) {
        return value === 'all' ? this.activeFilters.length === 0 : this.activeFilters.includes(value)
      },
      matchesStateFilter(flag, filterValue) {
        if (filterValue === 'has-overrides') return !!this.packageOverrideCount(flag)
        if (filterValue === 'mismatch') return !!this.mismatchCount(flag)
        if (filterValue === 'installed-only') return !!this.installedSupportCount(flag)
        if (filterValue === 'forced') return !!flag?.forced_count
        if (filterValue === 'masked') return !!flag?.masked_count
        if (filterValue === 'global-on') return flag?.has_global && flag?.global_enabled === true
        if (filterValue === 'global-off') return flag?.has_global && flag?.global_enabled === false
        return true
      },
      filteredFlags() {
        const query = this.search.trim().toLowerCase()
        return this._allFlags().filter(flag => {
          if (this.activeFilters.length && !this.activeFilters.every(filterValue => this.matchesStateFilter(flag, filterValue))) return false
          if (!query) return true
          return (
            flag.name.toLowerCase().includes(query) ||
            useFlagDescription(flag).toLowerCase().includes(query)
          )
        })
      },
      visibleCountText() {
        if (this.loading) return 'Loading USE flags…'
        const shown = this.filteredFlags().length
        const total = this._allFlags().length
        if (!total) return 'No USE flags'
        return shown === total ? total + ' USE flags' : shown + ' of ' + total + ' USE flags'
      },
      packageOverrideCount(flag) {
        return flag?.package_override_count || flag?.local_count || 0
      },
      packageOverrideEnabledCount(flag) {
        return flag?.package_override_enabled_count || flag?.enabled_count || 0
      },
      packageOverrideDisabledCount(flag) {
        return flag?.package_override_disabled_count || flag?.disabled_count || 0
      },
      installedSupportCount(flag) {
        return flag?.installed_support_count || flag?.installed_usage_count || 0
      },
      installedEnabledCount(flag) {
        return flag?.installed_enabled_count || 0
      },
      installedDisabledCount(flag) {
        return flag?.installed_disabled_count || 0
      },
      mismatchCount(flag) {
        return flag?.mismatch_count || 0
      },
      overridePackagesEnabled(flag) {
        return Array.isArray(flag?.override_packages_enabled) ? flag.override_packages_enabled : (Array.isArray(flag?.packages_enabled) ? flag.packages_enabled : [])
      },
      overridePackagesDisabled(flag) {
        return Array.isArray(flag?.override_packages_disabled) ? flag.override_packages_disabled : (Array.isArray(flag?.packages_disabled) ? flag.packages_disabled : [])
      },
      installedPackagesEnabled(flag) {
        return Array.isArray(flag?.installed_packages_enabled) ? flag.installed_packages_enabled : []
      },
      installedPackagesDisabled(flag) {
        return Array.isArray(flag?.installed_packages_disabled) ? flag.installed_packages_disabled : []
      },
      summaryCountLabel(count, noun) {
        return count + ' ' + noun + (count === 1 ? '' : 's')
      },
      summaryText(flag) {
        const parts = []
        if (flag?.has_global) parts.push('global ' + (flag.global_enabled ? 'on' : 'off'))
        if (this.packageOverrideCount(flag)) parts.push(this.summaryCountLabel(this.packageOverrideCount(flag), 'override'))
        if (this.installedSupportCount(flag)) parts.push(this.installedSupportCount(flag) + ' installed supporting packages')
        if (this.mismatchCount(flag)) parts.push(this.summaryCountLabel(this.mismatchCount(flag), 'mismatch'))
        return parts.join(' · ') || 'No summary available'
      },
      selectFlag(flag) {
        if (!flag?.name) return
        navigateToUse(flag.name)
      },
      backToList() {
        navigate('use-flags')
      },
      isSelected(flag) {
        return flag?.name === this.selectedFlagName()
      },
      globalStateLabel(flag) {
        if (!flag?.has_global) return 'Unset'
        return flag.global_enabled ? 'Enabled' : 'Disabled'
      },
      globalSourceLabel(flag) {
        if (!flag?.has_global) return 'none'
        return useFlagSourceLabel({ source: flag.global_source, origin_type: flag.global_origin_type })
      },
      globalOriginDetail(flag) {
        if (!flag?.has_global) return 'No explicit global source recorded for this flag.'
        return useFlagOriginDetail({
          source: flag.global_source,
          origin_type: flag.global_origin_type,
          origin_file: flag.global_origin_file,
          default_on: false,
        })
      },
      detailBadges(flag) {
        const badges = []
        if (flag?.has_global) {
          badges.push({ tone: flag.global_enabled ? 'on' : 'off', text: 'Global ' + (flag.global_enabled ? 'on' : 'off') })
        }
        if (this.packageOverrideCount(flag)) badges.push({ tone: 'local', text: this.summaryCountLabel(this.packageOverrideCount(flag), 'override') })
        if (this.installedSupportCount(flag)) badges.push({ tone: 'info', text: this.installedSupportCount(flag) + ' supporting' })
        if (this.mismatchCount(flag)) badges.push({ tone: 'warn', text: this.summaryCountLabel(this.mismatchCount(flag), 'mismatch') })
        if (flag?.forced_count) badges.push({ tone: 'forced', text: flag.forced_count + ' forced' })
        if (flag?.masked_count) badges.push({ tone: 'masked', text: flag.masked_count + ' masked' })
        return badges
      },
      listBadges(flag) {
        const badges = []
        if (flag?.has_global) badges.push({ tone: flag.global_enabled ? 'on' : 'off', text: flag.global_enabled ? 'Global on' : 'Global off' })
        if (this.packageOverrideCount(flag)) badges.push({ tone: 'local', text: 'Overrides' })
        if (this.installedSupportCount(flag)) badges.push({ tone: 'info', text: 'Supporting' })
        if (this.mismatchCount(flag)) badges.push({ tone: 'warn', text: 'Mismatch' })
        if (flag?.forced_count) badges.push({ tone: 'forced', text: 'Forced' })
        if (flag?.masked_count) badges.push({ tone: 'masked', text: 'Masked' })
        return badges
      },
      packageStateLabel(pkg) {
        if (pkg?.forced) return 'Forced enabled'
        if (pkg?.masked) return 'Masked disabled'
        return pkg?.enabled ? 'Override enabled' : 'Override disabled'
      },
      packageSourceLabel(pkg) {
        return useFlagSourceLabel(pkg)
      },
      packageSourceTone(pkg) {
        return useFlagSourceTone(pkg)
      },
      packageStateTone(pkg) {
        if (pkg?.forced) return 'forced'
        if (pkg?.masked) return 'masked'
        return pkg?.enabled ? 'on' : 'off'
      },
      packageOriginDetail(pkg) {
        return useFlagOriginDetail(pkg)
      },
      installedPackageStateLabel(pkg) {
        return pkg?.enabled ? 'Built enabled' : 'Built disabled'
      },
      installedPackageStateTone(pkg) {
        return pkg?.enabled ? 'on' : 'off'
      },
      configuredPackageStateLabel(pkg) {
        return pkg?.configured_enabled ? 'Configured enabled' : 'Configured disabled'
      },
      configuredPackageStateTone(pkg) {
        return pkg?.configured_enabled ? 'on' : 'off'
      },
      configuredPackageSourceLabel(pkg) {
        return useFlagSourceLabel({
          configured_source: pkg?.configured_source,
          configured_origin_type: pkg?.configured_origin_type,
        })
      },
      configuredPackageSourceTone(pkg) {
        return useFlagSourceTone({
          configured_source: pkg?.configured_source,
          configured_origin_type: pkg?.configured_origin_type,
        })
      },
      configuredPackageOriginDetail(pkg) {
        return useFlagOriginDetail({
          configured_source: pkg?.configured_source,
          configured_origin_type: pkg?.configured_origin_type,
          configured_origin_file: pkg?.configured_origin_file,
          default_on: pkg?.default_on,
        })
      },
      sourceLabel(item) {
        return useFlagSourceLabel(item)
      },
      mismatchLabel(pkg) {
        return pkg?.mismatch ? 'Mismatch' : ''
      },
      mismatchText(flag) {
        const count = this.mismatchCount(flag)
        if (!count) return ''
        return count === 1
          ? '1 installed package differs between configured state and built state.'
          : count + ' installed packages differ between configured state and built state.'
      },
      termHelp(term) {
        const help = {
          override: 'Explicit package-specific state from package.use for this flag.',
          'supporting-package': 'Installed package whose IUSE advertises this flag.',
          'built-enabled': 'Installed package was built with this flag enabled.',
          'built-disabled': 'Installed package supports the flag but was built without it.',
          forced: 'The profile or repository forces this flag on for the package.',
          masked: 'The profile or repository masks this flag off for the package.',
          mismatch: 'Configured state differs from the installed build state.',
        }
        return help[term] || ''
      },
      summaryValueClass(flag, key) {
        if (key === 'global') return this.globalStateLabel(flag) === 'Enabled' ? 'is-on' : (this.globalStateLabel(flag) === 'Disabled' ? 'is-off' : '')
        if (key === 'mismatch' && this.mismatchCount(flag)) return 'is-warn'
        return ''
      },
      hasAdvancedDetails(flag) {
        return !!(flag?.global_history?.length || flag?.global_origin_file || flag?.global_source)
      },
      sectionKey(flag, key) {
        return (flag?.name || 'flag') + ':' + key
      },
      visiblePackages(flag, key, items) {
        if (!Array.isArray(items)) return []
        return this._expandedSections[this.sectionKey(flag, key)] ? items : items.slice(0, this._sectionLimit)
      },
      remainingPackages(flag, key, items) {
        if (!Array.isArray(items)) return 0
        return Math.max(0, items.length - this.visiblePackages(flag, key, items).length)
      },
      togglePackageSection(flag, key) {
        const sectionKey = this.sectionKey(flag, key)
        this._expandedSections = {
          ...this._expandedSections,
          [sectionKey]: !this._expandedSections[sectionKey],
        }
      },
      emptyStateText() {
        return this.search.trim() ? 'No USE flags match the current search and filters.' : 'No USE flags available.'
      },
      packageOverrideSectionTitle(flag, enabled) {
        const count = enabled ? this.packageOverrideEnabledCount(flag) : this.packageOverrideDisabledCount(flag)
        return (enabled ? 'Overrides enabling this flag' : 'Overrides disabling this flag') + ' (' + count + ')'
      },
      installedSectionTitle(flag, enabled) {
        const count = enabled ? this.installedEnabledCount(flag) : this.installedDisabledCount(flag)
        return (enabled ? 'Installed packages built with this flag enabled' : 'Installed packages supporting this flag but built without it') + ' (' + count + ')'
      },
    }
  }

  function searchComponent() {
    return {
      query: Alpine.store('router').searchViewQuery,
      results: [], loading: false, searched: false, _timer: null,
      init() {
        if (this.query.length >= 2) this._search()
        this.$watch('$store.router.searchViewQuery', value => {
          const next = value || ''
          if (next === this.query) return
          this.query = next
          clearTimeout(this._timer)
          if (this.query.length < 2) {
            this.results = []
            this.searched = false
            return
          }
          if (Alpine.store('router').view === 'search') this._search()
        })
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
          if (atom && ['packages', 'use-flags'].includes(Alpine.store('router').view)) this._load(atom)
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
      error: null, flagsError: null, flagsNotice: null, depsError: null,
      init() {
        const atom = Alpine.store('router').selectedPackage
        if (atom) this._load(atom)
        else this._reset()
        this.$watch('$store.router.selectedPackage', atom => {
          if (atom && ['packages', 'use-flags'].includes(Alpine.store('router').view)) this._load(atom)
          else this._reset()
        })
        this.$watch('$store.router.view', view => {
          if (view === 'use-flags') this.tab = 'use flags'
          else if (view === 'packages') this.tab = 'info'
          const atom = Alpine.store('router').selectedPackage
          if (atom && ['packages', 'use-flags'].includes(view)) this._load(atom)
        })
        this.$watch('$store.router.packageStateVersion', () => {
          const atom = Alpine.store('router').selectedPackage
          const view = Alpine.store('router').view
          if (atom && ['packages', 'use-flags'].includes(view)) this._load(atom)
        })
      },
      _reset() {
        this.info = null; this.flags = null; this.deps = null
        this.error = null; this.flagsError = null; this.flagsNotice = null; this.depsError = null
        this.tab = Alpine.store('router').view === 'use-flags' ? 'use flags' : 'info'
      },
      async _load(atom) {
        this._reset()
        const [infoRes, plainFlagsRes, originFlagsRes, depsRes] = await Promise.allSettled([
          api.packageInfo(atom),
          api.useFlags(atom),
          api.useFlagOrigins(atom),
          api.deps(atom),
        ])
        if (infoRes.status === 'fulfilled') {
          this.info = normalizePayload(infoRes.value)
        } else {
          this.error = infoRes.reason?.message ?? 'Failed to load package info'
        }
        const originFlags = originFlagsRes.status === 'fulfilled' ? normalizePayload(originFlagsRes.value) : null
        const plainFlags = plainFlagsRes.status === 'fulfilled' ? normalizePayload(plainFlagsRes.value) : null
        if (originFlags?.flags?.length) {
          this.flags = originFlags
        } else if (plainFlagsRes.status === 'fulfilled') {
          this.flags = plainFlags
          if (originFlagsRes.status === 'rejected') {
            this.flagsNotice = 'USE provenance unavailable; showing effective flags only.'
          }
        } else {
          this.flags = null
          this.flagsError = plainFlagsRes.reason?.message ?? originFlagsRes.reason?.message ?? 'Failed to load use flags'
        }
        this.deps = depsRes.status === 'fulfilled' ? depsRes.value : null
        if (depsRes.status === 'rejected') this.depsError = depsRes.reason?.message ?? 'Failed to load deps'
      },
      hasFlagHistory(flag) {
        return !!(flag && Array.isArray(flag.history) && flag.history.length)
      },
      flagOriginText(flag) {
        return useFlagSourceLabel(flag)
      },
      flagFileName(path) {
        if (!path) return '—'
        const parts = String(path).split('/')
        return parts[parts.length - 1] || path
      },
      flagHistoryState(step) {
        return step?.enabled ? 'enabled' : 'disabled'
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
            if (this.returncode === 0) {
              invalidatePackageState(atom)
              this.step = 'done'
            }
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
              invalidatePackageState(atom)
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
          invalidatePackageState(Alpine.store('router').installAtom)
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
          if (this.etcFiles.every(f => f.resolved)) {
            invalidatePackageState(Alpine.store('router').installAtom)
            this.step = 'done'
          }
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

  const MAINTENANCE_ACTIONS = {
    sync: {
      id: 'sync',
      title: 'Sync',
      summary: 'Refresh repository metadata before any world resolution.',
      risk: 'Low impact. Updates local Portage repository state only.',
      notes: [
        'Run this when the tree may be stale.',
        'A fresh sync makes update checks and depclean previews more trustworthy.',
      ],
    },
    worldPretend: {
      id: 'worldPretend',
      title: 'Check updates',
      summary: 'Resolve the pending @world plan without modifying the system.',
      risk: 'Read-only preview. Use it to inspect blockers, rebuild size, and keyword changes.',
      notes: [
        'Pretend output is the safest place to spot conflicts before a real update.',
      ],
    },
    worldUpdate: {
      id: 'worldUpdate',
      title: 'Update @world',
      summary: 'Apply the selected world-update plan with the current emerge options.',
      risk: 'High impact. Can rebuild a large part of the system and keep jobs running for a while.',
      notes: [
        'Review the preview first, then run the real update with only the flags you actually need.',
      ],
    },
    preserved: {
      id: 'preserved',
      title: 'Preserved rebuild',
      summary: 'Rebuild packages that still rely on preserved libraries after upgrades.',
      risk: 'Moderate impact. Usually safe and targeted, but it can still trigger multiple rebuilds.',
      notes: [
        'This is typically follow-up work after updates changed linked libraries.',
      ],
    },
    depclean: {
      id: 'depclean',
      title: 'Depclean',
      summary: 'Preview and remove packages that are no longer required by the current world set.',
      risk: 'High risk if skipped straight to removal. Always inspect the pretend set first.',
      notes: [
        'Use the pretend phase to confirm nothing important will be removed unexpectedly.',
      ],
    },
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
      pkgStats: null,
      selectedAction: 'worldPretend',
      init() {
        this.eoLoad()
        this.$watch('$store.router.view', v => { if (v === 'updates') { this._resumeAll(); this._loadSidebar() } })
        this._loadSidebar()
        this._resumeAll()
      },
      async _loadSidebar() {
        try {
          this.pkgStats = await api.pkgStats()
        } catch (_) {}
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
        this._syncSelectedAction()
      },
      maintenanceActions() {
        return Object.values(MAINTENANCE_ACTIONS)
      },
      hasPortageDisk() {
        return this.portageDiskRows().length > 0
      },
      portageDiskRows() {
        return buildPortageDiskRows(this.pkgStats)
      },
      portageHint() {
        return portageDiskHint(this.pkgStats)
      },
      selectAction(id) {
        if (MAINTENANCE_ACTIONS[id]) this.selectedAction = id
      },
      _syncSelectedAction() {
        const active = this.maintenanceActions().find(action => this.isActionAttentionWorthy(action.id))
        if (active) this.selectedAction = active.id
        else if (!MAINTENANCE_ACTIONS[this.selectedAction]) this.selectedAction = 'worldPretend'
      },
      isActionAttentionWorthy(id) {
        const op = this.opFor(id)
        if (!op) return false
        if (op.running) return true
        return id === 'depclean' && this.depclean.dcStep === 'confirm'
      },
      opFor(id) {
        return this[id] || null
      },
      actionSummary(id) {
        return MAINTENANCE_ACTIONS[id]?.summary || ''
      },
      selectedActionMeta() {
        return MAINTENANCE_ACTIONS[this.selectedAction] || MAINTENANCE_ACTIONS.worldPretend
      },
      selectedOp() {
        return this.opFor(this.selectedActionMeta().id)
      },
      commandText(id = this.selectedActionMeta().id) {
        if (id === 'worldUpdate') {
          return [this._eoCommand, ...this._eoBaseFlags, ...this.eoUserFlags(), '@world'].join(' ')
        }
        if (id === 'worldPretend') return 'emerge -uDN --pretend @world'
        if (id === 'sync') return 'emaint sync -a'
        if (id === 'preserved') return 'emerge @preserved-rebuild'
        if (id === 'depclean') return 'emerge --depclean'
        return ''
      },
      optionSummary() {
        const flags = this.eoUserFlags()
        return flags.length ? flags.join(' ') : 'Using Arbor default world-update flags only.'
      },
      lastOutputLine(id = this.selectedActionMeta().id) {
        const op = this.opFor(id)
        if (!op?.lines?.length) return ''
        for (let i = op.lines.length - 1; i >= 0; i -= 1) {
          const line = String(op.lines[i] || '').trim()
          if (line) return line
        }
        return ''
      },
      activityStatus(id = this.selectedActionMeta().id) {
        const op = this.opFor(id)
        if (!op) return { tone: 'muted', label: 'Idle', detail: 'No active job.' }
        if (id === 'depclean' && this.depclean.dcStep === 'confirm' && !op.running) {
          return { tone: 'warn', label: 'Awaiting confirmation', detail: 'Pretend completed. Review the removal set before starting depclean.' }
        }
        if (op.running) {
          return { tone: 'info', label: 'Running', detail: this.lastOutputLine(id) || 'Streaming output from the active job.' }
        }
        if (op.rc === 0) {
          return { tone: 'ok', label: 'Completed', detail: 'No active job. Last run exited cleanly.' }
        }
        if (op.rc !== null) {
          return { tone: 'err', label: 'Stopped on error', detail: 'No active job. Last run exited with status ' + op.rc + '.' }
        }
        return { tone: 'muted', label: 'Idle', detail: 'No active job.' }
      },
      lastResultText(id = this.selectedActionMeta().id) {
        const op = this.opFor(id)
        if (!op) return 'No completed run yet.'
        if (id === 'depclean' && this.depclean.dcStep === 'confirm' && !op.running) {
          return this.lastOutputLine(id) || 'Pretend finished successfully; removal has not started yet.'
        }
        if (op.running) return this.lastOutputLine(id) || 'Job is still running.'
        if (op.rc === 0) return this.lastOutputLine(id) || 'Completed successfully.'
        if (op.rc !== null) return this.lastOutputLine(id) || 'Exited with status ' + op.rc + '.'
        return 'No completed run yet.'
      },
      riskNotes(id = this.selectedActionMeta().id) {
        const meta = MAINTENANCE_ACTIONS[id]
        if (!meta) return []
        const notes = [meta.risk, ...meta.notes]
        if (id === 'worldUpdate') notes.push(this.optionSummary())
        if (id === 'depclean' && this.depclean.dcStep === 'confirm') {
          notes.push('Removal is armed from a clean pretend pass. Start it only after reviewing the pretend output in the main pane.')
        }
        return notes
      },
      cardState(id) {
        const op = this.opFor(id)
        if (!op) return { tone: 'muted', text: 'idle' }
        if (id === 'depclean' && this.depclean.dcStep === 'confirm' && !op.running) return { tone: 'warn', text: 'review' }
        if (op.running) return { tone: 'info', text: 'running' }
        if (op.rc === 0) return { tone: 'ok', text: 'done' }
        if (op.rc !== null) return { tone: 'err', text: 'exit ' + op.rc }
        return { tone: 'muted', text: 'idle' }
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
        this.selectAction('sync')
        this.sync.lines = []; this.sync.rc = null; this.sync.running = true; this.sync.expanded = true
        this.sync.ws = wsGlobalEmerge('sync', (msg) => {
          if (msg.job_id) { localStorage.setItem(_JOB_META.sync.storage, msg.job_id); return }
          if (msg.line !== undefined) this._appendLine(this.sync, 'syncTerm', msg.line)
          if (msg.done) { this.sync.running = false; this.sync.rc = msg.returncode ?? null; this.sync.ws = null; localStorage.removeItem(_JOB_META.sync.storage) }
        })
      },
      _attachSync(id) {
        this.selectAction('sync')
        this.sync.running = true; this.sync.expanded = true; this.sync.lines = []; this.sync.rc = null
        this.sync.ws = wsJobAttach(id, (msg) => {
          if (msg.line !== undefined) this._appendLine(this.sync, 'syncTerm', msg.line)
          if (msg.done) { this.sync.running = false; this.sync.rc = msg.returncode ?? null; this.sync.ws = null; localStorage.removeItem(_JOB_META.sync.storage) }
        })
      },
      startWorldPretend() {
        this.selectAction('worldPretend')
        this.worldPretend.lines = []; this.worldPretend.rc = null; this.worldPretend.running = true; this.worldPretend.expanded = true
        this.worldPretend.ws = wsGlobalEmerge('world-pretend', (msg) => {
          if (msg.job_id) { localStorage.setItem(_JOB_META.worldPretend.storage, msg.job_id); return }
          if (msg.line !== undefined) this._appendLine(this.worldPretend, 'wpTerm', msg.line)
          if (msg.done) { this.worldPretend.running = false; this.worldPretend.rc = msg.returncode ?? null; this.worldPretend.ws = null; localStorage.removeItem(_JOB_META.worldPretend.storage) }
        })
      },
      _attachWorldPretend(id) {
        this.selectAction('worldPretend')
        this.worldPretend.running = true; this.worldPretend.expanded = true; this.worldPretend.lines = []; this.worldPretend.rc = null
        this.worldPretend.ws = wsJobAttach(id, (msg) => {
          if (msg.line !== undefined) this._appendLine(this.worldPretend, 'wpTerm', msg.line)
          if (msg.done) { this.worldPretend.running = false; this.worldPretend.rc = msg.returncode ?? null; this.worldPretend.ws = null; localStorage.removeItem(_JOB_META.worldPretend.storage) }
        })
      },
      startWorldUpdate() {
        this.selectAction('worldUpdate')
        this.worldUpdate.lines = []; this.worldUpdate.rc = null; this.worldUpdate.running = true; this.worldUpdate.expanded = true
        this.worldUpdate.ws = wsGlobalEmerge('world-update', (msg) => {
          if (msg.job_id) { localStorage.setItem(_JOB_META.worldUpdate.storage, msg.job_id); return }
          if (msg.line !== undefined) this._appendLine(this.worldUpdate, 'wuTerm', msg.line)
          if (msg.done) { this.worldUpdate.running = false; this.worldUpdate.rc = msg.returncode ?? null; this.worldUpdate.ws = null; localStorage.removeItem(_JOB_META.worldUpdate.storage) }
        }, { opts: this.eoOpts() })
      },
      _attachWorldUpdate(id) {
        this.selectAction('worldUpdate')
        this.worldUpdate.running = true; this.worldUpdate.expanded = true; this.worldUpdate.lines = []; this.worldUpdate.rc = null
        this.worldUpdate.ws = wsJobAttach(id, (msg) => {
          if (msg.line !== undefined) this._appendLine(this.worldUpdate, 'wuTerm', msg.line)
          if (msg.done) { this.worldUpdate.running = false; this.worldUpdate.rc = msg.returncode ?? null; this.worldUpdate.ws = null; localStorage.removeItem(_JOB_META.worldUpdate.storage) }
        })
      },
      startDepcleanPretend() {
        this.selectAction('depclean')
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
        this.selectAction('depclean')
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
        this.selectAction('depclean')
        localStorage.setItem('arbor_depclean_ran', '1')
        this.depclean.lines = []; this.depclean.rc = null; this.depclean.running = true; this.depclean.expanded = true; this.depclean.dcStep = 'running'
        this.depclean.ws = wsGlobalEmerge('depclean', (msg) => {
          if (msg.job_id) { localStorage.setItem(_JOB_META.depclean.storage, msg.job_id); return }
          if (msg.line !== undefined) this._appendLine(this.depclean, 'dcTerm', msg.line)
          if (msg.done) { this.depclean.running = false; this.depclean.rc = msg.returncode ?? null; this.depclean.ws = null; localStorage.removeItem(_JOB_META.depclean.storage) }
        })
      },
      _attachDepclean(id) {
        this.selectAction('depclean')
        this.depclean.running = true; this.depclean.expanded = true; this.depclean.dcStep = 'running'; this.depclean.lines = []; this.depclean.rc = null
        this.depclean.ws = wsJobAttach(id, (msg) => {
          if (msg.line !== undefined) this._appendLine(this.depclean, 'dcTerm', msg.line)
          if (msg.done) { this.depclean.running = false; this.depclean.rc = msg.returncode ?? null; this.depclean.ws = null; localStorage.removeItem(_JOB_META.depclean.storage) }
        })
      },
      startPreserved() {
        this.selectAction('preserved')
        this.preserved.lines = []; this.preserved.rc = null; this.preserved.running = true; this.preserved.expanded = true
        this.preserved.ws = wsGlobalEmerge('preserved-rebuild', (msg) => {
          if (msg.job_id) { localStorage.setItem(_JOB_META.preserved.storage, msg.job_id); return }
          if (msg.line !== undefined) this._appendLine(this.preserved, 'psTerm', msg.line)
          if (msg.done) { this.preserved.running = false; this.preserved.rc = msg.returncode ?? null; this.preserved.ws = null; localStorage.removeItem(_JOB_META.preserved.storage) }
        })
      },
      _attachPreserved(id) {
        this.selectAction('preserved')
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
      selectedUseFlag: null,
      installAtom:     null,
      uninstallAtom:   null,
      packageStateVersion: 0,
      lastChangedPackage: null,
      packageListSearch: '',
      searchViewQuery:   '',
      useFlagsQuery:     '',
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
      addShow: false, addStep: 'form', addEnabled: null, addConfigError: null, addName: '', addSyncType: 'git', addSyncUri: '',
      addBusy: false, addError: null, addInfo: null, addDisabledNotice: null, addDangerAck: false, addApprovalText: '',
      expanded: null,
      // flat top-level sync state (one active sync at a time)
      syncName: null, syncRunning: false, syncLines: [], syncRc: null,

      init() {
        this._load()
        this.$watch('$store.router.view', v => { if (v === 'overlays') this._load() })
      },
      async _load() {
        this.loading = true; this.error = null; this.addConfigError = null; this.addEnabled = null
        try {
          this.list = await overlays.list()
          try {
            const cfg = await overlays.config()
            this.addEnabled = !!cfg.add_enabled
          } catch (e) {
            this.addConfigError = e.message
          }
          this.addDisabledNotice = null
        }
        catch(e) { this.error = e.message }
        finally { this.loading = false }
      },
      _resetAdd() {
        this.addStep = 'form'
        this.addName = ''
        this.addSyncType = 'git'
        this.addSyncUri = ''
        this.addError = null
        this.addInfo = null
        this.addDisabledNotice = null
        this.addDangerAck = false
        this.addApprovalText = ''
      },
      toggleAdd() {
        this.addShow = !this.addShow
        if (!this.addShow) this._resetAdd()
        else {
          this.addError = null
          this.addInfo = null
          this.addDisabledNotice = this.addEnabled === false
            ? 'Overlay add is disabled in the backend. You can review the form, but the server will reject the add until ARBOR_ENABLE_OVERLAY_ADD is enabled and Arbor is restarted.'
            : null
        }
      },
      addApprovalPhrase() {
        return 'ADD ' + this.addName.trim() + ' ' + this.addSyncUri.trim()
      },
      reviewAdd() {
        this.addError = null
        this.addInfo = null
        if (!this.addName.trim()) { this.addError = 'Name is required'; return }
        if (!this.addSyncUri.trim()) { this.addError = 'Sync URI is required'; return }
        this.addStep = 'confirm'
      },
      editAdd() {
        this.addStep = 'form'
        this.addError = null
      },
      async add() {
        this.addError = null
        this.addInfo = null
        if (!this.addDangerAck) { this.addError = 'You must acknowledge the root-equivalent trust warning'; return }
        if (this.addApprovalText.trim() !== this.addApprovalPhrase()) {
          this.addError = 'Confirmation text must exactly match the approval phrase'
          return
        }
        this.addBusy = true
        try {
          const name = this.addName.trim()
          const syncUri = this.addSyncUri.trim()
          const res = await overlays.add(name, this.addSyncType, syncUri, this.addDangerAck, this.addApprovalText.trim())
          this.addShow = false
          this._resetAdd()
          this.addInfo = res.warning || 'Overlay added. Run sync explicitly after reviewing it.'
          await this._load()
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
    navigate, navigateTo, navigateToUse, navigateBack,
    api, emerge, jobs, jobHistory, overlays,
    wsEmerge, wsGlobalEmerge, wsJobAttach, wsOverlaySync, detachWs,
    loginComponent,
    appShellComponent,
    navComponent,
    dashboardComponent,
    packageListComponent,
    useFlagsExplorerComponent,
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
