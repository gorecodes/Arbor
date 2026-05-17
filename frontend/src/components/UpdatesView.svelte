<script>
  import { onMount, onDestroy } from 'svelte'
  import { wsGlobalEmerge, wsJobAttach, detachWs, jobs } from '../lib/api.js'
  import EmergeOptions from './EmergeOptions.svelte'

  const MAX_LINES = 5000

  const UPDATE_OPTS_SCHEMA = [
    { type: 'bool', key: 'keep-going',  label: '--keep-going',  desc: `Don't bail on the first failure: skip the broken package and keep building the rest.` },
    { type: 'bool', key: 'usepkg',      label: '--usepkg',      desc: 'Use a matching binary package if one is available instead of compiling (much faster).' },
    { type: 'bool', key: 'buildpkg',    label: '--buildpkg',    desc: 'Save a binary package for every installed atom into /var/cache/binpkgs (useful for backups or reuse).' },
    { type: 'bool', key: 'quiet-build', label: '--quiet-build', desc: 'Show only major phases and hide the verbose compile output.' },
    { type: 'int',  key: 'jobs',        label: '--jobs=N',      desc: 'Build up to N packages in parallel. Helps when dependencies are independent; uses much more RAM/CPU.', min: 1, max: 64,   default: 4  },
    { type: 'int',  key: 'backtrack',   label: '--backtrack=N', desc: 'How many alternative resolutions portage may try when it hits a conflict. Raise if you see “backtrack limit exceeded”.',     min: 0, max: 1000, default: 30 },
  ]

  let worldOpts = $state('')

  let sync         = $state(mkOp(true))
  let worldPretend = $state(mkOp(false))
  let worldUpdate  = $state(mkOp(false))
  let depclean     = $state({ ...mkOp(false), step: 'idle' })
  let preserved    = $state(mkOp(false))

  function mkOp(expanded) {
    return { lines: [], running: false, rc: null, ws: null, jobId: null, expanded, termEl: null }
  }

  const JOB_KEYS = {
    worldUpdate:      { storage: 'arbor_job_@world',             atom: '@world',             attachOnDone: false },
    depclean:         { storage: 'arbor_job_@depclean',          atom: '@depclean',          attachOnDone: false },
    preserved:        { storage: 'arbor_job_@preserved-rebuild', atom: '@preserved-rebuild', attachOnDone: false },
    sync:             { storage: 'arbor_job_@sync',              atom: '@sync',              attachOnDone: true  },
    worldPretend:     { storage: 'arbor_job_@world-pretend',     atom: '@world-pretend',     attachOnDone: true  },
    depcleanPretend:  { storage: 'arbor_job_@depclean-pretend',  atom: '@depclean-pretend',  attachOnDone: true  },
  }

  function _appendLine(op, line) {
    op.lines.push(line)
    if (op.lines.length > MAX_LINES) op.lines.splice(0, op.lines.length - MAX_LINES)
  }

  $effect(() => {
    // track lines changes to auto-scroll terminals after new output
    for (const op of [sync, worldPretend, worldUpdate, depclean, preserved]) {
      op.lines.length
      if (op.termEl) op.termEl.scrollTop = op.termEl.scrollHeight
    }
  })

  function lineClass(l) {
    if (/^\[ebuild/.test(l) || /^>>> /.test(l) || /Completed/.test(l)) return 'hi-ok'
    if (/^!!!/.test(l) || /[Ee]rror/.test(l)) return 'hi-err'
    if (/^ \* /.test(l) || /^NOTE:/.test(l)) return 'hi-warn'
    return ''
  }

  function _attachWorldUpdate(jobId) {
    worldUpdate.running = true; worldUpdate.expanded = true
    worldUpdate.jobId = jobId; worldUpdate.lines = []; worldUpdate.rc = null
    worldUpdate.ws = wsJobAttach(jobId, (msg) => {
      if (msg.line !== undefined) _appendLine(worldUpdate, msg.line)
      if (msg.done) {
        worldUpdate.running = false; worldUpdate.rc = msg.returncode ?? null
        worldUpdate.ws = null; localStorage.removeItem(JOB_KEYS.worldUpdate.storage)
      }
    })
  }

  function _attachDepclean(jobId) {
    depclean.running = true; depclean.expanded = true; depclean.step = 'running'
    depclean.jobId = jobId; depclean.lines = []; depclean.rc = null
    depclean.ws = wsJobAttach(jobId, (msg) => {
      if (msg.line !== undefined) _appendLine(depclean, msg.line)
      if (msg.done) {
        depclean.running = false; depclean.rc = msg.returncode ?? null
        depclean.ws = null; localStorage.removeItem(JOB_KEYS.depclean.storage)
      }
    })
  }

  function _attachPreserved(jobId) {
    preserved.running = true; preserved.expanded = true
    preserved.jobId = jobId; preserved.lines = []; preserved.rc = null
    preserved.ws = wsJobAttach(jobId, (msg) => {
      if (msg.line !== undefined) _appendLine(preserved, msg.line)
      if (msg.done) {
        preserved.running = false; preserved.rc = msg.returncode ?? null
        preserved.ws = null; localStorage.removeItem(JOB_KEYS.preserved.storage)
      }
    })
  }

  function _attachSync(jobId) {
    sync.running = true; sync.expanded = true
    sync.jobId = jobId; sync.lines = []; sync.rc = null
    sync.ws = wsJobAttach(jobId, (msg) => {
      if (msg.line !== undefined) _appendLine(sync, msg.line)
      if (msg.done) {
        sync.running = false; sync.rc = msg.returncode ?? null
        sync.ws = null; localStorage.removeItem(JOB_KEYS.sync.storage)
      }
    })
  }

  function _attachWorldPretend(jobId) {
    worldPretend.running = true; worldPretend.expanded = true
    worldPretend.jobId = jobId; worldPretend.lines = []; worldPretend.rc = null
    worldPretend.ws = wsJobAttach(jobId, (msg) => {
      if (msg.line !== undefined) _appendLine(worldPretend, msg.line)
      if (msg.done) {
        worldPretend.running = false; worldPretend.rc = msg.returncode ?? null
        worldPretend.ws = null; localStorage.removeItem(JOB_KEYS.worldPretend.storage)
      }
    })
  }

  function _attachDepcleanPretend(jobId) {
    depclean.running = true; depclean.expanded = true; depclean.step = 'pretend'
    depclean.jobId = jobId; depclean.lines = []; depclean.rc = null
    depclean.ws = wsJobAttach(jobId, (msg) => {
      if (msg.line !== undefined) _appendLine(depclean, msg.line)
      if (msg.done) {
        depclean.running = false; depclean.rc = msg.returncode ?? null; depclean.ws = null
        if (depclean.rc === 0) depclean.step = 'confirm'
        localStorage.removeItem(JOB_KEYS.depcleanPretend.storage)
      }
    })
  }

  async function _resumeIfRunning(name, attach) {
    const meta = JOB_KEYS[name]
    const stored = localStorage.getItem(meta.storage)
    let candidate = stored
    if (!candidate) {
      try {
        const active = await jobs.listByAtom(meta.atom)
        const running = active.find(j => j.status === 'running')
        if (running) candidate = running.job_id
        else if (meta.attachOnDone) {
          const done = [...active].sort((a, b) => (b.created_at || 0) - (a.created_at || 0))
                                  .find(j => j.status === 'done')
          if (done) candidate = done.job_id
        }
      } catch (_) {}
    }
    if (!candidate) return
    try {
      const status = await jobs.status(candidate)
      if (status.status === 'running' || (meta.attachOnDone && status.status === 'done')) {
        if (status.status === 'running') localStorage.setItem(meta.storage, candidate)
        else                              localStorage.removeItem(meta.storage)
        attach(candidate)
      } else {
        localStorage.removeItem(meta.storage)
      }
    } catch (_) {
      localStorage.removeItem(meta.storage)
    }
  }

  onMount(async () => {
    await Promise.all([
      _resumeIfRunning('worldUpdate',     _attachWorldUpdate),
      _resumeIfRunning('depclean',        _attachDepclean).then(() => {
        if (!depclean.ws) return _resumeIfRunning('depcleanPretend', _attachDepcleanPretend)
      }),
      _resumeIfRunning('preserved',       _attachPreserved),
      _resumeIfRunning('sync',            _attachSync),
      _resumeIfRunning('worldPretend',    _attachWorldPretend),
    ])
  })

  onDestroy(() => {
    for (const op of [sync, worldPretend, worldUpdate, depclean, preserved]) {
      detachWs(op.ws); op.ws = null
    }
  })

  // ── Sync ──────────────────────────────────────────────────────────────────
  function startSync() {
    sync.lines = []; sync.rc = null; sync.running = true; sync.expanded = true
    sync.ws = wsGlobalEmerge('sync', (msg) => {
      if (msg.job_id) { sync.jobId = msg.job_id; localStorage.setItem(JOB_KEYS.sync.storage, msg.job_id); return }
      if (msg.line !== undefined) _appendLine(sync, msg.line)
      if (msg.done) { sync.running = false; sync.rc = msg.returncode ?? null; sync.ws = null; localStorage.removeItem(JOB_KEYS.sync.storage) }
    })
  }

  // ── World pretend ─────────────────────────────────────────────────────────
  function startWorldPretend() {
    worldPretend.lines = []; worldPretend.rc = null; worldPretend.running = true; worldPretend.expanded = true
    worldPretend.ws = wsGlobalEmerge('world-pretend', (msg) => {
      if (msg.job_id) { worldPretend.jobId = msg.job_id; localStorage.setItem(JOB_KEYS.worldPretend.storage, msg.job_id); return }
      if (msg.line !== undefined) _appendLine(worldPretend, msg.line)
      if (msg.done) { worldPretend.running = false; worldPretend.rc = msg.returncode ?? null; worldPretend.ws = null; localStorage.removeItem(JOB_KEYS.worldPretend.storage) }
    })
  }

  // ── World update ──────────────────────────────────────────────────────────
  function startWorldUpdate() {
    worldUpdate.lines = []; worldUpdate.rc = null; worldUpdate.running = true; worldUpdate.expanded = true
    worldUpdate.ws = wsGlobalEmerge('world-update', (msg) => {
      if (msg.job_id) { worldUpdate.jobId = msg.job_id; localStorage.setItem(JOB_KEYS.worldUpdate.storage, msg.job_id); return }
      if (msg.line !== undefined) _appendLine(worldUpdate, msg.line)
      if (msg.done) { worldUpdate.running = false; worldUpdate.rc = msg.returncode ?? null; worldUpdate.ws = null; localStorage.removeItem(JOB_KEYS.worldUpdate.storage) }
    }, { opts: worldOpts })
  }

  // ── Depclean ──────────────────────────────────────────────────────────────
  function startDepcleanPretend() {
    depclean.lines = []; depclean.rc = null; depclean.running = true; depclean.expanded = true; depclean.step = 'pretend'
    depclean.ws = wsGlobalEmerge('depclean-pretend', (msg) => {
      if (msg.job_id) { depclean.jobId = msg.job_id; localStorage.setItem(JOB_KEYS.depcleanPretend.storage, msg.job_id); return }
      if (msg.line !== undefined) _appendLine(depclean, msg.line)
      if (msg.done) {
        depclean.running = false; depclean.rc = msg.returncode ?? null; depclean.ws = null
        if (depclean.rc === 0) depclean.step = 'confirm'
        localStorage.removeItem(JOB_KEYS.depcleanPretend.storage)
      }
    })
  }

  function startDepclean() {
    depclean.lines = []; depclean.rc = null; depclean.running = true; depclean.expanded = true; depclean.step = 'running'
    depclean.ws = wsGlobalEmerge('depclean', (msg) => {
      if (msg.job_id) { depclean.jobId = msg.job_id; localStorage.setItem(JOB_KEYS.depclean.storage, msg.job_id); return }
      if (msg.line !== undefined) _appendLine(depclean, msg.line)
      if (msg.done) { depclean.running = false; depclean.rc = msg.returncode ?? null; depclean.ws = null; localStorage.removeItem(JOB_KEYS.depclean.storage) }
    })
  }

  // ── Preserved rebuild ─────────────────────────────────────────────────────
  function startPreserved() {
    preserved.lines = []; preserved.rc = null; preserved.running = true; preserved.expanded = true
    preserved.ws = wsGlobalEmerge('preserved-rebuild', (msg) => {
      if (msg.job_id) { preserved.jobId = msg.job_id; localStorage.setItem(JOB_KEYS.preserved.storage, msg.job_id); return }
      if (msg.line !== undefined) _appendLine(preserved, msg.line)
      if (msg.done) { preserved.running = false; preserved.rc = msg.returncode ?? null; preserved.ws = null; localStorage.removeItem(JOB_KEYS.preserved.storage) }
    })
  }

  function statusClass(rc) {
    if (rc === null) return ''
    return rc === 0 ? 'ok' : 'err'
  }
</script>

<div class="view">
  <h2>Maintenance</h2>

  <!-- Sync -->
  <div class="card">
    <div class="card-header">
      <div class="card-title">
        <span class="title">Sync</span>
        <span class="cmd">emaint sync -a</span>
      </div>
      <div class="card-actions">
        {#if sync.rc !== null}
          <span class="rc {statusClass(sync.rc)}">{sync.rc === 0 ? 'done' : `exit ${sync.rc}`}</span>
        {/if}
        <button class="btn-toggle" on:click={() => { sync.expanded = !sync.expanded }}>
          {sync.expanded ? '▲' : '▼'}
        </button>
        <button class="btn-run" on:click={startSync} disabled={sync.running}>
          {sync.running ? 'Running…' : sync.rc !== null ? 'Re-sync' : 'Sync'}
        </button>
      </div>
    </div>
    {#if sync.expanded}
      <div class="terminal" bind:this={sync.termEl}>
        {#each sync.lines as line}
          <div class="line {lineClass(line)}">{line || ' '}</div>
        {/each}
        {#if sync.running}<div class="line cursor">▊</div>{/if}
        {#if sync.lines.length === 0 && !sync.running}<div class="line muted">Run sync to update the portage tree.</div>{/if}
      </div>
    {/if}
  </div>

  <!-- World pretend -->
  <div class="card">
    <div class="card-header">
      <div class="card-title">
        <span class="title">Check updates</span>
        <span class="cmd">emerge -uDN --pretend @world</span>
      </div>
      <div class="card-actions">
        {#if worldPretend.rc !== null}
          <span class="rc {statusClass(worldPretend.rc)}">{worldPretend.rc === 0 ? 'done' : `exit ${worldPretend.rc}`}</span>
        {/if}
        <button class="btn-toggle" on:click={() => { worldPretend.expanded = !worldPretend.expanded }}>
          {worldPretend.expanded ? '▲' : '▼'}
        </button>
        <button class="btn-run" on:click={startWorldPretend} disabled={worldPretend.running}>
          {worldPretend.running ? 'Running…' : 'Check'}
        </button>
      </div>
    </div>
    {#if worldPretend.expanded}
      <div class="terminal" bind:this={worldPretend.termEl}>
        {#each worldPretend.lines as line}
          <div class="line {lineClass(line)}">{line || ' '}</div>
        {/each}
        {#if worldPretend.running}<div class="line cursor">▊</div>{/if}
        {#if worldPretend.lines.length === 0 && !worldPretend.running}<div class="line muted">Run a check to see pending updates.</div>{/if}
      </div>
    {/if}
  </div>

  <!-- World update -->
  <div class="card">
    <div class="card-header">
      <div class="card-title">
        <span class="title">Update @world</span>
        <span class="cmd">emerge -uDN --with-bdeps=y @world</span>
      </div>
      <div class="card-actions">
        {#if worldUpdate.rc !== null}
          <span class="rc {statusClass(worldUpdate.rc)}">{worldUpdate.rc === 0 ? 'done' : `exit ${worldUpdate.rc}`}</span>
        {/if}
        <button class="btn-toggle" on:click={() => { worldUpdate.expanded = !worldUpdate.expanded }}>
          {worldUpdate.expanded ? '▲' : '▼'}
        </button>
        <button class="btn-run" on:click={startWorldUpdate} disabled={worldUpdate.running}>
          {worldUpdate.running ? 'Running…' : worldUpdate.rc !== null ? 'Retry' : 'Update'}
        </button>
      </div>
    </div>
    <div class="card-opts">
      <EmergeOptions schema={UPDATE_OPTS_SCHEMA}
                     storageKey="arbor_opts_world"
                     baseFlags={['--update', '--deep', '--newuse', '--with-bdeps=y', '--color=n']}
                     target="@world"
                     bind:opts={worldOpts} />
    </div>
    {#if worldUpdate.expanded}
      <div class="terminal" bind:this={worldUpdate.termEl}>
        {#each worldUpdate.lines as line}
          <div class="line {lineClass(line)}">{line || ' '}</div>
        {/each}
        {#if worldUpdate.running}<div class="line cursor">▊</div>{/if}
        {#if worldUpdate.lines.length === 0 && !worldUpdate.running}<div class="line muted">Runs as a background job — safe to navigate away.</div>{/if}
      </div>
    {/if}
  </div>

  <!-- Preserved rebuild -->
  <div class="card">
    <div class="card-header">
      <div class="card-title">
        <span class="title">Preserved rebuild</span>
        <span class="cmd">emerge @preserved-rebuild</span>
      </div>
      <div class="card-actions">
        {#if preserved.rc !== null}
          <span class="rc {statusClass(preserved.rc)}">{preserved.rc === 0 ? 'done' : `exit ${preserved.rc}`}</span>
        {/if}
        <button class="btn-toggle" on:click={() => { preserved.expanded = !preserved.expanded }}>
          {preserved.expanded ? '▲' : '▼'}
        </button>
        <button class="btn-run" on:click={startPreserved} disabled={preserved.running}>
          {preserved.running ? 'Running…' : preserved.rc !== null ? 'Retry' : 'Rebuild'}
        </button>
      </div>
    </div>
    {#if preserved.expanded}
      <div class="terminal" bind:this={preserved.termEl}>
        {#each preserved.lines as line}
          <div class="line {lineClass(line)}">{line || ' '}</div>
        {/each}
        {#if preserved.running}<div class="line cursor">▊</div>{/if}
        {#if preserved.lines.length === 0 && !preserved.running}<div class="line muted">Rebuild libraries preserved after updates.</div>{/if}
      </div>
    {/if}
  </div>

  <!-- Depclean -->
  <div class="card">
    <div class="card-header">
      <div class="card-title">
        <span class="title">Depclean</span>
        <span class="cmd">emerge --depclean</span>
      </div>
      <div class="card-actions">
        {#if depclean.rc !== null}
          <span class="rc {statusClass(depclean.rc)}">{depclean.rc === 0 ? 'done' : `exit ${depclean.rc}`}</span>
        {/if}
        <button class="btn-toggle" on:click={() => { depclean.expanded = !depclean.expanded }}>
          {depclean.expanded ? '▲' : '▼'}
        </button>
        <button class="btn-run" on:click={startDepcleanPretend} disabled={depclean.running}>
          {depclean.running ? 'Running…' : depclean.step === 'idle' ? 'Check' : 'Re-check'}
        </button>
      </div>
    </div>
    {#if depclean.expanded}
      <div class="terminal" bind:this={depclean.termEl}>
        {#each depclean.lines as line}
          <div class="line {lineClass(line)}">{line || ' '}</div>
        {/each}
        {#if depclean.running}<div class="line cursor">▊</div>{/if}
        {#if depclean.lines.length === 0 && !depclean.running}<div class="line muted">Remove packages no longer needed.</div>{/if}
        {#if depclean.step === 'confirm' && !depclean.running}
          <div class="confirm-row">
            <span class="confirm-msg">⚠ The packages above will be removed.</span>
            <button class="btn-confirm-run" on:click={startDepclean}>Remove</button>
            <button class="btn-confirm-cancel" on:click={() => { depclean.step = 'idle'; depclean.lines = [] }}>Cancel</button>
          </div>
        {/if}
      </div>
    {/if}
  </div>
</div>

<style>
  .view { max-width: 900px; display: flex; flex-direction: column; gap: 1rem; }
  h2 { color: #c9d1d9; font-size: 1.1rem; margin-bottom: .5rem; }

  .card {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 8px;
    overflow: hidden;
  }
  .card-header {
    display: flex; align-items: center; justify-content: space-between;
    padding: .7rem 1rem; gap: .75rem;
  }
  .card-title { display: flex; flex-direction: column; gap: .15rem; flex: 1; }
  .title { color: #c9d1d9; font-size: .88rem; font-weight: bold; }
  .cmd { color: #6e7681; font-size: .72rem; font-family: 'JetBrains Mono', monospace; }
  .card-actions { display: flex; align-items: center; gap: .5rem; }

  .rc { font-size: .72rem; font-weight: bold; }
  .rc.ok  { color: #3fb950; }
  .rc.err { color: #f85149; }

  button { font-family: inherit; font-size: .78rem; border-radius: 5px; cursor: pointer; padding: .25rem .6rem; border: none; }
  .btn-toggle { background: #21262d; border: 1px solid #30363d; color: #8b949e; }
  .btn-toggle:hover { color: #c9d1d9; }
  .btn-run { background: #1a7f37; color: #fff; min-width: 5rem; }
  .btn-run:hover:not(:disabled) { background: #2ea043; }
  .btn-run:disabled { opacity: .5; cursor: default; }

  .card-opts { padding: .5rem .75rem 0; border-top: 1px solid #30363d; }

  .terminal {
    background: #0d1117;
    border-top: 1px solid #30363d;
    font-family: 'JetBrains Mono', 'Fira Code', monospace;
    font-size: .76rem; line-height: 1.5;
    max-height: 300px; overflow-y: auto;
    padding: .6rem 1rem;
  }
  .line { white-space: pre-wrap; word-break: break-all; color: #c9d1d9; }
  .line.hi-ok  { color: #3fb950; }
  .line.hi-err { color: #f85149; }
  .line.hi-warn { color: #d29922; }
  .muted { color: #6e7681; }
  .cursor { color: #58a6ff; animation: blink .8s step-end infinite; }
  @keyframes blink { 50% { opacity: 0; } }

  .confirm-row {
    display: flex; align-items: center; gap: .75rem;
    border-top: 1px solid #30363d;
    padding: .6rem 0 .2rem;
    margin-top: .4rem;
  }
  .confirm-msg { color: #d29922; font-size: .76rem; flex: 1; }
  .btn-confirm-run {
    background: #6e1a1a; color: #fff; border: none;
    border-radius: 5px; cursor: pointer; font-family: inherit;
    font-size: .76rem; padding: .25rem .7rem;
  }
  .btn-confirm-run:hover { background: #a03a3a; }
  .btn-confirm-cancel {
    background: #21262d; color: #8b949e; border: 1px solid #30363d;
    border-radius: 5px; cursor: pointer; font-family: inherit;
    font-size: .76rem; padding: .25rem .7rem;
  }
  .btn-confirm-cancel:hover { color: #c9d1d9; border-color: #8b949e; }
</style>
