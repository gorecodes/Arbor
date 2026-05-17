<script>
  import { onMount, onDestroy, afterUpdate } from 'svelte'
  import { wsEmerge, wsJobAttach, detachWs, emerge, jobs } from '../lib/api.js'
  import { navigate } from '../lib/stores.js'
  import EmergeOptions from './EmergeOptions.svelte'

  export let atom
  export let cpv  // displayed name

  const MAX_LINES = 5000
  const FLUSH_MS = 80

  const INSTALL_OPTS_SCHEMA = [
    { type: 'bool', key: 'keep-going',  label: '--keep-going',  desc: 'Don’t bail on the first failure: skip the broken package and keep building the rest.' },
    { type: 'bool', key: 'usepkg',      label: '--usepkg',      desc: 'Use a matching binary package if one is available instead of compiling (much faster).' },
    { type: 'bool', key: 'buildpkg',    label: '--buildpkg',    desc: 'Save a binary package for every installed atom into /var/cache/binpkgs (useful for backups or reuse).' },
    { type: 'bool', key: 'oneshot',     label: '--oneshot',     desc: 'Install without adding the atom to @world — it won’t be pulled by future updates.' },
    { type: 'bool', key: 'quiet-build', label: '--quiet-build', desc: 'Show only major phases and hide the verbose compile output.' },
    { type: 'int',  key: 'jobs',        label: '--jobs=N',      desc: 'Build up to N packages in parallel. Helps when dependencies are independent; uses much more RAM/CPU.', min: 1, max: 64,   default: 4  },
    { type: 'int',  key: 'backtrack',   label: '--backtrack=N', desc: 'How many alternative resolutions portage may try when it hits a conflict. Raise if you see “backtrack limit exceeded”.',     min: 0, max: 1000, default: 30 },
  ]

  let installOpts = ''  // bound from EmergeOptions

  // Steps: pretend → (autounmask →) install → etcupdate → done
  let step = 'pretend'   // pretend | autounmask | install | etcupdate | done
  let lines = []
  let terminalEl
  let running = false
  let returncode = null
  let needsUnmask = false
  let etcFiles = []
  let ws = null
  let jobId = null       // active install job id, persisted in localStorage
  let _attachRetries = 0

  // Batch incoming WS lines so we don't re-render on every message.
  let _pending = []
  let _flushTimer = null
  function pushLine(l) {
    _pending.push(l)
    if (_flushTimer === null) _flushTimer = setTimeout(flushLines, FLUSH_MS)
  }
  function flushLines() {
    _flushTimer = null
    if (_pending.length === 0) return
    const next = lines.concat(_pending)
    _pending = []
    lines = next.length > MAX_LINES ? next.slice(next.length - MAX_LINES) : next
  }
  function resetLines() {
    if (_flushTimer !== null) { clearTimeout(_flushTimer); _flushTimer = null }
    _pending = []
    lines = []
  }

  $: statusClass = returncode === 0 ? 'ok' : returncode !== null ? 'err' : ''
  $: statusText  = returncode === 0 ? 'completed successfully' : returncode !== null ? `failed (exit ${returncode})` : ''

  function _jobKey() { return `arbor_job_${atom}` }
  function _saveJob(id) { jobId = id; localStorage.setItem(_jobKey(), id) }
  function _clearJob() { jobId = null; localStorage.removeItem(_jobKey()) }

  function lineClass(l) {
    if (/^\[ebuild/.test(l) || /^>>> /.test(l) || /Completed/.test(l)) return 'hi-ok'
    if (/^!!!/.test(l) || /[Ee]rror/.test(l)) return 'hi-err'
    if (/^ \* /.test(l) || /^NOTE:/.test(l) || /autounmask/.test(l)) return 'hi-warn'
    return ''
  }

  function startStream(cmd, onDone) {
    resetLines()
    running = true
    ws = wsEmerge(cmd, atom, (msg) => {
      if (msg.line !== undefined) pushLine(msg.line)
      if (msg.done) {
        flushLines()
        running = false
        returncode = msg.returncode ?? null
        ws = null
        onDone(msg)
      }
    })
  }

  function runPretend(clean = false) {
    step = 'pretend'
    returncode = null
    needsUnmask = false
    const extra = { opts: installOpts }
    if (clean) extra.clean = '1'
    resetLines()
    running = true
    ws = wsEmerge('pretend', atom, (msg) => {
      if (msg.line !== undefined) pushLine(msg.line)
      if (msg.done) {
        flushLines()
        running = false
        returncode = msg.returncode ?? null
        ws = null
        needsUnmask = !!msg.needs_unmask
      }
    }, extra)
  }

  function runAutounmask() {
    step = 'autounmask'
    returncode = null
    startStream('autounmask', () => {
      // Always re-run a clean pretend after writing keyword/license changes
      setTimeout(() => runPretend(true), 600)
    })
  }

  async function _afterInstallDone(rc) {
    if (rc === 0) {
      const pending = await emerge.etcUpdateCheck()
      if (pending.length > 0) {
        etcFiles = pending.map(f => ({ ...f, resolved: false }))
        step = 'etcupdate'
      } else {
        step = 'done'
      }
    }
    // non-zero: stay on install step showing failure
  }

  // Attach to an existing background job by ID and stream its output.
  function _attachToJob(id) {
    step = 'install'
    running = true
    resetLines()
    let gotLines = false
    ws = wsJobAttach(id, async (msg) => {
      if (msg.line !== undefined) { pushLine(msg.line); gotLines = true }
      if (msg.done) {
        flushLines()
        running = false
        returncode = msg.returncode ?? -1
        ws = null
        _clearJob()
        if (returncode !== 0 && !gotLines && _attachRetries < 1) {
          _attachRetries++
          returncode = null
          runInstall()
        } else {
          _attachRetries = 0
          await _afterInstallDone(returncode)
        }
      }
    })
  }

  function runInstall() {
    step = 'install'
    returncode = null
    resetLines()
    running = true
    ws = wsEmerge('install', atom, async (msg) => {
      if (msg.job_id) {
        _saveJob(msg.job_id)
        return
      }
      if (msg.line !== undefined) pushLine(msg.line)
      if (msg.done) {
        flushLines()
        running = false
        returncode = msg.returncode ?? null
        ws = null
        _clearJob()
        await _afterInstallDone(msg.returncode ?? -1)
      }
    }, { opts: installOpts })
  }

  async function resolveFile(file, action) {
    try {
      await emerge.etcUpdateResolve(file.cfg_file, action)
      etcFiles = etcFiles.map(f => f.cfg_file === file.cfg_file ? { ...f, resolved: true, action } : f)
      if (etcFiles.every(f => f.resolved)) step = 'done'
    } catch(e) {
      alert(`etc-update error: ${e.message}`)
    }
  }

  afterUpdate(() => {
    if (terminalEl) terminalEl.scrollTop = terminalEl.scrollHeight
  })

  function goBack() {
    detachWs(ws); ws = null
    navigate('packages', atom)
  }

  onDestroy(() => {
    if (_flushTimer !== null) { clearTimeout(_flushTimer); _flushTimer = null }
    detachWs(ws); ws = null
  })

  onMount(async () => {
    // 1. Try job_id from localStorage
    const savedId = localStorage.getItem(_jobKey())
    if (savedId) {
      try {
        const status = await jobs.status(savedId)
        if (status.status === 'running') {
          _attachToJob(savedId)
          return
        }
        if (status.status === 'done' && status.returncode === 0) {
          _clearJob()
          await _afterInstallDone(0)
          return
        }
      } catch (_) {}
      _clearJob()
    }

    // 2. Fallback: look up by atom in case localStorage was lost — reattach only if still running
    try {
      const active = await jobs.listByAtom(atom)
      const running = active.find(j => j.status === 'running')
      if (running) {
        _saveJob(running.job_id)
        _attachToJob(running.job_id)
        return
      }
    } catch (_) {}

    // No existing job — wait for the user to click "Run pretend" so they can
    // tweak options first instead of having the run start immediately.
  })
</script>

<div class="view-page">
  <div class="page-header">
    <button class="back" on:click={goBack}>← {cpv || atom}</button>
    <span class="step-title">
      {#if step === 'pretend'}Pretend — {cpv || atom}
      {:else if step === 'autounmask'}Accepting keywords — {cpv || atom}
      {:else if step === 'install'}Installing — {cpv || atom}
      {:else if step === 'etcupdate'}Config updates
      {:else}Done — {cpv || atom}
      {/if}
    </span>
  </div>

  <div class="content">
    <!-- Emerge options (apply to pretend + install) -->
    {#if step !== 'etcupdate' && step !== 'done'}
      <div class="opts-wrap">
        <EmergeOptions schema={INSTALL_OPTS_SCHEMA}
                       storageKey="arbor_opts_install"
                       baseFlags={['--verbose', '--color=n']}
                       target={atom}
                       bind:opts={installOpts} />
      </div>
    {/if}

    <!-- Terminal output (pretend / autounmask / install) -->
    {#if step !== 'etcupdate' && step !== 'done'}
      <div class="terminal" bind:this={terminalEl}>
        {#each lines as line, i (i)}
          <div class="line {lineClass(line)}">{line || ' '}</div>
        {/each}
        {#if running}<div class="line cursor">▊</div>{/if}
        {#if returncode !== null && !running}
          <div class="line status {statusClass}">── {statusText} ──</div>
        {/if}
      </div>
    {/if}

    <!-- etc-update: file list with diffs -->
    {#if step === 'etcupdate'}
      <div class="etclist">
        {#each etcFiles as file}
          <div class="etcfile" class:resolved={file.resolved}>
            <div class="etcfile-header">
              <span class="fname">{file.real_file}</span>
              {#if file.resolved}
                <span class="badge-action">{file.action === 'replace' ? '✓ replaced' : '✓ kept'}</span>
              {:else}
                <div class="etcfile-actions">
                  <button class="btn-keep" on:click={() => resolveFile(file, 'keep')}>Keep old</button>
                  <button class="btn-replace" on:click={() => resolveFile(file, 'replace')}>Take new</button>
                </div>
              {/if}
            </div>
            {#if !file.resolved && file.diff}
              <pre class="diff">{file.diff}</pre>
            {/if}
          </div>
        {/each}
      </div>
    {/if}

    {#if step === 'done'}
      <div class="done-msg">
        <span class="done-icon">✓</span>
        <span>{cpv || atom} installed successfully.</span>
      </div>
    {/if}

    <!-- Action bar -->
    <div class="actions">
      {#if step === 'pretend' && !running}
        {#if needsUnmask}
          <button class="btn-primary" on:click={runAutounmask}>Unmask & retry</button>
        {:else if returncode === 0}
          <button class="btn-primary" on:click={runInstall}>Install</button>
        {:else if returncode === null}
          <button class="btn-primary" on:click={() => runPretend()}>Run pretend</button>
        {:else}
          <button class="btn-secondary" on:click={() => runPretend()}>Retry pretend</button>
        {/if}
      {/if}

      {#if (step === 'install' || step === 'autounmask') && !running && returncode !== 0}
        <button class="btn-secondary" on:click={step === 'install' ? runInstall : runAutounmask}>Retry</button>
      {/if}

      {#if step === 'done'}
        <button class="btn-primary" on:click={() => navigate('packages', atom)}>Close</button>
      {/if}

      {#if step !== 'done'}
        <button class="btn-cancel" on:click={goBack} disabled={running && step === 'install'}>
          {running ? 'Running…' : 'Cancel'}
        </button>
      {/if}

      {#if running}
        <span class="spinner">⟳</span>
      {/if}
    </div>
  </div>
</div>

<style>
  .view-page { display: flex; flex-direction: column; height: calc(100vh - 4rem); width: 100%; }
  .page-header { margin-bottom: 1.5rem; }
  .back { background: none; border: none; color: #58a6ff; cursor: pointer; font-family: inherit; font-size: .9rem; padding: 0; margin-bottom: .75rem; display: block; }
  .back:hover { text-decoration: underline; }
  .step-title { color: #c9d1d9; font-size: 1rem; font-weight: bold; }
  .content { flex: 1; display: flex; flex-direction: column; background: #161b22; border: 1px solid #30363d; border-radius: 8px; overflow: hidden; }
  .opts-wrap { padding: .6rem .75rem 0; flex-shrink: 0; }

  /* terminal */
  .terminal {
    flex: 1; overflow-y: auto;
    background: #0d1117;
    font-family: 'JetBrains Mono', 'Fira Code', monospace;
    font-size: .78rem;
    line-height: 1.5;
    padding: .75rem 1rem;
    min-height: 0;
  }
  .line { white-space: pre-wrap; word-break: break-all; color: #c9d1d9; }
  .line.hi-ok { color: #3fb950; }
  .line.hi-err { color: #f85149; }
  .line.hi-warn { color: #d29922; }
  .line.status { margin-top: .5rem; font-weight: bold; }
  .line.status.ok { color: #3fb950; }
  .line.status.err { color: #f85149; }
  .cursor { color: #58a6ff; animation: blink .8s step-end infinite; }
  @keyframes blink { 50% { opacity: 0; } }

  /* etc-update */
  .etclist { flex: 1; overflow-y: auto; padding: .75rem 1rem; }
  .etcfile {
    border: 1px solid #30363d;
    border-radius: 6px;
    margin-bottom: .75rem;
    overflow: hidden;
  }
  .etcfile.resolved { opacity: .6; }
  .etcfile-header {
    display: flex; align-items: center; justify-content: space-between;
    background: #21262d; padding: .5rem .75rem; gap: .5rem;
  }
  .fname { color: #c9d1d9; font-size: .82rem; flex: 1; }
  .etcfile-actions { display: flex; gap: .4rem; }
  .badge-action { color: #3fb950; font-size: .78rem; }
  .diff {
    background: #0d1117;
    color: #8b949e;
    font-size: .75rem;
    line-height: 1.5;
    max-height: 200px;
    overflow-y: auto;
    padding: .5rem .75rem;
    white-space: pre;
  }

  /* done */
  .done-msg {
    flex: 1; display: flex; align-items: center; justify-content: center;
    gap: .75rem; padding: 2rem; color: #3fb950; font-size: 1.1rem;
  }
  .done-icon { font-size: 1.5rem; }

  /* actions */
  .actions {
    display: flex; align-items: center; gap: .5rem;
    border-top: 1px solid #30363d;
    flex-shrink: 0;
    padding: .4rem 1rem;
  }
  button { font-family: inherit; font-size: .82rem; border-radius: 6px; cursor: pointer; padding: .35rem .85rem; border: none; }
  .btn-primary { background: #1a7f37; color: #fff; }
  .btn-primary:hover { background: #2ea043; }
  .btn-secondary { background: #21262d; color: #c9d1d9; border: 1px solid #30363d; }
  .btn-secondary:hover { border-color: #58a6ff; color: #58a6ff; }
  .btn-cancel { background: none; color: #6e7681; border: 1px solid #30363d; }
  .btn-cancel:hover:not(:disabled) { color: #f85149; border-color: #f85149; }
  .btn-cancel:disabled { cursor: default; opacity: .5; }
  .btn-keep { background: #21262d; color: #8b949e; border: 1px solid #30363d; font-size: .78rem; padding: .2rem .6rem; }
  .btn-keep:hover { color: #c9d1d9; }
  .btn-replace { background: #1a3a1e; color: #3fb950; border: 1px solid #3fb950; font-size: .78rem; padding: .2rem .6rem; }
  .btn-replace:hover { background: #1f4024; }
  .spinner { color: #58a6ff; margin-left: auto; animation: spin 1s linear infinite; display: inline-block; }
  @keyframes spin { to { transform: rotate(360deg); } }
</style>
