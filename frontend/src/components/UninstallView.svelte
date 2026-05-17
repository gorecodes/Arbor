<script>
  import { onMount, onDestroy, afterUpdate } from 'svelte'
  import { wsEmerge, wsJobAttach, detachWs, jobs } from '../lib/api.js'
  import { navigate } from '../lib/stores.js'

  export let atom
  export let cpv

  const MAX_LINES = 5000
  const FLUSH_MS = 80

  let step = 'pretend'   // pretend | uninstall | done
  let lines = []
  let running = false
  let returncode = null
  let ws = null
  let terminalEl

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

  onDestroy(() => {
    if (_flushTimer !== null) { clearTimeout(_flushTimer); _flushTimer = null }
    detachWs(ws); ws = null
  })

  $: statusClass = returncode === 0 ? 'ok' : returncode !== null ? 'err' : ''
  $: statusText  = returncode === 0 ? 'removed successfully' : returncode !== null ? `failed (exit ${returncode})` : ''

  function _jobKey() { return `arbor_uninstall_${atom}` }
  function _saveJob(id) { localStorage.setItem(_jobKey(), id) }
  function _clearJob() { localStorage.removeItem(_jobKey()) }

  afterUpdate(() => { if (terminalEl) terminalEl.scrollTop = terminalEl.scrollHeight })

  function lineClass(l) {
    if (/^>>> /.test(l) || /Completed/.test(l) || /^--- /.test(l)) return 'hi-ok'
    if (/^!!!/.test(l) || /[Ee]rror/.test(l)) return 'hi-err'
    if (/^ \* /.test(l) || /^NOTE:/.test(l)) return 'hi-warn'
    return ''
  }

  function runPretend() {
    step = 'pretend'
    returncode = null
    resetLines()
    running = true
    ws = wsEmerge('uninstall-pretend', atom, (msg) => {
      if (msg.line !== undefined) pushLine(msg.line)
      if (msg.done) { flushLines(); running = false; returncode = msg.returncode ?? null; ws = null }
    })
  }

  function runUninstall() {
    step = 'uninstall'
    returncode = null
    resetLines()
    running = true
    ws = wsEmerge('uninstall', atom, (msg) => {
      if (msg.job_id) { _saveJob(msg.job_id); return }
      if (msg.line !== undefined) pushLine(msg.line)
      if (msg.done) {
        flushLines()
        running = false
        returncode = msg.returncode ?? null
        ws = null
        _clearJob()
        if (returncode === 0) step = 'done'
      }
    })
  }

  function _attachToJob(id) {
    step = 'uninstall'
    running = true
    resetLines()
    let gotLines = false
    ws = wsJobAttach(id, (msg) => {
      if (msg.line !== undefined) { pushLine(msg.line); gotLines = true }
      if (msg.done) {
        flushLines()
        running = false
        returncode = msg.returncode ?? -1
        ws = null
        _clearJob()
        if (msg.connectionLost || (returncode !== 0 && !gotLines)) {
          returncode = null; runUninstall()
        } else if (returncode === 0) {
          step = 'done'
        }
      }
    })
  }

  function goBack() {
    detachWs(ws); ws = null
    navigate('packages', atom)
  }

  onMount(async () => {
    const savedId = localStorage.getItem(_jobKey())
    if (savedId) {
      try {
        const status = await jobs.status(savedId)
        if (status.status === 'running') { _attachToJob(savedId); return }
        if (status.status === 'done' && status.returncode === 0) {
          _clearJob(); step = 'done'; return
        }
      } catch (_) {}
      _clearJob()
    }
    // No existing job — wait for user confirmation before running pretend.
  })
</script>

<div class="view-page">
  <div class="page-header">
    <button class="back" on:click={goBack}>← {cpv || atom}</button>
    <span class="step-title">
      {#if step === 'pretend'}Pretend uninstall — {cpv || atom}
      {:else if step === 'uninstall'}Uninstalling — {cpv || atom}
      {:else}Done — {cpv || atom}
      {/if}
    </span>
  </div>

  <div class="content">
    {#if step !== 'done'}
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

    {#if step === 'done'}
      <div class="done-msg">
        <span class="done-icon">✓</span>
        <span>{cpv || atom} removed successfully.</span>
      </div>
    {/if}

    <div class="actions">
      {#if step === 'pretend' && !running && returncode === null}
        <button class="btn-primary" on:click={runPretend}>Run pretend</button>
      {/if}
      {#if step === 'pretend' && !running && returncode === 0}
        <button class="btn-danger" on:click={runUninstall}>Uninstall</button>
      {/if}
      {#if (step === 'pretend' || step === 'uninstall') && !running && returncode !== null && returncode !== 0}
        <button class="btn-secondary" on:click={step === 'pretend' ? runPretend : runUninstall}>Retry</button>
      {/if}
      {#if step === 'done'}
        <button class="btn-primary" on:click={() => navigate('packages', atom)}>Close</button>
      {/if}
      {#if step !== 'done'}
        <button class="btn-cancel" on:click={goBack} disabled={running && step === 'uninstall'}>
          {running ? 'Running…' : 'Cancel'}
        </button>
      {/if}
      {#if running}<span class="spinner">⟳</span>{/if}
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

  .terminal {
    flex: 1; overflow-y: auto;
    background: #0d1117;
    font-family: 'JetBrains Mono', 'Fira Code', monospace;
    font-size: .78rem; line-height: 1.5;
    padding: .75rem 1rem;
    min-height: 0;
  }
  .line { white-space: pre-wrap; word-break: break-all; color: #c9d1d9; }
  .line.hi-ok  { color: #3fb950; }
  .line.hi-err { color: #f85149; }
  .line.hi-warn { color: #d29922; }
  .line.status { margin-top: .5rem; font-weight: bold; }
  .line.status.ok  { color: #3fb950; }
  .line.status.err { color: #f85149; }
  .cursor { color: #58a6ff; animation: blink .8s step-end infinite; }
  @keyframes blink { 50% { opacity: 0; } }
  .done-msg {
    flex: 1; display: flex; align-items: center; justify-content: center;
    gap: .75rem; padding: 2rem; color: #3fb950; font-size: 1.1rem;
  }
  .done-icon { font-size: 1.5rem; }
  .actions {
    display: flex; align-items: center; gap: .5rem;
    border-top: 1px solid #30363d; flex-shrink: 0;
    padding: .4rem 1rem;
  }
  button { font-family: inherit; font-size: .82rem; border-radius: 6px; cursor: pointer; padding: .35rem .85rem; border: none; }
  .btn-danger   { background: #6e1a1a; color: #fff; }
  .btn-danger:hover { background: #a03a3a; }
  .btn-primary  { background: #1a7f37; color: #fff; }
  .btn-primary:hover { background: #2ea043; }
  .btn-secondary { background: #21262d; color: #c9d1d9; border: 1px solid #30363d; }
  .btn-secondary:hover { border-color: #58a6ff; color: #58a6ff; }
  .btn-cancel { background: none; color: #6e7681; border: 1px solid #30363d; }
  .btn-cancel:hover:not(:disabled) { color: #f85149; border-color: #f85149; }
  .btn-cancel:disabled { cursor: default; opacity: .5; }
  .spinner { color: #58a6ff; margin-left: auto; animation: spin 1s linear infinite; display: inline-block; }
  @keyframes spin { to { transform: rotate(360deg); } }
</style>
