<script>
  import { onMount, onDestroy, afterUpdate } from 'svelte'
  import { jobs, wsJobAttach, detachWs } from '../lib/api.js'
  import { navigate } from '../lib/stores.js'

  const MAX_LINES = 5000
  const FLUSH_MS = 80

  let jobList = []
  let loading = true
  let error = null
  let refreshTimer

  // inline terminal — single active terminal at a time
  let expanded = null
  let activeLines = []
  let termWs = null
  let termEl = null

  let _pending = []
  let _flushTimer = null
  function pushLine(l) {
    _pending.push(l)
    if (_flushTimer === null) _flushTimer = setTimeout(flushLines, FLUSH_MS)
  }
  function flushLines() {
    _flushTimer = null
    if (_pending.length === 0) return
    const next = activeLines.concat(_pending)
    _pending = []
    activeLines = next.length > MAX_LINES ? next.slice(next.length - MAX_LINES) : next
  }
  function resetLines() {
    if (_flushTimer !== null) { clearTimeout(_flushTimer); _flushTimer = null }
    _pending = []
    activeLines = []
  }


  async function load() {
    try {
      jobList = await jobs.list()
      error = null
    } catch(e) {
      error = e.message
    } finally {
      loading = false
    }
  }

  async function kill(jobId, e) {
    e.stopPropagation()
    if (!confirm('Kill this job?')) return
    try {
      await jobs.cancel(jobId)
      await load()
    } catch(e) {
      alert(`Kill failed: ${e.message}`)
    }
  }

  function openPanel(job, e) {
    e.stopPropagation()
    const kind = job.kind || ''
    const atom = job.atom || ''
    const maintenanceKinds = new Set(['world', 'world-pretend', 'depclean', 'depclean-pretend', 'preserved-rebuild', 'sync'])
    if (maintenanceKinds.has(kind) || atom.startsWith('@')) {
      navigate('updates')
    } else if (kind === 'uninstall' || atom.startsWith('uninstall:')) {
      navigate('uninstall', atom.replace(/^uninstall:/, ''))
    } else {
      navigate('install', atom)
    }
  }

  function toggle(jobId) {
    if (expanded === jobId) {
      closeStream()
      expanded = null
      resetLines()
      return
    }
    closeStream()
    expanded = jobId
    resetLines()
    termWs = wsJobAttach(jobId, (msg) => {
      if (msg.line !== undefined) pushLine(msg.line)
      if (msg.done) { flushLines(); termWs = null; load() }
    })
  }

  function closeStream() {
    detachWs(termWs); termWs = null
    if (_flushTimer !== null) { clearTimeout(_flushTimer); _flushTimer = null }
  }

  afterUpdate(() => {
    if (termEl) termEl.scrollTop = termEl.scrollHeight
  })

  function scheduleRefresh() {
    const delay = jobList.some(j => j.status === 'running') ? 3000 : 15000
    refreshTimer = setTimeout(async () => { await load(); scheduleRefresh() }, delay)
  }

  onMount(() => { load().then(scheduleRefresh) })
  onDestroy(() => { clearTimeout(refreshTimer); closeStream() })

  function statusLabel(j) {
    if (j.status === 'running') return 'running'
    if (j.status === 'done' && j.returncode === 0) return 'done'
    if (j.status === 'done') return `exit ${j.returncode}`
    return j.status
  }

  function statusClass(j) {
    if (j.status === 'running') return 'run'
    if (j.status === 'done' && j.returncode === 0) return 'ok'
    return 'err'
  }

  function ago(ts) {
    if (!ts) return ''
    const s = Math.floor(Date.now() / 1000 - ts)
    if (s < 60) return `${s}s ago`
    if (s < 3600) return `${Math.floor(s / 60)}m ago`
    return `${Math.floor(s / 3600)}h ago`
  }

  function lineClass(l) {
    if (/^\[ebuild/.test(l) || /^>>> /.test(l) || /Completed/.test(l)) return 'hi-ok'
    if (/^!!!/.test(l) || /[Ee]rror/.test(l)) return 'hi-err'
    if (/^ \* /.test(l) || /^NOTE:/.test(l)) return 'hi-warn'
    return ''
  }
</script>

<div class="view">
  <div class="header">
    <h2>Jobs</h2>
    <button class="btn-refresh" on:click={load}>Refresh</button>
  </div>

  {#if loading}
    <p class="muted">Loading…</p>
  {:else if error}
    <p class="err-msg">{error}</p>
  {:else if jobList.length === 0}
    <p class="muted">No jobs.</p>
  {:else}
    <div class="table">
      {#each jobList as job (job.job_id)}
        <div class="row" class:expanded={expanded === job.job_id}>
          <div class="row-main">
            <span class="atom">{job.atom}</span>
            <span class="badge {statusClass(job)}">{statusLabel(job)}</span>
            <span class="ago">{ago(job.created_at)}</span>
            <div class="actions">
              <button class="btn-output" on:click={() => toggle(job.job_id)}>
                {expanded === job.job_id ? '▲ output' : '▼ output'}
              </button>
              {#if job.status === 'running'}
                <button class="btn-open" on:click={(e) => openPanel(job, e)}>Open</button>
                <button class="btn-kill" on:click={(e) => kill(job.job_id, e)}>Kill</button>
              {/if}
            </div>
          </div>

          {#if expanded === job.job_id}
            <div class="terminal" bind:this={termEl}>
              {#each activeLines as line, i (i)}
                <div class="line {lineClass(line)}">{line || ' '}</div>
              {/each}
              {#if job.status === 'running' && termWs}
                <div class="line cursor">▊</div>
              {/if}
              {#if activeLines.length === 0 && !termWs}
                <div class="line muted-line">No output available.</div>
              {/if}
            </div>
          {/if}
        </div>
      {/each}
    </div>
  {/if}
</div>

<style>
  .view { max-width: 900px; }
  .header {
    display: flex; align-items: center; gap: 1rem;
    margin-bottom: 1.5rem;
  }
  h2 { color: #c9d1d9; font-size: 1.1rem; }
  .btn-refresh {
    background: #21262d; border: 1px solid #30363d;
    color: #8b949e; border-radius: 6px; cursor: pointer;
    font-family: inherit; font-size: .8rem; padding: .3rem .75rem;
  }
  .btn-refresh:hover { color: #c9d1d9; border-color: #8b949e; }

  .muted { color: #6e7681; font-size: .85rem; }
  .err-msg { color: #f85149; font-size: .85rem; }

  .table { display: flex; flex-direction: column; gap: .4rem; }

  .row {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 8px;
    overflow: hidden;
  }
  .row.expanded { border-color: #58a6ff66; }

  .row-main {
    display: flex; align-items: center; gap: .75rem;
    padding: .65rem 1rem;
  }
  .atom { flex: 1; color: #c9d1d9; font-size: .85rem; }
  .ago { color: #6e7681; font-size: .78rem; min-width: 5rem; text-align: right; }

  .badge {
    font-size: .72rem; border-radius: 4px;
    padding: .15rem .5rem; font-weight: bold;
  }
  .badge.run { background: #1a3a4a; color: #58a6ff; }
  .badge.ok  { background: #1a3a1e; color: #3fb950; }
  .badge.err { background: #3a1a1a; color: #f85149; }

  .actions { display: flex; gap: .4rem; }

  button {
    font-family: inherit; font-size: .75rem; border-radius: 5px;
    cursor: pointer; padding: .2rem .55rem; border: none;
  }
  .btn-output {
    background: #21262d; border: 1px solid #30363d; color: #8b949e;
  }
  .btn-output:hover { color: #c9d1d9; border-color: #8b949e; }

  .btn-open {
    background: #1a3050; border: 1px solid #58a6ff66; color: #58a6ff;
  }
  .btn-open:hover { background: #1e3a60; border-color: #58a6ff; }

  .btn-kill {
    background: #3a1a1a; border: 1px solid #f8514966; color: #f85149;
  }
  .btn-kill:hover { background: #5a2020; border-color: #f85149; }

  .terminal {
    background: #0d1117;
    border-top: 1px solid #30363d;
    font-family: 'JetBrains Mono', 'Fira Code', monospace;
    font-size: .76rem;
    line-height: 1.5;
    max-height: 320px;
    overflow-y: auto;
    padding: .6rem 1rem;
  }
  .line { white-space: pre-wrap; word-break: break-all; color: #c9d1d9; }
  .line.hi-ok   { color: #3fb950; }
  .line.hi-err  { color: #f85149; }
  .line.hi-warn { color: #d29922; }
  .muted-line   { color: #6e7681; }
  .cursor { color: #58a6ff; animation: blink .8s step-end infinite; }
  @keyframes blink { 50% { opacity: 0; } }
</style>
