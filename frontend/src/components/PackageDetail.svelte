<script>
  import { onMount } from 'svelte'
  import { api } from '../lib/api.js'
  import { navigateBack, navigate } from '../lib/stores.js'
  import DepGraph from './DepGraph.svelte'

  export let atom

  let info = null
  let flags = null
  let deps = null
  let tab = 'info'
  let error = null
  let flagsError = null
  let depsError = null

  onMount(async () => {
    const [infoRes, flagsRes, depsRes] = await Promise.allSettled([
      api.packageInfo(atom),
      api.useFlags(atom),
      api.deps(atom),
    ])
    if (infoRes.status === 'fulfilled') {
      info = Array.isArray(infoRes.value) ? infoRes.value[0] : infoRes.value
    } else {
      error = infoRes.reason?.message ?? 'Failed to load package info'
    }
    flags = flagsRes.status === 'fulfilled' ? flagsRes.value : null
    if (flagsRes.status === 'rejected') flagsError = flagsRes.reason?.message ?? 'Failed to load use flags'
    deps = depsRes.status === 'fulfilled' ? depsRes.value : null
    if (depsRes.status === 'rejected') depsError = depsRes.reason?.message ?? 'Failed to load deps'
  })

  function back() {
    navigateBack()
  }

  function fmt_size(b) {
    if (!b) return '—'
    const kb = parseInt(b) / 1024
    return kb > 1024 ? `${(kb/1024).toFixed(1)} MB` : `${kb.toFixed(0)} KB`
  }

  function fmt_date(ts) {
    if (!ts) return '—'
    return new Date(parseInt(ts) * 1000).toLocaleString()
  }

</script>

<div class="detail">
  <button class="back" on:click={back}>← Back</button>

  {#if error}
    <p class="error">{error}</p>
  {:else if !info}
    <p class="muted">Loading…</p>
  {:else}
    <div class="header">
      <div class="header-row">
        <h2>{info.cpv}</h2>
        {#if !info.installed}
          <button class="btn-install" on:click={() => navigate('install', atom)}>⬇ Install</button>
        {:else}
          <span class="installed-badge">✓ installed</span>
          <button class="btn-uninstall" on:click={() => navigate('uninstall', atom)}>✕ Uninstall</button>
        {/if}
      </div>
      <p class="desc">{info.DESCRIPTION}</p>
      {#if info.HOMEPAGE && /^https?:\/\//.test(info.HOMEPAGE)}
        <a href={info.HOMEPAGE} target="_blank" rel="noopener noreferrer">{info.HOMEPAGE}</a>
      {/if}
    </div>

    <div class="meta">
      <span class="badge">slot {info.SLOT || '0'}</span>
      <span class="badge">{info.LICENSE}</span>
      {#if info.installed}
        <span class="badge muted">built {fmt_date(info.BUILD_TIME)}</span>
        <span class="badge muted">{fmt_size(info.SIZE)}</span>
      {/if}
    </div>

    <div class="tabs">
      {#each ['info', 'use flags', 'deps'] as t}
        <button class:active={tab === t} on:click={() => tab = t}>{t}</button>
      {/each}
    </div>

    {#if tab === 'info'}
      <div class="panel">
        <h4>RDEPEND</h4>
        <pre class="dep-raw">{deps?.rdepend || '—'}</pre>
      </div>

    {:else if tab === 'use flags'}
      {#if flagsError}
        <p class="error">{flagsError}</p>
      {:else if flags?.flags}
        <div class="flags">
          {#each flags.flags as f}
            <span class="flag" class:on={f.enabled} class:off={!f.enabled}>
              {f.enabled ? '+' : '-'}{f.name}
            </span>
          {/each}
        </div>
      {:else}
        <p class="muted">No USE flags.</p>
      {/if}

    {:else if tab === 'deps'}
      {#if depsError}
        <p class="error">{depsError}</p>
      {:else}
        <DepGraph atom={atom} />
      {/if}
    {/if}
  {/if}
</div>

<style>
  .header-row { display: flex; align-items: center; gap: 1rem; margin-bottom: .25rem; }
  .header-row h2 { flex: 1; margin: 0; }
  .btn-install {
    background: #1a7f37; border: none; border-radius: 6px;
    color: #fff; cursor: pointer; font-family: inherit;
    font-size: .82rem; padding: .35rem .9rem; white-space: nowrap;
  }
  .btn-install:hover { background: #2ea043; }
  .installed-badge { color: #3fb950; font-size: .8rem; white-space: nowrap; }
  .btn-uninstall {
    background: none; border: 1px solid #f8514966; border-radius: 6px;
    color: #f85149; cursor: pointer; font-family: inherit;
    font-size: .78rem; padding: .25rem .7rem; white-space: nowrap;
  }
  .btn-uninstall:hover { background: #3a1a1a; border-color: #f85149; }

  .back {
    background: none;
    border: none;
    color: #58a6ff;
    cursor: pointer;
    font-family: inherit;
    font-size: 0.9rem;
    margin-bottom: 1.5rem;
    padding: 0;
  }
  .back:hover { text-decoration: underline; }
  .header { margin-bottom: 1rem; }
  h2 { color: #e6edf3; margin-bottom: 0.25rem; }
  .desc { color: #8b949e; margin-bottom: 0.25rem; }
  .meta { display: flex; flex-wrap: wrap; gap: 0.5rem; margin-bottom: 1.5rem; }
  .badge {
    background: #21262d;
    border-radius: 4px;
    color: #c9d1d9;
    font-size: 0.75rem;
    padding: 0.2rem 0.5rem;
  }
  .badge.muted { color: #8b949e; }
  .tabs { display: flex; gap: 0.25rem; margin-bottom: 1.5rem; border-bottom: 1px solid #30363d; }
  .tabs button {
    background: none;
    border: none;
    border-bottom: 2px solid transparent;
    color: #8b949e;
    cursor: pointer;
    font-family: inherit;
    font-size: 0.85rem;
    padding: 0.5rem 1rem;
    margin-bottom: -1px;
  }
  .tabs button.active { color: #7ee787; border-bottom-color: #7ee787; }
  .tabs button:hover:not(.active) { color: #c9d1d9; }
  .flags { display: flex; flex-wrap: wrap; gap: 0.4rem; }
  .flag {
    border-radius: 4px;
    font-size: 0.8rem;
    padding: 0.2rem 0.5rem;
  }
  .flag.on { background: #1a3a1e; color: #7ee787; }
  .flag.off { background: #1c1c1c; color: #6e7681; }
  h4 { color: #8b949e; font-size: 0.75rem; text-transform: uppercase; margin-bottom: 0.75rem; }
  .dep-raw {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 6px;
    color: #c9d1d9;
    font-family: inherit;
    font-size: 0.8rem;
    overflow-x: auto;
    padding: 1rem;
    white-space: pre-wrap;
    word-break: break-all;
  }
.muted { color: #8b949e; }
  .error { color: #f85149; }
</style>
