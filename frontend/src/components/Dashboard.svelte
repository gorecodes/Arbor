<script>
  import { onMount } from 'svelte'
  import { api } from '../lib/api.js'

  let status = null
  let error = null

  onMount(async () => {
    try {
      status = await api.status()
    } catch(e) {
      error = e.message
    }
  })

  function fmt_bytes(b) {
    const gb = b / 1024 ** 3
    return gb >= 1 ? `${gb.toFixed(1)} GB` : `${(b / 1024 ** 2).toFixed(0)} MB`
  }

  function disk_pct(used, total) {
    return ((used / total) * 100).toFixed(1)
  }
</script>

<div class="dashboard">
  <h2>System Overview</h2>

  {#if error}
    <p class="error">{error}</p>
  {:else if !status}
    <p class="muted">Loading…</p>
  {:else}
    <div class="cards">
      <div class="card">
        <span class="label">Installed packages</span>
        <span class="value">{status.pkg_count}</span>
      </div>

      <div class="card">
        <span class="label">Last sync</span>
        <span class="value mono">{status.last_sync}</span>
      </div>

      <div class="card wide">
        <span class="label">Disk usage ({fmt_bytes(status.disk_used)} / {fmt_bytes(status.disk_total)})</span>
        <div class="bar">
          <div class="fill" style="width: {disk_pct(status.disk_used, status.disk_total)}%"></div>
        </div>
        <span class="sub">{fmt_bytes(status.disk_free)} free</span>
      </div>
    </div>
  {/if}
</div>

<style>
  h2 { color: #e6edf3; margin-bottom: 1.5rem; }
  .cards {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
    gap: 1rem;
  }
  .card {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 8px;
    padding: 1.25rem 1.5rem;
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }
  .card.wide { grid-column: 1 / -1; }
  .label { color: #8b949e; font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em; }
  .value { color: #7ee787; font-size: 1.6rem; }
  .value.mono { font-size: 0.95rem; }
  .sub { color: #8b949e; font-size: 0.8rem; }
  .bar {
    background: #21262d;
    border-radius: 4px;
    height: 8px;
    overflow: hidden;
  }
  .fill {
    background: #7ee787;
    height: 100%;
    border-radius: 4px;
    transition: width 0.4s ease;
  }
  .muted { color: #8b949e; }
  .error { color: #f85149; }
</style>
