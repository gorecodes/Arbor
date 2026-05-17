<script>
  import { onMount, onDestroy } from 'svelte'
  import { api } from '../lib/api.js'
  import { navigateTo, packageListSearch } from '../lib/stores.js'

  let packages = []
  let search = ''
  let loading = true
  let timer

  const unsub = packageListSearch.subscribe(v => { search = v })

  onMount(() => load())
  onDestroy(() => unsub())

  async function load() {
    loading = true
    try {
      packages = await api.packages(search)
    } finally {
      loading = false
    }
  }

  function onSearch() {
    packageListSearch.set(search)
    clearTimeout(timer)
    timer = setTimeout(load, 300)
  }

  function fmt_date(ts) {
    if (!ts) return '—'
    return new Date(parseInt(ts) * 1000).toLocaleDateString()
  }
</script>

<div>
  <div class="toolbar">
    <h2>Installed Packages</h2>
    <input
      type="search"
      bind:value={search}
      on:input={onSearch}
      placeholder="Filter…"
    />
  </div>

  {#if loading}
    <p class="muted">Loading…</p>
  {:else}
    <table>
      <thead>
        <tr>
          <th>Package</th>
          <th>Category</th>
          <th>Slot</th>
          <th>Built</th>
        </tr>
      </thead>
      <tbody>
        {#each packages as pkg}
          <tr on:click={() => navigateTo(pkg.cpv)} class="clickable">
            <td class="pkg">{pkg.pf}</td>
            <td class="cat">{pkg.cat}</td>
            <td>{pkg.slot}</td>
            <td>{fmt_date(pkg.build_time)}</td>
          </tr>
        {/each}
      </tbody>
    </table>
    <p class="count">{packages.length} packages</p>
  {/if}
</div>

<style>
  .toolbar {
    display: flex;
    align-items: center;
    gap: 1rem;
    margin-bottom: 1.5rem;
  }
  h2 { color: #e6edf3; flex: 1; }
  input {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 6px;
    color: #c9d1d9;
    font-family: inherit;
    font-size: 0.9rem;
    padding: 0.4rem 0.8rem;
    width: 240px;
  }
  input:focus { outline: none; border-color: #58a6ff; }
  table { width: 100%; border-collapse: collapse; }
  th {
    color: #8b949e;
    font-size: 0.75rem;
    text-align: left;
    text-transform: uppercase;
    padding: 0.5rem 0.75rem;
    border-bottom: 1px solid #30363d;
  }
  td { padding: 0.45rem 0.75rem; border-bottom: 1px solid #21262d; }
  tr.clickable { cursor: pointer; }
  tr.clickable:hover td { background: #161b22; }
  .pkg { color: #e6edf3; }
  .cat { color: #8b949e; font-size: 0.85rem; }
  .count { color: #8b949e; font-size: 0.8rem; margin-top: 1rem; }
  .muted { color: #8b949e; }
</style>
