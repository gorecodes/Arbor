<script>
  import { onMount, onDestroy } from 'svelte'
  import { api } from '../lib/api.js'
  import { navigateTo, searchViewQuery } from '../lib/stores.js'

  let query = ''
  let results = []
  let loading = false
  let searched = false
  let timer

  const unsub = searchViewQuery.subscribe(v => { query = v })

  onMount(() => {
    if (query.length >= 2) search()
  })
  onDestroy(() => unsub())

  function onInput() {
    clearTimeout(timer)
    if (query.length < 2) { results = []; searched = false; searchViewQuery.set(''); return }
    searchViewQuery.set(query)
    timer = setTimeout(search, 350)
  }

  async function search() {
    loading = true
    searched = true
    try {
      results = await api.search(query)
    } finally {
      loading = false
    }
  }
</script>

<div>
  <div class="toolbar">
    <h2>Search Portage Tree</h2>
    <input
      type="search"
      bind:value={query}
      on:input={onInput}
      placeholder="package name…"
    />
  </div>

  {#if loading}
    <p class="muted">Searching…</p>
  {:else if searched && results.length === 0}
    <p class="muted">No results for "{query}"</p>
  {:else}
    <table>
      <thead>
        <tr>
          <th>Package</th>
          <th>Best version</th>
          <th>Description</th>
        </tr>
      </thead>
      <tbody>
        {#each results as r}
          <tr class="clickable" on:click={() => navigateTo(r.best || r.cp)}>
            <td class="pkg">{r.cp}</td>
            <td class="ver">{r.best || '—'}</td>
            <td class="desc">{r.description}</td>
          </tr>
        {/each}
      </tbody>
    </table>
  {/if}
</div>

<style>
  .toolbar { display: flex; align-items: center; gap: 1rem; margin-bottom: 1.5rem; }
  h2 { color: #e6edf3; flex: 1; }
  input {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 6px;
    color: #c9d1d9;
    font-family: inherit;
    font-size: 0.9rem;
    padding: 0.4rem 0.8rem;
    width: 300px;
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
  .ver { color: #8b949e; font-size: 0.85rem; }
  .desc { color: #8b949e; font-size: 0.85rem; max-width: 400px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .muted { color: #8b949e; }
</style>
