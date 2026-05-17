<script>
  import { onMount } from 'svelte'

  // Schema items:
  //   { type: 'bool', key, label, desc }
  //   { type: 'int',  key, label, desc, min, max, default }
  export let schema = []
  export let storageKey = ''
  // Comma-separated tokens: "k1,k2:N" — bind:opts on the parent.
  export let opts = ''
  // Preview bar: flags the daemon always adds + the eventual target.
  export let command = 'emerge'
  export let baseFlags = []
  export let target = ''

  let checked = {}
  let values = {}
  let open = false

  function load() {
    try {
      const saved = JSON.parse(localStorage.getItem(storageKey) || '{}') || {}
      checked = saved.checked || {}
      values  = saved.values  || {}
    } catch (_) {
      checked = {}; values = {}
    }
  }

  function save() {
    try { localStorage.setItem(storageKey, JSON.stringify({ checked, values })) } catch (_) {}
  }

  function toggle(key) {
    checked = { ...checked, [key]: !checked[key] }
    save()
  }

  function valueFor(item) {
    const v = values[item.key]
    return v === undefined || v === null || v === '' ? item.default : v
  }

  // Don't clamp while the user is typing (would cause the input to flicker as
  // its `value` attribute is rewritten). Clamp only when serialising into the
  // outgoing opts string.
  function setValue(item, raw) {
    values = { ...values, [item.key]: raw }
    save()
  }

  function clamped(item) {
    let n = parseInt(valueFor(item), 10)
    if (!Number.isFinite(n)) n = item.default
    if (n < item.min) n = item.min
    if (n > item.max) n = item.max
    return n
  }

  function flagFor(item) {
    return item.type === 'int' ? item.label.replace('N', clamped(item)) : item.label
  }

  onMount(load)

  $: opts = schema
    .filter(s => checked[s.key])
    .map(s => s.type === 'int' ? `${s.key}:${clamped(s)}` : s.key)
    .join(',')
  $: userFlags = schema.filter(s => checked[s.key]).map(flagFor)
  $: activeCount = userFlags.length
</script>

<div class="opts">
  <div class="preview" title="Command that will be executed">
    <span class="prompt">$</span>
    <span class="cmd">{command}</span>
    {#each baseFlags as f}<span class="base">{f}</span>{/each}
    {#each userFlags as f}<span class="user">{f}</span>{/each}
    {#if target}<span class="target">{target}</span>{/if}
  </div>

  <button class="opts-toggle" type="button" on:click={() => open = !open}>
    <span class="chev">{open ? '▾' : '▸'}</span>
    <span>Options</span>
    {#if activeCount > 0}<span class="badge">{activeCount}</span>{/if}
  </button>

  {#if open}
    <div class="opts-list">
      {#each schema as item}
        <label class="opt">
          <input type="checkbox" checked={!!checked[item.key]} on:change={() => toggle(item.key)} />
          <span class="flag">{item.label}</span>
          {#if item.type === 'int'}
            <input class="num"
                   type="number"
                   min={item.min}
                   max={item.max}
                   value={valueFor(item)}
                   disabled={!checked[item.key]}
                   on:input={(e) => setValue(item, e.target.value)} />
          {:else}
            <span class="num-spacer"></span>
          {/if}
          <span class="desc">{item.desc}</span>
        </label>
      {/each}
    </div>
  {/if}
</div>

<style>
  .opts {
    background: #0d1117;
    border: 1px solid #30363d;
    border-radius: 6px;
    margin-bottom: .5rem;
  }
  .preview {
    display: flex; flex-wrap: wrap; align-items: baseline;
    gap: .4em;
    padding: .45rem .75rem;
    font-family: 'JetBrains Mono', 'Fira Code', monospace;
    font-size: .76rem;
    line-height: 1.4;
    border-bottom: 1px solid #30363d;
    overflow-wrap: anywhere;
  }
  .preview .prompt { color: #6e7681; user-select: none; }
  .preview .cmd { color: #c9d1d9; }
  .preview .base { color: #6e7681; }
  .preview .user { color: #58a6ff; }
  .preview .target { color: #7ee787; }
  .opts-toggle {
    display: flex; align-items: center; gap: .5rem;
    width: 100%;
    background: none; border: none;
    color: #8b949e; cursor: pointer;
    font-family: inherit; font-size: .8rem;
    padding: .45rem .75rem;
    text-align: left;
  }
  .opts-toggle:hover { color: #c9d1d9; }
  .chev { display: inline-block; width: .9em; color: #6e7681; }
  .badge {
    background: #1a3050;
    color: #58a6ff;
    border-radius: 10px;
    font-size: .7rem;
    padding: .05rem .45rem;
    margin-left: auto;
  }
  .opts-list {
    border-top: 1px solid #30363d;
    padding: .5rem .75rem;
    display: flex; flex-direction: column; gap: .3rem;
  }
  .opt {
    display: grid;
    grid-template-columns: auto auto 4.5em 1fr;
    align-items: baseline;
    gap: .6rem;
    cursor: pointer;
    padding: .15rem 0;
  }
  .opt input[type=checkbox] { cursor: pointer; accent-color: #58a6ff; margin: 0; }
  .flag {
    color: #c9d1d9;
    font-family: 'JetBrains Mono', 'Fira Code', monospace;
    font-size: .78rem;
    white-space: nowrap;
  }
  .num {
    width: 4.5em;
    background: #161b22;
    color: #c9d1d9;
    border: 1px solid #30363d;
    border-radius: 4px;
    font-family: inherit;
    font-size: .76rem;
    padding: .1rem .3rem;
  }
  .num:disabled { color: #6e7681; background: #0d1117; }
  .num-spacer { width: 4.5em; }
  .desc {
    color: #8b949e;
    font-size: .76rem;
    line-height: 1.35;
  }
</style>
