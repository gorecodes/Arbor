<script>
  import { onMount } from 'svelte'
  import { api } from '../lib/api.js'
  import { navigateTo } from '../lib/stores.js'

  let { atom } = $props()

  let root = $state(null)
  let error = $state(null)
  let loading = $state(true)

  onMount(async () => {
    try {
      const data = await api.depGraph(atom, 1)
      if (data?.error) { error = data.error; return }
      const byId = {}
      data.nodes.forEach(n => byId[n.id] = n)
      const rootInfo = byId[data.root] || { id: data.root, cpv: data.root, installed: false }
      const directCps = data.edges
        .filter(e => e.source === data.root && byId[e.target])
        .map(e => e.target)
      root = {
        cp: data.root,
        cpv: rootInfo.cpv,
        installed: rootInfo.installed,
        expanded: true,
        loading: false,
        error: null,
        circular: false,
        children: directCps.map(cp => mknode(byId[cp], new Set([data.root])))
      }
    } catch(e) {
      error = e.message
    } finally {
      loading = false
    }
  })

  function mknode(n, selfAndAncestors) {
    return {
      cp: n.id,
      cpv: n.cpv,
      installed: n.installed,
      expanded: false,
      loading: false,
      error: null,
      circular: selfAndAncestors.has(n.id),
      children: null
    }
  }

  async function toggle(node, ancestors) {
    if (node.circular) return
    if (node.expanded) {
      node.expanded = false
      return
    }
    node.expanded = true
    root = root
    if (node.children !== null) return

    node.loading = true
    root = root
    const selfAndAncestors = new Set([...ancestors, node.cp])
    try {
      const data = await api.depGraph(node.cpv, 1)
      if (data?.error) { node.error = data.error; node.children = []; return }
      const byId = {}
      data.nodes.forEach(n => byId[n.id] = n)
      const childCps = data.edges
        .filter(e => e.source === data.root && byId[e.target])
        .map(e => e.target)
      node.children = childCps.map(cp => mknode(byId[cp], selfAndAncestors))
    } catch(e) {
      node.error = e.message
      node.children = []
    } finally {
      node.loading = false
    }
  }
</script>

<div class="tree">
  {#if loading}
    <p class="msg">Resolving…</p>
  {:else if error}
    <p class="msg err">{error}</p>
  {:else if root}
    {#snippet tnode(n, ancestors, isRoot)}
      <li class="item">
        <div class="row" class:is-root={isRoot}>
          {#if n.circular}
            <span class="tog circ" title="circular dependency">↺</span>
          {:else}
            <button class="tog" onclick={() => toggle(n, ancestors)}>
              {#if n.loading}…{:else if n.expanded}▾{:else}▸{/if}
            </button>
          {/if}
          <span class="dot" class:inst={n.installed} onclick={() => navigateTo(n.cpv)} role="button" tabindex="0"></span>
          <button class="pkg" onclick={() => navigateTo(n.cpv)}>
            {n.cp.split('/')[1] || n.cp}
          </button>
          <span class="cat">{n.cp.split('/')[0]}</span>
          {#if !n.installed}<span class="badge miss">not installed</span>{/if}
          {#if n.error}<span class="badge err-badge">{n.error}</span>{/if}
        </div>
        {#if n.expanded}
          {#if n.children === null}
            <ul><li class="msg indent">Loading…</li></ul>
          {:else if n.children.length === 0}
            <ul><li class="msg indent muted">no runtime deps</li></ul>
          {:else}
            <ul>
              {#each n.children as child}
                {@render tnode(child, new Set([...ancestors, n.cp]), false)}
              {/each}
            </ul>
          {/if}
        {/if}
      </li>
    {/snippet}
    <ul class="tree-root">
      {@render tnode(root, new Set(), true)}
    </ul>
  {/if}
</div>

<style>
  .tree { overflow: auto; height: calc(100vh - 300px); min-height: 300px; }
  ul { list-style: none; margin: 0; padding: 0 0 0 1.4rem; border-left: 1px solid #21262d; }
  ul.tree-root { padding: 0; border: none; }
  .item { padding: 1px 0; }
  .row {
    display: flex;
    align-items: center;
    gap: .4rem;
    padding: .15rem .3rem;
    border-radius: 4px;
    cursor: default;
  }
  .row:hover { background: #161b22; }
  .row.is-root { font-weight: 600; }
  .tog {
    background: none;
    border: none;
    color: #6e7681;
    cursor: pointer;
    font-size: .75rem;
    padding: 0;
    width: 1rem;
    text-align: center;
    flex-shrink: 0;
    font-family: inherit;
    line-height: 1;
  }
  .tog:hover { color: #c9d1d9; }
  .tog.circ { cursor: default; color: #6e7681; font-size: .8rem; }
  .dot {
    width: 7px; height: 7px;
    border-radius: 50%;
    flex-shrink: 0;
    background: #161b22;
    border: 1.5px solid #444d56;
    cursor: pointer;
  }
  .dot.inst { background: #1a3a1e; border-color: #3fb950; }
  .pkg {
    background: none;
    border: none;
    color: #c9d1d9;
    cursor: pointer;
    font-family: inherit;
    font-size: .85rem;
    padding: 0;
  }
  .pkg:hover { color: #58a6ff; text-decoration: underline; }
  .cat { color: #484f58; font-size: .72rem; }
  .badge {
    font-size: .68rem;
    padding: .1rem .3rem;
    border-radius: 3px;
  }
  .badge.miss { background: #161b22; color: #484f58; border: 1px solid #30363d; }
  .badge.err-badge { background: #3d1c1c; color: #f85149; }
  .msg { color: #8b949e; font-size: .8rem; margin: 0; }
  .msg.indent { padding-left: 1.4rem; }
  .msg.err { color: #f85149; }
  .muted { color: #484f58; }
</style>
