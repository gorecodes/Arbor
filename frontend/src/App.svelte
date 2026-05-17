<script>
  import { onMount } from 'svelte'
  import { authToken, currentView, selectedPackage, installAtom, uninstallAtom, initRouter } from './lib/stores.js'
  import Login from './components/Login.svelte'
  import Nav from './components/Nav.svelte'
  import Dashboard from './components/Dashboard.svelte'
  import PackageList from './components/PackageList.svelte'
  import PackageDetail from './components/PackageDetail.svelte'
  import SearchView from './components/SearchView.svelte'
  import UpdatesView from './components/UpdatesView.svelte'
  import JobsView from './components/JobsView.svelte'
  import InstallView from './components/InstallView.svelte'
  import UninstallView from './components/UninstallView.svelte'

  onMount(initRouter)
</script>

{#if !$authToken}
  <Login />
{:else}
  <div class="layout">
    <Nav />
    <main>
      {#if $currentView === 'install' && $installAtom}
        <InstallView atom={$installAtom} cpv={$installAtom} />
      {:else if $currentView === 'uninstall' && $uninstallAtom}
        <UninstallView atom={$uninstallAtom} cpv={$uninstallAtom} />
      {:else if $selectedPackage}
        {#key $selectedPackage}
          <PackageDetail atom={$selectedPackage} />
        {/key}
      {:else if $currentView === 'dashboard'}
        <Dashboard />
      {:else if $currentView === 'packages'}
        <PackageList />
      {:else if $currentView === 'search'}
        <SearchView />
      {:else if $currentView === 'updates'}
        <UpdatesView />
      {:else if $currentView === 'jobs'}
        <JobsView />
      {/if}
    </main>
  </div>
{/if}

<style>
  :global(*, *::before, *::after) { box-sizing: border-box; margin: 0; padding: 0; }
  :global(body) {
    font-family: 'JetBrains Mono', 'Fira Code', monospace;
    background: #0e1117;
    color: #c9d1d9;
    font-size: 14px;
  }
  :global(a) { color: #58a6ff; text-decoration: none; }
  :global(a:hover) { text-decoration: underline; }

  .layout {
    display: grid;
    grid-template-columns: 220px 1fr;
    min-height: 100vh;
  }
  main {
    padding: 2rem;
    overflow-y: auto;
  }
</style>
