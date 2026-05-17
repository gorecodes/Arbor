<script>
  import { currentView, selectedPackage, authToken, navigate } from '../lib/stores.js'

  const items = [
    { id: 'dashboard', label: 'Dashboard' },
    { id: 'packages',  label: 'Installed' },
    { id: 'search',    label: 'Search' },
    { id: 'updates',   label: 'Maintenance' },
    { id: 'jobs',      label: 'Jobs' },
  ]

  function nav(id) {
    navigate(id)
  }

  function logout() {
    authToken.set('')
    localStorage.removeItem('arbor_token')
  }
</script>

<nav>
  <div class="logo">
    <span class="tree">⬡</span> Arbor
  </div>

  <ul>
    {#each items as item}
      <li class:active={$currentView === item.id && !$selectedPackage}>
        <button on:click={() => nav(item.id)}>{item.label}</button>
      </li>
    {/each}
  </ul>

  <div class="bottom">
    <button class="logout" on:click={logout}>Logout</button>
  </div>
</nav>

<style>
  nav {
    background: #161b22;
    border-right: 1px solid #30363d;
    display: flex;
    flex-direction: column;
    padding: 1.5rem 0;
    position: sticky;
    top: 0;
    height: 100vh;
  }
  .logo {
    color: #7ee787;
    font-size: 1.2rem;
    font-weight: bold;
    padding: 0 1.5rem 1.5rem;
    border-bottom: 1px solid #30363d;
  }
  .tree { font-size: 1rem; }
  ul {
    list-style: none;
    padding: 1rem 0;
    flex: 1;
  }
  li button {
    background: none;
    border: none;
    color: #8b949e;
    cursor: pointer;
    font-family: inherit;
    font-size: 0.9rem;
    padding: 0.6rem 1.5rem;
    text-align: left;
    width: 100%;
  }
  li button:hover { color: #c9d1d9; background: #21262d; }
  li.active button { color: #7ee787; border-left: 2px solid #7ee787; }
  .bottom { padding: 1rem 1.5rem; }
  .logout {
    background: none;
    border: 1px solid #30363d;
    border-radius: 6px;
    color: #8b949e;
    cursor: pointer;
    font-family: inherit;
    font-size: 0.8rem;
    padding: 0.4rem 0.8rem;
    width: 100%;
  }
  .logout:hover { color: #f85149; border-color: #f85149; }
</style>
