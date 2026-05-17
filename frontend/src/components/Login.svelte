<script>
  import { authToken } from '../lib/stores.js'
  import { api } from '../lib/api.js'

  let token = ''
  let error = ''
  let loading = false

  async function submit() {
    loading = true
    error = ''
    const trimmed = token.trim()
    api.setToken(trimmed)
    try {
      await api.status()
      authToken.set(trimmed)
    } catch {
      error = 'Invalid token'
      api.setToken('')
    } finally {
      loading = false
    }
  }
</script>

<div class="login">
  <div class="card">
    <h1>Arbor</h1>
    <p class="sub">Portage explorer</p>
    <form on:submit|preventDefault={submit}>
      <input
        type="password"
        bind:value={token}
        placeholder="Access token"
        autocomplete="current-password"
      />
      {#if error}<span class="error">{error}</span>{/if}
      <button type="submit" disabled={loading || !token}>
        {loading ? 'Connecting…' : 'Connect'}
      </button>
    </form>
  </div>
</div>

<style>
  .login {
    display: flex;
    align-items: center;
    justify-content: center;
    min-height: 100vh;
  }
  .card {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 8px;
    padding: 2.5rem;
    width: 340px;
  }
  h1 { font-size: 1.8rem; color: #7ee787; margin-bottom: 0.25rem; }
  .sub { color: #8b949e; margin-bottom: 2rem; }
  form { display: flex; flex-direction: column; gap: 0.75rem; }
  input {
    background: #0e1117;
    border: 1px solid #30363d;
    border-radius: 6px;
    color: #c9d1d9;
    font-family: inherit;
    font-size: 0.9rem;
    padding: 0.6rem 0.8rem;
    outline: none;
  }
  input:focus { border-color: #58a6ff; }
  button {
    background: #238636;
    border: none;
    border-radius: 6px;
    color: #fff;
    cursor: pointer;
    font-family: inherit;
    font-size: 0.9rem;
    padding: 0.6rem;
  }
  button:disabled { opacity: 0.5; cursor: default; }
  button:not(:disabled):hover { background: #2ea043; }
  .error { color: #f85149; font-size: 0.8rem; }
</style>
