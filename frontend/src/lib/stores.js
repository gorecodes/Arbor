import { writable, get } from 'svelte/store'

export const currentView = writable('dashboard')
export const selectedPackage = writable(null)
export const authToken = writable(localStorage.getItem('arbor_token') || '')
export const packageListSearch = writable('')
export const searchViewQuery = writable('')
export const installAtom = writable(null)
export const uninstallAtom = writable(null)

authToken.subscribe(v => {
  if (v) localStorage.setItem('arbor_token', v)
})

export function navigate(view, param = null) {
  if (param !== null) {
    location.hash = `/${view}/${encodeURIComponent(param)}`
  } else {
    location.hash = `/${view}`
  }
}

let _routerInit = false

export function initRouter() {
  if (_routerInit) return
  _routerInit = true
  window.addEventListener('hashchange', applyRoute)
  if (!location.hash || location.hash === '#' || location.hash === '#/') {
    location.hash = '/dashboard'
  }
  applyRoute()
}

function applyRoute() {
  const hash = location.hash.replace(/^#/, '') // e.g. "/packages/foo%2Fbar"
  const prevView = get(currentView)

  const packageMatch = hash.match(/^\/packages\/(.+)$/)
  const installMatch = hash.match(/^\/install\/(.+)$/)
  const uninstallMatch = hash.match(/^\/uninstall\/(.+)$/)
  const simpleMatch = hash.match(/^\/([^/]+)$/)

  if (packageMatch) {
    const atom = decodeURIComponent(packageMatch[1])
    selectedPackage.set(atom)
    currentView.set('packages')
  } else if (installMatch) {
    const atom = decodeURIComponent(installMatch[1])
    installAtom.set(atom)
    currentView.set('install')
  } else if (uninstallMatch) {
    const atom = decodeURIComponent(uninstallMatch[1])
    uninstallAtom.set(atom)
    currentView.set('uninstall')
  } else if (simpleMatch) {
    const view = simpleMatch[1]
    currentView.set(view)
    selectedPackage.set(null)
  } else {
    currentView.set('dashboard')
    selectedPackage.set(null)
  }
}

export function navigateTo(cpv) {
  navigate('packages', cpv)
}

export function navigateBack() {
  window.history.back()
}
