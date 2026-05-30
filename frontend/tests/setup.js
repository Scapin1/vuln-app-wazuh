import { config } from '@vue/test-utils'
import clickOutside from '@/presentation/directives/clickOutside'

config.global.directives = {
    'click-outside': clickOutside
}

// Polyfill ResizeObserver for jsdom test environment
// AreaChartTab.vue uses ResizeObserver which is not available in jsdom
if (typeof globalThis.ResizeObserver === 'undefined') {
  globalThis.ResizeObserver = class ResizeObserver {
    constructor(callback) {
      this.callback = callback
    }
    observe() {}
    unobserve() {}
    disconnect() {}
  }
}

// Vitest 4 with jsdom 28 provides localStorage/sessionStorage as empty
// null-prototype objects without Storage methods (clear, getItem, etc.).
// This polyfill ensures the full Storage API is available.
function createStorageMock() {
  const store = new Map()
  const mock = {
    get length() { return store.size },
    clear() { store.clear() },
    getItem(key) { return store.get(String(key)) ?? null },
    key(index) { return [...store.keys()][index] ?? null },
    removeItem(key) { store.delete(String(key)) },
    setItem(key, value) { store.set(String(key), String(value)) },
  }
  Object.setPrototypeOf(mock, null)
  return mock
}

if (typeof localStorage !== 'undefined' && typeof localStorage.clear !== 'function') {
  globalThis.localStorage = createStorageMock()
}
if (typeof sessionStorage !== 'undefined' && typeof sessionStorage.clear !== 'function') {
  globalThis.sessionStorage = createStorageMock()
}
