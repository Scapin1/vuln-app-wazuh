import { config } from '@vue/test-utils'
import clickOutside from '@/presentation/directives/clickOutside'

// Polyfill canvas 2D context for Chart.js in jsdom test environment
if (typeof HTMLCanvasElement !== 'undefined' &&
    typeof HTMLCanvasElement.prototype.getContext !== 'function') {
  HTMLCanvasElement.prototype.getContext = function mockGetContext() {
    return {
      canvas: this,
      clearRect: () => {},
      fillRect: () => {},
      fillText: () => {},
      beginPath: () => {},
      arc: () => {},
      fill: () => {},
      stroke: () => {},
      moveTo: () => {},
      lineTo: () => {},
      closePath: () => {},
      translate: () => {},
      scale: () => {},
      rotate: () => {},
      drawImage: () => {},
      createLinearGradient: () => ({ addColorStop: () => {} }),
      createRadialGradient: () => ({ addColorStop: () => {} }),
      measureText: () => ({ width: 0 }),
      restore: () => {},
      save: () => {},
    }
  }
}

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
