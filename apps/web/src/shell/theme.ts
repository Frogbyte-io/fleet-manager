import { ref } from 'vue'

export type Theme = 'dark' | 'light'

const STORAGE_KEY = 'fleet-console-theme'

const theme = ref<Theme>('dark')

function apply(value: Theme) {
  theme.value = value
  document.documentElement.dataset.theme = value
  document.documentElement.classList.toggle('dark', value === 'dark')
}

function readStored(): Theme | null {
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY)
    return raw === 'dark' || raw === 'light' ? raw : null
  } catch {
    return null
  }
}

/** Applies the initial theme: URL param wins, then localStorage, then dark. */
export function applyInitialTheme() {
  const param = new URLSearchParams(window.location.search).get('theme')
  apply(param === 'light' || param === 'dark' ? param : (readStored() ?? 'dark'))
}

export function useTheme() {
  function toggle() {
    const next: Theme = theme.value === 'dark' ? 'light' : 'dark'
    apply(next)
    try {
      window.localStorage.setItem(STORAGE_KEY, next)
    } catch {
      // persistence is best-effort
    }
  }
  return { theme, toggle }
}
