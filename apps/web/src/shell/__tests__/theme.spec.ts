import { beforeEach, describe, expect, it, vi } from 'vitest'

import { applyInitialTheme, useTheme } from '../theme'

describe('theme', () => {
  beforeEach(() => {
    window.localStorage.clear()
    document.documentElement.dataset.theme = ''
    document.documentElement.classList.remove('dark')
    vi.stubGlobal('location', new URL('http://localhost/', window.location.href))
  })

  it('defaults to dark', () => {
    applyInitialTheme()
    expect(document.documentElement.dataset.theme).toBe('dark')
    expect(document.documentElement.classList.contains('dark')).toBe(true)
  })

  it('honors the localStorage value', () => {
    window.localStorage.setItem('fleet-console-theme', 'light')
    applyInitialTheme()
    expect(document.documentElement.dataset.theme).toBe('light')
    expect(document.documentElement.classList.contains('dark')).toBe(false)
  })

  it('the URL param wins over localStorage', () => {
    window.localStorage.setItem('fleet-console-theme', 'light')
    vi.stubGlobal('location', new URL('http://localhost/?theme=dark', window.location.href))
    applyInitialTheme()
    expect(document.documentElement.dataset.theme).toBe('dark')
  })

  it('toggle persists to localStorage and flips the dark class', () => {
    applyInitialTheme()
    const { theme, toggle } = useTheme()
    expect(theme.value).toBe('dark')
    toggle()
    expect(theme.value).toBe('light')
    expect(window.localStorage.getItem('fleet-console-theme')).toBe('light')
    expect(document.documentElement.classList.contains('dark')).toBe(false)
    toggle()
    expect(window.localStorage.getItem('fleet-console-theme')).toBe('dark')
    expect(document.documentElement.classList.contains('dark')).toBe(true)
  })
})
