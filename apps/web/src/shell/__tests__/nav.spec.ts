import { beforeEach, describe, expect, it, vi } from 'vitest'

import { NAV_GROUPS } from '../nav'

describe('nav', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
  })

  it('has the specified groups, labels, and order', () => {
    const labels = NAV_GROUPS.map(g => g.label)
    expect(labels).toEqual([null, 'Infrastructure', 'Work', 'Control'])

    const paths = NAV_GROUPS.flatMap(g => g.items.map(i => i.to))
    expect(paths).toEqual([
      '/',
      '/fleet',
      '/proxmox',
      '/tailnet',
      '/containers',
      '/projects',
      '/skills',
      '/lab',
      '/images',
      '/operations',
      '/audit',
      '/settings',
    ])
  })

  it('exposes exactly the six available items', () => {
    const available = NAV_GROUPS.flatMap(g => g.items.filter(i => i.available).map(i => i.to))
    expect(available).toEqual(['/', '/fleet', '/projects', '/operations', '/audit', '/settings'])
  })
})
