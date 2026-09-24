import { describe, expect, it } from 'vitest'

import { NAV_GROUPS } from '../nav'
import { routes, router } from '@/router'

function resolve(path: string) {
  const resolved = router.resolve(path)
  return resolved.matched.at(-1)?.path ?? ''
}

describe('router', () => {
  it('resolves every NAV item path to a route', () => {
    for (const item of NAV_GROUPS.flatMap(g => g.items)) {
      expect(resolve(item.to), item.to).not.toBe('')
    }
  })

  it('resolves an unknown path to the not-found route', () => {
    expect(resolve('/nope/nothing')).toBe('/:pathMatch(.*)*')
  })

  it('has the /fleet/add route', () => {
    expect(resolve('/fleet/add')).toBe('/fleet/add')
  })
})

describe('routes', () => {
  it('carries meta titles for the pages', () => {
    const overview = routes.find(r => r.path === '/')
    expect(overview?.meta?.title).toBe('Overview')
    const fleet = routes.find(r => r.path === '/fleet')
    expect(fleet?.meta?.group).toBe('Infrastructure')
  })
})
