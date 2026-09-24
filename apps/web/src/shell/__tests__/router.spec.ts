import { describe, expect, it } from 'vitest'

import { NAV_GROUPS } from '../nav'
import { legacyHashUrl, routes, router } from '@/router'

function resolve(path: string) {
  const resolved = router.resolve(path)
  return resolved.matched.at(-1)?.path ?? ''
}

describe('router', () => {
  it('resolves every NAV item path to a route', () => {
    for (const item of NAV_GROUPS.flatMap(g => g.items)) {
      const resolved = router.resolve(item.to)
      expect(resolved.matched[0]?.path, item.to).toBe(item.to)
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

describe('legacy hash URLs', () => {
  it('returns the clean path and query for old hash links', () => {
    expect(legacyHashUrl('?theme=dark', '#/fleet/add')).toBe('/fleet/add?theme=dark')
  })

  it('combines the legacy outer and route queries', () => {
    expect(legacyHashUrl('?campaign=x', '#/fleet?tab=y')).toBe('/fleet?campaign=x&tab=y')
  })

  it('preserves outer-query precedence for repeated keys', () => {
    expect(legacyHashUrl('?theme=dark', '#/fleet?theme=light'))
      .toBe('/fleet?theme=dark&theme=light')
  })

  it('leaves ordinary URLs unchanged', () => {
    expect(legacyHashUrl('?theme=dark', '')).toBeNull()
    expect(legacyHashUrl('', '#section')).toBeNull()
  })

  it('ignores hash routes that could be interpreted as network paths', () => {
    expect(legacyHashUrl('', '#//evil.example')).toBeNull()
    expect(legacyHashUrl('', '#/\\\\evil.example')).toBeNull()
  })
})
