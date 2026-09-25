import { describe, expect, it } from 'vitest'

import {
  buildParams,
  EMPTY_FILTERS,
  hasFilters,
  type AuditFilters,
} from '../filters'

function filtersWith(overrides: Partial<AuditFilters>): AuditFilters {
  return { ...EMPTY_FILTERS, ...overrides }
}

describe('audit filters', () => {
  it('drops blank fields and keeps set ones', () => {
    const { params, error } = buildParams(filtersWith({ actor: ' anon ', action: 'machine.update' }))
    expect(error).toBeNull()
    expect(params).toEqual({ actor: 'anon', action: 'machine.update' })
  })

  it('parses dates as epoch milliseconds and rejects an inverted range', () => {
    const ok = buildParams(filtersWith({ from: '2026-01-01T00:00', to: '2026-01-02T00:00' }))
    expect(ok.error).toBeNull()
    expect(ok.params.from as number).toBeLessThan(ok.params.to as number)

    const inverted = buildParams(filtersWith({ from: '2026-01-02T00:00', to: '2026-01-01T00:00' }))
    expect(inverted.error).toContain('after')
  })

  it('rejects a malformed date instead of sending garbage', () => {
    const bad = buildParams(filtersWith({ from: 'not-a-date' }))
    expect(bad.error).toContain('not a valid date')
  })

  it('keeps the outcome only when it is one of the honest set', () => {
    const good = buildParams(filtersWith({ outcome: 'denied' }))
    expect(good.params.outcome).toBe('denied')
    // An outcome that is not one of the API's ids is dropped, not sent.
    const bad = buildParams(filtersWith({ outcome: 'excellent' as never }))
    expect(bad.params.outcome).toBeUndefined()
  })

  it('reports whether any filter is set', () => {
    expect(hasFilters(EMPTY_FILTERS)).toBe(false)
    expect(hasFilters(filtersWith({ actor: 'anon' }))).toBe(true)
    expect(hasFilters(filtersWith({ outcome: 'denied' }))).toBe(true)
  })

  it('passes the cursor through when given', () => {
    const { params, error } = buildParams(EMPTY_FILTERS, '42')
    expect(error).toBeNull()
    expect(params.cursor).toBe('42')
  })
})
