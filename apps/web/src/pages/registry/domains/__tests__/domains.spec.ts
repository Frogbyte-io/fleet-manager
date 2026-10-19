import { describe, expect, expectTypeOf, it } from 'vitest'

import type { DomainObservationViewDto, FieldDiffDto, RegistryEntryDto, SuggestedFieldDto } from '@frogbyte-io/fleet-api-client'

import { diffText, domainRow, domainRows, domainSummary, expiryState, shellWord, suggestCommand } from '../domains'

const NOW = Date.UTC(2026, 9, 16, 12)

function entry(key: string, fields: Record<string, unknown>): RegistryEntryDto {
  return { id: key, key, name: key, type: 'domain', fields, links: [], relations: [], tags: [] }
}

const NO_RECORDS = { a: [], aaaa: [], cname: [], ns: [] }

function view(key: string, patch: Record<string, unknown> = {}): DomainObservationViewDto {
  return {
    key,
    diffs: [],
    suggestion: [],
    warnings: [],
    observation: {
      observedAt: NOW,
      failures: 0,
      rdap: { status: 'ok', nameservers: ['ns1.example.net'], expires: '2027-03-01', registrar: 'Webhuset' },
      dns: { status: 'ok', apex: { ...NO_RECORDS, a: ['192.0.2.10'] }, www: { ...NO_RECORDS, cname: ['example.org'] } },
    },
    ...patch,
  } as unknown as DomainObservationViewDto
}

describe('expiryState', () => {
  it('classifies expired, soon, ok and unknown dates', () => {
    expect(expiryState('2026-10-10', NOW)).toMatchObject({ kind: 'expired', tone: 'err', label: 'Expired 6 days ago' })
    expect(expiryState('2026-10-16', NOW)).toMatchObject({ kind: 'soon', tone: 'err', label: 'Expires today' })
    expect(expiryState('2026-10-17', NOW)).toMatchObject({ kind: 'soon', tone: 'err', label: 'Expires in 1 day' })
    expect(expiryState('2026-10-23', NOW)).toMatchObject({ tone: 'err', days: 7 })
    expect(expiryState('2026-10-24', NOW)).toMatchObject({ tone: 'warn', days: 8 })
    expect(expiryState('2026-11-10', NOW)).toMatchObject({ kind: 'soon', tone: 'warn', days: 25 })
    expect(expiryState('2026-11-16', NOW)).toMatchObject({ kind: 'ok', tone: 'ok', days: 31 })
    expect(expiryState(null, NOW)).toMatchObject({ kind: 'unknown', tone: 'muted' })
    expect(expiryState('soon', NOW).kind).toBe('unknown')
  })
})

describe('domainRow', () => {
  it('joins an observation: points-at, nameservers, in-sync count', () => {
    const row = domainRow(entry('example.org', { registrar: 'Webhuset', expires: '2027-03-01' }), view('example.org', {
      diffs: [{ field: 'registrar', state: 'in_sync', recorded: 'Webhuset', observed: 'Webhuset' }],
    }), NOW)
    expect(row.pointsAt).toEqual([
      { name: 'apex', records: ['A 192.0.2.10'] },
      { name: 'www', records: ['CNAME example.org'] },
    ])
    expect(row.nameservers).toEqual(['ns1.example.net'])
    expect(row).toMatchObject({ observed: true, inSync: 1, tone: 'ok', command: null, expirySource: 'observed' })
  })

  it('reports drift with both values and the suggested set command', () => {
    const row = domainRow(entry('example.org', { registrar: 'GoDaddy', expires: '2027-03-01' }), view('example.org', {
      diffs: [
        { field: 'registrar', state: 'changed', recorded: 'GoDaddy', observed: 'Webhuset' },
        { field: 'nameservers', state: 'changed', recorded: null, observed: ['ns1.example.net', 'ns2.example.net'] },
        { field: 'dnsHost', state: 'unknown', recorded: null, observed: null },
      ],
      suggestion: [
        { field: 'registrar', value: 'Webhuset' },
        { field: 'nameservers', value: ['ns1.example.net', 'ns2.example.net'] },
      ],
    }), NOW)
    expect(row.drift).toEqual([
      { field: 'registrar', recorded: 'GoDaddy', observed: 'Webhuset' },
      { field: 'nameservers', recorded: 'none', observed: 'ns1.example.net, ns2.example.net' },
    ])
    expect(row.notCompared).toEqual(['dnsHost'])
    expect(row.tone).toBe('info')
    expect(row.command).toBe('fleetctl registry set domain/example.org --field registrar=Webhuset --field nameservers=ns1.example.net,ns2.example.net')
  })

  it('takes the most serious of expiry and warnings, and falls back to the observed expiry', () => {
    const warn = domainRow(entry('a.example', { expires: '2027-03-01' }), view('a.example', {
      warnings: [{ code: 'registrar_mismatch', severity: 'warn', message: 'x' }],
    }), NOW)
    expect(warn.tone).toBe('warn')
    const soon = domainRow(entry('b.example', { expires: '2026-11-05' }), undefined, NOW)
    expect(soon).toMatchObject({ tone: 'warn', observed: false, pointsAt: [] })
    const base = view('c.example').observation!
    const fallback = domainRow(entry('c.example', {}), view('c.example', {
      observation: { ...base, rdap: { ...base.rdap, nameservers: [], expires: '2026-10-20' } },
    }), NOW)
    expect(fallback).toMatchObject({ expires: '2026-10-20', expirySource: 'observed', tone: 'err' })
  })

  it('computes expiry from the observed date when both exist, keeping the recorded one beside it', () => {
    const base = view('e.example').observation!
    const row = domainRow(entry('e.example', { expires: '2027-06-01' }), view('e.example', {
      observation: { ...base, rdap: { ...base.rdap, expires: '2026-10-20' } },
      diffs: [{ field: 'expires', state: 'changed', recorded: '2027-06-01', observed: '2026-10-20' }],
    }), NOW)
    expect(row).toMatchObject({ expires: '2026-10-20', expirySource: 'observed', recordedExpires: '2027-06-01', tone: 'err' })
    expect(row.drift.map(d => d.field)).toEqual(['expires'])
  })

  it('is in sync only when something matched and nothing was left uncompared', () => {
    const sync = (diffs: unknown[]) => domainRow(entry('f.example', {}), view('f.example', { diffs }), NOW).sync
    expect(sync([{ field: 'registrar', state: 'in_sync' }, { field: 'expires', state: 'in_sync' }])).toBe('in_sync')
    expect(sync([{ field: 'registrar', state: 'in_sync' }, { field: 'dnsHost', state: 'unknown' }])).toBe('partial')
    expect(sync([{ field: 'registrar', state: 'unknown' }])).toBe('none')
    expect(sync([])).toBe('none')
  })

  it('keeps DNS detail when the DNS half failed', () => {
    const base = view('d.example').observation!
    const row = domainRow(entry('d.example', {}), view('d.example', {
      observation: { ...base, dns: { status: 'error', detail: 'timed out', apex: NO_RECORDS, www: NO_RECORDS } },
    }), NOW)
    expect(row.pointsAt).toEqual([])
    expect(row.dnsDetail).toBe('timed out')
  })
})

describe('domainRows and summary', () => {
  it('sorts the most serious first, then soonest expiry, and summarises', () => {
    const rows = domainRows(
      [
        entry('fine.example', { expires: '2027-06-01' }),
        entry('soon.example', { expires: '2026-10-25' }),
        entry('gone.example', { expires: '2026-10-01' }),
        entry('drift.example', { expires: '2027-06-01' }),
      ],
      [view('drift.example', { diffs: [{ field: 'registrar', state: 'changed', recorded: 'A', observed: 'B' }] })],
      NOW,
    )
    expect(rows.map(r => r.key)).toEqual(['gone.example', 'soon.example', 'drift.example', 'fine.example'])
    expect(domainSummary(rows)).toEqual({ total: 4, attention: 2, expiring: 2, drifted: 1, unobserved: 3 })
  })
})

describe('suggestCommand', () => {
  it('quotes values the shell would split and is null with nothing to change', () => {
    expect(suggestCommand('example.org', [])).toBeNull()
    expect(suggestCommand('example.org', [{ field: 'registrar', value: 'Name Cheap' }])).toBe(`fleetctl registry set domain/example.org --field registrar='Name Cheap'`)
    expect(shellWord(`it's`)).toBe(`'it'\\''s'`)
    expect(shellWord('')).toBe(`''`)
  })
})

describe('generated observation value types', () => {
  it('types diff and suggestion values as a string or a list of strings', () => {
    expectTypeOf<FieldDiffDto['recorded']>().toEqualTypeOf<string | string[] | null | undefined>()
    expectTypeOf<FieldDiffDto['observed']>().toEqualTypeOf<string | string[] | null | undefined>()
    expectTypeOf<SuggestedFieldDto['value']>().toEqualTypeOf<string | string[]>()
  })

  it('renders them as one line of text', () => {
    expect(diffText(null)).toBe('none')
    expect(diffText([])).toBe('none')
    expect(diffText('Name Cheap')).toBe('Name Cheap')
    expect(diffText(['ns1.example.net', 'ns2.example.net'])).toBe('ns1.example.net, ns2.example.net')
    expect(suggestCommand('example.org', [{ field: 'nameservers', value: ['a.example', 'b.example'] }])).toBe('fleetctl registry set domain/example.org --field nameservers=a.example,b.example')
  })
})
