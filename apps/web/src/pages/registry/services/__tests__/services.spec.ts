import { describe, expect, it } from 'vitest'

import type { RegistryEntryDto } from '@frogbyte-io/fleet-api-client'

import { costTotals, formatMicros, parseMoney, relativeDays, serviceRow, serviceRows, upcomingRenewals } from '../services'

const NOW = Date.UTC(2026, 9, 16, 12)

function entry(key: string, fields: Record<string, unknown>): RegistryEntryDto {
  return { id: key, key, name: key, type: 'service', fields, links: [], relations: [], tags: [] }
}

describe('parseMoney', () => {
  it('parses amount and ISO code exactly, rejecting anything else', () => {
    expect(parseMoney('12.50 eur')).toEqual({ micros: 12_500_000, currency: 'EUR' })
    expect(parseMoney('0.1 USD')).toEqual({ micros: 100_000, currency: 'USD' })
    for (const bad of ['12', 'EUR 12', '12.5 EURO', null, 12])
      expect(parseMoney(bad)).toBeNull()
  })
})

describe('costTotals', () => {
  const rows = serviceRows([
    entry('a', { cost: '10.00 EUR', billingPeriod: 'monthly' }),
    entry('b', { cost: '0.10 EUR', billingPeriod: 'monthly' }),
    entry('c', { cost: '120.00 EUR', billingPeriod: 'yearly' }),
    entry('d', { cost: '5.00 USD', billingPeriod: 'monthly' }),
    entry('e', { cost: '300.00 EUR', billingPeriod: 'other' }),
    entry('f', { cost: 'free' }),
    entry('g', { billingPeriod: 'yearly' }),
  ], NOW)

  it('totals per currency without converting between currencies', () => {
    const { currencies } = costTotals(rows)
    expect(currencies.map(c => c.currency)).toEqual(['EUR', 'USD'])
    const eur = currencies[0]!
    expect(eur).toMatchObject({ monthlyCount: 2, yearlyCount: 1 })
    expect(formatMicros(eur.monthlyPlans, 'EUR')).toBe('€10.10')
    expect(formatMicros(eur.yearlyPlans, 'EUR')).toBe('€120.00')
    // monthly + yearly / 12, and yearly + monthly x 12
    expect(formatMicros(eur.perMonth, 'EUR')).toBe('€20.10')
    expect(formatMicros(eur.perYear, 'EUR')).toBe('€241.20')
    expect(formatMicros(currencies[1]!.perYear, 'USD')).toBe('$60.00')
  })

  it('excludes the other period and counts it, and counts what has no usable cost', () => {
    const totals = costTotals(rows)
    expect(totals.excludedOther).toBe(1)
    expect(totals.uncosted).toBe(2)
  })

  it('has no currencies for an empty list', () => {
    expect(costTotals([])).toEqual({ currencies: [], excludedOther: 0, uncosted: 0 })
  })
})

describe('upcomingRenewals', () => {
  it('lists overdue and in-window renewals soonest first, leaving out later and missing ones', () => {
    const rows = serviceRows([
      entry('later', { name: 'Later', renewal: '2027-02-01' }),
      entry('soon', { name: 'Soon', renewal: '2026-10-20' }),
      entry('mid', { name: 'Mid', renewal: '2026-11-20' }),
      entry('late', { name: 'Late', renewal: '2026-10-10' }),
      entry('stale', { name: 'Stale', renewal: '2026-08-01' }),
      entry('none', { name: 'None' }),
    ], NOW)
    expect(upcomingRenewals(rows).map(r => [r.row.key, r.days, r.state])).toEqual([
      ['late', -6, 'overdue'],
      ['soon', 4, 'soon'],
      ['mid', 35, 'later'],
    ])
  })
})

describe('serviceRow', () => {
  it('falls back to the key for the name and keeps an unparsable cost as text', () => {
    const row = serviceRow(entry('aptabase', { cost: 'ask sales', billingPeriod: 'monthly', hostingProvider: 'Hetzner' }), NOW)
    expect(row).toMatchObject({ name: 'aptabase', cost: null, costText: 'ask sales', hosting: 'Hetzner', period: 'monthly' })
  })

  it('words relative days', () => {
    expect([relativeDays(0), relativeDays(1), relativeDays(5), relativeDays(-1), relativeDays(-3)]).toEqual(['today', 'in 1 day', 'in 5 days', '1 day ago', '3 days ago'])
  })
})
