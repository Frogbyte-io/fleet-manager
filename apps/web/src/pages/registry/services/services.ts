// Pure model for the Services view: third-party service entries (the built-in
// `service` type), their costs per currency, and upcoming renewals. No
// currency conversion: every currency is totalled on its own.

import type { RegistryEntryDto } from '@frogbyte-io/fleet-api-client'

import { daysUntil } from '../dates'
import { fieldValues } from '../registry'

export type BillingPeriod = 'monthly' | 'yearly' | 'other'

export interface Money {
  /** Micro-units (amount x 1,000,000), so sums stay exact. */
  micros: number
  currency: string
}

const MICROS = 1_000_000

/** `12.50 EUR` as exact micro-units; null when it does not parse. */
export function parseMoney(value: unknown): Money | null {
  if (typeof value !== 'string')
    return null
  const match = /^(-?\d+(?:\.\d+)?)\s+([A-Za-z]{3})$/.exec(value.trim())
  if (!match)
    return null
  return { micros: Math.round(Number(match[1]) * MICROS), currency: match[2]!.toUpperCase() }
}

/** Micro-units formatted for a currency, falling back to the plain number and code. */
export function formatMicros(micros: number, currency: string): string {
  const amount = micros / MICROS
  try {
    return new Intl.NumberFormat('en', { style: 'currency', currency }).format(amount)
  }
  catch {
    return `${amount.toFixed(2)} ${currency}`
  }
}

function period(value: unknown): BillingPeriod | null {
  return value === 'monthly' || value === 'yearly' || value === 'other' ? value : null
}

function text(value: unknown): string | null {
  return typeof value === 'string' && value.trim() ? value : null
}

export interface ServiceRow {
  key: string
  entry: RegistryEntryDto
  name: string
  vendor: string | null
  plan: string | null
  cost: Money | null
  /** The cost as written, when it does not parse as money. */
  costText: string | null
  period: BillingPeriod | null
  renewal: string | null
  renewalDays: number | null
  hosting: string | null
  region: string | null
  url: string | null
}

export function serviceRow(entry: RegistryEntryDto, now = Date.now()): ServiceRow {
  const fields = fieldValues(entry.fields)
  const renewal = text(fields.renewal)
  const cost = parseMoney(fields.cost)
  return {
    key: entry.key,
    entry,
    name: text(fields.name) ?? entry.key,
    vendor: text(fields.vendor),
    plan: text(fields.plan),
    cost,
    costText: cost ? null : text(fields.cost),
    period: period(fields.billingPeriod),
    renewal,
    renewalDays: daysUntil(renewal, now),
    hosting: text(fields.hostingProvider),
    region: text(fields.region),
    url: text(fields.url),
  }
}

export function serviceRows(entries: RegistryEntryDto[], now = Date.now()): ServiceRow[] {
  return entries.map(entry => serviceRow(entry, now)).sort((a, b) => a.name.localeCompare(b.name) || a.key.localeCompare(b.key))
}

export interface CurrencyTotal {
  currency: string
  /** Sum of services billed monthly. */
  monthlyPlans: number
  /** Sum of services billed yearly. */
  yearlyPlans: number
  /** Monthly plans plus yearly plans / 12: a converted figure. */
  perMonth: number
  /** Yearly plans plus monthly plans x 12: a converted figure. */
  perYear: number
  monthlyCount: number
  yearlyCount: number
}

export interface CostTotals {
  currencies: CurrencyTotal[]
  /** Services billed on an `other` period: in no total. */
  excludedOther: number
  /** Services with no usable cost or billing period: in no total. */
  uncosted: number
}

export function costTotals(rows: Pick<ServiceRow, 'cost' | 'period'>[]): CostTotals {
  const byCurrency = new Map<string, CurrencyTotal>()
  let excludedOther = 0
  let uncosted = 0
  for (const row of rows) {
    if (row.period === 'other') {
      excludedOther++
      continue
    }
    if (!row.cost || !row.period) {
      uncosted++
      continue
    }
    const total = byCurrency.get(row.cost.currency)
      ?? { currency: row.cost.currency, monthlyPlans: 0, yearlyPlans: 0, perMonth: 0, perYear: 0, monthlyCount: 0, yearlyCount: 0 }
    if (row.period === 'monthly') {
      total.monthlyPlans += row.cost.micros
      total.monthlyCount++
    }
    else {
      total.yearlyPlans += row.cost.micros
      total.yearlyCount++
    }
    byCurrency.set(row.cost.currency, total)
  }
  const currencies = [...byCurrency.values()]
    .map(t => ({
      ...t,
      perMonth: Math.round(t.monthlyPlans + t.yearlyPlans / 12),
      perYear: t.yearlyPlans + t.monthlyPlans * 12,
    }))
    .sort((a, b) => a.currency.localeCompare(b.currency))
  return { currencies, excludedOther, uncosted }
}

/** How far ahead renewals count as upcoming. */
export const RENEWAL_WINDOW_DAYS = 60
/** How long a passed renewal date stays listed as stale. */
export const OVERDUE_WINDOW_DAYS = 30

export interface Renewal {
  row: ServiceRow
  days: number
  /** `overdue` when the recorded date has passed (the entry may just be stale). */
  state: 'overdue' | 'soon' | 'later'
}

/** Renewals within the window, and ones passed by at most 30 days, soonest first. */
export function upcomingRenewals(rows: ServiceRow[], windowDays = RENEWAL_WINDOW_DAYS): Renewal[] {
  return rows
    .flatMap((row) => {
      if (row.renewalDays === null || row.renewalDays > windowDays || row.renewalDays < -OVERDUE_WINDOW_DAYS)
        return []
      const state: Renewal['state'] = row.renewalDays < 0 ? 'overdue' : row.renewalDays <= 14 ? 'soon' : 'later'
      return [{ row, days: row.renewalDays, state }]
    })
    .sort((a, b) => a.days - b.days || a.row.name.localeCompare(b.row.name))
}

/** `in 12 days`, `today`, `3 days ago`. */
export function relativeDays(days: number): string {
  if (days === 0)
    return 'today'
  const unit = Math.abs(days) === 1 ? 'day' : 'days'
  return days > 0 ? `in ${days} ${unit}` : `${-days} ${unit} ago`
}
