// Pure model for the Domains view: a domain entry joined with its latest
// RDAP/DNS observation (FM-1020). Nothing here fetches or renders.

import type { DomainObservationViewDto, DomainWarningDto, RegistryEntryDto } from '@frogbyte-io/fleet-api-client'

import { daysUntil } from '../dates'
import { fieldValues } from '../registry'

export { daysUntil }

export type Tone = 'err' | 'warn' | 'info' | 'ok' | 'muted'

/** Days before expiry at which a domain is flagged (the API's default window). */
export const EXPIRY_WARN_DAYS = 30
/** Days before expiry at which the flag is an error (the API's urgent threshold). */
export const EXPIRY_URGENT_DAYS = 7

export interface ExpiryState {
  kind: 'expired' | 'soon' | 'ok' | 'unknown'
  days: number | null
  tone: Tone
  label: string
}

export function expiryState(date: string | null | undefined, now = Date.now()): ExpiryState {
  const days = daysUntil(date, now)
  if (days === null)
    return { kind: 'unknown', days, tone: 'muted', label: 'No expiry recorded' }
  const unit = (n: number) => (Math.abs(n) === 1 ? 'day' : 'days')
  if (days < 0)
    return { kind: 'expired', days, tone: 'err', label: `Expired ${-days} ${unit(days)} ago` }
  if (days <= EXPIRY_WARN_DAYS)
    return { kind: 'soon', days, tone: days <= EXPIRY_URGENT_DAYS ? 'err' : 'warn', label: days === 0 ? 'Expires today' : `Expires in ${days} ${unit(days)}` }
  return { kind: 'ok', days, tone: 'ok', label: `In ${days} days` }
}

export interface DriftBadge {
  field: string
  recorded: string
  observed: string
}

/** A diff value (a string, or a list of strings) as one line of text. */
export function diffText(value: unknown): string {
  if (value === null || value === undefined || value === '')
    return 'none'
  if (Array.isArray(value))
    return value.length ? value.map(String).join(', ') : 'none'
  return typeof value === 'object' ? JSON.stringify(value) : String(value)
}

export interface PointsAt {
  /** `apex` or `www`. */
  name: string
  /** `A 192.0.2.1`, `CNAME app.example.net`. */
  records: string[]
}

export interface DomainRow {
  key: string
  entry: RegistryEntryDto
  registrar: string | null
  dnsHost: string | null
  autoRenew: boolean | null
  /** The expiry the state is computed from: the observed (RDAP) date, else the recorded one (as the API does). */
  expires: string | null
  expirySource: 'recorded' | 'observed' | null
  /** The expiry Fleet Git records. */
  recordedExpires: string | null
  /** Every compared field matches, some were not compared, or none were. */
  sync: 'in_sync' | 'partial' | 'none'
  expiry: ExpiryState
  /** Whether a lookup has produced an observation for this domain. */
  observed: boolean
  observedAt: number | null
  dnsDetail: string | null
  pointsAt: PointsAt[]
  nameservers: string[]
  drift: DriftBadge[]
  /** Fields the lookups could not compare. */
  notCompared: string[]
  inSync: number
  warnings: DomainWarningDto[]
  /** The most serious state of the row, for sorting and the status badge. */
  tone: Tone
  /** The `fleetctl registry set` command for the suggested patch, or null. */
  command: string | null
}

function text(value: unknown): string | null {
  return typeof value === 'string' && value.trim() ? value : null
}

function dnsRecords(view: DomainObservationViewDto | undefined): PointsAt[] {
  const dns = view?.observation?.dns
  if (!dns || dns.status !== 'ok')
    return []
  const lines = (records: typeof dns.apex) => [
    ...records.cname.map(v => `CNAME ${v}`),
    ...records.a.map(v => `A ${v}`),
    ...records.aaaa.map(v => `AAAA ${v}`),
  ]
  return [{ name: 'apex', records: lines(dns.apex) }, { name: 'www', records: lines(dns.www) }]
    .filter(group => group.records.length > 0)
}

/** Single-quotes a value for a POSIX shell when it needs it (mirrors `fleetctl registry suggest`). */
export function shellWord(value: string): string {
  return value !== '' && /^[A-Za-z0-9\-._,/:@]+$/.test(value) ? value : `'${value.replace(/'/g, `'\\''`)}'`
}

/** The `fleetctl registry set` command that applies a suggestion; null when there is nothing to change. */
export function suggestCommand(key: string, suggestion: { field: string, value: unknown }[]): string | null {
  if (suggestion.length === 0)
    return null
  const fields = suggestion.map(({ field, value }) => {
    const rendered = Array.isArray(value) ? value.map(String).join(',') : typeof value === 'string' ? value : JSON.stringify(value)
    return `--field ${field}=${shellWord(rendered)}`
  })
  return `fleetctl registry set domain/${key} ${fields.join(' ')}`
}

const TONE_RANK: Record<Tone, number> = { err: 0, warn: 1, info: 2, muted: 3, ok: 4 }

function syncOf(diffs: { state: string }[]): 'in_sync' | 'partial' | 'none' {
  if (!diffs.some(d => d.state === 'in_sync'))
    return 'none'
  return diffs.every(d => d.state === 'in_sync') ? 'in_sync' : 'partial'
}

function worse(a: Tone, b: Tone): Tone {
  return TONE_RANK[a] <= TONE_RANK[b] ? a : b
}

export function domainRow(entry: RegistryEntryDto, view: DomainObservationViewDto | undefined, now = Date.now()): DomainRow {
  const fields = fieldValues(entry.fields)
  const recorded = text(fields.expires)
  const observedExpiry = text(view?.observation?.rdap.expires)
  const expires = observedExpiry ?? recorded
  const expiry = expiryState(expires, now)
  const diffs = view?.diffs ?? []
  const warnings = view?.warnings ?? []
  const drift = diffs
    .filter(diff => diff.state === 'changed')
    .map(diff => ({ field: diff.field, recorded: diffText(diff.recorded), observed: diffText(diff.observed) }))
  let tone: Tone = worse('ok', expiry.tone === 'muted' ? 'ok' : expiry.tone)
  for (const warning of warnings)
    tone = worse(tone, warning.severity)
  // Drift is at least informational even when no warning was raised for it.
  if (drift.length > 0)
    tone = worse(tone, 'info')
  return {
    key: entry.key,
    entry,
    registrar: text(fields.registrar),
    dnsHost: text(fields.dnsHost),
    autoRenew: typeof fields.autoRenew === 'boolean' ? fields.autoRenew : null,
    expires,
    expirySource: observedExpiry ? 'observed' : recorded ? 'recorded' : null,
    recordedExpires: recorded,
    sync: syncOf(diffs),
    expiry,
    observed: !!view?.observation,
    observedAt: view?.observation?.observedAt ?? null,
    dnsDetail: view?.observation?.dns.detail ?? null,
    pointsAt: dnsRecords(view),
    nameservers: view?.observation?.rdap.nameservers ?? [],
    drift,
    notCompared: diffs.filter(diff => diff.state === 'unknown').map(diff => diff.field),
    inSync: diffs.filter(diff => diff.state === 'in_sync').length,
    warnings,
    tone,
    command: suggestCommand(entry.key, view?.suggestion ?? []),
  }
}

/** Domains joined with their observations: most serious first, then soonest expiry. */
export function domainRows(entries: RegistryEntryDto[], views: DomainObservationViewDto[], now = Date.now()): DomainRow[] {
  const byKey = new Map(views.map(view => [view.key, view] as const))
  return entries
    .map(entry => domainRow(entry, byKey.get(entry.key), now))
    .sort((a, b) =>
      TONE_RANK[a.tone] - TONE_RANK[b.tone]
      || (a.expiry.days ?? Number.MAX_SAFE_INTEGER) - (b.expiry.days ?? Number.MAX_SAFE_INTEGER)
      || a.key.localeCompare(b.key))
}

export interface DomainSummary {
  total: number
  attention: number
  expiring: number
  drifted: number
  unobserved: number
}

export function domainSummary(rows: DomainRow[]): DomainSummary {
  return {
    total: rows.length,
    attention: rows.filter(r => r.tone === 'err' || r.tone === 'warn').length,
    expiring: rows.filter(r => r.expiry.kind === 'soon' || r.expiry.kind === 'expired').length,
    drifted: rows.filter(r => r.drift.length > 0).length,
    unobserved: rows.filter(r => !r.observed).length,
  }
}
