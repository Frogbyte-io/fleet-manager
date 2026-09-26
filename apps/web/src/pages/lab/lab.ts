// Pure Lab helpers: lease lifecycle, tones, TTL arithmetic, template lookup,
// and the `fleetctl` equivalents of every Lab mutation. No Vue imports, so the
// rules here are unit-tested directly.

import type { LabTemplateDto, LeaseDto } from '@frogbyte-io/fleet-api-client'

import { shellQuote } from '../machine/fleetctl'

import type { Tone } from '../fleet/inventory'

/** The happy-path lease lifecycle (fleet-core `LeaseState`), in order. */
export const LEASE_STEPS = [
  'requested',
  'queued',
  'reserving',
  'provisioning',
  'booting',
  'bootstrapping',
  'ready',
  'releasing',
  'released',
] as const

/** States a lease never leaves (fleet-core `LeaseState::is_terminal`). */
const TERMINAL = new Set(['released', 'failed', 'cleanup_failed'])

/** States in which the lease is still being brought up. */
const PROGRESSING = new Set(['requested', 'queued', 'reserving', 'provisioning', 'booting', 'bootstrapping'])

export function isTerminal(state: string): boolean {
  return TERMINAL.has(state)
}

/** Whether a lease still changes on its own, so the page keeps polling. */
export function isLive(state: string): boolean {
  return !TERMINAL.has(state)
}

export function isProgressing(state: string): boolean {
  return PROGRESSING.has(state)
}

/** Status tone per DESIGN.md §3 (lab lease row). */
export function leaseTone(state: string): Tone {
  if (state === 'ready')
    return 'ok'
  if (PROGRESSING.has(state))
    return 'info'
  if (state === 'releasing' || state === 'released')
    return 'muted'
  if (state === 'failed' || state === 'cleanup_failed')
    return 'err'
  return 'faint'
}

export type StepStatus = 'done' | 'current' | 'failed' | 'todo'

export interface Step {
  label: string
  status: StepStatus
}

/**
 * The stepper for one lease. `failed` and `cleanup_failed` are not points on
 * the happy path, so they mark the step after the last one the lease is known
 * to have passed: a failure before `ready` fails `ready`; `cleanup_failed`
 * fails `released`. The API does not record which step a failure happened
 * at, so the stepper claims no more than that.
 */
export function leaseSteps(lease: Pick<LeaseDto, 'state' | 'readyAt'>): Step[] {
  const index = LEASE_STEPS.indexOf(lease.state as (typeof LEASE_STEPS)[number])
  if (index >= 0) {
    return LEASE_STEPS.map((label, i) => ({
      label,
      status: i < index ? 'done' : i === index ? (lease.state === 'released' ? 'done' : 'current') : 'todo',
    }))
  }
  if (lease.state === 'cleanup_failed') {
    const releasedAt = LEASE_STEPS.indexOf('released')
    return LEASE_STEPS.map((label, i) => ({ label, status: i < releasedAt ? 'done' : 'failed' }))
  }
  if (lease.state === 'failed') {
    // A failure after ready (the API recorded a ready time) fails the release
    // path; one before ready fails ready. Steps the lease was not seen to pass
    // stay unclaimed.
    const reachedReady = lease.readyAt != null
    const failedAt = LEASE_STEPS.indexOf(reachedReady ? 'releasing' : 'ready')
    return LEASE_STEPS.map((label, i) => {
      if (i === failedAt)
        return { label, status: 'failed' as const }
      if (reachedReady && i < failedAt)
        return { label, status: 'done' as const }
      if (!reachedReady && i === 0)
        return { label, status: 'done' as const }
      return { label, status: 'todo' as const }
    })
  }
  // A state this client does not know: show the path with nothing claimed.
  return LEASE_STEPS.map(label => ({ label, status: 'todo' }))
}

export interface Ttl {
  /** Seconds left before expiry (0 once past). */
  remainingSeconds: number
  /** Fraction of the TTL already used, 0..1. */
  usedFraction: number
  /** Seconds left before the absolute lifetime cap (0 once past). */
  lifetimeRemainingSeconds: number
}

/**
 * TTL progress for a ready lease. Null until the lease has both a ready time
 * and an expiry: TTL only starts at ready (docs/architecture/lab.md).
 */
export function leaseTtl(lease: Pick<LeaseDto, 'readyAt' | 'expiresAt' | 'maxLifetimeAt'>, now: number): Ttl | null {
  const { readyAt, expiresAt } = lease
  if (readyAt == null || expiresAt == null)
    return null
  const span = Math.max(1, expiresAt - readyAt)
  const used = Math.min(1, Math.max(0, (now - readyAt) / span))
  return {
    remainingSeconds: Math.max(0, Math.floor((expiresAt - now) / 1000)),
    usedFraction: used,
    lifetimeRemainingSeconds: Math.max(0, Math.floor((lease.maxLifetimeAt - now) / 1000)),
  }
}

/** `01:02:03` for durations under a day, `2D 03:04` above. */
export function formatDuration(seconds: number): string {
  const s = Math.max(0, Math.floor(seconds))
  const days = Math.floor(s / 86_400)
  const hours = Math.floor((s % 86_400) / 3600)
  const minutes = Math.floor((s % 3600) / 60)
  const secs = s % 60
  const pad = (n: number) => String(n).padStart(2, '0')
  return days > 0
    ? `${days}D ${pad(hours)}:${pad(minutes)}`
    : `${pad(hours)}:${pad(minutes)}:${pad(secs)}`
}

/** `2H`, `30M`, `1D 4H`, `1M 1S` — for configured TTLs and deadlines. */
export function formatSpan(seconds: number): string {
  const s = Math.max(0, Math.floor(seconds))
  const days = Math.floor(s / 86_400)
  const hours = Math.floor((s % 86_400) / 3600)
  const minutes = Math.floor((s % 3600) / 60)
  const secs = s % 60
  const parts: string[] = []
  if (days)
    parts.push(`${days}D`)
  if (hours)
    parts.push(`${hours}H`)
  if (minutes)
    parts.push(`${minutes}M`)
  // Never drop configured seconds: 45 → 45S, 61 → 1M 1S.
  if (secs || parts.length === 0)
    parts.push(`${secs}S`)
  return parts.join(' ')
}

/**
 * Templates keyed by the published version they currently point at. A
 * template's draft records the version it was last published as
 * (`publishedFrom`), so older versions of a template do not resolve here —
 * callers show the raw version id for those instead of guessing.
 */
export function templatesByVersion(templates: LabTemplateDto[]): Map<string, LabTemplateDto> {
  const map = new Map<string, LabTemplateDto>()
  for (const template of templates) {
    if (template.publishedFrom)
      map.set(template.publishedFrom, template)
  }
  return map
}

/** Templates that can be leased: those with a published version. */
export function leasableTemplates(templates: LabTemplateDto[]): LabTemplateDto[] {
  return templates.filter(t => t.publishedFrom !== null)
}

export function templateSpec(template: Pick<LabTemplateDto, 'cores' | 'memoryMib' | 'diskGib' | 'ttlSeconds'>): string {
  const memory = template.memoryMib >= 1024 && template.memoryMib % 1024 === 0
    ? `${template.memoryMib / 1024}G`
    : `${template.memoryMib}M`
  return `${template.cores}C · ${memory} · ${template.diskGib}G · TTL ${formatSpan(template.ttlSeconds)}`
}

export function shortId(id: string): string {
  return id.length > 8 ? id.slice(0, 8) : id
}

// ---- fleetctl equivalents (crates/fleetctl `usage()`) -----------------------

/** `fleetctl --output json <words…>`; global flags precede the command. */
function fleetctl(words: string[]): string {
  return ['fleetctl', '--output', 'json', ...words].map(shellQuote).join(' ')
}

/**
 * `fleetctl lab lease <version> --purpose <text>`. The CLI has no project
 * flag, so a project-scoped request has no exact equivalent: null.
 */
export function leaseCommand(versionId: string, purpose: string, projectId: string | null): string | null {
  if (projectId)
    return null
  return fleetctl(['lab', 'lease', versionId, '--purpose', purpose])
}

export function provisionLeaseCommand(leaseId: string, accountId: string): string {
  return fleetctl(['lab', 'provision-lease', leaseId, '--account', accountId])
}

export function releaseCommand(leaseId: string, keep: boolean): string {
  return fleetctl(['lab', 'release', leaseId, ...(keep ? ['--keep'] : [])])
}

export function extendCommand(leaseId: string, seconds: number): string {
  return fleetctl(['lab', 'extend', leaseId, '--seconds', String(seconds)])
}

export function sweepCommand(): string {
  return fleetctl(['lab', 'sweep'])
}

export function publishCommand(templateId: string): string {
  return fleetctl(['lab', 'publish', templateId])
}
