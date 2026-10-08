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

/** `fleetctl lab lease <version> --purpose <text> [--project <id>]`: request only. */
export function leaseCommand(versionId: string, purpose: string, projectId: string | null): string {
  return fleetctl(['lab', 'lease', versionId, '--purpose', purpose, ...(projectId ? ['--project', projectId] : [])])
}

/**
 * `fleetctl lab create <version> --purpose <text> [--project <id>] --account <id>`:
 * request and provision through an explicit account. Only with one: without
 * `--account`, `lab create` picks the single trusted account itself instead
 * of the controller's placement, so automatic placement is `lab lease` then
 * `lab provision-lease` (see `provisionLeaseCommand`).
 */
export function createCommand(versionId: string, purpose: string, projectId: string | null, accountId: string): string {
  return fleetctl([
    'lab',
    'create',
    versionId,
    '--purpose',
    purpose,
    ...(projectId ? ['--project', projectId] : []),
    '--account',
    accountId,
  ])
}

/** `fleetctl lab provision-lease <lease> [--account <id>]`; without one, placement picks. */
export function provisionLeaseCommand(leaseId: string, accountId: string | null): string {
  return fleetctl(['lab', 'provision-lease', leaseId, ...(accountId ? ['--account', accountId] : [])])
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

export function cleanupRetryCommand(leaseId: string): string {
  return fleetctl(['lab', 'cleanup-retry', leaseId])
}

export function statusCommand(leaseId: string): string {
  return fleetctl(['lab', 'status', leaseId])
}

export function leasesCommand(projectId: string | null): string {
  return fleetctl(['lab', 'leases', ...(projectId ? ['--project', projectId] : [])])
}

/**
 * `fleetctl lab exec <lease> --timeout <s> -- sh -c <script>`. The CLI joins
 * the words after `--` into the script, so the console's script runs through
 * `sh -c` there: the same command, wrapped once more.
 */
export function execCommand(leaseId: string, script: string, timeoutSeconds: number): string {
  return fleetctl(['lab', 'exec', leaseId, '--timeout', String(timeoutSeconds), '--', 'sh', '-c', script])
}

export function collectCommand(leaseId: string, paths: string[]): string {
  return fleetctl(['lab', 'collect', leaseId, ...paths])
}

export function artifactsCommand(filter: { leaseId?: string | null, projectId?: string | null }): string {
  return fleetctl([
    'lab',
    'artifacts',
    ...(filter.leaseId ? ['--lease', filter.leaseId] : []),
    ...(filter.projectId ? ['--project', filter.projectId] : []),
  ])
}

export function artifactGetCommand(artifactId: string, out: string): string {
  return fleetctl(['lab', 'artifact-get', artifactId, '--out', out])
}

// ---- operation results ------------------------------------------------------

export interface OperationFailure {
  /** The stable reason id, when the error names one. */
  reason: string | null
  /** The controller's explanation, verbatim. */
  detail: string | null
  /** The failed saga step, when a provision names one. */
  step: string | null
}

/**
 * The `{reason, detail, step}` of an operation's public error (placement
 * refusals, provisioning and cleanup failures), read as-is. Null when the
 * error is absent or not that shape, so the caller shows the raw JSON.
 */
export function operationFailure(errorJson: string | null | undefined): OperationFailure | null {
  if (!errorJson)
    return null
  try {
    const parsed = JSON.parse(errorJson) as Record<string, unknown>
    const text = (key: string) => (typeof parsed[key] === 'string' ? parsed[key] as string : null)
    const failure = { reason: text('reason'), detail: text('detail'), step: text('step') }
    return failure.reason || failure.detail ? failure : null
  }
  catch {
    return null
  }
}

export interface ExecOutput {
  /** Null when the command never reported one (killed, never ran). */
  exitCode: number | null
  stdout: string
  stderr: string
  truncatedStdout: boolean
  truncatedStderr: boolean
  /** Why it did not finish normally (`deadline_killed`, `connection_failed`, …). */
  reason: string | null
  detail: string | null
}

/**
 * A `lab.exec` operation's bounded output. A zero exit succeeds with the
 * output in `resultJson`; a nonzero exit fails with the same object in
 * `errorJson`; a deadline kill fails with `partialOutput` beside its reason;
 * a connection failure carries only a reason. Null while the operation has
 * neither.
 */
export function execOutput(operation: { resultJson?: string | null, errorJson?: string | null }): ExecOutput | null {
  const parse = (raw: string | null | undefined): Record<string, unknown> | null => {
    if (!raw)
      return null
    try {
      const value = JSON.parse(raw) as unknown
      return value && typeof value === 'object' ? value as Record<string, unknown> : null
    }
    catch {
      return null
    }
  }
  const outer = parse(operation.resultJson) ?? parse(operation.errorJson)
  if (!outer)
    return null
  const partial = outer.partialOutput && typeof outer.partialOutput === 'object'
    ? outer.partialOutput as Record<string, unknown>
    : null
  const streams = 'stdout' in outer || 'stderr' in outer ? outer : partial ?? {}
  const str = (from: Record<string, unknown>, key: string) => (typeof from[key] === 'string' ? from[key] as string : '')
  const flag = (key: string) => streams[key] === true || outer[key] === true
  return {
    exitCode: typeof outer.exitCode === 'number' ? outer.exitCode : null,
    stdout: str(streams, 'stdout'),
    stderr: str(streams, 'stderr'),
    truncatedStdout: flag('truncatedStdout'),
    truncatedStderr: flag('truncatedStderr'),
    reason: typeof outer.reason === 'string' ? outer.reason : null,
    detail: typeof outer.detail === 'string' ? outer.detail : null,
  }
}

/** Collect paths from a textarea: one per line, trimmed, blanks and repeats dropped. */
export function parsePaths(text: string): string[] {
  return [...new Set(text.split('\n').map(line => line.trim()).filter(Boolean))]
}

/** Bytes in binary units with explicit rounding: `512 B`, `1.5 KiB`, `12.0 MiB`. */
export function formatBytes(bytes: number): string {
  if (bytes < 1024)
    return `${bytes} B`
  const units = ['KiB', 'MiB', 'GiB', 'TiB']
  let value = bytes / 1024
  let unit = 0
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024
    unit++
  }
  return `${value.toFixed(1)} ${units[unit]}`
}

/** `2026-10-08 14:03:12 UTC`: absolute timestamps in the detail timeline. */
export function formatTimestamp(ms: number): string {
  return `${new Date(ms).toISOString().slice(0, 19).replace('T', ' ')} UTC`
}
