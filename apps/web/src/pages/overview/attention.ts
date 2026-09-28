// The Overview's needs-attention queue: one pure builder per source in
// FM-916's acceptance list, each row linking to the page that resolves it.
// No Vue imports, so every source is unit-tested directly.

import type {
  LabTemplateDto,
  LeaseDto,
  MachineDto,
  OnboardingDraftDto,
  OperationDto,
  RecipeVersionDto,
} from '@frogbyte-io/fleet-api-client'
import type { RouteLocationRaw } from 'vue-router'

import { pinState } from '../images/images'
import type { AccountView } from '../proxmox/proxmox'

export type Severity = 'err' | 'warn' | 'info'

export type AttentionSource =
  | 'machine'
  | 'lease-cleanup'
  | 'operation-blocked'
  | 'proxmox-trust'
  | 'onboarding'
  | 'lease-expiring'
  | 'template-pin'

export interface AttentionRow {
  key: string
  source: AttentionSource
  severity: Severity
  title: string
  detail: string
  /** The page that resolves it. */
  to: RouteLocationRaw
  /** For ordering: newest or most urgent first within a severity. */
  at: number
}

/** Leases expiring within this window are flagged. */
export const EXPIRING_WINDOW_MS = 30 * 60 * 1000

export function machineRows(machines: Pick<MachineDto, 'id' | 'name' | 'machineStatus' | 'lastSeenAt'>[]): AttentionRow[] {
  return machines
    .filter(m => m.machineStatus === 'offline' || m.machineStatus === 'stale')
    .map(m => ({
      key: `machine:${m.id}`,
      source: 'machine',
      severity: m.machineStatus === 'offline' ? 'err' : 'warn',
      title: `${m.name} is ${m.machineStatus}`,
      detail: m.lastSeenAt ? 'The node stopped reporting.' : 'The node has never connected.',
      to: `/fleet/machines/${m.id}`,
      at: m.lastSeenAt ?? 0,
    }))
}

export function leaseRows(leases: Pick<LeaseDto, 'id' | 'state' | 'purpose' | 'expiresAt' | 'createdAt'>[], now: number): AttentionRow[] {
  const rows: AttentionRow[] = []
  for (const lease of leases) {
    if (lease.state === 'cleanup_failed') {
      rows.push({
        key: `lease-cleanup:${lease.id}`,
        source: 'lease-cleanup',
        severity: 'err',
        title: `Lab lease ${lease.id.slice(0, 12)} failed cleanup`,
        detail: `It still owns resources (${lease.purpose}). Sweep retries the cleanup.`,
        to: '/lab',
        at: lease.createdAt,
      })
    }
    else if (lease.state === 'ready' && lease.expiresAt !== null && lease.expiresAt !== undefined && lease.expiresAt - now <= EXPIRING_WINDOW_MS) {
      const minutes = Math.max(0, Math.round((lease.expiresAt - now) / 60000))
      rows.push({
        key: `lease-expiring:${lease.id}`,
        source: 'lease-expiring',
        severity: 'warn',
        title: `Lab lease ${lease.id.slice(0, 12)} expires ${minutes === 0 ? 'now' : `in ${minutes} min`}`,
        detail: `${lease.purpose}. Extend it or let it be released.`,
        to: '/lab',
        at: lease.expiresAt,
      })
    }
  }
  return rows
}

export function blockedDetail(operation: Pick<OperationDto, 'errorJson'>): string {
  try {
    const parsed = JSON.parse(operation.errorJson ?? '') as { detail?: unknown }
    return typeof parsed.detail === 'string' ? parsed.detail : 'A step needs a person to approve it.'
  }
  catch {
    return 'A step needs a person to approve it.'
  }
}

export function operationRows(operations: Pick<OperationDto, 'id' | 'kind' | 'state' | 'errorJson' | 'updatedAt'>[]): AttentionRow[] {
  return operations
    .filter(o => o.state === 'blocked_manual_approval')
    .map(o => ({
      key: `operation:${o.id}`,
      source: 'operation-blocked',
      severity: 'warn',
      title: `${o.kind} is blocked on an approval`,
      detail: blockedDetail(o),
      to: { path: '/operations', query: { op: o.id } },
      at: o.updatedAt,
    }))
}

export function proxmoxRows(views: Pick<AccountView, 'account' | 'state'>[]): AttentionRow[] {
  return views
    .filter(v => v.state === 'changed' || v.state === 'unconfirmed')
    .map(v => ({
      key: `proxmox:${v.account.id}`,
      source: 'proxmox-trust',
      severity: v.state === 'changed' ? 'err' : 'warn',
      title: v.state === 'changed'
        ? `${v.account.name}: TLS fingerprint changed`
        : `${v.account.name}: fingerprint not confirmed`,
      detail: v.state === 'changed'
        ? 'Fleet refuses every call to this account until the new fingerprint is confirmed.'
        : 'Fleet cannot call this account until its certificate is pinned.',
      to: '/proxmox',
      at: v.account.createdAt,
    }))
}

export function onboardingRows(drafts: Pick<OnboardingDraftDto, 'id' | 'name' | 'stage' | 'endpoint' | 'updatedAt'>[]): AttentionRow[] {
  // Adding or cancelling a draft deletes it, so every listed draft is pending.
  return drafts.map(d => ({
    key: `onboarding:${d.id}`,
    source: 'onboarding',
    severity: 'info',
    title: `Onboarding ${d.name || `${d.endpoint.user}@${d.endpoint.host}`} is unfinished`,
    detail: { untested: 'Connection not tested yet.', review: 'A host key awaits confirmation.', ready: 'Ready to discover and add.' }[d.stage] ?? `Stage: ${d.stage}.`,
    to: '/fleet/add',
    at: d.updatedAt,
  }))
}

export function templatePinRows(
  templates: Pick<LabTemplateDto, 'id' | 'name' | 'imageVersionId'>[],
  versions: Pick<RecipeVersionDto, 'id' | 'recipeId' | 'promotedAt'>[],
): AttentionRow[] {
  const rows: AttentionRow[] = []
  for (const template of templates) {
    const pin = pinState(template, versions)
    if (!pin.stale)
      continue
    rows.push({
      key: `template-pin:${template.id}`,
      source: 'template-pin',
      severity: 'warn',
      title: `Lab template ${template.name} has a stale image pin`,
      detail: { unknown: 'It pins an image version Fleet does not know.', superseded: 'It pins a version its recipe no longer promotes.', unpromoted: 'It pins a version that was never promoted.' }[pin.reason],
      to: { path: '/images', query: { select: `template:${template.id}` } },
      at: 0,
    })
  }
  return rows
}

const SEVERITY_ORDER: Record<Severity, number> = { err: 0, warn: 1, info: 2 }

/** Errors first, then warnings, then information; newest first within each. */
export function sortAttention(rows: AttentionRow[]): AttentionRow[] {
  return [...rows].sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] || b.at - a.at || a.key.localeCompare(b.key))
}

// ---------------------------------------------------------------------------
// KPIs and activity

export interface Kpis {
  connected: number
  agentless: number
  unreachable: number
  leasesReady: number
  leasesInProgress: number
  running: number
}

const LEASE_IN_PROGRESS = new Set(['requested', 'queued', 'reserving', 'provisioning', 'booting', 'bootstrapping', 'releasing'])
const OPERATION_LIVE = new Set(['pending', 'running', 'cancelling'])

export function kpis(
  machines: Pick<MachineDto, 'machineStatus'>[],
  leases: Pick<LeaseDto, 'state'>[],
  operations: Pick<OperationDto, 'state'>[],
): Kpis {
  const count = <T>(list: T[], test: (item: T) => boolean) => list.filter(test).length
  return {
    connected: count(machines, m => m.machineStatus === 'connected'),
    agentless: count(machines, m => m.machineStatus === 'agentless'),
    unreachable: count(machines, m => m.machineStatus === 'offline' || m.machineStatus === 'stale'),
    leasesReady: count(leases, l => l.state === 'ready'),
    leasesInProgress: count(leases, l => LEASE_IN_PROGRESS.has(l.state)),
    running: count(operations, o => OPERATION_LIVE.has(o.state)),
  }
}

export interface ActivityItem {
  key: string
  at: number
  kind: 'operation' | 'audit'
  title: string
  detail: string
  tone: 'ok' | 'info' | 'warn' | 'err' | 'muted' | 'faint'
  to: RouteLocationRaw | null
}

export function operationTone(state: string): ActivityItem['tone'] {
  switch (state) {
    case 'succeeded': return 'ok'
    case 'failed':
    case 'timed_out': return 'err'
    case 'blocked_manual_approval': return 'warn'
    case 'running':
    case 'pending':
    case 'cancelling': return 'info'
    case 'cancelled': return 'muted'
    default: return 'faint'
  }
}

/** Operations and audit events, newest first. */
export function activity(
  operations: Pick<OperationDto, 'id' | 'kind' | 'state' | 'updatedAt' | 'progressMessage'>[],
  audit: { id: string, occurredAt: number, action: string, actor: string, resource?: string | null, outcome?: string | null, allowed: boolean }[],
  limit = 25,
): ActivityItem[] {
  const items: ActivityItem[] = [
    ...operations.map(o => ({
      key: `op:${o.id}`,
      at: o.updatedAt,
      kind: 'operation' as const,
      title: `${o.kind} · ${o.state}`,
      detail: o.progressMessage ?? '',
      tone: operationTone(o.state),
      to: { path: '/operations', query: { op: o.id } },
    })),
    ...audit.map(a => ({
      key: `audit:${a.id}`,
      at: a.occurredAt,
      kind: 'audit' as const,
      title: `${a.action}${a.resource ? ` · ${a.resource}` : ''}`,
      detail: `${a.actor} · ${a.allowed ? a.outcome ?? 'recorded' : 'denied'}`,
      tone: !a.allowed || a.outcome === 'failed' ? 'err' as const : 'faint' as const,
      to: null,
    })),
  ]
  return items.sort((a, b) => b.at - a.at).slice(0, limit)
}
