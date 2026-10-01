// Pure Proxmox page helpers: account trust state, per-node capacity, the
// resource joins behind each tab, and the web-UI handoff. No Vue imports, so
// the rules here are unit-tested directly.

import type {
  AssociatedGuestDto,
  ProxmoxAccountDto,
  ProxmoxDiscoveryDto,
  ProxmoxNodeCapacityDto,
  ProxmoxPrivilegeStatusDto,
  ProxmoxPrivilegeTierDto,
  ProxmoxPrivilegesDto,
  ProxmoxResourceDto,
  ProxmoxTaskStatusDto,
} from '@frogbyte-io/fleet-api-client'

import type { Tone } from '../fleet/inventory'
import { ApiRequestError } from '../machine/api'
import { shellQuote } from '../machine/fleetctl'

/**
 * What Fleet can do with an account right now.
 * - `unconfirmed`: nothing is pinned; every call is refused until confirmed.
 * - `pinned`: a fingerprint is pinned and discovery verified against it.
 * - `changed`: the host now presents a different certificate; every call is
 *   refused until the new fingerprint is re-confirmed.
 * - `checking`: pinned, discovery still loading.
 * - `unreachable`: pinned, but discovery failed for another reason.
 */
export type TrustState = 'unconfirmed' | 'pinned' | 'changed' | 'checking' | 'unreachable'

export function isFingerprintMismatch(error: unknown): boolean {
  return error instanceof ApiRequestError && error.code === 'proxmox_fingerprint_mismatch'
}

export function trustState(account: ProxmoxAccountDto, discovery: { loading: boolean, error: unknown }): TrustState {
  if (account.fingerprintState !== 'confirmed')
    return 'unconfirmed'
  if (isFingerprintMismatch(discovery.error))
    return 'changed'
  if (discovery.error)
    return 'unreachable'
  return discovery.loading ? 'checking' : 'pinned'
}

/** Guest actions and discovery-backed views need a verified pin. */
export function actionsAllowed(state: TrustState): boolean {
  return state === 'pinned'
}

export function trustTone(state: TrustState): Tone {
  switch (state) {
    case 'pinned': return 'ok'
    case 'changed': return 'err'
    case 'unconfirmed': return 'warn'
    case 'unreachable': return 'warn'
    default: return 'faint'
  }
}

export function trustLabel(state: TrustState): string {
  return state === 'changed' ? 'fingerprint changed' : state
}

/**
 * The fingerprints a mismatch error names ("… fingerprint X does not match
 * the pinned Y"), for when the account or an observation does not supply
 * them. Only a fallback: the page prefers the account's pin and a fresh
 * observation.
 */
export function mismatchFingerprints(message: string): { observed: string, pinned: string } | null {
  const match = /fingerprint (\S+) does not match the pinned (\S+)/.exec(message)
  return match ? { observed: match[1]!, pinned: match[2]!.replace(/[.,;]$/, '') } : null
}

/** Fingerprints compare without separators or case. */
export function sameFingerprint(a: string | null | undefined, b: string | null | undefined): boolean {
  const norm = (value: string) => value.replace(/[^0-9a-f]/gi, '').toLowerCase()
  return !!a && !!b && norm(a) === norm(b)
}

// ---------------------------------------------------------------------------
// Capacity

export function ratio(used: number | null | undefined, total: number | null | undefined): number | null {
  if (used === null || used === undefined || !total || total <= 0)
    return null
  return Math.min(1, Math.max(0, used / total))
}

export function percent(value: number | null): string {
  return value === null ? '—' : `${Math.round(value * 100)}%`
}

/** Usage tone: fine below 75%, warning below 90%, then error. */
export function usageTone(value: number | null): Tone {
  if (value === null)
    return 'faint'
  return value >= 0.9 ? 'err' : value >= 0.75 ? 'warn' : 'ok'
}

// ---------------------------------------------------------------------------
// Joins

export interface AccountView {
  account: ProxmoxAccountDto
  state: TrustState
  discovery: ProxmoxDiscoveryDto | null
  guests: AssociatedGuestDto[]
  guestsLoading?: boolean
  guestsError?: unknown
  /** The guest list hit the paging safety cap. */
  guestsTruncated?: boolean
  /** The token's privilege report (FM-604), once read. */
  privileges?: ProxmoxPrivilegesDto | null
  privilegesLoading?: boolean
  privilegesError?: unknown
}

export interface NodeRow {
  accountId: string
  accountName: string
  node: string
  status: string | null
  pveVersion: string
  capacity: ProxmoxNodeCapacityDto | null
  guestCount: number
  templateCount: number
}

export function nodeRows(views: AccountView[]): NodeRow[] {
  const rows: NodeRow[] = []
  for (const view of views) {
    const discovery = view.discovery
    if (!discovery)
      continue
    const capacities = new Map(discovery.nodeCapacities.map(c => [c.node, c]))
    for (const resource of discovery.resources.filter(r => r.kind === 'node')) {
      const node = resource.node ?? resource.name ?? resource.id.replace(/^node\//, '')
      rows.push({
        accountId: view.account.id,
        accountName: view.account.name,
        node,
        status: resource.status ?? null,
        pveVersion: resource.pveVersion,
        capacity: capacities.get(node) ?? null,
        guestCount: discovery.resources.filter(r => (r.kind === 'qemu' || r.kind === 'lxc') && r.node === node).length,
        templateCount: discovery.resources.filter(r => r.kind === 'qemu-template' && r.node === node).length,
      })
    }
  }
  return rows.sort((a, b) => a.accountName.localeCompare(b.accountName) || a.node.localeCompare(b.node))
}

export interface StorageRow {
  accountId: string
  accountName: string
  node: string | null
  storage: string
  status: string | null
  usedBytes: number | null
  totalBytes: number | null
}

/**
 * Storage resources joined with each node's reported storage capacity. A
 * capacity with no matching resource still gets a row: the node reported it.
 */
export function storageRows(views: AccountView[]): StorageRow[] {
  const rows: StorageRow[] = []
  for (const view of views) {
    const discovery = view.discovery
    if (!discovery)
      continue
    const capacity = new Map<string, { usedBytes: number, totalBytes: number }>()
    for (const node of discovery.nodeCapacities) {
      for (const storage of node.storages)
        capacity.set(`${node.node}/${storage.storage}`, storage)
    }
    const seen = new Set<string>()
    for (const resource of discovery.resources.filter(r => r.kind === 'storage')) {
      const storage = storageName(resource)
      const key = `${resource.node ?? ''}/${storage}`
      seen.add(key)
      const cap = capacity.get(key)
      rows.push({
        accountId: view.account.id,
        accountName: view.account.name,
        node: resource.node ?? null,
        storage,
        status: resource.status ?? null,
        usedBytes: cap?.usedBytes ?? null,
        totalBytes: cap?.totalBytes ?? null,
      })
    }
    for (const [key, cap] of capacity) {
      if (seen.has(key))
        continue
      const [node, storage] = [key.slice(0, key.indexOf('/')), key.slice(key.indexOf('/') + 1)]
      rows.push({ accountId: view.account.id, accountName: view.account.name, node, storage, status: null, usedBytes: cap.usedBytes, totalBytes: cap.totalBytes })
    }
  }
  return rows.sort((a, b) => a.accountName.localeCompare(b.accountName) || (a.node ?? '').localeCompare(b.node ?? '') || a.storage.localeCompare(b.storage))
}

/** PVE storage ids look like `storage/<node>/<name>`; the name is the last part. */
function storageName(resource: ProxmoxResourceDto): string {
  if (resource.name)
    return resource.name
  const parts = resource.id.split('/')
  return parts[parts.length - 1] ?? resource.id
}

export interface TemplateRow {
  /** The cluster-visible resource id, unique per account. */
  id: string
  accountId: string
  accountName: string
  node: string | null
  vmid: number | null
  name: string
  status: string | null
}

export function templateRows(views: AccountView[]): TemplateRow[] {
  return views.flatMap(view => (view.discovery?.resources ?? [])
    .filter(r => r.kind === 'qemu-template')
    .map(r => ({
      id: r.id,
      accountId: view.account.id,
      accountName: view.account.name,
      node: r.node ?? null,
      vmid: r.vmid ?? null,
      name: r.name ?? r.id,
      status: r.status ?? null,
    })))
    .sort((a, b) => a.accountName.localeCompare(b.accountName) || (a.vmid ?? 0) - (b.vmid ?? 0))
}

export interface GuestRow {
  accountId: string
  accountName: string
  state: TrustState
  guest: AssociatedGuestDto
}

export function guestRows(views: AccountView[]): GuestRow[] {
  return views.flatMap(view => view.guests.map(guest => ({ accountId: view.account.id, accountName: view.account.name, state: view.state, guest })))
    .sort((a, b) => a.accountName.localeCompare(b.accountName) || (a.guest.vmid ?? 0) - (b.guest.vmid ?? 0))
}

// ---------------------------------------------------------------------------
// Handoff

function hostPart(host: string): string {
  return host.includes(':') && !host.startsWith('[') ? `[${host}]` : host
}

/**
 * The account's own PVE web UI. With a resource, the URL carries PVE's
 * view state (`#v1:0:=<type>/<id>`), which selects it in the resource tree;
 * PVE falls back to its dashboard if the state is not understood. This is a
 * handoff only: Fleet is not a hypervisor console.
 */
export function pveUrl(account: Pick<ProxmoxAccountDto, 'host' | 'port'>, resource?: { type: 'qemu' | 'lxc' | 'node', id: string | number }): string {
  const base = `https://${hostPart(account.host)}:${account.port}/`
  return resource ? `${base}#v1:0:=${encodeURIComponent(`${resource.type}/${resource.id}`)}` : base
}

function command(words: string[]): string {
  return words.map(shellQuote).join(' ')
}

// ---------------------------------------------------------------------------
// Privileges (FM-604)

/** The tiers in the order the API reports them and the card shows them. */
export const PRIVILEGE_TIERS: readonly ProxmoxPrivilegeTierDto[] = ['discover', 'operate', 'destructive', 'lab']

export function tierOf(privileges: ProxmoxPrivilegesDto | null | undefined, tier: ProxmoxPrivilegeTierDto) {
  return privileges?.tiers.find(t => t.tier === tier) ?? null
}

/** A tier's reported status; `unknown` until a report exists. */
export function tierStatus(privileges: ProxmoxPrivilegesDto | null | undefined, tier: ProxmoxPrivilegeTierDto): ProxmoxPrivilegeStatusDto {
  return tierOf(privileges, tier)?.status ?? 'unknown'
}

export function privilegeTone(status: ProxmoxPrivilegeStatusDto): Tone {
  switch (status) {
    case 'granted': return 'ok'
    case 'missing': return 'err'
    default: return 'faint'
  }
}

/**
 * Why actions of `tier` are withheld, or null when they are offered. Only a
 * reported `missing` withholds them: `unknown`, or no report yet, leaves
 * them enabled, and the controller stays authoritative either way.
 */
export function tierBlockReason(privileges: ProxmoxPrivilegesDto | null | undefined, tier: ProxmoxPrivilegeTierDto): string | null {
  const report = tierOf(privileges, tier)
  if (report?.status !== 'missing')
    return null
  const needs = report.missing.map(m => `${m.privileges.join(m.anyOf ? ' or ' : ', ')} on ${m.path}`).join('; ')
  return `This account's API token lacks the ${tier} privileges${needs ? ` (${needs})` : ''}. Grant them in PVE; the ${tier} chip on the Accounts tab lists them.`
}

export function privilegesCommand(accountId: string): string {
  return command(['fleetctl', 'proxmox', 'privileges', accountId])
}

// ---------------------------------------------------------------------------
// Compatibility

/**
 * The PVE majors Fleet verifies against, named once for the whole console.
 * The API reports the version and the major whose privilege rules it applied
 * (`rulesMajor`), but clamps an unsupported major to the nearest table, so
 * "verified" cannot be read from `rulesMajor` alone. Mirrors
 * `fleet_application::proxmox::privileges::SUPPORTED_PVE_MAJORS`.
 */
export const VERIFIED_PVE_MAJORS: readonly number[] = [8, 9]

export function pveMajor(version: string | null | undefined): number | null {
  const match = /^(\d+)(?:[.-]|$)/.exec(version ?? '')
  return match ? Number(match[1]) : null
}

export interface Compatibility {
  label: string
  tone: Tone
  verified: boolean
  title: string
}

/**
 * The compatibility badge, from the reported PVE version and, once the
 * privilege report exists, the rules major it applied. A major outside the
 * verified list, or one the API evaluated with another major's rules, is an
 * "unverified major".
 */
export function compatibility(version: string | null | undefined, rulesMajor?: number | null): Compatibility | null {
  if (!version)
    return null
  const major = pveMajor(version)
  const verified = major !== null && VERIFIED_PVE_MAJORS.includes(major)
    && (rulesMajor === null || rulesMajor === undefined || rulesMajor === major)
  if (verified)
    return { label: `PVE ${major} · verified`, tone: 'ok', verified, title: `PVE ${version} is a verified Fleet target.` }
  const rules = rulesMajor ? `; privileges were evaluated with the ${rulesMajor}.x rules` : ''
  return {
    label: 'unverified major',
    tone: 'warn',
    verified,
    title: `PVE ${version} is not a verified Fleet target (verified: ${VERIFIED_PVE_MAJORS.map(m => `${m}.x`).join(', ')})${rules}.`,
  }
}

// ---------------------------------------------------------------------------
// Tasks (FM-609)

export const TASK_STATUSES: readonly ProxmoxTaskStatusDto[] = ['running', 'ok', 'error', 'unknown']

export function taskTone(status: ProxmoxTaskStatusDto): Tone {
  switch (status) {
    case 'ok': return 'ok'
    case 'error': return 'err'
    case 'running': return 'info'
    default: return 'faint'
  }
}

/** Fleet's status taxonomy: outcomes in capitals, live or unknown states lower-case. */
export function taskLabel(status: ProxmoxTaskStatusDto): string {
  return status === 'ok' ? 'OK' : status === 'error' ? 'ERROR' : status
}

export interface TaskFilters {
  node: string
  /** A VMID as typed or picked; anything but digits is ignored. */
  vmid: string
  status: '' | ProxmoxTaskStatusDto
}

export const EMPTY_TASK_FILTERS: TaskFilters = { node: '', vmid: '', status: '' }

export const TASK_PAGE = 50

function vmidOf(filters: TaskFilters): number | undefined {
  return /^\d+$/.test(filters.vmid) ? Number(filters.vmid) : undefined
}

/** The API parameters for a filter set; empty filters are omitted. */
export function taskParams(filters: TaskFilters, cursor?: string | null, limit = TASK_PAGE): { node?: string, vmid?: number, status?: string, cursor?: string, limit: number } {
  const vmid = vmidOf(filters)
  return {
    ...(filters.node ? { node: filters.node } : {}),
    ...(vmid !== undefined ? { vmid } : {}),
    ...(filters.status ? { status: filters.status } : {}),
    ...(cursor ? { cursor } : {}),
    limit,
  }
}

export function tasksCommand(accountId: string, filters: TaskFilters): string {
  const words = ['fleetctl', 'proxmox', 'tasks', accountId]
  const vmid = vmidOf(filters)
  if (filters.node)
    words.push('--node', filters.node)
  if (vmid !== undefined)
    words.push('--vmid', String(vmid))
  if (filters.status)
    words.push('--status', filters.status)
  return command(words)
}

/** A finished task's duration in a compact form, or null while it runs. */
export function taskDuration(startedAt: number, endedAt: number | null | undefined): string | null {
  if (endedAt === null || endedAt === undefined)
    return null
  const seconds = Math.max(0, Math.round((endedAt - startedAt) / 1000))
  if (seconds < 60)
    return `${seconds}s`
  const minutes = Math.floor(seconds / 60)
  return minutes < 60 ? `${minutes}m ${seconds % 60}s` : `${Math.floor(minutes / 60)}h ${minutes % 60}m`
}

/** The least-privilege token guide (FM-605), linked from the tier popover. */
export const TOKEN_GUIDE_URL = 'https://github.com/Frogbyte-io/fleet-manager/blob/dev/docs/operations/proxmox-token.md'
