// Pure Proxmox page helpers: account trust state, per-node capacity, the
// resource joins behind each tab, and the web-UI handoff. No Vue imports, so
// the rules here are unit-tested directly.

import type {
  AssociatedGuestDto,
  ProxmoxAccountDto,
  ProxmoxDiscoveryDto,
  ProxmoxNodeCapacityDto,
  ProxmoxResourceDto,
} from '@frogbyte-io/fleet-api-client'

import type { Tone } from '../fleet/inventory'
import { ApiRequestError } from '../machine/api'

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
      const node = resource.node ?? resource.name ?? resource.id
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
