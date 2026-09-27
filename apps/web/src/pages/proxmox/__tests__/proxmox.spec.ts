import { describe, expect, it } from 'vitest'

import type { ProxmoxAccountDto, ProxmoxDiscoveryDto } from '@frogbyte-io/fleet-api-client'

import { ApiRequestError } from '../../machine/api'
import {
  actionsAllowed,
  mismatchFingerprints,
  nodeRows,
  pveUrl,
  ratio,
  sameFingerprint,
  storageRows,
  templateRows,
  trustState,
  usageTone,
  type AccountView,
} from '../proxmox'

const account: ProxmoxAccountDto = {
  id: 'acc1', name: 'homelab', host: 'pve.lan', port: 8006, tokenId: 'fleet@pve!c', fingerprint: 'AA:BB', fingerprintState: 'confirmed', createdAt: 0,
}

const mismatch = new ApiRequestError(409, 'proxmox_fingerprint_mismatch', 'proxmox_fingerprint_mismatch: the host certificate\'s fingerprint CC:DD does not match the pinned AA:BB')

describe('trust state', () => {
  it('distinguishes unconfirmed, pinned, changed, checking, and unreachable', () => {
    expect(trustState({ ...account, fingerprintState: 'unconfirmed' }, { loading: false, error: null })).toBe('unconfirmed')
    expect(trustState(account, { loading: false, error: null })).toBe('pinned')
    expect(trustState(account, { loading: true, error: null })).toBe('checking')
    expect(trustState(account, { loading: false, error: mismatch })).toBe('changed')
    expect(trustState(account, { loading: false, error: new ApiRequestError(502, 'proxmox_auth', 'refused') })).toBe('unreachable')
  })

  it('allows actions only on a verified pin', () => {
    expect(['unconfirmed', 'pinned', 'changed', 'checking', 'unreachable'].filter(s => actionsAllowed(s as never))).toEqual(['pinned'])
  })

  it('reads both fingerprints from a mismatch message', () => {
    expect(mismatchFingerprints(mismatch.message)).toEqual({ observed: 'CC:DD', pinned: 'AA:BB' })
    expect(mismatchFingerprints('something else')).toBeNull()
  })

  it('compares fingerprints without separators or case', () => {
    expect(sameFingerprint('aa:bb', 'AABB')).toBe(true)
    expect(sameFingerprint('aa:bb', 'AA:BC')).toBe(false)
    expect(sameFingerprint(null, 'AA')).toBe(false)
  })
})

const discovery: ProxmoxDiscoveryDto = {
  accountId: 'acc1',
  pveVersion: '8.2.4',
  reportedCount: 6,
  warnings: [],
  observedAt: 1,
  resources: [
    { accountId: 'acc1', id: 'node/pve1', kind: 'node', name: 'pve1', node: 'pve1', status: 'online', vmid: null, observedAt: 1, pveVersion: '8.2.4' },
    { accountId: 'acc1', id: 'qemu/101', kind: 'qemu', name: 'dev', node: 'pve1', status: 'running', vmid: 101, observedAt: 1, pveVersion: '8.2.4' },
    { accountId: 'acc1', id: 'qemu/9000', kind: 'qemu-template', name: 'ubuntu-tpl', node: 'pve1', status: 'stopped', vmid: 9000, observedAt: 1, pveVersion: '8.2.4' },
    { accountId: 'acc1', id: 'storage/pve1/local-lvm', kind: 'storage', name: null, node: 'pve1', status: 'available', vmid: null, observedAt: 1, pveVersion: '8.2.4' },
  ],
  nodeCapacities: [{
    node: 'pve1', observedAt: 1, cpuCount: 8, cpuUsageRatio: 0.5, memoryUsedBytes: 8, memoryTotalBytes: 16,
    storages: [{ storage: 'local-lvm', usedBytes: 90, totalBytes: 100 }, { storage: 'nfs', usedBytes: 1, totalBytes: 4 }],
  }],
}

const views: AccountView[] = [{ account, state: 'pinned', discovery, guests: [] }]

describe('joins', () => {
  it('builds node rows with capacity and counts', () => {
    expect(nodeRows(views)).toMatchObject([{ node: 'pve1', status: 'online', guestCount: 1, templateCount: 1, capacity: { cpuCount: 8 } }])
  })

  it('joins storage resources with capacity and keeps capacity-only pools', () => {
    expect(storageRows(views).map(r => [r.storage, r.usedBytes, r.totalBytes, r.status])).toEqual([
      ['local-lvm', 90, 100, 'available'],
      ['nfs', 1, 4, null],
    ])
  })

  it('lists templates', () => {
    expect(templateRows(views)).toMatchObject([{ vmid: 9000, name: 'ubuntu-tpl', node: 'pve1' }])
  })

  it('shows nothing for an account without discovery', () => {
    expect(nodeRows([{ account, state: 'changed', discovery: null, guests: [] }])).toEqual([])
  })
})

describe('capacity and handoff', () => {
  it('computes bounded ratios and tones', () => {
    expect(ratio(8, 16)).toBe(0.5)
    expect(ratio(20, 16)).toBe(1)
    expect(ratio(null, 16)).toBeNull()
    expect(ratio(1, 0)).toBeNull()
    expect([0.5, 0.8, 0.95, null].map(usageTone)).toEqual(['ok', 'warn', 'err', 'faint'])
  })

  it('links to the account web UI and selects a resource', () => {
    expect(pveUrl(account)).toBe('https://pve.lan:8006/')
    expect(pveUrl(account, { type: 'qemu', id: 101 })).toBe('https://pve.lan:8006/#v1:0:=qemu%2F101')
    expect(pveUrl({ host: 'fd00::1', port: 8006 })).toBe('https://[fd00::1]:8006/')
  })
})
