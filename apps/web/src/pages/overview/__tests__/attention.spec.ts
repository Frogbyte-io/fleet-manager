import { describe, expect, it } from 'vitest'

import type { OperationDto } from '@frogbyte-io/fleet-api-client'

import {
  activity,
  EXPIRING_WINDOW_MS,
  kpis,
  leaseRows,
  machineRows,
  onboardingRows,
  operationRows,
  proxmoxRows,
  sortAttention,
  templatePinRows,
} from '../attention'

const NOW = 1_000_000_000

describe('attention sources', () => {
  it('flags offline and stale machines, linking to the machine', () => {
    const rows = machineRows([
      { id: 'm1', name: 'ws', machineStatus: 'offline', lastSeenAt: 5 },
      { id: 'm2', name: 'laptop', machineStatus: 'stale', lastSeenAt: null },
      { id: 'm3', name: 'ok', machineStatus: 'connected', lastSeenAt: 9 },
    ])
    expect(rows.map(r => [r.title, r.severity, r.to])).toEqual([
      ['ws is offline', 'err', '/fleet/machines/m1'],
      ['laptop is stale', 'warn', '/fleet/machines/m2'],
    ])
  })

  it('flags cleanup_failed and soon-expiring leases, linking to Lab', () => {
    const rows = leaseRows([
      { id: 'lease-cleanup-1', state: 'cleanup_failed', purpose: 'old', expiresAt: null, createdAt: 1 },
      { id: 'lease-soon-0001', state: 'ready', purpose: 'debug', expiresAt: NOW + 10 * 60_000, createdAt: 2 },
      { id: 'lease-later-001', state: 'ready', purpose: 'long', expiresAt: NOW + EXPIRING_WINDOW_MS + 60_000, createdAt: 3 },
    ], NOW)
    expect(rows.map(r => [r.source, r.severity, r.to])).toEqual([
      ['lease-cleanup', 'err', '/lab'],
      ['lease-expiring', 'warn', '/lab'],
    ])
    expect(rows[1]!.title).toContain('in 10 min')
  })

  it('flags blocked operations with their recorded reason, linking to the operation', () => {
    const rows = operationRows([
      { id: 'op-1', kind: 'ready.workflow', state: 'blocked_manual_approval', errorJson: '{"reason":"blocked_manual_approval","detail":"frogenv approval pending"}', updatedAt: 7 },
      { id: 'op-2', kind: 'mise.install', state: 'failed', errorJson: null, updatedAt: 8 },
    ] as OperationDto[])
    expect(rows).toHaveLength(1)
    expect(rows[0]).toMatchObject({ detail: 'frogenv approval pending', to: { path: '/operations', query: { op: 'op-1' } } })
  })

  it('flags changed and unconfirmed Proxmox fingerprints, linking to Proxmox', () => {
    const account = (id: string) => ({ id, name: id, host: 'h', port: 8006, tokenId: 't', fingerprintState: 'confirmed', createdAt: 0 })
    const rows = proxmoxRows([
      { account: account('changed'), state: 'changed' },
      { account: account('new'), state: 'unconfirmed' },
      { account: account('fine'), state: 'pinned' },
    ])
    expect(rows.map(r => [r.title, r.severity, r.to])).toEqual([
      ['changed: TLS fingerprint changed', 'err', '/proxmox'],
      ['new: fingerprint not confirmed', 'warn', '/proxmox'],
    ])
  })

  it('lists every pending onboarding draft, linking to the Add dialog', () => {
    const rows = onboardingRows([{ id: 'd1', name: '', stage: 'review', endpoint: { user: 'dev', host: 'box', port: 22 }, updatedAt: 3 }])
    expect(rows[0]).toMatchObject({ title: 'Onboarding dev@box is unfinished', detail: 'A host key awaits confirmation.', to: '/fleet/add' })
  })

  it('flags stale template pins, linking to the template in Images', () => {
    const rows = templatePinRows(
      [{ id: 't1', name: 'ubuntu-dev', imageVersionId: 'r1@a' }, { id: 't2', name: 'fresh', imageVersionId: 'r1@b' }],
      [{ id: 'r1@a', recipeId: 'r1', promotedAt: null }, { id: 'r1@b', recipeId: 'r1', promotedAt: 5 }],
    )
    expect(rows.map(r => [r.title, r.to])).toEqual([
      ['Lab template ubuntu-dev has a stale image pin', { path: '/images', query: { select: 'template:t1' } }],
    ])
  })

  it('orders errors before warnings before to-dos, newest first', () => {
    const base = { source: 'machine' as const, title: '', detail: '', to: '/' }
    const sorted = sortAttention([
      { ...base, key: 'info', severity: 'info', at: 9 },
      { ...base, key: 'warn-old', severity: 'warn', at: 1 },
      { ...base, key: 'err', severity: 'err', at: 0 },
      { ...base, key: 'warn-new', severity: 'warn', at: 5 },
    ])
    expect(sorted.map(r => r.key)).toEqual(['err', 'warn-new', 'warn-old', 'info'])
  })
})

describe('kpis and activity', () => {
  it('counts machines, leases, and live operations', () => {
    expect(kpis(
      [{ machineStatus: 'connected' }, { machineStatus: 'agentless' }, { machineStatus: 'stale' }, { machineStatus: 'offline' }],
      [{ state: 'ready' }, { state: 'provisioning' }, { state: 'released' }],
      [{ state: 'running' }, { state: 'pending' }, { state: 'blocked_manual_approval' }, { state: 'succeeded' }],
    )).toEqual({ connected: 1, agentless: 1, unreachable: 2, leasesReady: 1, leasesInProgress: 1, running: 2 })
  })

  it('merges operations and audit events, newest first, and marks denials', () => {
    const feed = activity(
      [{ id: 'op-1', kind: 'image.build', state: 'running', updatedAt: 10, progressMessage: 'building' }],
      [{ id: 'a1', occurredAt: 20, action: 'machines.create', actor: 'me', resource: 'm1', outcome: null, allowed: false }],
    )
    expect(feed.map(i => [i.key, i.tone])).toEqual([['audit:a1', 'err'], ['op:op-1', 'info']])
    expect(feed[0]!.detail).toBe('me · denied')
  })
})
