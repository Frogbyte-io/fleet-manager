import { describe, expect, it } from 'vitest'

import type { ProxmoxPrivilegesDto, ProxmoxTierPrivilegesDto } from '@frogbyte-io/fleet-api-client'

import {
  compatibility,
  EMPTY_TASK_FILTERS,
  privilegesCommand,
  privilegeTone,
  pveMajor,
  taskDuration,
  taskLabel,
  taskParams,
  tasksCommand,
  taskTone,
  tierBlockReason,
  tierStatus,
  VERIFIED_PVE_MAJORS,
} from '../proxmox'

function tier(t: ProxmoxTierPrivilegesDto['tier'], status: ProxmoxTierPrivilegesDto['status'], missing: ProxmoxTierPrivilegesDto['missing'] = []): ProxmoxTierPrivilegesDto {
  return { tier: t, status, missing, checks: [] }
}

function report(tiers: ProxmoxTierPrivilegesDto[], overrides: Partial<ProxmoxPrivilegesDto> = {}): ProxmoxPrivilegesDto {
  return { accountId: 'acc1', pveVersion: '9.0.3', rulesMajor: 9, tiers, effectivePermissions: {}, warnings: [], observedAt: 0, ...overrides }
}

const operateMissing = report([
  tier('discover', 'granted'),
  tier('operate', 'missing', [{ path: '/vms/{vmid}', privileges: ['VM.PowerMgmt'], anyOf: false, capabilities: ['proxmox.guest.start'] }]),
  tier('destructive', 'unknown'),
  tier('lab', 'missing', []),
])

describe('privilege tiers', () => {
  it('reports each tier as the API did, and unknown without a report', () => {
    expect(tierStatus(operateMissing, 'discover')).toBe('granted')
    expect(tierStatus(operateMissing, 'operate')).toBe('missing')
    expect(tierStatus(operateMissing, 'destructive')).toBe('unknown')
    expect(tierStatus(null, 'operate')).toBe('unknown')
    expect(tierStatus(report([]), 'lab')).toBe('unknown')
  })

  it('tones chips granted ok, missing err, unknown faint', () => {
    expect(privilegeTone('granted')).toBe('ok')
    expect(privilegeTone('missing')).toBe('err')
    expect(privilegeTone('unknown')).toBe('faint')
  })

  it('withholds a tier only when it is reported missing', () => {
    expect(tierBlockReason(operateMissing, 'operate')).toContain('VM.PowerMgmt on /vms/{vmid}')
    // Unknown, granted, or no report leaves actions enabled: the server decides.
    expect(tierBlockReason(operateMissing, 'destructive')).toBeNull()
    expect(tierBlockReason(operateMissing, 'discover')).toBeNull()
    expect(tierBlockReason(null, 'operate')).toBeNull()
    expect(tierBlockReason(undefined, 'operate')).toBeNull()
    // Missing without itemized privileges still withholds.
    expect(tierBlockReason(operateMissing, 'lab')).toContain('lab privileges')
  })

  it('builds the privileges command', () => {
    expect(privilegesCommand('acc1')).toBe('fleetctl proxmox privileges acc1')
  })
})

describe('compatibility badge', () => {
  it('verifies exactly the listed majors', () => {
    expect(VERIFIED_PVE_MAJORS).toEqual([8, 9])
    expect(compatibility('9.0.3', 9)).toMatchObject({ label: 'PVE 9 · verified', verified: true, tone: 'ok' })
    expect(compatibility('8.4.1')).toMatchObject({ label: 'PVE 8 · verified', verified: true })
    expect(compatibility('7.4-3')).toMatchObject({ label: 'unverified major', verified: false, tone: 'warn' })
    expect(compatibility('10.0.1', 9)).toMatchObject({ label: 'unverified major', verified: false })
    expect(compatibility('10.0.1', 9)!.title).toContain('evaluated with the 9.x rules')
    expect(compatibility('garbage')).toMatchObject({ verified: false })
    expect(compatibility(null)).toBeNull()
  })

  it('treats a rules major that differs from the version as unverified', () => {
    expect(compatibility('9.1.0', 8)).toMatchObject({ verified: false })
  })

  it('parses the major from PVE version strings', () => {
    expect(pveMajor('9.0.3')).toBe(9)
    expect(pveMajor('7.4-3')).toBe(7)
    expect(pveMajor('8')).toBe(8)
    expect(pveMajor('v8')).toBeNull()
    expect(pveMajor(undefined)).toBeNull()
  })
})

describe('tasks', () => {
  it('uses the Fleet status taxonomy', () => {
    expect([taskLabel('ok'), taskLabel('error'), taskLabel('running'), taskLabel('unknown')]).toEqual(['OK', 'ERROR', 'running', 'unknown'])
    expect([taskTone('ok'), taskTone('error'), taskTone('running'), taskTone('unknown')]).toEqual(['ok', 'err', 'info', 'faint'])
  })

  it('omits empty filters and carries the cursor', () => {
    expect(taskParams(EMPTY_TASK_FILTERS)).toEqual({ limit: 50 })
    expect(taskParams({ node: 'pve1', vmid: '101', status: 'error' }, 'UPID:x')).toEqual({ node: 'pve1', vmid: 101, status: 'error', cursor: 'UPID:x', limit: 50 })
    expect(taskParams({ node: '', vmid: 'abc', status: '' }, null)).toEqual({ limit: 50 })
  })

  it('builds the tasks command from the same filters', () => {
    expect(tasksCommand('acc1', EMPTY_TASK_FILTERS)).toBe('fleetctl proxmox tasks acc1')
    expect(tasksCommand('acc1', { node: 'pve1', vmid: '101', status: 'running' })).toBe('fleetctl proxmox tasks acc1 --node pve1 --vmid 101 --status running')
  })

  it('formats durations and leaves running tasks open', () => {
    expect(taskDuration(0, null)).toBeNull()
    expect(taskDuration(0, 42_000)).toBe('42s')
    expect(taskDuration(0, 125_000)).toBe('2m 5s')
    expect(taskDuration(0, 3_900_000)).toBe('1h 5m')
  })
})
