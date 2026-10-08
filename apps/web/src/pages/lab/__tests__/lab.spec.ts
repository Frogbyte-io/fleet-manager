import { describe, expect, it } from 'vitest'

import type { LabTemplateDto } from '@frogbyte-io/fleet-api-client'

import {
  artifactGetCommand,
  artifactsCommand,
  cleanupRetryCommand,
  collectCommand,
  createCommand,
  execCommand,
  execOutput,
  extendCommand,
  formatBytes,
  formatDuration,
  formatSpan,
  formatTimestamp,
  isLive,
  leasableTemplates,
  leaseCommand,
  leasesCommand,
  leaseSteps,
  leaseTone,
  leaseTtl,
  operationFailure,
  parsePaths,
  provisionLeaseCommand,
  releaseCommand,
  statusCommand,
  sweepCommand,
  templatesByVersion,
  templateSpec,
} from '../lab'

function template(overrides: Partial<LabTemplateDto> = {}): LabTemplateDto {
  return {
    id: 't1',
    name: 'ubuntu-dev',
    description: '',
    imageVersionId: 'img-1',
    cores: 2,
    memoryMib: 4096,
    diskGib: 40,
    bootstrapProjectId: null,
    readinessProbe: 'guest_agent',
    readinessCommand: null,
    sshUser: 'root',
    sshPort: 22,
    sshTrustMode: 'tofu',
    sshFingerprint: null,
    readinessDeadlineSeconds: 600,
    ttlSeconds: 7200,
    cleanup: 'destroy',
    publishedFrom: 'v1',
    createdAt: 0,
    updatedAt: 0,
    ...overrides,
  }
}

const statuses = (state: string, readyAt: number | null = null) =>
  leaseSteps({ state, readyAt }).map(step => `${step.label}:${step.status}`)

describe('lease lifecycle', () => {
  it('marks steps before the current one done and the current one current', () => {
    const steps = statuses('booting')
    expect(steps.slice(0, 4)).toEqual(['requested:done', 'queued:done', 'reserving:done', 'provisioning:done'])
    expect(steps[4]).toBe('booting:current')
    expect(steps.slice(5).every(s => s.endsWith(':todo'))).toBe(true)
  })

  it('shows a released lease as entirely done', () => {
    expect(statuses('released').every(s => s.endsWith(':done'))).toBe(true)
  })

  it('fails ready when a lease fails before it was ever ready', () => {
    const steps = statuses('failed', null)
    expect(steps).toContain('ready:failed')
    expect(steps[0]).toBe('requested:done')
    // Nothing between request and ready is claimed: the API does not say where it failed.
    expect(steps.slice(1, 6).every(s => s.endsWith(':todo'))).toBe(true)
  })

  it('fails the release path when a lease failed after ready', () => {
    const steps = statuses('failed', 1000)
    expect(steps).toContain('ready:done')
    expect(steps).toContain('releasing:failed')
  })

  it('fails released for cleanup_failed', () => {
    const steps = statuses('cleanup_failed')
    expect(steps).toContain('releasing:done')
    expect(steps).toContain('released:failed')
  })

  it('claims nothing for an unknown state', () => {
    expect(statuses('teleporting').every(s => s.endsWith(':todo'))).toBe(true)
  })

  it('maps tones per DESIGN.md §3', () => {
    expect(leaseTone('ready')).toBe('ok')
    expect(leaseTone('bootstrapping')).toBe('info')
    expect(leaseTone('releasing')).toBe('muted')
    expect(leaseTone('released')).toBe('muted')
    expect(leaseTone('cleanup_failed')).toBe('err')
    expect(leaseTone('failed')).toBe('err')
    expect(leaseTone('mystery')).toBe('faint')
  })

  it('keeps polling only while a lease is live', () => {
    expect(isLive('provisioning')).toBe(true)
    expect(isLive('ready')).toBe(true)
    expect(isLive('released')).toBe(false)
    expect(isLive('failed')).toBe(false)
    expect(isLive('cleanup_failed')).toBe(false)
  })
})

describe('TTL', () => {
  it('is absent until the lease has a ready time and an expiry', () => {
    expect(leaseTtl({ readyAt: null, expiresAt: null, maxLifetimeAt: 10_000 }, 0)).toBeNull()
    expect(leaseTtl({ readyAt: 1000, expiresAt: null, maxLifetimeAt: 10_000 }, 0)).toBeNull()
  })

  it('reports time left, the used share, and the lifetime cap', () => {
    const ttl = leaseTtl({ readyAt: 0, expiresAt: 3_600_000, maxLifetimeAt: 7_200_000 }, 900_000)!
    expect(ttl.remainingSeconds).toBe(2700)
    expect(ttl.usedFraction).toBeCloseTo(0.25)
    expect(ttl.lifetimeRemainingSeconds).toBe(6300)
  })

  it('clamps once expired', () => {
    const ttl = leaseTtl({ readyAt: 0, expiresAt: 1000, maxLifetimeAt: 2000 }, 5000)!
    expect(ttl.remainingSeconds).toBe(0)
    expect(ttl.usedFraction).toBe(1)
    expect(ttl.lifetimeRemainingSeconds).toBe(0)
  })

  it('formats durations and spans', () => {
    expect(formatDuration(2530)).toBe('00:42:10')
    expect(formatDuration(90_061)).toBe('1D 01:01')
    expect(formatSpan(7200)).toBe('2H')
    expect(formatSpan(1800)).toBe('30M')
    expect(formatSpan(93_600)).toBe('1D 2H')
    // Configured seconds are never dropped.
    expect(formatSpan(45)).toBe('45S')
    expect(formatSpan(61)).toBe('1M 1S')
    expect(formatSpan(0)).toBe('0S')
  })
})

describe('templates', () => {
  it('resolves a lease version only through the version a template points at', () => {
    const map = templatesByVersion([template(), template({ id: 't2', name: 'draft', publishedFrom: null })])
    expect(map.get('v1')?.name).toBe('ubuntu-dev')
    expect(map.size).toBe(1)
  })

  it('offers only published templates for leasing', () => {
    expect(leasableTemplates([template(), template({ id: 't2', publishedFrom: null })]).map(t => t.id)).toEqual(['t1'])
  })

  it('describes a template spec in API units', () => {
    expect(templateSpec(template())).toBe('2C · 4G · 40G · TTL 2H')
    expect(templateSpec(template({ memoryMib: 1500 }))).toBe('2C · 1500M · 40G · TTL 2H')
  })
})

describe('fleetctl equivalents', () => {
  it('puts the global output flag before the command and quotes free text', () => {
    expect(leaseCommand('v1', 'try new mise', null)).toBe(`fleetctl --output json lab lease v1 --purpose 'try new mise'`)
    expect(provisionLeaseCommand('l1', 'acc')).toBe('fleetctl --output json lab provision-lease l1 --account acc')
    expect(releaseCommand('l1', false)).toBe('fleetctl --output json lab release l1')
    expect(releaseCommand('l1', true)).toBe('fleetctl --output json lab release l1 --keep')
    expect(extendCommand('l1', 3600)).toBe('fleetctl --output json lab extend l1 --seconds 3600')
    expect(sweepCommand()).toBe('fleetctl --output json lab sweep')
  })

  it('carries the project and the optional account', () => {
    expect(leaseCommand('v1', 'x', 'p1')).toBe('fleetctl --output json lab lease v1 --purpose x --project p1')
    expect(createCommand('v1', 'x', 'p1', 'acc')).toBe('fleetctl --output json lab create v1 --purpose x --project p1 --account acc')
    expect(createCommand('v1', 'x', null, 'acc')).toBe('fleetctl --output json lab create v1 --purpose x --account acc')
    expect(provisionLeaseCommand('l1', null)).toBe('fleetctl --output json lab provision-lease l1')
    expect(leasesCommand('p1')).toBe('fleetctl --output json lab leases --project p1')
    expect(leasesCommand(null)).toBe('fleetctl --output json lab leases')
  })

  it('spells out cleanup retry, status, exec, collect, and artifact commands', () => {
    expect(cleanupRetryCommand('l1')).toBe('fleetctl --output json lab cleanup-retry l1')
    expect(statusCommand('l1')).toBe('fleetctl --output json lab status l1')
    expect(execCommand('l1', 'uname -a', 60)).toBe(`fleetctl --output json lab exec l1 --timeout 60 -- sh -c 'uname -a'`)
    expect(collectCommand('l1', ['/var/log/a.log', '/tmp/b c'])).toBe(`fleetctl --output json lab collect l1 /var/log/a.log '/tmp/b c'`)
    expect(artifactsCommand({ leaseId: 'l1' })).toBe('fleetctl --output json lab artifacts --lease l1')
    expect(artifactsCommand({ projectId: 'p1' })).toBe('fleetctl --output json lab artifacts --project p1')
    expect(artifactGetCommand('a1', 'out.log')).toBe('fleetctl --output json lab artifact-get a1 --out out.log')
  })
})

describe('operation results', () => {
  it('reads a placement refusal verbatim', () => {
    const failure = operationFailure('{"reason":"insufficient_memory","detail":"insufficient memory on pve-02: need 4096 MiB, 2048 free"}')
    expect(failure).toEqual({ reason: 'insufficient_memory', detail: 'insufficient memory on pve-02: need 4096 MiB, 2048 free', step: null })
    expect(operationFailure('{"reason":"provision_failed","step":"clone","detail":"x"}')?.step).toBe('clone')
    expect(operationFailure('not json')).toBeNull()
    expect(operationFailure('{"other":1}')).toBeNull()
    expect(operationFailure(null)).toBeNull()
  })

  it('reads exec output from a success, a nonzero exit, a deadline kill, and a connection failure', () => {
    expect(execOutput({ resultJson: '{"exitCode":0,"stdout":"ok\\n","stderr":"","truncatedStdout":false,"truncatedStderr":false}' }))
      .toEqual({ exitCode: 0, stdout: 'ok\n', stderr: '', truncatedStdout: false, truncatedStderr: false, reason: null, detail: null })
    expect(execOutput({ errorJson: '{"exitCode":2,"stdout":"","stderr":"boom","truncatedStdout":true,"truncatedStderr":false}' }))
      .toMatchObject({ exitCode: 2, stderr: 'boom', truncatedStdout: true })
    expect(execOutput({ errorJson: '{"reason":"deadline_killed","detail":"killed","partialOutput":{"stdout":"half","stderr":"","truncatedStdout":false,"truncatedStderr":true}}' }))
      .toMatchObject({ exitCode: null, stdout: 'half', truncatedStderr: true, reason: 'deadline_killed', detail: 'killed' })
    expect(execOutput({ errorJson: '{"reason":"connection_failed","detail":"refused"}' }))
      .toMatchObject({ exitCode: null, stdout: '', stderr: '', reason: 'connection_failed' })
    expect(execOutput({})).toBeNull()
  })

  it('splits collect paths and formats sizes and timestamps', () => {
    expect(parsePaths(' /a \n\n/b\n/a\n')).toEqual(['/a', '/b'])
    expect(formatBytes(512)).toBe('512 B')
    expect(formatBytes(1536)).toBe('1.5 KiB')
    expect(formatBytes(5 * 1024 * 1024)).toBe('5.0 MiB')
    expect(formatTimestamp(Date.UTC(2026, 9, 8, 14, 3, 12))).toBe('2026-10-08 14:03:12 UTC')
  })
})
