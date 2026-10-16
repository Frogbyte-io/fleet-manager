import type { RunningServiceDto, ServicesCoverageDto } from '@frogbyte-io/fleet-api-client'

// Fake, public-safe data only: example hostnames, invented servers.

const NO_PLACEMENT = { state: 'unmatched', basis: null, machine: null, candidates: [], hiddenCandidates: 0 }

export function service(id: string, patch: Partial<RunningServiceDto> = {}): RunningServiceDto {
  return {
    id: `coolify:acc1:${id}`,
    name: id,
    kind: 'application',
    sources: ['coolify'],
    state: 'running',
    coolify: { accountId: 'acc1', accountLabel: 'Main Coolify', uuid: `uuid-${id}`, status: 'running:healthy', projectUuid: 'p1', projectName: 'Website', environmentName: 'production', detail: 'ghcr.io/example/app:1.2' },
    server: { uuid: 's1', name: 'edge-1', address: '192.0.2.10' },
    serverBasis: 'deployment',
    placement: { state: 'matched', basis: 'explicit_tag', machine: { id: 'm1', name: 'edge-1' }, candidates: [], hiddenCandidates: 0 },
    containers: [],
    fqdns: [`${id}.example.org`],
    lastDeploy: { deploymentUuid: 'd1', status: 'finished', commit: 'abc1234', at: '2026-10-15T10:00:00Z', stale: false },
    registry: [],
    deepLink: 'https://coolify.example.net/project/p1',
    stale: false,
    staleReasons: [],
    ...patch,
  } as RunningServiceDto
}

export const AVAILABLE = { state: 'available' }

export function coverage(patch: Partial<ServicesCoverageDto> = {}): ServicesCoverageDto {
  return {
    coolify: AVAILABLE,
    accounts: [{ accountId: 'acc1', label: 'Main Coolify', observed: true, recordedAt: 1, staleClasses: [], truncatedClasses: [] }],
    machines: AVAILABLE,
    containers: { state: 'not_configured' },
    registry: AVAILABLE,
    ...patch,
  } as ServicesCoverageDto
}

/** A spread of states: healthy, degraded, stopped, stale, ambiguous, unplaced, docker-only. */
export function sampleServices(): RunningServiceDto[] {
  return [
    service('blog'),
    service('api', { state: 'degraded', coolify: { ...service('api').coolify!, projectName: 'Platform', status: 'running:unhealthy' }, lastDeploy: { deploymentUuid: 'd2', status: 'failed', commit: 'def5678', at: '2026-10-15T11:00:00Z', stale: false } }),
    service('worker', { kind: 'service', state: 'stopped', fqdns: [], lastDeploy: null, coolify: { ...service('worker').coolify!, projectName: 'Platform' } }),
    service('docs', { stale: true, staleReasons: ['coolify_applications_stale', 'fqdns_stale'], server: { uuid: 's2', name: 'edge-2', address: '192.0.2.20' }, placement: { state: 'ambiguous', basis: 'address', machine: null, candidates: [{ id: 'm2', name: 'edge-2a' }, { id: 'm3', name: 'edge-2b' }], hiddenCandidates: 1 } }),
    service('db', { kind: 'database', fqdns: [], lastDeploy: null, server: null, serverBasis: 'unknown', placement: NO_PLACEMENT, coolify: { ...service('db').coolify!, projectName: null, environmentName: null } }),
    { ...service('cache'), id: 'docker:m1:cache', kind: 'container', sources: ['docker'], coolify: null, deepLink: null, fqdns: [], lastDeploy: null } as RunningServiceDto,
  ]
}
