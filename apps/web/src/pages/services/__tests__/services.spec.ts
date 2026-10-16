import { describe, expect, it } from 'vitest'

import {
  coverageNotes,
  deployView,
  detailPath,
  effectiveStatus,
  filterOptions,
  fqdnHref,
  groupServices,
  matchesFilters,
  NO_FILTERS,
  placementView,
  registryLinkTo,
  staleReason,
  statusFromQuery,
  statusCounts,
  statusView,
} from '../services'
import { coverage, sampleServices, service } from './fixtures'

const by = (name: string) => sampleServices().find(s => s.name === name)!

describe('status and staleness', () => {
  it('shows stale data as stale, never as healthy', () => {
    expect(statusView(by('blog'))).toEqual({ label: 'running', tone: 'ok' })
    expect(statusView(by('docs'))).toEqual({ label: 'running · stale', tone: 'warn' })
    expect(statusView(service('x', { state: 'unknown', stale: true }))).toEqual({ label: 'stale', tone: 'warn' })
    expect(statusView(service('x', { state: 'degraded', stale: true }))).toMatchObject({ tone: 'err' })
    expect(statusView(by('api'))).toEqual({ label: 'degraded', tone: 'err' })
    expect(statusView(by('worker'))).toEqual({ label: 'stopped', tone: 'muted' })
    expect(statusView(service('x', { state: 'unknown' }))).toEqual({ label: 'unknown', tone: 'faint' })
  })

  it('files stale running services under stale and keeps real problems visible', () => {
    expect(effectiveStatus(by('docs'))).toBe('stale')
    expect(effectiveStatus(service('x', { state: 'degraded', stale: true }))).toBe('degraded')
    expect(effectiveStatus(service('x', { state: 'weird' }))).toBe('unknown')
    expect(statusCounts(sampleServices())).toEqual({ running: 3, degraded: 1, stopped: 1, unknown: 0, stale: 1 })
  })

  it('explains stale reasons in words', () => {
    expect(staleReason('fqdns_stale')).toContain('Hostnames')
    expect(staleReason('coolify_applications_stale')).toBe('The Coolify applications observation is out of date.')
    expect(staleReason('state_conflict')).toContain('disagree')
    expect(staleReason('odd_code')).toBe('odd code')
  })
})

describe('placement', () => {
  it('names the machine and how it matched', () => {
    expect(placementView(by('blog'))).toMatchObject({ state: 'matched', label: 'edge-1', detail: 'matched by explicit tag', tone: 'ok' })
  })

  it('shows ambiguity as ambiguity, with hidden candidates counted and none chosen', () => {
    const view = placementView(by('docs'))
    expect(view).toMatchObject({ state: 'ambiguous', label: 'Ambiguous placement', tone: 'warn', machine: null })
    expect(view.detail).toBe('fits edge-2a, edge-2b and 1 more you cannot read by address; none chosen')
    expect(view.candidates.map(c => c.id)).toEqual(['m2', 'm3'])
  })

  it('says unmatched and unknown plainly', () => {
    expect(placementView(by('db'))).toMatchObject({ state: 'unmatched', tone: 'muted' })
    expect(placementView(service('x', { placement: { state: 'unknown', basis: null, candidates: [], hiddenCandidates: 0 } }))).toMatchObject({ state: 'unknown', tone: 'faint' })
  })
})

describe('deploys', () => {
  const deploy = (status: string, stale = false) => service('x', { lastDeploy: { deploymentUuid: 'd', status, stale } })
  it('classifies the latest deployment and labels stale ones', () => {
    expect(deployView(service('x', { lastDeploy: null }))).toBeNull()
    expect(deployView(deploy('finished'))).toEqual({ label: 'finished', tone: 'ok', failed: false })
    expect(deployView(deploy('failed'))).toEqual({ label: 'failed', tone: 'err', failed: true })
    expect(deployView(deploy('in_progress'))).toMatchObject({ tone: 'info', failed: false })
    expect(deployView(deploy('finished', true))).toEqual({ label: 'finished · stale', tone: 'warn', failed: false })
  })
})

describe('filtering', () => {
  const names = (filters: Partial<typeof NO_FILTERS>) => sampleServices().filter(s => matchesFilters(s, { ...NO_FILTERS, ...filters })).map(s => s.name).sort()

  it('filters by source, server, project, and status', () => {
    expect(names({})).toHaveLength(6)
    expect(names({ source: 'docker' })).toEqual(['cache'])
    expect(names({ source: 'coolify' })).toHaveLength(5)
    expect(names({ server: 'acc1:s2' })).toEqual(['docs'])
    expect(names({ server: 'none' })).toEqual(['cache', 'db'])
    expect(names({ project: 'acc1:p-Platform:production' })).toEqual(['api', 'worker'])
    expect(names({ project: 'none' })).toEqual(['cache', 'db'])
    expect(names({ status: 'degraded' })).toEqual(['api'])
    expect(names({ status: 'stale' })).toEqual(['docs'])
    // One meaning of stale: the filter and the count agree, and a stale degraded service stays degraded.
    const staleDegraded = service('sd', { state: 'degraded', stale: true })
    expect(matchesFilters(staleDegraded, { ...NO_FILTERS, status: 'stale' })).toBe(false)
    expect(matchesFilters(staleDegraded, { ...NO_FILTERS, status: 'degraded' })).toBe(true)
    expect(names({ status: 'running' })).toEqual(['blog', 'cache', 'db'])
  })

  it('searches name, image, and hostname, and narrows to a Coolify uuid', () => {
    expect(names({ search: 'DOCS.example' })).toEqual(['docs'])
    expect(names({ search: 'ghcr.io/example' })).toHaveLength(5)
    expect(names({ uuid: 'uuid-api' })).toEqual(['api'])
    expect(names({ uuid: 'UUID-API' })).toEqual(['api'])
  })

  it('keeps same-named servers from different accounts apart', () => {
    const other = service('o', { coolify: { ...service('o').coolify!, accountId: 'acc2' } })
    const opts = filterOptions([service('a'), other])
    expect(opts.servers.map(o => [o.key, o.label])).toEqual([['acc1:s1', 'edge-1 (acc1)'], ['acc2:s1', 'edge-1 (acc2)']])
    expect(matchesFilters(other, { ...NO_FILTERS, server: 'acc1:s1' })).toBe(false)
    expect(groupServices([service('a'), other], 'server')).toHaveLength(2)
  })

  it('validates a status from the query', () => {
    expect(statusFromQuery('degraded')).toBe('degraded')
    expect(statusFromQuery('bogus')).toBe('any')
    expect(statusFromQuery(['x'])).toBe('any')
  })

  it('offers the servers and projects present', () => {
    expect(filterOptions(sampleServices())).toEqual({
      servers: [{ key: 'acc1:s1', label: 'edge-1' }, { key: 'acc1:s2', label: 'edge-2' }],
      projects: [{ key: 'acc1:p-Platform:production', label: 'Platform / production' }, { key: 'acc1:p-Website:production', label: 'Website / production' }],
      noServer: true,
      noProject: true,
    })
  })
})

describe('grouping', () => {
  const grouped = (mode: Parameters<typeof groupServices>[1]) => groupServices(sampleServices(), mode).map(g => [g.name, g.services.map(s => s.name)])

  it('does not group when asked not to, ordered by name', () => {
    expect(grouped('none')).toEqual([['', ['api', 'blog', 'cache', 'db', 'docs', 'worker']]])
  })

  it('groups by server with the no-server bucket last', () => {
    expect(grouped('server')).toEqual([
      ['edge-1', ['api', 'blog', 'worker']],
      ['edge-2', ['docs']],
      ['No known server', ['cache', 'db']],
    ])
  })

  it('groups by Coolify project and environment', () => {
    expect(grouped('project')).toEqual([
      ['Platform / production', ['api', 'worker']],
      ['Website / production', ['blog', 'docs']],
      ['No Coolify project', ['cache', 'db']],
    ])
  })

  it('groups by source and by status with problems first', () => {
    expect(grouped('source')).toEqual([['Coolify', ['api', 'blog', 'db', 'docs', 'worker']], ['Docker', ['cache']]])
    expect(grouped('status')).toEqual([
      ['degraded', ['api']],
      ['stopped', ['worker']],
      ['stale', ['docs']],
      ['running', ['blog', 'cache', 'db']],
    ])
  })
})

describe('coverage', () => {
  it('is honest that containers are not collected yet', () => {
    const notes = coverageNotes(coverage())
    expect(notes).toHaveLength(1)
    expect(notes[0]).toMatchObject({ key: 'containers', tone: 'info' })
    expect(notes[0]!.text).toContain('not collected yet')
  })

  it('names denied, unavailable, unobserved, stale, truncated, and ambiguous inputs', () => {
    const notes = coverageNotes(coverage({
      coolify: { state: 'unavailable', detail: 'the snapshot could not be read' },
      machines: { state: 'denied' },
      containers: { state: 'available' },
      accounts: [
        { accountId: 'a', label: 'Main', observed: false, recordedAt: null, staleClasses: [], truncatedClasses: [] },
        { accountId: 'b', label: 'Side', observed: true, recordedAt: 1, staleClasses: ['servers'], truncatedClasses: ['applications'] },
      ],
    }), 2)
    expect(notes.map(n => n.text)).toEqual([
      'Coolify observations are unavailable: the snapshot could not be read; services may be missing.',
      'Coolify account Main has never been discovered, so it contributes no services.',
      'Coolify account Side: servers are out of date.',
      'Coolify account Side: applications were cut to fit the snapshot bound; some services may be missing.',
      'Fleet machines are left out: you may not read them.',
      '2 Coolify servers match more than one Fleet machine; their services are shown with ambiguous placement.',
    ])
  })
})

describe('links', () => {
  it('links hostnames only when they are http(s)', () => {
    expect(fqdnHref('app.example.org')).toBe('https://app.example.org/')
    expect(fqdnHref('http://app.example.org')).toBe('http://app.example.org/')
    expect(fqdnHref('javascript:alert(1)')).toBeNull()
  })

  it('opens registry entries in their view and details by encoded id', () => {
    expect(registryLinkTo({ type: 'domain', key: 'example.org' })).toEqual({ path: '/registry/domains', query: { open: 'example.org' } })
    expect(registryLinkTo({ type: 'service', key: 'aptabase' })).toEqual({ path: '/registry/services', query: { entry: 'aptabase' } })
    expect(registryLinkTo({ type: 'vendor', key: 'x' })).toEqual({ path: '/registry', query: { type: 'vendor', entry: 'x' } })
    expect(detailPath('coolify:a:b')).toBe('/services/coolify%3Aa%3Ab')
  })
})
