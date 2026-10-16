// The running-services model: pure functions over the generated DTOs, no Vue,
// so grouping, status, and staleness are unit-tested directly. The controller
// does the join (FM-1031); this file only decides how it is shown.

import type {
  AccountCoverageDto,
  InputStateDto,
  RunningServiceDto,
  ServicesCoverageDto,
  ServicesPage,
} from '@frogbyte-io/fleet-api-client'

import type { Tone } from '../fleet/inventory'
import { safeHref } from '../registry/registry'

export const SERVICES_VIEW_KEY = 'fleet-console-services-view'

export type GroupBy = 'none' | 'server' | 'project' | 'source' | 'status'

export const GROUP_LABELS: Record<GroupBy, string> = {
  none: 'None',
  server: 'Server',
  project: 'Coolify project',
  source: 'Source',
  status: 'Status',
}

export const STATUS_FILTERS = ['running', 'degraded', 'stopped', 'unknown', 'stale'] as const
export type StatusFilter = typeof STATUS_FILTERS[number]

export interface ServiceFilters {
  search: string
  /** `any`, `none` (no known server), or a {@link serverKey}. */
  server: string
  /** `any`, `none` (no Coolify project), or a {@link projectKey}. */
  project: string
  /** `any`, `coolify`, or `docker`. */
  source: string
  /** `any` or one of {@link STATUS_FILTERS}. */
  status: string
  /** Only the service with this Coolify resource uuid (a Registry link). */
  uuid: string
}

export const NO_FILTERS: ServiceFilters = { search: '', server: 'any', project: 'any', source: 'any', status: 'any', uuid: '' }

const NONE_KEY = 'none'
const NO_SERVER = 'No known server'
const NO_PROJECT = 'No Coolify project'

export function serverLabel(service: RunningServiceDto): string {
  return service.server?.name ?? NO_SERVER
}

/** Identity of the server: Coolify uuids are only unique per account. */
export function serverKey(service: RunningServiceDto): string {
  return service.server ? `${service.coolify?.accountId ?? ''}:${service.server.uuid}` : NONE_KEY
}

/** Identity of the project and environment, per account. */
export function projectKey(service: RunningServiceDto): string {
  const coolify = service.coolify
  if (!coolify?.projectName)
    return NONE_KEY
  return `${coolify.accountId}:${coolify.projectUuid ?? coolify.projectName}:${coolify.environmentName ?? ''}`
}

export function projectLabel(service: RunningServiceDto): string {
  const project = service.coolify?.projectName
  const environment = service.coolify?.environmentName
  if (!project)
    return NO_PROJECT
  return environment ? `${project} / ${environment}` : project
}

export function sourceLabel(service: RunningServiceDto): string {
  return service.sources.length > 0 ? service.sources.map(s => s.charAt(0).toUpperCase() + s.slice(1)).join(' + ') : 'Unknown'
}

/**
 * The status a service is filed under. Stale data is never filed as healthy:
 * a service that last reported `running` (or nothing) while any input is
 * stale sits under `stale`. A degraded or stopped service keeps that state,
 * stale or not, because the problem is worth seeing either way.
 */
export function effectiveStatus(service: RunningServiceDto): StatusFilter {
  if (service.stale && (service.state === 'running' || service.state === 'unknown'))
    return 'stale'
  return (STATUS_FILTERS as readonly string[]).includes(service.state) ? service.state as StatusFilter : 'unknown'
}

export interface StatusView {
  label: string
  tone: Tone
}

/** The chip for a service: the state in words, with `stale` named when it applies. */
export function statusView(service: RunningServiceDto): StatusView {
  const state = service.state
  if (service.stale)
    return { label: state === 'unknown' ? 'stale' : `${state} · stale`, tone: state === 'degraded' ? 'err' : 'warn' }
  switch (state) {
    case 'running': return { label: 'running', tone: 'ok' }
    case 'degraded': return { label: 'degraded', tone: 'err' }
    case 'stopped': return { label: 'stopped', tone: 'muted' }
    default: return { label: 'unknown', tone: 'faint' }
  }
}

const STALE_REASONS: Record<string, string> = {
  fqdns_stale: 'Hostnames come from an older Coolify read.',
  machine_offline: 'The Fleet machine it runs on is offline.',
  machine_stale: 'The Fleet machine it runs on has stopped reporting recently.',
  containers_stale: 'Container state is out of date.',
  coolify_servers_stale: 'The Coolify server list is out of date, so placement may have moved.',
  state_conflict: 'Coolify and the container disagree; the fresher container state is shown.',
}

/** One sentence per reason code; unknown codes are shown as written. */
export function staleReason(code: string): string {
  const known = STALE_REASONS[code]
  if (known)
    return known
  const match = /^coolify_(.+)_stale$/.exec(code)
  if (match)
    return `The Coolify ${match[1]!.replaceAll('_', ' ')} observation is out of date.`
  return code.replaceAll('_', ' ')
}

export interface PlacementView {
  state: 'matched' | 'ambiguous' | 'unmatched' | 'unknown'
  label: string
  detail: string
  tone: Tone
  machine: { id: string, name: string } | null
  candidates: { id: string, name: string }[]
}

const BASIS: Record<string, string> = { explicit_tag: 'explicit tag', address: 'address', container: 'container' }

/** Where it sits on Fleet machines; ambiguity is shown as ambiguity, never resolved. */
export function placementView(service: RunningServiceDto): PlacementView {
  const { placement } = service
  const basis = placement.basis ? BASIS[placement.basis] ?? placement.basis : null
  switch (placement.state) {
    case 'matched':
      return {
        state: 'matched',
        label: placement.machine?.name ?? 'Matched machine',
        detail: basis ? `matched by ${basis}` : 'matched',
        tone: 'ok',
        machine: placement.machine ?? null,
        candidates: [],
      }
    case 'ambiguous': {
      const hidden = placement.hiddenCandidates
      const names = placement.candidates.map(c => c.name)
      const more = hidden > 0 ? `${names.length > 0 ? ' and ' : ''}${hidden} more you cannot read` : ''
      return {
        state: 'ambiguous',
        label: 'Ambiguous placement',
        detail: `fits ${names.join(', ')}${more}${basis ? ` by ${basis}` : ''}; none chosen`,
        tone: 'warn',
        machine: null,
        candidates: placement.candidates,
      }
    }
    case 'unmatched':
      return { state: 'unmatched', label: 'Not on a Fleet machine', detail: 'no Fleet machine matches its server', tone: 'muted', machine: null, candidates: [] }
    default:
      return { state: 'unknown', label: 'Placement unknown', detail: 'no server could be determined', tone: 'faint', machine: null, candidates: [] }
  }
}

const SERVER_BASIS: Record<string, string> = {
  deployment: 'from its latest deployment',
  container: 'from its container',
  sole_server: 'the only Coolify server',
  unknown: 'not determined',
}

export function serverBasisLabel(basis: string): string {
  return SERVER_BASIS[basis] ?? basis.replaceAll('_', ' ')
}

export interface DeployView {
  label: string
  tone: Tone
  failed: boolean
}

const FAILED_DEPLOY = /fail|error|cancel/i
const RUNNING_DEPLOY = /progress|queued|running|building/i
const OK_DEPLOY = /finish|success|succeed/i

/** Coolify's deployment status in words; stale data is labelled, never shown as a clean pass. */
export function deployView(service: RunningServiceDto): DeployView | null {
  const deploy = service.lastDeploy
  if (!deploy)
    return null
  const failed = FAILED_DEPLOY.test(deploy.status)
  const tone: Tone = failed ? 'err' : RUNNING_DEPLOY.test(deploy.status) ? 'info' : OK_DEPLOY.test(deploy.status) ? 'ok' : 'muted'
  const label = deploy.status.replaceAll('_', ' ')
  return deploy.stale
    ? { label: `${label} · stale`, tone: tone === 'ok' ? 'warn' : tone, failed }
    : { label, tone, failed }
}

export function matchesFilters(service: RunningServiceDto, filters: ServiceFilters): boolean {
  // Registry relations match the uuid case-insensitively (FM-1031).
  if (filters.uuid && service.coolify?.uuid.toLowerCase() !== filters.uuid.toLowerCase())
    return false
  if (filters.search) {
    const needle = filters.search.toLowerCase()
    const text = [service.name, service.coolify?.detail ?? '', ...service.fqdns].join(' ').toLowerCase()
    if (!text.includes(needle))
      return false
  }
  if (filters.server !== 'any' && serverKey(service) !== filters.server)
    return false
  if (filters.project !== 'any' && projectKey(service) !== filters.project)
    return false
  if (filters.source !== 'any' && !service.sources.includes(filters.source))
    return false
  if (filters.status !== 'any' && effectiveStatus(service) !== filters.status)
    return false
  return true
}

export function sortServices(services: RunningServiceDto[]): RunningServiceDto[] {
  return [...services].sort((a, b) => a.name.localeCompare(b.name) || a.id.localeCompare(b.id))
}

export interface ServiceGroup {
  key: string
  name: string
  services: RunningServiceDto[]
}

function groupKey(service: RunningServiceDto, by: GroupBy): string {
  switch (by) {
    case 'server': return serverKey(service)
    case 'project': return projectKey(service)
    case 'source': return sourceLabel(service)
    case 'status': return effectiveStatus(service)
    default: return ''
  }
}

const STATUS_ORDER: Record<string, number> = { degraded: 0, stopped: 1, stale: 2, unknown: 3, running: 4 }

/**
 * Groups in a stable order: problems first for status, the "no X" bucket
 * last for server and project, names alphabetical otherwise.
 */
export function groupServices(services: RunningServiceDto[], by: GroupBy): ServiceGroup[] {
  const sorted = sortServices(services)
  if (by === 'none')
    return [{ key: '', name: '', services: sorted }]
  const map = new Map<string, RunningServiceDto[]>()
  for (const service of sorted) {
    const key = groupKey(service, by)
    const list = map.get(key) ?? []
    list.push(service)
    map.set(key, list)
  }
  const label = (key: string, first: RunningServiceDto): string =>
    by === 'server' ? serverLabel(first) : by === 'project' ? projectLabel(first) : key
  return [...map.entries()]
    .map(([key, list]) => ({ key, name: label(key, list[0]!), services: list }))
    .sort((a, b) => {
      if (by === 'status')
        return (STATUS_ORDER[a.key] ?? 9) - (STATUS_ORDER[b.key] ?? 9)
      return Number(a.key === NONE_KEY) - Number(b.key === NONE_KEY) || a.name.localeCompare(b.name) || a.key.localeCompare(b.key)
    })
}

export interface FilterOption {
  key: string
  label: string
}

export interface FilterOptions {
  servers: FilterOption[]
  projects: FilterOption[]
  noServer: boolean
  noProject: boolean
}

function options(entries: Map<string, string>): FilterOption[] {
  const counts = new Map<string, number>()
  for (const label of entries.values())
    counts.set(label, (counts.get(label) ?? 0) + 1)
  return [...entries]
    // Two servers or projects that share a name (different accounts) stay apart by their key.
    .map(([key, label]) => ({ key, label: (counts.get(label) ?? 0) > 1 ? `${label} (${key.split(':')[0]})` : label }))
    .sort((a, b) => a.label.localeCompare(b.label) || a.key.localeCompare(b.key))
}

/** The servers and projects present, one entry per identity. */
export function filterOptions(services: RunningServiceDto[]): FilterOptions {
  const servers = new Map<string, string>()
  const projects = new Map<string, string>()
  for (const service of services) {
    if (service.server)
      servers.set(serverKey(service), serverLabel(service))
    if (projectKey(service) !== NONE_KEY)
      projects.set(projectKey(service), projectLabel(service))
  }
  return {
    servers: options(servers),
    projects: options(projects),
    noServer: services.some(s => !s.server),
    noProject: services.some(s => projectKey(s) === NONE_KEY),
  }
}

/** A `?status=` value that names a real status filter, else `any`. */
export function statusFromQuery(value: unknown): string {
  return typeof value === 'string' && (STATUS_FILTERS as readonly string[]).includes(value) ? value : 'any'
}

export function statusCounts(services: RunningServiceDto[]): Record<StatusFilter, number> {
  const counts: Record<StatusFilter, number> = { running: 0, degraded: 0, stopped: 0, unknown: 0, stale: 0 }
  for (const service of services)
    counts[effectiveStatus(service)] += 1
  return counts
}

/** A hostname as an external link when it is a plain http(s) URL or bare host, else plain text. */
export function fqdnHref(fqdn: string): string | null {
  return safeHref(/^[a-z][a-z0-9+.-]*:/i.test(fqdn) ? fqdn : `https://${fqdn}`)
}

export interface CoverageNote {
  key: string
  tone: 'warn' | 'info'
  text: string
}

function inputNote(key: string, name: string, state: InputStateDto, notConfigured: string): CoverageNote | null {
  switch (state.state) {
    case 'available': return null
    case 'not_configured': return { key, tone: 'info', text: notConfigured }
    case 'denied': return { key, tone: 'warn', text: `${name} are left out: you may not read them.` }
    default: return { key, tone: 'warn', text: `${name} are unavailable${state.detail ? `: ${state.detail}` : ''}; services may be missing.` }
  }
}

function accountNotes(accounts: AccountCoverageDto[]): CoverageNote[] {
  const notes: CoverageNote[] = []
  for (const account of accounts) {
    if (!account.observed) {
      notes.push({ key: `account:${account.accountId}:unobserved`, tone: 'warn', text: `Coolify account ${account.label} has never been discovered, so it contributes no services.` })
      continue
    }
    if (account.staleClasses.length > 0)
      notes.push({ key: `account:${account.accountId}:stale`, tone: 'warn', text: `Coolify account ${account.label}: ${account.staleClasses.join(', ')} are out of date.` })
    if (account.truncatedClasses.length > 0)
      notes.push({ key: `account:${account.accountId}:truncated`, tone: 'warn', text: `Coolify account ${account.label}: ${account.truncatedClasses.join(', ')} were cut to fit the snapshot bound; some services may be missing.` })
  }
  return notes
}

/** What the answer was built from, as honest notes; empty means every input was fully available. */
export function coverageNotes(coverage: ServicesCoverageDto, ambiguousServerCount = 0): CoverageNote[] {
  const notes = [
    inputNote('coolify', 'Coolify observations', coverage.coolify, 'No Coolify account is configured, so no Coolify services are listed.'),
    ...accountNotes(coverage.accounts),
    inputNote('machines', 'Fleet machines', coverage.machines, 'No Fleet machines are registered, so no service is placed on one.'),
    inputNote('containers', 'Docker containers', coverage.containers, 'Docker containers are not collected yet (the container inventory is not configured). Services are listed from Coolify only, and container state is not shown.'),
    inputNote('registry', 'Registry entries', coverage.registry, 'No Registry revision is active, so services show no related entries.'),
  ].filter((note): note is CoverageNote => note !== null)
  if (ambiguousServerCount > 0)
    notes.push({ key: 'ambiguous-servers', tone: 'warn', text: `${ambiguousServerCount} Coolify ${ambiguousServerCount === 1 ? 'server matches' : 'servers match'} more than one Fleet machine; their services are shown with ambiguous placement.` })
  return notes
}

export type ServicesData = Pick<ServicesPage, 'ambiguousServers' | 'coverage' | 'evaluatedAt'> & { items: RunningServiceDto[], truncated: boolean }

/** Where a Registry entry linked from a service opens in the console. */
export function registryLinkTo(link: { type: string, key: string }): { path: string, query: Record<string, string> } {
  if (link.type === 'domain')
    return { path: '/registry/domains', query: { open: link.key } }
  if (link.type === 'service')
    return { path: '/registry/services', query: { entry: link.key } }
  return { path: '/registry', query: { type: link.type, entry: link.key } }
}

export function detailPath(id: string): string {
  return `/services/${encodeURIComponent(id)}`
}
