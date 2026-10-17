// The new-site wizard model (FM-1035): pure functions over the generated
// DTOs, no Vue, so every rule is unit-tested directly. The controller decides
// everything that matters (the template pin, the target checks, the policy,
// the approval, the audit); this file only shapes the form, mirrors the
// obvious input rules so a mistake shows before the call, and reads the
// operation result the controller recorded.

import type {
  CoolifyObservationDto,
  CoolifyProjectDto,
  SiteDeployBody,
  SiteTemplateDto,
} from '@frogbyte-io/fleet-api-client'

/** What the person fills in after choosing a template. */
export interface SiteDraft {
  accountId: string
  serverUuid: string
  projectUuid: string
  environmentName: string
  destinationUuid: string
  domain: string
  name: string
  repository: string
  branch: string
  reason: string
}

export function blankDraft(): SiteDraft {
  return {
    accountId: '',
    serverUuid: '',
    projectUuid: '',
    environmentName: '',
    destinationUuid: '',
    domain: '',
    name: '',
    repository: '',
    branch: 'main',
    reason: '',
  }
}

/** A host name, as the controller normalizes one (no path, port, or credentials). */
const HOST = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/

/** The host of a domain field: a bare host or an https URL, lower-cased. */
export function hostOf(domain: string): string {
  return domain.trim().replace(/^https:\/\//i, '').replace(/\/+$/, '').toLowerCase()
}

/** Why a domain cannot be used, or null. */
export function domainProblem(domain: string): string | null {
  const host = hostOf(domain)
  if (host === '')
    return 'Enter the domain the site will answer on.'
  if (/^http:\/\//i.test(domain.trim()))
    return 'Use a bare host name or an https:// URL.'
  if (!HOST.test(host))
    return 'Enter a host name such as blog.example.org (no path, port, or credentials).'
  return null
}

/**
 * Why a destination uuid cannot be used, or null. Coolify has several
 * destinations on a server only in unusual setups, and the observation does
 * not list them, so the console takes the uuid as text (the controller and
 * Coolify check it).
 */
export function destinationProblem(destination: string): string | null {
  const text = destination.trim()
  if (text === '')
    return null
  return /^[A-Za-z0-9_-]{1,64}$/.test(text) ? null : 'A destination uuid is letters, digits, "-" and "_".'
}

/** A resource name: lowercase letters, digits, and `-`. */
export function nameProblem(name: string): string | null {
  if (name.trim() === '')
    return null
  if (!/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/.test(name))
    return 'Use lowercase letters, digits, and "-" (at most 63 characters).'
  return null
}

/** The default resource name for a domain (`blog.example.org` is `blog-example-org`). */
export function defaultName(domain: string): string {
  return hostOf(domain).replace(/[^a-z0-9]/g, '-').replace(/^-+|-+$/g, '').slice(0, 63)
}

/** Why a repository cannot be used, or null. Only public https repositories are offered. */
export function repositoryProblem(repository: string): string | null {
  const text = repository.trim()
  if (text === '')
    return 'Enter the public repository URL.'
  if (!text.startsWith('https://'))
    return 'Use a public https:// repository URL; private repositories are not supported.'
  const rest = text.slice('https://'.length)
  const authority = rest.split(/[/?#]/)[0] ?? ''
  if (authority === '' || authority.includes('@') || !rest.includes('/'))
    return 'Use https://host/owner/repo without credentials.'
  if (/[\s?#`$;&|<>()\\"']/.test(text))
    return 'The repository URL has a character that is not allowed.'
  return null
}

/** Why a branch cannot be used, or null. */
export function branchProblem(branch: string): string | null {
  const ok = /^[A-Za-z0-9._/-]{1,100}$/.test(branch)
    && !/^[-/.]/.test(branch)
    && !branch.includes('..')
    && !/[/.]$/.test(branch)
  return ok ? null : 'Enter a branch name (letters, digits, ".", "_", "-", "/").'
}

/** The first problem that keeps the draft from being filed, or null. */
export function draftProblem(draft: SiteDraft, template: SiteTemplateDto | null): string | null {
  if (!template)
    return 'Choose a template.'
  if (draft.accountId === '')
    return 'Choose a Coolify account.'
  if (draft.serverUuid === '')
    return 'Choose a server.'
  if (draft.projectUuid === '')
    return 'Choose a project.'
  if (draft.environmentName === '')
    return 'Choose an environment.'
  const domain = domainProblem(draft.domain)
  if (domain)
    return domain
  const name = nameProblem(draft.name)
  if (name)
    return name
  const destination = destinationProblem(draft.destinationUuid)
  if (destination)
    return destination
  if (template.needsRepository)
    return repositoryProblem(draft.repository) ?? branchProblem(draft.branch)
  return null
}

/** The request body for a draft; secrets never travel here (a template has none). */
export function buildBody(draft: SiteDraft, template: SiteTemplateDto): SiteDeployBody {
  const body: SiteDeployBody = {
    accountId: draft.accountId,
    templateId: template.id,
    serverUuid: draft.serverUuid,
    projectUuid: draft.projectUuid,
    environmentName: draft.environmentName,
    domain: hostOf(draft.domain),
    reason: draft.reason.trim(),
  }
  if (draft.name.trim() !== '')
    body.name = draft.name.trim()
  if (draft.destinationUuid.trim() !== '')
    body.destinationUuid = draft.destinationUuid.trim()
  if (template.needsRepository) {
    body.repository = draft.repository.trim()
    body.branch = draft.branch.trim()
  }
  return body
}

/** What the template does, in the order Fleet does it. */
export function plannedSteps(template: SiteTemplateDto, domain: string): string[] {
  const host = hostOf(domain) || 'the domain'
  const creates = template.source.kind === 'service'
    ? `Create the ${template.name} service in Coolify`
    : `Create an application from the repository (${template.source.buildPack ?? 'build pack'}, port ${template.source.portsExposes ?? '?'})`
  const steps = [`${creates} and route https://${host} to it`]
  if (template.defaultEnv.length > 0)
    steps.push(`Write ${template.defaultEnv.length} default variable${template.defaultEnv.length === 1 ? '' : 's'}: ${template.defaultEnv.map(e => e.key).join(', ')}`)
  steps.push(template.source.kind === 'service' ? 'Start the service' : 'Queue the first deployment')
  return steps
}

/** The environments of the chosen project. */
export function environmentsOf(observation: CoolifyObservationDto | undefined, projectUuid: string): string[] {
  const project: CoolifyProjectDto | undefined = observation?.projects.find(p => p.uuid === projectUuid)
  return project?.environments.map(e => e.name) ?? []
}

/** What the controller recorded for a finished deployment (a subset of the operation result). */
export interface SiteResult {
  outcome: string
  resourceKind: string
  uuid: string
  serviceId: string
  domain: string
  steps: { step: string, status: string, detail?: string }[]
  deploymentUuid?: string
  deploymentStatus?: string
  followUpEnvKeys: string[]
  error?: string
}

/** Parses an operation's `resultJson`; null when there is none or it is not a site result. */
export function parseResult(resultJson: string | null | undefined): SiteResult | null {
  if (!resultJson)
    return null
  try {
    const value = JSON.parse(resultJson) as Partial<SiteResult>
    if (typeof value.uuid !== 'string' || typeof value.outcome !== 'string' || !Array.isArray(value.steps))
      return null
    return { followUpEnvKeys: [], ...value } as SiteResult
  }
  catch {
    return null
  }
}

/** The `fleetctl registry` commands that record a deployed site, as the CLI prints them. */
export function registryPatch(result: SiteResult): string[] {
  const host = hostOf(result.domain)
  return [
    `fleetctl registry set domain/${host} --field fqdn=${host}`,
    `fleetctl registry relate domain/${host} hosted-on coolify:${result.uuid}`,
  ]
}

function quote(value: string): string {
  return /^[A-Za-z0-9_./:@=+-]+$/.test(value) ? value : `'${value.replace(/'/g, `'\\''`)}'`
}

/** The `fleetctl services deploy` command equivalent to the draft (DESIGN.md: every mutation shows its CLI form). */
export function deployCommand(draft: SiteDraft, template: SiteTemplateDto): string {
  const body = buildBody(draft, template)
  const parts = [
    'fleetctl services deploy',
    `--template ${quote(template.id)}`,
    `--account ${quote(body.accountId)}`,
    `--server ${quote(body.serverUuid)}`,
    `--project ${quote(body.projectUuid)}`,
    `--environment ${quote(body.environmentName)}`,
    `--domain ${quote(body.domain)}`,
  ]
  if (body.name)
    parts.push(`--name ${quote(body.name)}`)
  if (body.destinationUuid)
    parts.push(`--destination ${quote(body.destinationUuid)}`)
  if (body.repository)
    parts.push(`--repo ${quote(body.repository)}`, `--branch ${quote(body.branch ?? '')}`)
  parts.push('--wait-approval')
  return parts.join(' ')
}
