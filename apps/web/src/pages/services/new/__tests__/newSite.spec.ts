import type { SiteTemplateDto } from '@frogbyte-io/fleet-api-client'
import { describe, expect, it } from 'vitest'

import {
  blankDraft,
  branchProblem,
  buildBody,
  defaultName,
  deployCommand,
  domainProblem,
  draftProblem,
  environmentsOf,
  hostOf,
  parseResult,
  plannedSteps,
  registryPatch,
  repositoryProblem,
} from '../newSite'

const GHOST: SiteTemplateDto = {
  id: 'ghost',
  version: 1,
  digest: 'a'.repeat(64),
  name: 'Ghost',
  description: 'A Ghost site',
  source: { kind: 'service', serviceType: 'ghost' },
  needsRepository: false,
  defaultEnv: [],
  followUpEnvKeys: [],
}

const NODE: SiteTemplateDto = {
  id: 'node-app',
  version: 1,
  digest: 'b'.repeat(64),
  name: 'Node.js app',
  description: 'A Node app',
  source: { kind: 'git', buildPack: 'nixpacks', portsExposes: 3000 },
  needsRepository: true,
  defaultEnv: [{ key: 'NODE_ENV', value: 'production' }, { key: 'PORT', value: '3000' }],
  followUpEnvKeys: ['API_KEY'],
}

function filled(patch: Partial<ReturnType<typeof blankDraft>> = {}) {
  return {
    ...blankDraft(),
    accountId: 'acc1',
    serverUuid: 'srv1',
    projectUuid: 'proj1',
    environmentName: 'production',
    domain: 'Blog.Example.Org',
    ...patch,
  }
}

describe('domain, name, repository, and branch rules', () => {
  it('accepts a bare host or an https URL and refuses the rest', () => {
    expect(domainProblem('blog.example.org')).toBeNull()
    expect(domainProblem('https://Blog.Example.org/')).toBeNull()
    expect(domainProblem('')).toMatch(/Enter the domain/)
    for (const bad of ['http://blog.example.org', 'blog.example.org/path', 'blog.example.org:8080', 'user@blog.example.org', 'localhost', 'not a host'])
      expect(domainProblem(bad), bad).not.toBeNull()
    expect(hostOf(' https://Blog.Example.org/ ')).toBe('blog.example.org')
    expect(defaultName('blog.example.org')).toBe('blog-example-org')
  })

  it('offers only public https repositories', () => {
    expect(repositoryProblem('https://github.com/owner/site')).toBeNull()
    for (const bad of ['', 'http://example.org/o/r', 'https://user:pw@example.org/o/r', 'ssh://example.org/o/r', 'https://example.org', 'https://example.org/o/r?x=1', 'https://example.org/o/r;rm'])
      expect(repositoryProblem(bad), bad).not.toBeNull()
    expect(branchProblem('main')).toBeNull()
    expect(branchProblem('release/1.2')).toBeNull()
    for (const bad of ['', '-x', '--upload-pack=x', 'a..b', 'a b', '/x'])
      expect(branchProblem(bad), bad).not.toBeNull()
  })
})

describe('the draft', () => {
  it('names the first missing piece in order', () => {
    expect(draftProblem(blankDraft(), null)).toMatch(/template/)
    expect(draftProblem(blankDraft(), GHOST)).toMatch(/account/)
    expect(draftProblem(filled({ serverUuid: '' }), GHOST)).toMatch(/server/)
    expect(draftProblem(filled({ projectUuid: '' }), GHOST)).toMatch(/project/)
    expect(draftProblem(filled({ environmentName: '' }), GHOST)).toMatch(/environment/)
    expect(draftProblem(filled({ domain: '' }), GHOST)).toMatch(/domain/)
    expect(draftProblem(filled(), GHOST)).toBeNull()
  })

  it('requires a repository and branch only for a Git template', () => {
    expect(draftProblem(filled(), NODE)).toMatch(/repository/)
    expect(draftProblem(filled({ repository: 'https://example.org/o/r' }), NODE)).toBeNull()
    expect(draftProblem(filled({ repository: 'https://example.org/o/r', branch: '' }), NODE)).toMatch(/branch/)
  })

  it('builds the request body and the equivalent command', () => {
    const body = buildBody(filled({ reason: ' launch ' }), GHOST)
    expect(body).toEqual({
      accountId: 'acc1',
      templateId: 'ghost',
      serverUuid: 'srv1',
      projectUuid: 'proj1',
      environmentName: 'production',
      domain: 'blog.example.org',
      reason: 'launch',
    })
    const git = buildBody(filled({ repository: 'https://example.org/o/r', name: 'site' }), NODE)
    expect(git.repository).toBe('https://example.org/o/r')
    expect(git.branch).toBe('main')
    expect(git.name).toBe('site')
    expect(deployCommand(filled(), GHOST)).toBe(
      'fleetctl services deploy --template ghost --account acc1 --server srv1 --project proj1 --environment production --domain blog.example.org --wait-approval',
    )
    expect(deployCommand(filled({ repository: 'https://example.org/o/r' }), NODE)).toContain('--repo https://example.org/o/r --branch main')
  })
})

describe('what the template does', () => {
  it('lists the steps in order, with default variables only when there are some', () => {
    const service = plannedSteps(GHOST, 'blog.example.org')
    expect(service).toHaveLength(2)
    expect(service[0]).toContain('https://blog.example.org')
    expect(service[1]).toBe('Start the service')
    const git = plannedSteps(NODE, 'app.example.org')
    expect(git).toHaveLength(3)
    expect(git[1]).toContain('NODE_ENV, PORT')
    expect(git[2]).toBe('Queue the first deployment')
  })

  it('reads the environments of the chosen project', () => {
    const observation = {
      projects: [{ uuid: 'proj1', name: 'sites', description: '', detailsStale: false, environments: [{ id: 1, name: 'production', description: '' }, { id: 2, name: 'staging', description: '' }] }],
    } as never
    expect(environmentsOf(observation, 'proj1')).toEqual(['production', 'staging'])
    expect(environmentsOf(observation, 'other')).toEqual([])
    expect(environmentsOf(undefined, 'proj1')).toEqual([])
  })
})

describe('the recorded result', () => {
  const result = JSON.stringify({
    outcome: 'deployed', resourceKind: 'service', uuid: 'svc1', serviceId: 'coolify:acc1:svc1',
    domain: 'https://blog.example.org', steps: [{ step: 'create', status: 'done' }],
  })

  it('parses a site result and the registry patch matches the CLI', () => {
    const parsed = parseResult(result)!
    expect(parsed.uuid).toBe('svc1')
    expect(parsed.followUpEnvKeys).toEqual([])
    expect(registryPatch(parsed)).toEqual([
      'fleetctl registry set domain/blog.example.org --field fqdn=blog.example.org',
      'fleetctl registry relate domain/blog.example.org hosted-on coolify:svc1',
    ])
  })

  it('ignores anything else', () => {
    expect(parseResult(null)).toBeNull()
    expect(parseResult('not json')).toBeNull()
    expect(parseResult('{"outcome":"x"}')).toBeNull()
  })
})
