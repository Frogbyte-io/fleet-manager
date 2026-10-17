import { describe, expect, it } from 'vitest'

import type { ServiceEnvVarDto, ServiceHealthDto } from '@frogbyte-io/fleet-api-client'

import {
  blankEnvForm,
  domainsProblem,
  envFlagLabels,
  envFormProblem,
  envSetBody,
  envUnsetBody,
  findEnv,
  healthForm,
  healthPatch,
  lifecycleVerbs,
  parseDomains,
  previewLines,
  requestOutcome,
  settingsFor,
  withCurrentFlags,
} from '../settings'

const SECRET = 'Zq9-never-show-this-7731'

function env(key: string, patch: Partial<ServiceEnvVarDto> = {}): ServiceEnvVarDto {
  return { key, isBuildtime: true, isRuntime: true, isLiteral: false, isMultiline: false, isShownOnce: false, isPreview: false, isShared: false, ...patch }
}

const HEALTH: ServiceHealthDto = {
  enabled: true, path: '/', port: null, host: null, method: 'GET', scheme: 'http', returnCode: 200,
  responseText: null, interval: 5, timeout: 5, retries: 10, startPeriod: 5,
}

describe('lifecycle verbs', () => {
  it('offers redeploy to applications only and nothing to a Docker container', () => {
    expect(lifecycleVerbs('application', true).map(v => v.verb)).toEqual(['start', 'stop', 'restart', 'redeploy'])
    expect(lifecycleVerbs('service', true).map(v => v.verb)).toEqual(['start', 'stop', 'restart'])
    expect(lifecycleVerbs('database', true).map(v => v.verb)).toEqual(['start', 'stop', 'restart'])
    expect(lifecycleVerbs('container', false)).toEqual([])
    expect(lifecycleVerbs('application', false)).toEqual([])
  })

  it('asks before stop and nothing else', () => {
    expect(lifecycleVerbs('application', true).filter(v => v.confirm).map(v => v.verb)).toEqual(['stop'])
  })
})

describe('request outcome', () => {
  it('says what each state means', () => {
    expect(requestOutcome({ state: 'pending', riskClass: 'approve', failure: null }).text).toContain('Waiting for a person')
    expect(requestOutcome({ state: 'succeeded', riskClass: 'approve', failure: null }).tone).toBe('ok')
    expect(requestOutcome({ state: 'failed', riskClass: 'approve', failure: 'the preview is stale' }).text).toBe('the preview is stale')
    expect(requestOutcome({ state: 'denied', riskClass: 'approve', failure: null }).tone).toBe('muted')
  })
})

describe('which settings a resource offers', () => {
  it('gives applications everything, services variables, and the rest nothing', () => {
    expect(settingsFor('application', true)).toEqual({ env: true, domains: true, health: true })
    expect(settingsFor('service', true)).toEqual({ env: true, domains: false, health: false })
    expect(settingsFor('database', true)).toEqual({ env: false, domains: false, health: false })
    expect(settingsFor('container', false)).toEqual({ env: false, domains: false, health: false })
  })
})

describe('environment variables', () => {
  it('shows flags that are on, without build scope for a service', () => {
    expect(envFlagLabels(env('A', { isLiteral: true, isPreview: true }), 'application')).toEqual(['build', 'runtime', 'literal', 'preview'])
    expect(envFlagLabels(env('A', { isLiteral: true }), 'service')).toEqual(['literal'])
  })

  it('takes the flags of an existing variable and never a value', () => {
    const envs = [env('API_URL', { isLiteral: true, isRuntime: false }), env('API_URL', { isPreview: true, isShownOnce: true })]
    expect(findEnv(envs, 'API_URL', true)?.isShownOnce).toBe(true)
    const form = withCurrentFlags({ ...blankEnvForm(), key: 'API_URL' }, envs)
    expect(form).toMatchObject({ literal: true, runtime: false, shownOnce: false, value: '' })
    // What was typed stays; an unknown name changes nothing.
    expect(withCurrentFlags({ ...blankEnvForm(), key: 'API_URL', value: 'typed' }, envs).value).toBe('typed')
    expect(withCurrentFlags({ ...blankEnvForm(), key: 'NEW' }, envs)).toEqual({ ...blankEnvForm(), key: 'NEW' })
  })

  it('refuses what Coolify would refuse', () => {
    const form = { ...blankEnvForm(), key: 'API_URL', value: 'x' }
    expect(envFormProblem(form)).toBeNull()
    expect(envFormProblem({ ...form, key: '' })).toContain('Name')
    expect(envFormProblem({ ...form, key: '1BAD' })).toContain('letters')
    expect(envFormProblem({ ...form, key: 'A-B' })).toContain('letters')
    expect(envFormProblem({ ...form, value: '' })).toContain('write-only')
    expect(envFormProblem({ ...form, value: 'a\u0000b' })).toContain('NUL')
    expect(envFormProblem({ ...form, value: 'x'.repeat(16 * 1024 + 1) })).toContain('16 KiB')
  })

  it('builds the request with the value only in the body of a set', () => {
    const form = { ...blankEnvForm(), key: 'API_URL', value: SECRET, literal: true, redeploy: true, reason: ' rotate ' }
    const body = envSetBody(form, 'application')
    expect(body.redeploy).toBe(true)
    expect(body.reason).toBe('rotate')
    expect(body.changes[0]).toMatchObject({ op: 'set', key: 'API_URL', value: SECRET, isLiteral: true, isPreview: false, isBuildtime: true })
    // A service has no preview or scope flags.
    const service = envSetBody(form, 'service').changes[0]
    expect(service).not.toHaveProperty('isPreview')
    expect(service).not.toHaveProperty('isBuildtime')
    // An unset carries no value at all.
    const unset = envUnsetBody(env('OLD', { isPreview: true }), false, 'drop it')
    expect(unset.changes[0]).toEqual({ op: 'unset', key: 'OLD', isPreview: true })
    expect(JSON.stringify(unset)).not.toContain('value')
  })
})

describe('domains', () => {
  it('reads one URL per line, and commas', () => {
    expect(parseDomains('https://a.example.org\n\n  https://b.example.org , https://c.example.org\n')).toEqual([
      'https://a.example.org', 'https://b.example.org', 'https://c.example.org',
    ])
    expect(parseDomains('')).toEqual([])
  })

  it('names the first problem and refuses a no-op', () => {
    const current = ['https://a.example.org']
    expect(domainsProblem(['https://a.example.org', 'https://b.example.org'], current)).toBeNull()
    expect(domainsProblem([], current)).toBeNull()
    expect(domainsProblem(['a.example.org'], current)).toContain('http')
    expect(domainsProblem(['https://user:pw@a.example.org'], current)).toContain('credentials')
    expect(domainsProblem(['https://a.example.org/x@y'], current)).toBeNull()
    expect(domainsProblem(['https://x.example.org', 'https://X.example.org'], current)).toContain('twice')
    expect(domainsProblem(['https://A.example.org'], current)).toContain('already match')
    expect(domainsProblem(Array.from({ length: 13 }, (_, i) => `https://${i}.example.org`), current)).toContain('At most')
  })
})

describe('health check', () => {
  it('sends only the fields that differ', () => {
    const form = { ...healthForm(HEALTH), path: '/healthz', interval: '30', enabled: false }
    expect(healthPatch(form, HEALTH)).toEqual({ patch: { enabled: false, path: '/healthz', interval: 30 } })
  })

  it('names what is wrong, and a form that changes nothing', () => {
    expect(healthPatch(healthForm(HEALTH), HEALTH)).toEqual({ error: 'Nothing differs from the current health check.' })
    expect('error' in healthPatch({ ...healthForm(HEALTH), path: 'healthz' }, HEALTH)).toBe(true)
    expect('error' in healthPatch({ ...healthForm(HEALTH), port: '70000' }, HEALTH)).toBe(true)
    expect('error' in healthPatch({ ...healthForm(HEALTH), returnCode: '99' }, HEALTH)).toBe(true)
    expect('error' in healthPatch({ ...healthForm(HEALTH), retries: '0' }, HEALTH)).toBe(true)
    expect('error' in healthPatch({ ...healthForm(HEALTH), interval: 'soon' }, HEALTH)).toBe(true)
    expect(healthPatch({ ...healthForm(HEALTH), port: '8080' }, HEALTH)).toEqual({ patch: { port: 8080 } })
  })
})

describe('preview lines', () => {
  it('lists variables by name with their flag changes and a write-only value', () => {
    const lines = previewLines({
      redeploy: true,
      preview: [
        { key: 'API_URL', isPreview: false, operation: 'update', changes: [{ field: 'isLiteral', from: false, to: true }, { field: 'value', from: '(write-only)', to: '(write-only, digest ab12)' }] },
        { key: 'NEW_ONE', isPreview: true, operation: 'create', changes: [{ field: 'isRuntime', from: null, to: true }, { field: 'value', from: null, to: '(write-only, digest cd34)' }] },
        { key: 'OLD', isPreview: false, operation: 'delete', changes: [] },
      ],
    })
    expect(lines).toEqual([
      'update API_URL [value write-only; isLiteral: false → true]',
      'create NEW_ONE (preview) [value write-only]',
      'delete OLD',
      'then redeploy (restart for a service)',
    ])
  })

  it('shows before and after for domains and the health check', () => {
    expect(previewLines({ preview: { changes: [{ field: 'domains', from: ['https://a.example.org'], to: ['https://a.example.org', 'https://b.example.org'] }] } })).toEqual([
      'domains: https://a.example.org → https://a.example.org, https://b.example.org',
    ])
    expect(previewLines({ preview: { changes: [{ field: 'interval', from: 5, to: 30 }, { field: 'port', from: null, to: 8080 }] } })).toEqual([
      'interval: 5 → 30',
      'port: — → 8080',
    ])
    expect(previewLines({})).toEqual([])
    expect(previewLines(null)).toEqual([])
  })
})
