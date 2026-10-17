import { QueryClient, VueQueryPlugin } from '@tanstack/vue-query'
import { enableAutoUnmount, flushPromises, mount } from '@vue/test-utils'
import { createMemoryHistory, createRouter } from 'vue-router'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const listSiteTemplates = vi.fn()
const listExternalAccounts = vi.fn()
const getCoolifyObservations = vi.fn()
const requestSiteDeployment = vi.fn()
const getActionRequest = vi.fn()
const getOperation = vi.fn()

vi.mock('@frogbyte-io/fleet-api-client', () => ({
  listSiteTemplates: (...a: unknown[]) => listSiteTemplates(...a),
  listExternalAccounts: (...a: unknown[]) => listExternalAccounts(...a),
  getCoolifyObservations: (...a: unknown[]) => getCoolifyObservations(...a),
  requestSiteDeployment: (...a: unknown[]) => requestSiteDeployment(...a),
  getActionRequest: (...a: unknown[]) => getActionRequest(...a),
  getOperation: (...a: unknown[]) => getOperation(...a),
}))

import { routes } from '@/router'
import NewSitePage from '../NewSitePage.vue'

function ok<T>(data: T, status = 200) {
  return { status, data: { data }, headers: new Headers() }
}

const TEMPLATES = {
  templates: [
    { id: 'ghost', version: 1, digest: 'a'.repeat(64), name: 'Ghost', description: 'A Ghost site', source: { kind: 'service', serviceType: 'ghost' }, needsRepository: false, defaultEnv: [], followUpEnvKeys: [] },
    { id: 'node-app', version: 1, digest: 'b'.repeat(64), name: 'Node.js app', description: 'A Node app', source: { kind: 'git', buildPack: 'nixpacks', portsExposes: 3000 }, needsRepository: true, defaultEnv: [{ key: 'NODE_ENV', value: 'production' }], followUpEnvKeys: [] },
  ],
}

const OBSERVATION = {
  accountId: 'acc1',
  servers: [{ uuid: 'srv1', name: 'edge-1', address: '192.0.2.10', description: '' }],
  projects: [{ uuid: 'proj1', name: 'sites', description: '', detailsStale: false, environments: [{ id: 1, name: 'production', description: '' }, { id: 2, name: 'staging', description: '' }] }],
  applications: [], services: [], databases: [], deployments: [], classes: [], warnings: [], evaluatedAt: 1, recordedAt: 1,
}

function filedRequest(patch: Record<string, unknown> = {}) {
  return {
    id: 'req-1', requester: 'anonymous-lan-admin', origin: 'api', actionId: 'coolify.site.deploy',
    target: 'site:acc1:blog.example.org', parameters: {}, riskClass: 'approve', reason: 'why',
    state: 'pending', terminal: false, decidedBy: null, decidedAt: null, decisionNote: null,
    operationId: null, failure: null, createdAt: 1, expiresAt: 2, updatedAt: 3, ...patch,
  }
}

async function mountPage() {
  const router = createRouter({ history: createMemoryHistory(), routes })
  await router.push('/services/new')
  await router.isReady()
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity }, mutations: { retry: false } } })
  const wrapper = mount(NewSitePage, { global: { plugins: [[VueQueryPlugin, { queryClient }], router] } })
  await flushPromises()
  await flushPromises()
  return wrapper
}

enableAutoUnmount(afterEach)

beforeEach(() => {
  for (const mock of [listSiteTemplates, listExternalAccounts, getCoolifyObservations, requestSiteDeployment, getActionRequest, getOperation])
    mock.mockReset()
  listSiteTemplates.mockResolvedValue(ok(TEMPLATES))
  listExternalAccounts.mockResolvedValue({ status: 200, data: { items: [{ id: 'acc1', kind: 'coolify', label: 'prod' }], page: {} }, headers: new Headers() })
  getCoolifyObservations.mockResolvedValue(ok(OBSERVATION))
})

async function toTarget(wrapper: Awaited<ReturnType<typeof mountPage>>, template = 'ghost') {
  await wrapper.get(`[data-testid="template-${template}"]`).trigger('click')
  await wrapper.get('[data-testid="next"]').trigger('click')
  await flushPromises()
}

async function fillTarget(wrapper: Awaited<ReturnType<typeof mountPage>>) {
  await wrapper.get('[data-testid="server"]').setValue('srv1')
  await wrapper.get('[data-testid="project"]').setValue('proj1')
  await flushPromises()
  await wrapper.get('[data-testid="domain"]').setValue('blog.example.org')
}

describe('the route', () => {
  it('is reachable before the service detail route', async () => {
    const router = createRouter({ history: createMemoryHistory(), routes })
    await router.push('/services/new')
    expect(router.currentRoute.value.meta.title).toBe('Deploy a site')
  })
})

describe('choosing a template', () => {
  it('lists the templates and only moves on once one is chosen', async () => {
    const wrapper = await mountPage()
    expect(wrapper.get('[data-testid="template-ghost"]').text()).toContain('one-click service')
    expect(wrapper.get('[data-testid="template-node-app"]').text()).toContain('git repository')
    expect(wrapper.get('[data-testid="next"]').attributes('disabled')).toBeDefined()
    await wrapper.get('[data-testid="template-ghost"]').trigger('click')
    expect(wrapper.get('[data-testid="template-ghost"]').attributes('aria-checked')).toBe('true')
    expect(wrapper.get('[data-testid="next"]').attributes('disabled')).toBeUndefined()
  })

  it('says so when the templates cannot be loaded', async () => {
    listSiteTemplates.mockResolvedValue({ status: 403, data: { code: 'denied', message: 'not allowed' }, headers: new Headers() })
    const wrapper = await mountPage()
    expect(wrapper.get('[data-testid="templates-error"]').text()).toContain('not allowed')
  })
})

describe('the target', () => {
  it('fills servers, projects, and environments from the observation, and guards the domain', async () => {
    const wrapper = await mountPage()
    await toTarget(wrapper)
    // One account: nothing to choose, and it is read at once.
    expect(wrapper.find('[data-testid="account"]').exists()).toBe(false)
    expect(getCoolifyObservations).toHaveBeenCalledWith('acc1')
    expect(wrapper.get('[data-testid="server"]').text()).toContain('edge-1')
    await wrapper.get('[data-testid="project"]').setValue('proj1')
    await flushPromises()
    // The production environment is preselected.
    expect((wrapper.get('[data-testid="environment"]').element as HTMLSelectElement).value).toBe('production')
    await wrapper.get('[data-testid="domain"]').setValue('http://nope')
    expect(wrapper.get('[data-testid="domain-problem"]').text()).toMatch(/bare host name or an https/)
    await wrapper.get('[data-testid="next"]').trigger('click')
    expect(wrapper.find('[data-testid="step-review"]').exists()).toBe(false)
    expect(wrapper.find('[data-testid="target-problem"]').exists()).toBe(true)
  })

  it('asks for a public repository and branch only for a Git template', async () => {
    const wrapper = await mountPage()
    await toTarget(wrapper, 'node-app')
    expect(wrapper.find('[data-testid="repository"]').exists()).toBe(true)
    await wrapper.get('[data-testid="repository"]').setValue('ssh://example.org/o/r')
    expect(wrapper.get('[data-testid="repository-problem"]').text()).toMatch(/public https/)
  })

  it('says when no Coolify account exists', async () => {
    listExternalAccounts.mockResolvedValue({ status: 200, data: { items: [], page: {} }, headers: new Headers() })
    const wrapper = await mountPage()
    await toTarget(wrapper)
    expect(wrapper.get('[data-testid="no-account"]').text()).toContain('No Coolify account')
  })
})

describe('filing', () => {
  it('reviews the steps, shows the CLI form, files one request, and follows it to the result', async () => {
    requestSiteDeployment.mockResolvedValue(ok(filedRequest(), 201))
    const wrapper = await mountPage()
    await toTarget(wrapper)
    await fillTarget(wrapper)
    await wrapper.get('[data-testid="next"]').trigger('click')
    await flushPromises()
    const steps = wrapper.findAll('[data-testid="planned-step"]').map(s => s.text())
    expect(steps[0]).toContain('https://blog.example.org')
    expect(wrapper.get('[data-testid="fleetctl-command"]').text()).toContain('fleetctl services deploy --template ghost')
    await wrapper.get('[data-testid="reason"]').setValue('launch')
    await wrapper.get('[data-testid="file-request"]').trigger('click')
    await flushPromises()
    expect(requestSiteDeployment).toHaveBeenCalledTimes(1)
    expect(requestSiteDeployment.mock.calls[0]![0]).toEqual({
      accountId: 'acc1', templateId: 'ghost', serverUuid: 'srv1', projectUuid: 'proj1',
      environmentName: 'production', domain: 'blog.example.org', reason: 'launch',
    })
    expect(wrapper.get('[data-testid="filed-state"]').text()).toBe('pending')
    expect(wrapper.find('[data-testid="deploy-result"]').exists()).toBe(false)
  })

  it('shows the created resource, every step, and the registry patch after a success', async () => {
    requestSiteDeployment.mockResolvedValue(ok(filedRequest(), 201))
    getActionRequest.mockResolvedValue(ok(filedRequest({ state: 'succeeded', terminal: true, operationId: 'op-1' })))
    getOperation.mockResolvedValue(ok({
      id: 'op-1', state: 'succeeded',
      resultJson: JSON.stringify({
        outcome: 'deployed', resourceKind: 'service', uuid: 'svc1', serviceId: 'coolify:acc1:svc1',
        domain: 'https://blog.example.org', followUpEnvKeys: [],
        steps: [{ step: 'create', status: 'done' }, { step: 'start', status: 'done' }],
      }),
    }))
    const wrapper = await mountPage()
    await toTarget(wrapper)
    await fillTarget(wrapper)
    await wrapper.get('[data-testid="next"]').trigger('click')
    await wrapper.get('[data-testid="file-request"]').trigger('click')
    await flushPromises()
    await flushPromises()
    expect(wrapper.get('[data-testid="deploy-result"]').text()).toContain('svc1')
    expect(wrapper.findAll('[data-testid="result-step"]')).toHaveLength(2)
    expect(wrapper.get('[data-testid="open-service"]').attributes('href')).toBe('/services/coolify%3Aacc1%3Asvc1')
    expect(wrapper.get('[data-testid="registry-patch"]').text()).toContain('fleetctl registry relate domain/blog.example.org hosted-on coolify:svc1')
  })

  it('says started, not deployed, while the deployment still builds, and labels the patch', async () => {
    requestSiteDeployment.mockResolvedValue(ok(filedRequest(), 201))
    getActionRequest.mockResolvedValue(ok(filedRequest({ state: 'succeeded', terminal: true, operationId: 'op-1' })))
    getOperation.mockResolvedValue(ok({
      id: 'op-1', state: 'succeeded',
      resultJson: JSON.stringify({
        outcome: 'started', resourceKind: 'application', uuid: 'app1', serviceId: 'coolify:acc1:app1',
        domain: 'https://blog.example.org', followUpEnvKeys: [], deploymentStatus: 'in_progress',
        steps: [{ step: 'create', status: 'done' }, { step: 'verify', status: 'pending', detail: 'deployment in_progress' }],
      }),
    }))
    const wrapper = await mountPage()
    await toTarget(wrapper)
    await fillTarget(wrapper)
    await wrapper.get('[data-testid="next"]').trigger('click')
    await wrapper.get('[data-testid="file-request"]').trigger('click')
    await flushPromises()
    await flushPromises()
    expect(wrapper.get('[data-testid="result-started"]').text()).toContain('had not finished')
    expect(wrapper.get('[data-testid="registry-patch"]').text()).toContain('has not finished yet')
  })

  it('sends a destination uuid when one is given', async () => {
    requestSiteDeployment.mockResolvedValue(ok(filedRequest(), 201))
    const wrapper = await mountPage()
    await toTarget(wrapper)
    await fillTarget(wrapper)
    await wrapper.get('[data-testid="destination"]').setValue('dest01')
    await wrapper.get('[data-testid="next"]').trigger('click')
    await wrapper.get('[data-testid="file-request"]').trigger('click')
    await flushPromises()
    expect(requestSiteDeployment.mock.calls[0]![0].destinationUuid).toBe('dest01')
  })

  it('shows what exists after a partial failure and offers no registry patch', async () => {
    requestSiteDeployment.mockResolvedValue(ok(filedRequest(), 201))
    getActionRequest.mockResolvedValue(ok(filedRequest({ state: 'failed', terminal: true, operationId: 'op-1', failure: 'the application app1 was created but the deployment did not complete' })))
    getOperation.mockResolvedValue(ok({
      id: 'op-1', state: 'failed',
      resultJson: JSON.stringify({
        outcome: 'partial', resourceKind: 'application', uuid: 'app1', serviceId: 'coolify:acc1:app1',
        domain: 'https://blog.example.org', error: 'queue unavailable', followUpEnvKeys: [],
        steps: [{ step: 'create', status: 'done' }, { step: 'start', status: 'failed', detail: 'queue unavailable' }],
      }),
    }))
    const wrapper = await mountPage()
    await toTarget(wrapper)
    await fillTarget(wrapper)
    await wrapper.get('[data-testid="next"]').trigger('click')
    await wrapper.get('[data-testid="file-request"]').trigger('click')
    await flushPromises()
    await flushPromises()
    expect(wrapper.get('[data-testid="result-error"]').text()).toContain('queue unavailable')
    expect(wrapper.get('[data-testid="result-error"]').text()).toContain('delete it there and file a new request')
    expect(wrapper.text()).toContain('app1')
    expect(wrapper.find('[data-testid="registry-patch"]').exists()).toBe(false)
  })

  it('shows the API refusal and keeps the form', async () => {
    requestSiteDeployment.mockResolvedValue({ status: 400, data: { code: 'invalid_request', message: 'https://blog.example.org is already routed to application shop' }, headers: new Headers() })
    const wrapper = await mountPage()
    await toTarget(wrapper)
    await fillTarget(wrapper)
    await wrapper.get('[data-testid="next"]').trigger('click')
    await wrapper.get('[data-testid="file-request"]').trigger('click')
    await flushPromises()
    expect(wrapper.get('[data-testid="deploy-error"]').text()).toContain('already routed')
    expect(wrapper.find('[data-testid="step-review"]').exists()).toBe(true)
  })
})
