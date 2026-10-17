import { QueryClient, VueQueryPlugin } from '@tanstack/vue-query'
import { enableAutoUnmount, flushPromises, mount } from '@vue/test-utils'
import { createMemoryHistory, createRouter } from 'vue-router'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const getServiceSettings = vi.fn()
const getActionRequest = vi.fn()
const requestServiceAction = vi.fn()
const requestServiceEnvChange = vi.fn()
const requestServiceDomainsChange = vi.fn()
const requestServiceHealthChange = vi.fn()

vi.mock('@frogbyte-io/fleet-api-client', () => ({
  getServiceSettings: (...a: unknown[]) => getServiceSettings(...a),
  getActionRequest: (...a: unknown[]) => getActionRequest(...a),
  requestServiceAction: (...a: unknown[]) => requestServiceAction(...a),
  requestServiceEnvChange: (...a: unknown[]) => requestServiceEnvChange(...a),
  requestServiceDomainsChange: (...a: unknown[]) => requestServiceDomainsChange(...a),
  requestServiceHealthChange: (...a: unknown[]) => requestServiceHealthChange(...a),
}))

import { routes } from '@/router'
import ServiceActions from '../components/ServiceActions.vue'
import ServiceSettings from '../components/ServiceSettings.vue'
import { service } from './fixtures'

const SECRET = 'Zq9-never-show-this-7731'

function ok<T>(data: T, status = 200) {
  return { status, data: { data }, headers: new Headers() }
}

function filedRequest(action: string, patch: Record<string, unknown> = {}) {
  return {
    id: 'req-1', requester: 'anonymous-lan-admin', origin: 'api', actionId: action,
    target: 'coolify:acc1:web', parameters: {}, riskClass: 'approve', reason: 'why',
    state: 'pending', terminal: false, decidedBy: null, decidedAt: null, decisionNote: null,
    operationId: null, failure: null, createdAt: 1, expiresAt: 2, updatedAt: 3, ...patch,
  }
}

const SETTINGS = {
  serviceId: 'coolify:acc1:web',
  resourceKind: 'application',
  name: 'web',
  env: [
    { key: 'DATABASE_URL', isPreview: false, isShared: false, isBuildtime: true, isRuntime: true, isMultiline: false, isLiteral: true, isShownOnce: false },
    { key: 'OLD_SETTING', isPreview: false, isShared: false, isBuildtime: true, isRuntime: true, isMultiline: false, isLiteral: false, isShownOnce: true },
  ],
  domains: ['https://shop.example.org'],
  health: { checkType: 'http', enabled: false, path: '/', port: null, host: null, method: 'GET', scheme: 'http', returnCode: 200, responseText: null, interval: 5, timeout: 5, retries: 10, startPeriod: 5 },
  notes: [],
}

let lastClient: QueryClient

async function mountComponent<T>(component: T, props: Record<string, unknown>) {
  const router = createRouter({ history: createMemoryHistory(), routes })
  await router.push('/services')
  await router.isReady()
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity }, mutations: { retry: false } } })
  lastClient = queryClient
  const wrapper = mount(component as never, { props: props as never, global: { plugins: [[VueQueryPlugin, { queryClient }], router] } })
  await flushPromises()
  await flushPromises()
  return wrapper
}

enableAutoUnmount(afterEach)

beforeEach(() => {
  for (const mock of [getServiceSettings, getActionRequest, requestServiceAction, requestServiceEnvChange, requestServiceDomainsChange, requestServiceHealthChange])
    mock.mockReset()
  getServiceSettings.mockResolvedValue(ok(SETTINGS))
})

describe('lifecycle buttons', () => {
  it('files a restart at once and shows the request with a link to Approvals', async () => {
    requestServiceAction.mockResolvedValue(ok(filedRequest('coolify.application.restart', { riskClass: 'auto', state: 'executing' }), 201))
    getActionRequest.mockResolvedValue(ok(filedRequest('coolify.application.restart', { riskClass: 'auto', state: 'succeeded' })))
    const wrapper = await mountComponent(ServiceActions, { service: service('web') })
    expect(wrapper.findAll('button').map(b => b.text())).toEqual(['Start', 'Stop', 'Restart', 'Redeploy'])
    await wrapper.get('[data-testid="action-restart"]').trigger('click')
    await flushPromises()
    expect(requestServiceAction).toHaveBeenCalledWith('coolify:acc1:web', 'restart', { reason: 'restart web from the console' })
    expect(wrapper.get('[data-testid="filed-state"]').text()).toBe('succeeded')
    expect(wrapper.get('[data-testid="filed-text"]').text()).toContain('status back')
    expect(wrapper.get('[data-testid="filed-link"]').attributes('href')).toBe('/requests?request=req-1')
  })

  it('asks before stop and files nothing until confirmed', async () => {
    requestServiceAction.mockResolvedValue(ok(filedRequest('coolify.application.stop'), 201))
    getActionRequest.mockResolvedValue(ok(filedRequest('coolify.application.stop')))
    const wrapper = await mountComponent(ServiceActions, { service: service('web') })
    await wrapper.get('[data-testid="action-stop"]').trigger('click')
    expect(requestServiceAction).not.toHaveBeenCalled()
    expect(wrapper.get('[data-testid="confirm-text"]').text()).toContain('Policy decides')
    await wrapper.get('[data-testid="cancel-stop"]').trigger('click')
    expect(wrapper.find('[data-testid="confirm-text"]').exists()).toBe(false)
    await wrapper.get('[data-testid="action-stop"]').trigger('click')
    await wrapper.get('[data-testid="confirm-stop"]').trigger('click')
    await flushPromises()
    expect(requestServiceAction).toHaveBeenCalledWith('coolify:acc1:web', 'stop', expect.anything())
    expect(wrapper.get('[data-testid="filed-state"]').text()).toBe('pending')
    expect(wrapper.get('[data-testid="filed-text"]').text()).toContain('Waiting for a person')
  })

  it('shows the API refusal, and draws nothing for a Docker container or a database restart-less kind', async () => {
    requestServiceAction.mockResolvedValue({ status: 403, data: { code: 'denied', message: 'denied: no' }, headers: new Headers() })
    const wrapper = await mountComponent(ServiceActions, { service: service('web') })
    await wrapper.get('[data-testid="action-start"]').trigger('click')
    await flushPromises()
    expect(wrapper.get('[data-testid="action-error"]').text()).toContain('denied')
    const docker = await mountComponent(ServiceActions, { service: { ...service('cache'), id: 'docker:m1:cache', kind: 'container', coolify: null } })
    expect(docker.find('[data-testid="service-actions"]').exists()).toBe(false)
  })
})

describe('settings tab', () => {
  it('lists variable names and flags, domains, and the health check, and no value', async () => {
    const wrapper = await mountComponent(ServiceSettings, { service: service('web') })
    expect(getServiceSettings).toHaveBeenCalledWith('coolify:acc1:web')
    const rows = wrapper.findAll('[data-testid="env-row"]')
    expect(rows.map(r => r.find('span').text())).toEqual(['DATABASE_URL', 'OLD_SETTING'])
    expect(rows[0]!.text()).toContain('literal')
    expect(rows[1]!.text()).toContain('hidden after save')
    expect((wrapper.get('[data-testid="domains-text"]').element as HTMLTextAreaElement).value).toBe('https://shop.example.org')
    expect((wrapper.get('[data-testid="health-path"]').element as HTMLInputElement).value).toBe('/')
    expect(wrapper.text()).toContain('Coolify does not show values')
  })

  it('never prefills a value: the field is a password input and stays empty after picking a variable', async () => {
    const wrapper = await mountComponent(ServiceSettings, { service: service('web') })
    const value = wrapper.get('[data-testid="env-value"]')
    expect(value.attributes('type')).toBe('password')
    expect(value.attributes('autocomplete')).toBe('new-password')
    await wrapper.get('[data-testid="env-edit-DATABASE_URL"]').trigger('click')
    expect((wrapper.get('[data-testid="env-key"]').element as HTMLInputElement).value).toBe('DATABASE_URL')
    expect((wrapper.get('[data-testid="env-value"]').element as HTMLInputElement).value).toBe('')
    expect(wrapper.text()).toContain('Replace a value')
  })

  it('files a set with the value in the request body only, then clears the field and shows names', async () => {
    requestServiceEnvChange.mockResolvedValue(ok(filedRequest('coolify.env.update', {
      parameters: {
        redeploy: true,
        preview: [{ key: 'DATABASE_URL', isPreview: false, operation: 'update', changes: [{ field: 'value', from: '(write-only)', to: '(write-only, digest ab12cd34ef56)' }] }],
      },
    }), 201))
    getActionRequest.mockResolvedValue(ok(filedRequest('coolify.env.update')))
    const wrapper = await mountComponent(ServiceSettings, { service: service('web') })
    await wrapper.get('[data-testid="env-edit-DATABASE_URL"]').trigger('click')
    await wrapper.get('[data-testid="env-value"]').setValue(SECRET)
    await wrapper.get('[data-testid="env-redeploy"]').setValue(true)
    expect((wrapper.get('[data-testid="env-submit"]').element as HTMLButtonElement).disabled).toBe(false)
    await wrapper.get('[data-testid="env-form"]').trigger('submit')
    await flushPromises()
    expect(requestServiceEnvChange).toHaveBeenCalledTimes(1)
    const [id, body] = requestServiceEnvChange.mock.calls[0]!
    expect(id).toBe('coolify:acc1:web')
    expect(body.changes[0]).toMatchObject({ op: 'set', key: 'DATABASE_URL', value: SECRET, isLiteral: true })
    expect(body.redeploy).toBe(true)
    // The flags of the existing variable were kept.
    expect(body.changes[0].isShownOnce).toBe(false)
    // The value left the page: not in the field, not anywhere in the DOM.
    expect((wrapper.get('[data-testid="env-value"]').element as HTMLInputElement).value).toBe('')
    expect(wrapper.html()).not.toContain(SECRET)
    expect(wrapper.get('[data-testid="filed-preview"]').text()).toContain('update DATABASE_URL [value write-only]')
    expect(wrapper.get('[data-testid="filed-preview"]').text()).toContain('then redeploy')
  })

  it('keeps the value out of the TanStack mutation cache, and clears the field after a failed send too', async () => {
    requestServiceEnvChange.mockResolvedValueOnce({ status: 500, data: { code: 'internal', message: 'boom' }, headers: new Headers() })
    requestServiceEnvChange.mockResolvedValueOnce(ok(filedRequest('coolify.env.update'), 201))
    getActionRequest.mockResolvedValue(ok(filedRequest('coolify.env.update')))
    const wrapper = await mountComponent(ServiceSettings, { service: service('web') })
    await wrapper.get('[data-testid="env-key"]').setValue('API_URL')
    await wrapper.get('[data-testid="env-value"]').setValue(SECRET)
    await wrapper.get('[data-testid="env-form"]').trigger('submit')
    await flushPromises()
    // Failed: the error is shown and the field is empty again.
    expect(wrapper.find('[data-testid="env-error"]').exists()).toBe(true)
    expect((wrapper.get('[data-testid="env-value"]').element as HTMLInputElement).value).toBe('')
    expect(wrapper.html()).not.toContain(SECRET)
    await wrapper.get('[data-testid="env-value"]').setValue(SECRET)
    await wrapper.get('[data-testid="env-form"]').trigger('submit')
    await flushPromises()
    await new Promise(resolve => setTimeout(resolve, 5))
    const cache = lastClient.getMutationCache().getAll()
    expect(cache).toHaveLength(0)
    expect(JSON.stringify(cache.map(m => m.state))).not.toContain(SECRET)
  })

  it('allows an empty value (Coolify stores it as blank) but not a bad name', async () => {
    requestServiceEnvChange.mockResolvedValue(ok(filedRequest('coolify.env.update'), 201))
    getActionRequest.mockResolvedValue(ok(filedRequest('coolify.env.update')))
    const wrapper = await mountComponent(ServiceSettings, { service: service('web') })
    await wrapper.get('[data-testid="env-key"]').setValue('EMPTY_ONE')
    expect((wrapper.get('[data-testid="env-submit"]').element as HTMLButtonElement).disabled).toBe(false)
    await wrapper.get('[data-testid="env-form"]').trigger('submit')
    await flushPromises()
    expect(requestServiceEnvChange.mock.calls[0]![1].changes[0]).toMatchObject({ key: 'EMPTY_ONE', value: '' })
  })

  it('shows a command health check but offers no form for it', async () => {
    getServiceSettings.mockResolvedValue(ok({ ...SETTINGS, health: { ...SETTINGS.health, checkType: 'cmd' } }))
    const wrapper = await mountComponent(ServiceSettings, { service: service('web') })
    expect(wrapper.get('[data-testid="health-command"]').text()).toContain('Command check (not editable)')
    expect(wrapper.find('[data-testid="health-form"]').exists()).toBe(false)
  })

  it('blocks a bad name before anything is sent', async () => {
    const wrapper = await mountComponent(ServiceSettings, { service: service('web') })
    await wrapper.get('[data-testid="env-key"]').setValue('1BAD')
    expect(wrapper.get('[data-testid="env-problem"]').text()).toContain('letters')
    expect((wrapper.get('[data-testid="env-submit"]').element as HTMLButtonElement).disabled).toBe(true)
    await wrapper.get('[data-testid="env-form"]').trigger('submit')
    expect(requestServiceEnvChange).not.toHaveBeenCalled()
  })

  it('files an unset by name after a confirmation click', async () => {
    requestServiceEnvChange.mockResolvedValue(ok(filedRequest('coolify.env.update'), 201))
    getActionRequest.mockResolvedValue(ok(filedRequest('coolify.env.update')))
    const wrapper = await mountComponent(ServiceSettings, { service: service('web') })
    await wrapper.get('[data-testid="env-unset-OLD_SETTING"]').trigger('click')
    expect(requestServiceEnvChange).not.toHaveBeenCalled()
    await wrapper.get('[data-testid="env-unset-confirm-OLD_SETTING"]').trigger('click')
    await flushPromises()
    expect(requestServiceEnvChange.mock.calls[0]![1].changes).toEqual([{ op: 'unset', key: 'OLD_SETTING', isPreview: false }])
  })

  it('files a domains change with the whole list', async () => {
    requestServiceDomainsChange.mockResolvedValue(ok(filedRequest('coolify.application.domains.set', {
      parameters: { preview: { changes: [{ field: 'domains', from: ['https://shop.example.org'], to: ['https://shop.example.org', 'https://www.example.org'] }] } },
    }), 201))
    getActionRequest.mockResolvedValue(ok(filedRequest('coolify.application.domains.set')))
    const wrapper = await mountComponent(ServiceSettings, { service: service('web') })
    expect((wrapper.get('[data-testid="domains-submit"]').element as HTMLButtonElement).disabled).toBe(true)
    await wrapper.get('[data-testid="domains-text"]').setValue('https://shop.example.org\nhttps://www.example.org')
    await wrapper.get('[data-testid="domains-form"]').trigger('submit')
    await flushPromises()
    expect(requestServiceDomainsChange.mock.calls[0]![1]).toMatchObject({ domains: ['https://shop.example.org', 'https://www.example.org'], redeploy: false })
    expect(wrapper.get('[data-testid="filed-preview"]').text()).toContain('domains: https://shop.example.org → https://shop.example.org, https://www.example.org')
  })

  it('warns that an empty domain list removes them all', async () => {
    const wrapper = await mountComponent(ServiceSettings, { service: service('web') })
    await wrapper.get('[data-testid="domains-text"]').setValue('')
    expect(wrapper.get('[data-testid="domains-clearing"]').text()).toContain('removes every domain')
  })

  it('files only the changed health-check fields', async () => {
    requestServiceHealthChange.mockResolvedValue(ok(filedRequest('coolify.application.health.set'), 201))
    getActionRequest.mockResolvedValue(ok(filedRequest('coolify.application.health.set')))
    const wrapper = await mountComponent(ServiceSettings, { service: service('web') })
    expect((wrapper.get('[data-testid="health-submit"]').element as HTMLButtonElement).disabled).toBe(true)
    await wrapper.get('[data-testid="health-path"]').setValue('/healthz')
    await wrapper.get('[data-testid="health-enabled"]').setValue(true)
    await wrapper.get('[data-testid="health-form"]').trigger('submit')
    await flushPromises()
    expect(requestServiceHealthChange.mock.calls[0]![1]).toEqual({ enabled: true, path: '/healthz', redeploy: false, reason: '' })
  })

  it('shows the API error when filing is refused', async () => {
    requestServiceHealthChange.mockResolvedValue({ status: 400, data: { code: 'invalid_request', message: 'the health check already matches' }, headers: new Headers() })
    const wrapper = await mountComponent(ServiceSettings, { service: service('web') })
    await wrapper.get('[data-testid="health-retries"]').setValue('3')
    await wrapper.get('[data-testid="health-form"]').trigger('submit')
    await flushPromises()
    expect(wrapper.get('[data-testid="health-error"]').text()).toContain('already matches')
  })

  it('shows a service its variables only, and a Compose note without a domains form', async () => {
    getServiceSettings.mockResolvedValue(ok({
      ...SETTINGS, resourceKind: 'service', domains: null, health: null, notes: ['a service keeps its domains per sub-application in Coolify; change them there'],
    }))
    const wrapper = await mountComponent(ServiceSettings, { service: service('plausible', { kind: 'service' }) })
    expect(wrapper.find('[data-testid="env-settings"]').exists()).toBe(true)
    expect(wrapper.find('[data-testid="domains-settings"]').exists()).toBe(false)
    expect(wrapper.find('[data-testid="health-settings"]').exists()).toBe(false)
    expect(wrapper.find('[data-testid="env-preview"]').exists()).toBe(false)
    expect(wrapper.get('[data-testid="settings-note"]').text()).toContain('sub-application')
  })

  it('says why there are no settings for a database or a Docker container', async () => {
    const database = await mountComponent(ServiceSettings, { service: service('db', { kind: 'database' }) })
    expect(database.get('[data-testid="settings-none"]').text()).toContain('database')
    const docker = await mountComponent(ServiceSettings, { service: { ...service('cache'), id: 'docker:m1:cache', kind: 'container', coolify: null } })
    expect(docker.get('[data-testid="settings-none"]').text()).toContain('Docker')
    expect(getServiceSettings).not.toHaveBeenCalled()
  })

  it('reports a failed read from Coolify', async () => {
    getServiceSettings.mockResolvedValue({ status: 403, data: { code: 'provider_permission', message: 'the token lacks the read ability' }, headers: new Headers() })
    const wrapper = await mountComponent(ServiceSettings, { service: service('web') })
    expect(wrapper.get('[data-testid="settings-error"]').text()).toContain('lacks the read ability')
  })
})
