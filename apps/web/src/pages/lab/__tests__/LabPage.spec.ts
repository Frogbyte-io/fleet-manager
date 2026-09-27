import { enableAutoUnmount, flushPromises, mount } from '@vue/test-utils'
import { QueryClient, VueQueryPlugin } from '@tanstack/vue-query'
import { createMemoryHistory, createRouter } from 'vue-router'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import type { LabTemplateDto, LeaseDto, ProxmoxAccountDto } from '@frogbyte-io/fleet-api-client'

const listLabLeases = vi.fn()
const listLabTemplates = vi.fn()
const listLabProvisions = vi.fn()
const listProxmoxAccounts = vi.fn()
const listProjects = vi.fn()
const createLabLease = vi.fn()
const startLabLeaseProvision = vi.fn()
const releaseLabLease = vi.fn()
const extendLabLease = vi.fn()
const sweepLabLeases = vi.fn()
const publishLabTemplate = vi.fn()
const getOperation = vi.fn()

vi.mock('@frogbyte-io/fleet-api-client', () => ({
  listLabLeases: (...args: unknown[]) => listLabLeases(...args),
  listLabTemplates: (...args: unknown[]) => listLabTemplates(...args),
  listLabProvisions: (...args: unknown[]) => listLabProvisions(...args),
  listProxmoxAccounts: (...args: unknown[]) => listProxmoxAccounts(...args),
  listTailnetDevices: vi.fn(),
  listProjects: (...args: unknown[]) => listProjects(...args),
  createLabLease: (...args: unknown[]) => createLabLease(...args),
  startLabLeaseProvision: (...args: unknown[]) => startLabLeaseProvision(...args),
  releaseLabLease: (...args: unknown[]) => releaseLabLease(...args),
  extendLabLease: (...args: unknown[]) => extendLabLease(...args),
  sweepLabLeases: (...args: unknown[]) => sweepLabLeases(...args),
  publishLabTemplate: (...args: unknown[]) => publishLabTemplate(...args),
  getOperation: (...args: unknown[]) => getOperation(...args),
  cancelOperation: vi.fn(),
}))

import LabPage from '../LabPage.vue'
import { routes } from '@/router'

// shadcn-vue primitives observe layout; jsdom lacks both APIs.
class ResizeObserverStub {
  observe() {}
  unobserve() {}
  disconnect() {}
}
vi.stubGlobal('ResizeObserver', ResizeObserverStub)
vi.stubGlobal('matchMedia', () => ({ matches: false, addListener: () => {}, removeListener: () => {}, addEventListener: () => {}, removeEventListener: () => {} }))

const NOW = Date.now()

function lease(overrides: Partial<LeaseDto> = {}): LeaseDto {
  return {
    id: 'lease-ready-0001',
    templateVersionId: 'v1',
    owner: 'anonymous-lan-admin',
    purpose: 'ci flake hunt',
    projectId: null,
    state: 'ready',
    cleanup: 'destroy',
    ttlSeconds: 7200,
    createdAt: NOW - 600_000,
    readyAt: NOW - 300_000,
    expiresAt: NOW + 3_600_000,
    maxLifetimeAt: NOW + 86_400_000,
    ...overrides,
  }
}

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
    readinessDeadlineSeconds: 600,
    ttlSeconds: 7200,
    cleanup: 'destroy',
    publishedFrom: 'v1',
    createdAt: 0,
    updatedAt: 0,
    ...overrides,
  }
}

function account(): ProxmoxAccountDto {
  return {
    id: 'acc-1',
    name: 'integration-pve',
    host: 'pve.lan',
    port: 8006,
    tokenId: 'fleet@pve!ctrl',
    fingerprint: 'AA:BB',
    fingerprintState: 'confirmed',
    createdAt: 0,
  }
}

function ok<T>(data: T, status = 200) {
  return { status, data, headers: new Headers() }
}

function page<T>(items: T[]) {
  return { items, page: { nextCursor: null, limit: 200 } }
}

async function mountPage() {
  const router = createRouter({ history: createMemoryHistory(), routes })
  await router.push('/lab')
  await router.isReady()
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } })
  const wrapper = mount(LabPage, { global: { plugins: [[VueQueryPlugin, { queryClient }], router] }, attachTo: document.body })
  await flushPromises()
  await flushPromises()
  return wrapper
}

function button(text: string): HTMLButtonElement {
  const found = [...document.body.querySelectorAll('button')].find(b => b.textContent?.trim().startsWith(text))
  if (!found)
    throw new Error(`no button "${text}"`)
  return found as HTMLButtonElement
}

enableAutoUnmount(afterEach)

beforeEach(() => {
  document.body.innerHTML = ''
  for (const mock of [listLabLeases, listLabTemplates, listLabProvisions, listProxmoxAccounts, listProjects, createLabLease,
    startLabLeaseProvision, releaseLabLease, extendLabLease, sweepLabLeases, publishLabTemplate, getOperation])
    mock.mockReset()
  listLabLeases.mockResolvedValue(ok(page([
    lease(),
    lease({ id: 'lease-boot-0002', state: 'bootstrapping', purpose: 'try mise', readyAt: null, expiresAt: null }),
    lease({ id: 'lease-cf-0003', state: 'cleanup_failed', purpose: 'old run', templateVersionId: 'v-old' }),
    lease({ id: 'lease-done-0004', state: 'released', purpose: 'finished run' }),
  ])))
  listLabTemplates.mockResolvedValue(ok(page([template(), template({ id: 't2', name: 'unpublished', publishedFrom: null })])))
  listLabProvisions.mockResolvedValue(ok(page([])))
  listProxmoxAccounts.mockResolvedValue(ok(page([account(), { ...account(), id: 'acc-2', name: 'untrusted', fingerprintState: 'unconfirmed' }])))
  listProjects.mockResolvedValue(ok(page([{ id: 'p1', name: 'fleet-manager', remote: 'x', description: '', checkouts: [], createdAt: 0, updatedAt: 0 }])))
  getOperation.mockResolvedValue(ok({ data: { id: 'op-1', kind: 'lab.provision', state: 'running' } }))
})

describe('LabPage', () => {
  it('lists active leases most urgent first and keeps released ones in History', async () => {
    const wrapper = await mountPage()
    const cards = wrapper.findAll('article').map(card => card.attributes('data-testid'))
    expect(cards).toEqual(['lease-lease-cf-0003', 'lease-lease-ready-0001', 'lease-lease-boot-0002'])
    expect(wrapper.text()).not.toContain('finished run')

    await wrapper.get('[data-testid="tab-history"]').trigger('click')
    expect(wrapper.text()).toContain('finished run')
  })

  it('names the template a lease pinned only when it still resolves', async () => {
    const wrapper = await mountPage()
    expect(wrapper.get('[data-testid="lease-lease-ready-0001"]').text()).toContain('ubuntu-dev')
    // v-old is not the version any template currently points at.
    expect(wrapper.get('[data-testid="lease-lease-cf-0003"]').text()).toContain('version v-old')
  })

  it('shows the TTL only for ready leases', async () => {
    const wrapper = await mountPage()
    expect(wrapper.get('[data-testid="lease-lease-ready-0001"]').find('[data-testid="ttl-bar"]').exists()).toBe(true)
    expect(wrapper.get('[data-testid="lease-lease-boot-0002"]').find('[data-testid="ttl-bar"]').exists()).toBe(false)
    // cleanup_failed still carries its old ready/expiry times; the TTL is over.
    expect(wrapper.get('[data-testid="lease-lease-cf-0003"]').find('[data-testid="ttl-bar"]').exists()).toBe(false)
  })

  it('explains why there is no command when nothing is published yet', async () => {
    listLabTemplates.mockResolvedValue(ok(page([template({ publishedFrom: null })])))
    const wrapper = await mountPage()
    await wrapper.get('[data-testid="new-environment"]').trigger('click')
    await flushPromises()
    const text = document.body.textContent ?? ''
    expect(text).toContain('No published templates.')
    expect(text).toContain('Choose a published template to see the equivalent command.')
    expect(text).not.toContain('no project flag')
  })

  it('offers only published templates and confirmed accounts when requesting', async () => {
    const wrapper = await mountPage()
    await wrapper.get('[data-testid="new-environment"]').trigger('click')
    await flushPromises()
    const text = document.body.textContent ?? ''
    expect(text).toContain('ubuntu-dev')
    expect(text).not.toContain('unpublished')
    const options = [...document.body.querySelectorAll('select[aria-label="Proxmox account"] option')].map(o => o.textContent)
    expect(options.some(o => o?.includes('integration-pve'))).toBe(true)
    expect(options.some(o => o?.includes('untrusted'))).toBe(false)
  })

  it('creates a lease from the published version and starts provisioning', async () => {
    createLabLease.mockResolvedValue(ok({ data: lease({ id: 'new-lease', state: 'requested' }) }, 201))
    startLabLeaseProvision.mockResolvedValue(ok({ data: { id: 'op-1', kind: 'lab.provision', state: 'pending' } }, 201))
    const wrapper = await mountPage()
    await wrapper.get('[data-testid="new-environment"]').trigger('click')
    await flushPromises()

    const purpose = document.body.querySelector('input[placeholder="what this environment is for"]') as HTMLInputElement
    purpose.value = 'try new mise'
    purpose.dispatchEvent(new Event('input'))
    await flushPromises()
    expect(document.body.textContent).toContain(`fleetctl --output json lab lease v1 --purpose 'try new mise'`)

    button('Request & provision').click()
    await flushPromises()
    expect(createLabLease).toHaveBeenCalledWith({ templateVersionId: 'v1', purpose: 'try new mise', projectId: null })
    expect(startLabLeaseProvision).toHaveBeenCalledWith('new-lease', { accountId: 'acc-1' })
  })

  it('keeps a lease that was created even when provisioning fails to start', async () => {
    createLabLease.mockResolvedValue(ok({ data: lease({ id: 'new-lease', state: 'requested' }) }, 201))
    startLabLeaseProvision.mockResolvedValue({ status: 409, data: { code: 'conflict', message: 'no capacity' } })
    const wrapper = await mountPage()
    await wrapper.get('[data-testid="new-environment"]').trigger('click')
    await flushPromises()
    const purpose = document.body.querySelector('input[placeholder="what this environment is for"]') as HTMLInputElement
    purpose.value = 'x'
    purpose.dispatchEvent(new Event('input'))
    await flushPromises()
    button('Request & provision').click()
    await flushPromises()
    expect(document.body.textContent).toContain('Lease created, but provisioning did not start: conflict: no capacity')
  })

  it('retries provisioning for the lease it created instead of creating another', async () => {
    createLabLease.mockResolvedValue(ok({ data: lease({ id: 'new-lease', state: 'requested', purpose: 'x' }) }, 201))
    startLabLeaseProvision
      .mockResolvedValueOnce({ status: 409, data: { code: 'conflict', message: 'no capacity' } })
      .mockResolvedValueOnce(ok({ data: { id: 'op-2', kind: 'lab.provision', state: 'pending' } }, 201))
    const wrapper = await mountPage()
    await wrapper.get('[data-testid="new-environment"]').trigger('click')
    await flushPromises()
    const purpose = document.body.querySelector('input[placeholder="what this environment is for"]') as HTMLInputElement
    purpose.value = 'x'
    purpose.dispatchEvent(new Event('input'))
    await flushPromises()
    button('Request & provision').click()
    await flushPromises()
    expect(document.body.querySelector('[data-testid="pending-lease"]')).not.toBeNull()

    button('Retry provisioning').click()
    await flushPromises()
    expect(createLabLease).toHaveBeenCalledTimes(1)
    expect(startLabLeaseProvision).toHaveBeenCalledTimes(2)
    expect(startLabLeaseProvision).toHaveBeenLastCalledWith('new-lease', { accountId: 'acc-1' })
  })

  it('shows no command until a purpose is entered', async () => {
    const wrapper = await mountPage()
    await wrapper.get('[data-testid="new-environment"]').trigger('click')
    await flushPromises()
    const text = document.body.textContent ?? ''
    expect(text).toContain('Enter a purpose to see the equivalent command.')
    expect(text).not.toContain('lab lease v1')
  })

  it('reports unavailable Proxmox accounts instead of implying none are configured', async () => {
    listProxmoxAccounts.mockRejectedValue(new Error('listProxmoxAccounts failed (503)'))
    const wrapper = await mountPage()
    expect(wrapper.text()).toContain('Could not load Proxmox accounts: listProxmoxAccounts failed (503)')
  })

  it('requires an explicit acknowledgement before keeping a VM', async () => {
    releaseLabLease.mockResolvedValue(ok({ data: lease({ state: 'releasing' }) }))
    const wrapper = await mountPage()
    const card = wrapper.get('[data-testid="lease-lease-ready-0001"]')
    await card.findAll('button').find(b => b.text().startsWith('Release'))!.trigger('click')
    await card.get('[data-testid="keep"]').setValue(true)
    expect(card.get('[data-testid="confirm-release"]').attributes('disabled')).toBeDefined()
    expect(card.text()).toContain('fleetctl --output json lab release lease-ready-0001 --keep')

    await card.get('[data-testid="keep-ack"]').setValue(true)
    await card.get('[data-testid="confirm-release"]').trigger('click')
    await flushPromises()
    expect(releaseLabLease).toHaveBeenCalledWith('lease-ready-0001', { keep: true })
  })

  it('extends a ready lease by the chosen span and surfaces a refusal', async () => {
    extendLabLease.mockResolvedValue({ status: 409, data: { code: 'conflict', message: 'past the maximum lifetime' } })
    const wrapper = await mountPage()
    const card = wrapper.get('[data-testid="lease-lease-ready-0001"]')
    await card.findAll('button').find(b => b.text().startsWith('Extend'))!.trigger('click')
    await card.findAll('button').find(b => b.text() === '+2H')!.trigger('click')
    await card.findAll('button').find(b => b.text().startsWith('Extend lease'))!.trigger('click')
    await flushPromises()
    expect(extendLabLease).toHaveBeenCalledWith('lease-ready-0001', { bySeconds: 7200 })
    expect(card.text()).toContain('past the maximum lifetime')
  })

  it('offers provisioning only for requested leases and release never for terminal ones', async () => {
    listLabLeases.mockResolvedValue(ok(page([lease({ id: 'req', state: 'requested', readyAt: null, expiresAt: null })])))
    const wrapper = await mountPage()
    const labels = wrapper.get('[data-testid="lease-req"]').findAll('button').map(b => b.text())
    expect(labels).toContain('Provision…')
    expect(labels).not.toContain('Extend…')

    await wrapper.get('[data-testid="tab-history"]').trigger('click')
    expect(wrapper.text()).toContain('No released or failed leases yet.')
  })

  it('sweeps on request and reports how many leases were due', async () => {
    sweepLabLeases.mockResolvedValue(ok(page([lease({ state: 'releasing' })])))
    const wrapper = await mountPage()
    await wrapper.findAll('button').find(b => b.text() === 'Sweep expired')!.trigger('click')
    expect(wrapper.text()).toContain('fleetctl --output json lab sweep')
    await wrapper.findAll('button').find(b => b.text() === 'Sweep now')!.trigger('click')
    await flushPromises()
    expect(sweepLabLeases).toHaveBeenCalled()
    expect(wrapper.text()).toContain('1 lease swept.')
  })

  it('reports a failed lease list instead of claiming there are none', async () => {
    listLabLeases.mockRejectedValue(new Error('listLabLeases failed (500)'))
    const wrapper = await mountPage()
    expect(wrapper.text()).toContain('Could not load leases: listLabLeases failed (500)')
    expect(wrapper.text()).not.toContain('No active environments')
  })
})
