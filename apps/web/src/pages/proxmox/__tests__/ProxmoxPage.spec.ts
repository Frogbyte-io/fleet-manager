import { enableAutoUnmount, flushPromises, mount } from '@vue/test-utils'
import { QueryClient, VueQueryPlugin } from '@tanstack/vue-query'
import { createMemoryHistory, createRouter } from 'vue-router'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import type { AssociatedGuestDto, ProxmoxAccountDto, ProxmoxDiscoveryDto } from '@frogbyte-io/fleet-api-client'

// The stub API: every generated client call the Proxmox page makes.
const listProxmoxAccounts = vi.fn()
const discoverProxmoxCluster = vi.fn()
const listProxmoxGuests = vi.fn()
const observeProxmoxFingerprint = vi.fn()
const confirmProxmoxFingerprint = vi.fn()
const startProxmoxLifecycle = vi.fn()
const getOperation = vi.fn()

vi.mock('@frogbyte-io/fleet-api-client', () => ({
  listProxmoxAccounts: (...args: unknown[]) => listProxmoxAccounts(...args),
  discoverProxmoxCluster: (...args: unknown[]) => discoverProxmoxCluster(...args),
  listProxmoxGuests: (...args: unknown[]) => listProxmoxGuests(...args),
  observeProxmoxFingerprint: (...args: unknown[]) => observeProxmoxFingerprint(...args),
  confirmProxmoxFingerprint: (...args: unknown[]) => confirmProxmoxFingerprint(...args),
  startProxmoxLifecycle: (...args: unknown[]) => startProxmoxLifecycle(...args),
  getOperation: (...args: unknown[]) => getOperation(...args),
  cancelOperation: vi.fn(),
  listTailnetDevices: vi.fn(),
}))

import ProxmoxPage from '../ProxmoxPage.vue'
import { routes } from '@/router'

function ok<T>(data: T, status = 200) {
  return { status, data, headers: new Headers() }
}

function page<T>(items: T[]) {
  return { items, page: { nextCursor: null, limit: 200 } }
}

function account(overrides: Partial<ProxmoxAccountDto> = {}): ProxmoxAccountDto {
  return { id: 'acc1', name: 'homelab', host: 'pve.lan', port: 8006, tokenId: 'fleet@pve!console', fingerprint: 'AA:BB:CC', fingerprintState: 'confirmed', createdAt: 0, ...overrides }
}

const discovery: ProxmoxDiscoveryDto = {
  accountId: 'acc1',
  pveVersion: '8.2.4',
  reportedCount: 3,
  warnings: [],
  observedAt: Date.now(),
  resources: [
    { accountId: 'acc1', id: 'node/pve1', kind: 'node', name: 'pve1', node: 'pve1', status: 'online', vmid: null, observedAt: 1, pveVersion: '8.2.4' },
    { accountId: 'acc1', id: 'qemu/101', kind: 'qemu', name: 'dev', node: 'pve1', status: 'running', vmid: 101, observedAt: 1, pveVersion: '8.2.4' },
  ],
  nodeCapacities: [{ node: 'pve1', observedAt: 1, cpuCount: 8, cpuUsageRatio: 0.42, memoryUsedBytes: 8 * 2 ** 30, memoryTotalBytes: 32 * 2 ** 30, storages: [{ storage: 'local-lvm', usedBytes: 95, totalBytes: 100 }] }],
}

const guest: AssociatedGuestDto = {
  id: 'qemu/101', kind: 'qemu', name: 'dev', node: 'pve1', status: 'running', vmid: 101, macs: [], warnings: [], observedAt: 1, pveVersion: '8.2.4',
  agent: null, candidates: [{ machineId: 'm1', machineName: 'dev-box', machineStatus: 'connected', kind: 'mac_match', evidence: 'aa:bb' }],
}

const MISMATCH = ok({ code: 'proxmox_fingerprint_mismatch', message: 'the host certificate\'s fingerprint DD:EE:FF does not match the pinned AA:BB:CC' }, 409)

async function mountAt(path: string) {
  const router = createRouter({ history: createMemoryHistory(), routes })
  await router.push(path)
  await router.isReady()
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } })
  const wrapper = mount(ProxmoxPage, { global: { plugins: [[VueQueryPlugin, { queryClient }], router] } })
  await flushPromises()
  await flushPromises()
  return { wrapper, router }
}

enableAutoUnmount(afterEach)

beforeEach(() => {
  for (const mock of [listProxmoxAccounts, discoverProxmoxCluster, listProxmoxGuests, observeProxmoxFingerprint, confirmProxmoxFingerprint, startProxmoxLifecycle, getOperation])
    mock.mockReset()
  listProxmoxAccounts.mockResolvedValue(ok(page([account()])))
  discoverProxmoxCluster.mockResolvedValue(ok({ data: discovery }))
  listProxmoxGuests.mockResolvedValue(ok(page([guest])))
  getOperation.mockResolvedValue(ok({ data: { id: 'op-1', kind: 'proxmox.lifecycle', state: 'succeeded' } }))
})

describe('accounts and trust', () => {
  it('shows a pinned account with its fingerprint and PVE handoff', async () => {
    const { wrapper } = await mountAt('/proxmox')
    const card = wrapper.get('[data-testid="account-acc1"]')
    expect(card.attributes('data-state')).toBe('pinned')
    expect(card.text()).toContain('AA:BB:CC')
    expect(card.get('[data-testid="open-pve"]').attributes('href')).toBe('https://pve.lan:8006/')
    expect(card.find('[data-testid="repin"]').exists()).toBe(false)
  })

  it('never calls an unconfirmed account', async () => {
    listProxmoxAccounts.mockResolvedValue(ok(page([account({ fingerprint: null, fingerprintState: 'unconfirmed' })])))
    const { wrapper } = await mountAt('/proxmox')
    expect(wrapper.get('[data-testid="account-acc1"]').attributes('data-state')).toBe('unconfirmed')
    expect(discoverProxmoxCluster).not.toHaveBeenCalled()
    expect(listProxmoxGuests).not.toHaveBeenCalled()
  })

  it('e2e: a changed certificate blocks actions until observed and re-confirmed', async () => {
    discoverProxmoxCluster.mockResolvedValue(MISMATCH)
    listProxmoxGuests.mockResolvedValue(MISMATCH)
    const { wrapper, router } = await mountAt('/proxmox')
    const card = () => wrapper.get('[data-testid="account-acc1"]')
    expect(card().attributes('data-state')).toBe('changed')
    // The mismatch is caught by discovery; guests are never asked for.
    expect(listProxmoxGuests).not.toHaveBeenCalled()
    // Both values, side by side, before anything is observed.
    expect(card().get('[data-testid="fingerprint-pinned"]').text()).toBe('AA:BB:CC')
    expect(card().get('[data-testid="fingerprint-observed"]').text()).toBe('DD:EE:FF')

    // Guests of the account are neither listed nor actionable.
    await router.replace({ query: { tab: 'guests' } })
    await flushPromises()
    expect(wrapper.get('[data-testid="guests-blocked"]').text()).toContain('homelab')
    expect(wrapper.find('[data-testid="guest-101"]').exists()).toBe(false)
    await router.replace({ query: {} })
    await flushPromises()

    // Observe, acknowledge, then re-pin.
    observeProxmoxFingerprint.mockResolvedValue(ok({ data: { accountId: 'acc1', fingerprint: 'DD:EE:FF' } }))
    await card().get('[data-testid="observe"]').trigger('click')
    await flushPromises()
    expect(observeProxmoxFingerprint).toHaveBeenCalledWith('acc1')
    expect(card().get('[data-testid="confirm"]').attributes('disabled')).toBeDefined()
    await card().get('[data-testid="acknowledge"]').setValue(true)

    confirmProxmoxFingerprint.mockResolvedValue(ok({ data: account({ fingerprint: 'DD:EE:FF' }) }))
    listProxmoxAccounts.mockResolvedValue(ok(page([account({ fingerprint: 'DD:EE:FF' })])))
    discoverProxmoxCluster.mockResolvedValue(ok({ data: discovery }))
    listProxmoxGuests.mockResolvedValue(ok(page([guest])))
    await card().get('[data-testid="confirm"]').trigger('click')
    await flushPromises()
    await flushPromises()
    expect(confirmProxmoxFingerprint).toHaveBeenCalledWith('acc1', { fingerprint: 'DD:EE:FF' })
    expect(card().attributes('data-state')).toBe('pinned')
    expect(card().text()).toContain('DD:EE:FF')

    // Actions are back.
    await router.replace({ query: { tab: 'guests' } })
    await flushPromises()
    expect(wrapper.get('[data-testid="guest-actions-101"]').attributes('disabled')).toBeUndefined()
  })

  it('needs a fresh acknowledgement after observing again', async () => {
    listProxmoxAccounts.mockResolvedValue(ok(page([account({ fingerprint: null, fingerprintState: 'unconfirmed' })])))
    observeProxmoxFingerprint.mockResolvedValue(ok({ data: { accountId: 'acc1', fingerprint: 'DD:EE:FF' } }))
    const { wrapper } = await mountAt('/proxmox')
    await wrapper.get('[data-testid="observe"]').trigger('click')
    await flushPromises()
    await wrapper.get('[data-testid="acknowledge"]').setValue(true)
    observeProxmoxFingerprint.mockResolvedValue(ok({ code: 'proxmox_source', message: 'unreachable' }, 502))
    await wrapper.get('[data-testid="observe"]').trigger('click')
    await flushPromises()
    expect(wrapper.find('[data-testid="confirm"]').exists()).toBe(false)
    observeProxmoxFingerprint.mockResolvedValue(ok({ data: { accountId: 'acc1', fingerprint: 'DD:EE:FF' } }))
    await wrapper.get('[data-testid="observe"]').trigger('click')
    await flushPromises()
    expect(wrapper.get('[data-testid="confirm"]').attributes('disabled')).toBeDefined()
  })

  it('does not pin without the out-of-band acknowledgement', async () => {
    listProxmoxAccounts.mockResolvedValue(ok(page([account({ fingerprint: null, fingerprintState: 'unconfirmed' })])))
    observeProxmoxFingerprint.mockResolvedValue(ok({ data: { accountId: 'acc1', fingerprint: 'DD:EE:FF' } }))
    const { wrapper } = await mountAt('/proxmox')
    await wrapper.get('[data-testid="observe"]').trigger('click')
    await flushPromises()
    await wrapper.get('[data-testid="confirm"]').trigger('click')
    expect(confirmProxmoxFingerprint).not.toHaveBeenCalled()
  })
})

describe('discovered resources', () => {
  it('shows node capacity with a warning tone for a nearly full pool', async () => {
    const { wrapper } = await mountAt('/proxmox?tab=nodes')
    const node = wrapper.get('[data-testid="node-pve1"]')
    expect(node.text()).toContain('42%')
    expect(node.text()).toContain('8 CPUs')
    expect(node.find('.bg-fc-err').exists()).toBe(true)
  })

  it('confirms a lifecycle action before running it', async () => {
    startProxmoxLifecycle.mockResolvedValue(ok({ data: { id: 'op-1', kind: 'proxmox.lifecycle', state: 'queued' } }, 202))
    const { wrapper } = await mountAt('/proxmox?tab=guests')
    expect(wrapper.get('[data-testid="guest-101"]').text()).toContain('dev-box')
    await wrapper.get('[data-testid="guest-actions-101"]').trigger('click')
    await wrapper.get('[data-testid="lifecycle-shutdown"]').trigger('click')
    expect(startProxmoxLifecycle).not.toHaveBeenCalled()
    await wrapper.get('[data-testid="confirm-lifecycle-101"]').trigger('click')
    await flushPromises()
    expect(startProxmoxLifecycle).toHaveBeenCalledWith('acc1', 101, 'shutdown', { node: 'pve1', vmid: 101, timeoutSeconds: 300 })
    expect(wrapper.text()).toContain('succeeded')
  })

  it('distinguishes a failed guest load and a filter with no matches from an empty cluster', async () => {
    listProxmoxGuests.mockResolvedValue(ok({ code: 'proxmox_auth', message: 'refused' }, 403))
    const failed = await mountAt('/proxmox?tab=guests')
    expect(failed.wrapper.get('[data-testid="guests-error"]').text()).toContain('homelab')
    expect(failed.wrapper.find('[data-testid="guests-empty"]').exists()).toBe(false)
    failed.wrapper.unmount()

    listProxmoxGuests.mockResolvedValue(ok(page([guest])))
    const { wrapper } = await mountAt('/proxmox?tab=guests')
    await wrapper.get('input[placeholder="VMID, name, or node"]').setValue('nothing-like-this')
    expect(wrapper.find('[data-testid="guests-no-match"]').exists()).toBe(true)
    expect(wrapper.find('[data-testid="guests-table"]').exists()).toBe(false)
  })

  it('states that recent tasks have no API yet', async () => {
    const { wrapper } = await mountAt('/proxmox?tab=tasks')
    expect(wrapper.get('[data-testid="tasks-gap"]').text()).toContain('no endpoint')
  })
})
