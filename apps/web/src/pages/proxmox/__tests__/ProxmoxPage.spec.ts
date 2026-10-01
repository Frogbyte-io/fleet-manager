import { enableAutoUnmount, flushPromises, mount } from '@vue/test-utils'
import { QueryClient, VueQueryPlugin } from '@tanstack/vue-query'
import { createMemoryHistory, createRouter } from 'vue-router'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import type {
  AssociatedGuestDto,
  ProxmoxAccountDto,
  ProxmoxDiscoveryDto,
  ProxmoxPrivilegesDto,
  ProxmoxTaskDto,
  ProxmoxTaskPage,
} from '@frogbyte-io/fleet-api-client'

// The stub API: every generated client call the Proxmox page makes.
const listProxmoxAccounts = vi.fn()
const discoverProxmoxCluster = vi.fn()
const listProxmoxGuests = vi.fn()
const observeProxmoxFingerprint = vi.fn()
const confirmProxmoxFingerprint = vi.fn()
const startProxmoxLifecycle = vi.fn()
const getOperation = vi.fn()
const getProxmoxPrivileges = vi.fn()
const listProxmoxTasks = vi.fn()

vi.mock('@frogbyte-io/fleet-api-client', () => ({
  getProxmoxPrivileges: (...args: unknown[]) => getProxmoxPrivileges(...args),
  listProxmoxTasks: (...args: unknown[]) => listProxmoxTasks(...args),
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
import { TOKEN_GUIDE_URL } from '../proxmox'
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

function privileges(overrides: Partial<ProxmoxPrivilegesDto> = {}): ProxmoxPrivilegesDto {
  return {
    accountId: 'acc1',
    pveVersion: '8.2.4',
    rulesMajor: 8,
    effectivePermissions: {},
    warnings: [],
    observedAt: Date.now(),
    tiers: [
      { tier: 'discover', status: 'granted', missing: [], checks: [] },
      { tier: 'operate', status: 'granted', missing: [], checks: [] },
      { tier: 'destructive', status: 'unknown', missing: [], checks: [] },
      { tier: 'lab', status: 'granted', missing: [], checks: [] },
    ],
    ...overrides,
  }
}

const OPERATE_MISSING = privileges({
  tiers: [
    { tier: 'discover', status: 'granted', missing: [], checks: [] },
    { tier: 'operate', status: 'missing', missing: [{ path: '/vms/{vmid}', privileges: ['VM.PowerMgmt'], anyOf: false, capabilities: ['proxmox.guest.start'] }], checks: [] },
    { tier: 'destructive', status: 'missing', missing: [{ path: '/vms/{vmid}', privileges: ['VM.Snapshot'], anyOf: false, capabilities: ['proxmox.guest.snapshot'] }], checks: [] },
    { tier: 'lab', status: 'missing', missing: [], checks: [] },
  ],
})

function task(overrides: Partial<ProxmoxTaskDto> = {}): ProxmoxTaskDto {
  return { upid: 'UPID:pve1:1', node: 'pve1', taskType: 'qmstart', targetId: '101', user: 'fleet@pve', tokenId: 'console', startedAt: Date.now() - 60_000, endedAt: Date.now() - 55_000, status: 'ok', exitStatus: 'OK', fleetOperationId: null, ...overrides }
}

function taskPage(items: ProxmoxTaskDto[], nextCursor: string | null = null, warnings: string[] = []): ProxmoxTaskPage {
  return { accountId: 'acc1', items, page: { nextCursor, limit: 50 }, pveVersion: '8.2.4', warnings, observedAt: Date.now() }
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
  return { wrapper, router, queryClient }
}

enableAutoUnmount(afterEach)

beforeEach(() => {
  for (const mock of [listProxmoxAccounts, discoverProxmoxCluster, listProxmoxGuests, observeProxmoxFingerprint, confirmProxmoxFingerprint, startProxmoxLifecycle, getOperation, getProxmoxPrivileges, listProxmoxTasks])
    mock.mockReset()
  getProxmoxPrivileges.mockResolvedValue(ok({ data: privileges() }))
  listProxmoxTasks.mockResolvedValue(ok(taskPage([])))
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

})

describe('privileges and compatibility', () => {
  it('shows each tier chip as the API reported it', async () => {
    getProxmoxPrivileges.mockResolvedValue(ok({ data: OPERATE_MISSING }))
    const { wrapper } = await mountAt('/proxmox')
    expect(getProxmoxPrivileges).toHaveBeenCalledWith('acc1')
    const card = wrapper.get('[data-testid="account-acc1"]')
    expect(card.get('[data-testid="tier-discover"]').attributes('data-status')).toBe('granted')
    expect(card.get('[data-testid="tier-operate"]').attributes('data-status')).toBe('missing')
    expect(card.get('[data-testid="tier-operate"]').text()).toContain('operate · missing')
    expect(card.get('[data-testid="tier-operate"]').classes()).toContain('text-fc-err')
    expect(card.get('[data-testid="tier-discover"]').classes()).toContain('text-fc-ok')
  })

  it('shows unknown chips with the reason while the permissions read is refused', async () => {
    getProxmoxPrivileges.mockResolvedValue(ok({ data: privileges({
      unknownReason: 'the token may not read its own permissions',
      tiers: (['discover', 'operate', 'destructive', 'lab'] as const).map(tier => ({ tier, status: 'unknown' as const, missing: [], checks: [] })),
    }) }))
    const { wrapper } = await mountAt('/proxmox')
    for (const tier of ['discover', 'operate', 'destructive', 'lab'])
      expect(wrapper.get(`[data-testid="tier-${tier}"]`).attributes('data-status')).toBe('unknown')
    await wrapper.get('[data-testid="tier-operate"]').trigger('click')
    await flushPromises()
    expect(document.body.querySelector('[data-testid="tier-popover-operate"]')?.textContent).toContain('may not read its own permissions')
  })

  it('lists missing privileges and paths in a popover with fleetctl and the token guide', async () => {
    getProxmoxPrivileges.mockResolvedValue(ok({ data: OPERATE_MISSING }))
    const { wrapper } = await mountAt('/proxmox')
    const trigger = wrapper.get('[data-testid="tier-operate"]')
    expect(trigger.attributes('aria-expanded')).toBe('false')
    await trigger.trigger('click')
    await flushPromises()
    expect(trigger.attributes('aria-expanded')).toBe('true')
    const popover = document.body.querySelector('[data-testid="tier-popover-operate"]')!
    expect(popover.querySelector('[data-testid="missing-privilege"]')?.textContent).toContain('VM.PowerMgmt')
    expect(popover.querySelector('[data-testid="missing-privilege"]')?.textContent).toContain('/vms/{vmid}')
    const guide = popover.querySelector<HTMLAnchorElement>('[data-testid="token-guide"]')!
    expect(guide.getAttribute('href')).toBe(TOKEN_GUIDE_URL)
    expect(guide.getAttribute('rel')).toBe('noopener noreferrer')
    expect(popover.querySelector('[data-testid="fleetctl-command"]')?.textContent).toBe('fleetctl proxmox privileges acc1')
  })

  it('does not ask an unconfirmed account for privileges or tasks', async () => {
    listProxmoxAccounts.mockResolvedValue(ok(page([account({ fingerprint: null, fingerprintState: 'unconfirmed' })])))
    const { wrapper } = await mountAt('/proxmox?tab=tasks')
    expect(getProxmoxPrivileges).not.toHaveBeenCalled()
    expect(listProxmoxTasks).not.toHaveBeenCalled()
    expect(wrapper.get('[data-testid="tasks-blocked"]').text()).toContain('homelab')
    expect(wrapper.find('[data-testid="tasks-no-account"]').exists()).toBe(true)
  })

  it('badges a verified major from the API version', async () => {
    const { wrapper } = await mountAt('/proxmox')
    const badge = wrapper.get('[data-testid="compatibility"]')
    expect(badge.text()).toContain('PVE 8 · verified')
    expect(badge.attributes('data-verified')).toBe('true')
  })

  it('badges an unverified major, including one the API clamped to another major\'s rules', async () => {
    getProxmoxPrivileges.mockResolvedValue(ok({ data: privileges({ pveVersion: '10.0.1', rulesMajor: 9 }) }))
    const { wrapper } = await mountAt('/proxmox')
    const badge = wrapper.get('[data-testid="compatibility"]')
    expect(badge.text()).toContain('unverified major')
    expect(badge.attributes('data-verified')).toBe('false')
    expect(badge.attributes('title')).toContain('9.x rules')
  })
})

describe('guest actions and privileges', () => {
  it('disables lifecycle actions with an explanation when operate is missing', async () => {
    getProxmoxPrivileges.mockResolvedValue(ok({ data: OPERATE_MISSING }))
    const { wrapper } = await mountAt('/proxmox?tab=guests')
    await wrapper.get('[data-testid="guest-actions-101"]').trigger('click')
    const start = wrapper.get('[data-testid="lifecycle-start"]')
    expect(start.attributes('disabled')).toBeDefined()
    expect(start.attributes('title')).toContain('VM.PowerMgmt on /vms/{vmid}')
    const note = wrapper.get('[data-testid="operate-blocked"]')
    expect(start.attributes('aria-describedby')).toBe(note.attributes('id'))
    expect(wrapper.get('[data-testid="destructive-blocked"]').text()).toContain('VM.Snapshot')
    await start.trigger('click')
    expect(wrapper.find('[data-testid="confirm-lifecycle-101"]').exists()).toBe(false)
    expect(startProxmoxLifecycle).not.toHaveBeenCalled()
  })

  it('keeps lifecycle actions enabled when operate is unknown or the report failed', async () => {
    getProxmoxPrivileges.mockResolvedValue(ok({ data: privileges({
      tiers: (['discover', 'operate', 'destructive', 'lab'] as const).map(tier => ({ tier, status: 'unknown' as const, missing: [], checks: [] })),
    }) }))
    const unknown = await mountAt('/proxmox?tab=guests')
    await unknown.wrapper.get('[data-testid="guest-actions-101"]').trigger('click')
    expect(unknown.wrapper.get('[data-testid="lifecycle-start"]').attributes('disabled')).toBeUndefined()
    expect(unknown.wrapper.find('[data-testid="operate-blocked"]').exists()).toBe(false)
    unknown.wrapper.unmount()

    getProxmoxPrivileges.mockResolvedValue(ok({ code: 'proxmox_source', message: 'unreachable' }, 502))
    const failed = await mountAt('/proxmox?tab=guests')
    await failed.wrapper.get('[data-testid="guest-actions-101"]').trigger('click')
    expect(failed.wrapper.get('[data-testid="lifecycle-start"]').attributes('disabled')).toBeUndefined()
  })
})

describe('stale privilege reports and refetches', () => {
  it('does not present a cached report as current after a failed refetch', async () => {
    getProxmoxPrivileges.mockResolvedValue(ok({ data: OPERATE_MISSING }))
    const { wrapper, queryClient } = await mountAt('/proxmox?tab=guests')
    await wrapper.get('[data-testid="guest-actions-101"]').trigger('click')
    expect(wrapper.get('[data-testid="lifecycle-start"]').attributes('disabled')).toBeDefined()

    getProxmoxPrivileges.mockResolvedValue(ok({ code: 'forbidden', message: 'denied' }, 403))
    await queryClient.refetchQueries({ queryKey: ['proxmox', 'privileges', 'acc1'] })
    await flushPromises()
    expect(wrapper.get('[data-testid="lifecycle-start"]').attributes('disabled')).toBeUndefined()
    expect(wrapper.find('[data-testid="operate-blocked"]').exists()).toBe(false)
  })

  it('shows tier chips as unknown, not as the cached result, after a failed refetch', async () => {
    getProxmoxPrivileges.mockResolvedValue(ok({ data: OPERATE_MISSING }))
    const { wrapper, queryClient } = await mountAt('/proxmox')
    expect(wrapper.get('[data-testid="tier-operate"]').attributes('data-status')).toBe('missing')
    getProxmoxPrivileges.mockResolvedValue(ok({ code: 'forbidden', message: 'denied' }, 403))
    await queryClient.refetchQueries({ queryKey: ['proxmox', 'privileges', 'acc1'] })
    await flushPromises()
    expect(wrapper.get('[data-testid="tier-operate"]').attributes('data-status')).toBe('unknown')
  })

  it('waits for a running discovery refetch before asking for privileges', async () => {
    const { queryClient } = await mountAt('/proxmox')
    expect(getProxmoxPrivileges).toHaveBeenCalledTimes(1)
    let finish!: (value: unknown) => void
    discoverProxmoxCluster.mockReturnValue(new Promise((resolve) => { finish = resolve }))
    const refetching = queryClient.refetchQueries({ queryKey: ['fleet', 'proxmox-discovery', 'acc1'] })
    await flushPromises()
    await queryClient.invalidateQueries({ queryKey: ['proxmox', 'privileges', 'acc1'] })
    await flushPromises()
    expect(getProxmoxPrivileges).toHaveBeenCalledTimes(1)
    finish(ok({ data: discovery }))
    await refetching
    await flushPromises()
    expect(getProxmoxPrivileges).toHaveBeenCalledTimes(2)
  })
})

describe('tasks', () => {
  it('keeps the account and filters while the account is briefly not pinned', async () => {
    const { wrapper, queryClient } = await mountAt('/proxmox?tab=tasks')
    await wrapper.get('[data-testid="tasks-status"]').setValue('error')
    await flushPromises()
    const calls = listProxmoxTasks.mock.calls.length

    discoverProxmoxCluster.mockResolvedValue(ok({ code: 'forbidden', message: 'denied' }, 403))
    await queryClient.refetchQueries({ queryKey: ['fleet', 'proxmox-discovery', 'acc1'] })
    await flushPromises()
    expect(wrapper.find('[data-testid="tasks-unavailable"]').exists()).toBe(true)
    expect(listProxmoxTasks).toHaveBeenCalledTimes(calls)

    discoverProxmoxCluster.mockResolvedValue(ok({ data: discovery }))
    await queryClient.refetchQueries({ queryKey: ['fleet', 'proxmox-discovery', 'acc1'] })
    await flushPromises()
    expect(wrapper.find('[data-testid="tasks-unavailable"]').exists()).toBe(false)
    expect((wrapper.get('[data-testid="tasks-status"]').element as HTMLSelectElement).value).toBe('error')
    expect(listProxmoxTasks).toHaveBeenLastCalledWith('acc1', { status: 'error', limit: 50 })
  })

  it('lists tasks with status chips and links Fleet operations', async () => {
    listProxmoxTasks.mockResolvedValue(ok(taskPage([
      task({ upid: 'UPID:a', status: 'running', endedAt: null, exitStatus: null, fleetOperationId: 'op-42' }),
      task({ upid: 'UPID:b', status: 'error', exitStatus: 'command failed' }),
      task({ upid: 'UPID:c', status: 'ok', taskType: 'vzdump', targetId: null }),
      task({ upid: 'UPID:d', status: 'unknown' }),
    ])))
    const { wrapper } = await mountAt('/proxmox?tab=tasks')
    expect(listProxmoxTasks).toHaveBeenCalledWith('acc1', { limit: 50 })
    expect(wrapper.findAll('[data-testid="task-row"]')).toHaveLength(4)
    expect(wrapper.get('[data-testid="task-status-running"]').text()).toBe('running')
    expect(wrapper.get('[data-testid="task-status-error"]').text()).toBe('ERROR')
    expect(wrapper.get('[data-testid="task-status-ok"]').text()).toBe('OK')
    expect(wrapper.get('[data-testid="task-status-unknown"]').text()).toBe('unknown')
    expect(wrapper.text()).toContain('command failed')
    const links = wrapper.findAll('[data-testid="task-operation"]')
    expect(links).toHaveLength(1)
    expect(links[0]!.attributes('href')).toBe('/operations?op=op-42')
    expect(wrapper.get('[data-testid="fleetctl-command"]').text()).toBe('fleetctl proxmox tasks acc1')
  })

  it('filters by node, guest, and status and mirrors them in fleetctl', async () => {
    listProxmoxGuests.mockResolvedValue(ok(page([guest])))
    const { wrapper } = await mountAt('/proxmox?tab=tasks')
    await wrapper.get('[data-testid="tasks-node"]').setValue('pve1')
    await flushPromises()
    expect(listProxmoxTasks).toHaveBeenLastCalledWith('acc1', { node: 'pve1', limit: 50 })
    await wrapper.get('[data-testid="tasks-guest"]').setValue('101')
    await wrapper.get('[data-testid="tasks-status"]').setValue('error')
    await flushPromises()
    expect(listProxmoxTasks).toHaveBeenLastCalledWith('acc1', { node: 'pve1', vmid: 101, status: 'error', limit: 50 })
    expect(wrapper.get('[data-testid="fleetctl-command"]').text()).toBe('fleetctl proxmox tasks acc1 --node pve1 --vmid 101 --status error')
    expect(wrapper.get('[data-testid="tasks-empty"]').text()).toContain('No tasks match')
    // Clearing returns to the unfiltered first page (cached here).
    await wrapper.get('[data-testid="tasks-clear"]').trigger('click')
    await flushPromises()
    expect(wrapper.get('[data-testid="fleetctl-command"]').text()).toBe('fleetctl proxmox tasks acc1')
    expect(wrapper.get('[data-testid="tasks-empty"]').text()).toContain('no recent tasks')
  })

  it('says the token cannot see the cluster when discover is missing, not that PVE has no tasks', async () => {
    getProxmoxPrivileges.mockResolvedValue(ok({ data: privileges({
      tiers: [
        { tier: 'discover', status: 'missing', missing: [{ path: '/nodes/{node}', privileges: ['Sys.Audit'], anyOf: false, capabilities: ['read.node-status'] }], checks: [] },
        { tier: 'operate', status: 'missing', missing: [], checks: [] },
        { tier: 'destructive', status: 'missing', missing: [], checks: [] },
        { tier: 'lab', status: 'missing', missing: [], checks: [] },
      ],
    }) }))
    listProxmoxTasks.mockResolvedValue(ok(taskPage([])))
    const { wrapper } = await mountAt('/proxmox?tab=tasks')
    const empty = wrapper.get('[data-testid="tasks-empty"]').text()
    expect(empty).toContain('cannot see this cluster')
    expect(empty).toContain('Sys.Audit on /nodes/{node}')
    expect(empty).not.toContain('no recent tasks')
  })

  it('loads more pages by cursor until the last page', async () => {
    listProxmoxTasks
      .mockResolvedValueOnce(ok(taskPage([task({ upid: 'UPID:1' })], 'UPID:1')))
      .mockResolvedValueOnce(ok(taskPage([task({ upid: 'UPID:2' })], null)))
    const { wrapper } = await mountAt('/proxmox?tab=tasks')
    expect(wrapper.findAll('[data-testid="task-row"]')).toHaveLength(1)
    await wrapper.get('[data-testid="tasks-more"]').trigger('click')
    await flushPromises()
    expect(listProxmoxTasks).toHaveBeenLastCalledWith('acc1', { cursor: 'UPID:1', limit: 50 })
    expect(wrapper.findAll('[data-testid="task-row"]').map(r => r.attributes('data-upid'))).toEqual(['UPID:1', 'UPID:2'])
    expect(wrapper.find('[data-testid="tasks-more"]').exists()).toBe(false)
  })

  it('shows the snapshot warnings once as a banner', async () => {
    const warnings = ['node pve2 answered 595; its tasks are missing', 'node pve3 is offline']
    listProxmoxTasks
      .mockResolvedValueOnce(ok(taskPage([task({ upid: 'UPID:1' })], 'UPID:1', warnings)))
      .mockResolvedValueOnce(ok(taskPage([task({ upid: 'UPID:2' })], null, warnings)))
    const { wrapper } = await mountAt('/proxmox?tab=tasks')
    await wrapper.get('[data-testid="tasks-more"]').trigger('click')
    await flushPromises()
    const banner = wrapper.get('[data-testid="tasks-warnings"]')
    expect(banner.text()).toContain('pve2 answered 595')
    expect(banner.text()).toContain('pve3 is offline')
    expect(banner.text().match(/pve3 is offline/g)).toHaveLength(1)
  })

  it('shows a task-list error with the API code', async () => {
    listProxmoxTasks.mockResolvedValue(ok({ code: 'proxmox_auth', message: 'refused' }, 403))
    const { wrapper } = await mountAt('/proxmox?tab=tasks')
    expect(wrapper.get('[data-testid="tasks-error"]').text()).toContain('proxmox_auth: refused')
  })
})
