import { enableAutoUnmount, flushPromises, mount } from '@vue/test-utils'
import { QueryClient, VueQueryPlugin } from '@tanstack/vue-query'
import { createMemoryHistory, createRouter } from 'vue-router'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import type {
  MachineDto,
  PageAssociatedGuestDtoItemsItem,
  PageCorrelatedDeviceDto,
  PageCorrelatedDeviceDtoItemsItem,
  PageMachineDto,
  PageProxmoxAccountDto,
  ProxmoxDiscoveryDto,
} from '@frogbyte-io/fleet-api-client'

const listMachines = vi.fn()
const listProxmoxAccounts = vi.fn()
const discoverProxmoxCluster = vi.fn()
const listProxmoxGuests = vi.fn()
const getTailnetStatus = vi.fn()
const listTailnetDevices = vi.fn()

vi.mock('@frogbyte-io/fleet-api-client', () => ({
  listMachines: (...args: unknown[]) => listMachines(...args),
  listProxmoxAccounts: (...args: unknown[]) => listProxmoxAccounts(...args),
  discoverProxmoxCluster: (...args: unknown[]) => discoverProxmoxCluster(...args),
  listProxmoxGuests: (...args: unknown[]) => listProxmoxGuests(...args),
  getTailnetStatus: (...args: unknown[]) => getTailnetStatus(...args),
  listTailnetDevices: (...args: unknown[]) => listTailnetDevices(...args),
}))

import FleetPage from '../FleetPage.vue'
import { routes } from '@/router'

// shadcn-vue primitives observe layout; jsdom lacks both APIs.
class ResizeObserverStub {
  observe() {}
  unobserve() {}
  disconnect() {}
}
vi.stubGlobal('ResizeObserver', ResizeObserverStub)
vi.stubGlobal('matchMedia', () => ({ matches: false, addListener: () => {}, removeListener: () => {}, addEventListener: () => {}, removeEventListener: () => {} }))

const NOW = 1_700_000_000_000

function machine(): MachineDto {
  return {
    id: 'm1',
    name: 'build-host',
    description: '',
    endpoints: [
      { id: 'e1', kind: 'fleetd', reference: 'node-abc' },
      { id: 'e2', kind: 'ssh', reference: '***@host:22' },
    ],
    tags: ['linux'],
    groups: [],
    machineStatus: 'connected',
    lastSeenAt: NOW - 30_000,
    lastObservation: null,
    capabilities: [
      { namespace: 'os', name: 'distribution', value: 'ubuntu', status: 'known', observedAt: NOW, source: 'fleetd/1' },
      { namespace: 'host', name: 'architecture', value: 'x86_64', status: 'known', observedAt: NOW, source: 'fleetd/1' },
    ],
    createdAt: 0,
    updatedAt: 0,
  }
}

function account() {
  return {
    id: 'acc1',
    name: 'homelab',
    host: 'pve.lan',
    port: 8006,
    tokenId: 'root@pam!tk',
    fingerprint: 'sha256:xyz',
    fingerprintState: 'confirmed',
    createdAt: 0,
  }
}

function discovery(): ProxmoxDiscoveryDto {
  return {
    accountId: 'acc1',
    observedAt: NOW,
    pveVersion: '8.2.4',
    reportedCount: 3,
    warnings: [],
    resources: [
      { accountId: 'acc1', id: 'node-pve', kind: 'node', name: 'pve', node: null, status: 'online', vmid: null, observedAt: NOW, pveVersion: '8.2.4' },
      { accountId: 'acc1', id: 'q-100', kind: 'qemu', name: 'web', node: 'pve', status: 'running', vmid: 100, observedAt: NOW, pveVersion: '8.2.4' },
      { accountId: 'acc1', id: 'lxc-200', kind: 'lxc', name: 'db', node: 'pve', status: 'stopped', vmid: 200, observedAt: NOW, pveVersion: '8.2.4' },
      { accountId: 'acc1', id: 't-9000', kind: 'qemu-template', name: 'tpl', node: 'pve', status: 'stopped', vmid: 9000, observedAt: NOW, pveVersion: '8.2.4' },
    ],
  }
}

function guest(): PageAssociatedGuestDtoItemsItem {
  return {
    id: 'q-100',
    kind: 'qemu',
    vmid: 100,
    name: 'web',
    node: 'pve',
    status: 'running',
    agent: { online: true, osName: 'Debian 12', version: null, kernel: null, interfaces: [] },
    candidates: [{ machineId: 'm1', machineName: 'build-host', machineStatus: 'connected', kind: 'mac_match', evidence: 'aa:bb:cc:dd:ee:ff' }],
    warnings: [],
    macs: [],
    observedAt: NOW,
    pveVersion: '8.2.4',
  }
}

function page<T>(items: T[], nextCursor: string | null = null): { items: T[], page: { nextCursor: string | null, limit: number } } {
  return { items, page: { nextCursor, limit: 200 } }
}

function ok<T>(data: T) {
  return { status: 200, data, headers: new Headers() }
}

function stubHappyPath() {
  listMachines.mockResolvedValue(ok(page([machine()]) as PageMachineDto))
  listProxmoxAccounts.mockResolvedValue(ok(page([account()]) as PageProxmoxAccountDto))
  discoverProxmoxCluster.mockResolvedValue(ok({ data: discovery() }))
  listProxmoxGuests.mockResolvedValue(ok(page([
    guest(),
    {
      id: 'lxc-200',
      kind: 'lxc',
      vmid: 200,
      name: 'db',
      node: 'pve',
      status: 'stopped',
      agent: null,
      candidates: [],
      warnings: [],
      macs: [],
      observedAt: NOW,
      pveVersion: '8.2.4',
    } as PageAssociatedGuestDtoItemsItem,
  ])))
  getTailnetStatus.mockResolvedValue(ok({ data: { configured: true, clientId: 'cid', scope: 'devices:core:read' } }))
  listTailnetDevices.mockResolvedValue(ok(page([
    {
      nodeId: 'ts1',
      name: 'build-host.tailnet.xyz',
      hostname: 'build-host',
      os: 'linux',
      addresses: ['100.64.0.1'],
      tags: [],
      user: 'op',
      online: true,
      lastSeen: null,
      candidates: [{ machineId: 'm1', machineName: 'build-host', machineStatus: 'connected', reference: '100.64.0.1', kind: 'address_match' }],
    },
    {
      nodeId: 'ts2',
      name: 'spare.tailnet.xyz',
      hostname: 'spare',
      os: 'linux',
      addresses: ['100.64.0.2'],
      tags: [],
      user: 'op',
      online: false,
      lastSeen: null,
      candidates: [],
    },
  ] as PageCorrelatedDeviceDtoItemsItem[])))
}

function makeRouter() {
  return createRouter({ history: createMemoryHistory(), routes })
}

async function mountPage() {
  const router = makeRouter()
  await router.push('/fleet')
  await router.isReady()
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false, staleTime: Infinity } },
  })
  return mount(FleetPage, {
    global: {
      plugins: [[VueQueryPlugin, { queryClient }], router],
    },
  })
}

afterEach(() => {
  document.body.innerHTML = ''
})

enableAutoUnmount(afterEach)

beforeEach(() => {
  localStorage.clear()
  listMachines.mockReset()
  listProxmoxAccounts.mockReset()
  discoverProxmoxCluster.mockReset()
  listProxmoxGuests.mockReset()
  getTailnetStatus.mockReset()
  listTailnetDevices.mockReset()
  stubHappyPath()
})

describe('FleetPage', () => {
  it('renders section headers, candidate evidence, and tailnet-only cards', async () => {
    const wrapper = await mountPage()
    await flushPromises()
    await flushPromises()

    const text = wrapper.text()
    expect(text).toContain('Proxmox hosts')
    expect(text).toContain('Virtual machines & containers')
    expect(text).toContain('Machines')
    expect(text).toContain('On your tailnet — not in Fleet')
    expect(text).toContain('build-host')
    expect(text).toContain('≈ build-host (aa:bb:cc:dd:ee:ff)')
    expect(text).toContain('spare.tailnet.xyz')
    expect(wrapper.find('[data-testid="copy-import"]').exists()).toBe(true)
  })

  it('excludes templates from the guest section', async () => {
    const wrapper = await mountPage()
    await flushPromises()
    await flushPromises()

    expect(wrapper.text()).not.toContain('tpl')
  })

  it('switches to the table view and renders rows', async () => {
    const wrapper = await mountPage()
    await flushPromises()
    await flushPromises()

    await wrapper.get('[data-testid="view-table"]').trigger('click')
    await flushPromises()
    expect(wrapper.find('[data-testid="table-view"]').exists()).toBe(true)
    expect(wrapper.text()).toContain('build-host')
  })

  it('shows an error banner and still renders machines when discovery fails', async () => {
    discoverProxmoxCluster.mockRejectedValue(new Error('connection refused'))
    const wrapper = await mountPage()
    await flushPromises()
    await flushPromises()

    const text = wrapper.text()
    expect(text).toContain('build-host')
    expect(text).toContain('connection refused')
    expect(text).toContain('Proxmox account homelab')
  })

  it('selects a machine via ?focus= and opens the table view', async () => {
    localStorage.setItem('fleet-console-fleet-view', 'cards')
    const router = makeRouter()
    await router.push('/fleet?focus=m1')
    await router.isReady()
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false, staleTime: Infinity } },
    })
    const wrapper = mount(FleetPage, {
      global: {
        plugins: [[VueQueryPlugin, { queryClient }], router],
      },
    })
    await flushPromises()
    await flushPromises()

    expect(wrapper.find('[data-testid="table-view"]').exists()).toBe(true)
    // A deep link switches the view for this visit only.
    expect(localStorage.getItem('fleet-console-fleet-view')).toBe('cards')
  })

  it('opens a guest drawer with agent info when clicking a guest row', async () => {
    const wrapper = await mountPage()
    await flushPromises()
    await flushPromises()

    await wrapper.get('[data-testid="view-table"]').trigger('click')
    await flushPromises()

    const guestRows = wrapper.findAll('tbody tr').filter(r => r.text().includes('web'))
    await guestRows[0]!.trigger('click')
    await flushPromises()

    expect(document.body.textContent).toContain('Guest agent')
    expect(document.body.textContent).toContain('ONLINE')
    expect(document.body.textContent).not.toContain('Not observed yet')
  })

  it('shows "Not observed yet" in the machine drawer when no facts exist', async () => {
    listMachines.mockResolvedValue(ok(page([{
      ...machine(),
      capabilities: [],
    }]) as PageMachineDto))
    const router = makeRouter()
    await router.push('/fleet?focus=m1')
    await router.isReady()
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false, staleTime: Infinity } },
    })
    await mount(FleetPage, {
      global: {
        plugins: [[VueQueryPlugin, { queryClient }], router],
      },
    })
    await flushPromises()
    await flushPromises()

    expect(document.body.textContent).toContain('Not observed yet')
    expect(document.body.textContent).not.toContain('—C')
  })

  it('shows the empty machines row in the table and cards view', async () => {
    listMachines.mockResolvedValue(ok(page([]) as PageMachineDto))
    const wrapper = await mountPage()
    await flushPromises()
    await flushPromises()

    expect(wrapper.text()).toContain('No machines yet')
    expect(wrapper.text()).toContain('Add machine')

    await wrapper.get('[data-testid="view-table"]').trigger('click')
    await flushPromises()
    expect(wrapper.text()).toContain('No machines yet')
  })

  it('shows an error empty state when machines fail with nothing else to show', async () => {
    listMachines.mockRejectedValue(new Error('listMachines failed (500)'))
    listProxmoxAccounts.mockResolvedValue(ok(page([]) as PageProxmoxAccountDto))
    getTailnetStatus.mockResolvedValue(ok({ data: { configured: false, clientId: null, scope: null } }))
    const wrapper = await mountPage()
    await flushPromises()
    await flushPromises()

    expect(wrapper.find('[data-testid="empty-error"]').exists()).toBe(true)
    expect(wrapper.text()).toContain('Machines could not be loaded')
    expect(wrapper.text()).not.toContain('No machines yet')

    await wrapper.get('[data-testid="view-table"]').trigger('click')
    await flushPromises()
    expect(wrapper.text()).toContain('Machines could not be loaded')
  })

  it('renders the normal views when machines fail but Proxmox data is present', async () => {
    listMachines.mockRejectedValue(new Error('listMachines failed (500)'))
    const wrapper = await mountPage()
    await flushPromises()
    await flushPromises()

    expect(wrapper.find('[data-testid="empty-error"]').exists()).toBe(false)
    expect(wrapper.text()).toContain('Proxmox hosts')
    expect(wrapper.text()).toContain('pve')
    expect(wrapper.text()).toContain('listMachines failed (500)')
  })

  it('fetches machines in one request and flags a truncated list', async () => {
    // The machines endpoint has no cursor parameter: one request with the
    // clamped limit is the whole list, and a reported next cursor means it was
    // cut short, which is surfaced rather than hidden (#151).
    listMachines.mockResolvedValueOnce(ok(page([machine()], 'more') as PageMachineDto))
    const wrapper = await mountPage()
    await flushPromises()
    await flushPromises()

    expect(wrapper.text()).toContain('build-host')
    expect(listMachines).toHaveBeenCalledTimes(1)
    expect(listMachines.mock.calls[0]![0]).toMatchObject({ limit: 200 })
    expect(listMachines.mock.calls[0]![0]).not.toHaveProperty('cursor')
    expect(wrapper.text()).toContain('Showing the first 200 machines — the machines API cannot page further yet (#151).')
  })

  it('paginates tailnet devices across nextCursor pages', async () => {
    listTailnetDevices
      .mockResolvedValueOnce(ok(page([{
        nodeId: 'ts2',
        name: 'spare.tailnet.xyz',
        hostname: 'spare',
        os: 'linux',
        addresses: ['100.64.0.2'],
        tags: [],
        user: 'op',
        online: true,
        lastSeen: null,
        candidates: [],
      }], 'ts-cursor') as unknown as PageCorrelatedDeviceDto))
      .mockResolvedValueOnce(ok(page([{
        nodeId: 'ts3',
        name: 'third.tailnet.xyz',
        hostname: 'third',
        os: 'linux',
        addresses: ['100.64.0.3'],
        tags: [],
        user: 'op',
        online: true,
        lastSeen: null,
        candidates: [],
      }], null) as unknown as PageCorrelatedDeviceDto))
    const wrapper = await mountPage()
    await flushPromises()
    await flushPromises()

    expect(wrapper.text()).toContain('spare.tailnet.xyz')
    expect(wrapper.text()).toContain('third.tailnet.xyz')
    expect(listTailnetDevices).toHaveBeenCalledTimes(2)
    expect(listTailnetDevices.mock.calls[1]![0]).toMatchObject({ cursor: 'ts-cursor' })
  })

  it('keeps the host row visible as context when only a guest matches the search', async () => {
    const wrapper = await mountPage()
    await flushPromises()
    await flushPromises()

    await wrapper.get('[data-testid="search"]').setValue('web')
    await flushPromises()

    const text = wrapper.text()
    expect(text).toContain('web')
    expect(text).toContain('pve')
  })

  it('renders UNKNOWN for a tailnet device with null online', async () => {
    listTailnetDevices.mockResolvedValue(ok(page([{
      nodeId: 'ts2',
      name: 'spare.tailnet.xyz',
      hostname: 'spare',
      os: 'linux',
      addresses: ['100.64.0.2'],
      tags: [],
      user: 'op',
      online: null,
      lastSeen: null,
      candidates: [],
    }] as unknown as PageCorrelatedDeviceDtoItemsItem[])))
    const wrapper = await mountPage()
    await flushPromises()
    await flushPromises()

    expect(wrapper.text()).toContain('UNKNOWN')
    expect(wrapper.text()).not.toContain('OFFLINE')
  })

  it('shows a tailnet status error banner when getTailnetStatus fails', async () => {
    getTailnetStatus.mockRejectedValue(new Error('getTailnetStatus failed (503)'))
    const wrapper = await mountPage()
    await flushPromises()
    await flushPromises()

    expect(wrapper.text()).toContain('Tailnet status unavailable: getTailnetStatus failed (503)')
  })

  it('shows an accounts-unavailable banner when listProxmoxAccounts fails', async () => {
    listProxmoxAccounts.mockRejectedValue(new Error('listProxmoxAccounts failed (503)'))
    const wrapper = await mountPage()
    await flushPromises()
    await flushPromises()

    expect(wrapper.text()).toContain('Proxmox accounts unavailable: listProxmoxAccounts failed (503)')
  })

  it('copies a shell-safe fleetctl import command', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined)
    const previous = Object.getOwnPropertyDescriptor(navigator, 'clipboard')
    Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true })
    try {
      const wrapper = await mountPage()
      await flushPromises()
      await flushPromises()

      await wrapper.get('[data-testid="copy-import"]').trigger('click')
      expect(writeText).toHaveBeenCalledWith('fleetctl tailnet import ts2 --user SSH_USER')
    }
    finally {
      if (previous)
        Object.defineProperty(navigator, 'clipboard', previous)
      else
        delete (navigator as { clipboard?: unknown }).clipboard
    }
  })

  it('clears a machines truncation warning after a complete refetch', async () => {
    listMachines
      .mockResolvedValueOnce(ok(page([machine()], 'more') as PageMachineDto))
      .mockResolvedValue(ok(page([machine()]) as PageMachineDto))
    const wrapper = await mountPage()
    await flushPromises()
    await flushPromises()

    expect(wrapper.text()).toContain('Showing the first 200 machines — the machines API cannot page further yet (#151).')

    await wrapper.get('[data-testid="refresh"]').trigger('click')
    await flushPromises()
    await flushPromises()

    expect(wrapper.text()).not.toContain('cannot page further yet')
  })
})
