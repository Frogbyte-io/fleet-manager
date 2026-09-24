import { flushPromises, mount } from '@vue/test-utils'
import { QueryClient, VueQueryPlugin } from '@tanstack/vue-query'
import { createMemoryHistory, createRouter } from 'vue-router'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import type {
  MachineDto,
  PageAssociatedGuestDtoItemsItem,
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

function page<T>(items: T[]): { items: T[], page: { nextCursor: null, limit: number } } {
  return { items, page: { nextCursor: null, limit: 200 } }
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

function mountPage(router = makeRouter()) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false, staleTime: Infinity } },
  })
  return mount(FleetPage, {
    global: {
      plugins: [[VueQueryPlugin, { queryClient }], router],
    },
  })
}

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
    const router = makeRouter()
    router.push('/fleet')
    await router.isReady()
    const wrapper = mountPage()
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
    expect(text).toContain('NOT LINKED TO A FLEET MACHINE')
    wrapper.unmount()
  })

  it('excludes templates from the guest section', async () => {
    const router = makeRouter()
    router.push('/fleet')
    await router.isReady()
    const wrapper = mountPage()
    await flushPromises()
    await flushPromises()

    expect(wrapper.text()).not.toContain('tpl')
    wrapper.unmount()
  })

  it('switches to the table view and renders rows', async () => {
    const router = makeRouter()
    router.push('/fleet')
    await router.isReady()
    const wrapper = mountPage()
    await flushPromises()
    await flushPromises()

    await wrapper.get('[data-testid="view-table"]').trigger('click')
    await flushPromises()
    expect(wrapper.find('[data-testid="table-view"]').exists()).toBe(true)
    expect(wrapper.text()).toContain('build-host')
    wrapper.unmount()
  })

  it('shows an error banner and still renders machines when discovery fails', async () => {
    discoverProxmoxCluster.mockRejectedValue(new Error('connection refused'))
    const router = makeRouter()
    router.push('/fleet')
    await router.isReady()
    const wrapper = mountPage()
    await flushPromises()
    await flushPromises()

    const text = wrapper.text()
    expect(text).toContain('build-host')
    expect(text).toContain('connection refused')
    expect(text).toContain('Proxmox account homelab')
    wrapper.unmount()
  })

  it('selects a machine via ?focus= and opens the table view', async () => {
    const router = makeRouter()
    router.push('/fleet?focus=m1')
    await router.isReady()
    const wrapper = mountPage(router)
    await flushPromises()
    await flushPromises()

    expect(wrapper.find('[data-testid="table-view"]').exists()).toBe(true)
    wrapper.unmount()
  })
})
