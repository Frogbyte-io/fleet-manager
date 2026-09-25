import { enableAutoUnmount, flushPromises, mount } from '@vue/test-utils'
import { QueryClient, VueQueryPlugin } from '@tanstack/vue-query'
import { defineComponent, h } from 'vue'
import { createMemoryHistory, createRouter, RouterView } from 'vue-router'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import type { MachineDto, OperationDto } from '@frogbyte-io/fleet-api-client'

// A stub of the generated API client: every function the machine page and
// the fleet inventory call, answering with the controller's envelopes.
const api = {
  getMachine: vi.fn(),
  getNode: vi.fn(),
  createEnrollmentToken: vi.fn(),
  revokeNode: vi.fn(),
  createOperation: vi.fn(),
  getOperation: vi.fn(),
  cancelOperation: vi.fn(),
  listProjects: vi.fn(),
  startMiseOperation: vi.fn(),
  startFrogenvOperation: vi.fn(),
  startSkillsOperation: vi.fn(),
  observeProxmoxGuest: vi.fn(),
  startProxmoxLifecycle: vi.fn(),
  reviewProxmoxOperation: vi.fn(),
  startReviewedProxmoxOperation: vi.fn(),
  listMachines: vi.fn(),
  listProxmoxAccounts: vi.fn(),
  discoverProxmoxCluster: vi.fn(),
  listProxmoxGuests: vi.fn(),
  getTailnetStatus: vi.fn(),
  listTailnetDevices: vi.fn(),
}

vi.mock('@frogbyte-io/fleet-api-client', () =>
  Object.fromEntries(Object.entries(api).map(([name, fn]) => [name, (...args: unknown[]) => fn(...args)])))

import { routes } from '@/router'

class ResizeObserverStub {
  observe() {}
  unobserve() {}
  disconnect() {}
}
vi.stubGlobal('ResizeObserver', ResizeObserverStub)
vi.stubGlobal('matchMedia', () => ({ matches: false, addListener: () => {}, removeListener: () => {}, addEventListener: () => {}, removeEventListener: () => {} }))

const writeText = vi.fn().mockResolvedValue(undefined)
Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true })

const NOW = 1_700_000_000_000

function machine(): MachineDto {
  return {
    id: 'm1',
    name: 'build-host',
    description: 'CI builder',
    endpoints: [
      { id: 'e1', kind: 'fleetd', reference: 'node-abc' },
      { id: 'e2', kind: 'ssh', reference: '***@build.lan:22' },
    ],
    tags: ['linux'],
    groups: ['ci'],
    machineStatus: 'connected',
    lastSeenAt: NOW - 30_000,
    lastObservation: { source: 'fleetd/1.2.0', collectedAt: NOW - 60_000 },
    capabilities: [
      { namespace: 'os', name: 'distribution', value: 'ubuntu', status: 'known', observedAt: NOW, source: 'fleetd/1.2.0' },
      { namespace: 'tool', name: 'git', value: '2.43', status: 'stale', observedAt: NOW - 86_400_000, source: 'agentless/1' },
      { namespace: 'tool', name: 'docker', value: null, status: 'unknown', observedAt: NOW, source: 'agentless/1' },
    ],
    createdAt: NOW - 1_000_000,
    updatedAt: NOW,
  }
}

function operation(id: string, kind: string, state = 'running'): OperationDto {
  return { id, kind, state, cancelRequested: false, createdAt: NOW, updatedAt: NOW }
}

function ok<T>(data: T, status = 200) {
  return { status, data, headers: new Headers() }
}

function page<T>(items: T[]) {
  return ok({ items, page: { nextCursor: null, limit: 200 } })
}

function stubApi() {
  api.getMachine.mockResolvedValue(ok({ data: machine() }))
  api.getNode.mockResolvedValue(ok({
    data: {
      machineId: 'm1',
      identity: {
        machineId: 'm1',
        publicKey: 'ab'.repeat(32),
        keyVersion: 2,
        status: 'active',
        os: 'linux',
        arch: 'x86_64',
        nodeVersion: '1.2.0',
        enrolledAt: NOW - 1_000_000,
        gatewayState: 'connected',
        lastSeenAt: NOW - 30_000,
      },
      pendingTokens: [],
      activeCredentials: [{ id: 'c1', machineId: 'm1', nodeKeyVersion: 2, issuedAt: NOW, expiresAt: NOW + 1, status: 'active' }],
      activeSessions: 1,
    },
  }))
  api.getOperation.mockImplementation(async (id: string) => ok({ data: operation(id, 'stub', 'running') }))
  api.listProjects.mockResolvedValue(page([
    {
      id: 'p1',
      name: 'fleet-manager',
      remote: 'github.com/frogbyte-io/fleet-manager',
      description: '',
      createdAt: 0,
      updatedAt: 0,
      checkouts: [
        { machineId: 'm1', root: '/home/dev/code/fleet-manager', branch: 'main', dirty: true, source: 'discovery', observedAt: NOW },
        { machineId: 'm2', root: '/srv/other', branch: 'main', dirty: false, source: 'discovery', observedAt: NOW },
      ],
    },
  ]))
  api.listMachines.mockResolvedValue(page([machine()]))
  api.listProxmoxAccounts.mockResolvedValue(page([
    { id: 'acc1', name: 'homelab', host: 'pve.lan', port: 8006, tokenId: 'root@pam!tk', fingerprint: 'sha256:x', fingerprintState: 'confirmed', createdAt: 0 },
  ]))
  api.discoverProxmoxCluster.mockResolvedValue(ok({
    data: {
      accountId: 'acc1',
      observedAt: NOW,
      pveVersion: '8.2.4',
      reportedCount: 2,
      warnings: [],
      resources: [
        { accountId: 'acc1', id: 'node-pve', kind: 'node', name: 'pve', node: null, status: 'online', vmid: null, observedAt: NOW, pveVersion: '8.2.4' },
        { accountId: 'acc1', id: 'q-100', kind: 'qemu', name: 'build-vm', node: 'pve', status: 'running', vmid: 100, observedAt: NOW, pveVersion: '8.2.4' },
      ],
    },
  }))
  api.listProxmoxGuests.mockResolvedValue(page([
    {
      id: 'q-100',
      kind: 'qemu',
      vmid: 100,
      name: 'build-vm',
      node: 'pve',
      status: 'running',
      agent: { online: true, osName: 'Ubuntu 24.04', version: null, kernel: null, interfaces: [] },
      candidates: [{ machineId: 'm1', machineName: 'build-host', machineStatus: 'connected', kind: 'mac_match', evidence: 'aa:bb:cc:dd:ee:ff' }],
      warnings: [],
      macs: [],
      observedAt: NOW,
      pveVersion: '8.2.4',
    },
  ]))
  api.getTailnetStatus.mockResolvedValue(ok({ data: { configured: false } }))
}

async function mountAt(path: string) {
  const router = createRouter({ history: createMemoryHistory(), routes })
  await router.push(path)
  await router.isReady()
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } })
  const wrapper = mount(defineComponent({ render: () => h(RouterView) }), {
    global: { plugins: [[VueQueryPlugin, { queryClient }], router] },
    attachTo: document.body,
  })
  // The route component is lazy-loaded; wait for it and its queries.
  await vi.waitFor(async () => {
    await flushPromises()
    expect(['h1', '[data-testid="machine-not-found"]', '[data-testid="machine-error"]'].some(sel => wrapper.find(sel).exists())).toBe(true)
  })
  await flushPromises()
  return { wrapper, router }
}

enableAutoUnmount(afterEach)

beforeEach(() => {
  vi.clearAllMocks()
  sessionStorage.clear()
  stubApi()
})

afterEach(() => {
  document.body.innerHTML = ''
})

describe('MachinePage', () => {
  it('overview shows the machine, its connectivity, and client handoffs', async () => {
    const { wrapper } = await mountAt('/fleet/machines/m1')
    expect(wrapper.find('h1').text()).toContain('build-host')
    expect(wrapper.text()).toContain('CI builder')
    expect(wrapper.text()).toContain('ssh · ***@build.lan:22')
    expect(wrapper.text()).toContain('QEMU 100 on pve')

    await wrapper.find('[data-testid="copy-ssh"]').trigger('click')
    // A redacted user is dropped, so the operator's SSH config supplies it.
    expect(writeText).toHaveBeenCalledWith('ssh build.lan')
    expect(wrapper.find('[data-testid="open-vscode"]').attributes('href')).toBe('vscode://vscode-remote/ssh-remote+build.lan/')
  })

  it('shows a not-found state for an unknown machine', async () => {
    api.getMachine.mockResolvedValue({ status: 404, data: { code: 'not_found', message: 'no such machine' }, headers: new Headers() })
    const { wrapper } = await mountAt('/fleet/machines/missing')
    expect(wrapper.find('[data-testid="machine-not-found"]').text()).toContain('missing')
  })

  it('inventory groups facts with provenance and filters by status', async () => {
    const { wrapper } = await mountAt('/fleet/machines/m1?tab=inventory')
    expect(wrapper.text()).toContain('fleetd/1.2.0')
    expect(wrapper.text()).toContain('agentless/1')
    const stale = wrapper.findAll('button').find(b => b.text().startsWith('stale'))!
    expect(stale.text()).toBe('stale 1')
    await stale.trigger('click')
    const rows = wrapper.findAll('tbody tr')
    expect(rows).toHaveLength(1)
    expect(rows[0]!.text()).toContain('git')
  })

  it('connections shows the node, creates a one-time token, and confirms before revoking', async () => {
    api.createEnrollmentToken.mockResolvedValue(ok({ data: { id: 't1', machineId: 'm1', token: 'fm_once_secret', expiresAt: NOW + 3_600_000 } }, 201))
    api.revokeNode.mockResolvedValue(ok({ data: { machineId: 'm1', status: 'revoked' } }))
    const { wrapper } = await mountAt('/fleet/machines/m1?tab=connections')

    expect(wrapper.find('[data-testid="node-identity"]').text()).toContain('fleetd 1.2.0')

    await wrapper.find('[data-testid="create-token"]').trigger('click')
    await flushPromises()
    expect(api.createEnrollmentToken).toHaveBeenCalledWith('m1', { ttlMillis: 3_600_000 })
    expect(wrapper.find('[data-testid="created-token"]').text()).toContain('fm_once_secret')

    await wrapper.find('[data-testid="revoke-node"]').trigger('click')
    expect(api.revokeNode).not.toHaveBeenCalled()
    await wrapper.find('[data-testid="confirm-revoke"]').trigger('click')
    await flushPromises()
    expect(api.revokeNode).toHaveBeenCalledWith('m1')
  })

  it('connections installs fleetd as a durable operation with its fleetctl equivalent', async () => {
    api.createOperation.mockResolvedValue(ok({ data: operation('op-install', 'machine.install-fleetd', 'pending') }, 201))
    const { wrapper } = await mountAt('/fleet/machines/m1?tab=connections')

    const commands = wrapper.findAll('[data-testid="fleetctl-command"]').map(c => c.text())
    expect(commands).toContain(`fleetctl machines install-node m1 --endpoint e2 --auth agent --controller-url ${window.location.origin} --wait`)

    await wrapper.find('[data-testid="install-fleetd"]').trigger('click')
    await flushPromises()
    const request = api.createOperation.mock.calls[0]![0]
    expect(request.kind).toBe('machine.install-fleetd')
    expect(JSON.parse(request.payloadJson)).toEqual({
      machineId: 'm1',
      endpointId: 'e2',
      auth: { type: 'agent' },
      timeoutSeconds: 300,
      controllerUrl: window.location.origin,
    })
    expect(wrapper.find('[data-testid="operation-status"]').text()).toContain('op-install')
  })

  it('projects lists only this machine\'s checkouts', async () => {
    const { wrapper } = await mountAt('/fleet/machines/m1?tab=projects')
    expect(wrapper.text()).toContain('/home/dev/code/fleet-manager')
    expect(wrapper.text()).toContain('dirty')
    expect(wrapper.text()).not.toContain('/srv/other')
  })

  it('tools runs mise install only with a pinned version and tracks the operation', async () => {
    api.startMiseOperation.mockResolvedValue(ok({ data: operation('op-mise', 'mise.install') }, 202))
    const { wrapper, router } = await mountAt('/fleet/machines/m1?tab=tools')

    await wrapper.find('[data-testid="mise-action"]').setValue('install')
    expect(wrapper.find('[data-testid="run-mise"]').attributes('disabled')).toBeDefined()
    await wrapper.find('[data-testid="mise-tool"]').setValue('node')
    await wrapper.find('[data-testid="mise-version"]').setValue('22.11.0')
    expect(wrapper.text()).toContain('fleetctl mise install m1 --tool node --version 22.11.0 --endpoint e2 --auth agent --wait')

    await wrapper.find('[data-testid="run-mise"]').trigger('click')
    await flushPromises()
    expect(api.startMiseOperation).toHaveBeenCalledWith('m1', {
      machineId: 'm1',
      endpointId: 'e2',
      auth: { type: 'agent' },
      timeoutSeconds: 300,
      action: 'install',
      tool: 'node',
      version: '22.11.0',
    })

    await router.replace('/fleet/machines/m1?tab=operations')
    await flushPromises()
    expect(wrapper.find('[data-testid="operation-status"]').text()).toContain('mise install')
  })

  it('operations and audit explain what the API cannot answer yet', async () => {
    const { wrapper, router } = await mountAt('/fleet/machines/m1?tab=operations')
    expect(wrapper.find('[data-testid="no-operations"]').exists()).toBe(true)
    await router.replace('/fleet/machines/m1?tab=audit')
    await flushPromises()
    expect(wrapper.text()).toContain('FM-943')
  })

  it('guest lifecycle asks for confirmation, then starts the operation', async () => {
    api.startProxmoxLifecycle.mockResolvedValue(ok({ data: operation('op-shutdown', 'proxmox.guest.shutdown') }, 202))
    const { wrapper } = await mountAt('/fleet/machines/m1?tab=guest')
    await vi.waitFor(async () => {
      await flushPromises()
      expect(wrapper.find('[data-testid="guest-panel"]').exists()).toBe(true)
    })

    await wrapper.find('[data-testid="lifecycle-shutdown"]').trigger('click')
    expect(api.startProxmoxLifecycle).not.toHaveBeenCalled()
    expect(wrapper.text()).toContain('fleetctl proxmox shutdown --account acc1 --node pve --vmid 100 --wait')
    await wrapper.find('[data-testid="confirm-lifecycle"]').trigger('click')
    await flushPromises()
    expect(api.startProxmoxLifecycle).toHaveBeenCalledWith('acc1', 100, 'shutdown', { node: 'pve', vmid: 100, timeoutSeconds: 300 })
    expect(wrapper.find('[data-testid="operation-status"]').text()).toContain('op-shutdown')
  })

  it('guest destructive operations run only the reviewed payload', async () => {
    api.reviewProxmoxOperation.mockImplementation(async (accountId: string, vmid: number, action: string, body: { node: string, params: unknown }) =>
      ok({ data: { reviewToken: `tok-${JSON.stringify(body.params)}`, action, node: body.node, vmid, accountId, params: body.params } }))
    api.startReviewedProxmoxOperation.mockResolvedValue(ok({ data: operation('op-snap', 'proxmox.guest.snapshot') }, 202))
    const { wrapper } = await mountAt('/fleet/machines/m1?tab=guest')
    await vi.waitFor(async () => {
      await flushPromises()
      expect(wrapper.find('[data-testid="guest-panel"]').exists()).toBe(true)
    })

    expect(wrapper.find('[data-testid="review-destructive"]').attributes('disabled')).toBeDefined()
    await wrapper.find('[data-testid="snapshot-name"]').setValue('before')
    await wrapper.find('[data-testid="review-destructive"]').trigger('click')
    await flushPromises()
    expect(wrapper.find('[data-testid="reviewed-payload"]').text()).toContain('"snapshot": "before"')

    // Editing after the review discards it: only reviewed bytes may run.
    await wrapper.find('[data-testid="snapshot-name"]').setValue('before-upgrade')
    expect(wrapper.find('[data-testid="reviewed-payload"]').exists()).toBe(false)

    await wrapper.find('[data-testid="review-destructive"]').trigger('click')
    await flushPromises()
    expect(wrapper.find('[data-testid="reviewed-payload"]').text()).toContain('"snapshot": "before-upgrade"')
    await wrapper.find('[data-testid="run-reviewed"]').trigger('click')
    await flushPromises()

    expect(api.startReviewedProxmoxOperation).toHaveBeenCalledTimes(1)
    expect(api.startReviewedProxmoxOperation).toHaveBeenCalledWith('acc1', 100, 'snapshot', {
      node: 'pve',
      reviewToken: 'tok-{"snapshot":"before-upgrade"}',
      params: { snapshot: 'before-upgrade' },
      timeoutSeconds: 300,
    })
    expect(wrapper.find('[data-testid="operation-status"]').text()).toContain('op-snap')
  })

  it('guest clone requires a valid target before review', async () => {
    const { wrapper } = await mountAt('/fleet/machines/m1?tab=guest')
    await vi.waitFor(async () => {
      await flushPromises()
      expect(wrapper.find('[data-testid="guest-panel"]').exists()).toBe(true)
    })
    await wrapper.find('[data-testid="destructive-action"]').setValue('clone')
    await wrapper.find('[data-testid="clone-id"]').setValue('50')
    await wrapper.find('[data-testid="clone-name"]').setValue('copy')
    expect(wrapper.find('[data-testid="review-destructive"]').attributes('disabled')).toBeDefined()
    await wrapper.find('[data-testid="clone-id"]').setValue('150')
    expect(wrapper.find('[data-testid="review-destructive"]').attributes('disabled')).toBeUndefined()
    expect(wrapper.text()).toContain(`printf '%s' '{"newId":150,"name":"copy","fullCopy":false}' | fleetctl proxmox clone`)
  })
})

describe('MachinePage review fixes', () => {
  it('cancels a tracked operation and keeps following it while it is cancelling', async () => {
    let state = 'running'
    api.getOperation.mockImplementation(async (id: string) => ok({ data: { ...operation(id, 'mise.status', state), cancelRequested: state === 'cancelling' } }))
    api.cancelOperation.mockImplementation(async (id: string) => {
      state = 'cancelling'
      return ok({ data: operation(id, 'mise.status', 'cancelling') })
    })
    sessionStorage.setItem('fleet-console-machine-operations:m1', JSON.stringify([{ id: 'op-1', kind: 'mise.status', label: 'mise status', startedAt: NOW }]))
    const { wrapper } = await mountAt('/fleet/machines/m1?tab=operations')

    const status = () => wrapper.find('[data-testid="operation-status"]')
    expect(status().text()).toContain('running')
    await status().findAll('button').find(b => b.text() === 'Cancel')!.trigger('click')
    await flushPromises()
    expect(api.cancelOperation).toHaveBeenCalledWith('op-1')
    expect(status().text()).toContain('cancelling')
    // Still live: the cancel control stays visible (disabled) until it settles.
    expect(status().text()).toContain('Cancel requested')

    state = 'cancelled'
    await wrapper.find('[data-testid="clear-finished"]').trigger('click')
    expect(wrapper.find('[data-testid="operation-status"]').exists()).toBe(true)
  })

  it('clears finished operations from the list', async () => {
    api.getOperation.mockImplementation(async (id: string) => ok({ data: operation(id, 'mise.status', 'succeeded') }))
    sessionStorage.setItem('fleet-console-machine-operations:m1', JSON.stringify([{ id: 'op-1', kind: 'mise.status', label: 'mise status', startedAt: NOW }]))
    const { wrapper } = await mountAt('/fleet/machines/m1?tab=operations')
    await wrapper.find('[data-testid="clear-finished"]').trigger('click')
    expect(wrapper.find('[data-testid="no-operations"]').exists()).toBe(true)
    expect(sessionStorage.getItem('fleet-console-machine-operations:m1')).toBe('[]')
  })

  it('still tracks an operation when session storage refuses writes', async () => {
    api.startMiseOperation.mockResolvedValue(ok({ data: operation('op-mise', 'mise.inventory') }, 202))
    const { wrapper } = await mountAt('/fleet/machines/m1?tab=tools')
    const setItem = vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
      throw new DOMException('quota', 'QuotaExceededError')
    })
    await wrapper.find('[data-testid="run-mise"]').trigger('click')
    await flushPromises()
    setItem.mockRestore()
    expect(wrapper.text()).not.toContain('quota')
    expect(wrapper.find('[data-testid="operation-status"]').text()).toContain('op-mise')
  })

  it('warns that pending enrollment tokens outlive a revoke', async () => {
    const view = (await api.getNode()).data.data
    api.getNode.mockResolvedValue(ok({ data: { ...view, pendingTokens: [{ id: 't1', machineId: 'm1', status: 'pending', createdAt: NOW, expiresAt: NOW + 3_600_000 }] } }))
    const { wrapper } = await mountAt('/fleet/machines/m1?tab=connections')
    expect(wrapper.find('[data-testid="pending-token-warning"]').text()).toContain('1 pending enrollment token(s) stay valid')
  })

  it('ignores a review answer when the form changed while it was in flight', async () => {
    let answer: (value: unknown) => void = () => {}
    api.reviewProxmoxOperation.mockImplementation(() => new Promise((resolve) => {
      answer = resolve
    }))
    const { wrapper } = await mountAt('/fleet/machines/m1?tab=guest')
    await vi.waitFor(async () => {
      await flushPromises()
      expect(wrapper.find('[data-testid="guest-panel"]').exists()).toBe(true)
    })
    await wrapper.find('[data-testid="snapshot-name"]').setValue('before')
    await wrapper.find('[data-testid="review-destructive"]').trigger('click')
    await wrapper.find('[data-testid="snapshot-name"]').setValue('after')
    answer(ok({ data: { reviewToken: 'tok', action: 'snapshot', node: 'pve', vmid: 100, accountId: 'acc1', params: { snapshot: 'before' } } }))
    await flushPromises()
    expect(wrapper.find('[data-testid="reviewed-payload"]').exists()).toBe(false)
  })

  it('shows a failed Proxmox source on the Guest tab instead of an empty state', async () => {
    api.listProxmoxGuests.mockResolvedValue({ status: 502, data: { code: 'upstream', message: 'pve unreachable' }, headers: new Headers() })
    api.discoverProxmoxCluster.mockResolvedValue({ status: 502, data: { code: 'upstream', message: 'pve unreachable' }, headers: new Headers() })
    const { wrapper } = await mountAt('/fleet/machines/m1?tab=guest')
    await vi.waitFor(async () => {
      await flushPromises()
      expect(wrapper.find('[data-testid="proxmox-problem"]').exists()).toBe(true)
    })
    expect(wrapper.text()).toContain('among the sources that answered')
  })

  it('does not retry a machine read the API refused', async () => {
    api.getMachine.mockResolvedValue({ status: 403, data: { code: 'forbidden', message: 'denied' }, headers: new Headers() })
    const { wrapper } = await mountAt('/fleet/machines/m1')
    await vi.waitFor(() => expect(wrapper.text()).toContain('forbidden: denied'))
    expect(api.getMachine).toHaveBeenCalledTimes(1)
  })
})
