import { mount } from '@vue/test-utils'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import type { PageMachineDtoItemsItem } from '@frogbyte-io/fleet-api-client'

const listMachines = vi.fn()
const getMachine = vi.fn()

vi.mock('@frogbyte-io/fleet-api-client', () => ({
  listMachines: (...args: unknown[]) => listMachines(...args),
  getMachine: (...args: unknown[]) => getMachine(...args),
  createOperation: (...args: unknown[]) => createOperation(...args),
  getOperation: (...args: unknown[]) => getOperation(...args),
  cancelOperation: (...args: unknown[]) => cancelOperation(...args),
}))

import MachinesPanel from '../MachinesPanel.vue'

function machine(overrides: Partial<PageMachineDtoItemsItem> = {}): PageMachineDtoItemsItem {
  return {
    id: '01990000-0000-7000-8000-000000000001',
    name: 'build-host',
    description: '',
    endpoints: [
      {
        id: 'endpoint-1',
        kind: 'ssh',
        reference: '***@build-host.lan:22',
      },
    ],
    tags: ['linux'],
    groups: [],
    machineStatus: 'connected',
    lastSeenAt: 1_000,
    lastObservation: null,
    capabilities: [],
    createdAt: 0,
    updatedAt: 0,
    ...overrides,
  }
}

beforeEach(() => {
  listMachines.mockReset()
  getMachine.mockReset()
})

describe('MachinesPanel', () => {
  it('renders the machine list with the status word in the chip', async () => {
    listMachines.mockResolvedValue({
      status: 200,
      data: { items: [machine()], page: { nextCursor: null, limit: 50 } },
    })
    const wrapper = mount(MachinesPanel)

    await vi.waitFor(() => expect(wrapper.text()).toContain('build-host'))
    const row = wrapper.get('tbody tr')
    expect(row.text()).toContain('connected')
    expect(row.text()).toContain('***@build-host.lan:22')
    expect(row.text()).toContain('linux')
    wrapper.unmount()
  })

  it('reports the failure instead of an empty table', async () => {
    listMachines.mockRejectedValue(new Error('the controller did not answer'))
    const wrapper = mount(MachinesPanel)

    await vi.waitFor(() => expect(wrapper.text()).toContain('the controller did not answer'))
    expect(wrapper.find('table').exists()).toBe(false)
    wrapper.unmount()
  })

  it('loads the detail when a row is opened', async () => {
    listMachines.mockResolvedValue({
      status: 200,
      data: { items: [machine()], page: { nextCursor: null, limit: 50 } },
    })
    getMachine.mockResolvedValue({
      status: 200,
      data: {
        data: {
          ...machine(),
          capabilities: [
            {
              namespace: 'os',
              name: 'family',
              value: 'linux',
              status: 'known',
              observedAt: 1_000,
              source: 'fleetd/0.1.0',
            },
          ],
        },
      },
    })
    const wrapper = mount(MachinesPanel)
    await vi.waitFor(() => expect(wrapper.text()).toContain('build-host'))

    await wrapper.get('tbody tr').trigger('click')
    await vi.waitFor(() => expect(wrapper.text()).toContain('os.family'))
    expect(getMachine).toHaveBeenCalledWith('01990000-0000-7000-8000-000000000001')
    wrapper.unmount()
  })
})

// ---------------------------------------------------------------------------
// The Install Fleet Node upgrade (FM-212)
// ---------------------------------------------------------------------------

const createOperation = vi.fn()
const getOperation = vi.fn()
const cancelOperation = vi.fn()

describe('MachinesPanel install flow', () => {
  beforeEach(() => {
    createOperation.mockReset()
    getOperation.mockReset()
    cancelOperation.mockReset()
  })

  function mockList() {
    listMachines.mockResolvedValue({
      status: 200,
      data: { items: [machine()], page: { nextCursor: null, limit: 50 } },
    })
  }

  it('starts the orchestrated install and shows the progress', async () => {
    mockList()
    getMachine.mockResolvedValue({
      status: 200,
      data: { data: machine() },
    })
    createOperation.mockResolvedValue({
      status: 201,
      data: {
        data: {
          id: 'op-1',
          kind: 'machine.install-fleetd',
          state: 'running',
          progressMessage: 'installing',
        },
      },
    })
    getOperation.mockResolvedValue({
      status: 200,
      data: {
        data: {
          id: 'op-1',
          state: 'succeeded',
          progressMessage: 'verified: the node reported 14 facts',
          resultJson: '{"connected":true,"inventoryFacts":14}',
        },
      },
    })

    const wrapper = mount(MachinesPanel)
    await vi.waitFor(() => expect(wrapper.text()).toContain('build-host'))
    await wrapper.get('tbody tr').trigger('click')
    await vi.waitFor(() => expect(wrapper.text()).toContain('Install Fleet Node'))

    await wrapper.get('input[placeholder="identity file path"]').setValue('/keys/deploy')
    await wrapper.findAll('button').filter(b => b.text() === 'Install')[0].trigger('click')

    await vi.waitFor(() =>
      expect(createOperation).toHaveBeenCalledWith(
        expect.objectContaining({
          kind: 'machine.install-fleetd',
        }),
      ),
    )
    const sent = JSON.parse(createOperation.mock.calls[0][0].payloadJson)
    expect(sent.controllerUrl).toBe(window.location.origin)
    expect(sent.auth).toEqual({ type: 'identityFile', path: '/keys/deploy' })

    await vi.waitFor(() => expect(wrapper.text()).toContain('succeeded'))
    await vi.waitFor(() => expect(wrapper.text()).toContain('inventoryFacts'))
    wrapper.unmount()
  })

  it('shows the failure and the recovery hint when the install fails', async () => {
    mockList()
    getMachine.mockResolvedValue({ status: 200, data: { data: machine() } })
    createOperation.mockResolvedValue({
      status: 201,
      data: {
        data: { id: 'op-2', kind: 'machine.install-fleetd', state: 'running' },
      },
    })
    getOperation.mockResolvedValue({
      status: 200,
      data: {
        data: {
          id: 'op-2',
          state: 'failed',
          progressMessage: 'verifying the node\'s inventory',
          errorJson:
            '{"reason":"node_did_not_connect","detail":"retry this install (it is idempotent)"}',
        },
      },
    })

    const wrapper = mount(MachinesPanel)
    await vi.waitFor(() => expect(wrapper.text()).toContain('build-host'))
    await wrapper.get('tbody tr').trigger('click')
    await wrapper
      .get('input[placeholder="identity file path"]')
      .setValue('/keys/deploy')
    await wrapper.findAll('button').filter(b => b.text() === 'Install')[0].trigger('click')
    await vi.waitFor(() => expect(wrapper.text()).toContain('retry this install'))
    wrapper.unmount()
  })
})
