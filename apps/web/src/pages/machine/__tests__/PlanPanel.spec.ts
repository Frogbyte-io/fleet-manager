import { enableAutoUnmount, flushPromises, mount } from '@vue/test-utils'
import { QueryClient, VueQueryPlugin } from '@tanstack/vue-query'
import { defineComponent, h } from 'vue'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import type { MachineDto } from '@frogbyte-io/fleet-api-client'

const createMachinePlan = vi.fn()
const applyMachinePlan = vi.fn()
const getOperation = vi.fn()

vi.mock('@frogbyte-io/fleet-api-client', () => ({
  createMachinePlan: (...args: unknown[]) => createMachinePlan(...args),
  applyMachinePlan: (...args: unknown[]) => applyMachinePlan(...args),
  getOperation: (...args: unknown[]) => getOperation(...args),
  cancelOperation: vi.fn(),
}))

import { provideMachineOperations } from '../operations'
import PlanPanel from '../components/PlanPanel.vue'

function ok<T>(data: T, status = 200) {
  return { status, data, headers: new Headers() }
}

const machine = {
  id: 'm1',
  name: 'workstation',
  endpoints: [{ id: 'e1', kind: 'ssh', reference: 'dev@ws:22' }],
} as unknown as MachineDto

const Host = defineComponent({
  setup() {
    provideMachineOperations('m1')
    return () => h(PlanPanel, { machine })
  },
})

function action(order: number, kind: string, requiresApproval: boolean) {
  return {
    order,
    kind,
    requiresApproval,
    reason: `because ${order}`,
    difference: { identity: `skill:s${order}`, state: 'missing', desired: null, observed: null, reason: null },
  }
}

function plan(actions: ReturnType<typeof action>[], unactionable: unknown[] = []) {
  return {
    planId: 'p'.repeat(64),
    machineId: 'm1',
    revision: { commitSha: 'c'.repeat(40), contentDigest: 'd' },
    actions,
    unactionable,
  }
}

async function mountPanel() {
  sessionStorage.clear()
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } })
  const wrapper = mount(Host, { global: { plugins: [[VueQueryPlugin, { queryClient }]] } })
  await flushPromises()
  return wrapper
}

async function preview(wrapper: Awaited<ReturnType<typeof mountPanel>>) {
  await wrapper.get('[data-testid="plan-preview"]').trigger('click')
  await flushPromises()
}

enableAutoUnmount(afterEach)

beforeEach(() => {
  for (const mock of [createMachinePlan, applyMachinePlan, getOperation])
    mock.mockReset()
  getOperation.mockResolvedValue(ok({ data: { id: 'op-1', kind: 'plan.apply', state: 'succeeded', createdAt: 0 } }))
})

describe('PlanPanel', () => {
  it('says there is nothing to apply for an empty plan', async () => {
    createMachinePlan.mockResolvedValue(ok({ data: plan([]) }))
    const wrapper = await mountPanel()
    await preview(wrapper)
    expect(createMachinePlan).toHaveBeenCalledWith('m1')
    expect(wrapper.get('[data-testid="plan-empty"]').text()).toContain('Nothing to apply')
    expect(wrapper.find('[data-testid="plan-apply"]').exists()).toBe(false)
  })

  it('gates Apply on approving every risky action', async () => {
    createMachinePlan.mockResolvedValue(ok({ data: plan([action(1, 'skills.deploy', false), action(2, 'skills.undeploy', true)]) }))
    const wrapper = await mountPanel()
    await preview(wrapper)
    const apply = () => wrapper.get('[data-testid="plan-apply"]')
    expect(apply().attributes('disabled')).toBeDefined()
    expect(wrapper.find('[data-testid="plan-needs-approval"]').exists()).toBe(true)
    expect(wrapper.find('[data-testid="plan-approve-1"]').exists()).toBe(false)

    await wrapper.get('[data-testid="plan-approve-2"]').setValue(true)
    expect(apply().attributes('disabled')).toBeUndefined()
    expect(wrapper.find('[data-testid="plan-needs-approval"]').exists()).toBe(false)

    await wrapper.get('[data-testid="plan-approve-2"]').setValue(false)
    expect(apply().attributes('disabled')).toBeDefined()
  })

  it('shows the blast radius before applying, and applies by plan id and approvals only', async () => {
    const p = plan([action(1, 'skills.deploy', false), action(2, 'skills.undeploy', true)])
    createMachinePlan.mockResolvedValue(ok({ data: p }))
    applyMachinePlan.mockResolvedValue(ok({ data: { id: 'op-1', kind: 'plan.apply', state: 'queued', createdAt: 0 } }, 202))
    const wrapper = await mountPanel()
    await preview(wrapper)
    await wrapper.get('[data-testid="plan-approve-2"]').setValue(true)
    await wrapper.get('[data-testid="plan-apply"]').trigger('click')
    expect(applyMachinePlan).not.toHaveBeenCalled()
    expect(wrapper.get('[data-testid="plan-confirm"]').text()).toContain('2 changes on workstation: 1 skill deployment, 1 skill removal.')

    await wrapper.get('[data-testid="plan-confirm-apply"]').trigger('click')
    await flushPromises()
    expect(applyMachinePlan).toHaveBeenCalledTimes(1)
    const [machineId, planId, body] = applyMachinePlan.mock.calls[0]
    expect(machineId).toBe('m1')
    expect(planId).toBe(p.planId)
    expect(Object.keys(body as object).sort()).toEqual(['approvals', 'auth', 'endpointId'])
    expect(body).toMatchObject({ endpointId: 'e1', approvals: [{ actionOrder: 2, kind: 'skills.undeploy' }] })
    expect(JSON.stringify(body)).not.toContain('actions')
  })

  it('follows the operation after a successful apply', async () => {
    createMachinePlan.mockResolvedValue(ok({ data: plan([action(1, 'skills.deploy', false)]) }))
    applyMachinePlan.mockResolvedValue(ok({ data: { id: 'op-1', kind: 'plan.apply', state: 'queued', createdAt: 0 } }, 202))
    const wrapper = await mountPanel()
    await preview(wrapper)
    await wrapper.get('[data-testid="plan-apply"]').trigger('click')
    await wrapper.get('[data-testid="plan-confirm-apply"]').trigger('click')
    await flushPromises()
    await flushPromises()
    expect(wrapper.get('[data-testid="operation-status"]').text()).toContain('succeeded')
  })

  it('shows the stale banner on a 409 stale_plan and offers to plan again', async () => {
    createMachinePlan.mockResolvedValue(ok({ data: plan([action(1, 'skills.deploy', false)]) }))
    applyMachinePlan.mockResolvedValue(ok({ code: 'stale_plan', message: 'the plan changed' }, 409))
    const wrapper = await mountPanel()
    await preview(wrapper)
    await wrapper.get('[data-testid="plan-apply"]').trigger('click')
    await wrapper.get('[data-testid="plan-confirm-apply"]').trigger('click')
    await flushPromises()
    expect(wrapper.get('[data-testid="plan-stale"]').text()).toContain('Nothing was applied')
    expect(wrapper.find('[data-testid="operation-status"]').exists()).toBe(false)
    expect(wrapper.find('[data-testid="plan-confirm"]').exists()).toBe(false)

    await wrapper.get('[data-testid="plan-replan"]').trigger('click')
    await flushPromises()
    expect(createMachinePlan).toHaveBeenCalledTimes(2)
    expect(wrapper.find('[data-testid="plan-stale"]').exists()).toBe(false)
  })

  it('shows another apply refusal as an error, not as stale', async () => {
    createMachinePlan.mockResolvedValue(ok({ data: plan([action(1, 'skills.deploy', false)]) }))
    applyMachinePlan.mockResolvedValue(ok({ code: 'denied', message: 'not allowed' }, 403))
    const wrapper = await mountPanel()
    await preview(wrapper)
    await wrapper.get('[data-testid="plan-apply"]').trigger('click')
    await wrapper.get('[data-testid="plan-confirm-apply"]').trigger('click')
    await flushPromises()
    expect(wrapper.get('[data-testid="plan-apply-error"]').text()).toContain('not allowed')
    expect(wrapper.find('[data-testid="plan-stale"]').exists()).toBe(false)
  })

  it('shows a plan error instead of an empty plan', async () => {
    createMachinePlan.mockResolvedValue(ok({ code: 'no_revision', message: 'no active revision' }, 409))
    const wrapper = await mountPanel()
    await preview(wrapper)
    expect(wrapper.get('[data-testid="plan-error"]').text()).toContain('no active revision')
    expect(wrapper.find('[data-testid="plan-empty"]').exists()).toBe(false)
  })

  it('reports differences it will not act on', async () => {
    createMachinePlan.mockResolvedValue(ok({ data: plan([], [{ identity: 'skill:x', state: 'unknown', desired: null, observed: null, reason: 'no answer' }]) }))
    const wrapper = await mountPanel()
    await preview(wrapper)
    expect(wrapper.get('[data-testid="plan-unactionable"]').text()).toContain('no answer')
  })
})
