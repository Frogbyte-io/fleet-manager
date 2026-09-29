import { enableAutoUnmount, flushPromises, mount } from '@vue/test-utils'
import { QueryClient, VueQueryPlugin } from '@tanstack/vue-query'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import type { MachineDto } from '@frogbyte-io/fleet-api-client'

const getMachineDrift = vi.fn()
vi.mock('@frogbyte-io/fleet-api-client', () => ({
  getMachineDrift: (...args: unknown[]) => getMachineDrift(...args),
}))

import DesiredTab from '../tabs/DesiredTab.vue'

function ok<T>(data: T, status = 200) {
  return { status, data, headers: new Headers() }
}

const machine = { id: 'm1', name: 'workstation' } as unknown as MachineDto

function drift(overrides: Record<string, unknown> = {}) {
  return {
    machineId: 'm1',
    machineName: 'workstation',
    status: 'computed',
    revision: { commitSha: 'abcdef1234567890', contentDigest: 'd' },
    counts: { missing: 0, changed: 0, extra: 0, unknown: 0, unsupported: 0 },
    differences: [],
    detail: null,
    ...overrides,
  }
}

async function mountTab() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } })
  const wrapper = mount(DesiredTab, { props: { machine }, global: { plugins: [[VueQueryPlugin, { queryClient }]] } })
  await flushPromises()
  return wrapper
}

enableAutoUnmount(afterEach)
beforeEach(() => getMachineDrift.mockReset())

describe('Desired tab', () => {
  it('says everything matches only when it does', async () => {
    getMachineDrift.mockResolvedValue(ok({ data: drift() }))
    const wrapper = await mountTab()
    expect(wrapper.get('[data-testid="desired-status"]').text()).toBe('in sync')
    expect(wrapper.get('[data-testid="desired-revision"]').text()).toContain('abcdef123456')
    expect(wrapper.find('[data-testid="desired-in-sync"]').exists()).toBe(true)
  })

  it('lists differences by state, actionable first, with the plan command', async () => {
    getMachineDrift.mockResolvedValue(ok({ data: drift({
      counts: { missing: 1, changed: 0, extra: 0, unknown: 1, unsupported: 0 },
      differences: [
        { identity: 'skill:db/codex', state: 'missing', desired: 'deployed', observed: null, reason: null },
        { identity: 'catalog-skill:builtin-fleet/codex', state: 'unknown', desired: 'v1', observed: null, reason: 'the deployment status did not answer' },
      ],
    }) }))
    const wrapper = await mountTab()
    expect(wrapper.get('[data-testid="desired-status"]').text()).toBe('1 drifted')
    const groups = wrapper.findAll('[data-testid^="desired-group-"]').map(g => g.attributes('data-testid'))
    expect(groups).toEqual(['desired-group-missing', 'desired-group-unknown'])
    expect(wrapper.get('[data-testid="difference-skill:db/codex"]').text()).toContain('on codex')
    expect(wrapper.get('[data-testid="difference-catalog-skill:builtin-fleet/codex"]').text()).toContain('did not answer')
    expect(wrapper.text()).toContain('fleetctl plan m1')
    expect(wrapper.find('[data-testid="desired-in-sync"]').exists()).toBe(false)
  })

  it('does not call an unobserved machine in sync', async () => {
    getMachineDrift.mockResolvedValue(ok({ data: drift({ counts: { missing: 0, changed: 0, extra: 0, unknown: 2, unsupported: 0 } }) }))
    const wrapper = await mountTab()
    expect(wrapper.get('[data-testid="desired-status"]').text()).toBe('unknown')
    expect(wrapper.find('[data-testid="desired-in-sync"]').exists()).toBe(false)
  })

  it('explains that no revision is active', async () => {
    getMachineDrift.mockResolvedValue(ok({ data: drift({ status: 'no_revision', revision: null }) }))
    const wrapper = await mountTab()
    expect(wrapper.get('[data-testid="desired-none"]').text()).toContain('No desired revision is active')
  })

  it('shows why drift is unavailable', async () => {
    getMachineDrift.mockResolvedValue(ok({ data: drift({ status: 'unavailable', revision: null, detail: 'reading the machine failed' }) }))
    const wrapper = await mountTab()
    expect(wrapper.get('[data-testid="desired-unavailable"]').text()).toContain('reading the machine failed')
  })

  it('states a refused or failed read instead of showing a clean machine', async () => {
    getMachineDrift.mockResolvedValue(ok({ code: 'denied', message: 'denied: no' }, 403))
    const wrapper = await mountTab()
    expect(wrapper.get('[data-testid="desired-error"]').text()).toContain('denied')
    expect(wrapper.find('[data-testid="desired-in-sync"]').exists()).toBe(false)
  })
})
