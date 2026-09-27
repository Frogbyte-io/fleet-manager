import { enableAutoUnmount, flushPromises, mount } from '@vue/test-utils'
import { QueryClient, VueQueryPlugin } from '@tanstack/vue-query'
import { createMemoryHistory, createRouter } from 'vue-router'
import { defineComponent, h } from 'vue'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import type { MachineDto } from '@frogbyte-io/fleet-api-client'

const getMachineSkills = vi.fn()
const startSkillsOperation = vi.fn()
const getOperation = vi.fn()

vi.mock('@frogbyte-io/fleet-api-client', () => ({
  getMachineSkills: (...args: unknown[]) => getMachineSkills(...args),
  startSkillsOperation: (...args: unknown[]) => startSkillsOperation(...args),
  getOperation: (...args: unknown[]) => getOperation(...args),
  cancelOperation: vi.fn(),
}))

import { provideMachineOperations } from '../operations'
import SkillsTab from '../tabs/SkillsTab.vue'

function ok<T>(data: T, status = 200) {
  return { status, data, headers: new Headers() }
}

const machine = {
  id: 'm1',
  name: 'workstation',
  description: '',
  machineStatus: 'connected',
  endpoints: [{ id: 'e1', kind: 'ssh', reference: 'dev@ws:22' }],
  capabilities: [],
  groups: [],
  tags: [],
  lastObservation: null,
  lastSeenAt: null,
  createdAt: 0,
  updatedAt: 0,
} as unknown as MachineDto

const Host = defineComponent({
  setup() {
    provideMachineOperations('m1')
    return () => h(SkillsTab, { machine })
  },
})

async function mountTab() {
  const router = createRouter({ history: createMemoryHistory(), routes: [{ path: '/:p(.*)*', component: { render: () => null } }] })
  await router.push('/fleet/machines/m1?tab=skills')
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } })
  const wrapper = mount(Host, { global: { plugins: [[VueQueryPlugin, { queryClient }], router] } })
  await flushPromises()
  return wrapper
}

let operationState: Record<string, { state: string, errorJson?: string, resultJson?: string }> = {}

enableAutoUnmount(afterEach)

beforeEach(() => {
  sessionStorage.clear()
  operationState = {}
  for (const mock of [getMachineSkills, startSkillsOperation, getOperation])
    mock.mockReset()
  getMachineSkills.mockResolvedValue(ok({ data: {
    machineId: 'm1',
    availability: 'available',
    cliVersion: '1.40.0',
    updateCheck: 'complete',
    observedAt: Date.now(),
    stale: false,
    data: {
      skills: [{ id: 'notes', name: 'notes', enabled: true, presetIds: [], deployedTo: ['claude_code'], updateStatus: 'up_to_date' }],
      presets: [],
      agents: [{ id: 'claude_code', name: 'Claude Code', installed: true, enabled: true }],
    },
  } }))
  let n = 0
  startSkillsOperation.mockImplementation(async () => {
    const id = `op-${++n}`
    operationState[id] ??= { state: 'succeeded', resultJson: '{"outcome":{"skills":["notes"]}}' }
    return ok({ data: { id, kind: 'skills.remove', state: 'queued', createdAt: 0 } }, 202)
  })
  getOperation.mockImplementation(async (id: string) => ok({ data: { id, kind: 'skills.remove', ...operationState[id] } }))
})

describe('machine Skills tab', () => {
  it('shows the library with per-agent deployments', async () => {
    const wrapper = await mountTab()
    expect(wrapper.get('[data-testid="library-notes"]').text()).toContain('CC')
  })

  it('says when the machine was never probed', async () => {
    getMachineSkills.mockResolvedValue(ok({ code: 'not_found', message: 'no snapshot' }, 404))
    const wrapper = await mountTab()
    expect(wrapper.find('[data-testid="skills-not-probed"]').exists()).toBe(true)
  })

  it('offers no actions on an unsupported CLI', async () => {
    getMachineSkills.mockResolvedValue(ok({ data: { machineId: 'm1', availability: 'unsupported', cliVersion: '1.30.0', updateCheck: 'unsupported', observedAt: 0, stale: false, data: {} } }))
    const wrapper = await mountTab()
    expect(wrapper.find('[data-testid="skills-actions-blocked"]').exists()).toBe(true)
    expect(wrapper.find('[data-testid="skills-action-form"]').exists()).toBe(false)
  })

  it('does not ask for a refresh after a preview', async () => {
    const wrapper = await mountTab()
    await wrapper.get('[data-testid="remove-notes"]').trigger('click')
    await wrapper.get('[data-testid="skills-preview"]').trigger('click')
    await flushPromises()
    await flushPromises()
    expect(wrapper.find('[data-testid="skills-probe-hint"]').exists()).toBe(false)
  })

  it('unlocks remove only after a successful dry run of the same request', async () => {
    const wrapper = await mountTab()
    await wrapper.get('[data-testid="remove-notes"]').trigger('click')
    expect(wrapper.get('[data-testid="skills-run"]').attributes('disabled')).toBeDefined()

    await wrapper.get('[data-testid="skills-preview"]').trigger('click')
    await flushPromises()
    await flushPromises()
    expect(startSkillsOperation).toHaveBeenLastCalledWith('m1', expect.objectContaining({ operation: 'remove', reference: 'notes', dryRun: true, confirm: true }))
    expect(wrapper.get('[data-testid="skills-run"]').attributes('disabled')).toBeUndefined()

    // A different request needs its own preview.
    await wrapper.get('[data-testid="skills-reference"]').setValue('other')
    expect(wrapper.get('[data-testid="skills-run"]').attributes('disabled')).toBeDefined()
    await wrapper.get('[data-testid="skills-reference"]').setValue('notes')
    expect(wrapper.get('[data-testid="skills-run"]').attributes('disabled')).toBeUndefined()

    await wrapper.get('[data-testid="skills-run"]').trigger('click')
    expect(startSkillsOperation).toHaveBeenCalledTimes(1)
    await wrapper.get('[data-testid="skills-confirm-run"]').trigger('click')
    await flushPromises()
    expect(startSkillsOperation).toHaveBeenLastCalledWith('m1', expect.objectContaining({ operation: 'remove', reference: 'notes', dryRun: false, confirm: true }))
  })

  it('keeps remove locked when the preview fails', async () => {
    operationState['op-1'] = { state: 'failed', errorJson: '{"reason":"cli_failed","detail":"no such skill"}' }
    const wrapper = await mountTab()
    await wrapper.get('[data-testid="remove-notes"]').trigger('click')
    await wrapper.get('[data-testid="skills-preview"]').trigger('click')
    await flushPromises()
    await flushPromises()
    expect(wrapper.get('[data-testid="skills-run"]').attributes('disabled')).toBeDefined()
    expect(wrapper.text()).toContain('The preview did not succeed')
  })

  it('shows a deploy target conflict as paths with both ways out', async () => {
    operationState['op-1'] = {
      state: 'failed',
      errorJson: JSON.stringify({ reason: 'TARGET_CONFLICT', detail: 'refusing', data: { code: 'TARGET_CONFLICT', target_conflict: [{ path: '/home/dev/.claude/skills/db' }] } }),
    }
    const wrapper = await mountTab()
    await wrapper.get('[data-testid="skills-action"]').setValue('deploy')
    await wrapper.get('[data-testid="skills-reference"]').setValue('db')
    await wrapper.get('[data-testid="agent-claude_code"]').trigger('click')
    await wrapper.get('[data-testid="skills-run"]').trigger('click')
    await flushPromises()
    await flushPromises()
    const conflict = wrapper.get('[data-testid="outcome-conflict"]').text()
    expect(conflict).toContain('/home/dev/.claude/skills/db')
    expect(conflict).toContain('adopt')
    expect(conflict).toContain('move it aside')
  })
})
