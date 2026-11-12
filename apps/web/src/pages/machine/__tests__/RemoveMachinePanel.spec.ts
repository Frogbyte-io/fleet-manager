import { enableAutoUnmount, flushPromises, mount } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import type { MachineDto, MachineRemovalReviewDto, MachineRemovedDto, RemovalFootprintDto } from '@frogbyte-io/fleet-api-client'

const reviewMachineRemoval = vi.fn()
const removeMachine = vi.fn()

vi.mock('@frogbyte-io/fleet-api-client', () => ({
  reviewMachineRemoval: (...args: unknown[]) => reviewMachineRemoval(...args),
  removeMachine: (...args: unknown[]) => removeMachine(...args),
}))

import RemoveMachinePanel from '../components/RemoveMachinePanel.vue'

function ok<T>(data: T, status = 200) {
  return { status, data, headers: new Headers() }
}

function refused(status: number, code: string, message: string) {
  return { status, data: { code, message }, headers: new Headers() }
}

const machine = {
  id: 'm1',
  name: 'workstation',
  endpoints: [
    { id: 'e1', kind: 'fleetd', reference: 'node-1' },
    { id: 'e2', kind: 'ssh', reference: 'dev@ws.example:22' },
  ],
} as unknown as MachineDto

function footprint(overrides: Partial<RemovalFootprintDto> = {}): RemovalFootprintDto {
  return {
    endpoints: 2,
    endpointAuth: 0,
    endpointAuthSecrets: 0,
    capabilities: 4,
    inventorySnapshots: 1,
    tagsAndGroups: 0,
    nodeIdentity: 1,
    nodeCredentials: 2,
    projectCheckouts: 0,
    skillsSnapshot: 0,
    catalogSkillInstalls: 0,
    guestLink: 0,
    storedSshKeys: 0,
    adminPasswords: 0,
    collectedFilesKept: 3,
    ...overrides,
  }
}

function review(overrides: Partial<MachineRemovalReviewDto> = {}): MachineRemovalReviewDto {
  return {
    reviewToken: 'tok-1',
    machineId: 'm1',
    name: 'workstation',
    endpoints: [
      { id: 'e1', kind: 'fleetd', host: null },
      { id: 'e2', kind: 'ssh', host: 'ws.example' },
    ],
    nodeIdentity: 'active',
    unpinHosts: ['ws.example'],
    keptHosts: [],
    uninstall: null,
    footprint: footprint(),
    warnings: [],
    blockers: [],
    ...overrides,
  }
}

function removed(overrides: Partial<MachineRemovedDto> = {}): MachineRemovedDto {
  return {
    machineId: 'm1',
    name: 'workstation',
    removed: true,
    uninstalled: false,
    uninstallSummary: null,
    nodeIdentityRemoved: true,
    sessionClosed: false,
    secretsRevoked: 0,
    secretRevocationError: null,
    unpinnedHosts: ['ws.example'],
    keptHosts: [],
    unpinFailedHosts: [],
    auditGaps: [],
    footprint: footprint(),
    ...overrides,
  }
}

async function mountPanel() {
  const wrapper = mount(RemoveMachinePanel, { props: { machine } })
  await flushPromises()
  return wrapper
}

enableAutoUnmount(afterEach)

beforeEach(() => {
  reviewMachineRemoval.mockReset()
  removeMachine.mockReset()
})

describe('RemoveMachinePanel', () => {
  it('reviews on open and removes with the token the review answered', async () => {
    reviewMachineRemoval.mockResolvedValue(ok({ data: review() }))
    removeMachine.mockResolvedValue(ok({ data: removed() }))
    const wrapper = await mountPanel()

    expect(reviewMachineRemoval).toHaveBeenCalledWith('m1', {})
    expect(wrapper.get('[data-testid="remove-unpin"]').text()).toBe('ws.example')
    expect(wrapper.find('[data-testid="remove-blockers"]').exists()).toBe(false)
    expect(wrapper.get('[data-testid="fleetctl-command"]').text()).toBe('fleetctl machines remove m1')

    await wrapper.get('form').trigger('submit')
    await flushPromises()

    expect(removeMachine).toHaveBeenCalledWith('m1', { reviewToken: 'tok-1' })
    expect(wrapper.get('[data-testid="remove-outcome"]').text()).toContain('workstation')
    expect(wrapper.emitted('removed')?.[0]).toEqual([removed()])
  })

  it('shows each blocker with its command and offers no removal without a token', async () => {
    reviewMachineRemoval.mockResolvedValue(ok({
      data: review({
        reviewToken: null,
        blockers: [{
          kind: 'active_operation',
          id: 'op-1',
          state: 'running',
          detail: 'operation op-1 (machine.inventory) on machine m1 is running; wait for it (`fleetctl operations get op-1`) or cancel it (`fleetctl operations cancel op-1`)',
        }],
      }),
    }))
    const wrapper = await mountPanel()

    const blockers = wrapper.findAll('[data-testid="remove-blocker"]')
    expect(blockers).toHaveLength(1)
    expect(blockers[0]!.findAll('[data-testid="blocker-command"]').map(c => c.text()))
      .toEqual(['fleetctl operations get op-1', 'fleetctl operations cancel op-1'])
    expect(wrapper.find('[data-testid="remove-confirm"]').exists()).toBe(false)
    expect(wrapper.get('[data-testid="remove-review-again"]').text()).toBe('Review again')

    await wrapper.get('form').trigger('submit')
    await flushPromises()
    expect(reviewMachineRemoval).toHaveBeenCalledTimes(2)
    expect(removeMachine).not.toHaveBeenCalled()
  })

  it('shows the warnings the review answers', async () => {
    reviewMachineRemoval.mockResolvedValue(ok({ data: review({ warnings: ['the removal destroys the password'] }) }))
    const wrapper = await mountPanel()
    expect(wrapper.get('[data-testid="remove-warnings"]').text()).toContain('the removal destroys the password')
  })

  it('reviews the uninstall again when it is chosen, and sends the reviewed body', async () => {
    reviewMachineRemoval.mockResolvedValueOnce(ok({ data: review() }))
    reviewMachineRemoval.mockResolvedValueOnce(ok({
      data: review({
        reviewToken: 'tok-2',
        uninstall: { endpointId: 'e2', auth: { type: 'agent' }, layout: { FLEETD_SERVICE: 'fleetd-test' } },
      }),
    }))
    removeMachine.mockResolvedValue(ok({ data: removed({ uninstalled: true, uninstallSummary: 'fleetd removed' }) }))
    const wrapper = await mountPanel()

    await wrapper.get('[data-testid="remove-uninstall"]').setValue(true)
    expect(wrapper.find('[data-testid="remove-confirm"]').exists()).toBe(false)
    await wrapper.get('[data-testid="remove-auth"]').setValue('agent')
    expect(wrapper.get('[data-testid="fleetctl-command"]').text())
      .toBe('fleetctl machines remove m1 --uninstall --endpoint e2 --auth agent')

    await wrapper.get('form').trigger('submit')
    await flushPromises()
    expect(reviewMachineRemoval).toHaveBeenLastCalledWith('m1', { uninstall: { endpointId: 'e2', auth: { type: 'agent' } } })
    expect(wrapper.get('[data-testid="remove-uninstall-plan"]').text()).toContain('FLEETD_SERVICE=fleetd-test')

    await wrapper.get('form').trigger('submit')
    await flushPromises()
    expect(removeMachine).toHaveBeenCalledWith('m1', {
      uninstall: { endpointId: 'e2', auth: { type: 'agent' } },
      reviewToken: 'tok-2',
    })
    expect(wrapper.get('[data-testid="outcome-uninstall"]').text()).toContain('fleetd removed')
  })

  it('leaves the auth out for the endpoint default', async () => {
    reviewMachineRemoval.mockResolvedValue(ok({ data: review() }))
    const wrapper = await mountPanel()
    await wrapper.get('[data-testid="remove-uninstall"]').setValue(true)
    await wrapper.get('form').trigger('submit')
    await flushPromises()
    expect(reviewMachineRemoval).toHaveBeenLastCalledWith('m1', { uninstall: { endpointId: 'e2' } })
  })

  it('shows a refused removal and asks for a fresh review', async () => {
    reviewMachineRemoval.mockResolvedValue(ok({ data: review() }))
    removeMachine.mockResolvedValue(refused(502, 'fleetd_uninstall_failed', 'the fleetd uninstall failed'))
    const wrapper = await mountPanel()

    await wrapper.get('form').trigger('submit')
    await flushPromises()

    const error = wrapper.get('[data-testid="remove-error"]')
    expect(error.text()).toContain('Not removed')
    expect(error.text()).toContain('fleetd_uninstall_failed: the fleetd uninstall failed')
    expect(wrapper.find('[data-testid="remove-outcome"]').exists()).toBe(false)
    expect(wrapper.find('[data-testid="remove-confirm"]').exists()).toBe(false)
    expect(wrapper.emitted('removed')).toBeUndefined()
  })

  it('says a review failed', async () => {
    reviewMachineRemoval.mockResolvedValue(refused(403, 'denied', 'not allowed'))
    const wrapper = await mountPanel()
    expect(wrapper.get('[data-testid="remove-error"]').text()).toContain('Review failed')
    expect(wrapper.find('[data-testid="remove-review"]').exists()).toBe(false)
  })

  it('reports what the removal could not finish', async () => {
    reviewMachineRemoval.mockResolvedValue(ok({ data: review() }))
    removeMachine.mockResolvedValue(ok({
      data: removed({ secretRevocationError: 'store offline', unpinFailedHosts: ['ws.example'], auditGaps: ['machine_deleted'] }),
    }))
    const wrapper = await mountPanel()
    await wrapper.get('form').trigger('submit')
    await flushPromises()
    expect(wrapper.get('[data-testid="outcome-secret-error"]').text()).toContain('store offline')
    expect(wrapper.get('[data-testid="outcome-unpin-failed"]').text()).toContain('ws.example')
    expect(wrapper.get('[data-testid="outcome-audit-gaps"]').text()).toContain('machine_deleted')
  })
})
