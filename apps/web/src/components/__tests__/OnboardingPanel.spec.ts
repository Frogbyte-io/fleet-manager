import { mount } from '@vue/test-utils'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import type {
  OnboardingDraftDetailDto,
  PageOnboardingDraftDtoItemsItem,
} from '@frogbyte-io/fleet-api-client'

const listOnboardingDrafts = vi.fn()
const getOnboardingDraft = vi.fn()
const createOnboardingDraft = vi.fn()
const testOnboardingDraft = vi.fn()
const discoverOnboardingDraft = vi.fn()
const confirmOnboardingHostKey = vi.fn()
const addOnboardingMachine = vi.fn()
const cancelOnboardingDraft = vi.fn()
const getOperation = vi.fn()

vi.mock('@frogbyte-io/fleet-api-client', () => ({
  listOnboardingDrafts: (...args: unknown[]) => listOnboardingDrafts(...args),
  getOnboardingDraft: (...args: unknown[]) => getOnboardingDraft(...args),
  createOnboardingDraft: (...args: unknown[]) => createOnboardingDraft(...args),
  testOnboardingDraft: (...args: unknown[]) => testOnboardingDraft(...args),
  discoverOnboardingDraft: (...args: unknown[]) => discoverOnboardingDraft(...args),
  confirmOnboardingHostKey: (...args: unknown[]) => confirmOnboardingHostKey(...args),
  addOnboardingMachine: (...args: unknown[]) => addOnboardingMachine(...args),
  cancelOnboardingDraft: (...args: unknown[]) => cancelOnboardingDraft(...args),
  getOperation: (...args: unknown[]) => getOperation(...args),
}))

import OnboardingPanel from '../OnboardingPanel.vue'

function buttonBy(wrapper: ReturnType<typeof mount>, text: string) {
  const matches = wrapper.findAll('button').filter(b => b.text() === text)
  expect(matches.length, `exactly one ${text} button`).toBe(1)
  return matches[0]
}

/// Clicks a stage button once its busy-gate has cleared: the review surface
/// renders its next stage before the stage's own bookkeeping finishes.
async function clickEnabled(wrapper: ReturnType<typeof mount>, text: string) {
  await vi.waitFor(() =>
    expect(buttonBy(wrapper, text).attributes('disabled')).toBeUndefined(),
  )
  await buttonBy(wrapper, text).trigger('click')
}

function draftSummary(
  overrides: Partial<PageOnboardingDraftDtoItemsItem> = {},
): PageOnboardingDraftDtoItemsItem {
  return {
    id: 'draft-1',
    endpoint: { user: '***', host: 'box.lan', port: 22 },
    name: 'builder',
    tags: [],
    groups: [],
    stage: 'untested',
    hostKeyStage: 'unseen',
    factCount: 0,
    createdAt: 0,
    updatedAt: 0,
    ...overrides,
  }
}

function draftDetail(
  overrides: Partial<OnboardingDraftDetailDto> = {},
): OnboardingDraftDetailDto {
  return {
    id: 'draft-1',
    endpoint: { user: 'deploy', host: 'box.lan', port: 22 },
    auth: { type: 'identityFile', path: '/keys/deploy' },
    name: 'builder',
    description: '',
    tags: [],
    groups: [],
    stage: 'untested',
    hostKeyStage: 'unseen',
    hostKey: null,
    confirmedFingerprint: null,
    lastTest: null,
    facts: [],
    discoveredAt: null,
    profileHint: null,
    duplicates: [],
    createdAt: 0,
    updatedAt: 0,
    ...overrides,
  }
}

function page(items: PageOnboardingDraftDtoItemsItem[]) {
  return {
    status: 200,
    data: { items, page: { nextCursor: null, limit: 50 } },
  }
}

beforeEach(() => {
  for (const mock of [
    listOnboardingDrafts,
    getOnboardingDraft,
    createOnboardingDraft,
    testOnboardingDraft,
    discoverOnboardingDraft,
    confirmOnboardingHostKey,
    addOnboardingMachine,
    cancelOnboardingDraft,
    getOperation,
  ]) {
    mock.mockReset()
  }
})

describe('OnboardingPanel', () => {
  it('renders an empty list honestly', async () => {
    listOnboardingDrafts.mockResolvedValue(page([]))
    const wrapper = mount(OnboardingPanel)
    await vi.waitFor(() => expect(wrapper.text()).toContain('No drafts yet'))
    wrapper.unmount()
  })

  it('creates a draft from the form and opens the review surface', async () => {
    listOnboardingDrafts.mockResolvedValue(page([]))
    createOnboardingDraft.mockResolvedValue({
      status: 201,
      data: { data: draftSummary() },
    })
    getOnboardingDraft.mockResolvedValue({
      status: 200,
      data: { data: draftDetail() },
    })
    const wrapper = mount(OnboardingPanel)
    await vi.waitFor(() => expect(wrapper.text()).toContain('No drafts yet'))

    await wrapper.get('input[placeholder="login user"]').setValue('deploy')
    await wrapper.get('input[placeholder="host"]').setValue('box.lan')
    await wrapper.get('input[placeholder="identity file path"]').setValue('/keys/deploy')
    await buttonBy(wrapper, 'Create draft').trigger('click')

    await vi.waitFor(() =>
      expect(createOnboardingDraft).toHaveBeenCalledWith(
        expect.objectContaining({
          user: 'deploy',
          host: 'box.lan',
          auth: { type: 'identityFile', path: '/keys/deploy' },
        }),
      ),
    )
    await vi.waitFor(() => expect(wrapper.text()).toContain('deploy@box.lan:22'))
    wrapper.unmount()
  })

  it('walks the staged flow: test, confirm, discover, add', async () => {
    // The initial list is empty; the draft arrives only through the flow.
    listOnboardingDrafts.mockResolvedValue(page([]))
    const observed: OnboardingDraftDetailDto = draftDetail({
      stage: 'review',
      hostKeyStage: 'observed',
      hostKey: {
        keyType: 'ED25519',
        fingerprint: 'SHA256:abc',
        rawLine: '[box.lan]:22 ssh-ed25519 x',
      },
      lastTest: { connectAttempted: false, connected: false, detail: null, at: 1 },
    })
    testOnboardingDraft.mockResolvedValue({
      status: 202,
      data: { data: { id: 'op-1', kind: 'machine.onboard.test', state: 'pending' } },
    })
    getOperation.mockResolvedValue({
      status: 200,
      data: { data: { id: 'op-1', kind: 'machine.onboard.test', state: 'succeeded' } },
    })
    const ready: OnboardingDraftDetailDto = draftDetail({
      stage: 'ready',
      hostKeyStage: 'confirmed',
      hostKey: observed.hostKey,
      confirmedFingerprint: 'SHA256:abc',
      facts: [
        {
          namespace: 'os',
          name: 'family',
          value: 'linux',
          status: 'known',
          observedAt: 1,
          source: 'agentless/1',
        },
      ],
      discoveredAt: 2,
      profileHint: 'Linux/ubuntu-24.04/x86_64',
    })
    const duplicate = draftDetail({
      ...ready,
      duplicates: [
        {
          machineId: 'm-1',
          name: 'twin',
          machineStatus: 'agentless' as const,
          reference: 'ops@box.lan:22',
        },
      ],
    })

    // The mock answers per stage: test shows the observed key, discover
    // shows facts, and each open() call reads the current stage.
    const stages: Record<string, OnboardingDraftDetailDto> = {
      review: observed,
      ready: ready,
      reviewed: duplicate,
    }
    getOnboardingDraft.mockImplementation(async () => {
      const current = stages.review.hostKeyStage === 'observed' ? stages.review : stages.ready
      return { status: 200, data: { data: current } }
    })

    const wrapper = mount(OnboardingPanel)
    await vi.waitFor(() => expect(wrapper.text()).toContain('No drafts yet'))

    // Start the flow from a draft that is already observed: click its row.
    listOnboardingDrafts.mockResolvedValue(
      page([draftSummary({ stage: 'review', hostKeyStage: 'observed' })]),
    )
    await buttonBy(wrapper, 'Refresh').trigger('click')
    await vi.waitFor(() => expect(wrapper.text()).toContain('builder'))
    await wrapper.get('tbody tr').trigger('click')
    await vi.waitFor(() => expect(wrapper.text()).toContain('SHA256:abc'))

    // Discover is offered only once the key is confirmed; confirm first.
    confirmOnboardingHostKey.mockResolvedValue({ status: 200, data: { data: ready } })
    await clickEnabled(wrapper, 'Confirm fingerprint')
    await vi.waitFor(() =>
      expect(confirmOnboardingHostKey).toHaveBeenCalledWith('draft-1', {
        fingerprint: 'SHA256:abc',
      }),
    )

    // After the confirm the panel re-renders with the use case's view; the
    // facts and hint render when present.
    await buttonBy(wrapper, 'Refresh').trigger('click')
    listOnboardingDrafts.mockResolvedValue(page([draftSummary({ stage: 'ready' })]))
    getOnboardingDraft.mockResolvedValue({ status: 200, data: { data: ready } })
    await wrapper.get('tbody tr').trigger('click')
    await vi.waitFor(() => expect(wrapper.text()).toContain('Linux/ubuntu-24.04/x86_64'))

    // Discover runs as a durable operation and the facts appear.
    discoverOnboardingDraft.mockResolvedValue({
      status: 202,
      data: { data: { id: 'op-2', kind: 'machine.onboard.discover', state: 'pending' } },
    })
    await clickEnabled(wrapper, 'Discover')
    await vi.waitFor(() => expect(discoverOnboardingDraft).toHaveBeenCalledWith('draft-1'))
    await vi.waitFor(() => expect(wrapper.text()).toContain('os.family'))

    // Add registers the machine and reports the duplicate as a warning.
    addOnboardingMachine.mockResolvedValue({
      status: 201,
      data: {
        data: {
          machine: {
            id: 'machine-1',
            name: 'builder',
            description: '',
            endpoints: [],
            tags: [],
            groups: [],
            machineStatus: 'agentless',
            lastSeenAt: null,
            lastObservation: null,
            capabilities: [],
            createdAt: 0,
            updatedAt: 0,
          },
          duplicates: [
            {
              machineId: 'm-1',
              name: 'twin',
              machineStatus: 'agentless',
              reference: 'ops@box.lan:22',
            },
          ],
        },
      },
    })
    await clickEnabled(wrapper, 'Add machine')
    await vi.waitFor(() => expect(wrapper.text()).toContain('Machine registered'))
    await vi.waitFor(() => expect(wrapper.text()).toContain('Duplicate candidate'))
    wrapper.unmount()
  })

  it('shows the duplicate warning on the review surface', async () => {
    listOnboardingDrafts.mockResolvedValue(
      page([draftSummary({ stage: 'review', hostKeyStage: 'observed' })]),
    )
    getOnboardingDraft.mockResolvedValue({
      status: 200,
      data: {
        data: draftDetail({
          stage: 'review',
          hostKeyStage: 'observed',
          duplicates: [
            {
              machineId: 'm-1',
              name: 'twin',
              machineStatus: 'agentless' as const,
              reference: 'ops@box.lan:22',
            },
          ],
        }),
      },
    })
    const wrapper = mount(OnboardingPanel)
    await vi.waitFor(() => expect(wrapper.text()).toContain('builder'))
    await wrapper.get('tbody tr').trigger('click')
    await vi.waitFor(() =>
      expect(wrapper.text()).toContain('warned, never merged'),
    )
    wrapper.unmount()
  })
})
