import { enableAutoUnmount, flushPromises, mount } from '@vue/test-utils'
import { QueryClient, VueQueryPlugin } from '@tanstack/vue-query'
import { createMemoryHistory, createRouter } from 'vue-router'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import type { ActionRequestDto } from '@frogbyte-io/fleet-api-client'

const listActionRequests = vi.fn()
const approveActionRequest = vi.fn()
const denyActionRequest = vi.fn()

vi.mock('@frogbyte-io/fleet-api-client', () => ({
  listActionRequests: (...a: unknown[]) => listActionRequests(...a),
  approveActionRequest: (...a: unknown[]) => approveActionRequest(...a),
  denyActionRequest: (...a: unknown[]) => denyActionRequest(...a),
}))

import RequestsPage from '../RequestsPage.vue'
import { invalidateFleetEvent } from '@/shell/fleetEvents'
import { routes } from '@/router'

function ok<T>(data: T, status = 200) {
  return { status, data, headers: new Headers() }
}

const NOW = Date.now()
function request(overrides: Partial<ActionRequestDto> = {}): ActionRequestDto {
  return {
    id: 'req-1',
    requester: 'agent-7',
    origin: 'api',
    actionId: 'coolify.application.redeploy',
    target: 'app-1',
    parameters: { force: true },
    riskClass: 'approve',
    reason: 'ship the fix',
    state: 'pending',
    terminal: false,
    decidedBy: null,
    decidedAt: null,
    decisionNote: null,
    operationId: null,
    failure: null,
    createdAt: NOW - 120_000,
    expiresAt: NOW + 3600_000,
    updatedAt: NOW - 120_000,
    ...overrides,
  } as ActionRequestDto
}

async function mountAt(path = '/requests') {
  const router = createRouter({ history: createMemoryHistory(), routes })
  await router.push(path)
  await router.isReady()
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } })
  const wrapper = mount(RequestsPage, { global: { plugins: [[VueQueryPlugin, { queryClient }], router] } })
  await flushPromises()
  await flushPromises()
  return { wrapper, queryClient }
}

enableAutoUnmount(afterEach)

beforeEach(() => {
  for (const mock of [listActionRequests, approveActionRequest, denyActionRequest])
    mock.mockReset()
  listActionRequests.mockResolvedValue(ok({ items: [
    request(),
    request({ id: 'req-2', state: 'succeeded', decidedBy: 'anonymous-lan-admin', operationId: 'op-9876543210ab', updatedAt: NOW - 1000 }),
    request({ id: 'req-3', state: 'denied', decidedBy: 'anonymous-lan-admin', decisionNote: 'not during the freeze', updatedAt: NOW - 2000 }),
    request({ id: 'req-4', state: 'failed', decidedBy: 'anonymous-lan-admin', failure: 'the operation was refused', updatedAt: NOW - 3000 }),
  ], page: { nextCursor: null, limit: 200 } }))
})

describe('Approval inbox', () => {
  it('lists pending requests with action, target, parameters, reason, requester, age, and risk', async () => {
    const { wrapper } = await mountAt()
    const card = wrapper.get('[data-testid="request-req-1"]')
    expect(card.text()).toContain('coolify.application.redeploy')
    expect(card.text()).toContain('on app-1')
    expect(card.text()).toContain('agent-7')
    expect(card.text()).toContain('ship the fix')
    expect(card.text()).toContain('2M AGO')
    expect(card.text()).toContain('risk approve')
    expect(card.get('[data-testid="parameters"]').text()).toContain('"force": true')
    expect(wrapper.get('[data-testid="pending-count"]').text()).toBe('1')
  })

  it('shows history with outcomes, notes, failures, and linked operations', async () => {
    const { wrapper } = await mountAt()
    expect(wrapper.get('[data-testid="history-req-2"]').text()).toContain('succeeded')
    expect(wrapper.get('[data-testid="history-req-2"] a').attributes('href')).toBe('/operations?op=op-9876543210ab')
    expect(wrapper.get('[data-testid="history-req-3"]').text()).toContain('not during the freeze')
    expect(wrapper.get('[data-testid="history-req-4"]').text()).toContain('the operation was refused')
  })

  it('says so when nothing is pending or decided', async () => {
    listActionRequests.mockResolvedValue(ok({ items: [], page: { nextCursor: null, limit: 200 } }))
    const { wrapper } = await mountAt()
    expect(wrapper.find('[data-testid="pending-empty"]').exists()).toBe(true)
    expect(wrapper.find('[data-testid="history-empty"]').exists()).toBe(true)
  })

  it('names a load failure', async () => {
    listActionRequests.mockResolvedValue(ok({ code: 'denied', message: 'not allowed' }, 403))
    const { wrapper } = await mountAt()
    expect(wrapper.get('[role="alert"]').text()).toContain('not allowed')
  })

  it('asks for confirmation, then approves and refetches', async () => {
    approveActionRequest.mockResolvedValue(ok({ data: request({ state: 'executing' }) }))
    const { wrapper } = await mountAt()
    await wrapper.get('[data-testid="approve"]').trigger('click')
    expect(approveActionRequest).not.toHaveBeenCalled()
    expect(wrapper.get('[data-testid="fleetctl-command"]').text()).toBe('fleetctl requests approve req-1 --output json')
    await wrapper.get('[data-testid="confirm"]').trigger('click')
    await flushPromises()
    expect(approveActionRequest).toHaveBeenCalledWith('req-1')
    expect(listActionRequests).toHaveBeenCalledTimes(2)
  })

  it('denies with an optional note', async () => {
    denyActionRequest.mockResolvedValue(ok({ data: request({ state: 'denied' }) }))
    const { wrapper } = await mountAt()
    await wrapper.get('[data-testid="deny"]').trigger('click')
    await wrapper.get('[data-testid="deny-note"]').setValue('not now')
    expect(wrapper.get('[data-testid="fleetctl-command"]').text()).toContain('--note')
    await wrapper.get('[data-testid="confirm"]').trigger('click')
    await flushPromises()
    expect(denyActionRequest).toHaveBeenCalledWith('req-1', { note: 'not now' })
  })

  it('denies without a note by sending no body', async () => {
    denyActionRequest.mockResolvedValue(ok({ data: request({ state: 'denied' }) }))
    const { wrapper } = await mountAt()
    await wrapper.get('[data-testid="deny"]').trigger('click')
    await wrapper.get('[data-testid="confirm"]').trigger('click')
    await flushPromises()
    expect(denyActionRequest).toHaveBeenCalledWith('req-1', null)
  })

  it('shows a lost decision and keeps the card for the refetch to settle', async () => {
    approveActionRequest.mockResolvedValue(ok({ code: 'conflict', message: 'another decision was made first' }, 409))
    const { wrapper } = await mountAt()
    await wrapper.get('[data-testid="approve"]').trigger('click')
    await wrapper.get('[data-testid="confirm"]').trigger('click')
    await flushPromises()
    expect(wrapper.get('[data-testid="decision-error"]').text()).toContain('another decision was made first')
  })

  it('goes back from a decision without sending anything', async () => {
    const { wrapper } = await mountAt()
    await wrapper.get('[data-testid="deny"]').trigger('click')
    await wrapper.get('[data-testid="cancel"]').trigger('click')
    expect(denyActionRequest).not.toHaveBeenCalled()
    expect(wrapper.find('[data-testid="confirm"]').exists()).toBe(false)
  })

  it('refetches when the event stream announces a request change', async () => {
    const { wrapper, queryClient } = await mountAt()
    listActionRequests.mockResolvedValue(ok({ items: [request({ id: 'req-5', target: 'app-5' })], page: { nextCursor: null, limit: 200 } }))
    invalidateFleetEvent(queryClient, 'request.changed')
    await flushPromises()
    expect(wrapper.find('[data-testid="request-req-5"]').exists()).toBe(true)
    expect(wrapper.find('[data-testid="request-req-1"]').exists()).toBe(false)
  })

  it('warns that a full page may hide older requests', async () => {
    listActionRequests.mockResolvedValue(ok({ items: Array.from({ length: 200 }, (_, i) => request({ id: `r${i}`, state: 'succeeded' })), page: { nextCursor: null, limit: 200 } }))
    const { wrapper } = await mountAt()
    expect(wrapper.get('[role="status"]').text()).toContain('newest 200')
  })
})
