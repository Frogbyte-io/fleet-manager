import { enableAutoUnmount, flushPromises, mount } from '@vue/test-utils'
import { QueryClient, VueQueryPlugin } from '@tanstack/vue-query'
import { createMemoryHistory, createRouter } from 'vue-router'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import type { OperationDto } from '@frogbyte-io/fleet-api-client'

const listOperations = vi.fn()
const getOperation = vi.fn()
const cancelOperation = vi.fn()

vi.mock('@frogbyte-io/fleet-api-client', () => ({
  listOperations: (...a: unknown[]) => listOperations(...a),
  getOperation: (...a: unknown[]) => getOperation(...a),
  cancelOperation: (...a: unknown[]) => cancelOperation(...a),
}))

import OperationsPage from '../OperationsPage.vue'
import { routes } from '@/router'

// A controllable EventSource: tests emit the operation stream's events.
class FakeEventSource {
  static instances: FakeEventSource[] = []
  readonly listeners = new Map<string, ((event: MessageEvent) => void)[]>()
  closed = false
  constructor(readonly url: string) {
    FakeEventSource.instances.push(this)
  }

  addEventListener(type: string, listener: (event: MessageEvent) => void) {
    this.listeners.set(type, [...(this.listeners.get(type) ?? []), listener])
  }

  emit(type: string, data?: unknown) {
    for (const listener of this.listeners.get(type) ?? [])
      listener({ data: data === undefined ? '' : JSON.stringify(data) } as MessageEvent)
  }

  close() {
    this.closed = true
  }
}
vi.stubGlobal('EventSource', FakeEventSource)

function ok<T>(data: T, status = 200) {
  return { status, data, headers: new Headers() }
}

function operation(overrides: Partial<OperationDto> = {}): OperationDto {
  return { id: 'op-1', kind: 'image.build', state: 'running', createdAt: 1, updatedAt: 2, cancelRequested: false, progressCurrent: 1, progressTotal: 2, progressMessage: 'building the image', ...overrides } as OperationDto
}

async function mountAt(path: string) {
  const router = createRouter({ history: createMemoryHistory(), routes })
  await router.push(path)
  await router.isReady()
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } })
  const wrapper = mount(OperationsPage, { global: { plugins: [[VueQueryPlugin, { queryClient }], router] } })
  await flushPromises()
  await flushPromises()
  return { wrapper, router }
}

enableAutoUnmount(afterEach)

beforeEach(() => {
  FakeEventSource.instances = []
  for (const mock of [listOperations, getOperation, cancelOperation])
    mock.mockReset()
  listOperations.mockResolvedValue(ok({ items: [
    operation(),
    operation({ id: 'op-2', kind: 'mise.install', state: 'failed', createdAt: 3, errorJson: '{"reason":"cli_failed"}' }),
    operation({ id: 'op-3', kind: 'ready.workflow', state: 'blocked_manual_approval', createdAt: 2, errorJson: '{"reason":"blocked_manual_approval","detail":"the Frogenv request awaits approval"}' }),
  ], page: { nextCursor: null, limit: 200 } }))
  getOperation.mockImplementation(async (id: string) => ok({ data: id === 'op-3'
    ? operation({ id: 'op-3', kind: 'ready.workflow', state: 'blocked_manual_approval', errorJson: '{"reason":"blocked_manual_approval","detail":"the Frogenv request awaits approval"}' })
    : operation({ id }) }))
})

describe('Operations page', () => {
  it('filters by state group and kind', async () => {
    const { wrapper } = await mountAt('/operations')
    await wrapper.get('[data-testid="group-failed"]').trigger('click')
    expect(wrapper.findAll('[data-testid^="operation-op"]').map(r => r.attributes('data-testid'))).toEqual(['operation-op-2'])
    await wrapper.get('[data-testid="group-all"]').trigger('click')
    await wrapper.get('[data-testid="filter-kind"]').setValue('ready.workflow')
    expect(wrapper.findAll('[data-testid^="operation-op"]').map(r => r.attributes('data-testid'))).toEqual(['operation-op-3'])
  })

  it('e2e: opens an operation, follows its stream, and cancels it after confirmation', async () => {
    const { wrapper, router } = await mountAt('/operations')
    await wrapper.get('[data-testid="operation-op-1"]').trigger('click')
    await flushPromises()
    expect(router.currentRoute.value.query.op).toBe('op-1')
    const stream = FakeEventSource.instances.at(-1)!
    expect(stream.url).toBe('/api/v1/operations/op-1/events')

    stream.emit('open')
    stream.emit('operation', operation({ progressMessage: 'validating the recipe', progressCurrent: 0 }))
    stream.emit('operation', operation())
    await flushPromises()
    expect(wrapper.get('[data-testid="stream-status"]').text()).toContain('live')
    expect(wrapper.get('[data-testid="timeline"]').text()).toContain('building the image')

    // Cancel needs a confirmation.
    cancelOperation.mockResolvedValue(ok({ data: operation({ cancelRequested: true, state: 'cancelling' }) }))
    getOperation.mockResolvedValue(ok({ data: operation({ cancelRequested: true, state: 'cancelling' }) }))
    await wrapper.get('[data-testid="cancel"]').trigger('click')
    expect(cancelOperation).not.toHaveBeenCalled()
    await wrapper.get('[data-testid="cancel-confirm"]').trigger('click')
    await flushPromises()
    expect(cancelOperation).toHaveBeenCalledWith('op-1')
    expect(wrapper.find('[data-testid="cancel"]').exists()).toBe(false)
    expect(wrapper.text()).toContain('Cancel requested')

    // The worker stops: the stream delivers the terminal snapshot and closes.
    stream.emit('operation', operation({ state: 'cancelled', cancelRequested: true }))
    await flushPromises()
    expect(stream.closed).toBe(true)
    expect(wrapper.get('[data-testid="operation-detail"]').text()).toContain('cancelled')
  })

  it('refetches after a gap in the stream', async () => {
    const { wrapper } = await mountAt('/operations?op=op-1')
    const stream = FakeEventSource.instances.at(-1)!
    getOperation.mockResolvedValue(ok({ data: operation({ state: 'succeeded', resultJson: '{"artifactId":"9000"}' }) }))
    stream.emit('gap')
    await flushPromises()
    expect(wrapper.text()).toContain('Changes were missed')
    expect(wrapper.get('[data-testid="operation-detail"]').text()).toContain('9000')
  })

  it('explains a blocked operation instead of offering cancel', async () => {
    const { wrapper } = await mountAt('/operations?op=op-3')
    const guidance = wrapper.get('[data-testid="blocked-guidance"]').text()
    expect(guidance).toContain('the Frogenv request awaits approval')
    expect(guidance).toContain('Run Make ready again')
    expect(wrapper.find('[data-testid="cancel"]').exists()).toBe(false)
  })
})
