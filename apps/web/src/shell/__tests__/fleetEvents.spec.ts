import { mount } from '@vue/test-utils'
import { QueryClient, VueQueryPlugin } from '@tanstack/vue-query'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { defineComponent, h, nextTick } from 'vue'

import { invalidateFleetEvent, useFleetEvents } from '../fleetEvents'

class FakeEventSource {
  static instances: FakeEventSource[] = []
  readonly listeners = new Map<string, Array<() => void>>()
  readonly close = vi.fn()

  constructor(readonly url: string) {
    FakeEventSource.instances.push(this)
  }

  addEventListener(type: string, listener: EventListenerOrEventListenerObject) {
    const callbacks = this.listeners.get(type) ?? []
    callbacks.push(listener as () => void)
    this.listeners.set(type, callbacks)
  }

  emit(type: string) {
    for (const callback of this.listeners.get(type) ?? []) callback()
  }
}

function queryClient() {
  return new QueryClient({ defaultOptions: { queries: { retry: false } } })
}

function seed(client: QueryClient, ...keys: string[][]) {
  for (const key of keys) client.setQueryData(key, {})
}

function isInvalidated(client: QueryClient, key: string[]) {
  return client.getQueryState(key)?.isInvalidated
}

describe('fleet event query invalidation', () => {
  const cases: [string, ...string[][]][] = [
    ['machine.changed', ['fleet', 'machines'], ['machine', 'm1'], ['machines', 'matrix']],
    ['operation.changed', ['operation', 'o1']],
    ['lease.changed', ['lab', 'leases'], ['lab', 'provisions']],
    ['onboarding.changed', ['add', 'drafts'], ['onboarding-draft', 'd1']],
    ['proxmox.changed', ['fleet', 'proxmox-accounts'], ['fleet', 'proxmox-discovery', 'a1'], ['fleet', 'proxmox-guests', 'a1'], ['machine', 'm1']],
    ['tailnet.changed', ['fleet', 'tailnet-status'], ['fleet', 'tailnet-devices']],
  ]

  it.each(cases)('%s refreshes its matching query keys', (eventType, ...matchingKeys) => {
    const client = queryClient()
    const unrelated = ['projects', 'all']
    seed(client, ...matchingKeys, unrelated)

    invalidateFleetEvent(client, eventType)

    for (const key of matchingKeys) expect(isInvalidated(client, key)).toBe(true)
    expect(isInvalidated(client, unrelated)).toBe(false)
  })

  it('invalidates the full cache on gap and ignores unknown types', () => {
    const client = queryClient()
    seed(client, ['fleet', 'machines'], ['projects', 'all'])
    invalidateFleetEvent(client, 'unknown.changed')
    expect(isInvalidated(client, ['fleet', 'machines'])).toBe(false)
    invalidateFleetEvent(client, 'gap')
    expect(isInvalidated(client, ['fleet', 'machines'])).toBe(true)
    expect(isInvalidated(client, ['projects', 'all'])).toBe(true)
  })
})

describe('fleet event connection', () => {
  beforeEach(() => {
    FakeEventSource.instances = []
    vi.stubGlobal('EventSource', FakeEventSource)
  })

  afterEach(() => vi.unstubAllGlobals())

  it('shows connection transitions, refetches on open, and closes on unmount', async () => {
    const client = queryClient()
    seed(client, ['projects', 'all'])
    const Consumer = defineComponent({
      setup() {
        const status = useFleetEvents()
        return () => h('span', status.value)
      },
    })
    const wrapper = mount(Consumer, { global: { plugins: [[VueQueryPlugin, { queryClient: client }]] } })
    const stream = FakeEventSource.instances[0]
    expect(stream.url).toBe('/api/v1/events')
    expect(wrapper.text()).toBe('connecting')

    stream.emit('open')
    await nextTick()
    expect(wrapper.text()).toBe('live')
    expect(isInvalidated(client, ['projects', 'all'])).toBe(true)
    seed(client, ['fleet', 'machines'], ['projects', 'all'])
    stream.emit('machine.changed')
    expect(isInvalidated(client, ['fleet', 'machines'])).toBe(true)
    expect(isInvalidated(client, ['projects', 'all'])).toBe(false)
    stream.emit('gap')
    expect(isInvalidated(client, ['projects', 'all'])).toBe(true)
    stream.emit('error')
    await nextTick()
    expect(wrapper.text()).toBe('disconnected')
    seed(client, ['projects', 'all'])
    stream.emit('open')
    await nextTick()
    expect(wrapper.text()).toBe('live')
    expect(isInvalidated(client, ['projects', 'all'])).toBe(true)
    wrapper.unmount()
    expect(stream.close).toHaveBeenCalledOnce()
  })
})
