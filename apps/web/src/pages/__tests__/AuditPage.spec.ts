import { flushPromises, mount } from '@vue/test-utils'
import { VueQueryPlugin, type VueQueryPluginOptions } from '@tanstack/vue-query'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createMemoryHistory, createRouter } from 'vue-router'

import { routes } from '@/router'
import AuditPage from '../audit/AuditPage.vue'

vi.mock('@frogbyte-io/fleet-api-client', () => ({
  listAuditEvents: vi.fn(async () => ({
    status: 200,
    data: {
      items: [
        {
          seq: 3,
          id: 'e3',
          occurredAt: 1_757_000_000_000,
          actor: 'anonymous-lan-admin',
          action: 'machine.update',
          resource: 'm1',
          allowed: true,
          reason: 'trusted-lan',
          outcome: 'succeeded',
          correlationId: null,
          operationId: null,
          metadata: [{ key: 'secret_material', value: 'TOPSECRETMARKER' }],
        },
        {
          seq: 2,
          id: 'e2',
          occurredAt: 1_756_900_000_000,
          actor: 'anonymous-lan-admin',
          action: 'machine.delete',
          resource: 'm9',
          allowed: false,
          reason: 'denied by policy',
          outcome: null,
          correlationId: null,
          operationId: null,
          metadata: [],
        },
      ],
      page: { limit: 200, nextCursor: null },
    },
    headers: new Headers(),
  })),
}))

function makeRouter() {
  return createRouter({ history: createMemoryHistory(), routes })
}

let router: ReturnType<typeof createRouter>

beforeEach(() => {
  router = makeRouter()
})

afterEach(() => {
  vi.resetAllMocks()
})

async function mountAt() {
  await router.push('/audit')
  await router.isReady()
  const wrapper = mount(AuditPage, {
    global: {
      plugins: [
        router,
        [VueQueryPlugin, { queryClientConfig: { defaultOptions: { queries: { retry: false } } } } as VueQueryPluginOptions],
      ],
    },
  })
  await flushPromises()
  return wrapper
}

describe('AuditPage', () => {
  let wrapper: Awaited<ReturnType<typeof mountAt>> | null = null

  afterEach(() => {
    wrapper?.unmount()
    wrapper = null
  })

  it('renders events with outcome chips and no secret surface', async () => {
    wrapper = await mountAt()
    expect(wrapper.text()).toContain('machine.update')
    expect(wrapper.text()).toContain('succeeded')
    expect(wrapper.text()).toContain('denied · denied by policy')
    expect(wrapper.text()).toContain('anonymous-lan-admin')
    // Metadata is metadata-only by construction: even a secret-shaped
    // value in the ledger's metadata never reaches the DOM.
    expect(wrapper.text()).not.toContain('TOPSECRETMARKER')
    expect(wrapper.text()).not.toContain('secret_material')
  })

  it('shows the empty state when nothing matches', async () => {
    const { listAuditEvents } = vi.mocked(await import('@frogbyte-io/fleet-api-client'))
    listAuditEvents.mockImplementation(async () => ({
      status: 200,
      data: { items: [], page: { limit: 200, nextCursor: null } },
      headers: new Headers(),
    }) as never)
    wrapper = await mountAt()
    expect(wrapper.find('[data-testid="no-audit"]').exists()).toBe(true)
  })

  it('applies filters and reports a query failure honestly', async () => {
    wrapper = await mountAt()
    const { listAuditEvents } = vi.mocked(await import('@frogbyte-io/fleet-api-client'))
    listAuditEvents.mockImplementation(async () => ({
      status: 403,
      data: { code: 'denied', message: 'no', correlationId: 'c1', retry: 'never' },
      headers: new Headers(),
    }) as never)
    await wrapper.find('[data-testid="audit-actor"]').setValue('anon')
    await wrapper.find('form').trigger('submit')
    await flushPromises()
    expect(wrapper.text()).toContain('the audit query failed (403)')
    // The filter actually reached the API.
    expect(listAuditEvents).toHaveBeenCalledWith(
      expect.objectContaining({ actor: 'anon', limit: 200 }),
    )
  })

  it('shows the truncation notice when the walk bound is reached', async () => {
    const { listAuditEvents } = vi.mocked(await import('@frogbyte-io/fleet-api-client'))
    listAuditEvents.mockImplementation(async () => ({
      status: 200,
      data: {
        items: [
          {
            seq: 1,
            id: 'e1',
            occurredAt: 1_756_000_000_000,
            actor: 'a',
            action: 'x',
            resource: null,
            allowed: true,
            reason: 'r',
            outcome: 'succeeded',
            correlationId: null,
            operationId: null,
            metadata: [],
          },
        ],
        page: { limit: 200, nextCursor: '1' },
      },
      headers: new Headers(),
    }) as never)
    wrapper = await mountAt()
    expect(wrapper.find('[data-testid="audit-truncated"]').exists()).toBe(true)
  })

  it('offers no next page when the ledger is exhausted', async () => {
    // The final page is not full and carries nextCursor: null — the end
    // of the ledger, not an invitation to query past it.
    wrapper = await mountAt()
    expect(wrapper.find('[data-testid="audit-next"]').exists()).toBe(false)
  })
})
