import { QueryClient, VueQueryPlugin } from '@tanstack/vue-query'
import { enableAutoUnmount, flushPromises, mount } from '@vue/test-utils'
import { createMemoryHistory, createRouter } from 'vue-router'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const listRunningServices = vi.fn()
const getRunningService = vi.fn()

vi.mock('@frogbyte-io/fleet-api-client', () => ({
  listRunningServices: (...a: unknown[]) => listRunningServices(...a),
  getRunningService: (...a: unknown[]) => getRunningService(...a),
}))

import { routes } from '@/router'
import ServiceDetailPage from '../ServiceDetailPage.vue'
import ServicesPage from '../ServicesPage.vue'
import { SERVICES_VIEW_KEY } from '../services'
import { coverage, sampleServices, service } from './fixtures'

function ok<T>(data: T) {
  return { status: 200, data, headers: new Headers() }
}

function listing(items = sampleServices(), patch: Record<string, unknown> = {}) {
  return ok({ items, page: { nextCursor: null, limit: 200 }, ambiguousServers: [], coverage: coverage(), evaluatedAt: 1, ...patch })
}

async function mountAt(path: string, component: typeof ServicesPage | typeof ServiceDetailPage) {
  const router = createRouter({ history: createMemoryHistory(), routes })
  await router.push(path)
  await router.isReady()
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } })
  const wrapper = mount(component, { global: { plugins: [[VueQueryPlugin, { queryClient }], router] } })
  await flushPromises()
  await flushPromises()
  return { wrapper, router }
}

enableAutoUnmount(afterEach)

beforeEach(() => {
  listRunningServices.mockReset()
  getRunningService.mockReset()
  localStorage.clear()
})

describe('Services page', () => {
  it('lists cards grouped by server with status chips', async () => {
    listRunningServices.mockResolvedValue(listing())
    const { wrapper } = await mountAt('/services', ServicesPage)
    const groups = wrapper.findAll('[data-testid="service-group"]')
    expect(groups.map(g => g.find('h2').text().replace(/\s+/g, ' '))).toEqual([
      'edge-1 3 SERVICES',
      'edge-2 1 SERVICE',
      'No known server 2 SERVICES',
    ])
    expect(wrapper.findAll('[data-testid="service-card"]')).toHaveLength(6)
    expect(wrapper.text()).toContain('6 running services · 1 degraded · 1 stale')
  })

  it('never shows a stale service as healthy and labels it', async () => {
    listRunningServices.mockResolvedValue(listing())
    const { wrapper } = await mountAt('/services', ServicesPage)
    const docs = wrapper.get('[data-service-id="coolify:acc1:docs"]')
    expect(docs.get('[data-testid="service-status"]').text()).toBe('running · stale')
    expect(docs.get('[data-testid="service-status"]').classes().join(' ')).toContain('text-fc-warn')
    expect(docs.get('[data-testid="service-stale"]').text()).toContain('Stale data')
    const blog = wrapper.get('[data-service-id="coolify:acc1:blog"]')
    expect(blog.get('[data-testid="service-status"]').classes().join(' ')).toContain('text-fc-ok')
  })

  it('shows ambiguous placement as ambiguous', async () => {
    listRunningServices.mockResolvedValue(listing())
    const { wrapper } = await mountAt('/services', ServicesPage)
    const docs = wrapper.get('[data-service-id="coolify:acc1:docs"]')
    expect(docs.get('[data-testid="service-placement"]').text()).toContain('Ambiguous placement')
    expect(docs.get('[data-testid="service-placement"]').text()).toContain('none chosen')
  })

  it('states that containers are not collected yet', async () => {
    listRunningServices.mockResolvedValue(listing())
    const { wrapper } = await mountAt('/services', ServicesPage)
    expect(wrapper.get('[data-testid="coverage-notes"]').text()).toContain('Docker containers are not collected yet')
  })

  it('toggles to the table, remembers the choice, and groups there too', async () => {
    listRunningServices.mockResolvedValue(listing())
    const { wrapper } = await mountAt('/services', ServicesPage)
    await wrapper.get('[data-testid="view-table"]').trigger('click')
    expect(localStorage.getItem(SERVICES_VIEW_KEY)).toBe('table')
    expect(wrapper.find('[data-testid="cards-view"]').exists()).toBe(false)
    expect(wrapper.findAll('[data-testid="service-row"]')).toHaveLength(6)
    expect(wrapper.findAll('[data-testid="table-group"]').map(g => g.text())).toEqual(['edge-1 · 3', 'edge-2 · 1', 'No known server · 2'])
    // Wide-only columns hide on a 390 px screen, so the table scrolls instead of overflowing the page.
    expect(wrapper.get('table').element.parentElement?.className).toContain('overflow')
    const hidden = wrapper.findAll('th').filter(th => th.classes().includes('hidden'))
    expect(hidden.length).toBeGreaterThanOrEqual(4)
  })

  it('opens in the saved view', async () => {
    localStorage.setItem(SERVICES_VIEW_KEY, 'table')
    listRunningServices.mockResolvedValue(listing())
    const { wrapper } = await mountAt('/services', ServicesPage)
    expect(wrapper.find('[data-testid="table-view"]').exists()).toBe(true)
  })

  it('narrows by search and says when nothing matches', async () => {
    listRunningServices.mockResolvedValue(listing())
    const { wrapper } = await mountAt('/services', ServicesPage)
    await wrapper.get('[data-testid="search"]').setValue('docs.example')
    expect(wrapper.findAll('[data-testid="service-card"]')).toHaveLength(1)
    await wrapper.get('[data-testid="search"]').setValue('nothing-like-this')
    expect(wrapper.find('[data-testid="services-no-match"]').exists()).toBe(true)
    await wrapper.get('[data-testid="reset-filters"]').trigger('click')
    expect(wrapper.findAll('[data-testid="service-card"]')).toHaveLength(6)
  })

  it('narrows to one Coolify resource from a Registry link', async () => {
    listRunningServices.mockResolvedValue(listing())
    const { wrapper } = await mountAt('/services?uuid=uuid-api', ServicesPage)
    expect(wrapper.findAll('[data-testid="service-card"]').map(c => c.attributes('data-service-id'))).toEqual(['coolify:acc1:api'])
  })

  it('clears the uuid narrowing with Clear filters', async () => {
    listRunningServices.mockResolvedValue(listing())
    const { wrapper, router } = await mountAt('/services?uuid=uuid-api', ServicesPage)
    await wrapper.get('[data-testid="reset-filters"]').trigger('click')
    await flushPromises()
    expect(router.currentRoute.value.query.uuid).toBeUndefined()
    expect(wrapper.findAll('[data-testid="service-card"]')).toHaveLength(6)
  })

  it('ignores an unknown status in the query', async () => {
    listRunningServices.mockResolvedValue(listing())
    const { wrapper } = await mountAt('/services?status=bogus', ServicesPage)
    expect(wrapper.findAll('[data-testid="service-card"]')).toHaveLength(6)
  })

  it('starts on a status from the query', async () => {
    listRunningServices.mockResolvedValue(listing())
    const { wrapper } = await mountAt('/services?status=degraded', ServicesPage)
    expect(wrapper.findAll('[data-testid="service-card"]')).toHaveLength(1)
  })

  it('explains an empty answer and a failed one', async () => {
    listRunningServices.mockResolvedValue(listing([]))
    const empty = await mountAt('/services', ServicesPage)
    expect(empty.wrapper.find('[data-testid="services-empty"]').exists()).toBe(true)

    listRunningServices.mockResolvedValue({ status: 403, data: { code: 'denied', message: 'you may not read any input' }, headers: new Headers() })
    const denied = await mountAt('/services', ServicesPage)
    expect(denied.wrapper.get('[data-testid="services-error"]').text()).toContain('you may not read any input')
  })

  it('follows pagination', async () => {
    listRunningServices
      .mockResolvedValueOnce(ok({ items: [service('a')], page: { nextCursor: 'c1', limit: 1 }, ambiguousServers: [], coverage: coverage(), evaluatedAt: 1 }))
      .mockResolvedValueOnce(ok({ items: [service('b')], page: { nextCursor: null, limit: 1 }, ambiguousServers: [], coverage: coverage(), evaluatedAt: 1 }))
    const { wrapper } = await mountAt('/services', ServicesPage)
    expect(wrapper.findAll('[data-testid="service-card"]')).toHaveLength(2)
    expect(listRunningServices.mock.calls[1]![0]).toMatchObject({ cursor: 'c1' })
  })
})

describe('Service detail page', () => {
  function detail(s = service('docs')) {
    return ok({ data: { service: s, coverage: coverage() } })
  }

  it('shows status, hostnames, last deploy, registry entries, and the Coolify link', async () => {
    const s = service('blog', {
      registry: [{ type: 'domain', key: 'example.org', link: 'domain_match', host: 'blog.example.org' }, { type: 'service', key: 'umami', link: 'hosted_on', host: null }],
    })
    getRunningService.mockResolvedValue(detail(s))
    const { wrapper } = await mountAt('/services/coolify%3Aacc1%3Ablog', ServiceDetailPage)
    expect(getRunningService).toHaveBeenCalledWith('coolify:acc1:blog')
    expect(wrapper.get('[data-testid="service-name"]').text()).toBe('blog')
    expect(wrapper.get('[data-testid="service-status"]').text()).toBe('running')
    expect(wrapper.get('[data-testid="service-fqdns"]').text()).toContain('blog.example.org')
    expect(wrapper.get('[data-testid="service-deploy"]').text()).toContain('abc1234')
    const links = wrapper.get('[data-testid="service-registry"]').findAll('a').map(a => a.attributes('href'))
    expect(links).toEqual(['/registry/domains?open=example.org', '/registry/services?entry=umami'])
    const coolify = wrapper.get('[data-testid="coolify-link"]')
    expect(coolify.attributes('href')).toBe('https://coolify.example.net/project/p1')
    expect(coolify.attributes('rel')).toContain('noopener')
    expect(wrapper.find('[data-testid="stale-banner"]').exists()).toBe(false)
    // The lifecycle slot exists and is empty until the broker has actions.
    expect(wrapper.get('[data-testid="service-actions"]').text()).toBe('')
  })

  it('lists why a service is stale and its ambiguous candidates', async () => {
    getRunningService.mockResolvedValue(detail(sampleServices().find(s => s.name === 'docs')))
    const { wrapper } = await mountAt('/services/coolify%3Aacc1%3Adocs', ServiceDetailPage)
    const banner = wrapper.get('[data-testid="stale-banner"]')
    expect(banner.text()).toContain('Stale data')
    expect(banner.text()).toContain('The Coolify applications observation is out of date.')
    expect(banner.text()).toContain('Hostnames come from an older Coolify read.')
    const placement = wrapper.get('[data-testid="service-placement"]')
    expect(placement.text()).toContain('Ambiguous placement')
    expect(placement.findAll('a').map(a => a.attributes('href'))).toEqual(['/fleet/machines/m2', '/fleet/machines/m3'])
    expect(wrapper.get('[data-testid="service-status"]').text()).toBe('running · stale')
  })

  it('refuses an unsafe deep link and omits it', async () => {
    getRunningService.mockResolvedValue(detail(service('x', { deepLink: 'javascript:alert(1)' })))
    const { wrapper } = await mountAt('/services/coolify%3Aacc1%3Ax', ServiceDetailPage)
    expect(wrapper.find('[data-testid="coolify-link"]').exists()).toBe(false)
  })

  it('draws no empty reasons list for a stale service without reasons', async () => {
    getRunningService.mockResolvedValue(detail(service('x', { stale: true, staleReasons: [] })))
    const { wrapper } = await mountAt('/services/coolify%3Aacc1%3Ax', ServiceDetailPage)
    expect(wrapper.get('[data-testid="stale-banner"]').find('ul').exists()).toBe(false)
  })

  it('says so when the service is gone', async () => {
    getRunningService.mockResolvedValue({ status: 404, data: { code: 'not_found', message: 'no such service' }, headers: new Headers() })
    const { wrapper } = await mountAt('/services/coolify%3Aacc1%3Agone', ServiceDetailPage)
    expect(wrapper.find('[data-testid="service-not-found"]').exists()).toBe(true)
  })
})
