import { QueryClient, VueQueryPlugin } from '@tanstack/vue-query'
import { enableAutoUnmount, flushPromises, mount } from '@vue/test-utils'
import { createMemoryHistory, createRouter } from 'vue-router'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const listRegistryTypes = vi.fn()
const listRegistryEntries = vi.fn()
const listDomainObservations = vi.fn()
const listMachines = vi.fn()
const getRegistryEntry = vi.fn()
const listRegistryEntryReferences = vi.fn()
const getDesiredSource = vi.fn()

vi.mock('@frogbyte-io/fleet-api-client', () => ({
  listRegistryTypes: (...a: unknown[]) => listRegistryTypes(...a),
  listRegistryEntries: (...a: unknown[]) => listRegistryEntries(...a),
  listDomainObservations: (...a: unknown[]) => listDomainObservations(...a),
  listMachines: (...a: unknown[]) => listMachines(...a),
  getRegistryEntry: (...a: unknown[]) => getRegistryEntry(...a),
  listRegistryEntryReferences: (...a: unknown[]) => listRegistryEntryReferences(...a),
  getDesiredSource: (...a: unknown[]) => getDesiredSource(...a),
}))

import { routes } from '@/router'
import DomainsPage from '../domains/DomainsPage.vue'
import ServicesPage from '../services/ServicesPage.vue'

function ok<T>(data: T) {
  return { status: 200, data, headers: new Headers() }
}
function page<T>(items: T[]) {
  return { items, page: { nextCursor: null, limit: 200 }, revision: { commitSha: 'abcdef0123456789', contentDigest: 'd' } }
}

const isoDay = (offset: number) => new Date(Date.now() + offset * 86_400_000).toISOString().slice(0, 10)

const types = [
  { name: 'domain', displayName: 'Domain', keyField: 'fqdn', origin: 'builtin', entryCount: 3, relations: [], spec: { fields: { fqdn: { type: 'hostname', required: true } } } },
  { name: 'service', displayName: 'Service', keyField: 'slug', origin: 'builtin', entryCount: 3, relations: [], spec: { fields: { slug: { type: 'string', required: true } } } },
]

function entry(type: string, key: string, fields: Record<string, unknown>, relations: unknown[] = []) {
  return { id: key, key, name: key, type, fields, links: [], relations, tags: [] }
}

const NO_RECORDS = { a: [], aaaa: [], cname: [], ns: [] }

function observation(key: string, patch: Record<string, unknown> = {}) {
  return {
    key,
    diffs: [],
    suggestion: [],
    warnings: [],
    observation: {
      observedAt: Date.now(),
      failures: 0,
      rdap: { status: 'ok', nameservers: ['ns1.example.net'], expires: isoDay(400) },
      dns: { status: 'ok', apex: { ...NO_RECORDS, a: ['192.0.2.10'] }, www: NO_RECORDS },
    },
    ...patch,
  }
}

async function mountAt(component: unknown, path: string) {
  const router = createRouter({ history: createMemoryHistory(), routes })
  await router.push(path)
  await router.isReady()
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } })
  const wrapper = mount(component as never, { global: { plugins: [[VueQueryPlugin, { queryClient }], router] } })
  for (let i = 0; i < 4; i++)
    await flushPromises()
  return wrapper
}

enableAutoUnmount(afterEach)

beforeEach(() => {
  for (const mock of [listRegistryTypes, listRegistryEntries, listDomainObservations, listMachines, getRegistryEntry, listRegistryEntryReferences, getDesiredSource])
    mock.mockReset()
  listRegistryTypes.mockResolvedValue(ok({ items: types, revision: { commitSha: 'abcdef0123456789', contentDigest: 'd' } }))
  listMachines.mockResolvedValue(ok(page([])))
  getDesiredSource.mockResolvedValue(ok({ remote: null }))
  listRegistryEntryReferences.mockResolvedValue(ok(page([])))
})

describe('Domains view', () => {
  function seed(entries: unknown[], views: unknown[]) {
    listRegistryEntries.mockResolvedValue(ok(page(entries)))
    listDomainObservations.mockResolvedValue(ok(page(views)))
  }

  it('shows drift, expiry warnings and the suggested patch command', async () => {
    seed(
      [
        entry('domain', 'fine.example.org', { registrar: 'Webhuset', dnsHost: 'Cloudflare', expires: isoDay(300), autoRenew: true }),
        entry('domain', 'soon.example.org', { registrar: 'Porkbun', expires: isoDay(9), autoRenew: false }),
        entry('domain', 'drift.example.org', { registrar: 'GoDaddy', expires: isoDay(200), autoRenew: true }),
      ],
      [
        observation('fine.example.org'),
        observation('drift.example.org', {
          diffs: [{ field: 'registrar', state: 'changed', recorded: 'GoDaddy', observed: 'Webhuset' }],
          suggestion: [{ field: 'registrar', value: 'Webhuset' }],
        }),
      ],
    )
    const wrapper = await mountAt(DomainsPage, '/registry/domains')
    const order = wrapper.findAll('[data-testid^="domain-"]:not([data-testid^="domain-detail"])').map(r => r.attributes('data-testid'))
    expect(order).toEqual(['domain-soon.example.org', 'domain-drift.example.org', 'domain-fine.example.org'])

    const soon = wrapper.get('[data-testid="domain-soon.example.org"]')
    expect(soon.text()).toContain('Expires in 9 days')
    expect(soon.text()).toContain('auto-renew off')
    expect(soon.text()).toContain('not looked up')

    const drift = wrapper.get('[data-testid="domain-drift.example.org"]')
    expect(drift.text()).toContain('registrar differs')
    expect(wrapper.get('[data-testid="domain-fine.example.org"]').text()).toContain('in sync')
    expect(wrapper.get('[data-testid="domains-summary"]').text()).toMatch(/Drifted from lookups\s*1/)

    await drift.trigger('click')
    const detail = wrapper.get('[data-testid="domain-detail-drift.example.org"]')
    expect(detail.text()).toContain('GoDaddy')
    expect(detail.text()).toContain('Webhuset')
    expect(detail.get('[data-testid="suggest-command"]').text()).toBe('fleetctl registry set domain/drift.example.org --field registrar=Webhuset')
  })

  it('degrades to what Fleet Git records when the lookups cannot be read', async () => {
    listRegistryEntries.mockResolvedValue(ok(page([entry('domain', 'a.example.org', { registrar: 'Webhuset', expires: isoDay(100) })])))
    listDomainObservations.mockResolvedValue({ status: 403, data: { code: 'forbidden', message: 'no lookups' }, headers: new Headers() })
    const wrapper = await mountAt(DomainsPage, '/registry/domains')
    expect(wrapper.find('[data-testid="domains-observations-error"]').exists()).toBe(true)
    expect(wrapper.get('[data-testid="domain-a.example.org"]').text()).toContain('Webhuset')
  })

  it('explains an empty Registry with the command to add a domain', async () => {
    seed([], [])
    const wrapper = await mountAt(DomainsPage, '/registry/domains')
    expect(wrapper.get('[data-testid="domains-empty"]').text()).toContain('fleetctl registry set domain/')
  })

  it('opens the details of the domain named in the link from the Overview', async () => {
    seed([entry('domain', 'soon.example.org', { expires: isoDay(9) })], [])
    const wrapper = await mountAt(DomainsPage, '/registry/domains?open=soon.example.org')
    expect(wrapper.find('[data-testid="domain-detail-soon.example.org"]').exists()).toBe(true)
  })
})

describe('Services view', () => {
  const services = [
    entry('service', 'plausible', { name: 'Plausible', vendor: 'Plausible Insights', plan: 'Growth', cost: '19.00 EUR', billingPeriod: 'monthly', renewal: isoDay(5), hostingProvider: 'EU cloud' }),
    entry('service', 'domains-bundle', { name: 'Domain bundle', cost: '120.00 EUR', billingPeriod: 'yearly', renewal: isoDay(200) }, [{ type: 'used-by', target: { class: 'registry', reference: 'domain/fine.example.org' } }]),
    entry('service', 'mail', { name: 'Mail', cost: '6.00 USD', billingPeriod: 'monthly' }),
    entry('service', 'oneoff', { name: 'One-off', cost: '50.00 EUR', billingPeriod: 'other' }),
  ]

  it('shows per-currency totals with the conversions labelled, and upcoming renewals', async () => {
    listRegistryEntries.mockResolvedValue(ok(page(services)))
    const wrapper = await mountAt(ServicesPage, '/registry/services')
    const eur = wrapper.get('[data-testid="total-EUR"]').text()
    expect(eur).toContain('€29.00') // 19 + 120 / 12
    expect(eur).toContain('€348.00') // 120 + 19 x 12
    expect(eur).toContain('includes yearly plans ÷ 12')
    expect(eur).toContain('includes monthly plans × 12')
    expect(wrapper.get('[data-testid="total-USD"]').text()).toContain('$72.00')
    expect(wrapper.get('[data-testid="totals-excluded"]').text()).toContain('1 billed on another period')

    const renewals = wrapper.get('[data-testid="renewals"]').text()
    expect(renewals).toContain('Plausible')
    expect(renewals).toContain('in 5 days')
    expect(renewals).not.toContain('Domain bundle')
  })

  it('links a relation to another Registry entry in the details', async () => {
    listRegistryEntries.mockResolvedValue(ok(page(services)))
    const wrapper = await mountAt(ServicesPage, '/registry/services')
    await wrapper.get('[data-testid="service-domains-bundle"]').trigger('click')
    const link = wrapper.get('[data-testid="service-detail-domains-bundle"] a')
    expect(link.attributes('href')).toBe('/registry?type=domain&entry=fine.example.org')
  })

  it('explains the empty state', async () => {
    listRegistryEntries.mockResolvedValue(ok(page([])))
    const wrapper = await mountAt(ServicesPage, '/registry/services')
    expect(wrapper.get('[data-testid="services-empty"]').text()).toContain('fleetctl registry set service/')
  })
})
