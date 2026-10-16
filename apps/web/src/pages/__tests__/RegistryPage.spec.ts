import { flushPromises, mount } from '@vue/test-utils'
import { VueQueryPlugin, type VueQueryPluginOptions } from '@tanstack/vue-query'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createMemoryHistory, createRouter } from 'vue-router'

import { routes } from '@/router'
import RegistryPage from '../registry/RegistryPage.vue'

const SHA = 'b'.repeat(40)
const revision = { commitSha: SHA, contentDigest: 'sha256:x' }

const domainType = {
  name: 'domain',
  displayName: 'Domain',
  entryCount: 1,
  keyField: 'fqdn',
  origin: 'builtin',
  relations: ['used-by'],
  spec: {
    displayName: 'Domain',
    key: 'fqdn',
    fields: {
      fqdn: { type: 'hostname', required: true },
      registrar: { type: 'string' },
      expires: { type: 'date' },
      autoRenew: { type: 'boolean' },
      cost: { type: 'money' },
    },
  },
}
const serviceType = { ...domainType, name: 'service', displayName: 'Service', entryCount: 0, keyField: 'slug', spec: { displayName: 'Service', key: 'slug', fields: { slug: { type: 'string', required: true } } } }

const entry = {
  id: 'e1',
  type: 'domain',
  key: 'example.org',
  name: 'domain-example-org',
  fields: { fqdn: 'example.org', registrar: 'Porkbun', expires: '2027-06-30', autoRenew: true, cost: '12.50 EUR' },
  tags: ['client-x'],
  links: [{ label: 'DNS', url: 'https://dash.example.org/dns' }],
  notes: 'Moved in 2025.',
  relations: [
    { type: 'used-by', target: { class: 'registry', reference: 'service/plausible' } },
    { type: 'hosted-on', target: { class: 'machine', reference: 'build-1' } },
  ],
  sourcePath: 'fleet/registry/domain/example.org.yaml',
}

const mocks = vi.hoisted(() => ({ entries: [] as unknown[] }))

vi.mock('@frogbyte-io/fleet-api-client', () => ({
  listRegistryTypes: vi.fn(async () => ({ status: 200, data: { items: [domainType, serviceType], revision }, headers: new Headers() })),
  listRegistryEntries: vi.fn(async (params: { type?: string, tag?: string }) => ({
    status: 200,
    data: { items: params.type === 'domain' ? (mocks.entries as { tags: string[] }[]).filter(e => !params.tag || e.tags.includes(params.tag)) : [], page: { limit: 200, nextCursor: null }, revision },
    headers: new Headers(),
  })),
  getRegistryEntry: vi.fn(async () => ({ status: 200, data: { data: entry, revision }, headers: new Headers() })),
  listRegistryEntryReferences: vi.fn(async () => ({
    status: 200,
    data: { items: [{ entryType: 'service', entryKey: 'mailer', entryName: 'service-mailer', relation: 'uses' }], page: { limit: 200, nextCursor: null }, revision },
    headers: new Headers(),
  })),
  listMachines: vi.fn(async () => ({ status: 200, data: { items: [{ id: 'm-1', name: 'build-1' }], page: { limit: 200, nextCursor: null } }, headers: new Headers() })),
  getDesiredSource: vi.fn(async () => ({ status: 200, data: { data: { remote: 'https://github.com/acme/fleet.git' } }, headers: new Headers() })),
}))

let router: ReturnType<typeof createRouter>

beforeEach(() => {
  mocks.entries = [entry]
  router = createRouter({ history: createMemoryHistory(), routes })
})

afterEach(() => {
  document.body.innerHTML = ''
})

async function mountAt(path: string) {
  await router.push(path)
  await router.isReady()
  const wrapper = mount(RegistryPage, {
    attachTo: document.body,
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

describe('RegistryPage', () => {
  it('renders columns and typed values from the type definition', async () => {
    const wrapper = await mountAt('/registry')
    const header = wrapper.find('thead').text()
    expect(header).toContain('fqdn')
    expect(header).toContain('registrar')
    expect(header).toContain('autoRenew')
    const row = wrapper.find('[data-testid="entry-example.org"]').text()
    expect(row).toContain('example.org')
    expect(row).toContain('Porkbun')
    expect(row).toContain('2027-06-30')
    expect(row).toContain('Yes')
    expect(row).toContain('€12.50')
    expect(row).toContain('client-x')
    expect(wrapper.find('[data-testid="type-service"]').text()).toContain('Service')
    wrapper.unmount()
  })

  it('opens the drawer with relations both ways and a source link, path, and set command', async () => {
    const wrapper = await mountAt('/registry?type=domain&entry=example.org')
    const body = document.body
    expect(body.querySelector('[data-testid="drawer-fields"]')?.textContent).toContain('Porkbun')
    const outgoing = body.querySelector('[data-testid="drawer-outgoing"]')!
    expect(outgoing.textContent).toContain('service/plausible')
    const machine = [...outgoing.querySelectorAll('a')].find(a => a.textContent?.includes('build-1'))
    expect(machine?.getAttribute('href')).toBe('/fleet/machines/m-1')
    expect(body.querySelector('[data-testid="drawer-incoming"]')?.textContent).toContain('service/mailer')
    expect(body.querySelector('[data-testid="drawer-links"] a')?.getAttribute('href')).toBe('https://dash.example.org/dns')
    expect(body.textContent).toContain('Moved in 2025.')
    expect(body.querySelector('[data-testid="view-source-at-revision"]')?.getAttribute('href'))
      .toBe(`https://github.com/acme/fleet/blob/${SHA}/fleet/registry/domain/example.org.yaml`)
    // The path and command are shown next to the link, not only as a fallback.
    expect(body.querySelector('[data-testid="source-path"]')?.textContent).toContain('fleet/registry/domain/example.org.yaml')
    expect(body.querySelector('[data-testid="set-command"]')?.textContent).toContain('fleetctl registry set domain/example.org')
    wrapper.unmount()
  })

  it('explains the fleetctl workflow when a type has no entries', async () => {
    mocks.entries = []
    const wrapper = await mountAt('/registry?type=domain')
    const empty = wrapper.find('[data-testid="registry-empty"]').text()
    expect(empty).toContain('fleetctl registry set domain/<fqdn>')
    expect(empty).toContain('fleetctl registry publish')
    wrapper.unmount()
  })

  it('sends the tag to the API and keeps a URL tag selected', async () => {
    const { listRegistryEntries } = vi.mocked(await import('@frogbyte-io/fleet-api-client'))
    mocks.entries = []
    const wrapper = await mountAt('/registry?type=domain&tag=other')
    expect(listRegistryEntries).toHaveBeenCalledWith(expect.objectContaining({ type: 'domain', tag: 'other' }))
    expect((wrapper.find('[data-testid="registry-tag"]').element as HTMLSelectElement).value).toBe('other')
    wrapper.unmount()
  })

  it('filters by tag and says so when nothing matches', async () => {
    const wrapper = await mountAt('/registry?type=domain&tag=other')
    expect(wrapper.find('[data-testid="registry-empty"]').text()).toContain('match these filters')
    wrapper.unmount()
  })

  it('falls back to the path and command when the remote has no web mapping', async () => {
    const { getDesiredSource } = vi.mocked(await import('@frogbyte-io/fleet-api-client'))
    getDesiredSource.mockImplementation(async () => ({ status: 200, data: { data: { remote: 'https://git.internal.example/acme/fleet' } }, headers: new Headers() }) as never)
    const wrapper = await mountAt('/registry?type=domain&entry=example.org')
    expect(document.body.querySelector('[data-testid="view-source-at-revision"]')).toBeNull()
    const fallback = document.body.querySelector('[data-testid="source-path"]')!.textContent
    expect(fallback).toContain('fleet/registry/domain/example.org.yaml')
    expect(fallback).toContain('fleetctl registry set domain/example.org')
    wrapper.unmount()
  })
})
