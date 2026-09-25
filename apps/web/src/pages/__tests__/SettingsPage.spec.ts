import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createMemoryHistory, createRouter } from 'vue-router'

import { routes } from '@/router'
import SettingsPage from '../settings/SettingsPage.vue'

vi.mock('@frogbyte-io/fleet-api-client', () => ({
  getSystemInfo: vi.fn(async () => ({
    status: 200,
    data: {
      service: 'fleet-controller',
      version: '0.1.0',
      trustMode: 'trusted-lan',
      trustWarning:
        'TRUSTED-LAN MODE: the controller has no accounts or login. Every client that can reach this controller can read and mutate.',
      storageOk: true,
      queuePending: 1,
      queueRunning: 2,
    },
  })),
  getMeta: vi.fn(async () => ({
    status: 200,
    data: { data: { apiVersion: 'v1', service: 'fleet-controller' } },
  })),
  listMachines: vi.fn(async () => ({
    status: 200,
    data: {
      items: [
        {
          id: 'm1',
          name: 'homelab-pve',
          machineStatus: 'connected',
          capabilities: [
            { namespace: 'agent', name: 'fleetd', value: '0.1.0', status: 'known' },
          ],
        },
        {
          id: 'm2',
          name: 'bare-lab',
          machineStatus: 'agentless',
          capabilities: [],
        },
      ],
      page: { limit: 100, nextCursor: null },
    },
  })),
  listProxmoxAccounts: vi.fn(async () => ({
    status: 200,
    data: {
      items: [
        {
          id: 'acc1',
          name: 'HOMELAB-PVE',
          host: 'pve.lan',
          port: 8006,
          tokenId: 'FLEET@PVE!CTRL',
          fingerprintState: 'confirmed',
          fingerprint: 'sha256:abc',
          createdAt: 1_757_000_000_000,
        },
      ],
      page: { limit: 100, nextCursor: null },
    },
  })),
  getTailnetStatus: vi.fn(async () => ({
    status: 200,
    data: { data: { configured: false, clientId: null, scope: 'devices:core:read' } },
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
  // resetAllMocks, not clearAllMocks: clearAllMocks leaves queued
  // mockImplementationOnce overrides in place, so a leaked once-override
  // would flow into the next test.
  vi.resetAllMocks()
})

async function mountAt(query: Record<string, string> = {}) {
  await router.push({ path: '/settings', query })
  await router.isReady()
  const wrapper = mount(SettingsPage, { global: { plugins: [router] } })
  await flushPromises()
  return wrapper
}

describe('SettingsPage', () => {
  let wrapper: Awaited<ReturnType<typeof mountAt>> | null = null

  afterEach(() => {
    wrapper?.unmount()
    wrapper = null
  })

  it('renders the grouped sub-nav and defaults to integrations', async () => {
    wrapper = await mountAt()
    expect(wrapper.text()).toContain('Controller')
    expect(wrapper.text()).toContain('Behaviour')
    expect(wrapper.text()).toContain('Integrations')
    expect(wrapper.text()).toContain('Proxmox VE')
    expect(wrapper.text()).toContain('1 account · confirmed')
    expect(wrapper.text()).toContain('FLEET@PVE!CTRL')
    expect(wrapper.text()).toContain('not configured')
    // No secret-shaped value is ever rendered: the fingerprint is exactly
    // the kind of value the page must keep out of the DOM.
    expect(wrapper.text()).not.toContain('sha256:abc')
    expect(wrapper.text()).not.toContain('SECRET')
  })

  it('shows an unconfirmed account as a warning, not ready', async () => {
    const { listProxmoxAccounts } = vi.mocked(await import('@frogbyte-io/fleet-api-client'))
    listProxmoxAccounts.mockImplementation(async () => ({
      status: 200,
      data: {
        items: [
          {
            id: 'acc1',
            name: 'HOMELAB-PVE',
            host: 'pve.lan',
            port: 8006,
            tokenId: 'FLEET@PVE!CTRL',
            fingerprintState: 'unconfirmed',
            createdAt: 1_757_000_000_000,
          },
        ],
        page: { limit: 100, nextCursor: null },
      },
      headers: new Headers(),
    }) as never)
    wrapper = await mountAt()
    expect(wrapper.text()).toContain('1 account · 0 confirmed')
  })

  it('shows the trusted-LAN warning in Security & access', async () => {
    wrapper = await mountAt({ section: 'security' })
    expect(wrapper.text()).toContain('Trusted-LAN mode.')
    expect(wrapper.text()).toContain('anonymous-lan-admin')
    // The API's own prefix is stripped so it is not duplicated next to the
    // static heading.
    expect(wrapper.text()).not.toContain('TRUSTED-LAN MODE:')
  })

  it('shows diagnostics from /system and /meta', async () => {
    wrapper = await mountAt({ section: 'diagnostics' })
    expect(wrapper.text()).toContain('fleet-controller 0.1.0')
    expect(wrapper.text()).toContain('ready')
    expect(wrapper.text()).toContain('1 pending · 2 running')
  })

  it('summarizes fleetd per machine without inventing tokens', async () => {
    wrapper = await mountAt({ section: 'fleetd' })
    expect(wrapper.text()).toContain('homelab-pve')
    expect(wrapper.text()).toContain('0.1.0')
    expect(wrapper.text()).toContain('agentless')
  })

  it('renders honest gaps with no invented controls', async () => {
    wrapper = await mountAt({ section: 'credentials' })
    expect(wrapper.text()).toContain('Credentials')
    expect(wrapper.text()).toContain('no backing API yet')
  })

  it('rejects an unknown section back to the default', async () => {
    wrapper = await mountAt({ section: 'not-a-section' })
    expect(wrapper.text()).toContain('Proxmox VE')
  })

  it('announces the loading state before any source answers', async () => {
    const { getSystemInfo } = vi.mocked(await import('@frogbyte-io/fleet-api-client'))
    getSystemInfo.mockImplementation(() => new Promise(() => undefined) as never)
    await router.push({ path: '/settings' })
    await router.isReady()
    wrapper = mount(SettingsPage, { global: { plugins: [router] } })
    expect(wrapper.find('[role="status"]').exists()).toBe(true)
    expect(wrapper.find('[aria-busy="true"]').exists()).toBe(true)
    expect(wrapper.text()).toContain('Loading settings…')
  })

  it('distinguishes an unavailable integration source from an empty one', async () => {
    const { listProxmoxAccounts, getTailnetStatus } = vi.mocked(
      await import('@frogbyte-io/fleet-api-client'),
    )
    listProxmoxAccounts.mockImplementation(async () => ({
      status: 403,
      data: { code: 'forbidden', message: 'no', correlationId: 'c1', retry: 'never' },
      headers: new Headers(),
    }) as never)
    getTailnetStatus.mockImplementation(async () => {
      throw new Error('refused')
    })
    wrapper = await mountAt()
    expect(wrapper.text()).toContain('unavailable')
    expect(wrapper.text()).toContain('could not be read')
  })

  it('renders the failure state when every source answers non-200', async () => {
    const client = await import('@frogbyte-io/fleet-api-client')
    for (const fn of [
      client.getSystemInfo,
      client.getMeta,
      client.listMachines,
      client.listProxmoxAccounts,
      client.getTailnetStatus,
    ]) {
      vi.mocked(fn).mockImplementation(async () => ({
        status: 503,
        data: { code: 'unavailable', message: 'down', correlationId: 'c1', retry: 'never' },
        headers: new Headers(),
      }) as never)
    }
    wrapper = await mountAt()
    expect(wrapper.text()).toContain('every settings source refused the request')
  })

  it('surfaces a full machine page as truncated rather than silent', async () => {
    const { listMachines } = vi.mocked(await import('@frogbyte-io/fleet-api-client'))
    listMachines.mockImplementation(async () => ({
      status: 200,
      data: {
        items: [
          {
            id: 'm1',
            name: 'homelab-pve',
            machineStatus: 'connected',
            capabilities: [
              { namespace: 'agent', name: 'fleetd', value: '0.1.0', status: 'known' },
            ],
          },
        ],
        page: { limit: 200, nextCursor: 'm1' },
      },
      headers: new Headers(),
    }) as never)
    wrapper = await mountAt({ section: 'fleetd' })
    expect(wrapper.text()).toContain('homelab-pve')
    expect(wrapper.text()).toContain('pagination bound')
    expect(listMachines).toHaveBeenCalledWith({ limit: 200 })
  })
})
