import { QueryClient, VueQueryPlugin } from '@tanstack/vue-query'
import { flushPromises, mount } from '@vue/test-utils'
import { defineComponent, h } from 'vue'
import { createMemoryHistory, createRouter } from 'vue-router'
import { beforeEach, describe, expect, it, vi } from 'vitest'

const getProxmoxPrivileges = vi.fn()
vi.mock('@frogbyte-io/fleet-api-client', () => ({
  getProxmoxPrivileges: (...args: unknown[]) => getProxmoxPrivileges(...args),
  createProxmoxConsoleSession: vi.fn(),
}))

// The panel itself is covered by ProxmoxConsole.spec.ts; the surfaces are
// checked for what they hand it.
vi.mock('../ProxmoxConsole.vue', () => ({
  __esModule: true,
  default: defineComponent({
    props: {
      accountId: { type: String, default: undefined },
      node: { type: String, default: undefined },
      vmid: { type: Number, default: undefined },
      guestStatus: { type: String, default: null },
      blockedReason: { type: String, default: null },
      sessionToken: { type: String, default: null },
      autoConnect: { type: Boolean, default: false },
    },
    setup: props => () => h('div', {
      'data-testid': 'console-stub',
      'data-account': props.accountId,
      'data-node': props.node,
      'data-vmid': props.vmid,
      'data-status': props.guestStatus,
      'data-blocked': props.blockedReason ?? '',
      'data-token': props.sessionToken ?? '',
      'data-auto': String(props.autoConnect),
    }),
  }),
}))

import type { GuestItem } from '../../../fleet/inventory'
import ScreenTab from '../../../machine/tabs/ScreenTab.vue'
import ConsolePage from '../ConsolePage.vue'

function guest(overrides: Partial<GuestItem> = {}): GuestItem {
  return {
    key: 'acc1/101',
    accountId: 'acc1',
    accountName: 'homelab',
    kind: 'vm',
    vmid: 101,
    name: 'build-01',
    node: 'pve-a',
    status: 'running',
    agentOnline: true,
    osName: null,
    addresses: [],
    candidates: [],
    ...overrides,
  }
}

function report(status: 'granted' | 'missing') {
  return {
    status: 200,
    data: {
      data: {
        accountId: 'acc1',
        pveVersion: '9.2.2',
        rulesMajor: 9,
        tiers: [
          { tier: 'console', status, checks: [], missing: status === 'missing' ? [{ privileges: ['VM.Console'], anyOf: false, path: '/vms/{vmid}', capabilities: ['proxmox.console'] }] : [] },
        ],
        unknownReason: null,
        effectivePermissions: {},
        warnings: [],
        observedAt: 0,
      },
    },
    headers: new Headers(),
  }
}

function mountTab(guests: GuestItem[], loading = false) {
  return mount(ScreenTab, {
    props: { guests, loading },
    global: { plugins: [[VueQueryPlugin, { queryClient: new QueryClient({ defaultOptions: { queries: { retry: false } } }) }]] },
  })
}

describe('ScreenTab', () => {
  beforeEach(() => getProxmoxPrivileges.mockReset())

  it('says so when no QEMU guest is associated', () => {
    const wrapper = mountTab([guest({ kind: 'lxc', key: 'acc1/200', vmid: 200 })])
    expect(wrapper.get('[data-testid="screen-no-guest"]').text()).toContain('no screen to show')
    expect(getProxmoxPrivileges).not.toHaveBeenCalled()
  })

  it('hands the linked guest to the console', async () => {
    getProxmoxPrivileges.mockResolvedValue(report('granted'))
    const wrapper = mountTab([guest()])
    await flushPromises()
    const stub = wrapper.get('[data-testid="console-stub"]')
    expect(stub.attributes()).toMatchObject({ 'data-account': 'acc1', 'data-node': 'pve-a', 'data-vmid': '101', 'data-status': 'running', 'data-blocked': '' })
  })

  it('withholds the console when the privilege report says VM.Console is missing', async () => {
    getProxmoxPrivileges.mockResolvedValue(report('missing'))
    const wrapper = mountTab([guest()])
    await flushPromises()
    expect(wrapper.get('[data-testid="console-stub"]').attributes('data-blocked')).toContain('VM.Console on /vms/{vmid}')
  })

  it('lets the controller decide when the report cannot be read', async () => {
    getProxmoxPrivileges.mockResolvedValue({ status: 502, data: { code: 'proxmox_source', message: 'down' }, headers: new Headers() })
    const wrapper = mountTab([guest()])
    await flushPromises()
    expect(wrapper.get('[data-testid="console-stub"]').attributes('data-blocked')).toBe('')
  })

  it('offers a choice between several linked guests', async () => {
    getProxmoxPrivileges.mockResolvedValue(report('granted'))
    const wrapper = mountTab([guest(), guest({ key: 'acc1/102', vmid: 102, name: 'build-02' })])
    await flushPromises()
    await wrapper.get('[data-testid="screen-guest"]').setValue('acc1/102')
    await flushPromises()
    expect(wrapper.get('[data-testid="console-stub"]').attributes('data-vmid')).toBe('102')
  })
})

describe('ConsolePage', () => {
  async function mountPage(hash: string) {
    window.history.replaceState(null, '', `/proxmox/console${hash}`)
    const router = createRouter({ history: createMemoryHistory(), routes: [{ path: '/proxmox', component: { template: '<p />' } }] })
    return mount(ConsolePage, { global: { plugins: [router] } })
  }

  it('connects with the link\'s token and removes it from the address bar', async () => {
    const wrapper = await mountPage('#session=abcdefghijklmnopqrstuvwxyz012345')
    const stub = wrapper.get('[data-testid="console-stub"]')
    expect(stub.attributes('data-token')).toBe('abcdefghijklmnopqrstuvwxyz012345')
    expect(stub.attributes('data-auto')).toBe('true')
    expect(window.location.hash).toBe('')
    expect(window.location.pathname).toBe('/proxmox/console')
  })

  it('explains what a console link is when there is none', async () => {
    const wrapper = await mountPage('')
    expect(wrapper.find('[data-testid="console-stub"]').exists()).toBe(false)
    expect(wrapper.get('[data-testid="console-link-missing"]').text()).toContain('fleetctl proxmox console')
  })
})
