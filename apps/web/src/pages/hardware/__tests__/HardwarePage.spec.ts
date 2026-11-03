import { enableAutoUnmount, flushPromises, mount } from '@vue/test-utils'
import { QueryClient, VueQueryPlugin } from '@tanstack/vue-query'
import { createMemoryHistory, createRouter } from 'vue-router'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const listHardwareDevices = vi.fn()
const refreshHardware = vi.fn()
const listProxmoxAccounts = vi.fn()

vi.mock('@frogbyte-io/fleet-api-client', () => ({
  listHardwareDevices: (...args: unknown[]) => listHardwareDevices(...args),
  refreshHardware: (...args: unknown[]) => refreshHardware(...args),
  listProxmoxAccounts: (...args: unknown[]) => listProxmoxAccounts(...args),
  listTailnetDevices: vi.fn(),
}))

import HardwarePage from '../HardwarePage.vue'
import { routes } from '@/router'
import { ACCOUNT_A, ACCOUNT_B, accounts, allDevices, refreshReport } from './fixtures'

const NOW = Date.now()

function ok<T>(data: T, status = 200) {
  return { status, data, headers: new Headers() }
}

function page<T>(items: T[]) {
  return { items, page: { nextCursor: null, limit: 200 } }
}

function refused(status: number, code: string, message: string) {
  return { status, data: { code, message }, headers: new Headers() }
}

async function mountPage() {
  const router = createRouter({ history: createMemoryHistory(), routes })
  await router.push('/hardware')
  await router.isReady()
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } })
  const wrapper = mount(HardwarePage, { global: { plugins: [[VueQueryPlugin, { queryClient }], router] }, attachTo: document.body })
  await flushPromises()
  await flushPromises()
  return wrapper
}

enableAutoUnmount(afterEach)

beforeEach(() => {
  document.body.innerHTML = ''
  for (const mock of [listHardwareDevices, refreshHardware, listProxmoxAccounts])
    mock.mockReset()
  listHardwareDevices.mockResolvedValue(ok(page(allDevices(NOW))))
  listProxmoxAccounts.mockResolvedValue(ok(page(accounts())))
})

describe('HardwarePage', () => {
  it('shows every device with its status, in the API order', async () => {
    const w = await mountPage()
    const cards = w.findAll('article[data-status]')
    expect(cards.map(c => c.attributes('data-status'))).toEqual([
      'available', 'reserved', 'reserved', 'externally_attached', 'missing',
      'unsupported', 'unsupported', 'unsupported', 'quarantined', 'unsupported',
    ])
    expect(w.get('[data-testid="device-token-limited"] [data-testid="reason-text"]').text())
      .toBe('the API token lacks Mapping.Use on this mapping')
  })

  it('summarises the counts per status and the stale devices', async () => {
    const w = await mountPage()
    expect(w.get('[data-testid="count-reserved"]').text()).toContain('2')
    expect(w.get('[data-testid="count-unsupported"]').text()).toContain('4')
    expect(w.get('[data-testid="count-quarantined"]').text()).toContain('1')
    expect(w.text()).toContain('10 devices')
    expect(w.text()).toContain('2 stale')
  })

  it('names the account by its Fleet name and says there is no event history', async () => {
    const w = await mountPage()
    expect(w.get('[data-testid="device-bench-dongle-a"]').text()).toContain('lab-cluster-a')
    expect(w.text()).toContain('reports no per-device event history')
  })

  it('offers a refresh only for pinned accounts', async () => {
    const w = await mountPage()
    expect(w.find(`[data-testid="refresh-${ACCOUNT_A}"]`).exists()).toBe(true)
    expect(w.find(`[data-testid="refresh-${ACCOUNT_B}"]`).exists()).toBe(true)
    expect(w.find('[data-testid="refresh-acct-example-c"]').exists()).toBe(false)
  })

  it('refreshes one account, then reloads the list and shows what the refresh reported', async () => {
    refreshHardware.mockResolvedValue(ok({ data: refreshReport(ACCOUNT_A, allDevices(NOW), NOW) }))
    const w = await mountPage()
    listHardwareDevices.mockClear()

    await w.get(`[data-testid="refresh-${ACCOUNT_A}"]`).trigger('click')
    await flushPromises()

    expect(refreshHardware).toHaveBeenCalledWith({ accountId: ACCOUNT_A })
    expect(listHardwareDevices).toHaveBeenCalledTimes(1)
    const report = w.get(`[data-testid="report-${ACCOUNT_A}"]`)
    expect(report.get('[data-testid="support-state"]').text().toLowerCase()).toBe('supported')
    expect(report.get('[data-testid="guest-scan"]').text()).toContain('11 of 12 configs read · 1 unreadable')
    expect(report.get('[data-testid="warning"]').text()).toContain('one guest config could not be read')
    // The external reference only a refresh reports now shows on its device.
    expect(w.get('[data-testid="device-hand-attached"] [data-testid="external-reference"]').text()).toContain('QEMU 9200')
  })

  it('hides the refresh action and says why when the API answers 403', async () => {
    refreshHardware.mockResolvedValue(refused(403, 'denied', 'hardware.refresh is not permitted'))
    const w = await mountPage()
    await w.get(`[data-testid="refresh-${ACCOUNT_A}"]`).trigger('click')
    await flushPromises()

    expect(w.find('[data-testid="refresh-actions"]').exists()).toBe(false)
    const message = w.get('[data-testid="refresh-error"]').text()
    expect(message).toContain('does not allow this viewer')
    expect(message).toContain('denied: hardware.refresh is not permitted')
    // The devices stay readable.
    expect(w.findAll('article[data-status]')).toHaveLength(10)
  })

  it('keeps the action after a refresh fails for another reason, and shows the API message', async () => {
    refreshHardware.mockResolvedValue(refused(409, 'proxmox_unconfirmed', 'the account is not confirmed'))
    const w = await mountPage()
    await w.get(`[data-testid="refresh-${ACCOUNT_B}"]`).trigger('click')
    await flushPromises()

    expect(w.find('[data-testid="refresh-actions"]').exists()).toBe(true)
    const message = w.get('[data-testid="refresh-error"]').text()
    expect(message).toContain('Refresh of lab-cluster-b failed')
    expect(message).toContain('proxmox_unconfirmed: the account is not confirmed')
  })

  it('offers no refresh when the API refuses the list, and shows its message', async () => {
    listHardwareDevices.mockResolvedValue(refused(403, 'denied', 'hardware.read is not permitted'))
    const w = await mountPage()
    expect(w.get('[data-testid="list-error"]').text()).toContain('denied: hardware.read is not permitted')
    expect(w.find('[data-testid="refresh-actions"]').exists()).toBe(false)
    expect(w.find('[data-testid="devices"]').exists()).toBe(false)
  })

  it('shows an unwired surface (503) as an error, not as an empty inventory', async () => {
    listHardwareDevices.mockResolvedValue(refused(503, 'machine_unavailable', 'the hardware surface is not wired'))
    const w = await mountPage()
    // A 5xx is retried (1s, then 2s) before the page gives up.
    await vi.waitFor(() => expect(w.find('[data-testid="list-error"]').exists()).toBe(true), { timeout: 6000 })
    expect(listHardwareDevices).toHaveBeenCalledTimes(3)
    expect(w.get('[data-testid="list-error"]').text()).toContain('the hardware surface is not wired')
    expect(w.find('[data-testid="empty"]').exists()).toBe(false)
    expect(w.find('[data-testid="refresh-actions"]').exists()).toBe(false)
  }, 10_000)

  it('explains an empty inventory and still offers the refresh that fills it', async () => {
    listHardwareDevices.mockResolvedValue(ok(page([])))
    const w = await mountPage()
    expect(w.get('[data-testid="empty"]').text()).toContain('Devices appear after a refresh')
    expect(w.find(`[data-testid="refresh-${ACCOUNT_A}"]`).exists()).toBe(true)
  })

  it('says so when an empty inventory has no pinned account to refresh', async () => {
    listHardwareDevices.mockResolvedValue(ok(page([])))
    listProxmoxAccounts.mockResolvedValue(ok(page([])))
    const w = await mountPage()
    expect(w.get('[data-testid="empty"]').text()).toContain('no pinned Proxmox account is available to refresh')
    expect(w.find('[data-testid="refresh-actions"]').exists()).toBe(false)
  })

  it('follows the list cursor until the last page', async () => {
    const [first, ...rest] = allDevices(NOW)
    listHardwareDevices
      .mockResolvedValueOnce(ok({ items: [first], page: { nextCursor: first!.id, limit: 1 } }))
      .mockResolvedValueOnce(ok(page(rest)))
    const w = await mountPage()
    expect(listHardwareDevices).toHaveBeenNthCalledWith(2, { limit: 200, cursor: first!.id })
    expect(w.findAll('article[data-status]')).toHaveLength(10)
  })

  it('shows the fleetctl equivalent of the list', async () => {
    const w = await mountPage()
    expect(w.findAll('[data-testid="fleetctl-command"]')[0]!.text()).toBe('fleetctl hardware list --output json')
  })
})
