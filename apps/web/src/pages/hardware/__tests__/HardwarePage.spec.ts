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
import { HARDWARE_KEY } from '../useHardware'
import { routes } from '@/router'
import {
  LAB_ACCOUNT,
  LAB_ACCOUNT_NAME,
  LIST_DENIED,
  REFRESH_DENIED,
  SPARE_ACCOUNT,
  SPARE_ACCOUNT_NAME,
  UNWIRED,
  accounts,
  oldRefresh,
  realDevice,
  realDevices,
  realRefresh,
} from './fixtures'

function ok<T>(data: T, status = 200) {
  return { status, data, headers: new Headers() }
}

function page<T>(items: T[]) {
  return { items, page: { nextCursor: null, limit: 200 } }
}

function refused(status: number, code: string, message: string) {
  return { status, data: { code, message }, headers: new Headers() }
}

let queryClient: QueryClient

async function mountPage() {
  const router = createRouter({ history: createMemoryHistory(), routes })
  await router.push('/hardware')
  await router.isReady()
  queryClient = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } })
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
  listHardwareDevices.mockResolvedValue(ok(page(realDevices())))
  listProxmoxAccounts.mockResolvedValue(ok(page(accounts())))
})

describe('HardwarePage', () => {
  it('shows every captured device with its status, in the API order', async () => {
    const w = await mountPage()
    expect(w.findAll('article[data-status]').map(c => c.attributes('data-status'))).toEqual([
      'reserved', 'externally_attached', 'missing', 'unsupported', 'unsupported', 'unsupported', 'quarantined', 'available',
    ])
    expect(w.get('[data-testid="device-fm-f"] [data-testid="reason-text"]').text())
      .toBe(realDevice('fm-f').reasonText)
  })

  it('summarises the counts per status and the stale devices', async () => {
    const w = await mountPage()
    expect(w.get('[data-testid="count-unsupported"]').text()).toContain('3')
    expect(w.get('[data-testid="count-quarantined"]').text()).toContain('1')
    expect(w.text()).toContain('8 devices')
    expect(w.text()).toContain('1 stale')
  })

  it('names the account by its Fleet name and says there is no event history', async () => {
    const w = await mountPage()
    expect(w.get('[data-testid="device-fm-a"]').text()).toContain(LAB_ACCOUNT_NAME)
    expect(w.text()).toContain('reports no per-device event history')
  })

  it('offers a refresh only for pinned accounts', async () => {
    const w = await mountPage()
    expect(w.find(`[data-testid="refresh-${LAB_ACCOUNT}"]`).exists()).toBe(true)
    expect(w.find(`[data-testid="refresh-${SPARE_ACCOUNT}"]`).exists()).toBe(true)
    expect(w.find('[data-testid="refresh-acct-example-unpinned"]').exists()).toBe(false)
  })

  it('refreshes one account, reloads the list and shows what the refresh reported and when', async () => {
    refreshHardware.mockResolvedValue(ok({ data: realRefresh() }))
    const w = await mountPage()
    listHardwareDevices.mockClear()

    await w.get(`[data-testid="refresh-${LAB_ACCOUNT}"]`).trigger('click')
    await flushPromises()

    expect(refreshHardware).toHaveBeenCalledWith({ accountId: LAB_ACCOUNT })
    expect(listHardwareDevices).toHaveBeenCalledTimes(1)
    const report = w.get(`[data-testid="report-${LAB_ACCOUNT}"]`)
    expect(report.get('[data-testid="support-state"]').text().toLowerCase()).toBe('supported')
    expect(report.get('[data-testid="guest-scan"]').text()).toContain('3 of 3 configs read')
    // The guest that holds the external device is only reported by a refresh.
    const external = w.get('[data-testid="device-fm-b"] [data-testid="external-reference"]').text()
    expect(external).toContain('QEMU 200')
    expect(w.get('[data-testid="device-fm-b"] [data-testid="observation"]').text()).toContain('Found by the refresh')
    expect(w.get('[data-testid="refresh-status"]').text()).toBe(`Refreshed ${LAB_ACCOUNT_NAME}`)
  })

  it('shows a refresh of an account whose Proxmox predates USB mappings as the API reported it', async () => {
    refreshHardware.mockResolvedValue(ok({ data: oldRefresh() }))
    const w = await mountPage()
    await w.get(`[data-testid="refresh-${SPARE_ACCOUNT}"]`).trigger('click')
    await flushPromises()
    const report = w.get(`[data-testid="report-${oldRefresh().accountId}"]`)
    expect(report.get('[data-testid="support-state"]').text().toLowerCase()).toBe('unsupported')
    expect(report.get('[data-testid="support-detail"]').text()).toContain('this Proxmox VE predates USB resource mappings')
  })

  it('drops what a refresh found once the list reports a different status for the device', async () => {
    refreshHardware.mockResolvedValue(ok({ data: realRefresh() }))
    const w = await mountPage()
    await w.get(`[data-testid="refresh-${LAB_ACCOUNT}"]`).trigger('click')
    await flushPromises()
    expect(w.find('[data-testid="device-fm-b"] [data-testid="external-reference"]').exists()).toBe(true)

    // A later list says the guest let go of it.
    listHardwareDevices.mockResolvedValue(ok(page(realDevices().map(d => (d.mappingId === 'fm-b' ? { ...d, status: 'available' } : d)))))
    await queryClient.invalidateQueries({ queryKey: HARDWARE_KEY })
    await flushPromises()

    const card = w.get('[data-testid="device-fm-b"]')
    expect(card.attributes('data-status')).toBe('available')
    expect(card.find('[data-testid="external-reference"]').exists()).toBe(false)
    expect(card.get('[data-testid="observation-superseded"]').text()).toContain('The list has changed since that refresh')
  })

  it('keeps the refresh control focusable and marks it busy while a refresh runs', async () => {
    let finish: (value: unknown) => void = () => {}
    refreshHardware.mockReturnValue(new Promise((resolve) => { finish = resolve }))
    const w = await mountPage()
    const button = w.get(`[data-testid="refresh-${LAB_ACCOUNT}"]`)
    const other = w.get(`[data-testid="refresh-${SPARE_ACCOUNT}"]`)
    ;(button.element as HTMLButtonElement).focus()

    await button.trigger('click')
    await flushPromises()

    expect(button.attributes('aria-busy')).toBe('true')
    expect(button.attributes('disabled')).toBeUndefined()
    expect(button.attributes('aria-disabled')).toBe('true')
    expect(document.activeElement).toBe(button.element)
    expect(w.get('[data-testid="refresh-status"]').text()).toBe(`Refreshing ${LAB_ACCOUNT_NAME}`)

    // A second click while one refresh runs does nothing.
    await other.trigger('click')
    expect(refreshHardware).toHaveBeenCalledTimes(1)

    finish(ok({ data: realRefresh() }))
    await flushPromises()
    expect(button.attributes('aria-busy')).toBe('false')
    expect(document.activeElement).toBe(button.element)
  })

  it('hides the refresh action for the account the API refused, keeps it for the others, and names the account', async () => {
    refreshHardware.mockImplementation(async ({ accountId }: { accountId: string }) =>
      accountId === SPARE_ACCOUNT ? REFRESH_DENIED : ok({ data: realRefresh() }))
    const w = await mountPage()
    await w.get(`[data-testid="refresh-${SPARE_ACCOUNT}"]`).trigger('click')
    await flushPromises()

    expect(w.find(`[data-testid="refresh-${SPARE_ACCOUNT}"]`).exists()).toBe(false)
    expect(w.find(`[data-testid="refresh-${LAB_ACCOUNT}"]`).exists()).toBe(true)
    const message = w.get(`[data-testid="refresh-denied-${SPARE_ACCOUNT}"]`).text()
    expect(message).toContain(`The API refused hardware.refresh for ${SPARE_ACCOUNT_NAME}`)
    expect(message).not.toContain('this viewer')
    // The real 403 envelope's message is shown verbatim.
    expect(message).toContain(REFRESH_DENIED.data.message)
    // The fleetctl equivalent now names the account that can still be refreshed.
    const commands = w.findAll('[data-testid="fleetctl-command"]').map(c => c.text())
    expect(commands).toContain(`fleetctl hardware refresh --account ${LAB_ACCOUNT} --output json`)
    expect(commands.join(' ')).not.toContain(SPARE_ACCOUNT)
    expect(w.findAll('article[data-status]')).toHaveLength(8)

    // The other account still refreshes.
    await w.get(`[data-testid="refresh-${LAB_ACCOUNT}"]`).trigger('click')
    await flushPromises()
    expect(w.find(`[data-testid="report-${LAB_ACCOUNT}"]`).exists()).toBe(true)
    expect(w.find(`[data-testid="refresh-denied-${SPARE_ACCOUNT}"]`).exists()).toBe(true)
  })

  it('hides the whole action only when every pinned account was refused', async () => {
    refreshHardware.mockResolvedValue(REFRESH_DENIED)
    const w = await mountPage()
    await w.get(`[data-testid="refresh-${SPARE_ACCOUNT}"]`).trigger('click')
    await flushPromises()
    await w.get(`[data-testid="refresh-${LAB_ACCOUNT}"]`).trigger('click')
    await flushPromises()
    expect(w.find('[data-testid="refresh-actions"]').exists()).toBe(false)
    expect(w.findAll('[data-testid="fleetctl-command"]')).toHaveLength(1)
  })

  it('keeps the action after a refresh fails for another reason, and shows the API message', async () => {
    refreshHardware.mockResolvedValue(refused(409, 'proxmox_unconfirmed', 'the account is not confirmed'))
    const w = await mountPage()
    await w.get(`[data-testid="refresh-${SPARE_ACCOUNT}"]`).trigger('click')
    await flushPromises()

    expect(w.find(`[data-testid="refresh-${SPARE_ACCOUNT}"]`).exists()).toBe(true)
    const message = w.get('[data-testid="refresh-error"]').text()
    expect(message).toContain(`Refresh of ${SPARE_ACCOUNT_NAME} failed`)
    expect(message).toContain('proxmox_unconfirmed: the account is not confirmed')
  })

  it('offers no refresh when the API refuses the list, and shows its real message', async () => {
    listHardwareDevices.mockResolvedValue(LIST_DENIED)
    const w = await mountPage()
    expect(w.get('[data-testid="list-error"]').text()).toContain(LIST_DENIED.data.message)
    expect(w.find('[data-testid="refresh-actions"]').exists()).toBe(false)
    expect(w.find('[data-testid="devices"]').exists()).toBe(false)
  })

  it('shows an unwired surface (503) as an error, not as an empty inventory', async () => {
    listHardwareDevices.mockResolvedValue(UNWIRED)
    const w = await mountPage()
    // A 5xx is retried (1s, then 2s) before the page gives up.
    await vi.waitFor(() => expect(w.find('[data-testid="list-error"]').exists()).toBe(true), { timeout: 6000 })
    expect(listHardwareDevices).toHaveBeenCalledTimes(3)
    expect(w.get('[data-testid="list-error"]').text()).toContain(UNWIRED.data.message)
    expect(w.find('[data-testid="empty"]').exists()).toBe(false)
    expect(w.find('[data-testid="refresh-actions"]').exists()).toBe(false)
  }, 10_000)

  it('explains an empty inventory and still offers the refresh that fills it', async () => {
    listHardwareDevices.mockResolvedValue(ok(page([])))
    const w = await mountPage()
    expect(w.get('[data-testid="empty"]').text()).toContain('Devices appear after a refresh')
    expect(w.get('[data-testid="empty"]').text()).not.toContain('No pinned Proxmox account')
    expect(w.find(`[data-testid="refresh-${LAB_ACCOUNT}"]`).exists()).toBe(true)
  })

  it('says so when an empty inventory has no pinned account to refresh', async () => {
    listHardwareDevices.mockResolvedValue(ok(page([])))
    listProxmoxAccounts.mockResolvedValue(ok(page([])))
    const w = await mountPage()
    expect(w.get('[data-testid="empty"]').text()).toContain('No pinned Proxmox account is available to refresh')
    expect(w.find('[data-testid="refresh-actions"]').exists()).toBe(false)
  })

  it('shows the accounts error instead of claiming there is no pinned account', async () => {
    listHardwareDevices.mockResolvedValue(ok(page([])))
    listProxmoxAccounts.mockResolvedValue(refused(403, 'denied', 'proxmox.read is not permitted'))
    const w = await mountPage()
    // The shared accounts reader throws a plain error, which is retried (1s, then 2s).
    await vi.waitFor(() => expect(w.find('[data-testid="accounts-error"]').exists()).toBe(true), { timeout: 6000 })
    expect(w.get('[data-testid="accounts-error"]').text()).toContain('Request failed (403)')
    expect(w.get('[data-testid="empty"]').text()).not.toContain('No pinned Proxmox account')
    expect(w.find('[data-testid="refresh-actions"]').exists()).toBe(false)
  }, 10_000)

  it('follows the list cursor until the last page', async () => {
    const [first, ...rest] = realDevices()
    listHardwareDevices
      .mockResolvedValueOnce(ok({ items: [first], page: { nextCursor: first!.id, limit: 1 } }))
      .mockResolvedValueOnce(ok(page(rest)))
    const w = await mountPage()
    expect(listHardwareDevices).toHaveBeenNthCalledWith(2, { limit: 200, cursor: first!.id })
    expect(w.findAll('article[data-status]')).toHaveLength(8)
  })

  it('shows the fleetctl equivalent of the list', async () => {
    const w = await mountPage()
    expect(w.findAll('[data-testid="fleetctl-command"]')[0]!.text()).toBe('fleetctl hardware list --output json')
  })
})
