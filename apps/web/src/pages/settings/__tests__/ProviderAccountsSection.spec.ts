import { enableAutoUnmount, flushPromises, mount } from '@vue/test-utils'
import { QueryClient, VueQueryPlugin } from '@tanstack/vue-query'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const listExternalAccounts = vi.fn()
const createExternalAccount = vi.fn()
const updateExternalAccount = vi.fn()
const deleteExternalAccount = vi.fn()
const probeExternalAccount = vi.fn()

vi.mock('@frogbyte-io/fleet-api-client', () => ({
  listExternalAccounts: (...a: unknown[]) => listExternalAccounts(...a),
  createExternalAccount: (...a: unknown[]) => createExternalAccount(...a),
  updateExternalAccount: (...a: unknown[]) => updateExternalAccount(...a),
  deleteExternalAccount: (...a: unknown[]) => deleteExternalAccount(...a),
  probeExternalAccount: (...a: unknown[]) => probeExternalAccount(...a),
}))

import ProviderAccountsSection from '../sections/ProviderAccountsSection.vue'
import { createCommand, probeView, sameOrigin } from '../accounts'

const TOKEN = 'typed-secret-token-0001'

function ok<T>(data: T, status = 200) {
  return { status, data, headers: new Headers() }
}

function account(extra: Record<string, unknown> = {}) {
  return {
    id: 'acc-1',
    kind: 'coolify',
    label: 'production',
    baseUrl: 'https://coolify.example.test',
    accountId: null,
    notes: '',
    lastProbe: null,
    createdAt: 1,
    updatedAt: 1,
    ...extra,
  }
}

function page(items: unknown[]) {
  return ok({ items, page: { limit: 200, nextCursor: null } })
}

async function mountSection() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } })
  const wrapper = mount(ProviderAccountsSection, { global: { plugins: [[VueQueryPlugin, { queryClient }]] } })
  await flushPromises()
  return wrapper
}

enableAutoUnmount(afterEach)

beforeEach(() => {
  for (const mock of [listExternalAccounts, createExternalAccount, updateExternalAccount, deleteExternalAccount, probeExternalAccount])
    mock.mockReset()
})

describe('provider account helpers', () => {
  it('reads each probe classification honestly', () => {
    expect(probeView(null).label).toBe('not probed')
    const base = { detail: 'd', granted: [], missing: [], unverified: [], checkedAt: 1 }
    expect(probeView({ ...base, status: 'ok' }).tone).toBe('ok')
    expect(probeView({ ...base, status: 'unreachable' }).tone).toBe('err')
    expect(probeView({ ...base, status: 'unauthorized' }).tone).toBe('err')
    expect(probeView({ ...base, status: 'insufficient_permission' })).toMatchObject({ label: 'insufficient permission', tone: 'warn' })
  })

  it('never puts a token into the fleetctl command', () => {
    const command = createCommand({ kind: 'coolify', label: 'prod', baseUrl: 'https://c.example.test', accountId: '', notes: 'a note' })
    expect(command).toContain('--kind coolify')
    expect(command).toContain('< token-file')
    expect(command).toContain(`--notes 'a note'`)
  })
})

describe('ProviderAccountsSection', () => {
  it('shows the empty state', async () => {
    listExternalAccounts.mockResolvedValue(page([]))
    const wrapper = await mountSection()
    expect(wrapper.find('[data-testid="accounts-empty"]').exists()).toBe(true)
  })

  it('lists accounts with their probe result and never renders a token', async () => {
    listExternalAccounts.mockResolvedValue(page([
      account({ lastProbe: { status: 'ok', detail: 'accepted', granted: ['read'], missing: [], unverified: ['write', 'deploy'], checkedAt: Date.now() } }),
    ]))
    const wrapper = await mountSection()
    expect(wrapper.find('[data-testid="probe-chip"]').text()).toContain('ok')
    expect(wrapper.find('[data-testid="probe-unverified"]').text()).toContain('write, deploy')
    expect(wrapper.html()).not.toContain(TOKEN)
  })

  it('creates an account, sends the token once, and clears the field', async () => {
    listExternalAccounts.mockResolvedValue(page([]))
    createExternalAccount.mockResolvedValue(ok({ data: account() }, 201))
    const wrapper = await mountSection()
    expect(wrapper.find('[data-testid="create-submit"]').attributes('disabled')).toBeDefined()
    await wrapper.find('[data-testid="create-label"]').setValue('production')
    await wrapper.find('[data-testid="create-base-url"]').setValue('https://coolify.example.test')
    await wrapper.find('[data-testid="create-token"]').setValue(TOKEN)
    await wrapper.find('[data-testid="create-form"]').trigger('submit')
    await flushPromises()
    expect(createExternalAccount).toHaveBeenCalledWith(expect.objectContaining({ kind: 'coolify', label: 'production', token: TOKEN }))
    expect((wrapper.find('[data-testid="create-token"]').element as HTMLInputElement).value).toBe('')
    expect(wrapper.html()).not.toContain(TOKEN)
  })

  it('reports a refused create', async () => {
    listExternalAccounts.mockResolvedValue(page([]))
    createExternalAccount.mockResolvedValue(ok({ code: 'conflict', message: 'the label is taken' }, 409))
    const wrapper = await mountSection()
    await wrapper.find('[data-testid="create-label"]').setValue('production')
    await wrapper.find('[data-testid="create-base-url"]').setValue('https://c.example.test')
    await wrapper.find('[data-testid="create-token"]').setValue(TOKEN)
    await wrapper.find('[data-testid="create-form"]').trigger('submit')
    await flushPromises()
    expect(wrapper.find('[data-testid="create-error"]').text()).toContain('the label is taken')
  })

  it('probes an account and refreshes the list', async () => {
    listExternalAccounts.mockResolvedValue(page([account()]))
    probeExternalAccount.mockResolvedValue(ok({ data: account() }))
    const wrapper = await mountSection()
    await wrapper.find('[data-testid="probe-button"]').trigger('click')
    await flushPromises()
    expect(probeExternalAccount).toHaveBeenCalledWith('acc-1')
    expect(listExternalAccounts).toHaveBeenCalledTimes(2)
  })

  it('asks for confirmation before removing', async () => {
    listExternalAccounts.mockResolvedValue(page([account()]))
    deleteExternalAccount.mockResolvedValue({ status: 204, data: undefined, headers: new Headers() })
    const wrapper = await mountSection()
    await wrapper.find('[data-testid="delete-button"]').trigger('click')
    expect(deleteExternalAccount).not.toHaveBeenCalled()
    await wrapper.find('[data-testid="delete-confirm"]').trigger('click')
    await flushPromises()
    expect(deleteExternalAccount).toHaveBeenCalledWith('acc-1')
  })

  it('edits without sending a token unless one is typed', async () => {
    listExternalAccounts.mockResolvedValue(page([account()]))
    updateExternalAccount.mockResolvedValue(ok({ data: account() }))
    const wrapper = await mountSection()
    await wrapper.find('[data-testid="edit-button"]').trigger('click')
    await wrapper.find('[data-testid="edit-form"]').trigger('submit')
    await flushPromises()
    expect(updateExternalAccount).toHaveBeenCalledWith('acc-1', expect.objectContaining({ token: undefined }))
  })
})

describe('origin changes', () => {
  it('compares scheme, host, and port only', () => {
    expect(sameOrigin('https://a.example.test/x', 'HTTPS://A.example.test')).toBe(true)
    expect(sameOrigin('https://a.example.test', 'http://a.example.test')).toBe(false)
    expect(sameOrigin('https://a.example.test', 'https://a.example.test:8443')).toBe(false)
  })

  it('requires a new token before saving a different origin', async () => {
    listExternalAccounts.mockResolvedValue(page([account()]))
    updateExternalAccount.mockResolvedValue(ok({ data: account() }))
    const wrapper = await mountSection()
    await wrapper.find('[data-testid="edit-button"]').trigger('click')
    await wrapper.find('[data-testid="edit-form"] input[class*="font-mono"]').setValue('https://elsewhere.example.test')
    expect(wrapper.find('[data-testid="origin-hint"]').exists()).toBe(true)
    expect(wrapper.find('[data-testid="edit-save"]').attributes('disabled')).toBeDefined()
    await wrapper.find('[data-testid="edit-token"]').setValue('fresh-token-value')
    expect(wrapper.find('[data-testid="edit-save"]').attributes('disabled')).toBeUndefined()
  })
})
