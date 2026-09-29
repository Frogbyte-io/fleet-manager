import { enableAutoUnmount, flushPromises, mount } from '@vue/test-utils'
import { QueryClient, VueQueryPlugin } from '@tanstack/vue-query'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const getDesiredSource = vi.fn()
const getDesiredRevision = vi.fn()
const listDesiredHistory = vi.fn()
const configureDesiredSource = vi.fn()
const fetchDesiredRevision = vi.fn()
const activateDesiredRevision = vi.fn()
const rollbackDesiredRevision = vi.fn()
const getOperation = vi.fn()

vi.mock('@frogbyte-io/fleet-api-client', () => ({
  getDesiredSource: (...a: unknown[]) => getDesiredSource(...a),
  getDesiredRevision: (...a: unknown[]) => getDesiredRevision(...a),
  listDesiredHistory: (...a: unknown[]) => listDesiredHistory(...a),
  configureDesiredSource: (...a: unknown[]) => configureDesiredSource(...a),
  fetchDesiredRevision: (...a: unknown[]) => fetchDesiredRevision(...a),
  activateDesiredRevision: (...a: unknown[]) => activateDesiredRevision(...a),
  rollbackDesiredRevision: (...a: unknown[]) => rollbackDesiredRevision(...a),
  getOperation: (...a: unknown[]) => getOperation(...a),
  cancelOperation: vi.fn(),
}))

import DesiredStateSection from '../sections/DesiredStateSection.vue'

function ok<T>(data: T, status = 200) {
  return { status, data, headers: new Headers() }
}

const SHA_A = 'a'.repeat(40)
const SHA_B = 'b'.repeat(40)
const SHA_C = 'c'.repeat(40)
const short = (sha: string) => sha.slice(0, 12)

function active(sha: string, extra: Record<string, unknown> = {}) {
  return {
    commitSha: sha,
    contentDigest: `digest-${sha.slice(0, 4)}`,
    activatedAt: Date.now() - 60_000,
    resourceCounts: { skill: 2, 'catalog-skill': 1 },
    resourcesAvailable: true,
    ...extra,
  }
}

async function mountSection() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } })
  const wrapper = mount(DesiredStateSection, { global: { plugins: [[VueQueryPlugin, { queryClient }]] } })
  await flushPromises()
  return wrapper
}

let fetchResult: Record<string, unknown>

enableAutoUnmount(afterEach)

beforeEach(() => {
  for (const mock of [getDesiredSource, getDesiredRevision, listDesiredHistory, configureDesiredSource, fetchDesiredRevision, activateDesiredRevision, rollbackDesiredRevision, getOperation])
    mock.mockReset()
  getDesiredSource.mockResolvedValue(ok({ data: { remote: 'ssh://git@host/fleet.git' } }))
  getDesiredRevision.mockResolvedValue(ok({ data: { active: null } }))
  listDesiredHistory.mockResolvedValue(ok({ items: [] }))
  fetchResult = { commitSha: SHA_B, contentDigest: 'digest-bbbb', valid: true, diagnostics: [], resourceCount: 3 }
  fetchDesiredRevision.mockResolvedValue(ok({ data: { id: 'op-fetch', kind: 'source.fetch', state: 'queued', createdAt: 0 } }, 202))
  activateDesiredRevision.mockResolvedValue(ok({ data: { id: 'op-act', kind: 'source.activate', state: 'queued', createdAt: 0 } }, 202))
  rollbackDesiredRevision.mockResolvedValue(ok({ data: { id: 'op-rb', kind: 'source.rollback', state: 'queued', createdAt: 0 } }, 202))
  getOperation.mockImplementation(async (id: string) => ok({ data: id === 'op-fetch'
    ? { id, kind: 'source.fetch', state: 'succeeded', createdAt: 0, resultJson: JSON.stringify(fetchResult) }
    : { id, kind: 'source.activate', state: 'succeeded', createdAt: 0 } }))
})

describe('remote', () => {
  it('says when no remote is configured', async () => {
    getDesiredSource.mockResolvedValue(ok({ data: { remote: null } }))
    const wrapper = await mountSection()
    expect(wrapper.get('[data-testid="source-none"]').text()).toContain('No remote is configured')
    expect(wrapper.get('[data-testid="fetch-start"]').attributes('disabled')).toBeDefined()
  })

  it('saves a remote and reloads the source', async () => {
    getDesiredSource.mockResolvedValueOnce(ok({ data: { remote: null } }))
    configureDesiredSource.mockResolvedValue(ok({ data: { remote: 'ssh://git@host/new.git' } }))
    const wrapper = await mountSection()
    getDesiredSource.mockResolvedValue(ok({ data: { remote: 'ssh://git@host/new.git' } }))
    await wrapper.get('[data-testid="remote-input"]').setValue('  ssh://git@host/new.git ')
    await wrapper.get('[data-testid="remote-save"]').trigger('submit')
    await flushPromises()
    expect(configureDesiredSource).toHaveBeenCalledWith({ remote: 'ssh://git@host/new.git' })
    expect(wrapper.get('[data-testid="source-remote"]').text()).toBe('ssh://git@host/new.git')
    expect(wrapper.find('[data-testid="remote-error"]').exists()).toBe(false)
  })

  it('shows why a remote was refused', async () => {
    configureDesiredSource.mockResolvedValue(ok({ code: 'invalid_request', message: 'remote must not embed credentials' }, 400))
    const wrapper = await mountSection()
    await wrapper.get('[data-testid="remote-input"]').setValue('https://user:pw@host/x.git')
    await wrapper.get('[data-testid="remote-save"]').trigger('submit')
    await flushPromises()
    expect(wrapper.get('[data-testid="remote-error"]').text()).toContain('remote must not embed credentials')
  })
})

describe('active revision', () => {
  it('says when no revision is active', async () => {
    const wrapper = await mountSection()
    expect(wrapper.get('[data-testid="revision-none"]').text()).toContain('No revision is active')
  })

  it('shows the active revision with its resource counts', async () => {
    getDesiredRevision.mockResolvedValue(ok({ data: { active: active(SHA_A) } }))
    const wrapper = await mountSection()
    expect(wrapper.get('[data-testid="revision-sha"]').text()).toBe(short(SHA_A))
    const counts = wrapper.get('[data-testid="revision-counts"]').text()
    expect(counts).toContain('skill 2')
    expect(counts).toContain('catalog-skill 1')
  })

  it('warns when the revision holds no resources', async () => {
    getDesiredRevision.mockResolvedValue(ok({ data: { active: active(SHA_A, { resourcesAvailable: false, resourceCounts: {} }) } }))
    const wrapper = await mountSection()
    expect(wrapper.get('[data-testid="revision-unheld"]').text()).toContain('nothing can be planned')
    expect(wrapper.find('[data-testid="revision-counts"]').exists()).toBe(false)
  })
})

describe('fetch and activate', () => {
  it('keeps fetch disabled for anything but a full lowercase sha', async () => {
    const wrapper = await mountSection()
    const button = () => wrapper.get('[data-testid="fetch-start"]')
    expect(button().attributes('disabled')).toBeDefined()
    await wrapper.get('[data-testid="fetch-sha"]').setValue('main')
    expect(button().attributes('disabled')).toBeDefined()
    expect(wrapper.find('[data-testid="fetch-sha-hint"]').exists()).toBe(true)
    await wrapper.get('[data-testid="fetch-sha"]').setValue('a'.repeat(39))
    expect(button().attributes('disabled')).toBeDefined()
    await wrapper.get('[data-testid="fetch-sha"]').setValue(SHA_B)
    expect(button().attributes('disabled')).toBeUndefined()
    expect(wrapper.find('[data-testid="fetch-sha-hint"]').exists()).toBe(false)
  })

  it('activates a valid candidate only after explicit confirmation', async () => {
    getDesiredRevision.mockResolvedValue(ok({ data: { active: active(SHA_A) } }))
    const wrapper = await mountSection()
    await wrapper.get('[data-testid="fetch-sha"]').setValue(SHA_B)
    await wrapper.get('[data-testid="fetch-start"]').trigger('submit')
    await flushPromises()
    await flushPromises()
    expect(fetchDesiredRevision).toHaveBeenCalledWith({ commitSha: SHA_B })
    expect(wrapper.get('[data-testid="candidate"]').text()).toContain('validated with 3 resources')

    await wrapper.get('[data-testid="candidate-activate"]').trigger('click')
    expect(activateDesiredRevision).not.toHaveBeenCalled()
    expect(wrapper.get('[data-testid="confirm"]').text()).toContain(short(SHA_B))

    await wrapper.get('[data-testid="confirm-yes"]').trigger('click')
    await flushPromises()
    expect(activateDesiredRevision).toHaveBeenCalledWith({ commitSha: SHA_B, contentDigest: 'digest-bbbb' })
  })

  it('cancelling the confirmation activates nothing', async () => {
    const wrapper = await mountSection()
    await wrapper.get('[data-testid="fetch-sha"]').setValue(SHA_B)
    await wrapper.get('[data-testid="fetch-start"]').trigger('submit')
    await flushPromises()
    await flushPromises()
    await wrapper.get('[data-testid="candidate-activate"]').trigger('click')
    await wrapper.get('[data-testid="confirm-no"]').trigger('click')
    expect(wrapper.find('[data-testid="confirm"]').exists()).toBe(false)
    expect(activateDesiredRevision).not.toHaveBeenCalled()
  })

  it('shows diagnostics for an invalid candidate and offers no activation', async () => {
    fetchResult = { commitSha: SHA_B, contentDigest: 'digest-bbbb', valid: false, diagnostics: ['skills/x.yaml: unknown field'], resourceCount: 0 }
    const wrapper = await mountSection()
    await wrapper.get('[data-testid="fetch-sha"]').setValue(SHA_B)
    await wrapper.get('[data-testid="fetch-start"]').trigger('submit')
    await flushPromises()
    await flushPromises()
    expect(wrapper.get('[data-testid="candidate"]').text()).toContain('did not validate')
    expect(wrapper.get('[data-testid="candidate-diagnostics"]').text()).toContain('unknown field')
    expect(wrapper.find('[data-testid="candidate-activate"]').exists()).toBe(false)
  })

  it('shows a refused fetch', async () => {
    fetchDesiredRevision.mockResolvedValue(ok({ code: 'conflict', message: 'another operation is running' }, 409))
    const wrapper = await mountSection()
    await wrapper.get('[data-testid="fetch-sha"]').setValue(SHA_B)
    await wrapper.get('[data-testid="fetch-start"]').trigger('submit')
    await flushPromises()
    expect(wrapper.get('[data-testid="operation-error"]').text()).toContain('another operation is running')
  })
})

describe('history', () => {
  const items = [
    { commitSha: SHA_C, contentDigest: 'digest-cccc', active: false },
    { commitSha: SHA_B, contentDigest: 'digest-bbbb', active: true },
    { commitSha: SHA_A, contentDigest: 'digest-aaaa', active: false },
  ]

  it('offers activate for newer entries and roll back for older ones', async () => {
    listDesiredHistory.mockResolvedValue(ok({ items }))
    const wrapper = await mountSection()
    expect(wrapper.get(`[data-testid="history-${short(SHA_B)}"]`).text()).toContain('active')
    expect(wrapper.find(`[data-testid="history-activate-${short(SHA_C)}"]`).exists()).toBe(true)
    expect(wrapper.find(`[data-testid="history-rollback-${short(SHA_A)}"]`).exists()).toBe(true)
  })

  it('rolls back only after confirmation', async () => {
    listDesiredHistory.mockResolvedValue(ok({ items }))
    const wrapper = await mountSection()
    await wrapper.get(`[data-testid="history-rollback-${short(SHA_A)}"]`).trigger('click')
    expect(rollbackDesiredRevision).not.toHaveBeenCalled()
    expect(wrapper.get('[data-testid="confirm"]').text()).toContain('Roll back to')
    await wrapper.get('[data-testid="confirm-yes"]').trigger('click')
    await flushPromises()
    expect(rollbackDesiredRevision).toHaveBeenCalledWith({ commitSha: SHA_A, contentDigest: 'digest-aaaa' })
    expect(activateDesiredRevision).not.toHaveBeenCalled()
  })

  it('says when there is no history', async () => {
    const wrapper = await mountSection()
    expect(wrapper.get('[data-testid="history-empty"]').exists()).toBe(true)
  })
})

describe('denied reads', () => {
  it('states each failed read and never an empty state', async () => {
    const denied = ok({ code: 'denied', message: 'denied: no' }, 403)
    getDesiredSource.mockResolvedValue(denied)
    getDesiredRevision.mockResolvedValue(denied)
    listDesiredHistory.mockResolvedValue(denied)
    const wrapper = await mountSection()
    expect(wrapper.get('[data-testid="source-error"]').text()).toContain('denied')
    expect(wrapper.get('[data-testid="revision-error"]').text()).toContain('denied')
    expect(wrapper.get('[data-testid="history-error"]').text()).toContain('denied')
    expect(wrapper.find('[data-testid="source-none"]').exists()).toBe(false)
    expect(wrapper.find('[data-testid="revision-none"]').exists()).toBe(false)
    expect(wrapper.find('[data-testid="history-empty"]').exists()).toBe(false)
  })
})
