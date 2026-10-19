import { enableAutoUnmount, flushPromises, mount } from '@vue/test-utils'
import { QueryClient, VueQueryPlugin } from '@tanstack/vue-query'
import { createMemoryHistory, createRouter } from 'vue-router'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import type { ImageBuildDto, RecipeVersionDto } from '@frogbyte-io/fleet-api-client'

const listImageBuilds = vi.fn()
const getImageBuild = vi.fn()

vi.mock('@frogbyte-io/fleet-api-client', () => ({
  listImageBuilds: (...args: unknown[]) => listImageBuilds(...args),
  getImageBuild: (...args: unknown[]) => getImageBuild(...args),
}))

import BuildHistory from '../components/BuildHistory.vue'

function ok<T>(data: T, status = 200) {
  return { status, data, headers: new Headers() }
}
function page<T>(items: T[], nextCursor: string | null = null) {
  return { items, page: { nextCursor, limit: 50 } }
}

const DIGEST = `sha256:${'a1'.repeat(32)}`
const ASSET = `sha256:${'b2'.repeat(32)}`
const T0 = Date.UTC(2026, 9, 7, 12, 0)

function version(overrides: Partial<RecipeVersionDto> = {}): RecipeVersionDto {
  return {
    id: 'r1@aaaa', recipeId: 'r1', name: 'ubuntu-24-dev', description: '', contentDigest: DIGEST, content: '{}', source: 'clone',
    node: 'pve1', storagePool: 'local-lvm', publishedAt: T0 - 3600e3, promotedAt: null, promotedBy: null, allowInsecureTls: false, structured: null, ...overrides,
  }
}

function build(id: string, overrides: Partial<ImageBuildDto> = {}): ImageBuildDto {
  return {
    id, operationId: `op-${id}`, recipeId: 'r1', versionId: 'r1@aaaa', contentDigest: DIGEST, assetDigests: [ASSET], packerVersion: '1.11.2',
    proxmoxPluginVersion: '1.2.2', accountId: 'acct-example', node: 'pve1', storagePool: 'local-lvm', startedAt: T0, endedAt: T0 + 754_000,
    outcome: 'succeeded', reason: 'succeeded', template: { name: 'ubuntu-24-dev', node: 'pve1', vmid: 9001 }, ...overrides,
  }
}

const SUCCEEDED = build('b-ok', { startedAt: T0 })
const FAILED = build('b-fail', { startedAt: T0 - 600e3, endedAt: T0 - 590e3, outcome: 'failed', reason: 'validate_failed', template: null, packerVersion: null, proxmoxPluginVersion: null })
const RUNNING = build('b-run', { startedAt: T0 + 900e3, endedAt: null, outcome: 'running', reason: null, template: null })

async function mountHistory(v: RecipeVersionDto = version(), path = '/images', live = false) {
  const router = createRouter({ history: createMemoryHistory(), routes: [{ path: '/images', component: { template: '<div />' } }, { path: '/operations', component: { template: '<div />' } }] })
  await router.push(path)
  await router.isReady()
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } })
  const wrapper = mount(BuildHistory, { props: { version: v, live }, global: { plugins: [[VueQueryPlugin, { queryClient }], router] } })
  await flushPromises()
  await flushPromises()
  return { wrapper, router }
}

enableAutoUnmount(afterEach)

beforeEach(() => {
  listImageBuilds.mockReset()
  getImageBuild.mockReset()
})

describe('build history', () => {
  it('shows a loading state while the records load', async () => {
    listImageBuilds.mockReturnValue(new Promise(() => {}))
    const { wrapper } = await mountHistory()
    expect(wrapper.find('[data-testid="build-history-loading"]').exists()).toBe(true)
    expect(wrapper.find('[data-testid="build-history-empty"]').exists()).toBe(false)
  })

  it('shows an error with the API message and retries', async () => {
    listImageBuilds.mockResolvedValueOnce({ status: 403, data: { code: 'forbidden', message: 'not allowed' }, headers: new Headers() })
    const { wrapper } = await mountHistory()
    expect(wrapper.get('[data-testid="build-history-error"]').text()).toContain('forbidden: not allowed')
    listImageBuilds.mockResolvedValue(ok(page([SUCCEEDED])))
    await wrapper.get('[data-testid="build-history-error"] button').trigger('click')
    await flushPromises()
    expect(wrapper.find('[data-testid="build-history-error"]').exists()).toBe(false)
    expect(wrapper.find('[data-testid="build-row-b-ok"]').exists()).toBe(true)
  })

  it('says when a version has no build records', async () => {
    listImageBuilds.mockResolvedValue(ok(page([])))
    const { wrapper } = await mountHistory()
    expect(listImageBuilds).toHaveBeenCalledWith({ versionId: 'r1@aaaa', limit: 50 })
    expect(wrapper.get('[data-testid="build-history-empty"]').text()).toContain('No build records')
    expect(wrapper.get('[data-testid="fleetctl-command"]').text()).toBe('fleetctl --output json images builds --version r1@aaaa')
  })

  it('lists builds newest first with outcome, reason, duration, template, and operation link', async () => {
    listImageBuilds.mockResolvedValue(ok(page([SUCCEEDED, FAILED])))
    const { wrapper } = await mountHistory()
    const rows = wrapper.findAll('li')
    expect(rows.map(r => r.attributes('data-testid'))).toEqual(['build-row-b-ok', 'build-row-b-fail'])
    const ok_ = wrapper.get('[data-testid="build-row-b-ok"]')
    expect(ok_.text()).toContain('succeeded')
    expect(ok_.get('[data-testid="build-duration"]').text()).toBe('12M 34S')
    expect(ok_.get('[data-testid="build-template"]').text()).toContain('ubuntu-24-dev · vmid 9001')
    expect(ok_.text()).toContain('latest success')
    expect(ok_.get('[data-testid="build-operation-b-ok"]').attributes('href')).toBe('/operations?op=op-b-ok')
    const failed = wrapper.get('[data-testid="build-row-b-fail"]')
    expect(failed.get('[data-testid="build-reason"]').text()).toBe('validate_failed')
    expect(failed.get('[data-testid="build-duration"]').text()).toBe('10S')
    expect(failed.get('[data-testid="build-template"]').text()).toContain('no template')
  })

  it('shows a running build as in progress', async () => {
    listImageBuilds.mockResolvedValue(ok(page([RUNNING, SUCCEEDED])))
    const { wrapper } = await mountHistory()
    const row = wrapper.get('[data-testid="build-row-b-run"]')
    expect(row.text()).toContain('running')
    expect(row.get('[data-testid="build-duration"]').text()).toBe('running')
    expect(row.find('[data-testid="build-reason"]').exists()).toBe(false)
  })

  it('opens a build record with truncated, copyable digests, tool versions, and the target', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined)
    Object.assign(navigator, { clipboard: { writeText } })
    listImageBuilds.mockResolvedValue(ok(page([SUCCEEDED, FAILED])))
    const { wrapper, router } = await mountHistory()
    await wrapper.get('[data-testid="build-row-b-ok"] button').trigger('click')
    await flushPromises()
    expect(router.currentRoute.value.query.build).toBe('b-ok')
    const record = wrapper.get('[data-testid="build-record"]')
    const content = record.get('[data-testid="build-record-content-digest"]')
    expect(content.text()).toContain('sha256:a1a1a1a1a1a1…')
    expect(content.text()).not.toContain('a1'.repeat(32))
    expect(content.get('[title]').attributes('title')).toBe(DIGEST)
    await content.get('[data-testid="copy-value"]').trigger('click')
    expect(writeText).toHaveBeenCalledWith(DIGEST)
    expect(record.get('[data-testid="build-record-asset-digests"]').text()).toContain('sha256:b2b2b2b2b2b2…')
    expect(record.get('[data-testid="build-record-packer"]').text()).toBe('1.11.2')
    expect(record.get('[data-testid="build-record-plugin"]').text()).toBe('1.2.2')
    expect(record.get('[data-testid="build-record-account"]').text()).toBe('acct-example')
    expect(record.text()).toContain('pve1 · local-lvm')
    expect(record.get('[data-testid="build-record-template"]').text()).toContain('ubuntu-24-dev · vmid 9001 on pve1')
    expect(record.get('[data-testid="build-record-operation"]').attributes('href')).toBe('/operations?op=op-b-ok')
    expect(record.get('[data-testid="fleetctl-command"]').text()).toBe('fleetctl --output json images build-show b-ok')
  })

  it('says what a failed record lacks instead of inventing it', async () => {
    listImageBuilds.mockResolvedValue(ok(page([FAILED])))
    const { wrapper } = await mountHistory(version(), '/images?build=b-fail')
    const record = wrapper.get('[data-testid="build-record"]')
    expect(record.get('[data-testid="build-record-reason"]').text()).toBe('validate_failed')
    expect(record.get('[data-testid="build-record-packer"]').text()).toBe('not probed')
    expect(record.get('[data-testid="build-record-template"]').text()).toBe('none recorded')
  })

  it('shows which build record a promoted version stood on', async () => {
    listImageBuilds.mockResolvedValue(ok(page([RUNNING, SUCCEEDED, FAILED])))
    const { wrapper } = await mountHistory(version({ promotedAt: T0 + 800e3, promotedBy: 'operator' }))
    expect(wrapper.get('[data-testid="promotion-record"]').text()).toContain('on the evidence of build b-ok')
    expect(wrapper.get('[data-testid="build-row-b-ok"]').text()).toContain('promotion evidence')
    expect(wrapper.get('[data-testid="build-row-b-ok"]').text()).not.toContain('latest success')
  })

  it('says so when the promotion\'s record is not listed', async () => {
    listImageBuilds.mockResolvedValue(ok(page([RUNNING])))
    const { wrapper } = await mountHistory(version({ promotedAt: T0 + 800e3, promotedBy: 'operator' }))
    expect(wrapper.get('[data-testid="promotion-record"]').text()).toContain('not among the records listed here')
  })

  it('notes a truncated history and loads a linked record that is not listed', async () => {
    listImageBuilds.mockResolvedValue(ok(page([SUCCEEDED], 'b-ok')))
    getImageBuild.mockResolvedValue(ok({ data: FAILED }))
    const { wrapper } = await mountHistory(version(), '/images?build=b-fail')
    expect(wrapper.get('[data-testid="build-history-truncated"]').text()).toContain('newest 50 build records')
    expect(getImageBuild).toHaveBeenCalledWith('b-fail')
    expect(wrapper.get('[data-testid="build-record"]').text()).toContain('validate_failed')
  })

  it('shows a linked record\'s lookup failure and retries it', async () => {
    listImageBuilds.mockResolvedValue(ok(page([SUCCEEDED], 'b-ok')))
    getImageBuild.mockResolvedValueOnce({ status: 404, data: { code: 'not_found', message: 'no such build' }, headers: new Headers() })
    const { wrapper } = await mountHistory(version(), '/images?build=b-fail')
    expect(wrapper.get('[data-testid="linked-error"]').text()).toContain('not_found: no such build')
    getImageBuild.mockResolvedValue(ok({ data: FAILED }))
    await wrapper.get('[data-testid="linked-error"] button').trigger('click')
    await flushPromises()
    expect(wrapper.find('[data-testid="linked-error"]').exists()).toBe(false)
    expect(wrapper.get('[data-testid="build-record"]').text()).toContain('validate_failed')
  })

  it('shows a linked record loading, and says when it is another version\'s', async () => {
    listImageBuilds.mockResolvedValue(ok(page([SUCCEEDED])))
    let resolve: (value: unknown) => void = () => {}
    getImageBuild.mockReturnValue(new Promise(r => (resolve = r)))
    const { wrapper } = await mountHistory(version(), '/images?build=b-other')
    expect(wrapper.find('[data-testid="linked-loading"]').exists()).toBe(true)
    resolve(ok({ data: build('b-other', { versionId: 'r1@zzzz' }) }))
    await flushPromises()
    expect(wrapper.get('[data-testid="linked-other-version"]').text()).toContain('another version')
    expect(wrapper.find('[data-testid="build-record"]').exists()).toBe(false)
  })

  it('keeps refreshing while a followed build has no record yet', async () => {
    vi.useFakeTimers()
    try {
      listImageBuilds.mockResolvedValue(ok(page([])))
      await mountHistory(version(), '/images', true)
      const before = listImageBuilds.mock.calls.length
      await vi.advanceTimersByTimeAsync(3100)
      expect(listImageBuilds.mock.calls.length).toBeGreaterThan(before)
    }
    finally {
      vi.useRealTimers()
    }
  })

  it('says when no listed record succeeded but older pages exist', async () => {
    listImageBuilds.mockResolvedValue(ok(page([FAILED], 'b-fail')))
    const { wrapper } = await mountHistory()
    expect(wrapper.get('[data-testid="build-history-truncated"]').text()).toContain('none of them succeeded')
  })

  it('expands a truncated digest and announces a copy', async () => {
    Object.assign(navigator, { clipboard: { writeText: vi.fn().mockResolvedValue(undefined) } })
    listImageBuilds.mockResolvedValue(ok(page([SUCCEEDED])))
    const { wrapper } = await mountHistory(version(), '/images?build=b-ok')
    const content = wrapper.get('[data-testid="build-record-content-digest"]')
    await content.get('[data-testid="value-toggle"]').trigger('click')
    expect(content.get('[data-testid="value-toggle"]').text()).toBe(DIGEST)
    expect(content.get('[data-testid="value-toggle"]').attributes('aria-expanded')).toBe('true')
    await content.get('[data-testid="copy-value"]').trigger('click')
    await flushPromises()
    expect(content.get('[role="status"]').text()).toBe('Copied recipe digest')
  })

  it('shows the full value to select when the clipboard is unavailable', async () => {
    Object.assign(navigator, { clipboard: { writeText: vi.fn().mockRejectedValue(new Error('denied')) } })
    listImageBuilds.mockResolvedValue(ok(page([SUCCEEDED])))
    const { wrapper } = await mountHistory(version(), '/images?build=b-ok')
    const content = wrapper.get('[data-testid="build-record-content-digest"]')
    await content.get('[data-testid="copy-value"]').trigger('click')
    await flushPromises()
    expect(content.get('[data-testid="value-toggle"]').text()).toBe(DIGEST)
  })
})
