import { enableAutoUnmount, flushPromises, mount } from '@vue/test-utils'
import { QueryClient, VueQueryPlugin } from '@tanstack/vue-query'
import { createMemoryHistory, createRouter } from 'vue-router'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

// The stub API behind every attention source.
const listMachines = vi.fn()
const listOnboardingDrafts = vi.fn()
const listAuditEvents = vi.fn()
const listOperations = vi.fn()
const listProxmoxAccounts = vi.fn()
const discoverProxmoxCluster = vi.fn()
const listProxmoxGuests = vi.fn()
const listImageRecipes = vi.fn()
const listImageRecipeVersions = vi.fn()
const listLabTemplates = vi.fn()
const listLabLeases = vi.fn()
const getSystemInfo = vi.fn()
const listDesiredDrift = vi.fn()
const getLabLease = vi.fn()

vi.mock('@frogbyte-io/fleet-api-client', () => ({
  listMachines: (...a: unknown[]) => listMachines(...a),
  listOnboardingDrafts: (...a: unknown[]) => listOnboardingDrafts(...a),
  listAuditEvents: (...a: unknown[]) => listAuditEvents(...a),
  listOperations: (...a: unknown[]) => listOperations(...a),
  listProxmoxAccounts: (...a: unknown[]) => listProxmoxAccounts(...a),
  discoverProxmoxCluster: (...a: unknown[]) => discoverProxmoxCluster(...a),
  listProxmoxGuests: (...a: unknown[]) => listProxmoxGuests(...a),
  listImageRecipes: (...a: unknown[]) => listImageRecipes(...a),
  listImageRecipeVersions: (...a: unknown[]) => listImageRecipeVersions(...a),
  listLabTemplates: (...a: unknown[]) => listLabTemplates(...a),
  listLabLeases: (...a: unknown[]) => listLabLeases(...a),
  getSystemInfo: (...a: unknown[]) => getSystemInfo(...a),
  listDesiredDrift: (...a: unknown[]) => listDesiredDrift(...a),
  getLabLease: (...a: unknown[]) => getLabLease(...a),
}))

import OverviewPage from '../OverviewPage.vue'
import { routes } from '@/router'

function ok<T>(data: T, status = 200) {
  return { status, data, headers: new Headers() }
}
function page<T>(items: T[]) {
  return { items, page: { nextCursor: null, limit: 200 } }
}

const NOW = Date.now()
const machine = (id: string, machineStatus: string) => ({ id, name: `box-${id}`, machineStatus, lastSeenAt: NOW - 60_000, endpoints: [], groups: [], tags: [], capabilities: [], description: '', lastObservation: null, createdAt: 0, updatedAt: 0 })
const lease = (id: string, state: string, expiresAt: number | null) => ({ id, state, purpose: 'p', templateVersionId: 't1@1', owner: 'me', projectId: null, cleanup: 'destroy', ttlSeconds: 3600, createdAt: 1, readyAt: 1, expiresAt, maxLifetimeAt: NOW + 9e7 })

function drift(machineId: string, machineName: string, status: string, counts: Partial<Record<'missing' | 'changed' | 'extra' | 'unknown' | 'unsupported', number>>, detail: string | null = null) {
  return { machineId, machineName, status, revision: status === 'computed' ? { commitSha: 'abc', contentDigest: 'd' } : null, counts: { missing: 0, changed: 0, extra: 0, unknown: 0, unsupported: 0, ...counts }, differences: [], detail }
}

function everythingFine() {
  listMachines.mockResolvedValue(ok(page([machine('m1', 'connected')])))
  listOnboardingDrafts.mockResolvedValue(ok(page([])))
  listAuditEvents.mockResolvedValue(ok(page([])))
  listOperations.mockResolvedValue(ok(page([])))
  listProxmoxAccounts.mockResolvedValue(ok(page([])))
  listImageRecipes.mockResolvedValue(ok(page([])))
  listLabTemplates.mockResolvedValue(ok(page([])))
  listLabLeases.mockResolvedValue(ok(page([])))
  listDesiredDrift.mockResolvedValue(ok(page([])))
  getSystemInfo.mockResolvedValue(ok({ service: 'fleet-controller', version: '0.1.0', trustMode: 'trusted-lan', trustWarning: '', storageOk: true, queuePending: 0, queueRunning: 0, currentPrincipal: 'me' }))
}

async function mountPage() {
  const router = createRouter({ history: createMemoryHistory(), routes })
  await router.push('/')
  await router.isReady()
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } })
  const wrapper = mount(OverviewPage, { global: { plugins: [[VueQueryPlugin, { queryClient }], router] } })
  await flushPromises()
  await flushPromises()
  await flushPromises()
  return wrapper
}

function row(wrapper: Awaited<ReturnType<typeof mountPage>>, source: string) {
  return wrapper.get(`[data-testid="attention-${source}"]`)
}

enableAutoUnmount(afterEach)

beforeEach(() => {
  for (const mock of [listMachines, listOnboardingDrafts, listAuditEvents, listOperations, listProxmoxAccounts, discoverProxmoxCluster, listProxmoxGuests, listImageRecipes, listImageRecipeVersions, listLabTemplates, listLabLeases, getSystemInfo, listDesiredDrift, getLabLease])
    mock.mockReset()
  everythingFine()
})

describe('Overview attention queue', () => {
  it('says so when nothing needs attention', async () => {
    const wrapper = await mountPage()
    expect(wrapper.find('[data-testid="attention-empty"]').exists()).toBe(true)
  })

  it('lists an offline machine and links to it', async () => {
    listMachines.mockResolvedValue(ok(page([machine('m1', 'offline')])))
    const wrapper = await mountPage()
    expect(row(wrapper, 'machine').text()).toContain('box-m1 is offline')
    expect(row(wrapper, 'machine').attributes('href')).toBe('/fleet/machines/m1')
  })

  it('lists a cleanup_failed lease and links to Lab', async () => {
    listLabLeases.mockResolvedValue(ok(page([lease('lease-cf-000001', 'cleanup_failed', null)])))
    const wrapper = await mountPage()
    expect(row(wrapper, 'lease-cleanup').attributes('href')).toBe('/lab?lease=lease-cf-000001')
  })

  it('names the node and VMID a cleanup_failed lease still holds', async () => {
    listLabLeases.mockResolvedValue(ok(page([lease('lease-cf-000001', 'cleanup_failed', null)])))
    getLabLease.mockResolvedValue(ok({ data: { ...lease('lease-cf-000001', 'cleanup_failed', null), node: 'pve-a', vmid: 9001 } }))
    const wrapper = await mountPage()
    expect(getLabLease).toHaveBeenCalledWith('lease-cf-000001')
    expect(row(wrapper, 'lease-cleanup').text()).toContain('on pve-a · VMID 9001')
  })

  it('lists an orphan Lab guest the sweeper reported, from the lab.lease audit events', async () => {
    listAuditEvents.mockImplementation(async (params: { action?: string }) => ok(page(params.action === 'lab.lease'
      ? [{ id: 'e1', seq: 1, actor: 'controller', action: 'lab.lease', resource: 'fm-lab-0009', allowed: true, reason: 'allowed', occurredAt: NOW - 1000, metadata: { event: 'lab_orphan_guest', vmid: '9009' } }]
      : [])))
    const wrapper = await mountPage()
    expect(listAuditEvents).toHaveBeenCalledWith(expect.objectContaining({ action: 'lab.lease' }))
    // No Proxmox account lists guests, so nothing proves it gone: it stays, without a node.
    expect(row(wrapper, 'lab-orphan').text()).toContain('unknown node')
  })

  it('keeps an orphan whose guest is still listed, with its node', async () => {
    listAuditEvents.mockImplementation(async (params: { action?: string }) => ok(page(params.action === 'lab.lease'
      ? [{ id: 'e1', seq: 1, actor: 'controller', action: 'lab.lease', resource: 'fm-lab-0009', allowed: true, reason: 'allowed', occurredAt: NOW - 1000, metadata: { event: 'lab_orphan_guest', vmid: '9009' } }]
      : [])))
    listProxmoxAccounts.mockResolvedValue(ok(page([{ id: 'acc1', name: 'example', host: 'pve', port: 8006, tokenId: 't', fingerprint: 'AA', fingerprintState: 'confirmed', createdAt: 0 }])))
    discoverProxmoxCluster.mockResolvedValue(ok({ data: { accountId: 'acc1', pveVersion: '8.4', reportedCount: 0, warnings: [], observedAt: NOW, resources: [], nodeCapacities: [] } }))
    listProxmoxGuests.mockResolvedValue(ok(page([{ id: 'g1', kind: 'qemu', name: 'fm-lab-0009', vmid: 9009, node: 'pve-b', macs: [], candidates: [], observedAt: 0, pveVersion: '8.4', warnings: [] }])))
    const wrapper = await mountPage()
    // Guests are asked for only once discovery verified the pin.
    await vi.waitFor(async () => {
      await flushPromises()
      expect(wrapper.find('[data-testid="attention-lab-orphan"]').exists()).toBe(true)
    })
    const orphan = row(wrapper, 'lab-orphan')
    expect(orphan.text()).toContain('Orphan Lab guest fm-lab-0009')
    expect(orphan.text()).toContain('on pve-b · VMID 9009')
    expect(orphan.attributes('href')).toBe('/proxmox')
  })

  it('lists an expiring lease and links to Lab', async () => {
    listLabLeases.mockResolvedValue(ok(page([lease('lease-soon-00001', 'ready', NOW + 5 * 60_000)])))
    const wrapper = await mountPage()
    expect(row(wrapper, 'lease-expiring').text()).toContain('expires in 5 min')
    expect(row(wrapper, 'lease-expiring').attributes('href')).toBe('/lab')
  })

  it('lists a blocked operation and links to it on the Operations page', async () => {
    listOperations.mockResolvedValue(ok(page([{ id: 'op-9', kind: 'ready.workflow', state: 'blocked_manual_approval', errorJson: '{"detail":"approve frogenv"}', createdAt: 1, updatedAt: 2, cancelRequested: false }])))
    const wrapper = await mountPage()
    expect(row(wrapper, 'operation-blocked').text()).toContain('approve frogenv')
    expect(row(wrapper, 'operation-blocked').attributes('href')).toBe('/operations?op=op-9')
  })

  it('lists a changed Proxmox fingerprint and links to Proxmox', async () => {
    listProxmoxAccounts.mockResolvedValue(ok(page([{ id: 'acc1', name: 'homelab', host: 'pve', port: 8006, tokenId: 't', fingerprint: 'AA', fingerprintState: 'confirmed', createdAt: 0 }])))
    discoverProxmoxCluster.mockResolvedValue(ok({ code: 'proxmox_fingerprint_mismatch', message: 'changed' }, 409))
    const wrapper = await mountPage()
    expect(row(wrapper, 'proxmox-trust').text()).toContain('TLS fingerprint changed')
    expect(row(wrapper, 'proxmox-trust').attributes('href')).toBe('/proxmox')
  })

  it('lists a pending onboarding draft and links to the Add dialog', async () => {
    listOnboardingDrafts.mockResolvedValue(ok(page([{ id: 'd1', name: 'rpi', stage: 'untested', endpoint: { user: 'pi', host: 'rpi', port: 22 }, hostKeyStage: 'none', factCount: 0, groups: [], tags: [], createdAt: 0, updatedAt: 1 }])))
    const wrapper = await mountPage()
    expect(row(wrapper, 'onboarding').attributes('href')).toBe('/fleet/add')
  })

  it('lists a stale template pin and links to the template in Images', async () => {
    listImageRecipes.mockResolvedValue(ok(page([{ id: 'r1', name: 'ubuntu', description: '', node: 'p', storagePool: 's', source: 'clone', content: '{}', createdAt: 0, updatedAt: 0 }])))
    listImageRecipeVersions.mockResolvedValue(ok(page([{ id: 'r1@a', recipeId: 'r1', name: 'ubuntu', description: '', contentDigest: 'a', content: '{}', source: 'clone', node: 'p', storagePool: 's', publishedAt: 1, promotedAt: null }])))
    listLabTemplates.mockResolvedValue(ok(page([{ id: 't1', name: 'ubuntu-dev', imageVersionId: 'r1@a', publishedFrom: 't1@1' }])))
    const wrapper = await mountPage()
    expect(row(wrapper, 'template-pin').attributes('href')).toBe('/images?select=template:t1')
  })

  it('does not call a failed source "all clear"', async () => {
    listMachines.mockResolvedValue(ok({ code: 'forbidden', message: 'denied' }, 403))
    const wrapper = await mountPage()
    expect(wrapper.get('[data-testid="attention-failures"]').text()).toContain('machines')
    expect(wrapper.find('[data-testid="attention-empty"]').exists()).toBe(false)
  })

  it('says when audit events could not be read instead of showing no activity', async () => {
    listAuditEvents.mockResolvedValue(ok({ code: 'forbidden', message: 'denied' }, 403))
    const wrapper = await mountPage()
    expect(wrapper.get('[data-testid="activity-error"]').text()).toContain('Audit events unavailable')
  })

  it('lists a machine that differs from Fleet Git and links to its Desired tab', async () => {
    listDesiredDrift.mockResolvedValue(ok(page([drift('m1', 'box-m1', 'computed', { missing: 2, extra: 1 })])))
    const wrapper = await mountPage()
    expect(row(wrapper, 'drift').text()).toContain('box-m1 differs from Fleet Git')
    expect(row(wrapper, 'drift').text()).toContain('2 missing, 1 extra')
    expect(row(wrapper, 'drift').attributes('href')).toBe('/fleet/machines/m1?tab=desired')
  })

  it('does not raise unknown or in-sync machines as drift', async () => {
    listDesiredDrift.mockResolvedValue(ok(page([
      drift('m1', 'box-m1', 'computed', { unknown: 3 }),
      drift('m2', 'box-m2', 'computed', {}),
    ])))
    const wrapper = await mountPage()
    expect(wrapper.find('[data-testid="attention-drift"]').exists()).toBe(false)
    expect(wrapper.find('[data-testid="attention-empty"]').exists()).toBe(true)
  })

  it('reports a machine whose drift could not be computed', async () => {
    listDesiredDrift.mockResolvedValue(ok(page([drift('m1', 'box-m1', 'unavailable', {}, 'reading the machine failed')])))
    const wrapper = await mountPage()
    expect(row(wrapper, 'drift').text()).toContain('Drift could not be computed for box-m1')
  })

  it('says when drift is not measured because no revision is active', async () => {
    listDesiredDrift.mockResolvedValue(ok(page([drift('m1', 'box-m1', 'no_revision', {})])))
    const wrapper = await mountPage()
    expect(wrapper.get('[data-testid="drift-note"]').text()).toContain('No desired revision is active')
  })

  it('does not call a failed drift read "all clear"', async () => {
    listDesiredDrift.mockResolvedValue(ok({ code: 'forbidden', message: 'denied' }, 403))
    const wrapper = await mountPage()
    expect(wrapper.get('[data-testid="attention-failures"]').text()).toContain('skill drift')
    expect(wrapper.find('[data-testid="attention-empty"]').exists()).toBe(false)
  })
})

describe('Overview figures and activity', () => {
  it('counts machines and running operations, and merges the activity feed', async () => {
    listMachines.mockResolvedValue(ok(page([machine('m1', 'connected'), machine('m2', 'agentless'), machine('m3', 'stale')])))
    listOperations.mockResolvedValue(ok(page([{ id: 'op-1', kind: 'image.build', state: 'running', createdAt: 1, updatedAt: NOW - 1000, cancelRequested: false, progressMessage: 'building the image' }])))
    listAuditEvents.mockResolvedValue(ok(page([{ id: 'a1', seq: 1, occurredAt: NOW - 5000, action: 'machines.create', actor: 'me', resource: 'm1', allowed: true, outcome: 'succeeded', reason: 'ok', metadata: {} }])))
    const wrapper = await mountPage()
    expect(wrapper.get('[data-testid="kpi-Connected"]').text()).toContain('1')
    expect(wrapper.get('[data-testid="kpi-Offline / stale"]').text()).toContain('1')
    expect(wrapper.get('[data-testid="kpi-Running operations"]').text()).toContain('1')
    const feed = wrapper.get('[data-testid="activity"]').text()
    expect(feed.indexOf('image.build')).toBeLessThan(feed.indexOf('machines.create'))
  })

  it('keeps long unbroken activity tokens inside the page (truncated, full text in the title)', async () => {
    const long = 'example.invalid/acme/a-very-long-repository-name-with-no-breaks-at-all-0123456789'
    listMachines.mockResolvedValue(ok(page([])))
    listOperations.mockResolvedValue(ok(page([])))
    listAuditEvents.mockResolvedValue(ok(page([{ id: 'a1', seq: 1, occurredAt: NOW - 5000, action: 'projects.create', actor: 'me', resource: long, allowed: true, outcome: 'succeeded', reason: 'ok', metadata: {} }])))
    const wrapper = await mountPage()
    const row = wrapper.get('[data-testid="activity"] li')
    const truncated = row.findAll('.truncate')
    expect(truncated.length).toBeGreaterThan(0)
    for (const el of truncated) expect(el.attributes('title')).toBe(el.text())
    // Below xl the two-column grid must be a single minmax(0,1fr) track, or one long token widens the page.
    const grid = wrapper.get('[data-testid="activity"]').element.closest('.grid')
    expect(grid?.className).toContain('grid-cols-[minmax(0,1fr)]')
  })
})
