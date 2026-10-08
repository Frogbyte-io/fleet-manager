import { enableAutoUnmount, flushPromises, mount } from '@vue/test-utils'
import { QueryClient, VueQueryPlugin } from '@tanstack/vue-query'
import { createMemoryHistory, createRouter, type Router } from 'vue-router'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import type { LabArtifactDto, LabTemplateDto, LeaseDetailDto, LeaseDto, ProxmoxAccountDto } from '@frogbyte-io/fleet-api-client'

// The M7 Lab surface (FM-722): project filter, lease detail, cleanup retry,
// exec and its history, artifacts, and verbatim placement refusals. All data
// here is placeholder data.

const listLabLeases = vi.fn()
const listLabTemplates = vi.fn()
const listLabProvisions = vi.fn()
const listProxmoxAccounts = vi.fn()
const listProjects = vi.fn()
const createLabLease = vi.fn()
const startLabLeaseProvision = vi.fn()
const getOperation = vi.fn()
const getLabLease = vi.fn()
const listLabArtifacts = vi.fn()
const execLabLease = vi.fn()
const collectLabArtifacts = vi.fn()
const retryLabLeaseCleanup = vi.fn()

vi.mock('@frogbyte-io/fleet-api-client', () => ({
  listLabLeases: (...args: unknown[]) => listLabLeases(...args),
  listLabTemplates: (...args: unknown[]) => listLabTemplates(...args),
  listLabProvisions: (...args: unknown[]) => listLabProvisions(...args),
  listProxmoxAccounts: (...args: unknown[]) => listProxmoxAccounts(...args),
  listTailnetDevices: vi.fn(),
  listProjects: (...args: unknown[]) => listProjects(...args),
  createLabLease: (...args: unknown[]) => createLabLease(...args),
  startLabLeaseProvision: (...args: unknown[]) => startLabLeaseProvision(...args),
  releaseLabLease: vi.fn(),
  extendLabLease: vi.fn(),
  sweepLabLeases: vi.fn(),
  publishLabTemplate: vi.fn(),
  getOperation: (...args: unknown[]) => getOperation(...args),
  cancelOperation: vi.fn(),
  getLabLease: (...args: unknown[]) => getLabLease(...args),
  listLabArtifacts: (...args: unknown[]) => listLabArtifacts(...args),
  execLabLease: (...args: unknown[]) => execLabLease(...args),
  collectLabArtifacts: (...args: unknown[]) => collectLabArtifacts(...args),
  retryLabLeaseCleanup: (...args: unknown[]) => retryLabLeaseCleanup(...args),
  getDownloadLabArtifactUrl: (id: string) => `/api/v1/lab/artifacts/${id}/content`,
}))

import LabPage from '../LabPage.vue'
import { routes } from '@/router'

class ResizeObserverStub {
  observe() {}
  unobserve() {}
  disconnect() {}
}
vi.stubGlobal('ResizeObserver', ResizeObserverStub)
vi.stubGlobal('matchMedia', () => ({ matches: false, addListener: () => {}, removeListener: () => {}, addEventListener: () => {}, removeEventListener: () => {} }))

const NOW = Date.now()

function lease(overrides: Partial<LeaseDto> = {}): LeaseDto {
  return {
    id: 'lease-ready-0001',
    templateVersionId: 'v1',
    owner: 'anonymous-lan-admin',
    purpose: 'ci flake hunt',
    projectId: 'p1',
    state: 'ready',
    cleanup: 'destroy',
    cleanupAttempts: 0,
    cleanupNextAt: null,
    ttlSeconds: 7200,
    createdAt: NOW - 600_000,
    readyAt: NOW - 300_000,
    expiresAt: NOW + 3_600_000,
    maxLifetimeAt: NOW + 86_400_000,
    ...overrides,
  }
}

function detail(overrides: Partial<LeaseDetailDto> = {}): LeaseDetailDto {
  return { ...lease(), node: 'pve-a', vmid: 9001, machineId: 'machine-lab-0001', provisionState: 'ready', address: null, failedStep: null, collectionFailure: null, ...overrides }
}

function template(): LabTemplateDto {
  return {
    id: 't1', name: 'ubuntu-dev', description: '', imageVersionId: 'img-1', cores: 2, memoryMib: 4096, diskGib: 40,
    bootstrapProjectId: null, readinessProbe: 'guest_agent', readinessCommand: null, sshUser: 'root', sshPort: 22,
    sshTrustMode: 'tofu', sshFingerprint: null, readinessDeadlineSeconds: 600, ttlSeconds: 7200, cleanup: 'destroy',
    publishedFrom: 'v1', createdAt: 0, updatedAt: 0,
  }
}

function account(): ProxmoxAccountDto {
  return { id: 'acc-1', name: 'example-pve', host: 'pve.example.test', port: 8006, tokenId: 'fleet@pve!ctrl', fingerprint: 'AA:BB', fingerprintState: 'confirmed', createdAt: 0 }
}

function artifact(overrides: Partial<LabArtifactDto> = {}): LabArtifactDto {
  return {
    id: 'art-0001', leaseId: 'lease-ready-0001', kind: 'file', name: '/var/log/app.log', location: 'x', operationId: 'op-collect',
    owner: 'anonymous-lan-admin', projectId: 'p1', sha256: 'a'.repeat(64), sizeBytes: 2048, createdAt: NOW - 60_000, retainUntil: NOW + 86_400_000,
    ...overrides,
  }
}

function ok<T>(data: T, status = 200) {
  return { status, data, headers: new Headers() }
}

function page<T>(items: T[]) {
  return { items, page: { nextCursor: null, limit: 200 } }
}

function operation(overrides: Record<string, unknown>) {
  return ok({ data: { id: 'op-1', kind: 'lab.exec', state: 'running', cancelRequested: false, createdAt: 0, updatedAt: 0, ...overrides } })
}

let router: Router

async function mountPage(path = '/lab') {
  router = createRouter({ history: createMemoryHistory(), routes })
  await router.push(path)
  await router.isReady()
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } })
  const wrapper = mount(LabPage, { global: { plugins: [[VueQueryPlugin, { queryClient }], router] }, attachTo: document.body })
  await settle()
  return wrapper
}

async function settle() {
  for (let i = 0; i < 4; i++)
    await flushPromises()
}

function q<T extends Element = HTMLElement>(selector: string): T {
  const found = document.body.querySelector(selector)
  if (!found)
    throw new Error(`nothing matches ${selector}`)
  return found as T
}

function button(text: string): HTMLButtonElement {
  const found = [...document.body.querySelectorAll('button')].find(b => b.textContent?.trim().startsWith(text))
  if (!found)
    throw new Error(`no button "${text}"`)
  return found as HTMLButtonElement
}

async function type(selector: string, value: string) {
  const field = q<HTMLInputElement | HTMLTextAreaElement>(selector)
  field.value = value
  field.dispatchEvent(new Event('input'))
  await settle()
}

enableAutoUnmount(afterEach)

beforeEach(() => {
  document.body.innerHTML = ''
  for (const mock of [listLabLeases, listLabTemplates, listLabProvisions, listProxmoxAccounts, listProjects, createLabLease,
    startLabLeaseProvision, getOperation, getLabLease, listLabArtifacts, execLabLease, collectLabArtifacts, retryLabLeaseCleanup])
    mock.mockReset()
  listLabLeases.mockResolvedValue(ok(page([lease()])))
  listLabTemplates.mockResolvedValue(ok(page([template()])))
  listLabProvisions.mockResolvedValue(ok(page([])))
  listProxmoxAccounts.mockResolvedValue(ok(page([account()])))
  listProjects.mockResolvedValue(ok(page([
    { id: 'p1', name: 'demo-app', remote: 'x', description: '', checkouts: [], createdAt: 0, updatedAt: 0 },
    { id: 'p2', name: 'other-app', remote: 'y', description: '', checkouts: [], createdAt: 0, updatedAt: 0 },
  ])))
  getLabLease.mockResolvedValue(ok({ data: detail() }))
  listLabArtifacts.mockResolvedValue(ok(page([])))
  getOperation.mockResolvedValue(operation({}))
})

describe('project filter', () => {
  it('asks the server for one project\'s leases and keeps the filter in the URL', async () => {
    const wrapper = await mountPage()
    expect(listLabLeases).toHaveBeenLastCalledWith(undefined)
    const select = wrapper.get('[data-testid="project-filter"]')
    ;(select.element as HTMLSelectElement).value = 'p2'
    await select.trigger('change')
    await settle()
    expect(router.currentRoute.value.query.project).toBe('p2')
    expect(listLabLeases).toHaveBeenLastCalledWith({ projectId: 'p2' })
    expect(wrapper.text()).toContain('fleetctl --output json lab leases --project p2')
  })

  it('says the empty list is the project\'s', async () => {
    listLabLeases.mockResolvedValue(ok(page([])))
    const wrapper = await mountPage('/lab?project=p2')
    expect(wrapper.get('[data-testid="no-leases"]').text()).toContain('No active environments for this project')
  })
})

describe('lease detail', () => {
  it('opens from a card and shows placement, the Lab-owned machine, and the project', async () => {
    const wrapper = await mountPage()
    await wrapper.get('[data-testid="details-lease-ready-0001"]').trigger('click')
    await settle()
    expect(router.currentRoute.value.query.lease).toBe('lease-ready-0001')
    expect(getLabLease).toHaveBeenCalledWith('lease-ready-0001')
    expect(q('[data-testid="lease-node"]').textContent).toContain('pve-a')
    expect(q('[data-testid="lease-vmid"]').textContent).toContain('9001')
    expect(q('[data-testid="lease-machine"]').getAttribute('href')).toBe('/fleet/machines/machine-lab-0001')
    expect(q('[data-testid="lease-project"]').textContent).toContain('demo-app')
    expect(q('[data-testid="lease-timeline"]').textContent).toContain('Ready')
    expect(document.body.textContent).toContain('fleetctl --output json lab status lease-ready-0001')
  })

  it('shows the bootstrapping step as current with no machine yet', async () => {
    getLabLease.mockResolvedValue(ok({ data: detail({ state: 'bootstrapping', readyAt: null, expiresAt: null, machineId: null, node: null, vmid: null }) }))
    await mountPage('/lab?lease=lease-ready-0001')
    expect(q('[data-testid="lease-drawer"] [aria-current="step"]').textContent).toContain('bootstrapping')
    expect(q('[data-testid="lease-node"]').textContent).toContain('not placed yet')
    expect(document.body.textContent).toContain('Not registered yet')
  })

  it('shows a releasing lease\'s failed attempts and when the next one is due', async () => {
    getLabLease.mockResolvedValue(ok({ data: detail({ state: 'releasing', cleanupAttempts: 2, cleanupNextAt: NOW + 120_000 }) }))
    await mountPage('/lab?lease=lease-ready-0001')
    expect(q('[data-testid="cleanup-attempts"]').textContent).toContain('2')
    expect(q('[data-testid="cleanup-next"]').textContent).toMatch(/in (1M 5\dS|2M)/)
    expect(document.body.querySelector('[data-testid="retry-cleanup"]')).toBeNull()
  })

  it('shows a failed provision\'s step', async () => {
    getLabLease.mockResolvedValue(ok({ data: detail({ state: 'failed', failedStep: 'clone', machineId: null }) }))
    await mountPage('/lab?lease=lease-ready-0001')
    expect(q('[data-testid="lease-failed-step"]').textContent).toContain('clone')
  })

  it('retries a cleanup_failed lease\'s cleanup and names what remains', async () => {
    listLabLeases.mockResolvedValue(ok(page([lease({ state: 'cleanup_failed', cleanupAttempts: 5 })])))
    getLabLease.mockResolvedValue(ok({ data: detail({ state: 'cleanup_failed', cleanupAttempts: 5 }) }))
    retryLabLeaseCleanup.mockResolvedValue(ok({ data: { id: 'op-clean', kind: 'lab.cleanup', state: 'pending' } }, 202))
    await mountPage('/lab?lease=lease-ready-0001')
    const drawer = q('[data-testid="lease-drawer"]')
    expect(drawer.textContent).toContain('VMID 9001')
    expect(drawer.textContent).toContain('on pve-a')
    ;(drawer.querySelector('[data-testid="retry-cleanup"]') as HTMLButtonElement).click()
    await settle()
    expect(drawer.textContent).toContain('fleetctl --output json lab cleanup-retry lease-ready-0001')
    ;(drawer.querySelector('[data-testid="confirm-retry-cleanup"]') as HTMLButtonElement).click()
    await settle()
    expect(retryLabLeaseCleanup).toHaveBeenCalledWith('lease-ready-0001')
  })

  it('shows the last collection failure verbatim', async () => {
    getLabLease.mockResolvedValue(ok({ data: detail({ collectionFailure: { detail: '/var/log/x.log: not a regular file', reason: 'collection_partial', failedAt: NOW - 60_000, operationId: 'op-c' } }) }))
    await mountPage('/lab?lease=lease-ready-0001')
    expect(q('[data-testid="collection-failure"]').textContent).toContain('/var/log/x.log: not a regular file')
    expect(q('[data-testid="collection-failure"]').textContent).toContain('collection_partial')
  })

  it('names a load failure instead of an empty drawer', async () => {
    getLabLease.mockResolvedValue({ status: 404, data: { code: 'not_found', message: 'no such lease' } })
    await mountPage('/lab?lease=lease-gone')
    expect(q('[data-testid="lease-drawer"]').textContent).toContain('no such lease')
  })
})

describe('card cleanup states', () => {
  it('shows backoff on a releasing lease and a retry on a cleanup_failed one', async () => {
    listLabLeases.mockResolvedValue(ok(page([
      lease({ id: 'lease-rel', state: 'releasing', cleanupAttempts: 1, cleanupNextAt: NOW + 60_000 }),
      lease({ id: 'lease-cf', state: 'cleanup_failed', cleanupAttempts: 5 }),
    ])))
    const wrapper = await mountPage()
    expect(wrapper.get('[data-testid="lease-lease-rel"]').get('[data-testid="cleanup-backoff"]').text()).toContain('attempt 1 failed; the next attempt is in')
    const failing = wrapper.get('[data-testid="lease-lease-cf"]')
    expect(failing.text()).toContain('FAILED ATTEMPTS')
    expect(failing.text()).not.toContain('Sweep expired retries now')
    expect(failing.find('[data-testid="retry-cleanup"]').exists()).toBe(true)
  })
})

describe('run command', () => {
  async function openExec() {
    await mountPage('/lab?lease=lease-ready-0001')
    q<HTMLButtonElement>('[data-testid="lease-tab-exec"]').click()
    await settle()
  }

  it('runs a command and shows its exit code and bounded output', async () => {
    execLabLease.mockResolvedValue(ok({ data: { id: 'op-exec', kind: 'lab.exec', state: 'pending' } }, 202))
    getOperation.mockResolvedValue(operation({ id: 'op-exec', state: 'succeeded', resultJson: '{"exitCode":0,"stdout":"Linux demo\\n","stderr":"","truncatedStdout":true,"truncatedStderr":false}' }))
    await openExec()
    await type('textarea[id^="script-"]', 'uname -a')
    expect(document.body.textContent).toContain(`fleetctl --output json lab exec lease-ready-0001 --timeout 60 -- sh -c 'uname -a'`)
    q<HTMLButtonElement>('[data-testid="run-command"]').click()
    await settle()
    expect(execLabLease).toHaveBeenCalledWith('lease-ready-0001', { script: 'uname -a', timeoutSeconds: 60 })
    expect(q('[data-testid="exec-current"] [data-testid="exit-code"]').textContent).toContain('exit 0')
    expect(q('[data-testid="exec-current"] [data-testid="exec-stdout"]').textContent).toContain('Linux demo')
    expect(document.body.querySelector('[data-testid="exec-current"] [data-testid="stdout-truncated"]')).not.toBeNull()
  })

  it('shows a nonzero exit as a failure with stderr', async () => {
    execLabLease.mockResolvedValue(ok({ data: { id: 'op-exec', kind: 'lab.exec', state: 'pending' } }, 202))
    getOperation.mockResolvedValue(operation({ id: 'op-exec', state: 'failed', errorJson: '{"exitCode":2,"stdout":"","stderr":"no such file","truncatedStdout":false,"truncatedStderr":false}' }))
    await openExec()
    await type('textarea[id^="script-"]', 'cat /missing')
    q<HTMLButtonElement>('[data-testid="run-command"]').click()
    await settle()
    expect(q('[data-testid="exec-current"] [data-testid="exit-code"]').textContent).toContain('exit 2')
    expect(q('[data-testid="exec-current"] [data-testid="exec-stderr"]').textContent).toContain('no such file')
  })

  it('shows a refused command\'s error', async () => {
    execLabLease.mockResolvedValue({ status: 400, data: { code: 'invalid', message: 'the lease is not ready' } })
    await openExec()
    await type('textarea[id^="script-"]', 'true')
    q<HTMLButtonElement>('[data-testid="run-command"]').click()
    await settle()
    expect(document.body.textContent).toContain('the lease is not ready')
  })

  it('refuses a timeout outside 1–900 s before calling the API', async () => {
    await openExec()
    await type('textarea[id^="script-"]', 'true')
    await type('input[type="number"]', '901')
    expect(q<HTMLButtonElement>('[data-testid="run-command"]').disabled).toBe(true)
  })

  it('offers no command on a lease that is not ready', async () => {
    getLabLease.mockResolvedValue(ok({ data: detail({ state: 'booting', readyAt: null, expiresAt: null }) }))
    await openExec()
    expect(q('[data-testid="exec-not-ready"]').textContent).toContain('only on a ready lease')
    expect(q<HTMLButtonElement>('[data-testid="run-command"]').disabled).toBe(true)
  })

  it('lists exec history from exec-log artifacts and loads one\'s output', async () => {
    listLabArtifacts.mockResolvedValue(ok(page([
      artifact({ id: 'log-1', kind: 'exec-log', name: 'exec-op-old.log', operationId: 'op-old' }),
      artifact({ id: 'file-1' }),
    ])))
    getOperation.mockResolvedValue(operation({ id: 'op-old', state: 'succeeded', resultJson: '{"exitCode":0,"stdout":"earlier output","stderr":""}' }))
    await openExec()
    expect(listLabArtifacts).toHaveBeenCalledWith(expect.objectContaining({ leaseId: 'lease-ready-0001' }))
    const history = q('[data-testid="exec-history"]')
    expect(history.querySelectorAll('li')).toHaveLength(1)
    ;(history.querySelector('button') as HTMLButtonElement).click()
    await settle()
    expect(getOperation).toHaveBeenCalledWith('op-old')
    expect(history.textContent).toContain('earlier output')
  })

  it('says when no command has finished yet', async () => {
    await openExec()
    expect(q('[data-testid="exec-history-empty"]').textContent).toContain('No commands have finished')
  })
})

describe('artifacts', () => {
  it('lists the page\'s artifacts with their digest and a download link', async () => {
    listLabArtifacts.mockResolvedValue(ok(page([artifact()])))
    const wrapper = await mountPage('/lab?project=p1')
    await wrapper.get('[data-testid="tab-artifacts"]').trigger('click')
    await settle()
    expect(listLabArtifacts).toHaveBeenCalledWith(expect.objectContaining({ projectId: 'p1' }))
    const item = wrapper.get('[data-testid="artifact-art-0001"]')
    expect(item.get('[data-testid="artifact-digest"]').text()).toBe('a'.repeat(64))
    const link = item.get('[data-testid="download-artifact"]')
    expect(link.attributes('href')).toBe('/api/v1/lab/artifacts/art-0001/content')
    expect(link.attributes('download')).toBe('app.log')
    expect(item.text()).toContain('2.0 KiB')
    expect(wrapper.text()).toContain('fleetctl --output json lab artifacts --project p1')
  })

  it('shows the empty and failed states', async () => {
    const wrapper = await mountPage()
    await wrapper.get('[data-testid="tab-artifacts"]').trigger('click')
    await settle()
    expect(wrapper.get('[data-testid="no-artifacts"]').text()).toContain('No artifacts yet')

    listLabArtifacts.mockResolvedValue({ status: 503, data: { code: 'unavailable', message: 'the artifact store is not configured' } })
    const failing = await mountPage()
    await failing.get('[data-testid="tab-artifacts"]').trigger('click')
    await settle()
    expect(failing.get('[data-testid="artifacts-tab"]').text()).toContain('the artifact store is not configured')
  })

  it('collects paths from a ready lease, one per line', async () => {
    collectLabArtifacts.mockResolvedValue(ok({ data: { id: 'op-collect', kind: 'lab.collect', state: 'pending' } }, 202))
    await mountPage('/lab?lease=lease-ready-0001')
    q<HTMLButtonElement>('[data-testid="lease-tab-artifacts"]').click()
    await settle()
    expect(q('[data-testid="lease-artifacts-empty"]').textContent).toContain('No artifacts from this lease')
    await type('textarea[id^="collect-"]', '/var/log/app.log\n\n/tmp/report.json\n')
    expect(document.body.textContent).toContain('fleetctl --output json lab collect lease-ready-0001 /var/log/app.log /tmp/report.json')
    q<HTMLButtonElement>('[data-testid="collect"]').click()
    await settle()
    expect(collectLabArtifacts).toHaveBeenCalledWith('lease-ready-0001', { paths: ['/var/log/app.log', '/tmp/report.json'] })
  })
})

describe('request and placement', () => {
  async function request(purpose: string) {
    const wrapper = await mountPage()
    await wrapper.get('[data-testid="new-environment"]').trigger('click')
    await settle()
    await type('input[placeholder="what this environment is for"]', purpose)
    return wrapper
  }

  it('passes the project and an explicit account through, and says so in the command', async () => {
    createLabLease.mockResolvedValue(ok({ data: lease({ id: 'new-lease', state: 'requested' }) }, 201))
    startLabLeaseProvision.mockResolvedValue(ok({ data: { id: 'op-1', kind: 'lab.provision', state: 'pending' } }, 201))
    await request('demo')
    const project = [...document.body.querySelectorAll('select')].find(s => [...s.options].some(o => o.textContent?.trim() === 'None'))!
    project.value = 'p1'
    project.dispatchEvent(new Event('change'))
    const accountSelect = q<HTMLSelectElement>('[data-testid="request-account"]')
    accountSelect.value = 'acc-1'
    accountSelect.dispatchEvent(new Event('change'))
    await settle()
    expect(document.body.textContent).toContain('fleetctl --output json lab create v1 --purpose demo --project p1 --account acc-1')
    button('Request & provision').click()
    await settle()
    expect(createLabLease).toHaveBeenCalledWith({ templateVersionId: 'v1', purpose: 'demo', projectId: 'p1' })
    expect(startLabLeaseProvision).toHaveBeenCalledWith('new-lease', { accountId: 'acc-1' })
  })

  it('requests without provisioning as `lab lease`', async () => {
    await request('later')
    q<HTMLInputElement>('[data-testid="provision-now"]').click()
    await settle()
    expect(document.body.textContent).toContain('fleetctl --output json lab lease v1 --purpose later')
    expect(document.body.querySelector('[data-testid="then-command"]')).toBeNull()
    expect(document.body.querySelector('[data-testid="request-account"]')).toBeNull()
  })

  it('shows a placement refusal verbatim once the provision fails', async () => {
    const refusal = 'no configured Proxmox account reaches the pinned image\'s template: no trusted account reports VMID 9000 as a template'
    createLabLease.mockResolvedValue(ok({ data: lease({ id: 'new-lease', state: 'requested' }) }, 201))
    startLabLeaseProvision.mockResolvedValue(ok({ data: { id: 'op-place', kind: 'lab.provision', state: 'pending' } }, 201))
    getOperation.mockResolvedValue(operation({ id: 'op-place', kind: 'lab.provision', state: 'failed', errorJson: JSON.stringify({ reason: 'placement_no_candidate', detail: refusal }) }))
    await request('demo')
    button('Request & provision').click()
    await settle()
    expect(startLabLeaseProvision).toHaveBeenCalledWith('new-lease', { accountId: null })
    expect(q('[data-testid="provision-failure-reason"]').textContent).toBe('placement_no_candidate')
    expect(q('[data-testid="provision-failure-detail"]').textContent?.trim()).toBe(refusal)
  })
})
