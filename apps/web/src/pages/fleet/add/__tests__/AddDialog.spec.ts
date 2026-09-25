import { DOMWrapper, enableAutoUnmount, flushPromises, mount } from '@vue/test-utils'
import { QueryClient, VueQueryPlugin } from '@tanstack/vue-query'
import { defineComponent, h } from 'vue'
import { createMemoryHistory, createRouter, RouterView } from 'vue-router'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import type { OnboardingDraftDetailDto } from '@frogbyte-io/fleet-api-client'

// A stateful stub of the controller: onboarding drafts advance as the
// stages run, Proxmox accounts move from unconfirmed to confirmed.
const api = {
  listMachines: vi.fn(),
  listProxmoxAccounts: vi.fn(),
  discoverProxmoxCluster: vi.fn(),
  listProxmoxGuests: vi.fn(),
  getTailnetStatus: vi.fn(),
  listTailnetDevices: vi.fn(),
  listOnboardingDrafts: vi.fn(),
  createOnboardingDraft: vi.fn(),
  getOnboardingDraft: vi.fn(),
  testOnboardingDraft: vi.fn(),
  confirmOnboardingHostKey: vi.fn(),
  discoverOnboardingDraft: vi.fn(),
  addOnboardingMachine: vi.fn(),
  cancelOnboardingDraft: vi.fn(),
  importTailnetDevice: vi.fn(),
  createProxmoxAccount: vi.fn(),
  observeProxmoxFingerprint: vi.fn(),
  confirmProxmoxFingerprint: vi.fn(),
  deleteProxmoxAccount: vi.fn(),
  observeProxmoxGuest: vi.fn(),
  createOperation: vi.fn(),
  getOperation: vi.fn(),
  cancelOperation: vi.fn(),
}

vi.mock('@frogbyte-io/fleet-api-client', () =>
  Object.fromEntries(Object.entries(api).map(([name, fn]) => [name, (...args: unknown[]) => fn(...args)])))

import { routes } from '@/router'
import { RESUME_KEY, STAGE_KEY } from '../resume'

class ResizeObserverStub {
  observe() {}
  unobserve() {}
  disconnect() {}
}
vi.stubGlobal('ResizeObserver', ResizeObserverStub)
vi.stubGlobal('matchMedia', () => ({ matches: false, addListener: () => {}, removeListener: () => {}, addEventListener: () => {}, removeEventListener: () => {} }))

const NOW = 1_700_000_000_000
const FINGERPRINT = 'SHA256:q3Vt0000000000000000000000000000000009fA'

function ok<T>(data: T, status = 200) {
  return { status, data, headers: new Headers() }
}

function page<T>(items: T[]) {
  return ok({ items, page: { nextCursor: null, limit: 200 } })
}

let draft: OnboardingDraftDetailDto
let accounts: { id: string, name: string, host: string, port: number, tokenId: string, fingerprint: string | null, fingerprintState: string, createdAt: number }[]

function newDraft(body: { user: string, host: string, port?: number | null, auth: OnboardingDraftDetailDto['auth'], name?: string | null, description?: string | null, tags?: string[] }): OnboardingDraftDetailDto {
  return {
    id: 'd1',
    endpoint: { user: body.user, host: body.host, port: body.port ?? 22 },
    auth: body.auth,
    name: body.name ?? body.host,
    description: body.description ?? '',
    tags: body.tags ?? [],
    groups: [],
    stage: 'untested',
    hostKeyStage: 'unseen',
    facts: [],
    duplicates: [],
    createdAt: NOW,
    updatedAt: NOW,
  }
}

function stubApi() {
  accounts = []
  api.listMachines.mockResolvedValue(page([]))
  api.listProxmoxAccounts.mockImplementation(async () => page(accounts))
  api.getTailnetStatus.mockResolvedValue(ok({ data: { configured: true } }))
  api.listTailnetDevices.mockResolvedValue(page([
    { id: 'n1', nodeId: 'nA', name: 'nas-01.example.ts.net', hostname: 'nas-01', os: 'linux', addresses: ['100.101.4.12', 'fd7a:115c::1'], tags: ['tag:server'], user: 'op', online: true, lastSeen: null, candidates: [] },
    { id: 'n2', nodeId: 'nB', name: 'dev-01.example.ts.net', hostname: 'dev-01', os: 'linux', addresses: ['100.64.0.11'], tags: [], user: 'op', online: true, lastSeen: null, candidates: [{ machineId: 'm9', machineName: 'dev-01', machineStatus: 'connected', reference: '100.64.0.11', kind: 'address_match' }] },
  ]))
  api.listOnboardingDrafts.mockResolvedValue(page([]))
  api.createOnboardingDraft.mockImplementation(async (body) => {
    draft = newDraft(body)
    return ok({ data: draft }, 201)
  })
  api.importTailnetDevice.mockImplementation(async (_nodeId: string, body: { user: string, port?: number }) => {
    draft = newDraft({ user: body.user, host: '100.101.4.12', port: body.port, auth: { type: 'agent' }, name: 'nas-01' })
    return ok({ data: draft }, 201)
  })
  api.getOnboardingDraft.mockImplementation(async () => ok({ data: draft }))
  api.testOnboardingDraft.mockImplementation(async () => {
    draft = { ...draft, hostKeyStage: 'observed', hostKey: { keyType: 'ED25519', fingerprint: FINGERPRINT, rawLine: 'host ssh-ed25519 AAAA' }, lastTest: { connectAttempted: true, connected: true, at: NOW } }
    return ok({ data: { id: 'op-test', kind: 'onboarding.test', state: 'pending', cancelRequested: false, createdAt: NOW, updatedAt: NOW } }, 202)
  })
  api.confirmOnboardingHostKey.mockImplementation(async () => {
    draft = { ...draft, hostKeyStage: 'confirmed', confirmedFingerprint: FINGERPRINT }
    return ok({ data: draft })
  })
  api.discoverOnboardingDraft.mockImplementation(async () => {
    draft = { ...draft, stage: 'ready', discoveredAt: NOW, facts: [{ namespace: 'os', name: 'distribution', value: 'debian', status: 'known', observedAt: NOW, source: 'agentless/1' }] }
    return ok({ data: { id: 'op-discover', kind: 'onboarding.discover', state: 'pending', cancelRequested: false, createdAt: NOW, updatedAt: NOW } }, 202)
  })
  api.getOperation.mockImplementation(async (id: string) => ok({ data: { id, kind: 'stub', state: 'succeeded', cancelRequested: false, createdAt: NOW, updatedAt: NOW } }))
  api.addOnboardingMachine.mockImplementation(async () => ok({
    data: {
      machine: { id: 'm1', name: draft.name, description: '', endpoints: [{ id: 'e-ssh', kind: 'ssh', reference: '***@host:22' }], tags: [], groups: [], machineStatus: 'agentless', capabilities: [], createdAt: NOW, updatedAt: NOW },
      duplicates: [],
    },
  }, 201))
  api.cancelOnboardingDraft.mockResolvedValue({ status: 204, data: undefined, headers: new Headers() })
  api.createOperation.mockResolvedValue(ok({ data: { id: 'op-install', kind: 'machine.install-fleetd', state: 'pending', cancelRequested: false, createdAt: NOW, updatedAt: NOW } }, 201))
  api.createProxmoxAccount.mockImplementation(async (body: { name: string, host: string, port: number, tokenId: string }) => {
    accounts = [{ id: 'acc1', name: body.name, host: body.host, port: body.port, tokenId: body.tokenId, fingerprint: null, fingerprintState: 'unconfirmed', createdAt: NOW }]
    return ok({ data: accounts[0] }, 201)
  })
  api.observeProxmoxFingerprint.mockResolvedValue(ok({ data: { accountId: 'acc1', fingerprint: 'AB:CD:EF' } }))
  api.confirmProxmoxFingerprint.mockImplementation(async (_id: string, body: { fingerprint: string }) => {
    accounts = accounts.map(a => ({ ...a, fingerprint: body.fingerprint, fingerprintState: 'confirmed' }))
    return ok({ data: accounts[0] })
  })
  api.deleteProxmoxAccount.mockImplementation(async () => {
    accounts = []
    return { status: 204, data: undefined, headers: new Headers() }
  })
  api.discoverProxmoxCluster.mockResolvedValue(ok({
    data: {
      accountId: 'acc1',
      observedAt: NOW,
      pveVersion: '8.2.4',
      reportedCount: 3,
      warnings: [],
      resources: [
        { accountId: 'acc1', id: 'node-pve', kind: 'node', name: 'pve', node: null, status: 'online', vmid: null, observedAt: NOW, pveVersion: '8.2.4' },
        { accountId: 'acc1', id: 'q-100', kind: 'qemu', name: 'web', node: 'pve', status: 'running', vmid: 100, observedAt: NOW, pveVersion: '8.2.4' },
        { accountId: 'acc1', id: 't-9000', kind: 'qemu-template', name: 'tpl', node: 'pve', status: 'stopped', vmid: 9000, observedAt: NOW, pveVersion: '8.2.4' },
      ],
    },
  }))
  api.listProxmoxGuests.mockResolvedValue(page([
    {
      id: 'q-100',
      kind: 'qemu',
      vmid: 100,
      name: 'web',
      node: 'pve',
      status: 'running',
      agent: { online: true, osName: 'Debian 12', interfaces: [{ name: 'lo', addresses: ['127.0.0.1/8'] }, { name: 'eth0', addresses: ['192.168.1.50/24', 'fe80::1/64'] }] },
      candidates: [{ machineId: 'm7', machineName: 'web-host', machineStatus: 'agentless', kind: 'mac_match', evidence: 'aa:bb:cc:dd:ee:ff' }],
      warnings: [],
      macs: [],
      observedAt: NOW,
      pveVersion: '8.2.4',
    },
  ]))
  api.observeProxmoxGuest.mockResolvedValue({ status: 204, data: undefined, headers: new Headers() })
}

// The dialog renders in a portal on document.body.
function $(selector: string): DOMWrapper<HTMLElement> {
  const element = document.body.querySelector<HTMLElement>(selector)
  if (!element)
    throw new Error(`no element matches ${selector}`)
  return new DOMWrapper(element)
}

function exists(selector: string): boolean {
  return document.body.querySelector(selector) !== null
}

async function settle() {
  await vi.waitFor(async () => {
    await flushPromises()
  })
  await flushPromises()
  await flushPromises()
}

async function until(selector: string) {
  await vi.waitFor(async () => {
    await flushPromises()
    expect(exists(selector)).toBe(true)
  })
}

async function mountAt(path: string) {
  const router = createRouter({ history: createMemoryHistory(), routes })
  await router.push(path)
  await router.isReady()
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } })
  const wrapper = mount(defineComponent({ render: () => h(RouterView) }), {
    global: { plugins: [[VueQueryPlugin, { queryClient }], router] },
    attachTo: document.body,
  })
  await until('[data-testid="add-dialog"]')
  await settle()
  return { wrapper, router }
}

enableAutoUnmount(afterEach)

beforeEach(() => {
  document.body.innerHTML = ''
  vi.clearAllMocks()
  localStorage.clear()
  sessionStorage.clear()
  stubApi()
})

async function walkDraftToFinish() {
  await until('[data-testid="step-test"]')
  await $('[data-testid="run-test"]').trigger('click')
  await until('[data-testid="step-verify"]')

  expect($('[data-testid="observed-fingerprint"]').text()).toContain(FINGERPRINT)
  expect($('[data-testid="confirm-host-key"]').attributes('disabled')).toBeDefined()
  await $('[data-testid="verified-checkbox"]').setValue(true)
  await $('[data-testid="confirm-host-key"]').trigger('click')
  await until('[data-testid="step-discover"]')
  expect(api.confirmOnboardingHostKey).toHaveBeenCalledWith('d1', { fingerprint: FINGERPRINT })

  await $('[data-testid="run-discover"]').trigger('click')
  await until('[data-testid="step-finish"]')
}

describe('Add dialog', () => {
  it('Machine over SSH: draft → test → confirm host key → discover → add with fleetd', async () => {
    await mountAt('/fleet/add')
    await $('[data-testid="source-ssh"]').trigger('click')
    await settle()
    await $('[data-testid="ssh-host"]').setValue('pi-4.lan')
    await $('[data-testid="ssh-user"]').setValue('pi')
    expect(document.body.textContent).toContain('fleetctl machines onboard create --user pi --host pi-4.lan --auth agent')
    await $('[data-testid="create-draft"]').trigger('click')
    await settle()
    expect(api.createOnboardingDraft).toHaveBeenCalledWith(expect.objectContaining({ user: 'pi', host: 'pi-4.lan', port: 22, auth: { type: 'agent' } }))
    expect(JSON.parse(localStorage.getItem(RESUME_KEY)!)).toEqual({ kind: 'draft', id: 'd1' })

    await walkDraftToFinish()
    expect(document.body.textContent).toContain('os/distribution')
    await $('[data-testid="manage-fleetd"]').setValue(true)
    await $('[data-testid="add-to-fleet"]').trigger('click')
    await until('[data-testid="open-added-machine"]')

    expect(api.addOnboardingMachine).toHaveBeenCalledWith('d1')
    const install = api.createOperation.mock.calls[0]![0]
    expect(install.kind).toBe('machine.install-fleetd')
    expect(JSON.parse(install.payloadJson)).toMatchObject({ machineId: 'm1', endpointId: 'e-ssh', auth: { type: 'agent' } })
    expect($('[data-testid="open-added-machine"]').attributes('href')).toContain('/fleet/machines/m1')
    expect(localStorage.getItem(RESUME_KEY)).toBeNull()
  })

  it('agentless add installs nothing', async () => {
    draft = { ...newDraft({ user: 'pi', host: 'pi-4.lan', auth: { type: 'agent' } }), hostKeyStage: 'confirmed', discoveredAt: NOW }
    localStorage.setItem(RESUME_KEY, JSON.stringify({ kind: 'draft', id: 'd1' }))
    await mountAt('/fleet/add')
    await until('[data-testid="step-finish"]')
    await $('[data-testid="add-to-fleet"]').trigger('click')
    await until('[data-testid="open-added-machine"]')
    expect(api.createOperation).not.toHaveBeenCalled()
  })

  it('closing and reopening resumes the draft at the step the controller reports', async () => {
    const first = await mountAt('/fleet/add?source=ssh')
    await $('[data-testid="ssh-host"]').setValue('pi-4.lan')
    await $('[data-testid="ssh-user"]').setValue('pi')
    await $('[data-testid="create-draft"]').trigger('click')
    await until('[data-testid="step-test"]')
    await $('[data-testid="run-test"]').trigger('click')
    await until('[data-testid="step-verify"]')
    first.wrapper.unmount()

    await mountAt('/fleet/add')
    await until('[data-testid="step-verify"]')
    expect($('[data-testid="observed-fingerprint"]').text()).toContain(FINGERPRINT)
  })

  it('offers pending drafts to resume from the source step', async () => {
    draft = { ...newDraft({ user: 'pi', host: 'pi-4.lan', auth: { type: 'agent' } }), hostKeyStage: 'confirmed' }
    api.listOnboardingDrafts.mockResolvedValue(page([draft]))
    await mountAt('/fleet/add')
    await until('[data-testid="resume-draft-d1"]')
    await $('[data-testid="resume-draft-d1"]').trigger('click')
    await until('[data-testid="step-discover"]')
  })

  it('cancel discards the draft after confirmation and returns to the sources', async () => {
    draft = newDraft({ user: 'pi', host: 'pi-4.lan', auth: { type: 'agent' } })
    localStorage.setItem(RESUME_KEY, JSON.stringify({ kind: 'draft', id: 'd1' }))
    await mountAt('/fleet/add')
    await until('[data-testid="step-test"]')
    await $('[data-testid="cancel-draft"]').trigger('click')
    expect(api.cancelOnboardingDraft).not.toHaveBeenCalled()
    await $('[data-testid="confirm-cancel-draft"]').trigger('click')
    await until('[data-testid="source-ssh"]')
    expect(api.cancelOnboardingDraft).toHaveBeenCalledWith('d1')
    expect(localStorage.getItem(RESUME_KEY)).toBeNull()
  })

  it('From Tailscale: flags devices already in Fleet and connects via MagicDNS', async () => {
    await mountAt('/fleet/add?source=tailscale')
    await until('[data-testid="device-nA"]')
    expect($('[data-testid="device-nB"]').text()).toContain('In Fleet: dev-01')
    expect($('[data-testid="device-nA"]').text()).toContain('100.101.4.12')

    await $('[data-testid="device-nA"] input').setValue(true)
    await $('[data-testid="tailnet-user"]').setValue('dev')
    expect(document.body.textContent).toContain('nas-01.example.ts.net')
    await $('[data-testid="create-tailnet-draft"]').trigger('click')
    await until('[data-testid="step-test"]')
    expect(api.importTailnetDevice).not.toHaveBeenCalled()
    expect(api.createOnboardingDraft).toHaveBeenCalledWith(expect.objectContaining({
      host: 'nas-01.example.ts.net',
      user: 'dev',
      name: 'nas-01',
      description: 'Imported from tailnet device nA (nas-01.example.ts.net)',
    }))
  })

  it('From Tailscale: the 100.x address with the SSH agent is a tailnet import', async () => {
    await mountAt('/fleet/add?source=tailscale&device=nA')
    await until('[data-testid="tailnet-user"]')
    await $('[data-testid="via-tailnet-ip"]').setValue(true)
    await $('[data-testid="tailnet-user"]').setValue('dev')
    expect(document.body.textContent).toContain('fleetctl tailnet import nA --user dev')
    await $('[data-testid="create-tailnet-draft"]').trigger('click')
    await until('[data-testid="step-test"]')
    expect(api.importTailnetDevice).toHaveBeenCalledWith('nA', { user: 'dev', port: 22 })
  })

  it('From Tailscale: a LAN IP must be entered', async () => {
    await mountAt('/fleet/add?source=tailscale&device=nA')
    await until('[data-testid="tailnet-user"]')
    await $('[data-testid="via-lan"]').setValue(true)
    await $('[data-testid="tailnet-user"]').setValue('dev')
    expect($('[data-testid="create-tailnet-draft"]').attributes('disabled')).toBeDefined()
    await $('[data-testid="lan-ip"]').setValue('192.168.1.40')
    expect($('[data-testid="create-tailnet-draft"]').attributes('disabled')).toBeUndefined()
  })

  it('Proxmox server: save → observe → explicit TLS confirmation → discovery preview', async () => {
    await mountAt('/fleet/add?source=proxmox')
    await $('[data-testid="pve-name"]').setValue('homelab')
    await $('[data-testid="pve-host"]').setValue('pve.lan')
    await $('[data-testid="pve-token-id"]').setValue('fleet@pve!console')
    await $('[data-testid="pve-token-secret"]').setValue('s3cr3t-value')
    expect(document.body.textContent).toContain('fleetctl proxmox create --name homelab --host pve.lan --token-id \'fleet@pve!console\'')
    expect(document.body.textContent).not.toContain('s3cr3t-value')
    await $('[data-testid="create-pve"]').trigger('click')
    await until('[data-testid="observe-pve"]')
    expect(api.createProxmoxAccount).toHaveBeenCalledWith({ name: 'homelab', host: 'pve.lan', port: 8006, tokenId: 'fleet@pve!console', tokenSecret: 's3cr3t-value' })
    expect(JSON.parse(localStorage.getItem(RESUME_KEY)!)).toEqual({ kind: 'proxmox', id: 'acc1' })

    await $('[data-testid="observe-pve"]').trigger('click')
    await until('[data-testid="pve-fingerprint"]')
    expect($('[data-testid="pve-fingerprint"]').text()).toBe('AB:CD:EF')
    expect($('[data-testid="confirm-pve"]').attributes('disabled')).toBeDefined()
    await $('[data-testid="pve-verified"]').setValue(true)
    await $('[data-testid="confirm-pve"]').trigger('click')
    await until('[data-testid="pve-preview"]')
    expect(api.confirmProxmoxFingerprint).toHaveBeenCalledWith('acc1', { fingerprint: 'AB:CD:EF' })
    expect($('[data-testid="pve-preview"]').text()).toContain('1 node(s) · 1 guest(s) · 1 template(s)')
    expect(localStorage.getItem(RESUME_KEY)).toBeNull()
  })

  it('Proxmox server: an unconfirmed account resumes and can be discarded', async () => {
    accounts = [{ id: 'acc1', name: 'homelab', host: 'pve.lan', port: 8006, tokenId: 'fleet@pve!console', fingerprint: null, fingerprintState: 'unconfirmed', createdAt: NOW }]
    await mountAt('/fleet/add')
    await until('[data-testid="resume-pve-acc1"]')
    await $('[data-testid="resume-pve-acc1"]').trigger('click')
    await until('[data-testid="discard-pve"]')
    await $('[data-testid="discard-pve"]').trigger('click')
    await $('[data-testid="confirm-discard-pve"]').trigger('click')
    await until('[data-testid="source-proxmox"]')
    expect(api.deleteProxmoxAccount).toHaveBeenCalledWith('acc1')
  })

  it('Existing VM/LXC: records facts on a candidate or onboards over SSH', async () => {
    accounts = [{ id: 'acc1', name: 'homelab', host: 'pve.lan', port: 8006, tokenId: 't', fingerprint: 'AB', fingerprintState: 'confirmed', createdAt: NOW }]
    await mountAt('/fleet/add?source=guest')
    await until('[data-testid="guest-acc1:q-100"]')
    expect($('[data-testid="guest-acc1:q-100"]').text()).toContain('192.168.1.50')
    expect($('[data-testid="guest-acc1:q-100"]').text()).not.toContain('127.0.0.1')
    await $('[data-testid="guest-acc1:q-100"] input').setValue(true)
    await until('[data-testid="link-acc1:q-100-m7"]')
    await $('[data-testid="link-acc1:q-100-m7"]').trigger('click')
    await settle()
    expect(api.observeProxmoxGuest).toHaveBeenCalledWith('acc1', 100, { machineId: 'm7' })

    await $('[data-testid="onboard-guest"]').trigger('click')
    await until('[data-testid="ssh-host"]')
    expect(($('[data-testid="ssh-host"]').element as HTMLInputElement).value).toBe('192.168.1.50')
    expect(($('[data-testid="ssh-name"]').element as HTMLInputElement).value).toBe('web')
  })

  it('Lab environment hands off to the Lab page', async () => {
    const { router } = await mountAt('/fleet/add')
    await $('[data-testid="source-lab"]').trigger('click')
    await vi.waitFor(() => expect(router.currentRoute.value.path).toBe('/lab'))
  })
})

describe('Add dialog resume and error handling', () => {
  it('an explicit source wins over a stored resume, which stays listed', async () => {
    draft = newDraft({ user: 'pi', host: 'pi-4.lan', auth: { type: 'agent' } })
    localStorage.setItem(RESUME_KEY, JSON.stringify({ kind: 'draft', id: 'd1' }))
    await mountAt('/fleet/add?source=tailscale&device=nA')
    await until('[data-testid="tailnet-user"]')
    expect(exists('[data-testid="step-test"]')).toBe(false)
    expect(($('[data-testid="device-nA"] input').element as HTMLInputElement).checked).toBe(true)
  })

  it('a resumed draft that no longer exists offers a way back to the sources', async () => {
    api.getOnboardingDraft.mockResolvedValue({ status: 404, data: { code: 'not_found', message: 'no draft' }, headers: new Headers() })
    localStorage.setItem(RESUME_KEY, JSON.stringify({ kind: 'draft', id: 'gone' }))
    await mountAt('/fleet/add')
    await until('[data-testid="draft-restart"]')
    expect($('[data-testid="draft-unavailable"]').text()).toContain('no longer exists')
    await $('[data-testid="draft-restart"]').trigger('click')
    await until('[data-testid="source-ssh"]')
    expect(localStorage.getItem(RESUME_KEY)).toBeNull()
  })

  it('a resumed Proxmox account that no longer exists offers a way back', async () => {
    localStorage.setItem(RESUME_KEY, JSON.stringify({ kind: 'proxmox', id: 'gone' }))
    await mountAt('/fleet/add')
    await until('[data-testid="pve-missing-restart"]')
    await $('[data-testid="pve-missing-restart"]').trigger('click')
    await until('[data-testid="source-proxmox"]')
    expect(localStorage.getItem(RESUME_KEY)).toBeNull()
  })

  it('reopening while a test runs follows that operation instead of starting another', async () => {
    api.getOperation.mockImplementation(async (id: string) => ok({ data: { id, kind: 'onboarding.test', state: 'running', cancelRequested: false, createdAt: NOW, updatedAt: NOW } }))
    const first = await mountAt('/fleet/add?source=ssh')
    await $('[data-testid="ssh-host"]').setValue('pi-4.lan')
    await $('[data-testid="ssh-user"]').setValue('pi')
    await $('[data-testid="create-draft"]').trigger('click')
    await until('[data-testid="step-test"]')
    // The probe is still running on the controller: the draft has not moved.
    api.testOnboardingDraft.mockImplementation(async () => ok({ data: { id: 'op-test', kind: 'onboarding.test', state: 'pending', cancelRequested: false, createdAt: NOW, updatedAt: NOW } }, 202))
    await $('[data-testid="run-test"]').trigger('click')
    await settle()
    first.wrapper.unmount()

    await mountAt('/fleet/add')
    await until('[data-testid="step-test"]')
    await until('[data-testid="operation-status"]')
    expect($('[data-testid="operation-status"]').text()).toContain('op-test')
    expect($('[data-testid="run-test"]').attributes('disabled')).toBeDefined()
    expect(api.testOnboardingDraft).toHaveBeenCalledTimes(1)
  })

  it('a remembered operation the API cannot read no longer locks the step', async () => {
    draft = newDraft({ user: 'pi', host: 'pi-4.lan', auth: { type: 'agent' } })
    localStorage.setItem(RESUME_KEY, JSON.stringify({ kind: 'draft', id: 'd1' }))
    localStorage.setItem(STAGE_KEY, JSON.stringify({ draftId: 'd1', stage: 'test', id: 'op-expired' }))
    api.getOperation.mockResolvedValue({ status: 404, data: { code: 'not_found', message: 'no operation' }, headers: new Headers() })
    await mountAt('/fleet/add')
    await until('[data-testid="stage-lost"]')
    expect($('[data-testid="run-test"]').attributes('disabled')).toBeUndefined()
    expect(localStorage.getItem(STAGE_KEY)).toBeNull()
  })

  it('reports a fleetd install that failed to start after the add, with a retry', async () => {
    draft = { ...newDraft({ user: 'pi', host: 'pi-4.lan', auth: { type: 'agent' } }), hostKeyStage: 'confirmed', discoveredAt: NOW }
    localStorage.setItem(RESUME_KEY, JSON.stringify({ kind: 'draft', id: 'd1' }))
    api.createOperation.mockResolvedValueOnce({ status: 403, data: { code: 'forbidden', message: 'no install permission' }, headers: new Headers() })
    await mountAt('/fleet/add')
    await until('[data-testid="step-finish"]')
    await $('[data-testid="manage-fleetd"]').setValue(true)
    expect(document.body.textContent).toContain('appears once the machine exists')
    await $('[data-testid="add-to-fleet"]').trigger('click')
    await until('[data-testid="install-error"]')
    expect($('[data-testid="install-error"]').text()).toContain('forbidden: no install permission')
    expect(document.body.textContent).toContain('fleetctl machines install-node m1 --endpoint e-ssh --auth agent')
    await $('[data-testid="retry-install"]').trigger('click')
    await until('[data-testid="operation-status"]')
    expect(api.createOperation).toHaveBeenCalledTimes(2)
  })

  it('refuses out-of-range ports before calling the API', async () => {
    await mountAt('/fleet/add?source=proxmox')
    await $('[data-testid="pve-name"]').setValue('homelab')
    await $('[data-testid="pve-host"]').setValue('pve.lan')
    await $('[data-testid="pve-token-id"]').setValue('fleet@pve!console')
    await $('[data-testid="pve-token-secret"]').setValue('x')
    await $('[data-testid="pve-port"]').setValue('70000')
    expect($('[data-testid="create-pve"]').attributes('disabled')).toBeDefined()
    await $('[data-testid="pve-port"]').setValue('8006')
    expect($('[data-testid="create-pve"]').attributes('disabled')).toBeUndefined()
  })

  it('lists tailnet devices and accounts beyond the first page', async () => {
    api.listTailnetDevices
      .mockResolvedValueOnce(ok({ items: [{ id: 'n1', nodeId: 'nA', name: 'a.ts.net', hostname: 'a', os: 'linux', addresses: ['100.64.0.1'], tags: [], user: 'op', online: true, candidates: [] }], page: { nextCursor: 'p2', limit: 200 } }))
      .mockResolvedValueOnce(ok({ items: [{ id: 'n9', nodeId: 'nZ', name: 'z.ts.net', hostname: 'z', os: 'linux', addresses: ['100.64.0.9'], tags: [], user: 'op', online: true, candidates: [] }], page: { nextCursor: null, limit: 200 } }))
    await mountAt('/fleet/add?source=tailscale')
    await until('[data-testid="device-nZ"]')
    expect(api.listTailnetDevices).toHaveBeenLastCalledWith({ limit: 200, cursor: 'p2' })
  })

  it('carries the guest provenance into the copied onboard command', async () => {
    accounts = [{ id: 'acc1', name: 'homelab', host: 'pve.lan', port: 8006, tokenId: 't', fingerprint: 'AB', fingerprintState: 'confirmed', createdAt: NOW }]
    await mountAt('/fleet/add?source=guest')
    await until('[data-testid="guest-acc1:q-100"]')
    await $('[data-testid="guest-acc1:q-100"] input').setValue(true)
    await until('[data-testid="onboard-guest"]')
    await $('[data-testid="onboard-guest"]').trigger('click')
    await until('[data-testid="ssh-user"]')
    await $('[data-testid="ssh-user"]').setValue('root')
    expect(document.body.textContent).toContain(`--description 'Proxmox VM 100 on pve (homelab)'`)
  })

  it('closing replaces the history entry instead of pushing a new one', async () => {
    const { router } = await mountAt('/fleet/add')
    const replace = vi.spyOn(router, 'replace')
    const push = vi.spyOn(router, 'push')
    await $('[data-slot="dialog-close"]').trigger('click')
    await vi.waitFor(() => expect(replace).toHaveBeenCalledWith('/fleet'))
    expect(push).not.toHaveBeenCalled()
  })
})

describe('Add dialog review fixes', () => {
  it('refuses an SSH host or user that starts with a dash', async () => {
    await mountAt('/fleet/add?source=ssh')
    await $('[data-testid="ssh-host"]').setValue('pi-4.lan')
    await $('[data-testid="ssh-user"]').setValue('-oProxyCommand=x')
    expect($('[data-testid="create-draft"]').attributes('disabled')).toBeDefined()
    expect(exists('[data-testid="ssh-option-like"]')).toBe(true)
    await $('[data-testid="ssh-user"]').setValue('pi')
    expect($('[data-testid="create-draft"]').attributes('disabled')).toBeUndefined()
  })

  it('a rotated certificate leads back to TLS verification and re-pins', async () => {
    accounts = [{ id: 'acc1', name: 'homelab', host: 'pve.lan', port: 8006, tokenId: 't', fingerprint: 'AB', fingerprintState: 'confirmed', createdAt: NOW }]
    localStorage.setItem(RESUME_KEY, JSON.stringify({ kind: 'proxmox', id: 'acc1' }))
    const preview = await api.discoverProxmoxCluster()
    let rotated = true
    api.discoverProxmoxCluster.mockImplementation(async () => rotated
      ? { status: 409, data: { code: 'proxmox_fingerprint_mismatch', message: 'changed' }, headers: new Headers() }
      : preview)
    const confirm = api.confirmProxmoxFingerprint.getMockImplementation()!
    api.confirmProxmoxFingerprint.mockImplementation(async (...args: [string, { fingerprint: string }]) => {
      rotated = false
      return confirm(...args)
    })
    await mountAt('/fleet/add')
    await until('[data-testid="repin-pve"]')
    expect(exists('[data-testid="retry-discovery"]')).toBe(false)
    await $('[data-testid="repin-pve"]').trigger('click')
    await until('[data-testid="observe-pve"]')
    expect(exists('[data-testid="discard-pve"]')).toBe(false)
    await $('[data-testid="observe-pve"]').trigger('click')
    await until('[data-testid="pve-verified"]')
    await $('[data-testid="pve-verified"]').setValue(true)
    await $('[data-testid="confirm-pve"]').trigger('click')
    await until('[data-testid="pve-preview"]')
    expect(api.confirmProxmoxFingerprint).toHaveBeenCalledWith('acc1', { fingerprint: 'AB:CD:EF' })
  })

  it('offers a retry when discovery fails', async () => {
    accounts = [{ id: 'acc1', name: 'homelab', host: 'pve.lan', port: 8006, tokenId: 't', fingerprint: 'AB', fingerprintState: 'confirmed', createdAt: NOW }]
    localStorage.setItem(RESUME_KEY, JSON.stringify({ kind: 'proxmox', id: 'acc1' }))
    const preview = await api.discoverProxmoxCluster()
    let failing = true
    api.discoverProxmoxCluster.mockImplementation(async () => failing
      ? { status: 502, data: { code: 'proxmox_source', message: 'unreachable' }, headers: new Headers() }
      : preview)
    await mountAt('/fleet/add')
    await until('[data-testid="retry-discovery"]')
    expect($('[data-testid="pve-discovery-error"]').text()).toContain('proxmox_source: unreachable')
    failing = false
    await $('[data-testid="retry-discovery"]').trigger('click')
    await until('[data-testid="pve-preview"]')
  })

  it('shows a failed Resume load with a retry instead of an empty list', async () => {
    const draftItem = newDraft({ user: 'pi', host: 'pi-4.lan', auth: { type: 'agent' } })
    api.listOnboardingDrafts
      .mockResolvedValueOnce({ status: 500, data: { code: 'internal', message: 'down' }, headers: new Headers() })
      .mockResolvedValue(page([draftItem]))
    await mountAt('/fleet/add')
    await until('[data-testid="resume-error"]')
    expect($('[data-testid="resume-error"]').text()).toContain('Drafts unavailable')
    await $('[data-testid="resume-retry"]').trigger('click')
    await until('[data-testid="resume-draft-d1"]')
    expect(exists('[data-testid="resume-error"]')).toBe(false)
    expect(api.listOnboardingDrafts).toHaveBeenLastCalledWith({ limit: 200 })
  })
})
