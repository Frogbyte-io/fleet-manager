import { describe, expect, it } from 'vitest'

import type { MachineDto, PageAssociatedGuestDtoItemsItem, PageCorrelatedDeviceDtoItemsItem, ProxmoxDiscoveryDto } from '@frogbyte-io/fleet-api-client'

import {
  buildInventory,
  formatBytes,
  guestStatusTone,
  machineStatusTone,
  relativeTime,
  specLine,
  type InventoryInput,
} from '../inventory'

const NOW = 1_700_000_000_000

function inventoryInput(overrides: Partial<InventoryInput> = {}): InventoryInput {
  return {
    machines: [],
    machinesError: null,
    proxmoxAccountsError: null,
    proxmox: [],
    tailnet: { configured: false, loading: false, devices: null, error: null },
    paginationWarning: null,
    ...overrides,
  }
}

function machine(overrides: Partial<MachineDto> = {}): MachineDto {
  return {
    id: 'm1',
    name: 'build-host',
    description: '',
    endpoints: [{ id: 'e1', kind: 'ssh', reference: '***@host:22' }],
    tags: ['linux'],
    groups: ['ci'],
    machineStatus: 'connected',
    lastSeenAt: NOW - 30_000,
    lastObservation: null,
    capabilities: [
      { namespace: 'os', name: 'distribution', value: 'ubuntu', status: 'known', observedAt: NOW, source: 'agentless/1' },
      { namespace: 'os', name: 'distribution_version', value: '24.04', status: 'known', observedAt: NOW, source: 'agentless/1' },
      { namespace: 'os', name: 'family', value: 'debian', status: 'known', observedAt: NOW, source: 'agentless/1' },
      { namespace: 'host', name: 'architecture', value: 'x86_64', status: 'known', observedAt: NOW, source: 'agentless/1' },
      { namespace: 'hardware', name: 'cpu_cores', value: '8', status: 'known', observedAt: NOW, source: 'agentless/1' },
      { namespace: 'hardware', name: 'memory_bytes', value: String(16 * 1024 ** 3), status: 'known', observedAt: NOW, source: 'agentless/1' },
      { namespace: 'hardware', name: 'disk_free_bytes', value: String(180 * 1024 ** 3), status: 'known', observedAt: NOW, source: 'agentless/1' },
    ],
    createdAt: 0,
    updatedAt: 0,
    ...overrides,
  }
}

function discovery(overrides: Partial<ProxmoxDiscoveryDto> = {}): ProxmoxDiscoveryDto {
  return {
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
    ...overrides,
  }
}

function guest(overrides: Partial<PageAssociatedGuestDtoItemsItem> = {}): PageAssociatedGuestDtoItemsItem {
  return {
    id: 'q-100',
    kind: 'qemu',
    vmid: 100,
    name: 'web',
    node: 'pve',
    status: 'running',
    agent: { online: true, osName: 'Debian 12', version: '7.0', kernel: null, interfaces: [] },
    candidates: [{ machineId: 'm1', machineName: 'build-host', machineStatus: 'connected', kind: 'mac_match', evidence: 'aa:bb:cc:dd:ee:ff' }],
    warnings: [],
    macs: [],
    observedAt: NOW,
    pveVersion: '8.2.4',
    ...overrides,
  }
}

function device(overrides: Partial<PageCorrelatedDeviceDtoItemsItem> = {}): PageCorrelatedDeviceDtoItemsItem {
  return {
    nodeId: 'ts1',
    name: 'build-host.tailnet',
    hostname: 'build-host',
    os: 'linux',
    addresses: ['100.64.0.1'],
    tags: ['tag:ci'],
    user: 'op',
    online: true,
    lastSeen: '2026-01-01T00:00:00Z',
    candidates: [],
    ...overrides,
  }
}

describe('formatBytes', () => {
  it('formats GB with 0 decimals at 10GB and above', () => {
    expect(formatBytes(10 * 1024 ** 3)).toBe('10GB')
    expect(formatBytes(180 * 1024 ** 3)).toBe('180GB')
  })

  it('formats GB with 1 decimal below 10GB', () => {
    expect(formatBytes(4 * 1024 ** 3)).toBe('4.0GB')
  })

  it('formats TB above 1024 GB', () => {
    expect(formatBytes(2048 * 1024 ** 3)).toBe('2.0TB')
  })

  it('returns null for unknown values', () => {
    expect(formatBytes(null)).toBeNull()
  })
})

describe('specLine', () => {
  it('joins the known facts', () => {
    const built = buildInventory(inventoryInput({ machines: [machine()] }))
    expect(specLine(built.machines[0])).toBe('UBUNTU 24.04 · X86_64 · 8C · 16GB · 180GB FREE')
  })

  it('skips unknown parts', () => {
    const built = buildInventory(inventoryInput({
      machines: [machine({ capabilities: [machine().capabilities[0]] })],
    }))
    expect(specLine(built.machines[0])).toBe('UBUNTU')
  })

  it('falls back to family when no distribution', () => {
    const built = buildInventory(inventoryInput({
      machines: [machine({ capabilities: machine().capabilities.filter(c => c.name !== 'distribution' && c.name !== 'distribution_version') })],
    }))
    expect(specLine(built.machines[0]).startsWith('DEBIAN')).toBe(true)
  })
})

describe('tones', () => {
  it('maps machine statuses', () => {
    expect(machineStatusTone('connected')).toBe('ok')
    expect(machineStatusTone('agentless')).toBe('info')
    expect(machineStatusTone('stale')).toBe('warn')
    expect(machineStatusTone('offline')).toBe('err')
    expect(machineStatusTone('other')).toBe('faint')
  })

  it('maps guest statuses', () => {
    expect(guestStatusTone('running')).toBe('ok')
    expect(guestStatusTone('stopped')).toBe('muted')
    expect(guestStatusTone('paused')).toBe('info')
    expect(guestStatusTone('other')).toBe('faint')
  })
})

describe('relativeTime', () => {
  it('formats seconds, minutes, hours, days', () => {
    expect(relativeTime(NOW - 3000, NOW)).toBe('3S AGO')
    expect(relativeTime(NOW - 12 * 60_000, NOW)).toBe('12M AGO')
    expect(relativeTime(NOW - 2 * 3_600_000, NOW)).toBe('2H AGO')
    expect(relativeTime(NOW - 4 * 86_400_000, NOW)).toBe('4D AGO')
  })

  it('handles null', () => {
    expect(relativeTime(null, NOW)).toBe('NEVER')
  })
})

describe('buildInventory', () => {
  it('counts host guests and templates, excluding templates from guests', () => {
    const built = buildInventory(inventoryInput({
      proxmox: [{ accountId: 'acc1', accountName: 'homelab', confirmed: true, loading: false, discovery: discovery(), guests: null, discoveryError: null, guestsError: null }],
    }))
    expect(built.hosts).toHaveLength(1)
    expect(built.hosts[0].guestCount).toBe(1)
    expect(built.hosts[0].templateCount).toBe(1)
    expect(built.guests).toHaveLength(1)
    expect(built.guests[0].kind).toBe('vm')
  })

  it('enriches guests by accountId+vmid', () => {
    const built = buildInventory(inventoryInput({
      proxmox: [{ accountId: 'acc1', accountName: 'homelab', confirmed: true, loading: false, discovery: discovery(), guests: [guest()], discoveryError: null, guestsError: null }],
    }))
    expect(built.guests[0].osName).toBe('Debian 12')
    expect(built.guests[0].agentOnline).toBe(true)
    expect(built.guests[0].candidates[0].machineName).toBe('build-host')
  })

  it('does not enrich when no guest-list entry matches the discovered vmid', () => {
    const built = buildInventory(inventoryInput({
      proxmox: [{ accountId: 'acc1', accountName: 'homelab', confirmed: true, loading: false, discovery: discovery(), guests: [guest({ vmid: 999 })], discoveryError: null, guestsError: null }],
    }))
    expect(built.guests[0].agentOnline).toBeNull()
    expect(built.guests[0].candidates).toHaveLength(0)
  })

  it('builds machine guestCandidates from guest candidates', () => {
    const built = buildInventory(inventoryInput({
      machines: [machine()],
      proxmox: [{ accountId: 'acc1', accountName: 'homelab', confirmed: true, loading: false, discovery: discovery(), guests: [guest()], discoveryError: null, guestsError: null }],
    }))
    expect(built.machines[0].guestCandidates).toHaveLength(1)
    expect(built.machines[0].guestCandidates[0]).toMatchObject({ accountName: 'homelab', node: 'pve', vmid: 100 })
  })

  it('attaches a correlated tailnet device to the machine and keeps it out of tailnetOnly', () => {
    const built = buildInventory(inventoryInput({
      machines: [machine()],
      tailnet: {
        configured: true,
        loading: false,
        devices: [device({ candidates: [{ machineId: 'm1', machineName: 'build-host', machineStatus: 'connected', reference: '100.64.0.1', kind: 'address_match' }] })],
        error: null,
      },
    }))
    expect(built.machines[0].tailnet).toMatchObject({ online: true, name: 'build-host.tailnet' })
    expect(built.tailnetOnly).toHaveLength(0)
  })

  it('lists uncorrelated devices in tailnetOnly', () => {
    const built = buildInventory(inventoryInput({
      machines: [machine()],
      tailnet: { configured: true, loading: false, devices: [device()], error: null },
    }))
    expect(built.tailnetOnly).toHaveLength(1)
    expect(built.machines[0].tailnet).toBeNull()
  })

  it('a machine never merges with a guest: both appear', () => {
    const built = buildInventory(inventoryInput({
      machines: [machine()],
      proxmox: [{ accountId: 'acc1', accountName: 'homelab', confirmed: true, loading: false, discovery: discovery(), guests: [guest()], discoveryError: null, guestsError: null }],
    }))
    expect(built.machines[0].name).toBe('build-host')
    expect(built.guests[0].name).toBe('web')
  })

  it('marks unconfirmed accounts untrusted with no discovery data', () => {
    const built = buildInventory(inventoryInput({
      machines: [machine()],
      proxmox: [{ accountId: 'acc1', accountName: 'homelab', confirmed: false, loading: false, discovery: null, guests: null, discoveryError: null, guestsError: null }],
    }))
    expect(built.hosts).toHaveLength(0)
    expect(built.sources.find(s => s.key === 'proxmox:acc1')?.state).toBe('untrusted')
  })

  it('propagates a discovery error as a source error', () => {
    const built = buildInventory(inventoryInput({
      machines: [machine()],
      proxmox: [{ accountId: 'acc1', accountName: 'homelab', confirmed: true, loading: false, discovery: null, guests: null, discoveryError: 'unreachable', guestsError: null }],
    }))
    const source = built.sources.find(s => s.key === 'proxmox:acc1')
    expect(source?.state).toBe('error')
    expect(source?.message).toBe('unreachable')
    expect(built.machines).toHaveLength(1)
  })

  it('marks an unconfigured tailnet', () => {
    const built = buildInventory(inventoryInput({
      machines: [machine()],
    }))
    expect(built.sources.find(s => s.key === 'tailnet')?.state).toBe('unconfigured')
    expect(built.tailnetOnly).toHaveLength(0)
  })

  it('marks the machines source as error when machinesError is set', () => {
    const built = buildInventory(inventoryInput({
      machinesError: 'listMachines failed (500)',
    }))
    const source = built.sources.find(s => s.key === 'machines')
    expect(source?.state).toBe('error')
    expect(source?.message).toBe('listMachines failed (500)')
  })

  it('marks a confirmed account with no discovery and no error as loading, not untrusted', () => {
    const built = buildInventory(inventoryInput({
      proxmox: [{ accountId: 'acc1', accountName: 'homelab', confirmed: true, loading: true, discovery: null, guests: null, discoveryError: null, guestsError: null }],
    }))
    const source = built.sources.find(s => s.key === 'proxmox:acc1')
    expect(source?.state).toBe('loading')
    expect(source?.message).toBe('Discovering homelab…')
  })

  it('matches guests to nodes via the node key (node.node)', () => {
    const built = buildInventory(inventoryInput({
      proxmox: [{
        accountId: 'acc1',
        accountName: 'homelab',
        confirmed: true,
        loading: false,
        discovery: discovery({
          resources: [
            { accountId: 'acc1', id: 'node-pve', kind: 'node', name: 'pve', node: 'pve-cluster', status: 'online', vmid: null, observedAt: NOW, pveVersion: '8.2.4' },
            { accountId: 'acc1', id: 'q-100', kind: 'qemu', name: 'web', node: 'pve-cluster', status: 'running', vmid: 100, observedAt: NOW, pveVersion: '8.2.4' },
          ],
        }),
        guests: null,
        discoveryError: null,
        guestsError: null,
      }],
    }))
    expect(built.hosts[0].name).toBe('pve')
    expect(built.hosts[0].guestCount).toBe(1)
    expect(built.guests[0].node).toBe('pve-cluster')
  })
})

describe('buildInventory source honesty', () => {
  it('matches discovery to the right account when an unconfirmed account precedes a confirmed one', () => {
    const built = buildInventory({
      machines: [],
      machinesError: null,
      proxmoxAccountsError: null,
      paginationWarning: null,
      proxmox: [
        { accountId: 'acc-unconfirmed', accountName: 'unconfirmed', confirmed: false, loading: false, discovery: null, guests: null, discoveryError: null, guestsError: null },
        { accountId: 'acc1', accountName: 'homelab', confirmed: true, loading: false, discovery: discovery(), guests: null, discoveryError: null, guestsError: null },
      ],
      tailnet: { configured: false, loading: false, devices: null, error: null },
    })
    expect(built.hosts).toHaveLength(1)
    expect(built.guests).toHaveLength(1)
    expect(built.sources.find(s => s.key === 'proxmox:acc-unconfirmed')?.state).toBe('untrusted')
    expect(built.sources.find(s => s.key === 'proxmox:acc1')?.state).toBe('ok')
  })

  it('keeps hosts and guests when only the guest list fails', () => {
    const built = buildInventory({
      machines: [],
      machinesError: null,
      proxmoxAccountsError: null,
      paginationWarning: null,
      proxmox: [{ accountId: 'acc1', accountName: 'homelab', confirmed: true, loading: false, discovery: discovery(), guests: null, discoveryError: null, guestsError: 'listProxmoxGuests failed (500)' }],
      tailnet: { configured: false, loading: false, devices: null, error: null },
    })
    expect(built.hosts).toHaveLength(1)
    expect(built.guests).toHaveLength(1)
    expect(built.guests[0].agentOnline).toBeNull()
    const source = built.sources.find(s => s.key === 'proxmox:acc1')
    expect(source?.state).toBe('error')
    expect(source?.message).toBe('listProxmoxGuests failed (500)')
  })

  it('emits a proxmox error source when the account list fails', () => {
    const built = buildInventory({
      machines: [],
      machinesError: null,
      proxmoxAccountsError: 'listProxmoxAccounts failed (503)',
      paginationWarning: null,
      proxmox: [],
      tailnet: { configured: false, loading: false, devices: null, error: null },
    })
    const source = built.sources.find(s => s.key === 'proxmox')
    expect(source?.state).toBe('error')
    expect(source?.message).toBe('Proxmox accounts unavailable: listProxmoxAccounts failed (503)')
  })

  it('emits a tailnet error source when the tailnet status call fails', () => {
    const built = buildInventory({
      machines: [],
      machinesError: null,
      proxmoxAccountsError: null,
      paginationWarning: null,
      proxmox: [],
      tailnet: { configured: true, loading: false, devices: null, error: 'Tailnet status unavailable: getTailnetStatus failed (500)' },
    })
    const source = built.sources.find(s => s.key === 'tailnet')
    expect(source?.state).toBe('error')
    expect(source?.message).toBe('Tailnet status unavailable: getTailnetStatus failed (500)')
  })

  it('marks a confirmed account with no data, no error and loading false as an error', () => {
    const built = buildInventory({
      machines: [],
      machinesError: null,
      proxmoxAccountsError: null,
      paginationWarning: null,
      proxmox: [{ accountId: 'acc1', accountName: 'homelab', confirmed: true, loading: false, discovery: null, guests: null, discoveryError: null, guestsError: null }],
      tailnet: { configured: false, loading: false, devices: null, error: null },
    })
    const source = built.sources.find(s => s.key === 'proxmox:acc1')
    expect(source?.state).toBe('error')
    expect(source?.message).toBe('No discovery data returned')
  })

  it('reports a pagination cap warning as a source', () => {
    const built = buildInventory({
      machines: [],
      machinesError: null,
      proxmoxAccountsError: null,
      paginationWarning: 'Machines hit the 20-page safety cap — some machines may be missing.',
      proxmox: [],
      tailnet: { configured: false, loading: false, devices: null, error: null },
    })
    const source = built.sources.find(s => s.key === 'pagination')
    expect(source?.message).toContain('20-page safety cap')
  })
})

describe('cross-account enrichment', () => {
  it('keeps enrichment within each account when two accounts share a vmid', () => {
    const acc2Discovery = discovery({
      accountId: 'acc2',
      resources: [
        { accountId: 'acc2', id: 'node-pve2', kind: 'node', name: 'pve2', node: null, status: 'online', vmid: null, observedAt: NOW, pveVersion: '8.2.4' },
        { accountId: 'acc2', id: 'q-100', kind: 'qemu', name: 'web-acc2', node: 'pve2', status: 'running', vmid: 100, observedAt: NOW, pveVersion: '8.2.4' },
      ],
    })
    const acc1Guest = guest({ vmid: 100, agent: { online: true, osName: 'Debian 12', version: null, kernel: null, interfaces: [] } })
    const acc2Guest = guest({
      id: 'q-100',
      vmid: 100,
      agent: { online: false, osName: 'Ubuntu 24.04', version: null, kernel: null, interfaces: [] },
      candidates: [],
    })
    const built = buildInventory({
      machines: [],
      machinesError: null,
      proxmoxAccountsError: null,
      paginationWarning: null,
      proxmox: [
        { accountId: 'acc1', accountName: 'homelab', confirmed: true, loading: false, discovery: discovery(), guests: [acc1Guest], discoveryError: null, guestsError: null },
        { accountId: 'acc2', accountName: 'remote', confirmed: true, loading: false, discovery: acc2Discovery, guests: [acc2Guest], discoveryError: null, guestsError: null },
      ],
      tailnet: { configured: false, loading: false, devices: null, error: null },
    })
    const webAcc1 = built.guests.find(g => g.accountId === 'acc1')!
    const webAcc2 = built.guests.find(g => g.accountId === 'acc2')!
    expect(webAcc1.agentOnline).toBe(true)
    expect(webAcc1.osName).toBe('Debian 12')
    expect(webAcc1.candidates).toHaveLength(1)
    expect(webAcc2.agentOnline).toBe(false)
    expect(webAcc2.osName).toBe('Ubuntu 24.04')
    expect(webAcc2.candidates).toHaveLength(0)
  })
})

describe('loading flag honesty', () => {
  it('uses the loading flag: true means loading, false with no data means error', () => {
    const loading = buildInventory({
      machines: [],
      machinesError: null,
      proxmoxAccountsError: null,
      paginationWarning: null,
      proxmox: [{ accountId: 'acc1', accountName: 'homelab', confirmed: true, loading: true, discovery: null, guests: null, discoveryError: null, guestsError: null }],
      tailnet: { configured: false, loading: false, devices: null, error: null },
    })
    expect(loading.sources.find(s => s.key === 'proxmox:acc1')?.state).toBe('loading')

    const stalled = buildInventory({
      machines: [],
      machinesError: null,
      proxmoxAccountsError: null,
      paginationWarning: null,
      proxmox: [{ accountId: 'acc1', accountName: 'homelab', confirmed: true, loading: false, discovery: null, guests: null, discoveryError: null, guestsError: null }],
      tailnet: { configured: false, loading: false, devices: null, error: null },
    })
    expect(stalled.sources.find(s => s.key === 'proxmox:acc1')?.state).toBe('error')
  })

  it('shows a loading tailnet source while devices load', () => {
    const built = buildInventory({
      machines: [],
      machinesError: null,
      proxmoxAccountsError: null,
      paginationWarning: null,
      proxmox: [],
      tailnet: { configured: true, loading: true, devices: null, error: null },
    })
    expect(built.sources.find(s => s.key === 'tailnet')?.state).toBe('loading')
  })
})
