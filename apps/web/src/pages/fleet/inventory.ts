import type {
  MachineDto,
  PageAssociatedGuestDtoItemsItem,
  PageCorrelatedDeviceDtoItemsItem,
  ProxmoxDiscoveryDto,
  ProxmoxResourceDto,
} from '@frogbyte-io/fleet-api-client'

// localStorage keys for the Fleet page's persisted preferences.
export const VIEW_KEY = 'fleet-console-fleet-view'
export const VIEWS_KEY = 'fleet-console-fleet-views'
export const HIDDEN_KEY = 'fleet-console-hidden-tailnet'

export type Tone = 'ok' | 'info' | 'warn' | 'err' | 'muted' | 'faint'
export type SourceState = 'ok' | 'error' | 'partial' | 'unconfigured' | 'untrusted' | 'loading' | 'warn'

export interface HostItem {
  key: string
  accountId: string
  name: string
  nodeKey: string
  accountName: string
  pveVersion: string
  status: string
  guestCount: number
  templateCount: number
  observedAt: number
}

export interface GuestItem {
  key: string
  accountId: string
  accountName: string
  kind: 'vm' | 'lxc'
  vmid: number | null
  name: string
  node: string
  status: string
  agentOnline: boolean | null
  osName: string | null
  /** Routable addresses the guest agent reported (no loopback or link-local). */
  addresses: string[]
  candidates: { machineId: string, machineName: string, evidence: string }[]
}

export interface MachineItem {
  id: string
  name: string
  status: string
  os: string | null
  arch: string | null
  cpuCores: number | null
  memoryBytes: number | null
  diskFreeBytes: number | null
  endpointKinds: string[]
  tags: string[]
  groups: string[]
  lastSeenAt: number | null
  lastObservation: { collectedAt: number, source: string } | null
  guestCandidates: { accountName: string, node: string, kind: 'vm' | 'lxc', vmid: number | null, evidence: string }[]
  tailnet: { online: boolean | null, name: string, addresses: string[] } | null
}

export interface TailnetItem {
  nodeId: string
  name: string
  hostname: string
  os: string
  addresses: string[]
  tags: string[]
  online: boolean | null
  lastSeen: string | null
}

export interface SourceEntry {
  key: string
  label: string
  state: SourceState
  message: string
}

export interface Inventory {
  hosts: HostItem[]
  guests: GuestItem[]
  machines: MachineItem[]
  rawMachines: MachineDto[]
  tailnetOnly: TailnetItem[]
  sources: SourceEntry[]
}

export interface ProxmoxSourceInput {
  accountId: string
  accountName: string
  confirmed: boolean
  loading: boolean
  discovery: ProxmoxDiscoveryDto | null
  guests: PageAssociatedGuestDtoItemsItem[] | null
  discoveryError: string | null
  guestsError: string | null
  discoveryWarnings: string[] | null
}

export interface InventoryInput {
  machines: MachineDto[]
  machinesError: string | null
  proxmoxAccountsError: string | null
  proxmox: ProxmoxSourceInput[]
  tailnet: { configured: boolean, loading: boolean, devices: PageCorrelatedDeviceDtoItemsItem[] | null, error: string | null }
  paginationWarning: string | null
}

export function formatBytes(n: number | null): string | null {
  if (n === null || !Number.isFinite(n))
    return null
  const gb = n / (1024 ** 3)
  if (gb >= 1024)
    return `${(gb / 1024).toFixed(1)}TB`
  if (gb >= 10)
    return `${Math.round(gb)}GB`
  return `${gb.toFixed(1)}GB`
}

function fact(machine: MachineDto, namespace: string, name: string): string | null {
  const found = machine.capabilities.find(
    c => c.namespace === namespace && c.name === name && (c.status === 'known' || c.status === 'stale'),
  )
  return found?.value ?? null
}

export function resourcesLine(machine: MachineItem): string | null {
  const parts: string[] = []
  if (machine.cpuCores !== null)
    parts.push(`${machine.cpuCores}C`)
  const mem = formatBytes(machine.memoryBytes)
  if (mem)
    parts.push(mem)
  const disk = formatBytes(machine.diskFreeBytes)
  if (disk)
    parts.push(`${disk} FREE`)
  return parts.length > 0 ? parts.join(' · ').toUpperCase() : null
}

export function osLine(machine: MachineItem): string | null {
  const parts: string[] = []
  if (machine.os)
    parts.push(machine.os)
  if (machine.arch)
    parts.push(machine.arch)
  return parts.length > 0 ? parts.join(' · ').toUpperCase() : null
}

export function specLine(machine: MachineItem): string {
  const os = osLine(machine)
  const resources = resourcesLine(machine)
  const parts: string[] = []
  if (os)
    parts.push(os)
  if (resources)
    parts.push(resources)
  return parts.join(' · ').toUpperCase()
}

export function guestAgentLabel(agentOnline: boolean | null): string {
  if (agentOnline === null)
    return 'UNKNOWN (NO AGENT DATA)'
  return agentOnline ? 'ONLINE' : 'OFFLINE'
}

export function machineStatusTone(status: string): Tone {
  switch (status) {
    case 'connected':
      return 'ok'
    case 'stale':
      return 'warn'
    case 'offline':
      return 'err'
    case 'agentless':
      return 'info'
    default:
      return 'faint'
  }
}

export function guestStatusTone(status: string): Tone {
  switch (status) {
    case 'running':
      return 'ok'
    case 'stopped':
      return 'muted'
    case 'paused':
      return 'info'
    default:
      return 'faint'
  }
}

export function hostStatusTone(status: string): Tone {
  if (status === 'online')
    return 'ok'
  if (status === 'offline')
    return 'err'
  return 'faint'
}

export function hostStatusLabel(status: string): string {
  if (status === 'unknown')
    return 'UNKNOWN'
  return status.toUpperCase()
}

export function tailnetStatusLabel(online: boolean | null): string {
  if (online === null)
    return 'UNKNOWN'
  return online ? 'ONLINE' : 'OFFLINE'
}

export function guestAgentCell(agentOnline: boolean | null): string {
  if (agentOnline === null)
    return '—'
  return agentOnline ? 'ONLINE' : 'OFFLINE'
}

export function relativeTime(ms: number | null, now: number = Date.now()): string {
  if (ms === null || !Number.isFinite(ms))
    return 'NEVER'
  const delta = Math.max(0, now - ms)
  const seconds = Math.floor(delta / 1000)
  if (seconds < 60)
    return `${seconds}S AGO`
  const minutes = Math.floor(seconds / 60)
  if (minutes < 60)
    return `${minutes}M AGO`
  const hours = Math.floor(minutes / 60)
  if (hours < 24)
    return `${hours}H AGO`
  const days = Math.floor(hours / 24)
  return `${days}D AGO`
}

function isGuestKind(kind: string): boolean {
  return kind === 'qemu' || kind === 'lxc'
}

function buildHosts(resources: ProxmoxResourceDto[], accountId: string, accountName: string): HostItem[] {
  const nodes = resources.filter(r => r.kind === 'node')
  return nodes.map((node) => {
    const nodeKey = node.node ?? node.name
    const onNode = resources.filter(r => r.node === nodeKey)
    return {
      key: `${accountId}:${node.id}`,
      accountId,
      name: node.name ?? nodeKey ?? node.id,
      nodeKey: nodeKey ?? node.id,
      accountName,
      pveVersion: node.pveVersion,
      status: node.status ?? 'unknown',
      guestCount: onNode.filter(r => isGuestKind(r.kind)).length,
      templateCount: onNode.filter(r => r.kind === 'qemu-template').length,
      observedAt: node.observedAt,
    }
  })
}

function guestAddresses(guest: PageAssociatedGuestDtoItemsItem | undefined): string[] {
  const all = (guest?.agent?.interfaces ?? []).flatMap(i => i.addresses.map(a => a.split('/')[0]!))
  return [...new Set(all.filter(a => a && !/^(127\.|::1$|fe80:|169\.254\.)/i.test(a)))]
}

function buildGuests(
  resources: ProxmoxResourceDto[],
  guests: PageAssociatedGuestDtoItemsItem[] | null,
  accountId: string,
  accountName: string,
): GuestItem[] {
  const discovered = resources.filter(r => isGuestKind(r.kind))
  const byVmid = new Map<number, PageAssociatedGuestDtoItemsItem>()
  if (guests) {
    for (const g of guests) {
      if (g.vmid !== null && g.vmid !== undefined)
        byVmid.set(g.vmid, g)
    }
  }
  return discovered.map((resource) => {
    const enriched = resource.vmid !== null && resource.vmid !== undefined ? byVmid.get(resource.vmid) : undefined
    const kind: 'vm' | 'lxc' = resource.kind === 'lxc' ? 'lxc' : 'vm'
    return {
      key: `${accountId}:${resource.id}`,
      accountId,
      accountName,
      kind,
      vmid: resource.vmid ?? null,
      name: resource.name ?? (resource.vmid !== null && resource.vmid !== undefined ? `VMID ${resource.vmid}` : resource.id),
      node: resource.node ?? '—',
      status: resource.status ?? 'unknown',
      agentOnline: enriched?.agent ? enriched.agent.online : null,
      osName: enriched?.agent?.osName ?? null,
      addresses: guestAddresses(enriched),
      candidates: (enriched?.candidates ?? []).map(c => ({
        machineId: c.machineId,
        machineName: c.machineName,
        evidence: c.evidence,
      })),
    }
  })
}

function buildMachines(
  machines: MachineDto[],
  proxmox: ProxmoxSourceInput[],
  devices: PageCorrelatedDeviceDtoItemsItem[] | null,
): MachineItem[] {
  const guestCandidatesByMachine = new Map<string, MachineItem['guestCandidates']>()
  for (const source of proxmox) {
    if (!source.guests)
      continue
    for (const guest of source.guests) {
      const kind: 'vm' | 'lxc' = guest.kind === 'lxc' ? 'lxc' : 'vm'
      for (const candidate of guest.candidates) {
        const list = guestCandidatesByMachine.get(candidate.machineId) ?? []
        list.push({
          accountName: source.accountName,
          node: guest.node ?? '—',
          kind,
          vmid: guest.vmid ?? null,
          evidence: candidate.evidence,
        })
        guestCandidatesByMachine.set(candidate.machineId, list)
      }
    }
  }

  const tailnetByMachine = new Map<string, PageCorrelatedDeviceDtoItemsItem>()
  if (devices) {
    for (const device of devices) {
      for (const candidate of device.candidates) {
        if (!tailnetByMachine.has(candidate.machineId))
          tailnetByMachine.set(candidate.machineId, device)
      }
    }
  }

  return machines.map((machine) => {
    const distribution = fact(machine, 'os', 'distribution')
    const distributionVersion = fact(machine, 'os', 'distribution_version')
    const family = fact(machine, 'os', 'family')
    const coresRaw = fact(machine, 'hardware', 'cpu_cores')
    const cores = coresRaw !== null ? Number.parseInt(coresRaw, 10) : null
    const memoryRaw = fact(machine, 'hardware', 'memory_bytes')
    const diskRaw = fact(machine, 'hardware', 'disk_free_bytes')
    const tailnetDevice = tailnetByMachine.get(machine.id) ?? null
    return {
      id: machine.id,
      name: machine.name,
      status: machine.machineStatus,
      os: distribution ? (distributionVersion ? `${distribution} ${distributionVersion}` : distribution) : family,
      arch: fact(machine, 'host', 'architecture'),
      cpuCores: cores !== null && Number.isFinite(cores) ? cores : null,
      memoryBytes: memoryRaw !== null ? Number.parseInt(memoryRaw, 10) : null,
      diskFreeBytes: diskRaw !== null ? Number.parseInt(diskRaw, 10) : null,
      endpointKinds: [...new Set(machine.endpoints.map(e => e.kind))],
      tags: machine.tags,
      groups: machine.groups,
      lastSeenAt: machine.lastSeenAt ?? null,
      lastObservation: machine.lastObservation
        ? { collectedAt: machine.lastObservation.collectedAt, source: machine.lastObservation.source }
        : null,
      guestCandidates: guestCandidatesByMachine.get(machine.id) ?? [],
      tailnet: tailnetDevice
        ? {
            online: tailnetDevice.online ?? null,
            name: tailnetDevice.name,
            addresses: tailnetDevice.addresses,
          }
        : null,
    }
  })
}

export function buildInventory(input: InventoryInput): Inventory {
  const sources: SourceEntry[] = []
  const hosts: HostItem[] = []
  const guests: GuestItem[] = []

  sources.push({
    key: 'machines',
    label: 'Machines',
    state: input.machinesError ? 'error' : 'ok',
    message: input.machinesError ?? '',
  })

  if (input.proxmoxAccountsError) {
    sources.push({
      key: 'proxmox',
      label: 'Proxmox',
      state: 'error',
      message: `Proxmox accounts unavailable: ${input.proxmoxAccountsError}`,
    })
  }

  for (const source of input.proxmox) {
    const key = `proxmox:${source.accountId}`
    const label = `Proxmox account ${source.accountName}`
    if (!source.confirmed) {
      sources.push({
        key,
        label,
        state: 'untrusted',
        message: 'TLS fingerprint not confirmed — confirm it to discover guests.',
      })
      continue
    }
    if (source.discovery) {
      hosts.push(...buildHosts(source.discovery.resources, source.accountId, source.accountName))
      guests.push(...buildGuests(source.discovery.resources, source.guests, source.accountId, source.accountName))
      if (source.guestsError) {
        sources.push({
          key,
          label,
          state: 'error',
          message: source.guestsError,
        })
      }
      else if (source.discoveryWarnings && source.discoveryWarnings.length > 0) {
        sources.push({
          key,
          label,
          state: 'partial',
          message: `${source.accountName}: discovery returned ${source.discoveryWarnings.length} warning(s) — some resources may be missing: ${source.discoveryWarnings[0]}`,
        })
      }
      else {
        sources.push({
          key,
          label,
          state: 'ok',
          message: '',
        })
      }
    }
    else if (source.discoveryError) {
      sources.push({
        key,
        label,
        state: 'error',
        message: source.discoveryError,
      })
    }
    else if (source.loading) {
      sources.push({
        key,
        label,
        state: 'loading',
        message: `Discovering ${source.accountName}…`,
      })
    }
    else {
      sources.push({
        key,
        label,
        state: 'error',
        message: 'No discovery data returned',
      })
    }
  }

  let tailnetOnly: TailnetItem[] = []
  if (input.tailnet.error) {
    sources.push({
      key: 'tailnet',
      label: 'Tailnet',
      state: 'error',
      message: input.tailnet.error,
    })
  }
  else if (!input.tailnet.configured) {
    sources.push({
      key: 'tailnet',
      label: 'Tailnet',
      state: 'unconfigured',
      message: 'Tailnet not configured — configure it in Settings to see tailnet devices.',
    })
  }
  else if (input.tailnet.devices) {
    tailnetOnly = input.tailnet.devices
      .filter(device => device.candidates.length === 0)
      .map(device => ({
        nodeId: device.nodeId,
        name: device.name,
        hostname: device.hostname,
        os: device.os,
        addresses: device.addresses,
        tags: device.tags,
        online: device.online ?? null,
        lastSeen: device.lastSeen ?? null,
      }))
    sources.push({
      key: 'tailnet',
      label: 'Tailnet',
      state: 'ok',
      message: '',
    })
  }
  else if (input.tailnet.loading) {
    sources.push({
      key: 'tailnet',
      label: 'Tailnet',
      state: 'loading',
      message: 'Loading tailnet devices…',
    })
  }
  else {
    sources.push({
      key: 'tailnet',
      label: 'Tailnet',
      state: 'error',
      message: 'No tailnet device data returned.',
    })
  }

  if (input.paginationWarning) {
    sources.push({
      key: 'pagination',
      label: 'Pagination',
      state: 'warn' as SourceState,
      message: input.paginationWarning,
    })
  }

  const machines = buildMachines(input.machines, input.proxmox, input.tailnet.devices)

  return { hosts, guests, machines, rawMachines: input.machines, tailnetOnly, sources }
}
