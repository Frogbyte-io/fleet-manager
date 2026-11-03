import type {
  HardwareDeviceDto,
  HardwareEntryDto,
  HardwareHolderDto,
  HardwareRefreshDto,
  ProxmoxAccountDto,
} from '@frogbyte-io/fleet-api-client'

// Invented data only: no real serial, hostname, IP, account or token. The
// shapes follow the OpenAPI document (`HardwareDeviceDto`), which is also what
// `fleetctl hardware list --output json` prints. Shared by the component tests
// and by the screenshot fixture server.

export const ACCOUNT_A = 'acct-example-a'
export const ACCOUNT_B = 'acct-example-b'

const MINUTE = 60_000
const HOUR = 60 * MINUTE

export function entry(overrides: Partial<HardwareEntryDto> = {}, now = Date.now()): HardwareEntryDto {
  return {
    node: 'pve-a',
    vendorId: 'f00d',
    productId: 'c0de',
    usbpath: '1-4',
    manufacturer: 'Example Corp',
    product: 'Test Dongle',
    lastSeenAt: now - 2 * MINUTE,
    ...overrides,
  }
}

export function holder(overrides: Partial<HardwareHolderDto> = {}, now = Date.now()): HardwareHolderDto {
  return {
    reservationId: 'resv-0001-example',
    ownerKind: 'lease',
    ownerId: 'lease-ready-0001',
    state: 'attached',
    guest: { accountId: ACCOUNT_A, node: 'pve-a', vmid: 9101, usbSlot: 0 },
    reservedAt: now - 20 * MINUTE,
    ...overrides,
  }
}

export function device(overrides: Partial<HardwareDeviceDto> = {}, now = Date.now()): HardwareDeviceDto {
  return {
    id: 'hw-0001',
    accountId: ACCOUNT_A,
    mappingId: 'test-dongle-1',
    kind: 'usb',
    status: 'available',
    reason: null,
    reasonText: null,
    stale: false,
    observedAt: now - 2 * MINUTE,
    entries: [entry({}, now)],
    holder: null,
    note: null,
    observation: null,
    createdAt: now - 3 * 24 * HOUR,
    updatedAt: now - 2 * MINUTE,
    ...overrides,
  }
}

/** One device per API status and per unsupported reason, plus the stale flag. */
export function allDevices(now = Date.now()): HardwareDeviceDto[] {
  return [
    device({ id: 'hw-01', mappingId: 'bench-dongle-a', status: 'available' }, now),
    device({
      id: 'hw-02',
      mappingId: 'bench-dongle-b',
      status: 'reserved',
      holder: holder({}, now),
      entries: [entry({ usbpath: '1-5', lastSeenAt: now - MINUTE }, now)],
    }, now),
    device({
      id: 'hw-03',
      mappingId: 'shared-reader',
      status: 'reserved',
      holder: holder({ ownerKind: 'machine', ownerId: 'machine-example-01', state: 'held', guest: null }, now),
      entries: [entry({ vendorId: 'beef', productId: '0042', usbpath: null, manufacturer: null, product: null }, now)],
    }, now),
    device({
      id: 'hw-04',
      mappingId: 'hand-attached',
      status: 'externally_attached',
      entries: [entry({ usbpath: '2-1' }, now)],
      observation: {
        externalReferences: [
          { node: 'pve-a', vmid: 9200, guestName: 'scratch-vm', slot: 'usb1', template: false, pending: null },
        ],
        notes: [],
      },
    }, now),
    device({
      id: 'hw-05',
      mappingId: 'unplugged-board',
      status: 'missing',
      stale: true,
      observedAt: now - 3 * 24 * HOUR,
      updatedAt: now - 3 * 24 * HOUR,
      entries: [entry({ usbpath: '3-2', lastSeenAt: now - 3 * 24 * HOUR }, now)],
    }, now),
    device({
      id: 'hw-06',
      mappingId: 'no-node-mapping',
      status: 'unsupported',
      reason: 'no_node_entry',
      reasonText: 'the mapping has no entry for any node',
      stale: true,
      observedAt: 0,
      entries: [],
    }, now),
    device({
      id: 'hw-07',
      mappingId: 'token-limited',
      status: 'unsupported',
      reason: 'token_lacks_mapping_use',
      reasonText: 'the API token lacks Mapping.Use on this mapping',
      entries: [entry({ usbpath: '1-8' }, now)],
    }, now),
    device({
      id: 'hw-08',
      mappingId: 'twin-readers',
      status: 'unsupported',
      reason: 'ambiguous_mapping',
      reasonText: 'more than one device on the node matches this mapping',
      entries: [entry({ vendorId: 'f00d', productId: '0001', usbpath: null }, now)],
    }, now),
    device({
      id: 'hw-09',
      mappingId: 'stuck-attach',
      status: 'quarantined',
      holder: holder({ state: 'attach_unknown', ownerId: 'lease-cleanup-0002', guest: { accountId: ACCOUNT_A, node: 'pve-b', vmid: 9102, usbSlot: 1 } }, now),
      entries: [entry({ node: 'pve-b', usbpath: '1-2' }, now)],
    }, now),
    device({
      id: 'hw-10',
      mappingId: 'pve-eight-device',
      accountId: ACCOUNT_B,
      status: 'unsupported',
      reason: 'pve_too_old',
      reasonText: 'the PVE predates USB resource mappings',
      entries: [],
    }, now),
  ]
}

export function accounts(): ProxmoxAccountDto[] {
  return [
    { id: ACCOUNT_A, name: 'lab-cluster-a', fingerprintState: 'confirmed' },
    { id: ACCOUNT_B, name: 'lab-cluster-b', fingerprintState: 'confirmed' },
    { id: 'acct-example-c', name: 'unpinned-cluster', fingerprintState: 'unconfirmed' },
  ] as ProxmoxAccountDto[]
}

export function refreshReport(accountId: string, devices: HardwareDeviceDto[], now = Date.now()): HardwareRefreshDto {
  return {
    accountId,
    observedAt: now,
    pveVersion: '9.0.0',
    support: { state: 'supported', reason: null, detail: null },
    guestScan: { listed: 12, read: 11, unreadable: 1, truncated: false },
    devices: devices.filter(d => d.accountId === accountId),
    warnings: ['one guest config could not be read; a device it references may read as unsupported'],
  }
}
