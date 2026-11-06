import type {
  HardwareDeviceDto,
  HardwareEntryDto,
  HardwareHolderDto,
  HardwareRefreshDto,
  ProxmoxAccountDto,
} from '@frogbyte-io/fleet-api-client'

import accountsJson from './real/accounts.json'
import listJson from './real/list.json'
import listDeniedJson from './real/list-denied-403.json'
import oldRefreshJson from './real/old-refresh.json'
import refreshDeniedJson from './real/refresh-denied-403.json'
import refreshJson from './real/refresh-second.json'
import unwiredJson from './real/unwired-503.json'

// The `real/*.json` files are the answers of a real controller router (the
// hardware routes, the SQLite store and the account routes of this repository)
// over the scripted Proxmox of `crates/fleet-controller/tests/hardware_inventory.rs`,
// captured over HTTP: `GET /hardware/devices` after two refreshes with one lease
// and one machine reservation, the `POST /hardware/refresh` answer of the same
// state, the answer for an account whose Proxmox predates USB mappings, the
// account list, and the 403 and 503 envelopes. Everything in them is invented
// by that test (`fm-*` mappings, `aaaa:0001`, the documentation address range).
// The builders below are synthetic and only fill the cases that capture did not
// produce; each is named for what it adds.

export const MINUTE = 60_000

export const REAL_DEVICES = listJson.items as unknown as HardwareDeviceDto[]

/** Two minutes after the capture, so relative times read the way they did live. */
export const REAL_NOW = Math.max(...REAL_DEVICES.map(device => device.updatedAt)) + 2 * MINUTE

export const LAB_ACCOUNT = REAL_DEVICES[0]!.accountId
const ACCOUNTS = accountsJson.items as unknown as ProxmoxAccountDto[]
/** The account of the capture that has no device (nothing has refreshed it). */
export const SPARE_ACCOUNT = ACCOUNTS.find(account => account.id !== LAB_ACCOUNT)!.id
export const LAB_ACCOUNT_NAME = ACCOUNTS.find(account => account.id === LAB_ACCOUNT)!.name
export const SPARE_ACCOUNT_NAME = ACCOUNTS.find(account => account.id === SPARE_ACCOUNT)!.name

export function realDevices(): HardwareDeviceDto[] {
  return structuredClone(REAL_DEVICES)
}

export function realDevice(mappingId: string): HardwareDeviceDto {
  return structuredClone(REAL_DEVICES.find(device => device.mappingId === mappingId)!)
}

/** Both captured accounts plus one synthetic account whose certificate is not pinned. */
export function accounts(): ProxmoxAccountDto[] {
  return [
    ...structuredClone(ACCOUNTS),
    { id: 'acct-example-unpinned', name: 'unpinned-cluster', fingerprintState: 'unconfirmed' } as ProxmoxAccountDto,
  ]
}

/** The captured refresh of the lab account (devices carry their `observation`). */
export function realRefresh(): HardwareRefreshDto {
  return structuredClone(refreshJson.data) as unknown as HardwareRefreshDto
}

/** The captured refresh of the account whose Proxmox predates USB mappings. */
export function oldRefresh(): HardwareRefreshDto {
  return structuredClone(oldRefreshJson.data) as unknown as HardwareRefreshDto
}

export const LIST_DENIED = { status: 403, data: listDeniedJson, headers: new Headers() }
export const REFRESH_DENIED = { status: 403, data: refreshDeniedJson, headers: new Headers() }
export const UNWIRED = { status: 503, data: unwiredJson, headers: new Headers() }

// ---- synthetic builders ------------------------------------------------------

export function entry(overrides: Partial<HardwareEntryDto> = {}, now = REAL_NOW): HardwareEntryDto {
  return {
    node: 'pve',
    vendorId: 'f00d',
    productId: 'c0de',
    usbpath: '1-4',
    manufacturer: 'Example Corp',
    product: 'Test Dongle',
    lastSeenAt: now - 2 * MINUTE,
    ...overrides,
  }
}

export function holder(overrides: Partial<HardwareHolderDto> = {}, now = REAL_NOW): HardwareHolderDto {
  return {
    reservationId: 'resv-0001-example',
    ownerKind: 'lease',
    ownerId: 'lease-ready-0001',
    state: 'attached',
    guest: { accountId: LAB_ACCOUNT, node: 'pve', vmid: 9101, usbSlot: 0 },
    reservedAt: now - 20 * MINUTE,
    ...overrides,
  }
}

/** A synthetic device, for what the capture did not produce (a seen device that went stale, a held device with pending changes). */
export function device(overrides: Partial<HardwareDeviceDto> = {}, now = REAL_NOW): HardwareDeviceDto {
  return {
    id: 'hw-synthetic-0001',
    accountId: LAB_ACCOUNT,
    mappingId: 'synthetic-dongle',
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
    createdAt: now - 3 * 24 * 60 * MINUTE,
    updatedAt: now - 2 * MINUTE,
    ...overrides,
  }
}
