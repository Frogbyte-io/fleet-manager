// Pure helpers for the Hardware page: status tones, labels and summaries.
// No Vue imports, so the rules here are unit-tested directly. The controller
// decides every status and reason (ADR 0019); nothing here derives one. The
// page shows what `GET /hardware/devices` and `POST /hardware/refresh` report,
// which is also what `fleetctl hardware list|refresh --output json` prints.

import type {
  HardwareDeviceDto,
  HardwareEntryDto,
  HardwareGuestDto,
  HardwareHolderDto,
} from '@frogbyte-io/fleet-api-client'

import { relativeTime, type Tone } from '../fleet/inventory'
import { shellQuote } from '../machine/fleetctl'

/** The API's device statuses, in the order the summary lists them. */
export const STATUS_ORDER = [
  'available',
  'reserved',
  'externally_attached',
  'missing',
  'unsupported',
  'quarantined',
] as const

/** Status tone (DESIGN.md §3 vocabulary). An unknown status stays faint. */
export function statusTone(status: string): Tone {
  switch (status) {
    case 'available': return 'ok'
    case 'reserved': return 'info'
    case 'externally_attached':
    case 'missing': return 'warn'
    case 'unsupported': return 'muted'
    case 'quarantined': return 'err'
    default: return 'faint'
  }
}

/** `externally_attached` -> `externally attached`; the chip uppercases it. */
export function words(value: string): string {
  return value.replaceAll('_', ' ')
}

/**
 * The reservation states a holder reports. `attach_unknown` and
 * `detach_failed` wait for the reconciler or an operator, so they read as errors.
 */
export function holderTone(state: string): Tone {
  switch (state) {
    case 'attached': return 'ok'
    case 'held':
    case 'attaching':
    case 'detaching': return 'info'
    case 'attach_unknown':
    case 'detach_failed': return 'err'
    default: return 'faint'
  }
}

/** The reason in words: the API's own text, else its code spaced out. */
export function reasonLabel(device: Pick<HardwareDeviceDto, 'reason' | 'reasonText'>): string | null {
  if (device.reasonText)
    return device.reasonText
  return device.reason ? words(device.reason) : null
}

/** `vendor:product` identity of one node entry. */
export function entryId(entry: Pick<HardwareEntryDto, 'vendorId' | 'productId'>): string {
  return `${entry.vendorId}:${entry.productId}`
}

/** The manufacturer and product strings, when the node inventory was readable. */
export function entryName(entry: Pick<HardwareEntryDto, 'manufacturer' | 'product'>): string | null {
  const name = [entry.manufacturer, entry.product].filter(part => !!part).join(' ')
  return name || null
}

/** `0` means never seen (the API also reads it as stale). */
export function seenLabel(at: number, now: number): string {
  return at > 0 ? relativeTime(at, now) : 'NEVER'
}

/** `QEMU 9001 · pve-a · usb0`: the guest a reservation targets. */
export function guestLabel(guest: HardwareGuestDto): string {
  const slot = guest.usbSlot != null ? ` · usb${guest.usbSlot}` : ''
  return `QEMU ${guest.vmid} · ${guest.node}${slot}`
}

/** A lease owner opens in the Lab page; a machine owner has no verified route. */
export function holderLink(holder: Pick<HardwareHolderDto, 'ownerKind' | 'ownerId'>): string | null {
  return holder.ownerKind === 'lease' ? `/lab?lease=${encodeURIComponent(holder.ownerId)}` : null
}

export interface Summary {
  total: number
  byStatus: { status: string, count: number }[]
  stale: number
}

/** Counts per status (those present, API order first) and how many are stale. */
export function summarize(devices: HardwareDeviceDto[]): Summary {
  const counts = new Map<string, number>()
  for (const device of devices)
    counts.set(device.status, (counts.get(device.status) ?? 0) + 1)
  const known = STATUS_ORDER.filter(status => counts.has(status))
  const unknown = [...counts.keys()].filter(status => !(STATUS_ORDER as readonly string[]).includes(status))
  return {
    total: devices.length,
    byStatus: [...known, ...unknown].map(status => ({ status, count: counts.get(status)! })),
    stale: devices.filter(device => device.stale).length,
  }
}

/** The `fleetctl` equivalents (crates/fleetctl `hardware`). */
export const LIST_COMMAND = 'fleetctl hardware list --output json'

export function refreshCommand(accountId: string): string {
  return ['fleetctl', 'hardware', 'refresh', '--account', accountId, '--output', 'json'].map(shellQuote).join(' ')
}
