import { describe, expect, it } from 'vitest'

import {
  STATUS_ORDER,
  entryId,
  entryName,
  guestLabel,
  holderLink,
  holderTone,
  reasonLabel,
  refreshCommand,
  seenLabel,
  statusTone,
  summarize,
  words,
} from '../hardware'
import { allDevices, device } from './fixtures'

describe('statusTone', () => {
  it('gives every API status its documented tone', () => {
    expect(STATUS_ORDER.map(status => [status, statusTone(status)])).toEqual([
      ['available', 'ok'],
      ['reserved', 'info'],
      ['externally_attached', 'warn'],
      ['missing', 'warn'],
      ['unsupported', 'muted'],
      ['quarantined', 'err'],
    ])
  })

  it('keeps a status this client does not know faint', () => {
    expect(statusTone('something_new')).toBe('faint')
  })
})

describe('holderTone', () => {
  it('reads an undetermined or failed attach as an error', () => {
    expect(holderTone('attach_unknown')).toBe('err')
    expect(holderTone('detach_failed')).toBe('err')
    expect(holderTone('attached')).toBe('ok')
    for (const state of ['held', 'attaching', 'detaching'])
      expect(holderTone(state)).toBe('info')
    expect(holderTone('future_state')).toBe('faint')
  })
})

describe('labels', () => {
  it('spaces underscores out', () => {
    expect(words('externally_attached')).toBe('externally attached')
  })

  it('prefers the API reason text and falls back to the spaced code', () => {
    expect(reasonLabel({ reason: 'no_node_entry', reasonText: 'no entry on any node' })).toBe('no entry on any node')
    expect(reasonLabel({ reason: 'pve_too_old', reasonText: null })).toBe('pve too old')
    expect(reasonLabel({ reason: null, reasonText: null })).toBeNull()
  })

  it('formats a node entry', () => {
    expect(entryId({ vendorId: 'f00d', productId: 'c0de' })).toBe('f00d:c0de')
    expect(entryName({ manufacturer: 'Example Corp', product: 'Test Dongle' })).toBe('Example Corp Test Dongle')
    expect(entryName({ manufacturer: null, product: 'Test Dongle' })).toBe('Test Dongle')
    expect(entryName({ manufacturer: null, product: undefined })).toBeNull()
  })

  it('reports a device that was never seen (0) as NEVER, not as 1970', () => {
    expect(seenLabel(0, 1_000_000)).toBe('NEVER')
    expect(seenLabel(940_000, 1_000_000)).toBe('1M AGO')
  })

  it('names the guest with its slot only when known', () => {
    expect(guestLabel({ accountId: 'a', node: 'pve-a', vmid: 9101, usbSlot: 0 })).toBe('QEMU 9101 · pve-a · usb0')
    expect(guestLabel({ accountId: 'a', node: 'pve-a', vmid: 9101, usbSlot: null })).toBe('QEMU 9101 · pve-a')
  })
})

describe('holderLink', () => {
  it('links a lease owner to its Lab drawer and nothing else', () => {
    expect(holderLink({ ownerKind: 'lease', ownerId: 'lease-1' })).toBe('/lab?lease=lease-1')
    expect(holderLink({ ownerKind: 'machine', ownerId: 'machine-1' })).toBeNull()
  })
})

describe('summarize', () => {
  it('counts the statuses present in API order and the stale flags', () => {
    const summary = summarize(allDevices())
    expect(summary.total).toBe(10)
    expect(summary.byStatus).toEqual([
      { status: 'available', count: 1 },
      { status: 'reserved', count: 2 },
      { status: 'externally_attached', count: 1 },
      { status: 'missing', count: 1 },
      { status: 'unsupported', count: 4 },
      { status: 'quarantined', count: 1 },
    ])
    expect(summary.stale).toBe(2)
  })

  it('lists an unknown status after the known ones and handles an empty list', () => {
    const summary = summarize([device({ status: 'later_status' as never }), device({ id: 'b', status: 'available' })])
    expect(summary.byStatus.map(s => s.status)).toEqual(['available', 'later_status'])
    expect(summarize([])).toEqual({ total: 0, byStatus: [], stale: 0 })
  })
})

describe('refreshCommand', () => {
  it('is the fleetctl equivalent and quotes an unusual account id', () => {
    expect(refreshCommand('acct-1')).toBe('fleetctl hardware refresh --account acct-1 --output json')
    expect(refreshCommand('my account')).toBe(`fleetctl hardware refresh --account 'my account' --output json`)
  })
})
