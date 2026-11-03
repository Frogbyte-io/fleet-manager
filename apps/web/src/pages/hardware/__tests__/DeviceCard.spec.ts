import { mount } from '@vue/test-utils'
import { createMemoryHistory, createRouter } from 'vue-router'
import { describe, expect, it } from 'vitest'

import type { HardwareDeviceDto } from '@frogbyte-io/fleet-api-client'

import DeviceCard from '../components/DeviceCard.vue'
import { sessionObservation, type SessionObservation } from '../hardware'
import { MINUTE, REAL_NOW, device, oldRefresh, realDevice, realRefresh } from './fixtures'

const router = createRouter({ history: createMemoryHistory(), routes: [{ path: '/:p(.*)*', component: { template: '<div />' } }] })

function render(dto: HardwareDeviceDto, observation: SessionObservation | null = null) {
  return mount(DeviceCard, {
    props: { device: dto, accountName: 'lab-cluster-a', now: REAL_NOW, observation },
    global: { plugins: [router] },
  })
}

const refreshed = (mapping: string) => realRefresh().devices.find(d => d.mappingId === mapping)!
const observed = (mapping: string, listed = realDevice(mapping)) =>
  sessionObservation(listed, refreshed(mapping), REAL_NOW - MINUTE)

// The `fm-*` devices are the real capture of every status (see fixtures.ts).
describe('DeviceCard statuses', () => {
  const CASES: [string, string, string][] = [
    ['fm-h', 'available', 'text-fc-ok'],
    ['fm-a', 'reserved', 'text-fc-info'],
    ['fm-b', 'externally attached', 'text-fc-warn'],
    ['fm-c', 'missing', 'text-fc-warn'],
    ['fm-f', 'unsupported', 'text-fc-muted'],
    ['fm-g', 'quarantined', 'text-fc-err'],
  ]

  it.each(CASES)('%s shows the %s chip with its tone', (mapping, label, tone) => {
    const w = render(realDevice(mapping))
    const chip = w.get('[data-testid="status"]')
    expect(chip.text().toLowerCase()).toBe(label)
    expect(chip.classes()).toContain(tone)
    expect(w.attributes('data-status')).toBe(realDevice(mapping).status)
  })

  it('shows no reason block for a status that has none', () => {
    expect(render(realDevice('fm-h')).find('[data-testid="reason"]').exists()).toBe(false)
  })
})

describe('DeviceCard unsupported reasons', () => {
  it.each([
    ['fm-d', 'no_node_entry'],
    ['fm-e', 'ambiguous_mapping'],
    ['fm-f', 'token_lacks_mapping_use'],
  ])('%s shows the API reason code verbatim and the API text beside it', (mapping, code) => {
    const dto = realDevice(mapping)
    const w = render(dto)
    expect(w.get('[data-testid="reason-code"]').text()).toBe(code)
    expect(w.get('[data-testid="reason-text"]').text()).toBe(dto.reasonText)
  })

  it('shows pve_too_old as the controller reported it for an old Proxmox', () => {
    const dto = oldRefresh().devices[0]!
    const w = render(dto)
    expect(w.get('[data-testid="reason-code"]').text()).toBe('pve_too_old')
    expect(w.get('[data-testid="reason-text"]').text()).toBe('this Proxmox VE predates USB resource mappings')
  })

  it('still names an unsupported device whose API text is missing', () => {
    const w = render(device({ status: 'unsupported', reason: 'usb_inventory_unreadable', reasonText: null }))
    expect(w.get('[data-testid="reason-code"]').text()).toBe('usb_inventory_unreadable')
    expect(w.get('[data-testid="reason-text"]').text()).toBe('usb inventory unreadable')
  })
})

describe('DeviceCard stale and observed', () => {
  it('shows STALE for the device the API reports stale and not for a fresh one', () => {
    expect(realDevice('fm-c').stale).toBe(true)
    expect(render(realDevice('fm-c')).get('[data-testid="stale"]').text().toLowerCase()).toBe('stale')
    expect(render(realDevice('fm-a')).find('[data-testid="stale"]').exists()).toBe(false)
  })

  it('shows a seen device that went stale with how long ago it was observed', () => {
    const aged = device({ status: 'missing', stale: true, observedAt: REAL_NOW - 3 * 24 * 60 * MINUTE })
    const w = render(aged)
    expect(w.find('[data-testid="stale"]').exists()).toBe(true)
    expect(w.get('[data-testid="observed"]').text()).toBe('Observed 3D AGO')
  })

  it('reads an entry that was never seen as never observed', () => {
    expect(render(realDevice('fm-c')).get('[data-testid="observed"]').text()).toBe('Observed NEVER')
  })

  it('labels a device with no node entry as last changed, never as observed', () => {
    const w = render(realDevice('fm-d'))
    const text = w.get('[data-testid="observed"]').text()
    expect(text).toBe('Last changed 2M AGO')
    expect(text).not.toContain('Observed')
    expect(w.get('[data-testid="no-entries"]').text()).toContain('No node entry')
    expect(w.get('footer').text()).not.toContain('updated')
  })

  it('shows observed and updated for a device a node reported', () => {
    expect(render(realDevice('fm-a')).get('footer').text()).toBe('Observed 2M AGO · updated 2M AGO')
  })
})

describe('DeviceCard session observation', () => {
  it('dates what the refresh found and lists the guests that reference the mapping', () => {
    const w = render(realDevice('fm-b'), observed('fm-b'))
    const block = w.get('[data-testid="observation"]')
    expect(block.text()).toContain('Found by the refresh 1M AGO')
    const reference = w.get('[data-testid="external-reference"]').text()
    expect(reference).toContain('QEMU 200')
    expect(reference).toContain('guest-a')
    expect(reference).toContain('usb0')
    expect(w.get('[data-testid="observation-note"]').text()).toContain('id-only')
  })

  it('shows only a notice, not the old detail, once the list no longer agrees', () => {
    const listed = { ...realDevice('fm-b'), status: 'available' as const }
    const w = render(listed, observed('fm-b', listed))
    expect(w.get('[data-testid="observation-superseded"]').text()).toContain('The list has changed since that refresh')
    expect(w.find('[data-testid="external-reference"]').exists()).toBe(false)
    expect(w.find('[data-testid="observation-note"]').exists()).toBe(false)
  })

  it('shows no observation block for a list entry (observation is null)', () => {
    expect(render(realDevice('fm-h')).find('[data-testid="observation"]').exists()).toBe(false)
  })

  it('shows no block for a refresh that found nothing to add', () => {
    expect(render(realDevice('fm-h'), observed('fm-h')).find('[data-testid="observation"]').exists()).toBe(false)
  })
})

describe('DeviceCard holder', () => {
  it('links a lease holder to the Lab drawer and shows its guest and reservation state', () => {
    const dto = realDevice('fm-a')
    const w = render(dto)
    expect(w.get('[data-testid="holder-link"]').attributes('href')).toBe(`/lab?lease=${dto.holder!.ownerId}`)
    expect(w.get('[data-testid="holder-state"]').text().toLowerCase()).toBe('attached')
    expect(w.get('[data-testid="holder-guest"]').text()).toBe('QEMU 9101 · pve · usb0')
  })

  it('links a machine holder to its machine page and shows an attach_unknown reservation as an error', () => {
    const dto = realDevice('fm-g')
    const w = render(dto)
    expect(w.get('[data-testid="holder-link"]').attributes('href')).toBe(`/fleet/machines/${dto.holder!.ownerId}`)
    const state = w.get('[data-testid="holder-state"]')
    expect(state.text().toLowerCase()).toBe('attach unknown')
    expect(state.classes()).toContain('text-fc-err')
    expect(w.get('[data-testid="holder-guest"]').text()).toBe('QEMU 9102 · pve · usb0')
  })

  it('names a holder of a kind it has no route for, without a link', () => {
    const w = render(device({ status: 'reserved', holder: { ...realDevice('fm-a').holder!, ownerKind: 'something_new' } }))
    expect(w.find('[data-testid="holder-link"]').exists()).toBe(false)
    expect(w.find('[data-testid="holder-owner"]').exists()).toBe(true)
  })

  it('shows no holder for a free device', () => {
    expect(render(realDevice('fm-h')).find('[data-testid="holder"]').exists()).toBe(false)
  })
})

describe('DeviceCard entries', () => {
  it('shows vendor:product and port as the controller reported them', () => {
    const text = render(realDevice('fm-a')).get('[data-testid="entry"]').text()
    expect(text).toContain('pve')
    expect(text).toContain('aaaa:0001')
    expect(text).toContain('port 1-1')
  })

  it('omits the port and strings the API did not report (an id-only entry)', () => {
    const text = render(realDevice('fm-b')).get('[data-testid="entry"]').text()
    expect(text).toContain('bbbb:0002')
    expect(text).not.toContain('port')
  })

  it('shows the node inventory strings and the operator note when there are some', () => {
    const w = render(device({ note: 'on the top shelf' }))
    expect(w.get('[data-testid="entry"]').text()).toContain('Example Corp Test Dongle')
    expect(w.get('[data-testid="note"]').text()).toBe('on the top shelf')
  })
})
