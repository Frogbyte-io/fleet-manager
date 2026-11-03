import { mount } from '@vue/test-utils'
import { createMemoryHistory, createRouter } from 'vue-router'
import { describe, expect, it } from 'vitest'

import type { HardwareDeviceDto } from '@frogbyte-io/fleet-api-client'

import DeviceCard from '../components/DeviceCard.vue'
import { allDevices, device } from './fixtures'

const NOW = Date.now()
const router = createRouter({ history: createMemoryHistory(), routes: [{ path: '/:p(.*)*', component: { template: '<div />' } }] })

function render(dto: HardwareDeviceDto) {
  return mount(DeviceCard, {
    props: { device: dto, accountName: 'lab-cluster-a', now: NOW, observation: dto.observation ?? null },
    global: { plugins: [router] },
  })
}

const byMapping = (id: string) => allDevices(NOW).find(d => d.mappingId === id)!

describe('DeviceCard statuses', () => {
  const CASES: [string, string, string][] = [
    ['bench-dongle-a', 'available', 'text-fc-ok'],
    ['bench-dongle-b', 'reserved', 'text-fc-info'],
    ['hand-attached', 'externally attached', 'text-fc-warn'],
    ['unplugged-board', 'missing', 'text-fc-warn'],
    ['token-limited', 'unsupported', 'text-fc-muted'],
    ['stuck-attach', 'quarantined', 'text-fc-err'],
  ]

  it.each(CASES)('%s shows the %s chip with its tone', (mapping, label, tone) => {
    const w = render(byMapping(mapping))
    const chip = w.get('[data-testid="status"]')
    expect(chip.text().toLowerCase()).toBe(label)
    expect(chip.classes()).toContain(tone)
    expect(w.attributes('data-status')).toBe(byMapping(mapping).status)
  })

  it('shows no reason block for a status that has none', () => {
    expect(render(byMapping('bench-dongle-a')).find('[data-testid="reason"]').exists()).toBe(false)
  })
})

describe('DeviceCard unsupported reasons', () => {
  it.each([
    ['no-node-mapping', 'no node entry', 'the mapping has no entry for any node'],
    ['token-limited', 'token lacks mapping use', 'the API token lacks Mapping.Use on this mapping'],
    ['twin-readers', 'ambiguous mapping', 'more than one device on the node matches this mapping'],
    ['pve-eight-device', 'pve too old', 'the PVE predates USB resource mappings'],
  ])('%s carries its code and the API text', (mapping, code, text) => {
    const w = render(byMapping(mapping))
    expect(w.get('[data-testid="reason-code"]').text().toLowerCase()).toBe(code)
    expect(w.get('[data-testid="reason-text"]').text()).toBe(text)
  })

  it('still names an unsupported device whose API text is missing', () => {
    const w = render(device({ status: 'unsupported', reason: 'usb_inventory_unreadable', reasonText: null }))
    expect(w.get('[data-testid="reason-text"]').text()).toBe('usb inventory unreadable')
  })
})

describe('DeviceCard stale and observation', () => {
  it('shows STALE only when the API says stale', () => {
    expect(render(byMapping('unplugged-board')).find('[data-testid="stale"]').text().toLowerCase()).toBe('stale')
    expect(render(byMapping('bench-dongle-a')).find('[data-testid="stale"]').exists()).toBe(false)
  })

  it('reads a never-seen device as never observed', () => {
    const w = render(byMapping('no-node-mapping'))
    expect(w.get('[data-testid="observed"]').text()).toBe('Observed NEVER')
    expect(w.get('[data-testid="no-entries"]').text()).toContain('No node entry')
  })

  it('shows how long ago a seen device was observed', () => {
    expect(render(byMapping('unplugged-board')).get('[data-testid="observed"]').text()).toBe('Observed 3D AGO')
  })

  it('lists the guests a refresh found referencing the mapping', () => {
    const w = render(byMapping('hand-attached'))
    const reference = w.get('[data-testid="external-reference"]').text()
    expect(reference).toContain('QEMU 9200')
    expect(reference).toContain('scratch-vm')
    expect(reference).toContain('usb1')
  })

  it('shows no observation block for a list entry (observation is null)', () => {
    expect(render(byMapping('bench-dongle-a')).find('[data-testid="observation"]').exists()).toBe(false)
  })
})

describe('DeviceCard holder', () => {
  it('links a lease holder to the Lab drawer and shows its guest and reservation state', () => {
    const w = render(byMapping('bench-dongle-b'))
    expect(w.get('[data-testid="holder-link"]').attributes('href')).toBe('/lab?lease=lease-ready-0001')
    expect(w.get('[data-testid="holder-state"]').text().toLowerCase()).toBe('attached')
    expect(w.get('[data-testid="holder-guest"]').text()).toBe('QEMU 9101 · pve-a · usb0')
  })

  it('names a machine holder without inventing a link', () => {
    const w = render(byMapping('shared-reader'))
    expect(w.find('[data-testid="holder-link"]').exists()).toBe(false)
    expect(w.get('[data-testid="holder-owner"]').text()).toBe('machine-example-01')
    expect(w.find('[data-testid="holder-guest"]').exists()).toBe(false)
  })

  it('shows a quarantined holder whose attach outcome is unknown as an error', () => {
    const w = render(byMapping('stuck-attach'))
    const state = w.get('[data-testid="holder-state"]')
    expect(state.text().toLowerCase()).toBe('attach unknown')
    expect(state.classes()).toContain('text-fc-err')
  })

  it('shows no holder for a free device', () => {
    expect(render(byMapping('bench-dongle-a')).find('[data-testid="holder"]').exists()).toBe(false)
  })
})

describe('DeviceCard entries', () => {
  it('shows vendor:product, port, strings and node', () => {
    const text = render(byMapping('bench-dongle-a')).get('[data-testid="entry"]').text()
    expect(text).toContain('pve-a')
    expect(text).toContain('f00d:c0de')
    expect(text).toContain('port 1-4')
    expect(text).toContain('Example Corp Test Dongle')
  })

  it('omits the port and strings the API did not report', () => {
    const text = render(byMapping('shared-reader')).get('[data-testid="entry"]').text()
    expect(text).toContain('beef:0042')
    expect(text).not.toContain('port')
  })

  it('shows the operator note when there is one', () => {
    expect(render(device({ note: 'on the top shelf' })).get('[data-testid="note"]').text()).toBe('on the top shelf')
  })
})
