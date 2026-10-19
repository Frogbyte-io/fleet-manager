import { mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'

import type { ProvisionRecordDto } from '@frogbyte-io/fleet-api-client'

import ProvisionsTab from '../components/ProvisionsTab.vue'

// Placeholder data only.
const GUESTS = ['not_allocated', 'present', 'destroyed', 'kept', 'returned_to_pool', 'quarantined_in_pool']

function record(id: string, guest: string, extra: Partial<ProvisionRecordDto> = {}): ProvisionRecordDto {
  return {
    id, guest, state: 'ready', templateVersionId: 'tv-1', createdAt: 1000, updatedAt: 1000,
    vmid: 9000, node: 'pve-a', ...extra,
  } as ProvisionRecordDto
}

function render(provisions: ProvisionRecordDto[]) {
  return mount(ProvisionsTab, { props: { provisions, templates: [], now: 2000, loading: false } })
}

const TONE: Record<string, string> = {
  present: 'text-fc-ok',
  kept: 'text-fc-info',
  returned_to_pool: 'text-fc-info',
  quarantined_in_pool: 'text-fc-warn',
  destroyed: 'text-fc-muted',
  not_allocated: 'text-fc-faint',
}

describe('ProvisionsTab guest fate', () => {
  it('shows every guest value with its documented tone', () => {
    const w = render(GUESTS.map((g, i) => record(`rec-${i}-aaaaaaaa`, g, { createdAt: 1000 + i })))
    const chips = w.findAll('[data-testid="guest-fate"]')
    expect(chips).toHaveLength(GUESTS.length)
    for (const chip of chips) {
      const guest = chip.text().replaceAll(' ', '_').toLowerCase()
      expect(GUESTS).toContain(guest)
      expect(chip.classes()).toContain(TONE[guest]!)
    }
  })

  it('keeps the saga state and the fate separate on the same row', () => {
    const w = render([record('rec-1-aaaaaaaa', 'destroyed', { state: 'ready' })])
    expect(w.get('[data-testid="saga-state"]').text()).toBe('ready')
    expect(w.get('[data-testid="fate-cell"]').text()).toBe('destroyed')
    expect(w.get('[data-testid="saga-state"]').text()).not.toContain('destroyed')
  })

  it('renders a linked lease state with the lease tone, underscores spaced', () => {
    const w = render([record('rec-1-aaaaaaaa', 'present', { leaseState: 'cleanup_failed' })])
    const lease = w.get('[data-testid="lease-state"]')
    expect(lease.text()).toBe('lease cleanup failed')
    expect(lease.get('span').classes()).toContain('text-fc-err')
    const ready = render([record('rec-2-aaaaaaaa', 'present', { leaseState: 'ready' })])
    expect(ready.get('[data-testid="lease-state"] span').classes()).toContain('text-fc-ok')
  })

  it('omits the lease line for null and undefined leaseState', () => {
    const w = render([
      record('rec-1-aaaaaaaa', 'present', { leaseState: null }),
      record('rec-2-aaaaaaaa', 'destroyed', { leaseState: undefined }),
      record('rec-3-aaaaaaaa', 'kept', { leaseState: '' }),
    ])
    expect(w.findAll('[data-testid="lease-state"]')).toHaveLength(0)
  })

  it('keeps an unknown guest value readable and a missing one empty', () => {
    expect(render([record('rec-1-aaaaaaaa', 'some_new_value')]).text()).toContain('some new value')
    const w = render([record('rec-2-aaaaaaaa', undefined as unknown as string)])
    expect(w.get('[data-testid="guest-fate"]').text()).toBe('')
  })

  it('sorts newest first by createdAt', () => {
    const w = render([
      record('aaaa0001-old', 'present', { createdAt: 1 }),
      record('bbbb0002-new', 'present', { createdAt: 3 }),
      record('cccc0003-mid', 'present', { createdAt: 2 }),
    ])
    const ids = w.findAll('tbody tr').map(r => r.find('td').text())
    expect(ids).toEqual(['bbbb0002', 'cccc0003', 'aaaa0001'])
  })
})
