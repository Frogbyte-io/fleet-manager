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

describe('ProvisionsTab guest fate', () => {
  it('shows every guest value, with a destroyed guest distinct from its saga state', () => {
    const w = render(GUESTS.map((g, i) => record(`rec-${i}-aaaaaaaa`, g, { createdAt: 1000 + i })))
    const text = w.findAll('[data-testid="guest-fate"]').map(c => c.text())
    expect(text.sort()).toEqual(GUESTS.map(g => g.replaceAll('_', ' ')).sort())
    expect(w.text()).toContain('destroyed')
    expect(w.text()).toContain('ready')
  })

  it('shows the lease state only when a lease links back', () => {
    const w = render([
      record('rec-1-aaaaaaaa', 'present', { leaseState: 'ready', createdAt: 2 }),
      record('rec-2-aaaaaaaa', 'destroyed', { leaseState: null, createdAt: 1 }),
    ])
    const leases = w.findAll('[data-testid="lease-state"]')
    expect(leases).toHaveLength(1)
    expect(leases[0]!.text()).toBe('lease ready')
  })

  it('keeps an unknown future guest value readable', () => {
    expect(render([record('rec-1-aaaaaaaa', 'some_new_value')]).text()).toContain('some new value')
  })
})
