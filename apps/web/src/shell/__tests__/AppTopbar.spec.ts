import { shallowMount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'
import { createMemoryHistory, createRouter } from 'vue-router'

import AppTopbar from '../AppTopbar.vue'

const router = createRouter({
  history: createMemoryHistory(),
  routes: [{ path: '/', component: { template: '<div />' } }],
})

describe('AppTopbar fleet event status', () => {
  it.each([
    ['connecting', 'Connecting', 'text-fc-muted'],
    ['live', 'Live', 'text-fc-ok'],
    ['disconnected', 'Disconnected', 'text-fc-err'],
  ] as const)('shows %s as an accessible status', (eventStatus, label, tone) => {
    const wrapper = shallowMount(AppTopbar, {
      props: { eventStatus },
      global: { plugins: [router] },
    })
    const status = wrapper.find('[role="status"]')
    expect(status.attributes('aria-live')).toBe('polite')
    expect(status.text()).toBe(label)
    expect(status.classes()).toContain(tone)
    wrapper.unmount()
  })
})
