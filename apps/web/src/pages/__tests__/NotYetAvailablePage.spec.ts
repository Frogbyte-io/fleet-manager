import { mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'
import { createMemoryHistory, createRouter } from 'vue-router'

import { routes } from '@/router'
import NotYetAvailablePage from '../NotYetAvailablePage.vue'

describe('NotYetAvailablePage', () => {
  it('shows the route meta title for /lab', async () => {
    const router = createRouter({
      history: createMemoryHistory(),
      routes,
    })
    await router.push('/lab')
    await router.isReady()

    const wrapper = mount(NotYetAvailablePage, {
      global: { plugins: [router] },
    })
    expect(wrapper.text()).toContain('Lab')
    expect(wrapper.text()).toContain('not built yet')
    wrapper.unmount()
  })
})
