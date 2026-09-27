import { mount } from '@vue/test-utils'
import { afterEach, describe, expect, it } from 'vitest'
import { createMemoryHistory, createRouter } from 'vue-router'

import { routes } from '@/router'
import NotYetAvailablePage from '../NotYetAvailablePage.vue'

describe('NotYetAvailablePage', () => {
  let wrapper: ReturnType<typeof mount> | null = null

  afterEach(() => {
    wrapper?.unmount()
    wrapper = null
  })

  it('shows the route meta title for an unbuilt page', async () => {
    const router = createRouter({
      history: createMemoryHistory(),
      routes,
    })
    await router.push('/proxmox')
    await router.isReady()

    wrapper = mount(NotYetAvailablePage, {
      global: { plugins: [router] },
    })
    expect(wrapper.text()).toContain('Proxmox')
    expect(wrapper.text()).toContain('not built yet')
  })
})
