import { enableAutoUnmount, flushPromises, mount } from '@vue/test-utils'
import { QueryClient, VueQueryPlugin } from '@tanstack/vue-query'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const getRegistrySettings = vi.fn()
const updateRegistrySettings = vi.fn()

vi.mock('@frogbyte-io/fleet-api-client', () => ({
  getRegistrySettings: (...a: unknown[]) => getRegistrySettings(...a),
  updateRegistrySettings: (...a: unknown[]) => updateRegistrySettings(...a),
}))

import RegistrySettings from '../sections/RegistrySettings.vue'

function ok<T>(data: T, status = 200) {
  return { status, data, headers: new Headers() }
}

async function mountSection() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } })
  const wrapper = mount(RegistrySettings, { global: { plugins: [[VueQueryPlugin, { queryClient }]] } })
  await flushPromises()
  return wrapper
}

enableAutoUnmount(afterEach)

beforeEach(() => {
  getRegistrySettings.mockReset()
  updateRegistrySettings.mockReset()
  getRegistrySettings.mockResolvedValue(ok({ data: { autoActivate: true, changeMode: 'pull-request' } }))
})

describe('Registry settings', () => {
  it('shows the defaults the API reports', async () => {
    const wrapper = await mountSection()
    const auto = wrapper.get('[data-testid="registry-auto-activate"]').element as HTMLInputElement
    expect(auto.checked).toBe(true)
    expect((wrapper.get('[data-testid="registry-mode-pull-request"]').element as HTMLInputElement).checked).toBe(true)
    expect((wrapper.get('[data-testid="registry-mode-direct"]').element as HTMLInputElement).checked).toBe(false)
  })

  it('turns auto-activation off and shows the fleetctl equivalent', async () => {
    updateRegistrySettings.mockResolvedValue(ok({ data: { autoActivate: false, changeMode: 'pull-request' } }))
    const wrapper = await mountSection()
    const auto = wrapper.get('[data-testid="registry-auto-activate"]')
    ;(auto.element as HTMLInputElement).checked = false
    await auto.trigger('change')
    await flushPromises()
    expect(updateRegistrySettings).toHaveBeenCalledWith({ autoActivate: false })
    expect((wrapper.get('[data-testid="registry-auto-activate"]').element as HTMLInputElement).checked).toBe(false)
    expect(wrapper.text()).toContain('fleetctl desired settings set --auto-activate false')
  })

  it('switches the change mode', async () => {
    updateRegistrySettings.mockResolvedValue(ok({ data: { autoActivate: true, changeMode: 'direct' } }))
    const wrapper = await mountSection()
    await wrapper.get('[data-testid="registry-mode-direct"]').trigger('change')
    await flushPromises()
    expect(updateRegistrySettings).toHaveBeenCalledWith({ changeMode: 'direct' })
    expect((wrapper.get('[data-testid="registry-mode-direct"]').element as HTMLInputElement).checked).toBe(true)
  })

  it('reports a refused change without losing the shown value', async () => {
    updateRegistrySettings.mockResolvedValue(ok({ code: 'forbidden', message: 'not allowed' }, 403))
    const wrapper = await mountSection()
    await wrapper.get('[data-testid="registry-mode-direct"]').trigger('change')
    await flushPromises()
    expect(wrapper.find('[data-testid="registry-settings-save-error"]').exists()).toBe(true)
  })

  it('says so when the settings cannot be read', async () => {
    getRegistrySettings.mockResolvedValue(ok({ code: 'forbidden', message: 'no' }, 403))
    const wrapper = await mountSection()
    expect(wrapper.get('[data-testid="registry-settings-error"]').text()).toContain('could not be read')
    expect(wrapper.find('[data-testid="registry-auto-activate"]').exists()).toBe(false)
  })
})
