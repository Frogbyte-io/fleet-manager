import { mount } from '@vue/test-utils'
import { beforeEach, describe, expect, it, vi } from 'vitest'

const getSystemInfo = vi.fn()

vi.mock('@frogbyte-io/fleet-api-client', () => ({
  getSystemInfo: (...args: unknown[]) => getSystemInfo(...args),
}))

import SystemPanel from '../SystemPanel.vue'

describe('SystemPanel', () => {
  beforeEach(() => getSystemInfo.mockReset())

  it('shows the resolved principal for this browser request', async () => {
    getSystemInfo.mockResolvedValue({
      status: 200,
      data: {
        currentPrincipal: 'tailscale:alice@example.com',
        service: 'fleet-controller',
        version: '0.1.0',
        trustMode: 'trusted-lan',
        trustWarning: 'local clients have full access',
        storageOk: true,
        queuePending: 0,
        queueRunning: 0,
      },
    })

    const wrapper = mount(SystemPanel)
    await vi.waitFor(() => expect(wrapper.text()).toContain('tailscale:alice@example.com'))
    wrapper.unmount()
  })
})
