import type { CorrelatedDeviceDto } from '@frogbyte-io/fleet-api-client'

export type ConnectVia = 'magicdns' | 'tailnet-ip' | 'lan'

/**
 * The host the controller dials for a tailnet device: its MagicDNS name, its
 * Tailscale IPv4 address (what `tailnet import` uses), or an operator-entered
 * LAN address. Null when the device lacks the chosen kind.
 */
export function connectHost(device: Pick<CorrelatedDeviceDto, 'name' | 'addresses'>, via: ConnectVia, lanIp: string): string | null {
  switch (via) {
    case 'magicdns':
      return device.name.includes('.') ? device.name.replace(/\.$/, '') : null
    case 'tailnet-ip':
      return device.addresses.find(a => /^\d+\.\d+\.\d+\.\d+$/.test(a)) ?? null
    case 'lan': {
      const trimmed = lanIp.trim()
      return trimmed === '' ? null : trimmed
    }
  }
}
