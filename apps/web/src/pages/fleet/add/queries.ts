import {
  listProxmoxAccounts,
  listTailnetDevices,
  type CorrelatedDeviceDto,
  type ProxmoxAccountDto,
} from '@frogbyte-io/fleet-api-client'

import { fetchAllPages, type PagedResponse } from '../useFleetInventory'

// Full lists for the Add dialog, following every cursor. They share the
// Fleet page's cache keys and return the same shape, so the dialog over the
// Fleet page reuses its requests instead of repeating them.

export const ACCOUNTS_KEY = ['fleet', 'proxmox-accounts'] as const
export const TAILNET_DEVICES_KEY = ['fleet', 'tailnet-devices'] as const

export async function allProxmoxAccounts(): Promise<ProxmoxAccountDto[]> {
  const { items } = await fetchAllPages(cursor =>
    listProxmoxAccounts({ limit: 200, cursor }) as unknown as Promise<PagedResponse<ProxmoxAccountDto>>)
  return items
}

export async function allTailnetDevices(): Promise<CorrelatedDeviceDto[]> {
  const { items } = await fetchAllPages(cursor =>
    listTailnetDevices({ limit: 200, cursor }) as unknown as Promise<PagedResponse<CorrelatedDeviceDto>>)
  return items
}

export function validPort(port: number): boolean {
  return Number.isInteger(port) && port > 0 && port < 65536
}
