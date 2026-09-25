import {
  listProxmoxAccounts,
  listTailnetDevices,
  type CorrelatedDeviceDto,
  type ProxmoxAccountDto,
} from '@frogbyte-io/fleet-api-client'

import { fetchAllPages, type PagedResponse } from '../useFleetInventory'

// Full lists for the Add dialog, following every cursor like the Fleet page.

export const ACCOUNTS_KEY = ['add', 'proxmox-accounts'] as const

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
