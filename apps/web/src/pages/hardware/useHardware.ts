import { useMutation, useQuery, useQueryClient } from '@tanstack/vue-query'
import { computed, ref } from 'vue'

import {
  listHardwareDevices,
  refreshHardware,
  type HardwareDeviceDto,
  type HardwareRefreshDto,
} from '@frogbyte-io/fleet-api-client'

import { ACCOUNTS_KEY, allProxmoxAccounts } from '../fleet/add/queries'
import { ApiRequestError, retryTransient, unwrap } from '../machine/api'

// Server state for the Hardware page. The list is the API's own records (no
// Proxmox call); a refresh is the only thing that reads Proxmox, so a device is
// as fresh as the last refresh and `stale` says when that is too old.

export const HARDWARE_KEY = ['hardware', 'devices'] as const

/** Pages of 200; this many are followed before the list is declared cut short. */
const MAX_PAGES = 10

export async function allDevices(): Promise<{ items: HardwareDeviceDto[], truncated: boolean }> {
  const items: HardwareDeviceDto[] = []
  let cursor: string | undefined
  for (let page = 0; page < MAX_PAGES; page++) {
    const response = await listHardwareDevices({ limit: 200, cursor }) as { status: number, data: unknown }
    // A refused page keeps the API's code and message (e.g. 403 `denied`).
    if (response.status !== 200)
      unwrap(response)
    const body = response.data as { items: HardwareDeviceDto[], page?: { nextCursor?: string | null } }
    items.push(...body.items)
    const next = body.page?.nextCursor ?? null
    if (!next)
      return { items, truncated: false }
    cursor = next
  }
  return { items, truncated: true }
}

export interface RefreshFailure {
  accountId: string
  status: number | null
  message: string
}

export function useHardware() {
  const queryClient = useQueryClient()
  const devices = useQuery({ queryKey: HARDWARE_KEY, queryFn: allDevices, retry: retryTransient })
  const accounts = useQuery({ queryKey: ACCOUNTS_KEY, queryFn: allProxmoxAccounts, retry: retryTransient })

  // Only a pinned account can be refreshed; the controller answers 409 for the rest.
  const refreshable = computed(() => (accounts.data.value ?? []).filter(a => a.fingerprintState === 'confirmed'))
  const accountNames = computed(() => new Map((accounts.data.value ?? []).map(a => [a.id, a.name])))

  // What each account's last refresh in this session reported (the list carries
  // no observation), and whether the API refused the action to this viewer.
  const reports = ref(new Map<string, HardwareRefreshDto>())
  const refreshError = ref<RefreshFailure | null>(null)
  const refreshDenied = ref(false)

  const refresh = useMutation({
    mutationFn: async (accountId: string) => unwrap<HardwareRefreshDto>(await refreshHardware({ accountId })),
    onMutate: () => {
      refreshError.value = null
    },
    onSuccess: (report) => {
      reports.value = new Map(reports.value).set(report.accountId, report)
      void queryClient.invalidateQueries({ queryKey: HARDWARE_KEY })
    },
    onError: (error, accountId) => {
      const status = error instanceof ApiRequestError ? error.status : null
      refreshError.value = { accountId, status, message: error instanceof Error ? error.message : String(error) }
      // The API decides who may refresh; once it says no, the action goes away.
      if (status === 403)
        refreshDenied.value = true
    },
  })

  // The action is offered only while the list itself loads: a viewer the API
  // refuses (`hardware.read`) or a controller without the surface sees none.
  const canRefresh = computed(() => devices.isSuccess.value && !refreshDenied.value)

  return { devices, accounts, refreshable, accountNames, reports, refresh, refreshError, refreshDenied, canRefresh }
}
