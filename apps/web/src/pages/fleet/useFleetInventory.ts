import { useQueries, useQuery } from '@tanstack/vue-query'
import { computed, type ComputedRef } from 'vue'

import {
  discoverProxmoxCluster,
  getTailnetStatus,
  listMachines,
  listProxmoxAccounts,
  listProxmoxGuests,
  listTailnetDevices,
  type PageAssociatedGuestDtoItemsItem,
  type PageCorrelatedDeviceDtoItemsItem,
  type ProxmoxDiscoveryDto,
} from '@frogbyte-io/fleet-api-client'

import { buildInventory, type Inventory, type ProxmoxSourceInput } from './inventory'

function errorOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error)
}

export function useFleetInventory(): {
  inventory: ComputedRef<Inventory>
  isLoading: ComputedRef<boolean>
  refetchAll: () => Promise<void>
} {
  const machinesQuery = useQuery({
    queryKey: ['fleet', 'machines'],
    queryFn: async () => {
      const response = await listMachines({ limit: 200 })
      if (response.status === 200)
        return response.data.items
      throw new Error(`listMachines failed (${response.status})`)
    },
  })

  const accountsQuery = useQuery({
    queryKey: ['fleet', 'proxmox-accounts'],
    queryFn: async () => {
      const response = await listProxmoxAccounts()
      if (response.status === 200)
        return response.data.items
      throw new Error(`listProxmoxAccounts failed (${response.status})`)
    },
  })

  const tailnetStatusQuery = useQuery({
    queryKey: ['fleet', 'tailnet-status'],
    queryFn: async () => {
      const response = await getTailnetStatus()
      if (response.status === 200)
        return response.data.data
      throw new Error(`getTailnetStatus failed (${response.status})`)
    },
  })

  const accounts = computed(() => accountsQuery.data.value ?? [])
  const confirmedAccountIds = computed(() =>
    accounts.value.filter(a => a.fingerprintState === 'confirmed').map(a => a.id),
  )

  const discoveryQueries = useQueries({
    queries: computed(() =>
      confirmedAccountIds.value.map(accountId => ({
        queryKey: ['fleet', 'proxmox-discovery', accountId],
        queryFn: async () => {
          const response = await discoverProxmoxCluster(accountId)
          if (response.status === 200)
            return response.data.data as ProxmoxDiscoveryDto
          throw new Error(`discoverProxmoxCluster failed (${response.status})`)
        },
      })),
    ),
  })

  const guestQueries = useQueries({
    queries: computed(() =>
      confirmedAccountIds.value.map(accountId => ({
        queryKey: ['fleet', 'proxmox-guests', accountId],
        queryFn: async () => {
          const response = await listProxmoxGuests(accountId, { limit: 200 })
          if (response.status === 200)
            return response.data.items as PageAssociatedGuestDtoItemsItem[]
          throw new Error(`listProxmoxGuests failed (${response.status})`)
        },
      })),
    ),
  })

  const tailnetConfigured = computed(() => tailnetStatusQuery.data.value?.configured ?? false)

  const tailnetDevicesQuery = useQuery({
    queryKey: ['fleet', 'tailnet-devices'],
    queryFn: async () => {
      const response = await listTailnetDevices({ limit: 200 })
      if (response.status === 200)
        return response.data.items as PageCorrelatedDeviceDtoItemsItem[]
      throw new Error(`listTailnetDevices failed (${response.status})`)
    },
    enabled: tailnetConfigured,
  })

  const inventory = computed<Inventory>(() => {
    const proxmox: ProxmoxSourceInput[] = accounts.value.map((account, index) => {
      const confirmed = account.fingerprintState === 'confirmed'
      const discoveryQuery = discoveryQueries.value[index]
      const guestQuery = guestQueries.value[index]
      const discovery = confirmed ? discoveryQuery?.data ?? null : null
      const guests = confirmed ? guestQuery?.data ?? null : null
      const error = confirmed
        ? (discoveryQuery?.error
          ? errorOf(discoveryQuery.error)
          : guestQuery?.error
            ? errorOf(guestQuery.error)
            : null)
        : null
      return {
        accountId: account.id,
        accountName: account.name,
        confirmed,
        loading: confirmed ? (discoveryQuery?.isLoading ?? false) : false,
        discovery,
        guests,
        error,
      }
    })

    return buildInventory({
      machines: machinesQuery.data.value ?? [],
      machinesError: machinesQuery.error.value ? errorOf(machinesQuery.error.value) : null,
      proxmox,
      tailnet: {
        configured: tailnetConfigured.value,
        devices: tailnetConfigured.value ? tailnetDevicesQuery.data.value ?? null : null,
        error: tailnetConfigured.value && tailnetDevicesQuery.error.value
          ? errorOf(tailnetDevicesQuery.error.value)
          : null,
      },
    })
  })

  const discoveryPending = computed(() =>
    confirmedAccountIds.value.some((accountId, index) => {
      const query = discoveryQueries.value[index]
      if (!query)
        return true
      return query.isLoading ?? false
    }),
  )

  const isLoading = computed(() =>
    machinesQuery.isLoading.value
    || accountsQuery.isLoading.value
    || tailnetStatusQuery.isLoading.value
    || discoveryPending.value,
  )

  async function refetchAll(): Promise<void> {
    await Promise.all([
      machinesQuery.refetch(),
      accountsQuery.refetch(),
      tailnetStatusQuery.refetch(),
      tailnetConfigured.value ? tailnetDevicesQuery.refetch() : Promise.resolve(),
      ...discoveryQueries.value.flatMap(q => q.refetch ? [q.refetch()] : []),
      ...guestQueries.value.flatMap(q => q.refetch ? [q.refetch()] : []),
    ])
  }

  return { inventory, isLoading, refetchAll }
}
