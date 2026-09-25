import { useQueries, useQuery } from '@tanstack/vue-query'
import { computed, ref, type ComputedRef } from 'vue'

import {
  discoverProxmoxCluster,
  getTailnetStatus,
  listMachines,
  listProxmoxAccounts,
  listProxmoxGuests,
  listTailnetDevices,
  type PageAssociatedGuestDtoItemsItem,
  type PageCorrelatedDeviceDtoItemsItem,
  type PageProxmoxAccountDtoItemsItem,
  type ProxmoxDiscoveryDto,
} from '@frogbyte-io/fleet-api-client'

import { buildInventory, type Inventory, type ProxmoxSourceInput } from './inventory'

const MAX_PAGES = 20

function errorOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error)
}

export interface Paged<T> {
  items: T[]
  page: { nextCursor?: string | null }
}

export type PagedResponse<T> = { status: number, data: Paged<T> }

/** Follows `page.nextCursor` up to a safety cap; `truncated` reports hitting it. */
export async function fetchAllPages<T>(
  fetchPage: (cursor?: string) => Promise<PagedResponse<T>>,
): Promise<{ items: T[], truncated: boolean }> {
  const items: T[] = []
  let cursor: string | undefined
  for (let i = 0; i < MAX_PAGES; i++) {
    const response = await fetchPage(cursor)
    if (response.status !== 200)
      throw new Error(`Request failed (${response.status})`)
    items.push(...response.data.items)
    const next = response.data.page?.nextCursor ?? null
    if (!next)
      return { items, truncated: false }
    cursor = next
  }
  return { items, truncated: true }
}

export function useFleetInventory(): {
  inventory: ComputedRef<Inventory>
  isLoading: ComputedRef<boolean>
  refetchAll: () => Promise<void>
} {
  const paginationWarnings = ref(new Map<string, string>())

  function setPaginationWarning(key: string, message: string | null) {
    if (message)
      paginationWarnings.value.set(key, message)
    else
      paginationWarnings.value.delete(key)
  }

  const machinesQuery = useQuery({
    queryKey: ['fleet', 'machines'],
    queryFn: async () => {
      // The machines endpoint takes no cursor (only `limit`), so one request
      // is the whole list; a reported next cursor means it was cut short,
      // which is surfaced rather than hidden (#151).
      const response = await listMachines({ limit: 200 })
      if (response.status !== 200)
        throw new Error(`listMachines failed (${response.status})`)
      if (response.data.page?.nextCursor)
        setPaginationWarning('machines', `Showing the first ${response.data.page.limit} machines — the machines API cannot page further yet (#151).`)
      else
        setPaginationWarning('machines', null)
      return response.data.items
    },
  })

  const accountsQuery = useQuery({
    queryKey: ['fleet', 'proxmox-accounts'],
    queryFn: async () => {
      const { items, truncated } = await fetchAllPages(cursor =>
        listProxmoxAccounts({ limit: 200, cursor }) as unknown as Promise<PagedResponse<PageProxmoxAccountDtoItemsItem>>)
      setPaginationWarning('accounts', truncated ? 'Proxmox accounts hit the 20-page safety cap — some accounts may be missing.' : null)
      return items
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
          const { items, truncated } = await fetchAllPages(cursor =>
            listProxmoxGuests(accountId, { limit: 200, cursor }) as unknown as Promise<PagedResponse<PageAssociatedGuestDtoItemsItem>>)
          setPaginationWarning(`guests:${accountId}`, truncated ? 'Guests hit the 20-page safety cap — some guests may be missing.' : null)
          return items
        },
      })),
    ),
  })

  const tailnetConfigured = computed(() => tailnetStatusQuery.data.value?.configured ?? false)

  const tailnetDevicesQuery = useQuery({
    queryKey: ['fleet', 'tailnet-devices'],
    queryFn: async () => {
      const { items, truncated } = await fetchAllPages(cursor =>
        listTailnetDevices({ limit: 200, cursor }) as unknown as Promise<PagedResponse<PageCorrelatedDeviceDtoItemsItem>>)
      setPaginationWarning('tailnet', truncated ? 'Tailnet devices hit the 20-page safety cap — some devices may be missing.' : null)
      return items
    },
    enabled: tailnetConfigured,
  })

  const discoveryQueryByAccount = computed(() => {
    const map = new Map<string, (typeof discoveryQueries.value)[number]>()
    confirmedAccountIds.value.forEach((accountId, index) => {
      const query = discoveryQueries.value[index]
      if (query)
        map.set(accountId, query)
    })
    return map
  })

  const guestQueryByAccount = computed(() => {
    const map = new Map<string, (typeof guestQueries.value)[number]>()
    confirmedAccountIds.value.forEach((accountId, index) => {
      const query = guestQueries.value[index]
      if (query)
        map.set(accountId, query)
    })
    return map
  })

  const inventory = computed<Inventory>(() => {
    const proxmox: ProxmoxSourceInput[] = accounts.value.map((account) => {
      const confirmed = account.fingerprintState === 'confirmed'
      const discoveryQuery = confirmed ? discoveryQueryByAccount.value.get(account.id) : undefined
      const guestQuery = confirmed ? guestQueryByAccount.value.get(account.id) : undefined
      const discovery = confirmed ? discoveryQuery?.data ?? null : null
      const guests = confirmed ? guestQuery?.data ?? null : null
      const discoveryError = confirmed && discoveryQuery?.error
        ? errorOf(discoveryQuery.error)
        : null
      const guestsError = confirmed && guestQuery?.error
        ? errorOf(guestQuery.error)
        : null
      return {
        accountId: account.id,
        accountName: account.name,
        confirmed,
        loading: confirmed ? (discoveryQuery?.isLoading ?? false) || (guestQuery?.isLoading ?? false) : false,
        discovery,
        guests,
        discoveryError,
        guestsError,
        discoveryWarnings: discovery?.warnings ?? null,
      }
    })

    return buildInventory({
      machines: machinesQuery.data.value ?? [],
      machinesError: machinesQuery.error.value ? errorOf(machinesQuery.error.value) : null,
      proxmoxAccountsError: accountsQuery.error.value ? errorOf(accountsQuery.error.value) : null,
      proxmox,
      tailnet: {
        configured: tailnetConfigured.value,
        loading: tailnetConfigured.value ? tailnetDevicesQuery.isLoading.value : false,
        devices: tailnetConfigured.value ? tailnetDevicesQuery.data.value ?? null : null,
        error: tailnetStatusQuery.error.value
          ? `Tailnet status unavailable: ${errorOf(tailnetStatusQuery.error.value)}`
          : tailnetConfigured.value
            ? (tailnetDevicesQuery.error.value ? errorOf(tailnetDevicesQuery.error.value) : null)
            : null,
      },
      paginationWarning: [...paginationWarnings.value.values()].join(' ') || null,
    })
  })

  const discoveryPending = computed(() =>
    confirmedAccountIds.value.some((accountId) => {
      const query = discoveryQueryByAccount.value.get(accountId)
      if (!query)
        return true
      return query.isLoading ?? false
    }),
  )

  const guestsPending = computed(() =>
    confirmedAccountIds.value.some((accountId) => {
      const query = guestQueryByAccount.value.get(accountId)
      return query ? (query.isLoading ?? false) : true
    }),
  )

  const isLoading = computed(() =>
    machinesQuery.isLoading.value
    || accountsQuery.isLoading.value
    || tailnetStatusQuery.isLoading.value
    || (tailnetConfigured.value && tailnetDevicesQuery.isLoading.value)
    || discoveryPending.value
    || guestsPending.value,
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
