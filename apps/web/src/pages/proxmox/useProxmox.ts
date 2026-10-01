import { useInfiniteQuery, useQueries, useQuery } from '@tanstack/vue-query'
import { computed, ref, type Ref } from 'vue'

import {
  getProxmoxPrivileges,
  listProxmoxGuests,
  listProxmoxTasks,
  type AssociatedGuestDto,
  type ProxmoxPrivilegesDto,
  type ProxmoxTaskPage,
} from '@frogbyte-io/fleet-api-client'

import { ACCOUNTS_KEY, allProxmoxAccounts } from '../fleet/add/queries'
import { fetchAllPages, proxmoxDiscovery, type PagedResponse } from '../fleet/useFleetInventory'
import { retryTransient, unwrap } from '../machine/api'

import { taskParams, trustState, type AccountView, type TaskFilters } from './proxmox'

// Server state for the Proxmox page. It shares the Fleet page's cache keys
// (accounts, per-account discovery and guests), so moving between the two
// pages reuses the same requests.

export function discoveryKey(accountId: string) {
  return ['fleet', 'proxmox-discovery', accountId] as const
}

export function guestsKey(accountId: string) {
  return ['fleet', 'proxmox-guests', accountId] as const
}

export function privilegesKey(accountId: string) {
  return ['proxmox', 'privileges', accountId] as const
}

export function tasksKey(accountId: string, filters: TaskFilters) {
  return ['proxmox', 'tasks', accountId, filters] as const
}

async function privileges(accountId: string): Promise<ProxmoxPrivilegesDto> {
  return unwrap<ProxmoxPrivilegesDto>(await getProxmoxPrivileges(accountId))
}

/** One page of an account's PVE task history; the page is not enveloped. */
export async function tasksPage(accountId: string, filters: TaskFilters, cursor?: string | null): Promise<ProxmoxTaskPage> {
  const response = await listProxmoxTasks(accountId, taskParams(filters, cursor)) as { status: number, data: unknown }
  if (response.status !== 200)
    unwrap(response)
  return response.data as ProxmoxTaskPage
}

/**
 * The Tasks tab's history for one account: the first page, then each
 * "load more" follows the last page's cursor. A filter change is a new
 * query key, so it starts at the first page again. `ready` is the account's
 * trust gate (pinned, and no pin discovery in flight); the query never runs
 * without it.
 */
export function useProxmoxTasks(accountId: Ref<string | null>, filters: Ref<TaskFilters>, ready: Ref<boolean>) {
  return useInfiniteQuery({
    // Spread so each filter field is a tracked dependency of the key.
    queryKey: computed(() => tasksKey(accountId.value ?? '', { ...filters.value })),
    queryFn: ({ queryKey, pageParam }) => tasksPage(queryKey[2], queryKey[3], pageParam),
    initialPageParam: null as string | null,
    getNextPageParam: (last: ProxmoxTaskPage) => last.page.nextCursor ?? null,
    enabled: computed(() => !!accountId.value && ready.value),
    retry: retryTransient,
  })
}

/** Accounts whose guest list hit the paging safety cap. */
const truncatedGuests = ref(new Set<string>())

async function allGuests(accountId: string): Promise<AssociatedGuestDto[]> {
  // The cache entry is shared with the Fleet page as a plain list, so a
  // truncated result is recorded beside it rather than inside it.
  const { items, truncated } = await fetchAllPages<AssociatedGuestDto>(async (cursor) => {
    const response = await listProxmoxGuests(accountId, { limit: 200, cursor }) as { status: number, data: unknown }
    // A refused page keeps the API's code (e.g. a fingerprint mismatch).
    if (response.status !== 200)
      unwrap(response)
    return response as PagedResponse<AssociatedGuestDto>
  })
  const next = new Set(truncatedGuests.value)
  if (truncated)
    next.add(accountId)
  else
    next.delete(accountId)
  truncatedGuests.value = next
  return items
}

export function useProxmox() {
  const accounts = useQuery({ queryKey: ACCOUNTS_KEY, queryFn: allProxmoxAccounts, retry: retryTransient })
  const list = computed(() => accounts.data.value ?? [])
  // Only a pinned account can be asked anything; the controller refuses
  // the rest, so they are not asked.
  const confirmed = computed(() => list.value.filter(a => a.fingerprintState === 'confirmed').map(a => a.id))

  const discoveries = useQueries({
    queries: computed(() => confirmed.value.map(accountId => ({
      queryKey: discoveryKey(accountId),
      queryFn: () => proxmoxDiscovery(accountId),
      retry: retryTransient,
    }))),
  })
  // Guests are asked for only after discovery verified the pin, so a changed
  // certificate is caught before any guest request goes out.
  const guests = useQueries({
    queries: computed(() => confirmed.value.map((accountId, index) => {
      const discovery = discoveries.value[index]
      return {
        queryKey: guestsKey(accountId),
        queryFn: () => allGuests(accountId),
        retry: retryTransient,
        enabled: !!discovery?.data && !discovery.error,
      }
    })),
  })

  // The privilege report follows the same gate, and also waits out any pin
  // discovery in flight: a refetch (or a re-pinned certificate) must verify
  // the pin again before a credentialed request goes out on cached trust.
  const privilegeReports = useQueries({
    queries: computed(() => confirmed.value.map((accountId, index) => {
      const discovery = discoveries.value[index]
      return {
        queryKey: privilegesKey(accountId),
        queryFn: () => privileges(accountId),
        retry: retryTransient,
        enabled: !!discovery?.data && !discovery.error && !discovery.isFetching,
      }
    })),
  })

  const views = computed<AccountView[]>(() => list.value.map((account) => {
    const index = confirmed.value.indexOf(account.id)
    const discovery = index >= 0 ? discoveries.value[index] : undefined
    const guestList = index >= 0 ? guests.value[index] : undefined
    const report = index >= 0 ? privilegeReports.value[index] : undefined
    const state = trustState(account, { loading: discovery?.isLoading ?? false, error: discovery?.error ?? null })
    // Anything fetched before the certificate changed is not shown as current.
    const usable = state === 'pinned'
    return {
      account,
      state,
      discovery: usable ? discovery?.data ?? null : null,
      discoveryFetching: discovery?.isFetching ?? false,
      guests: usable ? guestList?.data ?? [] : [],
      guestsLoading: usable && (guestList?.isLoading ?? false),
      guestsError: usable ? guestList?.error ?? null : null,
      guestsTruncated: usable && truncatedGuests.value.has(account.id),
      privileges: usable ? report?.data ?? null : null,
      privilegesLoading: usable && (report?.isLoading ?? false),
      privilegesError: usable ? report?.error ?? null : null,
    }
  }))

  const discoveryErrors = computed(() => new Map(list.value.map((account) => {
    const index = confirmed.value.indexOf(account.id)
    return [account.id, index >= 0 ? discoveries.value[index]?.error ?? null : null] as const
  })))
  const guestErrors = computed(() => new Map(list.value.map((account) => {
    const index = confirmed.value.indexOf(account.id)
    return [account.id, index >= 0 ? guests.value[index]?.error ?? null : null] as const
  })))
  const loading = computed(() => accounts.isLoading.value || discoveries.value.some(q => q.isLoading) || views.value.some(v => v.guestsLoading))

  return { accounts, views, discoveryErrors, guestErrors, loading }
}
