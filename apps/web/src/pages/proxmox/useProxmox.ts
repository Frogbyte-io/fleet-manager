import { useQueries, useQuery } from '@tanstack/vue-query'
import { computed } from 'vue'

import { listProxmoxGuests, type AssociatedGuestDto } from '@frogbyte-io/fleet-api-client'

import { ACCOUNTS_KEY, allProxmoxAccounts } from '../fleet/add/queries'
import { fetchAllPages, proxmoxDiscovery, type PagedResponse } from '../fleet/useFleetInventory'
import { retryTransient, unwrap } from '../machine/api'

import { trustState, type AccountView } from './proxmox'

// Server state for the Proxmox page. It shares the Fleet page's cache keys
// (accounts, per-account discovery and guests), so moving between the two
// pages reuses the same requests.

export function discoveryKey(accountId: string) {
  return ['fleet', 'proxmox-discovery', accountId] as const
}

export function guestsKey(accountId: string) {
  return ['fleet', 'proxmox-guests', accountId] as const
}

async function allGuests(accountId: string): Promise<AssociatedGuestDto[]> {
  const { items } = await fetchAllPages<AssociatedGuestDto>(async (cursor) => {
    const response = await listProxmoxGuests(accountId, { limit: 200, cursor }) as { status: number, data: unknown }
    // A refused page keeps the API's code (e.g. a fingerprint mismatch).
    if (response.status !== 200)
      unwrap(response)
    return response as PagedResponse<AssociatedGuestDto>
  })
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
  const guests = useQueries({
    queries: computed(() => confirmed.value.map(accountId => ({
      queryKey: guestsKey(accountId),
      queryFn: () => allGuests(accountId),
      retry: retryTransient,
    }))),
  })

  const views = computed<AccountView[]>(() => list.value.map((account) => {
    const index = confirmed.value.indexOf(account.id)
    const discovery = index >= 0 ? discoveries.value[index] : undefined
    const guestList = index >= 0 ? guests.value[index] : undefined
    const state = trustState(account, { loading: discovery?.isLoading ?? false, error: discovery?.error ?? null })
    // Anything fetched before the certificate changed is not shown as current.
    const usable = state === 'pinned'
    return {
      account,
      state,
      discovery: usable ? discovery?.data ?? null : null,
      guests: usable ? guestList?.data ?? [] : [],
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
  const loading = computed(() => accounts.isLoading.value || discoveries.value.some(q => q.isLoading))

  return { accounts, views, discoveryErrors, guestErrors, loading }
}
