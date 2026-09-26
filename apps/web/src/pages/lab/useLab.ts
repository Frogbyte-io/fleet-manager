import { useQuery } from '@tanstack/vue-query'
import { computed } from 'vue'

import {
  listLabLeases,
  listLabProvisions,
  listLabTemplates,
  listProjects,
  type LabTemplateDto,
  type LeaseDto,
  type ProjectDto,
  type ProvisionRecordDto,
} from '@frogbyte-io/fleet-api-client'

import { ACCOUNTS_KEY, allProxmoxAccounts } from '../fleet/add/queries'
import { fetchAllPages, type PagedResponse } from '../fleet/useFleetInventory'

import { isLive } from './lab'

// Server state for the Lab page. Every list comes from the public API; the
// page adds no state of its own beyond what the operator is typing.

export const LEASES_KEY = ['lab', 'leases'] as const
export const TEMPLATES_KEY = ['lab', 'templates'] as const
export const PROVISIONS_KEY = ['lab', 'provisions'] as const

/** How often to refresh while any lease is still changing on its own. */
const LIVE_REFRESH_MS = 5000

function pageItems<T>(response: { status: number, data: unknown }, what: string): T[] {
  if (response.status !== 200)
    throw new Error(`${what} failed (${response.status})`)
  return (response.data as { items: T[] }).items
}

export function useLab() {
  const leases = useQuery({
    queryKey: LEASES_KEY,
    queryFn: async () => pageItems<LeaseDto>(await listLabLeases(), 'listLabLeases'),
    // Leases move through provisioning, expiry, and cleanup without the
    // browser doing anything, so poll only while one is still live.
    refetchInterval: q => ((q.state.data ?? []).some(lease => isLive(lease.state)) ? LIVE_REFRESH_MS : false),
  })

  const templates = useQuery({
    queryKey: TEMPLATES_KEY,
    queryFn: async () => pageItems<LabTemplateDto>(await listLabTemplates(), 'listLabTemplates'),
  })

  // Reactive, so provisions start polling as soon as a live lease appears
  // (a function interval is only re-evaluated after the query's own fetches).
  const anyLive = computed(() => (leases.data.value ?? []).some(lease => isLive(lease.state)))
  const provisions = useQuery({
    queryKey: PROVISIONS_KEY,
    queryFn: async () => pageItems<ProvisionRecordDto>(await listLabProvisions(), 'listLabProvisions'),
    refetchInterval: computed(() => (anyLive.value ? LIVE_REFRESH_MS : false)),
  })

  // Same key and shape as the Fleet page and Add dialog, so they share a cache.
  const accounts = useQuery({ queryKey: ACCOUNTS_KEY, queryFn: allProxmoxAccounts })

  // Same key and shape ({ items, truncated }) as the machine page's Projects tab.
  const projects = useQuery({
    queryKey: ['projects', 'all'],
    queryFn: async () => fetchAllPages(cursor =>
      listProjects({ limit: 200, cursor }) as unknown as Promise<PagedResponse<ProjectDto>>),
  })

  /** Only confirmed accounts can provision: the trust gate refuses the rest. */
  const provisioningAccounts = computed(() =>
    (accounts.data.value ?? []).filter(account => account.fingerprintState === 'confirmed'),
  )

  return { leases, templates, provisions, accounts, provisioningAccounts, projects }
}
