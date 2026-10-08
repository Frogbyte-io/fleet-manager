import { useQuery } from '@tanstack/vue-query'
import { computed, type Ref } from 'vue'

import {
  getLabLease,
  getOperation,
  listLabArtifacts,
  listLabLeases,
  listLabProvisions,
  listLabTemplates,
  listProjects,
  type LabArtifactDto,
  type LabTemplateDto,
  type LeaseDetailDto,
  type LeaseDto,
  type OperationDto,
  type ProjectDto,
  type ProvisionRecordDto,
} from '@frogbyte-io/fleet-api-client'

import { isTerminal as isOperationTerminal, retryTransient, unwrap } from '../machine/api'
import { ACCOUNTS_KEY, allProxmoxAccounts } from '../fleet/add/queries'
import { fetchAllPages, type PagedResponse } from '../fleet/useFleetInventory'

import { isLive } from './lab'

// Server state for the Lab page. Every list comes from the public API; the
// page adds no state of its own beyond what the operator is typing.

export const LEASES_KEY = ['lab', 'leases'] as const
export const TEMPLATES_KEY = ['lab', 'templates'] as const
export const PROVISIONS_KEY = ['lab', 'provisions'] as const
export const ARTIFACTS_KEY = ['lab', 'artifacts'] as const

/**
 * The lease list's key: the unfiltered list keeps `LEASES_KEY` (shared with
 * the Images page and Overview); a project filter extends it, so invalidating
 * `LEASES_KEY` refreshes every variant, and lease details with them.
 */
export function leasesKey(projectId: string | null) {
  return projectId ? [...LEASES_KEY, 'project', projectId] as const : LEASES_KEY
}

export function leaseDetailKey(leaseId: string) {
  return [...LEASES_KEY, 'detail', leaseId] as const
}

/** At most this many artifact pages (200 each) are followed. */
const MAX_ARTIFACT_PAGES = 10

/** How often to refresh while any lease is still changing on its own. */
const LIVE_REFRESH_MS = 5000

function pageItems<T>(response: { status: number, data: unknown }, what: string): T[] {
  if (response.status !== 200)
    throw new Error(`${what} failed (${response.status})`)
  return (response.data as { items: T[] }).items
}

export function useLab(projectFilter: Ref<string | null>) {
  // The server filters by project (`fleetctl lab leases --project`).
  const leases = useQuery({
    queryKey: computed(() => leasesKey(projectFilter.value)),
    queryFn: async () => pageItems<LeaseDto>(
      await listLabLeases(projectFilter.value ? { projectId: projectFilter.value } : undefined),
      'listLabLeases',
    ),
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

/** One lease with its guest's placement, machine, and failure details. */
export function useLeaseDetail(leaseId: Ref<string | null>) {
  return useQuery({
    queryKey: computed(() => leaseDetailKey(leaseId.value ?? '')),
    queryFn: async () => unwrap<LeaseDetailDto>(await getLabLease(leaseId.value!)),
    enabled: computed(() => leaseId.value !== null),
    refetchInterval: q => (q.state.data && isLive(q.state.data.state) ? LIVE_REFRESH_MS : false),
  })
}

export interface ArtifactFilter {
  leaseId?: string | null
  projectId?: string | null
}

/** Stored artifacts, newest first as the API returns them, across pages. */
export function useArtifacts(filter: Ref<ArtifactFilter>, enabled: Ref<boolean> = computed(() => true)) {
  return useQuery({
    queryKey: computed(() => [...ARTIFACTS_KEY, filter.value.leaseId ?? null, filter.value.projectId ?? null] as const),
    enabled,
    queryFn: async () => {
      const items: LabArtifactDto[] = []
      let cursor: string | undefined
      for (let i = 0; i < MAX_ARTIFACT_PAGES; i++) {
        const response = await listLabArtifacts({
          ...(filter.value.leaseId ? { leaseId: filter.value.leaseId } : {}),
          ...(filter.value.projectId ? { projectId: filter.value.projectId } : {}),
          limit: 200,
          ...(cursor ? { cursor } : {}),
        })
        if (response.status !== 200)
          unwrap(response)
        const page = response.data as { items: LabArtifactDto[], page?: { nextCursor?: string | null } }
        items.push(...page.items)
        cursor = page.page?.nextCursor ?? undefined
        if (!cursor)
          return { items, truncated: false }
      }
      return { items, truncated: true }
    },
  })
}

/** Follows one operation until it settles (exec and collect results). */
export function useOperation(operationId: Ref<string | null>) {
  return useQuery({
    queryKey: computed(() => ['operation', operationId.value ?? '']),
    queryFn: async () => unwrap<OperationDto>(await getOperation(operationId.value!)),
    enabled: computed(() => operationId.value !== null),
    refetchInterval: q => (q.state.status === 'error' || (q.state.data && isOperationTerminal(q.state.data.state)) ? false : 1000),
    retry: retryTransient,
  })
}
