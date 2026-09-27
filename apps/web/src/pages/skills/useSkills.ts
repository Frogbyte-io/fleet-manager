import { useQuery } from '@tanstack/vue-query'
import { computed, type MaybeRefOrGetter, toValue } from 'vue'

import {
  getSkillsMatrix,
  listMachines,
  listSkillCatalog,
  listSkillCatalogVersions,
  type CatalogDto,
  type CatalogVersionDto,
  type MachineDto,
  type SkillsSnapshotDto,
} from '@frogbyte-io/fleet-api-client'

import { fetchAllPages, type PagedResponse } from '../fleet/useFleetInventory'
import { retryTransient, unwrap } from '../machine/api'

import { newestFirst } from './catalog'
import { buildMatrix, fleetAgents } from './model'

// Server state for the Skills console. Everything comes from the public API;
// the console keeps nothing of its own beyond what the operator is typing.

export const MATRIX_KEY = ['skills', 'matrix'] as const
export const CATALOG_KEY = ['skills', 'catalog'] as const
// Shared with the Fleet page, which caches the same list under this key.
export const MACHINES_KEY = ['fleet', 'machines'] as const

export function versionsKey(catalogId: string) {
  return ['skills', 'catalog', catalogId, 'versions'] as const
}

export function machineSkillsKey(machineId: string) {
  return ['skills', 'machine', machineId] as const
}

/**
 * Every page of a list. A refused page throws the API's own error (status,
 * code, message), so a denial is shown as such and not retried.
 */
async function allPages<T>(fetchPage: (cursor?: string) => Promise<unknown>) {
  return fetchAllPages<T>(async (cursor) => {
    const response = await fetchPage(cursor) as { status: number, data: unknown }
    if (response.status !== 200)
      unwrap(response)
    return response as PagedResponse<T>
  })
}

export async function allMachines(): Promise<MachineDto[]> {
  // The machines endpoint takes no cursor (#151); the Fleet page reports
  // truncation, and this cache entry has the same shape.
  const response = await listMachines({ limit: 200 })
  if (response.status !== 200)
    unwrap(response)
  return (response.data as { items: MachineDto[] }).items
}

export function useSkills() {
  const matrix = useQuery({
    queryKey: MATRIX_KEY,
    queryFn: async () => allPages<SkillsSnapshotDto>(cursor => getSkillsMatrix({ limit: 200, ...(cursor ? { cursor } : {}) })),
    retry: retryTransient,
  })
  const machines = useQuery({ queryKey: MACHINES_KEY, queryFn: allMachines, retry: retryTransient })
  const catalog = useQuery({
    queryKey: CATALOG_KEY,
    queryFn: async () => allPages<CatalogDto>(cursor => listSkillCatalog({ limit: 200, cursor })),
    retry: retryTransient,
  })

  const snapshots = computed(() => matrix.data.value?.items ?? [])
  const entries = computed(() => catalog.data.value?.items ?? [])
  const catalogByName = computed(() => new Map(entries.value.map(e => [e.content.name, e.id])))
  const model = computed(() => buildMatrix(snapshots.value, machines.data.value ?? [], catalogByName.value))
  const agents = computed(() => fleetAgents(snapshots.value))

  return { matrix, machines, catalog, snapshots, entries, model, agents }
}

export function useCatalogVersions(catalogId: MaybeRefOrGetter<string | null>) {
  return useQuery({
    queryKey: computed(() => versionsKey(toValue(catalogId) ?? '')),
    enabled: computed(() => !!toValue(catalogId)),
    queryFn: async () => {
      const id = toValue(catalogId)!
      const { items } = await allPages<CatalogVersionDto>(cursor => listSkillCatalogVersions(id, { limit: 200, cursor }))
      return newestFirst(items)
    },
    retry: retryTransient,
  })
}
