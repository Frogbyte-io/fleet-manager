import { useQuery } from '@tanstack/vue-query'
import { computed, toValue, type MaybeRefOrGetter } from 'vue'

import {
  getDesiredSource,
  getRegistryEntry,
  listMachines,
  listRegistryEntries,
  listRegistryEntryReferences,
  listRegistryTypes,
  type MachineDto,
  type RegistryEntryDto,
  type RegistryReferenceDto,
  type RegistryRevisionDto,
  type RegistryTypeDto,
} from '@frogbyte-io/fleet-api-client'

import { fetchAllPages, type PagedResponse } from '../fleet/useFleetInventory'
import { retryTransient, unwrap } from '../machine/api'

// Server state for the Registry console. Everything is read through the
// public Registry API; the console stores nothing of its own.

export const REGISTRY_TYPES_KEY = ['registry', 'types'] as const

/** Every page of a list; a refused page throws the API's own error. */
async function allPages<T>(fetchPage: (cursor?: string) => Promise<unknown>) {
  let revision: RegistryRevisionDto | null = null
  const result = await fetchAllPages<T>(async (cursor) => {
    const response = await fetchPage(cursor) as { status: number, data: unknown }
    if (response.status !== 200)
      unwrap(response)
    const body = response.data as { revision?: RegistryRevisionDto | null }
    revision = body.revision ?? revision
    return response as PagedResponse<T>
  })
  return { ...result, revision }
}

export function useRegistryTypes() {
  return useQuery({
    queryKey: REGISTRY_TYPES_KEY,
    queryFn: async () => {
      const response = await listRegistryTypes()
      if (response.status !== 200)
        unwrap(response)
      const body = response.data as { items: RegistryTypeDto[], revision?: RegistryRevisionDto | null }
      return { items: body.items, revision: body.revision ?? null }
    },
    retry: retryTransient,
  })
}

export function useRegistryEntries(type: MaybeRefOrGetter<string | null>, text: MaybeRefOrGetter<string>) {
  return useQuery({
    queryKey: computed(() => ['registry', 'entries', toValue(type), toValue(text)] as const),
    enabled: computed(() => !!toValue(type)),
    queryFn: async () => {
      const q = toValue(text).trim()
      return allPages<RegistryEntryDto>(cursor => listRegistryEntries({
        type: toValue(type),
        limit: 200,
        ...(q ? { q } : {}),
        ...(cursor ? { cursor } : {}),
      }))
    },
    retry: retryTransient,
  })
}

/** One entry with the revision it was read at, for the drawer. */
export function useRegistryEntry(type: MaybeRefOrGetter<string | null>, key: MaybeRefOrGetter<string | null>) {
  return useQuery({
    queryKey: computed(() => ['registry', 'entry', toValue(type), toValue(key)] as const),
    enabled: computed(() => !!toValue(type) && !!toValue(key)),
    queryFn: async () => {
      const response = await getRegistryEntry(toValue(type)!, toValue(key)!)
      if (response.status !== 200)
        unwrap(response)
      return response.data as unknown as { data: RegistryEntryDto, revision: RegistryRevisionDto }
    },
    retry: retryTransient,
  })
}

/** Entries that point at the open entry (the incoming relations). */
export function useRegistryReferencedBy(type: MaybeRefOrGetter<string | null>, key: MaybeRefOrGetter<string | null>) {
  return useQuery({
    queryKey: computed(() => ['registry', 'referenced-by', toValue(type), toValue(key)] as const),
    enabled: computed(() => !!toValue(type) && !!toValue(key)),
    queryFn: async () => allPages<RegistryReferenceDto>(cursor => listRegistryEntryReferences(
      toValue(type)!,
      toValue(key)!,
      { limit: 200, ...(cursor ? { cursor } : {}) },
    )),
    retry: retryTransient,
  })
}

/** Machine name to id, so relation targets link to the machine page. */
export function useMachineIds(enabled: MaybeRefOrGetter<boolean>) {
  return useQuery({
    queryKey: ['registry', 'machine-ids'] as const,
    enabled: computed(() => toValue(enabled)),
    queryFn: async () => {
      const { items } = await fetchAllPages<MachineDto>(async (cursor) => {
        const response = await listMachines({ limit: 200, ...(cursor ? { cursor } : {}) })
        if (response.status !== 200)
          unwrap(response)
        return response as PagedResponse<MachineDto>
      })
      return new Map(items.map(machine => [machine.name, machine.id] as const))
    },
    retry: retryTransient,
  })
}

/** The configured Fleet Git remote (never carries credentials), for the file link. */
export function useDesiredSourceRemote(enabled: MaybeRefOrGetter<boolean>) {
  return useQuery({
    queryKey: ['registry', 'desired-source'] as const,
    enabled: computed(() => toValue(enabled)),
    queryFn: async () => unwrap<{ remote?: string | null }>(await getDesiredSource()).remote ?? null,
    retry: retryTransient,
  })
}
