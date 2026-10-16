import { useQuery } from '@tanstack/vue-query'
import { computed, toValue, type MaybeRefOrGetter } from 'vue'

import {
  getRunningService,
  listRunningServices,
  type ServiceDetailDto,
  type ServicesPage,
} from '@frogbyte-io/fleet-api-client'

import { retryTransient, unwrap } from '../machine/api'
import type { ServicesData } from './services'

// Server state for the Services console. The controller joins Coolify,
// Docker, and the Registry on every read, so the page re-reads on a slow
// clock; no event announces a service change.

export const SERVICES_KEY = ['services', 'list'] as const
export const SERVICES_REFRESH_MS = 30_000
const MAX_PAGES = 20

/** Every page of running services; a refused page throws the API's own error. */
export async function fetchAllServices(): Promise<ServicesData> {
  const items: ServicesData['items'] = []
  let cursor: string | undefined
  let first: ServicesPage | null = null
  for (let i = 0; i < MAX_PAGES; i++) {
    const response = await listRunningServices({ limit: 200, ...(cursor ? { cursor } : {}) }) as { status: number, data: unknown }
    if (response.status !== 200)
      unwrap(response)
    const body = response.data as ServicesPage
    first ??= body
    items.push(...body.items)
    const next = body.page?.nextCursor ?? null
    if (!next)
      return { items, ambiguousServers: first.ambiguousServers, coverage: first.coverage, evaluatedAt: first.evaluatedAt, truncated: false }
    cursor = next
  }
  return { items, ambiguousServers: first!.ambiguousServers, coverage: first!.coverage, evaluatedAt: first!.evaluatedAt, truncated: true }
}

export function useServices() {
  return useQuery({
    queryKey: SERVICES_KEY,
    queryFn: fetchAllServices,
    retry: retryTransient,
    refetchInterval: SERVICES_REFRESH_MS,
  })
}

export function useService(id: MaybeRefOrGetter<string>) {
  return useQuery({
    queryKey: computed(() => ['services', 'detail', toValue(id)] as const),
    enabled: computed(() => !!toValue(id)),
    queryFn: async () => unwrap<ServiceDetailDto>(await getRunningService(toValue(id))),
    retry: retryTransient,
    refetchInterval: SERVICES_REFRESH_MS,
  })
}
