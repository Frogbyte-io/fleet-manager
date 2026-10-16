import { useQuery } from '@tanstack/vue-query'
import { listDomainObservations, type DomainObservationViewDto } from '@frogbyte-io/fleet-api-client'

import { fetchAllPages, type PagedResponse } from '../../fleet/useFleetInventory'
import { retryTransient, unwrap } from '../../machine/api'

/** Every domain's latest lookup, with its drift comparison and suggested patch. */
export function useDomainObservations() {
  return useQuery({
    queryKey: ['registry', 'domain-observations'] as const,
    queryFn: async () => fetchAllPages<DomainObservationViewDto>(async (cursor) => {
      const response = await listDomainObservations({ limit: 200, ...(cursor ? { cursor } : {}) }) as { status: number, data: unknown }
      if (response.status !== 200)
        unwrap(response)
      return response as PagedResponse<DomainObservationViewDto>
    }),
    retry: retryTransient,
    // Lookups run on the controller's schedule; no event announces them.
    refetchInterval: 5 * 60_000,
  })
}
