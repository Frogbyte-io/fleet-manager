import { useQuery } from '@tanstack/vue-query'

import { listOperations, type OperationDto } from '@frogbyte-io/fleet-api-client'

import { retryTransient, unwrap } from '../machine/api'

// The newest operations, shared by the Overview and the Operations page.
// The FM-902 event stream invalidates this key on every operation change.

export const OPERATIONS_KEY = ['operations', 'list'] as const
/** The operations API takes only a limit (no cursor, no filters). */
export const OPERATIONS_LIMIT = 200

export function useOperationsList() {
  return useQuery({
    queryKey: OPERATIONS_KEY,
    queryFn: async () => {
      const response = await listOperations({ limit: OPERATIONS_LIMIT })
      if (response.status !== 200)
        unwrap(response)
      const page = response.data as { items: OperationDto[], page?: { nextCursor?: string | null } }
      // The API reports more only through the page's cursor.
      return { items: page.items, truncated: Boolean(page.page?.nextCursor) }
    },
    retry: retryTransient,
  })
}
