import { useMutation, useQuery, useQueryClient } from '@tanstack/vue-query'

import {
  approveActionRequest,
  denyActionRequest,
  listActionRequests,
  type ActionRequestDto,
} from '@frogbyte-io/fleet-api-client'

import { retryTransient, unwrap } from '../machine/api'

// Action requests, shared by the inbox and the Overview. The fleet event
// stream's `request.changed` (and `operation.changed`, which moves an
// executing request) invalidate this key, so the inbox stays live.

export const REQUESTS_KEY = ['requests', 'list'] as const
/** The list takes a limit and no cursor; this is the API's maximum. */
export const REQUESTS_LIMIT = 200

export function useRequestsList() {
  return useQuery({
    queryKey: REQUESTS_KEY,
    queryFn: async () => {
      const response = await listActionRequests({ limit: REQUESTS_LIMIT })
      if (response.status !== 200)
        unwrap(response)
      const page = response.data as { items: ActionRequestDto[], page?: { nextCursor?: string | null } }
      // The pending list is read from the same page as the history, so a full
      // page may hide older pending requests: say so rather than imply a
      // complete inbox.
      return { items: page.items, truncated: page.items.length >= REQUESTS_LIMIT }
    },
    retry: retryTransient,
  })
}

/** Approve or deny one request; the list is refetched either way. */
export function useDecision() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (input: { id: string, decision: 'approve', note?: undefined } | { id: string, decision: 'deny', note: string }) => {
      const response = input.decision === 'approve'
        ? await approveActionRequest(input.id)
        : await denyActionRequest(input.id, input.note.trim() ? { note: input.note.trim() } : null)
      return unwrap<ActionRequestDto>(response)
    },
    // A lost decision (409) means someone else decided first; the refetch shows how.
    onSettled: () => queryClient.invalidateQueries({ queryKey: ['requests'] }),
  })
}
