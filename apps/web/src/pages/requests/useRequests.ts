import { useMutation, useQuery, useQueryClient } from '@tanstack/vue-query'

import {
  approveActionRequest,
  denyActionRequest,
  listActionRequests,
  type ActionRequestDto,
} from '@frogbyte-io/fleet-api-client'

import { retryTransient, unwrap } from '../machine/api'

// Action requests. The inbox and the Overview attention list read the pending
// queue (`state=pending`); the history is a separate query, so a long history
// can never push a waiting request off the page. The fleet event stream's
// `request.changed` (and `operation.changed`, which moves an executing
// request) invalidate the shared ['requests'] prefix, so both stay live.

export const PENDING_REQUESTS_KEY = ['requests', 'pending'] as const
export const HISTORY_REQUESTS_KEY = ['requests', 'history'] as const
/** The list takes a limit and no cursor; this is the API's maximum. */
export const REQUESTS_LIMIT = 200

async function readRequests(params: { state?: string, limit: number }) {
  const response = await listActionRequests(params)
  if (response.status !== 200)
    unwrap(response)
  return (response.data as { items: ActionRequestDto[] }).items
}

/** Requests waiting for a decision, from a `state=pending` query. */
export function usePendingRequests() {
  return useQuery({
    queryKey: PENDING_REQUESTS_KEY,
    queryFn: async () => {
      const items = await readRequests({ state: 'pending', limit: REQUESTS_LIMIT })
      return { items, truncated: items.length >= REQUESTS_LIMIT }
    },
    retry: retryTransient,
  })
}

/** The newest decided requests: everything the API lists except what is pending. */
export function useHistoryRequests() {
  return useQuery({
    queryKey: HISTORY_REQUESTS_KEY,
    queryFn: async () => {
      const items = await readRequests({ limit: REQUESTS_LIMIT })
      return { items: items.filter(r => r.state !== 'pending'), truncated: items.length >= REQUESTS_LIMIT }
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
