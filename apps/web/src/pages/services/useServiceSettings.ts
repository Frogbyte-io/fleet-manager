import { useMutation, useQuery, useQueryClient } from '@tanstack/vue-query'
import { computed, toValue, type MaybeRefOrGetter } from 'vue'

import {
  getActionRequest,
  getServiceSettings,
  requestServiceAction,
  requestServiceDomainsChange,
  requestServiceEnvChange,
  requestServiceHealthChange,
  type ActionRequestDto,
  type ServiceDomainsBody,
  type ServiceEnvBody,
  type ServiceHealthBody,
  type ServiceSettingsDto,
} from '@frogbyte-io/fleet-api-client'

import { retryTransient, unwrap } from '../machine/api'
import { requestTerminal, type Verb } from './settings'

// Server state for one resource's settings and the requests the console
// files. Every change is a brokered action request: the API answers 201 with
// the request, and the person follows it to its outcome. Nothing here keeps a
// variable value: the mutation input holds it until the call is sent, and the
// answer carries names and flags only.

/** Settings are read on demand: they cost a call to Coolify. */
export function useServiceSettings(id: MaybeRefOrGetter<string>, enabled: MaybeRefOrGetter<boolean> = true) {
  return useQuery({
    queryKey: computed(() => ['services', 'settings', toValue(id)] as const),
    enabled: computed(() => !!toValue(id) && toValue(enabled)),
    queryFn: async () => unwrap<ServiceSettingsDto>(await getServiceSettings(toValue(id))),
    retry: retryTransient,
    // A change that was approved elsewhere shows up on the next focus.
    refetchOnWindowFocus: true,
  })
}

/** One filed request, refreshed until it settles (and live via `request.changed`). */
export function useFiledRequest(id: MaybeRefOrGetter<string | null>) {
  return useQuery({
    queryKey: computed(() => ['requests', 'detail', toValue(id)] as const),
    enabled: computed(() => !!toValue(id)),
    queryFn: async () => unwrap<ActionRequestDto>(await getActionRequest(toValue(id)!)),
    retry: retryTransient,
    refetchInterval: query => (query.state.data && requestTerminal(query.state.data.state) ? false : 3000),
  })
}

function fileOnce<Body>(send: (serviceId: string, body: Body) => Promise<{ status: number, data: unknown }>) {
  return async (input: { serviceId: string, body: Body }) =>
    unwrap<ActionRequestDto>(await send(input.serviceId, input.body), [201])
}

/** Refreshes what a settled request may have changed. */
function useRefresh() {
  const queryClient = useQueryClient()
  return () => Promise.all([
    queryClient.invalidateQueries({ queryKey: ['requests'] }),
    queryClient.invalidateQueries({ queryKey: ['services'] }),
  ])
}

export function useLifecycleRequest() {
  const refresh = useRefresh()
  return useMutation({
    mutationFn: async (input: { serviceId: string, verb: Verb, reason?: string }) =>
      unwrap<ActionRequestDto>(await requestServiceAction(input.serviceId, input.verb, { reason: input.reason ?? '' }), [201]),
    onSettled: refresh,
  })
}

export function useEnvRequest() {
  const refresh = useRefresh()
  return useMutation({ mutationFn: fileOnce<ServiceEnvBody>(requestServiceEnvChange), onSettled: refresh })
}

export function useDomainsRequest() {
  const refresh = useRefresh()
  return useMutation({ mutationFn: fileOnce<ServiceDomainsBody>(requestServiceDomainsChange), onSettled: refresh })
}

export function useHealthRequest() {
  const refresh = useRefresh()
  return useMutation({ mutationFn: fileOnce<ServiceHealthBody>(requestServiceHealthChange), onSettled: refresh })
}
