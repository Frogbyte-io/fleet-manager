import { useMutation, useQuery, useQueryClient } from '@tanstack/vue-query'
import { computed, toValue, type MaybeRefOrGetter } from 'vue'

import {
  getCoolifyObservations,
  getOperation,
  listExternalAccounts,
  listSiteTemplates,
  requestSiteDeployment,
  type ActionRequestDto,
  type CoolifyObservationDto,
  type ExternalAccountDto,
  type SiteDeployBody,
  type SiteTemplateDto,
} from '@frogbyte-io/fleet-api-client'

import { isTerminal, retryTransient, unwrap } from '../../machine/api'
import { parseResult } from './newSite'

// Server state for the new-site wizard. Deploying is one brokered action
// request: the API answers 201 with the request, and the person follows it to
// its outcome. The targets (servers, projects, environments) come from the
// account's latest Coolify observation, the same read model the Services list
// uses.

export function useSiteTemplates() {
  return useQuery({
    queryKey: ['services', 'site-templates'] as const,
    queryFn: async () => unwrap<{ templates: SiteTemplateDto[] }>(await listSiteTemplates()).templates,
    retry: retryTransient,
    // Templates are built into the controller: they change only with an upgrade.
    staleTime: 5 * 60 * 1000,
  })
}

export function useCoolifyAccounts() {
  return useQuery({
    queryKey: ['services', 'coolify-accounts'] as const,
    queryFn: async () => {
      const response = await listExternalAccounts({ kind: 'coolify', limit: 200 }) as { status: number, data: unknown }
      if (response.status !== 200)
        unwrap(response)
      return (response.data as { items: ExternalAccountDto[] }).items.filter(account => account.kind === 'coolify')
    },
    retry: retryTransient,
  })
}

export function useCoolifyObservation(accountId: MaybeRefOrGetter<string>) {
  return useQuery({
    queryKey: computed(() => ['services', 'coolify-observation', toValue(accountId)] as const),
    enabled: computed(() => !!toValue(accountId)),
    queryFn: async () => unwrap<CoolifyObservationDto>(await getCoolifyObservations(toValue(accountId))),
    retry: retryTransient,
  })
}

export function useDeploySite() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (body: SiteDeployBody) => unwrap<ActionRequestDto>(await requestSiteDeployment(body), [201]),
    onSettled: () => Promise.all([
      queryClient.invalidateQueries({ queryKey: ['requests'] }),
      queryClient.invalidateQueries({ queryKey: ['services'] }),
    ]),
  })
}

/**
 * The structured result of the deployment's operation: the created resource
 * and every step. A failed operation still carries it when the resource was
 * created, so a partial deployment is shown rather than lost.
 */
export function useDeployResult(operationId: MaybeRefOrGetter<string | null | undefined>) {
  return useQuery({
    queryKey: computed(() => ['operations', 'detail', toValue(operationId)] as const),
    enabled: computed(() => !!toValue(operationId)),
    queryFn: async () => {
      const operation = unwrap<{ state: string, resultJson?: string | null, errorJson?: string | null }>(await getOperation(toValue(operationId)!))
      return { state: operation.state, result: parseResult(operation.resultJson) }
    },
    retry: retryTransient,
    refetchInterval: query => (query.state.data && isTerminal(query.state.data.state) ? false : 3000),
  })
}
