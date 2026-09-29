import { useQuery } from '@tanstack/vue-query'
import { computed, type MaybeRefOrGetter, toValue } from 'vue'

import {
  getMachineDrift,
  listDesiredDrift,
  type MachineDriftDto,
} from '@frogbyte-io/fleet-api-client'

import { fetchAllPages, type PagedResponse } from '../fleet/useFleetInventory'
import { retryTransient, unwrap } from '../machine/api'

// Server state for drift. The fleet list backs the Skills matrix and the
// Overview; the machine read backs the machine's Desired tab. The FM-902
// event stream invalidates the `drift` prefix.

export const FLEET_DRIFT_KEY = ['drift', 'fleet'] as const

export function machineDriftKey(machineId: string) {
  return ['drift', 'machine', machineId] as const
}

/** Every page of fleet drift; a refused page throws the API's own error. */
export function useFleetDrift() {
  const query = useQuery({
    queryKey: FLEET_DRIFT_KEY,
    queryFn: async () => fetchAllPages<MachineDriftDto>(async (cursor) => {
      const response = await listDesiredDrift({ limit: 200, ...(cursor ? { cursor } : {}) }) as { status: number, data: unknown }
      if (response.status !== 200)
        unwrap(response)
      return response as PagedResponse<MachineDriftDto>
    }),
    retry: retryTransient,
  })
  const byMachine = computed(() => new Map((query.data.value?.items ?? []).map(entry => [entry.machineId, entry])))
  return { query, byMachine }
}

export function useMachineDrift(machineId: MaybeRefOrGetter<string>) {
  return useQuery({
    queryKey: computed(() => machineDriftKey(toValue(machineId))),
    queryFn: async () => unwrap<MachineDriftDto>(await getMachineDrift(toValue(machineId))),
    retry: retryTransient,
  })
}
