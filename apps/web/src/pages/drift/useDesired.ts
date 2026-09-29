import { useQuery } from '@tanstack/vue-query'

import {
  getDesiredRevision,
  getDesiredSource,
  listDesiredHistory,
  type DesiredHistoryEntryDto,
  type DesiredSourceDto,
  type DesiredStatusDto,
} from '@frogbyte-io/fleet-api-client'

import { retryTransient, unwrap } from '../machine/api'

// Server state for the Settings "Desired state" section (FM-409).

export const DESIRED_KEY = ['desired'] as const
export const SOURCE_KEY = ['desired', 'source'] as const
export const REVISION_KEY = ['desired', 'revision'] as const
export const HISTORY_KEY = ['desired', 'history'] as const

export function useDesiredState() {
  const source = useQuery({
    queryKey: SOURCE_KEY,
    queryFn: async () => unwrap<DesiredSourceDto>(await getDesiredSource()),
    retry: retryTransient,
  })
  const revision = useQuery({
    queryKey: REVISION_KEY,
    queryFn: async () => unwrap<DesiredStatusDto>(await getDesiredRevision()),
    retry: retryTransient,
  })
  const history = useQuery({
    queryKey: HISTORY_KEY,
    queryFn: async () => {
      const response = await listDesiredHistory() as { status: number, data: unknown }
      if (response.status !== 200)
        unwrap(response)
      return (response.data as { items: DesiredHistoryEntryDto[] }).items
    },
    retry: retryTransient,
  })
  return { source, revision, history }
}
