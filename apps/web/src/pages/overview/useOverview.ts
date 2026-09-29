import { useQuery } from '@tanstack/vue-query'
import { useIntervalFn } from '@vueuse/core'
import { computed, ref } from 'vue'

import {
  listAuditEvents,
  listMachines,
  listOnboardingDrafts,
  type AuditEventDto,
  type MachineDto,
  type OnboardingDraftDto,
} from '@frogbyte-io/fleet-api-client'

import { useFleetDrift } from '../drift/useDrift'
import { fetchAllPages, type PagedResponse } from '../fleet/useFleetInventory'
import { useImages } from '../images/useImages'
import { retryTransient, unwrap } from '../machine/api'
import { useOperationsList } from '../operations/useOperations'
import { isFingerprintMismatch } from '../proxmox/proxmox'
import { useProxmox } from '../proxmox/useProxmox'

import {
  activity,
  driftRows,
  kpis,
  leaseRows,
  machineRows,
  onboardingRows,
  operationRows,
  proxmoxRows,
  sortAttention,
  templatePinRows,
} from './attention'

// The Overview composes existing reads on the client ("client-side
// composition first", docs/planning/web-console.md). Every query shares its
// cache key with the page that owns the data, and the FM-902 event stream
// invalidates them, so the page stays live without polling.

export const RECENT_AUDIT_KEY = ['audit', 'recent'] as const
const AUDIT_LIMIT = 25

function page<T>(response: { status: number, data: unknown }): T[] {
  if (response.status !== 200)
    unwrap(response)
  return (response.data as { items: T[] }).items
}

export function useOverview() {
  // Same key and shape as the Fleet page's machines query.
  const machines = useQuery({
    queryKey: ['fleet', 'machines'],
    queryFn: async () => (await fetchAllPages<MachineDto>(async (cursor) => {
      const response = await listMachines({ limit: 200, cursor }) as { status: number, data: unknown }
      // A refused page keeps the API's status, so a denial is shown, not retried.
      if (response.status !== 200)
        unwrap(response)
      return response as PagedResponse<MachineDto>
    })).items,
    retry: retryTransient,
  })
  // Same key and shape as the Add dialog's resume list.
  const drafts = useQuery({
    queryKey: ['add', 'drafts'],
    queryFn: async () => page<OnboardingDraftDto>(await listOnboardingDrafts({ limit: 200 })),
    retry: retryTransient,
  })
  const audit = useQuery({
    queryKey: RECENT_AUDIT_KEY,
    queryFn: async () => page<AuditEventDto>(await listAuditEvents({ limit: AUDIT_LIMIT })),
    retry: retryTransient,
  })
  const operations = useOperationsList()
  const proxmox = useProxmox()
  const images = useImages()
  const drift = useFleetDrift()

  // One clock for "expires in N min".
  const now = ref(Date.now())
  useIntervalFn(() => (now.value = Date.now()), 30_000)

  const leases = computed(() => images.leases.data.value ?? [])
  const operationList = computed(() => operations.data.value?.items ?? [])

  const attention = computed(() => {
    return sortAttention([
      ...machineRows(machines.data.value ?? []),
      ...leaseRows(leases.value, now.value),
      ...operationRows(operationList.value),
      ...proxmoxRows(proxmox.views.value),
      ...onboardingRows(drafts.data.value ?? []),
      ...templatePinRows(images.templates.data.value ?? [], images.versions.value),
      ...driftRows(drift.query.data.value?.items ?? []),
    ])
  })

  const figures = computed(() => kpis(machines.data.value ?? [], leases.value, operationList.value))
  const feed = computed(() => activity(operationList.value, audit.data.value ?? []))

  // A source that failed to load is named, so an empty queue is never
  // mistaken for "all clear".
  const failures = computed(() => [
    machines.error.value && 'machines',
    drafts.error.value && 'onboarding drafts',
    operations.error.value && 'operations',
    proxmox.accounts.error.value && 'Proxmox accounts',
    drift.query.error.value && 'skill drift',
    images.leases.error.value && 'Lab leases',
    images.templates.error.value && 'Lab templates',
    images.loadError.value.some(([what]) => what === 'versions' || what === 'recipes') && 'image versions',
    [...proxmox.discoveryErrors.value.values(), ...proxmox.guestErrors.value.values()].some(e => e && !isFingerprintMismatch(e)) && 'Proxmox discovery',
  ].filter((name): name is string => !!name))

  // "Nothing needs attention" waits for every source.
  const loading = computed(() => machines.isLoading.value
    || drift.query.isLoading.value
    || operations.isLoading.value
    || drafts.isLoading.value
    || proxmox.loading.value
    || images.leases.isLoading.value
    || images.templates.isLoading.value
    || images.loading.value)

  // Nothing is measured until a desired revision is active; say so instead
  // of letting an empty drift list read as "in sync".
  const driftNote = computed(() => {
    const items = drift.query.data.value?.items ?? []
    return items.length > 0 && items.every(entry => entry.status === 'no_revision')
      ? 'No desired revision is active, so skill drift is not measured.'
      : ''
  })

  return { attention, figures, feed, failures, loading, audit, proxmox, driftNote }
}
