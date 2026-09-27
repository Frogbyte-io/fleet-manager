import { useQueryClient, type QueryClient } from '@tanstack/vue-query'
import { onBeforeUnmount, onMounted, ref } from 'vue'

export type FleetEventStatus = 'connecting' | 'live' | 'disconnected'

// The stream contains no resource payloads. Every notification refreshes the
// corresponding authorized API reads already held by the web query cache.
const QUERY_KEYS: Record<string, readonly (readonly string[])[]> = {
  'machine.changed': [['fleet', 'machines'], ['machine'], ['machines', 'matrix']],
  'operation.changed': [['operation']],
  'lease.changed': [['lab', 'leases'], ['lab', 'provisions']],
  'onboarding.changed': [['add', 'drafts'], ['onboarding-draft']],
  'proxmox.changed': [['fleet', 'proxmox-accounts'], ['fleet', 'proxmox-discovery'], ['fleet', 'proxmox-guests'], ['machine']],
  'tailnet.changed': [['fleet', 'tailnet-status'], ['fleet', 'tailnet-devices']],
}

export function invalidateFleetEvent(queryClient: QueryClient, eventType: string): void {
  if (eventType === 'gap') {
    void queryClient.invalidateQueries()
    return
  }
  for (const queryKey of QUERY_KEYS[eventType] ?? []) {
    void queryClient.invalidateQueries({ queryKey })
  }
}

/** One stream per app shell; native EventSource reconnects with Last-Event-ID. */
export function useFleetEvents() {
  const queryClient = useQueryClient()
  const status = ref<FleetEventStatus>('connecting')
  let stream: EventSource | null = null

  onMounted(() => {
    stream = new EventSource('/api/v1/events')
    stream.addEventListener('open', () => {
      status.value = 'live'
      // Covers the initial fetch/subscribe race and reconnects with no cursor
      // (the server sends no ID until its first change notification).
      void queryClient.invalidateQueries()
    })
    stream.addEventListener('error', () => {
      status.value = 'disconnected'
    })
    for (const eventType of [...Object.keys(QUERY_KEYS), 'gap']) {
      stream.addEventListener(eventType, () => invalidateFleetEvent(queryClient, eventType))
    }
  })

  onBeforeUnmount(() => {
    stream?.close()
    stream = null
  })

  return status
}
