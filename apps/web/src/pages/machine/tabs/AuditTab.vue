<script setup lang="ts">
import { useInfiniteQuery } from '@tanstack/vue-query'
import { computed } from 'vue'

import { listAuditEvents, type PageAuditEventDto } from '@frogbyte-io/fleet-api-client'
import StatusChip from '@/components/fleet/StatusChip.vue'

import { relativeTime } from '../../fleet/inventory'
import { errorMessage } from '../api'
import { absoluteTime } from '../facts'

// Audit events whose resource is this machine, newest first as the API
// orders them. The full audit log with every filter is the Audit page.
const props = defineProps<{ machineId: string }>()

const PAGE = 50

const query = useInfiniteQuery({
  queryKey: computed(() => ['audit', 'resource', props.machineId]),
  queryFn: async ({ pageParam }) => {
    const response = await listAuditEvents({ resource: props.machineId, limit: PAGE, cursor: pageParam ?? undefined })
    if (response.status !== 200)
      throw new Error(`listAuditEvents failed (${response.status})`)
    return response.data as PageAuditEventDto
  },
  initialPageParam: null as string | null,
  getNextPageParam: last => last.page.nextCursor ?? null,
})

const events = computed(() => (query.data.value?.pages ?? []).flatMap(p => p.items))

function tone(event: { allowed: boolean, outcome?: string | null }) {
  if (!event.allowed)
    return 'err' as const
  switch (event.outcome) {
    case 'succeeded': return 'ok' as const
    case 'failed': return 'err' as const
    case 'blocked_manual_approval': return 'warn' as const
    default: return 'muted' as const
  }
}
</script>

<template>
  <div>
    <p
      v-if="query.isLoading.value"
      class="text-xs text-fc-faint"
    >
      Loading audit events…
    </p>
    <p
      v-else-if="query.error.value"
      class="text-xs text-fc-err"
    >
      Audit events unavailable: {{ errorMessage(query.error.value) }}
    </p>
    <p
      v-else-if="events.length === 0"
      class="text-sm text-fc-faint"
      data-testid="no-audit"
    >
      No audit events for this machine.
    </p>
    <table
      v-else
      class="w-full text-left text-xs"
    >
      <thead class="font-mono text-[10px] uppercase tracking-wider text-fc-faint">
        <tr>
          <th class="py-1 pr-3 font-normal">
            When
          </th>
          <th class="py-1 pr-3 font-normal">
            Action
          </th>
          <th class="py-1 pr-3 font-normal">
            Actor
          </th>
          <th class="py-1 pr-3 font-normal">
            Outcome
          </th>
          <th class="py-1 font-normal">
            Operation
          </th>
        </tr>
      </thead>
      <tbody class="font-mono text-fc-ink">
        <tr
          v-for="event in events"
          :key="event.id"
          class="border-t border-fc-line"
          data-testid="audit-row"
        >
          <td
            class="py-1.5 pr-3 text-fc-muted"
            :title="absoluteTime(event.occurredAt)"
          >
            {{ relativeTime(event.occurredAt) }}
          </td>
          <td class="py-1.5 pr-3">
            {{ event.action }}
          </td>
          <td class="py-1.5 pr-3 text-fc-muted">
            {{ event.actor }}
          </td>
          <td class="py-1.5 pr-3">
            <StatusChip
              :label="event.allowed ? (event.outcome ?? 'allowed') : `denied · ${event.reason}`"
              :tone="tone(event)"
            />
          </td>
          <td class="py-1.5 text-fc-faint">
            {{ event.operationId ?? '—' }}
          </td>
        </tr>
      </tbody>
    </table>
    <button
      v-if="query.hasNextPage.value"
      type="button"
      class="mt-3 font-mono text-[10px] uppercase tracking-wider text-fc-info hover:text-fc-ink disabled:opacity-50"
      :disabled="query.isFetchingNextPage.value"
      data-testid="audit-more"
      @click="query.fetchNextPage()"
    >
      Load older events
    </button>
  </div>
</template>
