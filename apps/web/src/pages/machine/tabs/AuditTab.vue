<script setup lang="ts">
import { useQuery } from '@tanstack/vue-query'
import { computed, ref } from 'vue'

import { listAuditEvents, type PageAuditEventDto, type PageAuditEventDtoItemsItem } from '@frogbyte-io/fleet-api-client'
import StatusChip from '@/components/fleet/StatusChip.vue'

import { relativeTime } from '../../fleet/inventory'
import { errorMessage } from '../api'
import { absoluteTime } from '../facts'

// Audit events whose resource is this machine, newest first. The API pages
// in append (oldest-first) order only, so the tab reads a time window whole
// and reverses it; the full audit log with every filter is the Audit page.
const props = defineProps<{ machineId: string }>()

const WINDOWS = [
  { value: 86_400_000, label: '24 hours' },
  { value: 7 * 86_400_000, label: '7 days' },
  { value: 30 * 86_400_000, label: '30 days' },
  { value: 0, label: 'All time' },
] as const
const PAGE = 200
const MAX_PAGES = 10

const windowMs = ref<number>(7 * 86_400_000)

const query = useQuery({
  queryKey: computed(() => ['audit', 'resource', props.machineId, windowMs.value]),
  queryFn: async () => {
    const from = windowMs.value ? Date.now() - windowMs.value : undefined
    const items: PageAuditEventDtoItemsItem[] = []
    let cursor: string | undefined
    for (let i = 0; i < MAX_PAGES; i++) {
      const response = await listAuditEvents({ resource: props.machineId, from, limit: PAGE, cursor })
      if (response.status !== 200)
        throw new Error(`listAuditEvents failed (${response.status})`)
      const page = response.data as PageAuditEventDto
      items.push(...page.items)
      if (!page.page.nextCursor)
        return { events: items.reverse(), truncated: false }
      cursor = page.page.nextCursor
    }
    return { events: items.reverse(), truncated: true }
  },
})

const events = computed(() => query.data.value?.events ?? [])

function tone(event: { allowed: boolean, outcome?: string | null }) {
  if (!event.allowed)
    return 'err' as const
  switch (event.outcome) {
    case 'succeeded': return 'ok' as const
    case 'failed':
    case 'timed_out': return 'err' as const
    case 'blocked_manual_approval': return 'warn' as const
    default: return 'muted' as const
  }
}
</script>

<template>
  <div class="space-y-3">
    <div class="flex items-center gap-2 text-xs">
      <label
        for="audit-window"
        class="fc-kicker"
      >Window</label>
      <select
        id="audit-window"
        v-model.number="windowMs"
        class="h-8 rounded-sm border border-input bg-background px-2 text-foreground"
        data-testid="audit-window"
      >
        <option
          v-for="option in WINDOWS"
          :key="option.value"
          :value="option.value"
        >
          {{ option.label }}
        </option>
      </select>
    </div>
    <p
      v-if="query.isLoading.value"
      class="text-xs text-fc-faint"
    >
      Loading audit events…
    </p>
    <template v-else-if="query.error.value">
      <p class="text-xs text-fc-err">
        Audit events unavailable: {{ errorMessage(query.error.value) }}
      </p>
      <button
        type="button"
        class="font-mono text-[10px] uppercase tracking-wider text-fc-info hover:text-fc-ink"
        @click="query.refetch()"
      >
        Retry
      </button>
    </template>
    <template v-else>
      <p
        v-if="query.data.value?.truncated"
        class="text-xs text-fc-warn"
        data-testid="audit-truncated"
      >
        More than {{ PAGE * MAX_PAGES }} events in this window; showing the first {{ PAGE * MAX_PAGES }} recorded. Pick a shorter window for the latest.
      </p>
      <p
        v-if="events.length === 0"
        class="text-sm text-fc-faint"
        data-testid="no-audit"
      >
        No audit events for this machine in this window.
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
    </template>
  </div>
</template>
