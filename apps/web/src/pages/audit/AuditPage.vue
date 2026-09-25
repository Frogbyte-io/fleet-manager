<script setup lang="ts">
import { useQuery } from '@tanstack/vue-query'
import { computed, ref, watch } from 'vue'

import {
  listAuditEvents,
  type PageAuditEventDtoItemsItem,
} from '@frogbyte-io/fleet-api-client'
import StatusChip from '@/components/fleet/StatusChip.vue'

import { relativeTime } from '../fleet/inventory'
import {
  buildParams,
  EMPTY_FILTERS,
  hasFilters,
  MAX_PAGES,
  OUTCOMES,
  PAGE,
  type AuditFilters,
} from './filters'

// The fleet-wide audit log. Metadata only by construction: the API's DTO
// omits free-form metadata strings, so a secret cannot reach this page
// even if one leaked into the ledger's metadata.
const filters = ref<AuditFilters>({ ...EMPTY_FILTERS })
const applied = ref<AuditFilters>({ ...EMPTY_FILTERS })
const cursor = ref<string | undefined>(undefined)

const showFilters = computed(() => hasFilters(applied.value))

function apply(): void {
  cursor.value = undefined
  applied.value = { ...filters.value }
}

function clear(): void {
  filters.value = { ...EMPTY_FILTERS }
  apply()
}

function nextPage(): void {
  if (nextCursor.value) cursor.value = nextCursor.value
}

const query = useQuery({
  queryKey: computed(() => ['audit', 'page', applied.value, cursor.value]),
  queryFn: async () => {
    const { params, error } = buildParams(applied.value, cursor.value)
    if (error) throw new Error(error)
    const items: PageAuditEventDtoItemsItem[] = []
    let next: string | undefined = params.cursor as string | undefined
    let walked = 0
    // Walk whole pages so a filter's result set is complete up to the
    // bound, matching the machine Audit tab's convention. The final
    // page's own nextCursor decides whether more pages exist.
    for (;;) {
      const response = await listAuditEvents({ ...params, cursor: next, limit: PAGE } as never)
      if (response.status !== 200) {
        throw new Error(`the audit query failed (${response.status})`)
      }
      const page = response.data as { items: PageAuditEventDtoItemsItem[]; page: { nextCursor?: string | null } }
      items.push(...page.items)
      walked += 1
      const finalCursor = page.page.nextCursor ?? null
      if (!finalCursor) return { events: items, truncated: false, nextCursor: null }
      if (walked >= MAX_PAGES) return { events: items, truncated: true, nextCursor: finalCursor }
      next = finalCursor
    }
  },
})

const events = computed(() => query.data.value?.events ?? [])
const truncated = computed(() => query.data.value?.truncated ?? false)
const nextCursor = computed(() => query.data.value?.nextCursor ?? undefined)

// Re-running a query resets the cursor: new filters start at page one.
watch(applied, () => {
  cursor.value = undefined
})

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

function absolute(ms: number): string {
  return new Date(ms).toISOString()
}
</script>

<template>
  <div class="flex items-end justify-between">
    <div>
      <p class="fc-kicker">
        who did what
      </p>
      <h1 class="fc-h1 mt-1">
        <span class="fc-grad-text">Audit log</span>
      </h1>
    </div>
  </div>

  <form
    class="mt-6 flex flex-wrap items-end gap-3"
    @submit.prevent="apply"
  >
    <label class="text-xs text-fc-muted">
      Actor
      <input
        v-model="filters.actor"
        type="text"
        placeholder="principal id"
        class="mt-1 block h-8 w-48 rounded-sm border border-input bg-background px-2 text-sm text-foreground"
        data-testid="audit-actor"
      >
    </label>
    <label class="text-xs text-fc-muted">
      Action
      <input
        v-model="filters.action"
        type="text"
        placeholder="machine.update"
        class="mt-1 block h-8 w-44 rounded-sm border border-input bg-background px-2 text-sm text-foreground"
        data-testid="audit-action"
      >
    </label>
    <label class="text-xs text-fc-muted">
      Resource
      <input
        v-model="filters.resource"
        type="text"
        placeholder="resource id"
        class="mt-1 block h-8 w-48 rounded-sm border border-input bg-background px-2 text-sm text-foreground"
        data-testid="audit-resource"
      >
    </label>
    <label class="text-xs text-fc-muted">
      Outcome
      <select
        v-model="filters.outcome"
        class="mt-1 block h-8 w-44 rounded-sm border border-input bg-background px-2 text-sm text-foreground"
        data-testid="audit-outcome"
      >
        <option value="">
          any
        </option>
        <option
          v-for="outcome in OUTCOMES"
          :key="outcome"
          :value="outcome"
        >
          {{ outcome }}
        </option>
      </select>
    </label>
    <label class="text-xs text-fc-muted">
      From
      <input
        v-model="filters.from"
        type="datetime-local"
        class="mt-1 block h-8 w-52 rounded-sm border border-input bg-background px-2 text-sm text-foreground"
        data-testid="audit-from"
      >
    </label>
    <label class="text-xs text-fc-muted">
      To
      <input
        v-model="filters.to"
        type="datetime-local"
        class="mt-1 block h-8 w-52 rounded-sm border border-input bg-background px-2 text-sm text-foreground"
        data-testid="audit-to"
      >
    </label>
    <button
      type="submit"
      class="fc-grad-bg h-8 rounded-sm px-4 text-sm font-medium"
      data-testid="audit-apply"
    >
      Apply
    </button>
    <button
      v-if="showFilters"
      type="button"
      class="h-8 rounded-sm border border-border px-3 text-sm text-fc-muted hover:text-foreground"
      data-testid="audit-clear"
      @click="clear"
    >
      Clear
    </button>
  </form>

  <p
    v-if="query.isLoading.value"
    class="mt-4 text-sm text-fc-faint"
    role="status"
    aria-busy="true"
  >
    Loading audit events…
  </p>
  <template v-else-if="query.error.value">
    <p
      class="mt-4 text-sm text-fc-err"
      role="alert"
    >
      Audit events unavailable: {{ (query.error.value as Error).message }}
    </p>
    <button
      type="button"
      class="mt-2 font-mono text-xs uppercase tracking-wider text-fc-info hover:text-fc-ink"
      @click="query.refetch()"
    >
      Retry
    </button>
  </template>
  <template v-else>
    <p
      v-if="truncated"
      class="mt-4 text-xs text-fc-warn"
      data-testid="audit-truncated"
    >
      More than {{ PAGE * MAX_PAGES }} events match; showing the first {{ PAGE * MAX_PAGES }} in ledger order. Narrow the filters or page forward.
    </p>
    <p
      v-if="events.length === 0"
      class="mt-4 text-sm text-fc-faint"
      data-testid="no-audit"
    >
      No audit events match these filters.
    </p>
    <table
      v-else
      class="mt-4 w-full text-left text-sm"
      data-testid="audit-table"
    >
      <thead class="text-xs uppercase tracking-wide text-fc-muted">
        <tr>
          <th class="py-2 pr-3 font-medium">
            When
          </th>
          <th class="py-2 pr-3 font-medium">
            Action
          </th>
          <th class="py-2 pr-3 font-medium">
            Actor
          </th>
          <th class="py-2 pr-3 font-medium">
            Resource
          </th>
          <th class="py-2 font-medium">
            Outcome
          </th>
        </tr>
      </thead>
      <tbody class="font-mono">
        <tr
          v-for="event in events"
          :key="event.id"
          class="border-t border-border"
          data-testid="audit-row"
        >
          <td
            class="py-2 pr-3 text-fc-muted"
            :title="absolute(event.occurredAt)"
          >
            {{ relativeTime(event.occurredAt) }}
          </td>
          <td class="py-2 pr-3 text-foreground">
            {{ event.action }}
          </td>
          <td class="py-2 pr-3 text-fc-muted">
            {{ event.actor }}
          </td>
          <td class="py-2 pr-3 text-fc-muted">
            {{ event.resource ?? '—' }}
          </td>
          <td class="py-2">
            <StatusChip
              :label="event.allowed ? (event.outcome ?? 'allowed') : `denied · ${event.reason}`"
              :tone="tone(event)"
            />
          </td>
        </tr>
      </tbody>
    </table>
    <button
      v-if="nextCursor"
      type="button"
      class="mt-4 h-8 rounded-sm border border-border px-3 text-sm text-fc-muted hover:text-foreground"
      data-testid="audit-next"
      @click="nextPage"
    >
      Next page
    </button>
  </template>
</template>
