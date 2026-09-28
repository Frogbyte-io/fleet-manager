<script setup lang="ts">
import { computed, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'

import StatusChip from '@/components/fleet/StatusChip.vue'
import { Skeleton } from '@/components/ui/skeleton'

import { relativeTime } from '../fleet/inventory'
import { errorMessage } from '../machine/api'
import { operationTone } from '../overview/attention'
import OperationDetail from './components/OperationDetail.vue'
import { filterOperations, type StateGroup } from './operations'
import { OPERATIONS_LIMIT, useOperationsList } from './useOperations'

// Durable operations: every mutation Fleet runs. The list refreshes from
// the FM-902 event stream; the selected operation follows its own stream.
const list = useOperationsList()
const route = useRoute()
const router = useRouter()

const all = computed(() => list.data.value?.items ?? [])
const group = ref<StateGroup>('all')
const kind = ref('')
const text = ref('')
const kinds = computed(() => [...new Set(all.value.map(o => o.kind))].sort())
const rows = computed(() => filterOperations(all.value, { group: group.value, kind: kind.value, text: text.value }))

const GROUPS: { id: StateGroup, label: string }[] = [
  { id: 'all', label: 'All' },
  { id: 'live', label: 'Running' },
  { id: 'blocked', label: 'Blocked' },
  { id: 'failed', label: 'Failed' },
  { id: 'succeeded', label: 'Succeeded' },
  { id: 'cancelled', label: 'Cancelled' },
]
const counts = computed(() => Object.fromEntries(GROUPS.map(g => [g.id, filterOperations(all.value, { group: g.id, kind: '', text: '' }).length])))

// The selected operation is in the URL (`?op=`), so attention rows and
// toasts can link straight to it.
const selected = computed(() => (typeof route.query.op === 'string' ? route.query.op : null))
function select(id: string | null) {
  router.replace({ query: { ...route.query, op: id ?? undefined } })
}
const selectedInitial = computed(() => all.value.find(o => o.id === selected.value) ?? null)
</script>

<template>
  <div>
    <p class="fc-kicker">
      durable operations · every mutation Fleet runs
    </p>
    <h1 class="fc-h1">
      Operations
    </h1>

    <div
      class="mt-4 flex flex-wrap gap-1.5"
      role="group"
      aria-label="Filter by state"
    >
      <button
        v-for="item in GROUPS"
        :key="item.id"
        type="button"
        class="rounded-sm border px-2.5 py-1 text-xs"
        :class="group === item.id ? 'border-ring text-fc-ink' : 'border-fc-line2 text-fc-muted hover:text-fc-ink'"
        :aria-pressed="group === item.id"
        :data-testid="`group-${item.id}`"
        @click="group = item.id"
      >
        {{ item.label }} <span class="font-mono text-[10px] text-fc-faint">{{ counts[item.id] }}</span>
      </button>
    </div>
    <div class="mt-3 flex flex-wrap items-end gap-3 text-xs">
      <label class="flex flex-col gap-1">
        <span class="fc-kicker">Kind</span>
        <select
          v-model="kind"
          class="h-8 rounded-sm border border-input bg-background px-2 font-mono text-foreground"
          data-testid="filter-kind"
        >
          <option value="">All kinds</option>
          <option
            v-for="k in kinds"
            :key="k"
            :value="k"
          >
            {{ k }}
          </option>
        </select>
      </label>
      <label class="flex flex-col gap-1">
        <span class="fc-kicker">Search</span>
        <input
          v-model="text"
          placeholder="Operation id or kind"
          class="h-8 w-64 rounded-sm border border-input bg-background px-2 text-foreground"
          data-testid="filter-text"
        >
      </label>
    </div>

    <div
      v-if="list.error.value"
      class="mt-4 border-l-2 border-l-fc-err bg-card px-3 py-2 text-xs text-fc-muted"
      role="alert"
    >
      Could not load operations: {{ errorMessage(list.error.value) }}
    </div>
    <div
      v-if="list.data.value?.truncated"
      class="mt-4 border-l-2 border-l-fc-warn bg-card px-3 py-2 text-xs text-fc-muted"
      role="status"
    >
      Showing the newest {{ OPERATIONS_LIMIT }} operations; the operations API does not page further.
    </div>

    <div
      class="mt-4 grid gap-4"
      :class="selected ? 'xl:grid-cols-[minmax(0,1fr)_minmax(0,520px)]' : ''"
    >
      <div>
        <div
          v-if="list.isLoading.value"
          class="grid gap-2"
        >
          <Skeleton
            v-for="i in 4"
            :key="i"
            class="h-10 rounded-sm"
          />
        </div>
        <p
          v-else-if="rows.length === 0"
          class="rounded-sm border border-fc-line p-6 text-sm text-fc-muted"
          data-testid="operations-empty"
        >
          {{ all.length === 0 ? 'No operations yet.' : 'No operations match these filters.' }}
        </p>
        <table
          v-else
          class="w-full border border-fc-line bg-card text-xs"
          data-testid="operations-table"
        >
          <thead>
            <tr class="bg-fc-inset text-left">
              <th class="fc-kicker px-2 py-1.5 font-normal">
                Kind
              </th>
              <th class="fc-kicker px-2 py-1.5 font-normal">
                State
              </th>
              <th class="fc-kicker px-2 py-1.5 font-normal">
                Progress
              </th>
              <th class="fc-kicker px-2 py-1.5 font-normal">
                Updated
              </th>
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="operation in rows"
              :key="operation.id"
              class="cursor-pointer border-t border-fc-line hover:bg-fc-inset"
              :class="operation.id === selected ? 'bg-fc-inset' : ''"
              :data-testid="`operation-${operation.id}`"
              @click="select(operation.id)"
            >
              <td class="px-2 py-1.5">
                <button
                  type="button"
                  class="text-left font-mono text-fc-ink hover:underline"
                  :aria-current="operation.id === selected ? 'true' : undefined"
                  :aria-label="`Open ${operation.kind} ${operation.id}`"
                  @click.stop="select(operation.id)"
                >
                  {{ operation.kind }}
                </button>
                <span class="block font-mono text-[10px] text-fc-faint">{{ operation.id }}</span>
              </td>
              <td class="px-2 py-1.5">
                <StatusChip
                  :label="operation.state"
                  :tone="operationTone(operation.state)"
                />
              </td>
              <td class="px-2 py-1.5 font-mono text-[11px] text-fc-muted">
                {{ operation.progressMessage ?? '' }}
              </td>
              <td class="px-2 py-1.5 font-mono text-[10px] text-fc-faint">
                {{ relativeTime(operation.updatedAt) }}
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <OperationDetail
        v-if="selected"
        :key="selected"
        :operation-id="selected"
        :initial="selectedInitial"
        @close="select(null)"
      />
    </div>
  </div>
</template>
