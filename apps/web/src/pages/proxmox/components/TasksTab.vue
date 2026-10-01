<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { RouterLink } from 'vue-router'

import StatusChip from '@/components/fleet/StatusChip.vue'

import { relativeTime } from '../../fleet/inventory'
import { errorMessage } from '../../machine/api'
import CopyFleetctl from '../../machine/components/CopyFleetctl.vue'
import {
  EMPTY_TASK_FILTERS,
  TASK_STATUSES,
  taskDuration,
  taskLabel,
  tasksCommand,
  taskTone,
  tierBlockReason,
  tierStatus,
  type AccountView,
  type TaskFilters,
} from '../proxmox'
import { useProxmoxTasks } from '../useProxmox'

// Recent PVE tasks of one pinned account (FM-609), newest first. Read-only:
// the API joins each UPID to the Fleet operation that started it, and the
// warnings say which nodes the snapshot is missing.
const props = defineProps<{ views: AccountView[] }>()

const STATUSES = TASK_STATUSES

// Only an account whose pin discovery verified is asked for tasks.
const pinned = computed(() => props.views.filter(v => v.state === 'pinned'))
const blocked = computed(() => props.views.filter(v => v.state === 'changed' || v.state === 'unconfirmed'))

// The selection (and its filters) survives an account being briefly not
// pinned, e.g. while discovery refetches; it moves only when the account is
// gone from the list. Nothing is asked of it until it is pinned again.
const accountId = ref<string | null>(null)
watch([pinned, () => props.views], ([list, all]) => {
  if (!all.some(v => v.account.id === accountId.value))
    accountId.value = list[0]?.account.id ?? null
}, { immediate: true })
const view = computed(() => pinned.value.find(v => v.account.id === accountId.value) ?? null)
const selected = computed(() => props.views.find(v => v.account.id === accountId.value) ?? null)
const queryAccountId = computed(() => view.value ? accountId.value : null)
// A token without the discover tier sees no nodes, so PVE answers no tasks:
// say why instead of claiming the cluster has none.
const blind = computed(() => view.value && tierStatus(view.value.privileges, 'discover') === 'missing'
  ? tierBlockReason(view.value.privileges, 'discover')
  : null)
const selectable = computed(() => selected.value && !view.value ? [...pinned.value, selected.value] : pinned.value)

const filters = ref<TaskFilters>({ ...EMPTY_TASK_FILTERS })
watch(accountId, () => (filters.value = { ...EMPTY_TASK_FILTERS }))

// The filter choices come from what discovery and the guest list report.
const nodes = computed(() => (view.value?.discovery?.resources ?? [])
  .filter(r => r.kind === 'node')
  .map(r => r.node ?? r.name ?? r.id.replace(/^node\//, ''))
  .sort())
const guests = computed(() => (view.value?.guests ?? [])
  .filter(g => g.vmid !== null && g.vmid !== undefined)
  .sort((a, b) => (a.vmid ?? 0) - (b.vmid ?? 0)))

const tasks = useProxmoxTasks(queryAccountId, filters)
const pages = computed(() => tasks.data.value?.pages ?? [])
const rows = computed(() => pages.value.flatMap(p => p.items))
// Warnings describe the whole snapshot, so every page repeats them.
const warnings = computed(() => [...new Set(pages.value.flatMap(p => p.warnings))])
const first = computed(() => pages.value[0] ?? null)
const filtered = computed(() => !!(filters.value.node || filters.value.vmid || filters.value.status))

function clear() {
  filters.value = { ...EMPTY_TASK_FILTERS }
}

function absolute(ms: number): string {
  return new Date(ms).toISOString()
}

function user(task: { user: string, tokenId?: string | null }): string {
  return task.tokenId ? `${task.user}!${task.tokenId}` : task.user
}
</script>

<template>
  <div class="mt-4 space-y-3">
    <div
      v-if="blocked.length"
      class="border-l-2 border-l-fc-err bg-card px-3 py-2 text-xs text-fc-muted"
      role="status"
      data-testid="tasks-blocked"
    >
      Tasks of {{ blocked.map(v => v.account.name).join(', ') }} are not shown until {{ blocked.length === 1 ? 'its' : 'their' }} fingerprint is confirmed (Accounts).
    </div>

    <p
      v-if="pinned.length === 0 && !selected"
      class="rounded-sm border border-fc-line p-6 text-sm text-fc-muted"
      data-testid="tasks-no-account"
    >
      No pinned Proxmox account to read tasks from.
    </p>

    <template v-else>
      <form
        class="flex flex-wrap items-end gap-3"
        aria-label="Task filters"
        @submit.prevent
      >
        <label class="flex flex-col gap-1 text-xs">
          <span class="fc-kicker">Account</span>
          <select
            v-model="accountId"
            class="h-8 w-48 max-w-full rounded-sm border border-input bg-background px-2 text-foreground"
            data-testid="tasks-account"
          >
            <option
              v-for="item in selectable"
              :key="item.account.id"
              :value="item.account.id"
            >
              {{ item.account.name }}
            </option>
          </select>
        </label>
        <label class="flex flex-col gap-1 text-xs">
          <span class="fc-kicker">Node</span>
          <select
            v-model="filters.node"
            class="h-8 w-36 max-w-full rounded-sm border border-input bg-background px-2 text-foreground"
            data-testid="tasks-node"
          >
            <option value="">
              any
            </option>
            <option
              v-for="node in nodes"
              :key="node"
              :value="node"
            >
              {{ node }}
            </option>
          </select>
        </label>
        <label class="flex flex-col gap-1 text-xs">
          <span class="fc-kicker">Guest</span>
          <select
            v-model="filters.vmid"
            class="h-8 w-48 max-w-full rounded-sm border border-input bg-background px-2 text-foreground"
            data-testid="tasks-guest"
          >
            <option value="">
              any
            </option>
            <option
              v-for="guest in guests"
              :key="guest.vmid!"
              :value="String(guest.vmid)"
            >
              {{ guest.vmid }}{{ guest.name ? ` · ${guest.name}` : '' }}
            </option>
          </select>
        </label>
        <label class="flex flex-col gap-1 text-xs">
          <span class="fc-kicker">Status</span>
          <select
            v-model="filters.status"
            class="h-8 w-32 max-w-full rounded-sm border border-input bg-background px-2 text-foreground"
            data-testid="tasks-status"
          >
            <option value="">
              any
            </option>
            <option
              v-for="status in STATUSES"
              :key="status"
              :value="status"
            >
              {{ taskLabel(status) }}
            </option>
          </select>
        </label>
        <button
          v-if="filtered"
          type="button"
          class="h-8 rounded-sm border border-border px-3 text-xs text-fc-muted hover:text-foreground"
          data-testid="tasks-clear"
          @click="clear"
        >
          Clear
        </button>
        <button
          type="button"
          class="h-8 rounded-sm border border-border px-3 text-xs text-fc-muted hover:text-foreground disabled:opacity-50"
          :disabled="tasks.isFetching.value"
          data-testid="tasks-refresh"
          @click="tasks.refetch()"
        >
          Refresh
        </button>
      </form>

      <div
        v-if="warnings.length"
        class="space-y-0.5 border-l-2 border-l-fc-warn bg-card px-3 py-2 text-xs text-fc-muted"
        role="status"
        data-testid="tasks-warnings"
      >
        <p class="font-semibold text-fc-warn">
          This task list is incomplete:
        </p>
        <p
          v-for="warning in warnings"
          :key="warning"
        >
          {{ warning }}
        </p>
      </div>

      <p
        v-if="!view"
        class="rounded-sm border border-fc-line p-6 text-sm text-fc-muted"
        role="status"
        data-testid="tasks-unavailable"
      >
        {{ selected?.account.name }} is not verified right now ({{ selected?.state }}); its tasks are not asked for until it is pinned again.
      </p>
      <p
        v-else-if="tasks.isLoading.value"
        class="text-xs text-fc-faint"
        role="status"
        aria-busy="true"
        data-testid="tasks-loading"
      >
        Loading tasks…
      </p>
      <div
        v-else-if="tasks.error.value && rows.length === 0"
        class="space-y-1 border-l-2 border-l-fc-err bg-card px-3 py-2 text-xs text-fc-muted"
        role="alert"
        data-testid="tasks-error"
      >
        <p>Could not load tasks of {{ view?.account.name }}: {{ errorMessage(tasks.error.value) }}</p>
        <button
          type="button"
          class="font-mono text-[10px] uppercase tracking-wider text-fc-info hover:text-fc-ink"
          @click="tasks.refetch()"
        >
          Retry
        </button>
      </div>
      <p
        v-else-if="rows.length === 0"
        class="rounded-sm border border-fc-line p-6 text-sm text-fc-muted"
        data-testid="tasks-empty"
      >
        {{ filtered ? 'No tasks match these filters.' : blind ? `The token cannot see this cluster's nodes, so no tasks are listed. ${blind}` : 'PVE reports no recent tasks for this account.' }}
      </p>
      <div
        v-else
        class="overflow-x-auto"
      >
        <table
          class="w-full border border-fc-line bg-card text-xs"
          data-testid="tasks-table"
        >
          <caption class="sr-only">
            Recent PVE tasks of {{ view?.account.name }}, newest first
          </caption>
          <thead>
            <tr class="bg-fc-inset text-left">
              <th
                scope="col"
                class="fc-kicker px-2 py-1.5 font-normal"
              >
                Task
              </th>
              <th
                scope="col"
                class="fc-kicker px-2 py-1.5 font-normal"
              >
                Node
              </th>
              <th
                scope="col"
                class="fc-kicker px-2 py-1.5 font-normal"
              >
                Status
              </th>
              <th
                scope="col"
                class="fc-kicker px-2 py-1.5 font-normal"
              >
                Started
              </th>
              <th
                scope="col"
                class="fc-kicker px-2 py-1.5 font-normal"
              >
                User
              </th>
              <th
                scope="col"
                class="fc-kicker px-2 py-1.5 font-normal"
              >
                Fleet operation
              </th>
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="task in rows"
              :key="task.upid"
              class="border-t border-fc-line"
              data-testid="task-row"
              :data-upid="task.upid"
            >
              <td class="px-2 py-1.5">
                <span class="font-mono text-fc-ink">{{ task.taskType }}</span>
                <span
                  v-if="task.targetId"
                  class="ml-1.5 font-mono text-fc-muted"
                >{{ task.targetId }}</span>
              </td>
              <td class="px-2 py-1.5 font-mono text-fc-muted">
                {{ task.node }}
              </td>
              <td class="px-2 py-1.5">
                <StatusChip
                  :label="taskLabel(task.status)"
                  :tone="taskTone(task.status)"
                  :data-testid="`task-status-${task.status}`"
                />
                <span
                  v-if="task.exitStatus && task.exitStatus !== 'OK'"
                  class="mt-0.5 block max-w-xs break-words font-mono text-[10px] text-fc-faint"
                >{{ task.exitStatus }}</span>
              </td>
              <td
                class="whitespace-nowrap px-2 py-1.5 font-mono text-fc-muted"
                :title="absolute(task.startedAt)"
              >
                {{ relativeTime(task.startedAt) }}<template v-if="taskDuration(task.startedAt, task.endedAt)">
                  · {{ taskDuration(task.startedAt, task.endedAt) }}
                </template>
              </td>
              <td class="break-all px-2 py-1.5 font-mono text-[10.5px] text-fc-muted">
                {{ user(task) }}
              </td>
              <td class="px-2 py-1.5">
                <RouterLink
                  v-if="task.fleetOperationId"
                  :to="{ path: '/operations', query: { op: task.fleetOperationId } }"
                  class="font-mono text-[10.5px] text-fc-info hover:text-fc-ink"
                  data-testid="task-operation"
                >
                  {{ task.fleetOperationId }}
                </RouterLink>
                <span
                  v-else
                  class="text-fc-faint"
                >—</span>
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <div
        v-if="rows.length"
        class="flex flex-wrap items-center gap-3"
      >
        <button
          v-if="tasks.hasNextPage.value"
          type="button"
          class="h-8 rounded-sm border border-border px-3 text-xs text-fc-muted hover:text-foreground disabled:opacity-50"
          :disabled="tasks.isFetchingNextPage.value"
          data-testid="tasks-more"
          @click="tasks.fetchNextPage()"
        >
          {{ tasks.isFetchingNextPage.value ? 'Loading…' : 'Load more' }}
        </button>
        <p
          v-if="tasks.error.value"
          class="text-xs text-fc-err"
          role="alert"
        >
          {{ errorMessage(tasks.error.value) }}
        </p>
        <p
          v-if="first"
          class="font-mono text-[10px] uppercase tracking-wide text-fc-faint"
        >
          {{ rows.length }} task{{ rows.length === 1 ? '' : 's' }} · PVE {{ first.pveVersion }} · reflects the controller's read {{ relativeTime(first.observedAt) }}
        </p>
      </div>

      <CopyFleetctl
        v-if="accountId"
        :command="tasksCommand(accountId, filters)"
      />
    </template>
  </div>
</template>
