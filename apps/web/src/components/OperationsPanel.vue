<script setup lang="ts">
import { onBeforeUnmount, onMounted, ref } from 'vue'

import {
  cancelOperation,
  getOperation,
  listOperations,
  type OperationDto,
} from '@frogbyte-io/fleet-api-client'

const operations = ref<readonly OperationDto[]>([])
const failed = ref(false)
const failure = ref('')
const selected = ref<OperationDto | null>(null)
const gapSeen = ref(false)
let stream: EventSource | null = null
let refresh: ReturnType<typeof setInterval> | null = null

const TERMINAL = new Set(['succeeded', 'failed', 'cancelled', 'timed_out'])

async function load() {
  try {
    const response = await listOperations({ limit: 50 })
    if (response.status === 200) {
      operations.value = response.data.items
      failed.value = false
    }
  } catch (error) {
    failed.value = true
    failure.value = error instanceof Error ? error.message : String(error)
  }
}

async function open(operation: OperationDto) {
  closeStream()
  selected.value = operation
  gapSeen.value = false
  await watch(operation.id)
}

/** Subscribes to the operation's SSE stream; a gap refetches before trusting it. */
async function watch(id: string) {
  stream = new EventSource(`/api/v1/operations/${id}/events`)
  stream.addEventListener('operation', (event) => {
    const snapshot = JSON.parse((event as MessageEvent).data) as OperationDto
    selected.value = snapshot
    if (TERMINAL.has(snapshot.state)) closeStream()
  })
  // History is not archived: a gap means changes were missed while away, and
  // the honest recovery is a refetch, not a replay.
  stream.addEventListener('gap', async () => {
    gapSeen.value = true
    const response = await getOperation(id)
    if (response.status === 200) selected.value = response.data.data
  })
  stream.addEventListener('closed', () => closeStream())
  stream.onerror = () => stream?.close()
}

function closeStream() {
  stream?.close()
  stream = null
}

async function cancel(operation: OperationDto) {
  await cancelOperation(operation.id)
  await load()
  if (selected.value?.id === operation.id) {
    const response = await getOperation(operation.id)
    if (response.status === 200) selected.value = response.data.data
  }
}

onMounted(() => {
  load()
  refresh = setInterval(load, 3000)
})

onBeforeUnmount(() => {
  if (refresh) clearInterval(refresh)
  closeStream()
})
</script>

<template>
  <section class="rounded-sm border border-border bg-card p-6">
    <div class="flex items-center justify-between">
      <h2 class="text-lg font-semibold text-foreground">
        Operations
      </h2>
      <button
        class="rounded-sm border border-input px-3 py-1 text-xs text-foreground hover:border-fc-line2"
        @click="load"
      >
        Refresh
      </button>
    </div>

    <p
      v-if="failed"
      class="mt-4 text-sm text-fc-err"
    >
      {{ failure }}
    </p>

    <table
      v-else
      class="mt-4 w-full text-left text-sm"
    >
      <thead class="text-xs uppercase tracking-wide text-fc-faint">
        <tr>
          <th class="py-2">
            ID
          </th>
          <th class="py-2">
            Kind
          </th>
          <th class="py-2">
            State
          </th>
          <th class="py-2" />
        </tr>
      </thead>
      <tbody class="font-mono text-foreground">
        <tr
          v-for="operation in operations"
          :key="operation.id"
          class="cursor-pointer border-t border-border hover:bg-accent"
          @click="open(operation)"
        >
          <td class="py-2 text-xs">
            {{ operation.id }}
          </td>
          <td class="py-2">
            {{ operation.kind }}
          </td>
          <td class="py-2">
            {{ operation.state }}
          </td>
          <td class="py-2 text-right">
            <button
              v-if="!TERMINAL.has(operation.state)"
              class="rounded border border-fc-err/40 px-2 py-0.5 text-xs text-fc-err hover:bg-fc-err/10"
              @click.stop="cancel(operation)"
            >
              Cancel
            </button>
          </td>
        </tr>
        <tr v-if="operations.length === 0">
          <td
            colspan="4"
            class="py-4 text-center text-fc-faint"
          >
            No operations yet
          </td>
        </tr>
      </tbody>
    </table>

    <div
      v-if="selected"
      class="mt-6 rounded-sm border border-border bg-inset p-4"
    >
      <h3 class="text-sm font-semibold text-foreground">
        Operation {{ selected.id }}
      </h3>
      <p
        v-if="gapSeen"
        class="mt-2 text-xs text-fc-warn"
      >
        You missed changes to this operation; the view was refetched.
      </p>
      <dl class="mt-3 grid grid-cols-2 gap-x-4 gap-y-1 text-xs">
        <dt class="text-fc-faint">
          Kind
        </dt>
        <dd class="font-mono">
          {{ selected.kind }}
        </dd>
        <dt class="text-fc-faint">
          State
        </dt>
        <dd class="font-mono">
          {{ selected.state }}
        </dd>
        <dt class="text-fc-faint">
          Cancel requested
        </dt>
        <dd class="font-mono">
          {{ selected.cancelRequested ? 'yes' : 'no' }}
        </dd>
        <dt class="text-fc-faint">
          Progress
        </dt>
        <dd class="font-mono">
          {{ selected.progressCurrent ?? '–' }} / {{ selected.progressTotal ?? '–' }}
          {{ selected.progressMessage ?? '' }}
        </dd>
        <dt class="text-fc-faint">
          Correlation
        </dt>
        <dd class="font-mono">
          {{ selected.correlationId ?? '–' }}
        </dd>
      </dl>
    </div>
  </section>
</template>
