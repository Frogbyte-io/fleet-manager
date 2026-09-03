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
  <section class="rounded-2xl border border-slate-800 bg-slate-900 p-6 shadow-xl">
    <div class="flex items-center justify-between">
      <h2 class="text-lg font-semibold text-slate-100">Operations</h2>
      <button
        class="rounded-lg border border-slate-700 px-3 py-1 text-xs text-slate-300 hover:border-slate-500"
        @click="load"
      >
        Refresh
      </button>
    </div>

    <p v-if="failed" class="mt-4 text-sm text-rose-400">{{ failure }}</p>

    <table v-else class="mt-4 w-full text-left text-sm">
      <thead class="text-xs uppercase tracking-wide text-slate-500">
        <tr>
          <th class="py-2">ID</th>
          <th class="py-2">Kind</th>
          <th class="py-2">State</th>
          <th class="py-2" />
        </tr>
      </thead>
      <tbody class="font-mono text-slate-200">
        <tr
          v-for="operation in operations"
          :key="operation.id"
          class="cursor-pointer border-t border-slate-800 hover:bg-slate-800/60"
          @click="open(operation)"
        >
          <td class="py-2 text-xs">{{ operation.id }}</td>
          <td class="py-2">{{ operation.kind }}</td>
          <td class="py-2">{{ operation.state }}</td>
          <td class="py-2 text-right">
            <button
              v-if="!TERMINAL.has(operation.state)"
              class="rounded border border-rose-500/40 px-2 py-0.5 text-xs text-rose-300 hover:bg-rose-500/10"
              @click.stop="cancel(operation)"
            >
              Cancel
            </button>
          </td>
        </tr>
        <tr v-if="operations.length === 0">
          <td colspan="4" class="py-4 text-center text-slate-500">No operations yet</td>
        </tr>
      </tbody>
    </table>

    <div v-if="selected" class="mt-6 rounded-xl border border-slate-800 bg-slate-950 p-4">
      <h3 class="text-sm font-semibold text-slate-200">Operation {{ selected.id }}</h3>
      <p v-if="gapSeen" class="mt-2 text-xs text-amber-300">
        You missed changes to this operation; the view was refetched.
      </p>
      <dl class="mt-3 grid grid-cols-2 gap-x-4 gap-y-1 text-xs">
        <dt class="text-slate-500">Kind</dt>
        <dd class="font-mono">{{ selected.kind }}</dd>
        <dt class="text-slate-500">State</dt>
        <dd class="font-mono">{{ selected.state }}</dd>
        <dt class="text-slate-500">Cancel requested</dt>
        <dd class="font-mono">{{ selected.cancelRequested ? 'yes' : 'no' }}</dd>
        <dt class="text-slate-500">Progress</dt>
        <dd class="font-mono">
          {{ selected.progressCurrent ?? '–' }} / {{ selected.progressTotal ?? '–' }}
          {{ selected.progressMessage ?? '' }}
        </dd>
        <dt class="text-slate-500">Correlation</dt>
        <dd class="font-mono">{{ selected.correlationId ?? '–' }}</dd>
      </dl>
    </div>
  </section>
</template>
