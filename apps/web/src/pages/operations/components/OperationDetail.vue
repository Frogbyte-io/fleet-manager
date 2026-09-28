<script setup lang="ts">
import { useQueryClient } from '@tanstack/vue-query'
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { RouterLink } from 'vue-router'

import { cancelOperation, getOperation, type OperationDto } from '@frogbyte-io/fleet-api-client'
import StatusChip from '@/components/fleet/StatusChip.vue'

import { errorMessage, isTerminal, unwrap } from '../../machine/api'
import { operationTone } from '../../overview/attention'
import { blockedGuidance, cancellable } from '../operations'
import { OPERATIONS_KEY } from '../useOperations'

// One operation, followed live over its SSE stream
// (`/api/v1/operations/{id}/events`). Snapshots are not archived: a `gap`
// means changes were missed, and the honest recovery is a refetch.
const props = defineProps<{ operationId: string, initial: OperationDto | null }>()
const emit = defineEmits<{ close: [] }>()

const queryClient = useQueryClient()

const operation = ref<OperationDto | null>(props.initial)
const loadError = ref('')
const gapSeen = ref(false)
const live = ref(false)
/** Each distinct snapshot this page saw, newest last. */
const timeline = ref<{ at: number, state: string, progress: string }[]>([])

function record(snapshot: OperationDto) {
  operation.value = snapshot
  const progress = [
    snapshot.progressCurrent !== null && snapshot.progressCurrent !== undefined ? `${snapshot.progressCurrent}/${snapshot.progressTotal ?? '?'}` : '',
    snapshot.progressMessage ?? '',
  ].filter(Boolean).join(' · ')
  const last = timeline.value[timeline.value.length - 1]
  if (!last || last.state !== snapshot.state || last.progress !== progress)
    timeline.value = [...timeline.value, { at: snapshot.updatedAt, state: snapshot.state, progress }]
}

async function refetch() {
  try {
    record(unwrap<OperationDto>(await getOperation(props.operationId)))
    loadError.value = ''
  }
  catch (error) {
    loadError.value = errorMessage(error)
  }
}

let stream: EventSource | null = null
function close() {
  stream?.close()
  stream = null
  live.value = false
}

function follow() {
  close()
  timeline.value = []
  gapSeen.value = false
  if (props.initial)
    record(props.initial)
  void refetch()
  if (typeof EventSource === 'undefined')
    return
  stream = new EventSource(`/api/v1/operations/${encodeURIComponent(props.operationId)}/events`)
  stream.addEventListener('open', () => (live.value = true))
  stream.addEventListener('operation', (event) => {
    try {
      const snapshot = JSON.parse((event as MessageEvent).data) as OperationDto
      record(snapshot)
      if (isTerminal(snapshot.state)) {
        close()
        void queryClient.invalidateQueries({ queryKey: OPERATIONS_KEY })
      }
    }
    catch {
      void refetch()
    }
  })
  stream.addEventListener('gap', () => {
    gapSeen.value = true
    void refetch()
  })
  stream.addEventListener('closed', close)
  stream.addEventListener('error', () => (live.value = false))
}

watch(() => props.operationId, follow, { immediate: true })
onBeforeUnmount(close)

const confirming = ref(false)
const cancelBusy = ref(false)
const cancelError = ref('')

async function cancel() {
  cancelBusy.value = true
  cancelError.value = ''
  try {
    const response = await cancelOperation(props.operationId)
    if (response.status < 200 || response.status >= 300)
      unwrap(response)
    confirming.value = false
    await refetch()
    await queryClient.invalidateQueries({ queryKey: OPERATIONS_KEY })
  }
  catch (error) {
    cancelError.value = errorMessage(error)
  }
  finally {
    cancelBusy.value = false
  }
}

const blocked = computed(() => (operation.value?.state === 'blocked_manual_approval' ? blockedGuidance(operation.value) : null))

function pretty(json: string | null | undefined): string {
  if (!json)
    return ''
  try {
    return JSON.stringify(JSON.parse(json), null, 2)
  }
  catch {
    return json
  }
}

function time(ms: number | null | undefined): string {
  return ms ? new Date(ms).toISOString().replace('T', ' ').slice(0, 19) : '—'
}
</script>

<template>
  <section
    class="space-y-3 rounded-sm border border-fc-line bg-card p-4 text-xs"
    data-testid="operation-detail"
  >
    <div class="flex items-start gap-2">
      <div class="min-w-0">
        <p class="fc-kicker">
          operation · {{ operationId }}
        </p>
        <h2 class="flex items-center gap-2 font-head text-[16px] font-extrabold">
          {{ operation?.kind ?? 'loading…' }}
          <StatusChip
            v-if="operation"
            :label="operation.state"
            :tone="operationTone(operation.state)"
          />
          <span
            class="font-mono text-[10px] font-normal"
            :class="live ? 'text-fc-ok' : 'text-fc-faint'"
            data-testid="stream-status"
          >{{ live ? '● live' : operation && isTerminal(operation.state) ? 'settled' : '○ not streaming' }}</span>
        </h2>
      </div>
      <button
        type="button"
        class="ml-auto text-fc-muted hover:text-fc-ink"
        aria-label="Close operation"
        @click="emit('close')"
      >
        ✕
      </button>
    </div>

    <p
      v-if="loadError && !operation"
      class="text-fc-err"
      role="alert"
    >
      {{ loadError }}
    </p>
    <p
      v-if="gapSeen"
      class="text-fc-warn"
      role="status"
    >
      Changes were missed while disconnected; the operation was refetched.
    </p>

    <template v-if="operation">
      <dl class="grid grid-cols-[110px_1fr] gap-x-3 gap-y-0.5 font-mono text-[11px]">
        <dt class="text-fc-faint">
          created
        </dt><dd>{{ time(operation.createdAt) }}Z</dd>
        <dt class="text-fc-faint">
          updated
        </dt><dd>{{ time(operation.updatedAt) }}Z</dd>
        <dt class="text-fc-faint">
          deadline
        </dt><dd>{{ operation.deadlineAt ? `${time(operation.deadlineAt)}Z` : '—' }}</dd>
        <dt class="text-fc-faint">
          progress
        </dt><dd>{{ operation.progressCurrent ?? '–' }} / {{ operation.progressTotal ?? '–' }} {{ operation.progressMessage ?? '' }}</dd>
        <dt class="text-fc-faint">
          correlation
        </dt><dd>{{ operation.correlationId ?? '—' }}</dd>
      </dl>

      <div
        v-if="blocked"
        class="space-y-1.5 rounded-sm border border-fc-warn/40 bg-fc-warn/5 p-3"
        data-testid="blocked-guidance"
      >
        <p class="font-semibold text-fc-warn">
          Blocked on an approval. This is final for this operation: it will not resume by itself.
        </p>
        <p class="text-fc-ink">
          {{ blocked.detail }}
        </p>
        <ol class="list-decimal pl-5 text-fc-muted">
          <li
            v-for="step in blocked.steps"
            :key="step"
          >
            {{ step }}
          </li>
        </ol>
        <RouterLink
          v-if="blocked.link"
          :to="blocked.link.to"
          class="inline-block font-mono text-[10px] uppercase tracking-wider text-fc-info hover:text-fc-ink"
        >
          {{ blocked.link.label }} →
        </RouterLink>
      </div>

      <div
        v-if="cancellable(operation)"
        class="space-y-2"
      >
        <button
          v-if="!confirming"
          type="button"
          class="h-8 rounded-sm border border-fc-err/40 px-3 text-fc-err hover:bg-fc-err/10"
          data-testid="cancel"
          @click="confirming = true"
        >
          Cancel operation…
        </button>
        <div
          v-else
          class="flex flex-wrap items-center gap-2 rounded-sm border border-fc-err/40 p-2"
          role="alertdialog"
          aria-label="Confirm cancel"
        >
          <span>Ask the worker to stop <span class="font-mono">{{ operation.kind }}</span>? Work already done is not undone; the operation records what completed.</span>
          <button
            type="button"
            class="h-7 rounded-sm border border-fc-err bg-fc-err/10 px-2.5 font-semibold text-fc-err disabled:opacity-50"
            :disabled="cancelBusy"
            data-testid="cancel-confirm"
            @click="cancel"
          >
            Yes, cancel
          </button>
          <button
            type="button"
            class="h-7 px-2 text-fc-muted hover:text-fc-ink"
            @click="confirming = false"
          >
            Keep running
          </button>
        </div>
      </div>
      <p
        v-else-if="operation.cancelRequested && !isTerminal(operation.state)"
        class="text-fc-muted"
      >
        Cancel requested; waiting for the worker to stop.
      </p>
      <p
        v-if="cancelError"
        class="text-fc-err"
        role="alert"
      >
        {{ cancelError }}
      </p>

      <div>
        <h3 class="fc-kicker border-b border-fc-line pb-1">
          Event stream
        </h3>
        <ol
          class="mt-1 space-y-0.5 font-mono text-[11px]"
          data-testid="timeline"
        >
          <li
            v-for="(entry, index) in timeline"
            :key="index"
            class="flex gap-2"
          >
            <span class="text-fc-faint">{{ time(entry.at).slice(11) }}</span>
            <span class="text-fc-ink">{{ entry.state }}</span>
            <span class="text-fc-muted">{{ entry.progress }}</span>
          </li>
        </ol>
      </div>

      <div v-if="operation.errorJson">
        <h3 class="fc-kicker border-b border-fc-line pb-1">
          Error
        </h3>
        <pre class="mt-1 max-h-60 overflow-auto whitespace-pre-wrap break-all font-mono text-[11px] text-fc-err">{{ pretty(operation.errorJson) }}</pre>
      </div>
      <div v-if="operation.resultJson">
        <h3 class="fc-kicker border-b border-fc-line pb-1">
          Result
        </h3>
        <pre class="mt-1 max-h-60 overflow-auto whitespace-pre-wrap break-all font-mono text-[11px] text-fc-muted">{{ pretty(operation.resultJson) }}</pre>
      </div>
    </template>
  </section>
</template>
