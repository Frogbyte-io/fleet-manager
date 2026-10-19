<script setup lang="ts">
import { useQueryClient } from '@tanstack/vue-query'
import { computed, ref, watch } from 'vue'

import { execLabLease, type LabArtifactDto, type OperationDto } from '@frogbyte-io/fleet-api-client'
import StatusChip from '@/components/fleet/StatusChip.vue'

import { operationTone } from '../../overview/attention'

import { relativeTime } from '../../fleet/inventory'
import { errorMessage, isTerminal, unwrap } from '../../machine/api'
import CopyFleetctl from '../../machine/components/CopyFleetctl.vue'
import {
  EXEC_TIMEOUT_MAX_SECONDS,
  EXEC_TIMEOUT_MIN_SECONDS,
  execCommand,
  execOutput,
  formatBytes,
  operationLabel,
  shortId,
} from '../lab'
import { ARTIFACTS_KEY, useOperation } from '../useLab'
import ExecResult from './ExecResult.vue'

// Run one command on a ready lease (FM-720) and read its bounded output.
// The history is the lease's `exec-log` artifacts: the controller keeps
// every finished command's output as one, so it outlives this page.
const props = defineProps<{
  leaseId: string
  ready: boolean
  history: LabArtifactDto[]
  historyLoading: boolean
  historyError: string
  now: number
}>()

const queryClient = useQueryClient()

const script = ref('')
const timeoutSeconds = ref(60)
const busy = ref(false)
const error = ref('')
const runningId = ref<string | null>(null)

const timeoutValid = computed(() => Number.isInteger(timeoutSeconds.value)
  && timeoutSeconds.value >= EXEC_TIMEOUT_MIN_SECONDS && timeoutSeconds.value <= EXEC_TIMEOUT_MAX_SECONDS)
const command = computed(() => (script.value.trim() && timeoutValid.value ? execCommand(props.leaseId, script.value, timeoutSeconds.value) : null))

const current = useOperation(runningId)
const currentOutput = computed(() => (current.data.value ? execOutput(current.data.value) : null))

/** A command is in flight from the moment it is accepted until it settles. */
const running = computed(() => runningId.value !== null && !(current.data.value && isTerminal(current.data.value.state)))

// A finished command's log becomes an artifact just after the operation
// settles (the controller writes it second), so refresh the history now and
// again shortly after; no event announces the artifact.
const HISTORY_RETRY_MS = [0, 1500, 5000]
watch(() => current.data.value?.state, (state) => {
  if (!state || !isTerminal(state))
    return
  for (const delay of HISTORY_RETRY_MS)
    setTimeout(() => void queryClient.invalidateQueries({ queryKey: ARTIFACTS_KEY }), delay)
})

async function run() {
  if (!command.value || running.value)
    return
  busy.value = true
  error.value = ''
  try {
    const operation = unwrap<OperationDto>(await execLabLease(props.leaseId, {
      script: script.value,
      timeoutSeconds: timeoutSeconds.value,
    }), [202])
    runningId.value = operation.id
  }
  catch (caught) {
    error.value = errorMessage(caught)
  }
  finally {
    busy.value = false
  }
}

// One history entry opened at a time; its operation holds the output.
const openId = ref<string | null>(null)
const opened = useOperation(openId)
const openedOutput = computed(() => (opened.data.value ? execOutput(opened.data.value) : null))

function toggle(entry: LabArtifactDto) {
  openId.value = openId.value === entry.operationId ? null : entry.operationId ?? null
}

const execHistory = computed(() => props.history.filter(artifact => artifact.kind === 'exec-log'))


</script>

<template>
  <div class="grid grid-cols-[minmax(0,1fr)] gap-4">
    <form
      class="grid gap-2 text-xs"
      data-testid="exec-form"
      @submit.prevent="run"
    >
      <p
        v-if="!ready"
        class="text-fc-warn"
        data-testid="exec-not-ready"
      >
        Commands run only on a ready lease.
      </p>
      <label
        class="fc-kicker"
        :for="`script-${leaseId}`"
      >Command</label>
      <textarea
        :id="`script-${leaseId}`"
        v-model="script"
        :disabled="!ready"
        rows="4"
        spellcheck="false"
        placeholder="uname -a"
        class="rounded-sm border border-input bg-fc-inset p-2 font-mono text-[11.5px] disabled:opacity-50"
      />
      <p class="text-fc-faint">
        Runs as a shell script (at most 64 KiB) on the guest. The script is never audited. The output shown here is the
        operation's bounded record, as the controller stores it.
      </p>
      <label class="flex items-center gap-2">
        <span class="fc-kicker">Timeout (s)</span>
        <input
          v-model.number="timeoutSeconds"
          type="number"
          :min="EXEC_TIMEOUT_MIN_SECONDS"
          :max="EXEC_TIMEOUT_MAX_SECONDS"
          :disabled="!ready"
          class="h-8 w-20 rounded-sm border border-input bg-background px-2 font-mono"
          :aria-invalid="!timeoutValid"
        >
        <span class="text-fc-faint">{{ EXEC_TIMEOUT_MIN_SECONDS }}–{{ EXEC_TIMEOUT_MAX_SECONDS }}</span>
      </label>
      <CopyFleetctl
        :command="command"
        :missing="`Enter a command (and a ${EXEC_TIMEOUT_MIN_SECONDS}–${EXEC_TIMEOUT_MAX_SECONDS} s timeout) to see the equivalent.`"
      />
      <p
        v-if="command"
        class="-mt-1 text-fc-faint"
      >
        The CLI joins the words after <span class="font-mono">--</span> into the script, so it runs this script wrapped
        once more in <span class="font-mono">sh -c</span>.
      </p>
      <button
        type="submit"
        class="fc-grad-bg h-8 w-fit rounded-sm px-3 font-semibold disabled:opacity-50"
        :disabled="!ready || busy || !command || running"
        data-testid="run-command"
      >
        Run command →
      </button>
      <p
        v-if="error"
        class="text-fc-err"
        role="alert"
      >
        {{ error }}
      </p>
    </form>

    <div
      v-if="runningId"
      class="grid gap-2 rounded-sm border border-fc-line bg-fc-panel p-3"
      data-testid="exec-current"
    >
      <div class="flex items-center gap-2 text-xs">
        <span
          role="status"
          aria-live="polite"
        >
          <StatusChip
            :label="operationLabel(current.data.value?.state ?? 'pending')"
            :tone="operationTone(current.data.value?.state ?? 'pending')"
          />
        </span>
        <span class="font-mono text-[10px] text-fc-faint">{{ runningId }}</span>
      </div>
      <p
        v-if="current.error.value"
        class="text-xs text-fc-err"
      >
        {{ errorMessage(current.error.value) }}
      </p>
      <ExecResult
        v-if="currentOutput"
        :output="currentOutput"
      />
      <p
        v-else-if="current.data.value && !isTerminal(current.data.value.state)"
        class="font-mono text-xs text-fc-muted"
      >
        {{ current.data.value.progressMessage ?? 'Waiting for the command to finish…' }}
      </p>
    </div>

    <section>
      <div class="flex items-baseline justify-between border-b-2 border-fc-ink pb-1.5">
        <h3 class="font-head text-xs font-extrabold uppercase tracking-wide">
          Exec history
        </h3>
        <span class="fc-kicker">exec-log artifacts</span>
      </div>
      <p
        v-if="historyError"
        class="mt-2 border-l-2 border-l-fc-err bg-card px-3 py-2 text-xs text-fc-muted"
        role="alert"
      >
        Could not load the exec history: {{ historyError }}
      </p>
      <p
        v-else-if="historyLoading"
        class="mt-2 text-xs text-fc-muted"
      >
        Loading…
      </p>
      <p
        v-else-if="execHistory.length === 0"
        class="mt-2 text-xs text-fc-muted"
        data-testid="exec-history-empty"
      >
        No commands have finished on this lease.
      </p>
      <ul
        v-else
        class="mt-2 grid gap-1.5"
        data-testid="exec-history"
      >
        <li
          v-for="entry in execHistory"
          :key="entry.id"
          class="rounded-sm border border-fc-line bg-card"
        >
          <button
            type="button"
            class="flex w-full flex-wrap items-center gap-x-3 gap-y-1 px-3 py-2 text-left font-mono text-[10.5px] uppercase tracking-wide text-fc-muted hover:text-fc-ink disabled:cursor-default"
            :aria-expanded="openId !== null && openId === entry.operationId"
            :disabled="!entry.operationId"
            @click="toggle(entry)"
          >
            <span class="text-fc-ink">{{ entry.operationId ? shortId(entry.operationId) : shortId(entry.id) }}</span>
            <span>{{ relativeTime(entry.createdAt, now) }}</span>
            <span>{{ formatBytes(entry.sizeBytes) }}</span>
            <span class="ml-auto">{{ openId !== null && openId === entry.operationId ? 'Hide output' : 'Show output' }}</span>
          </button>
          <div
            v-if="openId !== null && openId === entry.operationId"
            class="border-t border-fc-line p-3"
          >
            <p
              v-if="opened.error.value"
              class="text-xs text-fc-err"
            >
              {{ errorMessage(opened.error.value) }}
            </p>
            <ExecResult
              v-else-if="openedOutput"
              :output="openedOutput"
            />
            <p
              v-else-if="opened.data.value"
              class="text-xs text-fc-muted"
            >
              No output was recorded on this command's operation ({{ operationLabel(opened.data.value.state) }}).
            </p>
            <p
              v-else
              class="text-xs text-fc-muted"
            >
              Loading…
            </p>
          </div>
        </li>
      </ul>
    </section>
  </div>
</template>
