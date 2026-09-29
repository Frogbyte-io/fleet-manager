<script setup lang="ts">
import { useQueryClient } from '@tanstack/vue-query'
import { computed, ref } from 'vue'

import {
  activateDesiredRevision,
  configureDesiredSource,
  fetchDesiredRevision,
  rollbackDesiredRevision,
  type OperationDto,
} from '@frogbyte-io/fleet-api-client'
import StatusChip from '@/components/fleet/StatusChip.vue'

import { historyAction, isCommitSha, parseFetchResult, type FetchResult } from '../../drift/plan'
import { DESIRED_KEY, useDesiredState } from '../../drift/useDesired'
import { FLEET_DRIFT_KEY } from '../../drift/useDrift'
import { relativeTime } from '../../fleet/inventory'
import { errorMessage, unwrap } from '../../machine/api'
import CopyFleetctl from '../../machine/components/CopyFleetctl.vue'
import OperationStatus from '../../machine/components/OperationStatus.vue'
import { desiredFetchCommand, desiredRevisionCommand, desiredSourceSetCommand } from '../../machine/fleetctl'

// Fleet Git as the desired-state source (FM-409): the remote, the active
// revision, fetching a candidate, and moving between recorded revisions.
// Activation only ever follows a validation the controller ran; an invalid
// candidate has no activate control.
const queryClient = useQueryClient()
const { source, revision, history } = useDesiredState()

const active = computed(() => revision.data.value?.active ?? null)
const entries = computed(() => history.data.value ?? [])
const activeIndex = computed(() => entries.value.findIndex(entry => entry.active))

// --- remote
const remoteInput = ref('')
const remoteDraft = computed(() => remoteInput.value.trim())
const remoteError = ref('')
const savingRemote = ref(false)
const remote = computed(() => source.data.value?.remote ?? null)

async function saveRemote() {
  savingRemote.value = true
  remoteError.value = ''
  try {
    unwrap(await configureDesiredSource({ remote: remoteDraft.value }))
    remoteInput.value = ''
    await queryClient.invalidateQueries({ queryKey: DESIRED_KEY })
  }
  catch (error) {
    remoteError.value = errorMessage(error)
  }
  finally {
    savingRemote.value = false
  }
}

// --- operations (one at a time: they change what the fleet converges toward)
const operationId = ref<string | null>(null)
const operationLabel = ref('')
const startError = ref('')
const starting = ref(false)
const fetched = ref<FetchResult | null>(null)
// True from starting an operation until it settles; a settled operation left
// on screen must not keep the controls locked.
const inFlight = ref(false)

async function start(label: string, run: () => Promise<{ status: number, data: unknown }>) {
  starting.value = true
  startError.value = ''
  try {
    const operation = unwrap<OperationDto>(await run(), [202])
    operationId.value = operation.id
    operationLabel.value = label
    inFlight.value = true
  }
  catch (error) {
    startError.value = errorMessage(error)
  }
  finally {
    starting.value = false
  }
}

const shaInput = ref('')
const sha = computed(() => shaInput.value.trim().toLowerCase())
const shaValid = computed(() => isCommitSha(sha.value))

async function fetchCandidate() {
  fetched.value = null
  await start(`fetch ${sha.value.slice(0, 12)}`, () => fetchDesiredRevision({ commitSha: sha.value }))
}

async function onSettled(operation: OperationDto) {
  inFlight.value = false
  if (operation.kind === 'source.fetch')
    fetched.value = parseFetchResult(operation.resultJson)
  await Promise.all([
    queryClient.invalidateQueries({ queryKey: DESIRED_KEY }),
    queryClient.invalidateQueries({ queryKey: FLEET_DRIFT_KEY }),
  ])
}

// --- activate / roll back (explicit confirmation naming the revision)
interface Pending {
  action: 'activate' | 'rollback'
  commitSha: string
  contentDigest: string
}
const pending = ref<Pending | null>(null)

async function confirm() {
  const target = pending.value
  if (!target)
    return
  pending.value = null
  const run = target.action === 'activate' ? activateDesiredRevision : rollbackDesiredRevision
  await start(`${target.action} ${target.commitSha.slice(0, 12)}`, () => run({ commitSha: target.commitSha, contentDigest: target.contentDigest }))
}

const busy = computed(() => starting.value || inFlight.value)
function dismiss() {
  operationId.value = null
  inFlight.value = false
}
</script>

<template>
  <section
    class="space-y-6 rounded-sm border border-border bg-card p-6"
    data-testid="desired-state-section"
  >
    <div>
      <h2 class="text-lg font-semibold text-foreground">
        Desired state
      </h2>
      <p class="mt-1 text-sm text-fc-muted">
        Fleet Git holds the non-secret resources Fleet converges machines toward. A revision becomes active only after the controller validates it; the last valid one stays active if a fetch fails.
      </p>
    </div>

    <!-- Remote -->
    <div class="space-y-2">
      <h3 class="fc-kicker border-b border-fc-line pb-1">
        Source
      </h3>
      <p
        v-if="source.isLoading.value"
        class="text-xs text-fc-muted"
      >
        Loading…
      </p>
      <p
        v-else-if="source.error.value"
        class="text-xs text-fc-err"
        role="alert"
        data-testid="source-error"
      >
        The source could not be read: {{ errorMessage(source.error.value) }}
      </p>
      <p
        v-else-if="remote"
        class="font-mono text-sm text-fc-ink"
        data-testid="source-remote"
      >
        {{ remote }}
      </p>
      <p
        v-else
        class="text-sm text-fc-muted"
        data-testid="source-none"
      >
        No remote is configured. Set the repository Fleet reads desired state from.
      </p>
      <form
        class="flex flex-wrap items-end gap-2 text-xs"
        @submit.prevent="saveRemote"
      >
        <label class="flex flex-col gap-1">
          <span class="fc-kicker">{{ remote ? 'Change remote' : 'Remote' }}</span>
          <input
            v-model="remoteInput"
            placeholder="ssh://git@host/fleet.git"
            class="h-8 w-96 max-w-full rounded-sm border border-input bg-background px-2 font-mono text-foreground"
            data-testid="remote-input"
          >
        </label>
        <button
          type="submit"
          class="h-8 rounded-sm border border-fc-info/40 px-3 text-fc-info hover:bg-fc-info/10 disabled:opacity-50"
          :disabled="remoteDraft === '' || savingRemote"
          data-testid="remote-save"
        >
          {{ savingRemote ? 'Saving…' : 'Save remote' }}
        </button>
      </form>
      <p class="text-[11px] text-fc-faint">
        Credentials are never stored here: a remote with embedded credentials is refused, and git authenticates with the controller host's own ssh agent or credential helper.
      </p>
      <p
        v-if="remoteError"
        class="text-xs text-fc-err"
        role="alert"
        data-testid="remote-error"
      >
        {{ remoteError }}
      </p>
      <CopyFleetctl
        v-if="remoteDraft"
        :command="desiredSourceSetCommand(remoteDraft)"
      />
    </div>

    <!-- Active revision -->
    <div class="space-y-2">
      <h3 class="fc-kicker border-b border-fc-line pb-1">
        Active revision
      </h3>
      <p
        v-if="revision.isLoading.value"
        class="text-xs text-fc-muted"
      >
        Loading…
      </p>
      <p
        v-else-if="revision.error.value"
        class="text-xs text-fc-err"
        role="alert"
        data-testid="revision-error"
      >
        The active revision could not be read: {{ errorMessage(revision.error.value) }}
      </p>
      <p
        v-else-if="!active"
        class="text-sm text-fc-muted"
        data-testid="revision-none"
      >
        No revision is active. Fetch a commit below and activate it once it validates; until then machines are not compared with anything.
      </p>
      <template v-else>
        <div class="flex flex-wrap items-center gap-3">
          <span
            class="font-mono text-sm text-fc-ink"
            data-testid="revision-sha"
          >{{ active.commitSha.slice(0, 12) }}</span>
          <span class="font-mono text-[10px] text-fc-faint">digest {{ active.contentDigest.slice(0, 12) }}</span>
          <span class="font-mono text-[10px] text-fc-faint">activated {{ relativeTime(active.activatedAt) }}</span>
        </div>
        <p
          v-if="!active.resourcesAvailable"
          class="rounded-sm border border-fc-warn/40 p-3 text-xs text-fc-warn"
          role="alert"
          data-testid="revision-unheld"
        >
          This revision was activated before Fleet held its resources, so nothing can be planned from it. Fetch the same commit again.
        </p>
        <ul
          v-else
          class="flex flex-wrap gap-2 text-xs"
          data-testid="revision-counts"
        >
          <li
            v-for="(count, kind) in active.resourceCounts"
            :key="kind"
          >
            <StatusChip
              :label="`${kind} ${count}`"
              tone="muted"
            />
          </li>
          <li
            v-if="Object.keys(active.resourceCounts).length === 0"
            class="text-fc-muted"
          >
            The revision holds no resources.
          </li>
        </ul>
      </template>
    </div>

    <!-- Fetch -->
    <div class="space-y-2">
      <h3 class="fc-kicker border-b border-fc-line pb-1">
        Fetch a commit
      </h3>
      <form
        class="flex flex-wrap items-end gap-2 text-xs"
        @submit.prevent="fetchCandidate"
      >
        <label class="flex flex-col gap-1">
          <span class="fc-kicker">Commit SHA (40 characters)</span>
          <input
            v-model="shaInput"
            class="h-8 w-[26rem] max-w-full rounded-sm border border-input bg-background px-2 font-mono text-foreground"
            data-testid="fetch-sha"
          >
        </label>
        <button
          type="submit"
          class="h-8 rounded-sm border border-fc-info/40 px-3 text-fc-info hover:bg-fc-info/10 disabled:opacity-50"
          :disabled="!shaValid || !remote || busy"
          data-testid="fetch-start"
        >
          Fetch and validate
        </button>
      </form>
      <p
        v-if="shaInput && !shaValid"
        class="text-xs text-fc-warn"
        data-testid="fetch-sha-hint"
      >
        Use the full 40-character lowercase commit id; branch names are not accepted.
      </p>
      <p
        v-if="!remote"
        class="text-xs text-fc-faint"
      >
        Set a remote first.
      </p>
      <CopyFleetctl
        v-if="shaValid"
        :command="desiredFetchCommand(sha)"
      />
    </div>

    <p
      v-if="startError"
      class="text-xs text-fc-err"
      role="alert"
      data-testid="operation-error"
    >
      {{ startError }}
    </p>
    <OperationStatus
      v-if="operationId"
      :operation-id="operationId"
      :label="operationLabel"
      dismissible
      @settled="onSettled"
      @dismiss="dismiss"
    />

    <!-- Candidate outcome -->
    <div
      v-if="fetched"
      class="space-y-2 rounded-sm border p-3 text-xs"
      :class="fetched.valid ? 'border-fc-ok/40' : 'border-fc-err/40'"
      data-testid="candidate"
    >
      <template v-if="fetched.valid">
        <p class="text-fc-ink">
          <span class="font-mono">{{ fetched.commitSha.slice(0, 12) }}</span> validated with {{ fetched.resourceCount }} resource{{ fetched.resourceCount === 1 ? '' : 's' }}. It is recorded and can be activated.
        </p>
        <button
          v-if="!(active && active.commitSha === fetched.commitSha && active.contentDigest === fetched.contentDigest)"
          type="button"
          class="h-8 rounded-sm border border-fc-warn/50 px-3 text-fc-warn hover:bg-fc-warn/10 disabled:opacity-50"
          :disabled="busy"
          data-testid="candidate-activate"
          @click="pending = { action: 'activate', commitSha: fetched.commitSha, contentDigest: fetched.contentDigest }"
        >
          Activate…
        </button>
        <p
          v-else
          class="text-fc-muted"
        >
          This is already the active revision.
        </p>
      </template>
      <template v-else>
        <p class="font-semibold text-fc-err">
          <span class="font-mono">{{ fetched.commitSha.slice(0, 12) }}</span> did not validate, so it cannot become active. The active revision is unchanged.
        </p>
        <ul
          class="list-disc space-y-0.5 pl-5 font-mono text-[11px] text-fc-muted"
          data-testid="candidate-diagnostics"
        >
          <li
            v-for="diagnostic in fetched.diagnostics"
            :key="diagnostic"
          >
            {{ diagnostic }}
          </li>
        </ul>
      </template>
    </div>

    <!-- History -->
    <div class="space-y-2">
      <h3 class="fc-kicker border-b border-fc-line pb-1">
        History
      </h3>
      <p
        v-if="history.isLoading.value"
        class="text-xs text-fc-muted"
      >
        Loading…
      </p>
      <p
        v-else-if="history.error.value"
        class="text-xs text-fc-err"
        role="alert"
        data-testid="history-error"
      >
        The history could not be read: {{ errorMessage(history.error.value) }}
      </p>
      <p
        v-else-if="entries.length === 0"
        class="text-sm text-fc-muted"
        data-testid="history-empty"
      >
        No valid revision has been fetched yet.
      </p>
      <ul
        v-else
        class="space-y-1"
        data-testid="history"
      >
        <li
          v-for="(entry, index) in entries"
          :key="`${entry.commitSha}:${entry.contentDigest}`"
          class="flex flex-wrap items-center gap-3 rounded-sm border border-fc-line bg-background px-3 py-1.5 text-xs"
          :data-testid="`history-${entry.commitSha.slice(0, 12)}`"
        >
          <span class="font-mono text-fc-ink">{{ entry.commitSha.slice(0, 12) }}</span>
          <span class="font-mono text-[10px] text-fc-faint">digest {{ entry.contentDigest.slice(0, 12) }}</span>
          <StatusChip
            v-if="entry.active"
            label="active"
            tone="ok"
          />
          <button
            v-else
            type="button"
            class="ml-auto h-7 rounded-sm border border-fc-warn/50 px-2 text-fc-warn hover:bg-fc-warn/10 disabled:opacity-50"
            :disabled="busy"
            :data-testid="`history-${historyAction(index, activeIndex)}-${entry.commitSha.slice(0, 12)}`"
            @click="pending = { action: historyAction(index, activeIndex) === 'rollback' ? 'rollback' : 'activate', commitSha: entry.commitSha, contentDigest: entry.contentDigest }"
          >
            {{ historyAction(index, activeIndex) === 'rollback' ? 'Roll back…' : 'Activate…' }}
          </button>
        </li>
      </ul>
    </div>

    <!-- Confirmation -->
    <div
      v-if="pending"
      class="space-y-2 rounded-sm border border-fc-warn/40 p-3 text-xs"
      role="alertdialog"
      aria-label="Confirm revision change"
      data-testid="confirm"
    >
      <p class="text-fc-ink">
        {{ pending.action === 'rollback' ? 'Roll back to' : 'Activate' }}
        <span class="font-mono">{{ pending.commitSha.slice(0, 12) }}</span>?
      </p>
      <p class="text-fc-muted">
        This changes what every machine is compared with and what a plan would do. Nothing is applied to a machine until you apply a plan. It is recorded in the audit log.
      </p>
      <div class="flex flex-wrap items-center gap-2">
        <button
          type="button"
          class="h-8 rounded-sm border border-fc-warn/50 px-3 text-fc-warn hover:bg-fc-warn/10"
          data-testid="confirm-yes"
          @click="confirm"
        >
          {{ pending.action === 'rollback' ? 'Roll back' : 'Activate' }}
        </button>
        <button
          type="button"
          class="h-8 rounded-sm px-3 text-fc-muted hover:text-fc-ink"
          data-testid="confirm-no"
          @click="pending = null"
        >
          Cancel
        </button>
      </div>
      <CopyFleetctl :command="desiredRevisionCommand(pending.action, pending.commitSha, pending.contentDigest)" />
    </div>
  </section>
</template>
