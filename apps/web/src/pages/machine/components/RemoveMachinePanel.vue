<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'

import {
  removeMachine,
  reviewMachineRemoval,
  type MachineDto,
  type MachineRemovalReviewDto,
  type MachineRemovedDto,
  type MachineUninstallDto,
  type ReviewMachineRemovalRequest,
} from '@frogbyte-io/fleet-api-client'
import StatusChip from '@/components/fleet/StatusChip.vue'

import { ApiRequestError, errorMessage, unwrap } from '../api'
import { machineRemoveCommand, type UninstallAuth, type UninstallChoice } from '../fleetctl'
import { authLabel, codeSpans, deletedRows } from '../removal'
import CopyFleetctl from './CopyFleetctl.vue'

// "Remove machine": the two calls `fleetctl machines remove` makes (#616).
// The review answers what the removal would do and, when nothing blocks it,
// the token that binds the removal to that answer. Everything shown here is
// the controller's answer; the only decision taken here is that a removal
// needs a token, which the review withholds while anything blocks it.
const props = defineProps<{ machine: MachineDto }>()
const emit = defineEmits<{
  busy: [value: boolean]
  removed: [outcome: MachineRemovedDto]
  close: []
}>()

const sshEndpoints = computed(() => props.machine.endpoints.filter(e => e.kind === 'ssh'))

const uninstall = ref(false)
const endpointId = ref(sshEndpoints.value[0]?.id ?? '')
const authType = ref<UninstallAuth['type']>('default')
const identityPath = ref('')

const review = ref<MachineRemovalReviewDto | null>(null)
// The request the shown review answered; the removal sends exactly this.
const reviewed = ref<ReviewMachineRemovalRequest | null>(null)
const outcome = ref<MachineRemovedDto | null>(null)
const error = ref<string | null>(null)
// Which call the error came from: a failed review, or a refused removal.
const errorStep = ref<'review' | 'remove' | 'unanswered'>('review')
const busy = ref<'review' | 'remove' | null>(null)

watch(busy, value => emit('busy', value !== null))

const choice = computed<UninstallChoice | null>(() => {
  if (!uninstall.value)
    return null
  const auth: UninstallAuth = authType.value === 'identityFile'
    ? { type: 'identityFile', path: identityPath.value.trim() }
    : { type: authType.value }
  return { endpointId: endpointId.value, auth }
})

const optionsReady = computed(() => {
  const picked = choice.value
  if (!picked)
    return true
  return picked.endpointId !== '' && (picked.auth.type !== 'identityFile' || picked.auth.path !== '')
})

const command = computed(() => (optionsReady.value ? machineRemoveCommand(props.machine.id, choice.value) : null))

function requestBody(): ReviewMachineRemovalRequest {
  const picked = choice.value
  if (!picked)
    return {}
  const body: MachineUninstallDto = { endpointId: picked.endpointId }
  if (picked.auth.type !== 'default')
    body.auth = picked.auth
  return { uninstall: body }
}

// Each review request carries a generation; changing the options starts a
// new one, so an answer to a request made for other options is dropped.
let generation = 0

// The token binds the uninstall: changing it drops the review.
watch([uninstall, endpointId, authType, identityPath], () => {
  generation += 1
  if (busy.value === 'review')
    busy.value = null
  review.value = null
  reviewed.value = null
  error.value = null
})

async function runReview() {
  const current = ++generation
  busy.value = 'review'
  error.value = null
  const body = requestBody()
  try {
    const answer = unwrap<MachineRemovalReviewDto>(await reviewMachineRemoval(props.machine.id, body))
    if (current !== generation)
      return
    review.value = answer
    reviewed.value = body
  }
  catch (cause) {
    if (current !== generation)
      return
    review.value = null
    reviewed.value = null
    errorStep.value = 'review'
    error.value = errorMessage(cause)
  }
  finally {
    if (current === generation)
      busy.value = null
  }
}

async function runRemove() {
  const token = review.value?.reviewToken
  if (!token || !reviewed.value)
    return
  busy.value = 'remove'
  error.value = null
  try {
    const removed = unwrap<MachineRemovedDto>(await removeMachine(props.machine.id, { ...reviewed.value, reviewToken: token }))
    outcome.value = removed
    emit('removed', removed)
  }
  catch (cause) {
    // Whatever refused the removal (a hold, a stale token, a failed
    // uninstall), the way on is a fresh review.
    // A refusal is an API answer; without one (a network failure) the
    // outcome is unknown, and a fresh review shows whether the machine is
    // still there.
    errorStep.value = cause instanceof ApiRequestError ? 'remove' : 'unanswered'
    error.value = errorMessage(cause)
    review.value = null
    reviewed.value = null
  }
  finally {
    busy.value = null
  }
}

onMounted(runReview)

const ERROR_KICKER = {
  review: 'Review failed',
  remove: 'Not removed',
  unanswered: 'No answer from the controller · review again to see the machine\'s state',
} as const

const blocked = computed(() => (review.value?.blockers.length ?? 0) > 0)
const layout = computed(() => Object.entries(review.value?.uninstall?.layout ?? {}))
</script>

<template>
  <div
    v-if="outcome"
    class="space-y-3 text-xs"
    data-testid="remove-outcome"
  >
    <div class="border-l-2 border-l-fc-ok bg-fc-inset px-3 py-2">
      <p class="fc-kicker">
        Removed
      </p>
      <p class="mt-0.5 text-sm text-fc-ink">
        <span class="font-semibold">{{ outcome.name }}</span>
        <span class="font-mono text-fc-muted"> · {{ outcome.machineId }}</span>
        is no longer in Fleet.
      </p>
    </div>

    <dl class="grid grid-cols-[minmax(0,7rem)_1fr] gap-x-3 gap-y-1.5 sm:grid-cols-[minmax(0,12rem)_1fr]">
      <dt class="text-fc-muted">
        fleetd uninstall
      </dt>
      <dd
        class="font-mono text-fc-ink"
        data-testid="outcome-uninstall"
      >
        {{ outcome.uninstalled ? 'uninstalled' : 'not run' }}<span
          v-if="outcome.uninstallSummary"
          class="text-fc-muted"
        > · {{ outcome.uninstallSummary }}</span>
      </dd>
      <dt class="text-fc-muted">
        Node identity
      </dt>
      <dd class="font-mono text-fc-ink">
        {{ outcome.nodeIdentityRemoved ? 'deleted' : 'none' }}{{ outcome.sessionClosed ? ' · live session closed' : '' }}
      </dd>
      <dt class="text-fc-muted">
        Stored secrets revoked
      </dt>
      <dd class="font-mono tabular-nums text-fc-ink">
        {{ outcome.secretsRevoked }}
      </dd>
      <dt class="text-fc-muted">
        Host keys unpinned
      </dt>
      <dd class="font-mono text-fc-ink">
        {{ outcome.unpinnedHosts.length > 0 ? outcome.unpinnedHosts.join(', ') : 'none' }}
      </dd>
      <dt class="text-fc-muted">
        Host keys kept (shared)
      </dt>
      <dd class="font-mono text-fc-ink">
        {{ outcome.keptHosts.length > 0 ? outcome.keptHosts.join(', ') : 'none' }}
      </dd>
    </dl>

    <p
      v-if="outcome.secretRevocationError"
      class="border-l-2 border-l-fc-err bg-fc-inset px-3 py-1.5 text-fc-ink"
      data-testid="outcome-secret-error"
    >
      <span class="fc-kicker block">Secrets not revoked · delete them by hand</span>
      {{ outcome.secretRevocationError }}
    </p>
    <p
      v-if="outcome.unpinFailedHosts.length > 0"
      class="border-l-2 border-l-fc-warn bg-fc-inset px-3 py-1.5 text-fc-ink"
      data-testid="outcome-unpin-failed"
    >
      <span class="fc-kicker block">Pins not removed · remove them from the controller's known-hosts file</span>
      <span class="font-mono">{{ outcome.unpinFailedHosts.join(', ') }}</span>
    </p>
    <p
      v-if="outcome.auditGaps.length > 0"
      class="border-l-2 border-l-fc-warn bg-fc-inset px-3 py-1.5 text-fc-ink"
      data-testid="outcome-audit-gaps"
    >
      <span class="fc-kicker block">Audit events not written · the controller log has the cause</span>
      <span class="font-mono">{{ outcome.auditGaps.join(', ') }}</span>
    </p>

    <div class="flex justify-end">
      <button
        type="button"
        class="fc-grad-bg inline-flex h-8 items-center rounded-sm px-4 text-xs font-medium"
        data-testid="remove-done"
        @click="emit('close')"
      >
        Back to Fleet →
      </button>
    </div>
  </div>

  <form
    v-else
    class="space-y-4 text-xs"
    @submit.prevent="review?.reviewToken ? runRemove() : runReview()"
  >
    <section class="space-y-2">
      <label class="inline-flex items-center gap-2 text-fc-ink">
        <input
          v-model="uninstall"
          type="checkbox"
          :disabled="busy !== null"
          data-testid="remove-uninstall"
        >
        Uninstall fleetd over SSH first
      </label>
      <p class="text-fc-muted">
        Without it nothing on the machine is touched. With it the controller runs the fleetd uninstall first; a failed
        uninstall leaves the machine in Fleet.
      </p>
      <template v-if="uninstall">
        <p
          v-if="sshEndpoints.length === 0"
          class="text-fc-warn"
          data-testid="remove-no-ssh"
        >
          This machine has no SSH endpoint, so the uninstall cannot run.
        </p>
        <div
          v-else
          class="flex flex-wrap items-end gap-3"
        >
          <label class="flex flex-col gap-1">
            <span class="fc-kicker">Endpoint</span>
            <select
              v-model="endpointId"
              :disabled="busy !== null"
              class="h-8 rounded-sm border border-input bg-background px-2 font-mono text-foreground"
              data-testid="remove-endpoint"
            >
              <option
                v-for="endpoint in sshEndpoints"
                :key="endpoint.id"
                :value="endpoint.id"
              >
                {{ endpoint.reference }}
              </option>
            </select>
          </label>
          <label class="flex flex-col gap-1">
            <span class="fc-kicker">Auth</span>
            <select
              v-model="authType"
              :disabled="busy !== null"
              class="h-8 rounded-sm border border-input bg-background px-2 text-foreground"
              data-testid="remove-auth"
            >
              <option value="default">
                Endpoint default
              </option>
              <option value="agent">
                SSH agent
              </option>
              <option value="identityFile">
                Identity file
              </option>
            </select>
          </label>
          <label
            v-if="authType === 'identityFile'"
            class="flex flex-col gap-1"
          >
            <span class="fc-kicker">Identity path (controller host)</span>
            <input
              v-model="identityPath"
              :disabled="busy !== null"
              placeholder="~/.ssh/id_ed25519"
              class="h-8 w-64 max-w-full rounded-sm border border-input bg-background px-2 font-mono text-foreground"
              data-testid="remove-identity"
            >
          </label>
        </div>
      </template>
    </section>

    <p
      v-if="busy === 'review' && !review"
      class="font-mono text-fc-faint"
      data-testid="remove-reviewing"
    >
      Reviewing…
    </p>

    <template v-if="review">
      <section
        v-if="blocked"
        class="space-y-2"
        data-testid="remove-blockers"
      >
        <h3 class="fc-kicker border-b-2 border-fc-ink pb-1 text-fc-ink">
          Blocked · {{ review.blockers.length }}
        </h3>
        <p class="text-fc-muted">
          The controller refuses this removal until each of these is cleared. Clear them, then review again.
        </p>
        <div
          v-for="blocker in review.blockers"
          :key="`${blocker.kind}:${blocker.id}`"
          class="border-l-2 border-l-fc-err bg-fc-inset px-3 py-2"
          data-testid="remove-blocker"
        >
          <div class="flex flex-wrap items-center gap-2">
            <span class="fc-kicker">{{ blocker.kind.replaceAll('_', ' ') }} · <span class="normal-case tracking-normal">{{ blocker.id }}</span></span>
            <StatusChip
              :label="blocker.state.replaceAll('_', ' ')"
              tone="faint"
            />
          </div>
          <p class="mt-1 break-words leading-relaxed text-fc-ink">
            <template
              v-for="(span, index) in codeSpans(blocker.detail)"
              :key="index"
            >
              <code
                v-if="span.code"
                class="rounded-sm border border-fc-line bg-fc-panel px-1 font-mono text-[11px] text-fc-ink"
                data-testid="blocker-command"
              >{{ span.text }}</code>
              <template v-else>
                {{ span.text }}
              </template>
            </template>
          </p>
        </div>
      </section>

      <section
        v-if="review.warnings.length > 0"
        class="space-y-2"
        data-testid="remove-warnings"
      >
        <p
          v-for="warning in review.warnings"
          :key="warning"
          class="border-l-2 border-l-fc-warn bg-fc-inset px-3 py-1.5 text-fc-ink"
        >
          <span class="fc-kicker block">Before you confirm</span>
          {{ warning }}
        </p>
      </section>

      <section
        class="space-y-2"
        data-testid="remove-review"
      >
        <h3 class="fc-kicker border-b-2 border-fc-ink pb-1 text-fc-ink">
          Review
        </h3>
        <dl class="grid grid-cols-[minmax(0,7rem)_1fr] gap-x-3 gap-y-1.5 sm:grid-cols-[minmax(0,10rem)_1fr]">
          <dt class="text-fc-muted">
            Endpoints
          </dt>
          <dd class="space-y-0.5 font-mono text-fc-ink">
            <p
              v-for="endpoint in review.endpoints"
              :key="endpoint.id"
            >
              {{ endpoint.kind }} · {{ endpoint.id }}<span
                v-if="endpoint.host"
                class="text-fc-muted"
              > · {{ endpoint.host }}</span>
            </p>
            <p
              v-if="review.endpoints.length === 0"
              class="text-fc-faint"
            >
              none
            </p>
          </dd>
          <dt class="text-fc-muted">
            Node identity
          </dt>
          <dd class="font-mono text-fc-ink">
            {{ review.nodeIdentity ? `${review.nodeIdentity} · deleted` : 'none' }}
          </dd>
          <dt class="text-fc-muted">
            Host keys unpinned
          </dt>
          <dd
            class="font-mono text-fc-ink"
            data-testid="remove-unpin"
          >
            {{ review.unpinHosts.length > 0 ? review.unpinHosts.join(', ') : 'none' }}
          </dd>
          <dt class="text-fc-muted">
            Host keys kept (shared)
          </dt>
          <dd class="font-mono text-fc-ink">
            {{ review.keptHosts.length > 0 ? review.keptHosts.join(', ') : 'none' }}
          </dd>
          <dt class="text-fc-muted">
            fleetd uninstall
          </dt>
          <dd
            class="font-mono text-fc-ink"
            data-testid="remove-uninstall-plan"
          >
            <template v-if="review.uninstall">
              <p>over {{ review.uninstall.endpointId }} · {{ authLabel(review.uninstall.auth) }}</p>
              <p
                v-for="[name, value] in layout"
                :key="name"
                class="break-all text-fc-muted"
              >
                {{ name }}={{ value }}
              </p>
              <p
                v-if="layout.length === 0"
                class="text-fc-muted"
              >
                default layout
              </p>
            </template>
            <span
              v-else
              class="text-fc-faint"
            >not run · nothing on the machine is touched</span>
          </dd>
        </dl>

        <div class="grid gap-3 sm:grid-cols-2">
          <div class="rounded-sm border border-fc-line p-2">
            <p class="fc-kicker">
              Deleted
            </p>
            <p class="mt-0.5 text-fc-faint">
              Record kinds not listed have none.
            </p>
            <dl class="mt-1 grid grid-cols-[1fr_auto] gap-x-3 gap-y-0.5">
              <template
                v-for="row in deletedRows(review.footprint)"
                :key="row.key"
              >
                <dt :class="review.footprint[row.key] > 0 ? 'text-fc-ink' : 'text-fc-faint'">
                  {{ row.label }}
                </dt>
                <dd
                  class="text-right font-mono tabular-nums"
                  :class="review.footprint[row.key] > 0 ? 'text-fc-ink' : 'text-fc-faint'"
                >
                  {{ review.footprint[row.key] }}
                </dd>
              </template>
            </dl>
          </div>
          <div class="rounded-sm border border-fc-line p-2">
            <p class="fc-kicker">
              Kept
            </p>
            <dl class="mt-1 grid grid-cols-[1fr_auto] gap-x-3 gap-y-0.5">
              <dt class="text-fc-ink">
                Collected files (until retention)
              </dt>
              <dd class="text-right font-mono tabular-nums text-fc-ink">
                {{ review.footprint.collectedFilesKept }}
              </dd>
              <dt class="text-fc-ink">
                Endpoints using a fleet-wide stored key (key not revoked)
              </dt>
              <dd class="text-right font-mono tabular-nums text-fc-ink">
                {{ review.footprint.endpointAuthSecrets }}
              </dd>
            </dl>
            <p class="mt-2 text-fc-muted">
              The audit trail and finished operations stay.
            </p>
          </div>
        </div>
      </section>
    </template>

    <p
      v-if="error"
      class="border-l-2 border-l-fc-err bg-fc-inset px-3 py-1.5 text-fc-ink"
      role="alert"
      data-testid="remove-error"
    >
      <span class="fc-kicker block">{{ ERROR_KICKER[errorStep] }}</span>
      <span class="break-words">{{ error }}</span>
    </p>

    <CopyFleetctl
      :command="command"
      missing="Pick an SSH endpoint and an identity path to see the command."
    />

    <div class="flex flex-wrap justify-end gap-2">
      <button
        type="button"
        class="rounded-sm border border-input px-3 py-1.5 font-mono text-[10px] uppercase tracking-wider text-fc-muted hover:border-fc-line2 hover:text-fc-ink disabled:opacity-50"
        :disabled="busy !== null"
        data-testid="remove-cancel"
        @click="emit('close')"
      >
        Cancel
      </button>
      <button
        v-if="review?.reviewToken"
        type="submit"
        class="inline-flex h-8 items-center rounded-sm border border-fc-err bg-fc-err/10 px-4 text-xs font-medium text-fc-err hover:bg-fc-err/20 disabled:opacity-50"
        :disabled="busy !== null"
        data-testid="remove-confirm"
      >
        {{ busy === 'remove' ? (review.uninstall ? 'Uninstalling and removing…' : 'Removing…') : `Remove ${machine.name}` }}
      </button>
      <button
        v-else
        type="submit"
        class="inline-flex h-8 items-center rounded-sm border border-input px-4 text-xs font-medium text-fc-ink hover:border-fc-line2 disabled:opacity-50"
        :disabled="busy !== null || !optionsReady"
        data-testid="remove-review-again"
      >
        {{ review || error ? 'Review again' : 'Review' }}
      </button>
    </div>
  </form>
</template>
