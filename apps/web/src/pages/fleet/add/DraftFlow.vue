<script setup lang="ts">
import { useQuery, useQueryClient } from '@tanstack/vue-query'
import { computed, ref, watch } from 'vue'
import { RouterLink } from 'vue-router'

import {
  addOnboardingMachine,
  cancelOnboardingDraft,
  confirmOnboardingHostKey,
  createOperation,
  discoverOnboardingDraft,
  getOnboardingDraft,
  getOperation,
  testOnboardingDraft,
  type AddedMachineDto,
  type OnboardingDraftDetailDto,
  type OperationDto,
} from '@frogbyte-io/fleet-api-client'

import { ApiRequestError, errorMessage, isTerminal, unwrap } from '../../machine/api'
import CopyFleetctl from '../../machine/components/CopyFleetctl.vue'
import OperationStatus from '../../machine/components/OperationStatus.vue'
import { installNodeCommand, onboardConfirmCommand, onboardStageCommand } from '../../machine/fleetctl'
import { clearStageOperation, draftStep, loadStageOperation, saveStageOperation, type DraftStep } from './resume'

// One onboarding draft, from connection test to "Add to fleet". Every step
// is a call on the draft, so leaving and returning resumes where the
// controller says the draft stands.
const props = defineProps<{ draftId: string }>()
const emit = defineEmits<{
  step: [step: DraftStep]
  cancelled: []
  added: [machineId: string]
  /** The resumed draft no longer exists. */
  missing: []
}>()

const queryClient = useQueryClient()

const draftQuery = useQuery({
  queryKey: computed(() => ['onboarding-draft', props.draftId]),
  queryFn: async () => unwrap<OnboardingDraftDetailDto>(await getOnboardingDraft(props.draftId)),
})
const draft = computed(() => draftQuery.data.value ?? null)
const draftMissing = computed(() => draftQuery.error.value instanceof ApiRequestError && draftQuery.error.value.status === 404)
const step = computed<DraftStep | null>(() => (draft.value ? draftStep(draft.value) : null))
watch(step, s => s && emit('step', s), { immediate: true })

const error = ref('')
const busy = ref(false)

async function act(fn: () => Promise<void>) {
  busy.value = true
  error.value = ''
  try {
    await fn()
  }
  catch (e) {
    error.value = errorMessage(e)
  }
  finally {
    busy.value = false
  }
}

// Test and discover are durable operations; the draft is re-read when one
// reaches a terminal state. The running operation is remembered with the
// draft, so a reopened dialog follows it instead of starting another probe.
const stageOperation = ref<{ stage: 'test' | 'discover', id: string } | null>(loadStageOperation(props.draftId))
const stageQuery = useQuery({
  queryKey: computed(() => ['operation', stageOperation.value?.id]),
  queryFn: async () => unwrap<OperationDto>(await getOperation(stageOperation.value!.id)),
  enabled: computed(() => stageOperation.value !== null),
  refetchInterval: q => (q.state.data && isTerminal(q.state.data.state) ? false : 1000),
})
const stageRunning = computed(() => {
  const op = stageQuery.data.value
  return stageOperation.value !== null && (!op || !isTerminal(op.state))
})
watch(() => stageQuery.data.value?.state, async (state) => {
  if (state && isTerminal(state)) {
    clearStageOperation()
    await draftQuery.refetch()
  }
})
// A remembered operation the API can no longer read (expired, or from
// another controller) must not lock the step: forget it and re-read the
// draft, which says where things stand.
const lostStageOperation = ref(false)
watch(() => stageQuery.error.value, async (err) => {
  if (!err || !stageOperation.value)
    return
  stageOperation.value = null
  clearStageOperation()
  lostStageOperation.value = true
  await draftQuery.refetch()
})
/** The operation to show on a step: only one started for that step. */
function stageOperationFor(stage: 'test' | 'discover'): string | null {
  return stageOperation.value?.stage === stage ? stageOperation.value.id : null
}

function runStage(stage: 'test' | 'discover') {
  return act(async () => {
    const response = stage === 'test' ? await testOnboardingDraft(props.draftId) : await discoverOnboardingDraft(props.draftId)
    lostStageOperation.value = false
    stageOperation.value = { stage, id: unwrap<OperationDto>(response, [202]).id }
    saveStageOperation(props.draftId, stageOperation.value)
  })
}

// Host-key trust: the observed fingerprint is shown and must be explicitly
// confirmed; nothing is trusted on first use.
const verified = ref(false)

function confirmHostKey() {
  const hostKey = draft.value?.hostKey
  if (!hostKey)
    return
  return act(async () => {
    const updated = unwrap<OnboardingDraftDetailDto>(await confirmOnboardingHostKey(props.draftId, { fingerprint: hostKey.fingerprint }))
    queryClient.setQueryData(['onboarding-draft', props.draftId], updated)
    verified.value = false
  })
}

// Finish: add the machine, then optionally install fleetd over the same
// endpoint and credential the draft used.
const management = ref<'agentless' | 'fleetd'>('agentless')
const added = ref<AddedMachineDto | null>(null)
const installOperation = ref<string | null>(null)
const installError = ref('')
const addedSsh = computed(() => added.value?.machine.endpoints.find(e => e.kind === 'ssh') ?? null)
const installCmd = computed(() => (added.value && addedSsh.value && draft.value
  ? installNodeCommand(added.value.machine.id, addedSsh.value.id, draft.value.auth, controllerUrl)
  : null))
const INSTALL_TIMEOUT_SECONDS = 300
const controllerUrl = window.location.origin

function addToFleet() {
  return act(async () => {
    const result = unwrap<AddedMachineDto>(await addOnboardingMachine(props.draftId), [201])
    added.value = result
    emit('added', result.machine.id)
    await queryClient.invalidateQueries({ queryKey: ['fleet', 'machines'] })
    if (management.value === 'fleetd')
      await installFleetd()
  })
}

// Runs after the add; a failure here leaves an agentless machine, which the
// added view reports with a retry and the machine page's install form.
async function installFleetd() {
  const ssh = addedSsh.value
  if (!added.value || !draft.value)
    return
  installError.value = ''
  if (!ssh) {
    installError.value = 'The new machine has no SSH endpoint, so fleetd cannot be installed from here.'
    return
  }
  try {
    const operation = unwrap<OperationDto>(await createOperation({
      kind: 'machine.install-fleetd',
      payloadJson: JSON.stringify({
        machineId: added.value.machine.id,
        endpointId: ssh.id,
        auth: draft.value.auth,
        timeoutSeconds: INSTALL_TIMEOUT_SECONDS,
        controllerUrl,
      }),
      deadlineAt: Date.now() + (INSTALL_TIMEOUT_SECONDS + 180) * 1000,
    }), [201])
    installOperation.value = operation.id
  }
  catch (e) {
    installError.value = errorMessage(e)
  }
}

const confirmingCancel = ref(false)

function cancelDraft() {
  return act(async () => {
    const response = await cancelOnboardingDraft(props.draftId)
    if (response.status !== 204)
      unwrap(response, [204])
    emit('cancelled')
  })
}

const factPreview = computed(() => (draft.value?.facts ?? []).filter(f => f.status === 'known').slice(0, 12))
</script>

<template>
  <div class="flex min-h-0 flex-1 flex-col gap-3">
    <p
      v-if="draftQuery.isLoading.value"
      class="text-xs text-fc-faint"
    >
      Loading draft…
    </p>
    <template v-else-if="draftQuery.error.value">
      <p
        class="text-xs text-fc-err"
        data-testid="draft-unavailable"
      >
        {{ draftMissing ? 'This draft no longer exists; it was added or cancelled elsewhere.' : `Draft unavailable: ${errorMessage(draftQuery.error.value)}` }}
      </p>
      <button
        type="button"
        class="font-mono text-[10px] uppercase tracking-wider text-fc-info hover:text-fc-ink"
        data-testid="draft-restart"
        @click="draftMissing ? emit('missing') : draftQuery.refetch()"
      >
        {{ draftMissing ? 'Start over' : 'Retry' }}
      </button>
    </template>

    <template v-else-if="added">
      <h3 class="text-base font-bold text-fc-ink">
        {{ added.machine.name }} is in the fleet
      </h3>
      <p
        v-if="added.duplicates.length > 0"
        class="text-xs text-fc-warn"
      >
        Shares an endpoint with: {{ added.duplicates.map(d => d.name).join(', ') }}. Candidates warn; nothing was merged.
      </p>
      <OperationStatus
        v-if="installOperation"
        :operation-id="installOperation"
        label="Install fleetd"
      />
      <div
        v-if="installError"
        class="space-y-1 text-xs"
        data-testid="install-error"
      >
        <p class="text-fc-err">
          The machine was added, but fleetd installation did not start: {{ installError }}
        </p>
        <button
          v-if="addedSsh"
          type="button"
          class="font-mono text-[10px] uppercase tracking-wider text-fc-info hover:text-fc-ink"
          data-testid="retry-install"
          @click="installFleetd"
        >
          Retry install
        </button>
      </div>
      <CopyFleetctl
        v-if="management === 'fleetd'"
        :command="installCmd"
        missing="The new machine has no SSH endpoint."
      />
      <RouterLink
        :to="`/fleet/machines/${added.machine.id}`"
        class="font-mono text-[11px] uppercase tracking-wider text-fc-info hover:text-fc-ink"
        data-testid="open-added-machine"
      >
        Open machine page →
      </RouterLink>
    </template>

    <template v-else-if="draft && step">
      <div>
        <h3 class="text-base font-bold text-fc-ink">
          {{ draft.name }}
        </h3>
        <p class="font-mono text-[11px] text-fc-muted">
          {{ draft.endpoint.user }}@{{ draft.endpoint.host }}:{{ draft.endpoint.port }} · {{ draft.auth.type === 'agent' ? 'SSH agent' : `identity ${draft.auth.path}` }}
        </p>
      </div>

      <!-- Connection test -->
      <section
        v-if="step === 'test'"
        class="space-y-2"
        data-testid="step-test"
      >
        <p class="text-sm text-fc-ink">
          Test the connection. The test records the host key the machine presents.
        </p>
        <p
          v-if="draft.lastTest && !draft.lastTest.connected"
          class="text-xs text-fc-err"
        >
          Last test failed{{ draft.lastTest.detail ? `: ${draft.lastTest.detail}` : '' }}.
        </p>
        <button
          type="button"
          class="h-8 rounded-sm border border-fc-info/40 px-3 text-xs text-fc-info hover:bg-fc-info/10 disabled:opacity-50"
          :disabled="busy || stageRunning"
          data-testid="run-test"
          @click="runStage('test')"
        >
          {{ draft.lastTest ? 'Test again' : 'Test connection' }}
        </button>
        <OperationStatus
          v-if="stageOperationFor('test')"
          :operation-id="stageOperationFor('test')!"
          label="Connection test"
        />
        <CopyFleetctl :command="onboardStageCommand('test', draft.id)" />
      </section>

      <!-- Host key verification -->
      <section
        v-else-if="step === 'verify' && draft.hostKey"
        class="space-y-2"
        data-testid="step-verify"
      >
        <p
          v-if="draft.hostKeyStage === 'changed'"
          class="text-sm text-fc-err"
        >
          The host key changed since it was confirmed. Verify the new key before trusting it.
        </p>
        <p
          v-else
          class="text-sm text-fc-ink"
        >
          Compare this fingerprint with the machine's own (<span class="font-mono text-xs">ssh-keygen -lf /etc/ssh/ssh_host_{{ draft.hostKey.keyType.toLowerCase() }}_key.pub</span>).
        </p>
        <div
          v-if="draft.hostKeyStage === 'changed' && draft.confirmedFingerprint"
          class="font-mono text-[11px] text-fc-muted"
        >
          Previously confirmed: {{ draft.confirmedFingerprint }}
        </div>
        <div
          class="break-all rounded-sm border border-fc-line bg-fc-inset p-2 font-mono text-xs text-fc-ink"
          data-testid="observed-fingerprint"
        >
          {{ draft.hostKey.keyType }} {{ draft.hostKey.fingerprint }}
        </div>
        <label class="flex items-center gap-2 text-xs text-fc-ink">
          <input
            v-model="verified"
            type="checkbox"
            data-testid="verified-checkbox"
          >
          I compared this fingerprint with the machine and it matches.
        </label>
        <button
          type="button"
          class="h-8 rounded-sm border border-fc-info/40 px-3 text-xs text-fc-info hover:bg-fc-info/10 disabled:opacity-50"
          :disabled="busy || !verified"
          data-testid="confirm-host-key"
          @click="confirmHostKey"
        >
          Confirm host key
        </button>
        <CopyFleetctl :command="onboardConfirmCommand(draft.id, draft.hostKey.fingerprint)" />
      </section>

      <!-- Discovery -->
      <section
        v-else-if="step === 'discover'"
        class="space-y-2"
        data-testid="step-discover"
      >
        <p class="text-sm text-fc-ink">
          Host key confirmed. Discover the machine's OS, hardware, and tools.
        </p>
        <button
          type="button"
          class="h-8 rounded-sm border border-fc-info/40 px-3 text-xs text-fc-info hover:bg-fc-info/10 disabled:opacity-50"
          :disabled="busy || stageRunning"
          data-testid="run-discover"
          @click="runStage('discover')"
        >
          Discover
        </button>
        <OperationStatus
          v-if="stageOperationFor('discover')"
          :operation-id="stageOperationFor('discover')!"
          label="Discovery"
        />
        <CopyFleetctl :command="onboardStageCommand('discover', draft.id)" />
      </section>

      <!-- Name & manage -->
      <section
        v-else-if="step === 'finish'"
        class="space-y-3"
        data-testid="step-finish"
      >
        <div class="grid grid-cols-2 gap-x-4 gap-y-1 font-mono text-[11px] text-fc-muted">
          <span
            v-for="fact in factPreview"
            :key="`${fact.namespace}.${fact.name}`"
          >{{ fact.namespace }}/{{ fact.name }} <b class="font-normal text-fc-ink">{{ fact.value ?? '—' }}</b></span>
        </div>
        <p
          v-if="draft.facts.length > factPreview.length"
          class="text-[11px] text-fc-faint"
        >
          {{ draft.facts.length }} facts recorded{{ draft.profileHint ? ` · profile hint ${draft.profileHint}` : '' }}.
        </p>
        <p
          v-if="draft.duplicates.length > 0"
          class="text-xs text-fc-warn"
        >
          Already in Fleet at this address: {{ draft.duplicates.map(d => d.name).join(', ') }}. Adding anyway creates a second machine.
        </p>
        <p class="text-xs text-fc-muted">
          Name <span class="font-mono text-fc-ink">{{ draft.name }}</span><template v-if="draft.tags.length > 0">
            · tags <span class="font-mono text-fc-ink">{{ draft.tags.join(', ') }}</span>
          </template>
        </p>
        <fieldset class="grid grid-cols-2 gap-2">
          <legend class="fc-kicker mb-1">
            Management level
          </legend>
          <label
            class="cursor-pointer rounded-sm border p-3 text-xs"
            :class="management === 'agentless' ? 'border-fc-ink' : 'border-fc-line'"
          >
            <input
              v-model="management"
              type="radio"
              value="agentless"
              class="sr-only"
              data-testid="manage-agentless"
            >
            <b class="block text-sm text-fc-ink">Agentless (SSH)</b>
            Probe and run operations over SSH. Nothing is installed.
          </label>
          <label
            class="cursor-pointer rounded-sm border p-3 text-xs"
            :class="management === 'fleetd' ? 'border-fc-ink' : 'border-fc-line'"
          >
            <input
              v-model="management"
              type="radio"
              value="fleetd"
              class="sr-only"
              data-testid="manage-fleetd"
            >
            <b class="block text-sm text-fc-ink">Install fleetd</b>
            Live status and heartbeats. Installed right after the add, over the same SSH endpoint.
          </label>
        </fieldset>
        <button
          type="button"
          class="fc-grad-bg h-9 rounded-sm px-4 text-sm font-medium disabled:opacity-50"
          :disabled="busy"
          data-testid="add-to-fleet"
          @click="addToFleet"
        >
          Add to fleet →
        </button>
        <CopyFleetctl :command="onboardStageCommand('add', draft.id)" />
        <p
          v-if="management === 'fleetd'"
          class="text-[11px] text-fc-faint"
        >
          The fleetd install command appears once the machine exists and has an id.
        </p>
      </section>

      <p
        v-if="lostStageOperation"
        class="text-xs text-fc-warn"
        data-testid="stage-lost"
      >
        The earlier run can no longer be read; the draft shows where it stands. Run the step again if needed.
      </p>
      <p
        v-if="error"
        class="text-xs text-fc-err"
      >
        {{ error }}
      </p>

      <div class="mt-auto flex items-center gap-2 border-t border-fc-line pt-3 text-xs">
        <span class="font-mono text-[10px] uppercase tracking-wider text-fc-faint">Draft {{ draft.id }} · resumes when reopened</span>
        <template v-if="!confirmingCancel">
          <button
            type="button"
            class="ml-auto text-fc-muted hover:text-fc-err"
            data-testid="cancel-draft"
            @click="confirmingCancel = true"
          >
            Cancel draft
          </button>
        </template>
        <template v-else>
          <span class="ml-auto text-fc-err">Discard this draft?</span>
          <button
            type="button"
            class="rounded-sm border border-fc-err/40 px-2 py-1 text-fc-err disabled:opacity-50"
            :disabled="busy"
            data-testid="confirm-cancel-draft"
            @click="cancelDraft"
          >
            Discard
          </button>
          <button
            type="button"
            class="text-fc-muted hover:text-fc-ink"
            @click="confirmingCancel = false"
          >
            Keep
          </button>
        </template>
      </div>
    </template>
  </div>
</template>
