<script setup lang="ts">
import { useQueryClient } from '@tanstack/vue-query'
import { computed, ref, watch } from 'vue'

import {
  observeProxmoxGuest,
  reviewProxmoxOperation,
  startProxmoxLifecycle,
  startReviewedProxmoxOperation,
  type OperationDto,
  type ProxmoxReviewDto,
} from '@frogbyte-io/fleet-api-client'
import StatusChip from '@/components/fleet/StatusChip.vue'

import { guestAgentLabel, guestStatusTone, type GuestItem } from '../../fleet/inventory'
import { errorMessage, unwrap } from '../api'
import {
  destructiveCommand,
  lifecycleCommand,
  observeGuestCommand,
  type DestructiveAction,
  type GuestRef,
  type LifecycleAction,
} from '../fleetctl'
import { useMachineOperations } from '../operations'
import CopyFleetctl from './CopyFleetctl.vue'
import OperationStatus from './OperationStatus.vue'

const props = defineProps<{
  guest: GuestItem & { vmid: number }
  machineId: string
}>()

// Proxmox operations the CLI also runs with `timeoutSeconds: 300`.
const TIMEOUT_SECONDS = 300
const queryClient = useQueryClient()
const { track } = useMachineOperations()

const ref_ = computed<GuestRef>(() => ({ accountId: props.guest.accountId, node: props.guest.node, vmid: props.guest.vmid }))
const evidence = computed(() => props.guest.candidates.find(c => c.machineId === props.machineId) ?? null)

// Record the guest's facts onto this machine.
const observeBusy = ref(false)
const observeMessage = ref('')
const observeFailed = ref(false)

async function observe() {
  observeBusy.value = true
  observeMessage.value = ''
  try {
    const response = await observeProxmoxGuest(props.guest.accountId, props.guest.vmid, { machineId: props.machineId })
    if (response.status !== 204)
      unwrap(response, [204])
    observeFailed.value = false
    observeMessage.value = 'Guest facts recorded on this machine.'
    await queryClient.invalidateQueries({ queryKey: ['machine', props.machineId] })
  }
  catch (error) {
    observeFailed.value = true
    observeMessage.value = errorMessage(error)
  }
  finally {
    observeBusy.value = false
  }
}

// Lifecycle: not review-gated by the API, but still confirmed in the UI.
const LIFECYCLE: LifecycleAction[] = ['start', 'shutdown', 'reboot', 'stop']
const lifecycleAction = ref<LifecycleAction | null>(null)
const lifecycleBusy = ref(false)
const lifecycleError = ref('')
const lifecycleOperation = ref<string | null>(null)

async function runLifecycle() {
  const action = lifecycleAction.value
  if (!action)
    return
  lifecycleBusy.value = true
  lifecycleError.value = ''
  try {
    const operation = unwrap<OperationDto>(await startProxmoxLifecycle(props.guest.accountId, props.guest.vmid, action, {
      node: props.guest.node,
      vmid: props.guest.vmid,
      timeoutSeconds: TIMEOUT_SECONDS,
    }), [202])
    lifecycleOperation.value = operation.id
    lifecycleAction.value = null
    track(operation, `proxmox ${action} ${props.guest.vmid}`)
  }
  catch (error) {
    lifecycleError.value = errorMessage(error)
  }
  finally {
    lifecycleBusy.value = false
  }
}

// Destructive operations go through review → run: the review renders
// exactly what will run and returns a token bound to those bytes.
const DESTRUCTIVE: { value: DestructiveAction, label: string }[] = [
  { value: 'snapshot', label: 'Take snapshot' },
  { value: 'snapshot-revert', label: 'Revert to snapshot' },
  { value: 'snapshot-delete', label: 'Delete snapshot' },
  { value: 'clone', label: 'Clone' },
  { value: 'template', label: 'Convert to template' },
]
const destructiveAction = ref<DestructiveAction>('snapshot')
const snapshotName = ref('')
const snapshotDescription = ref('')
const includeRam = ref(false)
const cloneId = ref<number | null>(null)
const cloneName = ref('')
const fullCopy = ref(false)

const params = computed<Record<string, unknown> | null>(() => {
  switch (destructiveAction.value) {
    case 'snapshot':
      if (!snapshotName.value)
        return null
      return {
        snapshot: snapshotName.value,
        ...(snapshotDescription.value ? { description: snapshotDescription.value } : {}),
        ...(includeRam.value ? { includeRam: true } : {}),
      }
    case 'snapshot-revert':
    case 'snapshot-delete':
      return snapshotName.value ? { snapshot: snapshotName.value } : null
    case 'clone':
      if (cloneId.value === null || !Number.isInteger(cloneId.value) || cloneId.value < 100 || !cloneName.value)
        return null
      return { newId: cloneId.value, name: cloneName.value, fullCopy: fullCopy.value }
    case 'template':
      return {}
  }
  return null
})

const review = ref<ProxmoxReviewDto | null>(null)
const reviewBusy = ref(false)
const reviewError = ref('')
const runBusy = ref(false)
const runError = ref('')
const destructiveOperation = ref<string | null>(null)

// Any edit after a review invalidates it: the run must carry reviewed bytes.
watch([destructiveAction, params], () => {
  review.value = null
})

const reviewedPayload = computed(() => {
  if (!review.value)
    return ''
  const { action, accountId, node, vmid, params } = review.value
  return JSON.stringify({ action, accountId, node, vmid, params }, null, 2)
})

const destructiveCmd = computed(() => params.value ? destructiveCommand(destructiveAction.value, ref_.value, params.value) : null)

async function requestReview() {
  if (!params.value)
    return
  reviewBusy.value = true
  reviewError.value = ''
  try {
    review.value = unwrap<ProxmoxReviewDto>(await reviewProxmoxOperation(props.guest.accountId, props.guest.vmid, destructiveAction.value, {
      node: props.guest.node,
      params: params.value,
    }))
  }
  catch (error) {
    reviewError.value = errorMessage(error)
  }
  finally {
    reviewBusy.value = false
  }
}

async function runReviewed() {
  const reviewed = review.value
  if (!reviewed)
    return
  runBusy.value = true
  runError.value = ''
  try {
    // The reviewed params are the ones the controller echoed back, so the
    // run's bytes match the reviewed bytes (as fleetctl does).
    const operation = unwrap<OperationDto>(await startReviewedProxmoxOperation(props.guest.accountId, props.guest.vmid, reviewed.action, {
      node: reviewed.node,
      reviewToken: reviewed.reviewToken,
      params: reviewed.params,
      timeoutSeconds: TIMEOUT_SECONDS,
    }), [202])
    destructiveOperation.value = operation.id
    track(operation, `proxmox ${reviewed.action} ${reviewed.vmid}`)
    review.value = null
  }
  catch (error) {
    runError.value = errorMessage(error)
  }
  finally {
    runBusy.value = false
  }
}
</script>

<template>
  <article
    class="space-y-5 rounded-sm border border-fc-line bg-fc-panel p-4"
    data-testid="guest-panel"
  >
    <header class="flex flex-wrap items-center gap-3">
      <p class="text-sm font-semibold text-fc-ink">
        {{ guest.name }}
      </p>
      <span class="fc-kicker">{{ guest.kind === 'lxc' ? 'LXC' : 'QEMU' }} {{ guest.vmid }} · ON {{ guest.node }} · {{ guest.accountName }}</span>
      <StatusChip
        :label="guest.status"
        :tone="guestStatusTone(guest.status)"
      />
      <span class="font-mono text-[10px] uppercase text-fc-muted">Guest agent {{ guestAgentLabel(guest.agentOnline) }}<template v-if="guest.osName"> · {{ guest.osName }}</template></span>
    </header>

    <p class="text-xs text-fc-info">
      <template v-if="evidence">
        ≈ Candidate match by {{ evidence.evidence }}.
      </template>
      <span class="text-fc-faint">This is association evidence, not a confirmed link; confirming it arrives with FM-913.</span>
    </p>

    <section class="space-y-2">
      <h3 class="fc-kicker">
        Record guest facts
      </h3>
      <p class="text-xs text-fc-muted">
        Reads the guest's Proxmox and guest-agent facts and records them on this machine.
      </p>
      <button
        type="button"
        class="h-8 rounded-sm border border-fc-info/40 px-3 text-xs text-fc-info hover:bg-fc-info/10 disabled:opacity-50"
        :disabled="observeBusy"
        data-testid="observe-guest"
        @click="observe"
      >
        Record facts
      </button>
      <p
        v-if="observeMessage"
        class="text-xs"
        :class="observeFailed ? 'text-fc-err' : 'text-fc-ok'"
      >
        {{ observeMessage }}
      </p>
      <CopyFleetctl :command="observeGuestCommand(ref_, machineId)" />
    </section>

    <section class="space-y-2">
      <h3 class="fc-kicker">
        Lifecycle
      </h3>
      <div class="flex flex-wrap gap-2">
        <button
          v-for="action in LIFECYCLE"
          :key="action"
          type="button"
          class="h-8 rounded-sm border px-3 text-xs capitalize"
          :class="lifecycleAction === action ? 'border-fc-ink text-fc-ink' : 'border-fc-line text-fc-muted hover:text-fc-ink'"
          :data-testid="`lifecycle-${action}`"
          @click="lifecycleAction = action"
        >
          {{ action }}
        </button>
      </div>
      <div
        v-if="lifecycleAction"
        class="space-y-2"
      >
        <div class="flex flex-wrap items-center gap-2 text-xs">
          <span :class="lifecycleAction === 'stop' ? 'text-fc-err' : 'text-fc-ink'">
            {{ lifecycleAction === 'stop' ? 'Stop is a hard power-off. ' : '' }}Run {{ lifecycleAction }} on {{ guest.name }} ({{ guest.vmid }})?
          </span>
          <button
            type="button"
            class="h-8 rounded-sm border border-fc-info/40 bg-fc-info/10 px-3 text-fc-info disabled:opacity-50"
            :disabled="lifecycleBusy"
            data-testid="confirm-lifecycle"
            @click="runLifecycle"
          >
            Run {{ lifecycleAction }}
          </button>
          <button
            type="button"
            class="h-8 px-2 text-fc-muted hover:text-fc-ink"
            @click="lifecycleAction = null"
          >
            Cancel
          </button>
        </div>
        <CopyFleetctl :command="lifecycleCommand(lifecycleAction, ref_)" />
      </div>
      <p
        v-if="lifecycleError"
        class="text-xs text-fc-err"
      >
        {{ lifecycleError }}
      </p>
      <OperationStatus
        v-if="lifecycleOperation"
        :operation-id="lifecycleOperation"
      />
    </section>

    <section class="space-y-2">
      <h3 class="fc-kicker">
        Reviewed operations
      </h3>
      <p class="text-xs text-fc-muted">
        Snapshots, clones, and template conversion are reviewed first: the controller renders exactly what will run, and only that reviewed payload can run.
      </p>
      <div class="flex flex-wrap items-end gap-2 text-xs">
        <label class="flex flex-col gap-1">
          <span class="fc-kicker">Operation</span>
          <select
            v-model="destructiveAction"
            class="h-8 rounded-sm border border-input bg-background px-2 text-foreground"
            data-testid="destructive-action"
          >
            <option
              v-for="option in DESTRUCTIVE"
              :key="option.value"
              :value="option.value"
            >
              {{ option.label }}
            </option>
          </select>
        </label>
        <template v-if="destructiveAction === 'snapshot' || destructiveAction === 'snapshot-revert' || destructiveAction === 'snapshot-delete'">
          <label class="flex flex-col gap-1">
            <span class="fc-kicker">Snapshot name</span>
            <input
              v-model="snapshotName"
              class="h-8 w-44 rounded-sm border border-input bg-background px-2 font-mono text-foreground"
              data-testid="snapshot-name"
            >
          </label>
        </template>
        <template v-if="destructiveAction === 'snapshot'">
          <label class="flex flex-col gap-1">
            <span class="fc-kicker">Description</span>
            <input
              v-model="snapshotDescription"
              class="h-8 w-56 rounded-sm border border-input bg-background px-2 text-foreground"
            >
          </label>
          <label class="flex h-8 items-center gap-1.5">
            <input
              v-model="includeRam"
              type="checkbox"
            >
            <span>Include RAM</span>
          </label>
        </template>
        <template v-if="destructiveAction === 'clone'">
          <label class="flex flex-col gap-1">
            <span class="fc-kicker">New VMID</span>
            <input
              v-model.number="cloneId"
              type="number"
              min="100"
              class="h-8 w-28 rounded-sm border border-input bg-background px-2 font-mono text-foreground"
              data-testid="clone-id"
            >
          </label>
          <label class="flex flex-col gap-1">
            <span class="fc-kicker">Name</span>
            <input
              v-model="cloneName"
              class="h-8 w-44 rounded-sm border border-input bg-background px-2 font-mono text-foreground"
              data-testid="clone-name"
            >
          </label>
          <label class="flex h-8 items-center gap-1.5">
            <input
              v-model="fullCopy"
              type="checkbox"
            >
            <span>Full copy</span>
          </label>
        </template>
        <button
          type="button"
          class="h-8 rounded-sm border border-fc-warn/40 px-3 text-fc-warn hover:bg-fc-warn/10 disabled:opacity-50"
          :disabled="!params || reviewBusy"
          data-testid="review-destructive"
          @click="requestReview"
        >
          Review
        </button>
      </div>
      <p
        v-if="destructiveAction === 'template'"
        class="text-xs text-fc-warn"
      >
        Converting to a template cannot be undone; the guest stops being a runnable VM.
      </p>
      <p
        v-if="reviewError"
        class="text-xs text-fc-err"
      >
        {{ reviewError }}
      </p>
      <div
        v-if="review"
        class="space-y-2 rounded-sm border border-fc-warn/40 bg-fc-inset p-3"
        data-testid="reviewed-payload"
      >
        <p class="fc-kicker text-fc-warn">
          Reviewed payload — this exact request will run
        </p>
        <pre class="overflow-x-auto font-mono text-[11px] text-fc-ink">{{ reviewedPayload }}</pre>
        <div class="flex items-center gap-2">
          <button
            type="button"
            class="h-8 rounded-sm border border-fc-err bg-fc-err/10 px-3 text-xs text-fc-err disabled:opacity-50"
            :disabled="runBusy"
            data-testid="run-reviewed"
            @click="runReviewed"
          >
            Run reviewed {{ review.action }}
          </button>
          <button
            type="button"
            class="h-8 px-2 text-xs text-fc-muted hover:text-fc-ink"
            @click="review = null"
          >
            Discard review
          </button>
        </div>
      </div>
      <p
        v-if="runError"
        class="text-xs text-fc-err"
      >
        {{ runError }}
      </p>
      <OperationStatus
        v-if="destructiveOperation"
        :operation-id="destructiveOperation"
      />
      <CopyFleetctl
        :command="destructiveCmd"
        missing="Complete the parameters to see the command."
      />
    </section>
  </article>
</template>
