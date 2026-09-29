<script setup lang="ts">
import { useQueryClient } from '@tanstack/vue-query'
import { computed, ref } from 'vue'

import {
  applyMachinePlan,
  createMachinePlan,
  type MachineDto,
  type OperationDto,
  type PlanDto,
} from '@frogbyte-io/fleet-api-client'
import StatusChip from '@/components/fleet/StatusChip.vue'

import { allApproved, approvalsFor, approvalsRequired, blastRadius, isStalePlan } from '../../drift/plan'
import { FLEET_DRIFT_KEY, machineDriftKey } from '../../drift/useDrift'
import { MATRIX_KEY, machineSkillsKey } from '../../skills/useSkills'
import { errorMessage, unwrap } from '../api'
import { applyPlanCommand, planCommand, type SshAuth } from '../fleetctl'
import { useMachineOperations } from '../operations'
import CopyFleetctl from './CopyFleetctl.vue'
import OperationStatus from './OperationStatus.vue'
import SshAuthFields from './SshAuthFields.vue'

// Preview the controller's plan for this machine, approve each risky action,
// confirm the blast radius, and apply it by its plan id (FM-409, ADR 0013).
// The actions that run are the controller's own; the console only sends the
// plan id and the approvals.
const props = defineProps<{ machine: MachineDto }>()

const queryClient = useQueryClient()
const { track } = useMachineOperations()

const plan = ref<PlanDto | null>(null)
const planning = ref(false)
const planError = ref('')
const stale = ref(false)
const approved = ref(new Set<number>())
const confirming = ref(false)
const applying = ref(false)
const applyError = ref('')
const operationId = ref<string | null>(null)

const endpointId = ref('')
const auth = ref<SshAuth>({ type: 'agent' })
const ready = computed(() => endpointId.value !== '' && (auth.value.type === 'agent' || auth.value.path !== ''))

const needsApproval = computed(() => (plan.value ? approvalsRequired(plan.value) : []))
const canApply = computed(() => !!plan.value && plan.value.actions.length > 0 && ready.value && allApproved(plan.value, approved.value) && !applying.value && !operationId.value)
const radius = computed(() => (plan.value ? blastRadius(plan.value, props.machine.name) : ''))
const chosenApprovals = computed(() => (plan.value ? approvalsFor(plan.value, approved.value) : []))

async function preview() {
  planning.value = true
  planError.value = ''
  stale.value = false
  confirming.value = false
  operationId.value = null
  applyError.value = ''
  try {
    plan.value = unwrap<PlanDto>(await createMachinePlan(props.machine.id))
    approved.value = new Set()
  }
  catch (error) {
    plan.value = null
    planError.value = errorMessage(error)
  }
  finally {
    planning.value = false
  }
}

function toggle(order: number, checked: boolean) {
  const next = new Set(approved.value)
  if (checked)
    next.add(order)
  else
    next.delete(order)
  approved.value = next
}

async function apply() {
  if (!plan.value || !canApply.value)
    return
  applying.value = true
  applyError.value = ''
  try {
    const operation = unwrap<OperationDto>(await applyMachinePlan(props.machine.id, plan.value.planId, {
      endpointId: endpointId.value,
      auth: auth.value,
      approvals: chosenApprovals.value,
    }), [202])
    operationId.value = operation.id
    confirming.value = false
    track(operation, 'apply plan')
  }
  catch (error) {
    if (isStalePlan(error)) {
      stale.value = true
      confirming.value = false
    }
    else {
      applyError.value = errorMessage(error)
    }
  }
  finally {
    applying.value = false
  }
}

async function onSettled() {
  await Promise.all([
    queryClient.invalidateQueries({ queryKey: machineDriftKey(props.machine.id) }),
    queryClient.invalidateQueries({ queryKey: FLEET_DRIFT_KEY }),
    queryClient.invalidateQueries({ queryKey: machineSkillsKey(props.machine.id) }),
    queryClient.invalidateQueries({ queryKey: MATRIX_KEY }),
  ])
}
</script>

<template>
  <section
    class="space-y-3 border-t-2 border-fc-ink pt-3"
    data-testid="plan-panel"
  >
    <div class="flex flex-wrap items-center gap-2">
      <h2 class="fc-kicker">
        Plan
      </h2>
      <button
        type="button"
        class="h-8 rounded-sm border border-fc-info/40 px-3 text-xs text-fc-info hover:bg-fc-info/10 disabled:opacity-50"
        :disabled="planning"
        data-testid="plan-preview"
        @click="preview"
      >
        {{ planning ? 'Planning…' : plan ? 'Plan again' : 'Preview plan' }}
      </button>
      <CopyFleetctl :command="planCommand(machine.id)" />
    </div>

    <p
      v-if="planError"
      class="text-xs text-fc-err"
      role="alert"
      data-testid="plan-error"
    >
      The plan could not be computed: {{ planError }}
    </p>

    <div
      v-if="stale"
      class="rounded-sm border border-fc-warn/40 p-3 text-xs text-fc-warn"
      role="alert"
      data-testid="plan-stale"
    >
      The plan changed since you reviewed it (new observations or a new desired revision). Nothing was applied. Plan again to review what would run now.
      <button
        type="button"
        class="ml-2 underline hover:text-fc-ink"
        data-testid="plan-replan"
        @click="preview"
      >
        Plan again
      </button>
    </div>

    <template v-if="plan">
      <p class="font-mono text-[10px] tracking-wide text-fc-faint">
        plan {{ plan.planId.slice(0, 12) }} · revision {{ plan.revision.commitSha.slice(0, 12) }}
      </p>

      <p
        v-if="plan.actions.length === 0"
        class="rounded-sm border border-fc-line p-3 text-sm text-fc-muted"
        data-testid="plan-empty"
      >
        Nothing to apply: no difference is one Fleet would act on.
      </p>
      <ol
        v-else
        class="space-y-1"
        data-testid="plan-actions"
      >
        <li
          v-for="action in plan.actions"
          :key="action.order"
          class="rounded-sm border border-fc-line bg-card px-3 py-1.5 text-xs"
          :data-testid="`plan-action-${action.order}`"
        >
          <span class="font-mono text-fc-faint">{{ action.order }}.</span>
          <span class="ml-2 font-mono text-fc-ink">{{ action.kind }}</span>
          <span class="ml-2 text-fc-ink">{{ action.difference.identity }}</span>
          <StatusChip
            class="ml-2"
            :label="action.difference.state"
            tone="info"
          />
          <span class="mt-0.5 block text-fc-faint">{{ action.reason }}</span>
          <label
            v-if="action.requiresApproval"
            class="mt-1 flex items-center gap-2 text-fc-warn"
          >
            <input
              type="checkbox"
              :checked="approved.has(action.order)"
              :data-testid="`plan-approve-${action.order}`"
              @change="toggle(action.order, ($event.target as HTMLInputElement).checked)"
            >
            I approve this change
          </label>
        </li>
      </ol>

      <div
        v-if="plan.unactionable.length"
        class="space-y-1"
        data-testid="plan-unactionable"
      >
        <p class="fc-kicker">
          Not acting on
        </p>
        <ul class="space-y-1 text-xs text-fc-muted">
          <li
            v-for="difference in plan.unactionable"
            :key="difference.identity"
          >
            <span class="text-fc-ink">{{ difference.identity }}</span>
            <span class="ml-1 font-mono text-[10px] uppercase text-fc-faint">{{ difference.state }}</span>
            <span
              v-if="difference.reason"
              class="block text-fc-faint"
            >{{ difference.reason }}</span>
          </li>
        </ul>
      </div>

      <template v-if="plan.actions.length">
        <SshAuthFields
          v-model:endpoint-id="endpointId"
          v-model:auth="auth"
          :endpoints="machine.endpoints"
        />
        <p
          v-if="needsApproval.length && !allApproved(plan, approved)"
          class="text-xs text-fc-warn"
          data-testid="plan-needs-approval"
        >
          Approve each marked change to apply this plan.
        </p>

        <div
          v-if="!confirming"
          class="flex flex-wrap items-center gap-2"
        >
          <button
            type="button"
            class="h-8 rounded-sm border border-fc-warn/50 px-3 text-xs text-fc-warn hover:bg-fc-warn/10 disabled:opacity-50"
            :disabled="!canApply"
            data-testid="plan-apply"
            @click="confirming = true"
          >
            Apply plan…
          </button>
        </div>
        <div
          v-else
          class="space-y-2 rounded-sm border border-fc-warn/40 p-3 text-xs"
          role="alertdialog"
          aria-label="Confirm apply"
          data-testid="plan-confirm"
        >
          <p class="text-fc-ink">
            {{ radius }}
          </p>
          <p class="text-fc-muted">
            This runs the controller's own plan {{ plan.planId.slice(0, 12) }}. If anything changed since you reviewed it, nothing runs.
          </p>
          <div class="flex flex-wrap items-center gap-2">
            <button
              type="button"
              class="h-8 rounded-sm border border-fc-warn/50 px-3 text-fc-warn hover:bg-fc-warn/10 disabled:opacity-50"
              :disabled="applying"
              data-testid="plan-confirm-apply"
              @click="apply"
            >
              {{ applying ? 'Starting…' : 'Apply' }}
            </button>
            <button
              type="button"
              class="h-8 rounded-sm px-3 text-fc-muted hover:text-fc-ink"
              @click="confirming = false"
            >
              Cancel
            </button>
          </div>
          <CopyFleetctl :command="applyPlanCommand(machine.id, plan.planId, endpointId, auth, chosenApprovals.map(a => ({ order: a.actionOrder, kind: a.kind })))" />
        </div>
      </template>
    </template>

    <p
      v-if="applyError"
      class="text-xs text-fc-err"
      role="alert"
      data-testid="plan-apply-error"
    >
      Apply was refused: {{ applyError }}
    </p>
    <OperationStatus
      v-if="operationId"
      :operation-id="operationId"
      label="apply plan"
      @settled="onSettled"
    />
  </section>
</template>
