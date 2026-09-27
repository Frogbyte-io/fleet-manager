<script setup lang="ts">
import { useQueryClient } from '@tanstack/vue-query'
import { computed, ref, watch } from 'vue'

import {
  previewSkillCatalogRollout,
  startSkillCatalogRollout,
  type CatalogRolloutPlanDto,
  type CatalogRolloutRequest,
  type CatalogVersionDto,
  type MachineDto,
  type OperationDto,
} from '@frogbyte-io/fleet-api-client'

import { errorMessage, unwrap } from '../../machine/api'
import CopyFleetctl from '../../machine/components/CopyFleetctl.vue'
import OperationStatus from '../../machine/components/OperationStatus.vue'
import type { SshAuth } from '../../machine/fleetctl'
import { catalogRolloutCommand, OPERATION_TIMEOUT_SECONDS } from '../actions'
import { shortDigest } from '../catalog'
import type { AgentEntry, MatrixColumn } from '../model'
import { MATRIX_KEY } from '../useSkills'
import OutcomePanel from './OutcomePanel.vue'

// Rolls one immutable catalog version out to chosen machines. Every target
// is previewed through the rollout-plan endpoint first; Start unlocks only
// when each selected machine has a plan for exactly this selection.
const props = defineProps<{
  version: CatalogVersionDto
  machines: MachineDto[]
  columns: MatrixColumn[]
  agents: AgentEntry[]
}>()

const queryClient = useQueryClient()

const columnById = computed(() => new Map(props.columns.map(c => [c.machineId, c])))

interface Candidate {
  machine: MachineDto
  endpointId: string | null
  blocked: string | null
  note: string | null
}

const candidates = computed<Candidate[]>(() => props.machines.map((machine) => {
  const endpoint = machine.endpoints.find(e => e.kind === 'ssh')
  const column = columnById.value.get(machine.id)
  let blocked: string | null = null
  if (!endpoint)
    blocked = 'no SSH endpoint'
  else if (column?.state === 'absent')
    blocked = 'skills-manager-cli not installed'
  else if (column?.state === 'unsupported')
    blocked = 'unsupported skills-manager-cli'
  let note: string | null = null
  if (!blocked && column?.state === 'unobserved')
    note = 'never probed'
  else if (!blocked && column?.stale)
    note = 'stale observation'
  return { machine, endpointId: endpoint?.id ?? null, blocked, note }
}).sort((a, b) => a.machine.name.localeCompare(b.machine.name)))

const selected = ref<string[]>([])
const chosenAgents = ref<string[]>([])
const authType = ref<SshAuth['type']>('agent')
const identityPath = ref('')
const auth = computed<SshAuth>(() => (authType.value === 'agent' ? { type: 'agent' } : { type: 'identityFile', path: identityPath.value }))

function toggle(list: string[], value: string): string[] {
  return list.includes(value) ? list.filter(v => v !== value) : [...list, value]
}

const requests = computed<CatalogRolloutRequest[]>(() => candidates.value
  .filter(c => selected.value.includes(c.machine.id) && !c.blocked && c.endpointId)
  .map(c => ({
    versionId: props.version.id,
    machineId: c.machine.id,
    endpointId: c.endpointId!,
    auth: auth.value,
    agents: [...chosenAgents.value].sort(),
    timeoutSeconds: OPERATION_TIMEOUT_SECONDS,
  })))
const missing = computed(() => {
  if (requests.value.length === 0)
    return 'at least one machine'
  if (chosenAgents.value.length === 0)
    return 'at least one agent'
  if (authType.value === 'identityFile' && identityPath.value.trim() === '')
    return 'an identity file path'
  return null
})
const key = computed(() => JSON.stringify(requests.value))

type PlanResult = { machineId: string, plan: CatalogRolloutPlanDto | null, error: string | null }
const preview = ref<{ key: string, results: PlanResult[] } | null>(null)
const previewCurrent = computed(() => preview.value?.key === key.value)
const previewOk = computed(() => previewCurrent.value && (preview.value?.results.every(r => r.plan) ?? false))
const previewing = ref(false)

async function runPreview() {
  if (missing.value)
    return
  previewing.value = true
  const snapshot = key.value
  const results = await Promise.all(requests.value.map(async (request): Promise<PlanResult> => {
    try {
      return { machineId: request.machineId, plan: unwrap<CatalogRolloutPlanDto>(await previewSkillCatalogRollout(request)), error: null }
    }
    catch (error) {
      return { machineId: request.machineId, plan: null, error: errorMessage(error) }
    }
  }))
  preview.value = { key: snapshot, results }
  previewing.value = false
}

type Started = { machineId: string, operationId: string | null, error: string | null, settled: OperationDto | null }
const started = ref<Started[]>([])
const starting = ref(false)

async function start() {
  if (!previewOk.value)
    return
  starting.value = true
  started.value = await Promise.all(requests.value.map(async (request): Promise<Started> => {
    try {
      const operation = unwrap<OperationDto>(await startSkillCatalogRollout(request), [202])
      return { machineId: request.machineId, operationId: operation.id, error: null, settled: null }
    }
    catch (error) {
      return { machineId: request.machineId, operationId: null, error: errorMessage(error), settled: null }
    }
  }))
  preview.value = null
  starting.value = false
}

function onSettled(entry: Started, operation: OperationDto) {
  entry.settled = operation
  void queryClient.invalidateQueries({ queryKey: MATRIX_KEY })
}

// A different version starts a fresh rollout.
watch(() => props.version.id, () => {
  preview.value = null
  started.value = []
})

const names = computed(() => new Map(props.machines.map(m => [m.id, m.name])))
const commands = computed(() => (missing.value
  ? null
  : requests.value.map(r => catalogRolloutCommand(previewOk.value ? 'rollout' : 'plan', r)).join('\n')))
</script>

<template>
  <div
    class="space-y-3 text-xs"
    data-testid="rollout-panel"
  >
    <p class="text-fc-muted">
      Rolls out <span class="font-mono text-fc-ink">{{ version.name }}@{{ shortDigest(version.contentDigest) }}</span> to each machine through its SSH endpoint: stage into Fleet's own directory, install or update with skills-manager-cli, deploy to the chosen agents, verify.
    </p>

    <fieldset>
      <legend class="fc-kicker mb-1">
        Machines
      </legend>
      <p
        v-if="candidates.length === 0"
        class="text-fc-muted"
      >
        No machines.
      </p>
      <div class="grid gap-1 sm:grid-cols-2">
        <label
          v-for="c in candidates"
          :key="c.machine.id"
          class="flex items-center gap-2"
          :class="c.blocked ? 'text-fc-faint' : ''"
        >
          <input
            type="checkbox"
            :checked="selected.includes(c.machine.id)"
            :disabled="!!c.blocked"
            :data-testid="`rollout-machine-${c.machine.id}`"
            @change="selected = toggle(selected, c.machine.id)"
          >
          <span class="font-mono">{{ c.machine.name }}</span>
          <span
            v-if="c.blocked"
            class="text-fc-faint"
          >skip — {{ c.blocked }}</span>
          <span
            v-else-if="c.note"
            class="text-fc-warn"
          >{{ c.note }}</span>
        </label>
      </div>
    </fieldset>

    <fieldset>
      <legend class="fc-kicker mb-1">
        Agents
      </legend>
      <p
        v-if="agents.length === 0"
        class="text-fc-muted"
      >
        No machine has reported its agents yet — probe a machine first.
      </p>
      <div class="flex flex-wrap gap-1.5">
        <button
          v-for="agent in agents"
          :key="agent.id"
          type="button"
          class="rounded-sm border px-2 py-1"
          :class="chosenAgents.includes(agent.id) ? 'border-ring text-fc-ink' : 'border-fc-line2 text-fc-muted'"
          :aria-pressed="chosenAgents.includes(agent.id)"
          :data-testid="`rollout-agent-${agent.id}`"
          @click="chosenAgents = toggle(chosenAgents, agent.id)"
        >
          {{ agent.name }}
        </button>
      </div>
    </fieldset>

    <div class="flex flex-wrap items-end gap-3">
      <label class="flex flex-col gap-1">
        <span class="fc-kicker">SSH auth</span>
        <select
          v-model="authType"
          class="h-8 rounded-sm border border-input bg-background px-2 text-foreground"
        >
          <option value="agent">SSH agent</option>
          <option value="identityFile">Identity file</option>
        </select>
      </label>
      <label
        v-if="authType === 'identityFile'"
        class="flex flex-col gap-1"
      >
        <span class="fc-kicker">Identity path (controller host)</span>
        <input
          v-model="identityPath"
          placeholder="~/.ssh/id_ed25519"
          class="h-8 w-64 rounded-sm border border-input bg-background px-2 font-mono text-foreground"
        >
      </label>
    </div>

    <div class="flex flex-wrap items-center gap-2">
      <button
        type="button"
        class="h-8 rounded-sm border border-fc-info/40 px-3 text-fc-info hover:bg-fc-info/10 disabled:opacity-50"
        :disabled="!!missing || previewing"
        data-testid="rollout-preview"
        @click="runPreview"
      >
        Preview rollout plan
      </button>
      <button
        type="button"
        class="fc-grad-bg h-8 rounded-sm px-3 font-head font-bold disabled:opacity-50"
        :disabled="!previewOk || starting"
        :title="previewOk ? '' : 'Preview the plan for this exact selection first'"
        data-testid="rollout-start"
        @click="start"
      >
        Start rollout →
      </button>
      <span
        v-if="missing"
        class="text-fc-faint"
      >Needs {{ missing }}.</span>
      <span
        v-else-if="!previewOk"
        class="text-fc-faint"
      >{{ previewCurrent ? 'Some machines could not be planned; deselect them or fix the cause.' : 'Preview first — Start unlocks when every selected machine has a plan.' }}</span>
    </div>

    <div
      v-if="preview && previewCurrent"
      class="rounded-sm border border-fc-line bg-fc-inset p-3 font-mono text-[11px] leading-6"
      data-testid="rollout-plan"
    >
      <p class="fc-kicker">
        Rollout plan · {{ version.name }}@{{ shortDigest(version.contentDigest) }}
      </p>
      <div
        v-for="result in preview.results"
        :key="result.machineId"
        class="mt-2"
        :data-testid="`plan-${result.machineId}`"
      >
        <p class="text-fc-ink">
          {{ names.get(result.machineId) ?? result.machineId }}
          <span
            v-if="result.plan"
            class="text-fc-faint"
          >→ {{ result.plan.agents.join(', ') }}<template v-if="result.plan.stagingPath"> · staged at {{ result.plan.stagingPath }}</template></span>
        </p>
        <ol
          v-if="result.plan"
          class="list-decimal pl-6 text-fc-muted"
        >
          <li
            v-for="step in result.plan.steps"
            :key="step"
          >
            {{ step }}
          </li>
        </ol>
        <p
          v-else
          class="text-fc-err"
        >
          cannot plan: {{ result.error }}
        </p>
      </div>
    </div>

    <div
      v-if="started.length"
      class="space-y-2"
      data-testid="rollout-operations"
    >
      <div
        v-for="entry in started"
        :key="entry.machineId"
        class="space-y-1"
      >
        <OperationStatus
          v-if="entry.operationId"
          :operation-id="entry.operationId"
          :label="`rollout ${version.name} → ${names.get(entry.machineId) ?? entry.machineId}`"
          @settled="op => onSettled(entry, op)"
        />
        <p
          v-else
          class="text-fc-err"
          role="alert"
        >
          {{ names.get(entry.machineId) ?? entry.machineId }}: {{ entry.error }}
        </p>
        <OutcomePanel
          v-if="entry.settled"
          :operation="entry.settled"
        />
      </div>
    </div>

    <CopyFleetctl
      :command="commands"
      :missing="missing ? `Needs ${missing} to show the command.` : undefined"
    />
  </div>
</template>
