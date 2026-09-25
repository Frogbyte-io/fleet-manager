<script setup lang="ts">
import { computed, ref } from 'vue'

import {
  startFrogenvOperation,
  startMiseOperation,
  startSkillsOperation,
  type MachineDto,
  type OperationDto,
} from '@frogbyte-io/fleet-api-client'

import { errorMessage, unwrap } from '../api'
import CopyFleetctl from '../components/CopyFleetctl.vue'
import OperationStatus from '../components/OperationStatus.vue'
import SshAuthFields from '../components/SshAuthFields.vue'
import {
  frogenvCommand,
  miseCommand,
  skillsProbeCommand,
  type FrogenvAction,
  type MiseAction,
  type SshAuth,
} from '../fleetctl'
import { useMachineOperations } from '../operations'

// mise, Frogenv, and Skills Manager operations over the machine's SSH
// endpoint. Each is a durable operation; the fleet-wide skills console is
// FM-925.
const props = defineProps<{ machine: MachineDto }>()

const TIMEOUT_SECONDS = 300
const { track } = useMachineOperations()

const endpointId = ref('')
const auth = ref<SshAuth>({ type: 'agent' })
const ready = computed(() => endpointId.value !== '' && (auth.value.type === 'agent' || auth.value.path !== ''))

const miseAction = ref<MiseAction>('inventory')
const miseTool = ref('')
const miseVersion = ref('')
const miseValid = computed(() => ready.value && (miseAction.value !== 'install' || (miseTool.value !== '' && miseVersion.value !== '')))
const miseCmd = computed(() => miseValid.value
  ? miseCommand(props.machine.id, miseAction.value, endpointId.value, auth.value, { tool: miseTool.value, version: miseVersion.value })
  : null)

const frogenvAction = ref<FrogenvAction>('status')
const frogenvCmd = computed(() => ready.value ? frogenvCommand(props.machine.id, frogenvAction.value, endpointId.value, auth.value) : null)

const skillsCmd = computed(() => ready.value ? skillsProbeCommand(props.machine.id, endpointId.value, auth.value) : null)

type Tool = 'mise' | 'frogenv' | 'skills'
const running = ref<Record<Tool, string | null>>({ mise: null, frogenv: null, skills: null })
const errors = ref<Record<Tool, string>>({ mise: '', frogenv: '', skills: '' })
const busy = ref<Tool | null>(null)

function base() {
  return { machineId: props.machine.id, endpointId: endpointId.value, auth: auth.value, timeoutSeconds: TIMEOUT_SECONDS }
}

async function run(tool: Tool) {
  busy.value = tool
  errors.value[tool] = ''
  try {
    let response
    let label
    if (tool === 'mise') {
      label = `mise ${miseAction.value}`
      response = await startMiseOperation(props.machine.id, {
        ...base(),
        action: miseAction.value,
        ...(miseAction.value === 'install' ? { tool: miseTool.value, version: miseVersion.value } : {}),
      })
    }
    else if (tool === 'frogenv') {
      label = `frogenv ${frogenvAction.value}`
      response = await startFrogenvOperation(props.machine.id, { ...base(), action: frogenvAction.value })
    }
    else {
      label = 'skills probe'
      response = await startSkillsOperation(props.machine.id, { ...base(), dryRun: false })
    }
    const operation = unwrap<OperationDto>(response, [202])
    running.value[tool] = operation.id
    track(operation, label)
  }
  catch (error) {
    errors.value[tool] = errorMessage(error)
  }
  finally {
    busy.value = null
  }
}
</script>

<template>
  <div class="space-y-6">
    <SshAuthFields
      v-model:endpoint-id="endpointId"
      v-model:auth="auth"
      :endpoints="machine.endpoints"
    />

    <section class="space-y-2">
      <h2 class="fc-kicker border-b-2 border-fc-ink pb-1">
        mise
      </h2>
      <div class="flex flex-wrap items-end gap-2 text-xs">
        <label class="flex flex-col gap-1">
          <span class="fc-kicker">Action</span>
          <select
            v-model="miseAction"
            class="h-8 rounded-sm border border-input bg-background px-2 text-foreground"
            data-testid="mise-action"
          >
            <option value="inventory">inventory</option>
            <option value="status">status</option>
            <option value="install">install</option>
          </select>
        </label>
        <template v-if="miseAction === 'install'">
          <label class="flex flex-col gap-1">
            <span class="fc-kicker">Tool</span>
            <input
              v-model="miseTool"
              placeholder="node"
              class="h-8 w-32 rounded-sm border border-input bg-background px-2 font-mono text-foreground"
              data-testid="mise-tool"
            >
          </label>
          <label class="flex flex-col gap-1">
            <span class="fc-kicker">Pinned version</span>
            <input
              v-model="miseVersion"
              placeholder="22.11.0"
              class="h-8 w-32 rounded-sm border border-input bg-background px-2 font-mono text-foreground"
              data-testid="mise-version"
            >
          </label>
        </template>
        <button
          type="button"
          class="h-8 rounded-sm border border-fc-info/40 px-3 text-fc-info hover:bg-fc-info/10 disabled:opacity-50"
          :disabled="!miseValid || busy !== null"
          data-testid="run-mise"
          @click="run('mise')"
        >
          Run
        </button>
      </div>
      <p
        v-if="errors.mise"
        class="text-xs text-fc-err"
      >
        {{ errors.mise }}
      </p>
      <OperationStatus
        v-if="running.mise"
        :operation-id="running.mise"
      />
      <CopyFleetctl
        :command="miseCmd"
        missing="Complete the form to see the command."
      />
    </section>

    <section class="space-y-2">
      <h2 class="fc-kicker border-b-2 border-fc-ink pb-1">
        Frogenv
      </h2>
      <div class="flex flex-wrap items-end gap-2 text-xs">
        <label class="flex flex-col gap-1">
          <span class="fc-kicker">Action</span>
          <select
            v-model="frogenvAction"
            class="h-8 rounded-sm border border-input bg-background px-2 text-foreground"
          >
            <option value="status">status</option>
            <option value="setup">setup</option>
            <option value="login">login</option>
            <option value="request">request</option>
            <option value="sync">sync</option>
          </select>
        </label>
        <button
          type="button"
          class="h-8 rounded-sm border border-fc-info/40 px-3 text-fc-info hover:bg-fc-info/10 disabled:opacity-50"
          :disabled="!ready || busy !== null"
          data-testid="run-frogenv"
          @click="run('frogenv')"
        >
          Run
        </button>
      </div>
      <p
        v-if="errors.frogenv"
        class="text-xs text-fc-err"
      >
        {{ errors.frogenv }}
      </p>
      <OperationStatus
        v-if="running.frogenv"
        :operation-id="running.frogenv"
      />
      <CopyFleetctl
        :command="frogenvCmd"
        missing="Pick an SSH endpoint and auth to see the command."
      />
    </section>

    <section class="space-y-2">
      <h2 class="fc-kicker border-b-2 border-fc-ink pb-1">
        Skills Manager
      </h2>
      <p class="text-xs text-fc-muted">
        Probes the machine's skills library. Fleet-wide skills management arrives with the Skills console (FM-925).
      </p>
      <button
        type="button"
        class="h-8 rounded-sm border border-fc-info/40 px-3 text-xs text-fc-info hover:bg-fc-info/10 disabled:opacity-50"
        :disabled="!ready || busy !== null"
        data-testid="run-skills"
        @click="run('skills')"
      >
        Probe skills
      </button>
      <p
        v-if="errors.skills"
        class="text-xs text-fc-err"
      >
        {{ errors.skills }}
      </p>
      <OperationStatus
        v-if="running.skills"
        :operation-id="running.skills"
      />
      <CopyFleetctl
        :command="skillsCmd"
        missing="Pick an SSH endpoint and auth to see the command."
      />
    </section>
  </div>
</template>
