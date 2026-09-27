<script setup lang="ts">
import { useQuery, useQueryClient } from '@tanstack/vue-query'
import { computed, ref } from 'vue'
import { RouterLink } from 'vue-router'

import {
  getMachineSkills,
  startSkillsOperation,
  type MachineDto,
  type OperationDto,
  type SkillsSnapshotDto,
} from '@frogbyte-io/fleet-api-client'
import StatusChip from '@/components/fleet/StatusChip.vue'

import { relativeTime } from '../../fleet/inventory'
import { emptyInput, OPERATION_TIMEOUT_SECONDS, type ActionInput, type SkillAction } from '../../skills/actions'
import ActionForm from '../../skills/components/ActionForm.vue'
import { agentShort, parseSkillsData } from '../../skills/model'
import { MATRIX_KEY, machineSkillsKey } from '../../skills/useSkills'
import { ApiRequestError, errorMessage, retryTransient, unwrap } from '../api'
import CopyFleetctl from '../components/CopyFleetctl.vue'
import OperationStatus from '../components/OperationStatus.vue'
import SshAuthFields from '../components/SshAuthFields.vue'
import { skillsProbeCommand, type SshAuth } from '../fleetctl'
import { useMachineOperations } from '../operations'

// This machine's Skills Manager library, presets, and per-agent deployments,
// with the documented library and preset actions (FM-925). Machine-local
// skill content is not read or edited here.
const props = defineProps<{ machine: MachineDto }>()

const queryClient = useQueryClient()
const { track } = useMachineOperations()

const snapshotQuery = useQuery({
  queryKey: machineSkillsKey(props.machine.id),
  queryFn: async () => {
    try {
      return unwrap<SkillsSnapshotDto>(await getMachineSkills(props.machine.id))
    }
    catch (error) {
      // 404: the machine has never been probed.
      if (error instanceof ApiRequestError && error.status === 404)
        return null
      throw error
    }
  },
  retry: retryTransient,
})
const snapshot = computed(() => snapshotQuery.data.value ?? null)
const data = computed(() => parseSkillsData(snapshot.value?.data))
const agentNames = computed(() => new Map(data.value.agents.map(a => [a.id, a.name])))

const endpointId = ref('')
const auth = ref<SshAuth>({ type: 'agent' })
const target = computed(() => (endpointId.value !== '' && (auth.value.type === 'agent' || auth.value.path !== '')
  ? { machineId: props.machine.id, endpointId: endpointId.value, auth: auth.value }
  : null))

const probeId = ref<string | null>(null)
const probeError = ref('')
const probing = ref(false)

async function probe() {
  if (!target.value)
    return
  probing.value = true
  probeError.value = ''
  try {
    const operation = unwrap<OperationDto>(await startSkillsOperation(props.machine.id, {
      ...target.value,
      timeoutSeconds: OPERATION_TIMEOUT_SECONDS,
      dryRun: false,
    }), [202])
    probeId.value = operation.id
    track(operation, 'skills probe')
  }
  catch (error) {
    probeError.value = errorMessage(error)
  }
  finally {
    probing.value = false
  }
}

async function refresh() {
  await Promise.all([
    queryClient.invalidateQueries({ queryKey: machineSkillsKey(props.machine.id) }),
    queryClient.invalidateQueries({ queryKey: MATRIX_KEY }),
  ])
}

const input = ref<ActionInput>(emptyInput('install'))
const changed = ref(false)
const formRef = ref<HTMLElement | null>(null)

function prefill(action: SkillAction, reference: string, agents: string[] = []) {
  input.value = { ...emptyInput(action), reference, agents }
  formRef.value?.scrollIntoView?.({ behavior: 'smooth', block: 'start' })
}

function onStarted(operation: OperationDto, label: string) {
  track(operation, label)
}

function onSettled(operation: OperationDto, dryRun: boolean) {
  if (operation.state === 'succeeded' && !dryRun)
    changed.value = true
}

function onProbeSettled(operation: OperationDto) {
  void refresh()
  if (operation.state === 'succeeded')
    changed.value = false
}

/** Actions need a supported CLI; a machine never probed may still have one. */
const actionsBlocked = computed(() => snapshot.value !== null && snapshot.value.availability !== 'available')

const availabilityTone = computed(() => {
  if (!snapshot.value)
    return 'faint' as const
  if (snapshot.value.availability === 'available')
    return snapshot.value.stale ? 'warn' as const : 'ok' as const
  return 'muted' as const
})
</script>

<template>
  <div class="space-y-6">
    <SshAuthFields
      v-model:endpoint-id="endpointId"
      v-model:auth="auth"
      :endpoints="machine.endpoints"
    />

    <section class="space-y-2">
      <div class="flex flex-wrap items-center gap-2 border-b-2 border-fc-ink pb-1">
        <h2 class="fc-kicker">
          Skills Manager
        </h2>
        <StatusChip
          v-if="snapshot"
          :label="snapshot.availability === 'available' && snapshot.stale ? 'stale' : snapshot.availability"
          :tone="availabilityTone"
        />
        <span
          v-if="snapshot?.cliVersion"
          class="font-mono text-[10px] text-fc-faint"
        >cli {{ snapshot.cliVersion }}</span>
        <span
          v-if="snapshot"
          class="font-mono text-[10px] text-fc-faint"
        >observed {{ relativeTime(snapshot.observedAt) }} · update check {{ snapshot.updateCheck }}</span>
        <RouterLink
          to="/skills"
          class="ml-auto font-mono text-[10px] uppercase tracking-wider text-fc-info hover:text-fc-ink"
        >
          Fleet skills →
        </RouterLink>
      </div>

      <p
        v-if="snapshotQuery.isLoading.value"
        class="text-xs text-fc-faint"
      >
        Loading the skills inventory…
      </p>
      <p
        v-else-if="snapshotQuery.error.value"
        class="text-xs text-fc-err"
        role="alert"
      >
        Skills inventory unavailable: {{ errorMessage(snapshotQuery.error.value) }}
      </p>
      <p
        v-else-if="!snapshot"
        class="text-xs text-fc-muted"
        data-testid="skills-not-probed"
      >
        This machine has not been probed yet. Probe it to read its Skills Manager library.
      </p>
      <p
        v-else-if="snapshot.availability === 'absent'"
        class="text-xs text-fc-muted"
      >
        skills-manager-cli is not installed on this machine, so there is nothing to manage. A probe with a pinned release can install it (<span class="font-mono">fleetctl skills probe … --artifact-url … --artifact-sha256 …</span>).
      </p>
      <p
        v-else-if="snapshot.availability === 'unsupported'"
        class="text-xs text-fc-warn"
      >
        This machine's skills-manager-cli{{ snapshot.cliVersion ? ` ${snapshot.cliVersion}` : '' }} is outside Fleet's tested contract (v1.40.0). Fleet will not act on it until the contract covers that version.
      </p>

      <div class="flex flex-wrap items-center gap-2">
        <button
          type="button"
          class="h-8 rounded-sm border border-fc-info/40 px-3 text-xs text-fc-info hover:bg-fc-info/10 disabled:opacity-50"
          :disabled="!target || probing"
          data-testid="skills-probe"
          @click="probe"
        >
          Probe skills
        </button>
        <span
          v-if="changed"
          class="text-xs text-fc-muted"
          data-testid="skills-probe-hint"
        >An action changed this machine — probe again to refresh the library below.</span>
      </div>
      <p
        v-if="probeError"
        class="text-xs text-fc-err"
        role="alert"
      >
        {{ probeError }}
      </p>
      <OperationStatus
        v-if="probeId"
        :operation-id="probeId"
        label="skills probe"
        @settled="onProbeSettled"
      />
      <CopyFleetctl
        :command="target ? skillsProbeCommand(machine.id, target.endpointId, target.auth) : null"
        missing="Pick an SSH endpoint and auth to see the command."
      />
    </section>

    <template v-if="snapshot?.availability === 'available'">
      <section class="space-y-2">
        <h2 class="fc-kicker border-b-2 border-fc-ink pb-1">
          Library <span class="text-fc-faint">{{ data.skills.length }}</span>
        </h2>
        <p
          v-if="data.skills.length === 0"
          class="text-xs text-fc-muted"
        >
          The library is empty.
        </p>
        <table
          v-else
          class="w-full text-xs"
          data-testid="skills-library"
        >
          <thead>
            <tr class="text-left">
              <th class="fc-kicker py-1 font-normal">
                Skill
              </th>
              <th class="fc-kicker py-1 font-normal">
                Deployed to
              </th>
              <th class="fc-kicker py-1 font-normal">
                Presets
              </th>
              <th class="fc-kicker py-1 font-normal">
                Update
              </th>
              <th class="py-1" />
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="skill in data.skills"
              :key="skill.id"
              class="border-t border-fc-line"
              :data-testid="`library-${skill.id}`"
            >
              <td class="py-1.5">
                <span class="font-mono text-fc-ink">{{ skill.id }}</span>
                <span
                  v-if="skill.name !== skill.id"
                  class="ml-1 text-fc-muted"
                >{{ skill.name }}</span>
                <span
                  v-if="!skill.enabled"
                  class="ml-1 font-mono text-[10px] text-fc-faint"
                >disabled</span>
              </td>
              <td class="py-1.5">
                <span
                  v-if="skill.deployedTo.length === 0"
                  class="text-fc-faint"
                >—</span>
                <span
                  v-for="agent in skill.deployedTo"
                  :key="agent"
                  class="mr-0.5 rounded-sm border border-fc-ok/45 px-1 font-mono text-[9px] font-bold text-fc-ok"
                  :title="agentNames.get(agent) ?? agent"
                >{{ agentShort(agent) }}</span>
              </td>
              <td class="py-1.5 font-mono text-[11px] text-fc-muted">
                {{ skill.presetIds.join(', ') || '—' }}
              </td>
              <td
                class="py-1.5 font-mono text-[11px]"
                :class="skill.updateStatus === 'update_available' ? 'text-fc-info' : 'text-fc-faint'"
              >
                {{ skill.updateStatus.replaceAll('_', ' ') }}
              </td>
              <td class="py-1.5 text-right">
                <div class="flex justify-end gap-2 font-mono text-[10px] uppercase tracking-wider">
                  <button
                    type="button"
                    class="text-fc-info hover:text-fc-ink"
                    @click="prefill('deploy', skill.id)"
                  >
                    Deploy
                  </button>
                  <button
                    v-if="skill.deployedTo.length"
                    type="button"
                    class="text-fc-muted hover:text-fc-ink"
                    @click="prefill('undeploy', skill.id, [...skill.deployedTo])"
                  >
                    Undeploy
                  </button>
                  <button
                    v-if="skill.updateStatus === 'update_available'"
                    type="button"
                    class="text-fc-info hover:text-fc-ink"
                    @click="prefill('update', skill.id)"
                  >
                    Update
                  </button>
                  <button
                    type="button"
                    class="text-fc-err hover:text-fc-ink"
                    :data-testid="`remove-${skill.id}`"
                    @click="prefill('remove', skill.id)"
                  >
                    Remove
                  </button>
                </div>
              </td>
            </tr>
          </tbody>
        </table>
      </section>

      <section class="space-y-2">
        <h2 class="fc-kicker border-b-2 border-fc-ink pb-1">
          Presets <span class="text-fc-faint">{{ data.presets.length }}</span>
        </h2>
        <p
          v-if="data.presets.length === 0"
          class="text-xs text-fc-muted"
        >
          No presets.
        </p>
        <ul
          v-else
          class="divide-y divide-fc-line text-xs"
        >
          <li
            v-for="preset in data.presets"
            :key="preset.id"
            class="flex flex-wrap items-center gap-2 py-1.5"
          >
            <span class="font-mono text-fc-ink">{{ preset.id }}</span>
            <span
              v-if="preset.name !== preset.id"
              class="text-fc-muted"
            >{{ preset.name }}</span>
            <span class="font-mono text-[10px] text-fc-faint">{{ preset.skillCount }} skill{{ preset.skillCount === 1 ? '' : 's' }}</span>
            <StatusChip
              v-if="preset.active"
              label="active"
              tone="ok"
            />
            <span class="ml-auto flex gap-2 font-mono text-[10px] uppercase tracking-wider">
              <button
                type="button"
                class="text-fc-info hover:text-fc-ink"
                @click="prefill('presets.deploy', preset.id)"
              >
                Deploy
              </button>
              <button
                type="button"
                class="text-fc-muted hover:text-fc-ink"
                @click="prefill('presets.update', preset.id)"
              >
                Edit
              </button>
              <button
                type="button"
                class="text-fc-err hover:text-fc-ink"
                @click="prefill('presets.delete', preset.id)"
              >
                Delete
              </button>
            </span>
          </li>
        </ul>
      </section>

      <section class="space-y-2">
        <h2 class="fc-kicker border-b-2 border-fc-ink pb-1">
          Agents
        </h2>
        <ul class="flex flex-wrap gap-2 text-xs">
          <li
            v-for="agent in data.agents"
            :key="agent.id"
            class="rounded-sm border border-fc-line px-2 py-1"
            :class="agent.installed ? 'text-fc-ink' : 'text-fc-faint'"
          >
            <span class="font-mono text-[10px]">{{ agentShort(agent.id) }}</span> {{ agent.name }}
            <span class="text-fc-faint">{{ agent.installed ? (agent.enabled ? '' : '· disabled') : '· not installed' }}</span>
          </li>
        </ul>
      </section>
    </template>

    <section
      ref="formRef"
      class="space-y-2"
    >
      <h2 class="fc-kicker border-b-2 border-fc-ink pb-1">
        Actions
      </h2>
      <p
        v-if="actionsBlocked"
        class="text-xs text-fc-muted"
        data-testid="skills-actions-blocked"
      >
        Library and preset actions need a supported skills-manager-cli on this machine. Probe again once it is installed.
      </p>
      <p
        v-else
        class="text-xs text-fc-muted"
      >
        Each action is a durable, audited operation through skills-manager-cli. Remove, adopt, and preset delete preview with a dry run first. Conflicts are reported as paths for you to resolve; Fleet never forces or deletes them.
      </p>
      <ActionForm
        v-if="!actionsBlocked"
        v-model:input="input"
        :target="target"
        :data="data"
        @started="onStarted"
        @settled="onSettled"
      />
    </section>
  </div>
</template>
