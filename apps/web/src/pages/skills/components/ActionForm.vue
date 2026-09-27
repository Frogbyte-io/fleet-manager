<script setup lang="ts">
import { computed, ref, watch } from 'vue'

import { startSkillsOperation, type OperationDto } from '@frogbyte-io/fleet-api-client'

import { errorMessage, unwrap } from '../../machine/api'
import CopyFleetctl from '../../machine/components/CopyFleetctl.vue'
import OperationStatus from '../../machine/components/OperationStatus.vue'
import {
  actionCommand,
  CONFIRMED,
  DRY_RUNNABLE,
  emptyInput,
  missingField,
  operationRequest,
  PREVIEW_FIRST,
  type ActionInput,
  type SkillAction,
  type Target,
} from '../actions'
import type { SkillsData } from '../model'
import OutcomePanel from './OutcomePanel.vue'

// One Skills Manager library or preset action on one machine. Remove, adopt,
// and preset delete run as a dry run first; the real action unlocks only
// after that preview succeeded for exactly the same request.
const props = defineProps<{
  target: Target | null
  data: SkillsData
}>()
const input = defineModel<ActionInput>('input', { required: true })
const emit = defineEmits<{ started: [operation: OperationDto, label: string], settled: [operation: OperationDto] }>()

const ACTIONS: { value: SkillAction, label: string, group: string }[] = [
  { value: 'install', label: 'Install', group: 'Library' },
  { value: 'update', label: 'Update', group: 'Library' },
  { value: 'check', label: 'Check for updates', group: 'Library' },
  { value: 'remove', label: 'Remove', group: 'Library' },
  { value: 'adopt', label: 'Adopt unmanaged directory', group: 'Library' },
  { value: 'set-source', label: 'Set source', group: 'Library' },
  { value: 'deploy', label: 'Deploy to agents', group: 'Deployment' },
  { value: 'undeploy', label: 'Undeploy from agents', group: 'Deployment' },
  { value: 'presets.create', label: 'Create preset', group: 'Presets' },
  { value: 'presets.update', label: 'Update preset', group: 'Presets' },
  { value: 'presets.delete', label: 'Delete preset', group: 'Presets' },
  { value: 'presets.add-skill', label: 'Add skill to preset', group: 'Presets' },
  { value: 'presets.remove-skill', label: 'Remove skill from preset', group: 'Presets' },
  { value: 'presets.deploy', label: 'Deploy preset', group: 'Presets' },
  { value: 'presets.undeploy', label: 'Undeploy preset', group: 'Presets' },
]
const groups = ['Library', 'Deployment', 'Presets']

const action = computed({
  get: () => input.value.action,
  set: (value: SkillAction) => (input.value = emptyInput(value)),
})

const isPreset = computed(() => action.value.startsWith('presets.'))
const needsAgents = computed(() => ['deploy', 'undeploy', 'presets.deploy', 'presets.undeploy'].includes(action.value))
const previewFirst = computed(() => PREVIEW_FIRST.has(action.value))
const confirmed = computed(() => CONFIRMED.has(action.value))
const canDryRun = computed(() => DRY_RUNNABLE.has(action.value) && !previewFirst.value)

const referenceLabel = computed(() => {
  switch (action.value) {
    case 'install': return 'Source (skills.sh ref, Git URL, or local directory)'
    case 'update':
    case 'check': return 'Skill (empty = all)'
    case 'presets.create': return 'New preset name'
    default: return isPreset.value ? 'Preset' : 'Skill'
  }
})
const referenceOptions = computed(() => {
  if (action.value === 'install' || action.value === 'presets.create')
    return []
  return isPreset.value ? props.data.presets.map(p => p.id) : props.data.skills.map(s => s.id)
})
const agentOptions = computed(() => [...props.data.agents].sort((a, b) => Number(b.installed) - Number(a.installed) || a.name.localeCompare(b.name)))

function toggleAgent(id: string) {
  const agents = input.value.agents
  input.value = { ...input.value, agents: agents.includes(id) ? agents.filter(a => a !== id) : [...agents, id] }
}

const extraPaths = computed({
  get: () => input.value.paths.join('\n'),
  set: (value: string) => (input.value = { ...input.value, paths: value.split('\n').map(p => p.trim()).filter(Boolean) }),
})
const extraReferences = computed({
  get: () => input.value.references.join('\n'),
  set: (value: string) => (input.value = { ...input.value, references: value.split('\n').map(p => p.trim()).filter(Boolean) }),
})

const missing = computed(() => (props.target ? missingField(input.value) : 'an SSH endpoint and auth'))
const dryRun = ref(false)
watch(action, () => (dryRun.value = false))

/** Identifies the request apart from dryRun, so a preview matches only its own request. */
const requestKey = computed(() => (props.target ? JSON.stringify(operationRequest(props.target, input.value, false)) : ''))

const preview = ref<{ key: string, operationId: string, operation: OperationDto | null } | null>(null)
const previewCurrent = computed(() => preview.value?.key === requestKey.value)
const previewOk = computed(() => previewCurrent.value && preview.value?.operation?.state === 'succeeded')

const runId = ref<string | null>(null)
const runOperation = ref<OperationDto | null>(null)
const busy = ref(false)
const error = ref('')
const confirming = ref(false)
watch(requestKey, () => (confirming.value = false))

const label = computed(() => {
  const what = input.value.reference.trim() || (action.value === 'update' || action.value === 'check' ? 'all' : '')
  return `skills ${action.value}${what ? ` ${what}` : ''}`
})

async function start(asPreview: boolean) {
  if (!props.target || missing.value)
    return
  busy.value = true
  error.value = ''
  const key = requestKey.value
  const dry = asPreview || (canDryRun.value && dryRun.value)
  try {
    const operation = unwrap<OperationDto>(
      await startSkillsOperation(props.target.machineId, operationRequest(props.target, input.value, dry)),
      [202],
    )
    const text = `${label.value}${dry ? ' (dry run)' : ''}`
    emit('started', operation, text)
    if (asPreview) {
      preview.value = { key, operationId: operation.id, operation: null }
    }
    else {
      runId.value = operation.id
      runOperation.value = null
      confirming.value = false
      preview.value = null
    }
  }
  catch (caught) {
    error.value = errorMessage(caught)
  }
  finally {
    busy.value = false
  }
}

function onPreviewSettled(operation: OperationDto) {
  if (preview.value?.operationId === operation.id)
    preview.value = { ...preview.value, operation }
}

function onRunSettled(operation: OperationDto) {
  runOperation.value = operation
  emit('settled', operation)
}

const command = computed(() => (props.target && !missing.value
  ? actionCommand(props.target, input.value, previewFirst.value ? !previewOk.value : canDryRun.value && dryRun.value)
  : null))
</script>

<template>
  <div
    class="space-y-3"
    data-testid="skills-action-form"
  >
    <div class="flex flex-wrap items-end gap-3 text-xs">
      <label class="flex flex-col gap-1">
        <span class="fc-kicker">Action</span>
        <select
          v-model="action"
          class="h-8 rounded-sm border border-input bg-background px-2 text-foreground"
          data-testid="skills-action"
        >
          <optgroup
            v-for="group in groups"
            :key="group"
            :label="group"
          >
            <option
              v-for="item in ACTIONS.filter(a => a.group === group)"
              :key="item.value"
              :value="item.value"
            >
              {{ item.label }}
            </option>
          </optgroup>
        </select>
      </label>

      <label
        v-if="action !== 'adopt'"
        class="flex flex-col gap-1"
      >
        <span class="fc-kicker">{{ referenceLabel }}</span>
        <input
          v-model="input.reference"
          :list="referenceOptions.length ? 'skills-reference-options' : undefined"
          class="h-8 w-64 rounded-sm border border-input bg-background px-2 font-mono text-foreground"
          data-testid="skills-reference"
        >
        <datalist id="skills-reference-options">
          <option
            v-for="option in referenceOptions"
            :key="option"
            :value="option"
          />
        </datalist>
      </label>

      <template v-if="action === 'install'">
        <label class="flex items-center gap-1.5 pb-2">
          <input
            v-model="input.local"
            type="checkbox"
            :disabled="input.git"
          >
          <span>local dir</span>
        </label>
        <label class="flex items-center gap-1.5 pb-2">
          <input
            v-model="input.git"
            type="checkbox"
            :disabled="input.local"
          >
          <span>Git</span>
        </label>
        <label class="flex flex-col gap-1">
          <span class="fc-kicker">Name (optional)</span>
          <input
            v-model="input.name"
            class="h-8 w-40 rounded-sm border border-input bg-background px-2 font-mono text-foreground"
          >
        </label>
        <label class="flex items-center gap-1.5 pb-2">
          <input
            v-model="input.sync"
            type="checkbox"
            :disabled="input.syncPreset !== ''"
          >
          <span>add to current preset and sync</span>
        </label>
        <label class="flex flex-col gap-1">
          <span class="fc-kicker">Or sync preset</span>
          <input
            v-model="input.syncPreset"
            :disabled="input.sync"
            class="h-8 w-36 rounded-sm border border-input bg-background px-2 font-mono text-foreground disabled:opacity-50"
          >
        </label>
      </template>

      <template v-if="action === 'set-source'">
        <label class="flex flex-col gap-1">
          <span class="fc-kicker">Source URL</span>
          <input
            v-model="input.sourceUrl"
            placeholder="https://github.com/org/skills"
            class="h-8 w-72 rounded-sm border border-input bg-background px-2 font-mono text-foreground"
          >
        </label>
        <label class="flex flex-col gap-1">
          <span class="fc-kicker">Subpath</span>
          <input
            v-model="input.path"
            class="h-8 w-40 rounded-sm border border-input bg-background px-2 font-mono text-foreground"
          >
        </label>
        <label class="flex flex-col gap-1">
          <span class="fc-kicker">Branch</span>
          <input
            v-model="input.branch"
            class="h-8 w-32 rounded-sm border border-input bg-background px-2 font-mono text-foreground"
          >
        </label>
        <label class="flex items-center gap-1.5 pb-2 text-fc-warn">
          <input
            v-model="input.force"
            type="checkbox"
          >
          <span>force (replaces the library copy wholesale when content differs)</span>
        </label>
      </template>

      <template v-if="action === 'adopt'">
        <label class="flex flex-col gap-1">
          <span class="fc-kicker">Directory to adopt</span>
          <input
            v-model="input.path"
            placeholder="~/.claude/skills/db"
            class="h-8 w-72 rounded-sm border border-input bg-background px-2 font-mono text-foreground"
            data-testid="skills-adopt-path"
          >
        </label>
        <label class="flex flex-col gap-1">
          <span class="fc-kicker">Upstream Git URL (optional)</span>
          <input
            v-model="input.sourceUrl"
            class="h-8 w-60 rounded-sm border border-input bg-background px-2 font-mono text-foreground"
          >
        </label>
        <label class="flex flex-col gap-1">
          <span class="fc-kicker">Git subpath</span>
          <input
            v-model="input.gitSubpath"
            class="h-8 w-36 rounded-sm border border-input bg-background px-2 font-mono text-foreground"
          >
        </label>
        <label class="flex w-full flex-col gap-1">
          <span class="fc-kicker">More directories (one per line)</span>
          <textarea
            v-model="extraPaths"
            rows="2"
            class="w-full max-w-xl rounded-sm border border-input bg-background px-2 py-1 font-mono text-foreground"
          />
        </label>
      </template>

      <label
        v-if="action === 'remove'"
        class="flex w-full flex-col gap-1"
      >
        <span class="fc-kicker">More skills to remove (one per line)</span>
        <textarea
          v-model="extraReferences"
          rows="2"
          class="w-full max-w-xl rounded-sm border border-input bg-background px-2 py-1 font-mono text-foreground"
        />
      </label>

      <label
        v-if="action === 'presets.add-skill' || action === 'presets.remove-skill'"
        class="flex flex-col gap-1"
      >
        <span class="fc-kicker">Skill</span>
        <input
          v-model="input.path"
          list="skills-skill-options"
          class="h-8 w-56 rounded-sm border border-input bg-background px-2 font-mono text-foreground"
        >
        <datalist id="skills-skill-options">
          <option
            v-for="skill in data.skills"
            :key="skill.id"
            :value="skill.id"
          />
        </datalist>
      </label>

      <template v-if="action === 'presets.create' || action === 'presets.update'">
        <label
          v-if="action === 'presets.update'"
          class="flex flex-col gap-1"
        >
          <span class="fc-kicker">New name</span>
          <input
            v-model="input.name"
            class="h-8 w-40 rounded-sm border border-input bg-background px-2 text-foreground"
          >
        </label>
        <label class="flex flex-col gap-1">
          <span class="fc-kicker">Description</span>
          <input
            v-model="input.description"
            class="h-8 w-60 rounded-sm border border-input bg-background px-2 text-foreground"
          >
        </label>
        <label class="flex flex-col gap-1">
          <span class="fc-kicker">Icon</span>
          <input
            v-model="input.icon"
            class="h-8 w-28 rounded-sm border border-input bg-background px-2 font-mono text-foreground"
          >
        </label>
      </template>
    </div>

    <fieldset
      v-if="needsAgents"
      class="text-xs"
    >
      <legend class="fc-kicker mb-1">
        Agents
      </legend>
      <p
        v-if="agentOptions.length === 0"
        class="text-fc-muted"
      >
        No agents reported — probe the machine first.
      </p>
      <div class="flex flex-wrap gap-1.5">
        <button
          v-for="agent in agentOptions"
          :key="agent.id"
          type="button"
          class="rounded-sm border px-2 py-1"
          :class="input.agents.includes(agent.id) ? 'border-ring text-fc-ink' : 'border-fc-line2 text-fc-muted'"
          :aria-pressed="input.agents.includes(agent.id)"
          :data-testid="`agent-${agent.id}`"
          @click="toggleAgent(agent.id)"
        >
          {{ agent.name }}<span
            v-if="!agent.installed"
            class="ml-1 text-fc-faint"
          >(not installed)</span>
        </button>
      </div>
    </fieldset>

    <div class="flex flex-wrap items-center gap-2 text-xs">
      <template v-if="previewFirst">
        <button
          type="button"
          class="h-8 rounded-sm border border-fc-info/40 px-3 text-fc-info hover:bg-fc-info/10 disabled:opacity-50"
          :disabled="!!missing || busy"
          data-testid="skills-preview"
          @click="start(true)"
        >
          Preview (dry run)
        </button>
        <button
          v-if="!confirming"
          type="button"
          class="h-8 rounded-sm border px-3 disabled:opacity-50"
          :class="confirmed ? 'border-fc-err/50 text-fc-err hover:bg-fc-err/10' : 'border-fc-ok/50 text-fc-ok hover:bg-fc-ok/10'"
          :disabled="!previewOk || busy"
          :title="previewOk ? '' : 'Run a successful preview of this exact request first'"
          data-testid="skills-run"
          @click="confirmed ? (confirming = true) : start(false)"
        >
          {{ confirmed ? `${action === 'remove' ? 'Remove' : 'Delete'}…` : 'Adopt' }}
        </button>
        <span
          v-if="!previewOk"
          class="text-fc-faint"
        >{{ previewCurrent && preview?.operation && preview.operation.state !== 'succeeded' ? 'The preview did not succeed; fix the request and preview again.' : 'Preview first — the real action unlocks after a successful dry run of this exact request.' }}</span>
      </template>
      <template v-else>
        <label
          v-if="canDryRun"
          class="flex items-center gap-1.5"
        >
          <input
            v-model="dryRun"
            type="checkbox"
            data-testid="skills-dry-run"
          >
          <span>dry run</span>
        </label>
        <button
          type="button"
          class="h-8 rounded-sm border border-fc-info/40 px-3 text-fc-info hover:bg-fc-info/10 disabled:opacity-50"
          :disabled="!!missing || busy"
          data-testid="skills-run"
          @click="start(false)"
        >
          Run
        </button>
      </template>
      <span
        v-if="missing"
        class="text-fc-faint"
      >Needs {{ missing }}.</span>
    </div>

    <div
      v-if="confirming"
      class="rounded-sm border border-fc-err/40 bg-fc-err/5 p-3 text-xs"
      role="alertdialog"
      aria-label="Confirm removal"
      data-testid="skills-confirm"
    >
      <p>
        {{ action === 'remove' ? 'Remove' : 'Delete preset' }}
        <span class="font-mono text-fc-ink">{{ [input.reference, ...input.references].filter(Boolean).join(', ') }}</span>
        on <span class="font-mono text-fc-ink">{{ target?.machineId }}</span>. This is sent with the CLI's explicit <span class="font-mono">--yes</span>; the preview above shows what it touches.
      </p>
      <div class="mt-2 flex gap-2">
        <button
          type="button"
          class="h-8 rounded-sm border border-fc-err bg-fc-err/10 px-3 font-semibold text-fc-err disabled:opacity-50"
          :disabled="busy || !previewOk"
          data-testid="skills-confirm-run"
          @click="start(false)"
        >
          Yes, {{ action === 'remove' ? 'remove' : 'delete' }}
        </button>
        <button
          type="button"
          class="h-8 px-2 text-fc-muted hover:text-fc-ink"
          @click="confirming = false"
        >
          Cancel
        </button>
      </div>
    </div>

    <p
      v-if="error"
      class="text-xs text-fc-err"
      role="alert"
    >
      {{ error }}
    </p>

    <div
      v-if="preview && previewCurrent"
      class="space-y-2"
    >
      <p class="fc-kicker">
        Preview
      </p>
      <OperationStatus
        :operation-id="preview.operationId"
        :label="`${label} (dry run)`"
        @settled="onPreviewSettled"
      />
      <OutcomePanel
        v-if="preview.operation"
        :operation="preview.operation"
      />
    </div>

    <div
      v-if="runId"
      class="space-y-2"
    >
      <OperationStatus
        :operation-id="runId"
        :label="label"
        @settled="onRunSettled"
      />
      <OutcomePanel
        v-if="runOperation"
        :operation="runOperation"
      />
    </div>

    <CopyFleetctl
      :command="command"
      :missing="missing ? `Needs ${missing} to show the command.` : undefined"
    />
  </div>
</template>
