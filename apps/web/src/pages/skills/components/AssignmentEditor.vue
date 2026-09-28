<script setup lang="ts">
import { computed, ref, watch } from 'vue'

import type { CatalogVersionDto, MachineDto } from '@frogbyte-io/fleet-api-client'

import CopyFleetctl from '../../machine/components/CopyFleetctl.vue'
import { assignmentErrors, assignmentYaml, shortDigest, uuidv7, type Assignment, type AssignmentScope } from '../catalog'
import type { AgentEntry } from '../model'

// Assignments are `SkillPreset` resources in Fleet Git (desired state), not
// API records: the controller composes them per machine and the apply
// planner rolls them out. This editor builds the validated resource to
// commit; it does not write anything itself.
const props = defineProps<{
  skillId: string
  catalogId: string
  versions: CatalogVersionDto[]
  agents: AgentEntry[]
  machines: MachineDto[]
}>()

const scopeType = ref<AssignmentScope['type']>('all')
const scopeValue = ref('')
const versionId = ref<string>('')
const deployTo = ref<string[]>([])
const denyAgents = ref<string[]>([])
const name = ref(`${props.skillId}-all`)
// Stable per editor so re-rendering the YAML keeps one identity.
const id = ref(uuidv7())

watch(() => props.versions, (versions) => {
  if (!versions.some(v => v.id === versionId.value))
    versionId.value = versions[0]?.id ?? ''
}, { immediate: true })

watch([scopeType, scopeValue], ([type, value]) => {
  const suffix = type === 'all' ? 'all' : (value.trim().toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || type)
  name.value = `${props.skillId}-${suffix}`.slice(0, 63).replace(/-$/, '')
})

const groups = computed(() => [...new Set(props.machines.flatMap(m => m.groups))].sort())
const tags = computed(() => [...new Set(props.machines.flatMap(m => m.tags))].sort())
const scopeOptions = computed(() => {
  switch (scopeType.value) {
    case 'group': return groups.value.map(g => ({ value: g, label: g }))
    case 'tag': return tags.value.map(t => ({ value: t, label: t }))
    case 'machine': return props.machines.map(m => ({ value: m.id, label: `${m.name} (${m.id})` }))
    default: return []
  }
})

function toggle(list: string[], value: string): string[] {
  return list.includes(value) ? list.filter(v => v !== value) : [...list, value]
}

const assignment = computed<Assignment>(() => ({
  name: name.value,
  skillId: props.skillId,
  catalogId: props.catalogId,
  catalogVersionId: versionId.value || null,
  scope: scopeType.value === 'all' ? { type: 'all' } : { type: scopeType.value, value: scopeValue.value },
  deployTo: [...deployTo.value].sort(),
  denyAgents: [...denyAgents.value].sort(),
}))
// A built-in skill with no agents is how Fleet Git removes its default.
const builtin = computed(() => props.catalogId.startsWith('builtin-'))
const errors = computed(() => [
  ...assignmentErrors(assignment.value, { allowNoAgents: builtin.value }),
  ...(versionId.value ? [] : ['publish a version first: assignments pin a catalog version']),
])
const yaml = computed(() => (errors.value.length ? null : assignmentYaml(assignment.value, id.value)))
const path = computed(() => `skills/${name.value}.yaml`)

const copied = ref(false)
async function copyYaml() {
  if (!yaml.value)
    return
  try {
    await navigator.clipboard.writeText(yaml.value)
    copied.value = true
    setTimeout(() => (copied.value = false), 1500)
  }
  catch {
    // Clipboard unavailable (insecure context); the YAML stays selectable.
  }
}
</script>

<template>
  <div
    class="space-y-3 text-xs"
    data-testid="assignment-editor"
  >
    <p class="text-fc-muted">
      Assignments live in Fleet Git as <span class="font-mono">SkillPreset</span> resources. Commit the resource below; once the revision is active, the apply planner deploys it to every matching machine, queues stale and offline ones, and reports manual changes as drift.
    </p>
    <div class="flex flex-wrap items-end gap-3">
      <label class="flex flex-col gap-1">
        <span class="fc-kicker">Assigned to</span>
        <select
          v-model="scopeType"
          class="h-8 rounded-sm border border-input bg-background px-2 text-foreground"
          data-testid="assignment-scope"
        >
          <option value="all">All machines (global)</option>
          <option value="group">Group…</option>
          <option value="tag">Tag…</option>
          <option value="machine">Machine…</option>
        </select>
      </label>
      <label
        v-if="scopeType !== 'all'"
        class="flex flex-col gap-1"
      >
        <span class="fc-kicker">{{ scopeType }}</span>
        <input
          v-model="scopeValue"
          :list="`assignment-${scopeType}-options`"
          class="h-8 w-56 rounded-sm border border-input bg-background px-2 font-mono text-foreground"
          data-testid="assignment-scope-value"
        >
        <datalist :id="`assignment-${scopeType}-options`">
          <option
            v-for="option in scopeOptions"
            :key="option.value"
            :value="option.value"
          >
            {{ option.label }}
          </option>
        </datalist>
      </label>
      <label class="flex flex-col gap-1">
        <span class="fc-kicker">Pinned version</span>
        <select
          v-model="versionId"
          class="h-8 rounded-sm border border-input bg-background px-2 font-mono text-foreground"
        >
          <option
            v-for="version in versions"
            :key="version.id"
            :value="version.id"
          >
            {{ shortDigest(version.contentDigest) }} · {{ new Date(version.publishedAt).toISOString().slice(0, 10) }}
          </option>
        </select>
      </label>
      <label class="flex flex-col gap-1">
        <span class="fc-kicker">Resource name</span>
        <input
          v-model="name"
          class="h-8 w-56 rounded-sm border border-input bg-background px-2 font-mono text-foreground"
        >
      </label>
    </div>

    <fieldset>
      <legend class="fc-kicker mb-1">
        Deploy to agents
      </legend>
      <div class="flex flex-wrap gap-1.5">
        <button
          v-for="agent in agents"
          :key="agent.id"
          type="button"
          class="rounded-sm border px-2 py-1"
          :class="deployTo.includes(agent.id) ? 'border-ring text-fc-ink' : 'border-fc-line2 text-fc-muted'"
          :aria-pressed="deployTo.includes(agent.id)"
          :data-testid="`assignment-agent-${agent.id}`"
          @click="deployTo = toggle(deployTo, agent.id); denyAgents = denyAgents.filter(a => a !== agent.id)"
        >
          {{ agent.name }}
        </button>
      </div>
    </fieldset>
    <fieldset v-if="agents.length">
      <legend class="fc-kicker mb-1">
        Deny (wins over any other assignment)
      </legend>
      <div class="flex flex-wrap gap-1.5">
        <button
          v-for="agent in agents.filter(a => !deployTo.includes(a.id))"
          :key="agent.id"
          type="button"
          class="rounded-sm border px-2 py-1"
          :class="denyAgents.includes(agent.id) ? 'border-fc-err/60 text-fc-err' : 'border-fc-line2 text-fc-muted'"
          :aria-pressed="denyAgents.includes(agent.id)"
          @click="denyAgents = toggle(denyAgents, agent.id)"
        >
          {{ agent.name }}
        </button>
      </div>
    </fieldset>

    <p
      v-if="builtin"
      class="text-fc-muted"
      data-testid="assignment-builtin"
    >
      This skill ships with the controller. Once Fleet Git activation composes assignments, it is assigned by default to Claude Code and Codex on every machine. Committing any <span class="font-mono">SkillPreset</span> for it hands it to Fleet Git; <strong v-if="deployTo.length === 0">with no agents selected, this resource removes it everywhere.</strong><span v-else>this one replaces the default with the scope and agents above.</span>
    </p>
    <ul
      v-if="errors.length"
      class="list-disc pl-5 text-fc-warn"
      data-testid="assignment-errors"
    >
      <li
        v-for="error in errors"
        :key="error"
      >
        {{ error }}
      </li>
    </ul>
    <div
      v-else
      class="rounded-sm border border-fc-line bg-fc-inset p-2"
    >
      <div class="flex items-center justify-between gap-2">
        <span class="fc-kicker">{{ path }} in Fleet Git</span>
        <button
          type="button"
          class="font-mono text-[10px] uppercase tracking-wider text-fc-info hover:text-fc-ink"
          @click="copyYaml"
        >
          {{ copied ? 'Copied' : 'Copy YAML' }}
        </button>
      </div>
      <pre
        class="mt-1 overflow-x-auto font-mono text-[11px] text-fc-ink"
        data-testid="assignment-yaml"
      >{{ yaml }}</pre>
    </div>
    <CopyFleetctl
      :command="null"
      missing="Assignments are desired state, so there is no fleetctl mutation: commit the resource to Fleet Git and activate the revision."
    />
  </div>
</template>
