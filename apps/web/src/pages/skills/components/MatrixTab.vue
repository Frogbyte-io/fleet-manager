<script setup lang="ts">
import { computed, ref } from 'vue'
import { RouterLink } from 'vue-router'

import type { MachineDriftDto } from '@frogbyte-io/fleet-api-client'
import StatusChip from '@/components/fleet/StatusChip.vue'

import { driftLabel, driftTone, driftView, skillDifferences, STATE_EXPLANATION, type DriftState } from '../../drift/drift'

import {
  agentShort,
  columnLabel,
  columnTone,
  filterRows,
  type AgentEntry,
  type Matrix,
  type MatrixRow,
  type StateFilter,
} from '../model'

// The fleet matrix: skill × machine, one cell per machine showing which
// agents the skill is deployed to (docs/planning/web-console.md, Skills).
const props = withDefaults(defineProps<{
  matrix: Matrix
  agents: AgentEntry[]
  /** Drift against the active desired revision, by machine. */
  drift?: Map<string, MachineDriftDto>
  /** The drift read failed: say so instead of leaving the row blank. */
  driftFailed?: boolean
}>(), { drift: () => new Map(), driftFailed: false })
const emit = defineEmits<{ openCatalog: [catalogId: string] }>()

const text = ref('')
const agent = ref('')
const state = ref<StateFilter>('any')

const rows = computed(() => filterRows(props.matrix.rows, { text: text.value, agent: agent.value, state: state.value }))
const groups = computed(() => [
  { key: 'catalog', label: 'Fleet catalog · authored or referenced by Fleet', rows: rows.value.filter(r => r.group === 'catalog') },
  { key: 'local', label: 'Machine-local · not managed by Fleet', rows: rows.value.filter(r => r.group === 'local') },
].filter(g => g.rows.length > 0))

const agentNames = computed(() => new Map(props.agents.map(a => [a.id, a.name])))

function cellDrift(row: MatrixRow, machineId: string) {
  return skillDifferences(props.drift.get(machineId), row.skillId)
}

function driftTitle(differences: ReturnType<typeof cellDrift>): string {
  return differences.map(d => `${d.identity}: ${d.state}. ${STATE_EXPLANATION[d.state as DriftState] ?? ''}`).join('\n')
}

function cellTitle(row: MatrixRow, machineName: string, agents: string[], update: boolean): string {
  const deployed = agents.length ? `deployed to ${agents.map(a => agentNames.value.get(a) ?? a).join(', ')}` : 'in the library, not deployed'
  return `${row.skillId} on ${machineName}: ${deployed}${update ? ' · update available' : ''}`
}
</script>

<template>
  <div class="mt-4">
    <div class="flex flex-wrap items-end gap-3 text-xs">
      <label class="flex flex-col gap-1">
        <span class="fc-kicker">Skill</span>
        <input
          v-model="text"
          placeholder="Filter by name"
          class="h-8 w-48 rounded-sm border border-input bg-background px-2 text-foreground"
          data-testid="matrix-filter-text"
        >
      </label>
      <label class="flex flex-col gap-1">
        <span class="fc-kicker">Agent</span>
        <select
          v-model="agent"
          class="h-8 rounded-sm border border-input bg-background px-2 text-foreground"
          data-testid="matrix-filter-agent"
        >
          <option value="">All</option>
          <option
            v-for="a in agents"
            :key="a.id"
            :value="a.id"
          >
            {{ a.name }}
          </option>
        </select>
      </label>
      <label class="flex flex-col gap-1">
        <span class="fc-kicker">State</span>
        <select
          v-model="state"
          class="h-8 rounded-sm border border-input bg-background px-2 text-foreground"
          data-testid="matrix-filter-state"
        >
          <option value="any">Any</option>
          <option value="deployed">Deployed</option>
          <option value="update">Update available</option>
          <option value="library-only">In library, not deployed</option>
        </select>
      </label>
    </div>

    <div
      v-if="matrix.columns.length === 0"
      class="mt-4 rounded-sm border border-fc-line p-6 text-sm text-fc-muted"
      data-testid="matrix-empty"
    >
      No machines yet. Add one from the Fleet page, then probe its skills from the machine's Skills tab.
    </div>

    <div
      v-else
      class="mt-3 overflow-x-auto"
    >
      <table
        class="w-full border-collapse border border-fc-line bg-card text-xs"
        data-testid="skills-matrix"
      >
        <thead>
          <tr class="bg-fc-inset">
            <th
              scope="col"
              class="border-b border-fc-line2 px-2 py-2 text-left font-mono text-[9.5px] font-semibold uppercase tracking-widest text-fc-faint"
            >
              Skill
            </th>
            <th
              v-for="column in matrix.columns"
              :key="column.machineId"
              scope="col"
              class="border-b border-fc-line2 px-2 py-2 text-center align-bottom"
              :data-testid="`matrix-column-${column.machineId}`"
            >
              <RouterLink
                :to="{ path: `/fleet/machines/${column.machineId}`, query: { tab: 'skills' } }"
                class="block font-head text-[12px] font-bold text-fc-ink hover:underline"
              >
                {{ column.name }}
              </RouterLink>
              <StatusChip
                class="mt-1"
                :label="columnLabel(column)"
                :tone="columnTone(column)"
              />
            </th>
          </tr>
          <tr
            class="bg-fc-inset"
            data-testid="matrix-drift-row"
          >
            <th
              scope="row"
              class="border-b border-fc-line2 px-2 py-1.5 text-left font-mono text-[9.5px] font-semibold uppercase tracking-widest text-fc-faint"
            >
              Against Fleet Git
            </th>
            <td
              v-for="column in matrix.columns"
              :key="column.machineId"
              class="border-b border-fc-line2 px-2 py-1.5 text-center"
              :data-testid="`matrix-drift-${column.machineId}`"
            >
              <RouterLink
                v-if="drift.get(column.machineId)"
                :to="{ path: `/fleet/machines/${column.machineId}`, query: { tab: 'desired' } }"
              >
                <StatusChip
                  :label="driftLabel(driftView(drift.get(column.machineId)!))"
                  :tone="driftTone(driftView(drift.get(column.machineId)!))"
                />
              </RouterLink>
              <span
                v-else
                class="font-mono text-[10px] text-fc-faint"
                :title="driftFailed ? 'Drift could not be read' : 'No drift reported for this machine'"
              >{{ driftFailed ? 'unread' : '—' }}</span>
            </td>
          </tr>
        </thead>
        <tbody>
          <tr v-if="rows.length === 0">
            <td
              :colspan="matrix.columns.length + 1"
              class="px-3 py-6 text-center text-fc-muted"
              data-testid="matrix-no-rows"
            >
              {{ matrix.rows.length === 0 ? 'No skills reported yet. Machines report their library when probed.' : 'No skills match these filters.' }}
            </td>
          </tr>
          <template
            v-for="group in groups"
            :key="group.key"
          >
            <tr class="bg-fc-inset">
              <td
                :colspan="matrix.columns.length + 1"
                class="px-2 py-1.5 font-mono text-[10px] font-semibold uppercase tracking-[0.14em] text-fc-faint"
              >
                {{ group.label }}
              </td>
            </tr>
            <tr
              v-for="row in group.rows"
              :key="row.skillId"
              class="border-b border-fc-line"
              :data-testid="`matrix-row-${row.skillId}`"
            >
              <th
                scope="row"
                class="px-2 py-1.5 text-left font-normal"
              >
                <button
                  v-if="row.catalogId"
                  type="button"
                  class="font-head text-[13px] font-bold text-fc-ink hover:underline"
                  @click="emit('openCatalog', row.catalogId)"
                >
                  {{ row.skillId }}
                </button>
                <span
                  v-else
                  class="font-head text-[13px] font-bold"
                >{{ row.skillId }}</span>
                <span class="block font-mono text-[10px] tracking-wide text-fc-faint">
                  {{ row.group === 'catalog' ? 'fleet catalog' : 'local' }} · on {{ row.deployedOn }}<template v-if="row.updatesOn"> · <span class="text-fc-info">{{ row.updatesOn }} update{{ row.updatesOn === 1 ? '' : 's' }}</span></template>
                </span>
              </th>
              <td
                v-for="column in matrix.columns"
                :key="column.machineId"
                class="px-2 py-1.5 text-center"
                :data-testid="`cell-${row.skillId}-${column.machineId}`"
                :data-state="row.cells[column.machineId]?.state"
              >
                <template v-if="row.cells[column.machineId]?.state === 'deployed'">
                  <span
                    class="inline-flex gap-0.5"
                    :title="cellTitle(row, column.name, row.cells[column.machineId]!.agents, row.cells[column.machineId]!.update)"
                  >
                    <i
                      v-for="a in row.cells[column.machineId]!.agents"
                      :key="a"
                      class="rounded-sm border px-1 py-px font-mono text-[9px] font-bold not-italic"
                      :class="row.cells[column.machineId]!.update ? 'border-fc-info/45 text-fc-info' : 'border-fc-ok/45 text-fc-ok'"
                    >{{ agentShort(a) }}</i>
                  </span>
                </template>
                <span
                  v-else-if="row.cells[column.machineId]?.state === 'library'"
                  class="font-mono text-[10px]"
                  :class="row.cells[column.machineId]!.update ? 'text-fc-info' : 'text-fc-muted'"
                  :title="cellTitle(row, column.name, [], row.cells[column.machineId]!.update)"
                >library</span>
                <span
                  v-else-if="row.cells[column.machineId]?.state === 'no-cli'"
                  class="font-mono text-[10px] text-fc-faint"
                  :title="`${column.name}: ${columnLabel(column)}`"
                >·</span>
                <span
                  v-else
                  class="text-fc-faint"
                  :title="`${row.skillId} is not installed on ${column.name}`"
                >—</span>
                <span
                  v-if="cellDrift(row, column.machineId).length"
                  class="mt-0.5 block font-mono text-[9px] uppercase tracking-wide"
                  :class="cellDrift(row, column.machineId).some(d => d.state === 'missing' || d.state === 'changed' || d.state === 'extra') ? 'text-fc-warn' : 'text-fc-faint'"
                  :title="driftTitle(cellDrift(row, column.machineId))"
                  :data-testid="`cell-drift-${row.skillId}-${column.machineId}`"
                >{{ [...new Set(cellDrift(row, column.machineId).map(d => d.state))].join(' · ') }}</span>
              </td>
            </tr>
          </template>
        </tbody>
      </table>
      <p class="mt-2 flex flex-wrap gap-x-4 gap-y-1 font-mono text-[10px] tracking-wide text-fc-faint">
        <span><i class="rounded-sm border border-fc-ok/45 px-1 font-bold not-italic text-fc-ok">CC</i> deployed to that agent</span>
        <span><i class="rounded-sm border border-fc-info/45 px-1 font-bold not-italic text-fc-info">CC</i> deployed, update available</span>
        <span>library · installed, not deployed</span>
        <span>— not installed</span>
        <span>· no usable skills CLI or not probed</span>
        <span
          v-for="a in agents"
          :key="a.id"
        >{{ agentShort(a.id) }} {{ a.name }}</span>
      </p>
      <p class="mt-1 text-[11px] text-fc-faint">
        The "Against Fleet Git" row compares each machine with the active desired revision. A skill that is desired but not installed has no row here; open the machine's Desired tab to see it. Unknown means the machine did not answer, never "in sync".
      </p>
    </div>
  </div>
</template>
