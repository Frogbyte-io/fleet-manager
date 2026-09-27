<script setup lang="ts">
import { computed } from 'vue'
import { RouterLink } from 'vue-router'

import StatusChip from '@/components/fleet/StatusChip.vue'

import { parseSkillsData, type MatrixColumn, type SnapshotLike } from '../model'

// Skills Manager presets per machine. Presets are machine-local Skills
// Manager state; creating, editing, and deploying them happens on the
// machine's Skills tab, one audited operation at a time. Fleet-managed
// membership is expressed as assignments in Fleet Git instead.
const props = defineProps<{ snapshots: SnapshotLike[], columns: MatrixColumn[] }>()

const machines = computed(() => {
  const byId = new Map(props.snapshots.map(s => [s.machineId, s]))
  return props.columns
    .filter(c => c.state === 'available')
    .map(c => ({ column: c, presets: parseSkillsData(byId.get(c.machineId)?.data).presets }))
})
</script>

<template>
  <div class="mt-4 space-y-4">
    <p class="text-xs text-fc-muted">
      Presets are Skills Manager groups on each machine. Manage them from a machine's Skills tab; to make Fleet own a skill set, assign catalog skills instead (Catalog → Assign).
    </p>
    <p
      v-if="machines.length === 0"
      class="rounded-sm border border-fc-line p-6 text-sm text-fc-muted"
      data-testid="presets-empty"
    >
      No machine with a usable skills-manager-cli has been probed yet.
    </p>
    <section
      v-for="{ column, presets } in machines"
      :key="column.machineId"
      class="rounded-sm border border-fc-line bg-card p-3"
      :data-testid="`presets-${column.machineId}`"
    >
      <div class="flex items-center gap-2">
        <h3 class="font-head text-[13px] font-bold">
          {{ column.name }}
        </h3>
        <StatusChip
          v-if="column.stale"
          label="stale"
          tone="warn"
        />
        <RouterLink
          :to="{ path: `/fleet/machines/${column.machineId}`, query: { tab: 'skills' } }"
          class="ml-auto font-mono text-[10px] uppercase tracking-wider text-fc-info hover:text-fc-ink"
        >
          Manage →
        </RouterLink>
      </div>
      <p
        v-if="presets.length === 0"
        class="mt-1 text-xs text-fc-faint"
      >
        No presets.
      </p>
      <ul
        v-else
        class="mt-1 flex flex-wrap gap-2 text-xs"
      >
        <li
          v-for="preset in presets"
          :key="preset.id"
          class="rounded-sm border px-2 py-1"
          :class="preset.active ? 'border-fc-ok/45' : 'border-fc-line'"
        >
          <span class="font-mono text-fc-ink">{{ preset.name }}</span>
          <span class="ml-1 font-mono text-[10px] text-fc-faint">{{ preset.skillCount }}</span>
          <span
            v-if="preset.active"
            class="ml-1 font-mono text-[10px] text-fc-ok"
          >active</span>
        </li>
      </ul>
    </section>
  </div>
</template>
