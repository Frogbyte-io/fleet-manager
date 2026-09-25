<script setup lang="ts">
import { computed, ref } from 'vue'

import type { MachineDto } from '@frogbyte-io/fleet-api-client'
import StatusChip from '@/components/fleet/StatusChip.vue'

import { relativeTime } from '../../fleet/inventory'
import { absoluteTime, factStatusTone, groupFacts, statusCounts } from '../facts'

// Facts with their provenance (source, observed time) and the read-time
// staleness status. `stale` (was known, not re-observed) and `unknown`
// (never answered) are different states and are shown as such.
const props = defineProps<{ machine: MachineDto }>()

const filter = ref<'all' | 'known' | 'stale' | 'unknown' | 'unavailable'>('all')
const counts = computed(() => statusCounts(props.machine.capabilities))
const groups = computed(() =>
  groupFacts(props.machine.capabilities.filter(f => filter.value === 'all' || f.status === filter.value)),
)
</script>

<template>
  <div>
    <div class="flex flex-wrap items-center justify-between gap-3">
      <p class="text-xs text-fc-muted">
        <template v-if="machine.lastObservation">
          Newest observation: <span class="font-mono text-fc-ink">{{ machine.lastObservation.source }}</span>
          at <span class="font-mono text-fc-ink">{{ absoluteTime(machine.lastObservation.collectedAt) }}</span>
        </template>
        <template v-else>
          This machine was never probed.
        </template>
      </p>
      <div
        class="flex gap-1"
        role="group"
        aria-label="Filter facts by status"
      >
        <button
          v-for="option in (['all', 'known', 'stale', 'unknown', 'unavailable'] as const)"
          :key="option"
          type="button"
          class="rounded-sm border px-2 py-0.5 font-mono text-[10px] uppercase tracking-wider"
          :class="filter === option ? 'border-fc-ink text-fc-ink' : 'border-fc-line text-fc-faint hover:text-fc-ink'"
          :aria-pressed="filter === option"
          @click="filter = option"
        >
          {{ option }} {{ option === 'all' ? machine.capabilities.length : (counts[option] ?? 0) }}
        </button>
      </div>
    </div>

    <p
      v-if="groups.length === 0"
      class="mt-6 text-sm text-fc-faint"
    >
      No facts {{ filter === 'all' ? 'recorded' : `with status ${filter}` }}.
    </p>

    <section
      v-for="group in groups"
      :key="group.namespace"
      class="mt-6"
    >
      <h2 class="fc-kicker border-b-2 border-fc-ink pb-1">
        {{ group.namespace }}
      </h2>
      <table class="mt-2 w-full text-left text-xs">
        <thead class="font-mono text-[10px] uppercase tracking-wider text-fc-faint">
          <tr>
            <th class="py-1 pr-3 font-normal">
              Fact
            </th>
            <th class="py-1 pr-3 font-normal">
              Value
            </th>
            <th class="py-1 pr-3 font-normal">
              Status
            </th>
            <th class="py-1 pr-3 font-normal">
              Source
            </th>
            <th class="py-1 font-normal">
              Observed
            </th>
          </tr>
        </thead>
        <tbody class="font-mono text-fc-ink">
          <tr
            v-for="fact in group.facts"
            :key="fact.name"
            class="border-t border-fc-line"
          >
            <td class="py-1.5 pr-3">
              {{ fact.name }}
            </td>
            <td class="max-w-md break-all py-1.5 pr-3">
              {{ fact.value ?? '—' }}
            </td>
            <td class="py-1.5 pr-3">
              <StatusChip
                :label="fact.status"
                :tone="factStatusTone(fact.status)"
              />
            </td>
            <td class="py-1.5 pr-3 text-fc-muted">
              {{ fact.source }}
            </td>
            <td
              class="py-1.5 text-fc-muted"
              :title="absoluteTime(fact.observedAt)"
            >
              {{ relativeTime(fact.observedAt) }}
            </td>
          </tr>
        </tbody>
      </table>
    </section>
  </div>
</template>
