<script setup lang="ts">
import { computed } from 'vue'

import type { LeaseDto } from '@frogbyte-io/fleet-api-client'

import { leaseSteps } from '../lab'

// Lifecycle stepper (DESIGN.md §6): done segments muted, the current one
// gradient, a failed one --fc-err. The list carries the state as text for
// assistive technology; the segments are decoration.
const props = defineProps<{ lease: Pick<LeaseDto, 'state' | 'readyAt'> }>()

const steps = computed(() => leaseSteps(props.lease))
</script>

<template>
  <ol
    class="flex gap-[3px]"
    :aria-label="`Lease lifecycle: ${lease.state}`"
  >
    <li
      v-for="step in steps"
      :key="step.label"
      class="min-w-0 flex-1"
      :data-status="step.status"
    >
      <span
        class="block h-[3px] rounded-sm"
        :class="{
          'bg-fc-muted': step.status === 'done',
          'fc-grad-bg': step.status === 'current',
          'bg-fc-err': step.status === 'failed',
          'bg-fc-line2': step.status === 'todo',
        }"
        aria-hidden="true"
      />
      <span
        class="mt-1 block truncate font-mono text-[9px] uppercase tracking-wider"
        :class="{
          'text-fc-ink': step.status === 'current',
          'text-fc-err': step.status === 'failed',
          'text-fc-faint': step.status === 'done' || step.status === 'todo',
        }"
      >{{ step.label.replace('_', ' ') }}</span>
    </li>
  </ol>
</template>
