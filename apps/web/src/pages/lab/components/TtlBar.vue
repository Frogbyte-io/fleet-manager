<script setup lang="ts">
import { computed } from 'vue'

import type { LeaseDto } from '@frogbyte-io/fleet-api-client'

import { formatDuration, leaseTtl } from '../lab'

// TTL bar (DESIGN.md §6): gradient fill for the used share of the ready TTL,
// with the time left and the absolute lifetime cap in mono. TTL starts only
// at ready, so a lease that never reached ready shows nothing here.
const props = defineProps<{ lease: Pick<LeaseDto, 'readyAt' | 'expiresAt' | 'maxLifetimeAt'>, now: number }>()

const ttl = computed(() => leaseTtl(props.lease, props.now))
</script>

<template>
  <div
    v-if="ttl"
    class="grid grid-cols-[auto_1fr_auto] items-center gap-3 font-mono text-[10.5px] text-fc-faint"
    data-testid="ttl-bar"
  >
    <span>TTL</span>
    <div
      class="h-1 overflow-hidden rounded-sm bg-fc-inset"
      role="progressbar"
      :aria-valuenow="Math.round(ttl.usedFraction * 100)"
      aria-valuemin="0"
      aria-valuemax="100"
      aria-label="TTL used"
    >
      <i
        class="fc-grad-bg block h-full"
        :style="{ width: `${Math.round(ttl.usedFraction * 100)}%` }"
      />
    </div>
    <span class="text-fc-ink">
      {{ ttl.remainingSeconds > 0 ? `${formatDuration(ttl.remainingSeconds)} LEFT` : 'EXPIRED' }}
      · MAX LIFETIME {{ formatDuration(ttl.lifetimeRemainingSeconds) }}
    </span>
  </div>
</template>
