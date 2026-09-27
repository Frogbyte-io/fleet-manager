<script setup lang="ts">
import { computed } from 'vue'

import { percent, usageTone } from '../proxmox'

// One capacity bar: label, fill by tone, and the used / total detail.
const props = defineProps<{ label: string, value: number | null, detail?: string | null }>()

const fill = computed(() => ({
  ok: 'bg-fc-ok',
  warn: 'bg-fc-warn',
  err: 'bg-fc-err',
  info: 'bg-fc-info',
  muted: 'bg-fc-muted',
  faint: 'bg-fc-faint',
}[usageTone(props.value)]))
</script>

<template>
  <div class="grid grid-cols-[72px_1fr_auto] items-center gap-2 font-mono text-[10.5px] text-fc-faint">
    <span
      class="truncate"
      :title="label"
    >{{ label }}</span>
    <div
      class="h-1.5 overflow-hidden rounded-sm bg-fc-inset"
      role="progressbar"
      :aria-label="label ? `${label} used` : 'capacity used'"
      :aria-valuenow="value === null ? undefined : Math.round(value * 100)"
      aria-valuemin="0"
      aria-valuemax="100"
    >
      <i
        v-if="value !== null"
        class="block h-full"
        :class="fill"
        :style="{ width: `${Math.round(value * 100)}%` }"
      />
    </div>
    <span class="text-fc-ink">{{ percent(value) }}<template v-if="detail"> · {{ detail }}</template></span>
  </div>
</template>
