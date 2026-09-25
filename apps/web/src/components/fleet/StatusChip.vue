<script setup lang="ts">
import { computed } from 'vue'

const props = defineProps<{
  label: string
  tone: 'ok' | 'info' | 'warn' | 'err' | 'muted' | 'faint'
}>()

const toneClass = computed(() => ({
  ok: 'border-fc-ok/40 text-fc-ok',
  info: 'border-fc-info/40 text-fc-info',
  warn: 'border-fc-warn/40 text-fc-warn',
  err: 'border-fc-err/40 text-fc-err',
  muted: 'border-fc-line2 text-fc-muted',
  faint: 'border-fc-line2 text-fc-faint',
}[props.tone]))

const dotClass = computed(() => 'bg-fc-ok')
</script>

<template>
  <span
    class="inline-flex items-center gap-1.5 rounded-sm border px-1.5 py-px font-mono text-[9.5px] uppercase tracking-wider"
    :class="toneClass"
  >
    <span
      v-if="tone === 'ok'"
      class="size-1.5 rounded-full"
      :class="dotClass"
    />
    {{ label }}
  </span>
</template>
