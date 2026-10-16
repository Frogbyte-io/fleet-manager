<script setup lang="ts">
// A small status label. Colour is never the only signal: the text says it too.
defineProps<{ tone: 'err' | 'warn' | 'info' | 'ok' | 'muted' }>()

const CLASSES = {
  err: 'border-fc-err/50 text-fc-err',
  warn: 'border-fc-warn/50 text-fc-warn',
  info: 'border-fc-info/50 text-fc-info',
  ok: 'border-fc-ok/50 text-fc-ok',
  muted: 'border-fc-line2 text-fc-muted',
} as const
</script>

<template>
  <span
    class="inline-block rounded-sm border px-1.5 py-px font-mono text-[10px] uppercase tracking-wider"
    :class="CLASSES[tone]"
  ><slot /></span>
</template>
