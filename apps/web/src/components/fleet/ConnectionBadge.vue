<script setup lang="ts">
defineProps<{
  label: string
  dot: 'ok' | 'warn' | 'err' | 'faint'
}>()

const dotClass = {
  ok: 'bg-fc-ok',
  warn: 'bg-fc-warn',
  err: 'bg-fc-err',
  faint: 'bg-fc-faint',
}
</script>

<template>
  <span class="inline-flex items-center gap-1.5 rounded-full border border-fc-line bg-fc-inset px-2 py-0.5 font-mono text-[10px] uppercase tracking-wider text-fc-muted">
    <span
      class="size-[5px] rounded-full"
      :class="dotClass[dot]"
    />
    {{ label }}
  </span>
</template>
