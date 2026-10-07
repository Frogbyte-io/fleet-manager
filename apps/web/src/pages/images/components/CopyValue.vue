<script setup lang="ts">
import { ref } from 'vue'

// A long identifier (digest, build id) shown truncated. Activating the value
// expands it in place (selectable, keyboard reachable); the copy button
// announces its result through a polite live region.
const props = defineProps<{
  value: string
  display: string
  label: string
}>()

const copied = ref(false)
const expanded = ref(false)

async function copy() {
  try {
    await navigator.clipboard.writeText(props.value)
    copied.value = true
    setTimeout(() => (copied.value = false), 1500)
  }
  catch {
    // Clipboard unavailable (insecure context): show the full value to select instead.
    expanded.value = true
  }
}
</script>

<template>
  <span class="inline-flex min-w-0 max-w-full items-start gap-2">
    <button
      v-if="display !== value"
      type="button"
      class="min-w-0 text-left hover:text-fc-ink"
      :class="expanded ? 'select-all break-all' : 'truncate'"
      :title="value"
      :aria-expanded="expanded"
      :aria-label="expanded ? `${label}: ${value}` : `${label} ${display}, show the full value`"
      data-testid="value-toggle"
      @click="expanded = !expanded"
    >{{ expanded ? value : display }}</button>
    <span
      v-else
      class="min-w-0 select-all break-all"
    >{{ value }}</span>
    <button
      type="button"
      class="shrink-0 font-mono text-[10px] uppercase tracking-wider text-fc-info hover:text-fc-ink"
      data-testid="copy-value"
      @click="copy"
    >
      {{ copied ? 'Copied' : 'Copy' }}<span class="sr-only"> {{ label }}</span>
    </button>
    <span
      class="sr-only"
      role="status"
      aria-live="polite"
    >{{ copied ? `Copied ${label}` : '' }}</span>
  </span>
</template>
