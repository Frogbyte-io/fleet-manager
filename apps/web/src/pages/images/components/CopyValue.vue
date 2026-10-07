<script setup lang="ts">
import { ref } from 'vue'

// A long identifier (digest, build id) shown truncated, with the full value
// in the tooltip and a copy button.
const props = defineProps<{
  value: string
  display: string
  label: string
}>()

const copied = ref(false)

async function copy() {
  try {
    await navigator.clipboard.writeText(props.value)
    copied.value = true
    setTimeout(() => (copied.value = false), 1500)
  }
  catch {
    // Clipboard unavailable (insecure context); the full value stays in the tooltip.
  }
}
</script>

<template>
  <span class="inline-flex min-w-0 max-w-full items-center gap-2">
    <span
      class="truncate"
      :title="value"
    >{{ display }}</span>
    <button
      type="button"
      class="shrink-0 font-mono text-[10px] uppercase tracking-wider text-fc-info hover:text-fc-ink"
      :aria-label="`Copy ${label}`"
      data-testid="copy-value"
      @click="copy"
    >
      {{ copied ? 'Copied' : 'Copy' }}
    </button>
  </span>
</template>
