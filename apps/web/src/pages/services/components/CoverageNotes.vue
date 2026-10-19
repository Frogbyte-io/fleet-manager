<script setup lang="ts">
import type { CoverageNote } from '../services'

// What the answer was built from, stated plainly. An input that is not
// configured, denied, stale, or cut short is named so a short list is never
// mistaken for a complete one.
defineProps<{ notes: CoverageNote[] }>()
</script>

<template>
  <div
    v-if="notes.length > 0"
    class="mt-4 space-y-1.5"
    data-testid="coverage-notes"
  >
    <div
      v-for="note in notes"
      :key="note.key"
      class="border-l-2 bg-card px-3 py-1.5 text-xs text-fc-muted"
      :class="note.tone === 'warn' ? 'border-l-fc-warn' : 'border-l-fc-info'"
      role="status"
    >
      {{ note.text }}
    </div>
  </div>
</template>
