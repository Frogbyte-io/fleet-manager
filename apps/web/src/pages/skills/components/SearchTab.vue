<script setup lang="ts">
import { computed, ref } from 'vue'

// skills.sh search. Skills Manager's `skills search --json` exists upstream,
// but Fleet has no executor or API for it yet, so the console cannot run a
// search; it says so and offers the two paths that do work today.
const emit = defineEmits<{ reference: [] }>()

const query = ref('')
const url = computed(() => `https://skills.sh/search?q=${encodeURIComponent(query.value.trim())}`)
</script>

<template>
  <div class="mt-4 max-w-2xl space-y-3 text-sm">
    <div
      class="border-l-2 border-l-fc-warn bg-card px-3 py-2 text-xs text-fc-muted"
      data-testid="search-gap"
    >
      The controller has no skills search endpoint yet (Skills Manager's <span class="font-mono">skills search --json</span> is not wired into a Fleet operation), so search results cannot be shown here.
    </div>
    <p class="text-xs text-fc-muted">
      Browse skills.sh, then either add the skill to Fleet's catalog as a pinned reference, or install it on one machine from its Skills tab (Install → source reference).
    </p>
    <div class="flex flex-wrap items-end gap-2 text-xs">
      <label class="flex flex-col gap-1">
        <span class="fc-kicker">Search skills.sh</span>
        <input
          v-model="query"
          placeholder="react best practices"
          class="h-8 w-64 rounded-sm border border-input bg-background px-2 text-foreground"
        >
      </label>
      <a
        :href="url"
        target="_blank"
        rel="noopener noreferrer"
        class="flex h-8 items-center rounded-sm border border-input px-3 font-head font-bold hover:border-fc-muted"
      >
        Open skills.sh ↗
      </a>
      <button
        type="button"
        class="h-8 rounded-sm border border-fc-info/40 px-3 text-fc-info hover:bg-fc-info/10"
        @click="emit('reference')"
      >
        Add a reference to the catalog…
      </button>
    </div>
  </div>
</template>
