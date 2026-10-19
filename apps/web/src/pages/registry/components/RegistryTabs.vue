<script setup lang="ts">
import { RouterLink } from 'vue-router'

// The Registry's views: the generic table over any type, and the purpose-built
// Domains and Services overviews. They are sub-routes of /registry.
const tabs = [
  { to: '/registry', label: 'All entries', id: 'all' },
  { to: '/registry/domains', label: 'Domains', id: 'domains' },
  { to: '/registry/services', label: 'Services', id: 'services' },
] as const

defineProps<{ active: (typeof tabs)[number]['id'] }>()
</script>

<template>
  <nav
    class="mt-4 flex flex-wrap gap-1.5"
    aria-label="Registry views"
  >
    <RouterLink
      v-for="tab in tabs"
      :key="tab.id"
      :to="tab.to"
      class="rounded-sm border px-2.5 py-1 text-xs"
      :class="active === tab.id ? 'border-ring text-fc-ink' : 'border-fc-line2 text-fc-muted hover:text-fc-ink'"
      :aria-current="active === tab.id ? 'page' : undefined"
      :data-testid="`view-${tab.id}`"
    >
      {{ tab.label }}
    </RouterLink>
  </nav>
</template>
