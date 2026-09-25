<script setup lang="ts">
import { computed } from 'vue'
import { useRoute } from 'vue-router'

import MachinePage from './MachinePage.vue'

// Remounts the page when the id changes, so per-machine state never leaks
// from one machine to the next.
const route = useRoute()
const id = computed(() => String(route.params.id))
</script>

<template>
  <MachinePage
    :key="id"
    :machine-id="id"
  />
</template>
