<script setup lang="ts">
import { RouterLink } from 'vue-router'

import MachinesPanel from '@/components/MachinesPanel.vue'
</script>

<template>
  <div class="flex items-end justify-between">
    <div>
      <p class="fc-kicker">
        machines
      </p>
      <h1 class="fc-h1 mt-1">
        <span class="fc-grad-text">Fleet</span>
      </h1>
    </div>
    <RouterLink
      to="/fleet/add"
      class="fc-grad-bg inline-flex h-9 items-center rounded-sm px-4 text-sm font-medium"
    >
      + Add machine
    </RouterLink>
  </div>
  <div class="mt-6">
    <MachinesPanel />
  </div>
</template>
