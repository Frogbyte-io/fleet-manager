<script setup lang="ts">
import SystemPanel from '@/components/SystemPanel.vue'
</script>

<template>
  <p class="fc-kicker">
    controller configuration
  </p>
  <h1 class="fc-h1 mt-1">
    Settings
  </h1>
  <h2 class="mt-6 text-sm font-semibold uppercase tracking-wide text-fc-muted">
    Diagnostics
  </h2>
  <div class="mt-3">
    <SystemPanel />
  </div>
</template>
