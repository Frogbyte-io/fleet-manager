<script setup lang="ts">
import OperationsPanel from '@/components/OperationsPanel.vue'
import SystemPanel from '@/components/SystemPanel.vue'
</script>

<template>
  <p class="fc-kicker">
    controller
  </p>
  <h1 class="fc-h1 mt-1">
    Overview
  </h1>
  <div class="mt-6 space-y-6">
    <SystemPanel />
    <OperationsPanel />
  </div>
</template>
