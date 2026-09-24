<script setup lang="ts">
import { RouterLink } from 'vue-router'

import OperationStatus from '../components/OperationStatus.vue'
import { useMachineOperations } from '../operations'

// The operations API cannot filter by machine, so this lists the operations
// started from this page in this browser tab.
const { operations } = useMachineOperations()
</script>

<template>
  <div class="space-y-3">
    <p class="text-xs text-fc-muted">
      Operations started from this page in this browser tab. The operations API cannot filter by machine yet; the
      <RouterLink
        to="/operations"
        class="text-fc-info underline decoration-dotted"
      >
        Operations page
      </RouterLink>
      lists every operation.
    </p>
    <p
      v-if="operations.length === 0"
      class="text-sm text-fc-faint"
      data-testid="no-operations"
    >
      No operations started from this page yet.
    </p>
    <OperationStatus
      v-for="operation in operations"
      :key="operation.id"
      :operation-id="operation.id"
      :label="operation.label"
    />
  </div>
</template>
