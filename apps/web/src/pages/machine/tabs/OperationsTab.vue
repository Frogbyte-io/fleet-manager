<script setup lang="ts">
import { useQueryClient } from '@tanstack/vue-query'
import { RouterLink } from 'vue-router'

import type { OperationDto } from '@frogbyte-io/fleet-api-client'

import { isTerminal } from '../api'
import OperationStatus from '../components/OperationStatus.vue'
import { useMachineOperations } from '../operations'

// The operations API cannot filter by machine, so this lists the operations
// started from this page in this browser tab.
const { operations, forget } = useMachineOperations()
const queryClient = useQueryClient()

function clearFinished() {
  forget(operations.value
    .filter((o) => {
      const cached = queryClient.getQueryData<OperationDto>(['operation', o.id])
      return cached !== undefined && isTerminal(cached.state)
    })
    .map(o => o.id))
}
</script>

<template>
  <div class="space-y-3">
    <div class="flex flex-wrap items-center gap-3">
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
      <button
        v-if="operations.length > 0"
        type="button"
        class="ml-auto font-mono text-[10px] uppercase tracking-wider text-fc-faint hover:text-fc-ink"
        data-testid="clear-finished"
        @click="clearFinished"
      >
        Clear finished
      </button>
    </div>
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
