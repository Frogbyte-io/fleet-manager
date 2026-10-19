<script setup lang="ts">
import { useQueryClient } from '@tanstack/vue-query'
import { ref } from 'vue'

import { retryLabLeaseCleanup, type OperationDto } from '@frogbyte-io/fleet-api-client'

import { errorMessage, unwrap } from '../../machine/api'
import CopyFleetctl from '../../machine/components/CopyFleetctl.vue'
import OperationStatus from '../../machine/components/OperationStatus.vue'
import { cleanupRetryCommand } from '../lab'
import { LEASES_KEY, PROVISIONS_KEY } from '../useLab'

// Re-arms a `cleanup_failed` lease's cleanup (FM-713, #292). The lease goes
// back to `releasing` with a fresh round of attempts; the controller decides
// everything else, including that a guest removed by hand counts as gone.
// The parent keeps this mounted while the lease is `releasing` too, so the
// retry's operation stays visible after the lease leaves `cleanup_failed`;
// `available` says whether a retry can be requested now.
const props = defineProps<{ leaseId: string, available: boolean }>()

const queryClient = useQueryClient()
const open = ref(false)
const busy = ref(false)
const error = ref('')
const operationId = ref<string | null>(null)

async function refresh() {
  await Promise.all([
    queryClient.invalidateQueries({ queryKey: LEASES_KEY }),
    queryClient.invalidateQueries({ queryKey: PROVISIONS_KEY }),
  ])
}

async function retry() {
  busy.value = true
  error.value = ''
  try {
    const operation = unwrap<OperationDto>(await retryLabLeaseCleanup(props.leaseId), [202])
    operationId.value = operation.id
    open.value = false
    await refresh()
  }
  catch (caught) {
    error.value = errorMessage(caught)
  }
  finally {
    busy.value = false
  }
}
</script>

<template>
  <div
    v-if="available || operationId || error"
    class="grid gap-2"
  >
    <button
      v-if="available && !open"
      type="button"
      class="h-7 w-fit rounded-sm border border-input px-2.5 text-xs hover:border-fc-muted"
      :aria-expanded="open"
      data-testid="retry-cleanup"
      @click="open = true; error = ''"
    >
      Retry cleanup…
    </button>
    <div
      v-else-if="available"
      class="grid gap-2 rounded-sm border border-fc-line bg-fc-inset p-3 text-xs"
    >
      <p>
        Fix what made cleanup fail first. Retrying puts the lease back in <span class="font-mono">releasing</span> and queues
        a new round of cleanup attempts. A guest already removed by hand counts as destroyed.
      </p>
      <CopyFleetctl :command="cleanupRetryCommand(leaseId)" />
      <div class="flex gap-2">
        <button
          type="button"
          class="fc-grad-bg h-8 rounded-sm px-3 font-semibold disabled:opacity-50"
          :disabled="busy"
          data-testid="confirm-retry-cleanup"
          @click="retry"
        >
          Retry cleanup →
        </button>
        <button
          type="button"
          class="h-8 px-2 text-fc-muted hover:text-fc-ink"
          @click="open = false"
        >
          Cancel
        </button>
      </div>
    </div>
    <p
      v-if="error"
      class="text-xs text-fc-err"
      role="alert"
    >
      {{ error }}
    </p>
    <OperationStatus
      v-if="operationId"
      :operation-id="operationId"
      label="Cleanup"
      dismissible
      @settled="refresh"
      @dismiss="operationId = null"
    />
  </div>
</template>
