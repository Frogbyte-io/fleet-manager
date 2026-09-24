<script setup lang="ts">
import { useQuery } from '@tanstack/vue-query'
import { computed, ref } from 'vue'

import { cancelOperation, getOperation, type OperationDto } from '@frogbyte-io/fleet-api-client'
import StatusChip from '@/components/fleet/StatusChip.vue'

import { errorMessage, isTerminal, unwrap } from '../api'

// Follows one durable operation until it reaches a terminal state.
const props = defineProps<{ operationId: string, label?: string }>()

const query = useQuery({
  queryKey: computed(() => ['operation', props.operationId]),
  queryFn: async () => unwrap<OperationDto>(await getOperation(props.operationId)),
  refetchInterval: q => (q.state.data && isTerminal(q.state.data.state) ? false : 1000),
})

const operation = computed(() => query.data.value ?? null)
const cancelError = ref('')

const tone = computed(() => {
  switch (operation.value?.state) {
    case 'succeeded': return 'ok' as const
    case 'failed': return 'err' as const
    case 'running': return 'info' as const
    case 'cancelled': return 'muted' as const
    default: return 'faint' as const
  }
})

async function cancel() {
  cancelError.value = ''
  try {
    unwrap(await cancelOperation(props.operationId))
    await query.refetch()
  }
  catch (error) {
    cancelError.value = errorMessage(error)
  }
}
</script>

<template>
  <div
    class="rounded-sm border border-fc-line bg-fc-panel p-2 text-xs"
    data-testid="operation-status"
  >
    <div class="flex flex-wrap items-center gap-2">
      <StatusChip
        :label="operation?.state ?? 'loading'"
        :tone="tone"
      />
      <span class="font-mono text-fc-ink">{{ label ?? operation?.kind ?? '' }}</span>
      <span class="font-mono text-[10px] text-fc-faint">{{ operationId }}</span>
      <button
        v-if="operation && !isTerminal(operation.state)"
        type="button"
        class="ml-auto font-mono text-[10px] uppercase tracking-wider text-fc-err hover:text-fc-ink disabled:opacity-50"
        :disabled="operation.cancelRequested"
        @click="cancel"
      >
        {{ operation.cancelRequested ? 'Cancel requested' : 'Cancel' }}
      </button>
    </div>
    <p
      v-if="operation?.progressMessage"
      class="mt-1 font-mono text-fc-muted"
    >
      {{ operation.progressMessage }}
    </p>
    <p
      v-if="query.error.value"
      class="mt-1 text-fc-err"
    >
      {{ errorMessage(query.error.value) }}
    </p>
    <p
      v-if="cancelError"
      class="mt-1 text-fc-err"
    >
      {{ cancelError }}
    </p>
    <pre
      v-if="operation?.errorJson"
      class="mt-1 max-h-40 overflow-auto whitespace-pre-wrap break-all font-mono text-[11px] text-fc-err"
    >{{ operation.errorJson }}</pre>
    <pre
      v-else-if="operation?.resultJson"
      class="mt-1 max-h-40 overflow-auto whitespace-pre-wrap break-all font-mono text-[11px] text-fc-muted"
    >{{ operation.resultJson }}</pre>
  </div>
</template>
