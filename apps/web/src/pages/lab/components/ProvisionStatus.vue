<script setup lang="ts">
import { ref } from 'vue'

import type { OperationDto } from '@frogbyte-io/fleet-api-client'

import OperationStatus from '../../machine/components/OperationStatus.vue'
import { operationFailure, type OperationFailure } from '../lab'

// Follows a `lab.provision` operation. When it fails (a placement refusal
// such as `placement_no_candidate` or `insufficient_memory`, or a failed
// saga step), the controller's reason and explanation are shown verbatim
// above the raw operation record: the console never rephrases why
// placement was impossible.
defineProps<{ operationId: string, label?: string }>()
const emit = defineEmits<{ settled: [operation: OperationDto], dismiss: [] }>()

const failure = ref<OperationFailure | null>(null)

function onSettled(operation: OperationDto) {
  failure.value = operation.state === 'succeeded' ? null : operationFailure(operation.errorJson)
  emit('settled', operation)
}
</script>

<template>
  <div class="grid gap-2">
    <div
      v-if="failure"
      class="border-l-2 border-l-fc-err bg-card px-3 py-2 text-xs"
      role="alert"
      data-testid="provision-failure"
    >
      <p class="fc-kicker text-fc-err">
        Not provisioned<template v-if="failure.reason">
          · <span data-testid="provision-failure-reason">{{ failure.reason }}</span>
        </template><template v-if="failure.step">
          · step {{ failure.step }}
        </template>
      </p>
      <p
        v-if="failure.detail"
        class="mt-1 whitespace-pre-wrap break-words font-mono text-fc-ink"
        data-testid="provision-failure-detail"
      >
        {{ failure.detail }}
      </p>
    </div>
    <OperationStatus
      :operation-id="operationId"
      :label="label ?? 'Provisioning'"
      dismissible
      @settled="onSettled"
      @dismiss="emit('dismiss')"
    />
  </div>
</template>
