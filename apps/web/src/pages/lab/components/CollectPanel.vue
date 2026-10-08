<script setup lang="ts">
import { useQueryClient } from '@tanstack/vue-query'
import { computed, ref } from 'vue'

import { collectLabArtifacts, type OperationDto } from '@frogbyte-io/fleet-api-client'

import { errorMessage, unwrap } from '../../machine/api'
import CopyFleetctl from '../../machine/components/CopyFleetctl.vue'
import OperationStatus from '../../machine/components/OperationStatus.vue'
import { collectCommand, parsePaths } from '../lab'
import { ARTIFACTS_KEY, LEASES_KEY } from '../useLab'

// Copy files off a ready lease's guest as artifacts (`lab.collect`). The
// controller validates the paths and the size cap; the console only splits
// the textarea into lines.
const props = defineProps<{ leaseId: string, ready: boolean }>()

const queryClient = useQueryClient()
const text = ref('')
const busy = ref(false)
const error = ref('')
const operationId = ref<string | null>(null)

const paths = computed(() => parsePaths(text.value))
const command = computed(() => (paths.value.length ? collectCommand(props.leaseId, paths.value) : null))

async function refresh() {
  await Promise.all([
    queryClient.invalidateQueries({ queryKey: ARTIFACTS_KEY }),
    // A failed collection is recorded on the lease detail.
    queryClient.invalidateQueries({ queryKey: LEASES_KEY }),
  ])
}

async function collect() {
  if (!paths.value.length)
    return
  busy.value = true
  error.value = ''
  try {
    const operation = unwrap<OperationDto>(await collectLabArtifacts(props.leaseId, { paths: paths.value }), [202])
    operationId.value = operation.id
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
  <form
    class="grid gap-2 text-xs"
    data-testid="collect-form"
    @submit.prevent="collect"
  >
    <label
      class="fc-kicker"
      :for="`collect-${leaseId}`"
    >Collect files</label>
    <textarea
      :id="`collect-${leaseId}`"
      v-model="text"
      :disabled="!ready"
      rows="3"
      spellcheck="false"
      placeholder="/var/log/cloud-init.log"
      class="rounded-sm border border-input bg-fc-inset p-2 font-mono text-[11.5px] disabled:opacity-50"
    />
    <p class="text-fc-faint">
      Absolute guest paths of regular files, one per line (up to 16). Each must fit the controller's artifact size cap.
    </p>
    <p
      v-if="!ready"
      class="text-fc-warn"
    >
      Files can be collected only from a ready lease.
    </p>
    <CopyFleetctl
      :command="command"
      missing="Enter at least one path to see the equivalent."
    />
    <button
      type="submit"
      class="h-8 w-fit rounded-sm border border-input px-3 font-semibold hover:border-fc-muted disabled:opacity-50"
      :disabled="!ready || busy || paths.length === 0"
      data-testid="collect"
    >
      Collect {{ paths.length || '' }} {{ paths.length === 1 ? 'file' : 'files' }}
    </button>
    <p
      v-if="error"
      class="text-fc-err"
      role="alert"
    >
      {{ error }}
    </p>
    <OperationStatus
      v-if="operationId"
      :operation-id="operationId"
      label="Collect"
      dismissible
      @settled="refresh"
      @dismiss="operationId = null"
    />
  </form>
</template>
