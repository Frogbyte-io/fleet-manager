<script setup lang="ts">
import { computed, ref } from 'vue'

import type { ActionRequestDto, RunningServiceDto } from '@frogbyte-io/fleet-api-client'
import { Button } from '@/components/ui/button'

import { errorMessage } from '../../machine/api'
import { lifecycleVerbs, type Verb } from '../settings'
import { useLifecycleRequest } from '../useServiceSettings'
import FiledRequest from './FiledRequest.vue'

// Start, stop, restart, and redeploy (FM-1033) as brokered requests. The
// controller's policy decides what runs at once and what waits for a person;
// stop asks here first because it takes the service down. The button only
// files a request: authorization, approval, and audit are the controller's.
const props = defineProps<{ service: RunningServiceDto }>()

const verbs = computed(() => lifecycleVerbs(props.service.kind, props.service.coolify != null))
const mutation = useLifecycleRequest()
const confirming = ref<Verb | null>(null)
const filed = ref<ActionRequestDto | null>(null)
const error = ref('')

async function file(verb: Verb) {
  error.value = ''
  confirming.value = null
  try {
    filed.value = await mutation.mutateAsync({ serviceId: props.service.id, verb, reason: `${verb} ${props.service.name} from the console` })
  }
  catch (caught) {
    filed.value = null
    error.value = errorMessage(caught)
  }
}

function press(verb: Verb, confirm: boolean) {
  if (confirm)
    confirming.value = verb
  else
    void file(verb)
}
</script>

<template>
  <div
    v-if="verbs.length > 0"
    class="flex flex-wrap items-center gap-2"
    data-testid="service-actions"
    :data-service-id="service.id"
  >
    <template v-if="confirming">
      <span
        class="text-xs text-fc-warn"
        role="alert"
        data-testid="confirm-text"
      >
        Stop {{ service.name }}? It goes down until it is started again. Policy decides whether the request runs at once or waits for a person; the request shows which.
      </span>
      <Button
        size="sm"
        variant="destructive"
        :disabled="mutation.isPending.value"
        data-testid="confirm-stop"
        @click="file(confirming)"
      >
        File stop request
      </Button>
      <Button
        size="sm"
        variant="outline"
        data-testid="cancel-stop"
        @click="confirming = null"
      >
        Cancel
      </Button>
    </template>
    <template v-else>
      <Button
        v-for="item in verbs"
        :key="item.verb"
        size="sm"
        variant="outline"
        class="font-mono text-[10px] uppercase tracking-wider"
        :disabled="mutation.isPending.value"
        :data-testid="`action-${item.verb}`"
        @click="press(item.verb, item.confirm)"
      >
        {{ item.label }}
      </Button>
    </template>
    <p
      v-if="error"
      class="basis-full border-l-2 border-l-fc-err bg-card px-3 py-2 text-xs text-fc-muted"
      role="alert"
      data-testid="action-error"
    >
      Could not file the request: {{ error }}
    </p>
    <div
      v-if="filed"
      class="basis-full"
    >
      <FiledRequest
        kind="lifecycle"
        :request="filed"
        @dismiss="filed = null"
      />
    </div>
  </div>
</template>
