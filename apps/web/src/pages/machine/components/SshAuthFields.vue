<script setup lang="ts">
import { computed, watch } from 'vue'

import type { EndpointDto } from '@frogbyte-io/fleet-api-client'

import type { SshAuth } from '../fleetctl'

// The SSH endpoint and credential an operation acts through. Only a path to
// an identity file on the controller host is collected — never key material.
const props = defineProps<{ endpoints: EndpointDto[] }>()
const endpointId = defineModel<string>('endpointId', { required: true })
const auth = defineModel<SshAuth>('auth', { required: true })

const sshEndpoints = computed(() => props.endpoints.filter(e => e.kind === 'ssh'))

watch(sshEndpoints, (list) => {
  if (!list.some(e => e.id === endpointId.value))
    endpointId.value = list[0]?.id ?? ''
}, { immediate: true })

const authType = computed({
  get: () => auth.value.type,
  set: (type: SshAuth['type']) => {
    auth.value = type === 'agent' ? { type } : { type, path: '' }
  },
})

const identityPath = computed({
  get: () => (auth.value.type === 'identityFile' ? auth.value.path : ''),
  set: (path: string) => {
    auth.value = { type: 'identityFile', path }
  },
})
</script>

<template>
  <p
    v-if="sshEndpoints.length === 0"
    class="text-xs text-fc-warn"
    data-testid="no-ssh-endpoint"
  >
    This machine has no SSH endpoint, so SSH-driven operations cannot run.
  </p>
  <div
    v-else
    class="flex flex-wrap items-end gap-3 text-xs"
  >
    <label class="flex flex-col gap-1">
      <span class="fc-kicker">Endpoint</span>
      <select
        v-model="endpointId"
        class="h-8 rounded-sm border border-input bg-background px-2 font-mono text-foreground"
      >
        <option
          v-for="endpoint in sshEndpoints"
          :key="endpoint.id"
          :value="endpoint.id"
        >
          {{ endpoint.reference }}
        </option>
      </select>
    </label>
    <label class="flex flex-col gap-1">
      <span class="fc-kicker">Auth</span>
      <select
        v-model="authType"
        class="h-8 rounded-sm border border-input bg-background px-2 text-foreground"
        data-testid="auth-type"
      >
        <option value="agent">
          SSH agent
        </option>
        <option value="identityFile">
          Identity file
        </option>
      </select>
    </label>
    <label
      v-if="authType === 'identityFile'"
      class="flex flex-col gap-1"
    >
      <span class="fc-kicker">Identity path (controller host)</span>
      <input
        v-model="identityPath"
        placeholder="~/.ssh/id_ed25519"
        class="h-8 w-64 rounded-sm border border-input bg-background px-2 font-mono text-foreground"
        data-testid="identity-path"
      >
    </label>
  </div>
</template>
