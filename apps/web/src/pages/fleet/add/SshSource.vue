<script setup lang="ts">
import { computed, ref } from 'vue'

import { createOnboardingDraft, type OnboardingDraftDto } from '@frogbyte-io/fleet-api-client'

import { errorMessage, unwrap } from '../../machine/api'
import CopyFleetctl from '../../machine/components/CopyFleetctl.vue'
import { onboardCreateCommand, type SshAuth } from '../../machine/fleetctl'
import { validPort } from './queries'

// A machine reached over SSH by address or name: any Linux host, laptop, or
// Raspberry Pi. Creates the onboarding draft the rest of the flow works on.
const props = withDefaults(defineProps<{
  initialHost?: string
  initialName?: string
  description?: string
}>(), { initialHost: '', initialName: '', description: '' })
const emit = defineEmits<{ created: [draftId: string] }>()

const host = ref(props.initialHost)
const user = ref('')
const port = ref(22)
const name = ref(props.initialName)
const tags = ref('')
const authType = ref<SshAuth['type']>('agent')
const identityPath = ref('')

const auth = computed<SshAuth>(() => authType.value === 'agent' ? { type: 'agent' } : { type: 'identityFile', path: identityPath.value })
const tagList = computed(() => tags.value.split(',').map(t => t.trim()).filter(Boolean))
// A leading `-` would reach `ssh` as an option instead of a destination.
const optionLike = computed(() => host.value.trim().startsWith('-') || user.value.trim().startsWith('-'))
const valid = computed(() =>
  host.value.trim() !== '' && user.value.trim() !== '' && !optionLike.value && validPort(port.value)
  && (authType.value === 'agent' || identityPath.value.trim() !== ''),
)
const command = computed(() => valid.value
  ? onboardCreateCommand({ user: user.value.trim(), host: host.value.trim(), port: port.value, name: name.value.trim(), description: props.description, tags: tagList.value, auth: auth.value })
  : null)

const busy = ref(false)
const error = ref('')

async function create() {
  busy.value = true
  error.value = ''
  try {
    const draft = unwrap<OnboardingDraftDto>(await createOnboardingDraft({
      user: user.value.trim(),
      host: host.value.trim(),
      port: port.value,
      auth: auth.value,
      name: name.value.trim() || undefined,
      description: props.description,
      tags: tagList.value,
      groups: [],
    }), [201])
    emit('created', draft.id)
  }
  catch (e) {
    error.value = errorMessage(e)
  }
  finally {
    busy.value = false
  }
}
</script>

<template>
  <div class="space-y-3">
    <div class="grid grid-cols-[1fr_110px] gap-3 text-xs">
      <label class="flex flex-col gap-1">
        <span class="fc-kicker">Host or address</span>
        <input
          v-model="host"
          placeholder="pi-4.lan or 192.168.1.40"
          class="h-8 rounded-sm border border-input bg-background px-2 font-mono text-foreground"
          data-testid="ssh-host"
        >
      </label>
      <label class="flex flex-col gap-1">
        <span class="fc-kicker">Port</span>
        <input
          v-model.number="port"
          type="number"
          class="h-8 rounded-sm border border-input bg-background px-2 font-mono text-foreground"
        >
      </label>
      <label class="flex flex-col gap-1">
        <span class="fc-kicker">SSH user</span>
        <input
          v-model="user"
          placeholder="pi"
          class="h-8 rounded-sm border border-input bg-background px-2 font-mono text-foreground"
          data-testid="ssh-user"
        >
      </label>
      <label class="flex flex-col gap-1">
        <span class="fc-kicker">Auth</span>
        <select
          v-model="authType"
          class="h-8 rounded-sm border border-input bg-background px-2 text-foreground"
        >
          <option value="agent">SSH agent</option>
          <option value="identityFile">Identity file</option>
        </select>
      </label>
      <label
        v-if="authType === 'identityFile'"
        class="col-span-2 flex flex-col gap-1"
      >
        <span class="fc-kicker">Identity path (controller host)</span>
        <input
          v-model="identityPath"
          placeholder="~/.ssh/id_ed25519"
          class="h-8 rounded-sm border border-input bg-background px-2 font-mono text-foreground"
        >
      </label>
      <label class="flex flex-col gap-1">
        <span class="fc-kicker">Name (optional)</span>
        <input
          v-model="name"
          placeholder="derived from the host"
          class="h-8 rounded-sm border border-input bg-background px-2 font-mono text-foreground"
          data-testid="ssh-name"
        >
      </label>
      <label class="flex flex-col gap-1">
        <span class="fc-kicker">Tags</span>
        <input
          v-model="tags"
          placeholder="homelab, arm"
          class="h-8 rounded-sm border border-input bg-background px-2 font-mono text-foreground"
        >
      </label>
    </div>
    <p
      v-if="optionLike"
      class="text-xs text-fc-err"
      data-testid="ssh-option-like"
    >
      Host and user cannot start with "-".
    </p>
    <p
      v-if="error"
      class="text-xs text-fc-err"
    >
      {{ error }}
    </p>
    <button
      type="button"
      class="fc-grad-bg h-9 rounded-sm px-4 text-sm font-medium disabled:opacity-50"
      :disabled="!valid || busy"
      data-testid="create-draft"
      @click="create"
    >
      Create draft →
    </button>
    <CopyFleetctl
      :command="command"
      missing="Fill in host, user, and auth to see the command."
    />
  </div>
</template>
