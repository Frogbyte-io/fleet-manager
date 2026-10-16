<script setup lang="ts">
import { useMutation, useQuery, useQueryClient } from '@tanstack/vue-query'
import { computed, ref } from 'vue'

import {
  getRegistrySettings,
  updateRegistrySettings,
  type RegistrySettingsDto,
  type UpdateRegistrySettingsRequest,
} from '@frogbyte-io/fleet-api-client'

import { errorMessage, retryTransient, unwrap } from '../../machine/api'
import CopyFleetctl from '../../machine/components/CopyFleetctl.vue'

// Registry settings (FM-1014): whether a Registry-only revision activates
// without a manual step, and how Registry edits are meant to reach the
// default branch. Self-contained: it owns its query, its mutation, and its
// copy, so the section around it needs no knowledge of either.
const REGISTRY_SETTINGS_KEY = ['desired', 'settings'] as const

const queryClient = useQueryClient()
const settings = useQuery({
  queryKey: REGISTRY_SETTINGS_KEY,
  queryFn: async () => unwrap<RegistrySettingsDto>(await getRegistrySettings()),
  retry: retryTransient,
})

const saveError = ref('')
const lastCommand = ref<string | null>(null)

const save = useMutation({
  mutationFn: async (change: UpdateRegistrySettingsRequest) =>
    unwrap<RegistrySettingsDto>(await updateRegistrySettings(change)),
  onSuccess: (updated) => {
    queryClient.setQueryData(REGISTRY_SETTINGS_KEY, updated)
  },
})

const CHANGE_MODES = [
  { id: 'pull-request', label: 'Pull request', hint: 'Edits are proposed for review.' },
  { id: 'direct', label: 'Direct push', hint: 'Edits are pushed to the default branch.' },
] as const

const current = computed(() => settings.data.value ?? null)

function commandFor(change: UpdateRegistrySettingsRequest): string {
  const words = ['fleetctl', 'desired', 'settings', 'set']
  if (change.autoActivate != null)
    words.push('--auto-activate', String(change.autoActivate))
  if (change.changeMode != null)
    words.push('--change-mode', change.changeMode)
  return words.join(' ')
}

async function apply(change: UpdateRegistrySettingsRequest) {
  saveError.value = ''
  lastCommand.value = commandFor(change)
  try {
    await save.mutateAsync(change)
  }
  catch (error) {
    saveError.value = errorMessage(error)
  }
}
</script>

<template>
  <div
    class="space-y-3"
    data-testid="registry-settings"
  >
    <h3 class="fc-kicker border-b border-fc-line pb-1">
      Registry
    </h3>
    <p class="text-sm text-fc-muted">
      Registry entries describe domains and services in Fleet Git. A fetched, valid revision that changes only Registry resources can go live without a manual activation; any other change still waits for you.
    </p>

    <p
      v-if="settings.isLoading.value"
      class="text-xs text-fc-muted"
    >
      Loading…
    </p>
    <p
      v-else-if="settings.error.value"
      class="text-xs text-fc-err"
      role="alert"
      data-testid="registry-settings-error"
    >
      The Registry settings could not be read: {{ errorMessage(settings.error.value) }}
    </p>
    <template v-else-if="current">
      <label class="flex items-start gap-3 text-sm">
        <input
          type="checkbox"
          class="mt-0.5 size-4 accent-[var(--fc-info)]"
          :checked="current.autoActivate"
          :disabled="save.isPending.value"
          data-testid="registry-auto-activate"
          @change="apply({ autoActivate: ($event.target as HTMLInputElement).checked })"
        >
        <span class="flex flex-col gap-0.5">
          <span class="text-fc-ink">Activate Registry-only revisions automatically</span>
          <span class="text-xs text-fc-muted">
            The controller records each automatic activation in the audit log as itself, with the commit and the number of entries and types added, removed, or changed. The first revision is always activated by hand.
          </span>
        </span>
      </label>

      <fieldset
        class="space-y-2"
        :disabled="save.isPending.value"
      >
        <legend class="fc-kicker mb-1">
          How Registry edits reach the default branch
        </legend>
        <label
          v-for="mode in CHANGE_MODES"
          :key="mode.id"
          class="flex items-start gap-3 text-sm"
        >
          <input
            type="radio"
            name="registry-change-mode"
            class="mt-0.5 size-4 accent-[var(--fc-info)]"
            :value="mode.id"
            :checked="current.changeMode === mode.id"
            :data-testid="`registry-mode-${mode.id}`"
            @change="apply({ changeMode: mode.id })"
          >
          <span class="flex flex-col gap-0.5">
            <span class="text-fc-ink">{{ mode.label }}</span>
            <span class="text-xs text-fc-muted">{{ mode.hint }}</span>
          </span>
        </label>
        <p class="text-[11px] text-fc-faint">
          This is advice for <span class="font-mono">fleetctl</span> and agents. Fleet does not enforce it: branch protection on your Git host does.
        </p>
      </fieldset>

      <p
        v-if="current.autoActivateHold"
        class="rounded-sm border border-fc-warn/40 p-3 text-xs text-fc-warn"
        data-testid="registry-hold"
      >
        Automatic activation is held because of a rollback. It resumes after you activate a revision by hand.
      </p>
      <p
        v-if="saveError"
        class="text-xs text-fc-err"
        role="alert"
        data-testid="registry-settings-save-error"
      >
        {{ saveError }}
      </p>
      <CopyFleetctl
        v-if="lastCommand"
        :command="lastCommand"
      />
    </template>
  </div>
</template>
