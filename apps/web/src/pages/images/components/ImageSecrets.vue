<script setup lang="ts">
import { computed, ref } from 'vue'

import { errorMessage } from '../../machine/api'
import CopyFleetctl from '../../machine/components/CopyFleetctl.vue'
import { useDeleteImageSecret, useImageSecrets, useSetImageSecret } from '../useImages'

// The `images/<name>` secret records image builds may reference
// (`fleetctl images secret set|list|rm`). Values are write-only: the page
// can create, replace, and delete a record, and never shows one.
const secrets = useImageSecrets()
const setter = useSetImageSecret()
const remover = useDeleteImageSecret()

const NAME = /^[\w.-]+$/
const name = ref('')
const value = ref('')
const error = ref('')
const saved = ref('')
const confirming = ref<string | null>(null)

const shortName = computed(() => name.value.trim().replace(/^images\//, ''))
const nameValid = computed(() => NAME.test(shortName.value) && !shortName.value.startsWith('.') && shortName.value.length <= 128)
const valid = computed(() => nameValid.value && value.value.trim() !== '')

async function save() {
  if (!valid.value || setter.isPending.value)
    return
  error.value = ''
  saved.value = ''
  try {
    const written = await setter.save(shortName.value, value.value)
    saved.value = `${written.reference} ${written.replaced ? 'replaced' : 'created'}`
    // The value leaves the page as soon as it is stored.
    value.value = ''
    name.value = ''
  }
  catch (cause) {
    error.value = errorMessage(cause)
  }
}

async function remove(reference: string) {
  error.value = ''
  saved.value = ''
  try {
    await remover.mutateAsync(reference.replace(/^images\//, ''))
    saved.value = `${reference} deleted`
  }
  catch (cause) {
    error.value = errorMessage(cause)
  }
  finally {
    confirming.value = null
  }
}

const inputClass = 'h-8 rounded-sm border border-input bg-background px-2 text-foreground'
const buttonClass = 'h-8 rounded-sm border border-fc-info/40 px-3 text-fc-info hover:bg-fc-info/10 disabled:opacity-50'
</script>

<template>
  <section
    id="image-secrets"
    class="mt-8 space-y-2 border-t-2 border-fc-ink pt-3"
    data-testid="image-secrets"
    tabindex="-1"
  >
    <h2 class="fc-kicker flex items-center gap-1">
      Build secrets <span class="text-fc-faint">images/&lt;name&gt;</span>
    </h2>
    <p class="max-w-prose text-xs text-fc-muted">
      A build's secret variable names one of these records. Values are write-only: they are never shown here, in the API, in logs, or in audit. Saving an existing name replaces its value.
    </p>

    <p
      v-if="secrets.isError.value"
      class="border-l-2 border-l-fc-err bg-card px-3 py-2 text-xs text-fc-muted"
      role="alert"
    >
      Could not load build secrets: {{ errorMessage(secrets.error.value) }}
    </p>
    <p
      v-else-if="!secrets.isLoading.value && (secrets.data.value ?? []).length === 0"
      class="text-xs text-fc-muted"
      data-testid="secrets-empty"
    >
      No build secrets yet.
    </p>
    <ul
      v-if="(secrets.data.value ?? []).length > 0"
      class="divide-y divide-fc-line border border-fc-line text-xs"
      data-testid="secrets-list"
    >
      <li
        v-for="secret in secrets.data.value"
        :key="secret.reference"
        class="flex flex-wrap items-center gap-2 bg-card px-3 py-1.5"
      >
        <span class="break-all font-mono text-foreground">{{ secret.reference }}</span>
        <span class="ml-auto flex items-center gap-2">
          <template v-if="confirming === secret.reference">
            <span class="text-fc-warn">Builds that use it will fail.</span>
            <button
              type="button"
              class="h-7 rounded-sm border border-fc-err/50 px-2 text-fc-err hover:bg-fc-err/10 disabled:opacity-50"
              :disabled="remover.isPending.value"
              :data-testid="`secret-confirm-${secret.reference}`"
              @click="remove(secret.reference)"
            >
              Delete
            </button>
            <button
              type="button"
              class="h-7 rounded-sm border border-input px-2 text-fc-muted hover:text-fc-ink"
              @click="confirming = null"
            >
              Keep
            </button>
          </template>
          <button
            v-else
            type="button"
            class="h-7 rounded-sm border border-input px-2 text-fc-muted hover:text-fc-err"
            :aria-label="`Delete ${secret.reference}`"
            @click="confirming = secret.reference"
          >
            Delete
          </button>
        </span>
      </li>
    </ul>

    <form
      class="grid max-w-2xl gap-2 sm:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_auto] sm:items-end"
      autocomplete="off"
      @submit.prevent="save"
    >
      <label class="flex flex-col gap-1">
        <span class="fc-kicker">Name</span>
        <input
          v-model="name"
          placeholder="images/<name>"
          autocomplete="off"
          :class="[inputClass, 'font-mono']"
          data-testid="secret-name"
        >
      </label>
      <label class="flex flex-col gap-1">
        <span class="fc-kicker">Value (write-only)</span>
        <input
          v-model="value"
          type="password"
          autocomplete="new-password"
          :class="[inputClass, 'font-mono']"
          data-testid="secret-value"
        >
      </label>
      <button
        type="submit"
        :class="buttonClass"
        :disabled="!valid || setter.isPending.value"
        data-testid="secret-save"
      >
        {{ setter.isPending.value ? 'Saving…' : 'Save secret' }}
      </button>
    </form>
    <p
      v-if="name.trim() !== '' && !nameValid"
      class="text-[11px] text-fc-warn"
    >
      Use letters, digits, '.', '_' and '-'.
    </p>
    <p
      v-if="error"
      class="text-xs text-fc-err"
      role="alert"
    >
      {{ error }}
    </p>
    <p
      v-if="saved"
      class="text-xs text-fc-ok"
      role="status"
      data-testid="secret-saved"
    >
      {{ saved }}
    </p>
    <div class="max-w-2xl">
      <CopyFleetctl
        :command="`fleetctl images secret set ${shortName || '<name>'}   # the value is read from stdin`"
      />
    </div>
  </section>
</template>
