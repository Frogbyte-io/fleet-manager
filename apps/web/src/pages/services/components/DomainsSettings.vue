<script setup lang="ts">
import { computed, ref, watch } from 'vue'

import type { ActionRequestDto } from '@frogbyte-io/fleet-api-client'
import { Button } from '@/components/ui/button'

import { errorMessage } from '../../machine/api'
import { domainsProblem, domainsText, parseDomains } from '../settings'
import { useDomainsRequest } from '../useServiceSettings'
import FiledRequest from './FiledRequest.vue'

// An application's domains. The form edits the whole list; the request the
// controller files carries a before/after preview, and the change is refused
// as stale if the domains moved before it was approved.
const props = defineProps<{ serviceId: string, domains: string[] }>()

const request = useDomainsRequest()
const text = ref(domainsText(props.domains))
const redeploy = ref(false)
const reason = ref('')
const filed = ref<ActionRequestDto | null>(null)
const error = ref('')

// A fresh read replaces what is shown, unless the person has started editing.
const dirty = ref(false)
watch(() => props.domains, (next) => {
  if (!dirty.value)
    text.value = domainsText(next)
})

const list = computed(() => parseDomains(text.value))
const problem = computed(() => domainsProblem(list.value, props.domains))
const clearing = computed(() => list.value.length === 0 && props.domains.length > 0)

async function submit() {
  if (problem.value)
    return
  error.value = ''
  try {
    filed.value = await request.mutateAsync({
      serviceId: props.serviceId,
      body: { domains: list.value, redeploy: redeploy.value, reason: reason.value.trim() },
    })
    dirty.value = false
  }
  catch (caught) {
    error.value = errorMessage(caught)
  }
}
</script>

<template>
  <div
    class="space-y-3"
    data-testid="domains-settings"
  >
    <form
      class="grid gap-2"
      data-testid="domains-form"
      @submit.prevent="submit"
    >
      <label class="grid gap-1">
        <span class="font-mono text-[10px] uppercase tracking-wider text-fc-faint">Domains, one URL per line</span>
        <textarea
          v-model="text"
          rows="4"
          class="w-full rounded-sm border border-input bg-fc-inset px-3 py-2 font-mono text-[11px] text-fc-ink outline-none focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50"
          spellcheck="false"
          placeholder="https://shop.example.org"
          data-testid="domains-text"
          @input="dirty = true"
        />
      </label>
      <label class="flex items-center gap-1.5 text-xs text-fc-muted"><input
        v-model="redeploy"
        type="checkbox"
        data-testid="domains-redeploy"
      >Redeploy after the change (part of the same approved request)</label>
      <label class="grid gap-1">
        <span class="font-mono text-[10px] uppercase tracking-wider text-fc-faint">Reason for the approver (optional)</span>
        <input
          v-model="reason"
          maxlength="1000"
          class="h-8 w-full rounded-sm border border-input bg-transparent px-3 text-xs outline-none focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50"
          data-testid="domains-reason"
        >
      </label>
      <p
        v-if="clearing && !problem"
        class="text-[11px] text-fc-warn"
        data-testid="domains-clearing"
      >
        An empty list removes every domain.
      </p>
      <p
        v-if="problem && dirty"
        class="text-[11px] text-fc-faint"
        data-testid="domains-problem"
      >
        {{ problem }}
      </p>
      <div>
        <Button
          type="submit"
          size="sm"
          :disabled="Boolean(problem) || request.isPending.value"
          data-testid="domains-submit"
        >
          File request
        </Button>
        <span class="ml-2 text-[11px] text-fc-faint">Shows a before/after preview and needs approval.</span>
      </div>
    </form>
    <p
      v-if="error"
      class="border-l-2 border-l-fc-err bg-card px-3 py-2 text-xs text-fc-muted"
      role="alert"
      data-testid="domains-error"
    >
      Could not file the request: {{ error }}
    </p>
    <FiledRequest
      v-if="filed"
      :request="filed"
      @dismiss="filed = null"
    />
  </div>
</template>
