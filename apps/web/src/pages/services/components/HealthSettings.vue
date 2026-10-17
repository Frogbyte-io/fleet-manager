<script setup lang="ts">
import { computed, ref, watch } from 'vue'

import type { ActionRequestDto, ServiceHealthDto } from '@frogbyte-io/fleet-api-client'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'

import { errorMessage } from '../../machine/api'
import { HEALTH_METHODS, HEALTH_SCHEMES, healthForm, healthPatch } from '../settings'
import { useHealthRequest } from '../useServiceSettings'
import FiledRequest from './FiledRequest.vue'

// An application's health check (the HTTP kind). The form starts from what
// Coolify holds; only the fields that differ are sent, so the request names
// exactly what was edited and the approver sees a before/after preview.
const props = defineProps<{ serviceId: string, health: ServiceHealthDto }>()

const request = useHealthRequest()
const form = ref(healthForm(props.health))
const filed = ref<ActionRequestDto | null>(null)
const error = ref('')
const dirty = ref(false)

watch(() => props.health, (next) => {
  if (!dirty.value)
    form.value = healthForm(next)
})

const result = computed(() => healthPatch(form.value, props.health))
const problem = computed(() => ('error' in result.value ? result.value.error : null))

async function submit() {
  const outcome = result.value
  if ('error' in outcome)
    return
  error.value = ''
  try {
    filed.value = await request.mutateAsync({
      serviceId: props.serviceId,
      body: { ...outcome.patch, redeploy: form.value.redeploy, reason: form.value.reason.trim() },
    })
    dirty.value = false
  }
  catch (caught) {
    error.value = errorMessage(caught)
  }
}

const labelClass = 'grid gap-1'
const captionClass = 'font-mono text-[10px] uppercase tracking-wider text-fc-faint'
const selectClass = 'h-8 w-full rounded-sm border border-input bg-fc-inset px-2 text-xs outline-none focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50'
</script>

<template>
  <div
    class="space-y-3"
    data-testid="health-settings"
  >
    <form
      class="grid gap-2"
      data-testid="health-form"
      @submit.prevent="submit"
      @input="dirty = true"
      @change="dirty = true"
    >
      <label class="flex items-center gap-1.5 text-xs text-fc-muted"><input
        v-model="form.enabled"
        type="checkbox"
        data-testid="health-enabled"
      >Health check enabled</label>
      <div class="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
        <label :class="labelClass">
          <span :class="captionClass">Method</span>
          <select
            v-model="form.method"
            :class="selectClass"
            data-testid="health-method"
          >
            <option
              v-for="method in HEALTH_METHODS"
              :key="method"
              :value="method"
            >{{ method }}</option>
          </select>
        </label>
        <label :class="labelClass">
          <span :class="captionClass">Scheme</span>
          <select
            v-model="form.scheme"
            :class="selectClass"
            data-testid="health-scheme"
          >
            <option
              v-for="scheme in HEALTH_SCHEMES"
              :key="scheme"
              :value="scheme"
            >{{ scheme }}</option>
          </select>
        </label>
        <label :class="labelClass">
          <span :class="captionClass">Path</span>
          <Input
            v-model="form.path"
            class="h-8 text-xs"
            spellcheck="false"
            data-testid="health-path"
          />
        </label>
        <label :class="labelClass">
          <span :class="captionClass">Port (blank: the application's)</span>
          <Input
            v-model="form.port"
            class="h-8 text-xs"
            inputmode="numeric"
            data-testid="health-port"
          />
        </label>
        <label :class="labelClass">
          <span :class="captionClass">Host header</span>
          <Input
            v-model="form.host"
            class="h-8 text-xs"
            spellcheck="false"
            data-testid="health-host"
          />
        </label>
        <label :class="labelClass">
          <span :class="captionClass">Healthy status code</span>
          <Input
            v-model="form.returnCode"
            class="h-8 text-xs"
            inputmode="numeric"
            data-testid="health-return-code"
          />
        </label>
        <label :class="labelClass">
          <span :class="captionClass">Response must contain</span>
          <Input
            v-model="form.responseText"
            class="h-8 text-xs"
            data-testid="health-response-text"
          />
        </label>
        <label :class="labelClass">
          <span :class="captionClass">Interval (s)</span>
          <Input
            v-model="form.interval"
            class="h-8 text-xs"
            inputmode="numeric"
            data-testid="health-interval"
          />
        </label>
        <label :class="labelClass">
          <span :class="captionClass">Timeout (s)</span>
          <Input
            v-model="form.timeout"
            class="h-8 text-xs"
            inputmode="numeric"
            data-testid="health-timeout"
          />
        </label>
        <label :class="labelClass">
          <span :class="captionClass">Retries</span>
          <Input
            v-model="form.retries"
            class="h-8 text-xs"
            inputmode="numeric"
            data-testid="health-retries"
          />
        </label>
        <label :class="labelClass">
          <span :class="captionClass">Start period (s)</span>
          <Input
            v-model="form.startPeriod"
            class="h-8 text-xs"
            inputmode="numeric"
            data-testid="health-start-period"
          />
        </label>
      </div>
      <label class="flex items-center gap-1.5 text-xs text-fc-muted"><input
        v-model="form.redeploy"
        type="checkbox"
        data-testid="health-redeploy"
      >Redeploy after the change (part of the same approved request)</label>
      <label :class="labelClass">
        <span :class="captionClass">Reason for the approver (optional)</span>
        <Input
          v-model="form.reason"
          class="h-8 text-xs"
          maxlength="1000"
          data-testid="health-reason"
        />
      </label>
      <p
        v-if="problem && dirty"
        class="text-[11px] text-fc-faint"
        data-testid="health-problem"
      >
        {{ problem }}
      </p>
      <div>
        <Button
          type="submit"
          size="sm"
          :disabled="Boolean(problem) || request.isPending.value"
          data-testid="health-submit"
        >
          File request
        </Button>
        <span class="ml-2 text-[11px] text-fc-faint">Sends only the fields you changed; needs approval.</span>
      </div>
    </form>
    <p
      v-if="error"
      class="border-l-2 border-l-fc-err bg-card px-3 py-2 text-xs text-fc-muted"
      role="alert"
      data-testid="health-error"
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
