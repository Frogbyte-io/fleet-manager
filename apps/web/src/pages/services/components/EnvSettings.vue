<script setup lang="ts">
import { computed, ref } from 'vue'

import type { ActionRequestDto, ServiceEnvVarDto } from '@frogbyte-io/fleet-api-client'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'

import { errorMessage } from '../../machine/api'
import {
  blankEnvForm,
  envFlagLabels,
  envFormProblem,
  envSetBody,
  envUnsetBody,
  withCurrentFlags,
} from '../settings'
import { useEnvRequest } from '../useServiceSettings'
import FiledRequest from './FiledRequest.vue'

// Environment variables: names and flags only. Coolify never shows a value to
// this token and Fleet never asks, so there is nothing to prefill: a value is
// typed into a password field, sent once with the request, and cleared. The
// request the approver reads lists names and flags.
const props = defineProps<{
  serviceId: string
  kind: string
  envs: ServiceEnvVarDto[]
}>()

const request = useEnvRequest()
const form = ref(blankEnvForm())
const filed = ref<ActionRequestDto | null>(null)
const error = ref('')
const unsetting = ref<ServiceEnvVarDto | null>(null)
const isApplication = computed(() => props.kind === 'application')
const exists = computed(() => props.envs.some(env => env.key === form.value.key && env.isPreview === form.value.preview))
const problem = computed(() => envFormProblem(form.value))
const redeployLabel = computed(() => (isApplication.value ? 'Redeploy after the change' : 'Restart after the change'))

/** Picking a row names its variable and takes its flags; the value stays empty. */
function edit(env: ServiceEnvVarDto) {
  form.value = withCurrentFlags({ ...blankEnvForm(), key: env.key, preview: env.isPreview }, props.envs)
  error.value = ''
}

/** Typing a name that exists adopts that variable's flags. */
function onKey() {
  form.value = withCurrentFlags(form.value, props.envs)
}

async function submit() {
  if (problem.value)
    return
  error.value = ''
  try {
    filed.value = await request.file(props.serviceId, envSetBody(form.value, props.kind))
    form.value = blankEnvForm()
  }
  catch (caught) {
    error.value = errorMessage(caught)
  }
  finally {
    // The value leaves the page as soon as it is sent, whatever the outcome.
    form.value.value = ''
  }
}

async function unset(env: ServiceEnvVarDto) {
  error.value = ''
  unsetting.value = null
  try {
    filed.value = await request.file(props.serviceId, envUnsetBody(env, form.value.redeploy, `unset ${env.key} from the console`))
  }
  catch (caught) {
    error.value = errorMessage(caught)
  }
}

const fieldClass = 'h-8 text-xs'
const labelClass = 'font-mono text-[10px] uppercase tracking-wider text-fc-faint'
</script>

<template>
  <div
    class="space-y-3"
    data-testid="env-settings"
  >
    <p class="text-xs text-fc-muted">
      Names and flags only. Coolify does not show values to Fleet, and Fleet never asks it to: a value you type is sent once with the request and never shown again.
    </p>

    <ul
      v-if="envs.length > 0"
      class="divide-y divide-fc-line border border-fc-line"
      data-testid="env-list"
    >
      <li
        v-for="env in envs"
        :key="`${env.key}/${env.isPreview}`"
        class="flex flex-wrap items-center gap-x-3 gap-y-1 px-3 py-1.5 text-xs"
        data-testid="env-row"
      >
        <span class="min-w-0 break-all font-mono text-[11px] text-fc-ink">{{ env.key }}</span>
        <span class="flex flex-wrap gap-1">
          <span
            v-for="flag in envFlagLabels(env, kind)"
            :key="flag"
            class="rounded-sm border border-fc-line2 px-1.5 py-px font-mono text-[9.5px] uppercase tracking-wider text-fc-muted"
          >{{ flag }}</span>
        </span>
        <span class="ml-auto flex gap-1.5">
          <Button
            size="xs"
            variant="outline"
            :data-testid="`env-edit-${env.key}`"
            @click="edit(env)"
          >
            Set value…
          </Button>
          <template v-if="unsetting?.key === env.key && unsetting.isPreview === env.isPreview">
            <Button
              size="xs"
              variant="destructive"
              :disabled="request.isPending.value"
              :data-testid="`env-unset-confirm-${env.key}`"
              @click="unset(env)"
            >
              File unset request
            </Button>
            <Button
              size="xs"
              variant="ghost"
              @click="unsetting = null"
            >
              Cancel
            </Button>
          </template>
          <Button
            v-else
            size="xs"
            variant="ghost"
            :data-testid="`env-unset-${env.key}`"
            @click="unsetting = env"
          >
            Unset…
          </Button>
        </span>
      </li>
    </ul>
    <p
      v-else
      class="text-xs text-fc-faint"
      data-testid="env-empty"
    >
      No environment variables.
    </p>

    <form
      class="grid gap-2 border border-fc-line bg-card p-3"
      data-testid="env-form"
      autocomplete="off"
      @submit.prevent="submit"
    >
      <p class="fc-kicker">
        {{ exists ? 'Replace a value' : 'Set a variable' }}
      </p>
      <div class="grid gap-2 sm:grid-cols-2">
        <label class="grid gap-1">
          <span :class="labelClass">Name</span>
          <Input
            v-model="form.key"
            :class="fieldClass"
            placeholder="DATABASE_URL"
            autocomplete="off"
            spellcheck="false"
            data-testid="env-key"
            @update:model-value="onKey"
          />
        </label>
        <label class="grid gap-1">
          <span :class="labelClass">Value (write-only, may be empty)</span>
          <Input
            v-model="form.value"
            type="password"
            :class="fieldClass"
            autocomplete="new-password"
            spellcheck="false"
            placeholder="type the new value"
            data-testid="env-value"
          />
        </label>
      </div>
      <div class="flex flex-wrap gap-x-4 gap-y-1 text-xs text-fc-muted">
        <label
          v-if="isApplication"
          class="flex items-center gap-1.5"
        ><input
          v-model="form.preview"
          type="checkbox"
          data-testid="env-preview"
          @change="onKey"
        >Preview deployments</label>
        <label
          v-if="isApplication"
          class="flex items-center gap-1.5"
        ><input
          v-model="form.buildtime"
          type="checkbox"
        >Build time</label>
        <label
          v-if="isApplication"
          class="flex items-center gap-1.5"
        ><input
          v-model="form.runtime"
          type="checkbox"
        >Runtime</label>
        <label class="flex items-center gap-1.5"><input
          v-model="form.literal"
          type="checkbox"
        >Literal</label>
        <label class="flex items-center gap-1.5"><input
          v-model="form.multiline"
          type="checkbox"
        >Multiline</label>
        <label class="flex items-center gap-1.5"><input
          v-model="form.shownOnce"
          type="checkbox"
        >Hide after saving</label>
      </div>
      <label class="flex items-center gap-1.5 text-xs text-fc-muted"><input
        v-model="form.redeploy"
        type="checkbox"
        data-testid="env-redeploy"
      >{{ redeployLabel }} (part of the same approved request)</label>
      <label class="grid gap-1">
        <span :class="labelClass">Reason for the approver (optional)</span>
        <Input
          v-model="form.reason"
          :class="fieldClass"
          maxlength="1000"
          data-testid="env-reason"
        />
      </label>
      <p
        v-if="form.key && problem"
        class="text-[11px] text-fc-faint"
        data-testid="env-problem"
      >
        {{ problem }}
      </p>
      <div>
        <Button
          type="submit"
          size="sm"
          :disabled="Boolean(problem) || request.isPending.value"
          data-testid="env-submit"
        >
          File request
        </Button>
        <span class="ml-2 text-[11px] text-fc-faint">Needs approval before anything changes.</span>
      </div>
    </form>

    <p
      v-if="error"
      class="border-l-2 border-l-fc-err bg-card px-3 py-2 text-xs text-fc-muted"
      role="alert"
      data-testid="env-error"
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
