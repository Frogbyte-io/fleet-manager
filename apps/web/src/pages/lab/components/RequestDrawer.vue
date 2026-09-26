<script setup lang="ts">
import { useQueryClient } from '@tanstack/vue-query'
import { computed, ref, watch } from 'vue'

import {
  createLabLease,
  startLabLeaseProvision,
  type LabTemplateDto,
  type LeaseDto,
  type OperationDto,
  type ProjectDto,
  type ProxmoxAccountDto,
} from '@frogbyte-io/fleet-api-client'
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from '@/components/ui/sheet'

import { errorMessage, unwrap } from '../../machine/api'
import CopyFleetctl from '../../machine/components/CopyFleetctl.vue'
import { leaseCommand, provisionLeaseCommand, templateSpec } from '../lab'
import { LEASES_KEY, PROVISIONS_KEY } from '../useLab'

// Request a disposable environment. A lease is created from a template's
// published version; provisioning is a separate durable operation that needs
// a Proxmox account, so the drawer can start it right away or leave the
// lease requested for later.
const props = defineProps<{
  open: boolean
  templates: LabTemplateDto[]
  projects: ProjectDto[]
  accounts: ProxmoxAccountDto[]
}>()

const emit = defineEmits<{
  'update:open': [open: boolean]
  'created': [lease: LeaseDto, operationId: string | null]
}>()

const queryClient = useQueryClient()

const templateId = ref('')
const purpose = ref('')
const projectId = ref('')
const provisionNow = ref(true)
const accountId = ref('')
const busy = ref(false)
const error = ref('')

// Defaults follow the lists as they load: the first template and account.
watch(() => props.templates, (list) => {
  if (!list.some(t => t.id === templateId.value))
    templateId.value = list[0]?.id ?? ''
}, { immediate: true })
watch(() => props.accounts, (list) => {
  if (!list.some(a => a.id === accountId.value))
    accountId.value = list[0]?.id ?? ''
}, { immediate: true })

const template = computed(() => props.templates.find(t => t.id === templateId.value) ?? null)
const versionId = computed(() => template.value?.publishedFrom ?? null)
const willProvision = computed(() => provisionNow.value && props.accounts.length > 0 && accountId.value !== '')

const valid = computed(() => versionId.value !== null && purpose.value.trim() !== '')

const command = computed(() =>
  versionId.value && purpose.value.trim()
    ? leaseCommand(versionId.value, purpose.value.trim(), projectId.value || null)
    : null,
)

// Why there is no command: nothing to lease yet, or a project the CLI cannot express.
const missingReason = computed(() => {
  if (versionId.value === null)
    return 'Choose a published template to see the equivalent command.'
  if (!purpose.value.trim())
    return 'Enter a purpose to see the equivalent command.'
  return 'fleetctl lab lease has no project flag yet, so a project-scoped request has no exact CLI equivalent.'
})

// A lease created whose provisioning did not start: the drawer then retries
// provisioning for that lease instead of creating a second one.
const pendingLease = ref<LeaseDto | null>(null)

watch(() => props.open, (open) => {
  if (!open) {
    pendingLease.value = null
    error.value = ''
  }
})

async function refresh() {
  await Promise.all([
    queryClient.invalidateQueries({ queryKey: LEASES_KEY }),
    queryClient.invalidateQueries({ queryKey: PROVISIONS_KEY }),
  ])
}

/** Starts provisioning; returns the operation id, or null with `error` set. */
async function provision(lease: LeaseDto): Promise<string | null> {
  try {
    const operation = unwrap<OperationDto>(await startLabLeaseProvision(lease.id, { accountId: accountId.value }), [201])
    return operation.id
  }
  catch (caught) {
    // The lease exists either way; say so rather than hiding it.
    error.value = `Lease created, but provisioning did not start: ${errorMessage(caught)}`
    return null
  }
}

function finish(lease: LeaseDto, operationId: string | null) {
  emit('created', lease, operationId)
  if (!error.value) {
    purpose.value = ''
    pendingLease.value = null
    emit('update:open', false)
  }
}

async function submit() {
  busy.value = true
  error.value = ''
  try {
    if (pendingLease.value) {
      const operationId = await provision(pendingLease.value)
      await refresh()
      finish(pendingLease.value, operationId)
      return
    }
    if (!valid.value || !versionId.value)
      return
    const lease = unwrap<LeaseDto>(await createLabLease({
      templateVersionId: versionId.value,
      purpose: purpose.value.trim(),
      projectId: projectId.value || null,
    }), [201])
    const operationId = willProvision.value ? await provision(lease) : null
    if (error.value)
      pendingLease.value = lease
    await refresh()
    finish(lease, operationId)
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
  <Sheet
    :open="open"
    @update:open="emit('update:open', $event)"
  >
    <SheetContent
      side="right"
      class="w-[400px] overflow-y-auto border-fc-line bg-fc-panel sm:w-[400px]"
    >
      <SheetHeader>
        <SheetTitle class="font-head text-base font-extrabold uppercase tracking-wide">
          New environment
        </SheetTitle>
        <SheetDescription class="text-xs text-fc-muted">
          A disposable VM from a published template. Cleanup follows the template; TTL starts when it is ready.
        </SheetDescription>
      </SheetHeader>

      <form
        class="grid gap-4 px-4 pb-6 text-sm"
        @submit.prevent="submit"
      >
        <p
          v-if="pendingLease"
          class="rounded-sm border border-fc-warn/40 bg-fc-warn/10 p-2 text-xs text-fc-warn"
          data-testid="pending-lease"
        >
          Lease "{{ pendingLease.purpose }}" exists and is waiting to be provisioned. Retrying provisions it; it does not create another lease.
        </p>
        <fieldset
          class="grid gap-1.5"
          :disabled="pendingLease !== null"
        >
          <legend class="fc-kicker mb-1.5">
            Template
          </legend>
          <p
            v-if="templates.length === 0"
            class="text-xs text-fc-warn"
          >
            No published templates. Publish one from the Templates tab first.
          </p>
          <label
            v-for="item in templates"
            :key="item.id"
            class="flex cursor-pointer items-center gap-3 rounded-sm border px-3 py-2"
            :class="item.id === templateId ? 'border-[var(--fc-g1)] bg-[color-mix(in_srgb,var(--fc-g1)_6%,transparent)]' : 'border-input'"
          >
            <input
              v-model="templateId"
              type="radio"
              name="template"
              :value="item.id"
              class="sr-only"
            >
            <span class="font-semibold">{{ item.name }}</span>
            <span class="ml-auto font-mono text-[9.5px] uppercase tracking-wider text-fc-muted">{{ templateSpec(item) }}</span>
          </label>
        </fieldset>

        <div
          v-if="template"
          class="font-mono text-[10.5px] uppercase tracking-wide text-fc-muted"
          data-testid="template-facts"
        >
          CLEANUP <span class="text-fc-ink">{{ template.cleanup }}</span> ·
          READINESS <span class="text-fc-ink">{{ template.readinessProbe.replace('_', ' ') }}</span>
        </div>

        <label class="grid gap-1.5">
          <span class="fc-kicker">Purpose</span>
          <input
            v-model="purpose"
            :disabled="pendingLease !== null"
            required
            maxlength="200"
            placeholder="what this environment is for"
            class="h-9 rounded-sm border border-input bg-background px-3"
          >
        </label>

        <label class="grid gap-1.5">
          <span class="fc-kicker">Project (optional)</span>
          <select
            v-model="projectId"
            :disabled="pendingLease !== null"
            class="h-9 rounded-sm border border-input bg-background px-2"
          >
            <option value="">
              None
            </option>
            <option
              v-for="project in projects"
              :key="project.id"
              :value="project.id"
            >
              {{ project.name }}
            </option>
          </select>
        </label>

        <fieldset class="grid gap-1.5">
          <legend class="fc-kicker mb-1.5">
            Provisioning
          </legend>
          <p
            v-if="accounts.length === 0"
            class="text-xs text-fc-warn"
          >
            No Proxmox account with a confirmed TLS fingerprint, so the lease will stay requested until one exists.
          </p>
          <template v-else>
            <label class="flex items-center gap-2 text-xs">
              <input
                v-model="provisionNow"
                type="checkbox"
                class="accent-[var(--fc-g2)]"
              >
              Start provisioning now
            </label>
            <select
              v-if="provisionNow"
              v-model="accountId"
              aria-label="Proxmox account"
              class="h-9 rounded-sm border border-input bg-background px-2"
            >
              <option
                v-for="account in accounts"
                :key="account.id"
                :value="account.id"
              >
                {{ account.name }} · {{ account.host }}
              </option>
            </select>
          </template>
        </fieldset>

        <CopyFleetctl
          :command="command"
          :missing="missingReason"
        />
        <p
          v-if="willProvision && versionId"
          class="-mt-2 font-mono text-[10.5px] text-fc-faint"
        >
          then: {{ provisionLeaseCommand('LEASE_ID', accountId) }}
        </p>

        <p
          v-if="error"
          class="text-xs text-fc-err"
          role="alert"
        >
          {{ error }}
        </p>

        <button
          type="submit"
          class="fc-grad-bg h-10 rounded-sm font-head text-sm font-bold disabled:opacity-50"
          :disabled="busy || (pendingLease ? !willProvision : !valid)"
        >
          {{ pendingLease ? 'Retry provisioning →' : willProvision ? 'Request & provision →' : 'Request environment →' }}
        </button>
      </form>
    </SheetContent>
  </Sheet>
</template>
