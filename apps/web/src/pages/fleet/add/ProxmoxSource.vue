<script setup lang="ts">
import { useQuery, useQueryClient } from '@tanstack/vue-query'
import { computed, ref, watch } from 'vue'
import { RouterLink } from 'vue-router'

import {
  confirmProxmoxFingerprint,
  createProxmoxAccount,
  deleteProxmoxAccount,
  observeProxmoxFingerprint,
  type ProxmoxAccountDto,
  type ProxmoxFingerprintDto,
} from '@frogbyte-io/fleet-api-client'

import { ApiRequestError, errorMessage, retryTransient, unwrap } from '../../machine/api'
import CopyFleetctl from '../../machine/components/CopyFleetctl.vue'
import { proxmoxAccountCommand, proxmoxConfirmCommand, proxmoxCreateCommand } from '../../machine/fleetctl'
import { proxmoxDiscovery } from '../useFleetInventory'
import { ACCOUNTS_KEY, allProxmoxAccounts, validPort } from './queries'

// Connect a Proxmox VE cluster: save the account (the token secret is
// write-only), observe the TLS certificate, have the operator confirm the
// fingerprint, then preview what discovery sees. An unconfirmed account is
// the durable state a reopened dialog resumes from.
const props = defineProps<{ accountId: string | null }>()
const emit = defineEmits<{
  created: [accountId: string]
  step: [step: 'connect' | 'verify' | 'preview']
  discarded: []
  /** The resumed account no longer exists. */
  missing: []
}>()

const queryClient = useQueryClient()

const accountsQuery = useQuery({
  queryKey: ACCOUNTS_KEY,
  queryFn: allProxmoxAccounts,
  enabled: computed(() => props.accountId !== null),
})

function invalidateAccounts() {
  return queryClient.invalidateQueries({ queryKey: ACCOUNTS_KEY })
}
const account = computed(() => accountsQuery.data.value?.find(a => a.id === props.accountId) ?? null)
const confirmed = computed(() => account.value?.fingerprintState === 'confirmed')

// A confirmed account whose certificate changed goes back through
// observe → confirm; the controller refuses every call until it is re-pinned.
const repinning = ref(false)
const step = computed(() => (props.accountId === null ? 'connect' : confirmed.value && !repinning.value ? 'preview' : 'verify'))
watch(step, s => emit('step', s), { immediate: true })

const busy = ref(false)
const error = ref('')

async function act(fn: () => Promise<void>) {
  busy.value = true
  error.value = ''
  try {
    await fn()
  }
  catch (e) {
    error.value = errorMessage(e)
  }
  finally {
    busy.value = false
  }
}

// Connect
const name = ref('')
const host = ref('')
const port = ref(8006)
const tokenId = ref('')
const tokenSecret = ref('')
const formValid = computed(() => name.value.trim() !== '' && host.value.trim() !== '' && validPort(port.value)
  && /^[^@\s]+@[^!\s]+![^\s]+$/.test(tokenId.value.trim()) && tokenSecret.value !== '')
const createCmd = computed(() => (formValid.value ? proxmoxCreateCommand(name.value.trim(), host.value.trim(), port.value, tokenId.value.trim()) : null))

function create() {
  return act(async () => {
    const created = unwrap<ProxmoxAccountDto>(await createProxmoxAccount({
      name: name.value.trim(),
      host: host.value.trim(),
      port: port.value,
      tokenId: tokenId.value.trim(),
      tokenSecret: tokenSecret.value,
    }), [201])
    // The secret leaves component state as soon as the controller has it.
    tokenSecret.value = ''
    await invalidateAccounts()
    emit('created', created.id)
  })
}

// Verify TLS
const observed = ref<string | null>(null)
const verified = ref(false)

function observe() {
  return act(async () => {
    observed.value = unwrap<ProxmoxFingerprintDto>(await observeProxmoxFingerprint(props.accountId!)).fingerprint
    verified.value = false
  })
}

function confirm() {
  const fingerprint = observed.value
  if (!fingerprint)
    return
  return act(async () => {
    unwrap<ProxmoxAccountDto>(await confirmProxmoxFingerprint(props.accountId!, { fingerprint }))
    // Invalidation refetches the active account query before resolving.
    await invalidateAccounts()
    if (repinning.value) {
      repinning.value = false
      observed.value = null
      verified.value = false
      await discoveryQuery.refetch()
    }
  })
}

const confirmingDiscard = ref(false)

function discard() {
  return act(async () => {
    const response = await deleteProxmoxAccount(props.accountId!)
    if (response.status !== 204)
      unwrap(response, [204])
    await invalidateAccounts()
    emit('discarded')
  })
}

// Preview
const discoveryQuery = useQuery({
  queryKey: computed(() => ['fleet', 'proxmox-discovery', props.accountId]),
  queryFn: () => proxmoxDiscovery(props.accountId!),
  retry: retryTransient,
  enabled: computed(() => step.value === 'preview'),
})
const certificateChanged = computed(() => {
  const error = discoveryQuery.error.value
  return error instanceof ApiRequestError && error.code === 'proxmox_fingerprint_mismatch'
})
const counts = computed(() => {
  const resources = discoveryQuery.data.value?.resources ?? []
  return {
    nodes: resources.filter(r => r.kind === 'node').length,
    guests: resources.filter(r => r.kind === 'qemu' || r.kind === 'lxc').length,
    templates: resources.filter(r => r.kind === 'qemu-template').length,
  }
})
</script>

<template>
  <div
    class="space-y-3"
    :data-step="step"
  >
    <template v-if="step === 'connect'">
      <div class="grid grid-cols-[1fr_1fr_90px] gap-3 text-xs">
        <label class="flex flex-col gap-1">
          <span class="fc-kicker">Name</span>
          <input
            v-model="name"
            placeholder="homelab"
            class="h-8 rounded-sm border border-input bg-background px-2 text-foreground"
            data-testid="pve-name"
          >
        </label>
        <label class="flex flex-col gap-1">
          <span class="fc-kicker">Host</span>
          <input
            v-model="host"
            placeholder="pve.lan"
            class="h-8 rounded-sm border border-input bg-background px-2 font-mono text-foreground"
            data-testid="pve-host"
          >
        </label>
        <label class="flex flex-col gap-1">
          <span class="fc-kicker">Port</span>
          <input
            v-model.number="port"
            type="number"
            min="1"
            max="65535"
            class="h-8 rounded-sm border border-input bg-background px-2 font-mono text-foreground"
            data-testid="pve-port"
          >
        </label>
        <label class="col-span-3 flex flex-col gap-1">
          <span class="fc-kicker">API token id</span>
          <input
            v-model="tokenId"
            placeholder="fleet@pve!console"
            class="h-8 rounded-sm border border-input bg-background px-2 font-mono text-foreground"
            data-testid="pve-token-id"
          >
        </label>
        <label class="col-span-3 flex flex-col gap-1">
          <span class="fc-kicker">API token secret (write-only)</span>
          <input
            v-model="tokenSecret"
            type="password"
            autocomplete="off"
            class="h-8 rounded-sm border border-input bg-background px-2 font-mono text-foreground"
            data-testid="pve-token-secret"
          >
        </label>
      </div>
      <button
        type="button"
        class="fc-grad-bg h-9 rounded-sm px-4 text-sm font-medium disabled:opacity-50"
        :disabled="!formValid || busy"
        data-testid="create-pve"
        @click="create"
      >
        Save account →
      </button>
      <CopyFleetctl
        :command="createCmd"
        missing="Fill in the account to see the command. The secret is never part of it."
      />
    </template>

    <template v-else-if="accountsQuery.isLoading.value">
      <p class="text-xs text-fc-faint">
        Loading account…
      </p>
    </template>

    <template v-else-if="accountsQuery.error.value">
      <p class="text-xs text-fc-err">
        Proxmox accounts unavailable: {{ errorMessage(accountsQuery.error.value) }}
      </p>
      <button
        type="button"
        class="font-mono text-[10px] uppercase tracking-wider text-fc-info hover:text-fc-ink"
        @click="accountsQuery.refetch()"
      >
        Retry
      </button>
    </template>

    <template v-else-if="!account">
      <p
        class="text-xs text-fc-err"
        data-testid="pve-missing"
      >
        This Proxmox account no longer exists.
      </p>
      <button
        type="button"
        class="font-mono text-[10px] uppercase tracking-wider text-fc-info hover:text-fc-ink"
        data-testid="pve-missing-restart"
        @click="emit('missing')"
      >
        Start over
      </button>
    </template>

    <template v-else-if="step === 'verify'">
      <p class="text-sm text-fc-ink">
        {{ account.name }} · <span class="font-mono text-xs">{{ account.host }}:{{ account.port }}</span>
      </p>
      <p class="text-xs text-fc-muted">
        Fetch the certificate the host presents, then compare its SHA-256 fingerprint with the one in the PVE web UI (Datacenter → node → Certificates).
      </p>
      <button
        type="button"
        class="h-8 rounded-sm border border-fc-info/40 px-3 text-xs text-fc-info hover:bg-fc-info/10 disabled:opacity-50"
        :disabled="busy"
        data-testid="observe-pve"
        @click="observe"
      >
        {{ observed ? 'Observe again' : 'Observe TLS fingerprint' }}
      </button>
      <CopyFleetctl :command="proxmoxAccountCommand('observe', account.id)" />
      <template v-if="observed">
        <div
          class="break-all rounded-sm border border-fc-line bg-fc-inset p-2 font-mono text-xs text-fc-ink"
          data-testid="pve-fingerprint"
        >
          {{ observed }}
        </div>
        <label class="flex items-center gap-2 text-xs text-fc-ink">
          <input
            v-model="verified"
            type="checkbox"
            data-testid="pve-verified"
          >
          I compared this fingerprint with the PVE host and it matches.
        </label>
        <button
          type="button"
          class="h-8 rounded-sm border border-fc-info/40 px-3 text-xs text-fc-info hover:bg-fc-info/10 disabled:opacity-50"
          :disabled="busy || !verified"
          data-testid="confirm-pve"
          @click="confirm"
        >
          Pin fingerprint
        </button>
        <CopyFleetctl :command="proxmoxConfirmCommand(account.id, observed)" />
      </template>
      <div
        v-if="repinning"
        class="flex items-center gap-2 border-t border-fc-line pt-3 text-xs"
      >
        <span class="font-mono text-[10px] uppercase tracking-wider text-fc-warn">Certificate changed · the old pin stays until you pin the new one</span>
        <button
          type="button"
          class="ml-auto text-fc-muted hover:text-fc-ink"
          data-testid="cancel-repin"
          @click="repinning = false"
        >
          Back
        </button>
      </div>
      <div
        v-else
        class="flex items-center gap-2 border-t border-fc-line pt-3 text-xs"
      >
        <span class="font-mono text-[10px] uppercase tracking-wider text-fc-faint">Unconfirmed account · resumes when reopened</span>
        <button
          v-if="!confirmingDiscard"
          type="button"
          class="ml-auto text-fc-muted hover:text-fc-err"
          data-testid="discard-pve"
          @click="confirmingDiscard = true"
        >
          Discard account
        </button>
        <template v-else>
          <span class="ml-auto text-fc-err">Delete {{ account.name }}?</span>
          <button
            type="button"
            class="rounded-sm border border-fc-err/40 px-2 py-1 text-fc-err disabled:opacity-50"
            :disabled="busy"
            data-testid="confirm-discard-pve"
            @click="discard"
          >
            Delete
          </button>
          <button
            type="button"
            class="text-fc-muted hover:text-fc-ink"
            @click="confirmingDiscard = false"
          >
            Keep
          </button>
        </template>
      </div>
    </template>

    <template v-else>
      <p class="text-sm text-fc-ink">
        {{ account.name }} is trusted. Fingerprint <span class="break-all font-mono text-xs">{{ account.fingerprint }}</span>
      </p>
      <p
        v-if="discoveryQuery.isLoading.value"
        class="text-xs text-fc-faint"
      >
        Discovering…
      </p>
      <template v-else-if="discoveryQuery.error.value">
        <p
          class="text-xs text-fc-err"
          data-testid="pve-discovery-error"
        >
          {{ certificateChanged ? 'The host now presents a different TLS certificate than the pinned one.' : `Discovery failed: ${errorMessage(discoveryQuery.error.value)}` }}
        </p>
        <button
          v-if="certificateChanged"
          type="button"
          class="h-8 rounded-sm border border-fc-info/40 px-3 text-xs text-fc-info hover:bg-fc-info/10"
          data-testid="repin-pve"
          @click="repinning = true"
        >
          Verify the new certificate
        </button>
        <button
          v-else
          type="button"
          class="font-mono text-[10px] uppercase tracking-wider text-fc-info hover:text-fc-ink disabled:opacity-50"
          :disabled="discoveryQuery.isFetching.value"
          data-testid="retry-discovery"
          @click="discoveryQuery.refetch()"
        >
          Retry
        </button>
      </template>
      <template v-else-if="discoveryQuery.data.value">
        <p
          class="font-mono text-xs text-fc-ink"
          data-testid="pve-preview"
        >
          PVE {{ discoveryQuery.data.value.pveVersion }} · {{ counts.nodes }} node(s) · {{ counts.guests }} guest(s) · {{ counts.templates }} template(s)
        </p>
        <p
          v-for="warning in discoveryQuery.data.value.warnings"
          :key="warning"
          class="text-xs text-fc-warn"
        >
          {{ warning }}
        </p>
      </template>
      <CopyFleetctl :command="proxmoxAccountCommand('discover', account.id)" />
      <RouterLink
        to="/fleet"
        class="inline-block font-mono text-[11px] uppercase tracking-wider text-fc-info hover:text-fc-ink"
      >
        See it on the Fleet page →
      </RouterLink>
    </template>

    <p
      v-if="error"
      class="text-xs text-fc-err"
    >
      {{ error }}
    </p>
  </div>
</template>
