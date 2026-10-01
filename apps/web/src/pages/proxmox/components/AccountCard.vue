<script setup lang="ts">
import { useQueryClient } from '@tanstack/vue-query'
import { computed, ref, watch } from 'vue'

import {
  confirmProxmoxFingerprint,
  observeProxmoxFingerprint,
  type ProxmoxAccountDto,
  type ProxmoxFingerprintDto,
} from '@frogbyte-io/fleet-api-client'
import StatusChip from '@/components/fleet/StatusChip.vue'

import { ACCOUNTS_KEY } from '../../fleet/add/queries'
import { relativeTime } from '../../fleet/inventory'
import { errorMessage, unwrap } from '../../machine/api'
import CopyFleetctl from '../../machine/components/CopyFleetctl.vue'
import { proxmoxAccountCommand, proxmoxConfirmCommand } from '../../machine/fleetctl'
import {
  compatibility,
  mismatchFingerprints,
  pveUrl,
  sameFingerprint,
  trustLabel,
  trustTone,
  type AccountView,
} from '../proxmox'
import { discoveryKey, guestsKey, privilegesKey } from '../useProxmox'
import PrivilegeTiers from './PrivilegeTiers.vue'

// One account and its trust anchor. A new or changed certificate is pinned
// only after the operator observes it and states they verified it out of
// band; until then the controller refuses every call and the page offers no
// actions for this account.
const props = defineProps<{ view: AccountView, discoveryError: unknown, guestError: unknown }>()

const queryClient = useQueryClient()
const account = computed<ProxmoxAccountDto>(() => props.view.account)
const state = computed(() => props.view.state)

const observed = ref<string | null>(null)
const acknowledged = ref(false)
const busy = ref(false)
const error = ref('')

// A different trust state (e.g. just re-pinned) starts the flow over.
watch(state, () => {
  observed.value = null
  acknowledged.value = false
})
watch(observed, () => (acknowledged.value = false))

/** The mismatch error's own values, until the operator observes afresh. */
const reported = computed(() => (state.value === 'changed' ? mismatchFingerprints(errorMessage(props.discoveryError)) : null))
const pinned = computed(() => account.value.fingerprint ?? reported.value?.pinned ?? null)
const matchesPin = computed(() => sameFingerprint(observed.value, pinned.value))
const needsPin = computed(() => state.value === 'unconfirmed' || state.value === 'changed')

async function observe() {
  // Each confirmation needs the current observation and a fresh
  // acknowledgement, even if the host presents the same fingerprint again.
  observed.value = null
  acknowledged.value = false
  busy.value = true
  error.value = ''
  try {
    observed.value = unwrap<ProxmoxFingerprintDto>(await observeProxmoxFingerprint(account.value.id)).fingerprint
  }
  catch (caught) {
    error.value = errorMessage(caught)
  }
  finally {
    busy.value = false
  }
}

async function confirm() {
  const fingerprint = observed.value
  if (!fingerprint || !acknowledged.value)
    return
  busy.value = true
  error.value = ''
  try {
    unwrap<ProxmoxAccountDto>(await confirmProxmoxFingerprint(account.value.id, { fingerprint }))
    await Promise.all([
      queryClient.invalidateQueries({ queryKey: ACCOUNTS_KEY }),
      queryClient.invalidateQueries({ queryKey: discoveryKey(account.value.id) }),
      queryClient.invalidateQueries({ queryKey: guestsKey(account.value.id) }),
      queryClient.invalidateQueries({ queryKey: privilegesKey(account.value.id) }),
    ])
    observed.value = null
  }
  catch (caught) {
    error.value = errorMessage(caught)
  }
  finally {
    busy.value = false
  }
}

const command = computed(() => (observed.value && needsPin.value
  ? proxmoxConfirmCommand(account.value.id, observed.value)
  : proxmoxAccountCommand('observe', account.value.id)))

const discovery = computed(() => props.view.discovery)
// The privilege report's version and rules major when it exists; otherwise
// discovery's version alone.
const compat = computed(() => compatibility(
  props.view.privileges?.pveVersion ?? discovery.value?.pveVersion,
  props.view.privileges?.rulesMajor,
))
const counts = computed(() => {
  const resources = discovery.value?.resources ?? []
  return {
    nodes: resources.filter(r => r.kind === 'node').length,
    guests: resources.filter(r => r.kind === 'qemu' || r.kind === 'lxc').length,
    templates: resources.filter(r => r.kind === 'qemu-template').length,
  }
})
</script>

<template>
  <article
    class="space-y-3 rounded-sm border bg-card p-4"
    :class="state === 'changed' ? 'border-fc-err/50' : 'border-fc-line'"
    :data-testid="`account-${account.id}`"
    :data-state="state"
  >
    <header class="flex flex-wrap items-start gap-3">
      <div class="min-w-0">
        <p class="fc-kicker">
          Proxmox account · {{ account.tokenId }}
        </p>
        <h3 class="font-head text-[15px] font-extrabold">
          {{ account.name }}
          <span class="ml-1 font-mono text-[11px] font-normal text-fc-muted">{{ account.host }}:{{ account.port }}</span>
        </h3>
      </div>
      <StatusChip
        class="mt-1"
        :label="trustLabel(state)"
        :tone="trustTone(state)"
      />
      <a
        :href="pveUrl(account)"
        target="_blank"
        rel="noopener noreferrer"
        class="ml-auto font-mono text-[10px] uppercase tracking-wider text-fc-info hover:text-fc-ink"
        data-testid="open-pve"
      >Open in PVE ↗</a>
    </header>

    <div
      v-if="discovery"
      class="flex flex-wrap items-center gap-2"
    >
      <p class="font-mono text-[10px] uppercase tracking-wide text-fc-muted">
        PVE {{ discovery.pveVersion }} · {{ counts.nodes }} node{{ counts.nodes === 1 ? '' : 's' }} · {{ counts.guests }} guests · {{ counts.templates }} templates · seen {{ relativeTime(discovery.observedAt) }}
      </p>
      <span
        v-if="compat"
        :title="compat.title"
        data-testid="compatibility"
        :data-verified="compat.verified"
      >
        <StatusChip
          :label="compat.label"
          :tone="compat.tone"
        />
        <span class="sr-only">{{ compat.title }}</span>
      </span>
    </div>

    <PrivilegeTiers
      v-if="state === 'pinned'"
      :account-id="account.id"
      :privileges="view.privileges"
      :loading="view.privilegesLoading"
      :error="view.privilegesError"
    />

    <!-- Pinned -->
    <p
      v-if="state === 'pinned' || state === 'checking'"
      class="text-xs text-fc-muted"
    >
      Pinned <span class="break-all font-mono text-[11px] text-fc-ink">{{ account.fingerprint }}</span>
    </p>

    <p
      v-if="state === 'unreachable'"
      class="text-xs text-fc-warn"
      role="alert"
    >
      Discovery failed: {{ errorMessage(discoveryError) }}
    </p>
    <p
      v-else-if="state === 'pinned' && guestError"
      class="text-xs text-fc-warn"
      role="alert"
    >
      Guests unavailable: {{ errorMessage(guestError) }}
    </p>

    <!-- Unconfirmed / changed: re-pin -->
    <div
      v-if="needsPin"
      class="space-y-2 rounded-sm border p-3 text-xs"
      :class="state === 'changed' ? 'border-fc-err/40 bg-fc-err/5' : 'border-fc-warn/40 bg-fc-warn/5'"
      data-testid="repin"
    >
      <p
        v-if="state === 'changed'"
        class="font-semibold text-fc-err"
      >
        The host presents a different certificate than the one pinned. Fleet refuses every call to this account, and this page offers no actions for it, until you confirm the new fingerprint.
      </p>
      <p
        v-else
        class="font-semibold text-fc-warn"
      >
        Not trusted yet: no fingerprint is pinned, so Fleet cannot call this account.
      </p>

      <dl class="grid gap-1 sm:grid-cols-[110px_1fr]">
        <template v-if="state === 'changed'">
          <dt class="fc-kicker pt-0.5">
            Pinned
          </dt>
          <dd
            class="break-all font-mono text-[11px] text-fc-ink"
            data-testid="fingerprint-pinned"
          >
            {{ pinned ?? 'not reported' }}
          </dd>
        </template>
        <dt class="fc-kicker pt-0.5">
          {{ observed ? 'Observed now' : state === 'changed' ? 'Reported' : 'Observed' }}
        </dt>
        <dd
          class="break-all font-mono text-[11px]"
          :class="observed ? 'text-fc-ink' : 'text-fc-faint'"
          data-testid="fingerprint-observed"
        >
          {{ observed ?? reported?.observed ?? 'observe the certificate to see it' }}
        </dd>
      </dl>
      <p
        v-if="observed && state === 'changed' && matchesPin"
        class="text-fc-muted"
      >
        The observed certificate matches the pin again; discovery will verify on its next read.
      </p>

      <div class="flex flex-wrap items-center gap-2">
        <button
          type="button"
          class="h-8 rounded-sm border border-fc-info/40 px-3 text-fc-info hover:bg-fc-info/10 disabled:opacity-50"
          :disabled="busy"
          data-testid="observe"
          @click="observe"
        >
          {{ observed ? 'Observe again' : 'Observe certificate' }}
        </button>
      </div>
      <template v-if="observed">
        <label class="flex items-start gap-2">
          <input
            v-model="acknowledged"
            type="checkbox"
            class="mt-0.5"
            data-testid="acknowledge"
          >
          <span>I compared this fingerprint with the one the PVE host itself reports (<span class="font-mono">pvenode cert info</span> or the web UI's Certificates panel) and it matches.</span>
        </label>
        <button
          type="button"
          class="h-8 rounded-sm border border-fc-ok/50 px-3 font-semibold text-fc-ok hover:bg-fc-ok/10 disabled:opacity-50"
          :disabled="busy || !acknowledged"
          data-testid="confirm"
          @click="confirm"
        >
          {{ state === 'changed' ? 'Re-pin this fingerprint' : 'Pin this fingerprint' }}
        </button>
      </template>
      <p
        v-if="error"
        class="text-fc-err"
        role="alert"
      >
        {{ error }}
      </p>
      <CopyFleetctl :command="command" />
    </div>
  </article>
</template>
