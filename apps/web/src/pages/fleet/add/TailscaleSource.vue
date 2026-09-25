<script setup lang="ts">
import { useQuery } from '@tanstack/vue-query'
import { computed, ref, watch } from 'vue'
import { RouterLink } from 'vue-router'

import {
  createOnboardingDraft,
  getTailnetStatus,
  importTailnetDevice,
  type OnboardingDraftDetailDto,
  type OnboardingDraftDto,
} from '@frogbyte-io/fleet-api-client'
import StatusChip from '@/components/fleet/StatusChip.vue'

import { errorMessage, unwrap } from '../../machine/api'
import CopyFleetctl from '../../machine/components/CopyFleetctl.vue'
import { onboardCreateCommand, tailnetImportCommand, type SshAuth } from '../../machine/fleetctl'
import { allTailnetDevices, TAILNET_DEVICES_KEY, validPort } from './queries'
import { connectHost, type ConnectVia } from './tailnet'

// Pick a tailnet device, choose how the controller reaches it, and create
// the draft. The 100.x + SSH-agent path is exactly `tailnet import`; the
// other choices create an SSH draft that records the same provenance.
const props = defineProps<{ initialDevice?: string | null }>()
const emit = defineEmits<{ created: [draftId: string] }>()

const statusQuery = useQuery({
  queryKey: ['fleet', 'tailnet-status'],
  queryFn: async () => unwrap<{ configured: boolean }>(await getTailnetStatus()),
})
const configured = computed(() => statusQuery.data.value?.configured ?? false)

const devicesQuery = useQuery({
  queryKey: TAILNET_DEVICES_KEY,
  queryFn: allTailnetDevices,
  enabled: configured,
})
const devices = computed(() =>
  [...(devicesQuery.data.value ?? [])].sort((a, b) => Number(a.candidates.length > 0) - Number(b.candidates.length > 0) || a.hostname.localeCompare(b.hostname)),
)

const selectedId = ref<string | null>(props.initialDevice ?? null)
const selected = computed(() => devices.value.find(d => d.nodeId === selectedId.value) ?? null)

const via = ref<ConnectVia>('magicdns')
const lanIp = ref('')
const user = ref('')
const port = ref(22)
const authType = ref<SshAuth['type']>('agent')
const identityPath = ref('')
const auth = computed<SshAuth>(() => authType.value === 'agent' ? { type: 'agent' } : { type: 'identityFile', path: identityPath.value })

watch(selectedId, () => {
  lanIp.value = ''
})

const host = computed(() => (selected.value ? connectHost(selected.value, via.value, lanIp.value) : null))
const useImport = computed(() => via.value === 'tailnet-ip' && authType.value === 'agent')
const valid = computed(() => selected.value !== null && host.value !== null && user.value.trim() !== '' && validPort(port.value)
  && (authType.value === 'agent' || identityPath.value.trim() !== ''))

const command = computed(() => {
  if (!valid.value || !selected.value || !host.value)
    return null
  if (useImport.value)
    return tailnetImportCommand(selected.value.nodeId, user.value.trim(), port.value)
  return onboardCreateCommand({ user: user.value.trim(), host: host.value, port: port.value, name: selected.value.hostname, description: provenance(selected.value), tags: [], auth: auth.value })
})

// The same provenance note `tailnet import` writes on its drafts.
function provenance(device: { nodeId: string, name: string }): string {
  return `Imported from tailnet device ${device.nodeId} (${device.name})`
}

const busy = ref(false)
const error = ref('')

async function create() {
  const device = selected.value
  if (!device || !host.value)
    return
  busy.value = true
  error.value = ''
  try {
    if (useImport.value) {
      const draft = unwrap<OnboardingDraftDetailDto>(await importTailnetDevice(device.nodeId, { user: user.value.trim(), port: port.value }), [201])
      emit('created', draft.id)
    }
    else {
      const draft = unwrap<OnboardingDraftDto>(await createOnboardingDraft({
        user: user.value.trim(),
        host: host.value,
        port: port.value,
        auth: auth.value,
        name: device.hostname,
        description: provenance(device),
        tags: [],
        groups: [],
      }), [201])
      emit('created', draft.id)
    }
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
    <p
      v-if="statusQuery.isLoading.value || devicesQuery.isLoading.value"
      class="text-xs text-fc-faint"
    >
      Loading tailnet devices…
    </p>
    <p
      v-else-if="statusQuery.error.value || devicesQuery.error.value"
      class="text-xs text-fc-err"
    >
      Tailnet unavailable: {{ errorMessage(statusQuery.error.value ?? devicesQuery.error.value) }}
    </p>
    <p
      v-else-if="!configured"
      class="text-sm text-fc-muted"
      data-testid="tailnet-unconfigured"
    >
      The tailnet integration is not configured. Configure it in
      <RouterLink
        to="/settings"
        class="text-fc-info underline decoration-dotted"
      >
        Settings
      </RouterLink>, or add the machine over SSH.
    </p>
    <template v-else>
      <p class="text-xs text-fc-muted">
        Read-only OAuth (<span class="font-mono">devices:core:read</span>). Fleet identity stays independent of Tailscale.
      </p>
      <div
        class="max-h-56 space-y-1.5 overflow-y-auto"
        role="radiogroup"
        aria-label="Tailnet device"
      >
        <label
          v-for="device in devices"
          :key="device.nodeId"
          class="grid cursor-pointer grid-cols-[16px_minmax(0,1fr)_auto] items-center gap-2.5 rounded-sm border p-2 text-sm"
          :class="selectedId === device.nodeId ? 'border-fc-ink' : 'border-fc-line'"
          :data-testid="`device-${device.nodeId}`"
        >
          <input
            v-model="selectedId"
            type="radio"
            :value="device.nodeId"
          >
          <span class="min-w-0">
            <b class="font-semibold text-fc-ink">{{ device.hostname }}</b>
            <span class="block truncate font-mono text-[10px] uppercase text-fc-faint">
              {{ [device.os, ...device.addresses, device.name, ...device.tags].filter(Boolean).join(' · ') }}
            </span>
          </span>
          <span class="flex gap-1">
            <StatusChip
              v-if="device.candidates.length > 0"
              :label="`In Fleet: ${device.candidates[0]!.machineName}`"
              tone="info"
            />
            <StatusChip
              :label="device.online === null || device.online === undefined ? 'unknown' : device.online ? 'online' : 'offline'"
              :tone="device.online ? 'ok' : 'faint'"
            />
          </span>
        </label>
        <p
          v-if="devices.length === 0"
          class="text-sm text-fc-faint"
        >
          No tailnet devices.
        </p>
      </div>

      <template v-if="selected">
        <p
          v-if="selected.candidates.length > 0"
          class="text-xs text-fc-warn"
        >
          This device looks like {{ selected.candidates.map(c => c.machineName).join(', ') }}, already in Fleet ({{ selected.candidates[0]!.kind.replace('_', ' ') }}). Adding it again creates a second machine.
        </p>
        <fieldset class="rounded-sm border border-fc-info/40 bg-fc-info/5 p-2 text-xs">
          <legend class="fc-kicker px-1">
            Connect via
          </legend>
          <div
            class="flex flex-wrap gap-1"
            role="radiogroup"
          >
            <label
              v-for="option in ([['magicdns', 'MagicDNS name'], ['tailnet-ip', '100.x address'], ['lan', 'LAN IP']] as const)"
              :key="option[0]"
              class="cursor-pointer rounded-sm border px-2 py-1"
              :class="via === option[0] ? 'border-fc-ink text-fc-ink' : 'border-fc-line text-fc-muted'"
            >
              <input
                v-model="via"
                type="radio"
                :value="option[0]"
                class="sr-only"
                :data-testid="`via-${option[0]}`"
              >
              {{ option[1] }}
            </label>
          </div>
          <p class="mt-1 text-fc-muted">
            MagicDNS survives re-IP; the LAN IP works when the controller is not on the tailnet.
          </p>
          <input
            v-if="via === 'lan'"
            v-model="lanIp"
            placeholder="192.168.1.40"
            class="mt-1 h-8 w-48 rounded-sm border border-input bg-background px-2 font-mono text-foreground"
            data-testid="lan-ip"
          >
          <p
            v-else-if="!host"
            class="mt-1 text-fc-warn"
          >
            This device reports no {{ via === 'magicdns' ? 'MagicDNS name' : 'Tailscale IPv4 address' }}.
          </p>
          <p
            v-else
            class="mt-1 font-mono text-fc-ink"
          >
            {{ host }}
          </p>
        </fieldset>
        <div class="grid grid-cols-[1fr_90px_1fr] gap-3 text-xs">
          <label class="flex flex-col gap-1">
            <span class="fc-kicker">SSH user</span>
            <input
              v-model="user"
              class="h-8 rounded-sm border border-input bg-background px-2 font-mono text-foreground"
              data-testid="tailnet-user"
            >
          </label>
          <label class="flex flex-col gap-1">
            <span class="fc-kicker">Port</span>
            <input
              v-model.number="port"
              type="number"
              min="1"
              max="65535"
              data-testid="tailnet-port"
              class="h-8 rounded-sm border border-input bg-background px-2 font-mono text-foreground"
            >
          </label>
          <label class="flex flex-col gap-1">
            <span class="fc-kicker">Auth</span>
            <select
              v-model="authType"
              class="h-8 rounded-sm border border-input bg-background px-2 text-foreground"
              data-testid="tailnet-auth"
            >
              <option value="agent">SSH agent</option>
              <option value="identityFile">Identity file</option>
            </select>
          </label>
          <label
            v-if="authType === 'identityFile'"
            class="col-span-3 flex flex-col gap-1"
          >
            <span class="fc-kicker">Identity path (controller host)</span>
            <input
              v-model="identityPath"
              class="h-8 rounded-sm border border-input bg-background px-2 font-mono text-foreground"
            >
          </label>
        </div>
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
          data-testid="create-tailnet-draft"
          @click="create"
        >
          Create draft →
        </button>
        <CopyFleetctl
          :command="command"
          missing="Pick a device and fill in the SSH user to see the command."
        />
      </template>
    </template>
  </div>
</template>
