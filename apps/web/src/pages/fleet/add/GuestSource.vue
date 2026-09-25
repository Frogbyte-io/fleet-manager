<script setup lang="ts">
import { computed, ref } from 'vue'
import { RouterLink } from 'vue-router'

import { observeProxmoxGuest } from '@frogbyte-io/fleet-api-client'
import StatusChip from '@/components/fleet/StatusChip.vue'

import { errorMessage, unwrap } from '../../machine/api'
import CopyFleetctl from '../../machine/components/CopyFleetctl.vue'
import { observeGuestCommand } from '../../machine/fleetctl'
import { guestStatusTone, type GuestItem } from '../inventory'
import { useFleetInventory } from '../useFleetInventory'

// Adopt a discovered VM/LXC: record its facts on a candidate machine it
// already is, or onboard it as a new machine over SSH. Confirming the
// guest↔machine association itself is FM-913.
const emit = defineEmits<{
  onboard: [prefill: { host: string, name: string, description: string }]
  step: [step: 'pick' | 'link']
}>()

const { inventory, isLoading } = useFleetInventory()
const guests = computed(() => inventory.value.guests.filter((g): g is GuestItem & { vmid: number } => g.vmid !== null))
const proxmoxSources = computed(() => inventory.value.sources.filter(s => s.key.startsWith('proxmox')))

const selectedKey = ref<string | null>(null)
const selected = computed(() => guests.value.find(g => g.key === selectedKey.value) ?? null)

const linking = ref<string | null>(null)
const linked = ref<string | null>(null)
const error = ref('')

async function link(machineId: string) {
  const guest = selected.value
  if (!guest)
    return
  linking.value = machineId
  error.value = ''
  try {
    const response = await observeProxmoxGuest(guest.accountId, guest.vmid, { machineId })
    if (response.status !== 204)
      unwrap(response, [204])
    linked.value = machineId
  }
  catch (e) {
    error.value = errorMessage(e)
  }
  finally {
    linking.value = null
  }
}

function onboard() {
  const guest = selected.value
  if (!guest)
    return
  emit('onboard', {
    host: guest.addresses[0] ?? '',
    name: guest.name,
    description: `Proxmox ${guest.kind === 'lxc' ? 'LXC' : 'VM'} ${guest.vmid} on ${guest.node} (${guest.accountName})`,
  })
}
</script>

<template>
  <div class="space-y-3">
    <p
      v-if="isLoading && guests.length === 0"
      class="text-xs text-fc-faint"
    >
      Loading Proxmox guests…
    </p>
    <template v-else-if="guests.length === 0">
      <p
        class="text-sm text-fc-muted"
        data-testid="no-guests"
      >
        No discovered guests. Connect a Proxmox server first.
      </p>
      <p
        v-for="source in proxmoxSources.filter(s => s.state !== 'ok')"
        :key="source.key"
        class="text-xs text-fc-warn"
      >
        {{ source.message }}
      </p>
    </template>
    <template v-else>
      <div
        class="max-h-56 space-y-1.5 overflow-y-auto"
        role="radiogroup"
        aria-label="Guest"
      >
        <label
          v-for="guest in guests"
          :key="guest.key"
          class="grid cursor-pointer grid-cols-[16px_minmax(0,1fr)_auto] items-center gap-2.5 rounded-sm border p-2 text-sm"
          :class="selectedKey === guest.key ? 'border-fc-ink' : 'border-fc-line'"
          :data-testid="`guest-${guest.vmid}`"
        >
          <input
            v-model="selectedKey"
            type="radio"
            :value="guest.key"
            @change="emit('step', 'link'); linked = null"
          >
          <span class="min-w-0">
            <b class="font-semibold text-fc-ink">{{ guest.name }}</b>
            <span class="block truncate font-mono text-[10px] uppercase text-fc-faint">
              {{ guest.kind === 'lxc' ? 'LXC' : 'QEMU' }} {{ guest.vmid }} · ON {{ guest.node }} · {{ guest.accountName }}{{ guest.addresses.length ? ` · ${guest.addresses.join(' · ')}` : '' }}
            </span>
          </span>
          <StatusChip
            :label="guest.candidates.length > 0 ? `${guest.candidates.length} candidate(s)` : guest.status"
            :tone="guest.candidates.length > 0 ? 'info' : guestStatusTone(guest.status)"
          />
        </label>
      </div>

      <template v-if="selected">
        <section
          v-if="selected.candidates.length > 0"
          class="space-y-2"
        >
          <h4 class="fc-kicker">
            It may already be in Fleet
          </h4>
          <div
            v-for="candidate in selected.candidates"
            :key="candidate.machineId"
            class="flex flex-wrap items-center gap-2 rounded-sm border border-fc-line p-2 text-xs"
          >
            <span class="text-fc-ink">{{ candidate.machineName }}</span>
            <span class="font-mono text-fc-info">≈ {{ candidate.evidence }}</span>
            <template v-if="linked === candidate.machineId">
              <span class="ml-auto text-fc-ok">Guest facts recorded.</span>
              <RouterLink
                :to="`/fleet/machines/${candidate.machineId}?tab=guest`"
                class="font-mono text-[10px] uppercase tracking-wider text-fc-info hover:text-fc-ink"
              >
                Open →
              </RouterLink>
            </template>
            <button
              v-else
              type="button"
              class="ml-auto h-7 rounded-sm border border-fc-info/40 px-2 text-fc-info hover:bg-fc-info/10 disabled:opacity-50"
              :disabled="linking !== null"
              :data-testid="`link-${candidate.machineId}`"
              @click="link(candidate.machineId)"
            >
              Record facts on this machine
            </button>
            <div class="w-full">
              <CopyFleetctl :command="observeGuestCommand({ accountId: selected.accountId, node: selected.node, vmid: selected.vmid }, candidate.machineId)" />
            </div>
          </div>
          <p class="text-[11px] text-fc-faint">
            Candidates are MAC, address, or name evidence. Confirming the association arrives with FM-913.
          </p>
        </section>
        <section class="space-y-2">
          <h4 class="fc-kicker">
            Or onboard it as a new machine
          </h4>
          <p class="text-xs text-fc-muted">
            <template v-if="selected.addresses.length > 0">
              Continues over SSH to <span class="font-mono text-fc-ink">{{ selected.addresses[0] }}</span>, the first address the guest agent reports.
            </template>
            <template v-else>
              The guest agent reports no address; enter one on the next step.
            </template>
          </p>
          <button
            type="button"
            class="fc-grad-bg h-9 rounded-sm px-4 text-sm font-medium"
            data-testid="onboard-guest"
            @click="onboard"
          >
            Onboard over SSH →
          </button>
        </section>
        <p
          v-if="error"
          class="text-xs text-fc-err"
        >
          {{ error }}
        </p>
      </template>
    </template>
  </div>
</template>
