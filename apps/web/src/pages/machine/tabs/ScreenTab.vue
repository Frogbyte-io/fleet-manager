<script setup lang="ts">
import { useQuery } from '@tanstack/vue-query'
import { computed, defineAsyncComponent, ref, watch } from 'vue'

import { getProxmoxPrivileges, type ProxmoxPrivilegesDto } from '@frogbyte-io/fleet-api-client'

import type { GuestItem } from '../../fleet/inventory'
import { tierBlockReason } from '../../proxmox/proxmox'
import { privilegesKey } from '../../proxmox/useProxmox'
import { retryTransient, unwrap } from '../api'

// The Screen tab (FM-495): the VM's screen through the controller, for the
// QEMU guest(s) Fleet has associated with this machine. The panel and its
// noVNC dependency load only when the tab is opened.
const ProxmoxConsole = defineAsyncComponent(() => import('../../proxmox/console/ProxmoxConsole.vue'))

const props = defineProps<{
  guests: GuestItem[]
  loading: boolean
}>()

// Only QEMU guests have a VNC screen (an LXC console is out of scope).
const screens = computed(() => props.guests.filter((g): g is GuestItem & { vmid: number, node: string } =>
  g.vmid !== null && !!g.node && g.kind !== 'lxc'))

const chosen = ref<string | null>(null)
watch(screens, (list) => {
  if (!list.some(g => g.key === chosen.value))
    chosen.value = list[0]?.key ?? null
}, { immediate: true })
const guest = computed(() => screens.value.find(g => g.key === chosen.value) ?? null)

const privileges = useQuery({
  queryKey: computed(() => privilegesKey(guest.value?.accountId ?? '')),
  queryFn: async () => unwrap<ProxmoxPrivilegesDto>(await getProxmoxPrivileges(guest.value!.accountId)),
  enabled: computed(() => guest.value !== null),
  retry: retryTransient,
})
// A report that failed to load is not evidence either way: the controller
// stays the authority and explains any refusal.
const blocked = computed(() => privileges.error.value ? null : tierBlockReason(privileges.data.value, 'console'))
</script>

<template>
  <div class="space-y-4">
    <p
      v-if="loading && screens.length === 0"
      class="text-xs text-fc-faint"
    >
      Loading Proxmox guests…
    </p>
    <p
      v-else-if="screens.length === 0"
      class="text-sm text-fc-faint"
      data-testid="screen-no-guest"
    >
      No QEMU guest is associated with this machine, so there is no screen to show.
    </p>
    <template v-else-if="guest">
      <label
        v-if="screens.length > 1"
        class="flex flex-col gap-1 text-xs"
      >
        <span class="fc-kicker">Guest</span>
        <select
          v-model="chosen"
          class="h-8 w-64 rounded-sm border border-input bg-background px-2 text-foreground"
          data-testid="screen-guest"
        >
          <option
            v-for="g in screens"
            :key="g.key"
            :value="g.key"
          >
            VM {{ g.vmid }} {{ g.name ?? '' }} · {{ g.node }}
          </option>
        </select>
      </label>
      <p
        class="text-[11px] text-fc-faint"
        data-testid="screen-lan-note"
      >
        On a trusted-LAN controller every caller is the same principal: any client that can reach it may open consoles, and the session limit is shared.
      </p>
      <ProxmoxConsole
        :key="guest.key"
        :account-id="guest.accountId"
        :node="guest.node"
        :vmid="guest.vmid"
        :guest-status="guest.status"
        :blocked-reason="blocked"
      />
    </template>
  </div>
</template>
