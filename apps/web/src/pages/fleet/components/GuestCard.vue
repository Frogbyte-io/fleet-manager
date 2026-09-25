<script setup lang="ts">
import { RouterLink } from 'vue-router'

import ConnectionBadge from '@/components/fleet/ConnectionBadge.vue'
import KindIcon from '@/components/fleet/KindIcon.vue'
import StatusChip from '@/components/fleet/StatusChip.vue'
import { guestStatusTone, type GuestItem } from '../inventory'

defineProps<{ guest: GuestItem }>()
</script>

<template>
  <article
    class="fc-card rounded-sm p-4"
    :class="guest.candidates.length > 0
      ? 'border border-fc-line bg-fc-panel'
      : 'border border-dashed border-fc-line bg-transparent'"
  >
    <div class="flex items-start gap-3">
      <KindIcon :kind="guest.kind === 'lxc' ? 'lxc' : 'vm'" />
      <div class="min-w-0 flex-1">
        <p class="truncate text-sm font-semibold text-fc-ink">
          {{ guest.name }}
        </p>
        <p class="fc-kicker mt-0.5">
          {{ guest.kind === 'vm' ? `VM · QEMU ${guest.vmid ?? '—'}` : `LXC ${guest.vmid ?? '—'}` }} · ON {{ guest.node }}
        </p>
      </div>
      <StatusChip
        :label="guest.status.toUpperCase()"
        :tone="guestStatusTone(guest.status)"
      />
    </div>

    <p
      v-if="guest.osName"
      class="mt-3 font-mono text-[10px] uppercase tracking-wide text-fc-muted"
    >
      {{ guest.osName }}
    </p>

    <div class="mt-3">
      <ConnectionBadge
        :label="guest.agentOnline === null ? 'GUEST AGENT —' : guest.agentOnline ? 'GUEST AGENT ONLINE' : 'GUEST AGENT OFFLINE'"
        :dot="guest.agentOnline ? 'ok' : 'faint'"
      />
    </div>

    <div
      v-if="guest.candidates.length > 0"
      class="mt-3 font-mono text-[10px] text-fc-info"
    >
      <p
        v-for="candidate in guest.candidates"
        :key="candidate.machineId"
      >
        ≈
        <RouterLink
          :to="`/fleet/machines/${candidate.machineId}?tab=guest`"
          class="underline decoration-dotted hover:text-fc-ink"
        >
          {{ candidate.machineName }}
        </RouterLink>
        ({{ candidate.evidence }})
      </p>
    </div>
    <p
      v-else
      class="mt-3 border-t border-dashed border-fc-line pt-2 font-mono text-[10px] uppercase tracking-wide text-fc-faint"
    >
      NOT LINKED TO A FLEET MACHINE
    </p>
  </article>
</template>
