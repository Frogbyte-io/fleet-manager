<script setup lang="ts">
import ConnectionBadge from '@/components/fleet/ConnectionBadge.vue'
import KindIcon from '@/components/fleet/KindIcon.vue'
import StatusChip from '@/components/fleet/StatusChip.vue'
import { hostStatusLabel, hostStatusTone, relativeTime, type GuestItem, type HostItem } from '../inventory'

defineProps<{
  host: HostItem
  guests: GuestItem[]
  context?: boolean
}>()
</script>

<template>
  <article
    class="fc-card rounded-sm border border-fc-line bg-fc-panel p-4"
    :class="{ 'opacity-60': context }"
  >
    <div class="flex items-start gap-3">
      <KindIcon kind="host" />
      <div class="min-w-0 flex-1">
        <p class="truncate text-sm font-semibold text-fc-ink">
          {{ host.name }}
        </p>
        <p class="fc-kicker mt-0.5">
          PROXMOX NODE · {{ host.accountName }}
        </p>
      </div>
      <StatusChip
        :label="hostStatusLabel(host.status)"
        :tone="hostStatusTone(host.status)"
      />
    </div>

    <p class="mt-3 font-mono text-[10px] uppercase tracking-wide text-fc-muted">
      PVE {{ host.pveVersion }} · {{ host.guestCount }} GUESTS · {{ host.templateCount }} TEMPLATES
    </p>

    <div class="mt-3">
      <ConnectionBadge
        label="PVE API"
        dot="ok"
      />
    </div>

    <div
      v-if="guests.length > 0"
      class="mt-3 border-t border-fc-line pt-2"
    >
      <p
        v-for="guest in guests"
        :key="guest.key"
        class="truncate font-mono text-[10px] text-fc-faint"
      >
        └ {{ guest.kind === 'vm' ? 'VM' : 'LXC' }} {{ guest.vmid ?? '—' }} · {{ guest.name }} · {{ guest.status }}
      </p>
    </div>

    <div class="mt-3 border-t border-fc-line pt-2">
      <span class="font-mono text-[9.5px] uppercase tracking-wider text-fc-faint">
        SEEN {{ relativeTime(host.observedAt) }}
      </span>
    </div>
  </article>
</template>
