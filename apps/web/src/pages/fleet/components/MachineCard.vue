<script setup lang="ts">
import ConnectionBadge from '@/components/fleet/ConnectionBadge.vue'
import KindIcon from '@/components/fleet/KindIcon.vue'
import StatusChip from '@/components/fleet/StatusChip.vue'
import { machineStatusTone, relativeTime, specLine, type MachineItem } from '../inventory'

defineProps<{ machine: MachineItem }>()
</script>

<template>
  <article class="fc-card flex flex-col gap-3 rounded-sm border border-fc-line bg-fc-panel p-4">
    <div class="flex items-start gap-3">
      <KindIcon kind="machine" />
      <div class="min-w-0 flex-1">
        <p class="truncate text-sm font-semibold text-fc-ink">
          {{ machine.name }}
        </p>
        <p class="fc-kicker mt-0.5">
          MACHINE · {{ machine.tags.length > 0 ? machine.tags[0] : (machine.endpointKinds[0] ?? 'NO ENDPOINT') }}
        </p>
      </div>
      <StatusChip
        :label="machine.status"
        :tone="machineStatusTone(machine.status)"
      />
    </div>

    <p class="font-mono text-[10px] uppercase tracking-wide text-fc-muted">
      {{ specLine(machine) || 'SPEC UNKNOWN' }}
    </p>

    <div class="flex flex-wrap gap-1.5">
      <ConnectionBadge
        v-if="machine.endpointKinds.includes('fleetd')"
        label="FLEETD"
        :dot="machine.status === 'connected' ? 'ok' : machine.status === 'stale' ? 'warn' : machine.status === 'offline' ? 'err' : 'faint'"
      />
      <ConnectionBadge
        v-if="machine.endpointKinds.includes('ssh')"
        label="SSH"
        dot="faint"
      />
      <ConnectionBadge
        v-if="machine.tailnet"
        label="TAILSCALE"
        :dot="machine.tailnet.online ? 'ok' : 'faint'"
      />
    </div>

    <p
      v-if="machine.guestCandidates.length > 0"
      class="font-mono text-[10px] text-fc-info"
    >
      ≈ {{ machine.guestCandidates[0].kind === 'lxc' ? 'LXC' : 'QEMU' }} {{ machine.guestCandidates[0].vmid ?? '—' }} ON {{ machine.guestCandidates[0].node }} ({{ machine.guestCandidates[0].evidence }})
    </p>

    <div
      v-if="machine.tags.length > 0"
      class="flex flex-wrap gap-1"
    >
      <span
        v-for="tag in machine.tags"
        :key="tag"
        class="rounded-sm border border-fc-line px-1.5 py-px font-mono text-[9.5px] uppercase text-fc-faint"
      >{{ tag }}</span>
    </div>

    <div class="mt-auto flex items-center justify-between border-t border-fc-line pt-2">
      <span class="font-mono text-[9.5px] uppercase tracking-wider text-fc-faint">
        SEEN {{ relativeTime(machine.lastSeenAt ?? machine.lastObservation?.collectedAt ?? null) }}
      </span>
      <slot name="actions" />
    </div>
  </article>
</template>
