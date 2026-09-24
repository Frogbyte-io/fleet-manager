<script setup lang="ts">
import { computed } from 'vue'
import { RouterLink } from 'vue-router'

import type { MachineDto } from '@frogbyte-io/fleet-api-client'

import { osLine, relativeTime, resourcesLine, type GuestItem, type MachineItem } from '../../fleet/inventory'
import { absoluteTime, statusCounts } from '../facts'

const props = defineProps<{
  machine: MachineDto
  item: MachineItem | null
  guests: GuestItem[]
}>()

const counts = computed(() => statusCounts(props.machine.capabilities))
</script>

<template>
  <div class="grid gap-6 lg:grid-cols-2">
    <section>
      <h2 class="fc-kicker border-b-2 border-fc-ink pb-1">
        Summary
      </h2>
      <dl class="mt-3 grid grid-cols-[140px_1fr] gap-x-3 gap-y-2 text-xs">
        <dt class="text-fc-faint">
          Status
        </dt>
        <dd class="font-mono uppercase text-fc-ink">
          {{ machine.machineStatus }}
        </dd>
        <dt class="text-fc-faint">
          Last seen (gateway)
        </dt>
        <dd
          class="font-mono text-fc-ink"
          :title="absoluteTime(machine.lastSeenAt)"
        >
          {{ relativeTime(machine.lastSeenAt ?? null) }}
        </dd>
        <dt class="text-fc-faint">
          Last inventory
        </dt>
        <dd class="font-mono text-fc-ink">
          <template v-if="machine.lastObservation">
            {{ machine.lastObservation.source }} · {{ relativeTime(machine.lastObservation.collectedAt) }}
          </template>
          <template v-else>
            Never probed
          </template>
        </dd>
        <dt class="text-fc-faint">
          OS
        </dt>
        <dd class="font-mono text-fc-ink">
          {{ (item && osLine(item)) ?? 'Not observed yet' }}
        </dd>
        <dt class="text-fc-faint">
          Hardware
        </dt>
        <dd class="font-mono text-fc-ink">
          {{ (item && resourcesLine(item)) ?? 'Not observed yet' }}
        </dd>
        <dt class="text-fc-faint">
          Facts
        </dt>
        <dd class="font-mono text-fc-ink">
          {{ machine.capabilities.length }}
          <span class="text-fc-faint">
            ({{ Object.entries(counts).map(([status, n]) => `${n} ${status}`).join(' · ') || 'none' }})
          </span>
        </dd>
        <dt class="text-fc-faint">
          Tags
        </dt>
        <dd class="font-mono text-fc-ink">
          {{ machine.tags.join(', ') || '—' }}
        </dd>
        <dt class="text-fc-faint">
          Groups
        </dt>
        <dd class="font-mono text-fc-ink">
          {{ machine.groups.join(', ') || '—' }}
        </dd>
        <dt class="text-fc-faint">
          Registered
        </dt>
        <dd class="font-mono text-fc-ink">
          {{ absoluteTime(machine.createdAt) }}
        </dd>
      </dl>
      <p
        v-if="machine.description"
        class="mt-4 whitespace-pre-wrap text-sm text-fc-muted"
      >
        {{ machine.description }}
      </p>
    </section>

    <section>
      <h2 class="fc-kicker border-b-2 border-fc-ink pb-1">
        Connectivity
      </h2>
      <dl class="mt-3 grid grid-cols-[140px_1fr] gap-x-3 gap-y-2 text-xs">
        <dt class="text-fc-faint">
          Endpoints
        </dt>
        <dd class="font-mono text-fc-ink">
          <div
            v-for="endpoint in machine.endpoints"
            :key="endpoint.id"
          >
            {{ endpoint.kind }} · {{ endpoint.reference }}
          </div>
          <div v-if="machine.endpoints.length === 0">
            —
          </div>
        </dd>
        <dt class="text-fc-faint">
          Tailscale
        </dt>
        <dd class="font-mono text-fc-ink">
          <template v-if="item?.tailnet">
            {{ item.tailnet.name }} · {{ item.tailnet.addresses.join(', ') }} ·
            {{ item.tailnet.online === null ? 'UNKNOWN' : item.tailnet.online ? 'ONLINE' : 'OFFLINE' }}
          </template>
          <template v-else>
            Not correlated with a tailnet device
          </template>
        </dd>
        <dt class="text-fc-faint">
          Proxmox guest
        </dt>
        <dd class="font-mono text-fc-info">
          <div
            v-for="guest in guests"
            :key="guest.key"
          >
            ≈ {{ guest.kind === 'lxc' ? 'LXC' : 'QEMU' }} {{ guest.vmid ?? '—' }} on {{ guest.node }} ({{ guest.accountName }})
          </div>
          <div
            v-if="guests.length === 0"
            class="text-fc-ink"
          >
            No candidate guest
          </div>
          <RouterLink
            v-else
            :to="{ query: { tab: 'guest' } }"
            class="mt-1 inline-block font-mono text-[10px] uppercase tracking-wider text-fc-info hover:text-fc-ink"
          >
            Guest tab →
          </RouterLink>
        </dd>
      </dl>
    </section>
  </div>
</template>
