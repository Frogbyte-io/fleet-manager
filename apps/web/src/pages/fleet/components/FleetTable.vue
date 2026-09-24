<script setup lang="ts">
import { RouterLink } from 'vue-router'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import StatusChip from '@/components/fleet/StatusChip.vue'
import GuestRow from './GuestRow.vue'
import {
  hostStatusLabel,
  hostStatusTone,
  machineStatusTone,
  osLine,
  relativeTime,
  resourcesLine,
  specLine,
  tailnetStatusLabel,
  type GuestItem,
  type HostItem,
  type MachineItem,
  type TailnetItem,
} from '../inventory'

defineProps<{
  hosts: HostItem[]
  contextHostKeys: Set<string>
  guests: GuestItem[]
  machineGroups: { name: string, machines: MachineItem[] }[]
  tailnetOnly: TailnetItem[]
  flat: boolean
}>()

const emit = defineEmits<{
  'open-machine': [machineId: string]
  'open-guest': [guestKey: string]
}>()

const headClass = 'font-mono text-[10px] uppercase font-semibold text-fc-faint [letter-spacing:.14em]'

function guestsOf(host: HostItem, guests: GuestItem[]): GuestItem[] {
  return guests.filter(g => g.accountId === host.accountId && g.node === host.nodeKey)
}
</script>

<template>
  <Table>
    <TableHeader>
      <TableRow class="border-fc-line hover:bg-transparent">
        <TableHead :class="headClass">
          Name
        </TableHead>
        <TableHead :class="headClass">
          Kind
        </TableHead>
        <TableHead :class="headClass">
          Status
        </TableHead>
        <TableHead :class="headClass">
          Connections
        </TableHead>
        <TableHead :class="headClass">
          OS / Arch
        </TableHead>
        <TableHead :class="headClass">
          Resources
        </TableHead>
        <TableHead :class="headClass">
          Seen
        </TableHead>
      </TableRow>
    </TableHeader>
    <TableBody>
      <template
        v-for="host in hosts"
        :key="host.key"
      >
        <TableRow
          class="border-fc-line bg-fc-inset hover:bg-fc-inset"
          :class="{ 'opacity-60': contextHostKeys.has(host.key) }"
        >
          <TableCell class="font-semibold text-fc-ink">
            {{ host.name }}
          </TableCell>
          <TableCell class="font-mono text-[10px] uppercase text-fc-muted">
            HOST
          </TableCell>
          <TableCell>
            <StatusChip
              :label="hostStatusLabel(host.status)"
              :tone="hostStatusTone(host.status)"
            />
          </TableCell>
          <TableCell class="font-mono text-[10px] text-fc-muted">
            PVE API
          </TableCell>
          <TableCell class="font-mono text-[10px] text-fc-muted">
            PVE {{ host.pveVersion }}
          </TableCell>
          <TableCell class="font-mono text-[10px] text-fc-muted">
            {{ host.guestCount }} GUESTS · {{ host.templateCount }} TPL
          </TableCell>
          <TableCell class="font-mono text-[10px] uppercase text-fc-faint">
            {{ relativeTime(host.observedAt) }}
          </TableCell>
        </TableRow>
        <template v-if="!flat">
          <GuestRow
            v-for="guest in guestsOf(host, guests)"
            :key="guest.key"
            :guest="guest"
            nested
            @open-guest="emit('open-guest', $event)"
          />
        </template>
      </template>
      <template v-if="flat">
        <GuestRow
          v-for="guest in guests"
          :key="guest.key"
          :guest="guest"
          :nested="false"
          :context-host="guest.node"
          @open-guest="emit('open-guest', $event)"
        />
      </template>

      <template
        v-for="group in machineGroups"
        :key="group.name || '_machines'"
      >
        <TableRow
          v-if="group.name"
          class="border-fc-line bg-fc-inset hover:bg-fc-inset"
        >
          <TableCell class="font-semibold text-fc-ink">
            {{ group.name }}
          </TableCell>
          <TableCell
            v-for="i in 6"
            :key="i"
          />
        </TableRow>
        <TableRow
          v-if="group.machines.length === 0 && !group.name"
          class="border-fc-line"
        >
          <TableCell
            colspan="7"
            class="text-xs text-fc-faint"
          >
            No machines yet —
            <RouterLink
              to="/fleet/add"
              class="underline decoration-dotted hover:text-fc-ink"
            >
              Add machine
            </RouterLink>
          </TableCell>
        </TableRow>
        <TableRow
          v-for="machine in group.machines"
          :key="machine.id"
          class="cursor-pointer border-fc-line"
          @click="emit('open-machine', machine.id)"
        >
          <TableCell class="text-sm text-fc-ink">
            <button
              type="button"
              class="text-left text-sm text-fc-ink"
              @click.stop="emit('open-machine', machine.id)"
            >
              {{ machine.name }}
            </button>
            <span class="block font-mono text-[10px] text-fc-faint">{{ specLine(machine) }}</span>
          </TableCell>
          <TableCell class="font-mono text-[10px] uppercase text-fc-muted">
            MACHINE
          </TableCell>
          <TableCell>
            <StatusChip
              :label="machine.status"
              :tone="machineStatusTone(machine.status)"
            />
          </TableCell>
          <TableCell class="font-mono text-[10px] text-fc-muted">
            {{ machine.endpointKinds.join(' · ') || '—' }}<template v-if="machine.tailnet">
              · TAILSCALE
            </template>
          </TableCell>
          <TableCell class="font-mono text-[10px] text-fc-muted">
            {{ osLine(machine) ?? '—' }}
          </TableCell>
          <TableCell class="font-mono text-[10px] text-fc-muted">
            {{ resourcesLine(machine) ?? '—' }}
          </TableCell>
          <TableCell class="font-mono text-[10px] uppercase text-fc-faint">
            {{ relativeTime(machine.lastSeenAt ?? machine.lastObservation?.collectedAt ?? null) }}
          </TableCell>
        </TableRow>
      </template>

      <TableRow
        v-if="tailnetOnly.length > 0"
        class="border-fc-line bg-fc-inset hover:bg-fc-inset"
      >
        <TableCell class="font-semibold text-fc-ink">
          Tailnet — not in Fleet
        </TableCell>
        <TableCell
          v-for="i in 6"
          :key="i"
        />
      </TableRow>
      <TableRow
        v-for="device in tailnetOnly"
        :key="device.nodeId"
        class="border-fc-line"
      >
        <TableCell class="text-sm text-fc-ink">
          {{ device.name }}
          <span class="block font-mono text-[10px] text-fc-faint">{{ device.os }} · {{ device.addresses[0] ?? '—' }}</span>
        </TableCell>
        <TableCell class="font-mono text-[10px] uppercase text-fc-muted">
          TAILNET
        </TableCell>
        <TableCell>
          <StatusChip
            :label="tailnetStatusLabel(device.online)"
            :tone="device.online ? 'ok' : device.online === null ? 'faint' : 'faint'"
          />
        </TableCell>
        <TableCell class="font-mono text-[10px] text-fc-muted">
          —
        </TableCell>
        <TableCell class="font-mono text-[10px] text-fc-muted">
          {{ device.os }}
        </TableCell>
        <TableCell class="font-mono text-[10px] text-fc-muted">
          —
        </TableCell>
        <TableCell class="font-mono text-[10px] uppercase text-fc-faint">
          —
        </TableCell>
      </TableRow>
    </TableBody>
  </Table>
</template>
