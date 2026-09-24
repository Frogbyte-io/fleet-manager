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
import {
  guestStatusTone,
  machineStatusTone,
  osLine,
  relativeTime,
  resourcesLine,
  specLine,
  type GuestItem,
  type HostItem,
  type MachineItem,
  type TailnetItem,
} from '../inventory'

defineProps<{
  hosts: HostItem[]
  guests: GuestItem[]
  machines: MachineItem[]
  tailnetOnly: TailnetItem[]
}>()

const emit = defineEmits<{
  'open-machine': [machineId: string]
  'open-guest': [guestKey: string]
}>()

const headClass = 'font-mono text-[10px] uppercase font-semibold text-fc-faint [letter-spacing:.14em]'

function guestsOf(host: HostItem, guests: GuestItem[]): GuestItem[] {
  return guests.filter(g => g.node === host.name)
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
        <TableRow class="border-fc-line bg-fc-inset hover:bg-fc-inset">
          <TableCell class="font-semibold text-fc-ink">
            {{ host.name }}
          </TableCell>
          <TableCell class="font-mono text-[10px] uppercase text-fc-muted">
            HOST
          </TableCell>
          <TableCell>
            <StatusChip
              :label="host.status.toUpperCase()"
              :tone="host.status === 'online' ? 'ok' : 'err'"
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
        <TableRow
          v-for="guest in guestsOf(host, guests)"
          :key="guest.key"
          class="cursor-pointer border-fc-line"
          @click="emit('open-guest', guest.key)"
        >
          <TableCell class="pl-6 text-sm text-fc-ink">
            └ {{ guest.name }}
            <span class="block font-mono text-[10px] text-fc-faint">{{ guest.kind === 'vm' ? `QEMU ${guest.vmid}` : `LXC ${guest.vmid}` }}</span>
          </TableCell>
          <TableCell class="font-mono text-[10px] uppercase text-fc-muted">
            {{ guest.kind === 'vm' ? 'VM' : 'LXC' }}
          </TableCell>
          <TableCell>
            <StatusChip
              :label="guest.status.toUpperCase()"
              :tone="guestStatusTone(guest.status)"
            />
          </TableCell>
          <TableCell class="font-mono text-[10px] text-fc-muted">
            GUEST AGENT {{ guest.agentOnline === null ? '?' : guest.agentOnline ? 'OK' : '—' }}
          </TableCell>
          <TableCell class="font-mono text-[10px] text-fc-muted">
            {{ guest.osName ?? '—' }}
          </TableCell>
          <TableCell class="font-mono text-[10px] text-fc-muted">
            —
          </TableCell>
          <TableCell class="font-mono text-[10px] uppercase text-fc-faint">
            —
          </TableCell>
        </TableRow>
      </template>

      <TableRow class="border-fc-line bg-fc-inset hover:bg-fc-inset">
        <TableCell class="font-semibold text-fc-ink">
          Machines
        </TableCell>
        <TableCell
          v-for="i in 6"
          :key="i"
        />
      </TableRow>
      <TableRow
        v-if="machines.length === 0"
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
        v-for="machine in machines"
        :key="machine.id"
        class="cursor-pointer border-fc-line"
        @click="emit('open-machine', machine.id)"
      >
        <TableCell class="text-sm text-fc-ink">
          {{ machine.name }}
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
            :label="device.online ? 'ONLINE' : 'OFFLINE'"
            :tone="device.online ? 'ok' : 'faint'"
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
