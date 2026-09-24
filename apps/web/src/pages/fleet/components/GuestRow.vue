<script setup lang="ts">
import { TableRow, TableCell } from '@/components/ui/table'
import StatusChip from '@/components/fleet/StatusChip.vue'
import {
  guestAgentCell,
  guestStatusTone,
  type GuestItem,
} from '../inventory'

defineProps<{
  guest: GuestItem
  nested: boolean
  contextHost?: string
}>()

const emit = defineEmits<{
  'open-guest': [guestKey: string]
}>()
</script>

<template>
  <TableRow
    class="cursor-pointer border-fc-line"
    @click="emit('open-guest', guest.key)"
  >
    <TableCell :class="nested ? 'pl-6 text-sm' : 'text-sm'">
      <button
        type="button"
        class="text-left text-sm text-fc-ink"
        @click.stop="emit('open-guest', guest.key)"
      >
        <template v-if="nested">└ {{ guest.name }}</template>
        <template v-else>{{ guest.name }}</template>
      </button>
      <span class="block font-mono text-[10px] text-fc-faint">
        {{ guest.kind === 'vm' ? `QEMU ${guest.vmid ?? '—'}` : `LXC ${guest.vmid ?? '—'}` }}<template v-if="!nested && contextHost"> · {{ contextHost }}</template><template v-else-if="!nested"> · {{ guest.node }}</template>
      </span>
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
      GUEST AGENT {{ guestAgentCell(guest.agentOnline) }}
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
