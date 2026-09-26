<script setup lang="ts">
import { computed } from 'vue'

import type { LabTemplateDto, ProvisionRecordDto } from '@frogbyte-io/fleet-api-client'
import StatusChip from '@/components/fleet/StatusChip.vue'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'

import { relativeTime, type Tone } from '../../fleet/inventory'
import { shortId, templatesByVersion } from '../lab'

// Provisioning records: the durable saga state for each guest the Lab cloned,
// with the external IDs it recorded (node, VMID, clone task, guest IP). The
// API does not link a record to a lease, so this list stands on its own.
const props = defineProps<{ provisions: ProvisionRecordDto[], templates: LabTemplateDto[], now: number, loading: boolean }>()

const byVersion = computed(() => templatesByVersion(props.templates))
const rows = computed(() => [...props.provisions].sort((a, b) => b.createdAt - a.createdAt))

/** fleet-core `GuestState`: provisioning → provisioned → ready | never_ready. */
function tone(state: string): Tone {
  switch (state) {
    case 'ready': return 'ok'
    case 'provisioning':
    case 'provisioned': return 'info'
    case 'never_ready': return 'err'
    default: return 'faint'
  }
}

const headClass = 'font-mono text-[10px] font-semibold uppercase tracking-[.14em] text-fc-faint'
</script>

<template>
  <p
    v-if="loading"
    class="rounded-sm border border-fc-line bg-card p-6 text-center text-sm text-fc-muted"
  >
    Loading provisioning records…
  </p>
  <p
    v-else-if="rows.length === 0"
    class="rounded-sm border border-fc-line bg-card p-6 text-center text-sm text-fc-muted"
  >
    No provisioning records yet.
  </p>
  <Table
    v-else
    class="rounded-sm border border-fc-line bg-card"
  >
    <TableHeader>
      <TableRow>
        <TableHead :class="headClass">
          Record
        </TableHead>
        <TableHead :class="headClass">
          State
        </TableHead>
        <TableHead :class="headClass">
          Template
        </TableHead>
        <TableHead :class="headClass">
          Guest
        </TableHead>
        <TableHead :class="headClass">
          Started
        </TableHead>
        <TableHead :class="headClass">
          Ready
        </TableHead>
      </TableRow>
    </TableHeader>
    <TableBody>
      <TableRow
        v-for="record in rows"
        :key="record.id"
      >
        <TableCell class="font-mono text-xs">
          {{ shortId(record.id) }}
        </TableCell>
        <TableCell>
          <StatusChip
            :label="record.state.replace('_', ' ')"
            :tone="tone(record.state)"
          />
        </TableCell>
        <TableCell class="text-xs">
          {{ byVersion.get(record.templateVersionId)?.name ?? `version ${shortId(record.templateVersionId)}` }}
        </TableCell>
        <TableCell class="font-mono text-xs">
          <template v-if="record.vmid != null">
            QEMU {{ record.vmid }} · {{ record.node ?? '—' }}
          </template>
          <template v-else>
            NOT CLONED YET
          </template>
          <div
            v-if="record.guestIpv4"
            class="text-fc-faint"
          >
            {{ record.guestIpv4 }}
          </div>
          <div
            v-else-if="record.cloneUpid"
            class="text-fc-faint"
          >
            CLONE TASK RUNNING
          </div>
        </TableCell>
        <TableCell class="font-mono text-xs">
          {{ relativeTime(record.createdAt, now) }}
        </TableCell>
        <TableCell class="font-mono text-xs">
          {{ record.readyAt != null ? relativeTime(record.readyAt, now) : '—' }}
        </TableCell>
      </TableRow>
    </TableBody>
  </Table>
</template>
