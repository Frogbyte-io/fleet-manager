<script setup lang="ts">
import { computed } from 'vue'

import type { LabTemplateDto, ProvisionRecordDto } from '@frogbyte-io/fleet-api-client'
import StatusChip from '@/components/fleet/StatusChip.vue'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'

import { relativeTime, type Tone } from '../../fleet/inventory'
import { leaseTone, shortId, templatesByVersion } from '../lab'

// Provisioning records: the durable saga state for each guest the Lab cloned,
// with the external IDs it recorded (node, VMID, clone task, guest IP). The
// Fate column adds what became of the guest and, when a lease links back to
// the record, that lease's state.
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

/** The guest's fate (API `guest`): saga state alone does not say it still exists. */
function guestTone(guest: string): Tone {
  switch (guest) {
    case 'present': return 'ok'
    case 'destroyed': return 'muted'
    case 'kept':
    case 'returned_to_pool': return 'info'
    case 'quarantined_in_pool': return 'warn'
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
          Fate
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
        <TableCell data-testid="saga-state">
          <StatusChip
            :label="record.state.replaceAll('_', ' ')"
            :tone="tone(record.state)"
          />
        </TableCell>
        <TableCell data-testid="fate-cell">
          <StatusChip
            :label="(record.guest ?? '').replaceAll('_', ' ')"
            :tone="guestTone(record.guest ?? '')"
            data-testid="guest-fate"
          />
          <div
            v-if="record.leaseState"
            class="mt-1"
            data-testid="lease-state"
          >
            <StatusChip
              :label="`lease ${record.leaseState.replaceAll('_', ' ')}`"
              :tone="leaseTone(record.leaseState)"
            />
          </div>
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
