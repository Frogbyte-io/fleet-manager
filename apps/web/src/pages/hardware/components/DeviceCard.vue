<script setup lang="ts">
import { computed } from 'vue'
import { RouterLink } from 'vue-router'

import type { HardwareDeviceDto } from '@frogbyte-io/fleet-api-client'
import StatusChip from '@/components/fleet/StatusChip.vue'

import { relativeTime } from '../../fleet/inventory'
import {
  entryId,
  entryName,
  guestLabel,
  holderLink,
  holderTone,
  observedLabel,
  reasonLabel,
  seenLabel,
  statusTone,
  type SessionObservation,
  words,
} from '../hardware'

// One PVE USB resource mapping. Every value is the API's: the status and its
// reason are the controller's, `stale` is its freshness bound, the holder is
// the live reservation. `observation` is only present for a device that came
// back from a refresh in this session (the list makes no Proxmox call); it is
// dated, and reduced to a notice once the list no longer agrees with it.
const props = defineProps<{
  device: HardwareDeviceDto
  accountName: string
  now: number
  observation?: SessionObservation | null
}>()

const reason = computed(() => reasonLabel(props.device))
const holder = computed(() => props.device.holder ?? null)
const link = computed(() => (holder.value ? holderLink(holder.value) : null))
const hasObservation = computed(() => !!props.observation
  && (props.observation.superseded
    || props.observation.data.externalReferences.length > 0
    || props.observation.data.notes.length > 0))

const labelClass = 'fc-kicker'
</script>

<template>
  <article
    class="space-y-3 rounded-sm border border-fc-line bg-card p-4"
    :data-testid="`device-${device.mappingId}`"
    :data-status="device.status"
    :data-stale="device.stale"
  >
    <header class="flex flex-wrap items-start gap-x-3 gap-y-2">
      <div class="min-w-0 flex-1">
        <p :class="labelClass">
          {{ accountName }} · {{ device.kind }}
        </p>
        <h3
          class="break-all font-mono text-[15px] font-bold"
          data-testid="mapping-id"
        >
          {{ device.mappingId }}
        </h3>
      </div>
      <div class="flex flex-wrap items-center gap-1.5">
        <StatusChip
          :label="words(device.status)"
          :tone="statusTone(device.status)"
          data-testid="status"
        />
        <StatusChip
          v-if="device.stale"
          label="stale"
          tone="warn"
          data-testid="stale"
        />
      </div>
    </header>

    <div
      v-if="device.status === 'unsupported' || reason"
      class="border-l-2 border-l-fc-line2 bg-fc-inset px-3 py-2"
      data-testid="reason"
    >
      <p
        v-if="device.reason"
        class="font-mono text-[11px] text-fc-muted"
        data-testid="reason-code"
      >
        {{ device.reason }}
      </p>
      <p
        v-if="reason"
        class="text-xs text-fc-ink"
        data-testid="reason-text"
      >
        {{ reason }}
      </p>
    </div>

    <section
      v-if="holder"
      class="space-y-1 border-l-2 bg-fc-inset px-3 py-2"
      :class="holder.state === 'attach_unknown' || holder.state === 'detach_failed' ? 'border-l-fc-err' : 'border-l-fc-info'"
      data-testid="holder"
    >
      <div class="flex flex-wrap items-center gap-2">
        <span :class="labelClass">Held by</span>
        <span class="text-xs font-semibold">{{ holder.ownerKind }}</span>
        <RouterLink
          v-if="link"
          :to="link"
          class="break-all font-mono text-xs text-fc-info hover:text-fc-ink"
          data-testid="holder-link"
        >
          {{ holder.ownerId }}
        </RouterLink>
        <span
          v-else
          class="break-all font-mono text-xs"
          data-testid="holder-owner"
        >{{ holder.ownerId }}</span>
        <StatusChip
          :label="words(holder.state)"
          :tone="holderTone(holder.state)"
          data-testid="holder-state"
        />
      </div>
      <p class="font-mono text-[11px] text-fc-muted">
        <template v-if="holder.guest">
          <span data-testid="holder-guest">{{ guestLabel(holder.guest) }}</span> ·
        </template>
        reserved {{ relativeTime(holder.reservedAt, now) }}
      </p>
    </section>

    <section data-testid="entries">
      <p :class="labelClass">
        Node entries
      </p>
      <p
        v-if="device.entries.length === 0"
        class="mt-1 text-xs text-fc-muted"
        data-testid="no-entries"
      >
        No node entry reported for this mapping.
      </p>
      <ul
        v-else
        class="mt-1 divide-y divide-fc-line"
      >
        <li
          v-for="entry in device.entries"
          :key="entry.node"
          class="flex flex-wrap items-baseline gap-x-3 gap-y-0.5 py-1.5 text-xs"
          data-testid="entry"
        >
          <span class="font-mono font-semibold">{{ entry.node }}</span>
          <span class="font-mono text-fc-muted">{{ entryId(entry) }}</span>
          <span
            v-if="entry.usbpath"
            class="font-mono text-fc-muted"
          >port {{ entry.usbpath }}</span>
          <span
            v-if="entryName(entry)"
            class="text-fc-ink"
          >{{ entryName(entry) }}</span>
          <span class="ml-auto font-mono text-[10px] uppercase tracking-wider text-fc-faint">seen {{ seenLabel(entry.lastSeenAt, now) }}</span>
        </li>
      </ul>
    </section>

    <section
      v-if="hasObservation && observation"
      class="space-y-1 border-l-2 border-l-fc-warn bg-fc-inset px-3 py-2"
      data-testid="observation"
    >
      <p :class="labelClass">
        Found by the refresh {{ relativeTime(observation.takenAt, now) }}
      </p>
      <p
        v-if="observation.superseded"
        class="text-xs text-fc-muted"
        data-testid="observation-superseded"
      >
        The list has changed since that refresh, so what it found is not shown.
      </p>
      <ul
        v-else-if="observation.data.externalReferences.length"
        class="space-y-0.5"
      >
        <li
          v-for="reference in observation.data.externalReferences"
          :key="`${reference.node}-${reference.vmid}-${reference.slot}`"
          class="font-mono text-[11px]"
          data-testid="external-reference"
        >
          {{ reference.template ? 'template' : 'guest' }} QEMU {{ reference.vmid }}<template v-if="reference.guestName">
            ({{ reference.guestName }})
          </template>
          · {{ reference.node }} · {{ reference.slot }}<template v-if="reference.pending">
            · pending {{ reference.pending }}
          </template>
        </li>
      </ul>
      <p
        v-for="note in observation.superseded ? [] : observation.data.notes"
        :key="note"
        class="text-xs text-fc-muted"
        data-testid="observation-note"
      >
        {{ note }}
      </p>
    </section>

    <p
      v-if="device.note"
      class="text-xs text-fc-muted"
      data-testid="note"
    >
      {{ device.note }}
    </p>

    <footer class="font-mono text-[10px] uppercase tracking-wider text-fc-faint">
      <span data-testid="observed">{{ observedLabel(device, now) }}</span><template v-if="device.entries.length">
        · updated {{ relativeTime(device.updatedAt, now) }}
      </template>
    </footer>
  </article>
</template>
