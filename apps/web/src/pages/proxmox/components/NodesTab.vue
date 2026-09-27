<script setup lang="ts">
import StatusChip from '@/components/fleet/StatusChip.vue'

import { formatBytes, hostStatusLabel, hostStatusTone, relativeTime } from '../../fleet/inventory'
import { pveUrl, ratio, type NodeRow } from '../proxmox'
import UsageBar from './UsageBar.vue'

// Nodes with their FM-915 capacity observations.
defineProps<{ rows: NodeRow[], hosts: Map<string, { host: string, port: number }> }>()
</script>

<template>
  <p
    v-if="rows.length === 0"
    class="mt-4 rounded-sm border border-fc-line p-6 text-sm text-fc-muted"
    data-testid="nodes-empty"
  >
    No nodes discovered. Nodes appear once an account is pinned and discovery succeeds.
  </p>
  <div
    v-else
    class="mt-4 grid gap-3 md:grid-cols-2 xl:grid-cols-3"
  >
    <article
      v-for="row in rows"
      :key="`${row.accountId}/${row.node}`"
      class="space-y-2 rounded-sm border border-fc-line bg-card p-4"
      :data-testid="`node-${row.node}`"
    >
      <div class="flex items-start gap-2">
        <div class="min-w-0">
          <p class="truncate text-sm font-semibold text-fc-ink">
            {{ row.node }}
          </p>
          <p class="fc-kicker">
            {{ row.accountName }} · PVE {{ row.pveVersion }}
          </p>
        </div>
        <StatusChip
          class="ml-auto"
          :label="hostStatusLabel(row.status ?? 'unknown')"
          :tone="hostStatusTone(row.status ?? 'unknown')"
        />
      </div>
      <template v-if="row.capacity">
        <UsageBar
          label="CPU"
          :value="row.capacity.cpuUsageRatio ?? null"
          :detail="row.capacity.cpuCount ? `${row.capacity.cpuCount} CPUs` : null"
        />
        <UsageBar
          label="MEM"
          :value="ratio(row.capacity.memoryUsedBytes, row.capacity.memoryTotalBytes)"
          :detail="row.capacity.memoryTotalBytes ? `${formatBytes(row.capacity.memoryUsedBytes ?? null) ?? '—'} / ${formatBytes(row.capacity.memoryTotalBytes)}` : null"
        />
        <UsageBar
          v-for="storage in row.capacity.storages"
          :key="storage.storage"
          :label="storage.storage"
          :value="ratio(storage.usedBytes, storage.totalBytes)"
          :detail="`${formatBytes(storage.usedBytes)} / ${formatBytes(storage.totalBytes)}`"
        />
      </template>
      <p
        v-else
        class="font-mono text-[10.5px] text-fc-faint"
      >
        No capacity observation for this node.
      </p>
      <div class="flex items-center gap-2 border-t border-fc-line pt-2 font-mono text-[10px] uppercase tracking-wide text-fc-faint">
        <span>{{ row.guestCount }} guests · {{ row.templateCount }} templates</span>
        <span v-if="row.capacity">· seen {{ relativeTime(row.capacity.observedAt) }}</span>
        <a
          v-if="hosts.get(row.accountId)"
          :href="pveUrl(hosts.get(row.accountId)!, { type: 'node', id: row.node })"
          target="_blank"
          rel="noopener noreferrer"
          class="ml-auto text-fc-info hover:text-fc-ink"
        >PVE ↗</a>
      </div>
    </article>
  </div>
</template>
