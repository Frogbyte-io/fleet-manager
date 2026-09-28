<script setup lang="ts">
import { computed } from 'vue'
import { RouterLink } from 'vue-router'

import StatusChip from '@/components/fleet/StatusChip.vue'
import SystemPanel from '@/components/SystemPanel.vue'
import { Skeleton } from '@/components/ui/skeleton'

import { formatBytes, relativeTime } from '../fleet/inventory'
import UsageBar from '../proxmox/components/UsageBar.vue'
import { nodeRows, ratio } from '../proxmox/proxmox'
import { useOverview } from './useOverview'

// The landing view: how the fleet is, what needs a person, what just
// happened, and how much room the Proxmox nodes have
// (docs/planning/web-console.md, Overview).
const { attention, figures, feed, failures, loading, proxmox } = useOverview()

const nodes = computed(() => nodeRows(proxmox.views.value))

const KPIS = computed(() => [
  { label: 'Connected', value: figures.value.connected, to: '/fleet', tone: 'text-fc-ok' },
  { label: 'Agentless', value: figures.value.agentless, to: '/fleet', tone: 'text-fc-ink' },
  { label: 'Offline / stale', value: figures.value.unreachable, to: '/fleet', tone: figures.value.unreachable ? 'text-fc-err' : 'text-fc-ink' },
  { label: 'Lab leases', value: figures.value.leasesReady, detail: figures.value.leasesInProgress ? `+${figures.value.leasesInProgress} in progress` : 'ready', to: '/lab', tone: 'text-fc-ink' },
  { label: 'Running operations', value: figures.value.running, to: { path: '/operations' }, tone: figures.value.running ? 'text-fc-info' : 'text-fc-ink' },
])

const severityClass = { err: 'border-l-fc-err', warn: 'border-l-fc-warn', info: 'border-l-fc-info' } as const
const severityLabel = { err: 'error', warn: 'warning', info: 'to do' } as const
</script>

<template>
  <div>
    <p class="fc-kicker">
      controller
    </p>
    <h1 class="fc-h1">
      Overview
    </h1>

    <div
      class="mt-4 grid grid-cols-2 gap-2.5 md:grid-cols-5"
      data-testid="kpis"
    >
      <RouterLink
        v-for="kpi in KPIS"
        :key="kpi.label"
        :to="kpi.to"
        class="rounded-sm border border-fc-line bg-card px-3.5 py-3 hover:border-fc-muted"
        :data-testid="`kpi-${kpi.label}`"
      >
        <p class="fc-kicker">
          {{ kpi.label }}
        </p>
        <p
          class="font-head text-2xl font-extrabold"
          :class="kpi.tone"
        >
          {{ kpi.value }}
        </p>
        <p
          v-if="kpi.detail"
          class="font-mono text-[10px] text-fc-faint"
        >
          {{ kpi.detail }}
        </p>
      </RouterLink>
    </div>

    <div class="mt-6 grid gap-6 xl:grid-cols-[minmax(0,1fr)_minmax(0,420px)]">
      <section class="space-y-2">
        <h2 class="fc-kicker border-b-2 border-fc-ink pb-1">
          Needs attention <span class="text-fc-faint">{{ attention.length }}</span>
        </h2>
        <div
          v-if="failures.length"
          class="border-l-2 border-l-fc-err bg-card px-3 py-2 text-xs text-fc-muted"
          role="alert"
          data-testid="attention-failures"
        >
          Could not check {{ failures.join(', ') }}; the queue may be missing items from {{ failures.length === 1 ? 'that source' : 'those sources' }}.
        </div>
        <div
          v-if="loading"
          class="grid gap-2"
        >
          <Skeleton
            v-for="i in 3"
            :key="i"
            class="h-12 rounded-sm"
          />
        </div>
        <p
          v-else-if="attention.length === 0 && failures.length === 0"
          class="rounded-sm border border-fc-line p-6 text-sm text-fc-muted"
          data-testid="attention-empty"
        >
          Nothing needs attention.
        </p>
        <ul
          v-else
          class="space-y-1.5"
          data-testid="attention"
        >
          <li
            v-for="row in attention"
            :key="row.key"
          >
            <RouterLink
              :to="row.to"
              class="flex items-start gap-3 rounded-sm border border-l-2 border-fc-line bg-card px-3 py-2 hover:border-fc-muted"
              :class="severityClass[row.severity]"
              :data-testid="`attention-${row.source}`"
            >
              <span class="min-w-0 flex-1">
                <span class="block text-[13px] font-semibold text-fc-ink">{{ row.title }}</span>
                <span class="block text-xs text-fc-muted">{{ row.detail }}</span>
              </span>
              <span class="shrink-0 font-mono text-[10px] uppercase tracking-wider text-fc-faint">{{ severityLabel[row.severity] }} →</span>
            </RouterLink>
          </li>
        </ul>
        <p
          class="text-[11px] text-fc-faint"
          data-testid="drift-gap"
        >
          Skill drift is not listed yet: no read API exposes the drift the planner composes, and Fleet Git activation is not wired into the controller.
        </p>
      </section>

      <section class="space-y-2">
        <h2 class="fc-kicker flex items-center border-b-2 border-fc-ink pb-1">
          Activity
          <RouterLink
            to="/audit"
            class="ml-auto font-mono text-[10px] tracking-wider text-fc-info hover:text-fc-ink"
          >
            Audit log →
          </RouterLink>
        </h2>
        <p
          v-if="feed.length === 0"
          class="text-xs text-fc-muted"
        >
          No recent activity.
        </p>
        <ol
          class="divide-y divide-fc-line text-xs"
          data-testid="activity"
        >
          <li
            v-for="item in feed"
            :key="item.key"
            class="flex items-start gap-2 py-1.5"
          >
            <StatusChip
              :label="item.kind === 'operation' ? 'op' : 'audit'"
              :tone="item.tone"
            />
            <span class="min-w-0 flex-1">
              <RouterLink
                v-if="item.to"
                :to="item.to"
                class="block truncate font-mono text-[11px] text-fc-ink hover:underline"
              >{{ item.title }}</RouterLink>
              <span
                v-else
                class="block truncate font-mono text-[11px] text-fc-ink"
              >{{ item.title }}</span>
              <span
                v-if="item.detail"
                class="block truncate text-[11px] text-fc-muted"
              >{{ item.detail }}</span>
            </span>
            <span class="shrink-0 font-mono text-[10px] text-fc-faint">{{ relativeTime(item.at) }}</span>
          </li>
        </ol>
      </section>
    </div>

    <section class="mt-6 space-y-2">
      <h2 class="fc-kicker flex items-center border-b-2 border-fc-ink pb-1">
        Proxmox capacity
        <RouterLink
          to="/proxmox?tab=nodes"
          class="ml-auto font-mono text-[10px] tracking-wider text-fc-info hover:text-fc-ink"
        >
          Proxmox →
        </RouterLink>
      </h2>
      <p
        v-if="nodes.length === 0"
        class="text-xs text-fc-muted"
      >
        No capacity observed: add and pin a Proxmox account to see its nodes.
      </p>
      <div
        class="grid gap-3 md:grid-cols-2 xl:grid-cols-3"
        data-testid="capacity"
      >
        <div
          v-for="node in nodes"
          :key="`${node.accountId}/${node.node}`"
          class="space-y-1.5 rounded-sm border border-fc-line bg-card p-3"
        >
          <p class="text-sm font-semibold text-fc-ink">
            {{ node.node }} <span class="fc-kicker ml-1">{{ node.accountName }}</span>
          </p>
          <template v-if="node.capacity">
            <UsageBar
              label="CPU"
              :value="node.capacity.cpuUsageRatio ?? null"
            />
            <UsageBar
              label="MEM"
              :value="ratio(node.capacity.memoryUsedBytes, node.capacity.memoryTotalBytes)"
              :detail="node.capacity.memoryTotalBytes ? formatBytes(node.capacity.memoryTotalBytes) : null"
            />
            <UsageBar
              v-for="storage in node.capacity.storages"
              :key="storage.storage"
              :label="storage.storage"
              :value="ratio(storage.usedBytes, storage.totalBytes)"
            />
          </template>
          <p
            v-else
            class="font-mono text-[10.5px] text-fc-faint"
          >
            No capacity observation.
          </p>
        </div>
      </div>
    </section>

    <div class="mt-6">
      <SystemPanel />
    </div>
  </div>
</template>
