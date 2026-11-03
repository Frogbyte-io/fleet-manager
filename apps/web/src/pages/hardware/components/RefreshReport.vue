<script setup lang="ts">
import type { HardwareRefreshDto } from '@frogbyte-io/fleet-api-client'
import StatusChip from '@/components/fleet/StatusChip.vue'

import { relativeTime } from '../../fleet/inventory'
import { words } from '../hardware'

// What one refresh reported, as the API returned it: whether the account could
// be inventoried, what the guest scan covered, and its warnings. A scan that
// was cut short is why a device may read `unsupported` instead of `available`.
defineProps<{ report: HardwareRefreshDto, accountName: string, now: number }>()
</script>

<template>
  <section
    class="space-y-1.5 rounded-sm border border-fc-line bg-card px-4 py-3"
    :data-testid="`report-${report.accountId}`"
  >
    <div class="flex flex-wrap items-center gap-2">
      <span class="fc-kicker">Last refresh · {{ accountName }}</span>
      <StatusChip
        :label="words(report.support.state)"
        :tone="report.support.state === 'supported' ? 'ok' : 'warn'"
        data-testid="support-state"
      />
      <span class="font-mono text-[10px] uppercase tracking-wider text-fc-faint">
        {{ relativeTime(report.observedAt, now) }}<template v-if="report.pveVersion"> · PVE {{ report.pveVersion }}</template>
      </span>
    </div>
    <p
      v-if="report.support.detail"
      class="text-xs text-fc-muted"
      data-testid="support-detail"
    >
      <span
        v-if="report.support.reason"
        class="font-mono uppercase"
      >{{ words(report.support.reason) }}: </span>{{ report.support.detail }}
    </p>
    <p
      v-if="report.guestScan"
      class="font-mono text-[11px] text-fc-muted"
      data-testid="guest-scan"
    >
      Guest scan: {{ report.guestScan.read }} of {{ report.guestScan.listed }} configs read<template v-if="report.guestScan.unreadable">
        · {{ report.guestScan.unreadable }} unreadable
      </template><template v-if="report.guestScan.truncated">
        · truncated
      </template>
    </p>
    <p
      v-for="warning in report.warnings"
      :key="warning"
      class="border-l-2 border-l-fc-warn pl-2 text-xs text-fc-muted"
      data-testid="warning"
    >
      {{ warning }}
    </p>
  </section>
</template>
