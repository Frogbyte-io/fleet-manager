<script setup lang="ts">
import { useIntervalFn } from '@vueuse/core'
import { computed, ref } from 'vue'
import { RefreshCw } from '@lucide/vue'

import StatusChip from '@/components/fleet/StatusChip.vue'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'

import { errorMessage } from '../machine/api'
import CopyFleetctl from '../machine/components/CopyFleetctl.vue'
import DeviceCard from './components/DeviceCard.vue'
import RefreshReport from './components/RefreshReport.vue'
import { LIST_COMMAND, refreshCommand, sessionObservation, statusTone, summarize, words, type SessionObservation } from './hardware'
import { useHardware } from './useHardware'

// USB hardware (ADR 0019, docs/planning/m11-usb-hardware.md): the devices the
// controller inventoried from Proxmox resource mappings, each with its status,
// the reason when it is unsupported, and its holder. The page is an adapter:
// it shows what GET /hardware/devices and POST /hardware/refresh return (what
// `fleetctl hardware list --output json` prints) and decides nothing itself.
const { devices, accounts, accountNames, reports, refresh, refreshError, denied, refreshActions } = useHardware()
const now = ref(Date.now())
useIntervalFn(() => (now.value = Date.now()), 30_000)

const items = computed(() => devices.data.value?.items ?? [])
const summary = computed(() => summarize(items.value))
const accountLabel = (accountId: string) => accountNames.value.get(accountId) ?? accountId

/**
 * The last refresh's finding per device, dated, and marked superseded once the
 * list shows a different status than the refresh did.
 */
const observations = computed(() => {
  const listed = new Map(items.value.map(device => [device.id, device]))
  const found = new Map<string, SessionObservation>()
  for (const report of reports.value.values()) {
    for (const refreshed of report.devices) {
      const current = listed.get(refreshed.id)
      const observation = current ? sessionObservation(current, refreshed, report.observedAt) : null
      if (observation)
        found.set(refreshed.id, observation)
    }
  }
  return found
})
const reportList = computed(() => [...reports.value.values()])
const refreshingAccount = computed(() => (refresh.isPending.value ? refresh.variables.value : null))
const deniedList = computed(() => [...denied.value.entries()].map(([accountId, message]) => ({ accountId, message })))

// The buttons stay enabled for focus (a disabled button drops it); a click
// during a refresh is ignored, and the busy state is announced instead.
function refreshAccount(accountId: string) {
  if (!refresh.isPending.value)
    refresh.mutate(accountId)
}
const announcement = computed(() => {
  if (refreshingAccount.value)
    return `Refreshing ${accountLabel(refreshingAccount.value)}`
  if (refresh.isSuccess.value && refresh.variables.value)
    return `Refreshed ${accountLabel(refresh.variables.value)}`
  return ''
})
</script>

<template>
  <div>
    <div class="flex flex-wrap items-end gap-4">
      <div>
        <p class="fc-kicker">
          {{ summary.total }} device{{ summary.total === 1 ? '' : 's' }}
          <template v-if="summary.stale">
            · <span class="text-fc-warn">{{ summary.stale }} stale</span>
          </template>
        </p>
        <h1 class="fc-h1">
          Hardware
        </h1>
      </div>
      <div
        v-if="refreshActions.length"
        class="ml-auto flex flex-wrap gap-2"
        data-testid="refresh-actions"
      >
        <Button
          v-for="account in refreshActions"
          :key="account.id"
          variant="outline"
          size="sm"
          class="aria-disabled:cursor-wait aria-disabled:opacity-50"
          :aria-busy="refreshingAccount === account.id"
          :aria-disabled="refresh.isPending.value"
          :data-testid="`refresh-${account.id}`"
          @click="refreshAccount(account.id)"
        >
          <RefreshCw
            class="size-3.5"
            :class="refreshingAccount === account.id ? 'animate-spin' : ''"
          />
          Refresh {{ account.name }}
        </Button>
      </div>
    </div>
    <p
      class="sr-only"
      role="status"
      data-testid="refresh-status"
    >
      {{ announcement }}
    </p>

    <p class="mt-2 max-w-3xl text-xs text-fc-muted">
      USB devices that Proxmox resource mappings name, with the status and holder Fleet reports. A device is as fresh as
      its last refresh; the API reports no per-device event history, so none is shown here.
    </p>

    <div
      v-if="devices.error.value"
      class="mt-4 border-l-2 border-l-fc-err bg-card px-3 py-2 text-xs text-fc-muted"
      role="alert"
      data-testid="list-error"
    >
      Could not load hardware devices: {{ errorMessage(devices.error.value) }}
    </div>

    <div
      v-if="accounts.error.value"
      class="mt-4 border-l-2 border-l-fc-err bg-card px-3 py-2 text-xs text-fc-muted"
      role="alert"
      data-testid="accounts-error"
    >
      Could not load Proxmox accounts, so no refresh is offered: {{ errorMessage(accounts.error.value) }}
    </div>

    <div
      v-if="refreshError"
      class="mt-4 border-l-2 border-l-fc-err bg-card px-3 py-2 text-xs text-fc-muted"
      role="alert"
      data-testid="refresh-error"
    >
      Refresh of {{ accountLabel(refreshError.accountId) }} failed: {{ refreshError.message }}
    </div>

    <div
      v-for="entry in deniedList"
      :key="entry.accountId"
      class="mt-4 border-l-2 border-l-fc-warn bg-card px-3 py-2 text-xs text-fc-muted"
      role="alert"
      :data-testid="`refresh-denied-${entry.accountId}`"
    >
      The API refused hardware.refresh for {{ accountLabel(entry.accountId) }}, so refreshing it is hidden: {{ entry.message }}
    </div>

    <div
      v-if="devices.isLoading.value"
      class="mt-4 grid gap-3 lg:grid-cols-2"
      data-testid="loading"
    >
      <Skeleton
        v-for="i in 2"
        :key="i"
        class="h-40 rounded-sm"
      />
    </div>

    <template v-else-if="devices.isSuccess.value">
      <div
        v-if="summary.byStatus.length"
        class="mt-4 flex flex-wrap items-center gap-2"
        data-testid="summary"
      >
        <span
          v-for="entry in summary.byStatus"
          :key="entry.status"
          class="inline-flex items-center gap-1.5"
          :data-testid="`count-${entry.status}`"
        >
          <StatusChip
            :label="words(entry.status)"
            :tone="statusTone(entry.status)"
          />
          <span class="font-mono text-[11px] text-fc-muted">{{ entry.count }}</span>
        </span>
      </div>

      <p
        v-if="devices.data.value?.truncated"
        class="mt-3 text-xs text-fc-warn"
        data-testid="truncated"
      >
        The list was cut short; narrow it with `fleetctl hardware list --account`.
      </p>

      <p
        v-if="items.length === 0"
        class="mt-4 rounded-sm border border-fc-line p-6 text-sm text-fc-muted"
        data-testid="empty"
      >
        No hardware devices. Devices appear after a refresh lists an account's USB resource mappings.
        <template v-if="accounts.isSuccess.value && accounts.data.value?.every(a => a.fingerprintState !== 'confirmed')">
          No pinned Proxmox account is available to refresh.
        </template>
      </p>

      <div
        v-else
        class="mt-4 grid gap-3 lg:grid-cols-2"
        data-testid="devices"
      >
        <DeviceCard
          v-for="device in items"
          :key="device.id"
          :device="device"
          :account-name="accountLabel(device.accountId)"
          :now="now"
          :observation="observations.get(device.id) ?? null"
        />
      </div>

      <div
        v-if="reportList.length"
        class="mt-4 grid gap-3"
        data-testid="reports"
      >
        <RefreshReport
          v-for="report in reportList"
          :key="report.accountId"
          :report="report"
          :account-name="accountLabel(report.accountId)"
          :now="now"
        />
      </div>
    </template>

    <div class="mt-6 grid gap-2 md:grid-cols-2">
      <CopyFleetctl :command="LIST_COMMAND" />
      <CopyFleetctl
        v-if="refreshActions.length"
        :command="refreshCommand(refreshActions[0]!.id)"
      />
    </div>
  </div>
</template>
