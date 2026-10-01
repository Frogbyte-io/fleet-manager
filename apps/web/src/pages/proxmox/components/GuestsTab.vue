<script setup lang="ts">
import { useQueryClient } from '@tanstack/vue-query'
import { computed, ref } from 'vue'
import { RouterLink } from 'vue-router'

import { startProxmoxLifecycle, type OperationDto } from '@frogbyte-io/fleet-api-client'
import StatusChip from '@/components/fleet/StatusChip.vue'

import { guestAgentLabel, guestStatusTone } from '../../fleet/inventory'
import { errorMessage, unwrap } from '../../machine/api'
import CopyFleetctl from '../../machine/components/CopyFleetctl.vue'
import OperationStatus from '../../machine/components/OperationStatus.vue'
import { lifecycleCommand, type LifecycleAction } from '../../machine/fleetctl'
import { actionsAllowed, pveUrl, tierBlockReason, type AccountView, type GuestRow } from '../proxmox'
import { discoveryKey, guestsKey } from '../useProxmox'

// Guests across pinned accounts. Lifecycle actions are authorized at the
// catalog level (`proxmox.operate`), so they need no Fleet machine; each is
// confirmed here and runs as a durable operation. Reviewed destructive
// operations (snapshot, clone, template) stay on the machine's Guest tab.
const props = defineProps<{ rows: GuestRow[], views: AccountView[] }>()

const queryClient = useQueryClient()
const TIMEOUT_SECONDS = 300
const LIFECYCLE: LifecycleAction[] = ['start', 'shutdown', 'reboot', 'stop']

const text = ref('')
const filtered = computed(() => {
  const needle = text.value.trim().toLowerCase()
  return needle
    ? props.rows.filter(r => `${r.guest.vmid ?? ''} ${r.guest.name ?? ''} ${r.guest.node ?? ''}`.toLowerCase().includes(needle))
    : props.rows
})
const blocked = computed(() => props.views.filter(v => v.state === 'changed' || v.state === 'unconfirmed'))
const loadingAccounts = computed(() => props.views.filter(v => v.guestsLoading))
const failedAccounts = computed(() => props.views.filter(v => v.guestsError))
const truncatedAccounts = computed(() => props.views.filter(v => v.guestsTruncated))
const accounts = computed(() => new Map(props.views.map(v => [v.account.id, v.account])))
const reports = computed(() => new Map(props.views.map(v => [v.account.id, v.privileges ?? null])))

// Why the token cannot run a tier's actions on this guest's account, from
// the privilege report; null (offered) unless the tier is reported missing.
function blockedBy(row: GuestRow, tier: 'operate' | 'destructive'): string | null {
  return tierBlockReason(reports.value.get(row.accountId), tier)
}

function key(row: GuestRow) {
  return `${row.accountId}/${row.guest.vmid ?? row.guest.id}`
}

const open = ref<string | null>(null)
const action = ref<LifecycleAction | null>(null)
const busy = ref(false)
const error = ref('')
const operations = ref<Record<string, string>>({})

function toggle(row: GuestRow) {
  open.value = open.value === key(row) ? null : key(row)
  action.value = null
  error.value = ''
}

function kindLabel(kind: string) {
  return kind === 'lxc' ? 'LXC' : 'QEMU'
}

async function run(row: GuestRow) {
  const chosen = action.value
  const { vmid, node } = row.guest
  // The page never offers actions on an unverified account; the controller
  // would refuse them anyway.
  if (!chosen || vmid === null || vmid === undefined || !node || !actionsAllowed(row.state) || blockedBy(row, 'operate'))
    return
  busy.value = true
  error.value = ''
  try {
    const operation = unwrap<OperationDto>(await startProxmoxLifecycle(row.accountId, vmid, chosen, { node, vmid, timeoutSeconds: TIMEOUT_SECONDS }), [202])
    operations.value = { ...operations.value, [key(row)]: operation.id }
    action.value = null
  }
  catch (caught) {
    error.value = errorMessage(caught)
  }
  finally {
    busy.value = false
  }
}

function settled(row: GuestRow) {
  void queryClient.invalidateQueries({ queryKey: guestsKey(row.accountId) })
  void queryClient.invalidateQueries({ queryKey: discoveryKey(row.accountId) })
}
</script>

<template>
  <div class="mt-4 space-y-3">
    <div
      v-if="blocked.length"
      class="border-l-2 border-l-fc-err bg-card px-3 py-2 text-xs text-fc-muted"
      role="status"
      data-testid="guests-blocked"
    >
      Guests of {{ blocked.map(v => v.account.name).join(', ') }} are not listed and cannot be acted on until {{ blocked.length === 1 ? 'its' : 'their' }} fingerprint is confirmed (Accounts).
    </div>

    <div
      v-for="view in failedAccounts"
      :key="`failed-${view.account.id}`"
      class="border-l-2 border-l-fc-err bg-card px-3 py-2 text-xs text-fc-muted"
      role="alert"
      data-testid="guests-error"
    >
      Could not load guests of {{ view.account.name }}: {{ errorMessage(view.guestsError) }}
    </div>
    <div
      v-if="truncatedAccounts.length"
      class="border-l-2 border-l-fc-warn bg-card px-3 py-2 text-xs text-fc-muted"
      role="status"
    >
      Guests of {{ truncatedAccounts.map(v => v.account.name).join(', ') }} hit the 20-page safety cap; some guests are missing.
    </div>
    <p
      v-if="loadingAccounts.length"
      class="text-xs text-fc-faint"
      data-testid="guests-loading"
    >
      Loading guests of {{ loadingAccounts.map(v => v.account.name).join(', ') }}…
    </p>

    <label class="flex flex-col gap-1 text-xs">
      <span class="fc-kicker">Filter</span>
      <input
        v-model="text"
        placeholder="VMID, name, or node"
        class="h-8 w-64 rounded-sm border border-input bg-background px-2 text-foreground"
      >
    </label>

    <p
      v-if="rows.length === 0 && loadingAccounts.length === 0 && failedAccounts.length === 0"
      class="rounded-sm border border-fc-line p-6 text-sm text-fc-muted"
      data-testid="guests-empty"
    >
      No guests on pinned accounts.
    </p>
    <p
      v-else-if="rows.length > 0 && filtered.length === 0"
      class="rounded-sm border border-fc-line p-6 text-sm text-fc-muted"
      data-testid="guests-no-match"
    >
      No guests match "{{ text }}".
    </p>
    <div
      v-if="filtered.length > 0"
      class="overflow-x-auto"
    >
      <table
        class="w-full border border-fc-line bg-card text-xs"
        data-testid="guests-table"
      >
        <thead>
          <tr class="bg-fc-inset text-left">
            <th class="fc-kicker px-2 py-1.5 font-normal">
              Guest
            </th>
            <th class="fc-kicker px-2 py-1.5 font-normal">
              Node
            </th>
            <th class="fc-kicker px-2 py-1.5 font-normal">
              Status
            </th>
            <th class="fc-kicker px-2 py-1.5 font-normal">
              Guest agent
            </th>
            <th class="fc-kicker px-2 py-1.5 font-normal">
              Fleet machine (candidates)
            </th>
            <th class="px-2 py-1.5" />
          </tr>
        </thead>
        <tbody>
          <template
            v-for="row in filtered"
            :key="key(row)"
          >
            <tr
              class="border-t border-fc-line"
              :data-testid="`guest-${row.guest.vmid}`"
            >
              <td class="px-2 py-1.5">
                <span class="font-mono text-fc-faint">{{ kindLabel(row.guest.kind) }} {{ row.guest.vmid ?? '—' }}</span>
                <span class="ml-1.5 text-fc-ink">{{ row.guest.name ?? row.guest.id }}</span>
                <span class="block font-mono text-[10px] text-fc-faint">{{ row.accountName }}</span>
              </td>
              <td class="px-2 py-1.5 font-mono text-fc-muted">
                {{ row.guest.node ?? '—' }}
              </td>
              <td class="px-2 py-1.5">
                <StatusChip
                  :label="row.guest.status ?? 'unknown'"
                  :tone="guestStatusTone(row.guest.status ?? 'unknown')"
                />
              </td>
              <td class="px-2 py-1.5 font-mono text-[10.5px] text-fc-muted">
                {{ guestAgentLabel(row.guest.agent?.online ?? null) }}<template v-if="row.guest.agent?.osName">
                  · {{ row.guest.agent.osName }}
                </template>
              </td>
              <td class="px-2 py-1.5">
                <span
                  v-if="row.guest.candidates.length === 0"
                  class="text-fc-faint"
                >none</span>
                <RouterLink
                  v-for="candidate in row.guest.candidates"
                  :key="candidate.machineId"
                  :to="{ path: `/fleet/machines/${candidate.machineId}`, query: { tab: 'guest' } }"
                  class="mr-2 text-fc-info hover:text-fc-ink"
                  :title="`candidate by ${candidate.kind.replace('_', ' ')}: ${candidate.evidence}`"
                >
                  ≈ {{ candidate.machineName }}
                </RouterLink>
              </td>
              <td class="px-2 py-1.5 text-right">
                <div class="flex justify-end gap-3 font-mono text-[10px] uppercase tracking-wider">
                  <a
                    v-if="accounts.get(row.accountId) && row.guest.vmid != null"
                    :href="pveUrl(accounts.get(row.accountId)!, { type: row.guest.kind === 'lxc' ? 'lxc' : 'qemu', id: row.guest.vmid })"
                    target="_blank"
                    rel="noopener noreferrer"
                    class="text-fc-info hover:text-fc-ink"
                  >PVE ↗</a>
                  <button
                    type="button"
                    class="text-fc-info hover:text-fc-ink disabled:opacity-50"
                    :disabled="!actionsAllowed(row.state) || row.guest.vmid == null || !row.guest.node"
                    :aria-expanded="open === key(row)"
                    :data-testid="`guest-actions-${row.guest.vmid}`"
                    @click="toggle(row)"
                  >
                    Actions
                  </button>
                </div>
              </td>
            </tr>
            <tr
              v-if="open === key(row)"
              class="bg-fc-inset"
            >
              <td
                colspan="6"
                class="space-y-2 px-3 py-3"
              >
                <div class="flex flex-wrap items-center gap-2">
                  <span class="fc-kicker">Lifecycle</span>
                  <button
                    v-for="item in LIFECYCLE"
                    :key="item"
                    type="button"
                    class="h-7 rounded-sm border px-2.5 capitalize disabled:cursor-not-allowed disabled:opacity-50"
                    :class="action === item ? 'border-ring text-fc-ink' : 'border-fc-line2 text-fc-muted hover:text-fc-ink'"
                    :aria-pressed="action === item"
                    :disabled="!!blockedBy(row, 'operate')"
                    :title="blockedBy(row, 'operate') ?? undefined"
                    :aria-describedby="blockedBy(row, 'operate') ? `operate-blocked-${key(row)}` : undefined"
                    :data-testid="`lifecycle-${item}`"
                    @click="action = item"
                  >
                    {{ item }}
                  </button>
                </div>
                <p
                  v-if="blockedBy(row, 'operate')"
                  :id="`operate-blocked-${key(row)}`"
                  class="border-l-2 border-l-fc-err pl-2 text-fc-muted"
                  data-testid="operate-blocked"
                >
                  {{ blockedBy(row, 'operate') }}
                </p>
                <div
                  v-if="action"
                  class="flex flex-wrap items-center gap-2 rounded-sm border p-2"
                  :class="action === 'stop' ? 'border-fc-err/40' : 'border-fc-line'"
                  role="alertdialog"
                  aria-label="Confirm lifecycle action"
                >
                  <span>
                    <span class="capitalize">{{ action }}</span> {{ kindLabel(row.guest.kind) }} {{ row.guest.vmid }} ({{ row.guest.name ?? row.guest.id }}) on {{ row.guest.node }}?
                    <span
                      v-if="action === 'stop'"
                      class="text-fc-err"
                    >Stop is a hard power-off; prefer shutdown.</span>
                  </span>
                  <button
                    type="button"
                    class="h-7 rounded-sm border border-fc-info/40 px-2.5 font-semibold text-fc-info hover:bg-fc-info/10 disabled:opacity-50"
                    :disabled="busy"
                    :data-testid="`confirm-lifecycle-${row.guest.vmid}`"
                    @click="run(row)"
                  >
                    Confirm {{ action }}
                  </button>
                  <button
                    type="button"
                    class="h-7 px-2 text-fc-muted hover:text-fc-ink"
                    @click="action = null"
                  >
                    Cancel
                  </button>
                </div>
                <p
                  v-if="error"
                  class="text-fc-err"
                  role="alert"
                >
                  {{ error }}
                </p>
                <OperationStatus
                  v-if="operations[key(row)]"
                  :operation-id="operations[key(row)]!"
                  :label="`proxmox ${row.guest.kind === 'lxc' ? 'lxc' : 'qemu'} ${row.guest.vmid}`"
                  @settled="settled(row)"
                />
                <CopyFleetctl
                  :command="action && row.guest.vmid != null && row.guest.node ? lifecycleCommand(action, { accountId: row.accountId, node: row.guest.node, vmid: row.guest.vmid }) : null"
                  missing="Pick an action to see the command."
                />
                <p
                  v-if="blockedBy(row, 'destructive')"
                  class="border-l-2 border-l-fc-err pl-2 text-fc-muted"
                  data-testid="destructive-blocked"
                >
                  {{ blockedBy(row, 'destructive') }}
                </p>
                <p class="text-fc-faint">
                  Snapshots, clones, and template conversion go through review first: use the
                  <template v-if="row.guest.candidates.length">
                    Guest tab of
                    <RouterLink
                      v-for="candidate in row.guest.candidates"
                      :key="candidate.machineId"
                      :to="{ path: `/fleet/machines/${candidate.machineId}`, query: { tab: 'guest' } }"
                      class="mr-1 text-fc-info hover:text-fc-ink"
                    >
                      {{ candidate.machineName }}
                    </RouterLink>
                  </template>
                  <template v-else>
                    <span class="font-mono">fleetctl proxmox snapshot|clone|template …</span> (the reviewed parameters are read from stdin)
                  </template>.
                </p>
              </td>
            </tr>
          </template>
        </tbody>
      </table>
    </div>
  </div>
</template>
