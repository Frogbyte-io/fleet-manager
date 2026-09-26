<script setup lang="ts">
import { useQueryClient } from '@tanstack/vue-query'
import { computed, ref } from 'vue'

import {
  extendLabLease,
  releaseLabLease,
  startLabLeaseProvision,
  type LabTemplateDto,
  type LeaseDto,
  type OperationDto,
  type ProxmoxAccountDto,
} from '@frogbyte-io/fleet-api-client'
import StatusChip from '@/components/fleet/StatusChip.vue'

import { relativeTime } from '../../fleet/inventory'
import { errorMessage, unwrap } from '../../machine/api'
import CopyFleetctl from '../../machine/components/CopyFleetctl.vue'
import OperationStatus from '../../machine/components/OperationStatus.vue'
import {
  extendCommand,
  isTerminal,
  leaseTone,
  provisionLeaseCommand,
  releaseCommand,
  shortId,
} from '../lab'
import { LEASES_KEY, PROVISIONS_KEY } from '../useLab'
import LeaseStepper from './LeaseStepper.vue'
import TtlBar from './TtlBar.vue'

// One lease: identity, lifecycle, TTL, and the actions its state allows.
// Every action is an authorized, audited API call; the card only decides
// which ones the state makes meaningful and shows their fleetctl equivalent.
const props = defineProps<{
  lease: LeaseDto
  template: LabTemplateDto | null
  projectName: string | null
  accounts: ProxmoxAccountDto[]
  now: number
}>()

const queryClient = useQueryClient()

type Panel = 'provision' | 'extend' | 'release' | null
const panel = ref<Panel>(null)
const busy = ref(false)
const error = ref('')
const operationId = ref<string | null>(null)

const accountId = ref(props.accounts[0]?.id ?? '')
const EXTEND_CHOICES = [
  { seconds: 1800, label: '+30M' },
  { seconds: 3600, label: '+1H' },
  { seconds: 7200, label: '+2H' },
  { seconds: 28_800, label: '+8H' },
]
const extendSeconds = ref(3600)
const keep = ref(false)
const keepAcknowledged = ref(false)

const canProvision = computed(() => props.lease.state === 'requested')
const canExtend = computed(() => props.lease.state === 'ready')
// Releasing is already underway; a terminal lease has nothing left to release.
const canRelease = computed(() => !isTerminal(props.lease.state) && props.lease.state !== 'releasing')

const stateLabel = computed(() => props.lease.state.replace('_', ' '))

const templateLabel = computed(() =>
  props.template ? props.template.name : `version ${shortId(props.lease.templateVersionId)}`,
)

// Identity facts in mono; owner and project names keep their own case.
const facts = computed(() => [
  { label: 'LEASE', value: shortId(props.lease.id), verbatim: false },
  { label: 'TEMPLATE', value: templateLabel.value, verbatim: false },
  { label: 'OWNER', value: props.lease.owner, verbatim: true },
  ...(props.lease.projectId
    ? [{ label: 'PROJECT', value: props.projectName ?? shortId(props.lease.projectId), verbatim: true }]
    : []),
  { label: 'CLEANUP', value: props.lease.cleanup, verbatim: false },
  { label: 'REQUESTED', value: relativeTime(props.lease.createdAt, props.now), verbatim: false },
])

const command = computed(() => {
  switch (panel.value) {
    case 'provision': return accountId.value ? provisionLeaseCommand(props.lease.id, accountId.value) : null
    case 'extend': return extendCommand(props.lease.id, extendSeconds.value)
    case 'release': return releaseCommand(props.lease.id, keep.value)
    default: return null
  }
})

function open(next: Panel) {
  panel.value = panel.value === next ? null : next
  error.value = ''
  keep.value = false
  keepAcknowledged.value = false
}

async function refresh() {
  await Promise.all([
    queryClient.invalidateQueries({ queryKey: LEASES_KEY }),
    queryClient.invalidateQueries({ queryKey: PROVISIONS_KEY }),
  ])
}

async function run(action: () => Promise<void>) {
  busy.value = true
  error.value = ''
  try {
    await action()
    panel.value = null
    await refresh()
  }
  catch (caught) {
    error.value = errorMessage(caught)
  }
  finally {
    busy.value = false
  }
}

function provision() {
  if (!accountId.value)
    return
  return run(async () => {
    const operation = unwrap<OperationDto>(await startLabLeaseProvision(props.lease.id, { accountId: accountId.value }), [201])
    operationId.value = operation.id
  })
}

function extend() {
  return run(async () => {
    unwrap<LeaseDto>(await extendLabLease(props.lease.id, { bySeconds: extendSeconds.value }))
  })
}

function release() {
  if (keep.value && !keepAcknowledged.value)
    return
  return run(async () => {
    unwrap<LeaseDto>(await releaseLabLease(props.lease.id, { keep: keep.value }))
  })
}
</script>

<template>
  <article
    class="rounded-sm border border-fc-line bg-card p-4"
    :class="{ 'border-l-2 border-l-fc-err': lease.state === 'failed' || lease.state === 'cleanup_failed' }"
    :data-testid="`lease-${lease.id}`"
  >
    <div class="flex flex-wrap items-start gap-3">
      <div class="min-w-0 flex-1">
        <div class="flex flex-wrap items-center gap-2">
          <h3 class="truncate font-head text-base font-extrabold text-fc-ink">
            {{ lease.purpose || 'Untitled lease' }}
          </h3>
          <StatusChip
            :label="stateLabel"
            :tone="leaseTone(lease.state)"
          />
        </div>
        <dl class="mt-1.5 flex flex-wrap gap-x-4 gap-y-1 font-mono text-[10.5px] uppercase tracking-wide text-fc-muted">
          <div
            v-for="fact in facts"
            :key="fact.label"
            class="flex gap-1"
          >
            <dt>{{ fact.label }}</dt>
            <dd
              class="text-fc-ink"
              :class="{ 'normal-case': fact.verbatim }"
            >
              {{ fact.value }}
            </dd>
          </div>
        </dl>
      </div>
      <div class="flex flex-wrap gap-1.5">
        <button
          v-if="canProvision"
          type="button"
          class="h-7 rounded-sm border border-input px-2.5 text-xs hover:border-fc-muted"
          :aria-expanded="panel === 'provision'"
          @click="open('provision')"
        >
          Provision…
        </button>
        <button
          v-if="canExtend"
          type="button"
          class="h-7 rounded-sm border border-input px-2.5 text-xs hover:border-fc-muted"
          :aria-expanded="panel === 'extend'"
          @click="open('extend')"
        >
          Extend…
        </button>
        <button
          v-if="canRelease"
          type="button"
          class="h-7 rounded-sm border border-input px-2.5 text-xs hover:border-fc-muted"
          :aria-expanded="panel === 'release'"
          @click="open('release')"
        >
          Release…
        </button>
      </div>
    </div>

    <div class="mt-3">
      <LeaseStepper :lease="lease" />
    </div>
    <!-- The ready TTL means nothing once a lease has left ready. -->
    <div
      v-if="lease.state === 'ready'"
      class="mt-3"
    >
      <TtlBar
        :lease="lease"
        :now="now"
      />
    </div>

    <p
      v-if="lease.state === 'cleanup_failed'"
      class="mt-3 text-xs text-fc-err"
    >
      Cleanup failed: the lease still owns whatever the controller could not remove. The expiry sweeper retries it;
      <span class="font-mono">Sweep expired</span> retries now.
    </p>

    <!-- Provision: pick the Proxmox account whose pinned trust the clone uses. -->
    <div
      v-if="panel === 'provision'"
      class="mt-3 grid gap-2 rounded-sm border border-fc-line bg-fc-inset p-3 text-xs"
    >
      <p
        v-if="accounts.length === 0"
        class="text-fc-warn"
      >
        No Proxmox account with a confirmed TLS fingerprint. Add or confirm one from Fleet → Add machine → Proxmox server.
      </p>
      <template v-else>
        <label
          class="fc-kicker"
          :for="`account-${lease.id}`"
        >Proxmox account</label>
        <select
          :id="`account-${lease.id}`"
          v-model="accountId"
          class="h-8 rounded-sm border border-input bg-background px-2"
        >
          <option
            v-for="account in accounts"
            :key="account.id"
            :value="account.id"
          >
            {{ account.name }} · {{ account.host }}
          </option>
        </select>
        <div class="flex gap-2">
          <button
            type="button"
            class="fc-grad-bg h-8 rounded-sm px-3 font-semibold disabled:opacity-50"
            :disabled="busy || !accountId"
            @click="provision"
          >
            Start provisioning →
          </button>
          <button
            type="button"
            class="h-8 px-2 text-fc-muted hover:text-fc-ink"
            @click="open(null)"
          >
            Cancel
          </button>
        </div>
      </template>
    </div>

    <!-- Extend: adds to the ready TTL; the API refuses past the lifetime cap. -->
    <div
      v-if="panel === 'extend'"
      class="mt-3 grid gap-2 rounded-sm border border-fc-line bg-fc-inset p-3 text-xs"
    >
      <span class="fc-kicker">Add to TTL</span>
      <div
        class="inline-flex w-fit overflow-hidden rounded-sm border border-input"
        role="group"
        aria-label="Extension"
      >
        <button
          v-for="choice in EXTEND_CHOICES"
          :key="choice.seconds"
          type="button"
          class="border-r border-input px-3 py-1.5 font-mono last:border-r-0"
          :class="extendSeconds === choice.seconds ? 'bg-card text-fc-ink' : 'text-fc-muted'"
          :aria-pressed="extendSeconds === choice.seconds"
          @click="extendSeconds = choice.seconds"
        >
          {{ choice.label }}
        </button>
      </div>
      <p class="text-fc-faint">
        The controller refuses an extension past the lease's maximum lifetime.
      </p>
      <div class="flex gap-2">
        <button
          type="button"
          class="fc-grad-bg h-8 rounded-sm px-3 font-semibold disabled:opacity-50"
          :disabled="busy"
          @click="extend"
        >
          Extend lease →
        </button>
        <button
          type="button"
          class="h-8 px-2 text-fc-muted hover:text-fc-ink"
          @click="open(null)"
        >
          Cancel
        </button>
      </div>
    </div>

    <!-- Release: destroy by default; keep is elevated and explained. -->
    <div
      v-if="panel === 'release'"
      class="mt-3 grid gap-2 rounded-sm border border-fc-line bg-fc-inset p-3 text-xs"
    >
      <p>
        Releasing ends the lease and runs its cleanup (<span class="font-mono">{{ lease.cleanup }}</span>).
      </p>
      <label class="flex items-start gap-2">
        <input
          v-model="keep"
          type="checkbox"
          class="mt-0.5 accent-[var(--fc-g2)]"
          data-testid="keep"
        >
        <span>
          Keep the VM instead (elevated). It leaves automatic cleanup and stays yours to remove.
        </span>
      </label>
      <label
        v-if="keep"
        class="flex items-start gap-2 text-fc-warn"
      >
        <input
          v-model="keepAcknowledged"
          type="checkbox"
          class="mt-0.5"
          data-testid="keep-ack"
        >
        <span>I understand nothing will delete this VM automatically.</span>
      </label>
      <div class="flex gap-2">
        <button
          type="button"
          class="h-8 rounded-sm border px-3 font-semibold disabled:opacity-50"
          :class="keep ? 'border-fc-warn text-fc-warn' : 'border-fc-err bg-fc-err/10 text-fc-err'"
          :disabled="busy || (keep && !keepAcknowledged)"
          data-testid="confirm-release"
          @click="release"
        >
          {{ keep ? 'Release and keep VM' : 'Release lease' }}
        </button>
        <button
          type="button"
          class="h-8 px-2 text-fc-muted hover:text-fc-ink"
          @click="open(null)"
        >
          Cancel
        </button>
      </div>
    </div>

    <div
      v-if="panel"
      class="mt-2"
    >
      <CopyFleetctl :command="command" />
    </div>

    <p
      v-if="error"
      class="mt-2 text-xs text-fc-err"
      role="alert"
    >
      {{ error }}
    </p>

    <div
      v-if="operationId"
      class="mt-3"
    >
      <OperationStatus
        :operation-id="operationId"
        label="Provisioning"
        dismissible
        @settled="refresh"
        @dismiss="operationId = null"
      />
    </div>
  </article>
</template>
