<script setup lang="ts">
import { useQueryClient } from '@tanstack/vue-query'
import { useIntervalFn } from '@vueuse/core'
import { computed, ref } from 'vue'

import { sweepLabLeases, type LeaseDto } from '@frogbyte-io/fleet-api-client'
import { Skeleton } from '@/components/ui/skeleton'

import { errorMessage } from '../machine/api'
import CopyFleetctl from '../machine/components/CopyFleetctl.vue'
import OperationStatus from '../machine/components/OperationStatus.vue'
import LeaseCard from './components/LeaseCard.vue'
import ProvisionsTab from './components/ProvisionsTab.vue'
import RequestDrawer from './components/RequestDrawer.vue'
import TemplatesTab from './components/TemplatesTab.vue'
import { isProgressing, isTerminal, leasableTemplates, sweepCommand, templatesByVersion } from './lab'
import { LEASES_KEY, PROVISIONS_KEY, useLab } from './useLab'

// Lab, environments first (docs/planning/web-console.md, decision 2): the
// leases you have now, a request drawer one click away, and templates and
// provisioning records on their own tabs.
const { leases, templates, provisions, provisioningAccounts, projects } = useLab()
const queryClient = useQueryClient()
// One clock for every TTL countdown on the page.
const now = ref(Date.now())
useIntervalFn(() => (now.value = Date.now()), 1000)

type Tab = 'environments' | 'templates' | 'provisions' | 'history'
const tab = ref<Tab>('environments')
const drawerOpen = ref(false)

const allLeases = computed(() => leases.data.value ?? [])
const allTemplates = computed(() => templates.data.value ?? [])
const byVersion = computed(() => templatesByVersion(allTemplates.value))
const projectNames = computed(() => new Map((projects.data.value?.items ?? []).map(p => [p.id, p.name])))

/**
 * Active leases, most urgent first: failures that still own resources, then
 * ready leases by the soonest expiry, then those still coming up by age.
 */
const active = computed(() => {
  const rank = (lease: LeaseDto) =>
    lease.state === 'cleanup_failed' ? 0 : lease.state === 'ready' ? 1 : 2
  return allLeases.value
    .filter(lease => !isTerminal(lease.state) || lease.state === 'cleanup_failed')
    .sort((a, b) => rank(a) - rank(b)
      || (a.expiresAt ?? Number.MAX_SAFE_INTEGER) - (b.expiresAt ?? Number.MAX_SAFE_INTEGER)
      || b.createdAt - a.createdAt)
})

const history = computed(() =>
  allLeases.value
    .filter(lease => lease.state === 'released' || lease.state === 'failed')
    .sort((a, b) => b.createdAt - a.createdAt),
)

const counts = computed(() => ({
  ready: allLeases.value.filter(l => l.state === 'ready').length,
  progressing: allLeases.value.filter(l => isProgressing(l.state) || l.state === 'releasing').length,
  failing: allLeases.value.filter(l => l.state === 'cleanup_failed').length,
  released: allLeases.value.filter(l => l.state === 'released').length,
}))

const leasable = computed(() => leasableTemplates(allTemplates.value))

// Sweep: the expiry sweeper runs on its own; this runs it now.
const sweepOpen = ref(false)
const sweepBusy = ref(false)
const sweepResult = ref('')
const sweepError = ref('')

async function sweep() {
  sweepBusy.value = true
  sweepError.value = ''
  sweepResult.value = ''
  try {
    const response = await sweepLabLeases()
    if (response.status !== 200)
      throw new Error((response.data as { message?: string })?.message ?? `sweep failed (${response.status})`)
    const swept = (response.data as { items: LeaseDto[] }).items.length
    sweepResult.value = swept === 0 ? 'Nothing was due.' : `${swept} lease${swept === 1 ? '' : 's'} swept.`
    sweepOpen.value = false
    await Promise.all([
      queryClient.invalidateQueries({ queryKey: LEASES_KEY }),
      queryClient.invalidateQueries({ queryKey: PROVISIONS_KEY }),
    ])
  }
  catch (caught) {
    sweepError.value = errorMessage(caught)
  }
  finally {
    sweepBusy.value = false
  }
}

// A provisioning operation started from the drawer, followed here.
const startedOperation = ref<string | null>(null)
function onCreated(_lease: LeaseDto, operationId: string | null) {
  startedOperation.value = operationId
  tab.value = 'environments'
}

const TABS: { id: Tab, label: string, count: () => number | null }[] = [
  { id: 'environments', label: 'Environments', count: () => active.value.length },
  { id: 'templates', label: 'Templates', count: () => allTemplates.value.length },
  { id: 'provisions', label: 'Provisions', count: () => provisions.data.value?.length ?? null },
  { id: 'history', label: 'History', count: () => history.value.length },
]

const loadError = computed(() => {
  const failed = [
    leases.error.value && `leases: ${errorMessage(leases.error.value)}`,
    templates.error.value && `templates: ${errorMessage(templates.error.value)}`,
  ].filter(Boolean)
  return failed.length ? failed.join(' · ') : ''
})
</script>

<template>
  <div>
    <div class="flex flex-wrap items-end gap-4">
      <div>
        <p class="fc-kicker">
          disposable environments · destroy by default
        </p>
        <h1 class="fc-h1">
          Lab
        </h1>
      </div>
      <div class="ml-auto flex gap-2">
        <button
          type="button"
          class="h-9 rounded-sm border border-input px-3 font-head text-xs font-bold hover:border-fc-muted"
          :aria-expanded="sweepOpen"
          @click="sweepOpen = !sweepOpen; sweepError = ''"
        >
          Sweep expired
        </button>
        <button
          type="button"
          class="fc-grad-bg h-9 rounded-sm px-3.5 font-head text-xs font-bold"
          data-testid="new-environment"
          @click="drawerOpen = true"
        >
          + New environment
        </button>
      </div>
    </div>

    <div
      v-if="sweepOpen"
      class="mt-3 grid gap-2 rounded-sm border border-fc-line bg-fc-inset p-3 text-xs"
    >
      <p>Release every lease past its TTL or maximum lifetime now and retry failed cleanups. The sweeper also does this on its own schedule.</p>
      <CopyFleetctl :command="sweepCommand()" />
      <div class="flex gap-2">
        <button
          type="button"
          class="h-8 rounded-sm border border-fc-err bg-fc-err/10 px-3 font-semibold text-fc-err disabled:opacity-50"
          :disabled="sweepBusy"
          @click="sweep"
        >
          Sweep now
        </button>
        <button
          type="button"
          class="h-8 px-2 text-fc-muted hover:text-fc-ink"
          @click="sweepOpen = false"
        >
          Cancel
        </button>
      </div>
      <p
        v-if="sweepError"
        class="text-fc-err"
        role="alert"
      >
        {{ sweepError }}
      </p>
    </div>
    <p
      v-if="sweepResult"
      class="mt-3 text-xs text-fc-muted"
      role="status"
    >
      {{ sweepResult }}
    </p>

    <div
      class="mt-4 flex gap-6 border-b border-fc-line"
      role="tablist"
    >
      <button
        v-for="item in TABS"
        :key="item.id"
        type="button"
        role="tab"
        class="pb-2 text-[13px] font-semibold"
        :class="tab === item.id ? 'text-fc-ink shadow-[inset_0_-2px_0_var(--fc-g1)]' : 'text-fc-muted hover:text-fc-ink'"
        :aria-selected="tab === item.id"
        :data-testid="`tab-${item.id}`"
        @click="tab = item.id"
      >
        {{ item.label }}<span
          v-if="item.count() !== null"
          class="ml-1 font-mono text-[10px] text-fc-faint"
        >{{ item.count() }}</span>
      </button>
    </div>

    <div
      v-if="loadError"
      class="mt-4 border-l-2 border-l-fc-err bg-card px-3 py-2 text-xs text-fc-muted"
      role="alert"
    >
      Could not load {{ loadError }}
    </div>

    <div
      v-if="leases.isLoading.value || templates.isLoading.value"
      class="mt-4 grid gap-3"
    >
      <Skeleton
        v-for="i in 3"
        :key="i"
        class="h-28 rounded-sm"
      />
    </div>

    <template v-else-if="tab === 'environments'">
      <div class="mt-4 grid grid-cols-2 gap-2.5 md:grid-cols-4">
        <div class="rounded-sm border border-fc-line bg-card px-3.5 py-3">
          <p class="fc-kicker">
            Ready
          </p>
          <p class="font-head text-2xl font-extrabold">
            {{ counts.ready }}
          </p>
        </div>
        <div class="rounded-sm border border-fc-line bg-card px-3.5 py-3">
          <p class="fc-kicker">
            In progress
          </p>
          <p class="font-head text-2xl font-extrabold">
            {{ counts.progressing }}
          </p>
        </div>
        <div class="rounded-sm border border-fc-line bg-card px-3.5 py-3">
          <p class="fc-kicker">
            Cleanup failed
          </p>
          <p
            class="font-head text-2xl font-extrabold"
            :class="{ 'text-fc-err': counts.failing > 0 }"
          >
            {{ counts.failing }}
          </p>
        </div>
        <div class="rounded-sm border border-fc-line bg-card px-3.5 py-3">
          <p class="fc-kicker">
            Released
          </p>
          <p class="font-head text-2xl font-extrabold">
            {{ counts.released }}
          </p>
        </div>
      </div>

      <div
        v-if="startedOperation"
        class="mt-4"
      >
        <OperationStatus
          :operation-id="startedOperation"
          label="Provisioning"
          dismissible
          @dismiss="startedOperation = null"
        />
      </div>

      <div class="mt-7 flex items-baseline justify-between border-b-2 border-fc-ink pb-1.5">
        <h2 class="font-head text-sm font-extrabold uppercase tracking-wide">
          Active
        </h2>
        <span class="fc-kicker">most urgent first</span>
      </div>
      <div
        v-if="active.length === 0 && !leases.error.value"
        class="mt-3 rounded-sm border border-fc-line bg-card p-8 text-center"
        data-testid="no-leases"
      >
        <p class="text-sm font-semibold">
          No active environments
        </p>
        <p class="mt-1 text-xs text-fc-muted">
          Request one from a published template; it is destroyed when released or when its TTL runs out.
        </p>
      </div>
      <div
        v-else
        class="mt-3 grid gap-2.5"
      >
        <LeaseCard
          v-for="lease in active"
          :key="lease.id"
          :lease="lease"
          :template="byVersion.get(lease.templateVersionId) ?? null"
          :project-name="lease.projectId ? projectNames.get(lease.projectId) ?? null : null"
          :accounts="provisioningAccounts"
          :now="now"
        />
      </div>
    </template>

    <div
      v-else-if="tab === 'templates'"
      class="mt-4"
    >
      <TemplatesTab
        :templates="allTemplates"
        :now="now"
      />
    </div>

    <div
      v-else-if="tab === 'provisions'"
      class="mt-4"
    >
      <p
        v-if="provisions.error.value"
        class="border-l-2 border-l-fc-err bg-card px-3 py-2 text-xs text-fc-muted"
        role="alert"
      >
        Could not load provisioning records: {{ errorMessage(provisions.error.value) }}
      </p>
      <ProvisionsTab
        v-else
        :provisions="provisions.data.value ?? []"
        :templates="allTemplates"
        :now="now"
      />
    </div>

    <div
      v-else
      class="mt-4 grid gap-2.5"
    >
      <p
        v-if="history.length === 0"
        class="rounded-sm border border-fc-line bg-card p-6 text-center text-sm text-fc-muted"
      >
        No released or failed leases yet.
      </p>
      <LeaseCard
        v-for="lease in history"
        :key="lease.id"
        :lease="lease"
        :template="byVersion.get(lease.templateVersionId) ?? null"
        :project-name="lease.projectId ? projectNames.get(lease.projectId) ?? null : null"
        :accounts="provisioningAccounts"
        :now="now"
      />
    </div>

    <RequestDrawer
      v-model:open="drawerOpen"
      :templates="leasable"
      :projects="projects.data.value?.items ?? []"
      :accounts="provisioningAccounts"
      @created="onCreated"
    />
  </div>
</template>
