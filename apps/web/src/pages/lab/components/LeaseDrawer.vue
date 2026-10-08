<script setup lang="ts">
import { computed, ref, toRef, watch } from 'vue'
import { RouterLink } from 'vue-router'

import type { LabTemplateDto } from '@frogbyte-io/fleet-api-client'
import StatusChip from '@/components/fleet/StatusChip.vue'
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from '@/components/ui/sheet'

import { relativeTime } from '../../fleet/inventory'
import { errorMessage } from '../../machine/api'
import CopyFleetctl from '../../machine/components/CopyFleetctl.vue'
import {
  artifactsCommand,
  formatSpan,
  formatTimestamp,
  leaseTone,
  shortId,
  statusCommand,
} from '../lab'
import { useArtifacts, useLeaseDetail } from '../useLab'
import ArtifactList from './ArtifactList.vue'
import CleanupRetry from './CleanupRetry.vue'
import CollectPanel from './CollectPanel.vue'
import ExecPanel from './ExecPanel.vue'
import LeaseStepper from './LeaseStepper.vue'

// One lease in full (`fleetctl lab status`): its lifecycle with timestamps,
// where its guest landed, the Lab-owned machine it registered as, its
// cleanup attempts, and the command and artifact tools a ready lease allows.
const props = defineProps<{
  leaseId: string | null
  templates: Map<string, LabTemplateDto>
  projectNames: Map<string, string>
  now: number
}>()

const emit = defineEmits<{ close: [] }>()

type Tab = 'details' | 'exec' | 'artifacts'
const tab = ref<Tab>('details')
watch(() => props.leaseId, () => (tab.value = 'details'))

const detail = useLeaseDetail(toRef(props, 'leaseId'))
const lease = computed(() => detail.data.value ?? null)
const ready = computed(() => lease.value?.state === 'ready')

const artifacts = useArtifacts(
  computed(() => ({ leaseId: props.leaseId })),
  computed(() => props.leaseId !== null),
)
const artifactItems = computed(() => artifacts.data.value?.items ?? [])
const artifactError = computed(() => (artifacts.error.value ? errorMessage(artifacts.error.value) : ''))

function when(ms: number | null | undefined): string {
  if (ms === null || ms === undefined)
    return '—'
  const delta = Math.floor((ms - props.now) / 1000)
  return delta > 0 ? `in ${formatSpan(delta)}` : relativeTime(ms, props.now)
}

const timeline = computed(() => {
  const l = lease.value
  if (!l)
    return []
  return [
    { label: 'Requested', at: l.createdAt },
    { label: 'Ready', at: l.readyAt ?? null },
    { label: 'Expires', at: l.expiresAt ?? null },
    { label: 'Max lifetime', at: l.maxLifetimeAt },
  ]
})

const templateName = computed(() => {
  const l = lease.value
  return l ? props.templates.get(l.templateVersionId)?.name ?? `version ${shortId(l.templateVersionId)}` : ''
})

const TABS: { id: Tab, label: string }[] = [
  { id: 'details', label: 'Details' },
  { id: 'exec', label: 'Run command' },
  { id: 'artifacts', label: 'Artifacts' },
]

// Tabs per the console's pattern (ProxmoxPage): roving tabindex, arrows,
// Home and End.
function onTabKey(event: KeyboardEvent, index: number) {
  const last = TABS.length - 1
  const moves: Record<string, number> = { ArrowRight: index === last ? 0 : index + 1, ArrowLeft: index === 0 ? last : index - 1, Home: 0, End: last }
  const next = moves[event.key]
  if (next === undefined)
    return
  event.preventDefault()
  tab.value = TABS[next]!.id
  document.getElementById(`lease-tab-${TABS[next]!.id}`)?.focus()
}
</script>

<template>
  <Sheet
    :open="leaseId !== null"
    @update:open="(open: boolean) => { if (!open) emit('close') }"
  >
    <SheetContent
      side="right"
      class="w-full overflow-y-auto border-fc-line bg-fc-panel sm:w-[520px] sm:max-w-[520px]"
      data-testid="lease-drawer"
    >
      <SheetHeader>
        <p class="fc-kicker">
          lab lease · {{ leaseId ? shortId(leaseId) : '' }}
        </p>
        <SheetTitle class="flex flex-wrap items-center gap-2 font-head text-base font-extrabold">
          {{ lease?.purpose || (detail.isLoading.value ? 'Loading…' : 'Lease') }}
          <StatusChip
            v-if="lease"
            :label="lease.state.replaceAll('_', ' ')"
            :tone="leaseTone(lease.state)"
          />
        </SheetTitle>
        <SheetDescription class="text-xs text-fc-muted">
          Reflects the controller's last observation.
        </SheetDescription>
      </SheetHeader>

      <div class="grid grid-cols-[minmax(0,1fr)] gap-4 px-4 pb-6 text-sm">
        <p
          v-if="detail.error.value"
          class="border-l-2 border-l-fc-err bg-card px-3 py-2 text-xs text-fc-muted"
          role="alert"
        >
          Could not load the lease: {{ errorMessage(detail.error.value) }}
        </p>

        <template v-if="lease">
          <div
            class="flex gap-5 border-b border-fc-line"
            role="tablist"
            aria-label="Lease sections"
          >
            <button
              v-for="(item, index) in TABS"
              :id="`lease-tab-${item.id}`"
              :key="item.id"
              type="button"
              role="tab"
              :tabindex="tab === item.id ? 0 : -1"
              :aria-controls="`lease-panel-${item.id}`"
              class="pb-2 text-[13px] font-semibold"
              :class="tab === item.id ? 'text-fc-ink shadow-[inset_0_-2px_0_var(--fc-g1)]' : 'text-fc-muted hover:text-fc-ink'"
              :aria-selected="tab === item.id"
              :data-testid="`lease-tab-${item.id}`"
              @click="tab = item.id"
              @keydown="onTabKey($event, index)"
            >
              {{ item.label }}<span
                v-if="item.id === 'artifacts' && artifacts.data.value"
                class="ml-1 font-mono text-[10px] text-fc-faint"
              >{{ artifactItems.length }}</span>
            </button>
          </div>

          <!-- Panels stay mounted (v-show), so a typed command or a running one survives a tab switch. -->
          <div
            v-show="tab === 'details'"
            id="lease-panel-details"
            role="tabpanel"
            aria-labelledby="lease-tab-details"
            class="grid grid-cols-[minmax(0,1fr)] gap-4"
          >
            <LeaseStepper :lease="lease" />

            <dl
              class="grid grid-cols-[auto_minmax(0,1fr)] gap-x-4 gap-y-1 font-mono text-[10.5px] uppercase tracking-wide"
              data-testid="lease-timeline"
            >
              <template
                v-for="row in timeline"
                :key="row.label"
              >
                <dt class="text-fc-muted">
                  {{ row.label }}
                </dt>
                <dd class="break-words text-fc-ink">
                  <template v-if="row.at !== null">
                    {{ when(row.at) }} <span class="text-fc-faint normal-case">· {{ formatTimestamp(row.at) }}</span>
                  </template>
                  <template v-else>
                    —
                  </template>
                </dd>
              </template>
            </dl>

            <section class="grid gap-1.5">
              <h3 class="fc-kicker border-b border-fc-line pb-1">
                Identity
              </h3>
              <dl class="grid grid-cols-[auto_minmax(0,1fr)] gap-x-4 gap-y-1 text-xs">
                <dt class="fc-kicker">
                  Template
                </dt>
                <dd>{{ templateName }}</dd>
                <dt class="fc-kicker">
                  Owner
                </dt>
                <dd class="font-mono">
                  {{ lease.owner }}
                </dd>
                <dt class="fc-kicker">
                  Project
                </dt>
                <dd data-testid="lease-project">
                  {{ lease.projectId ? projectNames.get(lease.projectId) ?? shortId(lease.projectId) : 'None' }}
                </dd>
              </dl>
            </section>

            <section
              class="grid gap-1.5"
              data-testid="lease-placement"
            >
              <h3 class="fc-kicker border-b border-fc-line pb-1">
                Placement
              </h3>
              <dl class="grid grid-cols-[auto_minmax(0,1fr)] gap-x-4 gap-y-1 text-xs">
                <dt class="fc-kicker">
                  Node
                </dt>
                <dd
                  class="font-mono"
                  data-testid="lease-node"
                >
                  {{ lease.node ?? 'not placed yet' }}
                </dd>
                <dt class="fc-kicker">
                  VMID
                </dt>
                <dd
                  class="font-mono"
                  data-testid="lease-vmid"
                >
                  {{ lease.vmid ?? '—' }}
                </dd>
                <template v-if="lease.provisionState">
                  <dt class="fc-kicker">
                    Guest
                  </dt>
                  <dd class="font-mono">
                    {{ lease.provisionState.replaceAll('_', ' ') }}
                  </dd>
                </template>
                <template v-if="lease.address">
                  <dt class="fc-kicker">
                    Address
                  </dt>
                  <dd class="font-mono">
                    {{ lease.address }}
                  </dd>
                </template>
                <template v-if="lease.failedStep">
                  <dt class="fc-kicker text-fc-err">
                    Failed at
                  </dt>
                  <dd
                    class="font-mono text-fc-err"
                    data-testid="lease-failed-step"
                  >
                    {{ lease.failedStep }}
                  </dd>
                </template>
                <dt class="fc-kicker">
                  Machine
                </dt>
                <dd>
                  <RouterLink
                    v-if="lease.machineId"
                    :to="`/fleet/machines/${lease.machineId}`"
                    class="font-mono text-fc-info hover:text-fc-ink"
                    data-testid="lease-machine"
                  >
                    Lab-owned machine {{ shortId(lease.machineId) }} →
                  </RouterLink>
                  <span
                    v-else
                    class="text-fc-muted"
                  >Not registered yet</span>
                </dd>
              </dl>
            </section>

            <section
              class="grid gap-1.5"
              data-testid="lease-cleanup"
            >
              <h3 class="fc-kicker border-b border-fc-line pb-1">
                Cleanup
              </h3>
              <dl class="grid grid-cols-[auto_minmax(0,1fr)] gap-x-4 gap-y-1 text-xs">
                <dt class="fc-kicker">
                  Strategy
                </dt>
                <dd class="font-mono">
                  {{ lease.cleanup }}
                </dd>
                <dt class="fc-kicker">
                  Failed attempts
                </dt>
                <dd
                  class="font-mono"
                  :class="{ 'text-fc-err': lease.cleanupAttempts > 0 }"
                  data-testid="cleanup-attempts"
                >
                  {{ lease.cleanupAttempts }}
                </dd>
                <template v-if="lease.cleanupNextAt">
                  <dt class="fc-kicker">
                    Next attempt
                  </dt>
                  <dd
                    class="font-mono"
                    data-testid="cleanup-next"
                  >
                    {{ when(lease.cleanupNextAt) }} <span class="text-fc-faint">· {{ formatTimestamp(lease.cleanupNextAt) }}</span>
                  </dd>
                </template>
              </dl>
              <p
                v-if="lease.state === 'cleanup_failed'"
                class="text-xs text-fc-err"
              >
                Cleanup gave up.<template v-if="lease.vmid !== null && lease.vmid !== undefined">
                  The lease may still hold its guest (VMID {{ lease.vmid }}<template v-if="lease.node">
                    on {{ lease.node }}
                  </template>) until a retried cleanup removes it.
                </template><template v-else>
                  Whatever the controller could not remove stays until a retried cleanup removes it.
                </template>
              </p>
              <CleanupRetry
                v-if="lease.state === 'cleanup_failed' || lease.state === 'releasing'"
                :lease-id="lease.id"
                :available="lease.state === 'cleanup_failed'"
              />
            </section>

            <p
              v-if="lease.collectionFailure"
              class="border-l-2 border-l-fc-warn bg-card px-3 py-2 text-xs"
              data-testid="collection-failure"
            >
              <span class="fc-kicker text-fc-warn">Last collection failed · {{ lease.collectionFailure.reason }} · {{ when(lease.collectionFailure.failedAt) }}</span>
              <span class="mt-1 block whitespace-pre-wrap break-words font-mono">{{ lease.collectionFailure.detail }}</span>
            </p>

            <CopyFleetctl :command="statusCommand(lease.id)" />
          </div>

          <div
            v-show="tab === 'exec'"
            id="lease-panel-exec"
            role="tabpanel"
            aria-labelledby="lease-tab-exec"
          >
            <ExecPanel
              :key="lease.id"
              :lease-id="lease.id"
              :ready="ready"
              :history="artifactItems"
              :history-loading="artifacts.isLoading.value"
              :history-error="artifactError"
              :now="now"
            />
          </div>

          <div
            v-show="tab === 'artifacts'"
            id="lease-panel-artifacts"
            role="tabpanel"
            aria-labelledby="lease-tab-artifacts"
            class="grid grid-cols-[minmax(0,1fr)] gap-4"
          >
            <CollectPanel
              :key="lease.id"
              :lease-id="lease.id"
              :ready="ready"
            />
            <p
              v-if="artifactError"
              class="border-l-2 border-l-fc-err bg-card px-3 py-2 text-xs text-fc-muted"
              role="alert"
            >
              Could not load artifacts: {{ artifactError }}
            </p>
            <p
              v-else-if="artifacts.isLoading.value"
              class="text-xs text-fc-muted"
            >
              Loading…
            </p>
            <p
              v-else-if="artifactItems.length === 0"
              class="text-xs text-fc-muted"
              data-testid="lease-artifacts-empty"
            >
              No artifacts from this lease.
            </p>
            <ArtifactList
              v-else
              :artifacts="artifactItems"
              :now="now"
            />
            <p
              v-if="artifacts.data.value?.truncated"
              class="text-xs text-fc-warn"
              data-testid="lease-artifacts-truncated"
            >
              Showing the newest {{ artifactItems.length }} artifacts; older ones (and older exec history) are not listed here.
            </p>
            <p class="break-all font-mono text-[10px] text-fc-faint">
              {{ artifactsCommand({ leaseId: lease.id }) }}
            </p>
          </div>
        </template>
      </div>
    </SheetContent>
  </Sheet>
</template>
