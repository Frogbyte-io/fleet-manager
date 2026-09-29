<script setup lang="ts">
import { computed } from 'vue'

import type { MachineDto } from '@frogbyte-io/fleet-api-client'
import StatusChip from '@/components/fleet/StatusChip.vue'

import {
  describeIdentity,
  driftLabel,
  driftTone,
  driftView,
  groupDifferences,
  STATE_EXPLANATION,
  STATE_LABEL,
} from '../../drift/drift'
import { useMachineDrift } from '../../drift/useDrift'
import { errorMessage } from '../api'
import CopyFleetctl from '../components/CopyFleetctl.vue'

// The machine's drift against the active desired revision (FM-408): what
// Fleet Git wants, compared with what was last observed. Nothing here acts;
// changes go through a reviewed plan.
const props = defineProps<{ machine: MachineDto }>()

const query = useMachineDrift(() => props.machine.id)
const entry = computed(() => query.data.value ?? null)
const view = computed(() => (entry.value ? driftView(entry.value) : null))
const groups = computed(() => groupDifferences(entry.value?.differences ?? []))
</script>

<template>
  <section
    class="space-y-3"
    data-testid="desired-tab"
  >
    <p
      v-if="query.isLoading.value"
      class="text-xs text-fc-muted"
    >
      Comparing with the desired state…
    </p>
    <p
      v-else-if="query.error.value"
      class="text-xs text-fc-err"
      data-testid="desired-error"
    >
      Drift could not be read: {{ errorMessage(query.error.value) }}
    </p>
    <template v-else-if="entry && view">
      <div class="flex flex-wrap items-center gap-3">
        <StatusChip
          :label="driftLabel(view)"
          :tone="driftTone(view)"
          data-testid="desired-status"
        />
        <span
          v-if="entry.revision"
          class="font-mono text-[10px] tracking-wide text-fc-faint"
          data-testid="desired-revision"
        >revision {{ entry.revision.commitSha.slice(0, 12) }}</span>
      </div>

      <p
        v-if="view.kind === 'no-revision'"
        class="rounded-sm border border-fc-line p-4 text-sm text-fc-muted"
        data-testid="desired-none"
      >
        No desired revision is active, so there is nothing to compare this machine with. Fetch and activate one from Fleet Git.
      </p>
      <p
        v-else-if="view.kind === 'unavailable'"
        class="rounded-sm border border-fc-err/40 p-4 text-sm text-fc-err"
        data-testid="desired-unavailable"
      >
        {{ view.detail }}
      </p>
      <p
        v-else-if="view.kind === 'in-sync'"
        class="rounded-sm border border-fc-line p-4 text-sm text-fc-muted"
        data-testid="desired-in-sync"
      >
        Everything Fleet Git manages on this machine matches what was last observed.
      </p>

      <div
        v-for="group in groups"
        :key="group.state"
        class="space-y-1"
        :data-testid="`desired-group-${group.state}`"
      >
        <h3 class="fc-kicker border-b border-fc-line pb-1">
          {{ STATE_LABEL[group.state] }} · {{ group.items.length }}
          <span class="ml-2 font-sans text-[11px] normal-case tracking-normal text-fc-faint">{{ STATE_EXPLANATION[group.state] }}</span>
        </h3>
        <ul class="space-y-1">
          <li
            v-for="difference in group.items"
            :key="difference.identity"
            class="rounded-sm border border-fc-line bg-card px-3 py-1.5 text-xs"
            :data-testid="`difference-${difference.identity}`"
          >
            <span class="font-mono text-[10px] uppercase tracking-wide text-fc-faint">{{ describeIdentity(difference.identity).kind }}</span>
            <span class="ml-2 font-semibold text-fc-ink">{{ describeIdentity(difference.identity).name }}</span>
            <span
              v-if="describeIdentity(difference.identity).agent"
              class="ml-1 text-fc-muted"
            >on {{ describeIdentity(difference.identity).agent }}</span>
            <span
              v-if="difference.desired"
              class="ml-2 text-fc-muted"
            >desired {{ difference.desired }}</span>
            <span
              v-if="difference.observed"
              class="ml-2 text-fc-muted"
            >observed {{ difference.observed }}</span>
            <span
              v-if="difference.reason"
              class="mt-0.5 block text-fc-faint"
            >{{ difference.reason }}</span>
          </li>
        </ul>
      </div>

      <div
        v-if="view.kind === 'drifted'"
        class="space-y-1 text-[11px] text-fc-faint"
      >
        <p>Review what would change, then apply the reviewed plan:</p>
        <CopyFleetctl :command="`fleetctl plan ${machine.id}`" />
      </div>
    </template>
  </section>
</template>
