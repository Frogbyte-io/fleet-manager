<script setup lang="ts">
import { computed } from 'vue'

import type { OperationDto } from '@frogbyte-io/fleet-api-client'

import { isTargetConflict, readOutcome } from '../actions'

// Conflicts and held-back removals are data for a person to resolve, never
// something Fleet retries or forces. The ways out are the ones Skills
// Manager's own `manage-skills` instructions document (v1.40.0).
const props = defineProps<{ operation: OperationDto }>()

const outcome = computed(() => readOutcome(props.operation))
const conflict = computed(() => isTargetConflict(outcome.value))
const heldBack = computed(() => outcome.value.heldBack.length > 0)
</script>

<template>
  <div
    v-if="conflict"
    class="rounded-sm border border-fc-warn/40 bg-fc-warn/5 p-3 text-xs"
    role="alert"
    data-testid="outcome-conflict"
  >
    <p class="font-semibold text-fc-warn">
      Target conflict — a directory Skills Manager does not manage is in the way
    </p>
    <ul
      v-if="outcome.conflicts.length"
      class="mt-1 list-disc pl-5 font-mono text-[11px] text-fc-ink"
    >
      <li
        v-for="path in outcome.conflicts"
        :key="path"
      >
        {{ path }}
      </li>
    </ul>
    <p
      v-else
      class="mt-1 text-fc-muted"
    >
      The controller did not report the conflicting path{{ outcome.detail ? `: ${outcome.detail}` : '.' }}
    </p>
    <p class="mt-2 text-fc-muted">
      Its contents are untouched. Two ways out: <strong class="text-fc-ink">adopt</strong> it into the library (Adopt, dry run first), or <strong class="text-fc-ink">move it aside</strong> on the machine and retry. Fleet never deletes it for you.
    </p>
  </div>
  <div
    v-if="heldBack"
    class="rounded-sm border border-fc-warn/40 bg-fc-warn/5 p-3 text-xs"
    role="alert"
    data-testid="outcome-held-back"
  >
    <p class="font-semibold text-fc-warn">
      Update held back — the new source no longer ships these paths
    </p>
    <ul class="mt-1 list-disc pl-5 font-mono text-[11px] text-fc-ink">
      <li
        v-for="path in outcome.heldBack"
        :key="path"
      >
        {{ path }}
      </li>
    </ul>
    <p class="mt-2 text-fc-muted">
      The skill is untouched and still on its previous version; this is not a failure to retry. Either restore these paths in the source (for Fleet-authored skills, add them back and publish a new version), or confirm in the Skills Manager desktop app that they are expendable — the CLI has no override, so only a person can decide.
    </p>
  </div>
</template>
