<script setup lang="ts">
import { computed } from 'vue'
import { RouterLink } from 'vue-router'

import type { ActionRequestDto } from '@frogbyte-io/fleet-api-client'
import StatusChip from '@/components/fleet/StatusChip.vue'

import { riskTone } from '../../requests/requests'
import { previewLines, requestOutcome } from '../settings'
import { useFiledRequest } from '../useServiceSettings'

// What happened to a request the console just filed: its state (kept fresh
// until it settles), what that means, the preview the approver reads, and the
// way to Approvals. The console decides nothing here; the controller's
// request is the truth.
const props = withDefaults(defineProps<{ request: ActionRequestDto, kind?: 'lifecycle' | 'settings' }>(), { kind: 'settings' })
const emit = defineEmits<{ dismiss: [] }>()

const live = useFiledRequest(() => props.request.id)
const current = computed(() => live.data.value ?? props.request)
const outcome = computed(() => requestOutcome(current.value, props.kind))
const preview = computed(() => previewLines(props.request.parameters))
</script>

<template>
  <div
    class="space-y-1.5 border border-fc-line border-l-2 bg-card px-3 py-2 text-xs"
    :class="outcome.tone === 'err' ? 'border-l-fc-err' : outcome.tone === 'ok' ? 'border-l-fc-ok' : outcome.tone === 'warn' ? 'border-l-fc-warn' : 'border-l-fc-info'"
    role="status"
    data-testid="filed-request"
  >
    <div class="flex flex-wrap items-center gap-2">
      <span class="font-mono text-[11px] text-fc-ink">{{ current.actionId }}</span>
      <StatusChip
        :label="`risk ${current.riskClass}`"
        :tone="riskTone(current.riskClass)"
      />
      <StatusChip
        :label="outcome.label"
        :tone="outcome.tone"
        data-testid="filed-state"
      />
      <button
        type="button"
        class="ml-auto font-mono text-[10px] uppercase tracking-wider text-fc-faint hover:text-fc-ink"
        data-testid="dismiss-filed"
        @click="emit('dismiss')"
      >
        Dismiss
      </button>
    </div>
    <p
      class="text-fc-muted"
      data-testid="filed-text"
    >
      {{ outcome.text }}
    </p>
    <ul
      v-if="preview.length > 0"
      class="grid gap-0.5 font-mono text-[11px] text-fc-muted"
      data-testid="filed-preview"
    >
      <li
        v-for="line in preview"
        :key="line"
        class="break-all"
      >
        {{ line }}
      </li>
    </ul>
    <RouterLink
      :to="`/requests?request=${encodeURIComponent(current.id)}`"
      class="inline-block font-mono text-[10px] uppercase tracking-wider text-fc-info hover:underline"
      data-testid="filed-link"
    >
      {{ current.state === 'pending' ? 'Open in Approvals →' : 'See the request in Approvals →' }}
    </RouterLink>
  </div>
</template>
