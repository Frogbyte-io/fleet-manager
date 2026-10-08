<script setup lang="ts">
import { computed } from 'vue'

import StatusChip from '@/components/fleet/StatusChip.vue'

import type { ExecOutput } from '../lab'

// One command's bounded output as the controller recorded it on the
// operation: the exit code, then stdout and stderr, each marked when the
// controller cut it.
const props = defineProps<{ output: ExecOutput }>()

const exitLabel = computed(() => (props.output.exitCode === null ? 'no exit code' : `exit ${props.output.exitCode}`))
// A nonzero exit failed; no exit code at all (killed, never ran) is a
// warning beside its stated reason, not a claim about the command.
const exitTone = computed(() => {
  if (props.output.exitCode === null)
    return 'warn' as const
  return props.output.exitCode === 0 ? 'ok' as const : 'err' as const
})

const streams = computed(() => [
  { name: 'stdout', text: props.output.stdout, truncated: props.output.truncatedStdout },
  { name: 'stderr', text: props.output.stderr, truncated: props.output.truncatedStderr },
])
</script>

<template>
  <div
    class="grid gap-2 text-xs"
    data-testid="exec-result"
  >
    <div class="flex flex-wrap items-center gap-2">
      <StatusChip
        :label="exitLabel"
        :tone="exitTone"
        data-testid="exit-code"
      />
      <span
        v-if="output.reason"
        class="font-mono text-[10.5px] text-fc-err"
      >{{ output.reason }}</span>
    </div>
    <p
      v-if="output.detail"
      class="text-fc-muted"
    >
      {{ output.detail }}
    </p>
    <div
      v-for="stream in streams"
      :key="stream.name"
    >
      <p class="fc-kicker flex gap-2">
        {{ stream.name }}
        <span
          v-if="stream.truncated"
          class="text-fc-warn"
          :data-testid="`${stream.name}-truncated`"
        >truncated by the controller</span>
      </p>
      <pre
        class="mt-1 max-h-64 overflow-auto whitespace-pre-wrap break-all rounded-sm border border-fc-line bg-fc-inset p-2 font-mono text-[11.5px] text-fc-ink"
        :data-testid="`exec-${stream.name}`"
      >{{ stream.text || '(empty)' }}</pre>
    </div>
  </div>
</template>
