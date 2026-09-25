<script setup lang="ts">
import { ref } from 'vue'

// Every mutation form shows its `fleetctl` equivalent (DESIGN.md §6). When
// the CLI has no such command, `command` is null and `missing` says so.
const props = defineProps<{
  command: string | null
  missing?: string
}>()

const copied = ref(false)

async function copy() {
  if (!props.command)
    return
  try {
    await navigator.clipboard.writeText(props.command)
    copied.value = true
    setTimeout(() => (copied.value = false), 1500)
  }
  catch {
    // Clipboard unavailable (insecure context); the command stays selectable below.
  }
}
</script>

<template>
  <div class="rounded-sm border border-fc-line bg-fc-inset p-2">
    <div class="flex items-center justify-between gap-2">
      <span class="fc-kicker">fleetctl</span>
      <button
        v-if="command"
        type="button"
        class="font-mono text-[10px] uppercase tracking-wider text-fc-info hover:text-fc-ink"
        data-testid="copy-fleetctl"
        @click="copy"
      >
        {{ copied ? 'Copied' : 'Copy as fleetctl' }}
      </button>
    </div>
    <pre
      v-if="command"
      class="mt-1 overflow-x-auto whitespace-pre-wrap break-all font-mono text-[11px] text-fc-ink"
      data-testid="fleetctl-command"
    >{{ command }}</pre>
    <p
      v-else
      class="mt-1 text-xs text-fc-faint"
    >
      {{ missing ?? 'fleetctl has no equivalent command yet.' }}
    </p>
  </div>
</template>
