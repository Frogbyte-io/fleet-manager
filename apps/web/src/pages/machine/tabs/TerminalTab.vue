<script setup lang="ts">
import { defineAsyncComponent } from 'vue'

// The Terminal tab (#494). The panel and its xterm dependency load only when
// the tab is opened.
const MachineTerminal = defineAsyncComponent(() => import('../terminal/MachineTerminal.vue'))

defineProps<{
  machineId: string
  /** Whether the machine has an SSH endpoint to open a shell on. */
  hasSsh: boolean
}>()
</script>

<template>
  <p
    v-if="!hasSsh"
    class="text-sm text-fc-faint"
    data-testid="terminal-no-ssh"
  >
    This machine has no SSH endpoint, so there is no shell to open.
  </p>
  <MachineTerminal
    v-else
    :key="machineId"
    :machine-id="machineId"
  />
</template>
