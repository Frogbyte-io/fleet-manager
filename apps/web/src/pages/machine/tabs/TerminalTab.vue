<script setup lang="ts">
import { useQuery } from '@tanstack/vue-query'
import { computed, defineAsyncComponent } from 'vue'

import { getSystemInfo } from '@frogbyte-io/fleet-api-client'

// The Terminal tab (#494). The panel and its xterm dependency load only when
// the tab is opened.
const MachineTerminal = defineAsyncComponent(() => import('../terminal/MachineTerminal.vue'))

defineProps<{
  machineId: string
  /** Whether the machine has an SSH endpoint to open a shell on. */
  hasSsh: boolean
}>()

// The trusted-LAN caveat only applies in that mode; the shell already asks
// for the system view (same cache key), which names the mode.
const system = useQuery({ queryKey: ['system'], queryFn: () => getSystemInfo(), retry: 1 })
const trustedLan = computed(() => {
  const answer = system.data.value
  return answer?.status === 200 && answer.data.trustMode === 'trusted-lan'
})
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
    :trusted-lan="trustedLan"
  />
</template>
