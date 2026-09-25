<script setup lang="ts">
import { computed } from 'vue'

import type { GuestItem, SourceEntry } from '../../fleet/inventory'
import GuestPanel from '../components/GuestPanel.vue'

const props = defineProps<{
  guests: GuestItem[]
  machineId: string
  loading: boolean
  /** Proxmox sources that failed or answered partially. */
  problems: SourceEntry[]
}>()

const actionable = computed(() => props.guests.filter((g): g is GuestItem & { vmid: number } => g.vmid !== null))
</script>

<template>
  <div class="space-y-4">
    <p
      v-for="problem in problems"
      :key="problem.key"
      class="rounded-sm border-l-2 px-3 py-2 text-xs"
      :class="problem.state === 'error' ? 'border-fc-err text-fc-err' : 'border-fc-warn text-fc-warn'"
      data-testid="proxmox-problem"
    >
      {{ problem.label }}: {{ problem.message }}
    </p>
    <p
      v-if="loading && actionable.length === 0"
      class="text-xs text-fc-faint"
    >
      Loading Proxmox guests…
    </p>
    <p
      v-else-if="actionable.length === 0"
      class="text-sm text-fc-faint"
    >
      {{ problems.length > 0 ? 'No associated Proxmox guest among the sources that answered.' : 'No Proxmox guest is associated with this machine.' }}
    </p>
    <GuestPanel
      v-for="guest in actionable"
      :key="guest.key"
      :guest="guest"
      :machine-id="machineId"
    />
  </div>
</template>
