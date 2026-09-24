<script setup lang="ts">
import { computed } from 'vue'

import type { GuestItem } from '../../fleet/inventory'
import GuestPanel from '../components/GuestPanel.vue'

const props = defineProps<{
  guests: GuestItem[]
  machineId: string
  loading: boolean
}>()

const actionable = computed(() => props.guests.filter((g): g is GuestItem & { vmid: number } => g.vmid !== null))
</script>

<template>
  <div class="space-y-4">
    <p
      v-if="loading && guests.length === 0"
      class="text-xs text-fc-faint"
    >
      Loading Proxmox guests…
    </p>
    <p
      v-else-if="actionable.length === 0"
      class="text-sm text-fc-faint"
    >
      No Proxmox guest is associated with this machine.
    </p>
    <GuestPanel
      v-for="guest in actionable"
      :key="guest.key"
      :guest="guest"
      :machine-id="machineId"
    />
  </div>
</template>
