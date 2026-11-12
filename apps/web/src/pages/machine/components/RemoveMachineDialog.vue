<script setup lang="ts">
import { computed, ref } from 'vue'

import type { MachineDto, MachineRemovedDto } from '@frogbyte-io/fleet-api-client'
import { Dialog, DialogContent, DialogDescription, DialogTitle } from '@/components/ui/dialog'

import RemoveMachinePanel from './RemoveMachinePanel.vue'

// The machine page's Remove action. The page mounts this only while it is
// open, so every opening starts with a fresh review. The panel holds the
// review and the removal; this wrapper keeps the dialog open while a call is
// in flight, so a running uninstall is never left without its answer on
// screen, and reports `done` when a removed machine's dialog closes.
defineProps<{ machine: MachineDto }>()
const open = defineModel<boolean>('open', { required: true })
const emit = defineEmits<{ removed: [outcome: MachineRemovedDto], done: [] }>()

const busy = ref(false)
const removed = ref(false)

const dialogOpen = computed({
  get: () => open.value,
  set: (value: boolean) => {
    if (!value && busy.value)
      return
    open.value = value
    if (!value && removed.value)
      emit('done')
  },
})

function onRemoved(outcome: MachineRemovedDto) {
  removed.value = true
  emit('removed', outcome)
}
</script>

<template>
  <Dialog v-model:open="dialogOpen">
    <DialogContent
      class="max-h-[90vh] overflow-y-auto rounded-sm border-fc-line2 bg-fc-panel p-5 sm:max-w-2xl"
      data-testid="remove-machine-dialog"
    >
      <DialogTitle class="text-[17px] font-extrabold text-fc-ink">
        Remove {{ machine.name }}
      </DialogTitle>
      <DialogDescription class="-mt-2 text-xs text-fc-muted">
        Removes the machine from Fleet: its record, endpoints, facts, node identity, recorded skill installs and the
        pinned host keys of hosts no other machine uses. The controller reviews it first and refuses while anything
        holds the machine.
      </DialogDescription>
      <RemoveMachinePanel
        :machine="machine"
        @busy="busy = $event"
        @removed="onRemoved"
        @close="dialogOpen = false"
      />
    </DialogContent>
  </Dialog>
</template>
