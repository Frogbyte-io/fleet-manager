<script setup lang="ts">
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from '@/components/ui/sheet'
import { RouterLink } from 'vue-router'
import StatusChip from '@/components/fleet/StatusChip.vue'
import { guestAgentLabel, guestStatusTone, type GuestItem } from '../inventory'

defineProps<{
  guest: GuestItem | null
  open: boolean
}>()

const emit = defineEmits<{ 'update:open': [value: boolean] }>()
</script>

<template>
  <Sheet
    :open="open"
    @update:open="emit('update:open', $event)"
  >
    <SheetContent
      v-if="guest"
      side="right"
      class="w-[380px] overflow-y-auto border-fc-line bg-fc-panel sm:w-[380px]"
    >
      <SheetHeader>
        <SheetTitle class="flex items-center gap-2 text-base">
          {{ guest.name }}
          <StatusChip
            :label="guest.status.toUpperCase()"
            :tone="guestStatusTone(guest.status)"
          />
        </SheetTitle>
        <SheetDescription class="fc-kicker">
          {{ guest.kind === 'vm' ? `QEMU ${guest.vmid ?? '—'}` : `LXC ${guest.vmid ?? '—'}` }} · ON {{ guest.node }}
        </SheetDescription>
      </SheetHeader>

      <div class="mt-2 space-y-4 px-4 pb-6">
        <dl class="grid grid-cols-[110px_1fr] gap-x-3 gap-y-1.5 text-xs">
          <dt class="text-fc-faint">
            Status
          </dt>
          <dd class="font-mono text-fc-ink">
            {{ guest.status.toUpperCase() }}
          </dd>
          <dt class="text-fc-faint">
            VMID
          </dt>
          <dd class="font-mono text-fc-ink">
            {{ guest.vmid ?? '—' }}
          </dd>
          <dt class="text-fc-faint">
            Node
          </dt>
          <dd class="font-mono text-fc-ink">
            {{ guest.node }}
          </dd>
          <dt class="text-fc-faint">
            Proxmox account
          </dt>
          <dd class="font-mono text-fc-ink">
            {{ guest.accountName }}
          </dd>
          <dt class="text-fc-faint">
            Guest agent
          </dt>
          <dd class="font-mono text-fc-ink">
            {{ guestAgentLabel(guest.agentOnline) }}<template v-if="guest.osName">
              · {{ guest.osName }}
            </template>
          </dd>
          <dt class="text-fc-faint">
            Candidates
          </dt>
          <dd class="font-mono text-fc-info">
            <div
              v-for="candidate in guest.candidates"
              :key="candidate.machineId"
            >
              ≈
              <RouterLink
                :to="`/fleet?focus=${candidate.machineId}`"
                class="underline decoration-dotted hover:text-fc-ink"
              >
                {{ candidate.machineName }}
              </RouterLink>
              ({{ candidate.evidence }})
            </div>
            <div
              v-if="guest.candidates.length === 0"
              class="uppercase"
            >
              Not linked to a Fleet machine
            </div>
          </dd>
        </dl>

        <p class="border-t border-fc-line pt-3 text-xs text-fc-faint">
          Lifecycle actions move to the machine page (FM-911).
        </p>
      </div>
    </SheetContent>
  </Sheet>
</template>
