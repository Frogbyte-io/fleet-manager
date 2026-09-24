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
import type { PageMachineDtoItemsItem } from '@frogbyte-io/fleet-api-client'
import { machineStatusTone, osLine, relativeTime, resourcesLine, type MachineItem } from '../inventory'

defineProps<{
  machine: MachineItem | null
  raw: PageMachineDtoItemsItem | null
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
      v-if="machine"
      side="right"
      class="w-[380px] overflow-y-auto border-fc-line bg-fc-panel sm:w-[380px]"
    >
      <SheetHeader>
        <SheetTitle class="flex items-center gap-2 text-base">
          {{ machine.name }}
          <StatusChip
            :label="machine.status"
            :tone="machineStatusTone(machine.status)"
          />
        </SheetTitle>
        <SheetDescription class="fc-kicker">
          MACHINE
        </SheetDescription>
      </SheetHeader>

      <div class="mt-2 space-y-4 px-4 pb-6">
        <dl class="grid grid-cols-[110px_1fr] gap-x-3 gap-y-1.5 text-xs">
          <dt class="text-fc-faint">
            Hardware
          </dt>
          <dd class="font-mono text-fc-ink">
            {{ resourcesLine(machine) ?? 'Not observed yet' }}
          </dd>
          <dt class="text-fc-faint">
            OS
          </dt>
          <dd class="font-mono text-fc-ink">
            {{ osLine(machine) ?? 'Not observed yet' }}
          </dd>
          <dt class="text-fc-faint">
            Endpoints
          </dt>
          <dd class="font-mono text-fc-ink">
            <div
              v-for="endpoint in raw?.endpoints ?? []"
              :key="endpoint.id"
            >
              {{ endpoint.kind }} · {{ endpoint.reference }}
            </div>
            <div v-if="(raw?.endpoints ?? []).length === 0">
              —
            </div>
          </dd>
          <dt class="text-fc-faint">
            Tailscale
          </dt>
          <dd class="font-mono text-fc-ink">
            <template v-if="machine.tailnet">
              {{ machine.tailnet.name }} · {{ machine.tailnet.addresses.join(', ') }} · {{ machine.tailnet.online ? 'ONLINE' : 'OFFLINE' }}
            </template>
            <template v-else>
              —
            </template>
          </dd>
          <dt class="text-fc-faint">
            Guest candidates
          </dt>
          <dd class="font-mono text-fc-info">
            <div
              v-for="(candidate, i) in machine.guestCandidates"
              :key="i"
            >
              ≈ {{ candidate.accountName }} · {{ candidate.node }} · {{ candidate.vmid }} ({{ candidate.evidence }})
            </div>
            <div v-if="machine.guestCandidates.length === 0">
              —
            </div>
          </dd>
          <dt class="text-fc-faint">
            Tags / Groups
          </dt>
          <dd class="font-mono text-fc-ink">
            {{ [...machine.tags, ...machine.groups].join(', ') || '—' }}
          </dd>
          <dt class="text-fc-faint">
            Last seen
          </dt>
          <dd class="font-mono text-fc-ink">
            {{ relativeTime(machine.lastSeenAt ?? machine.lastObservation?.collectedAt ?? null) }}
          </dd>
        </dl>

        <div v-if="(raw?.capabilities ?? []).length > 0">
          <p class="fc-kicker">
            Capability facts
          </p>
          <table class="mt-2 w-full text-left text-[11px]">
            <thead class="font-mono uppercase text-fc-faint">
              <tr>
                <th class="py-1">
                  Fact
                </th>
                <th class="py-1">
                  Value
                </th>
                <th class="py-1">
                  Status
                </th>
                <th class="py-1">
                  Source
                </th>
              </tr>
            </thead>
            <tbody class="font-mono text-fc-ink">
              <tr
                v-for="cap in raw?.capabilities ?? []"
                :key="`${cap.namespace}.${cap.name}`"
                class="border-t border-fc-line"
              >
                <td class="py-1">
                  {{ cap.namespace }}/{{ cap.name }}
                </td>
                <td class="py-1">
                  {{ cap.value ?? '—' }}
                </td>
                <td class="py-1 text-fc-faint">
                  {{ cap.status }}
                </td>
                <td class="py-1 text-fc-faint">
                  {{ cap.source }}
                </td>
              </tr>
            </tbody>
          </table>
        </div>

        <RouterLink
          :to="`/fleet/machines/${machine.id}`"
          class="block border-t border-fc-line pt-3 font-mono text-[11px] uppercase tracking-wider text-fc-info hover:text-fc-ink"
          data-testid="machine-page-link"
        >
          Open machine page →
        </RouterLink>
      </div>
    </SheetContent>
  </Sheet>
</template>
