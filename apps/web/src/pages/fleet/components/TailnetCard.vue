<script setup lang="ts">
import { RouterLink } from 'vue-router'

import KindIcon from '@/components/fleet/KindIcon.vue'
import StatusChip from '@/components/fleet/StatusChip.vue'
import type { TailnetItem } from '../inventory'

defineProps<{ device: TailnetItem }>()
</script>

<template>
  <article class="fc-card rounded-sm border border-dashed border-fc-line bg-transparent p-4">
    <div class="flex items-start gap-3">
      <KindIcon kind="tailnet" />
      <div class="min-w-0 flex-1">
        <p class="truncate text-sm font-semibold text-fc-ink">
          {{ device.name }}
        </p>
        <p class="fc-kicker mt-0.5 truncate">
          {{ device.os }} · {{ device.addresses[0] ?? 'NO ADDRESS' }} · {{ device.tags.join(' ') }}
        </p>
      </div>
      <StatusChip
        :label="device.online ? 'ONLINE' : 'OFFLINE'"
        :tone="device.online ? 'ok' : 'faint'"
      />
    </div>

    <div class="mt-auto flex items-center gap-2 border-t border-fc-line pt-2">
      <RouterLink
        :to="`/fleet/add?tailnetNode=${device.nodeId}`"
        class="font-mono text-[10px] uppercase tracking-wider text-fc-info hover:text-fc-ink"
      >
        Add to fleet →
      </RouterLink>
      <slot name="hide" />
    </div>
  </article>
</template>
