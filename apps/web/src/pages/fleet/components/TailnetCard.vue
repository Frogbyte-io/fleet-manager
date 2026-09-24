<script setup lang="ts">
import KindIcon from '@/components/fleet/KindIcon.vue'
import StatusChip from '@/components/fleet/StatusChip.vue'
import { toast } from 'vue-sonner'
import { tailnetStatusLabel, type TailnetItem } from '../inventory'

const props = defineProps<{ device: TailnetItem }>()

async function copyImportCommand() {
  try {
    await navigator.clipboard.writeText(`fleetctl tailnet import ${props.device.nodeId} --user SSH_USER`)
    toast('Copied import command')
  }
  catch {
    // clipboard unavailable — ignore
  }
}
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
        :label="tailnetStatusLabel(device.online)"
        :tone="device.online ? 'ok' : 'faint'"
      />
    </div>

    <div class="mt-auto flex items-center gap-2 border-t border-fc-line pt-2">
      <button
        type="button"
        disabled
        title="Guided tailnet import lands with FM-912"
        class="cursor-not-allowed rounded-sm border border-fc-line px-2 py-1 font-mono text-[10px] uppercase tracking-wider text-fc-faint opacity-60"
      >
        Add to fleet
      </button>
      <button
        type="button"
        data-testid="copy-import"
        class="rounded-sm border border-fc-line px-2 py-1 font-mono text-[10px] uppercase tracking-wider text-fc-info hover:text-fc-ink"
        @click="copyImportCommand"
      >
        Copy fleetctl
      </button>
      <slot name="hide" />
    </div>
  </article>
</template>
