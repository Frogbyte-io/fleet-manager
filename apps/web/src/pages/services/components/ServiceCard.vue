<script setup lang="ts">
import type { RunningServiceDto } from '@frogbyte-io/fleet-api-client'
import { computed } from 'vue'
import { RouterLink } from 'vue-router'

import StatusChip from '@/components/fleet/StatusChip.vue'

import { deployView, detailPath, placementView, projectLabel, serverLabel, sourceLabel, statusView } from '../services'

const props = defineProps<{ service: RunningServiceDto }>()

const status = computed(() => statusView(props.service))
const placement = computed(() => placementView(props.service))
const deploy = computed(() => deployView(props.service))
</script>

<template>
  <article
    class="fc-card flex flex-col gap-3 rounded-sm border border-fc-line bg-fc-panel p-4"
    data-testid="service-card"
    :data-service-id="service.id"
  >
    <div class="flex items-start gap-3">
      <div class="min-w-0 flex-1">
        <p class="truncate text-sm font-semibold text-fc-ink">
          {{ service.name }}
        </p>
        <p class="fc-kicker mt-0.5 truncate">
          {{ service.kind }} · {{ sourceLabel(service) }}
        </p>
      </div>
      <StatusChip
        :label="status.label"
        :tone="status.tone"
        data-testid="service-status"
      />
    </div>

    <dl class="grid gap-1.5 text-xs">
      <div class="flex gap-2">
        <dt class="w-16 shrink-0 font-mono text-[10px] uppercase tracking-wider text-fc-faint">
          Server
        </dt>
        <dd class="min-w-0 break-words text-fc-muted">
          {{ serverLabel(service) }}
        </dd>
      </div>
      <div class="flex gap-2">
        <dt class="w-16 shrink-0 font-mono text-[10px] uppercase tracking-wider text-fc-faint">
          Project
        </dt>
        <dd class="min-w-0 break-words text-fc-muted">
          {{ projectLabel(service) }}
        </dd>
      </div>
      <div class="flex gap-2">
        <dt class="w-16 shrink-0 font-mono text-[10px] uppercase tracking-wider text-fc-faint">
          Machine
        </dt>
        <dd
          class="min-w-0 break-words"
          :class="placement.state === 'ambiguous' ? 'text-fc-warn' : 'text-fc-muted'"
          data-testid="service-placement"
        >
          {{ placement.label }}
          <span class="text-fc-faint">· {{ placement.detail }}</span>
        </dd>
      </div>
      <div
        v-if="service.fqdns.length > 0"
        class="flex gap-2"
      >
        <dt class="w-16 shrink-0 font-mono text-[10px] uppercase tracking-wider text-fc-faint">
          Hosts
        </dt>
        <dd class="min-w-0 break-all font-mono text-[11px] text-fc-muted">
          {{ service.fqdns.slice(0, 2).join(', ') }}<span
            v-if="service.fqdns.length > 2"
            class="text-fc-faint"
          > +{{ service.fqdns.length - 2 }}</span>
        </dd>
      </div>
      <div
        v-if="deploy"
        class="flex gap-2"
      >
        <dt class="w-16 shrink-0 font-mono text-[10px] uppercase tracking-wider text-fc-faint">
          Deploy
        </dt>
        <dd class="min-w-0">
          <StatusChip
            :label="deploy.label"
            :tone="deploy.tone"
          />
        </dd>
      </div>
    </dl>

    <p
      v-if="service.stale"
      class="border-l-2 border-l-fc-warn pl-2 text-[11px] text-fc-muted"
      data-testid="service-stale"
    >
      Stale data: not confirmed by a recent read.
    </p>

    <div class="mt-auto flex items-center justify-end border-t border-fc-line pt-2">
      <RouterLink
        :to="detailPath(service.id)"
        class="font-mono text-[10px] uppercase tracking-wider text-fc-info hover:text-fc-ink"
        data-testid="open-service"
      >
        Open →
      </RouterLink>
    </div>
  </article>
</template>
