<script setup lang="ts">
import { computed } from 'vue'

import type { Meta, SystemInfo } from '@frogbyte-io/fleet-api-client'

const props = defineProps<{
  system: SystemInfo | null
  meta: Meta | null
}>()

const readiness = computed(() => {
  if (!props.system) return null
  return props.system.storageOk ? 'ready' : 'degraded'
})
</script>

<template>
  <section class="rounded-sm border border-border bg-card p-6">
    <h2 class="text-lg font-semibold text-foreground">
      Diagnostics
    </h2>
    <p class="mt-1 text-sm text-muted-foreground">
      What the controller reports about itself: <code class="font-mono">/system</code> and
      <code class="font-mono">/meta</code>.
    </p>

    <dl
      v-if="system"
      class="mt-4 grid grid-cols-2 gap-x-6 gap-y-2 text-sm"
    >
      <dt class="text-muted-foreground">
        Service
      </dt>
      <dd class="font-mono text-foreground">
        {{ system.service }} {{ system.version }}
      </dd>

      <dt class="text-muted-foreground">
        API version
      </dt>
      <dd class="font-mono text-foreground">
        {{ meta?.apiVersion ?? '—' }}
      </dd>

      <dt class="text-muted-foreground">
        Readiness
      </dt>
      <dd>
        <span :class="readiness === 'ready' ? 'text-fc-ok' : 'text-fc-err'">{{ readiness }}</span>
      </dd>

      <dt class="text-muted-foreground">
        Queue
      </dt>
      <dd class="font-mono text-foreground">
        {{ system.queuePending }} pending · {{ system.queueRunning }} running
      </dd>

      <dt class="text-muted-foreground">
        Trust mode
      </dt>
      <dd class="font-mono text-fc-warn">
        {{ system.trustMode }}
      </dd>
    </dl>
    <p
      v-else
      class="mt-4 text-sm text-fc-err"
    >
      The controller did not answer.
    </p>
  </section>
</template>
