<script setup lang="ts">
import { computed } from 'vue'

import type { SystemInfo } from '@frogbyte-io/fleet-api-client'

const props = defineProps<{
  system: SystemInfo | null
}>()

const warning = computed(() => props.system?.trustWarning ?? '')
</script>

<template>
  <section class="rounded-sm border border-border bg-card p-6">
    <h2 class="text-lg font-semibold text-foreground">
      Security &amp; access
    </h2>

    <div
      v-if="warning"
      role="alert"
      class="mt-4 border-l-2 border-fc-err bg-fc-err/10 p-3 text-sm"
    >
      <span class="font-semibold text-fc-err">Trusted-LAN mode.</span>
      <span class="text-fc-muted">{{ warning }}</span>
    </div>

    <dl
      v-if="system"
      class="mt-4 grid grid-cols-2 gap-x-6 gap-y-2 text-sm"
    >
      <dt class="text-muted-foreground">
        Trust mode
      </dt>
      <dd class="font-mono text-foreground">
        {{ system.trustMode }}
      </dd>
      <dt class="text-muted-foreground">
        Mutations audited as
      </dt>
      <dd class="font-mono text-foreground">
        anonymous-lan-admin
      </dd>
    </dl>

    <p class="mt-4 text-sm text-muted-foreground">
      Tailnet-identity login is planned for M8; today the controller trusts the LAN it
      listens on. Allowed origins are not configurable yet.
    </p>
  </section>
</template>
