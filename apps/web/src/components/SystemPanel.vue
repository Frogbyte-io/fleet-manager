<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'

import { getSystemInfo, type SystemInfo } from '@frogbyte-io/fleet-api-client'

const info = ref<SystemInfo | null>(null)
const failed = ref(false)
const failure = ref('')

const trustBanner = computed(() => info.value?.trustWarning ?? '')

onMounted(async () => {
  try {
    const response = await getSystemInfo()
    if (response.status === 200) {
      info.value = response.data
    }
  } catch (error) {
    failed.value = true
    failure.value = error instanceof Error ? error.message : String(error)
  }
})
</script>

<template>
  <section class="rounded-sm border border-border bg-card p-6">
    <h2 class="text-lg font-semibold text-foreground">
      System
    </h2>

    <p
      v-if="failed"
      class="mt-4 text-sm text-fc-err"
    >
      The controller did not answer: {{ failure }}
    </p>

    <dl
      v-else-if="info"
      class="mt-4 grid grid-cols-2 gap-x-6 gap-y-2 text-sm"
    >
      <dt class="text-muted-foreground">
        Service
      </dt>
      <dd class="font-mono text-foreground">
        {{ info.service }} {{ info.version }}
      </dd>

      <dt class="text-muted-foreground">
        Trust mode
      </dt>
      <dd class="font-mono text-fc-warn">
        {{ info.trustMode }}
      </dd>

      <dt class="text-muted-foreground">
        Storage
      </dt>
      <dd>
        <span :class="info.storageOk ? 'text-fc-ok' : 'text-fc-err'">
          {{ info.storageOk ? 'ready' : 'unavailable' }}
        </span>
      </dd>

      <dt class="text-muted-foreground">
        Queue
      </dt>
      <dd class="font-mono text-foreground">
        {{ info.queuePending }} pending · {{ info.queueRunning }} running
      </dd>
    </dl>

    <p
      v-else
      class="mt-4 text-sm text-muted-foreground"
    >
      Loading…
    </p>

    <p
      v-if="trustBanner"
      class="mt-4 rounded-sm border border-fc-warn/40 bg-fc-warn/10 p-3 text-xs leading-5 text-fc-warn"
      role="alert"
    >
      {{ trustBanner }}
    </p>
  </section>
</template>
