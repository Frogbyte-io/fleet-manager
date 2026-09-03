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
  <section class="rounded-2xl border border-slate-800 bg-slate-900 p-6 shadow-xl">
    <h2 class="text-lg font-semibold text-slate-100">System</h2>

    <p v-if="failed" class="mt-4 text-sm text-rose-400">
      The controller did not answer: {{ failure }}
    </p>

    <dl v-else-if="info" class="mt-4 grid grid-cols-2 gap-x-6 gap-y-2 text-sm">
      <dt class="text-slate-400">Service</dt>
      <dd class="font-mono text-slate-100">{{ info.service }} {{ info.version }}</dd>

      <dt class="text-slate-400">Trust mode</dt>
      <dd class="font-mono text-amber-300">{{ info.trustMode }}</dd>

      <dt class="text-slate-400">Storage</dt>
      <dd>
        <span :class="info.storageOk ? 'text-emerald-400' : 'text-rose-400'">
          {{ info.storageOk ? 'ready' : 'unavailable' }}
        </span>
      </dd>

      <dt class="text-slate-400">Queue</dt>
      <dd class="font-mono text-slate-100">
        {{ info.queuePending }} pending · {{ info.queueRunning }} running
      </dd>
    </dl>

    <p v-else class="mt-4 text-sm text-slate-400">Loading…</p>

    <p
      v-if="trustBanner"
      class="mt-4 rounded-lg border border-amber-500/40 bg-amber-500/10 p-3 text-xs leading-5 text-amber-200"
      role="alert"
    >
      {{ trustBanner }}
    </p>
  </section>
</template>
