<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'

import AddDialog from './add/AddDialog.vue'
import type { Source } from './add/resume'
import FleetPage from './FleetPage.vue'

// `/fleet/add` is the "+ Add" dialog over the Fleet page, so every existing
// link to it opens the guided flow; closing returns to the Fleet page.
const route = useRoute()
const router = useRouter()

const SOURCES: Source[] = ['tailscale', 'ssh', 'proxmox', 'guest']
const initialSource = computed(() => {
  const value = route.query.source
  return typeof value === 'string' && (SOURCES as string[]).includes(value) ? (value as Source) : null
})
const initialDevice = computed(() => (typeof route.query.device === 'string' ? route.query.device : null))

const open = ref(true)
watch(open, (value) => {
  if (!value)
    router.push('/fleet')
})
</script>

<template>
  <FleetPage />
  <AddDialog
    v-model:open="open"
    :initial-source="initialSource"
    :initial-device="initialDevice"
  />
</template>
