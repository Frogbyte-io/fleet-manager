<script setup lang="ts">
import type { RunningServiceDto } from '@frogbyte-io/fleet-api-client'

// The one place lifecycle actions (start, stop, restart, redeploy) slot into
// the detail view. They are brokered requests (FM-1033), so there is nothing
// to render until that API exists: this component deliberately draws nothing
// today and the detail page already mounts it in the header. When the broker
// lands, render its buttons here from `service`; no other file changes.
defineProps<{ service: RunningServiceDto }>()
</script>

<template>
  <div
    class="hidden"
    data-testid="service-actions"
    :data-service-id="service.id"
  />
</template>
