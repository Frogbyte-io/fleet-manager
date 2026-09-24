<script setup lang="ts">
import { computed } from 'vue'
import { useRoute } from 'vue-router'

import { Card, CardContent } from '@/components/ui/card'

const route = useRoute()
const title = computed(() => (route.meta.title as string | undefined) ?? '')
</script>

<template>
  <h1 class="fc-h1">
    {{ title }}
  </h1>
  <Card class="mt-6">
    <CardContent class="p-6">
      <p class="text-sm text-foreground">
        This page is part of the Fleet Console v2 plan and is not built yet.
      </p>
      <p class="mt-2 font-mono text-xs text-muted-foreground">
        See docs/planning/web-console.md
      </p>
    </CardContent>
  </Card>
</template>
