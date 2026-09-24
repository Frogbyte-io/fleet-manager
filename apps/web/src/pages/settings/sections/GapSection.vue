<script setup lang="ts">
defineProps<{
  title: string
  detail: string
}>()
</script>

<template>
  <section class="rounded-sm border border-border bg-card p-6">
    <h2 class="text-lg font-semibold text-foreground">
      {{ title }}
    </h2>
    <p class="mt-2 text-sm text-fc-muted">
      {{ detail }}
    </p>
    <p class="mt-2 text-sm text-muted-foreground">
      This section has no backing API yet, so it shows status only — no invented controls.
    </p>
  </section>
</template>
