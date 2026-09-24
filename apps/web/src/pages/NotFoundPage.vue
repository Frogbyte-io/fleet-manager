<script setup lang="ts">
import { RouterLink } from 'vue-router'
</script>

<template>
  <h1 class="fc-h1">
    Not found
  </h1>
  <p class="mt-4 text-sm text-muted-foreground">
    That page does not exist. <RouterLink
      to="/"
      class="text-fc-info underline"
    >
      Go home
    </RouterLink>
  </p>
</template>
