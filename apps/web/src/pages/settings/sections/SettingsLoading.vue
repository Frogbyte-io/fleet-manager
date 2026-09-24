<script setup lang="ts">
defineProps<{
  failure?: string
}>()</script>

<template>
  <p
    v-if="failure"
    role="alert"
    class="text-sm text-fc-err"
  >
    The controller did not answer: {{ failure }}
  </p>
  <div
    v-else
    role="status"
    aria-busy="true"
    class="space-y-2"
  >
    <span class="sr-only">Loading settings…</span>
    <div class="h-4 w-1/3 animate-pulse rounded bg-muted" />
    <div class="h-4 w-2/3 animate-pulse rounded bg-muted" />
  </div>
</template>
