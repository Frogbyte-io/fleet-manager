<script setup lang="ts">
import { computed } from 'vue'

const props = defineProps<{
  kind: 'host' | 'vm' | 'lxc' | 'machine' | 'tailnet'
}>()

const stroke = computed(() => ({
  host: 'var(--fc-c-compute)',
  vm: 'var(--fc-c-compute)',
  lxc: 'var(--fc-c-storage)',
  machine: 'var(--fc-c-desktop)',
  tailnet: 'var(--fc-info)',
}[props.kind]))
</script>

<template>
  <span aria-hidden="true" class="inline-flex size-11 items-center justify-center rounded-sm border border-fc-line bg-fc-inset">
    <svg
      v-if="kind === 'host'"
      width="22"
      height="22"
      viewBox="0 0 24 24"
      fill="none"
      :stroke="stroke"
      stroke-width="1.6"
      stroke-linecap="round"
      stroke-linejoin="round"
    >
      <rect
        x="3"
        y="4"
        width="18"
        height="7"
        rx="1"
      />
      <rect
        x="3"
        y="13"
        width="18"
        height="7"
        rx="1"
      />
      <circle
        cx="7"
        cy="7.5"
        r="0.6"
        fill="currentColor"
      />
      <circle
        cx="7"
        cy="16.5"
        r="0.6"
        fill="currentColor"
      />
    </svg>
    <svg
      v-else-if="kind === 'vm'"
      width="22"
      height="22"
      viewBox="0 0 24 24"
      fill="none"
      :stroke="stroke"
      stroke-width="1.6"
      stroke-linecap="round"
      stroke-linejoin="round"
    >
      <rect
        x="3"
        y="5"
        width="18"
        height="12"
        rx="1"
      />
      <path d="M8 21h8M12 17v4" />
    </svg>
    <svg
      v-else-if="kind === 'lxc'"
      width="22"
      height="22"
      viewBox="0 0 24 24"
      fill="none"
      :stroke="stroke"
      stroke-width="1.6"
      stroke-linecap="round"
      stroke-linejoin="round"
    >
      <path d="M12 3l8 4.5v9L12 21l-8-4.5v-9L12 3z" />
      <path d="M12 12l8-4.5M12 12v9M12 12L4 7.5" />
    </svg>
    <svg
      v-else-if="kind === 'machine'"
      width="22"
      height="22"
      viewBox="0 0 24 24"
      fill="none"
      :stroke="stroke"
      stroke-width="1.6"
      stroke-linecap="round"
      stroke-linejoin="round"
    >
      <rect
        x="2"
        y="4"
        width="20"
        height="13"
        rx="1.5"
      />
      <path d="M8 21h8M12 17v4" />
    </svg>
    <svg
      v-else
      width="22"
      height="22"
      viewBox="0 0 24 24"
      fill="none"
      :stroke="stroke"
      stroke-width="1.6"
      stroke-linecap="round"
      stroke-linejoin="round"
    >
      <circle
        cx="12"
        cy="12"
        r="3"
      />
      <path d="M12 2v3M12 19v3M2 12h3M19 12h3M4.9 4.9l2.1 2.1M17 17l2.1 2.1M19.1 4.9L17 7M7 17l-2.1 2.1" />
    </svg>
  </span>
</template>
