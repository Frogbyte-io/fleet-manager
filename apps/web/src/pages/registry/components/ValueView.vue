<script setup lang="ts">
import type { Rendered } from '../registry'

// One typed field value. URLs and emails are anchors (web schemes only);
// everything else is inert text.
defineProps<{ value: Rendered }>()
</script>

<template>
  <span
    v-if="value.kind === 'empty'"
    class="text-fc-faint"
    aria-label="empty"
  >–</span>
  <span
    v-else-if="value.kind === 'bool'"
    class="font-mono text-[10px] uppercase tracking-wider"
    :class="value.value ? 'text-fc-ok' : 'text-fc-muted'"
  >{{ value.value ? 'Yes' : 'No' }}</span>
  <a
    v-else-if="value.kind === 'link'"
    :href="value.href"
    target="_blank"
    rel="noopener noreferrer"
    class="break-all text-fc-info hover:underline"
    @click.stop
  >{{ value.text }}</a>
  <span
    v-else-if="value.kind === 'list'"
    class="inline-flex flex-wrap gap-1"
  >
    <span
      v-for="(item, index) in value.items"
      :key="index"
      class="rounded-sm border border-fc-line2 px-1.5 py-px"
    ><ValueView :value="item" /></span>
  </span>
  <span
    v-else
    class="break-words"
    :class="value.mono ? 'font-mono text-[11.5px]' : ''"
  >{{ value.text }}</span>
</template>
