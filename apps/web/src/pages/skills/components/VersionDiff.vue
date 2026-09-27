<script setup lang="ts">
import { computed } from 'vue'

import type { CatalogContentDto } from '@frogbyte-io/fleet-api-client'

import { contentDiff } from '../catalog'

// A per-file line diff between two catalog contents.
const props = defineProps<{ before: CatalogContentDto, after: CatalogContentDto, beforeLabel: string, afterLabel: string }>()

const files = computed(() => contentDiff(props.before, props.after))
const changed = computed(() => files.value.filter(f => f.change !== 'unchanged'))
const unchanged = computed(() => files.value.length - changed.value.length)
</script>

<template>
  <div
    class="space-y-2 text-xs"
    data-testid="version-diff"
  >
    <p class="font-mono text-[10px] text-fc-faint">
      <span class="text-fc-err">− {{ beforeLabel }}</span> · <span class="text-fc-ok">+ {{ afterLabel }}</span>
      <span v-if="unchanged">· {{ unchanged }} file{{ unchanged === 1 ? '' : 's' }} unchanged</span>
    </p>
    <p
      v-if="changed.length === 0"
      class="text-fc-muted"
      data-testid="diff-identical"
    >
      No differences.
    </p>
    <div
      v-for="file in changed"
      :key="file.path"
      class="rounded-sm border border-fc-line"
    >
      <p class="flex items-center gap-2 border-b border-fc-line bg-fc-inset px-2 py-1 font-mono text-[11px]">
        <span class="text-fc-ink">{{ file.path }}</span>
        <span class="text-fc-faint">{{ file.change }}</span>
      </p>
      <div class="max-h-72 overflow-auto p-2 font-mono text-[11px] leading-5">
        <div
          v-for="(line, index) in file.lines"
          :key="index"
          class="whitespace-pre-wrap break-all"
          :class="line.op === '+' ? 'bg-fc-ok/10 text-fc-ok' : line.op === '-' ? 'bg-fc-err/10 text-fc-err' : 'text-fc-muted'"
          v-text="`${line.op} ${line.text}`"
        />
      </div>
    </div>
  </div>
</template>
