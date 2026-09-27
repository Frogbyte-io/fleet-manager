<script setup lang="ts">
import { computed } from 'vue'

import type { CatalogDto, MachineDto } from '@frogbyte-io/fleet-api-client'

import { sourceLabel } from '../catalog'
import type { AgentEntry, MatrixColumn, MatrixRow } from '../model'
import CatalogEditor from './CatalogEditor.vue'

// Fleet's own catalog: authored skills and pinned references, with the
// selected entry's editor beside the list.
const props = defineProps<{
  entries: CatalogDto[]
  rows: MatrixRow[]
  machines: MachineDto[]
  columns: MatrixColumn[]
  agents: AgentEntry[]
}>()

/** The open entry id, `new:authored` / `new:referenced` for a new draft, or null. */
const selected = defineModel<string | null>('selected', { required: true })

const deployedOn = computed(() => new Map(props.rows.map(r => [r.skillId, r.deployedOn])))
const sorted = computed(() => [...props.entries].sort((a, b) => a.content.name.localeCompare(b.content.name)))
const entry = computed(() => props.entries.find(e => e.id === selected.value) ?? null)
const newKind = computed(() => (selected.value === 'new:referenced' ? 'referenced' as const : 'authored' as const))
const editing = computed(() => entry.value !== null || selected.value?.startsWith('new:'))
</script>

<template>
  <div
    class="mt-4 grid gap-4"
    :class="editing ? 'lg:grid-cols-[minmax(0,1fr)_minmax(0,560px)]' : ''"
  >
    <div>
      <div class="flex flex-wrap gap-2">
        <button
          type="button"
          class="fc-grad-bg h-8 rounded-sm px-3 font-head text-xs font-bold"
          data-testid="new-authored"
          @click="selected = 'new:authored'"
        >
          + New skill
        </button>
        <button
          type="button"
          class="h-8 rounded-sm border border-input px-3 font-head text-xs font-bold hover:border-fc-muted"
          data-testid="new-referenced"
          @click="selected = 'new:referenced'"
        >
          Reference a source…
        </button>
      </div>
      <p
        v-if="sorted.length === 0"
        class="mt-4 rounded-sm border border-fc-line p-6 text-sm text-fc-muted"
        data-testid="catalog-empty"
      >
        The catalog is empty. Author a skill here, or reference a skills.sh or Git source, then publish and roll it out.
      </p>
      <ul
        v-else
        class="mt-3 divide-y divide-fc-line rounded-sm border border-fc-line bg-card"
        data-testid="catalog-list"
      >
        <li
          v-for="item in sorted"
          :key="item.id"
        >
          <button
            type="button"
            class="flex w-full flex-wrap items-baseline gap-x-2 px-3 py-2 text-left hover:bg-fc-inset"
            :class="item.id === selected ? 'bg-fc-inset' : ''"
            :aria-current="item.id === selected"
            :data-testid="`catalog-entry-${item.id}`"
            @click="selected = item.id"
          >
            <span class="font-head text-[13px] font-bold">{{ item.content.name }}</span>
            <span class="font-mono text-[10px] uppercase tracking-wide text-fc-faint">{{ sourceLabel(item.content) }}</span>
            <span
              class="ml-auto font-mono text-[10px] text-fc-faint"
            >{{ item.publishedFrom ? 'published' : 'draft only' }} · on {{ deployedOn.get(item.content.name) ?? 0 }} machine{{ deployedOn.get(item.content.name) === 1 ? '' : 's' }}</span>
            <span class="w-full truncate text-xs text-fc-muted">{{ item.content.description }}</span>
          </button>
        </li>
      </ul>
    </div>

    <CatalogEditor
      v-if="editing"
      :key="entry?.id ?? selected ?? ''"
      :entry="entry"
      :kind="newKind"
      :machines="machines"
      :columns="columns"
      :agents="agents"
      @saved="saved => (selected = saved.id)"
      @close="selected = null"
    />
  </div>
</template>
