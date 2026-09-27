<script setup lang="ts">
import { computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'

import { Skeleton } from '@/components/ui/skeleton'

import { errorMessage } from '../machine/api'
import CatalogTab from './components/CatalogTab.vue'
import MatrixTab from './components/MatrixTab.vue'
import PresetsTab from './components/PresetsTab.vue'
import SearchTab from './components/SearchTab.vue'
import { useSkills } from './useSkills'

// Fleet-wide skills (docs/planning/web-console.md, Skills): the observed
// matrix, Fleet's catalog with rollout and assignments, per-machine presets,
// and skills.sh. Per-machine library actions live on the machine page.
const { matrix, machines, catalog, snapshots, entries, model, agents } = useSkills()
const route = useRoute()
const router = useRouter()

type Tab = 'matrix' | 'catalog' | 'presets' | 'search'
const TABS: { id: Tab, label: string, count: () => number | null }[] = [
  { id: 'matrix', label: 'Fleet matrix', count: () => model.value.rows.length },
  { id: 'catalog', label: 'Catalog', count: () => entries.value.length },
  { id: 'presets', label: 'Presets', count: () => null },
  { id: 'search', label: 'Search skills.sh', count: () => null },
]

const tab = computed<Tab>({
  get: () => {
    const requested = route.query.tab
    return TABS.some(t => t.id === requested) ? requested as Tab : 'matrix'
  },
  set: (value) => {
    router.replace({ query: { ...route.query, tab: value === 'matrix' ? undefined : value } })
  },
})

// The open catalog entry is part of the URL, so a link can open the editor.
const selected = computed<string | null>({
  get: () => (typeof route.query.entry === 'string' ? route.query.entry : null),
  set: (value) => {
    router.replace({ query: { ...route.query, tab: 'catalog', entry: value ?? undefined } })
  },
})

function openCatalog(id: string) {
  router.replace({ query: { ...route.query, tab: 'catalog', entry: id } })
}

const available = computed(() => model.value.columns.filter(c => c.state === 'available').length)

const loadError = computed(() => {
  const failed = [
    matrix.error.value && `skills matrix: ${errorMessage(matrix.error.value)}`,
    machines.error.value && `machines: ${errorMessage(machines.error.value)}`,
    catalog.error.value && `catalog: ${errorMessage(catalog.error.value)}`,
  ].filter(Boolean)
  return failed.length ? failed.join(' · ') : ''
})
const truncated = computed(() => matrix.data.value?.truncated || catalog.data.value?.truncated)
const loading = computed(() => matrix.isLoading.value || machines.isLoading.value || catalog.isLoading.value)
</script>

<template>
  <div>
    <div class="flex flex-wrap items-end gap-4">
      <div>
        <p class="fc-kicker">
          via skills-manager-cli --json · {{ model.columns.length }} machine{{ model.columns.length === 1 ? '' : 's' }} · {{ available }} with skills manager
        </p>
        <h1 class="fc-h1">
          Skills
        </h1>
      </div>
      <div class="ml-auto flex gap-2">
        <button
          type="button"
          class="fc-grad-bg h-9 rounded-sm px-3.5 font-head text-xs font-bold"
          data-testid="header-new-skill"
          @click="selected = 'new:authored'"
        >
          + New skill
        </button>
      </div>
    </div>

    <div
      class="mt-4 flex gap-6 border-b border-fc-line"
      role="tablist"
    >
      <button
        v-for="item in TABS"
        :key="item.id"
        type="button"
        role="tab"
        class="pb-2 text-[13px] font-semibold"
        :class="tab === item.id ? 'text-fc-ink shadow-[inset_0_-2px_0_var(--fc-g1)]' : 'text-fc-muted hover:text-fc-ink'"
        :aria-selected="tab === item.id"
        :data-testid="`tab-${item.id}`"
        @click="tab = item.id"
      >
        {{ item.label }}<span
          v-if="item.count() !== null"
          class="ml-1 font-mono text-[10px] text-fc-faint"
        >{{ item.count() }}</span>
      </button>
    </div>

    <div
      v-if="loadError"
      class="mt-4 border-l-2 border-l-fc-err bg-card px-3 py-2 text-xs text-fc-muted"
      role="alert"
    >
      Could not load {{ loadError }}
    </div>
    <div
      v-if="truncated"
      class="mt-4 border-l-2 border-l-fc-warn bg-card px-3 py-2 text-xs text-fc-muted"
      role="status"
    >
      Results hit the 20-page safety cap; some machines or catalog entries may be missing.
    </div>

    <div
      v-if="loading"
      class="mt-4 grid gap-3"
    >
      <Skeleton
        v-for="i in 3"
        :key="i"
        class="h-16 rounded-sm"
      />
    </div>

    <MatrixTab
      v-else-if="tab === 'matrix'"
      :matrix="model"
      :agents="agents"
      @open-catalog="openCatalog"
    />
    <CatalogTab
      v-else-if="tab === 'catalog'"
      v-model:selected="selected"
      :entries="entries"
      :rows="model.rows"
      :machines="machines.data.value ?? []"
      :columns="model.columns"
      :agents="agents"
    />
    <PresetsTab
      v-else-if="tab === 'presets'"
      :snapshots="snapshots"
      :columns="model.columns"
    />
    <SearchTab
      v-else
      @reference="selected = 'new:referenced'"
    />
  </div>
</template>
