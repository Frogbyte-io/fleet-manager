<script setup lang="ts">
import { refDebounced } from '@vueuse/core'
import { computed, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'

import { Skeleton } from '@/components/ui/skeleton'

import { errorMessage } from '../machine/api'
import EntryDrawer from './components/EntryDrawer.vue'
import ValueView from './components/ValueView.vue'
import { columnDefs, fieldDefs, fieldValues, renderValue } from './registry'
import { useRegistryEntries, useRegistryTypes } from './useRegistry'

// A read-only view over any Registry type, rendered from the type's own
// definition. Editing happens in Fleet Git (`fleetctl registry set`).
const route = useRoute()
const router = useRouter()

const types = useRegistryTypes()
const typeList = computed(() => types.data.value?.items ?? [])

const requestedType = computed(() => (typeof route.query.type === 'string' ? route.query.type : null))
const activeType = computed(() => typeList.value.find(t => t.name === requestedType.value) ?? typeList.value[0] ?? null)
const typeName = computed(() => activeType.value?.name ?? null)

const text = ref(typeof route.query.q === 'string' ? route.query.q : '')
const debounced = refDebounced(text, 250)
const tag = computed(() => (typeof route.query.tag === 'string' ? route.query.tag : ''))
const selectedKey = computed(() => (typeof route.query.entry === 'string' ? route.query.entry : null))

function setQuery(patch: Record<string, string | undefined>) {
  router.replace({ query: { ...route.query, ...patch } })
}

function selectType(name: string) {
  text.value = ''
  router.replace({ query: { type: name } })
}

watch(debounced, value => setQuery({ q: value.trim() || undefined }))
// A link from a relation can change the type or search from outside.
watch(() => route.query.q, (value) => {
  const next = typeof value === 'string' ? value : ''
  if (next !== text.value.trim())
    text.value = next
})

const entries = useRegistryEntries(typeName, debounced)
const allEntries = computed(() => entries.data.value?.items ?? [])
const tags = computed(() => [...new Set(allEntries.value.flatMap(e => e.tags))].sort())
const rows = computed(() => (tag.value ? allEntries.value.filter(e => e.tags.includes(tag.value)) : allEntries.value))

const defs = computed(() => (activeType.value ? fieldDefs(activeType.value.spec, activeType.value.keyField) : []))
const columns = computed(() => columnDefs(defs.value))
const filtered = computed(() => debounced.value.trim() !== '' || tag.value !== '')
const revision = computed(() => types.data.value?.revision ?? null)

const loading = computed(() => types.isLoading.value || (!!typeName.value && entries.isLoading.value))
</script>

<template>
  <div>
    <p class="fc-kicker">
      <template v-if="revision">
        descriptive records in Fleet Git · revision {{ revision.commitSha.slice(0, 12) }}
      </template>
      <template v-else>
        descriptive records in Fleet Git
      </template>
    </p>
    <h1 class="fc-h1">
      Registry
    </h1>

    <div
      v-if="types.error.value"
      class="mt-4 border-l-2 border-l-fc-err bg-card px-3 py-2 text-xs text-fc-muted"
      role="alert"
    >
      Could not load Registry types: {{ errorMessage(types.error.value) }}
    </div>

    <div
      v-if="types.isLoading.value"
      class="mt-4 grid gap-2"
    >
      <Skeleton
        v-for="i in 4"
        :key="i"
        class="h-10 rounded-sm"
      />
    </div>

    <div
      v-else-if="!types.error.value && typeList.length === 0"
      class="mt-4 rounded-sm border border-fc-line p-6 text-sm text-fc-muted"
      data-testid="registry-no-types"
    >
      <p>
        {{ revision ? 'This revision defines no Registry types.' : 'No desired revision is active, so there is no Registry yet.' }}
      </p>
      <p class="mt-2 text-xs text-fc-faint">
        Built-in types (<span class="font-mono">domain</span>, <span class="font-mono">service</span>) appear once Fleet Git has an active revision. See Settings to configure the repository.
      </p>
    </div>

    <template v-else-if="activeType">
      <div
        class="mt-4 flex flex-wrap gap-1.5"
        role="group"
        aria-label="Registry type"
      >
        <button
          v-for="item in typeList"
          :key="item.name"
          type="button"
          class="rounded-sm border px-2.5 py-1 text-xs"
          :class="activeType.name === item.name ? 'border-ring text-fc-ink' : 'border-fc-line2 text-fc-muted hover:text-fc-ink'"
          :aria-pressed="activeType.name === item.name"
          :data-testid="`type-${item.name}`"
          @click="selectType(item.name)"
        >
          {{ item.displayName }} <span class="font-mono text-[10px] text-fc-faint">{{ item.entryCount }}</span>
        </button>
      </div>

      <div class="mt-3 flex flex-wrap items-end gap-3 text-xs">
        <label class="flex min-w-0 basis-full flex-col gap-1 sm:max-w-72 sm:basis-auto">
          <span class="fc-kicker">Search</span>
          <input
            v-model="text"
            type="search"
            placeholder="Search entries"
            class="h-8 w-full rounded-sm border border-input bg-background px-2 text-foreground"
            data-testid="registry-search"
          >
        </label>
        <label class="flex flex-col gap-1">
          <span class="fc-kicker">Tag</span>
          <select
            :value="tag"
            class="h-8 rounded-sm border border-input bg-background px-2 font-mono text-foreground"
            data-testid="registry-tag"
            @change="setQuery({ tag: ($event.target as HTMLSelectElement).value || undefined })"
          >
            <option value="">All tags</option>
            <option
              v-for="t in tags"
              :key="t"
              :value="t"
            >
              {{ t }}
            </option>
          </select>
        </label>
        <p class="ml-auto font-mono text-[10px] text-fc-faint">
          key: {{ activeType.keyField }} · {{ activeType.origin }} type
        </p>
      </div>

      <div
        v-if="entries.error.value"
        class="mt-4 border-l-2 border-l-fc-err bg-card px-3 py-2 text-xs text-fc-muted"
        role="alert"
      >
        Could not load {{ activeType.displayName }} entries: {{ errorMessage(entries.error.value) }}
      </div>
      <div
        v-if="entries.data.value?.truncated"
        class="mt-4 border-l-2 border-l-fc-warn bg-card px-3 py-2 text-xs text-fc-muted"
        role="status"
      >
        Results hit the page safety cap; narrow the search to see the rest.
      </div>

      <div class="mt-4">
        <div
          v-if="loading"
          class="grid gap-2"
        >
          <Skeleton
            v-for="i in 4"
            :key="i"
            class="h-10 rounded-sm"
          />
        </div>
        <div
          v-else-if="rows.length === 0 && !entries.error.value"
          class="rounded-sm border border-fc-line p-6 text-sm text-fc-muted"
          data-testid="registry-empty"
        >
          <template v-if="filtered">
            No {{ activeType.displayName.toLowerCase() }} entries match these filters.
          </template>
          <template v-else>
            <p>No {{ activeType.displayName.toLowerCase() }} entries in the active revision.</p>
            <p class="mt-2 text-xs text-fc-faint">
              The Registry lives in Fleet Git and this view is read-only. In a checkout of the Fleet Git repository, add an entry and publish it:
            </p>
            <pre class="mt-2 overflow-x-auto rounded-sm bg-fc-inset p-2 font-mono text-[11.5px] text-fc-ink">fleetctl registry set {{ activeType.name }}/&lt;{{ activeType.keyField }}&gt; --field &lt;name&gt;=&lt;value&gt;
fleetctl registry validate
fleetctl registry publish -m "Add {{ activeType.name }}"</pre>
          </template>
        </div>
        <div
          v-else-if="rows.length"
          class="overflow-x-auto"
        >
          <table
            class="w-full border border-fc-line bg-card text-[13px]"
            data-testid="registry-table"
          >
            <thead>
              <tr class="bg-fc-inset text-left">
                <th
                  v-for="(col, index) in columns"
                  :key="col.name"
                  class="fc-kicker px-2 py-1.5 font-normal"
                  :class="index >= 2 ? 'hidden md:table-cell' : ''"
                >
                  {{ col.name }}
                </th>
                <th class="fc-kicker hidden px-2 py-1.5 font-normal lg:table-cell">
                  Tags
                </th>
              </tr>
            </thead>
            <tbody>
              <tr
                v-for="entry in rows"
                :key="entry.id"
                class="cursor-pointer border-t border-fc-line align-top hover:bg-fc-inset"
                :class="entry.key === selectedKey ? 'bg-fc-inset' : ''"
                :data-testid="`entry-${entry.key}`"
                @click="setQuery({ entry: entry.key })"
              >
                <td
                  v-for="(col, index) in columns"
                  :key="col.name"
                  class="px-2 py-1.5"
                  :class="index >= 2 ? 'hidden md:table-cell' : ''"
                >
                  <button
                    v-if="col.isKey"
                    type="button"
                    class="text-left font-mono text-fc-ink hover:underline"
                    :aria-label="`Open ${activeType.name}/${entry.key}`"
                    @click.stop="setQuery({ entry: entry.key })"
                  >
                    <ValueView :value="renderValue(col, fieldValues(entry.fields)[col.name])" />
                  </button>
                  <ValueView
                    v-else
                    :value="renderValue(col, fieldValues(entry.fields)[col.name])"
                  />
                </td>
                <td class="hidden px-2 py-1.5 lg:table-cell">
                  <span class="flex flex-wrap gap-1">
                    <span
                      v-for="t in entry.tags"
                      :key="t"
                      class="rounded-sm border border-fc-line2 px-1.5 py-px font-mono text-[10px] text-fc-muted"
                    >{{ t }}</span>
                  </span>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <EntryDrawer
        v-if="selectedKey"
        :key="`${activeType.name}/${selectedKey}`"
        :type="activeType"
        :entry-key="selectedKey"
        @close="setQuery({ entry: undefined })"
      />
    </template>
  </div>
</template>
