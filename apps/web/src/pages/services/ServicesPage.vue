<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { RouterLink, useRoute, useRouter } from 'vue-router'

import { Input } from '@/components/ui/input'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Skeleton } from '@/components/ui/skeleton'

import { errorMessage } from '../machine/api'
import CoverageNotes from './components/CoverageNotes.vue'
import ServiceCard from './components/ServiceCard.vue'
import ServiceTable from './components/ServiceTable.vue'
import {
  GROUP_LABELS,
  SERVICES_VIEW_KEY,
  coverageNotes,
  filterOptions,
  groupServices,
  matchesFilters,
  statusFromQuery,
  statusCounts,
  type GroupBy,
} from './services'
import { useServices } from './useServices'

// Every running service across every server: Coolify resources joined with
// Docker containers and Registry entries by the controller. Read-only; the
// page shows what the public API reports, including what it could not read.
const route = useRoute()
const router = useRouter()
const services = useServices()

const viewMode = ref<'cards' | 'table'>(localStorage.getItem(SERVICES_VIEW_KEY) === 'table' ? 'table' : 'cards')
function chooseView(mode: 'cards' | 'table') {
  viewMode.value = mode
  localStorage.setItem(SERVICES_VIEW_KEY, mode)
}

const search = ref('')
const server = ref('any')
const project = ref('any')
const source = ref('any')
const status = ref('any')
const groupBy = ref<GroupBy>('server')

// A Registry link (`?uuid=`) narrows the list to one Coolify resource.
const uuid = computed(() => (typeof route.query.uuid === 'string' ? route.query.uuid : ''))
// `?status=stale` and the like, so the Overview can link a filtered view.
watch(() => route.query.status, (value) => {
  if (value !== undefined)
    status.value = statusFromQuery(value)
}, { immediate: true })

const all = computed(() => services.data.value?.items ?? [])
const filters = computed(() => ({ search: search.value, server: server.value, project: project.value, source: source.value, status: status.value, uuid: uuid.value }))
const filtered = computed(() => all.value.filter(s => matchesFilters(s, filters.value)))
const groups = computed(() => groupServices(filtered.value, groupBy.value))
const options = computed(() => filterOptions(all.value))
const counts = computed(() => statusCounts(all.value))
const notes = computed(() => services.data.value ? coverageNotes(services.data.value.coverage, services.data.value.ambiguousServers.length) : [])
const filtering = computed(() => filtered.value.length !== all.value.length)

function resetFilters() {
  search.value = ''
  server.value = 'any'
  project.value = 'any'
  source.value = 'any'
  status.value = 'any'
  // A Registry link's ?uuid= narrows too, so clearing must drop it (and a status preset).
  const rest = { ...route.query }
  delete rest.uuid
  delete rest.status
  void router.replace({ query: rest })
}
</script>

<template>
  <div>
    <div class="flex flex-wrap items-end justify-between gap-3">
      <div>
        <p class="fc-kicker">
          <template v-if="services.data.value">
            {{ all.length }} running services · {{ counts.degraded }} degraded · {{ counts.stale }} stale
          </template>
          <template v-else>
            running services · observed, not stored
          </template>
        </p>
        <h1 class="fc-h1 mt-1">
          Services
        </h1>
      </div>
      <div class="flex items-center gap-3">
        <div class="inline-flex rounded-sm border border-fc-line">
          <button
            class="px-3 py-1.5 font-mono text-[10px] uppercase tracking-wider"
            :class="viewMode === 'cards' ? 'bg-fc-inset text-fc-ink' : 'text-fc-faint hover:text-fc-ink'"
            data-testid="view-cards"
            @click="chooseView('cards')"
          >
            Cards
          </button>
          <button
            class="px-3 py-1.5 font-mono text-[10px] uppercase tracking-wider"
            :class="viewMode === 'table' ? 'bg-fc-inset text-fc-ink' : 'text-fc-faint hover:text-fc-ink'"
            data-testid="view-table"
            @click="chooseView('table')"
          >
            Table
          </button>
        </div>
        <RouterLink
          to="/services/new"
          class="rounded-sm border border-input px-3 py-1.5 font-mono text-[10px] uppercase tracking-wider text-fc-ink hover:border-fc-line2"
          data-testid="new-site"
        >
          Deploy a site
        </RouterLink>
        <button
          class="rounded-sm border border-input px-3 py-1.5 font-mono text-[10px] uppercase tracking-wider text-fc-muted hover:border-fc-line2 hover:text-fc-ink"
          data-testid="refresh"
          @click="services.refetch()"
        >
          Refresh
        </button>
      </div>
    </div>

    <div
      v-if="services.error.value"
      class="mt-4 border-l-2 border-l-fc-err bg-card px-3 py-2 text-xs text-fc-muted"
      role="alert"
      data-testid="services-error"
    >
      Could not load services: {{ errorMessage(services.error.value) }}
    </div>
    <div
      v-if="services.data.value?.truncated"
      class="mt-4 border-l-2 border-l-fc-warn bg-card px-3 py-2 text-xs text-fc-muted"
      role="status"
    >
      The list hit the page safety cap; services beyond it are not shown.
    </div>
    <CoverageNotes :notes="notes" />

    <div class="mt-4 flex flex-wrap items-center gap-2">
      <Input
        v-model="search"
        placeholder="Search services…"
        class="h-8 w-56 border-input bg-background text-xs"
        data-testid="search"
      />
      <Select v-model="status">
        <SelectTrigger
          class="h-8 w-36 text-xs"
          aria-label="Status"
          data-testid="filter-status"
        >
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="any">
            Any status
          </SelectItem>
          <SelectItem
            v-for="name in ['running', 'degraded', 'stopped', 'unknown', 'stale']"
            :key="name"
            :value="name"
          >
            {{ name }} ({{ counts[name as keyof typeof counts] }})
          </SelectItem>
        </SelectContent>
      </Select>
      <Select v-model="source">
        <SelectTrigger
          class="h-8 w-32 text-xs"
          aria-label="Source"
          data-testid="filter-source"
        >
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="any">
            Any source
          </SelectItem>
          <SelectItem value="coolify">
            Coolify
          </SelectItem>
          <SelectItem value="docker">
            Docker
          </SelectItem>
        </SelectContent>
      </Select>
      <Select v-model="server">
        <SelectTrigger
          class="h-8 w-40 text-xs"
          aria-label="Server"
          data-testid="filter-server"
        >
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="any">
            Any server
          </SelectItem>
          <SelectItem
            v-for="option in options.servers"
            :key="option.key"
            :value="option.key"
          >
            {{ option.label }}
          </SelectItem>
          <SelectItem
            v-if="options.noServer"
            value="none"
          >
            No known server
          </SelectItem>
        </SelectContent>
      </Select>
      <Select v-model="project">
        <SelectTrigger
          class="h-8 w-44 text-xs"
          aria-label="Coolify project"
          data-testid="filter-project"
        >
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="any">
            Any project
          </SelectItem>
          <SelectItem
            v-for="option in options.projects"
            :key="option.key"
            :value="option.key"
          >
            {{ option.label }}
          </SelectItem>
          <SelectItem
            v-if="options.noProject"
            value="none"
          >
            No Coolify project
          </SelectItem>
        </SelectContent>
      </Select>
      <Select v-model="groupBy">
        <SelectTrigger
          class="h-8 w-44 text-xs"
          aria-label="Group by"
          data-testid="group-by"
        >
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          <SelectItem
            v-for="(label, key) in GROUP_LABELS"
            :key="key"
            :value="key"
          >
            Group: {{ label }}
          </SelectItem>
        </SelectContent>
      </Select>
      <button
        v-if="filtering || uuid"
        class="rounded-sm border border-input px-2 py-1 text-xs text-fc-muted hover:border-fc-line2 hover:text-fc-ink"
        data-testid="reset-filters"
        @click="resetFilters"
      >
        Clear filters
      </button>
    </div>
    <p
      v-if="uuid"
      class="mt-2 text-xs text-fc-faint"
    >
      Showing the service with Coolify uuid {{ uuid }}.
      <RouterLink
        to="/services"
        class="underline decoration-dotted hover:text-fc-ink"
      >
        Show all
      </RouterLink>
    </p>

    <div
      v-if="services.isLoading.value"
      class="mt-6 grid gap-3"
      style="grid-template-columns: repeat(auto-fill, minmax(290px, 1fr));"
    >
      <Skeleton
        v-for="i in 4"
        :key="i"
        class="h-40 rounded-sm"
      />
    </div>

    <div
      v-else-if="services.data.value && all.length === 0"
      class="mt-6 rounded-sm border border-fc-line bg-fc-panel p-10 text-center"
      data-testid="services-empty"
    >
      <p class="text-sm font-semibold text-fc-ink">
        No running services observed
      </p>
      <p class="mt-1 text-xs text-fc-faint">
        Add a Coolify account in Settings and run a discovery; services appear here once it has read them.
      </p>
    </div>

    <div
      v-else-if="services.data.value && filtered.length === 0"
      class="mt-6 rounded-sm border border-fc-line bg-fc-panel p-6 text-center text-xs text-fc-muted"
      data-testid="services-no-match"
    >
      No service matches these filters.
    </div>

    <template v-else-if="services.data.value">
      <div
        v-if="viewMode === 'cards'"
        class="mt-6 space-y-8"
        data-testid="cards-view"
      >
        <section
          v-for="group in groups"
          :key="group.key || '_all'"
          data-testid="service-group"
        >
          <div
            v-if="group.name"
            class="border-b-2 border-fc-line pb-1"
          >
            <h2 class="font-head text-sm font-bold uppercase tracking-wide text-fc-ink">
              {{ group.name }}
              <span class="float-right font-mono text-[9.5px] font-normal text-fc-faint">{{ group.services.length }} {{ group.services.length === 1 ? 'SERVICE' : 'SERVICES' }}</span>
            </h2>
          </div>
          <div
            class="grid gap-3"
            :class="group.name ? 'mt-3' : ''"
            style="grid-template-columns: repeat(auto-fill, minmax(290px, 1fr));"
          >
            <ServiceCard
              v-for="service in group.services"
              :key="service.id"
              :service="service"
            />
          </div>
        </section>
      </div>
      <div
        v-else
        class="mt-6"
        data-testid="table-view"
      >
        <ServiceTable :groups="groups" />
      </div>
    </template>
  </div>
</template>
