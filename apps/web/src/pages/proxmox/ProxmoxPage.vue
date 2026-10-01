<script setup lang="ts">
import { computed } from 'vue'
import { RouterLink, useRoute, useRouter } from 'vue-router'

import { Skeleton } from '@/components/ui/skeleton'

import { errorMessage } from '../machine/api'
import AccountCard from './components/AccountCard.vue'
import GuestsTab from './components/GuestsTab.vue'
import NodesTab from './components/NodesTab.vue'
import StorageTab from './components/StorageTab.vue'
import TasksTab from './components/TasksTab.vue'
import { guestRows, nodeRows, storageRows, templateRows } from './proxmox'
import { useProxmox } from './useProxmox'

// Proxmox VE (docs/planning/web-console.md, Proxmox page): accounts and
// their trust anchors first, then what pinned accounts discover. Fleet hands
// over to the PVE web UI for anything console-shaped.
const { accounts, views, discoveryErrors, guestErrors, loading } = useProxmox()
const route = useRoute()
const router = useRouter()

type Tab = 'accounts' | 'nodes' | 'storage' | 'guests' | 'tasks'

const nodes = computed(() => nodeRows(views.value))
const storage = computed(() => storageRows(views.value))
const templates = computed(() => templateRows(views.value))
const guests = computed(() => guestRows(views.value))
const attention = computed(() => views.value.filter(v => v.state !== 'pinned' && v.state !== 'checking').length)

const TABS: { id: Tab, label: string, count: () => number | null }[] = [
  { id: 'accounts', label: 'Accounts', count: () => views.value.length },
  { id: 'nodes', label: 'Nodes', count: () => nodes.value.length },
  { id: 'storage', label: 'Storage & templates', count: () => storage.value.length + templates.value.length },
  { id: 'guests', label: 'Guests', count: () => guests.value.length },
  { id: 'tasks', label: 'Tasks', count: () => null },
]

const tab = computed<Tab>({
  get: () => {
    const requested = route.query.tab
    return TABS.some(t => t.id === requested) ? requested as Tab : 'accounts'
  },
  set: (value) => {
    router.replace({ query: { ...route.query, tab: value === 'accounts' ? undefined : value } })
  },
})

// ARIA tabs: arrow keys, Home, and End move between tabs (roving tabindex).
function onTabKey(event: KeyboardEvent, index: number) {
  const last = TABS.length - 1
  const moves: Record<string, number> = { ArrowRight: index === last ? 0 : index + 1, ArrowLeft: index === 0 ? last : index - 1, Home: 0, End: last }
  const next = moves[event.key]
  if (next === undefined)
    return
  event.preventDefault()
  tab.value = TABS[next]!.id
  document.getElementById(`proxmox-tab-${TABS[next]!.id}`)?.focus()
}

const hosts = computed(() => new Map(views.value.map(v => [v.account.id, { host: v.account.host, port: v.account.port }])))
</script>

<template>
  <div>
    <div class="flex flex-wrap items-end gap-4">
      <div>
        <p class="fc-kicker">
          {{ views.length }} account{{ views.length === 1 ? '' : 's' }} · {{ nodes.length }} node{{ nodes.length === 1 ? '' : 's' }} · {{ guests.length }} guests<template v-if="attention">
            · <span class="text-fc-err">{{ attention }} need{{ attention === 1 ? 's' : '' }} attention</span>
          </template>
        </p>
        <h1 class="fc-h1">
          Proxmox
        </h1>
      </div>
      <div class="ml-auto flex gap-2">
        <RouterLink
          :to="{ path: '/fleet/add', query: { source: 'proxmox' } }"
          class="fc-grad-bg flex h-9 items-center rounded-sm px-3.5 font-head text-xs font-bold"
          data-testid="add-account"
        >
          + Proxmox account
        </RouterLink>
      </div>
    </div>

    <div
      class="mt-4 flex gap-6 border-b border-fc-line"
      role="tablist"
    >
      <button
        v-for="(item, index) in TABS"
        :id="`proxmox-tab-${item.id}`"
        :key="item.id"
        type="button"
        role="tab"
        :tabindex="tab === item.id ? 0 : -1"
        aria-controls="proxmox-tabpanel"
        class="pb-2 text-[13px] font-semibold"
        :class="tab === item.id ? 'text-fc-ink shadow-[inset_0_-2px_0_var(--fc-g1)]' : 'text-fc-muted hover:text-fc-ink'"
        :aria-selected="tab === item.id"
        :data-testid="`tab-${item.id}`"
        @click="tab = item.id"
        @keydown="onTabKey($event, index)"
      >
        {{ item.label }}<span
          v-if="item.count() !== null"
          class="ml-1 font-mono text-[10px] text-fc-faint"
        >{{ item.count() }}</span>
      </button>
    </div>

    <div
      v-if="accounts.error.value"
      class="mt-4 border-l-2 border-l-fc-err bg-card px-3 py-2 text-xs text-fc-muted"
      role="alert"
    >
      Could not load Proxmox accounts: {{ errorMessage(accounts.error.value) }}
    </div>

    <div
      v-if="accounts.isLoading.value"
      class="mt-4 grid gap-3"
    >
      <Skeleton
        v-for="i in 2"
        :key="i"
        class="h-24 rounded-sm"
      />
    </div>

    <div
      v-else
      id="proxmox-tabpanel"
      role="tabpanel"
      :aria-labelledby="`proxmox-tab-${tab}`"
    >
      <template v-if="tab === 'accounts'">
        <p
          v-if="views.length === 0 && !accounts.error.value"
          class="mt-4 rounded-sm border border-fc-line p-6 text-sm text-fc-muted"
          data-testid="accounts-empty"
        >
          No Proxmox accounts. Add one with an API token; Fleet pins its TLS certificate before it calls anything.
        </p>
        <div class="mt-4 grid gap-3 lg:grid-cols-2">
          <AccountCard
            v-for="view in views"
            :key="view.account.id"
            :view="view"
            :discovery-error="discoveryErrors.get(view.account.id)"
            :guest-error="guestErrors.get(view.account.id)"
          />
        </div>
      </template>

      <template v-else>
        <p
          v-if="loading"
          class="mt-4 text-xs text-fc-faint"
        >
          Discovering…
        </p>
        <NodesTab
          v-if="tab === 'nodes'"
          :rows="nodes"
          :hosts="hosts"
        />
        <StorageTab
          v-else-if="tab === 'storage'"
          :storage="storage"
          :templates="templates"
        />
        <GuestsTab
          v-else-if="tab === 'guests'"
          :rows="guests"
          :views="views"
        />
        <TasksTab
          v-else
          :views="views"
        />
      </template>
    </div>
  </div>
</template>
