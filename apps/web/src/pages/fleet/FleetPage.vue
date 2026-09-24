<script setup lang="ts">
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from '@/components/ui/collapsible'
import { Input } from '@/components/ui/input'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Skeleton } from '@/components/ui/skeleton'
import { RouterLink, useRoute } from 'vue-router'
import { computed, ref, watch } from 'vue'

import MachinesPanel from '@/components/MachinesPanel.vue'
import type { PageMachineDtoItemsItem } from '@frogbyte-io/fleet-api-client'

import GuestCard from './components/GuestCard.vue'
import GuestDrawer from './components/GuestDrawer.vue'
import HostCard from './components/HostCard.vue'
import MachineCard from './components/MachineCard.vue'
import MachineDrawer from './components/MachineDrawer.vue'
import FleetTable from './components/FleetTable.vue'
import TailnetCard from './components/TailnetCard.vue'
import { useFleetInventory } from './useFleetInventory'
import type { HostItem, MachineItem } from './inventory'
const route = useRoute()

const { inventory, isLoading, refetchAll } = useFleetInventory()

const rawMachines = computed(() => inventory.value.rawMachines ?? [])

const VIEW_KEY = 'fleet-console-fleet-view'
const VIEWS_KEY = 'fleet-console-fleet-views'
const HIDDEN_KEY = 'fleet-console-hidden-tailnet'

const viewMode = ref<'cards' | 'table'>(
  localStorage.getItem(VIEW_KEY) === 'table' ? 'table' : 'cards',
)
watch(viewMode, mode => localStorage.setItem(VIEW_KEY, mode))

const search = ref('')
const statusFilter = ref('any')
const kindFilter = ref('all')
const groupBy = ref<'kind' | 'group' | 'none'>('kind')

interface SavedView {
  name: string
  search: string
  statusFilter: string
  kindFilter: string
  groupBy: string
}

function loadSavedViews(): SavedView[] {
  try {
    return JSON.parse(localStorage.getItem(VIEWS_KEY) ?? '[]') as SavedView[]
  }
  catch {
    return []
  }
}
const savedViews = ref<SavedView[]>(loadSavedViews())
const saveViewName = ref('')

function saveView() {
  const name = saveViewName.value.trim()
  if (!name)
    return
  const views = loadSavedViews().filter(v => v.name !== name)
  views.push({ name, search: search.value, statusFilter: statusFilter.value, kindFilter: kindFilter.value, groupBy: groupBy.value })
  localStorage.setItem(VIEWS_KEY, JSON.stringify(views))
  savedViews.value = views
  saveViewName.value = ''
}

function applyView(view: SavedView) {
  search.value = view.search
  statusFilter.value = view.statusFilter
  kindFilter.value = view.kindFilter
  groupBy.value = view.groupBy as 'kind' | 'group' | 'none'
}

function deleteView(name: string) {
  const views = loadSavedViews().filter(v => v.name !== name)
  localStorage.setItem(VIEWS_KEY, JSON.stringify(views))
  savedViews.value = views
}

function loadHidden(): string[] {
  try {
    return JSON.parse(localStorage.getItem(HIDDEN_KEY) ?? '[]') as string[]
  }
  catch {
    return []
  }
}
const hiddenTailnet = ref<string[]>(loadHidden())
const showHidden = ref(false)
const hiddenCount = computed(() => hiddenTailnet.value.length)

function hideTailnet(nodeId: string) {
  const hidden = loadHidden()
  if (!hidden.includes(nodeId)) {
    hidden.push(nodeId)
    localStorage.setItem(HIDDEN_KEY, JSON.stringify(hidden))
  }
  hiddenTailnet.value = hidden
}

const classicOpen = ref(false)

const selectedMachineId = ref<string | null>(null)
const selectedGuestKey = ref<string | null>(null)
const drawerOpen = ref(false)

function openMachine(id: string) {
  selectedMachineId.value = id
  selectedGuestKey.value = null
  drawerOpen.value = true
}

function openGuest(key: string) {
  selectedGuestKey.value = key
  selectedMachineId.value = null
  drawerOpen.value = true
}

function applyFocus(focus: unknown) {
  if (typeof focus === 'string' && focus) {
    viewMode.value = 'table'
    openMachine(focus)
  }
}

applyFocus(route.query.focus)
watch(() => route.query.focus, applyFocus)

function matchesSearch(text: string, needle: string): boolean {
  return text.toLowerCase().includes(needle.toLowerCase())
}

const visibleTailnet = computed(() =>
  inventory.value.tailnetOnly.filter(d => !hiddenTailnet.value.includes(d.nodeId) || showHidden.value),
)

const machinesSourceOk = computed(() =>
  inventory.value.sources.find(s => s.key === 'machines')?.state === 'ok',
)

const filteredHosts = computed(() =>
  inventory.value.hosts.filter((h) => {
    if (kindFilter.value !== 'all' && kindFilter.value !== 'hosts')
      return false
    return !search.value || matchesSearch(h.name, search.value)
  }),
)

// Guests matched by search/kind keep their host row visible as context (finding 9).
const filteredGuests = computed(() =>
  inventory.value.guests.filter((g) => {
    if (kindFilter.value !== 'all' && kindFilter.value !== 'guests')
      return false
    if (search.value && !matchesSearch(`${g.name} ${g.node}`, search.value))
      return false
    return true
  }),
)

const contextHosts = computed(() => {
  if (kindFilter.value !== 'all' && kindFilter.value !== 'guests')
    return []
  if (!search.value)
    return []
  const matchedGuests = filteredGuests.value
  return inventory.value.hosts.filter((h) => {
    if (filteredHosts.value.some(fh => fh.key === h.key))
      return false
    return matchedGuests.some(g => g.accountId === h.accountId && g.node === h.nodeKey)
  })
})

const hostsWithContext = computed<HostItem[]>(() => {
  return [...filteredHosts.value, ...contextHosts.value.filter(h => !filteredHosts.value.some(fh => fh.key === h.key))]
})

const contextHostKeys = computed(() => new Set(contextHosts.value.map(h => h.key)))

const filteredMachines = computed(() =>
  inventory.value.machines.filter((m) => {
    if (kindFilter.value !== 'all' && kindFilter.value !== 'machines')
      return false
    if (statusFilter.value !== 'any' && m.status !== statusFilter.value)
      return false
    if (search.value && !matchesSearch(`${m.name} ${m.tags.join(' ')} ${m.groups.join(' ')}`, search.value))
      return false
    return true
  }),
)

const filteredTailnet = computed(() =>
  visibleTailnet.value.filter((d) => {
    if (kindFilter.value !== 'all' && kindFilter.value !== 'tailnet')
      return false
    if (search.value && !matchesSearch(`${d.name} ${d.hostname} ${d.tags.join(' ')}`, search.value))
      return false
    return true
  }),
)

interface MachineGroup {
  name: string
  machines: MachineItem[]
}

const machineGroups = computed<MachineGroup[]>(() => {
  if (groupBy.value === 'group') {
    const map = new Map<string, MachineItem[]>()
    for (const machine of filteredMachines.value) {
      const keys = machine.groups.length > 0 ? machine.groups : ['Ungrouped']
      for (const key of keys) {
        const list = map.get(key) ?? []
        list.push(machine)
        map.set(key, list)
      }
    }
    return [...map.entries()].map(([name, machines]) => ({ name, machines }))
  }
  return [{ name: '', machines: filteredMachines.value }]
})

const counts = computed(() => ({
  machines: inventory.value.machines.length,
  hosts: inventory.value.hosts.length,
  guests: inventory.value.guests.length,
  tailnetOnly: visibleTailnet.value.length,
}))

const isEmpty = computed(() =>
  counts.value.machines === 0
  && counts.value.hosts === 0
  && counts.value.guests === 0
  && counts.value.tailnetOnly === 0,
)

const selectedMachine = computed(() =>
  inventory.value.machines.find(m => m.id === selectedMachineId.value) ?? null,
)

const selectedRawMachine = computed<PageMachineDtoItemsItem | null>(() =>
  rawMachines.value.find(m => m.id === selectedMachineId.value) ?? null,
)

const selectedGuest = computed(() =>
  inventory.value.guests.find(g => g.key === selectedGuestKey.value) ?? null,
)

const errorSources = computed(() =>
  inventory.value.sources.filter(s => s.state !== 'ok'),
)

function sourceBorder(state: string): string {
  if (state === 'error')
    return 'border-l-fc-err'
  if (state === 'loading')
    return 'border-l-transparent'
  return 'border-l-fc-warn'
}
</script>

<template>
  <div>
    <div class="flex items-end justify-between">
      <div>
        <p class="fc-kicker">
          {{ counts.machines }} machines · {{ counts.hosts }} hosts · {{ counts.guests }} guests · {{ counts.tailnetOnly }} tailnet-only
        </p>
        <h1 class="fc-h1 mt-1">
          Your <span class="fc-grad-text">fleet</span>, observed.
        </h1>
      </div>
      <div class="flex items-center gap-3">
        <div class="inline-flex rounded-sm border border-fc-line">
          <button
            class="px-3 py-1.5 font-mono text-[10px] uppercase tracking-wider"
            :class="viewMode === 'cards' ? 'bg-fc-inset text-fc-ink' : 'text-fc-faint hover:text-fc-ink'"
            data-testid="view-cards"
            @click="viewMode = 'cards'"
          >
            Cards
          </button>
          <button
            class="px-3 py-1.5 font-mono text-[10px] uppercase tracking-wider"
            :class="viewMode === 'table' ? 'bg-fc-inset text-fc-ink' : 'text-fc-faint hover:text-fc-ink'"
            data-testid="view-table"
            @click="viewMode = 'table'"
          >
            Table
          </button>
        </div>
        <button
          class="rounded-sm border border-input px-3 py-1.5 font-mono text-[10px] uppercase tracking-wider text-fc-muted hover:border-fc-line2 hover:text-fc-ink"
          data-testid="refresh"
          @click="refetchAll"
        >
          Refresh
        </button>
        <RouterLink
          to="/fleet/add"
          class="fc-grad-bg inline-flex h-9 items-center rounded-sm px-4 text-sm font-medium"
        >
          + Add machine
        </RouterLink>
      </div>
    </div>

    <div
      v-if="errorSources.length > 0"
      class="mt-4 space-y-1.5"
    >
      <div
        v-for="source in errorSources"
        :key="source.key"
        class="border-l-2 bg-fc-panel px-3 py-1.5 text-xs text-fc-muted"
        :class="sourceBorder(source.state)"
      >
        {{ source.label }}: {{ source.message }}
      </div>
    </div>

    <div class="mt-4 flex flex-wrap items-center gap-2">
      <Input
        v-model="search"
        placeholder="Search name, host, tags…"
        class="h-8 w-56 border-input bg-background text-xs"
        data-testid="search"
      />
      <Select v-model="statusFilter">
        <SelectTrigger class="h-8 w-32 text-xs">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="any">
            Any status
          </SelectItem>
          <SelectItem value="connected">
            connected
          </SelectItem>
          <SelectItem value="agentless">
            agentless
          </SelectItem>
          <SelectItem value="stale">
            stale
          </SelectItem>
          <SelectItem value="offline">
            offline
          </SelectItem>
        </SelectContent>
      </Select>
      <Select v-model="kindFilter">
        <SelectTrigger class="h-8 w-32 text-xs">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="all">
            All kinds
          </SelectItem>
          <SelectItem value="hosts">
            Hosts
          </SelectItem>
          <SelectItem value="guests">
            Guests
          </SelectItem>
          <SelectItem value="machines">
            Machines
          </SelectItem>
          <SelectItem value="tailnet">
            Tailnet
          </SelectItem>
        </SelectContent>
      </Select>
      <Select v-model="groupBy">
        <SelectTrigger class="h-8 w-32 text-xs">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="kind">
            Group: Kind
          </SelectItem>
          <SelectItem value="group">
            Group: Group
          </SelectItem>
          <SelectItem value="none">
            Group: None
          </SelectItem>
        </SelectContent>
      </Select>
      <input
        v-model="saveViewName"
        placeholder="view name"
        class="h-8 w-28 rounded-sm border border-input bg-background px-2 text-xs"
      >
      <button
        class="rounded-sm border border-input px-2 py-1 text-xs text-fc-muted hover:border-fc-line2 hover:text-fc-ink"
        data-testid="save-view"
        @click="saveView"
      >
        Save view
      </button>
      <button
        v-for="view in savedViews"
        :key="view.name"
        class="group inline-flex items-center gap-1 rounded-sm border border-fc-line px-2 py-1 text-xs text-fc-muted hover:border-fc-line2 hover:text-fc-ink"
        @click="applyView(view)"
      >
        {{ view.name }}
        <span
          class="text-fc-faint hover:text-fc-err"
          @click.stop="deleteView(view.name)"
        >×</span>
      </button>
      <label
        v-if="hiddenCount > 0"
        class="inline-flex items-center gap-1 text-xs text-fc-faint"
      >
        <input
          v-model="showHidden"
          type="checkbox"
        >
        Show hidden ({{ hiddenCount }})
      </label>
    </div>

    <div
      v-if="isLoading"
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
      v-else-if="isEmpty && machinesSourceOk"
      class="mt-6 rounded-sm border border-fc-line bg-fc-panel p-10 text-center"
    >
      <p class="text-sm font-semibold text-fc-ink">
        No machines yet
      </p>
      <p class="mt-1 text-xs text-fc-faint">
        Add your first machine to start observing the fleet.
      </p>
      <RouterLink
        to="/fleet/add"
        class="fc-grad-bg mt-4 inline-flex h-8 items-center rounded-sm px-4 text-xs font-medium"
      >
        + Add machine
      </RouterLink>
    </div>

    <div
      v-else-if="!machinesSourceOk"
      class="mt-6 rounded-sm border border-fc-line bg-fc-panel p-10 text-center"
      data-testid="empty-error"
    >
      <p class="text-sm font-semibold text-fc-ink">
        Machines could not be loaded — see the banner above.
      </p>
    </div>

    <template v-else>
      <div
        v-if="viewMode === 'cards' && groupBy === 'none'"
        class="mt-6"
        data-testid="flat-view"
      >
        <div
          class="grid gap-3"
          style="grid-template-columns: repeat(auto-fill, minmax(290px, 1fr));"
        >
          <HostCard
            v-for="host in filteredHosts"
            :key="host.key"
            :host="host"
            :guests="[]"
          />
          <GuestCard
            v-for="guest in filteredGuests"
            :key="guest.key"
            :guest="guest"
          />
          <MachineCard
            v-for="machine in filteredMachines"
            :key="machine.id"
            :machine="machine"
          >
            <template #actions>
              <button
                class="font-mono text-[10px] uppercase tracking-wider text-fc-info hover:text-fc-ink"
                data-testid="open-machine"
                @click="openMachine(machine.id)"
              >
                Open →
              </button>
            </template>
          </MachineCard>
          <TailnetCard
            v-for="device in filteredTailnet"
            :key="device.nodeId"
            :device="device"
          >
            <template #hide>
              <button
                class="font-mono text-[10px] uppercase tracking-wider text-fc-faint hover:text-fc-err"
                @click="hideTailnet(device.nodeId)"
              >
                Hide
              </button>
            </template>
          </TailnetCard>
        </div>
      </div>

      <div
        v-else-if="viewMode === 'cards'"
        class="mt-6 space-y-8"
      >
        <section
          v-if="hostsWithContext.length > 0"
          data-testid="section-hosts"
        >
          <div class="border-b-2 border-fc-line pb-1">
            <h2 class="font-head text-sm font-bold uppercase tracking-wide text-fc-ink">
              Proxmox hosts
              <span class="float-right font-mono text-[9.5px] font-normal text-fc-faint">{{ hostsWithContext.length }} NODES</span>
            </h2>
          </div>
          <div
            class="mt-3 grid gap-3"
            style="grid-template-columns: repeat(auto-fill, minmax(290px, 1fr));"
          >
            <HostCard
              v-for="host in hostsWithContext"
              :key="host.key"
              :host="host"
              :guests="filteredGuests.filter(g => g.accountId === host.accountId && g.node === host.nodeKey)"
              :context="contextHostKeys.has(host.key)"
            />
          </div>
        </section>

        <section
          v-if="filteredGuests.length > 0"
          data-testid="section-guests"
        >
          <div class="border-b-2 border-fc-line pb-1">
            <h2 class="font-head text-sm font-bold uppercase tracking-wide text-fc-ink">
              Virtual machines &amp; containers
              <span class="float-right font-mono text-[9.5px] font-normal text-fc-faint">{{ filteredGuests.length }} GUESTS</span>
            </h2>
          </div>
          <div
            class="mt-3 grid gap-3"
            style="grid-template-columns: repeat(auto-fill, minmax(290px, 1fr));"
          >
            <GuestCard
              v-for="guest in filteredGuests"
              :key="guest.key"
              :guest="guest"
            />
          </div>
        </section>

        <section
          data-testid="section-machines"
        >
          <div class="border-b-2 border-fc-line pb-1">
            <h2 class="font-head text-sm font-bold uppercase tracking-wide text-fc-ink">
              Machines
              <span class="float-right font-mono text-[9.5px] font-normal text-fc-faint">{{ filteredMachines.length }} MACHINES</span>
            </h2>
          </div>
          <p
            v-if="filteredMachines.length === 0 && machinesSourceOk"
            class="mt-3 text-xs text-fc-faint"
          >
            No machines yet —
            <RouterLink
              to="/fleet/add"
              class="underline decoration-dotted hover:text-fc-ink"
            >
              Add machine
            </RouterLink>
          </p>
          <div
            v-for="group in machineGroups"
            :key="group.name || '_all'"
          >
            <p
              v-if="group.name"
              class="fc-kicker mt-3"
            >
              {{ group.name }}
            </p>
            <div
              class="mt-3 grid gap-3"
              style="grid-template-columns: repeat(auto-fill, minmax(290px, 1fr));"
            >
              <MachineCard
                v-for="machine in group.machines"
                :key="machine.id"
                :machine="machine"
              >
                <template #actions>
                  <button
                    class="font-mono text-[10px] uppercase tracking-wider text-fc-info hover:text-fc-ink"
                    data-testid="open-machine"
                    @click="openMachine(machine.id)"
                  >
                    Open →
                  </button>
                </template>
              </MachineCard>
            </div>
          </div>
        </section>

        <section
          v-if="filteredTailnet.length > 0"
          data-testid="section-tailnet"
        >
          <div class="border-b-2 border-fc-line pb-1">
            <h2 class="font-head text-sm font-bold uppercase tracking-wide text-fc-ink">
              On your tailnet — not in Fleet
              <span class="float-right font-mono text-[9.5px] font-normal text-fc-faint">{{ filteredTailnet.length }} DEVICES</span>
            </h2>
          </div>
          <div
            class="mt-3 grid gap-3"
            style="grid-template-columns: repeat(auto-fill, minmax(290px, 1fr));"
          >
            <TailnetCard
              v-for="device in filteredTailnet"
              :key="device.nodeId"
              :device="device"
            >
              <template #hide>
                <button
                  class="font-mono text-[10px] uppercase tracking-wider text-fc-faint hover:text-fc-err"
                  @click="hideTailnet(device.nodeId)"
                >
                  Hide
                </button>
              </template>
            </TailnetCard>
          </div>
        </section>
      </div>

      <div
        v-else
        class="mt-6"
        data-testid="table-view"
      >
        <FleetTable
          :hosts="hostsWithContext"
          :context-host-keys="contextHostKeys"
          :guests="filteredGuests"
          :machine-groups="machineGroups"
          :tailnet-only="filteredTailnet"
          :flat="groupBy === 'none'"
          @open-machine="openMachine"
          @open-guest="openGuest"
        />
      </div>
    </template>

    <MachineDrawer
      v-model:open="drawerOpen"
      :machine="selectedMachine"
      :raw="selectedRawMachine"
    />

    <GuestDrawer
      v-model:open="drawerOpen"
      :guest="selectedGuest"
    />

    <Collapsible
      v-model:open="classicOpen"
      class="mt-10"
    >
      <CollapsibleTrigger
        class="flex w-full items-center justify-between rounded-sm border border-fc-line bg-fc-panel px-4 py-2 text-left text-sm text-fc-muted hover:border-fc-line2"
      >
        Classic machine list
        <span class="font-mono text-[10px] uppercase">{{ classicOpen ? 'HIDE' : 'SHOW' }}</span>
      </CollapsibleTrigger>
      <CollapsibleContent>
        <div class="mt-3">
          <MachinesPanel />
        </div>
      </CollapsibleContent>
    </Collapsible>
  </div>
</template>
