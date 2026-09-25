<script setup lang="ts">
import { useQuery } from '@tanstack/vue-query'
import { computed, ref } from 'vue'
import { RouterLink, useRoute, useRouter } from 'vue-router'

import { getMachine, type MachineDto } from '@frogbyte-io/fleet-api-client'
import StatusChip from '@/components/fleet/StatusChip.vue'
import { Skeleton } from '@/components/ui/skeleton'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'

import { machineStatusTone } from '../fleet/inventory'
import { useFleetInventory } from '../fleet/useFleetInventory'
import { ApiRequestError, errorMessage, retryTransient, unwrap } from './api'
import { parseSshReference, sshCommand, vscodeRemoteUrl } from './handoff'
import { provideMachineOperations } from './operations'
import AuditTab from './tabs/AuditTab.vue'
import ConnectionsTab from './tabs/ConnectionsTab.vue'
import GuestTab from './tabs/GuestTab.vue'
import InventoryTab from './tabs/InventoryTab.vue'
import OperationsTab from './tabs/OperationsTab.vue'
import OverviewTab from './tabs/OverviewTab.vue'
import ProjectsTab from './tabs/ProjectsTab.vue'
import ToolsTab from './tabs/ToolsTab.vue'

// MachineRoute keys this page by id, so the id is fixed per instance.
const props = defineProps<{ machineId: string }>()
const machineId = props.machineId

const route = useRoute()
const router = useRouter()
provideMachineOperations(machineId)

const machineQuery = useQuery({
  queryKey: ['machine', machineId],
  queryFn: async () => unwrap<MachineDto>(await getMachine(machineId)),
  retry: retryTransient,
})
const machine = computed(() => machineQuery.data.value ?? null)
const notFound = computed(() => machineQuery.error.value instanceof ApiRequestError && machineQuery.error.value.status === 404)

const { inventory, isLoading: inventoryLoading } = useFleetInventory()
const item = computed(() => inventory.value.machines.find(m => m.id === machineId) ?? null)
const guests = computed(() => inventory.value.guests.filter(g => g.candidates.some(c => c.machineId === machineId)))
// The Guest tab depends on the Proxmox sources only, not on tailnet state.
const proxmoxSources = computed(() => inventory.value.sources.filter(s => s.key.startsWith('proxmox')))
const proxmoxLoading = computed(() =>
  proxmoxSources.value.some(s => s.state === 'loading') || (proxmoxSources.value.length === 0 && inventoryLoading.value),
)

const TABS = [
  { value: 'overview', label: 'Overview' },
  { value: 'inventory', label: 'Inventory' },
  { value: 'connections', label: 'Connections' },
  { value: 'projects', label: 'Projects' },
  { value: 'tools', label: 'Tools' },
  { value: 'operations', label: 'Operations' },
  { value: 'audit', label: 'Audit' },
  { value: 'guest', label: 'Guest' },
] as const

const visibleTabs = computed(() => TABS.filter(t => t.value !== 'guest' || guests.value.length > 0 || route.query.tab === 'guest'))

const tab = computed({
  get: () => {
    const requested = route.query.tab
    return typeof requested === 'string' && TABS.some(t => t.value === requested) ? requested : 'overview'
  },
  set: (value: string) => {
    router.replace({ query: { ...route.query, tab: value === 'overview' ? undefined : value } })
  },
})

// Client handoffs: the operator's own SSH client and VS Code connect; Fleet
// only hands over the address.
// The first SSH endpoint whose reference parses as a target.
const sshTarget = computed(() => {
  for (const endpoint of machine.value?.endpoints ?? []) {
    const target = endpoint.kind === 'ssh' ? parseSshReference(endpoint.reference) : null
    if (target)
      return target
  }
  return null
})
const sshLine = computed(() => (sshTarget.value ? sshCommand(sshTarget.value) : null))
const vscodeUrl = computed(() => (sshTarget.value ? vscodeRemoteUrl(sshTarget.value) : null))
const sshCopied = ref(false)

async function copySsh() {
  if (!sshLine.value)
    return
  try {
    await navigator.clipboard.writeText(sshLine.value)
    sshCopied.value = true
    setTimeout(() => (sshCopied.value = false), 1500)
  }
  catch {
    // Clipboard unavailable; the command is in the button's title.
  }
}
</script>

<template>
  <div class="mx-auto max-w-[1320px]">
    <RouterLink
      to="/fleet"
      class="font-mono text-[10px] uppercase tracking-wider text-fc-faint hover:text-fc-ink"
    >
      ← Fleet
    </RouterLink>

    <div
      v-if="machineQuery.isLoading.value"
      class="mt-4 space-y-3"
    >
      <Skeleton class="h-8 w-64" />
      <Skeleton class="h-40 w-full" />
    </div>

    <div
      v-else-if="notFound"
      class="mt-6 rounded-sm border border-fc-line p-6"
      data-testid="machine-not-found"
    >
      <p class="text-sm text-fc-ink">
        No machine with id <span class="font-mono">{{ machineId }}</span>.
      </p>
    </div>

    <div
      v-else-if="machineQuery.error.value && !machine"
      class="mt-6 rounded-sm border border-fc-err/40 p-6"
      data-testid="machine-error"
    >
      <p class="text-sm text-fc-err">
        Machine unavailable: {{ errorMessage(machineQuery.error.value) }}
      </p>
      <button
        type="button"
        class="mt-3 font-mono text-[10px] uppercase tracking-wider text-fc-info hover:text-fc-ink"
        @click="machineQuery.refetch()"
      >
        Retry
      </button>
    </div>

    <template v-else-if="machine">
      <header class="mt-3 flex flex-wrap items-end justify-between gap-4">
        <div>
          <p class="fc-kicker">
            Machine · {{ machine.id }}
          </p>
          <h1 class="fc-h1 mt-1 flex items-center gap-3">
            {{ machine.name }}
            <StatusChip
              :label="machine.machineStatus"
              :tone="machineStatusTone(machine.machineStatus)"
            />
          </h1>
        </div>
        <div class="flex flex-wrap items-center gap-2">
          <button
            type="button"
            class="h-8 rounded-sm border border-fc-line px-3 font-mono text-[11px] text-fc-ink hover:border-fc-line2 disabled:opacity-50"
            :disabled="!sshLine"
            :title="sshLine ?? 'No SSH endpoint'"
            data-testid="copy-ssh"
            @click="copySsh"
          >
            {{ sshCopied ? 'Copied' : 'Copy SSH' }}
          </button>
          <a
            v-if="vscodeUrl"
            :href="vscodeUrl"
            class="flex h-8 items-center rounded-sm border border-fc-line px-3 font-mono text-[11px] text-fc-ink hover:border-fc-line2"
            data-testid="open-vscode"
          >
            Open in VS Code
          </a>
          <span
            v-else-if="sshTarget"
            class="font-mono text-[10px] text-fc-faint"
            title="VS Code Remote-SSH links cannot carry a port; add a Host entry to your SSH config."
          >
            VS Code: non-default port
          </span>
        </div>
      </header>

      <Tabs
        v-model="tab"
        class="mt-6"
      >
        <TabsList class="h-auto w-full justify-start gap-1 overflow-x-auto rounded-sm border-b border-fc-line bg-transparent p-0">
          <TabsTrigger
            v-for="t in visibleTabs"
            :key="t.value"
            :value="t.value"
            class="flex-none rounded-none border-0 border-b-2 border-transparent px-3 py-2 font-mono text-[11px] uppercase tracking-wider text-fc-muted data-[state=active]:border-fc-ink data-[state=active]:bg-transparent data-[state=active]:text-fc-ink data-[state=active]:shadow-none"
            :data-testid="`tab-${t.value}`"
          >
            {{ t.label }}
          </TabsTrigger>
        </TabsList>
        <div class="pt-4">
          <TabsContent value="overview">
            <OverviewTab
              :machine="machine"
              :item="item"
              :guests="guests"
            />
          </TabsContent>
          <TabsContent value="inventory">
            <InventoryTab :machine="machine" />
          </TabsContent>
          <TabsContent value="connections">
            <ConnectionsTab :machine="machine" />
          </TabsContent>
          <TabsContent value="projects">
            <ProjectsTab :machine-id="machine.id" />
          </TabsContent>
          <TabsContent value="tools">
            <ToolsTab :machine="machine" />
          </TabsContent>
          <TabsContent value="operations">
            <OperationsTab />
          </TabsContent>
          <TabsContent value="audit">
            <AuditTab :machine-id="machine.id" />
          </TabsContent>
          <TabsContent value="guest">
            <GuestTab
              :guests="guests"
              :machine-id="machine.id"
              :loading="proxmoxLoading"
              :problems="proxmoxSources.filter(s => s.state !== 'ok' && s.state !== 'loading')"
            />
          </TabsContent>
        </div>
      </Tabs>
    </template>
  </div>
</template>
