<script setup lang="ts">
import { computed, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'

import {
  getMeta,
  getSystemInfo,
  listMachines,
  listProxmoxAccounts,
  getTailnetStatus,
  type MachineDto,
  type ResourceMetaData,
  type ProxmoxAccountDto,
  type SystemInfo,
  type ResourceTailnetStatusDtoData,
} from '@frogbyte-io/fleet-api-client'

import {
  DEFAULT_SECTION,
  SETTINGS_SECTION_GROUPS,
  isSectionId,
} from './sections'
import DiagnosticsSection from './sections/DiagnosticsSection.vue'
import FleetdSection from './sections/FleetdSection.vue'
import GapSection from './sections/GapSection.vue'
import IntegrationsSection from './sections/IntegrationsSection.vue'
import SecuritySection from './sections/SecuritySection.vue'
import SettingsLoading from './sections/SettingsLoading.vue'

const route = useRoute()
const router = useRouter()

const section = computed(() => {
  const requested = route.query.section
  const id = typeof requested === 'string' ? requested : DEFAULT_SECTION
  return isSectionId(id) ? id : DEFAULT_SECTION
})

function selectSection(id: string): void {
  void router.replace({ query: { section: id } })
}

const system = ref<SystemInfo | null>(null)
const meta = ref<ResourceMetaData | null>(null)
const machines = ref<MachineDto[]>([])
const proxmoxAccounts = ref<ProxmoxAccountDto[]>([])
const proxmoxUnavailable = ref(false)
const tailnet = ref<ResourceTailnetStatusDtoData | null>(null)
const tailnetUnavailable = ref(false)
const failed = ref(false)
const failure = ref('')
const loaded = ref(false)

const GAP_SECTIONS: Record<string, { title: string; detail: string }> = {
  general: {
    title: 'General',
    detail:
      'Controller name, URL, and time format are deployment facts set at start-up; there is no settings API to change them yet.',
  },
  appearance: {
    title: 'Appearance',
    detail:
      'The console follows your system light/dark preference; the theme toggle lives in the top bar and is per browser.',
  },
  backups: {
    title: 'Backups',
    detail:
      'SQLite backups are an operator task today; a backup surface has no backing API yet.',
  },
  credentials: {
    title: 'Credentials',
    detail:
      'Stored credentials have no HTTP surface yet. When it exists, this page will show names, scope, and set/rotated dates — never secret values.',
  },
  'ssh-keys': {
    title: 'SSH & host keys',
    detail:
      'Host keys are confirmed during onboarding per machine. A controller-side known-hosts review has no backing API yet.',
  },
  'lab-defaults': {
    title: 'Lab defaults',
    detail:
      'TTL, max lifetime, and cleanup strategy are set per lease and per template; a fleet-wide defaults surface has no backing API yet.',
  },
  'desired-state': {
    title: 'Desired state',
    detail:
      'Git sources are configured per apply workflow; a fleet-wide desired-state view has no backing API yet.',
  },
  notifications: {
    title: 'Notifications',
    detail:
      'Webhook and ntfy delivery for cleanup failures, offline machines, and blocked approvals is not built yet.',
  },
}

const gap = computed(() => GAP_SECTIONS[section.value] ?? null)

async function load(): Promise<void> {
  failed.value = false
  const results = await Promise.allSettled([
    getSystemInfo(),
    getMeta(),
    listMachines(),
    listProxmoxAccounts(),
    getTailnetStatus(),
  ])
  const [systemResult, metaResult, machinesResult, proxmoxResult, tailnetResult] = results
  if (systemResult.status === 'fulfilled' && systemResult.value.status === 200) {
    system.value = systemResult.value.data
  }
  if (metaResult.status === 'fulfilled' && metaResult.value.status === 200) {
    meta.value = metaResult.value.data.data
  }
  if (machinesResult.status === 'fulfilled' && machinesResult.value.status === 200) {
    machines.value = machinesResult.value.data.items
  }
  if (proxmoxResult.status === 'fulfilled' && proxmoxResult.value.status === 200) {
    proxmoxAccounts.value = proxmoxResult.value.data.items
  } else {
    proxmoxUnavailable.value = true
  }
  if (tailnetResult.status === 'fulfilled' && tailnetResult.value.status === 200) {
    tailnet.value = tailnetResult.value.data.data
  } else {
    tailnetUnavailable.value = true
  }
  // A fulfilled non-2xx response is still a failed load: the generated
  // client resolves errors, it does not reject them.
  const ok = (result: PromiseSettledResult<{ status: number }>): boolean =>
    result.status === 'fulfilled' && result.value.status === 200
  if (results.every((result) => !ok(result as PromiseSettledResult<{ status: number }>))) {
    failed.value = true
    failure.value = 'every settings source refused the request'
  }
  loaded.value = true
}

void load()
</script>

<template>
  <div class="flex items-end justify-between">
    <div>
      <p class="fc-kicker">
        controller configuration
      </p>
      <h1 class="fc-h1 mt-1">
        <span class="fc-grad-text">Settings</span>
      </h1>
    </div>
  </div>

  <div class="mt-6 grid gap-6 lg:grid-cols-[200px_1fr]">
    <nav aria-label="Settings sections">
      <div
        v-for="group in SETTINGS_SECTION_GROUPS"
        :key="group.label ?? 'root'"
        class="mb-4"
      >
        <p
          v-if="group.label"
          class="mb-1 px-2 text-xs font-semibold uppercase tracking-wide text-fc-muted"
        >
          {{ group.label }}
        </p>
        <ul>
          <li
            v-for="item in group.sections"
            :key="item.id"
          >
            <button
              type="button"
              class="block w-full rounded-sm px-2 py-1.5 text-left text-sm"
              :class="
                section === item.id
                  ? 'bg-card font-medium text-foreground shadow-[inset_2px_0_0_var(--fc-g1)]'
                  : 'text-fc-muted hover:text-foreground'
              "
              :aria-current="section === item.id ? 'page' : undefined"
              @click="selectSection(item.id)"
            >
              {{ item.title }}
            </button>
          </li>
        </ul>
      </div>
    </nav>

    <div>
      <SettingsLoading
        v-if="!loaded && !failed"
        :failure="failure"
      />
      <SettingsLoading
        v-else-if="failed"
        :failure="failure"
      />

      <template v-else>
        <SecuritySection
          v-if="section === 'security'"
          :system="system"
        />
        <IntegrationsSection
          v-else-if="section === 'integrations'"
          :proxmox-accounts="proxmoxAccounts"
          :proxmox-unavailable="proxmoxUnavailable"
          :tailnet="tailnet"
          :tailnet-unavailable="tailnetUnavailable"
        />
        <FleetdSection
          v-else-if="section === 'fleetd'"
          :machines="machines"
        />
        <DiagnosticsSection
          v-else-if="section === 'diagnostics'"
          :system="system"
          :meta="meta"
        />
        <GapSection
          v-else-if="gap"
          :title="gap.title"
          :detail="gap.detail"
        />
      </template>
    </div>
  </div>
</template>
