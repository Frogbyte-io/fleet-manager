<script setup lang="ts">
import { computed } from 'vue'

import {
  BadgeDollarSign,
  Box,
  Cloud,
  FolderGit2,
  Network,
  Package,
} from '@lucide/vue'

import type { ProxmoxAccountDto, ResourceTailnetStatusDtoData } from '@frogbyte-io/fleet-api-client'

const props = defineProps<{
  proxmoxAccounts: ProxmoxAccountDto[]
  tailnet: ResourceTailnetStatusDtoData | null
}>()

const proxmoxChip = computed(() => {
  const accounts = props.proxmoxAccounts
  if (accounts.length === 0) return { text: 'not configured', class: 'bg-muted text-fc-muted' }
  const pinned = accounts.filter((account) => account.fingerprintState === 'pinned').length
  return {
    text: `${accounts.length} account${accounts.length === 1 ? '' : 's'} · ${pinned} pinned`,
    class: 'bg-fc-ok/15 text-fc-ok',
  }
})

const tailnetChip = computed(() => {
  if (!props.tailnet) return { text: 'unknown', class: 'bg-muted text-fc-muted' }
  return props.tailnet.configured
    ? { text: 'configured', class: 'bg-fc-ok/15 text-fc-ok' }
    : { text: 'not configured', class: 'bg-muted text-fc-muted' }
})

function formatCreated(at: number): string {
  return new Date(at).toISOString().slice(0, 10)
}
</script>

<template>
  <section class="rounded-sm border border-border bg-card p-6">
    <div class="flex items-baseline justify-between">
      <h2 class="text-lg font-semibold text-foreground">
        Integrations
      </h2>
      <span class="text-xs text-fc-muted">secrets are write-only</span>
    </div>

    <ul class="mt-4 space-y-3">
      <li class="flex items-center gap-4 rounded-sm border border-border p-3">
        <Box class="size-5 shrink-0 text-fc-muted" />
        <div class="min-w-0 flex-1">
          <div class="flex items-center gap-2">
            <span class="text-sm font-semibold">Proxmox VE</span>
            <span
              class="rounded-full px-2 py-0.5 text-xs"
              :class="proxmoxChip.class"
            >{{ proxmoxChip.text }}</span>
          </div>
          <p
            v-if="proxmoxAccounts.length > 0"
            class="mt-1 truncate font-mono text-xs text-fc-muted"
          >
            {{ proxmoxAccounts.map((a) => `${a.name} · ${a.host} · ${a.tokenId} · SET ${formatCreated(a.createdAt)}`).join(' | ') }}
          </p>
          <p
            v-else
            class="mt-1 text-xs text-fc-muted"
          >
            No accounts; add one on the Proxmox page.
          </p>
        </div>
      </li>

      <li class="flex items-center gap-4 rounded-sm border border-border p-3">
        <Network class="size-5 shrink-0 text-fc-muted" />
        <div class="min-w-0 flex-1">
          <div class="flex items-center gap-2">
            <span class="text-sm font-semibold">Tailscale</span>
            <span
              class="rounded-full px-2 py-0.5 text-xs"
              :class="tailnetChip.class"
            >{{ tailnetChip.text }}</span>
          </div>
          <p
            v-if="tailnet?.configured"
            class="mt-1 truncate font-mono text-xs text-fc-muted"
          >
            {{ tailnet.clientId ?? 'client id withheld' }} · scope {{ tailnet.scope }}
          </p>
          <p
            v-else
            class="mt-1 text-xs text-fc-muted"
          >
            An OAuth client with <code class="font-mono">devices:core:read</code> enables discovery.
          </p>
        </div>
      </li>

      <li class="flex items-center gap-4 rounded-sm border border-border p-3 opacity-60">
        <Package class="size-5 shrink-0 text-fc-muted" />
        <div class="min-w-0 flex-1">
          <div class="flex items-center gap-2">
            <span class="text-sm font-semibold">Packer</span>
            <span class="rounded-full bg-muted px-2 py-0.5 text-xs text-fc-muted">no probe endpoint</span>
          </div>
          <p class="mt-1 text-xs text-fc-muted">
            Operator-installed; the build pipeline reports its own versions.
          </p>
        </div>
      </li>

      <li class="flex items-center gap-4 rounded-sm border border-border p-3 opacity-60">
        <FolderGit2 class="size-5 shrink-0 text-fc-muted" />
        <div class="min-w-0 flex-1">
          <div class="flex items-center gap-2">
            <span class="text-sm font-semibold">GitHub</span>
            <span class="rounded-full bg-muted px-2 py-0.5 text-xs text-fc-muted">not configured</span>
          </div>
          <p class="mt-1 text-xs text-fc-muted">
            Project remotes clone through machine credentials.
          </p>
        </div>
      </li>

      <li class="flex items-center gap-4 rounded-sm border border-border p-3 opacity-60">
        <BadgeDollarSign class="size-5 shrink-0 text-fc-muted" />
        <div class="min-w-0 flex-1">
          <div class="flex items-center gap-2">
            <span class="text-sm font-semibold">Skills Manager · Frogenv · mise</span>
            <span class="rounded-full bg-muted px-2 py-0.5 text-xs text-fc-muted">per machine</span>
          </div>
          <p class="mt-1 text-xs text-fc-muted">
            Detection is per machine; see each machine's inventory.
          </p>
        </div>
      </li>

      <li class="flex items-center gap-4 rounded-sm border border-border p-3 opacity-60">
        <Cloud class="size-5 shrink-0 text-fc-muted" />
        <div class="min-w-0 flex-1">
          <div class="flex items-center gap-2">
            <span class="text-sm font-semibold">Docker</span>
            <span class="rounded-full bg-muted px-2 py-0.5 text-xs text-fc-muted">M5</span>
          </div>
          <p class="mt-1 text-xs text-fc-muted">
            Planned via fleetd or the SSH context.
          </p>
        </div>
      </li>
    </ul>
  </section>
</template>
