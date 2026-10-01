<script setup lang="ts">
import { PopoverContent, PopoverPortal, PopoverRoot, PopoverTrigger } from 'reka-ui'
import { computed } from 'vue'

import type { ProxmoxPrivilegesDto } from '@frogbyte-io/fleet-api-client'

import { relativeTime } from '../../fleet/inventory'
import { errorMessage } from '../../machine/api'
import CopyFleetctl from '../../machine/components/CopyFleetctl.vue'
import {
  PRIVILEGE_TIERS,
  privilegesCommand,
  privilegeTone,
  tierOf,
  tierStatus,
  TOKEN_GUIDE_URL,
} from '../proxmox'

// The account token's capability tiers (FM-604), as the API evaluated them.
// Each chip opens a popover with what is missing and where; the page never
// decides a tier itself.
const props = defineProps<{
  accountId: string
  privileges: ProxmoxPrivilegesDto | null | undefined
  loading?: boolean
  error?: unknown
}>()

const tiers = computed(() => PRIVILEGE_TIERS.map((tier) => {
  const status = tierStatus(props.privileges, tier)
  return { tier, status, tone: privilegeTone(status), missing: tierOf(props.privileges, tier)?.missing ?? [] }
}))

const toneClass: Record<string, string> = {
  ok: 'border-fc-ok/40 text-fc-ok',
  err: 'border-fc-err/40 text-fc-err',
  faint: 'border-fc-line2 text-fc-faint',
}
</script>

<template>
  <div
    class="space-y-1.5"
    data-testid="privilege-tiers"
  >
    <div class="flex flex-wrap items-center gap-1.5">
      <span class="fc-kicker mr-1">Token tiers</span>
      <PopoverRoot
        v-for="item in tiers"
        :key="item.tier"
      >
        <PopoverTrigger
          class="inline-flex items-center gap-1.5 rounded-sm border px-1.5 py-px font-mono text-[9.5px] uppercase tracking-wider focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
          :class="toneClass[item.tone]"
          :aria-label="`${item.tier} tier: ${item.status}. Show details`"
          :data-testid="`tier-${item.tier}`"
          :data-status="item.status"
        >
          <span
            v-if="item.status === 'granted'"
            class="size-1.5 rounded-full bg-fc-ok"
          />
          {{ item.tier }} · {{ item.status }}
        </PopoverTrigger>
        <PopoverPortal>
          <PopoverContent
            side="bottom"
            align="start"
            :side-offset="6"
            :collision-padding="16"
            class="z-50 w-[min(22rem,calc(100vw-32px))] space-y-2 rounded-sm border border-fc-line2 bg-popover p-3 text-xs text-popover-foreground shadow-md focus:outline-none"
            :data-testid="`tier-popover-${item.tier}`"
          >
            <p class="fc-kicker">
              {{ item.tier }} tier · {{ item.status }}
            </p>
            <template v-if="item.status === 'missing'">
              <p class="text-fc-muted">
                The token lacks these privileges (grant them on the ACL path shown):
              </p>
              <ul class="space-y-1">
                <li
                  v-for="(need, index) in item.missing"
                  :key="index"
                  class="rounded-sm border border-fc-line bg-fc-inset px-2 py-1"
                  data-testid="missing-privilege"
                >
                  <span class="font-mono text-fc-ink">{{ need.privileges.join(need.anyOf ? ' | ' : ', ') }}</span>
                  <span class="text-fc-faint"> on </span>
                  <span class="break-all font-mono text-fc-ink">{{ need.path }}</span>
                  <span
                    v-if="need.anyOf"
                    class="block text-[10px] text-fc-faint"
                  >any one of them suffices</span>
                </li>
              </ul>
            </template>
            <p
              v-else-if="item.status === 'granted'"
              class="text-fc-muted"
            >
              Every required check of this tier is granted.
            </p>
            <p
              v-else
              class="text-fc-muted"
            >
              <template v-if="privileges?.unknownReason">
                Not known: {{ privileges.unknownReason }}
              </template>
              <template v-else-if="error">
                The privilege report could not be read: {{ errorMessage(error) }}
              </template>
              <template v-else-if="loading">
                Reading the token's permissions…
              </template>
              <template v-else>
                Not known. Actions stay available; the controller decides when it runs them.
              </template>
            </p>
            <a
              :href="TOKEN_GUIDE_URL"
              target="_blank"
              rel="noopener noreferrer"
              class="inline-block text-fc-info hover:text-fc-ink"
              data-testid="token-guide"
            >Least-privilege token guide (docs/operations/proxmox-token.md) ↗</a>
            <CopyFleetctl :command="privilegesCommand(accountId)" />
          </PopoverContent>
        </PopoverPortal>
      </PopoverRoot>
    </div>
    <p
      v-if="privileges?.warnings.length"
      class="text-[11px] text-fc-warn"
      data-testid="privilege-warnings"
    >
      {{ privileges.warnings.join(' · ') }}
    </p>
    <p
      v-if="privileges"
      class="font-mono text-[10px] uppercase tracking-wide text-fc-faint"
    >
      Privileges seen {{ relativeTime(privileges.observedAt) }}
    </p>
  </div>
</template>
