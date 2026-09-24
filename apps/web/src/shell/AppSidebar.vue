<script setup lang="ts">
import { useQuery } from '@tanstack/vue-query'
import { computed, watch } from 'vue'
import { useRoute } from 'vue-router'

import { getSystemInfo } from '@frogbyte-io/fleet-api-client'
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuBadge,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarRail,
  useSidebar,
} from '@/components/ui/sidebar'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { NAV_GROUPS } from '@/shell/nav'

const route = useRoute()
const { setOpenMobile } = useSidebar()

watch(() => route.fullPath, () => setOpenMobile(false))

const query = useQuery({
  queryKey: ['system'],
  queryFn: () => getSystemInfo(),
  retry: 1,
})

const serviceName = computed(() => {
  if (query.error.value) return 'CONTROLLER'
  return query.data.value?.status === 200 ? query.data.value.data.service : 'CONTROLLER'
})

const ready = computed(() => query.isSuccess.value && query.data.value?.status === 200 && query.data.value.data.storageOk === true)
const degraded = computed(() => query.isSuccess.value && query.data.value?.status === 200 && query.data.value.data.storageOk !== true)
const version = computed(() => (query.data.value?.status === 200 ? query.data.value.data.version : null))

const readinessLabel = computed(() => (ready.value ? 'READY' : degraded.value ? 'DEGRADED' : 'UNREACHABLE'))
const readinessDotClass = computed(() => (ready.value ? 'bg-fc-ok' : degraded.value ? 'bg-fc-warn' : 'bg-fc-err'))
const readinessTextClass = computed(() => (ready.value ? 'text-fc-ok' : degraded.value ? 'text-fc-warn' : 'text-fc-err'))

function isActive(to: string) {
  return to === '/' ? route.path === '/' : route.path.startsWith(to)
}
</script>

<template>
  <Sidebar collapsible="icon">
    <SidebarHeader>
      <div class="flex items-center gap-2 px-2 py-1.5">
        <div class="fc-grad-bg flex size-[26px] shrink-0 items-center justify-center rounded-sm font-head text-sm font-extrabold">
          F
        </div>
        <div class="min-w-0 group-data-[collapsible=icon]:hidden">
          <div class="font-head text-sm font-extrabold text-foreground">
            Fleet Console
          </div>
          <div class="truncate font-mono text-[10px] text-fc-faint">
            {{ serviceName }}
          </div>
        </div>
      </div>
    </SidebarHeader>

    <SidebarContent>
      <SidebarGroup
        v-for="group in NAV_GROUPS"
        :key="group.label ?? 'overview'"
      >
        <SidebarGroupLabel
          v-if="group.label"
          class="font-mono text-[10px] uppercase tracking-widest"
        >
          {{ group.label }}
        </SidebarGroupLabel>
        <SidebarGroupContent>
          <SidebarMenu>
            <SidebarMenuItem
              v-for="item in group.items"
              :key="item.to"
            >
              <SidebarMenuButton
                as-child
                :is-active="isActive(item.to)"
                :class="item.available ? '' : 'opacity-50'"
                :style="isActive(item.to) ? { boxShadow: 'inset 2px 0 0 var(--fc-g1)' } : undefined"
              >
                <RouterLink :to="item.to">
                  <component :is="item.icon" />
                  <span :class="isActive(item.to) ? 'fc-grad-text' : ''">{{ item.title }}</span>
                </RouterLink>
              </SidebarMenuButton>
              <SidebarMenuBadge
                v-if="!item.available"
                class="font-mono text-[9px] tracking-widest"
              >
                SOON
              </SidebarMenuBadge>
            </SidebarMenuItem>
          </SidebarMenu>
        </SidebarGroupContent>
      </SidebarGroup>
    </SidebarContent>

    <SidebarFooter>
      <div class="flex items-center gap-2 px-2 py-1.5">
        <span
          class="size-2 shrink-0 rounded-full"
          :class="readinessDotClass"
          aria-hidden="true"
        />
        <span
          class="min-w-0 truncate font-mono text-[10px] group-data-[collapsible=icon]:hidden"
          :class="readinessTextClass"
        >{{ readinessLabel }}</span>
        <span
          v-if="version"
          class="min-w-0 truncate font-mono text-[10px] text-fc-muted group-data-[collapsible=icon]:hidden"
        >· v{{ version }}</span>
      </div>
      <Tooltip>
        <TooltipTrigger as-child>
          <div class="cursor-default px-2 pb-2 font-mono text-[10px] text-fc-faint group-data-[collapsible=icon]:hidden">
            TRUSTED LAN
          </div>
        </TooltipTrigger>
        <TooltipContent side="top">
          Every client that can reach this controller can read and mutate. Actions are audited as
          anonymous-lan-admin.
        </TooltipContent>
      </Tooltip>
    </SidebarFooter>

    <SidebarRail />
  </Sidebar>
</template>
