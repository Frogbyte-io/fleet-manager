<script setup lang="ts">
import { Moon, Search, Sun } from '@lucide/vue'
import { computed } from 'vue'
import { RouterLink, useRoute } from 'vue-router'

import { Breadcrumb, BreadcrumbItem, BreadcrumbList, BreadcrumbPage, BreadcrumbSeparator } from '@/components/ui/breadcrumb'
import { SidebarTrigger } from '@/components/ui/sidebar'
import { useTheme } from '@/shell/theme'

const route = useRoute()
const { theme, toggle } = useTheme()

const group = computed(() => (route.meta.group as string | undefined) ?? null)
const title = computed(() => (route.meta.title as string | undefined) ?? '')
const isLight = computed(() => theme.value === 'light')
</script>

<template>
  <header
    class="sticky top-0 z-10 flex h-14 shrink-0 items-center gap-2 border-b border-border bg-background px-4"
  >
    <SidebarTrigger />
    <Breadcrumb>
      <BreadcrumbList>
        <template v-if="group">
          <BreadcrumbItem>
            <span class="font-mono text-xs uppercase tracking-widest text-fc-faint">{{ group }}</span>
          </BreadcrumbItem>
          <BreadcrumbSeparator />
        </template>
        <BreadcrumbItem>
          <BreadcrumbPage class="text-sm">
            {{ title }}
          </BreadcrumbPage>
        </BreadcrumbItem>
      </BreadcrumbList>
    </Breadcrumb>

    <div class="ml-auto flex items-center gap-2">
      <button
        type="button"
        aria-disabled="true"
        class="flex h-9 w-56 items-center gap-2 rounded-sm border border-input bg-inset px-3 text-sm text-fc-faint"
      >
        <Search class="size-4" />
        <span class="flex-1 text-left">Search…</span>
        <kbd class="font-mono text-[10px] text-fc-faint">⌘K</kbd>
      </button>

      <button
        type="button"
        aria-label="Toggle theme"
        :aria-pressed="isLight"
        class="flex size-9 items-center justify-center rounded-sm border border-input text-fc-muted hover:text-foreground"
        @click="toggle"
      >
        <Sun
          v-if="isLight"
          class="size-4"
        />
        <Moon
          v-else
          class="size-4"
        />
      </button>

      <RouterLink
        to="/fleet/add"
        class="fc-grad-bg inline-flex h-9 items-center rounded-sm px-4 text-sm font-medium"
      >
        + Add
      </RouterLink>
    </div>
  </header>
</template>
