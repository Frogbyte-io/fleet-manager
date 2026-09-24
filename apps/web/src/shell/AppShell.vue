<script setup lang="ts">
import { SidebarInset, SidebarProvider } from '@/components/ui/sidebar'
import AppSidebar from '@/shell/AppSidebar.vue'
import AppTopbar from '@/shell/AppTopbar.vue'

function skipToMain(event: MouseEvent) {
  event.preventDefault()
  document.getElementById('main')?.focus()
}
</script>

<template>
  <SidebarProvider>
    <AppSidebar />
    <SidebarInset>
      <a
        href="#main"
        class="sr-only focus:not-sr-only focus:absolute focus:z-50 focus:bg-background focus:p-2"
        @click.prevent="skipToMain"
      >
        Skip to content
      </a>
      <AppTopbar />
      <main
        id="main"
        tabindex="-1"
        class="mx-auto w-full max-w-[1320px] p-6 focus:outline-none"
      >
        <RouterView />
      </main>
    </SidebarInset>
  </SidebarProvider>
</template>
