<script setup lang="ts">
import { SidebarInset, SidebarProvider } from '@/components/ui/sidebar'
import AppSidebar from '@/shell/AppSidebar.vue'
import AppTopbar from '@/shell/AppTopbar.vue'
</script>

<template>
  <SidebarProvider default-open>
    <AppSidebar />
    <SidebarInset>
      <a
        href="#main"
        class="sr-only focus:not-sr-only focus:absolute focus:z-50 focus:bg-background focus:p-2"
      >
        Skip to content
      </a>
      <AppTopbar />
      <main
        id="main"
        class="mx-auto w-full max-w-[1320px] p-6"
      >
        <RouterView />
      </main>
    </SidebarInset>
  </SidebarProvider>
</template>
