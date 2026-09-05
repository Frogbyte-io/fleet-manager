<script setup lang="ts">
import MachinesPanel from './components/MachinesPanel.vue'
import OperationsPanel from './components/OperationsPanel.vue'
import SystemPanel from './components/SystemPanel.vue'
</script>

<template>
  <main class="mx-auto min-h-screen max-w-3xl bg-slate-950 px-6 py-10 text-slate-100">
    <header>
      <p class="text-sm font-semibold uppercase tracking-[0.2em] text-cyan-400">
        Fleet Manager
      </p>
      <h1 class="mt-2 text-3xl font-semibold tracking-tight">
        Controller
      </h1>
    </header>

    <div class="mt-8 space-y-6">
      <SystemPanel />
      <MachinesPanel />
      <OperationsPanel />
    </div>
  </main>
</template>
