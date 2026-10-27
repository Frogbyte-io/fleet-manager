<script setup lang="ts">
import { useQuery } from '@tanstack/vue-query'
import { ref } from 'vue'

import { listPersistentGuests, type PersistentGuestDto } from '@frogbyte-io/fleet-api-client'
import { Skeleton } from '@/components/ui/skeleton'

import { errorMessage, unwrap } from '../../machine/api'
import CreatePersistentDialog from './CreatePersistentDialog.vue'

// Persistent guests: VMs Fleet keeps and Lab never selects. The list is the
// marker table, the same data `fleetctl machines persistent list` prints.
const createOpen = ref(false)

const guests = useQuery({
  queryKey: ['fleet', 'persistent', 'guests'],
  queryFn: async () => unwrap<PersistentGuestDto[]>(await listPersistentGuests()),
})

function sourceOf(guest: PersistentGuestDto): string {
  return guest.imageVersionId === 'registered' ? 'registered' : 'from image'
}
</script>

<template>
  <section data-testid="section-persistent">
    <div class="border-b-2 border-fc-line pb-1">
      <h2 class="font-head text-sm font-bold uppercase tracking-wide text-fc-ink">
        Persistent machines
        <span class="float-right font-mono text-[9.5px] font-normal text-fc-faint">{{ (guests.data.value ?? []).length }} KEPT</span>
      </h2>
    </div>

    <div class="mt-3 flex items-center justify-between gap-3">
      <p class="text-xs text-fc-faint">
        Long-lived VMs Fleet keeps. Lab never selects them, and destroying one is a separate confirmed act.
      </p>
      <button
        type="button"
        class="shrink-0 rounded-sm border border-input px-3 py-1.5 font-mono text-[10px] uppercase tracking-wider text-fc-muted hover:border-fc-line2 hover:text-fc-ink"
        data-testid="create-persistent"
        @click="createOpen = true"
      >
        + Create persistent machine
      </button>
    </div>

    <Skeleton
      v-if="guests.isLoading.value"
      class="mt-3 h-16 rounded-sm"
    />
    <p
      v-else-if="guests.error.value"
      class="mt-3 border-l-2 border-l-fc-err bg-fc-panel px-3 py-1.5 text-xs text-fc-muted"
      data-testid="persistent-error"
    >
      Persistent machines could not be loaded: {{ errorMessage(guests.error.value) }}
    </p>
    <p
      v-else-if="(guests.data.value ?? []).length === 0"
      class="mt-3 text-xs text-fc-faint"
      data-testid="persistent-empty"
    >
      No persistent machines yet. Create one from a promoted image, or keep an existing VM with
      <span class="font-mono">fleetctl machines persistent register</span>.
    </p>
    <div
      v-else
      class="mt-3 grid gap-3"
      style="grid-template-columns: repeat(auto-fill, minmax(290px, 1fr));"
    >
      <article
        v-for="guest in guests.data.value"
        :key="`${guest.accountId}/${guest.vmid}`"
        class="rounded-sm border border-fc-line bg-fc-panel p-3"
        data-testid="persistent-guest"
      >
        <div class="flex items-start justify-between gap-2">
          <b class="min-w-0 truncate text-[13px] text-fc-ink">{{ guest.name }}</b>
          <span
            class="shrink-0 font-mono text-[9.5px] uppercase tracking-wider"
            :class="guest.state === 'ready' ? 'text-fc-ok' : 'text-fc-warn'"
          >{{ guest.state }}</span>
        </div>
        <p class="mt-1 font-mono text-[10.5px] text-fc-faint">
          VMID {{ guest.vmid }} · {{ guest.node }} · {{ sourceOf(guest) }}
        </p>
        <p
          v-if="guest.state !== 'ready' && guest.step"
          class="mt-1 text-[11px] text-fc-muted"
        >
          Stopped at {{ guest.step }}
        </p>
        <RouterLink
          v-if="guest.machineId"
          :to="`/fleet?focus=${guest.machineId}`"
          class="mt-2 inline-block font-mono text-[10px] uppercase tracking-wider text-fc-info hover:text-fc-ink"
        >
          Open machine →
        </RouterLink>
        <p
          v-else
          class="mt-2 text-[11px] text-fc-faint"
        >
          No Fleet machine linked
        </p>
      </article>
    </div>

    <CreatePersistentDialog v-model:open="createOpen" />
  </section>
</template>
