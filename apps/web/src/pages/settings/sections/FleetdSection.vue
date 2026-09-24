<script setup lang="ts">
import { computed } from 'vue'

import type { MachineDto } from '@frogbyte-io/fleet-api-client'

const props = defineProps<{
  machines: MachineDto[]
}>()

const nodes = computed(() =>
  props.machines.map((machine) => {
    const identity = machine.capabilities.find(
      (fact) => fact.namespace === 'agent' && fact.name === 'fleetd',
    )
    return {
      id: machine.id,
      name: machine.name,
      status: machine.machineStatus,
      fleetd: identity?.value ?? null,
    }
  }),
)
</script>

<template>
  <section class="rounded-sm border border-border bg-card p-6">
    <h2 class="text-lg font-semibold text-foreground">
      fleetd &amp; enrollment
    </h2>
    <p class="mt-1 text-sm text-muted-foreground">
      Enrollment tokens are minted per machine from its detail page; this section summarizes
      which machines run the node daemon.
    </p>

    <table
      v-if="nodes.length > 0"
      class="mt-4 w-full text-sm"
    >
      <thead>
        <tr class="text-left text-xs uppercase tracking-wide text-fc-muted">
          <th class="py-2 font-medium">
            Machine
          </th>
          <th class="py-2 font-medium">
            fleetd
          </th>
          <th class="py-2 font-medium">
            State
          </th>
        </tr>
      </thead>
      <tbody>
        <tr
          v-for="node in nodes"
          :key="node.id"
          class="border-t border-border"
        >
          <td class="py-2 font-mono text-foreground">
            {{ node.name }}
          </td>
          <td class="py-2 font-mono text-foreground">
            {{ node.fleetd ?? '—' }}
          </td>
          <td class="py-2">
            <span :class="node.status === 'connected' ? 'text-fc-ok' : 'text-fc-muted'">{{ node.status }}</span>
          </td>
        </tr>
      </tbody>
    </table>
    <p
      v-else
      class="mt-4 text-sm text-fc-muted"
    >
      No machines yet.
    </p>
  </section>
</template>
