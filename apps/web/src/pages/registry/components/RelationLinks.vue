<script setup lang="ts">
import type { RegistryRelationDto } from '@frogbyte-io/fleet-api-client'
import { computed } from 'vue'
import { RouterLink } from 'vue-router'

import { targetLink } from '../registry'

// An entry's outgoing relations as links. Registry entries, machines, and
// Proxmox guests link to their page, and a Coolify resource links to the running
// service that carries its uuid (FM-1032); targets without a page stay plain text.
const props = defineProps<{ relations: RegistryRelationDto[], machineIds: ReadonlyMap<string, string> }>()

const items = computed(() => props.relations.map(r => ({ relation: r.type, link: targetLink(r.target, props.machineIds) })))
</script>

<template>
  <ul
    v-if="items.length"
    class="grid gap-1"
  >
    <li
      v-for="(item, index) in items"
      :key="index"
      class="flex flex-wrap items-baseline gap-2"
    >
      <span class="font-mono text-[10px] uppercase tracking-wider text-fc-muted">{{ item.relation }}</span>
      <span class="text-[11px] text-fc-faint">{{ item.link.classLabel }}</span>
      <RouterLink
        v-if="item.link.to"
        :to="item.link.to"
        class="break-all text-fc-info hover:underline"
        @click.stop
      >
        {{ item.link.label }}
      </RouterLink>
      <span
        v-else
        class="break-all font-mono text-[11px]"
      >{{ item.link.label }}</span>
    </li>
  </ul>
  <p
    v-else
    class="text-xs text-fc-faint"
  >
    No outgoing relations.
  </p>
</template>
