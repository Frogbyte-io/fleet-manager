<script setup lang="ts">
import { formatBytes } from '../../fleet/inventory'
import { ratio, type StorageRow, type TemplateRow } from '../proxmox'
import UsageBar from './UsageBar.vue'

// Storage pools and templates: what a clone or Lab lease can land on.
defineProps<{ storage: StorageRow[], templates: TemplateRow[] }>()
</script>

<template>
  <div class="mt-4 grid gap-6 lg:grid-cols-2">
    <section>
      <h2 class="fc-kicker border-b-2 border-fc-ink pb-1">
        Storage <span class="text-fc-faint">{{ storage.length }}</span>
      </h2>
      <p
        v-if="storage.length === 0"
        class="mt-2 text-xs text-fc-muted"
      >
        No storage discovered.
      </p>
      <table
        v-else
        class="mt-2 w-full text-xs"
        data-testid="storage-table"
      >
        <thead>
          <tr class="text-left">
            <th class="fc-kicker py-1 font-normal">
              Storage
            </th>
            <th class="fc-kicker py-1 font-normal">
              Node
            </th>
            <th class="fc-kicker w-1/2 py-1 font-normal">
              Usage
            </th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="row in storage"
            :key="`${row.accountId}/${row.node}/${row.storage}`"
            class="border-t border-fc-line"
          >
            <td class="py-1.5 font-mono text-fc-ink">
              {{ row.storage }}
              <span
                v-if="row.status && row.status !== 'available'"
                class="ml-1 text-fc-warn"
              >{{ row.status }}</span>
            </td>
            <td class="py-1.5 font-mono text-fc-muted">
              {{ row.node ?? 'shared' }}
            </td>
            <td class="py-1.5">
              <UsageBar
                v-if="row.totalBytes !== null"
                :label="row.storage"
                :value="ratio(row.usedBytes, row.totalBytes)"
                :detail="`${formatBytes(row.usedBytes)} / ${formatBytes(row.totalBytes)}`"
              />
              <span
                v-else
                class="font-mono text-[10.5px] text-fc-faint"
              >no capacity reported</span>
            </td>
          </tr>
        </tbody>
      </table>
    </section>

    <section>
      <h2 class="fc-kicker border-b-2 border-fc-ink pb-1">
        Templates <span class="text-fc-faint">{{ templates.length }}</span>
      </h2>
      <p
        v-if="templates.length === 0"
        class="mt-2 text-xs text-fc-muted"
      >
        No templates. Promoted images become templates through the Images pipeline.
      </p>
      <ul
        v-else
        class="mt-2 divide-y divide-fc-line text-xs"
        data-testid="templates-list"
      >
        <li
          v-for="row in templates"
          :key="`${row.accountId}/${row.id}`"
          class="flex flex-wrap items-center gap-2 py-1.5"
        >
          <span class="font-mono text-fc-faint">{{ row.vmid ?? '—' }}</span>
          <span class="text-fc-ink">{{ row.name }}</span>
          <span class="ml-auto font-mono text-[10px] text-fc-faint">{{ row.node ?? '—' }} · {{ row.accountName }}</span>
        </li>
      </ul>
    </section>
  </div>
</template>
