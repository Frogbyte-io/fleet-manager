<script setup lang="ts">
import type { RunningServiceDto } from '@frogbyte-io/fleet-api-client'
import { RouterLink } from 'vue-router'

import StatusChip from '@/components/fleet/StatusChip.vue'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'

import { deployView, detailPath, placementView, projectLabel, serverLabel, sourceLabel, statusView, type ServiceGroup } from '../services'

defineProps<{ groups: ServiceGroup[] }>()

const headClass = 'font-mono text-[10px] uppercase font-semibold text-fc-faint [letter-spacing:.14em]'
</script>

<template>
  <Table>
    <TableHeader>
      <TableRow class="border-fc-line hover:bg-transparent">
        <TableHead :class="headClass">
          Name
        </TableHead>
        <TableHead :class="headClass">
          Status
        </TableHead>
        <TableHead
          :class="headClass"
          class="hidden md:table-cell"
        >
          Source
        </TableHead>
        <TableHead :class="headClass">
          Server
        </TableHead>
        <TableHead
          :class="headClass"
          class="hidden lg:table-cell"
        >
          Project
        </TableHead>
        <TableHead
          :class="headClass"
          class="hidden md:table-cell"
        >
          Machine
        </TableHead>
        <TableHead
          :class="headClass"
          class="hidden xl:table-cell"
        >
          Hostnames
        </TableHead>
        <TableHead
          :class="headClass"
          class="hidden lg:table-cell"
        >
          Last deploy
        </TableHead>
      </TableRow>
    </TableHeader>
    <TableBody>
      <template
        v-for="group in groups"
        :key="group.key || '_all'"
      >
        <TableRow
          v-if="group.name"
          class="border-fc-line bg-fc-inset hover:bg-fc-inset"
          data-testid="table-group"
        >
          <TableCell
            colspan="8"
            class="fc-kicker py-1.5"
          >
            {{ group.name }} · {{ group.services.length }}
          </TableCell>
        </TableRow>
        <TableRow
          v-for="service in group.services as RunningServiceDto[]"
          :key="service.id"
          class="border-fc-line"
          data-testid="service-row"
        >
          <TableCell class="max-w-56">
            <RouterLink
              :to="detailPath(service.id)"
              class="block truncate font-semibold text-fc-ink hover:underline"
              data-testid="open-service"
            >
              {{ service.name }}
            </RouterLink>
            <span class="fc-kicker block truncate">{{ service.kind }}</span>
          </TableCell>
          <TableCell>
            <StatusChip
              :label="statusView(service).label"
              :tone="statusView(service).tone"
              data-testid="service-status"
            />
          </TableCell>
          <TableCell class="hidden text-xs text-fc-muted md:table-cell">
            {{ sourceLabel(service) }}
          </TableCell>
          <TableCell class="text-xs text-fc-muted">
            {{ serverLabel(service) }}
          </TableCell>
          <TableCell class="hidden text-xs text-fc-muted lg:table-cell">
            {{ projectLabel(service) }}
          </TableCell>
          <TableCell
            class="hidden text-xs md:table-cell"
            :class="placementView(service).state === 'ambiguous' ? 'text-fc-warn' : 'text-fc-muted'"
          >
            {{ placementView(service).label }}
          </TableCell>
          <TableCell class="hidden max-w-56 truncate font-mono text-[11px] text-fc-muted xl:table-cell">
            {{ service.fqdns.join(', ') || '—' }}
          </TableCell>
          <TableCell class="hidden lg:table-cell">
            <StatusChip
              v-if="deployView(service)"
              :label="deployView(service)!.label"
              :tone="deployView(service)!.tone"
            />
            <span
              v-else
              class="text-xs text-fc-faint"
            >—</span>
          </TableCell>
        </TableRow>
      </template>
    </TableBody>
  </Table>
</template>
