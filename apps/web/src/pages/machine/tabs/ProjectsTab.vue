<script setup lang="ts">
import { useQuery } from '@tanstack/vue-query'
import { computed } from 'vue'
import { RouterLink } from 'vue-router'

import { listProjects, type ProjectDto } from '@frogbyte-io/fleet-api-client'

import { relativeTime } from '../../fleet/inventory'
import { errorMessage } from '../api'
import { absoluteTime } from '../facts'

// Observed checkouts on this machine, read from the projects list. Making a
// project ready on a machine is the Projects page's flow (FM-942).
const props = defineProps<{ machineId: string }>()

const PAGE_LIMIT = 200

const query = useQuery({
  queryKey: ['projects', 'all'],
  queryFn: async () => {
    const response = await listProjects({ limit: PAGE_LIMIT })
    if (response.status !== 200)
      throw new Error(`listProjects failed (${response.status})`)
    return { items: response.data.items as ProjectDto[], truncated: Boolean(response.data.page?.nextCursor) }
  },
})

const rows = computed(() =>
  (query.data.value?.items ?? []).flatMap(project =>
    project.checkouts
      .filter(checkout => checkout.machineId === props.machineId)
      .map(checkout => ({ project, checkout })),
  ),
)
</script>

<template>
  <div>
    <p
      v-if="query.isLoading.value"
      class="text-xs text-fc-faint"
    >
      Loading projects…
    </p>
    <p
      v-else-if="query.error.value"
      class="text-xs text-fc-err"
    >
      Projects unavailable: {{ errorMessage(query.error.value) }}
    </p>
    <template v-else>
      <p
        v-if="query.data.value?.truncated"
        class="mb-3 text-xs text-fc-warn"
      >
        Showing checkouts from the first {{ PAGE_LIMIT }} projects only.
      </p>
      <p
        v-if="rows.length === 0"
        class="text-sm text-fc-faint"
        data-testid="no-checkouts"
      >
        No checkouts observed on this machine. Run project discovery from the
        <RouterLink
          to="/projects"
          class="text-fc-info underline decoration-dotted"
        >
          Projects page
        </RouterLink>.
      </p>
      <table
        v-else
        class="w-full text-left text-xs"
      >
        <thead class="font-mono text-[10px] uppercase tracking-wider text-fc-faint">
          <tr>
            <th class="py-1 pr-3 font-normal">
              Project
            </th>
            <th class="py-1 pr-3 font-normal">
              Root
            </th>
            <th class="py-1 pr-3 font-normal">
              Branch
            </th>
            <th class="py-1 pr-3 font-normal">
              Worktree
            </th>
            <th class="py-1 pr-3 font-normal">
              Source
            </th>
            <th class="py-1 font-normal">
              Observed
            </th>
          </tr>
        </thead>
        <tbody class="font-mono text-fc-ink">
          <tr
            v-for="{ project, checkout } in rows"
            :key="`${project.id}:${checkout.root}`"
            class="border-t border-fc-line"
          >
            <td class="py-1.5 pr-3">
              {{ project.name }}
              <div class="text-[10px] text-fc-faint">
                {{ project.remote }}
              </div>
            </td>
            <td class="break-all py-1.5 pr-3">
              {{ checkout.root }}
            </td>
            <td class="py-1.5 pr-3">
              {{ checkout.branch ?? '—' }}
            </td>
            <td
              class="py-1.5 pr-3 uppercase"
              :class="checkout.dirty ? 'text-fc-warn' : 'text-fc-muted'"
            >
              {{ checkout.dirty === null || checkout.dirty === undefined ? 'unknown' : checkout.dirty ? 'dirty' : 'clean' }}
            </td>
            <td class="py-1.5 pr-3 text-fc-muted">
              {{ checkout.source }}
            </td>
            <td
              class="py-1.5 text-fc-muted"
              :title="absoluteTime(checkout.observedAt)"
            >
              {{ relativeTime(checkout.observedAt) }}
            </td>
          </tr>
        </tbody>
      </table>
    </template>
  </div>
</template>
