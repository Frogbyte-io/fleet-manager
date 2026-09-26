<script setup lang="ts">
import { useQuery } from '@tanstack/vue-query'
import { computed, onUnmounted, ref } from 'vue'

import {
  getOperation,
  listMachines,
  listProjects,
  startReadyWorkflow,
  type MachineDto,
  type PageProjectDtoItemsItem,
  type ReadyPlanDto,
} from '@frogbyte-io/fleet-api-client'
import { isTerminal } from '../machine/api'
import ProjectsPanel from '@/components/ProjectsPanel.vue'

import {
  blockedDetail,
  buildMatrix,
  dirtyLabel,
  planLines,
} from './matrix'

// The Projects page: a project × machine checkout matrix and the
// make-ready flow with its dry-run plan. No secrets are rendered anywhere
// on this page; blocked approvals are explicit states.
const PAGE = 200
const MAX_PAGES = 10
const POLL_MS = 500
const DEADLINE_MS = 30 * 60 * 1000

/// Walks a cursor-paginated list endpoint until it is exhausted (bounded),
/// so a list larger than one page is not silently truncated.
async function listAllPages<Item>(
  fetchPage: (
    cursor?: string,
  ) => Promise<{
    status: number
    data: { items: Item[]; page: { nextCursor?: string | null }; message?: string }
  } | null>,
): Promise<{ items: Item[]; complete: boolean } | null> {
  const items: Item[] = []
  let cursor: string | undefined
  for (let page = 0; page < MAX_PAGES; page += 1) {
    const response = await fetchPage(cursor)
    if (response === null) return null
    items.push(...response.data.items)
    const next = response.data.page.nextCursor ?? null
    if (!next) return { items, complete: true }
    cursor = next
  }
  return { items, complete: false }
}

const projectsQuery = useQuery({
  queryKey: ['projects', 'matrix'],
  queryFn: async () => {
    const result = await listAllPages<PageProjectDtoItemsItem>(async (cursor) => {
      const response = await listProjects({ limit: PAGE, cursor })
      if (response.status !== 200) {
        throw new Error(
          (response.data as { message?: string })?.message ??
            `the project list failed (${response.status})`,
        )
      }
      return response
    })
    if (result === null) {
      throw new Error('the project list could not be read')
    }
    return result
  },
})

const machinesQuery = useQuery({
  queryKey: ['machines', 'matrix'],
  queryFn: async () => {
    const result = await listAllPages<MachineDto>(async (cursor) => {
      const response = await listMachines({ limit: PAGE, cursor })
      if (response.status !== 200) {
        throw new Error(
          (response.data as { message?: string })?.message ??
            `the machine list failed (${response.status})`,
        )
      }
      return response
    })
    if (result === null) {
      throw new Error('the machine list could not be read')
    }
    return result
  },
})

const projects = computed(() => projectsQuery.data.value?.items ?? [])
const machines = computed(() => machinesQuery.data.value?.items ?? [])
const machinesTruncated = computed(() => !(machinesQuery.data.value?.complete ?? true))
const matrix = computed(() => buildMatrix(projects.value, machines.value))

// The make-ready flow for one project.
const readyFor = ref<string | null>(null)
const readyForm = ref({ machineId: '', endpointId: '', root: '', auth: 'agent', identity: '' })
const plan = ref<ReadyPlanDto | null>(null)
const progress = ref<string | null>(null)
const blocked = ref<string | null>(null)
const failed = ref<string | null>(null)
const busy = ref(false)
// Polling must not outlive the page: a navigation away stops the loop.
let disposed = false
onUnmounted(() => {
  disposed = true
})

function openReady(projectId: string): void {
  readyFor.value = projectId
  readyForm.value = { machineId: '', endpointId: '', root: '', auth: 'agent', identity: '' }
  plan.value = null
  progress.value = null
  blocked.value = null
  failed.value = null
}

function closeReady(): void {
  readyFor.value = null
}

function prefill(machineId: string): void {
  const project = readyFor.value
  if (!project) return
  const checkout = projects.value
    .find((candidate) => candidate.id === project)
    ?.checkouts.find((candidate) => candidate.machineId === machineId)
  readyForm.value.machineId = machineId
  readyForm.value.root = checkout?.root ?? ''
  readyForm.value.endpointId = ''
}

async function runReady(dryRun: boolean): Promise<void> {
  const projectId = readyFor.value
  if (!projectId) return
  busy.value = true
  plan.value = null
  progress.value = null
  blocked.value = null
  failed.value = null
  try {
    const auth =
      readyForm.value.auth === 'identityFile'
        ? { type: 'identityFile' as const, path: readyForm.value.identity }
        : { type: 'agent' as const }
    const response = await startReadyWorkflow(projectId, {
      machineId: readyForm.value.machineId,
      endpointId: readyForm.value.endpointId,
      auth,
      root: readyForm.value.root,
      dryRun,
    })
    if (response.status === 200) {
      plan.value = (response.data as { data: ReadyPlanDto }).data
    } else if (response.status === 202) {
      const operation = (response.data as { data?: { id?: string } }).data
      progress.value = `workflow ${operation?.id ?? ''} accepted`
      const deadline = Date.now() + DEADLINE_MS
      for (;;) {
        if (disposed) return
        await new Promise((resolve) => setTimeout(resolve, POLL_MS))
        if (disposed) return
        const detail = await getOperation(operation?.id ?? '')
        if (detail.status !== 200) {
          failed.value =
            (detail.data as { message?: string })?.message ??
            `the controller answered ${detail.status}`
          break
        }
        const state = (detail.data as { data?: { state?: string; errorJson?: string | null } }).data
        progress.value = `workflow state: ${state?.state ?? 'unknown'}`
        if (state?.state === 'blocked_manual_approval') {
          // A blocked approval is a state with a reason, not an error.
          blocked.value = blockedDetail(state?.errorJson) ?? 'waiting for a human to approve'
          break
        }
        // Only the four settled states end the wait; blocked is handled
        // above, and a state this client has not heard of keeps polling.
        if (state?.state && isTerminal(state.state)) {
          if (state.state !== 'succeeded') {
            failed.value =
              blockedDetail(state?.errorJson) ?? `the workflow ended: ${state.state}`
          }
          break
        }
        if (Date.now() > deadline) {
          failed.value =
            'the workflow did not reach a terminal state within 30 minutes; it is still durable — check the operation record'
          break
        }
      }
    } else {
      failed.value =
        (response.data as { message?: string })?.message ??
        `the controller answered ${response.status}`
    }
  } catch (error) {
    failed.value = error instanceof Error ? error.message : String(error)
  } finally {
    busy.value = false
  }
}

const lines = computed(() => (plan.value ? planLines(plan.value) : []))
</script>

<template>
  <div class="flex items-end justify-between">
    <div>
      <p class="fc-kicker">
        checkouts and readiness
      </p>
      <h1 class="fc-h1 mt-1">
        <span class="fc-grad-text">Projects</span>
      </h1>
    </div>
  </div>

  <p
    v-if="projectsQuery.isLoading.value || machinesQuery.isLoading.value"
    class="mt-6 text-sm text-fc-faint"
    role="status"
    aria-busy="true"
  >
    Loading projects…
  </p>
  <template v-else>
    <p
      v-if="projectsQuery.error.value || machinesQuery.error.value"
      class="mt-6 text-sm text-fc-err"
      role="alert"
    >
      {{
        (projectsQuery.error.value ?? machinesQuery.error.value) instanceof Error
          ? (projectsQuery.error.value ?? machinesQuery.error.value)!.message
          : 'the controller did not answer'
      }}
    </p>

    <div
      v-else
      class="mt-6 overflow-x-auto"
      data-testid="project-matrix"
    >
      <table
        v-if="matrix.length > 0 && machines.length > 0"
        class="w-full text-left text-sm"
      >
        <thead class="text-xs uppercase tracking-wide text-fc-muted">
          <tr>
            <th class="py-2 pr-4 font-medium">
              Project
            </th>
            <th
              v-for="machine in machines"
              :key="machine.id"
              class="py-2 pr-4 font-medium"
            >
              {{ machine.name }}
            </th>
          </tr>
        </thead>
        <tbody class="font-mono">
          <tr
            v-for="row in matrix"
            :key="row.projectId"
            class="border-t border-border"
            data-testid="matrix-row"
          >
            <td class="py-2 pr-4 text-foreground">
              {{ row.projectName }}
            </td>
            <td
              v-for="cell in row.cells"
              :key="cell.machineId"
              class="py-2 pr-4"
            >
              <template v-if="cell.observedAt !== null">
                <span class="text-foreground">{{ cell.branch ?? '–' }}</span>
                <span
                  class="ml-2 text-xs"
                  :class="cell.dirty ? 'text-fc-warn' : 'text-fc-muted'"
                >{{ dirtyLabel(cell.dirty) }}</span>
              </template>
              <span
                v-else
                class="text-fc-faint"
              >no checkout</span>
            </td>
          </tr>
        </tbody>
      </table>
      <p
        v-if="projects.length === 0"
        class="text-sm text-fc-faint"
      >
        No projects registered yet.
      </p>
      <p
        v-else-if="machines.length === 0"
        class="text-sm text-fc-faint"
      >
        No machines registered yet; add one on the Fleet page to see checkouts.
      </p>
      <p
        v-else-if="machinesTruncated"
        class="text-xs text-fc-warn"
      >
        The machine list stopped at the pagination bound; some machines may be missing from the matrix.
      </p>
    </div>

    <!-- Registration and removal stay on this page until a dedicated
         project admin surface exists. -->
    <ProjectsPanel class="mt-8" />

    <!-- Make ready: pick a project, inspect the dry-run plan, execute. -->
    <section class="mt-8 rounded-sm border border-border bg-card p-6">
      <h2 class="text-lg font-semibold text-foreground">
        Make ready
      </h2>

      <div
        v-if="!readyFor"
        class="mt-3 flex flex-wrap gap-2"
      >
        <button
          v-for="project in projects"
          :key="project.id"
          type="button"
          class="rounded-sm border border-border px-3 py-1.5 text-sm text-foreground hover:border-fc-muted"
          :data-testid="`ready-for-${project.name}`"
          @click="openReady(project.id)"
        >
          Make ready on… {{ project.name }}
        </button>
        <p
          v-if="projects.length === 0"
          class="text-sm text-fc-faint"
        >
          Register a project first.
        </p>
      </div>

      <div
        v-else
        class="mt-3"
      >
        <div class="flex items-center justify-between">
          <p class="text-sm text-foreground">
            {{ projects.find((project) => project.id === readyFor)?.name }}
          </p>
          <button
            type="button"
            class="text-xs text-fc-muted hover:text-foreground"
            @click="closeReady"
          >
            Cancel
          </button>
        </div>

        <!-- A machine with a checkout of this project can be picked
             straight from the matrix; any machine id remains typeable. -->
        <div class="mt-3 flex flex-wrap gap-2">
          <button
            v-for="cell in matrix.find((row) => row.projectId === readyFor)?.cells.filter((cell) => cell.observedAt !== null) ?? []"
            :key="cell.machineId"
            type="button"
            class="rounded-sm border border-border px-2 py-1 font-mono text-xs text-foreground hover:border-fc-muted"
            @click="prefill(cell.machineId)"
          >
            {{ cell.machineName }} @ {{ cell.branch ?? '?' }}
          </button>
        </div>

        <div class="mt-3 grid grid-cols-2 gap-3 text-sm md:grid-cols-3">
          <input
            v-model="readyForm.machineId"
            placeholder="machine id"
            class="rounded-sm border border-input bg-background px-3 py-2 font-mono text-foreground"
            data-testid="ready-machine"
          >
          <input
            v-model="readyForm.endpointId"
            placeholder="endpoint id"
            class="rounded-sm border border-input bg-background px-3 py-2 font-mono text-foreground"
            data-testid="ready-endpoint"
          >
          <input
            v-model="readyForm.root"
            placeholder="checkout root"
            class="rounded-sm border border-input bg-background px-3 py-2 font-mono text-foreground"
            data-testid="ready-root"
          >
          <select
            v-model="readyForm.auth"
            class="rounded-sm border border-input bg-background px-3 py-2 text-foreground"
          >
            <option value="agent">
              agent auth
            </option>
            <option value="identityFile">
              identity file
            </option>
          </select>
          <input
            v-if="readyForm.auth === 'identityFile'"
            v-model="readyForm.identity"
            placeholder="identity path"
            class="rounded-sm border border-input bg-background px-3 py-2 font-mono text-foreground"
          >
        </div>

        <div class="mt-3 flex items-center gap-2">
          <button
            type="button"
            class="rounded-sm border border-fc-info/40 bg-fc-info/10 px-3 py-1.5 text-sm text-fc-info hover:bg-fc-info/20 disabled:opacity-50"
            :disabled="busy || readyForm.machineId === '' || readyForm.endpointId === '' || readyForm.root === '' || (readyForm.auth === 'identityFile' && readyForm.identity === '')"
            data-testid="ready-plan"
            @click="runReady(true)"
          >
            Plan (dry run)
          </button>
          <button
            type="button"
            class="rounded-sm border border-fc-ok/40 bg-fc-ok/10 px-3 py-1.5 text-sm text-fc-ok hover:bg-fc-ok/20 disabled:opacity-50"
            :disabled="busy || readyForm.machineId === '' || readyForm.endpointId === '' || readyForm.root === '' || (readyForm.auth === 'identityFile' && readyForm.identity === '')"
            data-testid="ready-execute"
            @click="runReady(false)"
          >
            Execute
          </button>
        </div>

        <!-- The dry-run plan, in execution order, human-readable. -->
        <div
          v-if="plan"
          class="mt-4 rounded-sm border border-border bg-inset p-3"
          data-testid="ready-plan-view"
        >
          <p class="text-xs font-semibold uppercase tracking-wide text-fc-muted">
            Plan (dry run)
          </p>
          <ol class="mt-2 list-decimal space-y-1 pl-5 font-mono text-xs text-foreground">
            <li
              v-for="line in lines"
              :key="line"
            >
              {{ line }}
            </li>
          </ol>
        </div>

        <p
          v-if="blocked"
          class="mt-4 border-l-2 border-fc-warn bg-fc-warn/10 p-3 text-sm text-fc-warn"
          role="alert"
          data-testid="ready-blocked"
        >
          Blocked — manual approval required: {{ blocked }}
        </p>
        <p
          v-if="progress"
          class="mt-4 text-sm text-fc-muted"
          data-testid="ready-progress"
        >
          {{ progress }}
        </p>
        <p
          v-if="failed"
          class="mt-4 text-sm text-fc-err"
          role="alert"
        >
          {{ failed }}
        </p>
      </div>
    </section>
  </template>
</template>
