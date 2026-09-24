<script setup lang="ts">
import { onBeforeUnmount, onMounted, ref } from 'vue'

import {
  createProject,
  deleteProject,
  getOperation,
  getProject,
  listProjects,
  startReadyWorkflow,
  type PageProjectDtoItemsItem,
  type ReadyAuthDto,
  type ResourceProjectDtoData,
} from '@frogbyte-io/fleet-api-client'

type Project = PageProjectDtoItemsItem
type ProjectDetail = ResourceProjectDtoData

const projects = ref<readonly Project[]>([])
const failed = ref(false)
const failure = ref('')
const selected = ref<ProjectDetail | null>(null)
const form = ref({ remote: '', name: '', description: '' })
const busy = ref(false)
// The ready workflow's inputs and its live progress.
const readyForm = ref({
  machineId: '',
  endpointId: '',
  root: '',
  dryRun: false,
  auth: 'agent',
  identity: '',
})
const readyPlan = ref<string | null>(null)
const readyProgress = ref<string | null>(null)

async function load() {
  try {
    const response = await listProjects({ limit: 50 })
    if (response.status === 200) {
      projects.value = response.data.items
      failed.value = false
    } else {
      // A refused or failed request must say why, not look like an empty
      // list.
      failed.value = true
      failure.value =
        (response.data as { message?: string })?.message ??
        `the controller answered ${response.status}`
    }
  } catch (error) {
    failed.value = true
    failure.value = error instanceof Error ? error.message : String(error)
  }
}

async function open(project: Project) {
  const response = await getProject(project.id)
  if (response.status === 200) {
    selected.value = response.data.data
    // The ready form and its status belong to the selected project: a
    // selection change must not show the previous project's plan or
    // progress.
    readyForm.value = {
      machineId: '',
      endpointId: '',
      root: '',
      dryRun: false,
      auth: 'agent',
      identity: '',
    }
    readyPlan.value = null
    readyProgress.value = null
  }
}

async function close() {
  selected.value = null
}

async function create() {
  busy.value = true
  try {
    const response = await createProject({
      remote: form.value.remote,
      name: form.value.name,
      description: form.value.description,
    })
    if (response.status === 201) {
      form.value = { remote: '', name: '', description: '' }
      await load()
      await open(response.data.data)
    } else {
      // A conflict (the same remote under another spelling) or a refusal
      // must explain itself.
      failed.value = true
      failure.value =
        (response.data as { message?: string })?.message ??
        `the controller answered ${response.status}`
    }
  } finally {
    busy.value = false
  }
}

// Asks Fleet to make the selected project ready on a machine. A dry run
// shows the plan first; a real run reports progress until it reaches a
// terminal state, and a blocked Frogenv approval is a state, not an
// error.
async function makeReady() {
  if (!selected.value) return
  busy.value = true
  readyPlan.value = null
  readyProgress.value = null
  try {
    const auth: ReadyAuthDto =
      readyForm.value.auth === 'identity-file'
        ? { type: 'identityFile', path: readyForm.value.identity }
        : { type: 'agent' }
    const response = await startReadyWorkflow(selected.value.id, {
      machineId: readyForm.value.machineId,
      endpointId: readyForm.value.endpointId,
      auth,
      root: readyForm.value.root,
      dryRun: readyForm.value.dryRun,
    })
    if (response.status === 200) {
      readyPlan.value = JSON.stringify(response.data.data, null, 2)
    } else if (response.status === 202) {
      const operation = (
        response.data as { data?: { id?: string; state?: string } }
      ).data
      readyProgress.value = `workflow ${operation?.id ?? ''} accepted`
      // Poll until terminal or the deadline: an exhausted deadline is a
      // failure, not a silent stop, and the operation stays trackable via
      // `fleetctl operations get`.
      const deadline = Date.now() + 30 * 60 * 1000
      for (;;) {
        await new Promise((resolve) => setTimeout(resolve, 500))
        const detail = await getOperation(operation?.id ?? '')
        if (detail.status !== 200) {
          failed.value = true
          failure.value =
            (detail.data as { message?: string })?.message ??
            `the controller answered ${detail.status}`
          break
        }
        const state = (detail.data as { data?: { state?: string } }).data
          ?.state
        readyProgress.value = `workflow state: ${state ?? 'unknown'}`
        if (state && !['pending', 'running', 'cancelling'].includes(state)) {
          break
        }
        if (Date.now() > deadline) {
          failed.value = true
          failure.value = `the workflow did not reach a terminal state within 30 minutes; it is still durable — check the operation record`
          break
        }
      }
    } else {
      failed.value = true
      failure.value =
        (response.data as { message?: string })?.message ??
        `the controller answered ${response.status}`
    }
  } catch (error) {
    failed.value = true
    failure.value = error instanceof Error ? error.message : String(error)
  } finally {
    busy.value = false
  }
}

async function remove() {
  if (!selected.value) return
  busy.value = true
  try {
    const response = await deleteProject(selected.value.id)
    if (response.status === 204) {
      selected.value = null
      await load()
    }
  } finally {
    busy.value = false
  }
}

onMounted(() => {
  load()
  const refresh = setInterval(load, 5000)
  onBeforeUnmount(() => clearInterval(refresh))
})
</script>

<template>
  <section class="rounded-sm border border-border bg-card p-6">
    <div class="flex items-center justify-between">
      <h2 class="text-lg font-semibold text-foreground">
        Projects
      </h2>
      <button
        class="rounded-sm border border-input px-3 py-1 text-xs text-foreground hover:border-fc-muted"
        @click="load"
      >
        Refresh
      </button>
    </div>

    <p
      v-if="failed"
      class="mt-4 text-sm text-fc-err"
    >
      {{ failure }}
    </p>

    <div class="mt-4 grid grid-cols-2 gap-3 text-sm">
      <input
        v-model="form.remote"
        placeholder="git remote (any spelling)"
        class="rounded-sm border border-input bg-background px-3 py-2 font-mono text-foreground"
      >
      <input
        v-model="form.name"
        placeholder="display name"
        class="rounded-sm border border-input bg-background px-3 py-2 text-foreground"
      >
      <input
        v-model="form.description"
        placeholder="description (optional)"
        class="col-span-2 rounded-sm border border-input bg-background px-3 py-2 text-foreground"
      >
      <button
        class="col-span-2 rounded-sm border border-fc-info/40 bg-fc-info/10 px-3 py-2 text-sm text-fc-info hover:bg-fc-info/20 disabled:opacity-50"
        :disabled="busy || form.remote === '' || form.name === ''"
        @click="create"
      >
        Register project
      </button>
    </div>

    <table
      v-if="projects.length > 0"
      class="mt-4 w-full text-left text-sm"
    >
      <thead class="text-xs uppercase tracking-wide text-muted-foreground">
        <tr>
          <th class="py-2">
            Name
          </th>
          <th class="py-2">
            Remote
          </th>
        </tr>
      </thead>
      <tbody class="font-mono text-foreground">
        <tr
          v-for="project in projects"
          :key="project.id"
          class="cursor-pointer border-t border-border hover:bg-accent"
          @click="open(project)"
        >
          <td class="py-2">
            {{ project.name }}
          </td>
          <td class="py-2 text-xs">
            {{ project.remote }}
          </td>
        </tr>
      </tbody>
    </table>
    <p
      v-else
      class="mt-4 text-center text-sm text-muted-foreground"
    >
      No projects yet
    </p>

    <div
      v-if="selected"
      class="mt-6 rounded-sm border border-border bg-inset p-4"
    >
      <div class="flex items-center justify-between">
        <h3 class="text-sm font-semibold text-foreground">
          {{ selected.name }}
        </h3>
        <button
          class="rounded border border-input px-2 py-0.5 text-xs text-foreground hover:border-fc-muted"
          @click="close"
        >
          Close
        </button>
      </div>
      <dl class="mt-3 grid grid-cols-2 gap-x-4 gap-y-1 text-xs">
        <dt class="text-muted-foreground">
          Remote
        </dt>
        <dd class="font-mono">
          {{ selected.remote }}
        </dd>
        <dt class="text-muted-foreground">
          Checkouts
        </dt>
        <dd class="font-mono">
          <div
            v-for="checkout in selected.checkouts"
            :key="`${checkout.machineId}:${checkout.root}`"
          >
            {{ checkout.machineId }} @ {{ checkout.root }} ({{ checkout.branch ?? '–' }}{{ checkout.dirty ? ', dirty' : '' }})
          </div>
          <span
            v-if="selected.checkouts.length === 0"
            class="text-muted-foreground"
          >
            none observed
          </span>
        </dd>
      </dl>
      <button
        class="mt-4 rounded border border-fc-err/40 px-3 py-1 text-xs text-fc-err hover:bg-fc-err/10 disabled:opacity-50"
        :disabled="busy"
        @click="remove"
      >
        Remove project
      </button>

      <!-- The ready workflow: inspect the plan with a dry run, then
           execute and follow the operation's progress. -->
      <div class="mt-4 border-t border-border pt-4">
        <h4 class="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
          Make ready
        </h4>
        <div class="mt-2 grid grid-cols-3 gap-2 text-xs">
          <input
            v-model="readyForm.machineId"
            placeholder="machine id"
            class="rounded border border-input bg-inset px-2 py-1 font-mono text-foreground"
          >
          <input
            v-model="readyForm.endpointId"
            placeholder="endpoint id"
            class="rounded border border-input bg-inset px-2 py-1 font-mono text-foreground"
          >
          <input
            v-model="readyForm.root"
            placeholder="checkout root"
            class="rounded border border-input bg-inset px-2 py-1 font-mono text-foreground"
          >
          <select
            v-model="readyForm.auth"
            class="rounded border border-input bg-inset px-2 py-1 text-foreground"
          >
            <option value="agent">
              agent auth
            </option>
            <option value="identity-file">
              identity file
            </option>
          </select>
          <input
            v-if="readyForm.auth === 'identity-file'"
            v-model="readyForm.identity"
            placeholder="identity path"
            class="rounded border border-input bg-inset px-2 py-1 font-mono text-foreground"
          >
        </div>
        <div class="mt-2 flex items-center gap-2">
          <button
            class="rounded border border-fc-info/40 px-3 py-1 text-xs text-fc-info hover:bg-fc-info/10 disabled:opacity-50"
            :disabled="busy || readyForm.machineId === '' || readyForm.endpointId === '' || readyForm.root === ''"
            @click="readyForm.dryRun = true; makeReady()"
          >
            Plan (dry run)
          </button>
          <button
            class="rounded border border-fc-ok/40 px-3 py-1 text-xs text-fc-ok hover:bg-fc-ok/10 disabled:opacity-50"
            :disabled="busy || readyForm.machineId === '' || readyForm.endpointId === '' || readyForm.root === ''"
            @click="readyForm.dryRun = false; makeReady()"
          >
            Execute
          </button>
        </div>
        <pre
          v-if="readyPlan"
          class="mt-2 overflow-x-auto rounded bg-inset p-2 text-xs text-foreground"
        >{{ readyPlan }}</pre>
        <p
          v-if="readyProgress"
          class="mt-2 text-xs text-muted-foreground"
        >
          {{ readyProgress }}
        </p>
      </div>
    </div>
  </section>
</template>
