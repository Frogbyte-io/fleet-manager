<script setup lang="ts">
import { onBeforeUnmount, onMounted, ref } from 'vue'

import {
  createProject,
  deleteProject,
  getProject,
  listProjects,
  type PageProjectDtoItemsItem,
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
  if (response.status === 200) selected.value = response.data.data
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
  <section class="rounded-2xl border border-slate-800 bg-slate-900 p-6 shadow-xl">
    <div class="flex items-center justify-between">
      <h2 class="text-lg font-semibold text-slate-100">
        Projects
      </h2>
      <button
        class="rounded-lg border border-slate-700 px-3 py-1 text-xs text-slate-300 hover:border-slate-500"
        @click="load"
      >
        Refresh
      </button>
    </div>

    <p
      v-if="failed"
      class="mt-4 text-sm text-rose-400"
    >
      {{ failure }}
    </p>

    <div class="mt-4 grid grid-cols-2 gap-3 text-sm">
      <input
        v-model="form.remote"
        placeholder="git remote (any spelling)"
        class="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 font-mono text-slate-200"
      >
      <input
        v-model="form.name"
        placeholder="display name"
        class="rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-slate-200"
      >
      <input
        v-model="form.description"
        placeholder="description (optional)"
        class="col-span-2 rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-slate-200"
      >
      <button
        class="col-span-2 rounded-lg border border-cyan-500/40 bg-cyan-500/10 px-3 py-2 text-sm text-cyan-200 hover:bg-cyan-500/20 disabled:opacity-50"
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
      <thead class="text-xs uppercase tracking-wide text-slate-500">
        <tr>
          <th class="py-2">
            Name
          </th>
          <th class="py-2">
            Remote
          </th>
        </tr>
      </thead>
      <tbody class="font-mono text-slate-200">
        <tr
          v-for="project in projects"
          :key="project.id"
          class="cursor-pointer border-t border-slate-800 hover:bg-slate-800/60"
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
      class="mt-4 text-center text-sm text-slate-500"
    >
      No projects yet
    </p>

    <div
      v-if="selected"
      class="mt-6 rounded-xl border border-slate-800 bg-slate-950 p-4"
    >
      <div class="flex items-center justify-between">
        <h3 class="text-sm font-semibold text-slate-200">
          {{ selected.name }}
        </h3>
        <button
          class="rounded border border-slate-700 px-2 py-0.5 text-xs text-slate-300 hover:border-slate-500"
          @click="close"
        >
          Close
        </button>
      </div>
      <dl class="mt-3 grid grid-cols-2 gap-x-4 gap-y-1 text-xs">
        <dt class="text-slate-500">
          Remote
        </dt>
        <dd class="font-mono">
          {{ selected.remote }}
        </dd>
        <dt class="text-slate-500">
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
            class="text-slate-500"
          >
            none observed
          </span>
        </dd>
      </dl>
      <button
        class="mt-4 rounded border border-rose-500/40 px-3 py-1 text-xs text-rose-300 hover:bg-rose-500/10 disabled:opacity-50"
        :disabled="busy"
        @click="remove"
      >
        Remove project
      </button>
    </div>
  </section>
</template>
