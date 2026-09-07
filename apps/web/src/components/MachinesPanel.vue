<script setup lang="ts">
import { onBeforeUnmount, onMounted, ref } from 'vue'

import {
  createOperation,
  cancelOperation,
  getMachine,
  getOperation,
  listMachines,
  type PageMachineDtoItemsItem,
  type ResourceMachineDtoData,
} from '@frogbyte-io/fleet-api-client'

type Machine = PageMachineDtoItemsItem
type MachineDetail = ResourceMachineDtoData

const machines = ref<readonly Machine[]>([])
const failed = ref(false)
const failure = ref('')
const selected = ref<MachineDetail | null>(null)
const installForm = ref({ authType: 'identityFile' as 'agent' | 'identityFile', identityPath: '' })
const installOperationId = ref<string | null>(null)
const installState = ref('')
const installProgress = ref('')
const installResult = ref('')
const installFailed = ref(false)
const installBusy = ref(false)
let refresh: ReturnType<typeof setInterval> | null = null
let installPoll: ReturnType<typeof setTimeout> | null = null

async function load() {
  try {
    const response = await listMachines({ limit: 50 })
    if (response.status === 200) {
      machines.value = response.data.items
      failed.value = false
    }
  } catch (error) {
    failed.value = true
    failure.value = error instanceof Error ? error.message : String(error)
  }
}

async function open(machine: Machine) {
  const response = await getMachine(machine.id)
  if (response.status === 200) selected.value = response.data.data
}

async function close() {
  selected.value = null
  resetInstall()
}

function resetInstall() {
  installOperationId.value = null
  installState.value = ''
  installProgress.value = ''
  installResult.value = ''
  installFailed.value = false
  if (installPoll) clearTimeout(installPoll)
  installPoll = null
}

/// Starts the one-click upgrade: the controller selects the package for the
/// machine's own platform; the node's identity association keeps the
/// machine's Fleet id. The operation is durable, so a lost browser only
/// loses the view, not the work.
async function startInstall() {
  if (!selected.value) return
  installBusy.value = true
  try {
    const endpoint = selected.value.endpoints.find(e => e.kind === 'ssh') ?? selected.value.endpoints[0]
    const payload = {
      machineId: selected.value.id,
      endpointId: endpoint?.id,
      auth:
        installForm.value.authType === 'agent'
          ? { type: 'agent' }
          : { type: 'identityFile', path: installForm.value.identityPath },
      controllerUrl: window.location.origin,
    }
    const response = await createOperation({
      kind: 'machine.install-fleetd',
      payloadJson: JSON.stringify(payload),
    })
    if (response.status === 201) {
      installOperationId.value = response.data.data.id
      installState.value = response.data.data.state
      installFailed.value = false
      installResult.value = ''
      pollInstall()
    }
  } finally {
    installBusy.value = false
  }
}

async function pollInstall() {
  if (!installOperationId.value) return
  try {
    const response = await getOperation(installOperationId.value)
    if (response.status === 200) {
      const operation = response.data.data
      installState.value = operation.state
      installProgress.value = operation.progressMessage ?? ''
      if (operation.state === 'succeeded') {
        installResult.value = operation.resultJson ?? ''
        return
      }
      if (operation.state !== 'pending' && operation.state !== 'running') {
        installFailed.value = true
        installResult.value = operation.errorJson ?? ''
        return
      }
    }
  } catch {
    // transient; keep polling
  }
  installPoll = setTimeout(pollInstall, 1000)
}

async function cancelInstall() {
  if (!installOperationId.value) return
  await cancelOperation(installOperationId.value)
}

onMounted(() => {
  load()
  refresh = setInterval(load, 3000)
})

onBeforeUnmount(() => {
  if (refresh) clearInterval(refresh)
  if (installPoll) clearTimeout(installPoll)
})
</script>

<template>
  <section class="rounded-2xl border border-slate-800 bg-slate-900 p-6 shadow-xl">
    <div class="flex items-center justify-between">
      <h2 class="text-lg font-semibold text-slate-100">
        Machines
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

    <table
      v-else
      class="mt-4 w-full text-left text-sm"
    >
      <thead class="text-xs uppercase tracking-wide text-slate-500">
        <tr>
          <th class="py-2">
            Name
          </th>
          <th class="py-2">
            Status
          </th>
          <th class="py-2">
            Endpoint
          </th>
          <th class="py-2">
            Tags
          </th>
        </tr>
      </thead>
      <tbody class="font-mono text-slate-200">
        <tr
          v-for="machine in machines"
          :key="machine.id"
          class="cursor-pointer border-t border-slate-800 hover:bg-slate-800/60"
          @click="open(machine)"
        >
          <td class="py-2">
            {{ machine.name }}
          </td>
          <td class="py-2">
            <span
              class="rounded border px-1.5 py-0.5 text-xs"
              :class="{
                'border-emerald-500/40 text-emerald-300': machine.machineStatus === 'connected',
                'border-amber-500/40 text-amber-300': machine.machineStatus === 'stale',
                'border-slate-600 text-slate-400': machine.machineStatus === 'offline',
                'border-cyan-500/40 text-cyan-300': machine.machineStatus === 'agentless',
              }"
            >{{ machine.machineStatus }}</span>
          </td>
          <td class="py-2 text-xs">
            {{ machine.endpoints[0]?.reference ?? '–' }}
          </td>
          <td class="py-2 text-xs text-slate-400">
            {{ machine.tags.join(', ') }}
          </td>
        </tr>
        <tr v-if="machines.length === 0">
          <td
            colspan="4"
            class="py-4 text-center text-slate-500"
          >
            No machines yet
          </td>
        </tr>
      </tbody>
    </table>

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
          Status
        </dt>
        <dd class="font-mono">
          {{ selected.machineStatus }}
        </dd>
        <dt class="text-slate-500">
          Last seen
        </dt>
        <dd class="font-mono">
          {{ selected.lastSeenAt ?? '–' }}
        </dd>
        <dt class="text-slate-500">
          Last observation
        </dt>
        <dd class="font-mono">
          <template v-if="selected.lastObservation">
            {{ selected.lastObservation.source }} at {{ selected.lastObservation.collectedAt }}
          </template>
          <template v-else>
            –
          </template>
        </dd>
      </dl>
      <dl class="mt-3 grid grid-cols-2 gap-x-4 gap-y-1 text-xs">
        <dt class="text-slate-500">
          Endpoints
        </dt>
        <dd class="font-mono">
          <div
            v-for="endpoint in selected.endpoints"
            :key="endpoint.id"
          >
            {{ endpoint.kind }} {{ endpoint.reference }}
          </div>
        </dd>
        <dt class="text-slate-500">
          Tags
        </dt>
        <dd class="font-mono">
          {{ selected.tags.join(', ') || '–' }}
        </dd>
        <dt class="text-slate-500">
          Groups
        </dt>
        <dd class="font-mono">
          {{ selected.groups.join(', ') || '–' }}
        </dd>
      </dl>
      <dl
        v-if="selected.capabilities.length > 0"
        class="mt-3 grid grid-cols-2 gap-x-4 gap-y-1 text-xs"
      >
        <dt class="text-slate-500">
          Capabilities
        </dt>
        <dd class="font-mono">
          <div
            v-for="fact in selected.capabilities"
            :key="`${fact.namespace}.${fact.name}`"
          >
            {{ fact.namespace }}.{{ fact.name }} = {{ fact.value ?? '–' }}
            <span class="text-slate-500">{{ fact.status }}</span>
          </div>
        </dd>
      </dl>

      <div class="mt-4 border-t border-slate-800 pt-3">
        <p class="text-xs text-slate-500">
          Install Fleet Node — upgrades this machine to fully managed. The
          controller picks the package for the machine's platform; the
          machine's Fleet id is kept.
        </p>
        <div
          v-if="!installOperationId"
          class="mt-2 flex flex-wrap items-center gap-2 text-xs"
        >
          <select
            v-model="installForm.authType"
            class="rounded border border-slate-700 bg-slate-950 px-2 py-1 text-slate-200"
          >
            <option value="identityFile">
              identity file
            </option>
            <option value="agent">
              ssh agent
            </option>
          </select>
          <input
            v-if="installForm.authType === 'identityFile'"
            v-model="installForm.identityPath"
            placeholder="identity file path"
            class="rounded border border-slate-700 bg-slate-950 px-2 py-1 font-mono text-slate-200"
          >
          <button
            class="rounded border border-cyan-500/40 bg-cyan-500/10 px-3 py-1 text-cyan-200 hover:bg-cyan-500/20 disabled:opacity-50"
            :disabled="installBusy || (installForm.authType === 'identityFile' && installForm.identityPath === '')"
            @click="startInstall"
          >
            Install
          </button>
        </div>
        <div
          v-else
          class="mt-2 text-xs"
        >
          <p class="font-mono text-slate-300">
            {{ installState }}
            <span
              v-if="installProgress"
              class="text-slate-500"
            >— {{ installProgress }}</span>
          </p>
          <p
            v-if="installResult"
            class="mt-1 font-mono"
            :class="installFailed ? 'text-rose-400' : 'text-emerald-300'"
          >
            {{ installResult }}
          </p>
          <button
            v-if="installState === 'pending' || installState === 'running'"
            class="mt-2 rounded border border-rose-500/40 px-2 py-0.5 text-rose-300 hover:bg-rose-500/10"
            @click="cancelInstall"
          >
            Cancel operation
          </button>
        </div>
      </div>
    </div>
  </section>
</template>
