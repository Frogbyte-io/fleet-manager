<script setup lang="ts">
import { onMounted, ref } from 'vue'

import {
  addOnboardingMachine,
  cancelOnboardingDraft,
  confirmOnboardingHostKey,
  createOnboardingDraft,
  discoverOnboardingDraft,
  getOnboardingDraft,
  getOperation,
  listOnboardingDrafts,
  testOnboardingDraft,
  type AddedMachineDto,
  type PageOnboardingDraftDtoItemsItem,
  type ResourceOnboardingDraftDetailDtoData,
} from '@frogbyte-io/fleet-api-client'

type DraftSummary = PageOnboardingDraftDtoItemsItem
type DraftDetail = ResourceOnboardingDraftDetailDtoData

const drafts = ref<readonly DraftSummary[]>([])
const selected = ref<DraftDetail | null>(null)
const added = ref<AddedMachineDto | null>(null)
const failed = ref(false)
const failure = ref('')
const busy = ref(false)

// The new-draft form: an address and an authentication mode.
const form = ref({
  user: '',
  host: '',
  port: 22,
  authType: 'identityFile' as 'agent' | 'identityFile',
  identityPath: '',
  name: '',
  description: '',
  tags: '',
})

async function load() {
  try {
    const response = await listOnboardingDrafts({ limit: 50 })
    if (response.status === 200) {
      drafts.value = response.data.items
      failed.value = false
    }
  } catch (error) {
    failed.value = true
    failure.value = error instanceof Error ? error.message : String(error)
  }
}

async function open(id: string) {
  const response = await getOnboardingDraft(id)
  if (response.status === 200) selected.value = response.data.data
}

async function close() {
  selected.value = null
  added.value = null
  await load()
}

async function create() {
  busy.value = true
  try {
    const response = await createOnboardingDraft({
      user: form.value.user,
      host: form.value.host,
      port: form.value.port,
      auth:
        form.value.authType === 'agent'
          ? { type: 'agent' }
          : { type: 'identityFile', path: form.value.identityPath },
      name: form.value.name === '' ? undefined : form.value.name,
      description: form.value.description,
      tags: form.value.tags === '' ? [] : form.value.tags.split(',').map(tag => tag.trim()),
      groups: [],
    })
    if (response.status === 201) {
      form.value = {
        user: '',
        host: '',
        port: 22,
        authType: 'identityFile',
        identityPath: '',
        name: '',
        description: '',
        tags: '',
      }
      await load()
      await open(response.data.data.id)
    }
  } catch (error) {
    failed.value = true
    failure.value = error instanceof Error ? error.message : String(error)
  } finally {
    busy.value = false
  }
}

/// The test and discover stages are durable operations: start one, poll it
/// to a terminal state, then show the refreshed draft.
async function runStage(stage: 'test' | 'discover') {
  if (!selected.value) return
  busy.value = true
  const draftId = selected.value.id
  try {
    const response =
      stage === 'test' ? await testOnboardingDraft(draftId) : await discoverOnboardingDraft(draftId)
    if (response.status !== 202) return
    const operationId = response.data.data.id
    const deadline = Date.now() + 300_000
    while (Date.now() < deadline) {
      const operation = await getOperation(operationId)
      if (operation.status === 200) {
        const state = operation.data.data.state
        if (state !== 'pending' && state !== 'running' && state !== 'cancelling') break
      }
      await new Promise(resolve => setTimeout(resolve, 700))
    }
    await open(draftId)
    await load()
  } finally {
    busy.value = false
  }
}

async function confirmFingerprint() {
  if (!selected.value?.hostKey) return
  busy.value = true
  try {
    const response = await confirmOnboardingHostKey(selected.value.id, {
      fingerprint: selected.value.hostKey.fingerprint,
    })
    if (response.status === 200) selected.value = response.data.data
  } finally {
    busy.value = false
  }
}

async function add() {
  if (!selected.value) return
  busy.value = true
  try {
    const response = await addOnboardingMachine(selected.value.id)
    if (response.status === 201) {
      added.value = response.data.data
      selected.value = null
      await load()
    }
  } finally {
    busy.value = false
  }
}

async function cancel() {
  if (!selected.value) return
  busy.value = true
  try {
    const response = await cancelOnboardingDraft(selected.value.id)
    if (response.status === 204) {
      selected.value = null
      await load()
    }
  } finally {
    busy.value = false
  }
}

onMounted(load)
</script>

<template>
  <section class="rounded-sm border border-border bg-card p-6">
    <div class="flex items-center justify-between">
      <h2 class="text-lg font-semibold text-foreground">
        Add Machine
      </h2>
      <button
        class="rounded-sm border border-input px-3 py-1 text-xs text-foreground hover:border-fc-line2"
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
        v-model="form.user"
        placeholder="login user"
        class="rounded-sm border border-input bg-background px-3 py-2 font-mono text-foreground"
      >
      <input
        v-model="form.host"
        placeholder="host"
        class="rounded-sm border border-input bg-background px-3 py-2 font-mono text-foreground"
      >
      <input
        v-model.number="form.port"
        type="number"
        placeholder="port"
        class="rounded-sm border border-input bg-background px-3 py-2 font-mono text-foreground"
      >
      <select
        v-model="form.authType"
        class="rounded-sm border border-input bg-background px-3 py-2 text-foreground"
      >
        <option value="identityFile">
          identity file
        </option>
        <option value="agent">
          ssh agent
        </option>
      </select>
      <input
        v-if="form.authType === 'identityFile'"
        v-model="form.identityPath"
        placeholder="identity file path"
        class="col-span-2 rounded-sm border border-input bg-background px-3 py-2 font-mono text-foreground"
      >
      <input
        v-model="form.name"
        placeholder="machine name (optional)"
        class="rounded-sm border border-input bg-background px-3 py-2 text-foreground"
      >
      <input
        v-model="form.tags"
        placeholder="tags, comma-separated"
        class="rounded-sm border border-input bg-background px-3 py-2 text-foreground"
      >
      <input
        v-model="form.description"
        placeholder="description (optional)"
        class="col-span-2 rounded-sm border border-input bg-background px-3 py-2 text-foreground"
      >
      <button
        class="col-span-2 rounded-sm border border-fc-info/40 bg-fc-info/10 px-3 py-2 text-sm text-fc-info hover:bg-fc-info/20 disabled:opacity-50"
        :disabled="busy || form.user === '' || form.host === '' || (form.authType === 'identityFile' && form.identityPath === '')"
        @click="create"
      >
        Create draft
      </button>
    </div>

    <table
      v-if="drafts.length > 0"
      class="mt-4 w-full text-left text-sm"
    >
      <thead class="text-xs uppercase tracking-wide text-fc-faint">
        <tr>
          <th class="py-2">
            Name
          </th>
          <th class="py-2">
            Stage
          </th>
          <th class="py-2">
            Endpoint
          </th>
        </tr>
      </thead>
      <tbody class="font-mono text-foreground">
        <tr
          v-for="draft in drafts"
          :key="draft.id"
          class="cursor-pointer border-t border-border hover:bg-accent"
          @click="open(draft.id)"
        >
          <td class="py-2">
            {{ draft.name }}
          </td>
          <td class="py-2">
            <span
              class="rounded border px-1.5 py-0.5 text-xs"
              :class="{
                'border-fc-ok/40 text-fc-ok': draft.stage === 'ready',
                'border-fc-warn/40 text-fc-warn': draft.stage === 'review',
                'border-input text-muted-foreground': draft.stage === 'untested',
              }"
            >{{ draft.stage }}</span>
          </td>
          <td class="py-2 text-xs">
            {{ draft.endpoint.user }}@{{ draft.endpoint.host }}:{{ draft.endpoint.port }}
          </td>
        </tr>
      </tbody>
    </table>
    <p
      v-else
      class="mt-4 text-center text-sm text-fc-faint"
    >
      No drafts yet
    </p>

    <div
      v-if="selected"
      class="mt-6 rounded-sm border border-border bg-inset p-4"
    >
      <div class="flex items-center justify-between">
        <h3 class="text-sm font-semibold text-foreground">
          {{ selected.name }}
          <span class="ml-2 text-xs font-normal text-fc-faint">{{ selected.stage }}</span>
        </h3>
        <button
          class="rounded border border-input px-2 py-0.5 text-xs text-foreground hover:border-fc-line2"
          @click="close"
        >
          Close
        </button>
      </div>

      <dl class="mt-3 grid grid-cols-2 gap-x-4 gap-y-1 text-xs">
        <dt class="text-fc-faint">
          Endpoint
        </dt>
        <dd class="font-mono">
          {{ selected.endpoint.user }}@{{ selected.endpoint.host }}:{{ selected.endpoint.port }}
        </dd>
        <dt class="text-fc-faint">
          Auth
        </dt>
        <dd class="font-mono">
          <template v-if="selected.auth.type === 'identityFile'">
            identity file {{ selected.auth.path }}
          </template>
          <template v-else>
            ssh agent
          </template>
        </dd>
        <template v-if="selected.hostKey">
          <dt class="text-fc-faint">
            Host key ({{ selected.hostKeyStage }})
          </dt>
          <dd class="font-mono">
            {{ selected.hostKey.keyType }} {{ selected.hostKey.fingerprint }}
          </dd>
        </template>
        <template v-if="selected.lastTest">
          <dt class="text-fc-faint">
            Last test
          </dt>
          <dd class="font-mono">
            <template v-if="selected.lastTest.connectAttempted">
              {{ selected.lastTest.connected ? 'connected' : `failed: ${selected.lastTest.detail ?? ''}` }}
            </template>
            <template v-else>
              not attempted (fingerprint unconfirmed)
            </template>
          </dd>
        </template>
        <template v-if="selected.profileHint">
          <dt class="text-fc-faint">
            Profile hint
          </dt>
          <dd class="font-mono">
            {{ selected.profileHint }}
          </dd>
        </template>
      </dl>

      <div
        v-if="selected.duplicates.length > 0"
        class="mt-3 rounded-sm border border-fc-warn/40 bg-fc-warn/10 p-3 text-xs text-fc-warn"
      >
        Machines already registered on this host (warned, never merged):
        <div
          v-for="candidate in selected.duplicates"
          :key="candidate.machineId"
          class="font-mono"
        >
          {{ candidate.name }} {{ candidate.reference }}
        </div>
      </div>

      <div
        v-if="selected.facts.length > 0"
        class="mt-3 text-xs"
      >
        <p class="text-fc-faint">
          Discovered facts — review before adding:
        </p>
        <div class="mt-1 font-mono text-foreground">
          <div
            v-for="fact in selected.facts"
            :key="`${fact.namespace}.${fact.name}`"
          >
            {{ fact.namespace }}.{{ fact.name }} = {{ fact.value ?? '–' }}
            <span class="text-fc-faint">{{ fact.status }}</span>
          </div>
        </div>
      </div>

      <div class="mt-4 flex flex-wrap gap-2">
        <button
          class="rounded border border-input px-3 py-1 text-xs text-foreground hover:border-fc-line2 disabled:opacity-50"
          :disabled="busy"
          @click="runStage('test')"
        >
          Test
        </button>
        <button
          v-if="selected.hostKey && selected.hostKeyStage !== 'confirmed'"
          class="rounded border border-fc-warn/40 px-3 py-1 text-xs text-fc-warn hover:bg-fc-warn/10 disabled:opacity-50"
          :disabled="busy"
          @click="confirmFingerprint"
        >
          Confirm fingerprint
        </button>
        <button
          v-if="selected.stage === 'ready'"
          class="rounded border border-input px-3 py-1 text-xs text-foreground hover:border-fc-line2 disabled:opacity-50"
          :disabled="busy"
          @click="runStage('discover')"
        >
          Discover
        </button>
        <button
          v-if="selected.stage === 'ready'"
          class="rounded border border-fc-ok/40 bg-fc-ok/10 px-3 py-1 text-xs text-fc-ok hover:bg-fc-ok/20 disabled:opacity-50"
          :disabled="busy"
          @click="add"
        >
          Add machine
        </button>
        <button
          class="rounded border border-fc-err/40 px-3 py-1 text-xs text-fc-err hover:bg-fc-err/10 disabled:opacity-50"
          :disabled="busy"
          @click="cancel"
        >
          Cancel draft
        </button>
      </div>
    </div>

    <div
      v-if="added"
      class="mt-6 rounded-sm border border-fc-ok/40 bg-fc-ok/10 p-4 text-sm text-fc-ok"
    >
      Machine registered: {{ added.machine.name }} ({{ added.machine.id }})
      <div
        v-for="candidate in added.duplicates"
        :key="candidate.machineId"
        class="mt-1 text-xs text-fc-warn"
      >
        Duplicate candidate (warned, not merged): {{ candidate.name }} {{ candidate.reference }}
      </div>
    </div>
  </section>
</template>
