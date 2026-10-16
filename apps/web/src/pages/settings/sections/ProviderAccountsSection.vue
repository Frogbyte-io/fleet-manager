<script setup lang="ts">
import { useQuery, useQueryClient } from '@tanstack/vue-query'
import { computed, ref } from 'vue'

import {
  createExternalAccount,
  deleteExternalAccount,
  listExternalAccounts,
  probeExternalAccount,
  updateExternalAccount,
  type ExternalAccountDto,
} from '@frogbyte-io/fleet-api-client'
import StatusChip from '@/components/fleet/StatusChip.vue'

import { relativeTime } from '../../fleet/inventory'
import { errorMessage, retryTransient, unwrap } from '../../machine/api'
import CopyFleetctl from '../../machine/components/CopyFleetctl.vue'
import {
  PROVIDER_KINDS,
  createCommand,
  deleteCommand,
  kindTitle,
  probeCommand,
  probeView,
  sameOrigin,
  type CreateDraft,
  type ProviderKind,
} from '../accounts'

// External provider accounts for the API-token providers (FM-1001). The
// token is write-only: it is typed here once, sent, and cleared; no response
// carries it back.
const ACCOUNTS_KEY = ['external-accounts'] as const
const queryClient = useQueryClient()

const accounts = useQuery({
  queryKey: ACCOUNTS_KEY,
  queryFn: async () => {
    const response = await listExternalAccounts({ limit: 200 }) as { status: number, data: unknown }
    if (response.status !== 200)
      unwrap(response)
    return (response.data as { items: ExternalAccountDto[] }).items
  },
  retry: retryTransient,
})
const items = computed(() => accounts.data.value ?? [])

// --- create
const blank = (): CreateDraft => ({ kind: 'coolify', label: '', baseUrl: '', accountId: '', notes: '' })
const draft = ref<CreateDraft>(blank())
const token = ref('')
const createError = ref('')
const creating = ref(false)
const needsBaseUrl = computed(() => PROVIDER_KINDS.find(k => k.id === draft.value.kind)?.needsBaseUrl ?? false)
const canCreate = computed(() =>
  draft.value.label.trim() !== ''
  && token.value.trim() !== ''
  && (!needsBaseUrl.value || draft.value.baseUrl.trim() !== ''),
)

async function create() {
  creating.value = true
  createError.value = ''
  try {
    unwrap(await createExternalAccount({
      kind: draft.value.kind,
      label: draft.value.label.trim(),
      baseUrl: draft.value.baseUrl.trim() || undefined,
      accountId: draft.value.kind === 'cloudflare' ? draft.value.accountId.trim() || undefined : undefined,
      notes: draft.value.notes.trim() || undefined,
      token: token.value.trim(),
    }), [201])
    draft.value = blank()
    token.value = ''
    await queryClient.invalidateQueries({ queryKey: ACCOUNTS_KEY })
  }
  catch (error) {
    createError.value = errorMessage(error)
  }
  finally {
    creating.value = false
  }
}

// --- per-account actions
const busyId = ref<string | null>(null)
const actionError = ref<{ id: string, message: string } | null>(null)

async function act(id: string, run: () => Promise<unknown>) {
  busyId.value = id
  actionError.value = null
  try {
    await run()
    await queryClient.invalidateQueries({ queryKey: ACCOUNTS_KEY })
  }
  catch (error) {
    actionError.value = { id, message: errorMessage(error) }
  }
  finally {
    busyId.value = null
  }
}

const probe = (id: string) => act(id, async () => unwrap(await probeExternalAccount(id)))

const confirmingDelete = ref<string | null>(null)
async function remove(id: string) {
  confirmingDelete.value = null
  await act(id, async () => {
    const response = await deleteExternalAccount(id) as { status: number, data: unknown }
    if (response.status !== 204)
      unwrap(response)
  })
}

// --- edit (label, notes, endpoint, and a replacement token)
const editing = ref<string | null>(null)
const edit = ref({ label: '', baseUrl: '', accountId: '', notes: '', token: '' })

function startEdit(account: ExternalAccountDto) {
  editing.value = account.id
  edit.value = {
    label: account.label,
    baseUrl: account.baseUrl,
    accountId: account.accountId ?? '',
    notes: account.notes,
    token: '',
  }
}

async function saveEdit(account: ExternalAccountDto) {
  const form = edit.value
  await act(account.id, async () => {
    unwrap(await updateExternalAccount(account.id, {
      label: form.label.trim(),
      baseUrl: form.baseUrl.trim(),
      accountId: account.kind === 'cloudflare' ? form.accountId.trim() : undefined,
      notes: form.notes,
      token: form.token.trim() || undefined,
    }))
  })
  if (actionError.value === null)
    editing.value = null
  edit.value.token = ''
}

function originChanged(account: ExternalAccountDto): boolean {
  return !sameOrigin(account.baseUrl, edit.value.baseUrl)
}

const toneFor = (tone: string) => tone as 'ok' | 'info' | 'warn' | 'err' | 'muted'
const inputClass = 'h-8 rounded-sm border border-input bg-background px-2 text-foreground'
const buttonClass = 'h-8 rounded-sm border border-fc-info/40 px-3 text-fc-info hover:bg-fc-info/10 disabled:opacity-50'
</script>

<template>
  <section
    class="space-y-6 rounded-sm border border-border bg-card p-6"
    data-testid="provider-accounts-section"
  >
    <div>
      <div class="flex items-baseline justify-between">
        <h2 class="text-lg font-semibold text-foreground">
          Provider accounts
        </h2>
        <span class="text-xs text-fc-muted">tokens are write-only</span>
      </div>
      <p class="mt-1 text-sm text-fc-muted">
        API-token accounts for Coolify and Cloudflare. Fleet keeps each token encrypted and never shows it again; a probe checks that the service is reachable and the token is accepted with the permissions Fleet needs.
      </p>
    </div>

    <!-- Accounts -->
    <div class="space-y-2">
      <h3 class="fc-kicker border-b border-fc-line pb-1">
        Accounts
      </h3>
      <p
        v-if="accounts.isLoading.value"
        class="text-xs text-fc-muted"
      >
        Loading…
      </p>
      <p
        v-else-if="accounts.error.value"
        class="text-xs text-fc-err"
        role="alert"
        data-testid="accounts-error"
      >
        The accounts could not be read: {{ errorMessage(accounts.error.value) }}
      </p>
      <p
        v-else-if="items.length === 0"
        class="text-sm text-fc-muted"
        data-testid="accounts-empty"
      >
        No provider accounts yet. Add one below; several accounts per provider are fine.
      </p>
      <ul
        v-else
        class="space-y-3"
      >
        <li
          v-for="account in items"
          :key="account.id"
          class="rounded-sm border border-border p-3"
          data-testid="account-row"
        >
          <div class="flex flex-wrap items-center gap-x-3 gap-y-1">
            <span class="text-sm font-semibold">{{ account.label }}</span>
            <StatusChip
              :label="kindTitle(account.kind)"
              tone="muted"
            />
            <StatusChip
              :label="probeView(account.lastProbe).label"
              :tone="toneFor(probeView(account.lastProbe).tone)"
              data-testid="probe-chip"
            />
            <span
              v-if="account.lastProbe"
              class="font-mono text-[10px] text-fc-faint"
            >probed {{ relativeTime(account.lastProbe.checkedAt) }}</span>
          </div>
          <p class="mt-1 break-all font-mono text-xs text-fc-muted">
            {{ account.baseUrl }}{{ account.accountId ? ` · account ${account.accountId}` : '' }}
          </p>
          <p
            v-if="account.notes"
            class="mt-1 text-xs text-fc-muted"
          >
            {{ account.notes }}
          </p>
          <div
            v-if="account.lastProbe"
            class="mt-2 space-y-1 text-xs"
            data-testid="probe-detail"
          >
            <p class="text-fc-muted">
              {{ account.lastProbe.detail }}
            </p>
            <p
              v-if="account.lastProbe.granted.length"
              class="font-mono text-fc-ok"
            >
              granted: {{ account.lastProbe.granted.join(', ') }}
            </p>
            <p
              v-if="account.lastProbe.missing.length"
              class="font-mono text-fc-warn"
            >
              missing: {{ account.lastProbe.missing.join(', ') }}
            </p>
            <p
              v-if="account.lastProbe.unverified.length"
              class="font-mono text-fc-faint"
              data-testid="probe-unverified"
            >
              not verified: {{ account.lastProbe.unverified.join(', ') }}
            </p>
          </div>

          <div class="mt-3 flex flex-wrap items-center gap-2 text-xs">
            <button
              type="button"
              :class="buttonClass"
              :disabled="busyId === account.id"
              data-testid="probe-button"
              @click="probe(account.id)"
            >
              {{ busyId === account.id ? 'Working…' : 'Probe' }}
            </button>
            <button
              type="button"
              class="h-8 rounded-sm border border-border px-3 text-fc-muted hover:text-foreground"
              data-testid="edit-button"
              @click="editing === account.id ? (editing = null) : startEdit(account)"
            >
              {{ editing === account.id ? 'Cancel edit' : 'Edit' }}
            </button>
            <template v-if="confirmingDelete === account.id">
              <span class="text-fc-warn">Remove {{ account.label }} and its token?</span>
              <button
                type="button"
                class="h-8 rounded-sm border border-fc-err/40 px-3 text-fc-err hover:bg-fc-err/10"
                data-testid="delete-confirm"
                @click="remove(account.id)"
              >
                Remove
              </button>
              <button
                type="button"
                class="h-8 rounded-sm border border-border px-3 text-fc-muted"
                @click="confirmingDelete = null"
              >
                Keep
              </button>
            </template>
            <button
              v-else
              type="button"
              class="h-8 rounded-sm border border-fc-err/40 px-3 text-fc-err hover:bg-fc-err/10"
              data-testid="delete-button"
              @click="confirmingDelete = account.id"
            >
              Remove
            </button>
          </div>
          <p
            v-if="actionError?.id === account.id"
            class="mt-2 text-xs text-fc-err"
            role="alert"
            data-testid="action-error"
          >
            {{ actionError.message }}
          </p>

          <form
            v-if="editing === account.id"
            class="mt-3 grid gap-3 border-t border-fc-line pt-3 text-xs sm:grid-cols-2"
            data-testid="edit-form"
            @submit.prevent="saveEdit(account)"
          >
            <label class="flex flex-col gap-1">
              <span class="fc-kicker">Label</span>
              <input
                v-model="edit.label"
                :class="inputClass"
              >
            </label>
            <label class="flex flex-col gap-1">
              <span class="fc-kicker">Base URL</span>
              <input
                v-model="edit.baseUrl"
                :class="[inputClass, 'font-mono']"
              >
            </label>
            <label
              v-if="account.kind === 'cloudflare'"
              class="flex flex-col gap-1"
            >
              <span class="fc-kicker">Account id (account-owned tokens)</span>
              <input
                v-model="edit.accountId"
                :class="[inputClass, 'font-mono']"
              >
            </label>
            <label class="flex flex-col gap-1">
              <span class="fc-kicker">Replace token (optional)</span>
              <input
                v-model="edit.token"
                type="password"
                autocomplete="off"
                placeholder="leave empty to keep the stored token"
                :class="[inputClass, 'font-mono']"
                data-testid="edit-token"
              >
            </label>
            <label class="flex flex-col gap-1 sm:col-span-2">
              <span class="fc-kicker">Notes</span>
              <input
                v-model="edit.notes"
                :class="inputClass"
              >
            </label>
            <div class="sm:col-span-2">
              <button
                type="submit"
                :class="buttonClass"
                :disabled="busyId === account.id || edit.label.trim() === '' || (originChanged(account) && edit.token.trim() === '')"
                data-testid="edit-save"
              >
                Save changes
              </button>
              <span class="ml-2 text-[11px] text-fc-faint">Changing the endpoint or token clears the last probe.</span>
              <p
                v-if="originChanged(account)"
                class="mt-1 text-[11px] text-fc-warn"
                data-testid="origin-hint"
              >
                A different scheme, host, or port needs a new token in the same request.
              </p>
            </div>
          </form>

          <div class="mt-3 grid gap-2 sm:grid-cols-2">
            <CopyFleetctl :command="probeCommand(account.id)" />
            <CopyFleetctl :command="deleteCommand(account.id)" />
          </div>
        </li>
      </ul>
    </div>

    <!-- Add -->
    <div class="space-y-2">
      <h3 class="fc-kicker border-b border-fc-line pb-1">
        Add an account
      </h3>
      <form
        class="grid gap-3 text-xs sm:grid-cols-2"
        data-testid="create-form"
        @submit.prevent="create"
      >
        <label class="flex flex-col gap-1">
          <span class="fc-kicker">Provider</span>
          <select
            v-model="draft.kind"
            :class="inputClass"
            data-testid="create-kind"
          >
            <option
              v-for="kind in PROVIDER_KINDS"
              :key="kind.id"
              :value="kind.id satisfies ProviderKind"
            >
              {{ kind.title }}
            </option>
          </select>
        </label>
        <label class="flex flex-col gap-1">
          <span class="fc-kicker">Label</span>
          <input
            v-model="draft.label"
            placeholder="production"
            :class="inputClass"
            data-testid="create-label"
          >
        </label>
        <label class="flex flex-col gap-1">
          <span class="fc-kicker">Base URL{{ needsBaseUrl ? '' : ' (optional)' }}</span>
          <input
            v-model="draft.baseUrl"
            :placeholder="needsBaseUrl ? 'https://coolify.example.com' : 'https://api.cloudflare.com/client/v4'"
            :class="[inputClass, 'font-mono']"
            data-testid="create-base-url"
          >
        </label>
        <label
          v-if="draft.kind === 'cloudflare'"
          class="flex flex-col gap-1"
        >
          <span class="fc-kicker">Account id (account-owned tokens)</span>
          <input
            v-model="draft.accountId"
            placeholder="leave empty for a user-owned token"
            :class="[inputClass, 'font-mono']"
            data-testid="create-account-id"
          >
        </label>
        <label class="flex flex-col gap-1">
          <span class="fc-kicker">API token (write-only)</span>
          <input
            v-model="token"
            type="password"
            autocomplete="off"
            :class="[inputClass, 'font-mono']"
            data-testid="create-token"
          >
        </label>
        <label class="flex flex-col gap-1 sm:col-span-2">
          <span class="fc-kicker">Notes (optional)</span>
          <input
            v-model="draft.notes"
            :class="inputClass"
            data-testid="create-notes"
          >
        </label>
        <div class="sm:col-span-2">
          <button
            type="submit"
            :class="buttonClass"
            :disabled="!canCreate || creating"
            data-testid="create-submit"
          >
            {{ creating ? 'Adding…' : 'Add account' }}
          </button>
        </div>
      </form>
      <p class="text-[11px] text-fc-faint">
        A Coolify probe verifies the read ability only; write and deploy cannot be checked without changing state, so they show as not verified. Cloudflare tokens are checked with the token verify endpoint and need an https base URL. The token is stored encrypted and is not returned by the API, the CLI, or the audit log.
      </p>
      <p
        v-if="createError"
        class="text-xs text-fc-err"
        role="alert"
        data-testid="create-error"
      >
        {{ createError }}
      </p>
      <CopyFleetctl :command="createCommand(draft)" />
    </div>
  </section>
</template>
