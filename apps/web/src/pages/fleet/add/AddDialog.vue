<script setup lang="ts">
import { useQuery } from '@tanstack/vue-query'
import { computed, ref } from 'vue'
import { useRouter } from 'vue-router'

import {
  listOnboardingDrafts,
  listProxmoxAccounts,
  type OnboardingDraftDto,
  type ProxmoxAccountDto,
} from '@frogbyte-io/fleet-api-client'
import { Dialog, DialogContent, DialogDescription, DialogTitle } from '@/components/ui/dialog'

import DraftFlow from './DraftFlow.vue'
import GuestSource from './GuestSource.vue'
import ProxmoxSource from './ProxmoxSource.vue'
import { clearResume, loadResume, saveResume, type DraftStep, type Source } from './resume'
import SshSource from './SshSource.vue'
import TailscaleSource from './TailscaleSource.vue'

// One "+ Add" dialog. Each source is a view over durable controller state
// (onboarding drafts, unconfirmed Proxmox accounts), so the dialog can be
// closed at any step and reopened where it left off.
const props = defineProps<{
  initialSource?: Source | null
  initialDevice?: string | null
}>()
const open = defineModel<boolean>('open', { required: true })

const router = useRouter()

const resume = loadResume()
const source = ref<Source | null>(resume ? (resume.kind === 'proxmox' ? 'proxmox' : 'ssh') : props.initialSource ?? null)
const draftId = ref<string | null>(resume?.kind === 'draft' ? resume.id : null)
const proxmoxId = ref<string | null>(resume?.kind === 'proxmox' ? resume.id : null)
const sshPrefill = ref<{ host: string, name: string, description: string } | null>(null)
const draftStep = ref<DraftStep | 'added' | null>(null)
const proxmoxStep = ref<'connect' | 'verify' | 'preview'>('connect')
const guestStep = ref<'pick' | 'link'>('pick')

const SOURCES: { value: Source | 'lab', title: string, text: string }[] = [
  { value: 'tailscale', title: 'From Tailscale', text: 'Pick a device on your tailnet.' },
  { value: 'ssh', title: 'Machine over SSH', text: 'Any Linux host, laptop, or Raspberry Pi by address or name.' },
  { value: 'proxmox', title: 'Proxmox server', text: 'Connect a PVE cluster: API token and pinned TLS.' },
  { value: 'guest', title: 'Existing VM / LXC', text: 'Adopt a discovered guest or link it to a machine.' },
  { value: 'lab', title: 'Lab environment', text: 'Disposable and TTL-bound. Opens Lab.' },
]

function pick(value: Source | 'lab') {
  if (value === 'lab') {
    // Leaving the route closes the dialog.
    router.push('/lab')
    return
  }
  source.value = value
}

// Pending durable work the operator can pick up again.
const draftsQuery = useQuery({
  queryKey: ['add', 'drafts'],
  queryFn: async () => {
    const response = await listOnboardingDrafts({ limit: 50 })
    if (response.status !== 200)
      throw new Error(`listOnboardingDrafts failed (${response.status})`)
    return response.data.items as OnboardingDraftDto[]
  },
  enabled: computed(() => source.value === null),
})
const accountsQuery = useQuery({
  queryKey: ['fleet', 'proxmox-accounts'],
  queryFn: async () => {
    const response = await listProxmoxAccounts({ limit: 200 })
    if (response.status !== 200)
      throw new Error(`listProxmoxAccounts failed (${response.status})`)
    return response.data.items as ProxmoxAccountDto[]
  },
  enabled: computed(() => source.value === null),
})
const unconfirmedAccounts = computed(() => (accountsQuery.data.value ?? []).filter(a => a.fingerprintState !== 'confirmed'))

function resumeDraft(id: string) {
  source.value = 'ssh'
  onDraftCreated(id)
}

function resumeAccount(id: string) {
  source.value = 'proxmox'
  onAccountCreated(id)
}

function onDraftCreated(id: string) {
  draftId.value = id
  saveResume({ kind: 'draft', id })
}

function onAccountCreated(id: string) {
  proxmoxId.value = id
  saveResume({ kind: 'proxmox', id })
}

function onGuestOnboard(prefill: { host: string, name: string, description: string }) {
  sshPrefill.value = prefill
  source.value = 'ssh'
}

function finished() {
  clearResume()
}

function onProxmoxStep(step: 'connect' | 'verify' | 'preview') {
  proxmoxStep.value = step
  if (step === 'preview')
    clearResume()
}

function startOver() {
  clearResume()
  source.value = null
  draftId.value = null
  proxmoxId.value = null
  sshPrefill.value = null
  draftStep.value = null
  guestStep.value = 'pick'
}

const rail = computed(() => {
  if (source.value === 'proxmox') {
    const steps = ['Source', 'Connect', 'Verify TLS', 'Preview']
    return { steps, current: { connect: 1, verify: 2, preview: 3 }[proxmoxStep.value], done: proxmoxStep.value === 'preview' }
  }
  if (source.value === 'guest')
    return { steps: ['Source', 'Pick guest', 'Link or onboard'], current: guestStep.value === 'pick' ? 1 : 2, done: false }
  const steps = ['Source', 'Connect', 'Verify identity', 'Discover', 'Name & manage']
  if (source.value === null)
    return { steps, current: 0, done: false }
  const index = { test: 1, verify: 2, discover: 3, finish: 4, added: 4 }
  return { steps, current: draftId.value && draftStep.value ? index[draftStep.value] : 1, done: draftStep.value === 'added' }
})

const title = computed(() => {
  switch (source.value) {
    case null: return 'What are you adding?'
    case 'tailscale': return draftId.value ? 'Onboard tailnet device' : 'Pick a tailnet device'
    case 'ssh': return draftId.value ? 'Onboard machine' : 'Machine over SSH'
    case 'proxmox': return 'Proxmox server'
    case 'guest': return 'Existing VM / LXC'
  }
  return ''
})
</script>

<template>
  <Dialog v-model:open="open">
    <DialogContent
      class="grid max-h-[90vh] grid-cols-[170px_minmax(0,1fr)] gap-0 overflow-hidden rounded-sm border-fc-line2 bg-fc-panel p-0 sm:max-w-3xl"
      data-testid="add-dialog"
    >
      <nav
        class="flex flex-col gap-0.5 border-r border-fc-line px-3 py-4"
        aria-label="Steps"
      >
        <div
          v-for="(label, index) in rail.steps"
          :key="label"
          class="flex items-center gap-2 px-1 py-1.5 text-[12.5px]"
          :class="index < rail.current || (rail.done && index === rail.current) ? 'text-fc-muted' : index === rail.current ? 'font-semibold text-fc-ink' : 'text-fc-faint'"
          :aria-current="index === rail.current ? 'step' : undefined"
        >
          <span
            class="grid size-[18px] place-items-center rounded-full font-mono text-[10px]"
            :class="index < rail.current || (rail.done && index === rail.current) ? 'bg-fc-muted text-background' : index === rail.current ? 'fc-grad-bg text-white' : 'border border-fc-line2'"
          >{{ index < rail.current || (rail.done && index === rail.current) ? '✓' : index + 1 }}</span>
          {{ label }}
        </div>
      </nav>

      <div class="flex min-h-[470px] min-w-0 flex-col overflow-y-auto p-5">
        <DialogTitle class="text-[17px] font-extrabold text-fc-ink">
          {{ title }}
        </DialogTitle>
        <DialogDescription class="mb-4 mt-0.5 text-xs text-fc-muted">
          Every path creates durable controller state, so you can close this dialog and resume later.
        </DialogDescription>

        <template v-if="source === null">
          <div class="grid grid-cols-2 gap-2">
            <button
              v-for="tile in SOURCES"
              :key="tile.value"
              type="button"
              class="rounded-sm border border-fc-line2 p-3 text-left hover:border-fc-ink focus-visible:border-fc-ink"
              :data-testid="`source-${tile.value}`"
              @click="pick(tile.value)"
            >
              <b class="block text-[13px] text-fc-ink">{{ tile.title }}</b>
              <span class="text-[11.5px] leading-snug text-fc-muted">{{ tile.text }}</span>
            </button>
          </div>

          <section
            v-if="(draftsQuery.data.value ?? []).length > 0 || unconfirmedAccounts.length > 0"
            class="mt-5 space-y-1.5"
          >
            <h4 class="fc-kicker">
              Resume
            </h4>
            <button
              v-for="draft in draftsQuery.data.value ?? []"
              :key="draft.id"
              type="button"
              class="flex w-full items-center gap-2 rounded-sm border border-fc-line p-2 text-left text-xs hover:border-fc-line2"
              :data-testid="`resume-draft-${draft.id}`"
              @click="resumeDraft(draft.id)"
            >
              <span class="text-fc-ink">{{ draft.name }}</span>
              <span class="font-mono text-fc-faint">{{ draft.endpoint.host }}:{{ draft.endpoint.port }}</span>
              <span class="ml-auto font-mono uppercase text-fc-muted">draft · {{ draft.stage }} · host key {{ draft.hostKeyStage }}</span>
            </button>
            <button
              v-for="account in unconfirmedAccounts"
              :key="account.id"
              type="button"
              class="flex w-full items-center gap-2 rounded-sm border border-fc-line p-2 text-left text-xs hover:border-fc-line2"
              :data-testid="`resume-pve-${account.id}`"
              @click="resumeAccount(account.id)"
            >
              <span class="text-fc-ink">{{ account.name }}</span>
              <span class="font-mono text-fc-faint">{{ account.host }}:{{ account.port }}</span>
              <span class="ml-auto font-mono uppercase text-fc-warn">Proxmox · TLS {{ account.fingerprintState }}</span>
            </button>
          </section>
        </template>

        <template v-else>
          <DraftFlow
            v-if="draftId"
            :key="draftId"
            :draft-id="draftId"
            @step="draftStep = $event"
            @added="draftStep = 'added'; finished()"
            @cancelled="startOver"
          />
          <TailscaleSource
            v-else-if="source === 'tailscale'"
            :initial-device="initialDevice"
            @created="onDraftCreated"
          />
          <SshSource
            v-else-if="source === 'ssh'"
            :initial-host="sshPrefill?.host"
            :initial-name="sshPrefill?.name"
            :description="sshPrefill?.description"
            @created="onDraftCreated"
          />
          <ProxmoxSource
            v-else-if="source === 'proxmox'"
            :account-id="proxmoxId"
            @created="onAccountCreated"
            @step="onProxmoxStep"
            @discarded="startOver"
          />
          <GuestSource
            v-else-if="source === 'guest'"
            @step="guestStep = $event"
            @onboard="onGuestOnboard"
          />

          <div
            v-if="!draftId && !proxmoxId"
            class="mt-4"
          >
            <button
              type="button"
              class="font-mono text-[10px] uppercase tracking-wider text-fc-faint hover:text-fc-ink"
              data-testid="back-to-sources"
              @click="startOver"
            >
              ← Sources
            </button>
          </div>
          <div
            v-else-if="draftStep === 'added' || proxmoxStep === 'preview'"
            class="mt-4"
          >
            <button
              type="button"
              class="font-mono text-[10px] uppercase tracking-wider text-fc-faint hover:text-fc-ink"
              data-testid="add-another"
              @click="startOver"
            >
              Add another
            </button>
          </div>
        </template>
      </div>
    </DialogContent>
  </Dialog>
</template>
