<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { RouterLink } from 'vue-router'

import type { ActionRequestDto, SiteTemplateDto } from '@frogbyte-io/fleet-api-client'
import StatusChip from '@/components/fleet/StatusChip.vue'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'

import { errorMessage } from '../../machine/api'
import CopyFleetctl from '../../machine/components/CopyFleetctl.vue'
import FiledRequest from '../components/FiledRequest.vue'
import { useFiledRequest } from '../useServiceSettings'
import {
  blankDraft,
  branchProblem,
  buildBody,
  defaultName,
  deployCommand,
  domainProblem,
  draftProblem,
  environmentsOf,
  hostOf,
  nameProblem,
  plannedSteps,
  registryPatch,
  repositoryProblem,
} from './newSite'
import { useCoolifyAccounts, useCoolifyObservation, useDeployResult, useDeploySite, useSiteTemplates } from './useNewSite'

// Deploy a new site from a template: one brokered action request that creates
// the Coolify resource, sets the domain, and starts the first deployment. The
// console decides nothing: the controller checks the template pin, the target,
// and the domain, applies policy (a deploy waits for approval by default), and
// records what each step did. Everything shown here is what the public API and
// `fleetctl services deploy` report too.
const templates = useSiteTemplates()
const accounts = useCoolifyAccounts()
const deploy = useDeploySite()

const step = ref<1 | 2 | 3>(1)
const chosenId = ref('')
const draft = ref(blankDraft())
const touched = ref(false)
const filed = ref<ActionRequestDto | null>(null)
const error = ref('')

const chosen = computed<SiteTemplateDto | null>(() => templates.data.value?.find(t => t.id === chosenId.value) ?? null)
const observation = useCoolifyObservation(() => draft.value.accountId)
const environments = computed(() => environmentsOf(observation.data.value, draft.value.projectUuid))

// With one Coolify account there is nothing to choose.
watch(() => accounts.data.value, (items) => {
  if (items?.length === 1 && draft.value.accountId === '')
    draft.value.accountId = items[0]!.id
}, { immediate: true })
// A different account, server, or project invalidates what hangs below it.
watch(() => draft.value.accountId, () => {
  draft.value.serverUuid = ''
  draft.value.projectUuid = ''
  draft.value.environmentName = ''
})
watch(() => draft.value.projectUuid, () => {
  const names = environments.value
  draft.value.environmentName = names.includes('production') ? 'production' : (names.length === 1 ? names[0]! : '')
})

const problem = computed(() => draftProblem(draft.value, chosen.value))
const domainError = computed(() => (draft.value.domain === '' && !touched.value ? null : domainProblem(draft.value.domain)))
const nameError = computed(() => nameProblem(draft.value.name))
const repoError = computed(() => (draft.value.repository === '' && !touched.value ? null : repositoryProblem(draft.value.repository)))
const branchError = computed(() => branchProblem(draft.value.branch))
const namePlaceholder = computed(() => defaultName(draft.value.domain) || 'blog-example-org')
const steps = computed(() => (chosen.value ? plannedSteps(chosen.value, draft.value.domain) : []))
const command = computed(() => (chosen.value && !problem.value ? deployCommand(draft.value, chosen.value) : null))

function choose(template: SiteTemplateDto) {
  chosenId.value = template.id
}

function next() {
  touched.value = true
  if (step.value === 1 && chosen.value)
    step.value = 2
  else if (step.value === 2 && !problem.value)
    step.value = 3
}

async function submit() {
  if (!chosen.value || problem.value)
    return
  error.value = ''
  try {
    filed.value = await deploy.mutateAsync(buildBody(draft.value, chosen.value))
  }
  catch (caught) {
    error.value = errorMessage(caught)
  }
}

function reset() {
  filed.value = null
  draft.value = blankDraft()
  chosenId.value = ''
  touched.value = false
  step.value = 1
  if (accounts.data.value?.length === 1)
    draft.value.accountId = accounts.data.value[0]!.id
}

// The request, kept fresh until it settles, and the operation behind it.
const live = useFiledRequest(() => filed.value?.id ?? null)
const current = computed(() => live.data.value ?? filed.value)
const result = useDeployResult(() => current.value?.operationId)
const outcome = computed(() => result.data.value?.result ?? null)
const patch = computed(() => (outcome.value?.outcome === 'deployed' ? registryPatch(outcome.value) : []))
const failedWithoutResult = computed(() => current.value?.state === 'failed' && !outcome.value && !result.isFetching.value)

function stepTone(status: string): 'ok' | 'err' | 'warn' | 'faint' {
  if (status === 'done' || status === 'reused')
    return 'ok'
  if (status === 'failed')
    return 'err'
  if (status === 'pending')
    return 'warn'
  return 'faint'
}
</script>

<template>
  <div
    class="mx-auto max-w-3xl"
    data-testid="new-site-page"
  >
    <RouterLink
      to="/services"
      class="font-mono text-[10px] uppercase tracking-wider text-fc-faint hover:text-fc-ink"
      data-testid="back-to-services"
    >
      ← Services
    </RouterLink>
    <p class="fc-kicker mt-3">
      new site · coolify · needs approval
    </p>
    <h1 class="fc-h1 mt-1">
      Deploy a site
    </h1>
    <p class="mt-2 max-w-prose text-xs text-fc-muted">
      A template creates the Coolify resource, sets the domain, and starts the first deployment. Coolify builds and runs it; Fleet files one request that a person approves.
    </p>

    <!-- The request this page filed, then its result. -->
    <section
      v-if="filed"
      class="mt-6 space-y-3"
      data-testid="deploy-filed"
    >
      <FiledRequest
        :request="filed"
        @dismiss="reset"
      />
      <div
        v-if="outcome"
        class="space-y-2 border border-fc-line bg-card px-3 py-2 text-xs"
        data-testid="deploy-result"
      >
        <div class="flex flex-wrap items-center gap-2">
          <StatusChip
            :label="outcome.outcome"
            :tone="outcome.outcome === 'deployed' ? 'ok' : 'err'"
          />
          <span class="font-mono text-[11px] text-fc-ink">{{ outcome.resourceKind }} {{ outcome.uuid }}</span>
          <RouterLink
            :to="`/services/${encodeURIComponent(outcome.serviceId)}`"
            class="ml-auto font-mono text-[10px] uppercase tracking-wider text-fc-info hover:underline"
            data-testid="open-service"
          >
            Open the service →
          </RouterLink>
        </div>
        <ol class="grid gap-1">
          <li
            v-for="s in outcome.steps"
            :key="s.step"
            class="flex flex-wrap items-center gap-2"
            data-testid="result-step"
          >
            <StatusChip
              :label="s.status"
              :tone="stepTone(s.status)"
            />
            <span class="font-mono text-[11px] text-fc-ink">{{ s.step }}</span>
            <span class="text-fc-muted">{{ s.detail }}</span>
          </li>
        </ol>
        <p
          v-if="outcome.error"
          class="border-l-2 border-l-fc-err pl-2 text-fc-muted"
          data-testid="result-error"
        >
          Stopped: {{ outcome.error }}. The resource exists in Coolify; finish there, or re-run the approved request.
        </p>
        <p
          v-if="outcome.followUpEnvKeys.length > 0"
          class="text-fc-muted"
        >
          Set these variables next: {{ outcome.followUpEnvKeys.join(', ') }} (Open the service, Settings).
        </p>
      </div>
      <p
        v-else-if="failedWithoutResult"
        class="border-l-2 border-l-fc-err bg-card px-3 py-2 text-xs text-fc-muted"
        data-testid="result-none"
      >
        The deployment failed before anything was created. Nothing needs cleaning up in Coolify.
      </p>
      <div
        v-if="patch.length > 0"
        data-testid="registry-patch"
      >
        <p class="mb-1 text-xs text-fc-muted">
          Record the new site in the Registry, in a Fleet Git checkout:
        </p>
        <CopyFleetctl :command="patch.join('\n')" />
      </div>
    </section>

    <template v-else>
      <ol
        class="mt-6 flex items-center gap-2 font-mono text-[10px] uppercase tracking-wider"
        data-testid="steps"
        aria-label="Steps"
      >
        <li
          v-for="(label, index) in ['Template', 'Target', 'Review']"
          :key="label"
          class="flex items-center gap-2"
          :class="step === index + 1 ? 'text-fc-ink' : 'text-fc-faint'"
          :aria-current="step === index + 1 ? 'step' : undefined"
        >
          <span
            class="grid size-5 place-items-center rounded-full border"
            :class="step === index + 1 ? 'border-fc-ink' : 'border-fc-line2'"
          >{{ index + 1 }}</span>{{ label }}
          <span
            v-if="index < 2"
            class="text-fc-line2"
          >—</span>
        </li>
      </ol>

      <!-- 1. Template -->
      <section
        v-if="step === 1"
        class="mt-4"
        data-testid="step-template"
      >
        <div
          v-if="templates.isPending.value"
          class="grid gap-2 sm:grid-cols-2"
        >
          <Skeleton class="h-24" />
          <Skeleton class="h-24" />
        </div>
        <p
          v-else-if="templates.error.value"
          class="border-l-2 border-l-fc-err bg-card px-3 py-2 text-xs text-fc-muted"
          role="alert"
          data-testid="templates-error"
        >
          Could not load the templates: {{ errorMessage(templates.error.value) }}
        </p>
        <div
          v-else
          class="grid gap-2 sm:grid-cols-2"
          role="radiogroup"
          aria-label="Template"
        >
          <button
            v-for="template in templates.data.value"
            :key="template.id"
            type="button"
            role="radio"
            :aria-checked="chosenId === template.id"
            class="flex flex-col gap-1.5 border bg-card px-3 py-3 text-left transition-colors hover:border-fc-line2 focus-visible:outline-none focus-visible:ring-3 focus-visible:ring-ring/50"
            :class="chosenId === template.id ? 'border-fc-info' : 'border-fc-line'"
            :data-testid="`template-${template.id}`"
            @click="choose(template)"
          >
            <span class="flex items-center gap-2">
              <span class="text-sm font-medium text-fc-ink">{{ template.name }}</span>
              <StatusChip
                :label="template.source.kind === 'service' ? 'one-click service' : 'git repository'"
                tone="muted"
              />
            </span>
            <span class="text-xs text-fc-muted">{{ template.description }}</span>
            <span class="font-mono text-[10px] text-fc-faint">v{{ template.version }} · {{ template.digest.slice(0, 12) }}</span>
          </button>
        </div>
      </section>

      <!-- 2. Target -->
      <section
        v-else-if="step === 2 && chosen"
        class="mt-4 grid gap-3"
        data-testid="step-target"
      >
        <p
          v-if="accounts.data.value && accounts.data.value.length === 0"
          class="border-l-2 border-l-fc-warn bg-card px-3 py-2 text-xs text-fc-muted"
          data-testid="no-account"
        >
          No Coolify account is registered yet. Add one in Settings, then run a discovery so servers and projects can be chosen.
        </p>
        <div class="grid gap-3 sm:grid-cols-2">
          <label
            v-if="(accounts.data.value?.length ?? 0) > 1"
            class="grid gap-1 sm:col-span-2"
          >
            <span class="fc-kicker">Coolify account</span>
            <select
              v-model="draft.accountId"
              class="h-8 rounded-sm border border-input bg-background px-2 text-xs text-foreground"
              data-testid="account"
            >
              <option value="">Choose…</option>
              <option
                v-for="account in accounts.data.value"
                :key="account.id"
                :value="account.id"
              >{{ account.label }}</option>
            </select>
          </label>
          <label class="grid gap-1">
            <span class="fc-kicker">Server</span>
            <select
              v-model="draft.serverUuid"
              class="h-8 rounded-sm border border-input bg-background px-2 text-xs text-foreground"
              :disabled="!observation.data.value"
              data-testid="server"
            >
              <option value="">Choose…</option>
              <option
                v-for="server in observation.data.value?.servers"
                :key="server.uuid"
                :value="server.uuid"
              >{{ server.name }}</option>
            </select>
          </label>
          <label class="grid gap-1">
            <span class="fc-kicker">Project</span>
            <select
              v-model="draft.projectUuid"
              class="h-8 rounded-sm border border-input bg-background px-2 text-xs text-foreground"
              :disabled="!observation.data.value"
              data-testid="project"
            >
              <option value="">Choose…</option>
              <option
                v-for="project in observation.data.value?.projects"
                :key="project.uuid"
                :value="project.uuid"
              >{{ project.name }}</option>
            </select>
          </label>
          <label class="grid gap-1">
            <span class="fc-kicker">Environment</span>
            <select
              v-model="draft.environmentName"
              class="h-8 rounded-sm border border-input bg-background px-2 text-xs text-foreground"
              :disabled="environments.length === 0"
              data-testid="environment"
            >
              <option value="">Choose…</option>
              <option
                v-for="name in environments"
                :key="name"
                :value="name"
              >{{ name }}</option>
            </select>
          </label>
          <label class="grid gap-1">
            <span class="fc-kicker">Domain</span>
            <input
              v-model="draft.domain"
              class="h-8 rounded-sm border border-input bg-transparent px-3 font-mono text-xs outline-none focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50"
              placeholder="blog.example.org"
              spellcheck="false"
              autocomplete="off"
              data-testid="domain"
            >
            <span
              v-if="domainError"
              class="text-[11px] text-fc-warn"
              data-testid="domain-problem"
            >{{ domainError }}</span>
          </label>
        </div>
        <p
          v-if="accounts.data.value?.length && observation.error.value"
          class="border-l-2 border-l-fc-err bg-card px-3 py-2 text-xs text-fc-muted"
          role="alert"
          data-testid="observation-error"
        >
          Could not read the account's servers and projects: {{ errorMessage(observation.error.value) }}. Run a discovery for this account first.
        </p>
        <template v-if="chosen.needsRepository">
          <div class="grid gap-3 sm:grid-cols-[2fr_1fr]">
            <label class="grid gap-1">
              <span class="fc-kicker">Public repository</span>
              <input
                v-model="draft.repository"
                class="h-8 rounded-sm border border-input bg-transparent px-3 font-mono text-xs outline-none focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50"
                placeholder="https://github.com/owner/site"
                spellcheck="false"
                autocomplete="off"
                data-testid="repository"
              >
              <span
                v-if="repoError"
                class="text-[11px] text-fc-warn"
                data-testid="repository-problem"
              >{{ repoError }}</span>
            </label>
            <label class="grid gap-1">
              <span class="fc-kicker">Branch</span>
              <input
                v-model="draft.branch"
                class="h-8 rounded-sm border border-input bg-transparent px-3 font-mono text-xs outline-none focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50"
                spellcheck="false"
                autocomplete="off"
                data-testid="branch"
              >
              <span
                v-if="branchError"
                class="text-[11px] text-fc-warn"
              >{{ branchError }}</span>
            </label>
          </div>
          <p class="text-[11px] text-fc-faint">
            Only public https repositories are supported. Private repositories need a credential path Fleet does not have yet.
          </p>
        </template>
        <label class="grid gap-1">
          <span class="fc-kicker">Resource name (optional)</span>
          <input
            v-model="draft.name"
            class="h-8 rounded-sm border border-input bg-transparent px-3 font-mono text-xs outline-none focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50"
            :placeholder="namePlaceholder"
            spellcheck="false"
            autocomplete="off"
            data-testid="name"
          >
          <span
            v-if="nameError"
            class="text-[11px] text-fc-warn"
          >{{ nameError }}</span>
        </label>
        <p
          v-if="touched && problem"
          class="text-[11px] text-fc-warn"
          role="status"
          data-testid="target-problem"
        >
          {{ problem }}
        </p>
      </section>

      <!-- 3. Review -->
      <section
        v-else-if="step === 3 && chosen"
        class="mt-4 grid gap-3"
        data-testid="step-review"
      >
        <div class="border border-fc-line bg-card px-3 py-3">
          <p class="text-sm font-medium text-fc-ink">
            {{ chosen.name }} at https://{{ hostOf(draft.domain) }}
          </p>
          <ol class="mt-2 grid list-decimal gap-1 pl-5 text-xs text-fc-muted">
            <li
              v-for="line in steps"
              :key="line"
              data-testid="planned-step"
            >
              {{ line }}
            </li>
          </ol>
          <p
            v-if="chosen.followUpEnvKeys.length > 0"
            class="mt-2 text-xs text-fc-muted"
          >
            Afterwards set: {{ chosen.followUpEnvKeys.join(', ') }}.
          </p>
        </div>
        <label class="grid gap-1">
          <span class="fc-kicker">Reason for the approver (optional)</span>
          <input
            v-model="draft.reason"
            maxlength="1000"
            class="h-8 rounded-sm border border-input bg-transparent px-3 text-xs outline-none focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50"
            data-testid="reason"
          >
        </label>
        <p class="text-[11px] text-fc-faint">
          This files one request and needs approval. Until it is approved, nothing is created in Coolify. DNS is not changed here: point the domain at the server with <code class="font-mono">fleetctl services deploy --dns</code> or in your DNS provider.
        </p>
        <CopyFleetctl :command="command" />
        <p
          v-if="error"
          class="border-l-2 border-l-fc-err bg-card px-3 py-2 text-xs text-fc-muted"
          role="alert"
          data-testid="deploy-error"
        >
          Could not file the request: {{ error }}
        </p>
      </section>

      <div class="mt-5 flex items-center gap-2">
        <Button
          v-if="step > 1"
          type="button"
          variant="outline"
          size="sm"
          data-testid="back"
          @click="step = step === 3 ? 2 : 1"
        >
          Back
        </Button>
        <Button
          v-if="step < 3"
          type="button"
          size="sm"
          :disabled="step === 1 && !chosen"
          data-testid="next"
          @click="next"
        >
          Next
        </Button>
        <Button
          v-else
          type="button"
          size="sm"
          :disabled="Boolean(problem) || deploy.isPending.value"
          data-testid="file-request"
          @click="submit"
        >
          File deploy request
        </Button>
      </div>
    </template>
  </div>
</template>
