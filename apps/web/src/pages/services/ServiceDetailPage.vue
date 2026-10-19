<script setup lang="ts">
import { computed } from 'vue'
import { RouterLink, useRoute, useRouter } from 'vue-router'

import StatusChip from '@/components/fleet/StatusChip.vue'
import { Skeleton } from '@/components/ui/skeleton'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'

import { ApiRequestError, errorMessage } from '../machine/api'
import { safeHref } from '../registry/registry'
import CoverageNotes from './components/CoverageNotes.vue'
import ServiceActions from './components/ServiceActions.vue'
import ServiceSettings from './components/ServiceSettings.vue'
import {
  coverageNotes,
  deployView,
  fqdnHref,
  placementView,
  projectLabel,
  registryLinkTo,
  serverBasisLabel,
  serverLabel,
  sourceLabel,
  staleReason,
  statusView,
} from './services'
import { useService } from './useServices'

// One running service: status, where it runs, hostnames, last deploy, the
// Registry entries that relate to it, and a link into Coolify. The read is
// of cached observations; the lifecycle buttons (ServiceActions, FM-1033) and
// the Settings tab (FM-1034) only file brokered requests.
const route = useRoute()
const router = useRouter()
const id = computed(() => String(route.params.id ?? ''))
const query = useService(id)

const service = computed(() => query.data.value?.service ?? null)
const status = computed(() => (service.value ? statusView(service.value) : null))
const placement = computed(() => (service.value ? placementView(service.value) : null))
const deploy = computed(() => (service.value ? deployView(service.value) : null))
const notes = computed(() => (query.data.value ? coverageNotes(query.data.value.coverage) : []))
const deepLink = computed(() => (service.value?.deepLink ? safeHref(service.value.deepLink) : null))
const notFound = computed(() => query.error.value instanceof ApiRequestError && query.error.value.status === 404)

const TABS = [
  { value: 'overview', label: 'Overview' },
  { value: 'settings', label: 'Settings' },
] as const
const tab = computed({
  get: () => {
    const requested = route.query.tab
    return typeof requested === 'string' && TABS.some(t => t.value === requested) ? requested : 'overview'
  },
  set: (value: string) => {
    router.replace({ query: { ...route.query, tab: value === 'overview' ? undefined : value } })
  },
})

const labelClass = 'w-28 shrink-0 font-mono text-[10px] uppercase tracking-wider text-fc-faint'
const panelClass = 'rounded-sm border border-fc-line bg-fc-panel p-4'
</script>

<template>
  <div>
    <RouterLink
      to="/services"
      class="font-mono text-[10px] uppercase tracking-wider text-fc-info hover:text-fc-ink"
      data-testid="back-to-services"
    >
      ← Services
    </RouterLink>

    <div
      v-if="query.isLoading.value"
      class="mt-4 grid gap-3"
    >
      <Skeleton class="h-10 w-64 rounded-sm" />
      <Skeleton class="h-40 rounded-sm" />
    </div>

    <div
      v-else-if="notFound"
      class="mt-4 rounded-sm border border-fc-line bg-fc-panel p-6 text-sm text-fc-muted"
      data-testid="service-not-found"
    >
      This service is not observed any more. It may have been deleted in Coolify, or the observation that listed it was replaced.
    </div>

    <div
      v-else-if="query.error.value"
      class="mt-4 border-l-2 border-l-fc-err bg-card px-3 py-2 text-xs text-fc-muted"
      role="alert"
    >
      Could not load this service: {{ errorMessage(query.error.value) }}
    </div>

    <template v-else-if="service && status && placement">
      <div class="mt-3 flex flex-wrap items-end justify-between gap-3">
        <div class="min-w-0">
          <p class="fc-kicker">
            {{ service.kind }} · {{ sourceLabel(service) }}
          </p>
          <h1
            class="fc-h1 mt-1 break-words"
            data-testid="service-name"
          >
            {{ service.name }}
          </h1>
        </div>
        <div class="flex flex-wrap items-center gap-3">
          <StatusChip
            :label="status.label"
            :tone="status.tone"
            data-testid="service-status"
          />
          <a
            v-if="deepLink"
            :href="deepLink"
            target="_blank"
            rel="noopener noreferrer"
            class="rounded-sm border border-input px-3 py-1.5 font-mono text-[10px] uppercase tracking-wider text-fc-muted hover:border-fc-line2 hover:text-fc-ink"
            data-testid="coolify-link"
          >
            Open in Coolify ↗
          </a>
        </div>
      </div>

      <div class="mt-3">
        <ServiceActions :service="service" />
      </div>

      <div
        v-if="service.stale"
        class="mt-4 border-l-2 border-l-fc-warn bg-card px-3 py-2 text-xs text-fc-muted"
        role="status"
        data-testid="stale-banner"
      >
        <p class="font-semibold text-fc-ink">
          Stale data: this is the last known state, not a current one.
        </p>
        <ul
          v-if="service.staleReasons.length > 0"
          class="mt-1 list-disc pl-4"
        >
          <li
            v-for="reason in service.staleReasons"
            :key="reason"
          >
            {{ staleReason(reason) }}
          </li>
        </ul>
      </div>
      <CoverageNotes :notes="notes" />

      <Tabs
        v-model="tab"
        class="mt-4"
      >
        <TabsList class="h-auto w-full justify-start gap-1 overflow-x-auto rounded-sm border-b border-fc-line bg-transparent p-0">
          <TabsTrigger
            v-for="t in TABS"
            :key="t.value"
            :value="t.value"
            class="flex-none rounded-none border-0 border-b-2 border-transparent px-3 py-2 font-mono text-[11px] uppercase tracking-wider text-fc-muted data-[state=active]:border-fc-ink data-[state=active]:bg-transparent data-[state=active]:text-fc-ink data-[state=active]:shadow-none"
            :data-testid="`tab-${t.value}`"
          >
            {{ t.label }}
          </TabsTrigger>
        </TabsList>
        <TabsContent value="overview">
          <div class="mt-4 grid gap-3 lg:grid-cols-2">
            <section
              :class="panelClass"
              aria-labelledby="where-heading"
            >
              <h2
                id="where-heading"
                class="fc-kicker border-b border-fc-line pb-1"
              >
                Where it runs
              </h2>
              <dl class="mt-3 grid gap-2 text-xs">
                <div class="flex gap-2">
                  <dt :class="labelClass">
                    Server
                  </dt>
                  <dd class="min-w-0 break-words text-fc-muted">
                    {{ serverLabel(service) }}
                    <span
                      v-if="service.server"
                      class="text-fc-faint"
                    >· {{ serverBasisLabel(service.serverBasis) }}</span>
                  </dd>
                </div>
                <div class="flex gap-2">
                  <dt :class="labelClass">
                    Fleet machine
                  </dt>
                  <dd
                    class="min-w-0 break-words"
                    :class="placement.state === 'ambiguous' ? 'text-fc-warn' : 'text-fc-muted'"
                    data-testid="service-placement"
                  >
                    <RouterLink
                      v-if="placement.machine"
                      :to="`/fleet/machines/${encodeURIComponent(placement.machine.id)}`"
                      class="text-fc-info hover:underline"
                    >
                      {{ placement.label }}
                    </RouterLink>
                    <template v-else>
                      {{ placement.label }}
                    </template>
                    <span class="text-fc-faint"> · {{ placement.detail }}</span>
                    <ul
                      v-if="placement.candidates.length > 0"
                      class="mt-1 grid gap-0.5"
                    >
                      <li
                        v-for="candidate in placement.candidates"
                        :key="candidate.id"
                      >
                        <RouterLink
                          :to="`/fleet/machines/${encodeURIComponent(candidate.id)}`"
                          class="text-fc-info hover:underline"
                        >
                          {{ candidate.name }}
                        </RouterLink>
                      </li>
                    </ul>
                  </dd>
                </div>
                <div class="flex gap-2">
                  <dt :class="labelClass">
                    Project
                  </dt>
                  <dd class="min-w-0 break-words text-fc-muted">
                    {{ projectLabel(service) }}
                  </dd>
                </div>
              </dl>
            </section>

            <section
              :class="panelClass"
              aria-labelledby="coolify-heading"
            >
              <h2
                id="coolify-heading"
                class="fc-kicker border-b border-fc-line pb-1"
              >
                Coolify
              </h2>
              <dl
                v-if="service.coolify"
                class="mt-3 grid gap-2 text-xs"
              >
                <div class="flex gap-2">
                  <dt :class="labelClass">
                    Account
                  </dt>
                  <dd class="min-w-0 break-words text-fc-muted">
                    {{ service.coolify.accountLabel }}
                  </dd>
                </div>
                <div class="flex gap-2">
                  <dt :class="labelClass">
                    Status
                  </dt>
                  <dd class="min-w-0 break-words font-mono text-[11px] text-fc-muted">
                    {{ service.coolify.status ?? 'not reported' }}
                  </dd>
                </div>
                <div
                  v-if="service.coolify.detail"
                  class="flex gap-2"
                >
                  <dt :class="labelClass">
                    Image / type
                  </dt>
                  <dd class="min-w-0 break-all font-mono text-[11px] text-fc-muted">
                    {{ service.coolify.detail }}
                  </dd>
                </div>
                <div class="flex gap-2">
                  <dt :class="labelClass">
                    Resource
                  </dt>
                  <dd class="min-w-0 break-all font-mono text-[11px] text-fc-muted">
                    {{ service.coolify.uuid }}
                  </dd>
                </div>
              </dl>
              <p
                v-else
                class="mt-3 text-xs text-fc-faint"
              >
                Not a Coolify resource: observed from Docker only.
              </p>
            </section>

            <section
              :class="panelClass"
              aria-labelledby="hosts-heading"
            >
              <h2
                id="hosts-heading"
                class="fc-kicker border-b border-fc-line pb-1"
              >
                Hostnames
              </h2>
              <ul
                v-if="service.fqdns.length > 0"
                class="mt-3 grid gap-1 text-xs"
                data-testid="service-fqdns"
              >
                <li
                  v-for="fqdn in service.fqdns"
                  :key="fqdn"
                  class="break-all font-mono text-[11px]"
                >
                  <a
                    v-if="fqdnHref(fqdn)"
                    :href="fqdnHref(fqdn)!"
                    target="_blank"
                    rel="noopener noreferrer"
                    class="text-fc-info hover:underline"
                  >{{ fqdn }}</a>
                  <span
                    v-else
                    class="text-fc-muted"
                  >{{ fqdn }}</span>
                </li>
              </ul>
              <p
                v-else
                class="mt-3 text-xs text-fc-faint"
              >
                No public hostnames reported.
              </p>
              <p
                v-if="service.staleReasons.includes('fqdns_stale')"
                class="mt-2 text-[11px] text-fc-warn"
              >
                These hostnames are from an older read.
              </p>
            </section>

            <section
              :class="panelClass"
              aria-labelledby="deploy-heading"
            >
              <h2
                id="deploy-heading"
                class="fc-kicker border-b border-fc-line pb-1"
              >
                Last deploy
              </h2>
              <dl
                v-if="service.lastDeploy && deploy"
                class="mt-3 grid gap-2 text-xs"
                data-testid="service-deploy"
              >
                <div class="flex gap-2">
                  <dt :class="labelClass">
                    Status
                  </dt>
                  <dd>
                    <StatusChip
                      :label="deploy.label"
                      :tone="deploy.tone"
                    />
                  </dd>
                </div>
                <div
                  v-if="service.lastDeploy.commit"
                  class="flex gap-2"
                >
                  <dt :class="labelClass">
                    Commit
                  </dt>
                  <dd class="min-w-0 break-all font-mono text-[11px] text-fc-muted">
                    {{ service.lastDeploy.commit }}
                  </dd>
                </div>
                <div
                  v-if="service.lastDeploy.at"
                  class="flex gap-2"
                >
                  <dt :class="labelClass">
                    At
                  </dt>
                  <dd class="min-w-0 break-words font-mono text-[11px] text-fc-muted">
                    {{ service.lastDeploy.at }}
                  </dd>
                </div>
              </dl>
              <p
                v-else
                class="mt-3 text-xs text-fc-faint"
              >
                No deployment is known{{ service.kind === 'application' ? '' : ' (only applications are deployed from source)' }}.
              </p>
            </section>

            <section
              :class="panelClass"
              aria-labelledby="containers-heading"
            >
              <h2
                id="containers-heading"
                class="fc-kicker border-b border-fc-line pb-1"
              >
                Containers
              </h2>
              <ul
                v-if="service.containers.length > 0"
                class="mt-3 grid gap-2 text-xs"
              >
                <li
                  v-for="container in service.containers"
                  :key="`${container.machineId}:${container.id}`"
                  class="flex flex-wrap items-baseline gap-2"
                >
                  <span class="break-all font-mono text-[11px] text-fc-ink">{{ container.name }}</span>
                  <span class="break-all font-mono text-[11px] text-fc-faint">{{ container.image }}</span>
                  <span class="text-fc-muted">{{ container.state }} · {{ container.status }}</span>
                </li>
              </ul>
              <p
                v-else
                class="mt-3 text-xs text-fc-faint"
              >
                No containers observed. Container state is read from Docker once the container inventory is configured.
              </p>
            </section>

            <section
              :class="panelClass"
              aria-labelledby="registry-heading"
            >
              <h2
                id="registry-heading"
                class="fc-kicker border-b border-fc-line pb-1"
              >
                Registry
              </h2>
              <ul
                v-if="service.registry.length > 0"
                class="mt-3 grid gap-1.5 text-xs"
                data-testid="service-registry"
              >
                <li
                  v-for="link in service.registry"
                  :key="`${link.type}/${link.key}/${link.link}`"
                  class="flex flex-wrap items-baseline gap-2"
                >
                  <span class="font-mono text-[10px] uppercase tracking-wider text-fc-muted">{{ link.link === 'hosted_on' ? 'hosted on' : 'domain match' }}</span>
                  <RouterLink
                    :to="registryLinkTo(link)"
                    class="break-all text-fc-info hover:underline"
                  >
                    {{ link.type }}/{{ link.key }}
                  </RouterLink>
                  <span
                    v-if="link.host"
                    class="break-all font-mono text-[11px] text-fc-faint"
                  >via {{ link.host }}</span>
                </li>
              </ul>
              <p
                v-else
                class="mt-3 text-xs text-fc-faint"
              >
                No Registry entry relates to this service.
              </p>
            </section>
          </div>
        </TabsContent>
        <TabsContent value="settings">
          <ServiceSettings :service="service" />
        </TabsContent>
      </Tabs>
    </template>
  </div>
</template>
