<script setup lang="ts">
import { computed, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'

import { Skeleton } from '@/components/ui/skeleton'

import { errorMessage } from '../../machine/api'
import EntryDrawer from '../components/EntryDrawer.vue'
import RegistryTabs from '../components/RegistryTabs.vue'
import RelationLinks from '../components/RelationLinks.vue'
import ToneBadge from '../components/ToneBadge.vue'
import { useMachineIds, useRegistryEntries, useRegistryTypes } from '../useRegistry'
import { domainRows, domainSummary, type DomainRow } from './domains'
import { useDomainObservations } from './useDomains'

// Domains at a glance: registrar, DNS host, where each points, expiry, and
// drift against the public RDAP/DNS lookups. Read-only: a suggested change
// is a `fleetctl registry set` command to run in a Fleet Git checkout.
const route = useRoute()
const router = useRouter()

const types = useRegistryTypes()
const domainType = computed(() => types.data.value?.items.find(t => t.name === 'domain') ?? null)
const entries = useRegistryEntries('domain', '')
const observations = useDomainObservations()
const machines = useMachineIds(true)

const rows = computed(() => domainRows(entries.data.value?.items ?? [], observations.data.value?.items ?? []))
const summary = computed(() => domainSummary(rows.value))
const machineIds = computed(() => machines.data.value ?? new Map<string, string>())
const loading = computed(() => entries.isLoading.value || types.isLoading.value)

const open = ref(new Set<string>(typeof route.query.open === 'string' ? [route.query.open] : []))
function toggle(key: string) {
  const next = new Set(open.value)
  if (!next.delete(key))
    next.add(key)
  open.value = next
}

const selectedKey = computed(() => (typeof route.query.entry === 'string' ? route.query.entry : null))
function setQuery(patch: Record<string, string | undefined>) {
  router.replace({ query: { ...route.query, ...patch } })
}

const copiedKey = ref<string | null>(null)
async function copy(row: DomainRow) {
  if (!row.command)
    return
  try {
    await navigator.clipboard.writeText(row.command)
    copiedKey.value = row.key
    setTimeout(() => { copiedKey.value = null }, 1500)
  }
  catch {
    copiedKey.value = null
  }
}

function observedAgo(at: number): string {
  return new Date(at).toISOString().replace('T', ' ').slice(0, 16) + ' UTC'
}

const SEVERITY_TONE = { err: 'err', warn: 'warn', info: 'info' } as const
</script>

<template>
  <div>
    <p class="fc-kicker">
      descriptive records in Fleet Git · public RDAP and DNS lookups
    </p>
    <h1 class="fc-h1">
      Domains
    </h1>
    <RegistryTabs active="domains" />

    <div
      v-if="types.error.value || entries.error.value"
      class="mt-4 border-l-2 border-l-fc-err bg-card px-3 py-2 text-xs text-fc-muted"
      role="alert"
    >
      Could not load domains: {{ errorMessage(types.error.value ?? entries.error.value) }}
    </div>
    <div
      v-if="observations.error.value"
      class="mt-4 border-l-2 border-l-fc-warn bg-card px-3 py-2 text-xs text-fc-muted"
      role="alert"
      data-testid="domains-observations-error"
    >
      Lookup results are unavailable ({{ errorMessage(observations.error.value) }}). Domains show what Fleet Git records, without drift or points-at.
    </div>
    <div
      v-if="entries.data.value?.truncated"
      class="mt-4 border-l-2 border-l-fc-warn bg-card px-3 py-2 text-xs text-fc-muted"
      role="status"
    >
      The list hit the page safety cap; some domains are not shown.
    </div>

    <div
      v-if="loading"
      class="mt-4 grid gap-2"
    >
      <Skeleton
        v-for="i in 4"
        :key="i"
        class="h-10 rounded-sm"
      />
    </div>

    <div
      v-else-if="!entries.error.value && !types.error.value && rows.length === 0"
      class="mt-4 rounded-sm border border-fc-line p-6 text-sm text-fc-muted"
      data-testid="domains-empty"
    >
      <p>{{ domainType ? 'No domain entries in the active revision.' : 'No desired revision is active, so there are no domains yet.' }}</p>
      <p class="mt-2 text-xs text-fc-faint">
        Domains are recorded in Fleet Git and this view is read-only. In a checkout of the Fleet Git repository, add one and publish it:
      </p>
      <pre class="mt-2 overflow-x-auto rounded-sm bg-fc-inset p-2 font-mono text-[11.5px] text-fc-ink">fleetctl registry set domain/&lt;fqdn&gt; --field registrar=&lt;name&gt; --field expires=YYYY-MM-DD
fleetctl registry validate
fleetctl registry publish -m "Add domain"</pre>
    </div>

    <template v-else-if="rows.length">
      <dl
        class="mt-4 grid grid-cols-2 gap-2 sm:grid-cols-4"
        data-testid="domains-summary"
      >
        <div class="rounded-sm border border-fc-line bg-card px-3 py-2">
          <dt class="fc-kicker">
            Domains
          </dt>
          <dd class="mt-1 font-head text-xl font-extrabold">
            {{ summary.total }}
          </dd>
        </div>
        <div class="rounded-sm border border-fc-line bg-card px-3 py-2">
          <dt class="fc-kicker">
            Need attention
          </dt>
          <dd
            class="mt-1 font-head text-xl font-extrabold"
            :class="summary.attention ? 'text-fc-warn' : ''"
          >
            {{ summary.attention }}
          </dd>
        </div>
        <div class="rounded-sm border border-fc-line bg-card px-3 py-2">
          <dt class="fc-kicker">
            Expiring in 30 days
          </dt>
          <dd
            class="mt-1 font-head text-xl font-extrabold"
            :class="summary.expiring ? 'text-fc-warn' : ''"
          >
            {{ summary.expiring }}
          </dd>
        </div>
        <div class="rounded-sm border border-fc-line bg-card px-3 py-2">
          <dt class="fc-kicker">
            Drifted from lookups
          </dt>
          <dd
            class="mt-1 font-head text-xl font-extrabold"
            :class="summary.drifted ? 'text-fc-warn' : ''"
          >
            {{ summary.drifted }}
          </dd>
        </div>
      </dl>
      <p
        v-if="summary.unobserved && !observations.error.value"
        class="mt-2 text-xs text-fc-faint"
      >
        {{ summary.unobserved }} {{ summary.unobserved === 1 ? 'domain has' : 'domains have' }} not been looked up yet.
      </p>

      <div class="mt-4 overflow-x-auto">
        <table
          class="w-full border border-fc-line bg-card text-[13px]"
          aria-label="Domains"
          data-testid="domains-table"
        >
          <thead>
            <tr class="bg-fc-inset text-left">
              <th
                scope="col"
                class="fc-kicker px-2 py-1.5 font-normal"
              >
                Domain
              </th>
              <th
                scope="col"
                class="fc-kicker hidden px-2 py-1.5 font-normal md:table-cell"
              >
                Registrar
              </th>
              <th
                scope="col"
                class="fc-kicker hidden px-2 py-1.5 font-normal md:table-cell"
              >
                DNS host
              </th>
              <th
                scope="col"
                class="fc-kicker hidden px-2 py-1.5 font-normal lg:table-cell"
              >
                Points at
              </th>
              <th
                scope="col"
                class="fc-kicker px-2 py-1.5 font-normal"
              >
                Expires
              </th>
              <th
                scope="col"
                class="fc-kicker px-2 py-1.5 font-normal"
              >
                Status
              </th>
            </tr>
          </thead>
          <tbody>
            <template
              v-for="row in rows"
              :key="row.key"
            >
              <tr
                class="cursor-pointer border-t border-fc-line align-top hover:bg-fc-inset"
                :class="open.has(row.key) ? 'bg-fc-inset' : ''"
                :data-testid="`domain-${row.key}`"
                @click="toggle(row.key)"
              >
                <td class="px-2 py-1.5">
                  <button
                    type="button"
                    class="break-all text-left font-mono text-fc-ink hover:underline"
                    :aria-expanded="open.has(row.key)"
                    :aria-label="`${open.has(row.key) ? 'Hide' : 'Show'} details for ${row.key}`"
                    @click.stop="toggle(row.key)"
                  >
                    {{ row.key }}
                  </button>
                </td>
                <td class="hidden px-2 py-1.5 md:table-cell">
                  {{ row.registrar ?? '–' }}
                </td>
                <td class="hidden px-2 py-1.5 md:table-cell">
                  {{ row.dnsHost ?? '–' }}
                </td>
                <td class="hidden px-2 py-1.5 font-mono text-[11px] lg:table-cell">
                  <template v-if="row.pointsAt.length">
                    <span
                      v-for="group in row.pointsAt"
                      :key="group.name"
                      class="block break-all"
                    >{{ group.records.slice(0, 2).join(', ') }}<span v-if="group.records.length > 2"> +{{ group.records.length - 2 }}</span><span class="ml-1 text-fc-faint">{{ group.name }}</span></span>
                  </template>
                  <span
                    v-else
                    class="text-fc-faint"
                  >{{ row.observed ? 'no records' : 'not looked up' }}</span>
                </td>
                <td class="whitespace-nowrap px-2 py-1.5">
                  <span class="font-mono text-[11px]">{{ row.expires ?? '–' }}</span>
                  <span
                    v-if="row.recordedExpires && row.expires !== row.recordedExpires"
                    class="block font-mono text-[10px] text-fc-faint"
                  >recorded {{ row.recordedExpires }}</span>
                  <span class="mt-0.5 block">
                    <ToneBadge
                      v-if="row.expiry.kind !== 'unknown'"
                      :tone="row.expiry.tone"
                    >{{ row.expiry.label }}</ToneBadge>
                  </span>
                </td>
                <td class="px-2 py-1.5">
                  <span class="flex flex-wrap gap-1">
                    <ToneBadge
                      v-for="badge in row.drift"
                      :key="badge.field"
                      tone="warn"
                    >{{ badge.field }} differs</ToneBadge>
                    <ToneBadge
                      v-if="row.autoRenew === false"
                      tone="warn"
                    >auto-renew off</ToneBadge>
                    <ToneBadge
                      v-if="!row.observed"
                      tone="muted"
                    >not looked up</ToneBadge>
                    <template v-else-if="row.drift.length === 0 && row.warnings.length === 0 && row.autoRenew !== false">
                      <ToneBadge
                        v-if="row.sync === 'in_sync'"
                        tone="ok"
                      >in sync</ToneBadge>
                      <ToneBadge
                        v-else
                        tone="muted"
                      >{{ row.sync === 'partial' ? 'partly compared' : 'not compared' }}</ToneBadge>
                    </template>
                  </span>
                </td>
              </tr>
              <tr
                v-if="open.has(row.key)"
                class="bg-fc-inset"
                :data-testid="`domain-detail-${row.key}`"
              >
                <td
                  colspan="6"
                  class="min-w-0 px-3 pb-3 pt-1"
                >
                  <div class="grid w-0 min-w-full gap-4 text-[13px] md:grid-cols-2">
                    <section class="min-w-0">
                      <h2 class="fc-kicker border-b border-fc-line pb-1">
                        Registration
                      </h2>
                      <dl class="mt-2 grid grid-cols-[auto_minmax(0,1fr)] gap-x-3 gap-y-1 text-xs">
                        <dt class="text-fc-faint">
                          Registrar
                        </dt>
                        <dd>{{ row.registrar ?? '–' }}</dd>
                        <dt class="text-fc-faint">
                          DNS host
                        </dt>
                        <dd>{{ row.dnsHost ?? '–' }}</dd>
                        <dt class="text-fc-faint">
                          Expires
                        </dt>
                        <dd>
                          {{ row.expires ?? '–' }}<span
                            v-if="row.expirySource === 'observed'"
                            class="text-fc-faint"
                          > (from RDAP{{ row.recordedExpires ? '' : '; not recorded in Fleet Git' }})</span><span
                            v-if="row.recordedExpires && row.expires !== row.recordedExpires"
                            class="block text-fc-faint"
                          >Fleet Git records {{ row.recordedExpires }}</span>
                        </dd>
                        <dt class="text-fc-faint">
                          Auto-renew
                        </dt>
                        <dd>{{ row.autoRenew === null ? '–' : row.autoRenew ? 'Yes' : 'No' }}</dd>
                        <dt class="text-fc-faint">
                          Nameservers
                        </dt>
                        <dd class="break-all font-mono text-[11px]">
                          {{ row.nameservers.length ? row.nameservers.join(', ') : '–' }}
                        </dd>
                      </dl>
                    </section>
                    <section class="min-w-0">
                      <h2 class="fc-kicker border-b border-fc-line pb-1">
                        Points at
                      </h2>
                      <ul
                        v-if="row.pointsAt.length"
                        class="mt-2 grid gap-1 font-mono text-[11px]"
                      >
                        <li
                          v-for="group in row.pointsAt"
                          :key="group.name"
                          class="break-all"
                        >
                          <span class="text-fc-faint">{{ group.name }}</span> {{ group.records.join(', ') }}
                        </li>
                      </ul>
                      <p
                        v-else
                        class="mt-2 text-xs text-fc-faint"
                      >
                        {{ row.dnsDetail ?? (row.observed ? 'The lookup found no address or CNAME records.' : 'No lookup has run for this domain yet.') }}
                      </p>
                      <p
                        v-if="row.observedAt"
                        class="mt-1 text-[11px] text-fc-faint"
                      >
                        Looked up {{ observedAgo(row.observedAt) }}
                      </p>
                    </section>

                    <section
                      v-if="row.warnings.length"
                      class="min-w-0 md:col-span-2"
                    >
                      <h2 class="fc-kicker border-b border-fc-line pb-1">
                        Warnings
                      </h2>
                      <ul class="mt-2 grid gap-1 text-xs">
                        <li
                          v-for="warning in row.warnings"
                          :key="warning.code"
                          class="flex flex-wrap items-baseline gap-2"
                        >
                          <ToneBadge :tone="SEVERITY_TONE[warning.severity]">
                            {{ warning.severity === 'err' ? 'error' : warning.severity }}
                          </ToneBadge>
                          <span>{{ warning.message }}</span>
                        </li>
                      </ul>
                    </section>

                    <section class="min-w-0 md:col-span-2">
                      <h2 class="fc-kicker border-b border-fc-line pb-1">
                        Drift against Fleet Git
                      </h2>
                      <template v-if="row.observed">
                        <table
                          v-if="row.drift.length"
                          class="mt-2 w-full text-xs"
                          :aria-label="`Drift for ${row.key}`"
                        >
                          <thead>
                            <tr class="text-left">
                              <th
                                scope="col"
                                class="fc-kicker pr-3 font-normal"
                              >
                                Field
                              </th>
                              <th
                                scope="col"
                                class="fc-kicker pr-3 font-normal"
                              >
                                Fleet Git
                              </th>
                              <th
                                scope="col"
                                class="fc-kicker font-normal"
                              >
                                Lookup
                              </th>
                            </tr>
                          </thead>
                          <tbody>
                            <tr
                              v-for="badge in row.drift"
                              :key="badge.field"
                              class="align-top"
                            >
                              <td class="py-0.5 pr-3 font-mono text-[11px]">
                                {{ badge.field }}
                              </td>
                              <td class="break-all py-0.5 pr-3 font-mono text-[11px]">
                                {{ badge.recorded }}
                              </td>
                              <td class="break-all py-0.5 font-mono text-[11px]">
                                {{ badge.observed }}
                              </td>
                            </tr>
                          </tbody>
                        </table>
                        <p
                          v-else
                          class="mt-2 text-xs text-fc-muted"
                        >
                          {{ row.inSync ? `${row.inSync} ${row.inSync === 1 ? 'field matches' : 'fields match'} the lookups; nothing differs.` : 'The lookups raised no differences.' }}
                        </p>
                        <p
                          v-if="row.notCompared.length"
                          class="mt-1 text-[11px] text-fc-faint"
                        >
                          Not compared: {{ row.notCompared.join(', ') }} (the lookups or the entry had no value).
                        </p>
                      </template>
                      <p
                        v-else
                        class="mt-2 text-xs text-fc-faint"
                      >
                        There is nothing to compare until a lookup has run.
                      </p>
                      <template v-if="row.command">
                        <p class="mt-3 text-xs text-fc-faint">
                          To record what the lookups saw, run this in a checkout of the Fleet Git repository, then publish:
                        </p>
                        <div class="mt-1 flex items-start gap-2">
                          <pre
                            class="min-w-0 flex-1 overflow-x-auto rounded-sm bg-background p-2 font-mono text-[11.5px]"
                            data-testid="suggest-command"
                          >{{ row.command }}</pre>
                          <button
                            type="button"
                            class="shrink-0 rounded-sm border border-fc-line2 px-2 py-1 text-xs text-fc-muted hover:text-fc-ink"
                            @click.stop="copy(row)"
                          >
                            {{ copiedKey === row.key ? 'Copied' : 'Copy' }}
                          </button>
                        </div>
                      </template>
                    </section>

                    <section class="min-w-0 md:col-span-2">
                      <h2 class="fc-kicker border-b border-fc-line pb-1">
                        Related
                      </h2>
                      <div class="mt-2">
                        <RelationLinks
                          :relations="row.entry.relations"
                          :machine-ids="machineIds"
                        />
                      </div>
                      <button
                        type="button"
                        class="mt-3 rounded-sm border border-fc-line2 px-2 py-1 text-xs text-fc-muted hover:text-fc-ink"
                        @click.stop="setQuery({ entry: row.key })"
                      >
                        Open full entry
                      </button>
                    </section>
                  </div>
                </td>
              </tr>
            </template>
          </tbody>
        </table>
      </div>
    </template>

    <EntryDrawer
      v-if="selectedKey && domainType"
      :key="`domain/${selectedKey}`"
      :type="domainType"
      :entry-key="selectedKey"
      @close="setQuery({ entry: undefined })"
    />
  </div>
</template>
