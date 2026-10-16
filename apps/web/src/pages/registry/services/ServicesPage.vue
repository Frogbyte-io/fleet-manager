<script setup lang="ts">
import { computed, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'

import { Skeleton } from '@/components/ui/skeleton'

import { errorMessage } from '../../machine/api'
import EntryDrawer from '../components/EntryDrawer.vue'
import RegistryTabs from '../components/RegistryTabs.vue'
import RelationLinks from '../components/RelationLinks.vue'
import ToneBadge from '../components/ToneBadge.vue'
import { safeHref } from '../registry'
import { useMachineIds, useRegistryEntries, useRegistryTypes } from '../useRegistry'
import { costTotals, formatMicros, relativeDays, serviceRows, upcomingRenewals, RENEWAL_WINDOW_DAYS } from './services'

// Third-party services at a glance: who provides each, what it costs, when it
// renews. Totals are per currency with no conversion. Read-only.
const route = useRoute()
const router = useRouter()

const types = useRegistryTypes()
const serviceType = computed(() => types.data.value?.items.find(t => t.name === 'service') ?? null)
const entries = useRegistryEntries('service', '')
const machines = useMachineIds(true)

const rows = computed(() => serviceRows(entries.data.value?.items ?? []))
const totals = computed(() => costTotals(rows.value))
const renewals = computed(() => upcomingRenewals(rows.value))
const machineIds = computed(() => machines.data.value ?? new Map<string, string>())
const loading = computed(() => entries.isLoading.value || types.isLoading.value)

const open = ref(new Set<string>())
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

const RENEWAL_TONE = { overdue: 'err', soon: 'warn', later: 'info' } as const
</script>

<template>
  <div>
    <p class="fc-kicker">
      descriptive records in Fleet Git · no currency conversion
    </p>
    <h1 class="fc-h1">
      Services
    </h1>
    <RegistryTabs active="services" />

    <div
      v-if="types.error.value || entries.error.value"
      class="mt-4 border-l-2 border-l-fc-err bg-card px-3 py-2 text-xs text-fc-muted"
      role="alert"
    >
      Could not load services: {{ errorMessage(types.error.value ?? entries.error.value) }}
    </div>
    <div
      v-if="entries.data.value?.truncated"
      class="mt-4 border-l-2 border-l-fc-warn bg-card px-3 py-2 text-xs text-fc-muted"
      role="status"
    >
      The list hit the page safety cap; totals and renewals leave out the services not shown.
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
      data-testid="services-empty"
    >
      <p>{{ serviceType ? 'No service entries in the active revision.' : 'No desired revision is active, so there are no services yet.' }}</p>
      <p class="mt-2 text-xs text-fc-faint">
        Services are recorded in Fleet Git and this view is read-only. In a checkout of the Fleet Git repository, add one and publish it:
      </p>
      <pre class="mt-2 overflow-x-auto rounded-sm bg-fc-inset p-2 font-mono text-[11.5px] text-fc-ink">fleetctl registry set service/&lt;slug&gt; --field name=&lt;name&gt; --field cost="9.00 EUR" --field billingPeriod=monthly
fleetctl registry validate
fleetctl registry publish -m "Add service"</pre>
    </div>

    <template v-else-if="rows.length">
      <section
        class="mt-4"
        data-testid="cost-totals"
      >
        <h2 class="fc-kicker border-b border-fc-line pb-1">
          Cost
        </h2>
        <p
          v-if="totals.currencies.length === 0"
          class="mt-2 text-xs text-fc-faint"
        >
          No service has a cost and a billing period of monthly or yearly, so there is nothing to total.
        </p>
        <div
          v-else
          class="mt-2 overflow-x-auto"
        >
          <table
            class="w-full border border-fc-line bg-card text-[13px]"
            aria-label="Cost totals per currency"
          >
            <thead>
              <tr class="bg-fc-inset text-left">
                <th
                  scope="col"
                  class="fc-kicker px-2 py-1.5 font-normal"
                >
                  Currency
                </th>
                <th
                  scope="col"
                  class="fc-kicker px-2 py-1.5 font-normal"
                >
                  Per month
                </th>
                <th
                  scope="col"
                  class="fc-kicker px-2 py-1.5 font-normal"
                >
                  Per year
                </th>
                <th
                  scope="col"
                  class="fc-kicker hidden px-2 py-1.5 font-normal md:table-cell"
                >
                  Billed monthly
                </th>
                <th
                  scope="col"
                  class="fc-kicker hidden px-2 py-1.5 font-normal md:table-cell"
                >
                  Billed yearly
                </th>
              </tr>
            </thead>
            <tbody>
              <tr
                v-for="total in totals.currencies"
                :key="total.currency"
                class="border-t border-fc-line align-top"
                :data-testid="`total-${total.currency}`"
              >
                <th
                  scope="row"
                  class="px-2 py-1.5 text-left font-mono font-normal"
                >
                  {{ total.currency }}
                </th>
                <td class="px-2 py-1.5 font-mono">
                  {{ formatMicros(total.perMonth, total.currency) }}
                  <span
                    v-if="total.yearlyCount"
                    class="block font-sans text-[10px] text-fc-faint"
                  >includes yearly plans ÷ 12</span>
                </td>
                <td class="px-2 py-1.5 font-mono">
                  {{ formatMicros(total.perYear, total.currency) }}
                  <span
                    v-if="total.monthlyCount"
                    class="block font-sans text-[10px] text-fc-faint"
                  >includes monthly plans × 12</span>
                </td>
                <td class="hidden px-2 py-1.5 font-mono md:table-cell">
                  {{ total.monthlyCount ? formatMicros(total.monthlyPlans, total.currency) : '–' }}
                  <span class="font-sans text-[10px] text-fc-faint">/ month · {{ total.monthlyCount }} {{ total.monthlyCount === 1 ? 'service' : 'services' }}</span>
                </td>
                <td class="hidden px-2 py-1.5 font-mono md:table-cell">
                  {{ total.yearlyCount ? formatMicros(total.yearlyPlans, total.currency) : '–' }}
                  <span class="font-sans text-[10px] text-fc-faint">/ year · {{ total.yearlyCount }} {{ total.yearlyCount === 1 ? 'service' : 'services' }}</span>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
        <p
          v-if="totals.currencies.length"
          class="mt-1 text-[11px] text-fc-faint"
        >
          Per-month and per-year figures convert between billing periods only (monthly × 12, yearly ÷ 12). Currencies are never converted into each other.
        </p>
        <p
          v-if="totals.excludedOther || totals.uncosted"
          class="mt-1 text-xs text-fc-muted"
          data-testid="totals-excluded"
        >
          Not in the totals:
          <span v-if="totals.excludedOther">{{ totals.excludedOther }} billed on another period</span><span v-if="totals.excludedOther && totals.uncosted">, </span><span v-if="totals.uncosted">{{ totals.uncosted }} without a usable cost or billing period</span>.
        </p>
      </section>

      <section
        class="mt-5"
        data-testid="renewals"
      >
        <h2 class="fc-kicker border-b border-fc-line pb-1">
          Upcoming renewals · next {{ RENEWAL_WINDOW_DAYS }} days
        </h2>
        <p
          v-if="renewals.length === 0"
          class="mt-2 text-xs text-fc-faint"
        >
          Nothing renews in the next {{ RENEWAL_WINDOW_DAYS }} days.
        </p>
        <ul
          v-else
          class="mt-2 grid gap-1.5"
        >
          <li
            v-for="renewal in renewals"
            :key="renewal.row.key"
            class="flex flex-wrap items-baseline gap-x-3 gap-y-1 text-[13px]"
            :data-testid="`renewal-${renewal.row.key}`"
          >
            <ToneBadge :tone="RENEWAL_TONE[renewal.state]">
              {{ renewal.state === 'overdue' ? 'date passed' : relativeDays(renewal.days) }}
            </ToneBadge>
            <button
              type="button"
              class="text-left hover:underline"
              @click="setQuery({ entry: renewal.row.key })"
            >
              {{ renewal.row.name }}
            </button>
            <span class="font-mono text-[11px] text-fc-muted">{{ renewal.row.renewal }}</span>
            <span
              v-if="renewal.row.cost"
              class="font-mono text-[11px] text-fc-muted"
            >{{ formatMicros(renewal.row.cost.micros, renewal.row.cost.currency) }}{{ renewal.row.period && renewal.row.period !== 'other' ? ` / ${renewal.row.period === 'monthly' ? 'month' : 'year'}` : '' }}</span>
            <span
              v-if="renewal.state === 'overdue'"
              class="text-[11px] text-fc-faint"
            >It renewed or lapsed; update the renewal date in Fleet Git.</span>
          </li>
        </ul>
      </section>

      <section class="mt-5">
        <h2 class="fc-kicker border-b border-fc-line pb-1">
          All services · {{ rows.length }}
        </h2>
        <div class="mt-2 overflow-x-auto">
          <table
            class="w-full border border-fc-line bg-card text-[13px]"
            aria-label="Services"
            data-testid="services-table"
          >
            <thead>
              <tr class="bg-fc-inset text-left">
                <th
                  scope="col"
                  class="fc-kicker px-2 py-1.5 font-normal"
                >
                  Service
                </th>
                <th
                  scope="col"
                  class="fc-kicker hidden px-2 py-1.5 font-normal md:table-cell"
                >
                  Vendor
                </th>
                <th
                  scope="col"
                  class="fc-kicker hidden px-2 py-1.5 font-normal md:table-cell"
                >
                  Plan
                </th>
                <th
                  scope="col"
                  class="fc-kicker px-2 py-1.5 font-normal"
                >
                  Cost
                </th>
                <th
                  scope="col"
                  class="fc-kicker hidden px-2 py-1.5 font-normal sm:table-cell"
                >
                  Renewal
                </th>
                <th
                  scope="col"
                  class="fc-kicker hidden px-2 py-1.5 font-normal lg:table-cell"
                >
                  Hosting
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
                  :data-testid="`service-${row.key}`"
                  @click="toggle(row.key)"
                >
                  <td class="px-2 py-1.5">
                    <button
                      type="button"
                      class="text-left text-fc-ink hover:underline"
                      :aria-expanded="open.has(row.key)"
                      :aria-label="`${open.has(row.key) ? 'Hide' : 'Show'} details for ${row.name}`"
                      @click.stop="toggle(row.key)"
                    >
                      {{ row.name }}
                    </button>
                    <span class="block font-mono text-[10px] text-fc-faint">{{ row.key }}</span>
                  </td>
                  <td class="hidden px-2 py-1.5 md:table-cell">
                    {{ row.vendor ?? '–' }}
                  </td>
                  <td class="hidden px-2 py-1.5 md:table-cell">
                    {{ row.plan ?? '–' }}
                  </td>
                  <td class="px-2 py-1.5 font-mono text-[12px]">
                    <template v-if="row.cost">
                      {{ formatMicros(row.cost.micros, row.cost.currency) }}<span class="font-sans text-[10px] text-fc-faint"> / {{ row.period === 'monthly' ? 'month' : row.period === 'yearly' ? 'year' : 'other period' }}</span>
                    </template>
                    <template v-else-if="row.costText">
                      {{ row.costText }}
                    </template>
                    <span
                      v-else
                      class="text-fc-faint"
                    >–</span>
                  </td>
                  <td class="hidden px-2 py-1.5 sm:table-cell">
                    <span
                      v-if="row.renewal"
                      class="font-mono text-[11px]"
                    >{{ row.renewal }}</span>
                    <span
                      v-else
                      class="text-fc-faint"
                    >–</span>
                    <span
                      v-if="row.renewalDays !== null"
                      class="block text-[10px] text-fc-faint"
                    >{{ relativeDays(row.renewalDays) }}</span>
                  </td>
                  <td class="hidden px-2 py-1.5 lg:table-cell">
                    {{ row.hosting ?? '–' }}<span
                      v-if="row.region"
                      class="text-fc-faint"
                    > · {{ row.region }}</span>
                  </td>
                </tr>
                <tr
                  v-if="open.has(row.key)"
                  class="bg-fc-inset"
                  :data-testid="`service-detail-${row.key}`"
                >
                  <td
                    colspan="6"
                    class="min-w-0 px-3 pb-3 pt-1"
                  >
                    <div class="grid min-w-0 gap-4 text-[13px] md:grid-cols-2">
                      <section class="min-w-0">
                        <h3 class="fc-kicker border-b border-fc-line pb-1">
                          Details
                        </h3>
                        <dl class="mt-2 grid grid-cols-[auto_minmax(0,1fr)] gap-x-3 gap-y-1 text-xs">
                          <dt class="text-fc-faint">
                            Vendor
                          </dt>
                          <dd>{{ row.vendor ?? '–' }}</dd>
                          <dt class="text-fc-faint">
                            Plan
                          </dt>
                          <dd>{{ row.plan ?? '–' }}</dd>
                          <dt class="text-fc-faint">
                            Renewal
                          </dt>
                          <dd>{{ row.renewal ?? '–' }}</dd>
                          <dt class="text-fc-faint">
                            Hosting
                          </dt>
                          <dd>{{ row.hosting ?? '–' }}{{ row.region ? ` · ${row.region}` : '' }}</dd>
                          <dt class="text-fc-faint">
                            Address
                          </dt>
                          <dd class="break-all">
                            <a
                              v-if="row.url && safeHref(row.url)"
                              :href="safeHref(row.url)!"
                              target="_blank"
                              rel="noopener noreferrer"
                              class="text-fc-info hover:underline"
                              @click.stop
                            >{{ row.url }}</a>
                            <template v-else>
                              {{ row.url ?? '–' }}
                            </template>
                          </dd>
                        </dl>
                      </section>
                      <section class="min-w-0">
                        <h3 class="fc-kicker border-b border-fc-line pb-1">
                          Related
                        </h3>
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
      </section>
    </template>

    <EntryDrawer
      v-if="selectedKey && serviceType"
      :key="`service/${selectedKey}`"
      :type="serviceType"
      :entry-key="selectedKey"
      @close="setQuery({ entry: undefined })"
    />
  </div>
</template>
