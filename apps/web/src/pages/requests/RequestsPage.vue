<script setup lang="ts">
import { computed } from 'vue'
import { RouterLink, useRoute } from 'vue-router'

import StatusChip from '@/components/fleet/StatusChip.vue'
import { Skeleton } from '@/components/ui/skeleton'

import { relativeTime } from '../fleet/inventory'
import { errorMessage } from '../machine/api'
import PendingRequest from './components/PendingRequest.vue'
import { historyRequests, pendingRequests, riskTone, stateTone } from './requests'
import { REQUESTS_LIMIT, useHistoryRequests, usePendingRequests } from './useRequests'

// The approval inbox: provider actions agents asked Fleet to run, waiting
// for a person (ADR 0016). The list follows the fleet event stream.
// The pending queue and the history are separate queries: a long history
// can never hide a request that is waiting.
const pendingQuery = usePendingRequests()
const historyQuery = useHistoryRequests()
const route = useRoute()

const pending = computed(() => pendingRequests(pendingQuery.data.value?.items ?? []))
const history = computed(() => historyRequests(historyQuery.data.value?.items ?? []))
const loadError = computed(() => pendingQuery.error.value ?? historyQuery.error.value)
// `?request=` highlights one request, so attention rows link straight to it.
const focused = computed(() => (typeof route.query.request === 'string' ? route.query.request : null))
</script>

<template>
  <div>
    <p class="fc-kicker">
      action broker · agents ask, a person decides
    </p>
    <h1 class="fc-h1">
      Approval inbox
    </h1>

    <div
      v-if="loadError"
      class="mt-4 border-l-2 border-l-fc-err bg-card px-3 py-2 text-xs text-fc-muted"
      role="alert"
    >
      Could not load requests: {{ errorMessage(loadError) }}
    </div>
    <div
      v-if="pendingQuery.data.value?.truncated || historyQuery.data.value?.truncated"
      class="mt-4 border-l-2 border-l-fc-warn bg-card px-3 py-2 text-xs text-fc-muted"
      role="status"
    >
      Showing the newest {{ REQUESTS_LIMIT }} requests per list; the API does not page further, so older ones are not listed.
    </div>

    <section
      class="mt-6"
      aria-labelledby="pending-heading"
    >
      <div class="flex items-baseline justify-between border-b-2 border-fc-ink pb-1">
        <h2
          id="pending-heading"
          class="font-head text-sm font-extrabold uppercase tracking-tight"
        >
          Waiting for a decision
        </h2>
        <span
          class="font-mono text-[10px] text-fc-faint"
          data-testid="pending-count"
        >{{ pending.length }}</span>
      </div>
      <div
        v-if="pendingQuery.isLoading.value"
        class="mt-3 grid gap-2"
      >
        <Skeleton
          v-for="i in 2"
          :key="i"
          class="h-32 rounded-sm"
        />
      </div>
      <p
        v-else-if="pending.length === 0"
        class="mt-3 rounded-sm border border-fc-line p-6 text-sm text-fc-muted"
        data-testid="pending-empty"
      >
        Nothing is waiting for approval. Reflects the controller's last observation.
      </p>
      <div
        v-else
        class="mt-3 grid gap-3 lg:grid-cols-2"
      >
        <PendingRequest
          v-for="request in pending"
          :key="request.id"
          :request="request"
          :highlighted="request.id === focused"
        />
      </div>
    </section>

    <section
      class="mt-8"
      aria-labelledby="history-heading"
    >
      <div class="flex items-baseline justify-between border-b-2 border-fc-ink pb-1">
        <h2
          id="history-heading"
          class="font-head text-sm font-extrabold uppercase tracking-tight"
        >
          History
        </h2>
        <span class="font-mono text-[10px] text-fc-faint">{{ history.length }}</span>
      </div>
      <p
        v-if="!historyQuery.isLoading.value && history.length === 0"
        class="mt-3 rounded-sm border border-fc-line p-6 text-sm text-fc-muted"
        data-testid="history-empty"
      >
        No decided requests yet.
      </p>
      <div
        v-else-if="history.length > 0"
        class="mt-3"
      >
        <table
          class="w-full border border-fc-line bg-card text-xs"
          data-testid="history-table"
        >
          <thead>
            <tr class="bg-fc-inset text-left">
              <th class="fc-kicker px-2 py-1.5 font-normal">
                Action
              </th>
              <th class="fc-kicker px-2 py-1.5 font-normal">
                Outcome
              </th>
              <th class="fc-kicker hidden px-2 py-1.5 font-normal md:table-cell">
                Decided by
              </th>
              <th class="fc-kicker hidden px-2 py-1.5 font-normal md:table-cell">
                Operation
              </th>
              <th class="fc-kicker px-2 py-1.5 font-normal">
                Updated
              </th>
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="request in history"
              :key="request.id"
              class="border-t border-fc-line align-top"
              :class="request.id === focused ? 'bg-fc-inset' : ''"
              :data-testid="`history-${request.id}`"
            >
              <td class="px-2 py-1.5">
                <span class="font-mono text-fc-ink">{{ request.actionId }}</span>
                <span class="block break-all font-mono text-[10px] text-fc-muted">{{ request.target }}</span>
                <span class="block font-mono text-[10px] text-fc-faint">{{ request.requester }} · {{ request.id }}</span>
              </td>
              <td class="px-2 py-1.5">
                <div class="flex flex-wrap items-center gap-1">
                  <StatusChip
                    :label="request.state"
                    :tone="stateTone(request.state)"
                  />
                  <StatusChip
                    v-if="request.riskClass !== 'approve'"
                    :label="`risk ${request.riskClass}`"
                    :tone="riskTone(request.riskClass)"
                  />
                </div>
                <p
                  v-if="request.decisionNote"
                  class="mt-1 whitespace-pre-wrap break-words text-fc-muted"
                >
                  {{ request.decisionNote }}
                </p>
                <p
                  v-if="request.failure"
                  class="mt-1 whitespace-pre-wrap break-words text-fc-err"
                >
                  {{ request.failure }}
                </p>
                <!-- Below md the decider and the operation fold into this cell. -->
                <dl
                  class="mt-1 font-mono text-[10px] text-fc-muted md:hidden"
                  :data-testid="`outcome-meta-${request.id}`"
                >
                  <div
                    v-if="request.decidedBy"
                    class="flex gap-1"
                  >
                    <dt class="text-fc-faint">
                      by
                    </dt>
                    <dd class="break-all">
                      {{ request.decidedBy }}
                    </dd>
                  </div>
                  <div
                    v-if="request.operationId"
                    class="flex gap-1"
                  >
                    <dt class="text-fc-faint">
                      op
                    </dt>
                    <dd>
                      <RouterLink
                        :to="{ path: '/operations', query: { op: request.operationId } }"
                        class="text-fc-info hover:text-fc-ink"
                        :aria-label="`Open operation ${request.operationId}`"
                      >
                        {{ request.operationId.slice(0, 12) }} →
                      </RouterLink>
                    </dd>
                  </div>
                </dl>
              </td>
              <td class="hidden px-2 py-1.5 font-mono text-[11px] text-fc-muted md:table-cell">
                {{ request.decidedBy ?? '—' }}
              </td>
              <td class="hidden px-2 py-1.5 font-mono text-[11px] md:table-cell">
                <RouterLink
                  v-if="request.operationId"
                  :to="{ path: '/operations', query: { op: request.operationId } }"
                  class="text-fc-info hover:text-fc-ink"
                  :aria-label="`Open operation ${request.operationId}`"
                >
                  {{ request.operationId.slice(0, 12) }} →
                </RouterLink>
                <span
                  v-else
                  class="text-fc-faint"
                >—</span>
              </td>
              <td class="px-2 py-1.5 font-mono text-[10px] text-fc-faint">
                {{ relativeTime(request.updatedAt) }}
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </section>
  </div>
</template>
