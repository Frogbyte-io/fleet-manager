<script setup lang="ts">
import { computed } from 'vue'
import { RouterLink, useRoute, useRouter } from 'vue-router'

import type { RecipeVersionDto } from '@frogbyte-io/fleet-api-client'
import StatusChip from '@/components/fleet/StatusChip.vue'
import { Skeleton } from '@/components/ui/skeleton'

import { formatSpan } from '../../lab/lab'
import { errorMessage } from '../../machine/api'
import CopyFleetctl from '../../machine/components/CopyFleetctl.vue'
import { buildRunning, buildSeconds, buildsCommand, buildTone, latestSucceeded, promotionBuild, shortDigest, utcMinute } from '../images'
import { BUILD_HISTORY_LIMIT, useBuildRecord, useVersionBuilds } from '../useImages'
import BuildRecord from './BuildRecord.vue'

// A version's build history: every immutable build record, newest first,
// and the record behind its promotion. The open record lives in the URL
// (`?build=<id>`) so a provenance view can be linked.
const props = defineProps<{
  version: RecipeVersionDto
}>()

const route = useRoute()
const router = useRouter()

const builds = useVersionBuilds(() => props.version.id)
const list = computed(() => builds.data.value?.items ?? [])
const truncated = computed(() => builds.data.value?.truncated ?? false)

const promotedBy = computed(() => promotionBuild(props.version, list.value))
const latestSuccess = computed(() => latestSucceeded(list.value))

const openId = computed(() => (typeof route.query.build === 'string' ? route.query.build : null))
const listed = computed(() => list.value.find(b => b.id === openId.value) ?? null)
// A linked record that is not on the listed page (older, or another version's).
const linked = useBuildRecord(openId, computed(() => builds.isSuccess.value && !listed.value))
const unlisted = computed(() => (!listed.value && linked.data.value?.versionId === props.version.id ? linked.data.value : null))

function toggle(id: string) {
  router.replace({ query: { ...route.query, build: openId.value === id ? undefined : id } })
}
</script>

<template>
  <section
    class="space-y-2"
    data-testid="build-history"
  >
    <h4 class="fc-kicker flex items-center gap-2 border-b border-fc-line pb-1">
      Build history <span class="text-fc-faint">newest first</span>
    </h4>

    <p
      v-if="version.promotedAt && builds.isSuccess.value"
      class="text-fc-muted"
      data-testid="promotion-record"
    >
      <template v-if="promotedBy">
        Promoted {{ utcMinute(version.promotedAt) }} on the evidence of build
        <button
          type="button"
          class="font-mono text-fc-ok hover:text-fc-ink"
          @click="toggle(promotedBy)"
        >
          {{ promotedBy }}
        </button>, the newest build record when it was promoted.
      </template>
      <template v-else>
        Promoted {{ utcMinute(version.promotedAt) }}; the build record it stood on is not among the records listed here.
      </template>
    </p>

    <div
      v-if="builds.isLoading.value"
      class="space-y-1.5"
      data-testid="build-history-loading"
      aria-busy="true"
    >
      <Skeleton
        v-for="i in 3"
        :key="i"
        class="h-9 rounded-sm"
      />
    </div>

    <div
      v-else-if="builds.isError.value"
      class="flex flex-wrap items-center gap-2 border-l-2 border-l-fc-err bg-fc-inset px-3 py-2 text-fc-muted"
      role="alert"
      data-testid="build-history-error"
    >
      <span>Could not load build records: {{ errorMessage(builds.error.value) }}</span>
      <button
        type="button"
        class="ml-auto font-mono text-[10px] uppercase tracking-wider text-fc-info hover:text-fc-ink"
        @click="builds.refetch()"
      >
        Retry
      </button>
    </div>

    <p
      v-else-if="list.length === 0"
      class="text-fc-muted"
      data-testid="build-history-empty"
    >
      No build records for this version yet. Every build started above leaves an immutable record of its inputs, tools, target, and output.
    </p>

    <ul
      v-else
      class="divide-y divide-fc-line border-y border-fc-line"
    >
      <li
        v-for="build in list"
        :key="build.id"
        :data-testid="`build-row-${build.id}`"
      >
        <div class="flex items-center gap-2">
          <button
            type="button"
            class="flex min-w-0 flex-1 flex-wrap items-center gap-x-3 gap-y-1 px-1 py-2 text-left font-mono text-[11px] hover:bg-fc-inset"
            :aria-expanded="openId === build.id"
            :aria-label="`Build ${build.id}, ${build.outcome}`"
            @click="toggle(build.id)"
          >
            <StatusChip
              :label="build.outcome"
              :tone="buildTone(build.outcome)"
            />
            <span class="text-fc-ink">{{ utcMinute(build.startedAt) }}</span>
            <span
              class="text-fc-muted"
              data-testid="build-duration"
            >{{ buildRunning(build) ? 'running' : formatSpan(buildSeconds(build)!) }}</span>
            <span
              v-if="build.reason"
              class="text-fc-faint"
              data-testid="build-reason"
            >{{ build.reason }}</span>
            <span
              class="text-fc-muted"
              data-testid="build-template"
            >{{ build.template ? `→ ${build.template.name} · vmid ${build.template.vmid}` : '→ no template' }}</span>
            <StatusChip
              v-if="build.id === promotedBy"
              label="promotion evidence"
              tone="ok"
            />
            <StatusChip
              v-else-if="build.id === latestSuccess"
              label="latest success"
              tone="info"
            />
            <span class="ml-auto text-fc-faint">{{ shortDigest(build.contentDigest, 8) }} {{ openId === build.id ? '▴' : '▾' }}</span>
          </button>
          <RouterLink
            :to="{ path: '/operations', query: { op: build.operationId } }"
            class="shrink-0 px-1 font-mono text-[10px] uppercase tracking-wider text-fc-info hover:text-fc-ink"
            :aria-label="`Operation ${build.operationId}`"
            :data-testid="`build-operation-${build.id}`"
          >
            Operation →
          </RouterLink>
        </div>
        <div
          v-if="openId === build.id"
          class="pb-2"
        >
          <BuildRecord
            :build="build"
            :version-digest="version.contentDigest"
          />
        </div>
      </li>
    </ul>

    <div
      v-if="unlisted"
      class="space-y-1"
    >
      <p class="text-[11px] text-fc-faint">
        Linked build record, not on the listed page:
      </p>
      <BuildRecord
        :build="unlisted"
        :version-digest="version.contentDigest"
      />
    </div>

    <p
      v-if="truncated"
      class="text-[10.5px] text-fc-faint"
      data-testid="build-history-truncated"
    >
      Showing the newest {{ BUILD_HISTORY_LIMIT }} build records; <span class="font-mono">fleetctl images builds --cursor</span> pages further.
    </p>
    <CopyFleetctl :command="buildsCommand(version.id)" />
  </section>
</template>
