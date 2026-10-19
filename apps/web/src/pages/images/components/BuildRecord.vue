<script setup lang="ts">
import { RouterLink } from 'vue-router'

import type { ImageBuildDto } from '@frogbyte-io/fleet-api-client'

import { formatSpan } from '../../lab/lab'
import CopyFleetctl from '../../machine/components/CopyFleetctl.vue'
import { buildSeconds, buildShowCommand, shortDigest, utcMinute } from '../images'
import CopyValue from './CopyValue.vue'

// One immutable build record: what the build was made from (digests and
// tool versions), where it ran, and what it produced. Every field is the
// API's (`fleetctl images build-show <id>`); absent values say so.
defineProps<{
  build: ImageBuildDto
  /** The version's own content digest, to show whether the record matches it. */
  versionDigest: string
}>()
</script>

<template>
  <div
    class="space-y-3 border-l-2 border-l-fc-line2 bg-fc-inset p-3"
    data-testid="build-record"
  >
    <dl class="grid grid-cols-[minmax(0,110px)_minmax(0,1fr)] gap-x-3 gap-y-1 font-mono text-[11px]">
      <dt class="text-fc-faint">
        build
      </dt>
      <dd class="min-w-0">
        <CopyValue
          :value="build.id"
          :display="build.id"
          label="build id"
        />
      </dd>
      <dt class="text-fc-faint">
        operation
      </dt>
      <dd class="min-w-0 truncate">
        <RouterLink
          :to="{ path: '/operations', query: { op: build.operationId } }"
          class="text-fc-info hover:text-fc-ink"
          data-testid="build-record-operation"
        >
          {{ build.operationId }} →
        </RouterLink>
      </dd>
      <dt class="text-fc-faint">
        outcome
      </dt>
      <dd>
        {{ build.outcome }}<template v-if="build.reason">
          · <span data-testid="build-record-reason">{{ build.reason }}</span>
        </template>
      </dd>
      <dt class="text-fc-faint">
        started / ended
      </dt>
      <dd>
        {{ utcMinute(build.startedAt) }} → {{ build.endedAt != null ? utcMinute(build.endedAt) : 'not ended' }}<template v-if="buildSeconds(build) != null">
          · {{ formatSpan(buildSeconds(build)!) }}
        </template>
      </dd>

      <dt class="col-span-2 mt-2 border-b border-fc-line pb-0.5 font-mono text-[9.5px] uppercase tracking-wider text-fc-muted">
        inputs
      </dt>
      <dt class="text-fc-faint">
        recipe digest
      </dt>
      <dd
        class="min-w-0"
        data-testid="build-record-content-digest"
      >
        <CopyValue
          :value="build.contentDigest"
          :display="shortDigest(build.contentDigest)"
          label="recipe digest"
        />
        <span
          v-if="build.contentDigest !== versionDigest"
          class="block text-fc-warn"
        >differs from this version's digest</span>
      </dd>
      <dt class="text-fc-faint">
        asset digests
      </dt>
      <dd
        class="min-w-0"
        data-testid="build-record-asset-digests"
      >
        <span
          v-if="build.assetDigests.length === 0"
          class="text-fc-faint"
        >none</span>
        <span
          v-for="(digest, index) in build.assetDigests"
          :key="index"
          class="block"
        >
          <CopyValue
            :value="digest"
            :display="shortDigest(digest)"
            :label="`asset digest ${index + 1}`"
          />
        </span>
      </dd>
      <dt class="text-fc-faint">
        packer
      </dt>
      <dd data-testid="build-record-packer">
        {{ build.packerVersion ?? 'not probed' }}
      </dd>
      <dt class="text-fc-faint">
        proxmox plugin
      </dt>
      <dd data-testid="build-record-plugin">
        {{ build.proxmoxPluginVersion ?? 'not probed' }}
      </dd>

      <dt class="col-span-2 mt-2 border-b border-fc-line pb-0.5 font-mono text-[9.5px] uppercase tracking-wider text-fc-muted">
        target
      </dt>
      <dt class="text-fc-faint">
        account
      </dt>
      <dd
        class="min-w-0 truncate"
        data-testid="build-record-account"
      >
        {{ build.accountId ?? 'not bound' }}
      </dd>
      <dt class="text-fc-faint">
        node / storage
      </dt>
      <dd>{{ build.node }} · {{ build.storagePool }}</dd>
      <dt class="text-fc-faint">
        output template
      </dt>
      <dd data-testid="build-record-template">
        <template v-if="build.template">
          {{ build.template.name }} · vmid {{ build.template.vmid }} on {{ build.template.node }}
        </template>
        <span
          v-else
          class="text-fc-faint"
        >none recorded</span>
      </dd>
    </dl>
    <CopyFleetctl :command="buildShowCommand(build.id)" />
  </div>
</template>
