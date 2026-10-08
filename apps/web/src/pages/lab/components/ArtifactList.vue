<script setup lang="ts">
import { getDownloadLabArtifactUrl, type LabArtifactDto } from '@frogbyte-io/fleet-api-client'

import { relativeTime } from '../../fleet/inventory'
import { artifactGetCommand, formatBytes, formatTimestamp, shortId } from '../lab'

// Stored Lab artifacts (FM-721): what each is, its full sha256 digest, and a
// download. The controller serves the bytes only while they still match that
// digest (it refuses with 409 otherwise) and names it in `ETag`.
defineProps<{
  artifacts: LabArtifactDto[]
  now: number
  /** Show which lease each artifact came from (the page-wide list). */
  showLease?: boolean
  leaseLabel?: (leaseId: string) => string
}>()

defineEmits<{ openLease: [leaseId: string] }>()

/** A download file name: the guest path's last component, or the log name. */
function fileName(artifact: LabArtifactDto): string {
  return artifact.name.split('/').filter(Boolean).pop() ?? artifact.id
}
</script>

<template>
  <ul
    class="grid gap-2"
    data-testid="artifact-list"
  >
    <li
      v-for="artifact in artifacts"
      :key="artifact.id"
      class="rounded-sm border border-fc-line bg-card p-3 text-xs"
      :data-testid="`artifact-${artifact.id}`"
    >
      <div class="flex flex-wrap items-start gap-2">
        <div class="min-w-0 flex-1">
          <p class="break-all font-mono text-[12px] font-semibold text-fc-ink">
            {{ artifact.name }}
          </p>
          <p class="mt-1 flex flex-wrap gap-x-3 gap-y-1 font-mono text-[10.5px] uppercase tracking-wide text-fc-muted">
            <span>{{ artifact.kind }}</span>
            <span>{{ formatBytes(artifact.sizeBytes) }}</span>
            <span>stored {{ relativeTime(artifact.createdAt, now) }}</span>
            <span :title="formatTimestamp(artifact.retainUntil)">kept until {{ formatTimestamp(artifact.retainUntil) }}</span>
            <button
              v-if="showLease"
              type="button"
              class="uppercase text-fc-info hover:text-fc-ink"
              @click="$emit('openLease', artifact.leaseId)"
            >
              lease {{ leaseLabel ? leaseLabel(artifact.leaseId) : shortId(artifact.leaseId) }}
            </button>
          </p>
        </div>
        <a
          :href="getDownloadLabArtifactUrl(artifact.id)"
          :download="fileName(artifact)"
          class="inline-flex h-7 items-center rounded-sm border border-input px-2.5 hover:border-fc-muted"
          :aria-label="`Download ${artifact.name}`"
          data-testid="download-artifact"
        >
          Download
        </a>
      </div>
      <p class="mt-2 font-mono text-[10.5px] text-fc-faint">
        <span class="uppercase tracking-wide">sha256</span>
        <span
          class="ml-1 break-all text-fc-muted"
          data-testid="artifact-digest"
        >{{ artifact.sha256 }}</span>
      </p>
      <p class="mt-1 break-all font-mono text-[10px] text-fc-faint">
        {{ artifactGetCommand(artifact.id, fileName(artifact)) }}
      </p>
    </li>
  </ul>
</template>
