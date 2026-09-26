<script setup lang="ts">
import { useQueryClient } from '@tanstack/vue-query'
import { ref } from 'vue'

import { publishLabTemplate, type LabTemplateDto, type LabTemplateVersionDto } from '@frogbyte-io/fleet-api-client'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'

import { relativeTime } from '../../fleet/inventory'
import { errorMessage, unwrap } from '../../machine/api'
import CopyFleetctl from '../../machine/components/CopyFleetctl.vue'
import { formatSpan, publishCommand, shortId } from '../lab'
import { TEMPLATES_KEY } from '../useLab'

// Template drafts and their latest published version. Publishing freezes the
// draft into an immutable version that leases pin; editing templates stays in
// fleetctl until the template editor lands with the Images page (FM-932).
defineProps<{ templates: LabTemplateDto[], now: number }>()

const queryClient = useQueryClient()
const confirming = ref<string | null>(null)
// The template being published; other rows cannot open or close meanwhile.
const publishing = ref<string | null>(null)
const error = ref('')
const published = ref<{ templateId: string, versionId: string } | null>(null)

const headClass = 'font-mono text-[10px] font-semibold uppercase tracking-[.14em] text-fc-faint'

async function publish(template: LabTemplateDto) {
  publishing.value = template.id
  error.value = ''
  try {
    const version = unwrap<LabTemplateVersionDto>(await publishLabTemplate(template.id), [201])
    published.value = { templateId: template.id, versionId: version.id }
    if (confirming.value === template.id)
      confirming.value = null
    await queryClient.invalidateQueries({ queryKey: TEMPLATES_KEY })
  }
  catch (caught) {
    error.value = errorMessage(caught)
  }
  finally {
    publishing.value = null
  }
}

function toggle(templateId: string) {
  if (publishing.value)
    return
  confirming.value = confirming.value === templateId ? null : templateId
  error.value = ''
}
</script>

<template>
  <div>
    <p
      v-if="templates.length === 0"
      class="rounded-sm border border-fc-line bg-card p-6 text-center text-sm text-fc-muted"
    >
      No Lab templates yet. Create one with
      <span class="font-mono text-fc-ink">fleetctl lab create …</span>
      pinned to a promoted image version.
    </p>
    <Table
      v-else
      class="rounded-sm border border-fc-line bg-card"
    >
      <TableHeader>
        <TableRow>
          <TableHead :class="headClass">
            Template
          </TableHead>
          <TableHead :class="headClass">
            Resources
          </TableHead>
          <TableHead :class="headClass">
            Readiness
          </TableHead>
          <TableHead :class="headClass">
            TTL · cleanup
          </TableHead>
          <TableHead :class="headClass">
            Published
          </TableHead>
          <TableHead :class="headClass" />
        </TableRow>
      </TableHeader>
      <TableBody>
        <template
          v-for="template in templates"
          :key="template.id"
        >
          <TableRow>
            <TableCell>
              <div class="font-head text-sm font-bold">
                {{ template.name }}
              </div>
              <div class="font-mono text-[10px] text-fc-faint">
                IMAGE VERSION {{ shortId(template.imageVersionId) }} · EDITED {{ relativeTime(template.updatedAt, now) }}
              </div>
            </TableCell>
            <TableCell class="font-mono text-xs">
              {{ template.cores }}C · {{ template.memoryMib }} MIB · {{ template.diskGib }} GIB
            </TableCell>
            <TableCell class="font-mono text-xs">
              {{ template.readinessProbe.replace('_', ' ') }} · {{ formatSpan(template.readinessDeadlineSeconds) }}
            </TableCell>
            <TableCell class="font-mono text-xs">
              {{ formatSpan(template.ttlSeconds) }} · {{ template.cleanup }}
            </TableCell>
            <TableCell class="font-mono text-xs">
              <span v-if="template.publishedFrom">{{ shortId(template.publishedFrom) }}</span>
              <span
                v-else
                class="text-fc-warn"
              >DRAFT ONLY</span>
            </TableCell>
            <TableCell class="text-right">
              <button
                type="button"
                class="h-7 rounded-sm border border-input px-2.5 text-xs hover:border-fc-muted"
                :aria-expanded="confirming === template.id"
                :disabled="publishing !== null"
                @click="toggle(template.id)"
              >
                Publish…
              </button>
            </TableCell>
          </TableRow>
          <TableRow
            v-if="confirming === template.id"
            class="hover:bg-transparent"
          >
            <TableCell
              colspan="6"
              class="bg-fc-inset"
            >
              <div class="grid gap-2 text-xs">
                <p>
                  Publishing freezes the current draft of <b>{{ template.name }}</b> into a new immutable version.
                  New leases use it; existing leases keep the version they pinned.
                </p>
                <CopyFleetctl :command="publishCommand(template.id)" />
                <div class="flex gap-2">
                  <button
                    type="button"
                    class="fc-grad-bg h-8 rounded-sm px-3 font-semibold disabled:opacity-50"
                    :disabled="publishing !== null"
                    @click="publish(template)"
                  >
                    Publish version →
                  </button>
                  <button
                    type="button"
                    class="h-8 px-2 text-fc-muted hover:text-fc-ink disabled:opacity-50"
                    :disabled="publishing !== null"
                    @click="confirming = null"
                  >
                    Cancel
                  </button>
                </div>
                <p
                  v-if="error"
                  class="text-fc-err"
                  role="alert"
                >
                  {{ error }}
                </p>
              </div>
            </TableCell>
          </TableRow>
          <TableRow
            v-if="published?.templateId === template.id"
            class="hover:bg-transparent"
          >
            <TableCell
              colspan="6"
              class="text-xs text-fc-ok"
            >
              Published version {{ shortId(published.versionId) }}.
            </TableCell>
          </TableRow>
        </template>
      </TableBody>
    </Table>
  </div>
</template>
