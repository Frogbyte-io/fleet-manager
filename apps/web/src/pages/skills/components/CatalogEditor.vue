<script setup lang="ts">
import { useQueryClient } from '@tanstack/vue-query'
import { computed, ref, watch } from 'vue'

import {
  createSkillCatalog,
  publishSkillCatalog,
  updateSkillCatalog,
  type CatalogContentDto,
  type CatalogDto,
  type CatalogVersionDto,
  type MachineDto,
} from '@frogbyte-io/fleet-api-client'

import { errorMessage, unwrap } from '../../machine/api'
import CopyFleetctl from '../../machine/components/CopyFleetctl.vue'
import { catalogPublishCommand, catalogSaveCommand } from '../actions'
import {
  authoredContent,
  authoredErrors,
  referencedContent,
  referencedErrors,
  sameContent,
  shortDigest,
  sourceLabel,
  type EditableFile,
  type ReferencedInput,
} from '../catalog'
import type { AgentEntry, MatrixColumn } from '../model'
import { CATALOG_KEY, useCatalogVersions, versionsKey } from '../useSkills'
import AssignmentEditor from './AssignmentEditor.vue'
import RolloutPanel from './RolloutPanel.vue'
import VersionDiff from './VersionDiff.vue'

// One catalog entry: edit the draft (SKILL.md frontmatter checked while
// typing), publish immutable versions, diff them, roll one out, and build
// its Fleet Git assignment.
const props = defineProps<{
  entry: CatalogDto | null
  kind: 'authored' | 'referenced'
  machines: MachineDto[]
  columns: MatrixColumn[]
  agents: AgentEntry[]
}>()
const emit = defineEmits<{ saved: [entry: CatalogDto], close: [] }>()

const queryClient = useQueryClient()

const TEMPLATE = `---
name: my-skill
description: What this skill does and when an agent should use it.
---

# My skill

Instructions for the agent.
`

const kind = computed(() => props.entry?.content.source.kind ?? props.kind)
// Built-in entries (ADR 0012) change only with a controller release; the
// API refuses edits, so the editor offers none.
const builtin = computed(() => props.entry?.id.startsWith('builtin-') ?? false)
const locked = computed(() => saving.value || builtin.value)

function initialFiles(): EditableFile[] {
  const files = props.entry?.content.files ?? []
  if (files.length === 0)
    return [{ path: 'SKILL.md', content: TEMPLATE }]
  // SKILL.md first, the rest by path.
  return [...files].sort((a, b) => (a.path === 'SKILL.md' ? -1 : b.path === 'SKILL.md' ? 1 : a.path.localeCompare(b.path)))
    .map(f => ({ path: f.path, content: f.content }))
}

function initialReferenced(): ReferencedInput {
  const content = props.entry?.content
  const source = content?.source
  return {
    name: content?.name ?? '',
    description: content?.description ?? '',
    reference: source?.kind === 'referenced' ? source.reference : '',
    subpath: source?.kind === 'referenced' ? source.subpath ?? '' : '',
    revision: source?.kind === 'referenced' ? source.revision ?? '' : '',
  }
}

const files = ref<EditableFile[]>(initialFiles())
const active = ref(0)
const referenced = ref<ReferencedInput>(initialReferenced())

// A different entry (or a saved one coming back from the server) resets the form.
watch(() => [props.entry?.id, props.entry?.updatedAt], () => {
  files.value = initialFiles()
  referenced.value = initialReferenced()
  active.value = Math.min(active.value, files.value.length - 1)
})

const errors = computed(() => (kind.value === 'authored' ? authoredErrors(files.value) : referencedErrors(referenced.value)))
const content = computed<CatalogContentDto | null>(() =>
  kind.value === 'authored' ? authoredContent(files.value) : referencedContent(referenced.value))
const dirty = computed(() => !props.entry || !content.value || !sameContent(content.value, props.entry.content))

const newPath = ref('')
const pathError = computed(() => {
  const path = newPath.value.trim()
  if (!path)
    return null
  return files.value.some(f => f.path === path) ? 'that file already exists' : null
})
function addFile() {
  const path = newPath.value.trim()
  if (!path || pathError.value)
    return
  files.value = [...files.value, { path, content: '' }]
  active.value = files.value.length - 1
  newPath.value = ''
}
function removeFile(index: number) {
  files.value = files.value.filter((_, i) => i !== index)
  active.value = Math.max(0, Math.min(active.value, files.value.length - 1))
}

const saving = ref(false)
const saveError = ref('')

async function save() {
  if (!content.value || errors.value.length)
    return
  saving.value = true
  saveError.value = ''
  try {
    const body = { content: content.value }
    const saved = props.entry
      ? unwrap<CatalogDto>(await updateSkillCatalog(props.entry.id, body))
      : unwrap<CatalogDto>(await createSkillCatalog(body), [201])
    await queryClient.invalidateQueries({ queryKey: CATALOG_KEY })
    emit('saved', saved)
  }
  catch (error) {
    saveError.value = errorMessage(error)
  }
  finally {
    saving.value = false
  }
}

const versionsQuery = useCatalogVersions(() => props.entry?.id ?? null)
const versions = computed<CatalogVersionDto[]>(() => versionsQuery.data.value?.items ?? [])
const latest = computed(() => versions.value[0] ?? null)
const alreadyPublished = computed(() => !!props.entry && !!latest.value && sameContent(props.entry.content, latest.value.content))

const publishing = ref(false)
const publishError = ref('')
const publishedId = ref<string | null>(null)

async function publish() {
  if (!props.entry)
    return
  publishing.value = true
  publishError.value = ''
  try {
    const version = unwrap<CatalogVersionDto>(await publishSkillCatalog(props.entry.id), [201])
    publishedId.value = version.id
    await queryClient.invalidateQueries({ queryKey: versionsKey(props.entry.id) })
    rolloutVersionId.value = version.id
    section.value = 'rollout'
  }
  catch (error) {
    publishError.value = errorMessage(error)
  }
  finally {
    publishing.value = false
  }
}

type Section = 'edit' | 'versions' | 'rollout' | 'assign'
const section = ref<Section>('edit')
const SECTIONS: { id: Section, label: string }[] = [
  { id: 'edit', label: 'Draft' },
  { id: 'versions', label: 'Versions' },
  { id: 'rollout', label: 'Roll out' },
  { id: 'assign', label: 'Assign' },
]

// Diff: a published version against the draft or another version.
const DRAFT = '__draft__'
const diffBase = ref('')
const diffTarget = ref(DRAFT)
watch(versions, (list) => {
  if (!list.some(v => v.id === diffBase.value))
    diffBase.value = list[0]?.id ?? ''
}, { immediate: true })
const draftContent = computed(() => content.value ?? props.entry?.content ?? null)
function contentOf(id: string): CatalogContentDto | null {
  return id === DRAFT ? draftContent.value : versions.value.find(v => v.id === id)?.content ?? null
}
function labelOf(id: string): string {
  if (id === DRAFT)
    return dirty.value ? 'draft (unsaved edits)' : 'draft'
  const version = versions.value.find(v => v.id === id)
  return version ? shortDigest(version.contentDigest) : id
}

const rolloutVersionId = ref('')
watch(versions, (list) => {
  if (!list.some(v => v.id === rolloutVersionId.value))
    rolloutVersionId.value = list[0]?.id ?? ''
}, { immediate: true })
const rolloutVersion = computed(() => versions.value.find(v => v.id === rolloutVersionId.value) ?? null)

const saveCommand = computed(() => (content.value && !errors.value.length ? catalogSaveCommand(props.entry?.id ?? null, content.value) : null))
</script>

<template>
  <div
    class="flex flex-col gap-3 rounded-sm border border-fc-line bg-card p-4"
    data-testid="catalog-editor"
  >
    <div class="flex items-start gap-2">
      <div class="min-w-0">
        <p class="fc-kicker">
          {{ kind === 'authored' ? 'Fleet-authored skill' : 'Referenced skill' }}<template v-if="entry">
            · {{ entry.id }}
          </template>
        </p>
        <h3 class="font-head text-[17px] font-extrabold">
          {{ content?.name || entry?.content.name || 'New skill' }}
          <span
            v-if="latest"
            class="ml-1 font-mono text-[11px] font-normal text-fc-faint"
          >latest {{ shortDigest(latest.contentDigest) }}</span>
          <span
            v-if="dirty"
            class="ml-1 font-mono text-[11px] font-normal text-fc-warn"
          >{{ entry ? 'unsaved' : 'not saved' }}</span>
        </h3>
      </div>
      <button
        type="button"
        class="ml-auto text-fc-muted hover:text-fc-ink"
        aria-label="Close editor"
        @click="emit('close')"
      >
        ✕
      </button>
    </div>

    <div
      class="flex gap-4 border-b border-fc-line text-xs"
      role="tablist"
    >
      <button
        v-for="item in SECTIONS"
        :key="item.id"
        type="button"
        role="tab"
        class="pb-1.5 font-semibold"
        :class="section === item.id ? 'text-fc-ink shadow-[inset_0_-2px_0_var(--fc-g1)]' : 'text-fc-muted hover:text-fc-ink'"
        :aria-selected="section === item.id"
        :disabled="item.id !== 'edit' && !entry"
        :data-testid="`editor-${item.id}`"
        @click="section = item.id"
      >
        {{ item.label }}<span
          v-if="item.id === 'versions' && versions.length"
          class="ml-1 font-mono text-[10px] text-fc-faint"
        >{{ versions.length }}</span>
      </button>
    </div>

    <!-- Draft -->
    <template v-if="section === 'edit'">
      <p
        v-if="builtin"
        class="border-l-2 border-l-fc-info bg-fc-inset px-3 py-2 text-xs text-fc-muted"
        data-testid="catalog-builtin"
      >
        Built into the controller: this skill changes only with a controller release, so it cannot be edited or published here. It is assigned to every machine by default; Fleet Git takes it over with its own <span class="font-mono">SkillPreset</span> (an empty <span class="font-mono">deployTo</span> removes it everywhere). Roll out and Assign still work.
      </p>
      <template v-if="kind === 'authored'">
        <div class="flex flex-wrap items-center gap-1 text-xs">
          <button
            v-for="(file, index) in files"
            :key="file.path"
            type="button"
            class="rounded-sm border px-2 py-0.5 font-mono"
            :class="index === active ? 'border-ring text-fc-ink' : 'border-fc-line2 text-fc-muted'"
            @click="active = index"
          >
            {{ file.path }}
          </button>
          <input
            v-model="newPath"
            :disabled="locked"
            placeholder="references/notes.md"
            class="h-6 w-40 rounded-sm border border-input bg-background px-1.5 font-mono text-[11px] text-foreground"
            aria-label="New file path"
            @keydown.enter.prevent="addFile"
          >
          <button
            type="button"
            class="font-mono text-[10px] uppercase tracking-wider text-fc-info disabled:opacity-50"
            :disabled="locked || !newPath.trim() || !!pathError"
            @click="addFile"
          >
            + File
          </button>
          <span
            v-if="pathError"
            class="text-fc-err"
          >{{ pathError }}</span>
        </div>
        <div
          v-if="files[active]"
          class="space-y-1"
        >
          <div class="flex items-center gap-2">
            <label
              class="fc-kicker"
              :for="`file-${active}`"
            >{{ files[active]!.path }}</label>
            <button
              v-if="files[active]!.path !== 'SKILL.md'"
              type="button"
              class="ml-auto font-mono text-[10px] uppercase tracking-wider text-fc-err"
              @click="removeFile(active)"
            >
              Remove file
            </button>
          </div>
          <textarea
            :id="`file-${active}`"
            v-model="files[active]!.content"
            :readonly="locked"
            rows="16"
            spellcheck="false"
            class="w-full rounded-sm border border-input bg-fc-inset p-2.5 font-mono text-[12px] leading-relaxed text-foreground"
            data-testid="skill-md"
          />
        </div>
        <p class="text-[11px] text-fc-faint">
          The catalog name and description come from SKILL.md's frontmatter, so they always match. Only the files listed here are shipped.
        </p>
      </template>

      <template v-else>
        <div class="grid gap-2 text-xs sm:grid-cols-2">
          <label class="flex flex-col gap-1">
            <span class="fc-kicker">Name</span>
            <input
              v-model="referenced.name"
              :readonly="locked"
              class="h-8 rounded-sm border border-input bg-background px-2 font-mono text-foreground"
              data-testid="ref-name"
            >
          </label>
          <label class="flex flex-col gap-1 sm:col-span-2">
            <span class="fc-kicker">Description</span>
            <input
              v-model="referenced.description"
              :readonly="locked"
              class="h-8 rounded-sm border border-input bg-background px-2 text-foreground"
              data-testid="ref-description"
            >
          </label>
          <label class="flex flex-col gap-1 sm:col-span-2">
            <span class="fc-kicker">Reference (skills.sh ref or Git URL)</span>
            <input
              v-model="referenced.reference"
              :readonly="locked"
              placeholder="https://github.com/org/skills"
              class="h-8 rounded-sm border border-input bg-background px-2 font-mono text-foreground"
              data-testid="ref-reference"
            >
          </label>
          <label class="flex flex-col gap-1">
            <span class="fc-kicker">Subpath (pinned with revision)</span>
            <input
              v-model="referenced.subpath"
              :readonly="locked"
              class="h-8 rounded-sm border border-input bg-background px-2 font-mono text-foreground"
            >
          </label>
          <label class="flex flex-col gap-1">
            <span class="fc-kicker">Revision (full commit id)</span>
            <input
              v-model="referenced.revision"
              :readonly="locked"
              class="h-8 rounded-sm border border-input bg-background px-2 font-mono text-foreground"
            >
          </label>
        </div>
      </template>

      <ul
        v-if="errors.length"
        class="list-disc space-y-0.5 pl-5 text-xs text-fc-warn"
        data-testid="catalog-errors"
      >
        <li
          v-for="error in errors"
          :key="error"
        >
          {{ error }}
        </li>
      </ul>
      <p
        v-else
        class="text-xs text-fc-ok"
        data-testid="catalog-valid"
      >
        {{ kind === 'authored' ? 'Frontmatter and content pass the console\'s early checks' : 'The name, description, and source pin pass the console\'s early checks' }}; the controller validates again on save.
      </p>

      <div class="flex flex-wrap items-center gap-2 text-xs">
        <button
          type="button"
          class="h-8 rounded-sm border border-input px-3 font-head font-bold hover:border-fc-muted disabled:opacity-50"
          :disabled="builtin || !dirty || errors.length > 0 || saving"
          data-testid="catalog-save"
          @click="save"
        >
          Save draft
        </button>
        <button
          type="button"
          class="fc-grad-bg h-8 rounded-sm px-3 font-head font-bold disabled:opacity-50"
          :disabled="builtin || !entry || dirty || errors.length > 0 || publishing || alreadyPublished"
          :title="!entry || dirty ? 'Save the draft first' : alreadyPublished ? 'The latest version already has this content' : ''"
          data-testid="catalog-publish"
          @click="publish"
        >
          Publish version →
        </button>
        <span
          v-if="alreadyPublished"
          class="text-fc-faint"
        >Published as {{ shortDigest(latest!.contentDigest) }}.</span>
      </div>
      <p
        v-if="saveError"
        class="text-xs text-fc-err"
        role="alert"
      >
        {{ saveError }}
      </p>
      <p
        v-if="publishError"
        class="text-xs text-fc-err"
        role="alert"
      >
        {{ publishError }}
      </p>
      <CopyFleetctl
        :command="dirty ? saveCommand : entry ? catalogPublishCommand(entry.id) : null"
        missing="Fix the draft to see the command."
      />
    </template>

    <!-- Versions -->
    <template v-else-if="section === 'versions'">
      <p
        v-if="versionsQuery.isLoading.value"
        class="text-xs text-fc-faint"
      >
        Loading versions…
      </p>
      <p
        v-else-if="versionsQuery.error.value"
        class="text-xs text-fc-err"
        role="alert"
      >
        Versions unavailable: {{ errorMessage(versionsQuery.error.value) }}
      </p>
      <p
        v-else-if="versions.length === 0"
        class="text-xs text-fc-muted"
      >
        Nothing published yet. Save the draft and publish it to create the first immutable version.
      </p>
      <template v-else>
        <p
          v-if="versionsQuery.data.value?.truncated"
          class="text-xs text-fc-warn"
          role="status"
        >
          Version history hit the 20-page safety cap; older versions are not listed.
        </p>
        <ul
          class="divide-y divide-fc-line text-xs"
          data-testid="catalog-versions"
        >
          <li
            v-for="version in versions"
            :key="version.id"
            class="flex flex-wrap items-center gap-2 py-1.5 font-mono text-[11px]"
          >
            <span class="text-fc-ink">{{ shortDigest(version.contentDigest) }}</span>
            <span class="text-fc-faint">{{ new Date(version.publishedAt).toISOString().replace('T', ' ').slice(0, 16) }}Z</span>
            <span class="text-fc-muted">{{ sourceLabel(version.content) }}</span>
            <span
              v-if="version.id === publishedId"
              class="text-fc-ok"
            >just published</span>
            <button
              type="button"
              class="ml-auto uppercase tracking-wider text-fc-info hover:text-fc-ink"
              @click="diffBase = version.id; diffTarget = DRAFT"
            >
              Diff vs draft
            </button>
            <button
              type="button"
              class="uppercase tracking-wider text-fc-info hover:text-fc-ink"
              @click="rolloutVersionId = version.id; section = 'rollout'"
            >
              Roll out
            </button>
          </li>
        </ul>
        <div class="flex flex-wrap items-end gap-2 text-xs">
          <label class="flex flex-col gap-1">
            <span class="fc-kicker">From</span>
            <select
              v-model="diffBase"
              class="h-8 rounded-sm border border-input bg-background px-2 font-mono text-foreground"
              data-testid="diff-base"
            >
              <option
                v-for="version in versions"
                :key="version.id"
                :value="version.id"
              >
                {{ labelOf(version.id) }}
              </option>
            </select>
          </label>
          <label class="flex flex-col gap-1">
            <span class="fc-kicker">To</span>
            <select
              v-model="diffTarget"
              class="h-8 rounded-sm border border-input bg-background px-2 font-mono text-foreground"
              data-testid="diff-target"
            >
              <option :value="DRAFT">
                {{ labelOf(DRAFT) }}
              </option>
              <option
                v-for="version in versions"
                :key="version.id"
                :value="version.id"
              >
                {{ labelOf(version.id) }}
              </option>
            </select>
          </label>
        </div>
        <VersionDiff
          v-if="contentOf(diffBase) && contentOf(diffTarget)"
          :before="contentOf(diffBase)!"
          :after="contentOf(diffTarget)!"
          :before-label="labelOf(diffBase)"
          :after-label="labelOf(diffTarget)"
        />
      </template>
    </template>

    <!-- Roll out -->
    <template v-else-if="section === 'rollout'">
      <p
        v-if="versions.length === 0"
        class="text-xs text-fc-muted"
      >
        Publish a version first: rollouts install one immutable version.
      </p>
      <template v-else>
        <label class="flex flex-col gap-1 text-xs">
          <span class="fc-kicker">Version</span>
          <select
            v-model="rolloutVersionId"
            class="h-8 w-64 rounded-sm border border-input bg-background px-2 font-mono text-foreground"
            data-testid="rollout-version"
          >
            <option
              v-for="version in versions"
              :key="version.id"
              :value="version.id"
            >
              {{ shortDigest(version.contentDigest) }} · {{ new Date(version.publishedAt).toISOString().slice(0, 10) }}
            </option>
          </select>
        </label>
        <RolloutPanel
          v-if="rolloutVersion"
          :version="rolloutVersion"
          :machines="machines"
          :columns="columns"
          :agents="agents"
        />
      </template>
    </template>

    <!-- Assign -->
    <AssignmentEditor
      v-else-if="entry"
      :skill-id="entry.content.name"
      :catalog-id="entry.id"
      :versions="versions"
      :agents="agents"
      :machines="machines"
    />
  </div>
</template>
