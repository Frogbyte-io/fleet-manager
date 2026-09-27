<script setup lang="ts">
import { computed } from 'vue'
import { RouterLink, useRoute, useRouter } from 'vue-router'

import type { LabTemplateDto, RecipeDto, RecipeVersionDto } from '@frogbyte-io/fleet-api-client'
import StatusChip from '@/components/fleet/StatusChip.vue'
import { Skeleton } from '@/components/ui/skeleton'

import type { Tone } from '../fleet/inventory'
import { isTerminal as leaseEnded, leaseTone } from '../lab/lab'
import { errorMessage, isTerminal } from '../machine/api'
import RecipeEditor from './components/RecipeEditor.vue'
import VersionPanel from './components/VersionPanel.vue'
import { lineage, pinState, templateOfVersion, versionNumbers, type NodeKind, type Selection } from './images'
import { OPERATIONS_LIMIT, useImages } from './useImages'

// Images as a pipeline (docs/planning/web-console.md, Lab decision 2):
// recipes → image versions → Lab templates → environments. Selecting any
// item highlights everything upstream and downstream of it.
const { recipes, versions, templates, leases, operations, builds, loadError, loading } = useImages()
const route = useRoute()
const router = useRouter()

const recipeList = computed(() => [...(recipes.data.value?.items ?? [])].sort((a, b) => a.name.localeCompare(b.name)))
const recipeById = computed(() => new Map(recipeList.value.map(r => [r.id, r])))
const versionList = computed(() => [...versions.value].sort((a, b) =>
  (recipeById.value.get(a.recipeId)?.name ?? '').localeCompare(recipeById.value.get(b.recipeId)?.name ?? '') || b.publishedAt - a.publishedAt))
const numbers = computed(() => versionNumbers(versions.value))
const templateList = computed(() => [...(templates.data.value ?? [])].sort((a, b) => a.name.localeCompare(b.name)))
const leaseList = computed(() => (leases.data.value ?? []).filter(l => !leaseEnded(l.state) || l.state === 'cleanup_failed'))

// Selection lives in the URL (`?select=version:<id>`), so it survives reloads and links.
const selection = computed<Selection | null>(() => {
  const raw = route.query.select
  if (typeof raw !== 'string' || !raw.includes(':'))
    return null
  const kind = raw.slice(0, raw.indexOf(':')) as NodeKind
  return ['recipe', 'version', 'template', 'lease', 'new'].includes(kind) ? { kind, id: raw.slice(raw.indexOf(':') + 1) } : null
})
/** Selects an item; a card click on the selected item (`toggle`) deselects it. */
function select(kind: NodeKind | 'new', id: string, toggle = false) {
  const current = selection.value
  const same = toggle && current?.kind === kind && current.id === id
  router.replace({ query: { ...route.query, select: same ? undefined : `${kind}:${id}` } })
}
function clear() {
  router.replace({ query: { ...route.query, select: undefined } })
}

const creating = computed(() => (selection.value?.kind as string) === 'new')
const highlighted = computed(() => lineage({
  recipes: recipeList.value,
  versions: versions.value,
  templates: templateList.value,
  leases: leaseList.value,
}, creating.value ? null : selection.value))
const active = computed(() => !!selection.value && !creating.value)

function cardClass(kind: NodeKind, id: string) {
  const set = { recipe: highlighted.value.recipes, version: highlighted.value.versions, template: highlighted.value.templates, lease: highlighted.value.leases }[kind]
  const chosen = selection.value?.kind === kind && selection.value.id === id
  if (chosen)
    return 'border-ring bg-card'
  if (!active.value)
    return 'border-fc-line bg-card hover:border-fc-muted'
  return set.has(id) ? 'border-fc-info/50 bg-card' : 'border-fc-line bg-card opacity-40 hover:opacity-80'
}

function versionLabel(v: Pick<RecipeVersionDto, 'id'>) {
  const n = numbers.value.get(v.id)
  return n ? `v${n}` : v.id.slice(-8)
}

const pinnedBy = computed(() => {
  const out = new Map<string, LabTemplateDto[]>()
  for (const t of templateList.value) {
    if (t.imageVersionId)
      out.set(t.imageVersionId, [...(out.get(t.imageVersionId) ?? []), t])
  }
  return out
})

function versionStatus(v: RecipeVersionDto): { label: string, tone: Tone } {
  const build = builds.value.get(v.id)
  if (build && !isTerminal(build.state))
    return { label: 'building', tone: 'info' }
  if (v.promotedAt)
    return { label: 'promoted', tone: 'ok' }
  if (versions.value.some(o => o.recipeId === v.recipeId && o.promotedAt && o.publishedAt > v.publishedAt))
    return { label: 'superseded', tone: 'muted' }
  if (build?.state === 'succeeded')
    return { label: 'built', tone: 'info' }
  if (build && (build.state === 'failed' || build.state === 'timed_out'))
    return { label: 'build failed', tone: 'err' }
  return { label: 'published', tone: 'faint' }
}

function templatePin(t: LabTemplateDto) {
  return pinState(t, versions.value)
}
function pinnedLabel(t: LabTemplateDto) {
  const v = versions.value.find(o => o.id === t.imageVersionId)
  return v ? `${recipeById.value.get(v.recipeId)?.name ?? v.name} ${versionLabel(v)}` : t.imageVersionId
}
function leaseTemplateName(versionId: string) {
  const id = templateOfVersion(templateList.value, versionId)
  return templateList.value.find(t => t.id === id)?.name ?? versionId
}

const selectedRecipe = computed<RecipeDto | null>(() => (selection.value?.kind === 'recipe' ? recipeById.value.get(selection.value.id) ?? null : null))
const selectedVersion = computed(() => (selection.value?.kind === 'version' ? versions.value.find(v => v.id === selection.value!.id) ?? null : null))

// Running builds no version can be matched to yet: started elsewhere, and
// the version is only named in the result.
const unattributed = computed(() => {
  const attributed = new Set([...builds.value.values()].map(o => o.id))
  return (operations.data.value ?? []).filter(o => o.kind === 'image.build' && !isTerminal(o.state) && !attributed.has(o.id))
})

const staleCount = computed(() => templateList.value.filter(t => templatePin(t).stale).length)
</script>

<template>
  <div>
    <div class="flex flex-wrap items-end gap-4">
      <div>
        <p class="fc-kicker">
          recipe → image → template → environment<template v-if="staleCount">
            · <span class="text-fc-warn">{{ staleCount }} stale pin{{ staleCount === 1 ? '' : 's' }}</span>
          </template>
        </p>
        <h1 class="fc-h1">
          Images
        </h1>
      </div>
      <div class="ml-auto flex gap-2">
        <button
          type="button"
          class="fc-grad-bg h-9 rounded-sm px-3.5 font-head text-xs font-bold"
          data-testid="new-recipe"
          @click="select('new', 'recipe')"
        >
          + Recipe
        </button>
      </div>
    </div>

    <div
      v-for="[what, error] in loadError"
      :key="what"
      class="mt-4 border-l-2 border-l-fc-err bg-card px-3 py-2 text-xs text-fc-muted"
      role="alert"
    >
      Could not load {{ what }}: {{ errorMessage(error) }}
    </div>
    <div
      v-if="recipes.data.value?.truncated"
      class="mt-4 border-l-2 border-l-fc-warn bg-card px-3 py-2 text-xs text-fc-muted"
      role="status"
    >
      Showing the first 200 recipes; the recipes API does not page further.
    </div>

    <div
      v-if="loading"
      class="mt-4 grid gap-3 md:grid-cols-4"
    >
      <Skeleton
        v-for="i in 4"
        :key="i"
        class="h-40 rounded-sm"
      />
    </div>

    <div
      v-else
      class="mt-4 grid gap-4 md:grid-cols-2 xl:grid-cols-4"
      data-testid="pipeline"
    >
      <!-- Recipes -->
      <section class="space-y-2">
        <h2 class="fc-kicker flex items-center gap-1 border-b-2 border-fc-ink pb-1">
          Recipes <span class="text-fc-faint">packer .pkr.json</span>
        </h2>
        <p
          v-if="recipeList.length === 0"
          class="text-xs text-fc-muted"
        >
          No recipes yet.
        </p>
        <button
          v-for="recipe in recipeList"
          :key="recipe.id"
          type="button"
          class="block w-full rounded-sm border p-2.5 text-left transition"
          :class="cardClass('recipe', recipe.id)"
          :aria-pressed="selection?.kind === 'recipe' && selection.id === recipe.id"
          :data-testid="`recipe-${recipe.id}`"
          @click="select('recipe', recipe.id, true)"
        >
          <span class="block font-head text-[13px] font-bold">{{ recipe.name }}</span>
          <span class="block font-mono text-[10px] uppercase tracking-wide text-fc-faint">
            proxmox-{{ recipe.source }} · {{ recipe.node }} · {{ versions.filter(v => v.recipeId === recipe.id).length }} versions
          </span>
        </button>
      </section>

      <!-- Image versions -->
      <section class="space-y-2">
        <h2 class="fc-kicker border-b-2 border-fc-ink pb-1">
          Image versions <span class="text-fc-faint">builds</span>
        </h2>
        <p
          v-if="versionList.length === 0"
          class="text-xs text-fc-muted"
        >
          Publish a recipe to create a version.
        </p>
        <button
          v-for="version in versionList"
          :key="version.id"
          type="button"
          class="block w-full rounded-sm border p-2.5 text-left transition"
          :class="cardClass('version', version.id)"
          :aria-pressed="selection?.kind === 'version' && selection.id === version.id"
          :data-testid="`version-${version.id}`"
          @click="select('version', version.id, true)"
        >
          <span class="flex items-center gap-2">
            <span class="font-head text-[13px] font-bold">{{ recipeById.get(version.recipeId)?.name ?? version.name }} {{ versionLabel(version) }}</span>
            <StatusChip
              class="ml-auto"
              :label="versionStatus(version).label"
              :tone="versionStatus(version).tone"
            />
          </span>
          <span class="block font-mono text-[10px] uppercase tracking-wide text-fc-faint">
            {{ version.contentDigest.slice(0, 12) }} · {{ pinnedBy.get(version.id)?.length ?? 0 }} template{{ pinnedBy.get(version.id)?.length === 1 ? '' : 's' }}
            <template v-if="builds.get(version.id)?.progressMessage && !isTerminal(builds.get(version.id)!.state)"> · ▸ {{ builds.get(version.id)!.progressMessage }}</template>
          </span>
        </button>
        <p
          v-if="unattributed.length"
          class="text-[10.5px] text-fc-info"
          data-testid="unattributed-builds"
        >
          {{ unattributed.length }} build{{ unattributed.length === 1 ? '' : 's' }} running that {{ unattributed.length === 1 ? 'was' : 'were' }} started elsewhere; the version shows once the result names it
          (<RouterLink
            to="/operations"
            class="hover:text-fc-ink"
          >
            Operations
          </RouterLink>).
        </p>
        <p class="text-[10.5px] text-fc-faint">
          Build states come from the newest {{ OPERATIONS_LIMIT }} operations.
        </p>
      </section>

      <!-- Lab templates -->
      <section class="space-y-2">
        <h2 class="fc-kicker border-b-2 border-fc-ink pb-1">
          Lab templates <span class="text-fc-faint">pinned</span>
        </h2>
        <p
          v-if="templateList.length === 0"
          class="text-xs text-fc-muted"
        >
          No Lab templates.
        </p>
        <button
          v-for="template in templateList"
          :key="template.id"
          type="button"
          class="block w-full rounded-sm border p-2.5 text-left transition"
          :class="cardClass('template', template.id)"
          :aria-pressed="selection?.kind === 'template' && selection.id === template.id"
          :data-testid="`template-${template.id}`"
          @click="select('template', template.id, true)"
        >
          <span class="flex items-center gap-2">
            <span class="font-head text-[13px] font-bold">{{ template.name }}</span>
            <StatusChip
              v-if="templatePin(template).stale"
              class="ml-auto"
              label="stale pin"
              tone="warn"
            />
          </span>
          <span class="block font-mono text-[10px] uppercase tracking-wide text-fc-faint">
            pins {{ pinnedLabel(template) }}
            <template v-if="templatePin(template).stale">
              · {{ { unknown: 'unknown version', superseded: 'superseded', unpromoted: 'never promoted' }[(templatePin(template) as { reason: 'unknown' | 'superseded' | 'unpromoted' }).reason] }}
            </template>
          </span>
        </button>
      </section>

      <!-- Environments -->
      <section class="space-y-2">
        <h2 class="fc-kicker border-b-2 border-fc-ink pb-1">
          Environments <span class="text-fc-faint">leases</span>
        </h2>
        <p
          v-if="leaseList.length === 0"
          class="text-xs text-fc-muted"
        >
          No active environments.
        </p>
        <button
          v-for="lease in leaseList"
          :key="lease.id"
          type="button"
          class="block w-full rounded-sm border p-2.5 text-left transition"
          :class="cardClass('lease', lease.id)"
          :aria-pressed="selection?.kind === 'lease' && selection.id === lease.id"
          :data-testid="`lease-${lease.id}`"
          @click="select('lease', lease.id, true)"
        >
          <span class="flex items-center gap-2">
            <span class="font-mono text-[12px] font-bold">{{ lease.id.slice(0, 12) }}</span>
            <StatusChip
              class="ml-auto"
              :label="lease.state"
              :tone="leaseTone(lease.state)"
            />
          </span>
          <span class="block font-mono text-[10px] uppercase tracking-wide text-fc-faint">
            {{ leaseTemplateName(lease.templateVersionId) }} · {{ lease.purpose }}
          </span>
        </button>
        <RouterLink
          to="/lab"
          class="block font-mono text-[10px] uppercase tracking-wider text-fc-info hover:text-fc-ink"
        >
          Lab →
        </RouterLink>
      </section>
    </div>

    <div
      v-if="creating || selectedRecipe || selectedVersion || selection?.kind === 'template' || selection?.kind === 'lease'"
      class="mt-6"
    >
      <RecipeEditor
        v-if="creating || selectedRecipe"
        :key="selectedRecipe?.id ?? 'new'"
        :recipe="selectedRecipe"
        @saved="saved => select('recipe', saved.id)"
        @published="version => select('version', version.id)"
        @close="clear"
      />
      <VersionPanel
        v-else-if="selectedVersion"
        :version="selectedVersion"
        :label="versionLabel(selectedVersion)"
        :build="builds.get(selectedVersion.id) ?? null"
        :pinned-by="pinnedBy.get(selectedVersion.id) ?? []"
        :unattributed-running="unattributed.length"
        @close="clear"
      />
      <p
        v-else
        class="text-xs text-fc-muted"
      >
        {{ selection?.kind === 'template' ? 'Templates are created and published' : 'Environments are managed' }} on the
        <RouterLink
          to="/lab"
          class="text-fc-info hover:text-fc-ink"
        >
          Lab
        </RouterLink>
        page; the pipeline above highlights its lineage.
      </p>
    </div>
  </div>
</template>
