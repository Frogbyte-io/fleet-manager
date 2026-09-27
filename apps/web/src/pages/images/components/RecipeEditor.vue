<script setup lang="ts">
import { useQueryClient } from '@tanstack/vue-query'
import { computed, ref, watch } from 'vue'

import {
  createImageRecipe,
  publishImageRecipe,
  updateImageRecipe,
  type RecipeDto,
  type RecipeVersionDto,
} from '@frogbyte-io/fleet-api-client'

import { errorMessage, unwrap } from '../../machine/api'
import CopyFleetctl from '../../machine/components/CopyFleetctl.vue'
import {
  analyze,
  applyFields,
  createRecipeCommand,
  metadataFrom,
  NEW_RECIPE,
  publishRecipeCommand,
  recipeErrors,
  type StructuredFields,
} from '../images'
import { RECIPES_KEY, versionsKey } from '../useImages'
import RawEditor from './RawEditor.vue'

// One recipe draft: Fleet metadata, a structured Proxmox form, and the raw
// template. The form edits only the keys fleet-core's structured view
// reads, in place, so everything else in the template survives.
const props = defineProps<{ recipe: RecipeDto | null }>()
const emit = defineEmits<{ saved: [recipe: RecipeDto], published: [version: RecipeVersionDto], close: [] }>()

const queryClient = useQueryClient()

const name = ref('')
const description = ref('')
const node = ref('')
const storagePool = ref('')
const source = ref<'iso' | 'clone'>('clone')
const content = ref('')

function reset() {
  const r = props.recipe
  name.value = r?.name ?? ''
  description.value = r?.description ?? ''
  node.value = r?.node ?? ''
  storagePool.value = r?.storagePool ?? ''
  source.value = r?.source === 'iso' ? 'iso' : 'clone'
  content.value = r?.content ?? NEW_RECIPE
}
reset()
watch(() => [props.recipe?.id, props.recipe?.updatedAt], reset)

const analysis = computed(() => analyze(content.value))
const fields = computed(() => (analysis.value.editable ? analysis.value.fields : null))

// The builder is the source of truth for node, pool, and source when the
// template has one; the draft metadata follows it.
watch(fields, (value) => {
  if (!value)
    return
  const meta = metadataFrom(value)
  // An empty builder value (e.g. a new template) does not erase metadata
  // the draft already has.
  if (meta.node)
    node.value = meta.node
  if (meta.storagePool)
    storagePool.value = meta.storagePool
  source.value = meta.source
}, { immediate: true })

function update<K extends keyof StructuredFields>(key: K, value: StructuredFields[K]) {
  if (!fields.value)
    return
  content.value = applyFields(content.value, { ...fields.value, [key]: value })
  // A deliberate clear also clears the draft metadata it feeds; the sync
  // watch below only absorbs non-empty builder values.
  if (key === 'node' && String(value).trim() === '')
    node.value = ''
  if (key === 'storagePool' && String(value).trim() === '')
    storagePool.value = ''
}

function numberOrNull(value: string): number | null {
  const n = Number(value)
  return value.trim() !== '' && Number.isInteger(n) && n >= 0 ? n : null
}

const body = computed(() => ({
  name: name.value.trim(),
  description: description.value,
  node: node.value.trim(),
  storagePool: storagePool.value.trim(),
  source: source.value,
  content: content.value,
}))
const errors = computed(() => recipeErrors(body.value))
const dirty = computed(() => {
  const r = props.recipe
  if (!r)
    return true
  const b = body.value
  return b.name !== r.name || b.description !== r.description || b.node !== r.node || b.storagePool !== r.storagePool || b.source !== r.source || b.content !== r.content
})

const busy = ref(false)
const error = ref('')

async function save() {
  if (errors.value.length)
    return
  busy.value = true
  error.value = ''
  try {
    const saved = props.recipe
      ? unwrap<RecipeDto>(await updateImageRecipe(props.recipe.id, body.value))
      : unwrap<RecipeDto>(await createImageRecipe(body.value), [201])
    await queryClient.invalidateQueries({ queryKey: RECIPES_KEY })
    emit('saved', saved)
  }
  catch (caught) {
    error.value = errorMessage(caught)
  }
  finally {
    busy.value = false
  }
}

async function publish() {
  if (!props.recipe || dirty.value)
    return
  busy.value = true
  error.value = ''
  try {
    const version = unwrap<RecipeVersionDto>(await publishImageRecipe(props.recipe.id), [201])
    await Promise.all([
      queryClient.invalidateQueries({ queryKey: versionsKey(props.recipe.id) }),
      queryClient.invalidateQueries({ queryKey: RECIPES_KEY }),
    ])
    emit('published', version)
  }
  catch (caught) {
    error.value = errorMessage(caught)
  }
  finally {
    busy.value = false
  }
}

const command = computed(() => {
  if (!props.recipe)
    return errors.value.length ? null : createRecipeCommand(body.value)
  return dirty.value ? null : publishRecipeCommand(props.recipe.id)
})
const missing = computed(() => (props.recipe && dirty.value
  ? 'fleetctl has no recipe update command; save the draft here, then publish.'
  : 'Fix the draft to see the command.'))

const inputClass = 'h-8 rounded-sm border border-input bg-background px-2 font-mono text-foreground'
</script>

<template>
  <div
    class="space-y-4 rounded-sm border border-fc-line bg-card p-4"
    data-testid="recipe-editor"
  >
    <div class="flex items-start gap-2">
      <div>
        <p class="fc-kicker">
          {{ recipe ? `recipe · ${recipe.id}` : 'new recipe' }} · structured ⇄ raw · unknown fields preserved
        </p>
        <h3 class="font-head text-[17px] font-extrabold">
          {{ name || 'Untitled recipe' }}
          <span
            v-if="dirty"
            class="ml-1 font-mono text-[11px] font-normal text-fc-warn"
          >{{ recipe ? 'unsaved' : 'not saved' }}</span>
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

    <div class="grid gap-2 text-xs sm:grid-cols-2">
      <label class="flex flex-col gap-1">
        <span class="fc-kicker">Name</span>
        <input
          v-model="name"
          :class="inputClass"
          data-testid="recipe-name"
        >
      </label>
      <label class="flex flex-col gap-1">
        <span class="fc-kicker">Description</span>
        <input
          v-model="description"
          class="h-8 rounded-sm border border-input bg-background px-2 text-foreground"
        >
      </label>
    </div>

    <div class="grid gap-4 xl:grid-cols-2">
      <section class="space-y-2 text-xs">
        <h4 class="fc-kicker border-b border-fc-line pb-1">
          Structured (Proxmox builder)
        </h4>
        <template v-if="fields">
          <div class="grid grid-cols-2 gap-2">
            <label class="flex flex-col gap-1">
              <span class="fc-kicker">Builder</span>
              <select
                :value="fields.builderType"
                class="h-8 rounded-sm border border-input bg-background px-2 text-foreground"
                data-testid="field-builder"
                @change="update('builderType', ($event.target as HTMLSelectElement).value as StructuredFields['builderType'])"
              >
                <option value="proxmox-clone">proxmox-clone</option>
                <option value="proxmox-iso">proxmox-iso</option>
              </select>
            </label>
            <label class="flex flex-col gap-1">
              <span class="fc-kicker">Node</span>
              <input
                :value="fields.node"
                :class="inputClass"
                data-testid="field-node"
                @change="update('node', ($event.target as HTMLInputElement).value)"
              >
            </label>
            <label class="flex flex-col gap-1">
              <span class="fc-kicker">Storage pool</span>
              <input
                :value="fields.storagePool"
                :class="inputClass"
                data-testid="field-pool"
                @change="update('storagePool', ($event.target as HTMLInputElement).value)"
              >
            </label>
            <label
              v-if="fields.builderType === 'proxmox-clone'"
              class="flex flex-col gap-1"
            >
              <span class="fc-kicker">Clone from (VM name or VMID)</span>
              <input
                :value="fields.cloneVm"
                :class="inputClass"
                data-testid="field-clone"
                @change="update('cloneVm', ($event.target as HTMLInputElement).value)"
              >
            </label>
            <template v-else>
              <label class="flex flex-col gap-1">
                <span class="fc-kicker">ISO file</span>
                <input
                  :value="fields.isoFile"
                  :class="inputClass"
                  @change="update('isoFile', ($event.target as HTMLInputElement).value)"
                >
              </label>
              <label class="flex flex-col gap-1">
                <span class="fc-kicker">ISO storage pool</span>
                <input
                  :value="fields.isoStoragePool"
                  :class="inputClass"
                  @change="update('isoStoragePool', ($event.target as HTMLInputElement).value)"
                >
              </label>
            </template>
            <label class="flex flex-col gap-1">
              <span class="fc-kicker">Cores</span>
              <input
                :value="fields.cores ?? ''"
                type="number"
                min="1"
                :class="inputClass"
                data-testid="field-cores"
                @change="update('cores', numberOrNull(($event.target as HTMLInputElement).value))"
              >
            </label>
            <label class="flex flex-col gap-1">
              <span class="fc-kicker">Memory (MiB)</span>
              <input
                :value="fields.memory ?? ''"
                type="number"
                min="1"
                :class="inputClass"
                data-testid="field-memory"
                @change="update('memory', numberOrNull(($event.target as HTMLInputElement).value))"
              >
            </label>
            <label class="flex flex-col gap-1">
              <span class="fc-kicker">Disk size</span>
              <input
                :value="fields.diskSize"
                placeholder="40G"
                :class="inputClass"
                @change="update('diskSize', ($event.target as HTMLInputElement).value)"
              >
            </label>
            <label class="flex flex-col gap-1">
              <span class="fc-kicker">Bridge</span>
              <input
                :value="fields.bridge"
                placeholder="vmbr0"
                :class="inputClass"
                @change="update('bridge', ($event.target as HTMLInputElement).value)"
              >
            </label>
            <label class="flex flex-col gap-1">
              <span class="fc-kicker">Cloud-init user</span>
              <input
                :value="fields.cloudInitUser"
                :class="inputClass"
                @change="update('cloudInitUser', ($event.target as HTMLInputElement).value)"
              >
            </label>
            <label class="col-span-2 flex flex-col gap-1">
              <span class="fc-kicker">Cloud-init SSH keys (URL-encoded)</span>
              <input
                :value="fields.sshKeys"
                :class="inputClass"
                @change="update('sshKeys', ($event.target as HTMLInputElement).value)"
              >
            </label>
          </div>
          <p class="text-[11px] text-fc-faint">
            These are the keys Fleet's structured view reads from the first Proxmox builder. Everything else in the template (other builders, provisioners, variables, unknown fields) is left as it is. A cleared field removes its key.
          </p>
        </template>
        <template v-else>
          <p
            class="border-l-2 border-l-fc-warn bg-fc-inset px-3 py-2 text-fc-muted"
            data-testid="raw-only"
          >
            {{ analysis.editable ? '' : analysis.reason }}
          </p>
          <div class="grid grid-cols-3 gap-2">
            <label class="flex flex-col gap-1">
              <span class="fc-kicker">Node</span>
              <input
                v-model="node"
                :class="inputClass"
              >
            </label>
            <label class="flex flex-col gap-1">
              <span class="fc-kicker">Storage pool</span>
              <input
                v-model="storagePool"
                :class="inputClass"
              >
            </label>
            <label class="flex flex-col gap-1">
              <span class="fc-kicker">Source</span>
              <select
                v-model="source"
                class="h-8 rounded-sm border border-input bg-background px-2 text-foreground"
              >
                <option value="clone">clone</option>
                <option value="iso">iso</option>
              </select>
            </label>
          </div>
        </template>
      </section>

      <section class="space-y-2 text-xs">
        <h4 class="fc-kicker border-b border-fc-line pb-1">
          Raw .pkr.json
        </h4>
        <RawEditor
          v-model="content"
          label="Raw Packer template"
        />
      </section>
    </div>

    <ul
      v-if="errors.length"
      class="list-disc pl-5 text-xs text-fc-warn"
      data-testid="recipe-errors"
    >
      <li
        v-for="item in errors"
        :key="item"
      >
        {{ item }}
      </li>
    </ul>

    <div class="flex flex-wrap items-center gap-2 text-xs">
      <button
        type="button"
        class="h-8 rounded-sm border border-input px-3 font-head font-bold hover:border-fc-muted disabled:opacity-50"
        :disabled="!dirty || errors.length > 0 || busy"
        data-testid="recipe-save"
        @click="save"
      >
        Save draft
      </button>
      <button
        type="button"
        class="fc-grad-bg h-8 rounded-sm px-3 font-head font-bold disabled:opacity-50"
        :disabled="!recipe || dirty || busy"
        :title="!recipe || dirty ? 'Save the draft first' : ''"
        data-testid="recipe-publish"
        @click="publish"
      >
        Publish version →
      </button>
      <span class="text-fc-faint">Publishing freezes an immutable version by content digest; publishing unchanged content returns the same version.</span>
    </div>
    <p
      v-if="error"
      class="text-xs text-fc-err"
      role="alert"
    >
      {{ error }}
    </p>
    <CopyFleetctl
      :command="command"
      :missing="missing"
    />
  </div>
</template>
