<script setup lang="ts">
import { computed } from 'vue'
import { RouterLink } from 'vue-router'
import type { RegistryTypeDto } from '@frogbyte-io/fleet-api-client'

import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from '@/components/ui/sheet'

import { errorMessage } from '../../machine/api'
import {
  entryLinks,
  fieldDefs,
  fieldValues,
  renderValue,
  setCommand,
  sourceLocation,
  targetLink,
  undeclaredFields,
} from '../registry'
import { useDesiredSourceRemote, useMachineIds, useRegistryEntry, useRegistryReferencedBy } from '../useRegistry'
import ValueView from './ValueView.vue'

// One entry, read-only: fields by the type's definition, links, notes,
// relations both ways, and the revision and file it came from.
const props = defineProps<{ type: RegistryTypeDto, entryKey: string }>()
const emit = defineEmits<{ close: [] }>()

const typeName = computed(() => props.type.name)
const key = computed(() => props.entryKey)
const entry = useRegistryEntry(typeName, key)
const referencedBy = useRegistryReferencedBy(typeName, key)
const machines = useMachineIds(true)
const source = useDesiredSourceRemote(true)

const data = computed(() => entry.data.value?.data ?? null)
const revision = computed(() => entry.data.value?.revision ?? null)
const defs = computed(() => fieldDefs(props.type.spec, props.type.keyField))
const values = computed(() => fieldValues(data.value?.fields))
const extra = computed(() => undeclaredFields(data.value?.fields, defs.value))
const links = computed(() => entryLinks(data.value?.links))
const machineIds = computed(() => machines.data.value ?? new Map<string, string>())
const outgoing = computed(() => (data.value?.relations ?? []).map(r => ({ relation: r.type, link: targetLink(r.target, machineIds.value) })))
const incoming = computed(() => (referencedBy.data.value?.items ?? []).map(r => ({
  relation: r.relation,
  label: `${r.entryType}/${r.entryKey}`,
  to: { path: '/registry', query: { type: r.entryType, entry: r.entryKey } },
})))
const location = computed(() => sourceLocation(source.data.value, revision.value?.commitSha, data.value?.sourcePath))

function onOpenChange(open: boolean) {
  if (!open)
    emit('close')
}
</script>

<template>
  <Sheet
    :open="true"
    @update:open="onOpenChange"
  >
    <SheetContent
      class="w-full overflow-y-auto sm:max-w-[420px]"
      data-testid="registry-drawer"
    >
      <SheetHeader>
        <p class="fc-kicker">
          {{ type.displayName }} · {{ type.name }}/{{ entryKey }}
        </p>
        <SheetTitle class="font-head text-lg font-extrabold">
          {{ entryKey }}
        </SheetTitle>
        <SheetDescription class="sr-only">
          Read-only Registry entry
        </SheetDescription>
      </SheetHeader>

      <div class="grid gap-5 px-4 pb-6 text-[13px]">
        <p
          v-if="entry.error.value"
          class="border-l-2 border-l-fc-err bg-card px-3 py-2 text-xs text-fc-muted"
          role="alert"
        >
          Could not load this entry: {{ errorMessage(entry.error.value) }}
        </p>
        <p
          v-else-if="entry.isLoading.value"
          class="text-xs text-fc-muted"
        >
          Loading…
        </p>

        <template v-if="data">
          <section>
            <h2 class="fc-kicker border-b border-fc-line pb-1">
              Fields
            </h2>
            <dl
              class="mt-2 grid gap-2"
              data-testid="drawer-fields"
            >
              <div
                v-for="def in defs"
                :key="def.name"
              >
                <dt class="font-mono text-[10px] uppercase tracking-wider text-fc-faint">
                  {{ def.name }}<span v-if="def.required"> · required</span>
                </dt>
                <dd class="mt-0.5">
                  <ValueView :value="renderValue(def, values[def.name])" />
                </dd>
              </div>
              <div
                v-for="name in extra"
                :key="name"
              >
                <dt class="font-mono text-[10px] uppercase tracking-wider text-fc-faint">
                  {{ name }} · not declared by the type
                </dt>
                <dd class="mt-0.5">
                  <ValueView :value="renderValue({ type: 'string', items: null }, typeof values[name] === 'object' ? JSON.stringify(values[name]) : values[name])" />
                </dd>
              </div>
            </dl>
          </section>

          <section v-if="data.tags.length">
            <h2 class="fc-kicker border-b border-fc-line pb-1">
              Tags
            </h2>
            <p class="mt-2 flex flex-wrap gap-1">
              <span
                v-for="tag in data.tags"
                :key="tag"
                class="rounded-sm border border-fc-line2 px-1.5 py-px font-mono text-[10px] text-fc-muted"
              >{{ tag }}</span>
            </p>
          </section>

          <section v-if="links.length">
            <h2 class="fc-kicker border-b border-fc-line pb-1">
              Links
            </h2>
            <ul
              class="mt-2 grid gap-1"
              data-testid="drawer-links"
            >
              <li
                v-for="link in links"
                :key="link.url"
              >
                <a
                  v-if="link.href"
                  :href="link.href"
                  target="_blank"
                  rel="noopener noreferrer"
                  class="text-fc-info hover:underline"
                >{{ link.label }}</a>
                <span v-else>{{ link.label }} <span class="font-mono text-[11px] text-fc-faint">{{ link.url }}</span></span>
              </li>
            </ul>
          </section>

          <section v-if="data.notes">
            <h2 class="fc-kicker border-b border-fc-line pb-1">
              Notes
            </h2>
            <p class="mt-2 whitespace-pre-wrap text-fc-muted">
              {{ data.notes }}
            </p>
          </section>

          <section>
            <h2 class="fc-kicker border-b border-fc-line pb-1">
              Relations
            </h2>
            <p class="fc-kicker mt-2">
              Points at
            </p>
            <ul
              v-if="outgoing.length"
              class="mt-1 grid gap-1"
              data-testid="drawer-outgoing"
            >
              <li
                v-for="(item, index) in outgoing"
                :key="index"
                class="flex flex-wrap items-baseline gap-2"
              >
                <span class="font-mono text-[10px] uppercase tracking-wider text-fc-muted">{{ item.relation }}</span>
                <span class="text-[11px] text-fc-faint">{{ item.link.classLabel }}</span>
                <RouterLink
                  v-if="item.link.to"
                  :to="item.link.to"
                  class="break-all text-fc-info hover:underline"
                >
                  {{ item.link.label }}
                </RouterLink>
                <span
                  v-else
                  class="break-all font-mono text-[11.5px]"
                >{{ item.link.label }}</span>
              </li>
            </ul>
            <p
              v-else
              class="mt-1 text-xs text-fc-faint"
            >
              No outgoing relations.
            </p>
            <p class="fc-kicker mt-3">
              Referenced by
            </p>
            <p
              v-if="referencedBy.error.value"
              class="mt-1 text-xs text-fc-muted"
              role="alert"
            >
              Could not load references: {{ errorMessage(referencedBy.error.value) }}
            </p>
            <ul
              v-else-if="incoming.length"
              class="mt-1 grid gap-1"
              data-testid="drawer-incoming"
            >
              <li
                v-for="(item, index) in incoming"
                :key="index"
                class="flex flex-wrap items-baseline gap-2"
              >
                <span class="font-mono text-[10px] uppercase tracking-wider text-fc-muted">{{ item.relation }}</span>
                <RouterLink
                  :to="item.to"
                  class="break-all text-fc-info hover:underline"
                >
                  {{ item.label }}
                </RouterLink>
              </li>
            </ul>
            <p
              v-else-if="!referencedBy.isLoading.value"
              class="mt-1 text-xs text-fc-faint"
            >
              No other entry points here.
            </p>
          </section>

          <section data-testid="drawer-source">
            <h2 class="fc-kicker border-b border-fc-line pb-1">
              Source
            </h2>
            <p
              v-if="revision"
              class="mt-2 font-mono text-[11px] text-fc-muted"
            >
              revision {{ revision.commitSha.slice(0, 12) }}
            </p>
            <p
              v-if="location.kind === 'web'"
              class="mt-1"
            >
              <a
                :href="location.url"
                target="_blank"
                rel="noopener noreferrer"
                class="text-fc-info hover:underline"
                data-testid="edit-in-repository"
              >Edit in repository</a>
              <span class="ml-2 break-all font-mono text-[11px] text-fc-faint">{{ data.sourcePath }}</span>
            </p>
            <div
              v-else
              class="mt-1"
              data-testid="edit-fallback"
            >
              <p
                v-if="location.path"
                class="break-all font-mono text-[11px] text-fc-muted"
              >
                {{ location.path }}
              </p>
              <p class="mt-1 text-xs text-fc-faint">
                No web link for this repository. Edit the file in a checkout, or run:
              </p>
              <pre class="mt-1 overflow-x-auto rounded-sm bg-fc-inset p-2 font-mono text-[11.5px]">{{ setCommand(type.name, entryKey) }}</pre>
            </div>
            <p class="mt-2 text-[11px] text-fc-faint">
              Read-only here. Changes go through Fleet Git.
            </p>
          </section>
        </template>
      </div>
    </SheetContent>
  </Sheet>
</template>
