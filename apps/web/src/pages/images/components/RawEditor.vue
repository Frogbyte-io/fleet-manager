<script setup lang="ts">
import { onBeforeUnmount, onMounted, ref, shallowRef, watch } from 'vue'

import type { EditorView } from 'codemirror'

// The raw `.pkr.json` editor: CodeMirror 6 with JSON highlighting and
// lint, loaded only when the Images page opens. A plain textarea stands in
// while it loads, if it fails to load, and under unit tests.
const model = defineModel<string>({ required: true })
const props = defineProps<{ readonly?: boolean, label: string }>()

const host = ref<HTMLElement | null>(null)
const view = shallowRef<EditorView | null>(null)
const failed = ref(false)
const USE_CODEMIRROR = import.meta.env.MODE !== 'test'

onMounted(async () => {
  if (!USE_CODEMIRROR)
    return
  try {
    const [{ EditorView, basicSetup }, { json, jsonParseLinter }, { EditorState }, { linter, lintGutter }] = await Promise.all([
      import('codemirror'),
      import('@codemirror/lang-json'),
      import('@codemirror/state'),
      import('@codemirror/lint'),
    ])
    if (!host.value)
      return
    view.value = new EditorView({
      parent: host.value,
      state: EditorState.create({
        doc: model.value,
        extensions: [
          basicSetup,
          json(),
          lintGutter(),
          linter(jsonParseLinter()),
          EditorState.readOnly.of(props.readonly ?? false),
          EditorView.contentAttributes.of({ 'aria-label': props.label }),
          EditorView.updateListener.of((update) => {
            if (update.docChanged)
              model.value = update.state.doc.toString()
          }),
          EditorView.theme({
            '&': { fontSize: '12px', backgroundColor: 'var(--fc-inset)', color: 'var(--fc-ink)', maxHeight: '520px' },
            '.cm-scroller': { fontFamily: 'var(--fc-chart)', lineHeight: '1.6' },
            '.cm-gutters': { backgroundColor: 'var(--fc-panel)', color: 'var(--fc-faint)', borderRight: '1px solid var(--fc-line)' },
            '.cm-activeLine, .cm-activeLineGutter': { backgroundColor: 'color-mix(in srgb, var(--fc-g1) 6%, transparent)' },
            '&.cm-focused': { outline: '1px solid var(--fc-g1)' },
            '.cm-cursor': { borderLeftColor: 'var(--fc-ink)' },
          }),
        ],
      }),
    })
  }
  catch {
    failed.value = true
  }
})

// Outside edits (structured form, a reloaded draft) replace the document.
watch(model, (value) => {
  const current = view.value?.state.doc.toString()
  if (view.value && current !== value)
    view.value.dispatch({ changes: { from: 0, to: current!.length, insert: value } })
})

onBeforeUnmount(() => view.value?.destroy())
</script>

<template>
  <div
    v-show="view"
    ref="host"
    class="overflow-hidden rounded-sm border border-fc-line"
    data-testid="raw-codemirror"
  />
  <textarea
    v-if="!view"
    v-model="model"
    :readonly="readonly"
    :aria-label="label"
    rows="20"
    spellcheck="false"
    class="w-full rounded-sm border border-input bg-fc-inset p-2.5 font-mono text-[12px] leading-relaxed text-foreground"
    data-testid="raw-editor"
  />
  <p
    v-if="failed"
    class="text-[11px] text-fc-faint"
  >
    The code editor could not load; editing as plain text.
  </p>
</template>
