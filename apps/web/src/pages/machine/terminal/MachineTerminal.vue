<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, shallowRef } from 'vue'

import { createMachineTerminalSession, type TerminalSessionDto } from '@frogbyte-io/fleet-api-client'
import StatusChip from '@/components/fleet/StatusChip.vue'

import { ApiRequestError, errorMessage, unwrap } from '../api'
import {
  describeClose,
  describeRequestFailure,
  endOf,
  exitCodeOf,
  isReady,
  resizeMessage,
  socketUrl,
  type TerminalView,
} from './session'
import { allowXtermStyles } from './styleNonce'

// The machine terminal (#494): xterm.js (MIT) talking to the controller's
// relay over its own WebSocket. The browser holds a single-use Fleet session
// token and nothing else: the machine's SSH key stays on the controller, which
// runs `ssh -tt`. Nothing typed or shown is recorded.
const props = defineProps<{
  machineId: string
  /** Connect as soon as the panel is shown. */
  autoConnect?: boolean
  /** Whether the controller runs in trusted-LAN mode, where every caller may open a shell. */
  trustedLan?: boolean
}>()

const view = ref<TerminalView>({ kind: 'idle' })
const container = ref<HTMLElement | null>(null)
const limits = ref<{ idle: number, max: number } | null>(null)

// Typed loosely on purpose: xterm is imported lazily and is a browser-only
// library; the panel needs a handful of its methods.
interface Term {
  cols: number
  rows: number
  write: (data: string | Uint8Array) => void
  focus: () => void
  dispose: () => void
  onData: (listener: (data: string) => void) => { dispose: () => void }
  onBinary: (listener: (data: string) => void) => { dispose: () => void }
  onResize: (listener: (size: { cols: number, rows: number }) => void) => { dispose: () => void }
  options: { theme?: Record<string, string> }
}
interface Fit { fit: () => void }

const term = shallowRef<Term | null>(null)
let fit: Fit | null = null
let socket: WebSocket | null = null
let observer: ResizeObserver | null = null
let themeObserver: MutationObserver | null = null
let subscriptions: Array<{ dispose: () => void }> = []
let userClosed = false
let exitStatus: number | null = null
let generation = 0

const connecting = computed(() => view.value.kind === 'connecting')
const connected = computed(() => view.value.kind === 'connected')
const chip = computed(() => {
  switch (view.value.kind) {
    case 'connecting': return { label: 'connecting', tone: 'info' as const }
    case 'connected': return { label: 'live', tone: 'ok' as const }
    case 'ended': return { label: view.value.cause.kind.replace('-', ' '), tone: view.value.cause.tone }
    default: return { label: 'not connected', tone: 'faint' as const }
  }
})

function cssVar(name: string, fallback: string): string {
  const value = getComputedStyle(document.documentElement).getPropertyValue(name).trim()
  return value.length > 0 ? value : fallback
}

function theme() {
  return {
    background: cssVar('--fc-inset', '#0d1219'),
    foreground: cssVar('--fc-ink', '#e6e9ef'),
    cursor: cssVar('--fc-ink', '#e6e9ef'),
    selectionBackground: cssVar('--fc-line2', '#3a4254'),
  }
}

function teardown() {
  observer?.disconnect()
  observer = null
  themeObserver?.disconnect()
  themeObserver = null
  for (const subscription of subscriptions)
    subscription.dispose()
  subscriptions = []
  term.value?.dispose()
  term.value = null
  fit = null
}

function finish(code: number, reason: string, opened: boolean) {
  socket = null
  if (userClosed) {
    view.value = { kind: 'ended', cause: endOf('closed', 'You closed the terminal.') }
    return
  }
  // A refused upgrade never opens: say so rather than showing a blank screen.
  view.value = {
    kind: 'ended',
    cause: code === 1006 && !opened
      ? endOf('unavailable', 'The controller refused the terminal connection. Check that you are signed in and that terminals are enabled.')
      : describeClose(code, reason, exitStatus),
  }
}

async function connect() {
  if (connecting.value || connected.value)
    return
  const mine = ++generation
  userClosed = false
  exitStatus = null
  teardown()
  view.value = { kind: 'connecting' }
  let session: TerminalSessionDto
  try {
    session = unwrap<TerminalSessionDto>(await createMachineTerminalSession(props.machineId, {}), [201])
  }
  catch (error) {
    if (mine !== generation)
      return
    const status = error instanceof ApiRequestError ? error.status : 0
    view.value = { kind: 'ended', cause: describeRequestFailure(status, errorMessage(error)) }
    return
  }
  limits.value = { idle: session.idleTimeoutSeconds, max: session.maxDurationSeconds }
  if (mine !== generation || container.value === null)
    return
  try {
    const [{ Terminal }, { FitAddon }] = await Promise.all([
      import('@xterm/xterm'),
      import('@xterm/addon-fit'),
      import('@xterm/xterm/css/xterm.css'),
    ])
    if (mine !== generation || container.value === null)
      return
    allowXtermStyles()
    const created = new Terminal({
      cursorBlink: true,
      fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace',
      fontSize: 13,
      scrollback: 5000,
      theme: theme(),
    })
    const fitAddon = new FitAddon()
    created.loadAddon(fitAddon)
    created.open(container.value)
    fitAddon.fit()
    term.value = created as unknown as Term
    fit = fitAddon
    // The GPU renderer draws to a canvas, so it needs no injected <style>
    // elements (the nonce policy blocks them). Without WebGL, or after the
    // context is lost, xterm falls back to its DOM renderer.
    try {
      const { WebglAddon } = await import('@xterm/addon-webgl')
      const webgl = new WebglAddon()
      webgl.onContextLoss(() => webgl.dispose())
      created.loadAddon(webgl)
    }
    catch {
      // DOM renderer.
    }

    let opened = false
    const ws = new WebSocket(socketUrl(session.socketPath, window.location), session.subprotocols)
    ws.binaryType = 'arraybuffer'
    socket = ws
    ws.addEventListener('open', () => {
      opened = true
      ws.send(resizeMessage(created.cols, created.rows))
    })
    ws.addEventListener('message', (event) => {
      if (typeof event.data === 'string') {
        const status = exitCodeOf(event.data)
        if (status !== null)
          exitStatus = status
        if (isReady(event.data)) {
          view.value = { kind: 'connected' }
          created.focus()
        }
        return
      }
      created.write(new Uint8Array(event.data as ArrayBuffer))
    })
    ws.addEventListener('close', (event) => {
      finish(event.code, event.reason, opened)
      // Keep the last screen visible behind the overlay; free it on reconnect.
    })
    const encoder = new TextEncoder()
    subscriptions = [
      created.onData((data) => {
        if (ws.readyState === WebSocket.OPEN)
          ws.send(encoder.encode(data))
      }),
      created.onBinary((data) => {
        if (ws.readyState === WebSocket.OPEN)
          ws.send(Uint8Array.from(data, ch => ch.charCodeAt(0)))
      }),
      created.onResize(({ cols, rows }) => {
        if (ws.readyState === WebSocket.OPEN)
          ws.send(resizeMessage(cols, rows))
      }),
    ]
    if (typeof ResizeObserver !== 'undefined') {
      observer = new ResizeObserver(() => fit?.fit())
      observer.observe(container.value)
    }
    themeObserver = new MutationObserver(() => {
      if (term.value)
        term.value.options.theme = theme()
    })
    themeObserver.observe(document.documentElement, { attributes: true, attributeFilter: ['class', 'data-theme'] })
  }
  catch (error) {
    view.value = { kind: 'ended', cause: endOf('unavailable', errorMessage(error)) }
  }
}

function disconnect() {
  userClosed = true
  generation++
  if (socket)
    socket.close()
  else
    view.value = { kind: 'ended', cause: endOf('closed', 'You closed the terminal.') }
}

onBeforeUnmount(() => {
  userClosed = true
  generation++
  socket?.close()
  teardown()
})

onMounted(() => {
  if (props.autoConnect)
    void connect()
})

defineExpose({ connect, disconnect })
</script>

<template>
  <section
    class="space-y-2"
    data-testid="machine-terminal"
    aria-label="Machine terminal"
  >
    <div class="flex flex-wrap items-center gap-2">
      <span class="fc-kicker">Terminal</span>
      <StatusChip
        :label="chip.label"
        :tone="chip.tone"
        data-testid="terminal-state"
      />
      <span
        v-if="limits"
        class="font-mono text-[10px] text-fc-faint"
        data-testid="terminal-limits"
      >
        idle {{ Math.round(limits.idle / 60) }} min · max {{ Math.round(limits.max / 60) }} min
      </span>
      <div class="ml-auto flex items-center gap-2 font-mono text-[10px] uppercase tracking-wider">
        <button
          v-if="!connected && !connecting"
          type="button"
          class="h-7 rounded-sm border border-fc-info/40 px-2.5 font-semibold text-fc-info hover:bg-fc-info/10"
          data-testid="terminal-connect"
          @click="connect"
        >
          {{ view.kind === 'ended' ? 'Reconnect' : 'Connect' }}
        </button>
        <button
          v-else
          type="button"
          class="h-7 rounded-sm border border-fc-line2 px-2.5 text-fc-muted hover:text-fc-ink"
          data-testid="terminal-disconnect"
          @click="disconnect"
        >
          Disconnect
        </button>
      </div>
    </div>

    <p
      v-if="trustedLan"
      class="border-l-2 border-l-fc-warn pl-2 text-xs text-fc-muted"
      data-testid="terminal-lan-note"
    >
      This controller runs in trusted-LAN mode: anyone who can reach it can open a shell here as the machine's SSH user. Fleet audits who opened a terminal and for how long, never what is typed or shown.
    </p>
    <p
      v-else
      class="text-[11px] text-fc-faint"
      data-testid="terminal-audit-note"
    >
      Fleet audits who opened a terminal and for how long, never what is typed or shown.
    </p>

    <div class="relative overflow-hidden rounded-sm border border-fc-line bg-fc-inset">
      <div
        ref="container"
        class="h-[60vh] min-h-[320px] w-full p-2"
        data-testid="terminal-canvas"
      />
      <div
        v-if="view.kind !== 'connected'"
        class="absolute inset-0 flex flex-col items-center justify-center gap-2 bg-fc-inset/90 p-6 text-center"
        role="status"
        aria-live="polite"
        data-testid="terminal-overlay"
      >
        <template v-if="view.kind === 'connecting'">
          <p class="text-sm text-fc-ink">
            Connecting…
          </p>
          <p class="text-xs text-fc-muted">
            Opening a shell on the machine through the controller.
          </p>
        </template>
        <template v-else-if="view.kind === 'ended'">
          <p
            class="text-sm font-semibold"
            :class="view.cause.tone === 'err' ? 'text-fc-err' : view.cause.tone === 'warn' ? 'text-fc-warn' : 'text-fc-ink'"
            data-testid="terminal-end-title"
          >
            {{ view.cause.title }}
          </p>
          <p
            class="max-w-md text-xs text-fc-muted"
            data-testid="terminal-end-detail"
          >
            {{ view.cause.detail }}
          </p>
        </template>
        <template v-else>
          <p class="text-sm text-fc-ink">
            Not connected
          </p>
          <p class="max-w-md text-xs text-fc-muted">
            Connect to open an interactive shell on this machine with its stored credential.
          </p>
        </template>
      </div>
    </div>
  </section>
</template>
