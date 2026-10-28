<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, shallowRef } from 'vue'

import { createProxmoxConsoleSession, type ConsoleSessionDto } from '@frogbyte-io/fleet-api-client'
import StatusChip from '@/components/fleet/StatusChip.vue'

import { ApiRequestError, errorMessage, unwrap } from '../../machine/api'
import {
  describeClose,
  describeRequestFailure,
  endOf,
  guestHasNoScreen,
  socketUrl,
  subprotocolsFor,
  type ConsoleView,
} from './session'

// The VM screen (FM-495): noVNC (MPL-2.0, unmodified npm package) talking to
// the controller's relay over its own WebSocket. The browser holds a
// single-use Fleet session token and nothing else: the Proxmox API token,
// the VNC ticket, and the VNC password stay on the controller.
const props = withDefaults(defineProps<{
  /** The guest; absent when the panel was opened from a console link, which carries the session instead. */
  accountId?: string
  node?: string
  vmid?: number
  /** The guest's status from the inventory; a stopped guest has no screen. */
  guestStatus?: string | null
  /** A session token from a console link (`fleetctl proxmox console`); without it the panel creates its own. */
  sessionToken?: string | null
  /** Why the account's token cannot open consoles, from the privilege report. */
  blockedReason?: string | null
  /** Connect as soon as the panel is shown (a console link). */
  autoConnect?: boolean
}>(), { accountId: undefined, node: undefined, vmid: undefined, guestStatus: null, sessionToken: null, blockedReason: null, autoConnect: false })

const view = ref<ConsoleView>({ kind: 'idle' })
const container = ref<HTMLElement | null>(null)
const scale = ref(true)
const pasteOpen = ref(false)
const pasteText = ref('')

// Typed loosely on purpose: noVNC is imported lazily and is a browser-only
// library; the panel needs four of its methods.
interface Viewer {
  scaleViewport: boolean
  disconnect: () => void
  sendCtrlAltDel: () => void
  focus: () => void
  clipboardPasteFrom: (text: string) => void
}
const viewer = shallowRef<Viewer | null>(null)
let socket: WebSocket | null = null
let userClosed = false
let generation = 0

const noScreen = computed(() => guestHasNoScreen(props.guestStatus))
const connecting = computed(() => view.value.kind === 'connecting')
const connected = computed(() => view.value.kind === 'connected')
const chip = computed(() => {
  switch (view.value.kind) {
    case 'connecting': return { label: 'connecting', tone: 'info' as const }
    case 'connected': return { label: 'live', tone: 'ok' as const }
    case 'ended': return { label: view.value.cause.kind.replace('-', ' '), tone: view.value.cause.tone }
    default: return { label: noScreen.value ? 'guest stopped' : 'not connected', tone: 'faint' as const }
  }
})

function finish(code: number, reason: string, opened: boolean) {
  viewer.value = null
  socket = null
  if (userClosed) {
    view.value = { kind: 'ended', cause: endOf('disconnected', 'You closed the console.') }
    return
  }
  // A refused upgrade never opens: say so rather than showing a blank canvas.
  const cause = code === 1006 && !opened
    ? endOf('unavailable', 'The controller refused the console connection. Check that you are signed in and that Proxmox is configured.')
    : describeClose(code, reason)
  view.value = { kind: 'ended', cause }
}

async function createSession(): Promise<ConsoleSessionDto> {
  if (props.accountId === undefined || props.node === undefined || props.vmid === undefined)
    throw new Error('the console has no guest to open')
  return unwrap<ConsoleSessionDto>(await createProxmoxConsoleSession(props.accountId, { node: props.node, vmid: props.vmid }), [201])
}

async function connect() {
  if (connecting.value || connected.value || props.blockedReason)
    return
  const mine = ++generation
  userClosed = false
  view.value = { kind: 'connecting' }
  let token = props.sessionToken ?? null
  let path = '/api/v1/proxmox/console/socket'
  try {
    if (token === null) {
      const session = await createSession()
      token = session.token
      path = session.socketPath
    }
  }
  catch (error) {
    if (mine !== generation)
      return
    const status = error instanceof ApiRequestError ? error.status : 0
    view.value = { kind: 'ended', cause: describeRequestFailure(status, errorMessage(error)) }
    return
  }
  if (mine !== generation || container.value === null)
    return
  let opened = false
  try {
    const { default: RFB } = await import('@novnc/novnc')
    if (mine !== generation || container.value === null)
      return
    const ws = new WebSocket(socketUrl({ socketPath: path }, window.location), subprotocolsFor(token))
    ws.binaryType = 'arraybuffer'
    socket = ws
    ws.addEventListener('open', () => (opened = true))
    ws.addEventListener('close', event => finish(event.code, event.reason, opened))
    const rfb = new RFB(container.value, ws)
    rfb.scaleViewport = scale.value
    rfb.resizeSession = false
    rfb.addEventListener('connect', () => {
      view.value = { kind: 'connected' }
      rfb.focus()
    })
    // The controller offers no credentials prompt: a prompt means something
    // other than the relay answered.
    rfb.addEventListener('credentialsrequired', () => {
      view.value = { kind: 'ended', cause: endOf('unavailable', 'The console asked for credentials; the controller relay never does. Reload and try again.') }
      rfb.disconnect()
    })
    viewer.value = rfb
  }
  catch (error) {
    view.value = { kind: 'ended', cause: endOf('unavailable', errorMessage(error)) }
  }
}

function disconnect() {
  userClosed = true
  generation++
  if (viewer.value)
    viewer.value.disconnect()
  else if (socket)
    socket.close()
  else
    view.value = { kind: 'ended', cause: endOf('disconnected', 'You closed the console.') }
}

function toggleScale() {
  scale.value = !scale.value
  if (viewer.value)
    viewer.value.scaleViewport = scale.value
}

function sendCtrlAltDel() {
  viewer.value?.sendCtrlAltDel()
}

function paste() {
  if (!viewer.value || pasteText.value.length === 0)
    return
  viewer.value.clipboardPasteFrom(pasteText.value)
  pasteText.value = ''
  pasteOpen.value = false
  viewer.value.focus()
}

onBeforeUnmount(() => {
  userClosed = true
  generation++
  viewer.value?.disconnect()
  socket?.close()
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
    data-testid="proxmox-console"
    :aria-label="vmid === undefined ? 'Guest screen' : `Screen of VM ${vmid}`"
  >
    <div class="flex flex-wrap items-center gap-2">
      <span class="fc-kicker">Screen</span>
      <StatusChip
        :label="chip.label"
        :tone="chip.tone"
        data-testid="console-state"
      />
      <div class="ml-auto flex flex-wrap items-center gap-2 font-mono text-[10px] uppercase tracking-wider">
        <button
          v-if="!connected && !connecting"
          type="button"
          class="h-7 rounded-sm border border-fc-info/40 px-2.5 font-semibold text-fc-info hover:bg-fc-info/10 disabled:cursor-not-allowed disabled:opacity-50"
          :disabled="!!blockedReason || (noScreen && view.kind === 'idle')"
          data-testid="console-connect"
          @click="connect"
        >
          {{ view.kind === 'ended' ? 'Reconnect' : 'Connect' }}
        </button>
        <button
          v-else
          type="button"
          class="h-7 rounded-sm border border-fc-line2 px-2.5 text-fc-muted hover:text-fc-ink"
          data-testid="console-disconnect"
          @click="disconnect"
        >
          Disconnect
        </button>
        <button
          type="button"
          class="h-7 rounded-sm border border-fc-line2 px-2.5 text-fc-muted hover:text-fc-ink disabled:cursor-not-allowed disabled:opacity-50"
          :disabled="!connected"
          data-testid="console-cad"
          @click="sendCtrlAltDel"
        >
          Ctrl+Alt+Del
        </button>
        <button
          type="button"
          class="h-7 rounded-sm border px-2.5 disabled:cursor-not-allowed disabled:opacity-50"
          :class="scale ? 'border-ring text-fc-ink' : 'border-fc-line2 text-fc-muted hover:text-fc-ink'"
          :aria-pressed="scale"
          data-testid="console-scale"
          @click="toggleScale"
        >
          Fit to panel
        </button>
        <button
          type="button"
          class="h-7 rounded-sm border border-fc-line2 px-2.5 text-fc-muted hover:text-fc-ink disabled:cursor-not-allowed disabled:opacity-50"
          :disabled="!connected"
          :aria-expanded="pasteOpen"
          data-testid="console-paste-toggle"
          @click="pasteOpen = !pasteOpen"
        >
          Paste text
        </button>
      </div>
    </div>

    <form
      v-if="pasteOpen && connected"
      class="flex flex-wrap items-end gap-2"
      data-testid="console-paste"
      @submit.prevent="paste"
    >
      <label class="flex min-w-64 flex-1 flex-col gap-1 text-xs">
        <span class="fc-kicker">Text to type into the guest's clipboard</span>
        <textarea
          v-model="pasteText"
          rows="2"
          class="rounded-sm border border-input bg-background px-2 py-1 font-mono text-foreground"
        />
      </label>
      <button
        type="submit"
        class="h-7 rounded-sm border border-fc-info/40 px-2.5 font-semibold text-fc-info hover:bg-fc-info/10 disabled:opacity-50"
        :disabled="pasteText.length === 0"
      >
        Send
      </button>
    </form>

    <p
      v-if="blockedReason"
      class="border-l-2 border-l-fc-err pl-2 text-xs text-fc-muted"
      data-testid="console-blocked"
    >
      {{ blockedReason }}
    </p>

    <div class="relative overflow-hidden rounded-sm border border-fc-line bg-fc-inset">
      <div
        ref="container"
        class="h-[60vh] min-h-[320px] w-full"
        data-testid="console-canvas"
      />
      <div
        v-if="view.kind !== 'connected'"
        class="absolute inset-0 flex flex-col items-center justify-center gap-2 bg-fc-inset p-6 text-center"
        role="status"
        aria-live="polite"
        data-testid="console-overlay"
      >
        <template v-if="view.kind === 'connecting'">
          <p class="text-sm text-fc-ink">
            Connecting…
          </p>
          <p class="text-xs text-fc-muted">
            Opening the guest's screen through the controller.
          </p>
        </template>
        <template v-else-if="view.kind === 'ended'">
          <p
            class="text-sm font-semibold"
            :class="view.cause.tone === 'err' ? 'text-fc-err' : view.cause.tone === 'warn' ? 'text-fc-warn' : 'text-fc-ink'"
            data-testid="console-end-title"
          >
            {{ view.cause.title }}
          </p>
          <p
            class="max-w-md text-xs text-fc-muted"
            data-testid="console-end-detail"
          >
            {{ view.cause.detail }}
          </p>
        </template>
        <template v-else-if="noScreen">
          <p class="text-sm text-fc-ink">
            Guest stopped
          </p>
          <p class="max-w-md text-xs text-fc-muted">
            A stopped guest has no screen. Start it, then connect.
          </p>
        </template>
        <template v-else>
          <p class="text-sm text-fc-ink">
            Not connected
          </p>
          <p class="max-w-md text-xs text-fc-muted">
            Connect to see this guest's screen and use its keyboard and pointer.
          </p>
        </template>
      </div>
    </div>

    <p class="text-[11px] text-fc-faint">
      Screen access includes keyboard and pointer input in the guest. Fleet audits who opened which guest and for how long, never what the screen shows.
    </p>
  </section>
</template>
