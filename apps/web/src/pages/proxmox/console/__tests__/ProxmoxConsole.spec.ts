import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const createProxmoxConsoleSession = vi.fn()
vi.mock('@frogbyte-io/fleet-api-client', () => ({
  createProxmoxConsoleSession: (...args: unknown[]) => createProxmoxConsoleSession(...args),
}))

// noVNC is a browser library; the panel's contract with it is the channel it
// is handed and the events it raises.
const viewers: FakeRfb[] = []
class FakeRfb extends EventTarget {
  scaleViewport = false
  resizeSession = true
  disconnected = false
  sent: string[] = []
  pasted: string[] = []
  constructor(readonly target: HTMLElement, readonly channel: FakeSocket) {
    super()
    viewers.push(this)
  }

  disconnect() {
    this.disconnected = true
    this.channel.close()
  }

  sendCtrlAltDel() { this.sent.push('cad') }
  focus() { this.sent.push('focus') }
  clipboardPasteFrom(text: string) { this.pasted.push(text) }
  open() { this.dispatchEvent(new CustomEvent('connect')) }
}
vi.mock('@novnc/novnc', () => ({ default: FakeRfb }))

const sockets: FakeSocket[] = []
class FakeSocket extends EventTarget {
  binaryType = ''
  closed = false
  constructor(readonly url: string, readonly protocols: string[]) {
    super()
    sockets.push(this)
  }

  open() { this.dispatchEvent(new Event('open')) }
  close() {
    if (this.closed)
      return
    this.closed = true
    this.finish(1000, 'closed')
  }

  finish(code: number, reason: string) {
    this.closed = true
    this.dispatchEvent(Object.assign(new Event('close'), { code, reason }))
  }
}

import ProxmoxConsole from '../ProxmoxConsole.vue'

function session(overrides: Record<string, unknown> = {}) {
  return {
    status: 201,
    data: {
      data: {
        sessionId: 'console-0123456789abcdef',
        token: 'TOKEN-0123456789abcdef',
        socketPath: '/api/v1/proxmox/console/socket',
        subprotocols: ['binary', 'fleet-console-token.TOKEN-0123456789abcdef'],
        ...overrides,
      },
    },
    headers: new Headers(),
  }
}

function refusal(status: number, code: string, message: string) {
  return { status, data: { code, message }, headers: new Headers() }
}

const props = { accountId: 'acc1', node: 'pve-a', vmid: 101 }

async function connect(wrapper: ReturnType<typeof mount>) {
  await wrapper.get('[data-testid="console-connect"]').trigger('click')
  await flushPromises()
}

describe('ProxmoxConsole', () => {
  beforeEach(() => {
    viewers.length = 0
    sockets.length = 0
    createProxmoxConsoleSession.mockReset()
    vi.stubGlobal('WebSocket', FakeSocket)
  })
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('starts disconnected and says so', () => {
    const wrapper = mount(ProxmoxConsole, { props })
    expect(wrapper.get('[data-testid="console-state"]').text()).toBe('not connected')
    expect(wrapper.get('[data-testid="console-overlay"]').text()).toContain('Not connected')
    expect(createProxmoxConsoleSession).not.toHaveBeenCalled()
    expect((wrapper.get('[data-testid="console-cad"]').element as HTMLButtonElement).disabled).toBe(true)
  })

  it('connects through the controller, offering the token only as a subprotocol', async () => {
    createProxmoxConsoleSession.mockResolvedValue(session())
    const wrapper = mount(ProxmoxConsole, { props, attachTo: document.body })
    await connect(wrapper)
    expect(createProxmoxConsoleSession).toHaveBeenCalledWith('acc1', { node: 'pve-a', vmid: 101 })
    expect(sockets).toHaveLength(1)
    const [socket] = sockets
    expect(socket!.url).toMatch(/^wss?:\/\/[^/]+\/api\/v1\/proxmox\/console\/socket$/)
    expect(socket!.url).not.toContain('TOKEN')
    expect(socket!.protocols).toEqual(['binary', 'fleet-console-token.TOKEN-0123456789abcdef'])
    expect(wrapper.get('[data-testid="console-state"]').text()).toBe('connecting')
    expect(wrapper.get('[data-testid="console-overlay"]').text()).toContain('Connecting')

    socket!.open()
    viewers[0]!.open()
    await flushPromises()
    expect(wrapper.get('[data-testid="console-state"]').text()).toBe('live')
    expect(wrapper.find('[data-testid="console-overlay"]').exists()).toBe(false)
    expect(viewers[0]!.scaleViewport).toBe(true)
    expect(viewers[0]!.resizeSession).toBe(false)
    wrapper.unmount()
  })

  it('sends Ctrl+Alt+Del and pasted text, and scales on request', async () => {
    createProxmoxConsoleSession.mockResolvedValue(session())
    const wrapper = mount(ProxmoxConsole, { props, attachTo: document.body })
    await connect(wrapper)
    sockets[0]!.open()
    viewers[0]!.open()
    await flushPromises()

    await wrapper.get('[data-testid="console-cad"]').trigger('click')
    expect(viewers[0]!.sent).toContain('cad')

    await wrapper.get('[data-testid="console-scale"]').trigger('click')
    expect(viewers[0]!.scaleViewport).toBe(false)

    await wrapper.get('[data-testid="console-paste-toggle"]').trigger('click')
    await wrapper.get('[data-testid="console-paste"] textarea').setValue('hello guest')
    await wrapper.get('[data-testid="console-paste"]').trigger('submit')
    expect(viewers[0]!.pasted).toEqual(['hello guest'])
    wrapper.unmount()
  })

  it('disconnects on request and reports that you closed it', async () => {
    createProxmoxConsoleSession.mockResolvedValue(session())
    const wrapper = mount(ProxmoxConsole, { props, attachTo: document.body })
    await connect(wrapper)
    sockets[0]!.open()
    viewers[0]!.open()
    await flushPromises()
    await wrapper.get('[data-testid="console-disconnect"]').trigger('click')
    await flushPromises()
    expect(viewers[0]!.disconnected).toBe(true)
    expect(wrapper.get('[data-testid="console-end-title"]').text()).toBe('Disconnected')
    expect(wrapper.get('[data-testid="console-end-detail"]').text()).toContain('You closed')
    expect(wrapper.get('[data-testid="console-connect"]').text()).toBe('Reconnect')
    wrapper.unmount()
  })

  it('does not offer a screen for a stopped guest', async () => {
    const wrapper = mount(ProxmoxConsole, { props: { ...props, guestStatus: 'stopped' } })
    expect(wrapper.get('[data-testid="console-state"]').text()).toBe('guest stopped')
    expect(wrapper.get('[data-testid="console-overlay"]').text()).toContain('A stopped guest has no screen')
    expect((wrapper.get('[data-testid="console-connect"]').element as HTMLButtonElement).disabled).toBe(true)
  })

  it('explains a missing permission instead of showing a blank canvas', async () => {
    createProxmoxConsoleSession.mockResolvedValue(refusal(502, 'proxmox_source', 'the token lacks the privilege (403): the account\'s API token lacks VM.Console on /vms/101; grant it'))
    const wrapper = mount(ProxmoxConsole, { props })
    await connect(wrapper)
    expect(wrapper.get('[data-testid="console-end-title"]').text()).toBe('No permission')
    expect(wrapper.get('[data-testid="console-end-detail"]').text()).toContain('VM.Console on /vms/101')
    expect(sockets).toHaveLength(0)
  })

  it('shows the controller\'s refusal when Fleet itself denies the principal', async () => {
    createProxmoxConsoleSession.mockResolvedValue(refusal(403, 'denied', 'denied'))
    const wrapper = mount(ProxmoxConsole, { props })
    await connect(wrapper)
    expect(wrapper.get('[data-testid="console-end-title"]').text()).toBe('No permission')
    expect(wrapper.get('[data-testid="console-end-detail"]').text()).toContain('proxmox.console')
  })

  it('withholds Connect while the privilege report says the token lacks VM.Console', () => {
    const wrapper = mount(ProxmoxConsole, { props: { ...props, blockedReason: 'This account\'s API token lacks the console privileges (VM.Console on /vms/{vmid}).' } })
    expect(wrapper.get('[data-testid="console-blocked"]').text()).toContain('VM.Console')
    expect((wrapper.get('[data-testid="console-connect"]').element as HTMLButtonElement).disabled).toBe(true)
  })

  it.each([
    [4404, 'Link expired'],
    [4408, 'Closed after inactivity'],
    [4410, 'Time limit reached'],
    [1001, 'Controller restarting'],
    [4401, 'Sign-in required'],
    [4409, 'Too many consoles'],
  ])('reads close code %i as "%s"', async (code, title) => {
    createProxmoxConsoleSession.mockResolvedValue(session())
    const wrapper = mount(ProxmoxConsole, { props, attachTo: document.body })
    await connect(wrapper)
    sockets[0]!.open()
    viewers[0]!.open()
    await flushPromises()
    sockets[0]!.finish(code, 'reason')
    await flushPromises()
    expect(wrapper.get('[data-testid="console-end-title"]').text()).toBe(title)
    wrapper.unmount()
  })

  it('reads a guest that closes its screen as a stopped guest', async () => {
    createProxmoxConsoleSession.mockResolvedValue(session())
    const wrapper = mount(ProxmoxConsole, { props, attachTo: document.body })
    await connect(wrapper)
    sockets[0]!.open()
    viewers[0]!.open()
    await flushPromises()
    sockets[0]!.finish(1000, 'the guest closed its screen')
    await flushPromises()
    expect(wrapper.get('[data-testid="console-end-title"]').text()).toBe('Guest stopped')
    wrapper.unmount()
  })

  it('says a refused upgrade was refused', async () => {
    createProxmoxConsoleSession.mockResolvedValue(session())
    const wrapper = mount(ProxmoxConsole, { props, attachTo: document.body })
    await connect(wrapper)
    // The browser reports a refused upgrade as code 1006 without ever opening.
    sockets[0]!.finish(1006, '')
    await flushPromises()
    expect(wrapper.get('[data-testid="console-end-detail"]').text()).toContain('refused')
    wrapper.unmount()
  })

  it('attaches a console link\'s token without creating a session', async () => {
    const wrapper = mount(ProxmoxConsole, {
      props: { sessionToken: 'LINK-TOKEN-0123456789', autoConnect: true },
      attachTo: document.body,
    })
    await flushPromises()
    expect(createProxmoxConsoleSession).not.toHaveBeenCalled()
    expect(sockets[0]!.protocols).toEqual(['binary', 'fleet-console-token.LINK-TOKEN-0123456789'])
    wrapper.unmount()
  })

  it('closes the socket when the panel goes away', async () => {
    createProxmoxConsoleSession.mockResolvedValue(session())
    const wrapper = mount(ProxmoxConsole, { props, attachTo: document.body })
    await connect(wrapper)
    sockets[0]!.open()
    viewers[0]!.open()
    await flushPromises()
    wrapper.unmount()
    expect(viewers[0]!.disconnected).toBe(true)
    expect(sockets[0]!.closed).toBe(true)
  })
})
