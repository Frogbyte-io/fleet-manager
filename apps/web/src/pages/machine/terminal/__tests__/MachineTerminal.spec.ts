import { flushPromises, mount } from '@vue/test-utils'
import { beforeEach, describe, expect, it, vi } from 'vitest'

const createMachineTerminalSession = vi.fn()
vi.mock('@frogbyte-io/fleet-api-client', () => ({
  createMachineTerminalSession: (...args: unknown[]) => createMachineTerminalSession(...args),
}))

// xterm is a browser library; the panel's contract with it is what it writes
// and what it reports.
const terms: FakeTerm[] = []
class FakeTerm {
  cols = 100
  rows = 30
  written: Array<string | Uint8Array> = []
  options: { theme?: Record<string, string> } = {}
  disposed = false
  dataListener: ((data: string) => void) | null = null
  resizeListener: ((size: { cols: number, rows: number }) => void) | null = null
  constructor() { terms.push(this) }
  loadAddon() {}
  open() {}
  focus() {}
  write(data: string | Uint8Array) { this.written.push(data) }
  dispose() { this.disposed = true }
  onData(listener: (data: string) => void) { this.dataListener = listener; return { dispose() {} } }
  onBinary() { return { dispose() {} } }
  onResize(listener: (size: { cols: number, rows: number }) => void) { this.resizeListener = listener; return { dispose() {} } }
}
vi.mock('@xterm/xterm', () => ({ Terminal: FakeTerm }))
vi.mock('@xterm/addon-fit', () => ({ FitAddon: class { fit() {} } }))
vi.mock('@xterm/xterm/css/xterm.css', () => ({}))
vi.mock('@xterm/addon-webgl', () => ({
  WebglAddon: class {
    onContextLoss() {}
    dispose() {}
  },
}))

const sockets: FakeSocket[] = []
class FakeSocket extends EventTarget {
  static OPEN = 1
  readyState = 1
  binaryType = ''
  sent: unknown[] = []
  closed = false
  constructor(readonly url: string, readonly protocols: string[]) {
    super()
    sockets.push(this)
  }

  send(data: unknown) { this.sent.push(data) }
  open() { this.dispatchEvent(new Event('open')) }
  message(data: unknown) { this.dispatchEvent(Object.assign(new Event('message'), { data })) }
  close() {
    if (this.closed)
      return
    this.finish(1000, 'closed')
  }

  finish(code: number, reason: string) {
    this.closed = true
    this.readyState = 3
    this.dispatchEvent(Object.assign(new Event('close'), { code, reason }))
  }
}

import MachineTerminal from '../MachineTerminal.vue'

function session() {
  return {
    status: 201,
    data: {
      data: {
        sessionId: 'terminal-0123456789abcdef',
        token: 'TOKEN-0123456789abcdef',
        socketPath: '/api/v1/terminal/socket',
        subprotocols: ['fleet-terminal', 'fleet-terminal-token.TOKEN-0123456789abcdef'],
        idleTimeoutSeconds: 600,
        maxDurationSeconds: 3600,
      },
    },
    headers: new Headers(),
  }
}

async function connect(wrapper: ReturnType<typeof mount>) {
  await wrapper.get('[data-testid="terminal-connect"]').trigger('click')
  await flushPromises()
}

describe('MachineTerminal', () => {
  beforeEach(() => {
    terms.length = 0
    sockets.length = 0
    createMachineTerminalSession.mockReset()
    vi.stubGlobal('WebSocket', FakeSocket)
  })

  const mountIt = (trustedLan = true) => mount(MachineTerminal, { props: { machineId: 'm1', trustedLan }, attachTo: document.body })

  it('starts idle and shows the trusted-LAN note only in that mode', () => {
    const wrapper = mountIt()
    expect(wrapper.get('[data-testid="terminal-state"]').text()).toContain('not connected')
    expect(wrapper.get('[data-testid="terminal-lan-note"]').text()).toContain('trusted-LAN')
    const other = mountIt(false)
    expect(other.find('[data-testid="terminal-lan-note"]').exists()).toBe(false)
    expect(other.get('[data-testid="terminal-audit-note"]').text()).toContain('audits')
    expect(createMachineTerminalSession).not.toHaveBeenCalled()
  })

  it('connects with the token in a subprotocol, never in the URL, and goes live on ready', async () => {
    createMachineTerminalSession.mockResolvedValue(session())
    const wrapper = mountIt()
    await connect(wrapper)
    expect(createMachineTerminalSession).toHaveBeenCalledWith('m1', {})
    const socket = sockets[0]!
    expect(socket.url).toBe(`ws://${window.location.host}/api/v1/terminal/socket`)
    expect(socket.url).not.toContain('TOKEN')
    expect(socket.protocols).toEqual(['fleet-terminal', 'fleet-terminal-token.TOKEN-0123456789abcdef'])
    expect(wrapper.get('[data-testid="terminal-state"]').text()).toContain('connecting')

    socket.open()
    // The initial window size goes first.
    expect(JSON.parse(socket.sent[0] as string)).toEqual({ type: 'resize', cols: 100, rows: 30 })
    socket.message('{"type":"ready"}')
    await flushPromises()
    expect(wrapper.get('[data-testid="terminal-state"]').text()).toContain('live')
    expect(wrapper.find('[data-testid="terminal-overlay"]').exists()).toBe(false)
    expect(wrapper.get('[data-testid="terminal-limits"]').text()).toContain('idle 10 min')
  })

  it('relays output, keystrokes and resizes', async () => {
    createMachineTerminalSession.mockResolvedValue(session())
    const wrapper = mountIt()
    await connect(wrapper)
    const socket = sockets[0]!
    const term = terms[0]!
    socket.open()
    socket.message('{"type":"ready"}')
    socket.message(new TextEncoder().encode('hello').buffer)
    expect(new TextDecoder().decode(term.written[0] as Uint8Array)).toBe('hello')
    term.dataListener!('ls\n')
    expect(new TextDecoder().decode(socket.sent.at(-1) as Uint8Array)).toBe('ls\n')
    term.resizeListener!({ cols: 120, rows: 40 })
    expect(JSON.parse(socket.sent.at(-1) as string)).toEqual({ type: 'resize', cols: 120, rows: 40 })
  })

  it('explains each way a session ends and offers reconnect', async () => {
    createMachineTerminalSession.mockResolvedValue(session())
    const wrapper = mountIt()
    const cases: Array<[number, string, string]> = [
      [4408, '', 'Closed after inactivity'],
      [4410, '', 'Time limit reached'],
      [1001, '', 'Controller restarting'],
      [4403, '', 'No permission'],
      [4404, '', 'Session expired'],
      [1000, 'the shell ended', 'Session ended'],
    ]
    for (const [code, reason, title] of cases) {
      await connect(wrapper)
      const socket = sockets.at(-1)!
      socket.open()
      socket.message('{"type":"ready"}')
      if (code === 1000)
        socket.message('{"type":"exit","code":2}')
      socket.finish(code, reason)
      await flushPromises()
      expect(wrapper.get('[data-testid="terminal-end-title"]').text()).toBe(title)
      expect(wrapper.get('[data-testid="terminal-connect"]').text()).toBe('Reconnect')
    }
    expect(wrapper.get('[data-testid="terminal-end-detail"]').text()).toContain('exit status 2')
    // Every reconnect made a fresh session and a fresh terminal.
    expect(createMachineTerminalSession).toHaveBeenCalledTimes(cases.length)
    expect(terms.slice(0, -1).every(term => term.disposed)).toBe(true)
  })

  it('shows a refused session request', async () => {
    createMachineTerminalSession.mockResolvedValue({ status: 403, data: { code: 'denied', message: 'denied' }, headers: new Headers() })
    const wrapper = mountIt()
    await connect(wrapper)
    expect(wrapper.get('[data-testid="terminal-end-title"]').text()).toBe('No permission')
    expect(sockets).toHaveLength(0)
  })

  it('a refused upgrade is explained, not a blank screen', async () => {
    createMachineTerminalSession.mockResolvedValue(session())
    const wrapper = mountIt()
    await connect(wrapper)
    sockets[0]!.finish(1006, '')
    await flushPromises()
    expect(wrapper.get('[data-testid="terminal-end-detail"]').text()).toContain('refused')
  })

  it('disconnect closes the socket and says the user closed it', async () => {
    createMachineTerminalSession.mockResolvedValue(session())
    const wrapper = mountIt()
    await connect(wrapper)
    sockets[0]!.open()
    sockets[0]!.message('{"type":"ready"}')
    await flushPromises()
    await wrapper.get('[data-testid="terminal-disconnect"]').trigger('click')
    await flushPromises()
    expect(sockets[0]!.closed).toBe(true)
    expect(wrapper.get('[data-testid="terminal-end-detail"]').text()).toContain('You closed')
  })
})
