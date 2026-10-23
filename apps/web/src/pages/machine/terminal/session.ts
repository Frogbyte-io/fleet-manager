// The machine terminal's session logic (#494), kept free of xterm and the DOM
// so every state is unit-testable. The controller decides everything
// (authorization, the credential, the bounds); this file only turns its
// answers into the states the terminal shows.

/** What the terminal panel is showing. */
export type TerminalView =
  | { kind: 'idle' }
  | { kind: 'connecting' }
  | { kind: 'connected' }
  | { kind: 'ended', cause: TerminalEnd }

export type TerminalEndKind =
  | 'exited'
  | 'no-permission'
  | 'sign-in'
  | 'expired'
  | 'limit'
  | 'idle'
  | 'max-duration'
  | 'shutdown'
  | 'lost'
  | 'refused'
  | 'closed'
  | 'unavailable'

export interface TerminalEnd {
  kind: TerminalEndKind
  title: string
  detail: string
  tone: 'warn' | 'err' | 'muted'
}

const BASE: Record<TerminalEndKind, Omit<TerminalEnd, 'kind'>> = {
  'exited': { title: 'Session ended', detail: 'The shell ended.', tone: 'muted' },
  'no-permission': {
    title: 'No permission',
    detail: 'Your principal lacks machines.terminal on this machine. It is separate from machines.exec and is never implied by read access.',
    tone: 'err',
  },
  'sign-in': { title: 'Sign-in required', detail: 'The controller did not recognize you.', tone: 'err' },
  'expired': {
    title: 'Session expired',
    detail: 'The session link was already used or has expired. Links work once; connect again.',
    tone: 'warn',
  },
  'limit': {
    title: 'Too many terminals',
    detail: 'The controller limits how many terminals are open at once. Close one and connect again.',
    tone: 'warn',
  },
  'idle': {
    title: 'Closed after inactivity',
    detail: 'No keyboard input arrived for a while, so the controller closed the terminal.',
    tone: 'muted',
  },
  'max-duration': {
    title: 'Time limit reached',
    detail: 'The terminal reached its maximum duration and was closed.',
    tone: 'muted',
  },
  'shutdown': {
    title: 'Controller restarting',
    detail: 'The controller is shutting down and closed the terminal. Connect again once it is back.',
    tone: 'warn',
  },
  'lost': {
    title: 'Connection lost',
    detail: 'The connection to the controller stopped answering.',
    tone: 'warn',
  },
  'refused': {
    title: 'Could not open the shell',
    detail: 'The controller could not open a shell on the machine.',
    tone: 'err',
  },
  'closed': { title: 'Disconnected', detail: 'The terminal is closed.', tone: 'muted' },
  'unavailable': { title: 'Terminal unavailable', detail: 'The controller could not open the terminal.', tone: 'err' },
}

export function endOf(kind: TerminalEndKind, detail?: string): TerminalEnd {
  const base = BASE[kind]
  return { kind, ...base, detail: detail && detail.length > 0 ? detail : base.detail }
}

/**
 * The cause for a closed terminal socket. The relay uses private close codes
 * (crates/fleet-controller/src/machine_terminal.rs); the reason text is the
 * controller's own, already free of credentials.
 */
export function describeClose(code: number, reason: string): TerminalEnd {
  switch (code) {
    case 4401: return endOf('sign-in')
    case 4403: return endOf('no-permission')
    case 4404: return endOf('expired')
    case 4409: return endOf('limit', reason)
    case 4408: return endOf('idle')
    case 4410: return endOf('max-duration')
    case 4412: return endOf('lost')
    case 1001: return endOf('shutdown')
    case 4502: return endOf('refused', reason)
    case 4503: return endOf('unavailable', reason)
    case 1000: {
      const status = /exit status (\d+)/.exec(reason)
      return status
        ? endOf('exited', `The shell ended (exit status ${status[1]}).`)
        : reason.startsWith('the shell ended') ? endOf('exited') : endOf('closed')
    }
    default:
      return endOf('unavailable', code === 1006 ? 'The connection to the controller dropped.' : undefined)
  }
}

/** A failed session request (HTTP), as the cause to show. */
export function describeRequestFailure(status: number, message: string): TerminalEnd {
  if (status === 403)
    return endOf('no-permission')
  if (status === 503)
    return endOf('limit', message)
  return endOf('unavailable', message)
}

/** The socket URL for a session: the controller's own origin, ws or wss. */
export function socketUrl(socketPath: string, location: Pick<Location, 'protocol' | 'host'>): string {
  const scheme = location.protocol === 'https:' ? 'wss:' : 'ws:'
  return `${scheme}//${location.host}${socketPath}`
}

/** The control message for a window change. */
export function resizeMessage(cols: number, rows: number): string {
  return JSON.stringify({ type: 'resize', cols, rows })
}

/** Whether a text frame from the controller says the shell has started. */
export function isReady(text: string): boolean {
  try {
    return (JSON.parse(text) as { type?: string }).type === 'ready'
  }
  catch {
    return false
  }
}
