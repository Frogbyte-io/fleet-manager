// The Proxmox VM screen's session logic (FM-495), kept free of noVNC and the
// DOM so every state is unit-testable. The controller decides everything
// (authorization, the PVE credentials, the bounds); this file only turns its
// answers into the states the console shows.

import type { ConsoleSessionDto } from '@frogbyte-io/fleet-api-client'

/** What the console panel is showing. */
export type ConsoleView =
  | { kind: 'idle' }
  | { kind: 'connecting' }
  | { kind: 'connected' }
  | { kind: 'ended', cause: ConsoleEnd }

/** Why a console is not showing a screen. Every cause has words and a tone. */
export type ConsoleEndKind =
  | 'guest-stopped'
  | 'no-permission'
  | 'sign-in'
  | 'expired'
  | 'limit'
  | 'idle'
  | 'max-duration'
  | 'shutdown'
  | 'disconnected'
  | 'unavailable'

export interface ConsoleEnd {
  kind: ConsoleEndKind
  /** The headline. */
  title: string
  /** The explanation, never a blank canvas. */
  detail: string
  tone: 'warn' | 'err' | 'muted'
  /** Whether trying again can help. */
  retry: boolean
}

const BASE: Record<ConsoleEndKind, Omit<ConsoleEnd, 'kind'>> = {
  'guest-stopped': {
    title: 'Guest stopped',
    detail: 'The guest is not running, so it has no screen. Start it from Actions, then connect again.',
    tone: 'muted',
    retry: true,
  },
  'no-permission': {
    title: 'No permission',
    detail: 'The account\'s Proxmox API token lacks VM.Console on this guest. Grant it (the FleetConsole role from the token guide, or PVEVMUser) and connect again.',
    tone: 'err',
    retry: false,
  },
  'sign-in': {
    title: 'Sign-in required',
    detail: 'The controller did not recognize you. Open the console from an authenticated session.',
    tone: 'err',
    retry: false,
  },
  'expired': {
    title: 'Link expired',
    detail: 'The console link was already used or has expired. Links work once; request a new one.',
    tone: 'warn',
    retry: false,
  },
  'limit': {
    title: 'Too many consoles',
    detail: 'The controller limits how many screens are open at once. Close one and connect again.',
    tone: 'warn',
    retry: true,
  },
  'idle': {
    title: 'Closed after inactivity',
    detail: 'No keyboard or pointer input arrived for a while, so the controller closed the console.',
    tone: 'muted',
    retry: true,
  },
  'max-duration': {
    title: 'Time limit reached',
    detail: 'The console reached its maximum duration and was closed.',
    tone: 'muted',
    retry: true,
  },
  'shutdown': {
    title: 'Controller restarting',
    detail: 'The controller is shutting down and closed the console. Connect again once it is back.',
    tone: 'warn',
    retry: true,
  },
  'disconnected': {
    title: 'Disconnected',
    detail: 'The console is closed.',
    tone: 'muted',
    retry: true,
  },
  'unavailable': {
    title: 'Console unavailable',
    detail: 'The controller could not open the screen.',
    tone: 'err',
    retry: true,
  },
}

export function endOf(kind: ConsoleEndKind, detail?: string): ConsoleEnd {
  const base = BASE[kind]
  return { kind, ...base, detail: detail && detail.length > 0 ? detail : base.detail }
}

/**
 * The cause for a closed console socket. The relay uses private close codes
 * (apps: crates/fleet-controller/src/proxmox_console.rs); the reason text is
 * the controller's own, already free of credentials.
 */
export function describeClose(code: number, reason: string): ConsoleEnd {
  switch (code) {
    case 4401: return endOf('sign-in')
    case 4403: return endOf('no-permission', 'You may not open guest screens: your principal lacks proxmox.console.')
    case 4404: return endOf('expired')
    case 4409: return endOf('limit', reason)
    case 4400: return endOf('unavailable', reason || 'The browser sent something the console relay could not follow.')
    case 4408: return endOf('idle')
    case 4410: return endOf('max-duration')
    case 1001: return endOf('shutdown')
    case 4502:
      return reason.includes('VM.Console') ? endOf('no-permission', reason) : endOf('unavailable', reason)
    case 4503: return endOf('unavailable', reason)
    case 1000:
      return reason.includes('guest closed')
        ? endOf('guest-stopped', 'The guest closed its screen. It may have stopped or rebooted; start it if needed and connect again.')
        : endOf('disconnected')
    default:
      return endOf('unavailable', code === 1006 ? 'The connection to the controller dropped.' : undefined)
  }
}

/** A failed session request (HTTP), as the cause to show. */
export function describeRequestFailure(status: number, message: string): ConsoleEnd {
  if (status === 403)
    return endOf('no-permission', 'You may not open guest screens: your principal lacks proxmox.console.')
  if (status === 409)
    return endOf('limit', message)
  if (status === 502 && message.includes('VM.Console'))
    return endOf('no-permission', message)
  return endOf('unavailable', message)
}

/** The socket URL for a session: the controller's own origin, ws or wss. */
export function socketUrl(session: Pick<ConsoleSessionDto, 'socketPath'>, location: Pick<Location, 'protocol' | 'host'>): string {
  const scheme = location.protocol === 'https:' ? 'wss:' : 'ws:'
  return `${scheme}//${location.host}${session.socketPath}`
}

const CONSOLE_TOKEN_PREFIX = 'fleet-console-token.'

/** The subprotocols to offer: `binary`, then the token (never in the URL). */
export function subprotocolsFor(token: string): string[] {
  return ['binary', `${CONSOLE_TOKEN_PREFIX}${token}`]
}

/** The session token a console link carries in its URL fragment. */
export function sessionFromHash(hash: string): string | null {
  const match = /^#session=([A-Za-z0-9_-]{16,256})$/.exec(hash)
  return match ? match[1]! : null
}

/** Whether the inventory says the guest has no screen to show. */
export function guestHasNoScreen(status: string | null | undefined): boolean {
  return status === 'stopped'
}
