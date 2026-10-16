// Pure helpers for the approval inbox: which requests wait for a person,
// how a state or risk class is shown, and the `fleetctl` equivalent of each
// decision. No Vue imports, so each is unit-tested directly.

import type { ActionRequestDto } from '@frogbyte-io/fleet-api-client'

export type Tone = 'ok' | 'info' | 'warn' | 'err' | 'muted' | 'faint'

/** The request states in the order the API reports them (DESIGN.md §3). */
export function stateTone(state: string): Tone {
  switch (state) {
    case 'pending': return 'warn'
    case 'approved':
    case 'executing': return 'info'
    case 'succeeded': return 'ok'
    case 'failed': return 'err'
    case 'denied': return 'muted'
    case 'expired': return 'faint'
    default: return 'faint'
  }
}

/** `auto` ran without a decision, `approve` waits for a person, `deny` is refused. */
export function riskTone(risk: string): Tone {
  switch (risk) {
    case 'approve': return 'warn'
    case 'deny': return 'err'
    case 'auto': return 'muted'
    default: return 'faint'
  }
}

/** Requests waiting for a decision, oldest first: the longest wait is decided first. */
export function pendingRequests(requests: ActionRequestDto[]): ActionRequestDto[] {
  return requests
    .filter(r => r.state === 'pending')
    .sort((a, b) => a.createdAt - b.createdAt || a.id.localeCompare(b.id))
}

/** Everything else, newest decision or change first. */
export function historyRequests(requests: ActionRequestDto[]): ActionRequestDto[] {
  return requests
    .filter(r => r.state !== 'pending')
    .sort((a, b) => b.updatedAt - a.updatedAt || a.id.localeCompare(b.id))
}

/** The parameters as the requester sent them, or a note that there are none. */
export function parametersText(parameters: unknown): string {
  if (parameters === null || parameters === undefined)
    return ''
  if (typeof parameters === 'object' && Object.keys(parameters as object).length === 0)
    return ''
  return JSON.stringify(parameters, null, 2)
}

/** Quotes one shell word only when it needs it. */
function shellWord(word: string): string {
  return /^[\w./:=@%+-]+$/.test(word) ? word : `'${word.replace(/'/g, `'\\''`)}'`
}

export function approveCommand(id: string): string {
  return `fleetctl requests approve ${shellWord(id)} --output json`
}

export function denyCommand(id: string, note: string): string {
  const trimmed = note.trim()
  return `fleetctl requests deny ${shellWord(id)}${trimmed ? ` --note ${shellWord(trimmed)}` : ''} --output json`
}

/** `expires in 12M`, or `expired` once the deadline passed. */
export function expiresText(expiresAt: number, now: number = Date.now()): string {
  const seconds = Math.floor((expiresAt - now) / 1000)
  if (seconds <= 0)
    return 'EXPIRED'
  if (seconds < 60)
    return `EXPIRES IN ${seconds}S`
  const minutes = Math.floor(seconds / 60)
  if (minutes < 60)
    return `EXPIRES IN ${minutes}M`
  const hours = Math.floor(minutes / 60)
  if (hours < 48)
    return `EXPIRES IN ${hours}H`
  return `EXPIRES IN ${Math.floor(hours / 24)}D`
}
