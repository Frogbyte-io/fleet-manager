// Client handoffs: strings the operator's own SSH client or VS Code opens.
// Fleet never proxies these connections.

import { shellQuote } from './fleetctl'

export interface SshTarget {
  user: string | null
  host: string
  port: number
}

// What may appear in a host or user: DNS names, IPv4/IPv6 literals (with a
// zone id), and ordinary login names. Anything else (spaces, `;`, `$`,
// quotes) gets no handoff at all.
// A leading `-` is refused too, so a target can never read as an ssh option.
const HOST = /^[A-Za-z0-9._%:][A-Za-z0-9._%:-]*$/
const USER = /^[A-Za-z0-9._][A-Za-z0-9._-]*$/

function isIpv6(host: string): boolean {
  if (!host.includes(':'))
    return false
  try {
    return new URL(`http://[${host.replace(/%.*$/, '')}]/`).hostname !== ''
  }
  catch {
    return false
  }
}

/**
 * Parses an SSH endpoint reference (`user@host:port`, `host:port`, or
 * `host`). The controller writes IPv6 references unbracketed
 * (`user@fd7a::1:22`), so a multi-colon reference ends in its port when
 * the part before the last colon is itself an IPv6 address. A redacted user
 * (`***`) is dropped: the operator's own SSH config then supplies it.
 */
export function parseSshReference(reference: string): SshTarget | null {
  const at = reference.lastIndexOf('@')
  const rawUser = at >= 0 ? reference.slice(0, at) : ''
  let rest = at >= 0 ? reference.slice(at + 1) : reference
  let port = 22
  const bracketed = /^\[(.+)\](?::(\d+))?$/.exec(rest)
  if (bracketed) {
    rest = bracketed[1]!
    if (bracketed[2])
      port = Number(bracketed[2])
  }
  else {
    const colon = rest.lastIndexOf(':')
    const single = colon >= 0 && rest.indexOf(':') === colon
    const suffix = colon >= 0 ? rest.slice(colon + 1) : ''
    if (single) {
      if (!/^\d+$/.test(suffix))
        return null
      port = Number(suffix)
      rest = rest.slice(0, colon)
    }
    else if (colon >= 0 && /^\d+$/.test(suffix) && isIpv6(rest.slice(0, colon))) {
      port = Number(suffix)
      rest = rest.slice(0, colon)
    }
  }
  if (rest === '' || !HOST.test(rest) || !Number.isInteger(port) || port <= 0 || port > 65535)
    return null
  const redacted = rawUser === '' || /^\*+$/.test(rawUser)
  if (!redacted && !USER.test(rawUser))
    return null
  return { user: redacted ? null : rawUser, host: rest, port }
}

function destination(target: SshTarget): string {
  const host = target.host.includes(':') ? `[${target.host}]` : target.host
  return target.user ? `${target.user}@${host}` : host
}

/** The copied command; every word is shell-quoted before it reaches a clipboard. */
export function sshCommand(target: SshTarget): string {
  const host = target.user ? `${target.user}@${target.host}` : target.host
  const words = target.port === 22 ? ['ssh', host] : ['ssh', '-p', String(target.port), host]
  return words.map(shellQuote).join(' ')
}

/**
 * A `vscode://` Remote-SSH link; VS Code resolves it on the operator's
 * machine. The Remote-SSH authority names a host, not a port, so a
 * non-default port has no link: the operator adds a `Host` entry to their
 * SSH config instead.
 */
export function vscodeRemoteUrl(target: SshTarget): string | null {
  if (target.port !== 22)
    return null
  // A scoped IPv6 zone marker is a literal `%` inside a URI.
  return `vscode://vscode-remote/ssh-remote+${destination(target).replace(/%/g, '%25')}/`
}
