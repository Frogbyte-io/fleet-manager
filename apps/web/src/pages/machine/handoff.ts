// Client handoffs: strings the operator's own SSH client or VS Code opens.
// Fleet never proxies these connections.

export interface SshTarget {
  user: string | null
  host: string
  port: number
}

/**
 * Parses an SSH endpoint reference (`user@host:port`, `host:port`, or
 * `host`). A redacted user (`***`) is dropped: the operator's own SSH
 * config then supplies it.
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
    if (colon >= 0 && rest.indexOf(':') === colon) {
      const parsed = Number(rest.slice(colon + 1))
      if (!Number.isInteger(parsed))
        return null
      port = parsed
      rest = rest.slice(0, colon)
    }
  }
  if (rest === '' || !Number.isInteger(port) || port <= 0 || port > 65535)
    return null
  const user = rawUser === '' || /^\*+$/.test(rawUser) ? null : rawUser
  return { user, host: rest, port }
}

function destination(target: SshTarget): string {
  const host = target.host.includes(':') ? `[${target.host}]` : target.host
  return target.user ? `${target.user}@${host}` : host
}

export function sshCommand(target: SshTarget): string {
  const host = target.user ? `${target.user}@${target.host}` : target.host
  return target.port === 22 ? `ssh ${host}` : `ssh -p ${target.port} ${host}`
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
  return `vscode://vscode-remote/ssh-remote+${destination(target)}/`
}
