import { describe, expect, it } from 'vitest'

import { parseSshReference, sshCommand, vscodeRemoteUrl } from '../handoff'

describe('parseSshReference', () => {
  it('parses user, host, and port', () => {
    expect(parseSshReference('dev@build.lan:2222')).toEqual({ user: 'dev', host: 'build.lan', port: 2222 })
    expect(parseSshReference('build.lan')).toEqual({ user: null, host: 'build.lan', port: 22 })
    expect(parseSshReference('[fd7a::1]:22')).toEqual({ user: null, host: 'fd7a::1', port: 22 })
  })

  it('drops a redacted user so the operator\'s SSH config supplies it', () => {
    expect(parseSshReference('***@host:22')).toEqual({ user: null, host: 'host', port: 22 })
  })

  it('rejects references that are not an address', () => {
    expect(parseSshReference('')).toBeNull()
    expect(parseSshReference('host:notaport')).toBeNull()
    expect(parseSshReference('host:70000')).toBeNull()
  })
})

describe('handoffs', () => {
  it('builds an ssh command', () => {
    expect(sshCommand({ user: 'dev', host: 'h', port: 22 })).toBe('ssh dev@h')
    expect(sshCommand({ user: null, host: 'h', port: 2222 })).toBe('ssh -p 2222 h')
  })

  it('builds a VS Code Remote-SSH link only for the default port', () => {
    expect(vscodeRemoteUrl({ user: 'dev', host: 'h', port: 22 })).toBe('vscode://vscode-remote/ssh-remote+dev@h/')
    expect(vscodeRemoteUrl({ user: 'dev', host: 'h', port: 2222 })).toBeNull()
  })
})
