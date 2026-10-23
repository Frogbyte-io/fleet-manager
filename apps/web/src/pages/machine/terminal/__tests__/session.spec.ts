import { describe, expect, it } from 'vitest'

import { describeClose, describeRequestFailure, exitCodeOf, isReady, resizeMessage, socketUrl } from '../session'

describe('terminal session logic', () => {
  it('names every close the relay can send', () => {
    expect(describeClose(4401, '').kind).toBe('sign-in')
    expect(describeClose(4403, '').kind).toBe('no-permission')
    expect(describeClose(4403, '').detail).toContain('machines.terminal')
    expect(describeClose(4404, '').kind).toBe('expired')
    expect(describeClose(4408, '').kind).toBe('idle')
    expect(describeClose(4409, 'too many').detail).toBe('too many')
    expect(describeClose(4410, '').kind).toBe('max-duration')
    expect(describeClose(4412, '').kind).toBe('lost')
    expect(describeClose(1001, '').kind).toBe('shutdown')
    expect(describeClose(4502, 'the key was revoked').detail).toBe('the key was revoked')
    expect(describeClose(1006, '').detail).toContain('dropped')
  })

  it('reports the shell exit status', () => {
    const end = describeClose(1000, 'the shell ended', 7)
    expect(end.kind).toBe('exited')
    expect(end.detail).toContain('exit status 7')
    // Reason text is never parsed for a status.
    expect(describeClose(1000, 'the shell ended (exit status 9)').detail).not.toContain('9')
    expect(describeClose(1000, 'closed').kind).toBe('closed')
    expect(exitCodeOf('{"type":"exit","code":5}')).toBe(5)
    expect(exitCodeOf('{"type":"ready"}')).toBeNull()
    expect(exitCodeOf('nope')).toBeNull()
  })

  it('maps request failures', () => {
    expect(describeRequestFailure(403, 'x').kind).toBe('no-permission')
    expect(describeRequestFailure(503, 'busy').kind).toBe('limit')
    expect(describeRequestFailure(400, 'host key was never confirmed').detail).toContain('host key')
  })

  it('builds the socket URL on the controller origin and never carries the token', () => {
    expect(socketUrl('/api/v1/terminal/socket', { protocol: 'http:', host: 'box.lan:8080' })).toBe('ws://box.lan:8080/api/v1/terminal/socket')
    expect(socketUrl('/api/v1/terminal/socket', { protocol: 'https:', host: 'fleet.example.test' })).toBe('wss://fleet.example.test/api/v1/terminal/socket')
  })

  it('frames control messages', () => {
    expect(JSON.parse(resizeMessage(100, 30))).toEqual({ type: 'resize', cols: 100, rows: 30 })
    expect(isReady('{"type":"ready"}')).toBe(true)
    expect(isReady('nope')).toBe(false)
  })
})
