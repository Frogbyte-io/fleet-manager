import { describe, expect, it } from 'vitest'

import {
  describeClose,
  describeRequestFailure,
  guestHasNoScreen,
  sessionFromHash,
  socketUrl,
  subprotocolsFor,
} from '../session'

describe('describeClose', () => {
  it('turns every relay close code into a stated cause, never a blank canvas', () => {
    expect(describeClose(4401, '').kind).toBe('sign-in')
    expect(describeClose(4403, '').kind).toBe('no-permission')
    expect(describeClose(4404, '').kind).toBe('expired')
    expect(describeClose(4409, 'too many console sessions are open').detail).toContain('too many console sessions')
    expect(describeClose(4408, '').kind).toBe('idle')
    expect(describeClose(4410, '').kind).toBe('max-duration')
    expect(describeClose(1001, '').kind).toBe('shutdown')
    for (const code of [4401, 4403, 4404, 4409, 4408, 4410, 1001, 4502, 4503, 1000, 1006, 1011]) {
      const cause = describeClose(code, 'x')
      expect(cause.title.length).toBeGreaterThan(0)
      expect(cause.detail.length).toBeGreaterThan(0)
    }
  })

  it('explains a missing VM.Console with the controller\'s own words', () => {
    const cause = describeClose(4502, 'the account\'s API token lacks VM.Console on /vms/101; grant it')
    expect(cause.kind).toBe('no-permission')
    expect(cause.detail).toContain('/vms/101')
    // Any other upstream failure is "unavailable", not a permission claim.
    expect(describeClose(4502, 'the connection failed').kind).toBe('unavailable')
  })

  it('reads a guest that closed its screen as a stopped guest', () => {
    expect(describeClose(1000, 'the guest closed its screen').kind).toBe('guest-stopped')
    expect(describeClose(1000, 'closed').kind).toBe('disconnected')
  })

  it('says a dropped connection dropped', () => {
    expect(describeClose(1006, '').detail).toContain('dropped')
  })
})

describe('describeRequestFailure', () => {
  it('maps the session request\'s refusals', () => {
    expect(describeRequestFailure(403, 'denied').kind).toBe('no-permission')
    expect(describeRequestFailure(409, 'too many console sessions').kind).toBe('limit')
    expect(describeRequestFailure(502, 'proxmox_source: the token lacks VM.Console on /vms/101').kind).toBe('no-permission')
    expect(describeRequestFailure(502, 'proxmox_source: the connection failed').kind).toBe('unavailable')
    expect(describeRequestFailure(0, 'network down').detail).toBe('network down')
  })
})

describe('the socket', () => {
  it('uses the controller\'s own origin and keeps the token out of the URL', () => {
    expect(socketUrl({ socketPath: '/api/v1/proxmox/console/socket' }, { protocol: 'https:', host: 'fleet.example.test' }))
      .toBe('wss://fleet.example.test/api/v1/proxmox/console/socket')
    expect(socketUrl({ socketPath: '/p' }, { protocol: 'http:', host: 'localhost:8080' })).toBe('ws://localhost:8080/p')
    expect(subprotocolsFor('abc')).toEqual(['binary', 'fleet-console-token.abc'])
  })
})

describe('sessionFromHash', () => {
  it('reads only a well-formed session fragment', () => {
    expect(sessionFromHash('#session=abcdefghijklmnopqrstuvwxyz0123456789_-ABC')).toBe('abcdefghijklmnopqrstuvwxyz0123456789_-ABC')
    expect(sessionFromHash('')).toBeNull()
    expect(sessionFromHash('#session=short')).toBeNull()
    expect(sessionFromHash('#session=abcdefghijklmnop&x=1')).toBeNull()
    expect(sessionFromHash('#other=abcdefghijklmnopqrstuvwx')).toBeNull()
  })
})

describe('guestHasNoScreen', () => {
  it('is true only for a stopped guest', () => {
    expect(guestHasNoScreen('stopped')).toBe(true)
    expect(guestHasNoScreen('running')).toBe(false)
    expect(guestHasNoScreen(null)).toBe(false)
  })
})
