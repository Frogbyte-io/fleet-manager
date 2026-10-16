import { describe, expect, it } from 'vitest'

import type { ActionRequestDto } from '@frogbyte-io/fleet-api-client'

import { approveCommand, denyCommand, expiresText, historyRequests, parametersText, pendingRequests, riskTone, stateTone } from '../requests'

const req = (id: string, state: string, createdAt: number, updatedAt = createdAt) => ({ id, state, createdAt, updatedAt }) as ActionRequestDto

describe('request helpers', () => {
  it('splits pending (oldest first) from history (latest change first)', () => {
    const all = [req('a', 'pending', 5), req('b', 'succeeded', 1, 9), req('c', 'pending', 2), req('d', 'denied', 1, 12)]
    expect(pendingRequests(all).map(r => r.id)).toEqual(['c', 'a'])
    expect(historyRequests(all).map(r => r.id)).toEqual(['d', 'b'])
  })

  it('maps states and risk classes to tones', () => {
    expect(stateTone('pending')).toBe('warn')
    expect(stateTone('executing')).toBe('info')
    expect(stateTone('succeeded')).toBe('ok')
    expect(stateTone('failed')).toBe('err')
    expect(stateTone('denied')).toBe('muted')
    expect(stateTone('something-new')).toBe('faint')
    expect(riskTone('approve')).toBe('warn')
    expect(riskTone('auto')).toBe('muted')
  })

  it('shows parameters verbatim and nothing for empty ones', () => {
    expect(parametersText({})).toBe('')
    expect(parametersText(null)).toBe('')
    expect(parametersText({ uuid: 'x' })).toBe('{\n  "uuid": "x"\n}')
  })

  it('builds the equivalent fleetctl commands, quoting a note', () => {
    expect(approveCommand('req-1')).toBe('fleetctl requests approve req-1 --output json')
    expect(denyCommand('req-1', '')).toBe('fleetctl requests deny req-1 --output json')
    expect(denyCommand('req-1', 'not now; it\'s risky')).toBe('fleetctl requests deny req-1 --note \'not now; it\'\\\'\'s risky\' --output json')
  })

  it('words the deadline', () => {
    expect(expiresText(1000, 2000)).toBe('EXPIRED')
    expect(expiresText(31_000, 1000)).toBe('EXPIRES IN 30S')
    expect(expiresText(1000 + 5 * 60_000, 1000)).toBe('EXPIRES IN 5M')
    expect(expiresText(1000 + 3 * 3600_000, 1000)).toBe('EXPIRES IN 3H')
  })
})
