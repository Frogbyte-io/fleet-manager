import { describe, expect, it } from 'vitest'

import type { RemovalFootprintDto } from '@frogbyte-io/fleet-api-client'

import { authLabel, codeSpans, DELETED_COUNTS, deletedRows } from '../removal'

describe('codeSpans', () => {
  it('splits backticked commands out of a controller message', () => {
    expect(codeSpans('wait for it (`fleetctl operations get op1`) or cancel it (`fleetctl operations cancel op1`)')).toEqual([
      { text: 'wait for it (', code: false },
      { text: 'fleetctl operations get op1', code: true },
      { text: ') or cancel it (', code: false },
      { text: 'fleetctl operations cancel op1', code: true },
      { text: ')', code: false },
    ])
  })

  it('keeps a message without commands, and an unmatched backtick, as text', () => {
    expect(codeSpans('plain')).toEqual([{ text: 'plain', code: false }])
    expect(codeSpans('a ` b')).toEqual([{ text: 'a ` b', code: false }])
    expect(codeSpans('')).toEqual([])
  })
})

describe('authLabel', () => {
  it('names each resolved auth', () => {
    expect(authLabel({ type: 'agent' })).toBe('SSH agent')
    expect(authLabel({ type: 'identityFile', path: '/k' })).toBe('identity file /k')
    expect(authLabel({ type: 'secret', credential: 'ref-1' })).toBe('stored key ref-1')
  })
})

describe('deletedRows', () => {
  it('lists the non-zero counts and always the secret counts', () => {
    const footprint = Object.fromEntries(DELETED_COUNTS.map(row => [row.key, 0])) as unknown as RemovalFootprintDto
    footprint.endpoints = 2
    footprint.capabilities = 5
    expect(deletedRows(footprint).map(row => row.key)).toEqual(['endpoints', 'capabilities', 'storedSshKeys', 'adminPasswords'])
  })
})
