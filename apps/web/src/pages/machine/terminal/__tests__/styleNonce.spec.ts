import { describe, expect, it } from 'vitest'

import { withXtermStyleNonce } from '../styleNonce'

describe('withXtermStyleNonce', () => {
  it('nonces style elements only while the callback runs', () => {
    const meta = document.createElement('meta')
    meta.setAttribute('property', 'csp-nonce')
    meta.setAttribute('nonce', 'abc123nonce')
    document.head.appendChild(meta)

    const inside = withXtermStyleNonce(() => ({
      style: document.createElement('style').nonce,
      div: document.createElement('div').nonce ?? '',
    }))
    expect(inside.style).toBe('abc123nonce')
    expect(inside.div).toBe('')
    // Other code gets plain elements again.
    expect(document.createElement('style').nonce ?? '').toBe('')
  })

  it('restores createElement even when the callback throws', () => {
    const before = document.createElement
    expect(() => withXtermStyleNonce(() => { throw new Error('boom') })).toThrow('boom')
    expect(document.createElement).toBe(before)
  })
})
