import { describe, expect, it } from 'vitest'

import { allowXtermStyles } from '../styleNonce'

describe('allowXtermStyles', () => {
  it('gives style elements created afterwards the page nonce, and nothing else', () => {
    const meta = document.createElement('meta')
    meta.setAttribute('property', 'csp-nonce')
    meta.setAttribute('nonce', 'abc123nonce')
    document.head.appendChild(meta)
    allowXtermStyles(document)
    expect(document.createElement('style').nonce).toBe('abc123nonce')
    expect(document.createElement('div').nonce ?? '').toBe('')
    // Idempotent: a second call does not wrap again.
    allowXtermStyles(document)
    expect(document.createElement('STYLE').nonce).toBe('abc123nonce')
  })
})
