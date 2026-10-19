import { EditorView } from 'codemirror'
import { afterEach, describe, expect, it } from 'vitest'

import { CSP_NONCE_PLACEHOLDER, cspNonce } from '../cspNonce'

function setMeta(nonce: string | null) {
  document.head.querySelectorAll('meta[property="csp-nonce"]').forEach(meta => meta.remove())
  if (nonce === null)
    return
  const meta = document.createElement('meta')
  meta.setAttribute('property', 'csp-nonce')
  meta.setAttribute('nonce', nonce)
  document.head.append(meta)
}

afterEach(() => setMeta(null))

describe('cspNonce', () => {
  it('reads the nonce the controller wrote into the shell', () => {
    setMeta('r4nd0mN0nce/AAAAAAAAAA==')
    expect(cspNonce()).toBe('r4nd0mN0nce/AAAAAAAAAA==')
  })

  it('treats a missing tag or the unreplaced placeholder as no nonce', () => {
    expect(cspNonce()).toBeUndefined()
    setMeta(CSP_NONCE_PLACEHOLDER)
    expect(cspNonce()).toBeUndefined()
    setMeta('')
    expect(cspNonce()).toBeUndefined()
  })

  it('makes CodeMirror tag its injected theme with the nonce', () => {
    setMeta('c0dem1rr0rN0nce')
    const parent = document.createElement('div')
    document.body.append(parent)
    const view = new EditorView({ parent, extensions: [EditorView.cspNonce.of(cspNonce()!)] })
    const styles = [...document.querySelectorAll('style')]
    expect(styles.length).toBeGreaterThan(0)
    expect(styles.every(style => style.getAttribute('nonce') === 'c0dem1rr0rN0nce')).toBe(true)
    view.destroy()
    parent.remove()
  })
})
