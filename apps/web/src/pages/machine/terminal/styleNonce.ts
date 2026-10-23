import { cspNonce } from '../../images/cspNonce'

/**
 * xterm.js injects a `<style>` element for its scrollbar colours (and again
 * whenever the theme changes or the renderer falls back) and has no nonce
 * option, so the controller's nonce-only `style-src` blocks it. A `<style>`
 * element created with the page's nonce is allowed. So that no other code
 * silently gets nonced elements, `document.createElement` is wrapped only
 * while `run` executes (xterm's own calls) and the original is restored
 * right after. A no-op without a nonce (the Vite dev server sends no CSP).
 */
export function withXtermStyleNonce<T>(run: () => T, doc: Document = document): T {
  const nonce = cspNonce(doc)
  if (nonce === undefined)
    return run()
  const original = doc.createElement
  const create = original.bind(doc) as (tag: string, options?: ElementCreationOptions) => HTMLElement
  doc.createElement = ((tag: string, options?: ElementCreationOptions) => {
    const element = create(tag, options)
    if (tag.toLowerCase() === 'style')
      element.nonce = nonce
    return element
  }) as typeof doc.createElement
  try {
    return run()
  }
  finally {
    doc.createElement = original
  }
}
