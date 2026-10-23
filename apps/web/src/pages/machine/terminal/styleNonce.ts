import { cspNonce } from '../../images/cspNonce'

let installed = false

/**
 * xterm.js injects a `<style>` element for its scrollbar colours (and again
 * whenever the theme changes) and has no nonce option, so the controller's
 * nonce-only `style-src` blocks it. Elements created with the page's nonce
 * are allowed, so style elements made after this call carry it. Idempotent,
 * and a no-op without a nonce (the Vite dev server sends no CSP).
 */
export function allowXtermStyles(doc: Document = document): void {
  const nonce = cspNonce(doc)
  if (installed || nonce === undefined)
    return
  installed = true
  const create = doc.createElement.bind(doc) as (tag: string, options?: ElementCreationOptions) => HTMLElement
  doc.createElement = ((tag: string, options?: ElementCreationOptions) => {
    const element = create(tag, options)
    if (tag.toLowerCase() === 'style')
      element.nonce = nonce
    return element
  }) as typeof doc.createElement
}
