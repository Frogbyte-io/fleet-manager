/** The token `vite.config.ts` puts where the controller writes the nonce. */
export const CSP_NONCE_PLACEHOLDER = '__FLEET_CSP_NONCE__'

/**
 * The per-response CSP nonce the controller served with this page, for code
 * that injects `<style>` elements at runtime (CodeMirror's `EditorView.cspNonce`).
 *
 * Read from the `nonce` property, not the attribute: browsers hide nonce
 * attributes from the DOM once a CSP applies. An unreplaced placeholder (the
 * Vite dev server, which sends no CSP) counts as no nonce.
 */
export function cspNonce(doc: Document = document): string | undefined {
  const meta = doc.querySelector<HTMLMetaElement>('meta[property="csp-nonce"]')
  const nonce = meta?.nonce || meta?.getAttribute('nonce') || ''
  return nonce && nonce !== CSP_NONCE_PLACEHOLDER ? nonce : undefined
}
