// noVNC (MPL-2.0, used unmodified from the npm package) ships no types. This
// declares only the part of its API the console uses.
declare module '@novnc/novnc' {
  export interface RFBOptions {
    credentials?: { username?: string, password?: string, target?: string }
    shared?: boolean
    wsProtocols?: string[]
  }

  export default class RFB extends EventTarget {
    constructor(target: HTMLElement, urlOrChannel: string | WebSocket, options?: RFBOptions)
    scaleViewport: boolean
    clipViewport: boolean
    resizeSession: boolean
    viewOnly: boolean
    focusOnClick: boolean
    background: string
    showDotCursor: boolean
    disconnect(): void
    sendCtrlAltDel(): void
    sendKey(keysym: number, code: string | null, down?: boolean): void
    focus(options?: FocusOptions): void
    blur(): void
    clipboardPasteFrom(text: string): void
  }
}
