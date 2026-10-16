import type { ExternalAccountDto, ExternalProbeDto } from '@frogbyte-io/fleet-api-client'

// Pure helpers for the provider accounts section: how a probe result reads,
// and the `fleetctl accounts` command each form mirrors. The token is never
// part of a command: `fleetctl` reads it from standard input.

export type ProviderKind = ExternalAccountDto['kind']

export const PROVIDER_KINDS: { id: ProviderKind, title: string, needsBaseUrl: boolean }[] = [
  { id: 'coolify', title: 'Coolify', needsBaseUrl: true },
  { id: 'cloudflare', title: 'Cloudflare', needsBaseUrl: false },
]

export function kindTitle(kind: ProviderKind): string {
  return PROVIDER_KINDS.find(entry => entry.id === kind)?.title ?? kind
}

type Tone = 'ok' | 'warn' | 'err' | 'muted'

export interface ProbeView {
  label: string
  tone: Tone
  detail: string
}

/** How the latest probe reads; an account never probed says so. */
export function probeView(probe: ExternalProbeDto | null | undefined): ProbeView {
  if (!probe)
    return { label: 'not probed', tone: 'muted', detail: '' }
  switch (probe.status) {
    case 'ok':
      return { label: 'ok', tone: 'ok', detail: probe.detail }
    case 'unreachable':
      return { label: 'unreachable', tone: 'err', detail: probe.detail }
    case 'unauthorized':
      return { label: 'unauthorized', tone: 'err', detail: probe.detail }
    case 'insufficient_permission':
      return { label: 'insufficient permission', tone: 'warn', detail: probe.detail }
    default:
      return { label: String(probe.status), tone: 'muted', detail: probe.detail }
  }
}

function quote(word: string): string {
  return /^[\w./:@=-]+$/.test(word) ? word : `'${word.replace(/'/g, `'\\''`)}'`
}

function join(words: string[]): string {
  return words.map(quote).join(' ')
}

export interface CreateDraft {
  kind: ProviderKind
  label: string
  baseUrl: string
  accountId: string
  notes: string
}

/** The create command; the token arrives on stdin, so it is only hinted. */
export function createCommand(draft: CreateDraft): string {
  const words = ['fleetctl', 'accounts', 'create', '--kind', draft.kind, '--label', draft.label || '<label>']
  if (draft.baseUrl.trim())
    words.push('--base-url', draft.baseUrl.trim())
  if (draft.accountId.trim())
    words.push('--account-id', draft.accountId.trim())
  if (draft.notes.trim())
    words.push('--notes', draft.notes.trim())
  return `${join(words)} < token-file`
}

export function probeCommand(id: string): string {
  return join(['fleetctl', 'accounts', 'probe', id])
}

export function deleteCommand(id: string): string {
  return join(['fleetctl', 'accounts', 'delete', id])
}

/** Whether two base URLs share scheme, host, and port (case-insensitive). */
export function sameOrigin(a: string, b: string): boolean {
  const origin = (url: string) => {
    const lower = url.trim().toLowerCase()
    const [scheme, rest = ''] = lower.split('://')
    return `${scheme}://${rest.split('/')[0]}`
  }
  return origin(a) === origin(b)
}
