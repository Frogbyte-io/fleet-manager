// Presentation helpers for the machine removal review (#616, #623). They
// only format what `POST /machines/{id}/remove/review` and
// `POST /machines/{id}/remove` answer; the controller decides what blocks a
// removal, what is deleted and what is kept.

import type { EndpointAuthDto, RemovalFootprintDto } from '@frogbyte-io/fleet-api-client'

export interface TextSpan {
  text: string
  code: boolean
}

/**
 * Splits a controller message into plain text and its backticked spans, so
 * the `fleetctl …` command a blocker names renders as code. An unmatched
 * backtick stays as text.
 */
export function codeSpans(message: string): TextSpan[] {
  const spans: TextSpan[] = []
  const pattern = /`([^`]+)`/g
  let last = 0
  for (const match of message.matchAll(pattern)) {
    const start = match.index ?? 0
    if (start > last)
      spans.push({ text: message.slice(last, start), code: false })
    spans.push({ text: match[1] ?? '', code: true })
    last = start + match[0].length
  }
  if (last < message.length)
    spans.push({ text: message.slice(last), code: false })
  return spans
}

/** How the review resolved the uninstall's authentication, in words. */
export function authLabel(auth: EndpointAuthDto): string {
  switch (auth.type) {
    case 'agent':
      return 'SSH agent'
    case 'identityFile':
      return `identity file ${auth.path}`
    case 'secret':
      return `stored key ${auth.credential}`
  }
}

export interface CountRow {
  key: keyof RemovalFootprintDto
  label: string
  /** Shown even at zero: the stored secrets a removal destroys. */
  always?: boolean
}

/** The footprint counts the removal deletes, labelled as the API documents them. */
export const DELETED_COUNTS: CountRow[] = [
  { key: 'endpoints', label: 'Endpoints' },
  { key: 'endpointAuth', label: 'Endpoint auth defaults' },
  { key: 'capabilities', label: 'Capability facts' },
  { key: 'inventorySnapshots', label: 'Inventory snapshots' },
  { key: 'tagsAndGroups', label: 'Tag and group memberships' },
  { key: 'nodeIdentity', label: 'Node identity' },
  { key: 'nodeCredentials', label: 'Node credentials, sessions, tokens' },
  { key: 'projectCheckouts', label: 'Project checkouts' },
  { key: 'skillsSnapshot', label: 'Skills snapshot' },
  { key: 'catalogSkillInstalls', label: 'Recorded skill installs' },
  { key: 'guestLink', label: 'Proxmox guest link' },
  { key: 'storedSshKeys', label: 'Stored SSH keys (revoked)', always: true },
  { key: 'adminPasswords', label: 'Windows admin passwords (destroyed)', always: true },
]

/** The rows worth a line: every non-zero count, and the secret counts always. */
export function deletedRows(footprint: RemovalFootprintDto): CountRow[] {
  return DELETED_COUNTS.filter(row => row.always || footprint[row.key] > 0)
}
