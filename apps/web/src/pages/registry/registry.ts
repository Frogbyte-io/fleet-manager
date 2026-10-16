// Pure model for the Registry console. A type definition (`RegistryTypeDto.spec`)
// drives the columns and how each value renders; nothing here knows `domain` or
// `service` specifically (those views are FM-1021).

export type ScalarType = 'string' | 'text' | 'number' | 'boolean' | 'date' | 'url' | 'hostname' | 'email' | 'money' | 'enum'
export type ValueType = ScalarType | 'list'

const VALUE_TYPES: readonly string[] = ['string', 'text', 'number', 'boolean', 'date', 'url', 'hostname', 'email', 'money', 'enum', 'list']

export interface FieldDef {
  name: string
  type: ValueType
  /** The item type, for lists. */
  items: ScalarType | null
  required: boolean
  description: string | null
  isKey: boolean
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

/** The declared fields of a type spec, the key field first and the rest in name order. */
export function fieldDefs(spec: unknown, keyField: string): FieldDef[] {
  const declared = isRecord(spec) && isRecord(spec.fields) ? spec.fields : {}
  const defs: FieldDef[] = []
  for (const [name, raw] of Object.entries(declared)) {
    const field = isRecord(raw) ? raw : {}
    const type = typeof field.type === 'string' && VALUE_TYPES.includes(field.type) ? field.type as ValueType : 'string'
    const items = type === 'list' && typeof field.items === 'string' && VALUE_TYPES.includes(field.items) ? field.items as ScalarType : null
    defs.push({
      name,
      type,
      items,
      required: field.required === true,
      description: typeof field.description === 'string' ? field.description : null,
      isKey: name === keyField,
    })
  }
  defs.sort((a, b) => Number(b.isKey) - Number(a.isKey) || a.name.localeCompare(b.name))
  return defs
}

/** Table columns: the key field and the first few declared fields; the drawer shows the rest. */
export const MAX_COLUMNS = 5
export function columnDefs(defs: FieldDef[]): FieldDef[] {
  const wide = (d: FieldDef) => d.type === 'text' || d.type === 'list'
  const columns = defs.filter(d => !wide(d)).slice(0, MAX_COLUMNS)
  if (columns.length < MAX_COLUMNS)
    columns.push(...defs.filter(wide).slice(0, MAX_COLUMNS - columns.length))
  return columns
}

export type Rendered =
  | { kind: 'empty' }
  | { kind: 'text', text: string, mono?: boolean }
  | { kind: 'bool', value: boolean }
  | { kind: 'link', text: string, href: string }
  | { kind: 'list', items: Rendered[] }

/** Only web URLs become anchors; anything else stays inert text. */
export function safeHref(value: string): string | null {
  try {
    const url = new URL(value)
    return url.protocol === 'https:' || url.protocol === 'http:' ? url.href : null
  }
  catch {
    return null
  }
}

/** `12.50 EUR` formatted with the locale, or the raw text when it does not parse. */
export function formatMoney(value: string): string {
  const match = /^(-?\d+(?:\.\d+)?)\s+([A-Za-z]{3})$/.exec(value.trim())
  if (!match)
    return value
  const [, amount, code] = match
  try {
    return new Intl.NumberFormat('en', { style: 'currency', currency: code!.toUpperCase() }).format(Number(amount))
  }
  catch {
    return value
  }
}

const DAY_MS = 86_400_000

/** A `YYYY-MM-DD` date with a relative hint (`in 38 days`, `3 days ago`). */
export function formatDate(value: string, now = Date.now()): string {
  const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(value)
  if (!match)
    return value
  const at = Date.UTC(Number(match[1]), Number(match[2]) - 1, Number(match[3]))
  const today = Math.floor(now / DAY_MS) * DAY_MS
  const days = Math.round((at - today) / DAY_MS)
  if (days === 0)
    return `${value} (today)`
  const unit = Math.abs(days) === 1 ? 'day' : 'days'
  return days > 0 ? `${value} (in ${days} ${unit})` : `${value} (${-days} ${unit} ago)`
}

function renderScalar(type: ScalarType, value: unknown, now: number): Rendered {
  if (value === null || value === undefined || value === '')
    return { kind: 'empty' }
  if (type === 'boolean')
    return typeof value === 'boolean' ? { kind: 'bool', value } : { kind: 'text', text: String(value) }
  if (typeof value !== 'string' && typeof value !== 'number')
    return { kind: 'text', text: JSON.stringify(value), mono: true }
  const text = String(value)
  switch (type) {
    case 'url': {
      const href = safeHref(text)
      return href ? { kind: 'link', text, href } : { kind: 'text', text, mono: true }
    }
    case 'email':
      return { kind: 'link', text, href: `mailto:${text}` }
    case 'money':
      return { kind: 'text', text: formatMoney(text) }
    case 'date':
      return { kind: 'text', text: formatDate(text, now) }
    case 'hostname':
    case 'number':
      return { kind: 'text', text, mono: true }
    default:
      return { kind: 'text', text }
  }
}

/** Renders one field value according to its declared type. */
export function renderValue(def: Pick<FieldDef, 'type' | 'items'>, value: unknown, now = Date.now()): Rendered {
  if (def.type === 'list') {
    if (!Array.isArray(value) || value.length === 0)
      return { kind: 'empty' }
    return { kind: 'list', items: value.map(item => renderScalar(def.items ?? 'string', item, now)) }
  }
  return renderScalar(def.type, value, now)
}

/** The plain-text form of a rendered value, for compact cells and tests. */
export function renderedText(rendered: Rendered): string {
  switch (rendered.kind) {
    case 'empty': return ''
    case 'bool': return rendered.value ? 'Yes' : 'No'
    case 'list': return rendered.items.map(renderedText).filter(Boolean).join(', ')
    default: return rendered.text
  }
}

/** Entry fields as an object; anything else is treated as no fields. */
export function fieldValues(fields: unknown): Record<string, unknown> {
  return isRecord(fields) ? fields : {}
}

/** Values the type does not declare: kept visible, never dropped. */
export function undeclaredFields(fields: unknown, defs: FieldDef[]): string[] {
  const known = new Set(defs.map(d => d.name))
  return Object.keys(fieldValues(fields)).filter(name => !known.has(name)).sort()
}

export interface EntryLink { label: string, url: string, href: string | null }

export function entryLinks(links: unknown): EntryLink[] {
  if (!Array.isArray(links))
    return []
  return links.flatMap((raw) => {
    if (!isRecord(raw) || typeof raw.url !== 'string')
      return []
    const label = typeof raw.label === 'string' && raw.label ? raw.label : raw.url
    return [{ label, url: raw.url, href: safeHref(raw.url) }]
  })
}

export interface TargetRef { class: string, reference: string }

export interface TargetLink {
  /** A router location, or null when the target has no page of its own. */
  to: { path: string, query?: Record<string, string> } | null
  label: string
  classLabel: string
}

const CLASS_LABELS: Record<string, string> = {
  registry: 'Entry',
  machine: 'Machine',
  project: 'Project',
  coolify: 'Coolify',
  proxmoxGuest: 'Proxmox guest',
}

/**
 * Where a relation target lives in the console. Machines resolve by name to
 * their id when the machine list knows it; Registry entries open in the
 * Registry; the rest link to their section or stay as text.
 */
export function targetLink(target: TargetRef, machineIds: ReadonlyMap<string, string>): TargetLink {
  const classLabel = CLASS_LABELS[target.class] ?? target.class
  const label = target.reference
  switch (target.class) {
    case 'registry': {
      const slash = target.reference.indexOf('/')
      if (slash <= 0)
        return { to: null, label, classLabel }
      return { to: { path: '/registry', query: { type: target.reference.slice(0, slash), entry: target.reference.slice(slash + 1) } }, label, classLabel }
    }
    case 'machine': {
      const id = machineIds.get(target.reference)
      return { to: id ? { path: `/fleet/machines/${encodeURIComponent(id)}` } : { path: '/fleet' }, label, classLabel }
    }
    case 'project':
      return { to: { path: '/projects' }, label, classLabel }
    case 'proxmoxGuest':
      return { to: { path: '/proxmox' }, label, classLabel }
    default:
      return { to: null, label, classLabel }
  }
}

export type SourceLocation =
  | { kind: 'web', url: string }
  | { kind: 'path', path: string | null }

interface Remote { host: string, repo: string }

/** `host` and `owner/repo` from an https, ssh://, or scp-style remote; never the credentials. */
export function parseRemote(remote: string): Remote | null {
  const text = remote.trim()
  let host: string
  let path: string
  const scp = /^[^@/:\s]+@([^:/\s]+):(?!\/\/)(.+)$/.exec(text)
  if (scp) {
    host = scp[1]!
    path = scp[2]!
  }
  else {
    let url: URL
    try {
      url = new URL(text)
    }
    catch {
      return null
    }
    if (!['https:', 'http:', 'ssh:', 'git:'].includes(url.protocol))
      return null
    host = url.hostname
    path = url.pathname
  }
  const repo = path.replace(/^\/+/, '').replace(/\/+$/, '').replace(/\.git$/, '')
  const parts = repo.split('/')
  if (!host || parts.length < 2 || parts.some(part => !part || part === '.' || part === '..'))
    return null
  return { host: host.toLowerCase(), repo }
}

function validRepoPath(path: string): boolean {
  return path.length > 0 && !path.startsWith('/') && !path.includes('\\') && path.split('/').every(p => p && p !== '.' && p !== '..')
}

/**
 * The web URL of a source file at a commit for GitHub- and GitLab-style
 * hosts. Any other remote (or a missing path) yields the path alone so the
 * caller can show the `fleetctl registry set` command instead. The result
 * never contains anything from the remote beyond host and repository.
 */
export function sourceLocation(remote: string | null | undefined, commitSha: string | null | undefined, sourcePath: string | null | undefined): SourceLocation {
  const path = sourcePath && validRepoPath(sourcePath) ? sourcePath : null
  if (!remote || !commitSha || !path || !/^[0-9a-f]{7,64}$/i.test(commitSha))
    return { kind: 'path', path }
  const parsed = parseRemote(remote)
  if (!parsed)
    return { kind: 'path', path }
  const encodedPath = path.split('/').map(encodeURIComponent).join('/')
  const base = `https://${parsed.host}/${parsed.repo.split('/').map(encodeURIComponent).join('/')}`
  if (parsed.host === 'github.com')
    return { kind: 'web', url: `${base}/blob/${commitSha}/${encodedPath}` }
  if (parsed.host === 'gitlab.com' || parsed.host.startsWith('gitlab.'))
    return { kind: 'web', url: `${base}/-/blob/${commitSha}/${encodedPath}` }
  return { kind: 'path', path }
}

/** The CLI form of an edit, for when there is no web link. Values are placeholders. */
export function setCommand(type: string, key: string, field = 'field'): string {
  return `fleetctl registry set ${type}/${key} --field ${field}=<value>`
}
