// Pure catalog helpers: early checks modelled on fleet-core
// `skill_catalog.rs`, so most refusals show while typing (the controller's
// validation stays authoritative and may refuse what these miss),
// a line diff for version history, and the `SkillPreset` desired-state
// resource an assignment is committed as.

import type { CatalogContentDto, CatalogVersionDto } from '@frogbyte-io/fleet-api-client'

export const MAX_CATALOG_BYTES = 512 * 1024
export const MAX_CATALOG_FILES = 64

/** fleet-core `validate_skill_name`. */
export function skillNameError(name: string): string | null {
  if (name === '' || name.length > 64 || name.startsWith('-') || name.endsWith('-') || name.includes('--') || !/^[a-z0-9-]+$/.test(name))
    return 'name must use 1..=64 lowercase letters, digits, and single hyphens'
  return null
}

/** fleet-core `validate_relative_path`. */
export function relativePathError(path: string): string | null {
  // eslint-disable-next-line no-control-regex
  if (path === '' || path.length > 240 || path.startsWith('/') || path.includes('\\') || /[\x00-\x1f\x7f]/.test(path))
    return `invalid relative skill path "${path}"`
  if (path.split('/').some(part => part === '' || part === '.' || part === '..') || path.includes(':'))
    return `skill path must stay inside the skill directory: "${path}"`
  return null
}

const QUERY_SECRET_KEYS = [
  'token', 'access_token', 'refresh_token', 'password', 'passwd', 'secret', 'client_secret',
  'api_key', 'apikey', 'auth', 'signature', 'sig', 'credential',
]
const ASSIGNMENT_SECRET_MARKERS = ['password', 'passwd', 'secret', 'api_key', 'apikey', 'access_token', 'token']
const PLACEHOLDER_VALUES = ['${...}', '${token}', '<redacted>', 'changeme', 'your-token', 'example']

/**
 * fleet-core `reject_secret_shaped_content`, so an author sees the refusal
 * while typing. The controller's check stays authoritative.
 */
export function secretShapedError(content: string): string | null {
  const lower = content.toLowerCase()
  const aws = /AKIA[A-Za-z0-9]{16}/.test(content)
  const privateKey = lower.includes('-----begin ') && lower.includes(' private key-----')
  if (['ghp_', 'github_pat_', 'xoxb-', 'sk_live_'].some(n => lower.includes(n)) || aws || privateKey)
    return 'content appears to contain a credential or private key'
  const tokens = content.split(/\s+/).filter(Boolean)
  const query = tokens.some((token) => {
    const [, ...queries] = token.split(/[?#]/)
    return queries.flatMap(q => q.split('&')).some((part) => {
      const index = part.indexOf('=')
      return index >= 0 && index < part.length - 1 && QUERY_SECRET_KEYS.includes(part.slice(0, index).toLowerCase())
    })
  })
  if (query)
    return 'content contains a credential-bearing query parameter'
  const userinfo = tokens.some((token) => {
    const index = token.indexOf('://')
    return index >= 0 && (token.slice(index + 3).split(/[/?#]/)[0] ?? '').includes('@')
  })
  if (userinfo)
    return 'content appears to contain URL userinfo'
  const lines = content.split('\n')
  for (const [number, raw] of lines.entries()) {
    const line = raw.trim().toLowerCase()
    const index = line.search(/[=:]/)
    if (index < 0)
      continue
    const key = line.slice(0, index)
    const value = line.slice(index + 1).trim()
    if (ASSIGNMENT_SECRET_MARKERS.some(m => key.includes(m)) && value !== '' && !PLACEHOLDER_VALUES.includes(value))
      return `line ${number + 1} appears to assign a credential`
  }
  return null
}

/** Plain scalars YAML resolves to something other than a string. */
const YAML_RESERVED = /^(?:true|false|yes|no|on|off|null|~|[-+]?(?:\d[\d_]*(?:\.\d*)?|\.\d+)(?:e[-+]?\d+)?|0x[\da-f]+|0o[0-7]+|[-+]?\.inf|\.nan)$/i

export type Frontmatter =
  | { ok: true, name: string, description: string }
  | { ok: false, error: string }

function unquote(raw: string): string | null {
  const value = raw.trim()
  if (value.startsWith('"')) {
    try {
      const parsed = JSON.parse(value)
      return typeof parsed === 'string' ? parsed : null
    }
    catch {
      return null
    }
  }
  if (value.startsWith('\'')) {
    if (value.length < 2 || !value.endsWith('\''))
      return null
    return value.slice(1, -1).replace(/''/g, '\'')
  }
  // A plain scalar: a trailing ` #` starts a comment.
  const comment = value.search(/\s#/)
  const plain = (comment >= 0 ? value.slice(0, comment) : value).trim()
  // YAML reads `true`, `null`, or `123` as non-strings, which the
  // controller refuses; those must be quoted.
  if (plain === '' || /^[|>&*!%@`[{]/.test(plain) || /:\s/.test(plain) || YAML_RESERVED.test(plain))
    return null
  return plain
}

/**
 * Reads `name` and `description` from SKILL.md's YAML frontmatter. The
 * console needs both as single-line strings so it can fill the catalog
 * fields from them; richer YAML is left to the controller, which reports
 * anything this check cannot see.
 */
export function parseFrontmatter(markdown: string): Frontmatter {
  const lines = markdown.split(/\r?\n/)
  if (lines[0] !== '---')
    return { ok: false, error: 'SKILL.md must begin with a --- frontmatter line' }
  const end = lines.indexOf('---', 1)
  if (end < 0)
    return { ok: false, error: 'SKILL.md frontmatter is not terminated by ---' }
  const fields = new Map<string, string>()
  for (let i = 1; i < end; i++) {
    const line = lines[i]!
    if (line.trim() === '' || line.trimStart().startsWith('#') || /^\s/.test(line))
      continue
    const match = /^([^:#\s][^:]*):(?:\s(.*))?$/.exec(line)
    if (!match)
      return { ok: false, error: `frontmatter line ${i + 1} is not a "key: value" pair` }
    const key = match[1]!.trim()
    if (fields.has(key))
      return { ok: false, error: `frontmatter key "${key}" appears twice` }
    fields.set(key, match[2] ?? '')
  }
  const read = (key: 'name' | 'description') => {
    if (!fields.has(key))
      return { error: `frontmatter needs a ${key}` }
    const value = unquote(fields.get(key)!)
    return value === null ? { error: `frontmatter ${key} must be a single-line string (quote values YAML would read as a number, boolean, or null)` } : { value }
  }
  const name = read('name')
  if ('error' in name)
    return { ok: false, error: name.error! }
  const description = read('description')
  if ('error' in description)
    return { ok: false, error: description.error! }
  return { ok: true, name: name.value, description: description.value }
}

export interface EditableFile {
  path: string
  content: string
}

/**
 * Every problem the console can see in an authored draft, in the order the
 * controller would report them. An empty list means "send it".
 */
export function authoredErrors(files: EditableFile[]): string[] {
  const errors: string[] = []
  const skill = files.find(f => f.path === 'SKILL.md')
  if (!skill)
    errors.push('authored skills require SKILL.md at the root')
  else {
    const front = parseFrontmatter(skill.content)
    if (!front.ok)
      errors.push(front.error)
    else {
      const nameError = skillNameError(front.name)
      if (nameError)
        errors.push(nameError)
      if (front.description.trim() === '' || [...front.description].length > 1024)
        errors.push('description must contain 1..=1024 characters')
    }
  }
  if (files.length === 0 || files.length > MAX_CATALOG_FILES)
    errors.push(`authored skills must contain 1..=${MAX_CATALOG_FILES} files`)
  const seen = new Set<string>()
  let total = 0
  for (const file of files) {
    const pathError = relativePathError(file.path)
    if (pathError)
      errors.push(pathError)
    if (seen.has(file.path))
      errors.push(`duplicate file path "${file.path}"`)
    seen.add(file.path)
    total += new TextEncoder().encode(file.path + file.content).length
    const secret = secretShapedError(file.content)
    if (secret)
      errors.push(`${file.path}: ${secret}`)
  }
  if (total > MAX_CATALOG_BYTES)
    errors.push(`authored content exceeds ${MAX_CATALOG_BYTES} bytes`)
  return errors
}

/** The request content for an authored draft; name and description come from SKILL.md. */
export function authoredContent(files: EditableFile[]): CatalogContentDto | null {
  const skill = files.find(f => f.path === 'SKILL.md')
  const front = skill ? parseFrontmatter(skill.content) : null
  if (!front?.ok)
    return null
  return { name: front.name, description: front.description, files: files.map(f => ({ ...f })), source: { kind: 'authored' } }
}

export interface ReferencedInput {
  name: string
  description: string
  reference: string
  subpath: string
  revision: string
}

/** fleet-core `validate_referenced_source`, plus name and description. */
export function referencedErrors(input: ReferencedInput): string[] {
  const errors: string[] = []
  const nameError = skillNameError(input.name)
  if (nameError)
    errors.push(nameError)
  if (input.description.trim() === '' || [...input.description].length > 1024)
    errors.push('description must contain 1..=1024 characters')
  const reference = input.reference.trim()
  if (reference === '' || reference.length > 2048 || !/^[\x20-\x7e]+$/.test(reference) || reference.startsWith('-'))
    errors.push('the reference must be a non-empty ASCII reference or URL')
  const secret = secretShapedError(input.reference) ?? secretShapedError(input.description)
  if (secret)
    errors.push(secret)
  const subpath = input.subpath.trim()
  const revision = input.revision.trim()
  if ((subpath === '') !== (revision === ''))
    errors.push('a Git subpath and revision are pinned together; Fleet does not guess a default branch')
  // eslint-disable-next-line no-control-regex
  if (revision.length > 256 || /[\x00-\x1f\x7f]/.test(revision))
    errors.push('the revision must be 1..=256 printable characters')
  if (subpath) {
    const pathError = relativePathError(subpath)
    if (pathError)
      errors.push(pathError)
    // fleet-core `validate_github_pin`: each component is a safe URL segment.
    const safe = (part: string) => part !== '' && part !== '.' && part !== '..' && /^[A-Za-z0-9._-]+$/.test(part)
    const repository = reference.startsWith('https://github.com/')
      ? reference.slice('https://github.com/'.length).replace(/\.git$/, '').replace(/\/+$/, '')
      : null
    if (repository === null)
      errors.push('separate subpath and revision pins need an HTTPS GitHub repository URL')
    else if (repository.split('/').length !== 2 || !repository.split('/').every(safe) || !/^[A-Za-z0-9._-]+$/.test(revision) || !subpath.split('/').every(safe))
      errors.push('the GitHub repository, subpath, or revision contains unsupported URL path characters')
  }
  return errors
}

export function referencedContent(input: ReferencedInput): CatalogContentDto {
  const subpath = input.subpath.trim()
  const revision = input.revision.trim()
  return {
    name: input.name.trim(),
    description: input.description,
    files: [],
    source: { kind: 'referenced', reference: input.reference.trim(), subpath: subpath || null, revision: revision || null },
  }
}

export function sourceLabel(content: CatalogContentDto): string {
  const source = content.source
  if (source.kind === 'authored')
    return 'fleet-authored'
  const pin = source.revision ? `@${source.revision.slice(0, 12)}` : ''
  return `${source.reference}${source.subpath ? `/${source.subpath}` : ''}${pin}`
}

export function shortDigest(digest: string): string {
  return digest.slice(0, 12)
}

/** Published versions, newest first. */
export function newestFirst(versions: CatalogVersionDto[]): CatalogVersionDto[] {
  return [...versions].sort((a, b) => b.publishedAt - a.publishedAt || b.id.localeCompare(a.id))
}

/** Stable JSON for comparing a draft's content with a published version's. */
function canonical(content: CatalogContentDto): string {
  const files = [...content.files].sort((a, b) => a.path.localeCompare(b.path))
  return JSON.stringify({ ...content, files })
}

export function sameContent(a: CatalogContentDto, b: CatalogContentDto): boolean {
  return canonical(a) === canonical(b)
}

// ---------------------------------------------------------------------------
// Diff

export type DiffOp = ' ' | '+' | '-'

export interface DiffLine {
  op: DiffOp
  text: string
}

/** Past this many cells the LCS table is skipped and the whole file is replaced. */
const MAX_DIFF_CELLS = 4_000_000

/** A line diff from `before` to `after` (longest common subsequence). */
export function lineDiff(before: string, after: string): DiffLine[] {
  const a = before === '' ? [] : before.split('\n')
  const b = after === '' ? [] : after.split('\n')
  if ((a.length + 1) * (b.length + 1) > MAX_DIFF_CELLS)
    return [...a.map(text => ({ op: '-' as const, text })), ...b.map(text => ({ op: '+' as const, text }))]
  const width = b.length + 1
  const table = new Uint32Array((a.length + 1) * width)
  for (let i = a.length - 1; i >= 0; i--) {
    for (let j = b.length - 1; j >= 0; j--) {
      table[i * width + j] = a[i] === b[j]
        ? table[(i + 1) * width + j + 1]! + 1
        : Math.max(table[(i + 1) * width + j]!, table[i * width + j + 1]!)
    }
  }
  const out: DiffLine[] = []
  let i = 0
  let j = 0
  while (i < a.length && j < b.length) {
    if (a[i] === b[j]) {
      out.push({ op: ' ', text: a[i]! })
      i++
      j++
    }
    else if (table[(i + 1) * width + j]! >= table[i * width + j + 1]!) {
      out.push({ op: '-', text: a[i++]! })
    }
    else {
      out.push({ op: '+', text: b[j++]! })
    }
  }
  while (i < a.length) out.push({ op: '-', text: a[i++]! })
  while (j < b.length) out.push({ op: '+', text: b[j++]! })
  return out
}

export interface FileDiff {
  path: string
  change: 'added' | 'removed' | 'changed' | 'unchanged'
  lines: DiffLine[]
}

/** Per-file diffs between two catalog contents, metadata first. */
export function contentDiff(before: CatalogContentDto, after: CatalogContentDto): FileDiff[] {
  const out: FileDiff[] = []
  const meta = (c: CatalogContentDto) => [
    `name: ${c.name}`,
    `description: ${c.description}`,
    `source: ${c.source.kind === 'authored' ? 'authored' : sourceLabel(c)}`,
  ].join('\n')
  const metaBefore = meta(before)
  const metaAfter = meta(after)
  if (metaBefore !== metaAfter)
    out.push({ path: '(catalog metadata)', change: 'changed', lines: lineDiff(metaBefore, metaAfter) })
  const old = new Map(before.files.map(f => [f.path, f.content]))
  const now = new Map(after.files.map(f => [f.path, f.content]))
  const paths = [...new Set([...old.keys(), ...now.keys()])].sort()
  for (const path of paths) {
    const a = old.get(path)
    const b = now.get(path)
    if (a === undefined)
      out.push({ path, change: 'added', lines: lineDiff('', b!) })
    else if (b === undefined)
      out.push({ path, change: 'removed', lines: lineDiff(a, '') })
    else
      out.push({ path, change: a === b ? 'unchanged' : 'changed', lines: a === b ? [] : lineDiff(a, b) })
  }
  return out
}

// ---------------------------------------------------------------------------
// Assignments (`SkillPreset` desired-state resources in Fleet Git)

export type AssignmentScope =
  | { type: 'all' }
  | { type: 'group' | 'tag' | 'machine', value: string }

export interface Assignment {
  name: string
  skillId: string
  catalogId: string | null
  catalogVersionId: string | null
  scope: AssignmentScope
  deployTo: string[]
  denyAgents: string[]
}

const RESOURCE_NAME = /^[a-z0-9]+(?:-[a-z0-9]+)*$/

/** `schemas/generated/desired-resource.schema.json` for `SkillPreset`. */
export function assignmentErrors(assignment: Assignment): string[] {
  const errors: string[] = []
  if (!RESOURCE_NAME.test(assignment.name) || assignment.name.length > 63)
    errors.push('the resource name must be 1..=63 lowercase letters or digits separated by single hyphens')
  // The catalog accepts 64-character names, but the desired-state schema
  // caps `skillId` at 63, so such a skill cannot be assigned yet.
  if (assignment.skillId === '' || assignment.skillId.length > 63)
    errors.push('the desired-state schema limits skill ids to 1..=63 characters, so this skill cannot be assigned')
  if (assignment.deployTo.length === 0 || assignment.deployTo.length > 16)
    errors.push('pick 1..=16 agents to deploy to')
  if (assignment.denyAgents.length > 16)
    errors.push('at most 16 agents can be denied')
  if (assignment.scope.type !== 'all' && assignment.scope.value.trim() === '')
    errors.push(`the ${assignment.scope.type} scope needs a value`)
  if ((assignment.catalogVersionId?.length ?? 0) > 128)
    errors.push('the catalog version id is longer than 128 characters')
  return errors
}

/** A UUIDv7, as desired-resource `metadata.id` requires. */
export function uuidv7(now: number = Date.now(), random: Uint8Array = crypto.getRandomValues(new Uint8Array(10))): string {
  const time = now.toString(16).padStart(12, '0').slice(-12)
  const hex = [...random].map(b => b.toString(16).padStart(2, '0')).join('')
  const variant = ((random[2]! & 0x3f) | 0x80).toString(16).padStart(2, '0')
  return `${time.slice(0, 8)}-${time.slice(8, 12)}-7${hex.slice(0, 3)}-${variant}${hex.slice(6, 8)}-${hex.slice(8, 20)}`
}

const PLAIN_YAML = /^[A-Za-z0-9_][\w.@/-]*$/

/** A YAML scalar: plain when unambiguous, JSON-quoted (valid YAML) otherwise. */
export function yamlScalar(value: string): string {
  return PLAIN_YAML.test(value) && !YAML_RESERVED.test(value) ? value : JSON.stringify(value)
}

/** The `SkillPreset` resource to commit into Fleet Git. */
export function assignmentYaml(assignment: Assignment, id: string): string {
  const lines = [
    'apiVersion: fleet.frogbyte.io/v1alpha1',
    'kind: SkillPreset',
    'metadata:',
    `  id: ${id}`,
    `  name: ${yamlScalar(assignment.name)}`,
    'spec:',
    `  skillId: ${yamlScalar(assignment.skillId)}`,
  ]
  if (assignment.catalogId)
    lines.push(`  catalogId: ${yamlScalar(assignment.catalogId)}`)
  if (assignment.catalogVersionId)
    lines.push(`  catalogVersionId: ${yamlScalar(assignment.catalogVersionId)}`)
  lines.push('  scope:', `    type: ${assignment.scope.type}`)
  if (assignment.scope.type !== 'all')
    lines.push(`    value: ${yamlScalar(assignment.scope.value.trim())}`)
  lines.push('  deployTo:', ...assignment.deployTo.map(agent => `    - ${yamlScalar(agent)}`))
  if (assignment.denyAgents.length > 0)
    lines.push('  denyAgents:', ...assignment.denyAgents.map(agent => `    - ${yamlScalar(agent)}`))
  return `${lines.join('\n')}\n`
}
