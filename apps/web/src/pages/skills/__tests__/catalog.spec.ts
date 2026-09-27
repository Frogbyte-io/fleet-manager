import { describe, expect, it } from 'vitest'

import type { CatalogContentDto } from '@frogbyte-io/fleet-api-client'

import {
  assignmentErrors,
  assignmentYaml,
  authoredContent,
  authoredErrors,
  contentDiff,
  lineDiff,
  parseFrontmatter,
  referencedErrors,
  secretShapedError,
  uuidv7,
  yamlScalar,
  type Assignment,
} from '../catalog'

const SKILL = `---
name: fleet
description: "Operate Fleet: use fleetctl --output json"
license: MIT
metadata:
  owner: platform
---

# Fleet
`

describe('parseFrontmatter', () => {
  it('reads plain and quoted single-line values and ignores nested keys', () => {
    expect(parseFrontmatter(SKILL)).toEqual({ ok: true, name: 'fleet', description: 'Operate Fleet: use fleetctl --output json' })
    expect(parseFrontmatter('---\nname: \'it\'\'s\'\ndescription: plain text # comment\n---\n')).toEqual({ ok: true, name: 'it\'s', description: 'plain text' })
  })

  it('reports what the console cannot accept', () => {
    expect(parseFrontmatter('# no frontmatter')).toMatchObject({ ok: false, error: expect.stringContaining('must begin') })
    expect(parseFrontmatter('---\nname: a\n')).toMatchObject({ ok: false, error: expect.stringContaining('not terminated') })
    expect(parseFrontmatter('---\nname: a\nname: b\ndescription: d\n---')).toMatchObject({ ok: false, error: expect.stringContaining('twice') })
    expect(parseFrontmatter('---\nname: a\n---')).toMatchObject({ ok: false, error: 'frontmatter needs a description' })
    expect(parseFrontmatter('---\nname: a\ndescription: >\n  folded\n---')).toMatchObject({ ok: false, error: expect.stringContaining('single-line') })
    // YAML would read these as a number and a boolean, which the controller refuses.
    expect(parseFrontmatter('---\nname: 123\ndescription: d\n---')).toMatchObject({ ok: false })
    expect(parseFrontmatter('---\nname: a\ndescription: true\n---')).toMatchObject({ ok: false })
    expect(parseFrontmatter('---\nname: a\ndescription: "true"\n---')).toEqual({ ok: true, name: 'a', description: 'true' })
  })
})

describe('authored drafts', () => {
  it('accepts a valid skill and builds content from its frontmatter', () => {
    const files = [{ path: 'SKILL.md', content: SKILL }, { path: 'references/cli.md', content: 'x' }]
    expect(authoredErrors(files)).toEqual([])
    expect(authoredContent(files)).toMatchObject({ name: 'fleet', description: 'Operate Fleet: use fleetctl --output json', source: { kind: 'authored' } })
  })

  it('mirrors the controller rules for names, paths, and secrets', () => {
    const bad = [
      { path: 'SKILL.md', content: '---\nname: Bad--Name\ndescription: d\n---\n' },
      { path: '../escape.md', content: '' },
      { path: 'notes.md', content: 'api_token: hunter2' },
    ]
    const errors = authoredErrors(bad)
    expect(errors).toContain('name must use 1..=64 lowercase letters, digits, and single hyphens')
    expect(errors.some(e => e.includes('stay inside'))).toBe(true)
    expect(errors.some(e => e.startsWith('notes.md: line 1 appears to assign a credential'))).toBe(true)
    expect(authoredErrors([])).toContain('authored skills require SKILL.md at the root')
  })

  it('detects the controller credential shapes but allows placeholders', () => {
    expect(secretShapedError('ghp_abc')).not.toBeNull()
    expect(secretShapedError('see https://x.test/a?token=abc')).not.toBeNull()
    expect(secretShapedError('clone https://user@host/repo')).not.toBeNull()
    expect(secretShapedError('token: changeme')).toBeNull()
    expect(secretShapedError('Use fleetctl to list machines.')).toBeNull()
  })
})

describe('referenced drafts', () => {
  const base = { name: 'rust-review', description: 'Review Rust', reference: 'https://github.com/org/skills', subpath: '', revision: '' }

  it('needs subpath and revision together, on a GitHub URL', () => {
    expect(referencedErrors(base)).toEqual([])
    expect(referencedErrors({ ...base, subpath: 'rust' })).toContain('a Git subpath and revision are pinned together; Fleet does not guess a default branch')
    expect(referencedErrors({ ...base, reference: 'https://gitlab.com/org/skills', subpath: 'rust', revision: 'abc' }))
      .toContain('separate subpath and revision pins need an HTTPS GitHub repository URL')
    expect(referencedErrors({ ...base, subpath: 'rust', revision: 'abc!' }))
      .toContain('the GitHub repository, subpath, or revision contains unsupported URL path characters')
    expect(referencedErrors({ ...base, subpath: 'rust', revision: 'a'.repeat(257) }))
      .toContain('the revision must be 1..=256 printable characters')
    expect(referencedErrors({ ...base, subpath: 'rust', revision: '0123456789abcdef0123456789abcdef01234567' })).toEqual([])
  })
})

describe('lineDiff', () => {
  it('keeps common lines and marks changes', () => {
    expect(lineDiff('a\nb\nc', 'a\nx\nc')).toEqual([
      { op: ' ', text: 'a' },
      { op: '-', text: 'b' },
      { op: '+', text: 'x' },
      { op: ' ', text: 'c' },
    ])
    expect(lineDiff('', 'new')).toEqual([{ op: '+', text: 'new' }])
  })

  it('diffs catalog contents file by file', () => {
    const before: CatalogContentDto = { name: 'a', description: 'd', source: { kind: 'authored' }, files: [{ path: 'SKILL.md', content: 'one' }, { path: 'old.md', content: 'x' }] }
    const after: CatalogContentDto = { name: 'a', description: 'd2', source: { kind: 'authored' }, files: [{ path: 'SKILL.md', content: 'one' }, { path: 'new.md', content: 'y' }] }
    expect(contentDiff(before, after).map(f => [f.path, f.change])).toEqual([
      ['(catalog metadata)', 'changed'],
      ['SKILL.md', 'unchanged'],
      ['new.md', 'added'],
      ['old.md', 'removed'],
    ])
  })
})

describe('assignments', () => {
  const assignment: Assignment = {
    name: 'fleet-dev',
    skillId: 'fleet',
    catalogId: 'cat-1',
    catalogVersionId: 'cat-1@abcdef',
    scope: { type: 'group', value: 'dev' },
    deployTo: ['claude_code', 'codex'],
    denyAgents: [],
  }

  it('renders the SkillPreset resource', () => {
    expect(assignmentYaml(assignment, '01890f3e-9b4a-7cc2-98c3-d24e8f58a008')).toBe(`apiVersion: fleet.frogbyte.io/v1alpha1
kind: SkillPreset
metadata:
  id: 01890f3e-9b4a-7cc2-98c3-d24e8f58a008
  name: fleet-dev
spec:
  skillId: fleet
  catalogId: cat-1
  catalogVersionId: cat-1@abcdef
  scope:
    type: group
    value: dev
  deployTo:
    - claude_code
    - codex
`)
  })

  it('validates against the desired-resource schema', () => {
    expect(assignmentErrors(assignment)).toEqual([])
    expect(assignmentErrors({ ...assignment, name: 'Bad Name', deployTo: [], scope: { type: 'tag', value: ' ' } })).toEqual([
      'the resource name must be 1..=63 lowercase letters or digits separated by single hyphens',
      'pick 1..=16 agents to deploy to',
      'the tag scope needs a value',
    ])
  })

  it('quotes ambiguous YAML scalars', () => {
    expect(yamlScalar('dev')).toBe('dev')
    expect(yamlScalar('true')).toBe('"true"')
    expect(yamlScalar('123')).toBe('"123"')
    expect(yamlScalar('a: b')).toBe('"a: b"')
  })

  it('mints UUIDv7 metadata ids', () => {
    const id = uuidv7(0x0189_0f3e_9b4a, new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]))
    expect(id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/)
    expect(id.startsWith('01890f3e-9b4a-7')).toBe(true)
  })
})
