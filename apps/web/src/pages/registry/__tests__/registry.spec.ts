import { describe, expect, it } from 'vitest'

import {
  cellValue,
  columnDefs,
  entryLinks,
  fieldDefs,
  formatDate,
  formatMoney,
  parseRemote,
  renderedText,
  renderValue,
  setCommand,
  sourceLocation,
  targetLink,
  undeclaredFields,
} from '../registry'

const spec = {
  displayName: 'Domain',
  key: 'fqdn',
  fields: {
    registrar: { type: 'string' },
    notes: { type: 'text' },
    fqdn: { type: 'hostname', required: true, description: 'The domain' },
    expires: { type: 'date' },
    autoRenew: { type: 'boolean' },
    nameservers: { type: 'list', items: 'hostname' },
    cost: { type: 'money' },
    url: { type: 'url' },
    extra1: { type: 'string' },
    extra2: { type: 'string' },
  },
}

describe('fieldDefs and columnDefs', () => {
  it('puts the key first and orders the rest by name', () => {
    const defs = fieldDefs(spec, 'fqdn')
    expect(defs[0]).toMatchObject({ name: 'fqdn', isKey: true, required: true, type: 'hostname' })
    expect(defs.slice(1).map(d => d.name)).toEqual([...defs.slice(1).map(d => d.name)].sort())
    expect(defs.find(d => d.name === 'nameservers')).toMatchObject({ type: 'list', items: 'hostname' })
  })

  it('tolerates a missing or malformed spec', () => {
    expect(fieldDefs(null, 'k').map(d => d.name)).toEqual(['k'])
    expect(fieldDefs({ fields: { a: 7, b: { type: 'weird' } } }, 'a').map(d => d.type)).toEqual(['string', 'string'])
  })

  it('keeps narrow fields as columns and leaves long text and lists to the drawer first', () => {
    const columns = columnDefs(fieldDefs(spec, 'fqdn'))
    expect(columns).toHaveLength(5)
    expect(columns[0]!.name).toBe('fqdn')
    expect(columns.map(c => c.type)).not.toContain('text')
    expect(columns.map(c => c.type)).not.toContain('list')
  })
})

describe('renderValue', () => {
  const NOW = Date.UTC(2026, 9, 16)

  it('renders each value type', () => {
    expect(renderValue({ type: 'boolean', items: null }, true)).toEqual({ kind: 'bool', value: true })
    expect(renderValue({ type: 'money', items: null }, '19.00 EUR')).toEqual({ kind: 'text', text: expect.stringContaining('19.00') })
    expect(renderedText(renderValue({ type: 'date', items: null }, '2026-11-15', NOW))).toBe('2026-11-15 (in 30 days)')
    expect(renderValue({ type: 'url', items: null }, 'https://example.org/x')).toMatchObject({ kind: 'link', href: 'https://example.org/x' })
    expect(renderedText(renderValue({ type: 'list', items: 'hostname' }, ['a.example.org', 'b.example.org']))).toBe('a.example.org, b.example.org')
    expect(renderValue({ type: 'string', items: null }, undefined)).toEqual({ kind: 'empty' })
    expect(renderValue({ type: 'list', items: 'string' }, [])).toEqual({ kind: 'empty' })
  })

  it('never turns a non-web url into a link', () => {
    expect(renderValue({ type: 'url', items: null }, 'javascript:alert(1)')).toEqual({ kind: 'text', text: 'javascript:alert(1)', mono: true })
  })

  it('formats dates and money without guessing', () => {
    expect(formatDate('2026-10-15', Date.UTC(2026, 9, 16))).toBe('2026-10-15 (1 day ago)')
    expect(formatDate('2026-10-16', Date.UTC(2026, 9, 16))).toBe('2026-10-16 (today)')
    expect(formatDate('soon')).toBe('soon')
    expect(formatMoney('not money')).toBe('not money')
    expect(formatMoney('5 ZZZZ')).toBe('5 ZZZZ')
  })
})

describe('key column and email', () => {
  it('adds a synthetic key column when the type does not declare the key', () => {
    const defs = fieldDefs({ fields: { plan: { type: 'string' } } }, 'slug')
    expect(defs[0]).toMatchObject({ name: 'slug', isKey: true, synthetic: true })
    expect(cellValue(defs[0]!, { key: 'aptabase', fields: {} })).toBe('aptabase')
  })

  it('links only plausible emails', () => {
    expect(renderValue({ type: 'email', items: null }, 'ops@example.org')).toMatchObject({ kind: 'link' })
    expect(renderValue({ type: 'email', items: null }, 'a@b.c?subject=x&bcc=y@z.d')).toMatchObject({ kind: 'text' })
    expect(renderValue({ type: 'email', items: null }, 'not an email')).toMatchObject({ kind: 'text' })
  })
})

describe('entry helpers', () => {
  it('reports values the type does not declare', () => {
    const defs = fieldDefs(spec, 'fqdn')
    expect(undeclaredFields({ fqdn: 'a', stray: 1 }, defs)).toEqual(['stray'])
  })

  it('keeps unsafe links as text', () => {
    expect(entryLinks([{ label: 'DNS', url: 'https://dash.example.org' }, { label: 'x', url: 'ftp://h' }, 5])).toEqual([
      { label: 'DNS', url: 'https://dash.example.org', href: 'https://dash.example.org/' },
      { label: 'x', url: 'ftp://h', href: null },
    ])
  })
})

describe('targetLink', () => {
  const machines = new Map([['build-1', 'id-9']])

  it('links entries and known machines; unresolved targets stay text', () => {
    expect(targetLink({ class: 'registry', reference: 'service/aptabase' }, machines).to).toEqual({ path: '/registry', query: { type: 'service', entry: 'aptabase' } })
    expect(targetLink({ class: 'machine', reference: 'build-1' }, machines).to).toEqual({ path: '/fleet/machines/id-9' })
    expect(targetLink({ class: 'machine', reference: 'gone' }, machines).to).toBeNull()
    expect(targetLink({ class: 'project', reference: 'site' }, machines).to).toBeNull()
  })

  it('leaves targets without a page as text', () => {
    expect(targetLink({ class: 'coolify', reference: 'abc' }, machines).to).toBeNull()
    expect(targetLink({ class: 'registry', reference: 'nokey' }, machines).to).toBeNull()
  })
})

describe('sourceLocation', () => {
  const sha = 'a'.repeat(40)

  it('maps GitHub and GitLab remotes to file URLs', () => {
    expect(sourceLocation('https://github.com/acme/fleet.git', sha, 'fleet/registry/domain/example.org.yaml'))
      .toEqual({ kind: 'web', url: `https://github.com/acme/fleet/blob/${sha}/fleet/registry/domain/example.org.yaml` })
    expect(sourceLocation('git@github.com:acme/fleet.git', sha, 'a/b.yaml'))
      .toEqual({ kind: 'web', url: `https://github.com/acme/fleet/blob/${sha}/a/b.yaml` })
    expect(sourceLocation('https://gitlab.com/acme/sub/fleet', sha, 'a.yaml'))
      .toEqual({ kind: 'web', url: `https://gitlab.com/acme/sub/fleet/-/blob/${sha}/a.yaml` })
  })

  it('never carries credentials from the remote', () => {
    const result = sourceLocation('https://user:hunter2@github.com/acme/fleet.git', sha, 'a.yaml')
    expect(JSON.stringify(result)).not.toContain('hunter2')
    expect(JSON.stringify(result)).not.toContain('user')
    expect(parseRemote('https://tok@github.com/a/b')).toEqual({ host: 'github.com', repo: 'a/b' })
    expect(parseRemote('https://git.example:8443/a/b')).toEqual({ host: 'git.example:8443', repo: 'a/b' })
    expect(parseRemote('ssh://git@git.example:2222/a/b')).toEqual({ host: 'git.example', repo: 'a/b' })
  })

  it('falls back to the path for unknown hosts, missing data, and unsafe paths', () => {
    expect(sourceLocation('https://git.internal.example/acme/fleet', sha, 'a.yaml')).toEqual({ kind: 'path', path: 'a.yaml' })
    expect(sourceLocation(null, sha, 'a.yaml')).toEqual({ kind: 'path', path: 'a.yaml' })
    expect(sourceLocation('https://github.com/acme/fleet', sha, null)).toEqual({ kind: 'path', path: null })
    expect(sourceLocation('https://github.com/acme/fleet', sha, '../etc/passwd')).toEqual({ kind: 'path', path: null })
    expect(sourceLocation('https://github.com/acme/fleet', 'HEAD', 'a.yaml')).toEqual({ kind: 'path', path: 'a.yaml' })
    expect(sourceLocation('/srv/git/fleet.git', sha, 'a.yaml')).toEqual({ kind: 'path', path: 'a.yaml' })
  })

  it('offers the set command for the fallback', () => {
    expect(setCommand('domain', 'example.org', 'registrar')).toBe('fleetctl registry set domain/example.org --field registrar=<value>')
  })
})
