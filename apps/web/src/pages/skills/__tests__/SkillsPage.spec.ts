import { enableAutoUnmount, flushPromises, mount } from '@vue/test-utils'
import { QueryClient, VueQueryPlugin } from '@tanstack/vue-query'
import { createMemoryHistory, createRouter } from 'vue-router'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import type { CatalogDto, CatalogVersionDto, MachineDto, SkillsSnapshotDto } from '@frogbyte-io/fleet-api-client'

// The stub API: every generated client call the Skills console makes.
const getSkillsMatrix = vi.fn()
const listMachines = vi.fn()
const listSkillCatalog = vi.fn()
const listSkillCatalogVersions = vi.fn()
const createSkillCatalog = vi.fn()
const updateSkillCatalog = vi.fn()
const publishSkillCatalog = vi.fn()
const previewSkillCatalogRollout = vi.fn()
const startSkillCatalogRollout = vi.fn()
const getOperation = vi.fn()

vi.mock('@frogbyte-io/fleet-api-client', () => ({
  getSkillsMatrix: (...args: unknown[]) => getSkillsMatrix(...args),
  listMachines: (...args: unknown[]) => listMachines(...args),
  listSkillCatalog: (...args: unknown[]) => listSkillCatalog(...args),
  listSkillCatalogVersions: (...args: unknown[]) => listSkillCatalogVersions(...args),
  createSkillCatalog: (...args: unknown[]) => createSkillCatalog(...args),
  updateSkillCatalog: (...args: unknown[]) => updateSkillCatalog(...args),
  publishSkillCatalog: (...args: unknown[]) => publishSkillCatalog(...args),
  previewSkillCatalogRollout: (...args: unknown[]) => previewSkillCatalogRollout(...args),
  startSkillCatalogRollout: (...args: unknown[]) => startSkillCatalogRollout(...args),
  getOperation: (...args: unknown[]) => getOperation(...args),
  cancelOperation: vi.fn(),
}))

import SkillsPage from '../SkillsPage.vue'
import { routes } from '@/router'

class ResizeObserverStub {
  observe() {}
  unobserve() {}
  disconnect() {}
}
vi.stubGlobal('ResizeObserver', ResizeObserverStub)

function ok<T>(data: T, status = 200) {
  return { status, data, headers: new Headers() }
}

function page<T>(items: T[]) {
  return { items, page: { nextCursor: null, limit: 200 } }
}

function machine(id: string, name: string, overrides: Partial<MachineDto> = {}): MachineDto {
  return {
    id,
    name,
    description: '',
    machineStatus: 'connected',
    endpoints: [{ id: `${id}-ssh`, kind: 'ssh', reference: `dev@${name}:22` }],
    capabilities: [],
    groups: ['dev'],
    tags: [],
    lastObservation: null,
    lastSeenAt: null,
    createdAt: 0,
    updatedAt: 0,
    ...overrides,
  } as MachineDto
}

function snapshot(machineId: string, overrides: Partial<SkillsSnapshotDto> = {}): SkillsSnapshotDto {
  return {
    machineId,
    availability: 'available',
    cliVersion: '1.40.0',
    updateCheck: 'complete',
    observedAt: Date.now(),
    stale: false,
    data: {
      skills: [
        { id: 'fleet', name: 'fleet', enabled: true, presetIds: [], deployedTo: ['claude_code'], updateStatus: 'up_to_date' },
        { id: 'home-notes', name: 'home-notes', enabled: true, presetIds: [], deployedTo: [], updateStatus: 'update_available' },
      ],
      presets: [{ id: 'default', name: 'Default', skillCount: 2, active: true }],
      agents: [{ id: 'claude_code', name: 'Claude Code', installed: true, enabled: true }, { id: 'codex', name: 'Codex', installed: true, enabled: true }],
    },
    ...overrides,
  }
}

const SKILL_MD = `---
name: fleet
description: Operate Fleet through fleetctl --output json.
---

# Fleet
`

function entry(overrides: Partial<CatalogDto> = {}): CatalogDto {
  return {
    id: 'cat-fleet',
    content: { name: 'fleet', description: 'Operate Fleet through fleetctl --output json.', files: [{ path: 'SKILL.md', content: SKILL_MD }], source: { kind: 'authored' } },
    publishedFrom: null,
    createdAt: 0,
    updatedAt: 1,
    ...overrides,
  }
}

function version(digest: string, content: CatalogDto['content'], publishedAt: number): CatalogVersionDto {
  return { id: `cat-fleet@${digest}`, catalogId: 'cat-fleet', name: content.name, description: content.description, contentDigest: digest, content, publishedAt }
}

async function mountAt(path: string) {
  const router = createRouter({ history: createMemoryHistory(), routes })
  await router.push(path)
  await router.isReady()
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } })
  const wrapper = mount(SkillsPage, { global: { plugins: [[VueQueryPlugin, { queryClient }], router] }, attachTo: document.body })
  await flushPromises()
  await flushPromises()
  return { wrapper, router }
}

enableAutoUnmount(afterEach)

beforeEach(() => {
  document.body.innerHTML = ''
  for (const mock of [getSkillsMatrix, listMachines, listSkillCatalog, listSkillCatalogVersions, createSkillCatalog, updateSkillCatalog,
    publishSkillCatalog, previewSkillCatalogRollout, startSkillCatalogRollout, getOperation])
    mock.mockReset()
  listMachines.mockResolvedValue(ok(page([
    machine('m1', 'workstation'),
    machine('m2', 'rpi-kitchen'),
    machine('m3', 'laptop', { endpoints: [] }),
  ])))
  getSkillsMatrix.mockResolvedValue(ok(page([
    snapshot('m1'),
    snapshot('m2', { availability: 'absent', cliVersion: null, data: { skills: [], presets: [], agents: [] } }),
  ])))
  listSkillCatalog.mockResolvedValue(ok(page([entry()])))
  listSkillCatalogVersions.mockResolvedValue(ok(page([])))
  getOperation.mockImplementation(async (id: string) => ok({ data: { id, kind: 'skills.catalog-rollout', state: 'succeeded', resultJson: '{"outcome":{"verified":true}}' } }))
})

describe('fleet matrix', () => {
  it('shows each cell state and why empty columns are empty', async () => {
    const { wrapper } = await mountAt('/skills')
    const cell = (skill: string, m: string) => wrapper.get(`[data-testid="cell-${skill}-${m}"]`)
    expect(cell('fleet', 'm1').attributes('data-state')).toBe('deployed')
    expect(cell('fleet', 'm1').text()).toBe('CC')
    expect(cell('home-notes', 'm1').attributes('data-state')).toBe('library')
    expect(cell('home-notes', 'm1').find('.text-fc-info').exists()).toBe(true)
    expect(cell('fleet', 'm2').attributes('data-state')).toBe('no-cli')
    expect(wrapper.get('[data-testid="matrix-column-m2"]').text()).toContain('no CLI')
    expect(wrapper.get('[data-testid="matrix-column-m3"]').text()).toContain('not probed')
  })

  it('groups Fleet catalog skills apart from machine-local ones', async () => {
    const { wrapper } = await mountAt('/skills')
    const text = wrapper.get('[data-testid="skills-matrix"]').text()
    expect(text.indexOf('Fleet catalog')).toBeLessThan(text.indexOf('fleet catalog · on 1'))
    expect(text.indexOf('Machine-local')).toBeLessThan(text.indexOf('home-notes'))
  })

  it('filters by state', async () => {
    const { wrapper } = await mountAt('/skills')
    await wrapper.get('[data-testid="matrix-filter-state"]').setValue('update')
    expect(wrapper.find('[data-testid="matrix-row-fleet"]').exists()).toBe(false)
    expect(wrapper.find('[data-testid="matrix-row-home-notes"]').exists()).toBe(true)
  })

  it('says so when nothing has been probed', async () => {
    getSkillsMatrix.mockResolvedValue(ok(page([])))
    listSkillCatalog.mockResolvedValue(ok(page([])))
    const { wrapper } = await mountAt('/skills')
    expect(wrapper.get('[data-testid="matrix-no-rows"]').text()).toContain('No skills reported yet')
  })

  it('surfaces a failed load instead of an empty matrix', async () => {
    getSkillsMatrix.mockResolvedValue(ok({ code: 'forbidden', message: 'denied' }, 403))
    const { wrapper } = await mountAt('/skills')
    expect(wrapper.text()).toContain('Could not load skills matrix')
  })
})

describe('catalog: edit → publish → roll out', () => {
  it('validates frontmatter while typing and saves a new draft', async () => {
    createSkillCatalog.mockResolvedValue(ok({ data: entry({ id: 'cat-new', content: { ...entry().content, name: 'new-skill', description: 'New.' } }) }, 201))
    const { wrapper, router } = await mountAt('/skills?tab=catalog')
    await wrapper.get('[data-testid="new-authored"]').trigger('click')
    await flushPromises()
    const editor = wrapper.get('[data-testid="skill-md"]')
    await editor.setValue('---\nname: New Skill\ndescription: New.\n---\n')
    expect(wrapper.get('[data-testid="catalog-errors"]').text()).toContain('lowercase letters')
    expect(wrapper.get('[data-testid="catalog-save"]').attributes('disabled')).toBeDefined()

    await editor.setValue('---\nname: new-skill\ndescription: New.\n---\n# New\n')
    expect(wrapper.find('[data-testid="catalog-valid"]').exists()).toBe(true)
    listSkillCatalog.mockResolvedValue(ok(page([entry(), entry({ id: 'cat-new', content: { ...entry().content, name: 'new-skill', description: 'New.' } })])))
    await wrapper.get('[data-testid="catalog-save"]').trigger('click')
    await flushPromises()
    expect(createSkillCatalog).toHaveBeenCalledWith({
      content: { name: 'new-skill', description: 'New.', files: [{ path: 'SKILL.md', content: '---\nname: new-skill\ndescription: New.\n---\n# New\n' }], source: { kind: 'authored' } },
    })
    expect(router.currentRoute.value.query.entry).toBe('cat-new')
  })

  it('edits, publishes, diffs, previews the plan, and only then starts the rollout', async () => {
    const edited = SKILL_MD.replace('# Fleet', '# Fleet\n\nAlways pass --output json.')
    const v1 = version('1111111111111111aaaa', entry().content, 1000)
    updateSkillCatalog.mockImplementation(async (_id: string, body: { content: CatalogDto['content'] }) => {
      listSkillCatalog.mockResolvedValue(ok(page([entry({ content: body.content, updatedAt: 2 })])))
      return ok({ data: entry({ content: body.content, updatedAt: 2 }) })
    })
    listSkillCatalogVersions.mockResolvedValue(ok(page([v1])))
    const { wrapper } = await mountAt('/skills?tab=catalog&entry=cat-fleet')

    // Edit and save the draft.
    expect(wrapper.get('[data-testid="catalog-publish"]').attributes('disabled')).toBeDefined()
    await wrapper.get('[data-testid="skill-md"]').setValue(edited)
    await wrapper.get('[data-testid="catalog-save"]').trigger('click')
    await flushPromises()
    expect(updateSkillCatalog).toHaveBeenCalledWith('cat-fleet', expect.objectContaining({ content: expect.objectContaining({ name: 'fleet' }) }))

    // Publish: a new immutable version, then straight to rollout.
    const v2 = version('2222222222222222bbbb', { ...entry().content, files: [{ path: 'SKILL.md', content: edited }] }, 2000)
    publishSkillCatalog.mockImplementation(async () => {
      listSkillCatalogVersions.mockResolvedValue(ok(page([v1, v2])))
      return ok({ data: v2 }, 201)
    })
    await wrapper.get('[data-testid="catalog-publish"]').trigger('click')
    await flushPromises()
    expect(publishSkillCatalog).toHaveBeenCalledWith('cat-fleet')
    expect(wrapper.find('[data-testid="rollout-panel"]').exists()).toBe(true)
    expect(wrapper.get('[data-testid="rollout-version"]').element).toHaveProperty('value', v2.id)

    // Machines without a usable CLI or an SSH endpoint are skipped, not offered.
    expect(wrapper.get('[data-testid="rollout-machine-m2"]').attributes('disabled')).toBeDefined()
    expect(wrapper.get('[data-testid="rollout-machine-m3"]').attributes('disabled')).toBeDefined()

    await wrapper.get('[data-testid="rollout-machine-m1"]').setValue(true)
    await wrapper.get('[data-testid="rollout-agent-codex"]').trigger('click')
    expect(wrapper.get('[data-testid="rollout-start"]').attributes('disabled')).toBeDefined()

    previewSkillCatalogRollout.mockResolvedValue(ok({ data: {
      versionId: v2.id, contentDigest: v2.contentDigest, machineId: 'm1', agents: ['codex'], stagingPath: '~/.local/share/fleet/skills/fleet',
      steps: ['stage and verify authored files', 'install locally or update the pinned local source', 'deploy to the explicit agents', 'verify with skills show and skills status'],
    } }))
    await wrapper.get('[data-testid="rollout-preview"]').trigger('click')
    await flushPromises()
    const request = { versionId: v2.id, machineId: 'm1', endpointId: 'm1-ssh', auth: { type: 'agent' }, agents: ['codex'], timeoutSeconds: 300 }
    expect(previewSkillCatalogRollout).toHaveBeenCalledWith(request)
    expect(wrapper.get('[data-testid="plan-m1"]').text()).toContain('deploy to the explicit agents')

    // Changing the selection invalidates the preview.
    await wrapper.get('[data-testid="rollout-agent-claude_code"]').trigger('click')
    expect(wrapper.get('[data-testid="rollout-start"]').attributes('disabled')).toBeDefined()
    await wrapper.get('[data-testid="rollout-agent-claude_code"]').trigger('click')
    await wrapper.get('[data-testid="rollout-preview"]').trigger('click')
    await flushPromises()

    startSkillCatalogRollout.mockResolvedValue(ok({ data: { id: 'op-roll', kind: 'skills.catalog-rollout', state: 'queued' } }, 202))
    expect(wrapper.get('[data-testid="rollout-start"]').attributes('disabled')).toBeUndefined()
    await wrapper.get('[data-testid="rollout-start"]').trigger('click')
    await flushPromises()
    await flushPromises()
    expect(startSkillCatalogRollout).toHaveBeenCalledWith(request)
    expect(wrapper.get('[data-testid="rollout-operations"]').text()).toContain('succeeded')

    // Version history diffs the draft against the first version.
    await wrapper.get('[data-testid="editor-versions"]').trigger('click')
    await wrapper.get('[data-testid="diff-base"]').setValue(v1.id)
    expect(wrapper.get('[data-testid="version-diff"]').text()).toContain('+ Always pass --output json.')
  })

  it('shows a held-back update as data with the way out', async () => {
    const v1 = version('1111111111111111aaaa', entry().content, 1000)
    listSkillCatalogVersions.mockResolvedValue(ok(page([v1])))
    previewSkillCatalogRollout.mockResolvedValue(ok({ data: { versionId: v1.id, contentDigest: v1.contentDigest, machineId: 'm1', agents: ['codex'], stagingPath: null, steps: ['deploy'] } }))
    startSkillCatalogRollout.mockResolvedValue(ok({ data: { id: 'op-held', kind: 'skills.catalog-rollout', state: 'queued' } }, 202))
    getOperation.mockResolvedValue(ok({ data: {
      id: 'op-held', kind: 'skills.catalog-rollout', state: 'failed',
      errorJson: JSON.stringify({ reason: 'cli_failed', detail: 'held back', data: { held_back_removals: ['library: references/old.md'] } }),
    } }))
    const { wrapper } = await mountAt('/skills?tab=catalog&entry=cat-fleet')
    await wrapper.get('[data-testid="editor-rollout"]').trigger('click')
    await wrapper.get('[data-testid="rollout-machine-m1"]').setValue(true)
    await wrapper.get('[data-testid="rollout-agent-codex"]').trigger('click')
    await wrapper.get('[data-testid="rollout-preview"]').trigger('click')
    await flushPromises()
    await wrapper.get('[data-testid="rollout-start"]').trigger('click')
    await flushPromises()
    await flushPromises()
    const held = wrapper.get('[data-testid="outcome-held-back"]').text()
    expect(held).toContain('library: references/old.md')
    expect(held).toContain('not a failure to retry')
  })

  it('builds the SkillPreset assignment for Fleet Git', async () => {
    const v1 = version('1111111111111111aaaa', entry().content, 1000)
    listSkillCatalogVersions.mockResolvedValue(ok(page([v1])))
    const { wrapper } = await mountAt('/skills?tab=catalog&entry=cat-fleet')
    await wrapper.get('[data-testid="editor-assign"]').trigger('click')
    expect(wrapper.get('[data-testid="assignment-errors"]').text()).toContain('pick 1..=16 agents')
    await wrapper.get('[data-testid="assignment-scope"]').setValue('group')
    await wrapper.get('[data-testid="assignment-scope-value"]').setValue('dev')
    await wrapper.get('[data-testid="assignment-agent-claude_code"]').trigger('click')
    const yaml = wrapper.get('[data-testid="assignment-yaml"]').text()
    expect(yaml).toContain('kind: SkillPreset')
    expect(yaml).toContain(`catalogVersionId: ${v1.id}`)
    expect(yaml).toContain('type: group')
    expect(yaml).toContain('value: dev')
    expect(yaml).toContain('- claude_code')
  })
})

describe('presets and search', () => {
  it('lists presets for machines with a usable CLI', async () => {
    const { wrapper } = await mountAt('/skills?tab=presets')
    expect(wrapper.get('[data-testid="presets-m1"]').text()).toContain('Default')
    expect(wrapper.find('[data-testid="presets-m2"]').exists()).toBe(false)
  })

  it('states that search is not wired into the controller', async () => {
    const { wrapper } = await mountAt('/skills?tab=search')
    expect(wrapper.get('[data-testid="search-gap"]').text()).toContain('no skills search endpoint')
  })
})
