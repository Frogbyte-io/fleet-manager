import { enableAutoUnmount, flushPromises, mount } from '@vue/test-utils'
import { QueryClient, VueQueryPlugin } from '@tanstack/vue-query'
import { createMemoryHistory, createRouter } from 'vue-router'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import type { LabTemplateDto, LeaseDto, OperationDto, RecipeDto, RecipeVersionDto } from '@frogbyte-io/fleet-api-client'

// The stub API: every generated client call the Images page makes.
const listImageRecipes = vi.fn()
const listImageRecipeVersions = vi.fn()
const listLabTemplates = vi.fn()
const listLabLeases = vi.fn()
const listOperations = vi.fn()
const createImageRecipe = vi.fn()
const updateImageRecipe = vi.fn()
const publishImageRecipe = vi.fn()
const startImageBuild = vi.fn()
const promoteImageVersion = vi.fn()
const getOperation = vi.fn()

vi.mock('@frogbyte-io/fleet-api-client', () => ({
  listImageRecipes: (...args: unknown[]) => listImageRecipes(...args),
  listImageRecipeVersions: (...args: unknown[]) => listImageRecipeVersions(...args),
  listLabTemplates: (...args: unknown[]) => listLabTemplates(...args),
  listLabLeases: (...args: unknown[]) => listLabLeases(...args),
  listOperations: (...args: unknown[]) => listOperations(...args),
  createImageRecipe: (...args: unknown[]) => createImageRecipe(...args),
  updateImageRecipe: (...args: unknown[]) => updateImageRecipe(...args),
  publishImageRecipe: (...args: unknown[]) => publishImageRecipe(...args),
  startImageBuild: (...args: unknown[]) => startImageBuild(...args),
  promoteImageVersion: (...args: unknown[]) => promoteImageVersion(...args),
  getOperation: (...args: unknown[]) => getOperation(...args),
  cancelOperation: vi.fn(),
}))

import ImagesPage from '../ImagesPage.vue'
import { routes } from '@/router'

function ok<T>(data: T, status = 200) {
  return { status, data, headers: new Headers() }
}
function page<T>(items: T[]) {
  return { items, page: { nextCursor: null, limit: 200 } }
}

const CONTENT = JSON.stringify({
  builders: [{ type: 'proxmox-clone', node: 'pve-01', clone_vm: 'ubuntu-cloud', cores: 2, memory: 4096, x_keep: { a: 1 } }],
  provisioners: [{ type: 'shell', inline: ['true'] }],
}, null, 2)

function recipe(overrides: Partial<RecipeDto> = {}): RecipeDto {
  return { id: 'r1', name: 'ubuntu-24-dev', description: '', node: 'pve-01', storagePool: 'local-lvm', source: 'clone', content: CONTENT, publishedFrom: null, createdAt: 0, updatedAt: 1, ...overrides }
}

function version(id: string, publishedAt: number, overrides: Partial<RecipeVersionDto> = {}): RecipeVersionDto {
  return {
    id, recipeId: 'r1', name: 'ubuntu-24-dev', description: '', contentDigest: `${id.split('@')[1]}${'0'.repeat(60)}`, content: CONTENT,
    source: 'clone', node: 'pve-01', storagePool: 'local-lvm', publishedAt, promotedAt: null, promotedBy: null, structured: null, ...overrides,
  }
}

function template(overrides: Partial<LabTemplateDto> = {}): LabTemplateDto {
  return {
    id: 't1', name: 'ubuntu-dev', description: '', imageVersionId: 'r1@aaaa', cores: 2, memoryMib: 4096, diskGib: 40, bootstrapProjectId: null,
    readinessProbe: 'guest_agent', readinessCommand: null, readinessDeadlineSeconds: 600, ttlSeconds: 7200, cleanup: 'destroy', publishedFrom: 't1@1111', createdAt: 0, updatedAt: 0, ...overrides,
  } as LabTemplateDto
}

function lease(overrides: Partial<LeaseDto> = {}): LeaseDto {
  return { id: 'lease-1', templateVersionId: 't1@1111', owner: 'me', purpose: 'debug', projectId: null, state: 'ready', cleanup: 'destroy', cleanupAttempts: 0, cleanupNextAt: null, ttlSeconds: 3600, createdAt: 0, readyAt: 0, expiresAt: Date.now() + 3600e3, maxLifetimeAt: Date.now() + 86400e3, ...overrides } as LeaseDto
}

async function mountAt(path: string) {
  const router = createRouter({ history: createMemoryHistory(), routes })
  await router.push(path)
  await router.isReady()
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } })
  const wrapper = mount(ImagesPage, { global: { plugins: [[VueQueryPlugin, { queryClient }], router] } })
  await flushPromises()
  await flushPromises()
  return { wrapper, router, queryClient }
}

let operations: OperationDto[] = []

enableAutoUnmount(afterEach)

beforeEach(() => {
  sessionStorage.clear()
  for (const mock of [listImageRecipes, listImageRecipeVersions, listLabTemplates, listLabLeases, listOperations, createImageRecipe, updateImageRecipe, publishImageRecipe, startImageBuild, promoteImageVersion, getOperation])
    mock.mockReset()
  operations = []
  listImageRecipes.mockResolvedValue(ok(page([recipe()])))
  listImageRecipeVersions.mockResolvedValue(ok(page([version('r1@aaaa', 1)])))
  listLabTemplates.mockResolvedValue(ok(page([template()])))
  listLabLeases.mockResolvedValue(ok(page([lease()])))
  listOperations.mockImplementation(async () => ok(page(operations)))
  getOperation.mockImplementation(async (id: string) => ok({ data: operations.find(o => o.id === id) }))
})

describe('pipeline', () => {
  it('flags a template pinning a never-promoted version as stale', async () => {
    const { wrapper } = await mountAt('/images')
    expect(wrapper.get('[data-testid="template-t1"]').text()).toContain('stale pin')
    expect(wrapper.get('[data-testid="template-t1"]').text()).toContain('never promoted')
  })

  it('highlights the lineage of the selected environment', async () => {
    listImageRecipes.mockResolvedValue(ok(page([recipe(), recipe({ id: 'r2', name: 'debian' })])))
    listImageRecipeVersions.mockImplementation(async (id: string) => ok(page(id === 'r1' ? [version('r1@aaaa', 1)] : [{ ...version('r2@bbbb', 1), recipeId: 'r2', name: 'debian' }])))
    const { wrapper } = await mountAt('/images')
    await wrapper.get('[data-testid="lease-lease-1"]').trigger('click')
    await flushPromises()
    expect(wrapper.get('[data-testid="recipe-r1"]').classes()).toContain('border-fc-info/50')
    expect(wrapper.get('[data-testid="version-r1@aaaa"]').classes()).toContain('border-fc-info/50')
    expect(wrapper.get('[data-testid="recipe-r2"]').classes()).toContain('opacity-40')
  })
})

describe('e2e: edit → publish → build → promote', () => {
  it('runs the whole flow against the API', async () => {
    const { wrapper, router, queryClient } = await mountAt('/images?select=recipe:r1')

    // Structured edit: only `cores` changes in the raw content.
    await wrapper.get('[data-testid="field-cores"]').setValue('4')
    await wrapper.get('[data-testid="field-cores"]').trigger('change')
    const raw = (wrapper.get('[data-testid="raw-editor"]').element as HTMLTextAreaElement).value
    const parsed = JSON.parse(raw)
    expect(parsed.builders[0]).toEqual({ ...JSON.parse(CONTENT).builders[0], cores: 4 })
    expect(parsed.provisioners).toEqual(JSON.parse(CONTENT).provisioners)

    // Save the draft.
    updateImageRecipe.mockImplementation(async (_id: string, body: RecipeDto) => {
      const saved = recipe({ ...body, updatedAt: 2 })
      listImageRecipes.mockResolvedValue(ok(page([saved])))
      return ok({ data: saved })
    })
    expect(wrapper.get('[data-testid="recipe-publish"]').attributes('disabled')).toBeDefined()
    await wrapper.get('[data-testid="recipe-save"]').trigger('click')
    await flushPromises()
    expect(updateImageRecipe).toHaveBeenCalledWith('r1', expect.objectContaining({ node: 'pve-01', storagePool: 'local-lvm', source: 'clone', content: raw }))

    // Publish: the new version is selected.
    const v2 = version('r1@bbbb', 2, { content: raw })
    publishImageRecipe.mockImplementation(async () => {
      listImageRecipeVersions.mockResolvedValue(ok(page([version('r1@aaaa', 1), v2])))
      return ok({ data: v2 }, 201)
    })
    await wrapper.get('[data-testid="recipe-publish"]').trigger('click')
    await flushPromises()
    await flushPromises()
    expect(router.currentRoute.value.query.select).toBe('version:r1@bbbb')
    expect(wrapper.get('[data-testid="version-panel"]').text()).toContain('v2')
    expect(wrapper.get('[data-testid="promote"]').attributes('disabled')).toBeDefined()

    // Build with a secret variable reference.
    startImageBuild.mockImplementation(async () => {
      operations = [{ id: 'op-build', kind: 'image.build', state: 'running', createdAt: 10, progressMessage: 'building the image' } as OperationDto]
      return ok({ data: operations[0] }, 202)
    })
    await wrapper.findAll('button').find(b => b.text() === '+ Secret variable')!.trigger('click')
    await wrapper.get('input[aria-label="Packer variable name"]').setValue('pve_token')
    await wrapper.get('input[aria-label="Secret reference id"]').setValue('secret-ref-1')
    await wrapper.get('[data-testid="build"]').trigger('click')
    await flushPromises()
    expect(startImageBuild).toHaveBeenCalledWith({ versionId: 'r1@bbbb', timeoutSeconds: 14400, secretVars: [{ name: 'pve_token', reference: 'secret-ref-1' }] })
    expect(wrapper.get('[data-testid="version-r1@bbbb"]').text()).toContain('building')

    // The build succeeds with an artifact: the evidence appears and promotion unlocks.
    operations = [{ id: 'op-build', kind: 'image.build', state: 'succeeded', createdAt: 10, resultJson: JSON.stringify({ artifactId: '9001', recipeVersion: 'r1@bbbb', says: ['proxmox-clone: template 9001 created'] }) } as OperationDto]
    // The page polls while a build runs; refetch now instead of waiting for the timers.
    await queryClient.invalidateQueries({ queryKey: ['images', 'build-operations'] })
    await queryClient.invalidateQueries({ queryKey: ['operation', 'op-build'] })
    await flushPromises()
    expect(wrapper.get('[data-testid="promotion-evidence"]').text()).toContain('9001')
    expect(wrapper.get('[data-testid="promotion-evidence"]').text()).toContain('template 9001 created')

    promoteImageVersion.mockImplementation(async () => {
      const promoted = { ...v2, promotedAt: 20, promotedBy: 'me' }
      listImageRecipeVersions.mockResolvedValue(ok(page([version('r1@aaaa', 1), promoted])))
      return ok({ data: promoted })
    })
    await wrapper.get('[data-testid="promote"]').trigger('click')
    expect(promoteImageVersion).not.toHaveBeenCalled()
    await wrapper.get('[data-testid="promote-confirm"]').trigger('click')
    await flushPromises()
    await flushPromises()
    expect(promoteImageVersion).toHaveBeenCalledWith('r1@bbbb')
    expect(wrapper.get('[data-testid="version-r1@bbbb"]').text()).toContain('promoted')
    // The template still pins v1, which is now superseded.
    expect(wrapper.get('[data-testid="template-t1"]').text()).toContain('superseded')
  })

  it('starts each version with a clean build form', async () => {
    listImageRecipeVersions.mockResolvedValue(ok(page([version('r1@aaaa', 1), version('r1@bbbb', 2)])))
    const { wrapper, router } = await mountAt('/images?select=version:r1@aaaa')
    await wrapper.findAll('button').find(b => b.text() === '+ Secret variable')!.trigger('click')
    await wrapper.get('input[aria-label="Secret reference id"]').setValue('secret-ref-1')
    await router.replace({ query: { select: 'version:r1@bbbb' } })
    await flushPromises()
    expect(wrapper.find('input[aria-label="Secret reference id"]').exists()).toBe(false)
  })

  it('asks before building while a build started elsewhere is running', async () => {
    listImageRecipeVersions.mockResolvedValue(ok(page([version('r1@aaaa', 1)])))
    operations = [{ id: 'op-elsewhere', kind: 'image.build', state: 'running', createdAt: 1 } as OperationDto]
    const { wrapper } = await mountAt('/images?select=version:r1@aaaa')
    expect(wrapper.get('[data-testid="unattributed-builds"]').text()).toContain('1 build running')
    expect(wrapper.get('[data-testid="build"]').attributes('disabled')).toBeDefined()
    await wrapper.get('[data-testid="concurrent-builds"] input').setValue(true)
    expect(wrapper.get('[data-testid="build"]').attributes('disabled')).toBeUndefined()
  })

  it('treats a disk-less clone\'s storage pool as draft metadata only', async () => {
    const { wrapper } = await mountAt('/images?select=recipe:r1')
    const raw = () => (wrapper.get('[data-testid="raw-editor"]').element as HTMLTextAreaElement).value
    const before = raw()
    expect(wrapper.get('[data-testid="pool-inherited"]').text()).toContain('keeps the source template\'s storage')
    expect(wrapper.find('[data-testid="field-disk-size"]').exists()).toBe(false)
    await wrapper.get('[data-testid="field-pool"]').setValue('')
    expect(raw()).toBe(before)
    expect(wrapper.get('[data-testid="recipe-errors"]').text()).toContain('storage pool')
  })

  it('edits the first disk\'s pool when the builder declares disks', async () => {
    const withDisk = JSON.stringify({ builders: [{ type: 'proxmox-iso', node: 'pve-01', disks: [{ type: 'scsi', storage_pool: 'local-lvm', disk_size: '20G' }] }] }, null, 2)
    listImageRecipes.mockResolvedValue(ok(page([recipe({ source: 'iso', content: withDisk })])))
    const { wrapper } = await mountAt('/images?select=recipe:r1')
    expect(wrapper.find('[data-testid="pool-inherited"]').exists()).toBe(false)
    await wrapper.get('[data-testid="field-pool"]').setValue('fast')
    await wrapper.get('[data-testid="field-pool"]').trigger('change')
    const builder = JSON.parse((wrapper.get('[data-testid="raw-editor"]').element as HTMLTextAreaElement).value).builders[0]
    expect(builder.disks).toEqual([{ type: 'scsi', storage_pool: 'fast', disk_size: '20G' }])
    expect(builder).not.toHaveProperty('vm_storage_pool')
  })

  it('offers raw-only editing for a non-JSON template', async () => {
    listImageRecipes.mockResolvedValue(ok(page([recipe({ content: 'source "proxmox-iso" "x" {}' })])))
    const { wrapper } = await mountAt('/images?select=recipe:r1')
    expect(wrapper.get('[data-testid="raw-only"]').text()).toContain('not JSON')
  })
})
