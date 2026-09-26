import { flushPromises, mount } from '@vue/test-utils'
import { VueQueryPlugin, type VueQueryPluginOptions } from '@tanstack/vue-query'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createMemoryHistory, createRouter } from 'vue-router'

import { routes } from '@/router'
import ProjectsPage from '../projects/ProjectsPage.vue'

const listProjects = vi.fn()
const listMachines = vi.fn()
const startReadyWorkflow = vi.fn()
const getOperation = vi.fn()

vi.mock('@frogbyte-io/fleet-api-client', () => ({
  listProjects: (...args: unknown[]) => listProjects(...args),
  listMachines: (...args: unknown[]) => listMachines(...args),
  startReadyWorkflow: (...args: unknown[]) => startReadyWorkflow(...args),
  getOperation: (...args: unknown[]) => getOperation(...args),
}))

function machine(id: string, name: string) {
  return {
    id,
    name,
    machineStatus: 'connected',
    capabilities: [],
    createdAt: 0,
    updatedAt: 0,
    description: '',
    endpoints: [],
    groups: [],
    tags: [],
  }
}

function stubHappyPath() {
  listProjects.mockResolvedValue({
    status: 200,
    data: {
      items: [
        {
          id: 'p1',
          name: 'alpha',
          remote: 'git@github.com:acme/alpha',
          description: '',
          createdAt: 0,
          updatedAt: 0,
          checkouts: [
            {
              machineId: 'm1',
              branch: 'main',
              dirty: false,
              observedAt: 1_000,
              root: '/srv/alpha',
              source: 'agentless/1',
            },
          ],
        },
      ],
      page: { limit: 200, nextCursor: null },
    },
  })
  listMachines.mockResolvedValue({
    status: 200,
    data: {
      items: [machine('m1', 'homelab'), machine('m2', 'bare-lab')],
      page: { limit: 200, nextCursor: null },
    },
  })
}

function makeRouter() {
  return createRouter({ history: createMemoryHistory(), routes })
}

let router: ReturnType<typeof createRouter>

beforeEach(() => {
  router = makeRouter()
  listProjects.mockReset()
  listMachines.mockReset()
  startReadyWorkflow.mockReset()
  getOperation.mockReset()
})

afterEach(() => {
  vi.resetAllMocks()
})

async function mountAt() {
  await router.push('/projects')
  await router.isReady()
  const wrapper = mount(ProjectsPage, {
    global: {
      plugins: [
        router,
        [VueQueryPlugin, { queryClientConfig: { defaultOptions: { queries: { retry: false } } } } as VueQueryPluginOptions],
      ],
    },
  })
  await flushPromises()
  return wrapper
}

describe('ProjectsPage', () => {
  let wrapper: Awaited<ReturnType<typeof mountAt>> | null = null

  afterEach(() => {
    wrapper?.unmount()
    wrapper = null
  })

  it('renders the project × machine matrix with honest empty cells', async () => {
    stubHappyPath()
    wrapper = await mountAt()
    expect(wrapper.find('[data-testid="matrix-row"]').exists()).toBe(true)
    expect(wrapper.text()).toContain('alpha')
    expect(wrapper.text()).toContain('homelab')
    expect(wrapper.text()).toContain('main')
    expect(wrapper.text()).toContain('clean')
    expect(wrapper.text()).toContain('no checkout')
  })

  it('shows a dry-run plan in execution order', async () => {
    stubHappyPath()
    startReadyWorkflow.mockResolvedValue({
      status: 200,
      data: {
        data: {
          machineId: 'm1',
          projectId: 'p1',
          root: '/srv/alpha',
          note: 'how the executed plan relates to this description',
          steps: [
            { kind: 'clone', when: 'always' },
            { kind: 'verify', when: 'after clone' },
          ],
        },
      },
    })
    wrapper = await mountAt()
    await wrapper.find('[data-testid="ready-for-alpha"]').trigger('click')
    await wrapper.find('[data-testid="ready-machine"]').setValue('m1')
    await wrapper.find('[data-testid="ready-endpoint"]').setValue('ep1')
    await wrapper.find('[data-testid="ready-root"]').setValue('/srv/alpha')
    await wrapper.find('[data-testid="ready-plan"]').trigger('click')
    await flushPromises()
    const plan = wrapper.find('[data-testid="ready-plan-view"]').text()
    expect(plan).toContain('clone (always)')
    expect(plan).toContain('verify (after clone)')
    expect(startReadyWorkflow).toHaveBeenCalledWith(
      'p1',
      expect.objectContaining({ machineId: 'm1', dryRun: true }),
    )
  })

  it('surfaces a blocked Frogenv approval as a state with its reason', async () => {
    stubHappyPath()
    startReadyWorkflow.mockResolvedValue({
      status: 202,
      data: { data: { id: 'op-1', state: 'pending' } },
    })
    getOperation
      .mockResolvedValueOnce({
        status: 200,
        data: { data: { id: 'op-1', state: 'running' } },
      })
      .mockResolvedValue({
        status: 200,
        data: {
          data: {
            id: 'op-1',
            state: 'blocked_manual_approval',
            errorJson:
              '{"reason":"blocked_manual_approval","detail":"the frogenv_setup ceremony requires manual approval"}',
          },
        },
      })
    wrapper = await mountAt()
    await wrapper.find('[data-testid="ready-for-alpha"]').trigger('click')
    await wrapper.find('[data-testid="ready-machine"]').setValue('m1')
    await wrapper.find('[data-testid="ready-endpoint"]').setValue('ep1')
    await wrapper.find('[data-testid="ready-root"]').setValue('/srv/alpha')
    await wrapper.find('[data-testid="ready-execute"]').trigger('click')
    // The flow polls the operation every 500 ms; wait for the blocked
    // state rather than sleeping a magic duration.
    await vi.waitFor(
      // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
      () => expect(wrapper!.find('[data-testid="ready-blocked"]').exists()).toBe(true),
      // Two 500 ms polls plus latency; the 1 s default is too tight.
      { timeout: 5_000, interval: 100 },
    )
    expect(wrapper.text()).toContain('the frogenv_setup ceremony requires manual approval')
  })

  it('renders a refused list as an error, not an empty matrix', async () => {
    listProjects.mockResolvedValue({
      status: 403,
      data: { code: 'denied', message: 'no', correlationId: 'c1', retry: 'never' },
    })
    listMachines.mockResolvedValue({
      status: 200,
      data: { items: [], page: { limit: 200, nextCursor: null } },
    })
    wrapper = await mountAt()
    expect(wrapper.text()).toContain('no')
  })
})
