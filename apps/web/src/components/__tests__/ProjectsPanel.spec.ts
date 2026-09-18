import { mount } from '@vue/test-utils'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import type { PageProjectDtoItemsItem } from '@frogbyte-io/fleet-api-client'

const listProjects = vi.fn()
const getProject = vi.fn()
const createProject = vi.fn()
const deleteProject = vi.fn()
const getOperation = vi.fn()
const startReadyWorkflow = vi.fn()

vi.mock('@frogbyte-io/fleet-api-client', () => ({
  listProjects: (...args: unknown[]) => listProjects(...args),
  getProject: (...args: unknown[]) => getProject(...args),
  createProject: (...args: unknown[]) => createProject(...args),
  deleteProject: (...args: unknown[]) => deleteProject(...args),
  getOperation: (...args: unknown[]) => getOperation(...args),
  startReadyWorkflow: (...args: unknown[]) => startReadyWorkflow(...args),
}))

import ProjectsPanel from '../ProjectsPanel.vue'

function project(
  overrides: Partial<PageProjectDtoItemsItem> = {},
): PageProjectDtoItemsItem {
  return {
    id: 'project-1',
    remote: 'github.com/Frogbyte-io/fleet-manager',
    name: 'fleet-manager',
    description: '',
    checkouts: [],
    createdAt: 0,
    updatedAt: 0,
    ...overrides,
  }
}

beforeEach(() => {
  for (const mock of [
    listProjects,
    getProject,
    createProject,
    deleteProject,
    getOperation,
    startReadyWorkflow,
  ]) {
    mock.mockReset()
  }
})

describe('ProjectsPanel', () => {
  it('renders an empty list honestly', async () => {
    listProjects.mockResolvedValue({
      status: 200,
      data: { items: [], page: { nextCursor: null, limit: 50 } },
    })
    const wrapper = mount(ProjectsPanel)
    await vi.waitFor(() => expect(wrapper.text()).toContain('No projects yet'))
    wrapper.unmount()
  })

  it('registers a project and shows the normalized remote with checkouts', async () => {
    listProjects.mockResolvedValue({
      status: 200,
      data: { items: [], page: { nextCursor: null, limit: 50 } },
    })
    createProject.mockResolvedValue({
      status: 201,
      data: { data: project() },
    })
    getProject.mockResolvedValue({
      status: 200,
      data: {
        data: {
          ...project(),
          checkouts: [
            {
              machineId: 'machine-a',
              root: '/home/dev/code/fleet-manager',
              branch: 'main',
              dirty: false,
              source: 'agentless/1',
              observedAt: 1,
            },
          ],
        },
      },
    })
    const wrapper = mount(ProjectsPanel)
    await vi.waitFor(() => expect(wrapper.text()).toContain('No projects yet'))

    await wrapper.get('input[placeholder="git remote (any spelling)"]').setValue('git@github.com:Frogbyte-io/fleet-manager.git')
    await wrapper.get('input[placeholder="display name"]').setValue('fleet-manager')
    await wrapper.findAll('button').filter(b => b.text() === 'Register project')[0].trigger('click')

    await vi.waitFor(() =>
      expect(createProject).toHaveBeenCalledWith(
        expect.objectContaining({
          remote: 'git@github.com:Frogbyte-io/fleet-manager.git',
          name: 'fleet-manager',
        }),
      ),
    )
    await vi.waitFor(() => expect(wrapper.text()).toContain('machine-a'))
    await vi.waitFor(() => expect(wrapper.text()).toContain('/home/dev/code/fleet-manager'))
    // The detail shows the normalized remote, not the raw spelling.
    await vi.waitFor(() =>
      expect(wrapper.text()).toContain('github.com/Frogbyte-io/fleet-manager'),
    )
    wrapper.unmount()
  })

  it('plans the ready workflow with a dry run before executing', async () => {
    listProjects.mockResolvedValue({
      status: 200,
      data: { items: [project()], page: { nextCursor: null, limit: 50 } },
    })
    getProject.mockResolvedValue({ status: 200, data: { data: project() } })
    startReadyWorkflow.mockResolvedValue({
      status: 200,
      data: {
        data: {
          projectId: 'project-1',
          steps: [{ kind: 'clone' }, { kind: 'verify' }],
          note: 'the executed plan is computed from observed state',
        },
      },
    })
    const wrapper = mount(ProjectsPanel)
    await vi.waitFor(() => expect(wrapper.text()).toContain('fleet-manager'))
    await wrapper.find('tr.cursor-pointer').trigger('click')
    await vi.waitFor(() => expect(wrapper.text()).toContain('Make ready'))
    // Fill the form and plan.
    const inputs = wrapper.findAll('input')
    await inputs.at(-3)!.setValue('machine-1')
    await inputs.at(-2)!.setValue('endpoint-1')
    await inputs.at(-1)!.setValue('/srv/repo')
    const planButton = wrapper
      .findAll('button')
      .find((button) => button.text().includes('Plan (dry run)'))
    expect(planButton, 'the plan button exists').toBeDefined()
    await planButton!.trigger('click')
    await vi.waitFor(() =>
      expect(wrapper.text()).toContain('the executed plan is computed'),
    )
    expect(startReadyWorkflow).toHaveBeenCalledWith('project-1', {
      machineId: 'machine-1',
      endpointId: 'endpoint-1',
      auth: { type: 'agent' },
      root: '/srv/repo',
      dryRun: true,
    })
    wrapper.unmount()
  })

  it('reports a blocked workflow as a state, not an error', async () => {
    listProjects.mockResolvedValue({
      status: 200,
      data: { items: [project()], page: { nextCursor: null, limit: 50 } },
    })
    getProject.mockResolvedValue({ status: 200, data: { data: project() } })
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
    const wrapper = mount(ProjectsPanel)
    await vi.waitFor(() => expect(wrapper.text()).toContain('fleet-manager'))
    await wrapper.find('tr.cursor-pointer').trigger('click')
    await vi.waitFor(() => expect(wrapper.text()).toContain('Make ready'))
    const inputs = wrapper.findAll('input')
    await inputs.at(-3)!.setValue('machine-1')
    await inputs.at(-2)!.setValue('endpoint-1')
    await inputs.at(-1)!.setValue('/srv/repo')
    const runButton = wrapper
      .findAll('button')
      .find((button) => button.text().includes('Execute'))
    expect(runButton, 'the execute button exists').toBeDefined()
    await runButton!.trigger('click')
    await vi.waitFor(
      () => expect(wrapper.text()).toContain('blocked_manual_approval'),
      { timeout: 5000 },
    )
    wrapper.unmount()
  })

  it('shows the failure instead of an empty table', async () => {
    listProjects.mockRejectedValue(new Error('the controller did not answer'))
    const wrapper = mount(ProjectsPanel)
    await vi.waitFor(() => expect(wrapper.text()).toContain('the controller did not answer'))
    wrapper.unmount()
  })
})
