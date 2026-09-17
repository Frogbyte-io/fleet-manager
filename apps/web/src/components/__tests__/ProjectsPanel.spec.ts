import { mount } from '@vue/test-utils'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import type { PageProjectDtoItemsItem } from '@frogbyte-io/fleet-api-client'

const listProjects = vi.fn()
const getProject = vi.fn()
const createProject = vi.fn()
const deleteProject = vi.fn()

vi.mock('@frogbyte-io/fleet-api-client', () => ({
  listProjects: (...args: unknown[]) => listProjects(...args),
  getProject: (...args: unknown[]) => getProject(...args),
  createProject: (...args: unknown[]) => createProject(...args),
  deleteProject: (...args: unknown[]) => deleteProject(...args),
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
  for (const mock of [listProjects, getProject, createProject, deleteProject]) {
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

  it('shows the failure instead of an empty table', async () => {
    listProjects.mockRejectedValue(new Error('the controller did not answer'))
    const wrapper = mount(ProjectsPanel)
    await vi.waitFor(() => expect(wrapper.text()).toContain('the controller did not answer'))
    wrapper.unmount()
  })
})
