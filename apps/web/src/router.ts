import { createRouter, createWebHistory, type RouteRecordRaw } from 'vue-router'

/** Returns the clean URL represented by a legacy `/#/...` URL. */
export function legacyHashUrl(search: string, hash: string): string | null {
  if (!hash.startsWith('#/')) return null
  return `${hash.slice(1)}${search}`
}

const legacyUrl = typeof window === 'undefined'
  ? null
  : legacyHashUrl(window.location.search, window.location.hash)
if (legacyUrl) {
  window.history.replaceState(window.history.state, '', legacyUrl)
}

export const routes: RouteRecordRaw[] = [
  {
    path: '/',
    component: () => import('./pages/overview/OverviewPage.vue'),
    meta: { title: 'Overview', group: null },
  },
  {
    path: '/fleet',
    component: () => import('./pages/fleet/FleetPage.vue'),
    meta: { title: 'Fleet', group: 'Infrastructure' },
  },
  {
    path: '/fleet/add',
    component: () => import('./pages/fleet/AddMachinePage.vue'),
    meta: { title: 'Add machine', group: 'Infrastructure' },
  },
  {
    path: '/projects',
    component: () => import('./pages/projects/ProjectsPage.vue'),
    meta: { title: 'Projects', group: 'Work' },
  },
  {
    path: '/operations',
    component: () => import('./pages/operations/OperationsPage.vue'),
    meta: { title: 'Operations', group: 'Control' },
  },
  {
    path: '/settings',
    component: () => import('./pages/settings/SettingsPage.vue'),
    meta: { title: 'Settings', group: 'Control' },
  },
  {
    path: '/proxmox',
    component: () => import('./pages/NotYetAvailablePage.vue'),
    meta: { title: 'Proxmox', group: 'Infrastructure' },
  },
  {
    path: '/tailnet',
    component: () => import('./pages/NotYetAvailablePage.vue'),
    meta: { title: 'Tailnet', group: 'Infrastructure' },
  },
  {
    path: '/containers',
    component: () => import('./pages/NotYetAvailablePage.vue'),
    meta: { title: 'Containers', group: 'Infrastructure' },
  },
  {
    path: '/skills',
    component: () => import('./pages/NotYetAvailablePage.vue'),
    meta: { title: 'Skills', group: 'Work' },
  },
  {
    path: '/lab',
    component: () => import('./pages/NotYetAvailablePage.vue'),
    meta: { title: 'Lab', group: 'Work' },
  },
  {
    path: '/images',
    component: () => import('./pages/NotYetAvailablePage.vue'),
    meta: { title: 'Images', group: 'Work' },
  },
  {
    path: '/audit',
    component: () => import('./pages/NotYetAvailablePage.vue'),
    meta: { title: 'Audit log', group: 'Control' },
  },
  {
    path: '/:pathMatch(.*)*',
    component: () => import('./pages/NotFoundPage.vue'),
    meta: { title: 'Not found', group: null },
  },
]

export const router = createRouter({
  history: createWebHistory(),
  routes,
  scrollBehavior: () => ({ top: 0 }),
})
