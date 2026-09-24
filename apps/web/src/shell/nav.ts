import type { Component } from 'vue'
import {
  Activity,
  Boxes,
  FileText,
  FlaskConical,
  Folder,
  Image,
  Layers,
  LayoutGrid,
  Network,
  Server,
  Settings,
  Shield,
} from '@lucide/vue'

export interface NavItem {
  title: string
  to: string
  icon: Component
  available: boolean
}

export interface NavGroup {
  label: string | null
  items: NavItem[]
}

/** Append-only shared navigation registry for the Fleet Console. */
export const NAV_GROUPS: NavGroup[] = [
  {
    label: null,
    items: [{ title: 'Overview', to: '/', icon: LayoutGrid, available: true }],
  },
  {
    label: 'Infrastructure',
    items: [
      { title: 'Fleet', to: '/fleet', icon: Server, available: true },
      { title: 'Proxmox', to: '/proxmox', icon: Shield, available: false },
      { title: 'Tailnet', to: '/tailnet', icon: Network, available: false },
      { title: 'Containers', to: '/containers', icon: Boxes, available: false },
    ],
  },
  {
    label: 'Work',
    items: [
      { title: 'Projects', to: '/projects', icon: Folder, available: true },
      { title: 'Skills', to: '/skills', icon: Layers, available: false },
      { title: 'Lab', to: '/lab', icon: FlaskConical, available: false },
      { title: 'Images', to: '/images', icon: Image, available: false },
    ],
  },
  {
    label: 'Control',
    items: [
      { title: 'Operations', to: '/operations', icon: Activity, available: true },
      { title: 'Audit log', to: '/audit', icon: FileText, available: false },
      { title: 'Settings', to: '/settings', icon: Settings, available: true },
    ],
  },
]
