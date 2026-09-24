/** The Settings sub-nav: grouped sections per the settings mockup. */
export interface SettingsSection {
  id: string
  title: string
}

export interface SettingsSectionGroup {
  label: string | null
  sections: SettingsSection[]
}

export const SETTINGS_SECTION_GROUPS: SettingsSectionGroup[] = [
  {
    label: 'Controller',
    sections: [
      { id: 'general', title: 'General' },
      { id: 'appearance', title: 'Appearance' },
      { id: 'security', title: 'Security & access' },
      { id: 'backups', title: 'Backups' },
      { id: 'diagnostics', title: 'Diagnostics' },
    ],
  },
  {
    label: 'Connect',
    sections: [
      { id: 'integrations', title: 'Integrations' },
      { id: 'credentials', title: 'Credentials' },
      { id: 'ssh-keys', title: 'SSH & host keys' },
      { id: 'fleetd', title: 'fleetd & enrollment' },
    ],
  },
  {
    label: 'Behaviour',
    sections: [
      { id: 'lab-defaults', title: 'Lab defaults' },
      { id: 'desired-state', title: 'Desired state' },
      { id: 'notifications', title: 'Notifications' },
    ],
  },
]

export const DEFAULT_SECTION = 'integrations'

export function isSectionId(value: string): value is SettingsSection['id'] {
  return SETTINGS_SECTION_GROUPS.some((group) =>
    group.sections.some((section) => section.id === value),
  )
}
