import { loadRegistry } from '../registry.js';
import { resolveAllMachines, resolveProject } from '../resolve.js';

export function runValidate(rootDir) {
  const registry = loadRegistry(rootDir);
  const errors = [...registry.errors];

  const { errors: resolveErrors } = resolveAllMachines(registry);
  errors.push(...resolveErrors);

  for (const projectId of registry.projects.keys()) {
    try {
      resolveProject(projectId, registry);
    } catch (err) {
      errors.push(`project "${projectId}": ${err.message}`);
    }
  }

  for (const [profileId, profile] of registry.testProfiles) {
    for (const machineId of profile.machines ?? []) {
      if (!registry.machines.has(machineId)) {
        errors.push(`test profile "${profileId}" references unknown machine "${machineId}"`);
      }
    }
  }

  if (errors.length === 0) {
    console.log(
      `OK: ${registry.machines.size} machines, ${registry.roles.size} roles, ` +
        `${registry.packs.size} packs, ${registry.devices.size} devices, ` +
        `${registry.projects.size} projects, ${registry.testProfiles.size} test profiles - no errors.`,
    );
    return 0;
  }

  console.error(`Found ${errors.length} error(s):`);
  for (const err of errors) {
    console.error(`  - ${err}`);
  }
  return 1;
}
