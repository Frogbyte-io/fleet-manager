import { loadRegistry } from '../registry.js';
import { resolveMachine } from '../resolve.js';

export function runResolve(rootDir, machineId, { json = false } = {}) {
  const registry = loadRegistry(rootDir);
  if (registry.errors.length > 0) {
    console.error('Registry has load errors (run `agents-registry validate` for details); resolving best-effort.');
  }

  let resolved;
  try {
    resolved = resolveMachine(machineId, registry);
  } catch (err) {
    console.error(`Error: ${err.message}`);
    return 1;
  }

  if (json) {
    console.log(JSON.stringify(resolved, null, 2));
    return 0;
  }

  console.log(`Machine: ${resolved.id}`);
  if (resolved.os) console.log(`  OS: ${resolved.os}`);
  console.log(`  Roles: ${resolved.roles.join(', ') || '-'}`);
  console.log(`  Packs: ${resolved.packs.join(', ') || '-'}`);
  console.log(`  Skills (${resolved.skills.length}):`);
  for (const skill of resolved.skills) console.log(`    - ${skill}`);
  if (resolved.excluded.length > 0) console.log(`  Excluded: ${resolved.excluded.join(', ')}`);
  if (resolved.externalPacks.length > 0) {
    console.log(`  External packs: ${resolved.externalPacks.join(', ')}`);
  }
  console.log(`  Capabilities: ${resolved.capabilities.join(', ') || '-'}`);
  if (resolved.devices.length > 0) {
    console.log(`  Required devices: ${resolved.devices.map((d) => d.id).join(', ')}`);
  }
  if (resolved.lifecycle) {
    console.log(`  Lifecycle: mode=${resolved.lifecycle.mode ?? '-'} reset_strategy=${resolved.lifecycle.reset_strategy ?? '-'}`);
  }
  return 0;
}
