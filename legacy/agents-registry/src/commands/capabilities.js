import { loadRegistry } from '../registry.js';
import { machinesWithCapability } from '../resolve.js';

export function runCapabilities(rootDir, capability) {
  const registry = loadRegistry(rootDir);
  const { machines, errors } = machinesWithCapability(registry, capability);

  if (machines.length === 0) {
    console.log(`No machines have capability "${capability}".`);
  } else {
    console.log(`Machines with capability "${capability}":`);
    for (const machine of machines) console.log(`  - ${machine.id}`);
  }

  if (errors.length > 0) {
    console.error(`\n${errors.length} machine(s) failed to resolve and were skipped:`);
    for (const err of errors) console.error(`  - ${err}`);
  }
  return 0;
}
