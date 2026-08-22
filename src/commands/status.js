import { loadRegistry } from '../registry.js';
import { resolveAllMachines } from '../resolve.js';

function pad(str, width) {
  return str.length >= width ? `${str.slice(0, width - 1)}…` : str.padEnd(width);
}

/**
 * Live VM power state (the STATE column in issue #2 section 13) requires a
 * Proxmox adapter, which is out of scope here - see the follow-up issue.
 * Every row reports "unmanaged" until that adapter exists.
 */
export function runStatus(rootDir) {
  const registry = loadRegistry(rootDir);
  if (registry.errors.length > 0) {
    console.error(`Warning: ${registry.errors.length} registry load error(s); run \`agents-registry validate\` for details.`);
  }

  const { resolved, errors } = resolveAllMachines(registry);

  const header = ['NAME', 'STATE', 'ROLES', 'CAPABILITIES', 'DEVICES'];
  const widths = [16, 11, 26, 18, 16];
  console.log(header.map((h, i) => pad(h, widths[i])).join(' '));

  for (const machine of resolved.values()) {
    const row = [
      machine.id,
      'unmanaged',
      machine.roles.join(',') || '-',
      String(machine.capabilities.length),
      machine.devices.map((d) => d.id).join(',') || '-',
    ];
    console.log(row.map((v, i) => pad(v, widths[i])).join(' '));
  }

  if (errors.length > 0) {
    console.error(`\n${errors.length} machine(s) failed to resolve:`);
    for (const err of errors) console.error(`  - ${err}`);
  }

  console.error(
    '\nNote: STATE is not live - no Proxmox adapter is wired up yet (tracked separately from issue #2).',
  );

  return errors.length > 0 ? 1 : 0;
}
