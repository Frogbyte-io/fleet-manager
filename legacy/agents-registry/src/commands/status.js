import { loadRegistry } from '../registry.js';
import { resolveAllMachines } from '../resolve.js';
import { getPowerState } from '../proxmox/lifecycle.js';
import { ProxmoxClient } from '../proxmox/client.js';

function pad(str, width) {
  return str.length >= width ? `${str.slice(0, width - 1)}…` : str.padEnd(width);
}

function resolveClient(client) {
  if (client !== undefined) return client;
  try {
    return ProxmoxClient.fromEnv();
  } catch {
    return null;
  }
}

export async function runStatus(rootDir, { client, node = 'pve' } = {}) {
  const resolvedClient = resolveClient(client);
  const registry = loadRegistry(rootDir);
  if (registry.errors.length > 0) {
    console.error(`Warning: ${registry.errors.length} registry load error(s); run \`agents-registry validate\` for details.`);
  }

  const { resolved, errors } = resolveAllMachines(registry);

  const header = ['NAME', 'STATE', 'ROLES', 'CAPABILITIES', 'DEVICES'];
  const widths = [16, 11, 26, 18, 16];
  console.log(header.map((h, i) => pad(h, widths[i])).join(' '));

  const rows = await Promise.all([...resolved.values()].map(async (machine) => {
    const source = registry.machines.get(machine.id);
    const vmid = source?.vmid ?? null;
    let state;
    if (!resolvedClient) {
      state = 'unmanaged';
    } else {
      try {
        state = await getPowerState(resolvedClient, node, vmid);
      } catch {
        state = 'error';
      }
    }
    return [
      machine.id,
      state,
      machine.roles.join(',') || '-',
      String(machine.capabilities.length),
      machine.devices.map((d) => d.id).join(',') || '-',
    ];
  }));
  for (const row of rows) {
    console.log(row.map((v, i) => pad(v, widths[i])).join(' '));
  }

  if (errors.length > 0) {
    console.error(`\n${errors.length} machine(s) failed to resolve:`);
    for (const err of errors) console.error(`  - ${err}`);
  }

  if (!resolvedClient) {
    console.error('\nNote: STATE is not live - no PROXMOX_* env vars configured (see docs/schema.md).');
  }

  return errors.length > 0 ? 1 : 0;
}
