import { readFileSync, existsSync } from 'node:fs';
import { hostname } from 'node:os';
import { join } from 'node:path';

const MARKER_FILE = '.agents-registry-machine';

/**
 * Resolves which machine `sync` should act on, in order:
 * explicit id -> AGENTS_REGISTRY_MACHINE env var -> a local, gitignored
 * `.agents-registry-machine` marker file -> a machine whose `id` or `host`
 * matches this host's hostname.
 */
export function detectMachineId(rootDir, { explicitId, env = process.env } = {}) {
  if (explicitId) return { id: explicitId, source: '--machine' };
  if (env.AGENTS_REGISTRY_MACHINE) {
    return { id: env.AGENTS_REGISTRY_MACHINE, source: 'AGENTS_REGISTRY_MACHINE' };
  }
  const markerPath = join(rootDir, MARKER_FILE);
  if (existsSync(markerPath)) {
    const id = readFileSync(markerPath, 'utf8').trim();
    if (id) return { id, source: MARKER_FILE };
  }
  return { id: null, source: null, hostname: hostname() };
}

export function matchByHostname(registry, host) {
  for (const machine of registry.machines.values()) {
    if (machine.id === host || machine.host === host) return machine.id;
  }
  return null;
}
