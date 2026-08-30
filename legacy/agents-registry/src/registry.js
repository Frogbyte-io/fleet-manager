import { readdirSync, readFileSync, existsSync } from 'node:fs';
import { join, basename, extname } from 'node:path';
import { parse as parseYaml } from 'yaml';

const ENTITY_DIRS = {
  machines: 'machines',
  roles: 'roles',
  packs: 'packs',
  devices: 'devices',
  projects: 'projects',
  testProfiles: 'test-profiles',
};

function listYamlFiles(dir) {
  if (!existsSync(dir)) return [];
  return readdirSync(dir)
    .filter((f) => extname(f) === '.yaml' || extname(f) === '.yml')
    .sort();
}

function loadYamlFile(path) {
  const raw = readFileSync(path, 'utf8');
  return parseYaml(raw) ?? {};
}

/**
 * Loads every entity directory into `Map<id, entity>`. Every entity type
 * except `machines` uses the filename stem as its id and the file body as
 * the entity itself (no wrapper key) - see docs/schema.md. Machines use an
 * explicit `machine: { id, host, os, roles }` block, per the shape in
 * issue #2, and the filename stem must match `machine.id`.
 *
 * Load-time problems (duplicate ids, malformed YAML, id/filename mismatch)
 * are collected into `errors` rather than thrown, so callers such as
 * `agents-registry validate` can report everything at once.
 */
export function loadRegistry(rootDir) {
  const errors = [];
  const registry = {
    rootDir,
    machines: new Map(),
    roles: new Map(),
    packs: new Map(),
    devices: new Map(),
    projects: new Map(),
    testProfiles: new Map(),
    errors,
  };

  for (const file of listYamlFiles(join(rootDir, ENTITY_DIRS.machines))) {
    const path = join(rootDir, ENTITY_DIRS.machines, file);
    const stem = basename(file, extname(file));
    let data;
    try {
      data = loadYamlFile(path);
    } catch (err) {
      errors.push(`machines/${file}: failed to parse YAML: ${err.message}`);
      continue;
    }
    const machine = data.machine;
    if (!machine || !machine.id) {
      errors.push(`machines/${file}: missing required top-level "machine.id" field`);
      continue;
    }
    if (machine.id !== stem) {
      errors.push(`machines/${file}: machine.id "${machine.id}" does not match filename "${stem}"`);
      continue;
    }
    if (registry.machines.has(machine.id)) {
      errors.push(`machines/${file}: duplicate machine id "${machine.id}"`);
      continue;
    }
    registry.machines.set(machine.id, {
      id: machine.id,
      host: machine.host ?? null,
      os: machine.os ?? null,
      vmid: machine.vmid ?? null,
      roles: machine.roles ?? [],
      skills: data.skills ?? {},
      capabilities: data.capabilities ?? [],
      resources: data.resources ?? null,
      lifecycle: data.lifecycle ?? null,
      requires: data.requires ?? {},
      sourceFile: path,
    });
  }

  const simpleKinds = [
    ['roles', 'roles'],
    ['packs', 'packs'],
    ['devices', 'devices'],
    ['projects', 'projects'],
    ['testProfiles', 'test-profiles'],
  ];

  for (const [key, dirName] of simpleKinds) {
    for (const file of listYamlFiles(join(rootDir, dirName))) {
      const path = join(rootDir, dirName, file);
      const stem = basename(file, extname(file));
      let data;
      try {
        data = loadYamlFile(path);
      } catch (err) {
        errors.push(`${dirName}/${file}: failed to parse YAML: ${err.message}`);
        continue;
      }
      if (registry[key].has(stem)) {
        errors.push(`${dirName}/${file}: duplicate ${dirName} id "${stem}"`);
        continue;
      }
      registry[key].set(stem, { id: stem, sourceFile: path, ...(data ?? {}) });
    }
  }

  return registry;
}
