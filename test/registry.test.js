import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { loadRegistry } from '../src/registry.js';

function makeFixture(files) {
  const dir = mkdtempSync(join(tmpdir(), 'agents-registry-test-'));
  for (const [relPath, content] of Object.entries(files)) {
    const fullPath = join(dir, relPath);
    mkdirSync(join(fullPath, '..'), { recursive: true });
    writeFileSync(fullPath, content);
  }
  return dir;
}

test('loadRegistry loads machines, roles, and packs with filename-derived ids', () => {
  const dir = makeFixture({
    'machines/dev-01.yaml': 'machine:\n  id: dev-01\n  os: linux\n  roles: [developer]\n',
    'roles/developer.yaml': 'skills:\n  packs: [core-dev]\ncapabilities: [docker]\n',
    'packs/core-dev.yaml': 'skills:\n  - owner/debugging\n',
  });

  try {
    const registry = loadRegistry(dir);
    assert.deepEqual(registry.errors, []);
    assert.equal(registry.machines.size, 1);
    assert.equal(registry.machines.get('dev-01').os, 'linux');
    assert.equal(registry.roles.get('developer').capabilities[0], 'docker');
    assert.equal(registry.packs.get('core-dev').skills[0], 'owner/debugging');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('loadRegistry carries an optional machine.vmid through', () => {
  const dir = makeFixture({
    'machines/test-ubuntu.yaml': 'machine:\n  id: test-ubuntu\n  vmid: 201\n  os: ubuntu-desktop-24.04\n  roles: []\n',
  });
  try {
    const registry = loadRegistry(dir);
    assert.deepEqual(registry.errors, []);
    assert.equal(registry.machines.get('test-ubuntu').vmid, 201);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('loadRegistry defaults vmid to null when absent', () => {
  const dir = makeFixture({
    'machines/dev-01.yaml': 'machine:\n  id: dev-01\n  os: linux\n  roles: []\n',
  });
  try {
    const registry = loadRegistry(dir);
    assert.equal(registry.machines.get('dev-01').vmid, null);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('loadRegistry reports an error when machine.id does not match its filename', () => {
  const dir = makeFixture({
    'machines/dev-01.yaml': 'machine:\n  id: something-else\n  roles: []\n',
  });

  try {
    const registry = loadRegistry(dir);
    assert.equal(registry.machines.size, 0);
    assert.equal(registry.errors.length, 1);
    assert.match(registry.errors[0], /does not match filename/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('loadRegistry reports an error for a machine manifest missing machine.id', () => {
  const dir = makeFixture({
    'machines/dev-01.yaml': 'os: linux\nroles: []\n',
  });

  try {
    const registry = loadRegistry(dir);
    assert.equal(registry.machines.size, 0);
    assert.equal(registry.errors.length, 1);
    assert.match(registry.errors[0], /missing required top-level "machine.id"/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('loadRegistry reports duplicate ids within the same entity directory', () => {
  const dir = makeFixture({
    'roles/developer.yaml': 'capabilities: [docker]\n',
  });
  // Simulate a duplicate by loading twice against a copy under a different extension.
  writeFileSync(join(dir, 'roles', 'developer.yml'), 'capabilities: [docker]\n');

  try {
    const registry = loadRegistry(dir);
    assert.equal(registry.roles.size, 1);
    assert.equal(registry.errors.length, 1);
    assert.match(registry.errors[0], /duplicate roles id "developer"/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('loadRegistry tolerates missing entity directories', () => {
  const dir = makeFixture({});
  try {
    const registry = loadRegistry(dir);
    assert.deepEqual(registry.errors, []);
    assert.equal(registry.machines.size, 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
