import { test } from 'node:test';
import assert from 'node:assert/strict';
import { resolveMachine, resolveAllMachines, resolveProject, machinesWithCapability } from '../src/resolve.js';

function makeRegistry(overrides = {}) {
  return {
    machines: new Map(overrides.machines ?? []),
    roles: new Map(overrides.roles ?? []),
    packs: new Map(overrides.packs ?? []),
    devices: new Map(overrides.devices ?? []),
    projects: new Map(overrides.projects ?? []),
    testProfiles: new Map(overrides.testProfiles ?? []),
  };
}

test('resolveMachine composes packs/skills/capabilities through role chains', () => {
  const registry = makeRegistry({
    roles: [
      ['linux', { capabilities: ['linux'] }],
      ['developer', { extends: ['linux'], skills: { packs: ['core-dev'] }, capabilities: ['docker'] }],
      ['javascript', { extends: ['developer'], skills: { packs: ['javascript'] } }],
    ],
    packs: [
      ['core-dev', { skills: ['owner/debugging'] }],
      ['javascript', { skills: ['owner/js-style'] }],
    ],
    machines: [
      ['dev-01', { id: 'dev-01', roles: ['javascript'], capabilities: ['editor'] }],
    ],
  });

  const resolved = resolveMachine('dev-01', registry);

  assert.deepEqual(resolved.packs.sort(), ['core-dev', 'javascript']);
  assert.deepEqual(resolved.skills.sort(), ['owner/debugging', 'owner/js-style']);
  assert.deepEqual(resolved.capabilities.sort(), ['docker', 'editor', 'linux']);
});

test('machine-level exclude overrides skills pulled in by roles/packs', () => {
  const registry = makeRegistry({
    roles: [['developer', { skills: { packs: ['core-dev'] } }]],
    packs: [['core-dev', { skills: ['owner/debugging', 'owner/verification'] }]],
    machines: [
      [
        'dev-01',
        { id: 'dev-01', roles: ['developer'], skills: { exclude: ['owner/verification'] } },
      ],
    ],
  });

  const resolved = resolveMachine('dev-01', registry);
  assert.deepEqual(resolved.skills, ['owner/debugging']);
  assert.deepEqual(resolved.excluded, ['owner/verification']);
});

test('machine-level include adds a skill not covered by any pack', () => {
  const registry = makeRegistry({
    machines: [['dev-01', { id: 'dev-01', roles: [], skills: { include: ['owner/special'] } }]],
  });

  const resolved = resolveMachine('dev-01', registry);
  assert.deepEqual(resolved.skills, ['owner/special']);
});

test('resolveMachine throws on unknown role', () => {
  const registry = makeRegistry({
    machines: [['dev-01', { id: 'dev-01', roles: ['ghost'] }]],
  });
  assert.throws(() => resolveMachine('dev-01', registry), /unknown role "ghost"/);
});

test('resolveMachine throws on unknown pack referenced by a role', () => {
  const registry = makeRegistry({
    roles: [['developer', { skills: { packs: ['ghost-pack'] } }]],
    machines: [['dev-01', { id: 'dev-01', roles: ['developer'] }]],
  });
  assert.throws(() => resolveMachine('dev-01', registry), /unknown pack "ghost-pack"/);
});

test('resolveMachine throws on unknown required device', () => {
  const registry = makeRegistry({
    machines: [['dev-01', { id: 'dev-01', roles: [], requires: { devices: ['ghost-device'] } }]],
  });
  assert.throws(() => resolveMachine('dev-01', registry), /unknown device "ghost-device"/);
});

test('role extends cycle is detected instead of infinite-looping', () => {
  const registry = makeRegistry({
    roles: [
      ['a', { extends: ['b'] }],
      ['b', { extends: ['a'] }],
    ],
    machines: [['dev-01', { id: 'dev-01', roles: ['a'] }]],
  });
  assert.throws(() => resolveMachine('dev-01', registry), /role inheritance cycle/);
});

test('resolveAllMachines collects per-machine errors instead of throwing', () => {
  const registry = makeRegistry({
    machines: [
      ['ok', { id: 'ok', roles: [] }],
      ['broken', { id: 'broken', roles: ['ghost'] }],
    ],
  });
  const { resolved, errors } = resolveAllMachines(registry);
  assert.equal(resolved.size, 1);
  assert.ok(resolved.has('ok'));
  assert.equal(errors.length, 1);
  assert.match(errors[0], /"broken"/);
});

test('machinesWithCapability filters resolved machines by capability', () => {
  const registry = makeRegistry({
    machines: [
      ['a', { id: 'a', roles: [], capabilities: ['docker'] }],
      ['b', { id: 'b', roles: [], capabilities: [] }],
    ],
  });
  const { machines } = machinesWithCapability(registry, 'docker');
  assert.deepEqual(machines.map((m) => m.id), ['a']);
});

test('resolveProject expands packs and gathers test machines across profiles', () => {
  const registry = makeRegistry({
    packs: [['javascript', { skills: ['owner/js-style'] }]],
    testProfiles: [
      ['desktop-linux', { machines: ['test-ubuntu', 'test-bazzite'] }],
    ],
    projects: [
      [
        'dot-x',
        { id: 'dot-x', repo: 'git@example.com:dot-x.git', skills: { packs: ['javascript'] }, tests: ['desktop-linux'] },
      ],
    ],
  });

  const resolved = resolveProject('dot-x', registry);
  assert.deepEqual(resolved.skills, ['owner/js-style']);
  assert.deepEqual(resolved.testMachines.sort(), ['test-bazzite', 'test-ubuntu']);
});

test('resolveProject throws on unknown test profile', () => {
  const registry = makeRegistry({
    projects: [['dot-x', { id: 'dot-x', tests: ['ghost-profile'] }]],
  });
  assert.throws(() => resolveProject('dot-x', registry), /unknown test profile "ghost-profile"/);
});
