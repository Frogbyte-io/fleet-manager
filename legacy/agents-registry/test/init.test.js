// test/init.test.js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, existsSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runInit } from '../src/commands/init.js';
import { readConfig } from '../src/config.js';

function fakeGit() {
  const calls = [];
  return {
    calls,
    clone(url, dest) {
      calls.push(['clone', url, dest]);
      mkdirSync(join(dest, '.git'), { recursive: true });
    },
    pull(dest) {
      calls.push(['pull', dest]);
    },
  };
}

test('runInit clones when the destination has no .git dir, then writes config', () => {
  const home = mkdtempSync(join(tmpdir(), 'fleet-manager-init-test-'));
  const dest = join(home, 'fleet-clone');
  try {
    const git = fakeGit();
    const env = { HOME: home };
    const code = runInit(null, { repoUrl: 'git@github.com:Frogbyte-io/fleet.git', path: dest, env, platform: 'linux', git });
    assert.equal(code, 0);
    assert.deepEqual(git.calls, [['clone', 'git@github.com:Frogbyte-io/fleet.git', dest]]);
    assert.equal(readConfig({ platform: 'linux', env }).registry_path, dest);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('runInit pulls instead of cloning when the destination already has a .git dir', () => {
  const home = mkdtempSync(join(tmpdir(), 'fleet-manager-init-test-'));
  const dest = join(home, 'fleet-clone');
  mkdirSync(join(dest, '.git'), { recursive: true });
  try {
    const git = fakeGit();
    const env = { HOME: home };
    const code = runInit(null, { repoUrl: 'git@github.com:Frogbyte-io/fleet.git', path: dest, env, platform: 'linux', git });
    assert.equal(code, 0);
    assert.deepEqual(git.calls, [['pull', dest]]);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('runInit fails with a usage message when repoUrl is missing', () => {
  const home = mkdtempSync(join(tmpdir(), 'fleet-manager-init-test-'));
  try {
    const code = runInit(null, { path: join(home, 'x'), env: { HOME: home }, platform: 'linux', git: fakeGit() });
    assert.equal(code, 1);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});
