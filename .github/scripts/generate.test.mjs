// The acceptance test for FM-001: a deliberately stale generated artifact has
// to fail its dedicated check. These run the real CLI against fixture
// repositories rather than calling the exported function, so the exit code —
// the thing CI actually reads — is what is asserted.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { replaceRegion } from './lib/generators.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const script = join(here, 'generate.mjs');
const fixture = (name) => join(here, '__fixtures__', name);

function run(root, ...args) {
  return spawnSync(process.execPath, [script, ...args, root], { encoding: 'utf8' });
}

/** Fixtures are read-only inputs; anything that writes works on a copy. */
function scratch(name) {
  const dir = mkdtempSync(join(tmpdir(), 'fm-generate-'));
  cpSync(fixture(name), dir, { recursive: true });
  return dir;
}

test('a stale generated artifact fails the check', () => {
  const result = run(fixture('generated-stale'), '--check');
  assert.equal(result.status, 1);
  assert.match(result.stdout, /deny-allowed-licenses: STALE: deny\.toml/);
  assert.match(result.stderr, /is stale/);
  assert.match(result.stderr, /generate\.mjs/, 'the failure has to say how to fix it');
});

test('an up-to-date generated artifact passes the check', () => {
  const result = run(fixture('generated-fresh'), '--check');
  assert.equal(result.status, 0);
  assert.match(result.stdout, /deny-allowed-licenses: up to date/);
});

test('the check does not modify the tree it is checking', () => {
  const before = readFileSync(join(fixture('generated-stale'), 'deny.toml'), 'utf8');
  run(fixture('generated-stale'), '--check');
  assert.equal(readFileSync(join(fixture('generated-stale'), 'deny.toml'), 'utf8'), before);
});

test('regenerating a stale artifact makes the check pass', () => {
  const root = scratch('generated-stale');
  try {
    const write = run(root);
    assert.equal(write.status, 0);
    assert.match(write.stdout, /wrote deny\.toml/);
    assert.match(readFileSync(join(root, 'deny.toml'), 'utf8'), /"ISC",/);
    assert.equal(run(root, '--check').status, 0);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('a generator whose inputs do not exist yet is skipped, not failed', () => {
  // This is the state of the repository before the Cargo workspace lands: the
  // check has to pass, and has to say why it had nothing to do.
  const result = run(fixture('generated-absent'), '--check');
  assert.equal(result.status, 0);
  assert.match(result.stdout, /deny-allowed-licenses: skipped, not present yet \(deny\.toml\)/);
});

test('an unsorted policy table fails rather than producing churn', () => {
  const root = scratch('generated-fresh');
  try {
    const path = join(root, '.github', 'dependency-policy.md');
    writeFileSync(
      path,
      readFileSync(path, 'utf8').replace('| `Apache-2.0` | fixture |\n| `ISC` | fixture |', '| `ISC` | fixture |\n| `Apache-2.0` | fixture |'),
    );
    const result = run(root, '--check');
    assert.equal(result.status, 1);
    assert.match(result.stdout, /FAILED: .*sorted/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('a missing generated region is a failure, not a silent rewrite', () => {
  assert.throws(
    () => replaceRegion('nothing here\n', 'allowed-licenses', 'allow = []', 'fixture.toml'),
    /missing the "allowed-licenses" generated region markers/,
  );
});

test('replaceRegion keeps everything outside the markers', () => {
  const text = [
    'before',
    '# --- BEGIN GENERATED: allowed-licenses ---',
    'old',
    '# --- END GENERATED: allowed-licenses ---',
    'after',
    '',
  ].join('\n');
  assert.equal(
    replaceRegion(text, 'allowed-licenses', 'new', 'fixture.toml'),
    text.replace('old', 'new'),
  );
});
