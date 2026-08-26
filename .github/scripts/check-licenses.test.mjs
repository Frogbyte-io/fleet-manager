// Proves the acceptance criterion that the policy "fails on a license outside
// the Apache-2.0-compatible inbound set" — against fixture lockfiles, so the
// proof does not depend on what the real dependency tree happens to contain.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { satisfies } from './lib/spdx.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const script = join(here, 'check-licenses.mjs');
const fixture = (name) => join(here, '__fixtures__', name);

function run(name) {
  return spawnSync(process.execPath, [script, fixture(name)], { encoding: 'utf8' });
}

test('a copyleft dependency fails the check', () => {
  const result = run('licenses-rejected');
  assert.equal(result.status, 1);
  assert.match(result.stderr, /copyleft@6\.6\.6: GPL-3\.0-only is not in the allowed inbound set/);
  assert.match(result.stderr, /Apache-2\.0-compatible inbound set/);
});

test('an AND expression fails when either half is disallowed', () => {
  const result = run('licenses-rejected');
  assert.match(result.stderr, /dual-copyleft@1\.2\.3: \(MIT AND GPL-3\.0-only\)/);
});

test('permissive and dual-licensed dependencies pass', () => {
  const result = run('licenses-accepted');
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /4 package\(s\) checked, 0 rejected/);
});

test('a dependency with no recorded license fails', () => {
  // Absence of a grant is not a permissive grant.
  const result = run('licenses-unknown');
  assert.equal(result.status, 1);
  assert.match(result.stderr, /undeclared@1\.0\.0: no license recorded/);
});

test('the repository itself satisfies the policy', () => {
  const result = spawnSync(process.execPath, [script, join(here, '..', '..')], { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
});

test('SPDX expressions are evaluated, not string-matched', () => {
  const allowed = ['MIT', 'Apache-2.0', 'Apache-2.0 WITH LLVM-exception'];
  assert.equal(satisfies('MIT', allowed), true);
  assert.equal(satisfies('(MIT OR GPL-3.0-only)', allowed), true);
  assert.equal(satisfies('(GPL-3.0-only OR AGPL-3.0-only)', allowed), false);
  assert.equal(satisfies('MIT AND Apache-2.0', allowed), true);
  assert.equal(satisfies('MIT AND GPL-3.0-only', allowed), false);
  assert.equal(satisfies('Apache-2.0 WITH LLVM-exception', allowed), true);
  // The exception is part of the identifier: allowing the bare license does not
  // allow every variant of it, and vice versa.
  assert.equal(satisfies('Apache-2.0 WITH Bison-exception-2.2', allowed), false);
  assert.equal(satisfies('mit', allowed), true, 'SPDX identifiers are case-insensitive');
  assert.equal(satisfies('(MIT AND (ISC OR Apache-2.0))', allowed), true);
});

test('a malformed license expression is reported, not ignored', () => {
  assert.throws(() => satisfies('MIT OR', ['MIT']), /unexpected end of license expression/);
  assert.throws(() => satisfies('(MIT', ['MIT']), /unbalanced parentheses/);
  assert.throws(() => satisfies('MIT WITH', ['MIT']), /dangling WITH/);
});
