// Proves the acceptance criterion that the policy "fails on a license outside
// the Apache-2.0-compatible inbound set" — against fixture lockfiles, so the
// proof does not depend on what the real dependency tree happens to contain.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { checkPnpmLicenses, checkLicenses } from './check-licenses.mjs';
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

const ALLOWED = ['Apache-2.0', 'MIT', 'BlueOak-1.0.0', 'Python-2.0'];

test('a pnpm package outside the allowed set is rejected, naming package and version', () => {
  const report = { 'GPL-3.0-only': [{ name: 'copyleft', versions: ['6.6.6'], license: 'GPL-3.0-only' }] };
  const { checked, problems } = checkPnpmLicenses(report, ALLOWED);
  assert.equal(checked, 1);
  assert.deepEqual(problems, ['copyleft@6.6.6: GPL-3.0-only is not in the allowed inbound set (pnpm graph)']);
});

test('every installed version of a pnpm package is enforced separately', () => {
  const report = {
    BlueOak: [{ name: 'minimatch', versions: ['10.2.6'], license: 'BlueOak-1.0.0' }],
    'GPL-3.0-only': [{ name: 'glob-copyleft', versions: ['1.0.0', '2.0.0'], license: 'GPL-3.0-only' }],
  };
  const { checked, problems } = checkPnpmLicenses(report, ALLOWED);
  assert.equal(checked, 3);
  assert.deepEqual(problems, [
    'glob-copyleft@1.0.0: GPL-3.0-only is not in the allowed inbound set (pnpm graph)',
    'glob-copyleft@2.0.0: GPL-3.0-only is not in the allowed inbound set (pnpm graph)',
  ]);
});

test('a pnpm package with no license field fails like an npm one', () => {
  const report = { Unknown: [{ name: 'undeclared', versions: ['1.0.0'] }] };
  const { problems } = checkPnpmLicenses(report, ALLOWED);
  assert.deepEqual(problems, ['undeclared@1.0.0: no license recorded in the pnpm graph']);
});

test('a pnpm license expression is evaluated, not string-matched', () => {
  const report = { '(MIT OR Apache-2.0)': [{ name: 'dual', versions: ['1.0.0'], license: '(MIT OR Apache-2.0)' }] };
  const { checked, problems } = checkPnpmLicenses(report, ALLOWED);
  assert.equal(checked, 1);
  assert.deepEqual(problems, []);
});

test('a malformed pnpm report is a problem, not a silent pass', () => {
  assert.deepEqual(checkPnpmLicenses(null, ALLOWED).problems, ['pnpm licenses report is not an object']);
  assert.deepEqual(checkPnpmLicenses({ MIT: 'not-a-list' }, ALLOWED).problems, ['pnpm licenses report: MIT is not a package list']);
});

test('the repository pnpm graph satisfies the policy', () => {
  const { ok, lines, problems } = checkLicenses(join(here, '..', '..'));
  const pnpmLine = lines.find((line) => line.includes('pnpm workspace'));
  assert.ok(pnpmLine, `no pnpm graph was checked: ${lines.join(' | ')}`);
  assert.ok(!pnpmLine.includes('skipped'), 'the committed pnpm workspace must be checked, not skipped');
  assert.ok(ok, problems.join('\n'));
});
