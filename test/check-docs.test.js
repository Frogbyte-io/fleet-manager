// test/check-docs.test.js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const script = join(dirname(fileURLToPath(import.meta.url)), '..', 'scripts', 'check-docs.mjs');

function runOn(files) {
  const dir = mkdtempSync(join(tmpdir(), 'fleet-manager-docs-test-'));
  try {
    for (const [name, body] of Object.entries(files)) writeFileSync(join(dir, name), body);
    return spawnSync(process.execPath, [script, dir], { encoding: 'utf8' });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

const target = '# B\n\n## Second heading\n';

test('accepts links whose file and anchor both resolve', () => {
  const result = runOn({
    'a.md': '# Title\n\n[file](b.md) [anchor](b.md#second-heading) [self](#title)\n',
    'b.md': target,
  });
  assert.equal(result.status, 0, result.stderr);
});

test('rejects a link to a missing file', () => {
  const result = runOn({ 'a.md': '# Title\n\n[gone](nope.md)\n' });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /a\.md:3: \[gone\] -> missing nope\.md/);
});

test('rejects a fragment with no matching heading', () => {
  const result = runOn({ 'a.md': '# Title\n\n[frag](b.md#missing) [own](#nothing)\n', 'b.md': target });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /no heading matches #missing in b\.md/);
  assert.match(result.stderr, /no heading matches #nothing/);
});

test('ignores links inside fenced code blocks and external URLs', () => {
  const result = runOn({
    'a.md': '# Title\n\n[ext](https://example.com/nope.md)\n\n```\n[tree](does-not-exist.md)\n```\n',
  });
  assert.equal(result.status, 0, result.stderr);
});

test('slugs an em dash heading the way GitHub does', () => {
  const result = runOn({
    'a.md': '# Title\n\n[issue](b.md#fm-000--review-and-accept)\n',
    'b.md': '# B\n\n### FM-000 — Review and accept\n',
  });
  assert.equal(result.status, 0, result.stderr);
});

test('disambiguates repeated headings with a numeric suffix', () => {
  const result = runOn({
    'a.md': '# Title\n\n[first](b.md#context) [second](b.md#context-1)\n',
    'b.md': '# B\n\n## Context\n\n## Context\n',
  });
  assert.equal(result.status, 0, result.stderr);
});
