import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const packageRoot = join(dirname(fileURLToPath(import.meta.url)), '..');

test('package manifest exposes the agents-registry help command', () => {
  const manifest = JSON.parse(readFileSync(join(packageRoot, 'package.json'), 'utf8'));
  const relativeBin = manifest.bin?.['agents-registry'];
  assert.equal(relativeBin, './bin/agents-registry.js');

  const result = spawnSync(process.execPath, [join(packageRoot, relativeBin), '--help'], {
    encoding: 'utf8',
  });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /agents-registry - declarative fleet\/machine\/skill registry CLI/);
  assert.match(result.stdout, /agents-registry init --repo-url/);
});
