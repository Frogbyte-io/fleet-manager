#!/usr/bin/env node
// Regenerates the client into a temporary directory and compares it with the
// committed copy. It never rewrites in place: a stale client must fail the
// build rather than be silently corrected, because the difference between the
// two is exactly the API change nobody reviewed.

import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const packageRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const committed = join(packageRoot, 'src/generated/fleet.ts');
const scratch = mkdtempSync(join(tmpdir(), 'fleet-api-client-'));
const regenerated = join(scratch, 'fleet.ts');

try {
  execFileSync('node_modules/.bin/orval', ['--config', 'orval.config.ts'], {
    cwd: packageRoot,
    env: { ...process.env, FLEET_API_CLIENT_TARGET: regenerated },
    stdio: 'inherit',
  });

  const expected = readFileSync(regenerated, 'utf8');
  const actual = readFileSync(committed, 'utf8');

  if (expected !== actual) {
    const expectedLines = expected.split('\n');
    const actualLines = actual.split('\n');
    const at = actualLines.findIndex((line, index) => line !== expectedLines[index]);
    console.error('[FM_API_CLIENT_STALE] the committed client does not match openapi.json.');
    console.error(`First difference at line ${at + 1}:`);
    console.error(`  committed:   ${actualLines[at] ?? '<end of file>'}`);
    console.error(`  regenerated: ${expectedLines[at] ?? '<end of file>'}`);
    console.error('Run `pnpm --filter @frogbyte-io/fleet-api-client generate` and commit the result.');
    process.exit(1);
  }

  console.log('src/generated/fleet.ts is up to date');
} finally {
  rmSync(scratch, { recursive: true, force: true });
}
