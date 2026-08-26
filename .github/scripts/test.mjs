#!/usr/bin/env node
// Runs the tests for the policy scripts.
//
// This exists instead of `node --test '<glob>'` for two reasons. A glob that
// matches nothing makes `node --test` exit 0, so a renamed or relocated test
// file would quietly turn the CI step into a green no-op — the same silent-pass
// failure the workspace jobs are written to avoid. And an unquoted glob in an
// npm script is expanded by sh but not by cmd, so the quoting that works on one
// developer's machine fails on another's.
import { globSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(join(here, '..', '..'));
const pattern = '.github/scripts/**/*.test.mjs';

const files = globSync(pattern, { cwd: repoRoot }).map((file) => join(repoRoot, file)).sort();

if (files.length === 0) {
  console.error(`::error::no test files matched ${pattern}. Running zero tests is a failure, not a pass.`);
  process.exit(1);
}

console.log(`Running ${files.length} policy test file(s):`);
for (const file of files) console.log(`  ${relative(repoRoot, file)}`);

const result = spawnSync(process.execPath, ['--test', ...files], { stdio: 'inherit', cwd: repoRoot });
process.exit(result.status ?? 1);
