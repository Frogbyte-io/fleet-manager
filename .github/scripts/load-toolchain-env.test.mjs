// Proves the toolchain.env loader keeps its strict KEY=VALUE contract while
// tolerating the CRLF line endings a Windows checkout can produce
// (actions/checkout with core.autocrlf=true). The regression this guards is
// CI-only — the parser saw lone \r lines and rejected them before any Rust
// step ran — so the case is exercised here on every platform instead.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const script = join(here, 'load-toolchain-env.sh');

/** @returns {{dir: string, githubEnv: string, githubOutput: string}} */
function sandbox() {
  const dir = mkdtempSync(join(tmpdir(), 'toolchain-env-'));
  return { dir, githubEnv: join(dir, 'github_env'), githubOutput: join(dir, 'github_output') };
}

function run(envFile, { dir, githubEnv, githubOutput }) {
  // The loader reads required keys from the sourced file, but a CI job that
  // already ran setup-toolchain exports them into every later step's
  // environment — including this test process. Strip the toolchain keys so a
  // fixture's completeness decides the outcome, not the runner's.
  const env = { ...process.env, GITHUB_ENV: githubEnv, GITHUB_OUTPUT: githubOutput };
  for (const key of Object.keys(env)) {
    if (/^(NODE|PNPM|COREPACK|CARGO_DENY|GITLEAKS)_/.test(key)) delete env[key];
  }
  return spawnSync('bash', [script, envFile], { encoding: 'utf8', env });
}

const LF_CONTENT = [
  '# comment line',
  '',
  'NODE_VERSION=24.19.0',
  'PNPM_VERSION=9.15.9',
  'COREPACK_VERSION=0.35.0',
  '',
].join('\n');

test('a CRLF file loads exactly like an LF file', () => {
  const crlf = sandbox();
  writeFileSync(join(crlf.dir, 'toolchain.env'), LF_CONTENT.split('\n').join('\r\n'));
  const result = run(join(crlf.dir, 'toolchain.env'), crlf);
  assert.equal(result.status, 0, result.stderr);

  const lf = sandbox();
  writeFileSync(join(lf.dir, 'toolchain.env'), LF_CONTENT);
  const baseline = run(join(lf.dir, 'toolchain.env'), lf);
  assert.equal(baseline.status, 0, baseline.stderr);

  assert.equal(readFileSync(crlf.githubEnv, 'utf8'), readFileSync(lf.githubEnv, 'utf8'));
  assert.equal(readFileSync(crlf.githubOutput, 'utf8'), readFileSync(lf.githubOutput, 'utf8'));
});

test('a CRLF file reaches the job environment without carriage returns', () => {
  const box = sandbox();
  writeFileSync(join(box.dir, 'toolchain.env'), LF_CONTENT.split('\n').join('\r\n'));
  const result = run(join(box.dir, 'toolchain.env'), box);
  assert.equal(result.status, 0, result.stderr);

  const exported = readFileSync(box.githubEnv, 'utf8');
  assert.ok(!exported.includes('\r'), `carriage return reached the job environment: ${JSON.stringify(exported)}`);
  for (const line of ['NODE_VERSION=24.19.0', 'PNPM_VERSION=9.15.9', 'COREPACK_VERSION=0.35.0']) {
    assert.ok(exported.includes(line), `missing ${line}`);
  }
  assert.match(readFileSync(box.githubOutput, 'utf8'), /^node=24\.19\.0$/m);
});

test('a blank CRLF line is skipped, not rejected', () => {
  const box = sandbox();
  writeFileSync(join(box.dir, 'toolchain.env'), 'NODE_VERSION=24.19.0\r\n\r\nPNPM_VERSION=9.15.9\r\n');
  const result = run(join(box.dir, 'toolchain.env'), box);
  assert.equal(result.status, 0, result.stderr);
  assert.match(readFileSync(box.githubEnv, 'utf8'), /NODE_VERSION=24\.19\.0/);
});

test('a value that is not plain KEY=VALUE still fails after normalisation', () => {
  const box = sandbox();
  writeFileSync(join(box.dir, 'toolchain.env'), 'NODE_VERSION=24.19.0\r\nEXPANSION=$(rm -rf /)\r\n');
  const result = run(join(box.dir, 'toolchain.env'), box);
  assert.equal(result.status, 1);
  assert.match(result.stdout, /not a plain KEY=VALUE line/);
});

test('a missing required key fails', () => {
  const box = sandbox();
  writeFileSync(join(box.dir, 'toolchain.env'), 'NODE_VERSION=24.19.0\n');
  const result = run(join(box.dir, 'toolchain.env'), box);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /PNPM_VERSION missing/);
});

test('the repository toolchain.env itself loads cleanly', () => {
  const box = sandbox();
  const result = run(join(here, '..', 'toolchain.env'), box);
  assert.equal(result.status, 0, result.stderr);
  const exported = readFileSync(box.githubEnv, 'utf8');
  for (const key of ['NODE_VERSION', 'PNPM_VERSION', 'COREPACK_VERSION', 'CARGO_DENY_VERSION', 'GITLEAKS_VERSION', 'GITLEAKS_SHA256']) {
    assert.match(exported, new RegExp(`^${key}=[A-Za-z0-9._+-]+$`, 'm'), `missing ${key}`);
  }
  assert.ok(!exported.includes('\r'), 'carriage return reached the job environment');
});
