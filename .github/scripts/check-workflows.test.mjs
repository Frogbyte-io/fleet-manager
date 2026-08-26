// "CI has no deployment credentials" is an acceptance criterion that decays
// silently, so it is asserted rather than documented. The violating fixture
// carries every violation at once; if a check is removed, one of these fails.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const script = join(here, 'check-workflows.mjs');
const repoRoot = join(here, '..', '..');
const fixture = (name) => join(here, '__fixtures__', name);

function run(root) {
  return spawnSync(process.execPath, [script, root], { encoding: 'utf8' });
}

test('a workflow with a deployment secret fails', () => {
  const result = run(fixture('workflows-violating'));
  assert.equal(result.status, 1);
  assert.match(result.stderr, /references secrets\.REGISTRY_TOKEN/);
});

test('an unpinned third-party action fails', () => {
  assert.match(
    run(fixture('workflows-violating')).stderr,
    /some-vendor\/publish-action must be pinned to a full commit SHA/,
  );
});

test('a missing permissions block fails', () => {
  assert.match(run(fixture('workflows-violating')).stderr, /no top-level permissions block/);
});

test('a write permission other than contents fails', () => {
  assert.match(run(fixture('workflows-violating')).stderr, /grants packages: write/);
});

test('a job that widens permissions fails even when the workflow does not', () => {
  // The OIDC write scope is a deployment credential that leaves no secret
  // behind in the workflow to grep for.
  assert.match(run(fixture('workflows-violating')).stderr, /grants id-token: write on job publish/);
});

test('the pull_request_target trigger fails', () => {
  assert.match(run(fixture('workflows-violating')).stderr, /pull_request_target/);
});

test('a compliant workflow passes', () => {
  // Including secrets.GITHUB_TOKEN, a SHA-pinned third-party action, and a
  // local composite action, none of which are violations.
  const result = run(fixture('workflows-clean'));
  assert.equal(result.status, 0, result.stderr);
});

test('this repository holds no deployment credentials', () => {
  const result = run(repoRoot);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /\.github\/workflows: [1-9]\d* file\(s\) checked/);
  assert.match(result.stdout, /\.github\/actions: [1-9]\d* file\(s\) checked/);
});
