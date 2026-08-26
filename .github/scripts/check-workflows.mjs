#!/usr/bin/env node
// Structural checks on the workflows themselves.
//
//   node .github/scripts/check-workflows.mjs [root]
//
// "CI has no deployment credentials" is a property that decays silently: the
// workflow that adds a secret looks exactly like the workflow that does not.
// This asserts the property instead of documenting it, and covers the two
// neighbouring supply-chain footguns — an over-broad GITHUB_TOKEN and a
// third-party action pinned to a mutable tag.
import { readdirSync, readFileSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse } from 'yaml';

const repoRoot = resolve(join(dirname(fileURLToPath(import.meta.url)), '..', '..'));

// Triggers that hand a write-scoped token to a run whose inputs a fork controls.
const FORBIDDEN_TRIGGERS = ['pull_request_target'];
// The only secret CI may use: the ephemeral, per-run, read-scoped token.
const ALLOWED_SECRET = 'GITHUB_TOKEN';

function yamlFiles(dir) {
  const out = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...yamlFiles(full));
    else if (/\.ya?ml$/.test(entry.name)) out.push(full);
  }
  return out;
}

function collectUses(node, out = []) {
  if (Array.isArray(node)) {
    for (const item of node) collectUses(item, out);
  } else if (node && typeof node === 'object') {
    if (typeof node.uses === 'string') out.push(node.uses);
    for (const value of Object.values(node)) collectUses(value, out);
  }
  return out;
}

/**
 * Applies the least-privilege rule to one `permissions` block. Only `contents`
 * may be granted write: everything else in the list is a way to publish.
 */
function permissionProblems(name, where, permissions) {
  if (permissions === 'write-all') return [`${name}: permissions: write-all ${where}`];
  if (typeof permissions !== 'object' || permissions === null) return [];
  return Object.entries(permissions)
    .filter(([scope, level]) => level === 'write' && scope !== 'contents')
    .map(([scope]) => `${name}: grants ${scope}: write ${where}; CI publishes nothing`);
}

function checkFile(root, file, isWorkflow) {
  const name = relative(root, file).split('\\').join('/');
  const text = readFileSync(file, 'utf8');
  const problems = [];

  let document;
  try {
    document = parse(text);
  } catch (error) {
    return [`${name}: not parseable as YAML: ${error.message}`];
  }
  if (!document || typeof document !== 'object') return [`${name}: empty or non-mapping YAML document`];

  for (const [, secret] of text.matchAll(/\$\{\{\s*secrets\.([A-Za-z0-9_-]+)/g)) {
    if (secret !== ALLOWED_SECRET) {
      problems.push(
        `${name}: references secrets.${secret}. CI holds no deployment credentials; ` +
          'publishing and deployment are out of scope for this pipeline.',
      );
    }
  }

  for (const used of collectUses(document)) {
    // A local composite action is this repository's own code.
    if (used.startsWith('./')) continue;
    const at = used.lastIndexOf('@');
    if (at <= 0) {
      problems.push(`${name}: action ${JSON.stringify(used)} is not pinned to a version`);
      continue;
    }
    const action = used.slice(0, at);
    const version = used.slice(at + 1);
    // First-party actions are trusted by tag; anything else must be immutable.
    if (action.startsWith('actions/') || action.startsWith('github/')) continue;
    if (!/^[0-9a-f]{40}$/.test(version)) {
      problems.push(`${name}: third-party action ${action} must be pinned to a full commit SHA, not ${JSON.stringify(version)}`);
    }
  }

  if (!isWorkflow) return problems;

  const triggers = document.on;
  const triggerNames = Array.isArray(triggers)
    ? triggers
    : typeof triggers === 'string'
      ? [triggers]
      : Object.keys(triggers ?? {});
  for (const trigger of FORBIDDEN_TRIGGERS) {
    if (triggerNames.includes(trigger)) {
      problems.push(`${name}: uses the ${trigger} trigger, which runs fork-controlled input with a writable token`);
    }
  }

  if (document.permissions === undefined) {
    problems.push(`${name}: no top-level permissions block; GITHUB_TOKEN would inherit the repository default`);
  } else {
    problems.push(...permissionProblems(name, 'at the workflow level', document.permissions));
  }

  // A job may narrow the workflow's permissions, and may also widen them. A
  // `packages: write` or `id-token: write` on one job is a publishing
  // credential however deep in the file it is written, so jobs are held to the
  // same rule rather than trusted because the top of the file looked fine.
  for (const [id, job] of Object.entries(document.jobs ?? {})) {
    if (job?.permissions === undefined) continue;
    problems.push(...permissionProblems(name, `on job ${id}`, job.permissions));
  }

  return problems;
}

/** @returns {{ok: boolean, lines: string[], problems: string[]}} */
export function checkWorkflows(root) {
  const lines = [];
  const problems = [];
  for (const [dir, isWorkflow] of [
    [join(root, '.github', 'workflows'), true],
    [join(root, '.github', 'actions'), false],
  ]) {
    let files;
    try {
      files = yamlFiles(dir);
    } catch {
      lines.push(`- ${relative(root, dir)}: not present, skipped`);
      continue;
    }
    lines.push(`- ${relative(root, dir)}: ${files.length} file(s) checked`);
    for (const file of files) problems.push(...checkFile(root, file, isWorkflow));
  }
  return { ok: problems.length === 0, lines, problems };
}

function main(argv) {
  const root = resolve(argv[0] ?? repoRoot);
  const { ok, lines, problems } = checkWorkflows(root);
  for (const line of lines) console.log(line);
  if (ok) {
    console.log('Workflows declare least-privilege permissions and use no deployment credentials.');
    return 0;
  }
  console.error(`Workflow policy violations (${problems.length}):`);
  for (const problem of problems) console.error(`  ${problem}`);
  console.error('::error::A workflow violates the CI credential or action-pinning policy. See .github/SECURITY.md.');
  return 1;
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))) {
  process.exit(main(process.argv.slice(2)));
}
