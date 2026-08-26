// The registry of generated artifacts.
//
// A generated artifact is any tracked file that is derived from another tracked
// file. `generate.mjs` runs every entry here; `generate.mjs --check` runs them
// and fails if the result differs from what is committed, which is how a stale
// artifact is caught before review rather than after.
//
// Adding one: append an entry. `requires` lets an entry stay dormant until the
// workspace it belongs to exists, so this file is safe to extend from an issue
// that lands before its workspace does.
//
//   #22  Cargo.lock / workspace member lists
//   #30  pnpm workspace manifests
//   #31  the root verification command's generated outputs
//   #26  the OpenAPI document and the generated TypeScript client
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { readPolicy, POLICY_PATH } from './policy.mjs';

/**
 * Replaces the text between two marker lines, keeping the markers themselves.
 * Generated regions are used instead of whole generated files so that a config
 * file can stay hand-editable everywhere except the part we derive.
 */
export function replaceRegion(text, name, body, source) {
  const begin = `# --- BEGIN GENERATED: ${name} ---`;
  const end = `# --- END GENERATED: ${name} ---`;
  const beginAt = text.indexOf(begin);
  const endAt = text.indexOf(end);
  if (beginAt === -1 || endAt === -1 || endAt < beginAt) {
    throw new Error(`${source}: missing the "${name}" generated region markers`);
  }
  return `${text.slice(0, beginAt + begin.length)}\n${body}\n${text.slice(endAt)}`;
}

const DENY_PATH = 'deny.toml';

/** @type {ReadonlyArray<{id: string, description: string, requires: string[], outputs: string[], run: (root: string) => void}>} */
export const generators = [
  {
    id: 'deny-allowed-licenses',
    description: `the [licenses] allow list in ${DENY_PATH}, from ${POLICY_PATH}`,
    requires: [DENY_PATH, POLICY_PATH],
    outputs: [DENY_PATH],
    run(root) {
      const { allowed } = readPolicy(root);
      const path = join(root, DENY_PATH);
      const body = ['allow = [', ...allowed.map((id) => `    "${id}",`), ']'].join('\n');
      writeFileSync(path, replaceRegion(readFileSync(path, 'utf8'), 'allowed-licenses', body, DENY_PATH));
    },
  },
];
