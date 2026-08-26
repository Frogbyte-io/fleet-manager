// Reads the allowed-license set out of .github/dependency-policy.md.
//
// The policy document is the source of truth on purpose: the rationale for
// admitting a license has to live next to the license, and a table a human
// wrote is the thing a reviewer actually reads. Everything machine-readable —
// the `allow` list in deny.toml, the Node lockfile check — derives from here.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

export const POLICY_PATH = join('.github', 'dependency-policy.md');
const ALLOW_HEADING = '## Allowed inbound licenses';

/**
 * Extracts the first column of the Markdown table under `heading`.
 * Cells are expected to be backticked SPDX identifiers.
 */
function tableIdentifiers(text, heading, source) {
  const lines = text.split('\n');
  const start = lines.findIndex((line) => line.trim() === heading);
  if (start === -1) throw new Error(`${source}: no "${heading}" section`);

  const ids = [];
  let sawTable = false;
  for (const line of lines.slice(start + 1)) {
    const trimmed = line.trim();
    if (trimmed.startsWith('#')) break;
    if (!trimmed.startsWith('|')) {
      if (sawTable) break;
      continue;
    }
    sawTable = true;
    const first = trimmed.split('|')[1]?.trim() ?? '';
    // The header row and the |---| separator are not identifiers.
    if (/^:?-{2,}:?$/.test(first) || first === '' || !first.startsWith('`')) continue;
    const match = /^`([^`]+)`$/.exec(first);
    if (!match) throw new Error(`${source}: table cell ${JSON.stringify(first)} is not a backticked SPDX identifier`);
    ids.push(match[1]);
  }

  if (ids.length === 0) throw new Error(`${source}: the "${heading}" table lists no identifiers`);
  return ids;
}

/** Reads the inbound dependency policy from a repository root. */
export function readPolicy(root) {
  const path = join(root, POLICY_PATH);
  let text;
  try {
    text = readFileSync(path, 'utf8');
  } catch {
    throw new Error(`${POLICY_PATH} is missing; it is the source of truth for allowed licenses`);
  }

  const allowed = tableIdentifiers(text, ALLOW_HEADING, POLICY_PATH);
  const duplicates = allowed.filter((id, index) => allowed.indexOf(id) !== index);
  if (duplicates.length > 0) {
    throw new Error(`${POLICY_PATH}: duplicate license identifiers: ${[...new Set(duplicates)].join(', ')}`);
  }
  const misordered = [...allowed].sort((a, b) => a.localeCompare(b, 'en'));
  if (misordered.join('\n') !== allowed.join('\n')) {
    throw new Error(`${POLICY_PATH}: keep the allowed-license table sorted so generated output stays stable`);
  }

  return { allowed: Object.freeze(allowed) };
}
