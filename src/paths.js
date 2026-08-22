import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const THIS_FILE = fileURLToPath(import.meta.url);

/** Repo root, resolved relative to this file rather than process.cwd() so the CLI works from any directory. */
export function repoRoot() {
  return join(dirname(THIS_FILE), '..');
}
