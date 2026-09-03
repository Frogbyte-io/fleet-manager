#!/usr/bin/env bash
# Validates .github/toolchain.env and loads it into a GitHub Actions step.
#
#   load-toolchain-env.sh <env-file>
#
# Extracted from .github/actions/setup-toolchain/action.yml so the strict
# parser is executable and testable outside a runner; load-toolchain-env.test.mjs
# exercises it. Every CI job loads its pinned versions through here, so the
# rules below apply to all of them:
#
# - Blank lines and `#` comments are skipped.
# - Anything else must match KEY=VALUE with an uppercase key and a value from
#   [A-Za-z0-9._+-], because the content lands in the job environment.
# - Windows checkouts may hand the file over with CRLF line endings
#   (actions/checkout plus Git's core.autocrlf=true). The file is normalised
#   once into a temporary copy that both the validator and the loader read, so
#   a trailing \r can never reach the job environment — neither through the
#   per-line check nor through the sourcing that follows it.
set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo "usage: $0 <env-file>" >&2
  exit 64
fi
env_file="$1"
if [ ! -f "$env_file" ]; then
  echo "toolchain env file not found: ${env_file}" >&2
  exit 66
fi
: "${GITHUB_ENV:?GITHUB_ENV must be set}"
: "${GITHUB_OUTPUT:?GITHUB_OUTPUT must be set}"

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
tr -d '\r' < "$env_file" > "$tmp"

while IFS= read -r line || [ -n "$line" ]; do
  case "$line" in ''|'#'*) continue ;; esac
  # Strict KEY=VALUE only: this content lands in the job environment.
  if ! printf '%s\n' "$line" | grep -Eq '^[A-Z][A-Z0-9_]*=[A-Za-z0-9._+-]+$'; then
    echo "::error file=.github/toolchain.env::not a plain KEY=VALUE line: ${line}"
    exit 1
  fi
  printf '%s\n' "$line" >> "$GITHUB_ENV"
  echo "pinned ${line}"
done < "$tmp"

# Sourcing is safe: every line was just validated as plain KEY=VALUE, and the
# file was normalised above, so a value can no longer carry a trailing \r.
set -a; . "$tmp"; set +a
: "${NODE_VERSION:?NODE_VERSION missing from .github/toolchain.env}"
: "${PNPM_VERSION:?PNPM_VERSION missing from .github/toolchain.env}"
echo "node=${NODE_VERSION}" >> "$GITHUB_OUTPUT"
