#!/usr/bin/env bash
# Pulls the latest agents-registry changes and re-runs setup.sh if anything moved.
# Invoked periodically by the agents-registry-sync systemd --user timer (see setup.sh).
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_DIR"

BEFORE="$(git rev-parse HEAD)"
git fetch --quiet origin
git pull --ff-only --quiet
AFTER="$(git rev-parse HEAD)"

if [ "$BEFORE" != "$AFTER" ]; then
  echo "agents-registry: updated $BEFORE -> $AFTER, re-running setup.sh"
  "$REPO_DIR/setup.sh"
else
  echo "agents-registry: no changes ($AFTER)"
fi
