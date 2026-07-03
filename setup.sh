#!/usr/bin/env bash
# Wires this repo's AGENTS.md into both Claude Code and Codex CLI on the current
# machine. Safe to re-run (idempotent).
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AGENTS_FILE="$REPO_DIR/AGENTS.md"

if [ ! -f "$AGENTS_FILE" ]; then
  echo "Error: AGENTS.md not found at $AGENTS_FILE" >&2
  exit 1
fi

# --- Codex CLI: symlink ~/.codex/AGENTS.md -> this repo's AGENTS.md ---
mkdir -p "$HOME/.codex"
if [ -e "$HOME/.codex/AGENTS.md" ] && [ ! -L "$HOME/.codex/AGENTS.md" ]; then
  echo "~/.codex/AGENTS.md already exists and isn't a symlink — backing it up to AGENTS.md.bak"
  mv "$HOME/.codex/AGENTS.md" "$HOME/.codex/AGENTS.md.bak"
fi
ln -sf "$AGENTS_FILE" "$HOME/.codex/AGENTS.md"
echo "Linked ~/.codex/AGENTS.md -> $AGENTS_FILE"

# --- Claude Code: append an @import line to ~/.claude/CLAUDE.md ---
mkdir -p "$HOME/.claude"
touch "$HOME/.claude/CLAUDE.md"
IMPORT_LINE="@$AGENTS_FILE"
if ! grep -qF "$IMPORT_LINE" "$HOME/.claude/CLAUDE.md"; then
  {
    echo ""
    echo "## Machine registry"
    echo "$IMPORT_LINE"
  } >> "$HOME/.claude/CLAUDE.md"
  echo "Added import line to ~/.claude/CLAUDE.md"
else
  echo "~/.claude/CLAUDE.md already imports this registry — nothing to do"
fi

echo "Done. Don't forget to add matching Host entries to ~/.ssh/config (see ssh-config.example)."
