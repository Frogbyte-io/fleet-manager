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

chmod +x "$REPO_DIR/sync.sh"

# --- Periodic sync: systemd --user timer that pulls latest changes and re-runs
# setup.sh whenever the pull brings new commits. Runs every 30 min, no sudo needed. ---
SYSTEMD_USER_DIR="$HOME/.config/systemd/user"
mkdir -p "$SYSTEMD_USER_DIR"

cat > "$SYSTEMD_USER_DIR/agents-registry-sync.service" <<EOF
[Unit]
Description=Pull latest agents-registry and re-run setup.sh if changed

[Service]
Type=oneshot
WorkingDirectory=$REPO_DIR
ExecStart=$REPO_DIR/sync.sh
EOF

cp "$REPO_DIR/systemd/agents-registry-sync.timer" "$SYSTEMD_USER_DIR/agents-registry-sync.timer"

if command -v systemctl >/dev/null 2>&1 && systemctl --user daemon-reload 2>/dev/null; then
  systemctl --user enable --now agents-registry-sync.timer
  echo "Enabled agents-registry-sync.timer (systemctl --user) — syncs every 30 min."
  echo "To keep syncing after you log out, run: sudo loginctl enable-linger \$(whoami)"
else
  echo "systemd --user unavailable in this session — skipping periodic sync timer."
  echo "Unit files were written to $SYSTEMD_USER_DIR; re-run 'systemctl --user daemon-reload && systemctl --user enable --now agents-registry-sync.timer' once a user systemd session is available."
fi

echo "Done. Don't forget to add matching Host entries to ~/.ssh/config (see ssh-config.example)."
