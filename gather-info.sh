#!/usr/bin/env bash
# Run this against a new machine (over SSH) to collect the fields needed to fill
# out a new entry in AGENTS.md. Read-only — makes no changes on the target.
#
# Usage: ssh <alias-or-user@host> bash -s < gather-info.sh
set -uo pipefail

echo "=== hostname ==="
hostnamectl 2>/dev/null | head -20 || hostname

echo "=== os-release ==="
cat /etc/os-release 2>/dev/null

echo "=== kernel/arch ==="
uname -a

echo "=== timezone ==="
timedatectl 2>/dev/null | grep -i "time zone"

echo "=== desktop environment ==="
echo "XDG_CURRENT_DESKTOP=${XDG_CURRENT_DESKTOP:-<none, likely headless>}"
dpkg -l 2>/dev/null | grep -Ei 'gnome-shell|plasma-desktop|xfce4-session|budgie-desktop|cinnamon-session|mate-session' | awk '{print $2, $3}'
rpm -qa 2>/dev/null | grep -Ei 'gnome-shell|plasma-desktop|xfce4-session'

echo "=== tailscale ==="
command -v tailscale >/dev/null && tailscale ip -4 2>/dev/null || echo "tailscale not installed / not running"

echo "=== ssh host key fingerprints ==="
for f in /etc/ssh/ssh_host_*.pub; do ssh-keygen -lf "$f" 2>/dev/null; done

echo "=== authorized_keys fingerprints (this user) ==="
if [ -f ~/.ssh/authorized_keys ]; then
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    echo "$line" | ssh-keygen -lf /dev/stdin 2>/dev/null
  done < ~/.ssh/authorized_keys
fi

echo "=== package manager ==="
for pm in apt dnf pacman zypper apk; do command -v $pm >/dev/null && echo "$pm"; done

echo "=== cpu/mem ==="
nproc 2>/dev/null
free -h 2>/dev/null | grep Mem

echo "=== dev tools present ==="
for t in docker git python3 node tmux code; do
  command -v $t >/dev/null && echo "$t: $($t --version 2>&1 | head -1)"
done
