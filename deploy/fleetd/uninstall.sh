#!/usr/bin/env bash
# Remove the fleetd system service. The node's identity state
# (/var/lib/fleetd: key, credential, journal, inventory) is preserved by
# default so a reinstall keeps the machine's enrollment; pass --purge to
# delete it as well.
#
# Re-enrollment behavior (documented, FM-211): with the state kept, a
# reinstall re-proves the same identity and never needs a new token. With
# --purge (or after the machine's node identity is revoked), a reinstall
# enrolls fresh: create a new single-use token for the machine and install
# again — the controller supports rebinding an existing machine to a new key.
#
# The invoking account needs real root or passwordless sudo, like install.sh.
# The same layout overrides are honored (FLEETD_BIN_DIR, FLEETD_UNIT_DIR,
# FLEETD_ENV_FILE, FLEETD_STATE_DIR, FLEETD_SERVICE, FLEETD_SYSTEMCTL).

set -u

die() { printf 'uninstall: %s\n' "$1" >&2; exit 1; }
log() { printf 'uninstall: %s\n' "$1"; }

STATE_DIR="${FLEETD_STATE_DIR:-/var/lib/fleetd}"
BIN_DIR="${FLEETD_BIN_DIR:-/usr/local/bin}"
UNIT_DIR="${FLEETD_UNIT_DIR:-/etc/systemd/system}"
ENV_FILE="${FLEETD_ENV_FILE:-/etc/default/fleetd}"
SERVICE="${FLEETD_SERVICE:-fleetd}"
SYSTEMCTL="${FLEETD_SYSTEMCTL:-systemctl}"

IS_ROOT=false
[ "$(id -u)" = "0" ] && IS_ROOT=true
if [ "$IS_ROOT" = true ]; then
    RUN_PRIV=()
elif sudo -n true >/dev/null 2>&1; then
    RUN_PRIV=(sudo -n)
else
    RUN_PRIV=()
fi

PURGE=false
[ "${1:-}" = "--purge" ] && PURGE=true

BIN="$BIN_DIR/fleetd"
UNIT="$UNIT_DIR/$SERVICE.service"

"${RUN_PRIV[@]}" "$SYSTEMCTL" disable --now "$SERVICE" >/dev/null 2>&1 || true
"${RUN_PRIV[@]}" rm -f "$UNIT" || die "cannot remove $UNIT"
"${RUN_PRIV[@]}" rm -f "$ENV_FILE" || true
"${RUN_PRIV[@]}" rm -f "$BIN" || true
"${RUN_PRIV[@]}" "$SYSTEMCTL" daemon-reload >/dev/null 2>&1 || true

if [ "$PURGE" = true ]; then
    "${RUN_PRIV[@]}" rm -rf "$STATE_DIR" || die "cannot purge $STATE_DIR"
    log "service removed and state purged; the next install enrolls fresh"
else
    log "service removed; enrollment state kept at $STATE_DIR"
    log "a reinstall will re-prove the same identity"
fi
