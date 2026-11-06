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
# --purge deletes the state directory recursively with privilege, so it
# deletes only a directory that is fleetd's own: a real directory (not a
# symlink), owned by the service account (`fleet`; by the invoking non-root
# user when that account does not exist, as install.sh does without it), not
# a system directory, and either empty or holding fleetd's node key
# (`node.key`). Anything else is refused before anything is removed.
#
# A service that cannot be stopped is not removed either: with the unit
# present, a failing `systemctl disable --now` stops the uninstall; with the
# unit gone, a service systemd still reports active does.
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
SERVICE_USER=fleet

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

# What --purge will do with the state directory: "absent" (nothing there),
# "empty" (rmdir) or "state" (fleetd's own state, removed recursively).
# Refuses, removing nothing, unless the directory is fleetd's own.
purge_plan() {
    refuse() { die "refusing to purge $STATE_DIR: $1; nothing was removed"; }
    if [ -L "$STATE_DIR" ]; then
        refuse "it is a symbolic link"
    fi
    if [ ! -e "$STATE_DIR" ]; then
        PURGE_PLAN=absent
        return
    fi
    [ -d "$STATE_DIR" ] || refuse "it is not a directory"
    local normalized
    normalized="$(printf '%s' "$STATE_DIR" | tr -s '/' | sed 's:/*$::')"
    case "${normalized:-/}" in
        /|/bin|/boot|/dev|/etc|/home|/lib|/lib32|/lib64|/libx32|/media|/mnt|/opt|/proc|/root|/run|/sbin|/snap|/srv|/sys|/tmp|/usr|/var|/etc/*|/root/*|/usr/*|/var/lib|/var/log|/var/tmp|/var/cache|/var/spool|/var/run|/var/run/*|/run/user|/run/user/*|/proc/*|/sys/*|/dev/*|/boot/*)
            refuse "it is a system directory" ;;
    esac
    local owner expected
    owner="$(stat -c %U "$STATE_DIR" 2>/dev/null)" || refuse "its owner cannot be read"
    if getent passwd "$SERVICE_USER" >/dev/null 2>&1; then
        expected="$SERVICE_USER"
    elif [ "$IS_ROOT" = true ]; then
        refuse "there is no $SERVICE_USER account, so the directory cannot be fleetd's"
    else
        expected="$(id -un)"
    fi
    [ "$owner" = "$expected" ] || refuse "it is owned by $owner, not $expected"
    if [ -z "$("${RUN_PRIV[@]}" find "$STATE_DIR" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null)" ]; then
        PURGE_PLAN=empty
        return
    fi
    "${RUN_PRIV[@]}" test -f "$STATE_DIR/node.key" \
        && ! "${RUN_PRIV[@]}" test -L "$STATE_DIR/node.key" \
        || refuse "it does not hold fleetd's node key (node.key)"
    PURGE_PLAN=state
}

PURGE_PLAN=absent
if [ "$PURGE" = true ]; then
    purge_plan
fi

# A service that cannot be stopped is not removed: deleting its files under
# a running fleetd would leave it running without a unit.
if [ -e "$UNIT" ]; then
    "${RUN_PRIV[@]}" "$SYSTEMCTL" disable --now "$SERVICE" >/dev/null 2>&1 \
        || die "cannot stop and disable $SERVICE ($SYSTEMCTL disable --now failed); nothing was removed"
elif "${RUN_PRIV[@]}" "$SYSTEMCTL" is-active --quiet "$SERVICE" >/dev/null 2>&1; then
    die "$SERVICE is still active but its unit $UNIT is not there (installed elsewhere?); nothing was removed"
fi
"${RUN_PRIV[@]}" rm -f "$UNIT" || die "cannot remove $UNIT"
"${RUN_PRIV[@]}" rm -f "$ENV_FILE" || true
"${RUN_PRIV[@]}" rm -f "$BIN" || true
"${RUN_PRIV[@]}" "$SYSTEMCTL" daemon-reload >/dev/null 2>&1 || true

if [ "$PURGE" = true ]; then
    case "$PURGE_PLAN" in
        state) "${RUN_PRIV[@]}" rm -rf -- "$STATE_DIR" || die "cannot purge $STATE_DIR" ;;
        empty) "${RUN_PRIV[@]}" rmdir -- "$STATE_DIR" || die "cannot purge $STATE_DIR" ;;
        absent) ;;
    esac
    log "service removed and state purged; the next install enrolls fresh"
else
    log "service removed; enrollment state kept at $STATE_DIR"
    log "a reinstall will re-prove the same identity"
fi
