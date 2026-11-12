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
# deletes only a directory that is fleetd's own: an absolute path (trailing
# slashes are stripped first, so `link/` is the link itself), a real
# directory (not a symlink) named by a normalized path (no `//`, `.` or
# `..`), owned by the service account (`fleet`; by the
# invoking non-root user when that account does not exist, as install.sh
# does without it), not a system directory, and either empty or holding
# fleetd's node key (`node.key`). Every ancestor must be a real directory
# owned by root (or, in that stubbed case, by the invoking user), not
# writable by group or others and without a POSIX ACL, so nobody else can
# swap a path component; install.sh applies the same rule before it adopts
# the directory.
# Anything else is refused before anything is removed. The checks run again
# right before the delete, which stays on one file system.
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
# `dir/` would make every test below look through a symlink: strip trailing
# slashes first; nothing left means `/`, which is refused.
while [ "${STATE_DIR%/}" != "$STATE_DIR" ]; do STATE_DIR="${STATE_DIR%/}"; done
STATE_DIR="${STATE_DIR:-/}"
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

# >>> state directory ancestors: kept identical in install.sh and uninstall.sh
# (a test compares the two copies), so the installer never adopts a state
# directory that the purge would refuse.
#
# $STATE_DIR must be an absolute, normalized path (no `//`, `.` or `..`, so
# every test below names the directory `rm` would act on) that is not a
# system directory. Every ancestor must be a real directory (not a symbolic
# link), owned by root, not writable by group or others, and without a POSIX
# ACL. Then nobody else can swap a path component. (On Linux the group mode
# bits already show an ACL's mask, so the ACL test is defense in depth: a
# directory root set up plainly has none.) When the service account does not
# exist and a non-root user runs the script (stubbed installs), the invoking
# user may own an ancestor instead. With `missing-ok` as $1, an ancestor that
# does not exist yet passes: install.sh is about to create it. A failure calls
# refuse_state with the reason.
#
# ACLs are read with `getfacl --skip-base` when it is installed, otherwise from
# the `+` that `ls -ld` prints after the mode of a file that has one. An ACL
# that cannot be read counts as present.
ancestor_has_acl() {
    local listing
    if command -v getfacl >/dev/null 2>&1; then
        listing="$(getfacl --absolute-names --skip-base --omit-header -- "$1" 2>/dev/null)" \
            || return 0
        [ -n "$listing" ]
        return
    fi
    listing="$(ls -ld -- "$1" 2>/dev/null)" || return 0
    [ "${listing:10:1}" = "+" ]
}
check_state_ancestors() {
    local ancestor_owner dir a_owner a_mode
    # A relative path has no ancestors to check (and `dirname .` is `.`).
    case "$STATE_DIR" in
        /*) ;;
        *) refuse_state "it is not an absolute path" ;;
    esac
    # `/home/../var/lib` would pass every lexical test below as something it
    # is not.
    case "$STATE_DIR" in
        *//*|*/./*|*/../*|*/.|*/..)
            refuse_state "it is not a normalized path (no //, . or .. components)" ;;
    esac
    # The ancestor walk starts above the directory itself, so the shared
    # temporary directories (`/tmp`, `/var/tmp`, `/dev/shm`) are named here.
    case "$STATE_DIR" in
        /|/bin|/boot|/dev|/etc|/home|/lib|/lib32|/lib64|/libx32|/media|/mnt|/opt|/proc|/root|/run|/sbin|/snap|/srv|/sys|/tmp|/usr|/var|/etc/*|/root/*|/usr/*|/var/lib|/var/log|/var/tmp|/var/cache|/var/spool|/var/run|/var/run/*|/run/user|/run/user/*|/proc/*|/sys/*|/dev/*|/boot/*)
            refuse_state "it is a system directory" ;;
    esac
    if [ "$IS_ROOT" = true ] || getent passwd "$SERVICE_USER" >/dev/null 2>&1; then
        ancestor_owner=root
    else
        ancestor_owner="$(id -un)"
    fi
    dir="$(dirname -- "$STATE_DIR")"
    while :; do
        if [ -L "$dir" ]; then
            refuse_state "its ancestor $dir is a symbolic link"
        elif [ -e "$dir" ] || [ "${1:-}" != missing-ok ]; then
            [ -d "$dir" ] || refuse_state "its ancestor $dir is not a directory"
            a_owner="$(stat -c %U -- "$dir" 2>/dev/null)" || refuse_state "the owner of $dir cannot be read"
            a_mode="$(stat -c %a -- "$dir" 2>/dev/null)" || refuse_state "the mode of $dir cannot be read"
            [ "$a_owner" = root ] || [ "$a_owner" = "$ancestor_owner" ] \
                || refuse_state "its ancestor $dir is owned by $a_owner, not root"
            [ $(( 8#$a_mode & 8#022 )) -eq 0 ] \
                || refuse_state "its ancestor $dir is writable by group or others (mode $a_mode)"
            ! ancestor_has_acl "$dir" \
                || refuse_state "its ancestor $dir has a POSIX ACL (remove it with setfacl -b)"
        fi
        [ "$dir" = / ] && break
        dir="$(dirname -- "$dir")"
    done
}
# <<< state directory ancestors

refuse_state() { die "refusing to purge $STATE_DIR: $1; nothing was removed"; }

# What --purge will do with the state directory: "absent" (nothing there),
# "empty" (rmdir) or "state" (fleetd's own state, removed recursively).
# Refuses, removing nothing, unless the directory is fleetd's own.
purge_plan() {
    refuse() { refuse_state "$1"; }
    case "$STATE_DIR" in
        /*) ;;
        *) refuse "it is not an absolute path" ;;
    esac
    # Who may own the directory and its ancestors.
    local expected
    if getent passwd "$SERVICE_USER" >/dev/null 2>&1; then
        expected="$SERVICE_USER"
    elif [ "$IS_ROOT" = true ]; then
        refuse "there is no $SERVICE_USER account, so the directory cannot be fleetd's"
    else
        expected="$(id -un)"
    fi
    check_state_ancestors
    if [ -L "$STATE_DIR" ]; then
        refuse "it is a symbolic link"
    fi
    if [ ! -e "$STATE_DIR" ]; then
        PURGE_PLAN=absent
        return
    fi
    [ -d "$STATE_DIR" ] || refuse "it is not a directory"
    local owner
    owner="$(stat -c %U -- "$STATE_DIR" 2>/dev/null)" || refuse "its owner cannot be read"
    [ "$owner" = "$expected" ] || refuse "it is owned by $owner, not $expected"
    local entry
    entry="$("${RUN_PRIV[@]}" find "$STATE_DIR" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null)" \
        || refuse "its contents cannot be read"
    if [ -z "$entry" ]; then
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
else
    # Without the unit, the service counts as stopped only when systemd
    # says so; a query that fails any other way stops the uninstall.
    ACTIVE_STATE="$("${RUN_PRIV[@]}" "$SYSTEMCTL" is-active "$SERVICE" 2>/dev/null)"
    case "$ACTIVE_STATE" in
        inactive|unknown|failed) ;;
        active|activating|deactivating|reloading|refreshing)
            die "$SERVICE is still $ACTIVE_STATE but its unit $UNIT is not there (installed elsewhere?); nothing was removed" ;;
        *)
            die "cannot tell whether $SERVICE is running ($SYSTEMCTL is-active answered ${ACTIVE_STATE:-nothing}); nothing was removed" ;;
    esac
fi
"${RUN_PRIV[@]}" rm -f "$UNIT" || die "cannot remove $UNIT"
"${RUN_PRIV[@]}" rm -f "$ENV_FILE" || true
"${RUN_PRIV[@]}" rm -f "$BIN" || true
"${RUN_PRIV[@]}" "$SYSTEMCTL" daemon-reload >/dev/null 2>&1 || true

if [ "$PURGE" = true ]; then
    # Check again right before the delete: the stop took time.
    purge_plan
    case "$PURGE_PLAN" in
        state) "${RUN_PRIV[@]}" rm -rf --one-file-system -- "$STATE_DIR" || die "cannot purge $STATE_DIR" ;;
        empty) "${RUN_PRIV[@]}" rmdir -- "$STATE_DIR" || die "cannot purge $STATE_DIR" ;;
        absent) ;;
    esac
    log "service removed and state purged; the next install enrolls fresh"
else
    log "service removed; enrollment state kept at $STATE_DIR"
    log "a reinstall will re-prove the same identity"
fi
