#!/usr/bin/env bash
# Install (or upgrade) fleetd as a systemd system service on a Linux host.
#
# The invoking SSH account needs real root, or passwordless sudo (the
# documented prerequisite of this bootstrap). Privileged steps are prefixed
# with `sudo -n` only when the account is not already root.
#
# Inputs (environment):
#   FLEET_CONTROLLER_URL  the controller base URL, e.g. http://10.0.0.5:8080
#                         (required on first install; ignored on upgrades)
#   FLEET_ENROLL_TOKEN    a single-use enrollment token for this machine.
#                         Required unless a valid enrollment already exists
#                         (the upgrade case). It is piped to
#                         `fleetd enroll --token-stdin` and never written to
#                         disk, never placed in a process argument.
#   FLEET_FORCE_ENROLL    set to 1 to wipe the existing node identity first
#                         (the post-revocation re-enrollment path). The
#                         bootstrap executor sets this when the machine's
#                         node identity was revoked.
#   FLEETD_ARCHIVE_DIR    directory holding the extracted archive contents
#                         (the fleetd binary and the unit file). Default: the
#                         directory of this script.
#
# Layout overrides for tests and unusual hosts (all optional):
#   FLEETD_STATE_DIR   default /var/lib/fleetd
#   FLEETD_BIN_DIR     default /usr/local/bin
#   FLEETD_UNIT_DIR    default /etc/systemd/system
#   FLEETD_ENV_FILE    default /etc/default/fleetd
#   FLEETD_SERVICE     default fleetd
#   FLEETD_SYSTEMCTL   default systemctl (point at a stub to test offline)
#   FLEETD_USER_ADD    default useradd (point at a stub to test offline)
#   FLEETD_RUNUSER     default: runuser under root, `sudo -n -u` otherwise
#                      (point at a stub to test offline)
#
# Behavior:
#   - Creates the system account `fleet` (no login shell) and the state
#     directory 0750 fleet:fleet.
#   - Installs the binary atomically (write to temp, rename).
#   - Installs the unit and the environment file, enables the service.
#   - Enrolls only when there is no usable enrollment yet: an existing
#     credential survives upgrades, so a restart re-proves the same
#     identity. FLEET_FORCE_ENROLL=1 wipes the identity first (revocation).
#   - Starts (or restarts) the service and waits for it to be active.
#
# On failure the script removes what it created in this run (unit, env file,
# enabled state) so a retry starts clean, and leaves the agentless SSH
# endpoint — and any previous working installation — untouched.

set -u

die() { printf 'install: %s\n' "$1" >&2; exit 1; }
log() { printf 'install: %s\n' "$1"; }

SELF_DIR="$(cd "$(dirname "$0")" && pwd)"
ARCHIVE_DIR="${FLEETD_ARCHIVE_DIR:-$SELF_DIR}"
STATE_DIR="${FLEETD_STATE_DIR:-/var/lib/fleetd}"
BIN_DIR="${FLEETD_BIN_DIR:-/usr/local/bin}"
UNIT_DIR="${FLEETD_UNIT_DIR:-/etc/systemd/system}"
ENV_FILE="${FLEETD_ENV_FILE:-/etc/default/fleetd}"
SERVICE="${FLEETD_SERVICE:-fleetd}"
SYSTEMCTL="${FLEETD_SYSTEMCTL:-systemctl}"
USER_ADD="${FLEETD_USER_ADD:-useradd}"
RUNUSER="${FLEETD_RUNUSER:-}"

SERVICE_USER=fleet
BIN="$BIN_DIR/fleetd"
UNIT="$UNIT_DIR/$SERVICE.service"

ON_DISK_UNIT="$(ls "$ARCHIVE_DIR"/*.service 2>/dev/null | head -1)"
[ -n "${ON_DISK_UNIT:-}" ] || die "the archive has no unit file"
[ -x "$ARCHIVE_DIR/fleetd" ] || die "the archive has no fleetd binary"

# --- privilege ----------------------------------------------------------------
IS_ROOT=false
[ "$(id -u)" = "0" ] && IS_ROOT=true
if [ "$IS_ROOT" = true ]; then
    RUN_PRIV=()
elif sudo -n true >/dev/null 2>&1; then
    RUN_PRIV=(sudo -n)
else
    RUN_PRIV=()
    log "warning: this account is neither root nor a passwordless sudoer; \
privileged steps will fail (tests use layout overrides instead)"
fi

# Runs the enroll step as the service account. The token reaches fleetd on
# standard input and is never placed in a process argument. When the account
# does not exist (stubbed useradd in tests), the step runs as the invoking
# user — the state directory is theirs anyway.
run_as_service() {
    if [ -n "$RUNUSER" ]; then
        "$RUNUSER" -u "$SERVICE_USER" -- "$@"
    elif getent passwd "$SERVICE_USER" >/dev/null 2>&1; then
        if [ "$IS_ROOT" = true ]; then
            runuser -u "$SERVICE_USER" -- "$@"
        else
            sudo -n -u "$SERVICE_USER" -- "$@"
        fi
    else
        env FLEETD_STATE_DIR="$STATE_DIR" "$@"
    fi
}

# Writes one privileged file.
write_priv_file() {
    target=$1
    shift
    if [ "$IS_ROOT" = true ]; then
        cat >"$target"
    elif [ "${#RUN_PRIV[@]}" -gt 0 ]; then
        sudo -n tee "$target" >/dev/null
    else
        cat >"$target"
    fi
}

# --- idempotency: detect an existing, working installation -------------------
HAD_BINARY=false
[ -x "$BIN" ] && HAD_BINARY=true
HAD_UNIT=false
[ -f "$UNIT" ] && HAD_UNIT=true
FORCE_ENROLL="${FLEET_FORCE_ENROLL:-0}"
HAD_CREDENTIAL=false
# The credential test must be privileged: the state directory is 0700
# fleet:fleet, so an unprivileged check cannot even stat it and would
# misread an upgrade as a first install.
if [ "$FORCE_ENROLL" != "1" ]; then
    if [ "$IS_ROOT" = true ]; then
        [ -s "$STATE_DIR/credential" ] && HAD_CREDENTIAL=true
    elif [ "${#RUN_PRIV[@]}" -gt 0 ]; then
        sudo -n test -s "$STATE_DIR/credential" && HAD_CREDENTIAL=true
    else
        [ -s "$STATE_DIR/credential" ] && HAD_CREDENTIAL=true
    fi
fi

CREATED_UNIT=false
CREATED_ENV=false

cleanup() {
    code=$?
    if [ "$code" -ne 0 ]; then
        if [ "$CREATED_UNIT" = true ]; then
            "${RUN_PRIV[@]}" "$SYSTEMCTL" disable --now "$SERVICE" >/dev/null 2>&1 || true
            "${RUN_PRIV[@]}" rm -f "$UNIT"
        fi
        if [ "$CREATED_ENV" = true ]; then
            "${RUN_PRIV[@]}" rm -f "$ENV_FILE"
        fi
        if [ "$CREATED_UNIT" = true ]; then
            "${RUN_PRIV[@]}" "$SYSTEMCTL" daemon-reload >/dev/null 2>&1 || true
            log "removed the partially installed service; nothing else was touched"
        fi
    fi
    exit "$code"
}
trap cleanup EXIT

# --- system account and state directory ---------------------------------------
# Ownership flags derive from the account's actual existence: a stubbed
# useradd (tests) creates nothing, and `install -o fleet` would then fail
# even as root.
if ! getent passwd "$SERVICE_USER" >/dev/null 2>&1; then
    "${RUN_PRIV[@]}" "$USER_ADD" --system --user-group --home-dir "$STATE_DIR" \
        --shell /usr/sbin/nologin "$SERVICE_USER" \
        || die "cannot create the $SERVICE_USER service account"
fi
if getent passwd "$SERVICE_USER" >/dev/null 2>&1; then
    "${RUN_PRIV[@]}" install -d -m 0750 -o "$SERVICE_USER" -g "$SERVICE_USER" "$STATE_DIR" \
        || die "cannot prepare the state directory $STATE_DIR"
else
    # No account (stubbed tests): the state directory belongs to the
    # invoking user, so it is created without privilege escalation —
    # fleetd must be able to restrict it.
    install -d -m 0750 "$STATE_DIR" \
        || die "cannot prepare the state directory $STATE_DIR"
fi

# --- binary (atomic replace) -------------------------------------------------
"${RUN_PRIV[@]}" install -d -m 0755 "$BIN_DIR"
"${RUN_PRIV[@]}" install -m 0755 "$ARCHIVE_DIR/fleetd" "$BIN.fleet-new" \
    || die "cannot stage the binary"
"${RUN_PRIV[@]}" mv -f "$BIN.fleet-new" "$BIN" || die "cannot move the binary into place"

# --- unit + environment ------------------------------------------------------
if [ "$HAD_UNIT" = false ]; then
    "${RUN_PRIV[@]}" install -d -m 0755 "$UNIT_DIR" \
        || die "cannot prepare the unit directory $UNIT_DIR"
    "${RUN_PRIV[@]}" install -m 0644 "$ON_DISK_UNIT" "$UNIT" \
        || die "cannot install the unit"
    CREATED_UNIT=true
fi

# The controller URL is a deployment fact. On an upgrade it already exists in
# the environment file; refuse to silently change it.
if [ -f "$ENV_FILE" ]; then
    grep -q "^FLEETD_CONTROLLER_URL=" "$ENV_FILE" \
        || die "the environment file exists but has no controller URL"
else
    [ -n "${FLEET_CONTROLLER_URL:-}" ] || die "FLEET_CONTROLLER_URL is required on first install"
    "${RUN_PRIV[@]}" install -d -m 0755 "$(dirname "$ENV_FILE")"
    printf 'FLEETD_CONTROLLER_URL=%s\n' "$FLEET_CONTROLLER_URL" | write_priv_file "$ENV_FILE" \
        || die "cannot write the environment file"
    "${RUN_PRIV[@]}" chmod 0644 "$ENV_FILE"
    CREATED_ENV=true
fi

"${RUN_PRIV[@]}" "$SYSTEMCTL" daemon-reload || die "systemd did not accept the unit"
"${RUN_PRIV[@]}" "$SYSTEMCTL" enable "$SERVICE" >/dev/null 2>&1 \
    || die "cannot enable the service"

# --- enrollment (first install, or forced after revocation) -------------------
if [ "$HAD_CREDENTIAL" = true ]; then
    log "existing enrollment found; the identity survives this upgrade"
else
    [ -n "${FLEET_ENROLL_TOKEN:-}" ] || die "FLEET_ENROLL_TOKEN is required on first install"
    [ -n "${FLEET_CONTROLLER_URL:-}" ] || die "FLEET_CONTROLLER_URL is required on first install"
    if [ "$FORCE_ENROLL" = "1" ]; then
        "${RUN_PRIV[@]}" rm -f "$STATE_DIR/node.key" "$STATE_DIR/credential" \
            "$STATE_DIR/machine-id"
        log "forced re-enrollment: the previous node identity was wiped"
    fi
    printf '%s' "$FLEET_ENROLL_TOKEN" | \
        run_as_service "$BIN" enroll --controller "$FLEET_CONTROLLER_URL" \
        --token-stdin --state-dir "$STATE_DIR" \
        || die "enrollment failed"
    log "enrolled; the single-use token was consumed and never stored"
fi

# --- start -------------------------------------------------------------------
"${RUN_PRIV[@]}" "$SYSTEMCTL" restart "$SERVICE" || die "the service did not start"

# --- wait for active ---------------------------------------------------------
for _ in 1 2 3 4 5 6 7 8 9 10; do
    if [ "$("${RUN_PRIV[@]}" "$SYSTEMCTL" is-active "$SERVICE" 2>/dev/null)" = "active" ]; then
        log "service is active; installed $("$BIN" --version 2>/dev/null || echo fleetd)"
        exit 0
    fi
    sleep 1
done
die "the service never became active"
