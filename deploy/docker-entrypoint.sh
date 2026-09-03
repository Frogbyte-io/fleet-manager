#!/bin/sh
# Container entrypoint for the Fleet controller.
#
# The container starts as root only to prepare the two things the service
# process must reach — the runtime state directory and the mounted master
# key — and then drops privileges to the unprivileged service user
# (FLEET_UID/FLEET_GID, default 999 = the image's `fleet` user). The process
# that serves traffic never runs as root.
#
# Docker secret mounts are read-only, so the key is copied once into the
# container's tmpfs with owner-only permissions before the privilege drop.
set -e

uid="${FLEET_UID:-999}"
gid="${FLEET_GID:-999}"

if [ "$(id -u)" = "0" ]; then
  chown -R "$uid:$gid" /var/lib/fleet

  if [ -e /run/secrets/master_key ]; then
    install -D -m 400 -o "$uid" -g "$gid" \
      /run/secrets/master_key /tmp/fleet-secrets/master_key
    export FLEET_MASTER_KEY_FILE=/tmp/fleet-secrets/master_key
  fi

  exec setpriv --reuid "$uid" --regid "$gid" --clear-groups \
    /usr/local/bin/fleet-controller "$@"
fi

# Already non-root (e.g. `docker run --user`): run as-is.
exec /usr/local/bin/fleet-controller "$@"
