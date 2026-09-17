#!/usr/bin/env bash
# End-to-end smoke for the minimal controller deployment.
#
#   deploy/smoke.sh
#
# Proves the FM-008 acceptance criteria against a real daemon: the stack
# builds, the container reaches healthy, the controller serves the web shell
# and the public API, the root filesystem is read-only, and SIGTERM drains
# into a clean exit. Docker with the compose plugin is required; no other
# tools beyond curl.
set -euo pipefail
cd "$(dirname "$0")"

project="fleet-smoke"
service="controller"

# The host port dodges whatever the machine already uses: pick a free
# loopback port unless the caller pinned one. The probe URLs below derive
# from it, so the smoke never assumes 8080 is free.
if [ -z "${FLEET_SMOKE_PORT:-}" ]; then
  FLEET_SMOKE_PORT="$(python3 - <<'PORT'
import socket
with socket.socket() as probe:
    probe.bind(("127.0.0.1", 0))
    print(probe.getsockname()[1])
PORT
)"
fi
export FLEET_SMOKE_PORT

if ! docker compose version >/dev/null 2>&1; then
  echo "error: docker compose (v2 plugin) is required" >&2
  exit 1
fi

cleanup() {
  docker compose -p "$project" down --volumes --remove-orphans >/dev/null 2>&1 || true
  [ -n "${key_file:-}" ] && rm -f "$key_file"
  return 0
}
trap cleanup EXIT

container_of() {
  docker compose -p "$project" ps -q "$service"
}

# The controller refuses to start without a usable key source; the smoke hands
# the stack an ephemeral one in the documented key-file format (hex text, see
# crates/fleet-secrets/README.md). The file is mode 0600 and removed on exit;
# it is a throwaway artifact of this run, never a stored credential.
if [ -z "${FLEET_MASTER_KEY_SOURCE:-}" ]; then
  key_file="$(mktemp "${TMPDIR:-/tmp}/fleet-smoke-master-key.XXXXXX")"
  printf '1 %s\n' "$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')" > "$key_file"
  chmod 600 "$key_file"
  export FLEET_MASTER_KEY_SOURCE="$key_file"
fi

echo "==> Building and starting the stack"
docker compose -p "$project" up --build --detach --quiet-pull

container="$(container_of)"
if [ -z "$container" ]; then
  echo "error: the controller container did not start" >&2
  docker compose -p "$project" ps -a >&2 || true
  exit 1
fi

echo "==> Waiting for healthy"
healthy=""
for _ in $(seq 1 60); do
  status="$(docker inspect -f '{{.State.Health.Status}}' "$container" 2>/dev/null || echo missing)"
  if [ "$status" = "healthy" ]; then healthy=1; break; fi
  if [ "$status" = "missing" ] || [ "$(docker inspect -f '{{.State.Status}}' "$container" 2>/dev/null)" = "exited" ]; then
    echo "error: the controller exited before becoming healthy" >&2
    docker logs "$container" >&2 || true
    exit 1
  fi
  sleep 2
done
if [ -z "$healthy" ]; then
  echo "error: the controller never became healthy" >&2
  docker logs "$container" >&2 || true
  exit 1
fi
echo "    healthy"

echo "==> Probing the served surfaces"
readyz="$(curl -fsS "http://127.0.0.1:${FLEET_SMOKE_PORT}/readyz")"
[ "$readyz" = "ok" ] || { echo "error: /readyz answered '$readyz'" >&2; exit 1; }
curl -fsS "http://127.0.0.1:${FLEET_SMOKE_PORT}/" | grep -q "Fleet Manager" \
  || { echo "error: the web shell was not served at /" >&2; exit 1; }
curl -fsS "http://127.0.0.1:${FLEET_SMOKE_PORT}/api/v1/meta" | grep -q '"service":"fleet-controller"' \
  || { echo "error: /api/v1/meta did not answer the public envelope" >&2; exit 1; }
echo "    web shell, API, and readiness OK"

echo "==> Asserting the isolation posture"
[ "$(docker inspect -f '{{.HostConfig.ReadonlyRootfs}}' "$container")" = "true" ] \
  || { echo "error: the root filesystem is not read-only" >&2; exit 1; }
[ "$(docker inspect -f '{{.HostConfig.Privileged}}' "$container")" = "false" ] \
  || { echo "error: the container runs privileged" >&2; exit 1; }
network="$(docker inspect -f '{{.HostConfig.NetworkMode}}' "$container")"
case "$network" in
  host|container:*|"")
    echo "error: the container is not on a compose-managed network (network mode: ${network:-empty})" >&2
    exit 1
    ;;
esac
docker inspect -f '{{.Mounts}}' "$container" | grep -q "docker.sock" \
  && { echo "error: the Docker socket is mounted" >&2; exit 1; } || true
echo "    read-only root, unprivileged, no host Docker socket"

echo "==> Sending SIGTERM and expecting a graceful drain"
docker compose -p "$project" stop "$service" >/dev/null
docker logs "$container" 2>&1 | grep -q "stopped gracefully" \
  || { echo "error: SIGTERM did not drain gracefully" >&2; docker logs "$container" >&2; exit 1; }
code="$(docker inspect -f '{{.State.ExitCode}}' "$container")"
[ "$code" = "0" ] || { echo "error: the process exited with code $code" >&2; exit 1; }
echo "    drained and exited 0"

echo "Compose smoke passed."
