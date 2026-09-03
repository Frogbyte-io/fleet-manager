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

if ! docker compose version >/dev/null 2>&1; then
  echo "error: docker compose (v2 plugin) is required" >&2
  exit 1
fi

cleanup() {
  docker compose -p "$project" down --volumes --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

container_of() {
  docker compose -p "$project" ps -q "$service"
}

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
readyz="$(curl -fsS http://127.0.0.1:8080/readyz)"
[ "$readyz" = "ok" ] || { echo "error: /readyz answered '$readyz'" >&2; exit 1; }
curl -fsS http://127.0.0.1:8080/ | grep -q "Fleet Manager" \
  || { echo "error: the web shell was not served at /" >&2; exit 1; }
curl -fsS http://127.0.0.1:8080/api/v1/meta | grep -q '"service":"fleet-controller"' \
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
