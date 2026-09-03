# The Fleet controller image.
#
# Three stages, each pinned to the same toolchain versions CI pins in
# .github/toolchain.env and rust-toolchain.toml:
#
#   web  — builds the Vue shell with the pinned Node and pnpm
#   rust — builds the controller binary with the pinned Rust toolchain
#   runtime — a minimal non-root Debian image with binary and shell only
#
# The image holds no secrets, opens no privileged devices, and mounts no host
# paths; deployment posture is documented in deploy/README.md.
#
# syntax=docker/dockerfile:1

FROM node:24.19.0-slim AS web
WORKDIR /src
# Corepack is installed explicitly rather than relying on the copy bundled
# with Node, which is being unbundled upstream; versions match
# .github/toolchain.env.
RUN npm install --global corepack@0.35.0 \
    && corepack enable pnpm \
    && corepack prepare pnpm@9.15.9 --activate
COPY package.json pnpm-workspace.yaml pnpm-lock.yaml ./
COPY apps/ apps/
COPY packages/ packages/
RUN pnpm install --frozen-lockfile \
    && pnpm -r --if-present run build

FROM rust:1.98.0-slim AS rust
WORKDIR /src
# rustup reads rust-toolchain.toml for the channel and components, so the
# version is never repeated here.
COPY rust-toolchain.toml Cargo.toml Cargo.lock ./
COPY crates/ crates/
COPY schemas/ schemas/
COPY xtask/ xtask/
COPY proto/ proto/
RUN cargo build --release --locked -p fleet-controller

FROM debian:bookworm-slim AS runtime
# The service user (uid/gid 999) owns the runtime state directory. The
# entrypoint starts as root only to align ownership of the state directory and
# the mounted master key with FLEET_UID/FLEET_GID, then drops privileges with
# setpriv, so the process that serves traffic is never root.
RUN useradd --system --home-dir /var/lib/fleet --create-home --shell /usr/sbin/nologin fleet
COPY --from=rust /src/target/release/fleet-controller /usr/local/bin/fleet-controller
COPY --from=web /src/apps/web/dist /opt/fleet/web
COPY deploy/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod 0755 /usr/local/bin/docker-entrypoint.sh
ENV FLEET_LISTEN=0.0.0.0:8080 \
    FLEET_WEB_DIST=/opt/fleet/web \
    FLEET_DATA_DIR=/var/lib/fleet
EXPOSE 8080
# No USER directive: the entrypoint drops privileges itself (see above).
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
