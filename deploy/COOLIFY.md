# Fleet Manager on Coolify

Deploy one Linux controller with the Docker Compose build pack. Coolify manages
builds, container lifecycle, and logs; Tailscale on the deployment host provides
private ingress. No separate database, Docker socket, privileged container, or
Tailscale auth key in the application is needed.

The dashboard currently has no login. Every reachable caller can administer the
fleet. Only trusted administrators and enrolled machines should be allowed to
reach this service. Do not assign a public Coolify domain or enable Tailscale
Funnel. Other applications on the same Docker host/network are also inside
this trust boundary.

## Prepare the deployment host

Install and join Tailscale on the Linux server through your normal host setup.
The server must be able to reach managed machines' SSH endpoints and any
configured provider APIs (for example Proxmox). Managed nodes need a route back
to the controller through the tailnet.

Provision a master key **once**, outside the repository and Coolify checkout.
Run the following as a host administrator; it refuses to overwrite an existing
key and does not print key material:

```sh
install -d -m 700 /data/fleet-manager/secrets
(
  umask 077
  set -C
  printf '1 %s\n' "$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')" \
    > /data/fleet-manager/secrets/master_key
)
docker volume create fleet-manager-data
```

The key format is documented in [fleet-secrets](../crates/fleet-secrets/README.md).
Keep a protected recovery copy of this key separately from database backups.
Redeployments reuse it; generating a replacement makes existing secrets
unreadable. The external Docker volume persists independently of Coolify's
Compose project name. Never share it between two controller instances.

## Configure the Coolify application

1. Add this Git repository as an **Application**, selecting **Docker Compose**
   as the build pack.
2. Set **Base Directory** to `/` and **Docker Compose Location** to
   `/deploy/compose.coolify.yaml`.
3. Leave the controller service's **Domains** field empty. Remove any generated
   public domain before deploying. The Compose file disables Traefik routing
   and publishes the controller only to host loopback.
4. Configure the following variables; the example is in
   [coolify.env.example](coolify.env.example):

   | Variable | Value |
   |---|---|
   | `FLEET_MASTER_KEY_SOURCE` | `/data/fleet-manager/secrets/master_key` (required absolute host path) |
   | `FLEET_DATA_VOLUME` | `fleet-manager-data` (the external volume created above) |
   | `FLEET_COOLIFY_PORT` | `8080` (an unused host loopback port) |

   These are deployment settings. The key's contents must never be entered as
   a Coolify environment value, build argument, or inline Compose content.
5. Use one replica and stop/recreate deployments. Disable overlapping rolling
   deployments and automatic previews: two controllers must never open the
   same SQLite volume. An isolated preview needs its own volume, master key,
   loopback port, and private ingress.
6. Deploy and wait for the controller's binary healthcheck to report healthy.
   A missing key or external volume is a setup failure, not a reason to remove
   the mount. The root filesystem is read-only; state uses `/var/lib/fleet` and
   transient files use `/tmp`.

The image contains the web app, controller, Git/SSH client tools, CA roots, and
the Linux `fleetd` service package matching the image's native architecture.
The entrypoint copies that package into the persisted artifacts directory on
startup. Additional architectures require separately built packages in that
directory. Optional controller-side CLI integrations, such as Packer, need
an image extended with their documented dependencies; this deployment does
not install every optional provider tool.

Rust builds default to two parallel jobs to limit memory pressure on small
servers. An explicit Docker build argument `CARGO_BUILD_JOBS` can override
that limit on larger build hosts.

## Private access and node communication

On the deployment host, expose the loopback backend through
[Tailscale Serve](https://tailscale.com/docs/reference/tailscale-cli/serve).
Check existing Serve configuration first and choose unused tailnet ports:

```sh
tailscale serve status
tailscale serve --bg --http=8080 http://127.0.0.1:8080
tailscale serve --bg --https=443 http://127.0.0.1:8080
tailscale serve status
```

If `FLEET_COOLIFY_PORT` differs, change the **backend** port in both commands.
Restrict tailnet ACLs/grants to the administrators and nodes that should reach
these ports. HTTP Serve is private to the tailnet; the network connection is
encrypted by Tailscale. HTTPS Serve provides a separate browser endpoint.

| Client | Controller URL / transport |
|---|---|
| Browser | `https://<deployment-host>.<tailnet>.ts.net` with HTTP API and SSE |
| `fleetd` / Install Fleet Node | `http://<deployment-host>.<tailnet>.ts.net:8080` with HTTP enrollment/session proof and outbound `ws://.../api/node/v1/connect` |
| Agentless machine | Controller initiates SSH using the enrolled endpoint and verified host key |

**Current implementation limitation:** `fleetd` accepts only `http://` URLs
with an explicit port. It does not yet implement HTTPS/WSS, despite those
being the target in the protocol architecture. Use the private HTTP URL for
node enrollment and installation, including when the dashboard is opened
over HTTPS. In Install Fleet Node, explicitly set that HTTP controller URL
instead of using the browser's HTTPS origin. It must be reachable from the
target machine. Do not expose this HTTP endpoint outside the trusted network.

Do not enable `FLEET_TAILSCALE_SERVE_LISTEN` or combine this file with
`compose.tailscale.yaml`. Those enable optional Serve **identity** mode, which
currently requires host-loopback node routes and blocks remote `fleetd`
sessions. Ordinary Serve proxying here leaves Fleet identity mode disabled;
Fleet still verifies its own node credentials. See the
[security architecture](../docs/architecture/security.md).

## Verify and redeploy

From the server, check `http://127.0.0.1:8080/readyz`, `/`, and `/api/v1/meta`.
From an allowed tailnet client, check the private HTTP URL and the HTTPS
dashboard. Verify live SSE status in the dashboard, then enroll a disposable
Linux node using the HTTP URL and confirm connected state and inventory.
Redeploy the same configuration and verify that node identity, records, and
secrets survive. A healthy container alone does not prove tailnet reachability
or node connectivity.

Local configuration checks need Node and Docker Compose, but no Docker daemon:

```sh
node --test deploy/coolify.test.mjs
```

To build and exercise the actual Coolify Compose stack with a temporary key
and disposable external volume:

```sh
node deploy/coolify-smoke.mjs
```

Set `FLEET_SMOKE_IMAGE` to an already-built image tag to skip rebuilding.
The smoke checks web/API/SSE, installer downloads and script line endings,
non-root execution, isolation, persisted records across recreation, and graceful
shutdown. It deletes only its generated test containers, volume, and temporary
key files. The existing [container smoke test](README.md) exercises the standard
Compose stack. A real Coolify deployment still needs the tailnet checks above.

## Backup and recovery

A persistent volume is not a backup. Stop the sole controller and wait for it
to exit before taking a filesystem backup of the **entire** data volume
(including SQLite WAL files, artifacts, and other runtime files). The Compose
shutdown grace is 150 seconds to accommodate the worker's 120-second drain.
Store the master key in a separate protected backup and record the image/Git
revision. Restart only after the backup has finished.

Restore into an empty local Docker volume with the matching master key and
image revision. Point `FLEET_DATA_VOLUME` at it, start exactly one controller,
and verify readiness, stored records, secret-backed operations, and node
reconnection. Do not attach a backup copy to a second active controller with
the same enrolled nodes. Test recovery periodically; Coolify deployment
rollback does not roll back SQLite migrations or the data volume.

## Sources

- [Coolify Docker Compose](https://coolify.io/docs/applications/builds/docker-compose)
- [Coolify persistent storage](https://coolify.io/docs/applications/configuration/persistent-storage)
- [Tailscale Serve CLI](https://tailscale.com/docs/reference/tailscale-cli/serve)
- [ADR 0007: one controller and local SQLite](../docs/adr/0007-sqlite-single-controller.md)
