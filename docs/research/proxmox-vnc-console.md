# Proxmox VM screen: the VNC proxy spike (FM-495, #495)

Status: resolved 2026-10-22. The decision it supports is recorded in
[architecture/security.md](../architecture/security.md) (Proxmox console) and
implemented in `crates/providers/fleet-provider-proxmox/src/vnc.rs`,
`crates/fleet-application/src/proxmox/console.rs`, and
`crates/fleet-controller/src/proxmox_console.rs`.

## Question

Can the controller show a Proxmox guest's screen in the console without the
browser ever holding a Proxmox credential, using only the API token Fleet
already stores per account?

## Method

Live, against the integration host (PVE 9.2.2, physical) and the nested
fixture `pve8` (PVE 8.4.0). Each run used a scratch linked clone of the
fixture template (VMID 900, tagged for the acceptance suite), started and
destroyed by the spike. VM 100 and every pre-existing guest were not touched;
the nested node was stopped again afterwards. Tokens were the acceptance
suite's scoped admin token (PVEVMAdmin on `/vms`) and its `PVEAuditor`-only
read-only token. No token, ticket, or password was written anywhere.

## Results

| Check | PVE 9.2.2 | PVE 8.4.0 |
|---|---|---|
| `POST /nodes/{node}/qemu/{vmid}/vncproxy` with `websocket=1` and `generate-password=1`, authenticated by `Authorization: PVEAPIToken=<id>=<secret>` | 200: `port`, `ticket`, `password` (8 characters), `cert`, `user` (the token id), `upid` | 200, same shape (`port` may be a string or a number) |
| `GET .../vncwebsocket?port=<port>&vncticket=<ticket>` with the same token header and subprotocol `binary` | upgrades; first frame `RFB 003.008\n` | same |
| The same upgrade without the token header | 401 | (same code path) |
| `PVEAuditor` token (no `VM.Console`) at `vncproxy` | 403 `Permission check failed (/vms/900, VM.Console)` | (same code path) |
| Rust provider (`vnc_connect`) end to end: pinned TLS, token header, ticket in the query, RFB 3.8 and VNC authentication with the one-time password, `ServerInit` read | 744x400 framebuffer from the scratch guest | covered by the recorded 8.x fixture and the shared code path |

### How the WebSocket is authenticated

Two things, and both are required: the **API token** (`Authorization` header)
authenticates the HTTP upgrade, and the **`vncticket`** returned by `vncproxy`
binds the upgrade to the one-shot listener on the named port. After the
upgrade the RFB layer asks for VNC authentication, and the answer is the DES
challenge response keyed by the 8-character `password` that
`generate-password=1` returns (RFC 6143, section 7.2.2). The listener is
single-use and short-lived on the PVE side, so `vncproxy`, the upgrade, and
the authentication run back to back.

### Which privileges

`VM.Console` on `/vms/{vmid}`, checked at `vncproxy`; nothing else. The
built-in role `PVEVMUser` (and the `FleetConsole` role in the token guide) carries it, `PVEAuditor` does not.
It is a distinct privilege from `VM.PowerMgmt` and the agent privileges, so it
is a new Fleet tier (`console`, role `FleetConsole`) in the privilege table
rather than a new row in an existing tier.

## Decision

The token path works on both majors, so no cookie/ticket login, stored
password, or `Proxmox` realm user is needed. The controller therefore:

1. opens `vncproxy` and the WebSocket through the same pinned TLS policy as
   every other PVE call (the transport's `PinningVerifier`);
2. performs the RFB version exchange and VNC authentication itself, so the
   browser is offered RFB security type *None* on an already-authenticated
   stream. The browser never sees the API token, the ticket, or the VNC
   password. This is stronger than handing the browser the one-time password
   (the issue allowed that), at the cost of a small, tested handshake in the
   relay;
3. gives the browser only a single-use, two-minute Fleet session token, carried
   in a WebSocket subprotocol so it is never in a URL or a log line;
4. authorizes `proxmox.console` when the session is created and again when the
   socket attaches, and audits start and end.

## noVNC: license and bundling

- `@novnc/novnc` 1.7.0 is **MPL-2.0**, which `.github/dependency-policy.md`
  allows for **unmodified** upstream files only. Fleet uses the npm package as
  published (exact pin in `apps/web/package.json`, integrity in
  `pnpm-lock.yaml`) and does not copy or edit its files, so no MPL obligation
  attaches to Fleet's own code. The built bundle carries the unmodified noVNC
  modules; their source is the published npm package.
- The package has **no npm dependencies**. It bundles `vendor/pako` (MIT) as a
  file under the package, with its own license text.
- `node .github/scripts/check-licenses.mjs` passes with it: the pnpm workspace
  check reports every package version within the allowed inbound set.
- The Rust additions are `des` (MIT or Apache-2.0), `tokio-tungstenite`
  (MIT), and `tokio-rustls` (MIT or Apache-2.0), all in the allow list.
- noVNC ships no TypeScript types; `apps/web/src/novnc.d.ts` declares the few
  members the console uses. noVNC loads lazily, in its own chunk, only when a
  screen is opened.

## SPICE

Not worth supporting now. VNC already gives keyboard, pointer, scaling, and
clipboard through noVNC. SPICE would need a second client library, a
`spiceproxy` ticket and `.vv` flow that hands the client a PVE address and
secret, and it adds audio and USB redirection that are explicit non-goals.
Revisit only if a concrete workflow needs a feature VNC lacks.

## Caveats

- `generate-password` exists on both majors tested. A PVE that does not return
  a `password` is refused with a clear error rather than falling back to the
  ticket-as-password form.
- The token-wide permissions map can only show that `VM.Console` is held
  *somewhere*; PVE decides per guest at `vncproxy`. The privilege report and the
  create call refuse early when the token holds it nowhere, and a per-guest
  refusal from PVE is mapped to the same explained error.
- Windows guests need no special handling: the screen is PVE's VNC display of
  the VM, independent of the guest OS, its network, and Fleet's agent.
