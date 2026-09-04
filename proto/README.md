# Node protocol source

`fleet/node/v1/node.proto` is the source of truth for the controller–node
channel described in
[`docs/architecture/controller-node-protocol.md`](../docs/architecture/controller-node-protocol.md)
and ADR-0002/ADR-0003. Rust types are generated from it into `OUT_DIR` when
`fleet-protocol` builds; there is no checked-in generated code, so there is
nothing to regenerate and nothing that can go stale.

This protocol versions independently of the public HTTP API. A change here does
not imply an API version bump, and vice versa.

## Toolchain: no `protoc` required

The `.proto` file is compiled by [`protox`](https://crates.io/crates/protox), a
pure-Rust protobuf compiler, whose descriptor set is handed to
[`prost-build`](https://crates.io/crates/prost-build) with `skip_protoc_run()`.
Building this repository therefore needs no `protoc` binary — not on a
contributor's machine, not in CI, and not in the controller image.

The alternatives were rejected deliberately: `protoc-bin-vendored` ships a
prebuilt binary per platform, which is a second supply chain and a per-target
artifact for the Linux and Windows baseline in `deny.toml`; `protobuf-src`
compiles `protoc` from C++ source and adds a C++ toolchain everywhere; and a
documented prerequisite makes a clean checkout fail to build for a reason no
lockfile can fix. See `docs/research/ecosystem.md` for the recorded decision.

## Compatibility rules

Within a protocol version:

- **Adding a field is allowed.** Peers ignore fields they do not know. Prost
  drops unknown fields rather than preserving them, so a proxy or relay must not
  be built on the assumption that unknown fields survive a decode/encode cycle.
- **Adding an enum value is allowed**, but a peer that receives an unrecognised
  value must fall back to the `_UNSPECIFIED` behaviour rather than fail.
- **Renumbering, removing, or reusing a tag is not allowed.** Removed tags go in
  a `reserved` range. Envelope tags 4–15 are held for later single-byte-tag
  envelope scalars.
- **Adding a payload variant is a version change**, not an additive one. A frame
  whose payload this build cannot read is answered with an `UNKNOWN_PAYLOAD`
  fault, because a frame with no readable meaning cannot be acted on safely.
- **No `map<>` fields.** Prost lowers them to `HashMap`, whose iteration order is
  unspecified, which would make encodings unstable and the goldens below
  meaningless. Use a sorted `repeated` field.

Anything that breaks a rule above needs `fleet/node/v2/`, a new
`ProtocolVersion`, and fixtures for both versions across the supported rolling
upgrade window.

## Enrollment over HTTP (FM-204)

Enrollment and key proof do not use the frame channel: they happen over
ordinary TLS on the controller's HTTP listener, versioned with the node
protocol at `/api/node/v1`. These endpoints are the node trust surface; they
are not part of the public `OpenAPI` document, and the trusted-LAN principal
never authorizes them — possession of the enrollment token or of a verified
Ed25519 key proof does.

The implementation lives in `fleet-api/src/node.rs` (handlers) and
`fleet-auth/src/node.rs` (token, credential, and proof formats), with
`fleet-application/src/node.rs` as the use cases. `fleetd` (FM-205) is the
client.

### Endpoints

| Endpoint | Request | Response |
|---|---|---|
| `POST /api/node/v1/enroll` | `{token, publicKey, os, arch, nodeVersion}` | `201` `{machineId, credential, credentialExpiresAt, rebind}` |
| `POST /api/node/v1/challenge` | `{credential, purpose?, newPublicKey?}` | `200` `{challengeId, machineId, nonce, purpose, expiresAt}` |
| `POST /api/node/v1/session` | `{credential, challengeId, signature}` | `200` `{machineId, session, sessionExpiresAt}` |
| `POST /api/node/v1/rotate` | `{credential, newPublicKey, challengeId, signature}` | `200` `{machineId, credential, nodeKeyVersion, credentialExpiresAt}` |

Failures use the standard error envelope: `401` for a token, credential,
challenge, or proof that did not verify; `404` for unknown references; `409`
when the machine already has an active identity (enrollment over a live
identity is a rotation, not a second enrollment); `400` for malformed
requests; `503` when the controller has no master key configured.

### Formats

- **Enrollment token** `fmtenr1.<64 hex>`: 32 CSPRNG bytes. The value is shown
  exactly once to the operator who created it; the controller stores only its
  SHA-256 hash. A token is scoped to one machine, expires within a day, and
  claims exactly once — a replayed or concurrent claim is answered with `401`.
- **Key proof message** (the bytes the node signs with its *private* key):

  ```text
  fleet-node-proof/v1 <NUL> challengeId <NUL> machineId <NUL> purpose <NUL> newPublicKey
  ```

  where `purpose` is `session` or `rotate`, and `newPublicKey` is empty for
  session proofs. The signature is hex-encoded; the proof for a `rotate`
  challenge must be made with the *new* private key over the message that
  binds it.
- **Node credential** `fmnc1.<credentialId>.<machineId>.<nodeKeyVersion>.<expiresAt>.<HMAC>`:
  HMAC-SHA256 over the dotted prefix, under the controller's node-credential
  signing key, provisioned by the controller as an encrypted secret record.
  The credential is short-lived (default seven days), renewable by key proof,
  and invalidated by key rotation or revocation. Losing or replacing the
  controller signing key fails closed: every outstanding credential and
  session becomes unverifiable, and nodes re-prove or re-enroll through
  explicit, audited actions.
- **Node session** `fmns1.<sessionId>.<credentialId>.<machineId>.<expiresAt>.<HMAC>`:
  the same codec for the short-lived session (default ten minutes) a verified
  proof exchanges a credential for. A session is a node-surface credential
  only — it never authorizes an operator API call; the node gateway (FM-205)
  is its sole consumer.

### Lifecycle rules

- A node identity is one Ed25519 public key per machine, at a monotonic
  `nodeKeyVersion`. Enrollment claims the token, binds the key, and mints the
  first credential in one transaction; the machine and the audit record commit
  together.
- Every enrollment consumption, session issuance, and rotation is audited
  under the actor `node:<machineId>`. Challenges themselves are not audited:
  issuing one grants nothing, and nodes poll often enough to drown the ledger.
- Rotation consumes a `rotate` challenge whose `newPublicKey` matches the
  request, bumps the key version, revokes every outstanding credential and
  session of the machine, and issues one new credential — atomically.
- Revocation (operator action) invalidates the identity, every credential, and
  every session; renewal fails until an explicit re-enrollment replaces the
  revoked identity with a fresh token and a version bump. The disconnect of an
  existing gateway connection is the gateway's job (FM-205); revocation here
  prevents renewal.

## The gateway channel (FM-205)

The node gateway is the WebSocket session at `GET /api/node/v1/connect`,
speaking the subprotocol `fleet.node.v1`. Everything before the upgrade and
after it is deliberately split:

- **Before the upgrade** the node authenticates over HTTP: it proves key
  possession (`/challenge` + `/session`) and presents the resulting
  short-lived session in the `x-fleet-node-session` header. The controller
  validates the session chain before answering the upgrade; a refusal is an
  HTTP status (`401` for a missing/invalid session, `400` for a missing
  subprotocol), never a frame.
- **After the upgrade** the channel carries only FM-007's frames: `Hello`
  opens the session (machine id, software version, protocol and
  inventory-schema ranges, boot session id, journal position, platform
  facts, feature flags); `Welcome` fixes the negotiated terms (protocol
  version, inventory-schema version, controller-assigned session id,
  feature-flag intersection, `Limits`, heartbeat interval). `Heartbeat`
  frames carry the monotonic sequence, monotonic node uptime, journal
  position, and in-flight count. Any other payload is answered with
  `UNKNOWN_PAYLOAD`; an undecodable frame with `MALFORMED_FRAME`; a
  range mismatch with the typed version fault carrying the controller's
  supported range.

### Session rules

- One live session per machine. A second connect **supersedes** the first:
  the older session answers `FAULT_CODE_SESSION_REJECTED` and closes, so a
  reconnecting node always wins without wedging the registry.
- Heartbeats update the controller's in-memory registry only. A background
  sweeper transitions `connected` → `stale` after two missed intervals and
  persists only on transition; a closed connection settles `offline` once.
  Connect, disconnect, and superseded transitions are audited under
  `node:<machineId>`; staleness is observable in durable node state
  (`node_identities.gateway_state`) but deliberately not audited, because an
  offline node flaps faster than an operator can read the ledger.
- The journal position is reported but not yet acted on: command dispatch
  and journal reconciliation are FM-207.
- The client reconnects with bounded jitter (±25%, exponential from 500 ms
  to a 30 s cap) after re-proving the session over HTTP. A
  `SESSION_REJECTED` fault is retryable (session state may heal); every
  other fault is a build or wire problem and stops the client.

## Golden fixtures

`fixtures/v1/*.bin` are frozen encodings, one per message family, plus two
compatibility frames that no current encoder produces: a `Hello` carrying
unknown fields, and a frame carrying an unknown payload variant. They are
embedded into `fleet-protocol` with `include_bytes!` and exposed from
`fleet_protocol::fixtures`, so `fleet-controller` and `fleetd` consume the same
bytes without re-encoding them.

**A failing v1 fixture is a breaking protocol change, not a stale fixture.** The
regeneration path exists for adding a new fixture, not for re-blessing an
existing one:

```sh
FLEET_PROTOCOL_BLESS=1 cargo test -p fleet-protocol --test goldens
cargo test -p fleet-protocol --test goldens
```

The second run is required: the first rewrites the files, and only a rebuild
refreshes the copies embedded in the crate. If a re-blessed fixture appears in a
diff, the reviewer's question is which peers are now incompatible.

## Secrets

Frames carry an authorization *digest*, never an actor's credentials, and
Fleet-owned fault text derived from a code, never a peer's message or a
provider's output. Later command kinds may carry a secret *reference*; a secret
value must never appear in a frame, a log line, or a fixture. A fixture that
contains anything resembling a credential is a defect regardless of whether the
credential is real.
