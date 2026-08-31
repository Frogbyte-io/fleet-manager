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
