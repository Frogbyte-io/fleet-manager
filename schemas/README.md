# Desired-resource schemas

Fleet desired-state files use JSON Schema Draft 2020-12. The checked-in schema
is generated from the Rust envelope types; edit `src/lib.rs`, regenerate, and
commit both source and artifact:

```bash
cargo run -p fleet-schema -- generate
cargo run -p fleet-schema -- generate --check
```

Validate one file or a collection of YAML files with the published Rust CLI
path. Files passed together are one candidate revision, so resource identities
must be unique across all files and YAML documents:

```bash
cargo run -p fleet-schema -- validate fleet/fleet.yaml fleet/machines/*.yaml
```

Diagnostics have Fleet-owned `FM_SCHEMA_*` codes, a source/document/pointer
location, and a stable summary. Parser and validator dependency wording is not
part of the public contract.

## Envelope and versioning

Every resource contains exactly `apiVersion`, `kind`, `metadata`, and `spec`.
Metadata contains a stable opaque UUIDv7 `id` and a mutable slug `name`.
`status`, observations, runtime coordination, and inline secret values are not
desired state. Later kind-specific specs may expose secret-reference IDs, never
secret values.

The only M0 registry entry is `fleet.frogbyte.io/v1alpha1` / `FleetConfig`,
whose spec is intentionally empty. Adding a version or kind requires adding its
typed schema variant and compatibility fixtures; it must not silently widen an
existing published contract.

## Fixtures

- `fixtures/valid/*.yaml` must validate with no output.
- `fixtures/invalid/*.yaml` must fail; the adjacent `.stderr` file is its exact
  golden CLI diagnostic output.
- A multi-document YAML file represents multiple resources. Empty documents
  are ignored.
