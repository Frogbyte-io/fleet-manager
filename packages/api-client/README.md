# `@frogbyte-io/fleet-api-client`

The TypeScript client for the Fleet Manager public API. Every file under
`src/generated/` is produced by [orval](https://orval.dev) from `openapi.json`;
`src/index.ts` is the only hand-written source, and it exists so consumers import
a stable module path rather than a generated file name.

```sh
pnpm --filter @frogbyte-io/fleet-api-client generate         # regenerate
pnpm --filter @frogbyte-io/fleet-api-client check:generated  # verify, used by CI
```

`openapi.json` is itself generated, by `cargo run -p fleet-api --bin
fleet-openapi -- generate`. The chain is Rust handlers → OpenAPI document →
TypeScript client, and it only runs in that direction. Editing the document or
the client by hand produces a client that describes an API the controller does
not serve, which is the exact failure the chain exists to prevent.

`check:generated` regenerates into a temporary directory and compares. It never
rewrites in place: a stale client must fail the build rather than be quietly
corrected, because the difference between the two is an API change nobody
reviewed.

The orval version is pinned. It was selected by spike FM-S01 against recorded
evidence; changing the pin means rerunning that evidence, not editing
`package.json`. See `docs/research/ecosystem.md`.

The package ships TypeScript source rather than a build output. Its only
consumer is the Vue application in the same pnpm workspace, whose bundler
compiles it, so a separate emit step would add an artifact with no reader.
