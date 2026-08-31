# Public API conventions

`fleet-api` owns the shape of `/api/v1` and generates
[`packages/api-client/openapi.json`](../../packages/api-client/openapi.json)
from the router the controller actually serves. A handler cannot be served
without being documented, and the document cannot describe an endpoint that does
not exist.

```sh
cargo run -p fleet-api --bin fleet-openapi -- generate          # rewrite
cargo run -p fleet-api --bin fleet-openapi -- generate --check  # verify, used by CI
```

## Envelopes

| Shape | Used for |
|---|---|
| `Resource<T>` | one resource, under `data`, so later top-level fields are additive |
| `Page<T>` with `PageInfo` | list endpoints; opaque cursor, explicit limit |
| `OperationAccepted` | mutations, which return a durable operation rather than holding the request open |
| `ApiError` with `FieldViolation` | every unsuccessful response |

`PageInfo`, `OperationAccepted`, and the error types are published components
before any endpoint returns them. They are the contract, not a by-product of the
endpoints that happen to exist today.

## Headers

| Header | Direction | Meaning |
|---|---|---|
| `x-correlation-id` | request, optional | Ties this request to work the caller already tracks. Must be a canonical opaque Fleet identity; a malformed value is refused with `400`, never silently replaced, because substituting an identity breaks the audit trail the caller was trying to join. |
| `x-correlation-id` | response, always | The identity recorded with this request's audit events. Present on success, on errors, and on responses no handler produced. |
| `idempotency-key` | request, mutations | Replaying a mutation with the same key returns the original operation instead of starting a second one. |

## Pagination and filtering

Cursor-based, never offset-based: an offset silently skips or repeats rows when
the underlying set changes between requests. Cursors are opaque; a client that
parses one is depending on an implementation detail. Filters are explicit named
query parameters per endpoint — there is no general query language, because one
would be an unbounded and unauthorizable surface.

## Compatibility policy

`/api/v1` is a published contract. Within it:

**Allowed without a version bump**

- Adding an endpoint.
- Adding an optional request field or query parameter, with unchanged behaviour
  when it is absent.
- Adding a response field. Clients must ignore fields they do not know; the
  generated TypeScript client does.
- Adding a *request* enum value, provided the existing values keep their
  meaning.
- Relaxing a validation rule, so previously rejected requests now succeed.

**Requires `/api/v2`**

- Removing or renaming any field, endpoint, or enum value.
- Adding a *response* enum value that existing clients cannot ignore, changing a
  field's type or nullability, or making an optional request field required.
- Changing the status code, error code, or semantics of an existing operation.
- Tightening validation so a previously accepted request is refused.

Error `code` values and the `x-correlation-id` header name are part of the
contract at the same level as the paths: clients branch on them. `message` text
is not — it may be reworded at any time, which is why nothing should parse it.

A future removal is announced by marking the operation deprecated in the
document first; the version stays supported until its replacement exists and
clients have moved. Two API versions may be served at once. The node protocol in
`proto/` versions separately and on its own schedule: a change there does not
imply an API version bump, and vice versa.

## Layering

Everything here is an adapter. Authorization, operation creation, and audit
belong to the application layer, and this crate must not become the place a
business rule is enforced for the first time — a rule enforced only in an HTTP
handler is a rule `fleetctl`, the MCP server, and the node broker do not have.
