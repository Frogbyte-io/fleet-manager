# ADR-0009: Tailscale Serve identity as an optional request principal

Status: accepted for implementation with FM-944

## Context

The initial controller has no accounts and maps reachable callers to the fully privileged `anonymous-lan-admin`. Tailscale Serve can provide a signed-by-the-proxy user identity in `Tailscale-User-Login`, but tagged devices do not have a user identity and Serve omits these headers. Falling back to anonymous admin on an identity listener would silently turn missing authentication into full administration.

## Decision

- Keep the existing listener and its `anonymous-lan-admin` behavior for local CLI and host workflows.
- Add an opt-in listener bound only to `127.0.0.1`; accept it only when the connected TCP peer is also `127.0.0.1` and exactly one bounded, visible-ASCII `Tailscale-User-Login` is present.
- Reject missing, duplicate, malformed, or untrusted-peer claims with HTTP 401. Do not fall back to anonymous admin. Do not derive identity from `Forwarded`, `X-Forwarded-For`, or other headers.
- When enabled, require the regular listener to be loopback-only and require distinct addresses, so the anonymous listener cannot become a remote bypass.
- Map the claim to `tailscale:<login>` and use the existing full-admin policy. Per-user authorization, sessions, role assignment, and tagged-device access remain out of scope.
- Treat the controller host as trusted. Local processes can forge HTTP headers and already have access to the local anonymous-admin listener.
- Require Serve and the controller to share the host network namespace. In bridged containers the TCP peer is not loopback; reject rather than trusting a bridge gateway.

## Consequences

Missing identity on the dedicated listener is a deliberate 401, including for tagged devices. Operators must use a user-owned tailnet device for this entry point or continue to use the local listener. Docker Compose's default bridge deployment cannot enable this mode safely. This is caller attribution, not a security boundary against a compromised host or a replacement for scoped authorization.

## References

- [Tailscale Serve](https://tailscale.com/docs/features/tailscale-serve)
- Issue [FM-944](https://github.com/Frogbyte-io/fleet-manager/issues/147)
