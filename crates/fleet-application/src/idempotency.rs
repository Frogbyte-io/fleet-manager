//! The one construction of a caller-scoped idempotency key.
//!
//! A key is scoped to the principal that supplied it, so no other principal
//! can replay it. Principal ids and caller-chosen keys may both contain `:`
//! (Tailscale principal ids, free-form keys), so joining them with a bare
//! separator is ambiguous: `("a:b", "c")` and `("a", "b:c")` would spell the
//! same scope. Every part except the last is therefore length-prefixed. The
//! last part is delimited by the end of the string, so for one `kind` (each
//! of which has a fixed number of parts in code) no two distinct inputs
//! share a scope.
//!
//! Stored keys written before this construction used `{principal}:{key}`
//! (and `{principal}:lab-exec:{id}:{key}` and the like). They are not
//! rewritten: a retry that spans the upgrade is a new request. See
//! `docs/operations/lab.md`.

/// The namespace for a mutation that is not itself a Lab operation.
pub const CALLER_KEY: &str = "caller";

/// Builds the scoped key `{kind}:{len}:{principal}[:{len}:{part}]*:{last}`.
///
/// `kind` names the mutation (a fixed, code-chosen word without `:`);
/// `principal` is the identity the key is scoped to; `parts` are the further
/// components, the final one usually the caller's own key. `len` counts
/// bytes (`str::len`), so it is stable for any text.
///
/// # Panics
///
/// Panics when `parts` is empty: a scope with no key is a programming error.
#[must_use]
pub fn scoped_key(kind: &str, principal: &str, parts: &[&str]) -> String {
    use std::fmt::Write as _;
    debug_assert!(
        !kind.contains(':'),
        "an idempotency kind must not contain ':'"
    );
    let (last, leading) = parts
        .split_last()
        .expect("a scoped idempotency key needs at least one part");
    let mut scoped = format!("{kind}:{}:{principal}", principal.len());
    for part in leading {
        let _ = write!(scoped, ":{}:{part}", part.len());
    }
    scoped.push(':');
    scoped.push_str(last);
    scoped
}

#[cfg(test)]
mod tests {
    use super::scoped_key;

    #[test]
    fn matches_the_lease_creation_format() {
        assert_eq!(
            scoped_key("lab-lease-create", "alice", &["k1"]),
            "lab-lease-create:5:alice:k1"
        );
    }

    #[test]
    fn principals_and_keys_that_collide_when_joined_stay_distinct() {
        let a = scoped_key(super::CALLER_KEY, "tailscale:a", &["b:c"]);
        let b = scoped_key(super::CALLER_KEY, "tailscale:a:b", &["c"]);
        assert_ne!(a, b);
        assert_ne!(
            scoped_key("lab-exec", "p", &["lease:x", "k"]),
            scoped_key("lab-exec", "p", &["lease", "x:k"]),
        );
    }

    /// The old joins, per scope: each pair below spelled one string.
    #[test]
    fn every_scope_kind_separates_colliding_pairs() {
        for kind in [super::CALLER_KEY, "lab-provision", "lab-lease-create"] {
            assert_ne!(
                scoped_key(kind, "a", &["b:c"]),
                scoped_key(kind, "a:b", &["c"]),
                "{kind}"
            );
        }
        // exec and collect: {principal}:{kind}:{lease}:{key}
        for kind in ["lab-exec", "lab-collect"] {
            assert_ne!(
                scoped_key(kind, "a", &["lease", "b:c"]),
                scoped_key(kind, "a:b", &["lease", "c"]),
                "{kind}"
            );
            assert_ne!(
                scoped_key(kind, "a", &["l:1", "k"]),
                scoped_key(kind, "a", &["l", "1:k"]),
                "{kind}"
            );
        }
        // put: {principal}:lab-put:{lease}:{binding}:{key}
        assert_ne!(
            scoped_key("lab-put", "a", &["lease", "bind", "b:c"]),
            scoped_key("lab-put", "a:b", &["lease", "bind", "c"]),
        );
        assert_ne!(
            scoped_key("lab-put", "a", &["lease", "bind:x", "k"]),
            scoped_key("lab-put", "a", &["lease", "bind", "x:k"]),
        );
    }
}
