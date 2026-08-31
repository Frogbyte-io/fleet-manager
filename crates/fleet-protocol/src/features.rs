/// Returns feature flags in canonical form: sorted, deduplicated, and without
/// empty entries.
///
/// Both peers canonicalise before sending so that a flag set has one encoding,
/// which keeps frames byte-stable and comparable in tests and audit records.
#[must_use]
pub fn canonical_feature_flags<S: AsRef<str>>(flags: &[S]) -> Vec<String> {
    let mut canonical = flags
        .iter()
        .map(|flag| flag.as_ref().to_owned())
        .filter(|flag| !flag.is_empty())
        .collect::<Vec<_>>();
    canonical.sort();
    canonical.dedup();
    canonical
}

/// Returns the flags both peers offer, in canonical form.
///
/// A flag only one peer knows is dropped silently. Feature flags are additive
/// capability hints, so an unrecognised one must never fail a session; that is
/// what the protocol version is for.
#[must_use]
pub fn negotiate_feature_flags<S: AsRef<str>, T: AsRef<str>>(
    node: &[S],
    controller: &[T],
) -> Vec<String> {
    let offered = canonical_feature_flags(controller);
    canonical_feature_flags(node)
        .into_iter()
        .filter(|flag| offered.binary_search(flag).is_ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{canonical_feature_flags, negotiate_feature_flags};

    #[test]
    fn canonical_flags_are_sorted_deduplicated_and_nonempty() {
        assert_eq!(
            canonical_feature_flags(&["exec", "", "inventory", "exec"]),
            ["exec", "inventory"]
        );
    }

    #[test]
    fn negotiation_keeps_only_flags_both_peers_offer() {
        assert_eq!(
            negotiate_feature_flags(&["exec", "lab", "inventory"], &["inventory", "exec"]),
            ["exec", "inventory"]
        );
    }

    #[test]
    fn a_flag_only_one_peer_knows_is_dropped_rather_than_rejected() {
        assert!(negotiate_feature_flags(&["experimental"], &["exec"]).is_empty());
    }
}
