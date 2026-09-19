//! The difference model (FM-401): the stable drift vocabulary between
//! desired resources and observed state.
//!
//! Five states, exactly as `docs/architecture/desired-state.md` defines:
//! `missing` (desired, not observed), `extra` (observed, not desired),
//! `changed` (both present, values differ), `unknown` (the observation
//! was unavailable), and `unsupported` (the field has no normalization
//! path for this provider). `unknown` and `unsupported` are honest
//! terminal states: they are never coerced into `changed`, and a planner
//! consuming a difference set refuses to act on them.
//!
//! The model is a pure data structure with no I/O and no execution: a
//! difference set describes the world; the planner (a separate module)
//! decides what to do about it.
#![warn(missing_docs)]

use serde::{Deserialize, Serialize};

/// The drift state of one compared field.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum DifferenceState {
    /// Desired, not observed.
    Missing,
    /// Observed, not desired.
    Extra,
    /// Both present, values differ.
    Changed,
    /// The observation was unavailable: the truth is not knowable.
    Unknown,
    /// The field has no normalization path for this provider.
    Unsupported,
}

impl DifferenceState {
    /// The state's stable id, as serialized in plans and API payloads.
    #[must_use]
    pub fn id(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Extra => "extra",
            Self::Changed => "changed",
            Self::Unknown => "unknown",
            Self::Unsupported => "unsupported",
        }
    }

    /// Whether a planner may act on this state. `unknown` and
    /// `unsupported` are never actionable: acting on an unknown state
    /// would be guessing, and an unsupported state has no path.
    #[must_use]
    pub fn actionable(self) -> bool {
        matches!(self, Self::Missing | Self::Extra | Self::Changed)
    }
}

impl std::fmt::Display for DifferenceState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.id())
    }
}

/// One compared field: what was desired, what was observed, and the state
/// between them. Values are opaque strings — the comparison happens in
/// the normalizer, and this model carries the evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FieldDifference {
    /// The field's stable identity, e.g. `tool:node` or
    /// `skill:db/claude_code`.
    pub identity: String,
    /// The drift state.
    pub state: DifferenceState,
    /// The desired value, when the field is desired.
    pub desired: Option<String>,
    /// The observed value, when one was observed.
    pub observed: Option<String>,
    /// Why the state is `unknown` or `unsupported`, when it is.
    pub reason: Option<String>,
}

impl FieldDifference {
    /// A `missing` field: desired, not observed.
    #[must_use]
    pub fn missing(identity: &str, desired: &str) -> Self {
        Self {
            identity: identity.to_owned(),
            state: DifferenceState::Missing,
            desired: Some(desired.to_owned()),
            observed: None,
            reason: None,
        }
    }

    /// An `extra` field: observed, not desired.
    #[must_use]
    pub fn extra(identity: &str, observed: &str) -> Self {
        Self {
            identity: identity.to_owned(),
            state: DifferenceState::Extra,
            desired: None,
            observed: Some(observed.to_owned()),
            reason: None,
        }
    }

    /// A `changed` field: both present, values differ.
    #[must_use]
    pub fn changed(identity: &str, desired: &str, observed: &str) -> Self {
        Self {
            identity: identity.to_owned(),
            state: DifferenceState::Changed,
            desired: Some(desired.to_owned()),
            observed: Some(observed.to_owned()),
            reason: None,
        }
    }

    /// An `unknown` field: the observation was unavailable. The desired
    /// value is preserved so consumers can explain the target they could
    /// not verify.
    #[must_use]
    pub fn unknown(identity: &str, desired: Option<&str>, reason: &str) -> Self {
        Self {
            identity: identity.to_owned(),
            state: DifferenceState::Unknown,
            desired: desired.map(str::to_owned),
            observed: None,
            reason: Some(reason.to_owned()),
        }
    }

    /// An `unsupported` field: no normalization path for this provider.
    /// The desired value is preserved for the same reason.
    #[must_use]
    pub fn unsupported(identity: &str, desired: Option<&str>, reason: &str) -> Self {
        Self {
            identity: identity.to_owned(),
            state: DifferenceState::Unsupported,
            desired: desired.map(str::to_owned),
            observed: None,
            reason: Some(reason.to_owned()),
        }
    }

    /// Whether a planner may act on this difference.
    #[must_use]
    pub fn actionable(&self) -> bool {
        self.state.actionable()
    }
}

/// The complete difference set for one machine: compared fields in
/// stable identity order, so the same inputs always render the same
/// plan and the same dry-run output.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DifferenceSet {
    /// The compared fields, ordered by identity.
    pub fields: Vec<FieldDifference>,
}

impl DifferenceSet {
    /// An empty set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds one field difference.
    pub fn push(&mut self, difference: FieldDifference) {
        self.fields.push(difference);
    }

    /// Sorts the fields by identity and deduplicates: the canonical form
    /// the planner and the dry-run rendering consume. When duplicate
    /// identities carry different states, the honest terminal state wins —
    /// an `unknown` discarded in favor of an actionable state would let a
    /// planner act on a guess.
    pub fn canonicalize(&mut self) {
        self.fields.sort_by(|a, b| a.identity.cmp(&b.identity));
        // Sort duplicates so the honest terminal state sorts FIRST within
        // its identity group (descending precedence); dedup_by keeps the
        // first element of a run.
        self.fields.sort_by(|a, b| {
            a.identity
                .cmp(&b.identity)
                .then_with(|| state_precedence(b.state).cmp(&state_precedence(a.state)))
        });
        self.fields.dedup_by(|a, b| a.identity == b.identity);
    }

    /// The actionable fields, in canonical order: what a planner may act
    /// on. `unknown` and `unsupported` are excluded by definition.
    #[must_use]
    pub fn actionable(&self) -> Vec<&FieldDifference> {
        self.fields
            .iter()
            .filter(|field| field.actionable())
            .collect()
    }

    /// Whether the machine is converged: no actionable differences and
    /// no honest unknowns. An `unsupported` field does not block
    /// convergence (it is reported, not acted on), but an `unknown` does —
    /// the machine's state is not knowable enough to claim readiness.
    #[must_use]
    pub fn converged(&self) -> bool {
        self.fields.iter().all(|field| match field.state {
            DifferenceState::Unknown => false,
            DifferenceState::Unsupported
            | DifferenceState::Missing
            | DifferenceState::Extra
            | DifferenceState::Changed => !field.actionable(),
        })
    }
}

/// The precedence that decides which duplicate identity survives
/// canonicalization: the higher value wins. Honest terminal states
/// outrank actionable ones — `unknown` (3) and `unsupported` (2) beat
/// `missing`/`extra`/`changed` (1).
fn state_precedence(state: DifferenceState) -> u8 {
    match state {
        DifferenceState::Unknown => 3,
        DifferenceState::Unsupported => 2,
        _ => 1,
    }
}

/// Compares one desired field against one observed value. The single
/// comparison point every normalizer funnels through, so the vocabulary
/// stays consistent: a desired value with no observation is `missing`,
/// an observation with no desired value is `extra`, equal values are
/// converged (omitted from the set), and differing values are `changed`.
#[must_use]
pub fn compare_field(
    identity: &str,
    desired: Option<&str>,
    observed: Option<&str>,
) -> Option<FieldDifference> {
    match (desired, observed) {
        (Some(desired), Some(observed)) if desired == observed => None,
        (Some(desired), Some(observed)) => {
            Some(FieldDifference::changed(identity, desired, observed))
        }
        (Some(desired), None) => Some(FieldDifference::missing(identity, desired)),
        (None, Some(observed)) => Some(FieldDifference::extra(identity, observed)),
        (None, None) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{DifferenceSet, DifferenceState, FieldDifference, compare_field};

    #[test]
    fn the_five_states_serialize_stably() {
        let states = [
            DifferenceState::Missing,
            DifferenceState::Extra,
            DifferenceState::Changed,
            DifferenceState::Unknown,
            DifferenceState::Unsupported,
        ];
        for state in states {
            assert_eq!(
                serde_json::to_string(&state).unwrap(),
                format!("\"{}\"", state.id())
            );
        }
    }

    #[test]
    fn compare_field_covers_every_combination() {
        assert_eq!(
            compare_field("tool:node", Some("20.11.0"), Some("20.11.0")),
            None
        );
        let changed = compare_field("tool:node", Some("20.11.0"), Some("18.0.0")).unwrap();
        assert_eq!(changed.state, DifferenceState::Changed);
        assert_eq!(changed.desired.as_deref(), Some("20.11.0"));
        assert_eq!(changed.observed.as_deref(), Some("18.0.0"));
        let missing = compare_field("tool:node", Some("20.11.0"), None).unwrap();
        assert_eq!(missing.state, DifferenceState::Missing);
        let extra = compare_field("tool:nginx", None, Some("1.27.0")).unwrap();
        assert_eq!(extra.state, DifferenceState::Extra);
        assert_eq!(compare_field("tool:node", None, None), None);
    }

    #[test]
    fn unknown_and_unsupported_are_never_actionable() {
        let unknown = FieldDifference::unknown(
            "tool:node",
            Some("20.11.0"),
            "the mise status did not answer",
        );
        let unsupported =
            FieldDifference::unsupported("tool:exotic", Some("1.0"), "no normalization path");
        assert!(!unknown.actionable());
        assert!(!unsupported.actionable());
        assert_eq!(unknown.state.to_string(), "unknown");
        assert_eq!(unsupported.state.to_string(), "unsupported");
    }

    #[test]
    fn actionable_states_are_actionable() {
        assert!(FieldDifference::missing("tool:node", "20.11.0").actionable());
        assert!(FieldDifference::extra("tool:nginx", "1.27.0").actionable());
        assert!(FieldDifference::changed("tool:node", "20.11.0", "18.0.0").actionable());
    }

    #[test]
    fn canonicalize_sorts_and_dedupes_by_identity() {
        let mut set = DifferenceSet::new();
        set.push(FieldDifference::changed("tool:node", "20.11.0", "18.0.0"));
        set.push(FieldDifference::missing("tool:python", "3.12.1"));
        set.push(FieldDifference::extra("tool:nginx", "1.27.0"));
        // A duplicate identity: canonicalize keeps the first.
        set.push(FieldDifference::missing("tool:node", "20.11.0"));
        set.canonicalize();
        let identities: Vec<&str> = set
            .fields
            .iter()
            .map(|field| field.identity.as_str())
            .collect();
        assert_eq!(identities, ["tool:nginx", "tool:node", "tool:python"]);
    }

    #[test]
    fn convergence_requires_no_unknowns() {
        let mut set = DifferenceSet::new();
        set.push(FieldDifference::unsupported(
            "tool:exotic",
            Some("1.0"),
            "no path",
        ));
        assert!(
            set.converged(),
            "an unsupported field is reported, not blocking"
        );
        set.push(FieldDifference::unknown(
            "tool:mystery",
            Some("1.0"),
            "no answer",
        ));
        assert!(
            !set.converged(),
            "an unknown field blocks the readiness claim"
        );
    }

    #[test]
    fn canonicalize_keeps_the_honest_terminal_state_on_duplicates() {
        // An actionable difference followed by an honest unknown: the
        // unknown survives, because acting on the actionable one would be
        // guessing.
        let mut set = DifferenceSet::new();
        set.push(FieldDifference::missing("tool:node", "20.11.0"));
        set.push(FieldDifference::unknown(
            "tool:node",
            Some("20.11.0"),
            "the inventory did not answer",
        ));
        set.canonicalize();
        assert_eq!(set.fields.len(), 1);
        assert_eq!(set.fields[0].state, DifferenceState::Unknown);
    }

    #[test]
    fn actionable_excludes_the_honest_states() {
        let mut set = DifferenceSet::new();
        set.push(FieldDifference::missing("tool:node", "20.11.0"));
        set.push(FieldDifference::unknown(
            "tool:mystery",
            Some("1.0"),
            "no answer",
        ));
        set.push(FieldDifference::unsupported(
            "tool:exotic",
            Some("1.0"),
            "no path",
        ));
        set.canonicalize();
        let actionable = set.actionable();
        assert_eq!(actionable.len(), 1);
        assert_eq!(actionable[0].identity, "tool:node");
    }
}
