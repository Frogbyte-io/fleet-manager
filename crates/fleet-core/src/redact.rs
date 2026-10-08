//! Shared credential redaction for provider CLI output (FM-302/303/304).
//!
//! Every provider that runs an external CLI exposes its output through
//! this module's scrubbers, so a redaction fix lands once and reaches all
//! of them: URL authorities, schemeless `user:password@` patterns, and
//! control noise.

/// Replaces `user:password@` userinfo in URLs with a marker.
#[must_use]
pub fn redact_url_credentials(text: &str) -> String {
    let mut result = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(position) = rest.find("://") {
        let (before, after) = rest.split_at(position + 3);
        result.push_str(before);
        // A URL authority never contains whitespace, quotes or angle
        // brackets: stop there, so a bare URL in multi-line output cannot
        // swallow the lines up to a later '@'.
        let authority_end = after
            .find(|c: char| {
                matches!(c, '/' | '?' | '#' | '"' | '\'' | '<' | '>') || c.is_whitespace()
            })
            .unwrap_or(after.len());
        let authority = &after[..authority_end];
        let tail = &after[authority_end..];
        // The authority's LAST '@' separates userinfo from host: a
        // password may itself contain unescaped '@' characters.
        match authority.rsplit_once('@') {
            Some((_userinfo, host)) => {
                result.push_str("***@");
                result.push_str(host);
            }
            None => result.push_str(authority),
        }
        rest = tail;
    }
    result.push_str(rest);
    result
}

/// Redacts `user:password@` patterns anywhere in the text — scp-style
/// remotes and error text the URL pass cannot see. The `'@'` is consumed
/// with the userinfo so the loop always advances.
#[must_use]
pub fn redact_schemeless_credentials(text: &str) -> String {
    let is_start_delimiter = |c: char| c.is_whitespace() || matches!(c, '/' | '"' | '\'');
    let mut result = String::with_capacity(text.len());
    let mut search = 0;
    // The scan position and the start of the token it is inside. The start
    // is tracked while scanning forward, so each '@' costs the text between
    // it and the previous '@', not a backward search over everything before
    // it: the whole pass is linear.
    let mut scanned = 0;
    let mut token_start = 0;
    // The first ':' inside the current token, tracked with the scan so the
    // userinfo split never rescans a long token.
    let mut colon: Option<usize> = None;
    while let Some(offset) = text[search..].find('@') {
        let at = search + offset;
        if scanned < at {
            for (index, c) in text[scanned..at].char_indices() {
                if is_start_delimiter(c) {
                    token_start = scanned + index + c.len_utf8();
                    colon = None;
                } else if c == ':' && colon.is_none() {
                    colon = Some(scanned + index);
                }
            }
        }
        let has_password = colon.is_some_and(|colon| colon > token_start && colon + 1 < at);
        if has_password {
            let flush_start = search.min(token_start);
            result.push_str(&text[flush_start..token_start]);
            // The credential extends to the token's END delimiter: a
            // password may contain '@', so the host separator is the LAST
            // '@' before that delimiter, and the whole userinfo — user,
            // password, and every internal '@' — is replaced.
            let credential_end = text[at..]
                .char_indices()
                .find(|(_, c)| c.is_whitespace() || *c == '"' || *c == '\'')
                .map_or(text.len(), |(index, _)| at + index);
            let host_separator = text[search..credential_end]
                .rfind('@')
                .map_or(at, |offset| search + offset);
            result.push_str("***@");
            result.push_str(&text[host_separator + 1..credential_end]);
            search = credential_end;
            // The end delimiter is a start delimiter too: scanning resumes
            // there, so the next token begins after it.
            scanned = credential_end;
            token_start = credential_end;
            colon = None;
        } else {
            result.push_str(&text[search..=at]);
            search = at + 1;
            scanned = at + 1;
        }
    }
    result.push_str(&text[search..]);
    result
}

/// Redacts every credential shape this module knows: URL userinfo, then
/// schemeless `user:password@`. The single entry point for output that is
/// stored or returned (command output, logs), so a fix lands once.
#[must_use]
pub fn redact_credentials(text: &str) -> String {
    redact_schemeless_credentials(&redact_url_credentials(text))
}

/// Flattens control characters (except newlines) to spaces: hostile
/// terminal output stays data.
#[must_use]
pub fn flatten_control_characters(text: &str) -> String {
    text.chars()
        .map(|c| if c.is_control() && c != '\n' { ' ' } else { c })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The previous, quadratic implementation (it searched backwards from
    /// every '@'), kept to prove the linear scan changes no output.
    fn reference_schemeless(text: &str) -> String {
        let mut result = String::with_capacity(text.len());
        let mut search = 0;
        while let Some(offset) = text[search..].find('@') {
            let at = search + offset;
            let token_start = text[..at]
                .char_indices()
                .rev()
                .find(|(_, c)| c.is_whitespace() || *c == '/' || *c == '"' || *c == '\'')
                .map_or(0, |(index, c)| index + c.len_utf8());
            let token = &text[token_start..at];
            let has_password = token
                .split_once(':')
                .is_some_and(|(user, password)| !user.is_empty() && !password.is_empty());
            if has_password {
                let flush_start = search.min(token_start);
                result.push_str(&text[flush_start..token_start]);
                let credential_end = text[at..]
                    .char_indices()
                    .find(|(_, c)| c.is_whitespace() || *c == '"' || *c == '\'')
                    .map_or(text.len(), |(index, _)| at + index);
                let host_separator = text[search..credential_end]
                    .rfind('@')
                    .map_or(at, |offset| search + offset);
                result.push_str("***@");
                result.push_str(&text[host_separator + 1..credential_end]);
                search = credential_end;
            } else {
                result.push_str(&text[search..=at]);
                search = at + 1;
            }
        }
        result.push_str(&text[search..]);
        result
    }

    #[test]
    fn the_linear_scan_matches_the_reference_on_random_text() {
        let alphabet = ['a', 'b', ':', '@', '@', ' ', '/', '"', '\'', 'é', '\n'];
        let mut state = 0x9e37_79b9_7f4a_7c15_u64;
        for _ in 0..20_000 {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            let length = (state >> 59) as usize + 1;
            let text: String = (0..length)
                .map(|_| {
                    state = state
                        .wrapping_mul(6_364_136_223_846_793_005)
                        .wrapping_add(1);
                    alphabet[(state >> 33) as usize % alphabet.len()]
                })
                .collect();
            assert_eq!(
                redact_schemeless_credentials(&text),
                reference_schemeless(&text),
                "{text:?}"
            );
        }
    }

    #[test]
    fn the_schemeless_scan_is_linear() {
        // Quadratic code takes tens of seconds on this input in a debug build.
        let started = std::time::Instant::now();
        for text in [
            "@".repeat(200_000),
            "a@".repeat(100_000),
            "a:@".repeat(70_000),
        ] {
            let _ = redact_credentials(&text);
        }
        assert!(
            started.elapsed() < std::time::Duration::from_secs(2),
            "{:?}",
            started.elapsed()
        );
    }

    #[test]
    fn url_authorities_are_redacted() {
        let redacted = redact_url_credentials("remote https://user:secret@host.invalid/repo.git");
        assert!(!redacted.contains("secret"), "{redacted}");
        assert!(redacted.contains("***@host.invalid"), "{redacted}");
    }

    #[test]
    fn schemeless_credentials_are_redacted_and_terminate() {
        let scp = redact_schemeless_credentials("cannot reach user:secret@host:repo for sync");
        assert!(!scp.contains("secret"), "{scp}");
        assert!(scp.contains("***@host:repo"), "{scp}");
        // Two '@' in one token: the loop terminates instead of panicking.
        let double = redact_schemeless_credentials("user:secret@host@x and more");
        assert!(!double.contains("secret"), "{double}");
    }

    #[test]
    fn a_password_containing_an_at_sign_stays_redacted() {
        // The URL authority's last '@' separates userinfo from host.
        let redacted = redact_url_credentials("https://user:p@ss@host.invalid/repo.git");
        assert!(!redacted.contains("p@ss"), "{redacted}");
        assert!(redacted.contains("***@host.invalid"), "{redacted}");
        // The schemeless pass consumes the whole credential: a password
        // with an '@' cannot leak its tail or double the marker.
        let schemeless = redact_schemeless_credentials("reach user:p@ss@host:repo now");
        assert!(!schemeless.contains("p@ss"), "{schemeless}");
        assert!(schemeless.contains("***@host:repo"), "{schemeless}");
    }

    #[test]
    fn redact_credentials_applies_both_passes() {
        let redacted = redact_credentials("a https://u:one@h.invalid/x b scp u:two@h.invalid:r c");
        assert!(
            !redacted.contains("one") && !redacted.contains("two"),
            "{redacted}"
        );
    }

    #[test]
    fn a_bare_url_does_not_swallow_following_lines() {
        let text = "see https://example.com\nmail bob@corp.example\nmore";
        assert_eq!(redact_url_credentials(text), text);
    }

    #[test]
    fn control_noise_is_flattened() {
        let flattened = flatten_control_characters("a\u{1b}[31mb\nc");
        assert!(!flattened.contains('\u{1b}'), "{flattened}");
        assert!(flattened.contains('\n'), "newlines survive");
    }
}
