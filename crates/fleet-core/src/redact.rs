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
        let authority_end = after.find(['/', '?', '#']).unwrap_or(after.len());
        let authority = &after[..authority_end];
        let tail = &after[authority_end..];
        match authority.split_once('@') {
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
            result.push_str("***@");
            search = at + 1;
        } else {
            result.push_str(&text[search..=at]);
            search = at + 1;
        }
    }
    result.push_str(&text[search..]);
    result
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
    fn control_noise_is_flattened() {
        let flattened = flatten_control_characters("a\u{1b}[31mb\nc");
        assert!(!flattened.contains('\u{1b}'), "{flattened}");
        assert!(flattened.contains('\n'), "newlines survive");
    }
}
