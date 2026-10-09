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

/// Names whose `name=value` value is a secret. A word matches when it ENDS
/// with one (so `GITHUB_TOKEN=` and `access_token=` match).
const SECRET_KEYS: [&str; 14] = [
    "token",
    "password",
    "passwd",
    "secret",
    "apikey",
    "api_key",
    "api-key",
    "passphrase",
    "credential",
    "credentials",
    "secret_key",
    "access_key",
    "private_key",
    "signature",
];

const MASK: &str = "***";

/// Redacts header and pair shapes: `Authorization: <anything to end of
/// line>`, `Bearer <token>`, and `token=<value>` style pairs for the names in
/// [`SECRET_KEYS`]. Matching is ASCII case-insensitive and linear.
#[must_use]
pub fn redact_secret_pairs(text: &str) -> String {
    let text = mask_authorization(text);
    let text = mask_bearer(&text);
    mask_key_values(&text)
}

fn is_word_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.')
}

/// `Authorization: value`, `Authorization=value` or the JSON form
/// `"Authorization": "value"`: an unquoted value runs to the end of the line
/// or a closing quote, a quoted one to its matching quote.
fn mask_authorization(text: &str) -> String {
    const NAME: &str = "authorization";
    let lower = text.to_ascii_lowercase();
    let mut result = String::with_capacity(text.len());
    let mut cursor = 0;
    while let Some(offset) = lower[cursor..].find(NAME) {
        let start = cursor + offset;
        let name_end = start + NAME.len();
        let boundary = text[..start]
            .chars()
            .next_back()
            .is_none_or(|c| !is_word_char(c));
        let after = text[name_end..].trim_start_matches([' ', '\t', '"', '\'']);
        let separator = name_end + (text.len() - name_end - after.len());
        if boundary && after.starts_with([':', '=']) {
            let value_start = separator + 1;
            let (masked_start, value_end) = value_extent(text, value_start, true);
            result.push_str(&text[cursor..masked_start]);
            result.push_str(MASK);
            cursor = value_end;
        } else {
            result.push_str(&text[cursor..name_end]);
            cursor = name_end;
        }
    }
    result.push_str(&text[cursor..]);
    result
}

/// The extent of a value starting at `start` (after optional spaces): a
/// quoted value runs to its matching quote or the line end; an unquoted one
/// to whitespace, a quote, `&`, `;` or `,`, or (for a header, `to_line_end`)
/// to the line end or a quote.
fn value_extent(text: &str, start: usize, to_line_end: bool) -> (usize, usize) {
    let start = start + (text.len() - start - text[start..].trim_start_matches([' ', '\t']).len());
    let rest = &text[start..];
    if let Some(quote) = rest.chars().next().filter(|c| matches!(c, '"' | '\'')) {
        let inner = start + 1;
        let end = text[inner..]
            .find([quote, '\n'])
            .map_or(text.len(), |end| inner + end);
        return (inner, end);
    }
    let end = if to_line_end {
        rest.find(['\n', '"', '\''])
    } else {
        rest.find(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | '&' | ';' | ','))
    };
    (start, end.map_or(text.len(), |end| start + end))
}

/// A shorter word after "bearer" is prose ("the bearer of news"), not a token.
const BEARER_MIN_TOKEN: usize = 8;

/// `Bearer <token>`: the token runs to whitespace, a quote or a comma.
fn mask_bearer(text: &str) -> String {
    const NAME: &str = "bearer ";
    let lower = text.to_ascii_lowercase();
    let mut result = String::with_capacity(text.len());
    let mut cursor = 0;
    while let Some(offset) = lower[cursor..].find(NAME) {
        let start = cursor + offset;
        let value_start = start + NAME.len();
        let boundary = text[..start]
            .chars()
            .next_back()
            .is_none_or(|c| !is_word_char(c));
        let value_end = text[value_start..]
            .find(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | ',' | ')' | '}' | ';'))
            .map_or(text.len(), |end| value_start + end);
        result.push_str(&text[cursor..value_start]);
        if boundary
            && value_end - value_start >= BEARER_MIN_TOKEN
            && &text[value_start..value_end] != MASK
        {
            result.push_str(MASK);
        } else {
            result.push_str(&text[value_start..value_end]);
        }
        cursor = value_end;
    }
    result.push_str(&text[cursor..]);
    result
}

/// `name=value`, and the JSON form `"name": "value"`, where the word before
/// the separator ends with a secret name.
fn mask_key_values(text: &str) -> String {
    let mut result = String::with_capacity(text.len());
    let mut cursor = 0;
    let mut search = 0;
    while let Some(offset) = text[search..].find(['=', ':']) {
        let separator = search + offset;
        search = separator + 1;
        let mut key_end = separator;
        if text.as_bytes()[separator] == b':' {
            // Only the quoted-key JSON form: a bare `name: value` is prose.
            match text[..separator].chars().next_back() {
                Some(quote @ ('"' | '\'')) => key_end -= quote.len_utf8(),
                _ => continue,
            }
        }
        let key_start = text[..key_end]
            .char_indices()
            .rev()
            .take_while(|(_, c)| is_word_char(*c))
            .last()
            .map_or(key_end, |(index, _)| index);
        let key = text[key_start..key_end].to_ascii_lowercase();
        // The value is only scanned once the key names a secret, so a long
        // run of '=' with no secret name stays linear.
        if !SECRET_KEYS.iter().any(|name| key.ends_with(name)) {
            continue;
        }
        let (value_start, value_end) = value_extent(text, separator + 1, false);
        if value_end > value_start && &text[value_start..value_end] != MASK {
            result.push_str(&text[cursor..value_start]);
            result.push_str(MASK);
            cursor = value_end;
            search = value_end;
        }
    }
    result.push_str(&text[cursor..]);
    result
}

/// Redacts every credential shape this module knows: URL userinfo,
/// schemeless `user:password@`, then `Authorization`, `Bearer` and
/// `token=` style pairs. The single entry point for output that is stored or
/// returned (command output, logs), so a fix lands once.
#[must_use]
pub fn redact_credentials(text: &str) -> String {
    redact_secret_pairs(&redact_schemeless_credentials(&redact_url_credentials(
        text,
    )))
}

/// Flattens control characters (except newlines) to spaces: hostile
/// terminal output stays data.
#[must_use]
pub fn flatten_control_characters(text: &str) -> String {
    text.chars()
        .map(|c| if c.is_control() && c != '\n' { ' ' } else { c })
        .collect()
}

/// The bound for stored result and failure text; output is trimmed to fit.
pub const RESULT_STRING_BOUND: usize = 3_000;

/// How much of a stream is scrubbed before it is bounded.
const SCRUB_WINDOW: usize = 16 * 1024;

/// Scrubs credential shapes from stored text, then bounds it, with an extra,
/// tool-specific scrub that runs after the shared one and still before the
/// bound. Anything that stores command, node or tool text uses this so no
/// credential straddling the bound is ever half kept. The pure home of the
/// scrubber, so the application layer (worker failure details) and the
/// controller executors share one implementation.
#[must_use]
pub fn scrub_and_bound_with(
    text: &str,
    provider_truncated: bool,
    extra: impl FnOnce(&str) -> String,
) -> (String, bool) {
    // The transport allows up to 1 MiB per stream, so scrub only a window
    // that is far larger than the bound (the shared scrubber is linear, but
    // tool-specific ones need not be). A cut window ends at whitespace, so no credential is
    // split by it, and the dropped remainder counts as truncation.
    let (window, windowed) = scrub_window(text);
    // Scrub credentials first (a credential wrapped in terminal colour codes
    // is still one token then), then flatten control characters: terminal
    // escapes are hostile as output, and each JSON-escapes to up to six
    // bytes, which could push a result past its stored size limit.
    let scrubbed = flatten_control_characters(&extra(&redact_credentials(window)));
    let (mut bounded, cut) = trim_to_bound(&scrubbed);
    if windowed && !cut {
        // The window dropped the rest; say so in the text as well as the flag.
        bounded.push('…');
    }
    (bounded, provider_truncated || windowed || cut)
}

/// A failure detail as it is stored: scrubbed, flattened and bounded. The
/// one call every operation-failure writer uses for executor error text.
#[must_use]
pub fn scrub_failure_detail(detail: &str) -> String {
    scrub_and_bound_with(detail, false, str::to_owned).0
}

/// The prefix of `text` that is scrubbed, and whether text was left out. A
/// cut window always ends at whitespace, so no token (and no credential) is
/// split by it; a window with no whitespace at all keeps nothing.
#[must_use]
pub fn scrub_window(text: &str) -> (&str, bool) {
    if text.len() <= SCRUB_WINDOW {
        return (text, false);
    }
    let mut end = SCRUB_WINDOW;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    let end = text[..end].rfind(char::is_whitespace).unwrap_or(0);
    (&text[..end], true)
}

/// Cuts `text` so its JSON-escaped form is within [`RESULT_STRING_BOUND`]
/// bytes: `"`, `\` and newlines escape to two bytes, so a stream made of them
/// would otherwise double. Two such streams then still fit the stored result
/// limit.
#[must_use]
pub fn trim_to_bound(text: &str) -> (String, bool) {
    let mut escaped = 0;
    for (index, c) in text.char_indices() {
        escaped += match c {
            '"' | '\\' | '\n' => 2,
            other => other.len_utf8(),
        };
        if escaped > RESULT_STRING_BOUND {
            return (format!("{}…", &text[..index]), true);
        }
    }
    (text.to_owned(), false)
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
        let alphabet = [
            'a', 'b', ':', '@', '@', ' ', '/', '"', '\'', 'é', '\n', '\u{3000}', '\t',
        ];
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

    #[test]
    fn secret_pair_shapes_are_masked() {
        let cases = [
            (
                "Authorization: Basic ZmFrZTpmYWtl\nnext",
                "Authorization: ***\nnext",
            ),
            ("authorization=Token fakevalue", "authorization=***"),
            (
                "curl -H 'Authorization: Bearer fake-abc' x",
                "curl -H 'Authorization: ***' x",
            ),
            ("sent Bearer fake-abc.def, ok", "sent Bearer ***, ok"),
            ("token=fake123 other=1", "token=*** other=1"),
            ("GITHUB_TOKEN=fakegh&x=1", "GITHUB_TOKEN=***&x=1"),
            ("url ?access_token=fake9&a=b", "url ?access_token=***&a=b"),
            ("PASSWORD=\"fake pw tail\" x", "PASSWORD=\"***\" x"),
            (
                "{\"Authorization\": \"Basic fakebasic\"} x",
                "{\"Authorization\": \"***\"} x",
            ),
            (
                "{\"token\":\"fake-json\",\"a\":1}",
                "{\"token\":\"***\",\"a\":1}",
            ),
            ("AWS_SECRET_KEY=fakeaws ok", "AWS_SECRET_KEY=*** ok"),
            ("(Bearer fakebearer9)", "(Bearer ***)"),
            ("db api-key=fakekey;", "db api-key=***;"),
        ];
        for (input, expected) in cases {
            let out = redact_secret_pairs(input);
            assert!(
                !out.contains("fake-abc") && !out.contains("fake123"),
                "{out}"
            );
            assert!(!out.contains("fakekey") && !out.contains("fakegh"), "{out}");
            assert!(!out.contains("fake9") && !out.contains("ZmFrZ"), "{out}");
            for leaked in [
                "fake pw",
                "fakebasic",
                "fake-json",
                "fakeaws",
                "fakebearer9",
            ] {
                assert!(!out.contains(leaked), "{out}");
            }
            assert_eq!(out, expected);
        }
    }

    #[test]
    fn secret_pair_scrub_leaves_ordinary_text_and_is_idempotent() {
        for text in [
            "the bearer of bad news, a=b, tokens=3, key=value",
            "no secrets here: a == b",
            "token=",
            "x=y=z",
        ] {
            assert_eq!(redact_secret_pairs(text), text);
        }
        let once = redact_credentials("token=fake1 Bearer fakebearer2 Authorization: fake3");
        assert_eq!(redact_credentials(&once), once);
        assert!(!once.contains("fake"), "{once}");
    }

    #[test]
    fn secret_pair_scrub_is_linear_on_pathological_input() {
        let text = "=a".repeat(100_000) + &"token=".repeat(50_000);
        let _ = redact_credentials(&text);
    }
}
