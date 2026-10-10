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
const SECRET_KEYS: [&str; 24] = [
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
    "accesskeyid",
    "access_key_id",
    "access-key-id",
    "secretaccesskey",
    "secret_access_key",
    "secret-access-key",
    "sessionid",
    "session_id",
    "session-id",
    "sessid",
];

/// Short names that are only secret as a whole word or as a delimited
/// (`db_pass`, `db-pwd`) or camel-case (`dbPass`) suffix: a plain suffix
/// match would hit `bypass`, `compass` and `obsession`.
const DELIMITED_KEYS: [&str; 4] = ["pass", "pwd", "cookie", "session"];

const MASK: &str = "***";

/// Redacts header and pair shapes: `Authorization:` / `Cookie:` /
/// `Set-Cookie:` `<anything to end of line>`, PEM private keys, bare provider
/// tokens, `Basic <base64>`, short flags of known commands, `Bearer <token>`, `--password <value>` style flags, and
/// `token=<value>` / `password: <value>` style pairs for the names in
/// [`SECRET_KEYS`]. Matching is ASCII case-insensitive and linear.
#[must_use]
pub fn redact_secret_pairs(text: &str) -> String {
    settle(&strip_terminal_noise(text), secret_pairs_pass)
}

/// Runs `pass` once, and again while it keeps changing the text. A mask can
/// remove a delimiter or flag another rule keyed on (a masked backtick ends
/// no command, a masked key body joins two tokens), so a changed text is
/// scrubbed again until it settles, which makes the scrubber idempotent. Text
/// with no credential is scrubbed once. The cap keeps the cost a constant
/// factor.
fn settle(text: &str, pass: impl Fn(&str) -> String) -> String {
    let mut text = pass(text);
    for _ in 0..MAX_SETTLE_PASSES {
        let again = pass(&text);
        if again == text {
            break;
        }
        text = again;
    }
    text
}

/// Extra passes after the first: each only runs on text the last one changed.
const MAX_SETTLE_PASSES: usize = 4;

fn secret_pairs_pass(text: &str) -> String {
    let text = mask_private_keys(text);
    let text = mask_headers(&text);
    let text = mask_provider_tokens(&text);
    let text = mask_basic(&text);
    let text = mask_short_flags(&text);
    let text = mask_secret_flags(&text);
    let text = mask_bearer(&text);
    let text = mask_json_argv(&text);
    mask_key_values(&text)
}

fn is_word_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.')
}

/// `Authorization: value` (or another header name), `Authorization=value` or the JSON form
/// `"Authorization": "value"`: an unquoted value runs to the end of the line
/// or a closing quote, a quoted one to its matching quote.
fn mask_headers(text: &str) -> String {
    // `Proxy-Authorization` and `Set-Cookie` are their own names: the `-`
    // before the shorter word fails its word boundary.
    let mut text = text.to_owned();
    for name in [
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
    ] {
        text = mask_header(&text, name);
    }
    text
}

fn mask_header(text: &str, name: &str) -> String {
    let lower = text.to_ascii_lowercase();
    let mut result = String::with_capacity(text.len());
    let mut cursor = 0;
    while let Some(offset) = lower[cursor..].find(name) {
        let start = cursor + offset;
        let name_end = start + name.len();
        let boundary = text[..start]
            .chars()
            .next_back()
            .is_none_or(|c| !is_word_char(c));
        let after = text[name_end..].trim_start_matches([' ', '\t', '"', '\'']);
        let separator = name_end + (text.len() - name_end - after.len());
        if boundary && after.starts_with([':', '=']) {
            let value_start = separator + 1;
            let quote = text[..start]
                .chars()
                .next_back()
                .filter(|c| matches!(c, '"' | '\''));
            let (masked_start, value_end) = value_extent(text, value_start, Extent::Line { quote });
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
fn value_extent(text: &str, start: usize, mode: Extent) -> (usize, usize) {
    let start = start + (text.len() - start - text[start..].trim_start_matches([' ', '\t']).len());
    let rest = &text[start..];
    // A value opened by an escaped quote (`\"x\"`, a string inside JSON text)
    // runs to the next escaped quote.
    if let Some(quote) = rest
        .strip_prefix('\\')
        .and_then(|after| after.chars().next())
        .filter(|c| matches!(c, '"' | '\''))
    {
        let inner = start + 2;
        let bytes = text.as_bytes();
        let mut end = inner;
        while end < bytes.len()
            && bytes[end] != b'\n'
            && !(bytes[end] == b'\\' && bytes.get(end + 1) == Some(&(quote as u8)))
        {
            end += 1;
        }
        return (inner, end);
    }
    if let Some(quote) = rest.chars().next().filter(|c| matches!(c, '"' | '\'')) {
        let inner = start + 1;
        return (inner, quoted_end(text, inner, quote as u8));
    }
    let end = match mode {
        Extent::Line { quote: Some(quote) } => Some(quoted_end(text, start, quote as u8) - start),
        Extent::Line { quote: None } => rest.find('\n'),
        Extent::Word => {
            rest.find(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | '&' | ';' | ','))
        }
    };
    (start, end.map_or(text.len(), |end| start + end))
}

/// Where a quoted string that starts at `from` ends: its closing quote, or
/// the line end. A backslash escapes the byte after it (`\"` inside JSON), so
/// an escaped quote does not close the string.
fn quoted_end(text: &str, from: usize, quote: u8) -> usize {
    let bytes = text.as_bytes();
    let mut at = from;
    while at < bytes.len() {
        match bytes[at] {
            b'\n' => return at,
            byte if byte == quote => return at,
            b'\\' if bytes.get(at + 1).is_some_and(|next| *next != b'\n') => at += 2,
            _ => at += 1,
        }
    }
    bytes.len()
}

/// How far an unquoted value runs.
#[derive(Clone, Copy)]
enum Extent {
    /// To whitespace, a quote, `&`, `;` or `,`.
    Word,
    /// To the end of the line, or to `quote`: the quote that opened the
    /// header (`-H 'Cookie: sid="x"; a=b'`), so a quote inside the value does
    /// not cut it short.
    Line { quote: Option<char> },
}

/// A shorter word after "bearer" is prose ("the bearer of news"), not a
/// token, unless it looks like one: see [`bearer_token_is_secret`].
const BEARER_MIN_TOKEN: usize = 8;

/// Shortest token that is still masked when it is not a plain word.
const BEARER_MIN_MIXED_TOKEN: usize = 4;

/// Whether the word after "bearer" is a token: long enough, or a short word
/// with a digit or symbol in it (a plain short word is prose).
fn bearer_token_is_secret(token: &str) -> bool {
    if token == MASK {
        return false;
    }
    token.len() >= BEARER_MIN_TOKEN
        || (token.len() >= BEARER_MIN_MIXED_TOKEN
            && token.chars().any(|c| !c.is_ascii_alphabetic()))
}

/// Where the token after `Bearer` starts: past spaces and tabs and at most
/// one line break, so a blank line ends the header rather than being crossed.
fn after_bearer_gap(text: &str, name_end: usize) -> usize {
    let blanks = |from: usize| {
        from + (text.len() - from - text[from..].trim_start_matches([' ', '\t']).len())
    };
    let mut at = blanks(name_end);
    if text[at..].starts_with("\r\n") {
        at = blanks(at + 2);
    } else if text[at..].starts_with('\n') {
        at = blanks(at + 1);
    }
    at
}

/// `Bearer <token>`: the token runs to whitespace, a quote or a comma, and
/// may follow the word after spaces, tabs and one line break.
fn mask_bearer(text: &str) -> String {
    const NAME: &str = "bearer";
    let lower = text.to_ascii_lowercase();
    let mut result = String::with_capacity(text.len());
    let mut cursor = 0;
    while let Some(offset) = lower[cursor..].find(NAME) {
        let start = cursor + offset;
        let name_end = start + NAME.len();
        let value_start = after_bearer_gap(text, name_end);
        let boundary = text[..start]
            .chars()
            .next_back()
            .is_none_or(|c| !is_word_char(c));
        if !boundary || value_start == name_end {
            result.push_str(&text[cursor..name_end]);
            cursor = name_end;
            continue;
        }
        let value_end = text[value_start..]
            .find(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | ',' | ')' | '}' | ';'))
            .map_or(text.len(), |end| value_start + end);
        result.push_str(&text[cursor..value_start]);
        if bearer_token_is_secret(&text[value_start..value_end]) {
            result.push_str(MASK);
        } else {
            result.push_str(&text[value_start..value_end]);
        }
        cursor = value_end;
    }
    result.push_str(&text[cursor..]);
    result
}

const PEM_FENCE: &str = "-----";

fn is_armor_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'=')
}

/// The label of a `PRIVATE KEY` fence whose label starts at `label_start`:
/// bounded, on one line, and ending in `PRIVATE KEY` (or ` BLOCK`).
fn private_key_label(text: &str, label_start: usize) -> Option<&str> {
    const LABEL_MAX: usize = 40;
    let tail = &text[label_start..];
    let limit = tail
        .char_indices()
        .nth(LABEL_MAX)
        .map_or(tail.len(), |(index, _)| index);
    let label = &tail[..tail[..limit].find(PEM_FENCE)?];
    (!label.contains('\n')
        && (label.ends_with("PRIVATE KEY") || label.ends_with("PRIVATE KEY BLOCK")))
    .then_some(label)
}

/// The length of the line break at `at` (`\n`, `\r\n`, or the same written
/// out as `\n` / `\r\n` inside a JSON string), if there is one.
fn line_break_len(text: &str, at: usize) -> Option<usize> {
    let rest = &text.as_bytes()[at..];
    ["\r\n", "\n", "\\r\\n", "\\n"]
        .iter()
        .find(|candidate| rest.starts_with(candidate.as_bytes()))
        .map(|candidate| candidate.len())
}

/// Armor header names that may sit between a fence and the base64 body
/// (RFC 7468, PEM, `OpenPGP`, `PuTTY`).
const ARMOR_HEADERS: [&str; 11] = [
    "proc-type",
    "dek-info",
    "comment",
    "version",
    "hash",
    "charset",
    "messageid",
    "originator",
    "key-info",
    "content-domain",
    "cipher",
];

/// A body line this long is key material whatever it contains.
const KEY_RUN_MIN: usize = 16;

/// A full base64 line of a key is at least this long; a short last line is
/// only key material after one.
const FULL_LINE_MIN: usize = 32;

/// The shortest run accepted behind a `name: ` prefix on a body line.
const PREFIXED_RUN_MIN: usize = 20;

/// Whether a run of armor bytes is key material and not a plain word: long,
/// or with a digit or symbol in it.
fn is_key_run(run: &[u8]) -> bool {
    run.len() >= KEY_RUN_MIN || run.iter().any(|byte| !byte.is_ascii_alphabetic())
}

fn is_blank_byte(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t')
}

/// `at` moved past spaces and tabs.
fn skip_blanks(bytes: &[u8], mut at: usize) -> usize {
    while at < bytes.len() && is_blank_byte(bytes[at]) {
        at += 1;
    }
    at
}

/// The length of the run of armor bytes at `at`.
fn armor_run_len(bytes: &[u8], at: usize) -> usize {
    bytes[at..]
        .iter()
        .take_while(|byte| is_armor_byte(**byte))
        .count()
}

/// Whether `at` ends a line: the end of the text or a line break.
fn at_line_end(text: &str, at: usize) -> bool {
    at == text.len() || line_break_len(text, at).is_some()
}

/// The end of the line starting at `from`.
fn line_end_from(text: &str, mut at: usize) -> usize {
    while !at_line_end(text, at) {
        at += 1;
    }
    at
}

/// A `Name: value` armor header line starting at `at` (after indentation):
/// its end.
fn armor_header_end(text: &str, at: usize) -> Option<usize> {
    let rest = &text[at..];
    let colon = rest.bytes().take(17).position(|byte| byte == b':')?;
    let name = &rest.as_bytes()[..colon];
    ARMOR_HEADERS
        .iter()
        .any(|header| name.eq_ignore_ascii_case(header.as_bytes()))
        .then(|| line_end_from(text, at + colon))
}

/// The end of the armor lines (base64, or `Proc-Type:` / `Version:` style
/// headers and at most one blank line before the body) that follow `from`:
/// key material on the fence line itself (a key joined with spaces), then
/// each following line. `from` when nothing there is armor. This is what a
/// PEM body looks like when its END line was cut off. Lines may be indented
/// (YAML); a first body line may carry a `name: ` prefix. A short plain word
/// is prose, except as the last line after a full one.
fn armor_end(text: &str, from: usize) -> usize {
    let bytes = text.as_bytes();
    let mut end = from;
    let mut body = false;
    let mut last_run = 0;
    // A key joined with spaces on the fence line: words of key material.
    loop {
        let word = skip_blanks(bytes, end);
        let run = armor_run_len(bytes, word);
        let after = word + run;
        if run == 0
            || !is_key_run(&bytes[word..after])
            || !(at_line_end(text, after) || is_blank_byte(bytes[after]))
        {
            break;
        }
        end = after;
        body = true;
        last_run = run;
    }
    let mut blank = false;
    let mut scan = end;
    while let Some(break_len) = line_break_len(text, scan) {
        let content = skip_blanks(bytes, scan + break_len);
        if at_line_end(text, content) {
            // One blank line may separate the headers from the body.
            if body || blank {
                break;
            }
            blank = true;
            scan = content;
            continue;
        }
        if !body && let Some(header_end) = armor_header_end(text, content) {
            end = header_end;
            scan = header_end;
            continue;
        }
        let mut start = content;
        if !body && let Some(prefix) = armor_prefix_len(&text[content..]) {
            start += prefix;
        }
        let run = armor_run_len(bytes, start);
        let after = start + run;
        let prefixed = start > content;
        let key = if prefixed {
            run >= PREFIXED_RUN_MIN && is_key_run(&bytes[start..after])
        } else {
            is_key_run(&bytes[start..after]) || (body && last_run >= FULL_LINE_MIN && run > 0)
        };
        if !key {
            break;
        }
        let short_last = run < KEY_RUN_MIN && !is_key_run(&bytes[start..after]);
        let tail = skip_blanks(bytes, after);
        if at_line_end(text, tail) {
            end = after;
            scan = tail;
            body = true;
            last_run = run;
            if short_last {
                break;
            }
        } else {
            if matches!(bytes[tail], b'"' | b'\'') {
                // The closing quote of a JSON or repr string ends the key.
                end = after;
            }
            break;
        }
    }
    end
}

/// The length of a `name: ` prefix at the start of a body line (`stderr: `).
fn armor_prefix_len(line: &str) -> Option<usize> {
    let colon = line
        .bytes()
        .take(17)
        .position(|byte| byte == b':')
        .filter(|colon| *colon >= 1)?;
    let name = &line.as_bytes()[..colon];
    let spaces = line[colon + 1..]
        .bytes()
        .take_while(|byte| is_blank_byte(*byte))
        .count();
    (spaces > 0
        && name
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.')))
    .then_some(colon + 1 + spaces)
}

/// Where the armor lines before an `END` fence at `fence` start, not going
/// back past `floor`: the front of a key whose BEGIN line was cut off. Lines
/// may be indented; the first line of the body may follow a `name: ` prefix
/// (the prefix stays). A short plain word is prose, except as the line right
/// before the fence after a full one.
fn armor_start(text: &str, floor: usize, fence: usize) -> usize {
    let bytes = text.as_bytes();
    // The fence may be indented; its line must start after a line break.
    let mut indent = fence;
    while indent > floor && is_blank_byte(bytes[indent - 1]) {
        indent -= 1;
    }
    let mut start = indent;
    // `start` before a short plain line was accepted: where to fall back to
    // when no full line precedes it.
    let mut short_from: Option<usize> = None;
    let mut first = true;
    loop {
        let fallback = short_from.unwrap_or(start);
        // The line before `start` ends at a break right before it.
        let Some(break_at) = [4usize, 2, 1]
            .into_iter()
            .map(|len| (len, start.checked_sub(len)))
            .find_map(|(len, at)| {
                let at = at.filter(|at| *at >= floor)?;
                (line_break_len(text, at) == Some(len)).then_some(at)
            })
        else {
            return fallback;
        };
        let mut run_end = break_at;
        while run_end > floor && is_blank_byte(bytes[run_end - 1]) {
            run_end -= 1;
        }
        let mut run_start = run_end;
        // The `n` of a written-out `\n` is not armor.
        while run_start > floor
            && is_armor_byte(bytes[run_start - 1])
            && !(bytes[run_start - 1] == b'n' && run_start >= 2 && bytes[run_start - 2] == b'\\')
        {
            run_start -= 1;
        }
        let run = &bytes[run_start..run_end];
        if run.is_empty() {
            return fallback;
        }
        let mut line_start = run_start;
        while line_start > floor && is_blank_byte(bytes[line_start - 1]) {
            line_start -= 1;
        }
        let at_line_start = line_start == floor
            || (1..=4).any(|len| {
                line_start
                    .checked_sub(len)
                    .is_some_and(|at| at >= floor && line_break_len(text, at) == Some(len))
            });
        if !at_line_start {
            // The first line of the body behind a `name: ` prefix: mask the
            // key run only.
            let prefixed = run.len() >= PREFIXED_RUN_MIN
                && is_key_run(run)
                && run_start > floor
                && is_blank_byte(bytes[run_start - 1]);
            return if prefixed { run_start } else { fallback };
        }
        if is_key_run(run) {
            if run.len() >= FULL_LINE_MIN {
                short_from = None;
            }
            // A key line right after an accepted short one that is not full
            // leaves the short one as prose.
            else if short_from.is_some() {
                return fallback;
            }
        } else if first && short_from.is_none() {
            short_from = Some(start);
        } else {
            return fallback;
        }
        first = false;
        start = line_start;
    }
}

/// The start of the last `-----END <label>-----` fence of every private key
/// label in `text`: one forward pass.
fn last_end_positions(text: &str) -> std::collections::HashMap<&str, usize> {
    let mut ends = std::collections::HashMap::new();
    let mut search = 0;
    while let Some(offset) = text[search..].find("-----END ") {
        let fence = search + offset;
        search = fence + 1;
        let label_start = fence + "-----END ".len();
        if let Some(label) = private_key_label(text, label_start) {
            ends.insert(label, fence);
        }
    }
    ends
}

/// `-----BEGIN ... PRIVATE KEY-----` up to the matching `-----END ...-----`
/// line. When the END line is missing (a cut stream) only the armor lines
/// right after the header are masked, not the rest of the output; an END line
/// whose BEGIN is missing masks the armor lines before it. The label is
/// bounded and must stay on the fence line, so a certificate or prose that
/// mentions the marker is not a key.
fn mask_private_keys(text: &str) -> String {
    let mut result = String::with_capacity(text.len());
    let mut cursor = 0;
    let mut search = 0;
    let mut last_end: Option<std::collections::HashMap<&str, usize>> = None;
    while let Some(offset) = text[search..].find(PEM_FENCE) {
        let fence = search + offset;
        search = fence + 1;
        let after = fence + PEM_FENCE.len();
        let (is_begin, label_start) = if text[after..].starts_with("BEGIN ") {
            (true, after + "BEGIN ".len())
        } else if text[after..].starts_with("END ") {
            (false, after + "END ".len())
        } else {
            continue;
        };
        let Some(label) = private_key_label(text, label_start) else {
            continue;
        };
        let marker_end = label_start + label.len() + PEM_FENCE.len();
        let (start, end) = if is_begin {
            let end_marker = format!("-----END {label}-----");
            // The last END of each label, found once for the whole text: a
            // BEGIN with no END after it is then an O(1) check, however many
            // distinct labels there are. Otherwise the first END after this
            // BEGIN is found, and everything up to it is consumed.
            let ends = last_end.get_or_insert_with(|| last_end_positions(text));
            let found = if ends.get(label).is_some_and(|last| *last >= marker_end) {
                text[marker_end..].find(&end_marker)
            } else {
                None
            };
            let end = found.map_or_else(
                || armor_end(text, marker_end),
                |at| marker_end + at + end_marker.len(),
            );
            (fence, end)
        } else {
            (armor_start(text, cursor, fence), marker_end)
        };
        result.push_str(&text[cursor..start]);
        result.push_str(MASK);
        cursor = end;
        search = end;
    }
    result.push_str(&text[cursor..]);
    result
}

fn is_word_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.')
}

/// Length of the run of bytes at the start of `text` that satisfy `accept`.
fn run_len(text: &str, accept: impl Fn(u8) -> bool) -> usize {
    text.bytes().take_while(|byte| accept(*byte)).count()
}

/// The length of a provider token at the start of `text`, matched against
/// the documented format of each provider so ordinary words do not match:
/// GitHub (`ghp_`/`gho_`/`ghu_`/`ghs_`/`ghr_` + 36 alphanumerics,
/// `github_pat_` + 22 or more), `OpenAI` and Anthropic (`sk-` + a long key), AWS access
/// key ids (`AKIA`/`ASIA` + 16 uppercase alphanumerics), Slack
/// (`xox[abeoprs]-`, `xapp-` + digits and dashes).
fn provider_token_len(text: &str) -> Option<usize> {
    let alnum = |byte: u8| byte.is_ascii_alphanumeric();
    let has_digit = |token: &str| token.bytes().any(|byte| byte.is_ascii_digit());
    let bytes = text.as_bytes();
    if bytes.starts_with(b"gh") && bytes.get(3) == Some(&b'_') {
        if !matches!(bytes[2], b'p' | b'o' | b'u' | b's' | b'r') {
            return None;
        }
        let run = run_len(&text[4..], alnum);
        return (run >= 36).then_some(4 + run);
    }
    if let Some(rest) = text.strip_prefix("github_pat_") {
        let run = run_len(rest, |byte| alnum(byte) || byte == b'_');
        return (run >= 22).then_some(11 + run);
    }
    if let Some(rest) = text.strip_prefix("sk-") {
        let run = run_len(rest, |byte| alnum(byte) || matches!(byte, b'_' | b'-'));
        return (run >= 32 && has_digit(&rest[..run])).then_some(3 + run);
    }
    if text.starts_with("AKIA") || text.starts_with("ASIA") {
        let run = run_len(&text[4..], alnum);
        let id = &text[4..4 + run];
        let upper = id
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit());
        return (run == 16 && upper).then_some(4 + run);
    }
    let slack = if text.starts_with("xapp-") {
        5
    } else if bytes.starts_with(b"xox") && bytes.get(4) == Some(&b'-') {
        if !matches!(bytes[3], b'a' | b'b' | b'e' | b'o' | b'p' | b'r' | b's') {
            return None;
        }
        5
    } else {
        return None;
    };
    let rest = &text[slack..];
    let run = run_len(rest, |byte| alnum(byte) || byte == b'-');
    (run >= 10 && has_digit(&rest[..run])).then_some(slack + run)
}

/// Bare provider tokens, wherever they appear. A token must start at a word
/// boundary, and every token's charset is made of word characters, so a
/// failed attempt never rescans text a later candidate could start in.
fn mask_provider_tokens(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut result = String::with_capacity(text.len());
    let mut cursor = 0;
    let mut index = 0;
    while index < bytes.len() {
        if matches!(bytes[index], b'g' | b's' | b'A' | b'x')
            && (index == 0 || !is_word_byte(bytes[index - 1]))
            && let Some(len) = provider_token_len(&text[index..])
        {
            result.push_str(&text[cursor..index]);
            result.push_str(MASK);
            index += len;
            cursor = index;
            continue;
        }
        index += 1;
    }
    result.push_str(&text[cursor..]);
    result
}

/// Whether a word after `Basic` is an encoded credential rather than prose:
/// 12+ base64 characters with a digit or `+/=`, or (unpadded) mixed case in a
/// multiple of four, which `Basic setup` and `Basic Authentication` are not.
fn basic_token_is_secret(token: &str) -> bool {
    if token.len() < 12 {
        return false;
    }
    if token
        .bytes()
        .any(|b| b.is_ascii_digit() || matches!(b, b'+' | b'='))
    {
        return true;
    }
    // Letters and slashes only is a path (`Basic tests/integration`).
    if token.contains('/') {
        return false;
    }
    token.len().is_multiple_of(4)
        && token.bytes().skip(1).any(|b| b.is_ascii_uppercase())
        && token.bytes().any(|b| b.is_ascii_lowercase())
}

/// A standalone `Basic <base64>` outside an `Authorization` header.
fn mask_basic(text: &str) -> String {
    const NAME: &str = "basic";
    let lower = text.to_ascii_lowercase();
    let mut result = String::with_capacity(text.len());
    let mut copied = 0;
    let mut scan = 0;
    while let Some(offset) = lower[scan..].find(NAME) {
        let start = scan + offset;
        let name_end = start + NAME.len();
        scan = name_end;
        let blanks =
            text[name_end..].len() - text[name_end..].trim_start_matches([' ', '\t']).len();
        let value_start = name_end + blanks;
        let boundary = text[..start]
            .chars()
            .next_back()
            .is_none_or(|c| !is_word_char(c));
        if !boundary || blanks == 0 {
            continue;
        }
        let rest = &text[value_start..];
        let run = run_len(rest, |b| {
            b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'_' | b'-')
        });
        let glued = rest[run..]
            .chars()
            .next()
            .is_some_and(|c| c.is_alphanumeric() || c == '_');
        if !glued && basic_token_is_secret(&rest[..run]) {
            result.push_str(&text[copied..value_start]);
            result.push_str(MASK);
            copied = value_start + run;
            scan = copied;
        }
    }
    result.push_str(&text[copied..]);
    result
}

/// Commands whose short flags carry a credential. A short flag is only
/// masked after one of these names on the same command line: `-p` is a port
/// for `ssh`, a parents flag for `mkdir` and a prompt for a bare `mysql -p`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Tool {
    /// `mysql -pSECRET`: the value must be attached; `-p` alone prompts.
    Mysql,
    /// `sshpass -p SECRET` or `-pSECRET`.
    Sshpass,
    /// `ssh-keygen -N SECRET` / `-P SECRET` (new and old passphrase).
    SshKeygen,
    /// `curl -u user:pass`, `--user`, `--proxy-user`, `-b a=b`.
    Curl,
    /// `htpasswd -b [file] user SECRET`: a positional argument.
    Htpasswd,
    /// `docker login -p SECRET` (other `docker` commands use `-p` for ports).
    DockerLogin,
}

fn tool_named(word: &str) -> Option<Tool> {
    let name = word.rsplit('/').next().unwrap_or(word);
    Some(match name {
        "mysql" | "mysqldump" | "mysqladmin" | "mysqlimport" | "mysqlshow" | "mysqlpump"
        | "mariadb" | "mariadb-dump" | "mariadb-admin" => Tool::Mysql,
        "sshpass" => Tool::Sshpass,
        "ssh-keygen" => Tool::SshKeygen,
        "curl" => Tool::Curl,
        "htpasswd" => Tool::Htpasswd,
        _ => return None,
    })
}

/// Where the secret of a short flag sits.
struct ShortFlag {
    /// Byte offset of an attached value in the word (`-psecret`).
    attached: Option<usize>,
    /// The value is the next argument (`-p secret`).
    next: bool,
    /// Only a value containing `=` is a secret (`curl -b a=b`, not a file).
    needs_eq: bool,
}

/// Classifies a single-dash word for `tool`: a cluster is read left to right
/// up to the first letter that takes an argument. Letters that take an
/// argument but carry no secret end the scan, so their value is never read
/// as a flag cluster (`curl -d -ufoo`).
fn short_secret_flag(tool: Tool, word: &str) -> Option<ShortFlag> {
    let bytes = word.as_bytes();
    if bytes.len() < 2 || bytes[0] != b'-' || bytes[1] == b'-' {
        return None;
    }
    let (secret, with_arg): (&[u8], &[u8]) = match tool {
        Tool::Mysql => (b"p", b"uhPSeDor"),
        Tool::Sshpass => (b"p", b"fdP"),
        Tool::SshKeygen => (b"NP", b"abCEfIJmMnOrstVwYzDFR"),
        Tool::Curl => (b"ubU", b"oHdXAeFmTwxKEcCrzDyYQPt"),
        Tool::DockerLogin => (b"p", b"u"),
        Tool::Htpasswd => return None,
    };
    for (index, &byte) in bytes.iter().enumerate().skip(1) {
        if !byte.is_ascii_alphabetic() {
            return None;
        }
        if secret.contains(&byte) {
            let attached = index + 1 < bytes.len();
            return Some(ShortFlag {
                attached: attached.then_some(index + 1),
                next: !attached && tool != Tool::Mysql,
                needs_eq: tool == Tool::Curl && byte == b'b',
            });
        }
        if with_arg.contains(&byte) {
            return None;
        }
    }
    None
}

/// Long flags of a known command whose next argument is a credential and
/// whose name the generic `--password` rule does not cover.
fn long_secret_flag(tool: Tool, word: &str) -> bool {
    tool == Tool::Curl && matches!(word, "--user" | "--proxy-user" | "--oauth2-bearer")
}

/// `curl --user=u:p`: the value attached to a long flag with `=`.
fn long_flag_attached(tool: Tool, word: &str) -> Option<usize> {
    let (name, _) = word.split_once('=')?;
    long_secret_flag(tool, name).then_some(name.len() + 1)
}

fn is_command_end(byte: u8) -> bool {
    matches!(byte, b';' | b'|' | b'&' | b'(' | b')' | b'`')
}

/// The extent of one shell argument starting at `start`: a quoted one runs to
/// its closing quote (or the line end), an unquoted one to whitespace, a
/// quote or a command separator. Returns the value start and end and where
/// scanning resumes.
fn argument_extent(text: &str, start: usize) -> (usize, usize, usize) {
    let rest = &text[start..];
    if let Some(quote) = rest.chars().next().filter(|c| matches!(c, '"' | '\'')) {
        let inner = start + 1;
        return match text[inner..].find([quote, '\n']) {
            Some(at) if text.as_bytes()[inner + at] == quote as u8 => {
                (inner, inner + at, inner + at + 1)
            }
            Some(at) => (inner, inner + at, inner + at),
            None => (inner, text.len(), text.len()),
        };
    }
    let end = rest
        .find(|c: char| {
            c.is_ascii_whitespace()
                || matches!(c, '"' | '\'')
                || (c.is_ascii() && is_command_end(c as u8))
        })
        .map_or(text.len(), |at| start + at);
    // A trailing `\` before a line break continues the command.
    let continued = end > start
        && text.as_bytes()[end - 1] == b'\\'
        && (end == text.len() || matches!(text.as_bytes()[end], b'\n' | b'\r'));
    // So does the `\` of an escaped quote that closes the argument (`...\"`
    // inside JSON text): the escape is not part of the value.
    let escaped_quote = end > start
        && text.as_bytes()[end - 1] == b'\\'
        && matches!(text.as_bytes().get(end), Some(b'"' | b'\''));
    (
        start,
        if continued || escaped_quote {
            end - 1
        } else {
            end
        },
        end,
    )
}

/// `htpasswd -b [file] user password`: collects the positional arguments of
/// one command, then masks the password when `-b` put it on the command line.
#[derive(Default)]
struct HtpasswdArgs {
    active: bool,
    /// Which of `b` (password on the command line), `n` (no file) and `i`
    /// (password on stdin) were given.
    seen: String,
    skip_next: bool,
    positional: Vec<(usize, usize)>,
}

impl HtpasswdArgs {
    fn flags(&mut self, word: &str) {
        if word.starts_with("--") {
            return;
        }
        // A cluster is read left to right up to the letter that takes a
        // value: `-C` (bcrypt cost) and `-r` (rounds) take the next argument
        // (`-bC 10`) or, when more follows, carry it attached (`-bC10`).
        for (index, letter) in word.char_indices().skip(1) {
            match letter {
                'b' | 'n' | 'i' => {
                    if !self.seen.contains(letter) {
                        self.seen.push(letter);
                    }
                }
                'C' | 'r' => {
                    self.skip_next |= index + 1 == word.len();
                    return;
                }
                _ => {}
            }
        }
    }

    /// The password is the argument after the user: second with `-n` (no
    /// file), third otherwise.
    fn password(&self) -> Option<(usize, usize)> {
        if !self.seen.contains('b') || self.seen.contains('i') {
            return None;
        }
        let position = if self.seen.contains('n') { 1 } else { 2 };
        self.positional.get(position).copied()
    }

    /// Records a positional argument (a `-C` cost is not one).
    fn argument(&mut self, start: usize, end: usize) {
        if std::mem::take(&mut self.skip_next) {
            return;
        }
        self.positional.push((start, end));
    }
}

/// The state of one [`mask_short_flags`] pass over the words of the text.
struct ShortFlagScan<'a> {
    text: &'a str,
    result: String,
    cursor: usize,
    tool: Option<Tool>,
    /// Right after `docker`/`podman`: waiting for the `login` subcommand
    /// past global options (`docker -H host login`).
    docker_login_next: bool,
    docker_after_option: bool,
    /// The quote that opened the word being scanned (a JSON array element).
    quote: Option<u8>,
    htpasswd: HtpasswdArgs,
}

impl ShortFlagScan<'_> {
    /// Masks a span, unless it is empty, already masked or a placeholder.
    fn mask(&mut self, start: usize, end: usize) -> bool {
        let value = &self.text[start..end];
        if value.is_empty() || value == MASK || value.starts_with('<') {
            return false;
        }
        self.result.push_str(&self.text[self.cursor..start]);
        self.result.push_str(MASK);
        self.cursor = end;
        true
    }

    /// Ends the current command: masks a collected `htpasswd` password.
    fn finish_command(&mut self) {
        if self.htpasswd.active {
            if let Some((start, end)) = self.htpasswd.password() {
                self.mask(start, end);
            }
            self.htpasswd = HtpasswdArgs::default();
        }
        self.tool = None;
        self.docker_login_next = false;
        self.docker_after_option = false;
        self.quote = None;
    }

    /// Handles the word at `index` and returns where scanning resumes.
    fn word(&mut self, index: usize) -> usize {
        let text = self.text;
        let quote = self.quote.take();
        let word_end = text[index..]
            .find(|c: char| {
                c.is_ascii_whitespace()
                    || (c.is_ascii() && is_command_end(c as u8))
                    || quote.is_some_and(|q| c == q as char)
            })
            .map_or(text.len(), |at| index + at);
        let word = &text[index..word_end];
        // A command name may follow `cmd=` or `"cmd":`.
        // (a quote may glue to it: `cmd="mysql -pX"`, `\"mysql` in JSON text).
        let command = word.rsplit(['=', ':']).next().unwrap_or(word);
        let command = command.trim_start_matches(['"', '\'', '\\']);
        if let Some(named) = tool_named(command) {
            self.finish_command();
            self.tool = Some(named);
            self.htpasswd.active = named == Tool::Htpasswd;
            // The closing quote of a quoted name is not an argument's opening.
            let closed = quote.is_some_and(|q| text.as_bytes().get(word_end) == Some(&q));
            return word_end + usize::from(closed && self.htpasswd.active);
        }
        if matches!(command.rsplit('/').next(), Some("docker" | "podman")) {
            self.finish_command();
            self.docker_login_next = true;
            return word_end;
        }
        if self.docker_login_next {
            if word == "login" {
                self.docker_login_next = false;
                self.tool = Some(Tool::DockerLogin);
                return word_end;
            }
            if word.starts_with('-') {
                self.docker_after_option = !word.contains('=');
                return word_end;
            }
            if std::mem::take(&mut self.docker_after_option) {
                return word_end;
            }
            self.docker_login_next = false;
        }
        let Some(current) = self.tool else {
            return word_end;
        };
        if current == Tool::Htpasswd {
            if word.starts_with('-') {
                self.htpasswd.flags(word);
                return word_end;
            }
            let (start, end, next) = argument_extent(text, index);
            self.htpasswd.argument(start, end);
            return next;
        }
        if current == Tool::Sshpass && !word.starts_with('-') {
            // The wrapped command starts here; its flags are not sshpass's.
            self.tool = None;
            return word_end;
        }
        let flag = if long_secret_flag(current, word) {
            Some(ShortFlag {
                attached: None,
                next: true,
                needs_eq: false,
            })
        } else if let Some(at) = long_flag_attached(current, word) {
            Some(ShortFlag {
                attached: Some(at),
                next: false,
                needs_eq: false,
            })
        } else {
            short_secret_flag(current, word)
        };
        let Some(flag) = flag else { return word_end };
        let (start, end, next) = if let Some(offset) = flag.attached {
            argument_extent(text, index + offset)
        } else if flag.next {
            let mut at = word_end;
            if quote.is_some_and(|q| text.as_bytes().get(word_end) == Some(&q)) {
                // `"-p", "x"`: past the closing quote and the comma.
                at += 1;
                at += text[at..].len() - text[at..].trim_start_matches([' ', '\t']).len();
                if text[at..].starts_with(',') {
                    at += 1;
                }
            }
            at += text[at..].len() - text[at..].trim_start_matches([' ', '\t']).len();
            argument_extent(text, at)
        } else {
            return word_end;
        };
        let value = &text[start..end];
        if (flag.attached.is_none() && value.starts_with('-'))
            || (flag.needs_eq && !value.contains('='))
        {
            return word_end;
        }
        if self.mask(start, end) {
            next
        } else {
            word_end
        }
    }
}

/// Short flags that carry a credential, in a known-command context only:
/// `mysql -pSECRET`, `sshpass -p SECRET`, `ssh-keygen -N SECRET`,
/// `curl -u user:pass`, `htpasswd -b file user SECRET`, `docker login -p`.
/// A command's flags end at a newline (unless escaped), `;`, `|`, `&`, a
/// parenthesis or a backtick. One forward pass over the words.
fn mask_short_flags(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut scan = ShortFlagScan {
        text,
        result: String::with_capacity(text.len()),
        cursor: 0,
        tool: None,
        docker_login_next: false,
        docker_after_option: false,
        quote: None,
        htpasswd: HtpasswdArgs::default(),
    };
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        let continued = index > 0
            && (bytes[index - 1] == b'\\'
                || (bytes[index - 1] == b'\r' && index > 1 && bytes[index - 2] == b'\\'));
        if is_command_end(byte) || matches!(byte, b']' | b'}') || (byte == b'\n' && !continued) {
            scan.finish_command();
            index += 1;
        } else if byte.is_ascii_whitespace() || matches!(byte, b'[' | b'{' | b',') {
            // Brackets and commas separate the elements of a JSON argv array.
            index += 1;
        } else if matches!(byte, b'"' | b'\'') {
            // A quote opens an argument of `htpasswd`; elsewhere it only
            // wraps words that are scanned as usual (`sh -c "mysql -pX"`).
            if scan.htpasswd.active {
                // One element, read once: a quoted flag is a flag.
                let (start, end, next) = argument_extent(text, index);
                if text[start..end].starts_with('-') {
                    scan.htpasswd.flags(&text[start..end]);
                } else {
                    scan.htpasswd.argument(start, end);
                }
                index = next;
            } else {
                scan.quote = Some(byte);
                index += 1;
            }
        } else {
            index = scan.word(index);
        }
    }
    scan.finish_command();
    let ShortFlagScan {
        mut result, cursor, ..
    } = scan;
    result.push_str(&text[cursor..]);
    result
}

/// The value after a JSON or Python-repr argv element that is a secret long
/// flag: `["--password", "x"]`, `['--token', 'x']`.
fn mask_json_argv(text: &str) -> String {
    let mut result = String::with_capacity(text.len());
    let mut cursor = 0;
    let mut search = 0;
    while let Some(offset) = text[search..].find(['"', '\'']) {
        let open = search + offset;
        let quote = text.as_bytes()[open];
        search = open + 1;
        let name_start = open + 1;
        if !text[name_start..].starts_with("--") {
            continue;
        }
        let name_end = text[name_start..]
            .find(|c: char| !is_word_char(c))
            .map_or(text.len(), |at| name_start + at);
        if text.as_bytes().get(name_end) != Some(&quote) {
            continue;
        }
        search = name_end + 1;
        let name = &text[name_start + 2..name_end];
        if name.to_ascii_lowercase().starts_with("no-") || !names_a_secret(name) {
            continue;
        }
        let after = text[search..].trim_start_matches(char::is_whitespace);
        let Some(after) = after.strip_prefix(',') else {
            continue;
        };
        let after = after.trim_start_matches(char::is_whitespace);
        if !after.starts_with(quote as char) {
            continue;
        }
        let value_start = text.len() - after.len() + 1;
        let mut value_end = None;
        let mut escaped = false;
        for (at, byte) in text.bytes().enumerate().skip(value_start) {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == quote {
                value_end = Some(at);
                break;
            }
        }
        let Some(value_end) = value_end else { continue };
        let value = &text[value_start..value_end];
        if value.is_empty()
            || value.starts_with(['-', '<'])
            || value == MASK
            || is_benign_value(name, value)
        {
            continue;
        }
        result.push_str(&text[cursor..value_start]);
        result.push_str(MASK);
        cursor = value_end;
        // The closing quote may open the next element's name.
        search = value_end;
    }
    result.push_str(&text[cursor..]);
    result
}

/// One element of an argv array that may be part of a PEM key split over
/// elements. Returns whether the key continues in the next element, or `None`
/// when the element is not part of a key.
fn mask_key_element(
    items: &mut [serde_json::Value],
    at: usize,
    word: &str,
    in_key: bool,
) -> Option<bool> {
    if in_key {
        let armor = !word.is_empty() && word.bytes().all(is_armor_byte);
        let ends = word.contains("-----END ");
        if !ends && !armor {
            return None;
        }
        items[at] = serde_json::Value::String(MASK.to_owned());
        return Some(!ends);
    }
    // A BEGIN line: the string scrub masks it; the armor follows.
    (mask_private_keys(word) != word).then_some(true)
}

/// The same flag rules over a parsed argv array: a secret long flag, or a
/// short flag after a known command, masks the next element (or the attached
/// part of the same one). The armor lines of a PEM key split over elements,
/// and the password of `htpasswd -b`, are masked too.
fn mask_json_argv_array(items: &mut [serde_json::Value]) {
    use serde_json::Value;
    let mut tool: Option<Tool> = None;
    let mut docker_login_next = false;
    let mut docker_after_option = false;
    let mut in_key = false;
    let mut htpasswd = HtpasswdArgs::default();
    let mut index = 0;
    while index < items.len() {
        let Value::String(word) = &items[index] else {
            index += 1;
            continue;
        };
        let word = word.clone();
        index += 1;
        if in_key || (word.contains("-----BEGIN ") && !word.contains("-----END ")) {
            if let Some(still_in_key) = mask_key_element(items, index - 1, &word, in_key) {
                in_key = still_in_key;
                continue;
            }
            in_key = false;
        }
        let command = word.rsplit(['=', ':']).next().unwrap_or(&word);
        let named = tool_named(command);
        let docker = matches!(command.rsplit('/').next(), Some("docker" | "podman"));
        if named.is_some() || docker {
            finish_htpasswd_array(items, &mut htpasswd);
            tool = named;
            htpasswd.active = named == Some(Tool::Htpasswd);
            docker_login_next = docker;
            continue;
        }
        if docker_login_next {
            if word == "login" {
                docker_login_next = false;
                tool = Some(Tool::DockerLogin);
                continue;
            }
            if word.starts_with('-') {
                docker_after_option = !word.contains('=');
                continue;
            }
            if std::mem::take(&mut docker_after_option) {
                continue;
            }
            docker_login_next = false;
        }
        if tool == Some(Tool::Htpasswd) {
            if word.starts_with('-') {
                htpasswd.flags(&word);
            } else {
                htpasswd.argument(index - 1, index - 1);
            }
            continue;
        }
        if tool == Some(Tool::Sshpass) && !word.starts_with('-') {
            // The wrapped command starts here; its flags are not sshpass's.
            tool = None;
            continue;
        }
        let flag = array_flag(tool, &word);
        let Some(flag) = flag else { continue };
        let key = word.trim_start_matches('-').to_owned();
        let is_credential = |value: &str| {
            !value.is_empty()
                && value != MASK
                && !value.starts_with('<')
                && (!flag.needs_eq || value.contains('='))
                && !is_benign_value(&key, value)
        };
        if let Some(offset) = flag.attached {
            if is_credential(&word[offset..]) {
                items[index - 1] = Value::String(format!("{}{MASK}", &word[..offset]));
            }
        } else if flag.next
            && let Some(Value::String(value)) = items.get(index)
            && !value.starts_with('-')
            && is_credential(value)
        {
            items[index] = Value::String(MASK.to_owned());
            index += 1;
        }
    }
    finish_htpasswd_array(items, &mut htpasswd);
}

/// The credential flag an argv element is, for the current command: a secret
/// long flag anywhere, or a flag of the known command.
fn array_flag(tool: Option<Tool>, word: &str) -> Option<ShortFlag> {
    let long_secret = word.strip_prefix("--").is_some_and(|name| {
        !name.contains('=') && !name.to_ascii_lowercase().starts_with("no-") && names_a_secret(name)
    });
    let next_value = ShortFlag {
        attached: None,
        next: true,
        needs_eq: false,
    };
    if long_secret || tool.is_some_and(|t| long_secret_flag(t, word)) {
        return Some(next_value);
    }
    if let Some(at) = tool.and_then(|t| long_flag_attached(t, word)) {
        return Some(ShortFlag {
            attached: Some(at),
            ..next_value
        });
    }
    tool.and_then(|t| short_secret_flag(t, word))
}

/// Masks the password element collected for an `htpasswd -b` command.
fn finish_htpasswd_array(items: &mut [serde_json::Value], htpasswd: &mut HtpasswdArgs) {
    if htpasswd.active
        && let Some((at, _)) = htpasswd.password()
    {
        items[at] = serde_json::Value::String(MASK.to_owned());
    }
    *htpasswd = HtpasswdArgs::default();
}

/// Whether a word names a secret: it ENDS with one of [`SECRET_KEYS`].
fn names_a_secret(word: &str) -> bool {
    let lower = word.to_ascii_lowercase();
    SECRET_KEYS.iter().any(|name| lower.ends_with(name))
        || DELIMITED_KEYS
            .iter()
            .any(|name| ends_with_delimited_word(word, &lower, name))
}

/// Whether `word` is `name` or ends with it after a `_`, `-` or `.`, or at a
/// camel-case boundary (`dbPass`, not `bypass`, `Compass` or `COMPASS`).
fn ends_with_delimited_word(word: &str, lower: &str, name: &str) -> bool {
    if !lower.ends_with(name) {
        return false;
    }
    let split = word.len() - name.len();
    let Some(before) = word[..split].chars().next_back() else {
        return true;
    };
    matches!(before, '_' | '-' | '.')
        || ((before.is_ascii_lowercase() || before.is_ascii_digit())
            && word.as_bytes()[split].is_ascii_uppercase())
}

/// Values that a short, ambiguous key name holds without being a secret:
/// `pass=12` is a test count and `PWD=/home/x` the working directory.
fn is_benign_value(key: &str, value: &str) -> bool {
    let key = key.trim_start_matches('-');
    let bytes = value.as_bytes();
    if key.eq_ignore_ascii_case("pass") {
        // A count, a path or a test name (`PASS: tests/foo.sh` in a test
        // log), or a status word (`PASS: ok`).
        return (!bytes.is_empty() && bytes.iter().all(u8::is_ascii_digit))
            || value.starts_with(['/', '~'])
            || is_test_like(value)
            || ["ok", "passed", "success", "succeeded", "skipped"]
                .iter()
                .any(|status| value.eq_ignore_ascii_case(status));
    }
    key.eq_ignore_ascii_case("pwd")
        && (value.starts_with(['/', '~'])
            || (bytes.get(1) == Some(&b':') && matches!(bytes.get(2), Some(b'\\' | b'/'))))
}

/// A path or a test name: `tests/foo.sh`, `foo.test`, `suite::case`,
/// `test_login`. A plain word with a digit (`s3cretvalue`) is neither.
fn is_test_like(value: &str) -> bool {
    // Only the first bytes are read: `value` may run to the end of a very
    // long text, and this is asked once per key.
    let mut head_end = value.len().min(64);
    while !value.is_char_boundary(head_end) {
        head_end -= 1;
    }
    let head = &value[..head_end];
    let bytes = value.as_bytes();
    head.contains(['/', '\\'])
        || head.contains("::")
        || head.to_ascii_lowercase().contains("test")
        || [
            ".sh", ".js", ".ts", ".py", ".rs", ".go", ".rb", ".t", ".bats",
        ]
        .iter()
        .any(|extension| {
            bytes.len() >= extension.len()
                && bytes[bytes.len() - extension.len()..].eq_ignore_ascii_case(extension.as_bytes())
        })
}

/// `--password value`, `--api-key value`: a long CLI flag whose name ends
/// with a secret name masks the argument after it. (`--password=value` is
/// the pair form.) A following word that starts with `-` is the next flag,
/// so the flag was a switch, and a `<placeholder>` is usage text: neither is masked.
fn mask_secret_flags(text: &str) -> String {
    let mut result = String::with_capacity(text.len());
    let mut cursor = 0;
    let mut search = 0;
    while let Some(offset) = text[search..].find("--") {
        let start = search + offset;
        let name_start = start + 2;
        let name_end = text[name_start..]
            .find(|c: char| !is_word_char(c))
            .map_or(text.len(), |end| name_start + end);
        search = name_end.max(name_start);
        let boundary = text[..start]
            .chars()
            .next_back()
            .is_none_or(|c| !is_word_char(c));
        if !boundary
            || !text[name_end..].starts_with([' ', '\t'])
            || text[name_start..name_end]
                .to_ascii_lowercase()
                .starts_with("no-")
            || !names_a_secret(&text[name_start..name_end])
        {
            continue;
        }
        let (value_start, value_end) = value_extent(text, name_end, Extent::Word);
        let value = &text[value_start..value_end];
        if value.is_empty()
            || value.starts_with(['-', '<'])
            || value == MASK
            || is_benign_value(&text[name_start..name_end], value)
        {
            continue;
        }
        result.push_str(&text[cursor..value_start]);
        result.push_str(MASK);
        cursor = value_end;
        search = value_end;
    }
    result.push_str(&text[cursor..]);
    result
}

/// `name=value`, the JSON form `"name": "value"`, and the bare `name: value`
/// form, where the word before the separator ends with a secret name. A bare
/// colon is also prose ("invalid token: expired"), so it only masks a value
/// that is quoted, sits on a line that starts with the key (YAML or env
/// style), or reads like a credential rather than a plain word.
fn mask_key_values(text: &str) -> String {
    let mut result = String::with_capacity(text.len());
    let mut cursor = 0;
    let mut search = 0;
    // The end of the last unquoted value scanned: a later separator inside
    // it has the same end, so a long value full of `pwd=` is scanned once.
    let mut unquoted_end = 0;
    while let Some(offset) = text[search..].find(['=', ':']) {
        let separator = search + offset;
        search = separator + 1;
        let mut key_end = separator;
        let mut bare = false;
        if text.as_bytes()[separator] == b':' {
            // Blanks may sit before the colon (`password : x`).
            let trimmed = text[..separator].trim_end_matches([' ', '\t']);
            match trimmed.chars().next_back() {
                Some(quote @ ('"' | '\'')) => key_end = trimmed.len() - quote.len_utf8(),
                Some(c) if is_word_char(c) && text[separator + 1..].starts_with([' ', '\t']) => {
                    bare = true;
                    key_end = trimmed.len();
                }
                _ => continue,
            }
        }
        let key_start = text[..key_end]
            .char_indices()
            .rev()
            .take_while(|(_, c)| is_word_char(*c))
            .last()
            .map_or(key_end, |(index, _)| index);
        // The value is only scanned once the key names a secret, so a long
        // run of '=' with no secret name stays linear.
        if !names_a_secret(&text[key_start..key_end]) {
            continue;
        }
        let (value_start, value_end) = if separator + 1 < unquoted_end {
            (separator + 1, unquoted_end)
        } else {
            let extent = value_extent(text, separator + 1, Extent::Word);
            let quoted = text[..extent.0]
                .chars()
                .next_back()
                .is_some_and(|c| matches!(c, '"' | '\''));
            unquoted_end = if quoted { 0 } else { extent.1 };
            extent
        };
        if value_end > value_start
            && &text[value_start..value_end] != MASK
            && !is_benign_value(&text[key_start..key_end], &text[value_start..value_end])
            && (!bare || bare_value_is_secret(text, key_start, value_start, value_end))
        {
            result.push_str(&text[cursor..value_start]);
            result.push_str(MASK);
            cursor = value_end;
            search = value_end;
        }
    }
    result.push_str(&text[cursor..]);
    result
}

/// Plain status words: `Password: incorrect` is a message, not a credential,
/// even at the start of a line. (A quoted value is always masked.)
const STATUS_WORDS: [&str; 16] = [
    "incorrect",
    "invalid",
    "expired",
    "missing",
    "required",
    "not",
    "none",
    "null",
    "empty",
    "denied",
    "unknown",
    "true",
    "false",
    "active",
    "closed",
    "open",
];

/// Whether the value of a bare `key: value` is a secret: quoted, on a line
/// that starts with the key (an optional list dash aside), or a word of at
/// least [`BEARER_MIN_TOKEN`] characters with a digit or symbol in it.
fn bare_value_is_secret(
    text: &str,
    key_start: usize,
    value_start: usize,
    value_end: usize,
) -> bool {
    let quoted = text[..value_start]
        .chars()
        .next_back()
        .is_some_and(|c| matches!(c, '"' | '\''));
    // Walk back over indentation and a list dash only, so a long line of
    // keys stays linear: the walk ends at the first other character.
    let yaml_shape = text[..key_start]
        .chars()
        .rev()
        .find(|c| *c != ' ' && *c != '\t' && *c != '-')
        .is_none_or(|c| c == '\n');
    let value = &text[value_start..value_end];
    if !quoted && yaml_shape && STATUS_WORDS.contains(&value.to_ascii_lowercase().as_str()) {
        return false;
    }
    quoted
        || yaml_shape
        || (value.len() >= BEARER_MIN_TOKEN && value.chars().any(|c| !c.is_ascii_alphabetic()))
}

/// Redacts every credential shape this module knows: URL userinfo,
/// schemeless `user:password@`, then `Authorization`, `Bearer` and
/// `token=` style pairs. The single entry point for output that is stored or
/// returned (command output, logs), so a fix lands once.
#[must_use]
pub fn redact_credentials(text: &str) -> String {
    settle(&strip_terminal_noise(text), |text| {
        secret_pairs_pass(&redact_schemeless_credentials(&redact_url_credentials(
            text,
        )))
    })
}

/// Removes terminal escape sequences: CSI (`ESC [ ... final`, also the C1
/// form), OSC / DCS / APC / PM / SOS strings (to BEL, `ESC \` or the end of
/// the line, so an unterminated one cannot swallow the rest of the output)
/// and two-byte escapes. Colour codes split a credential from its name
/// (`token\x1b[0m=x`), so this runs before any rule looks at the text. One
/// forward pass; nothing is re-read.
#[must_use]
pub fn strip_terminal_escapes(text: &str) -> String {
    let mut result = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\u{1b}' => match chars.peek().copied() {
                Some('[') => {
                    chars.next();
                    skip_csi(&mut chars);
                }
                Some(']' | 'P' | 'X' | '^' | '_') => {
                    chars.next();
                    skip_string_sequence(&mut chars);
                }
                Some(' '..='/') => {
                    // `ESC` intermediates final (character-set selection).
                    while chars.next_if(|c| matches!(c, ' '..='/')).is_some() {}
                    chars.next_if(|c| matches!(c, '0'..='~'));
                }
                Some('0'..='~') => {
                    chars.next();
                }
                _ => {}
            },
            '\u{9b}' => skip_csi(&mut chars),
            '\u{9d}' | '\u{90}' | '\u{98}' | '\u{9e}' | '\u{9f}' => {
                skip_string_sequence(&mut chars);
            }
            other => result.push(other),
        }
    }
    result
}

/// The rest of a CSI sequence: parameter, intermediate and final bytes.
fn skip_csi(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) {
    while chars.next_if(|c| matches!(c, '0'..='?')).is_some() {}
    while chars.next_if(|c| matches!(c, ' '..='/')).is_some() {}
    chars.next_if(|c| matches!(c, '@'..='~'));
}

/// The rest of an OSC-style string: up to BEL, ST (`ESC \` or U+009C) or the
/// line end, which is left in place.
fn skip_string_sequence(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) {
    while let Some(&c) = chars.peek() {
        match c {
            '\n' => return,
            '\u{7}' | '\u{9c}' => {
                chars.next();
                return;
            }
            '\u{1b}' => {
                chars.next();
                if chars.next_if_eq(&'\\').is_some() {
                    return;
                }
            }
            _ => {
                chars.next();
            }
        }
    }
}

/// Escape sequences stripped, and control characters other than `\n`, `\t`
/// and `\r` flattened to spaces: the form every rule scans. Text without a
/// control character is returned as is.
fn strip_terminal_noise(text: &str) -> std::borrow::Cow<'_, str> {
    if !text
        .chars()
        .any(|c| c.is_control() && !matches!(c, '\n' | '\t' | '\r'))
    {
        return std::borrow::Cow::Borrowed(text);
    }
    let stripped = strip_terminal_escapes(text);
    std::borrow::Cow::Owned(
        stripped
            .chars()
            .map(|c| {
                if c.is_control() && !matches!(c, '\n' | '\t' | '\r') {
                    ' '
                } else {
                    c
                }
            })
            .collect(),
    )
}

/// Strips terminal escape sequences and flattens control characters (except
/// newlines) to spaces: hostile terminal output stays data.
#[must_use]
pub fn flatten_control_characters(text: &str) -> String {
    strip_terminal_escapes(text)
        .chars()
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
    // Strip terminal escapes and flatten control characters first, so a
    // colour code or a stray control byte cannot split a credential from its
    // name, then scrub. Control characters are hostile as output, and each
    // JSON-escapes to up to six bytes, which could push a result past its
    // stored size limit. Flattening before scrubbing also makes the stored
    // form a fixed point. The final flatten covers what `extra` adds.
    let scrubbed = flatten_control_characters(&extra(&redact_credentials(
        &flatten_control_characters(window),
    )));
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

/// How deep a JSON document may nest before [`redact_json_strings`] drops the
/// rest. Node-supplied documents are untrusted.
const MAX_JSON_DEPTH: usize = 16;

/// Scrubs and bounds every string (and object key) in a JSON document, in
/// place: credential shapes are masked, control characters flattened, each
/// string cut to [`RESULT_STRING_BOUND`]. Nesting beyond a fixed depth is
/// replaced by `null`. Used for node-supplied reports stored as data.
pub fn redact_json_strings(value: &mut serde_json::Value) {
    redact_json_at(value, 0);
}

fn redact_json_at(value: &mut serde_json::Value, depth: usize) {
    use serde_json::Value;
    if depth > MAX_JSON_DEPTH {
        *value = Value::Null;
        return;
    }
    match value {
        Value::String(text) => *text = scrub_failure_detail(text),
        Value::Array(items) => {
            // A mask can complete a shape another rule keys on, so the array
            // pass repeats until it settles, like the string scrub.
            for _ in 0..=MAX_SETTLE_PASSES {
                let before = items.clone();
                mask_json_argv_array(items);
                if *items == before {
                    break;
                }
            }
            for item in items {
                redact_json_at(item, depth + 1);
            }
        }
        Value::Object(map) => {
            let entries = std::mem::take(map);
            for (key, mut item) in entries {
                // A value under a secret-named key (`"password": "x"`) is
                // masked whole: the string scrubber never sees key and value
                // together, so the key's name is the only signal.
                if names_a_secret(&key) {
                    // A `pass` count (`{"pass": 12}`) is not a secret.
                    let numbers =
                        !key.eq_ignore_ascii_case("pass") && !key.eq_ignore_ascii_case("session");
                    mask_json_values(&mut item, depth + 1, numbers, &key);
                } else {
                    redact_json_at(&mut item, depth + 1);
                }
                map.insert(scrub_failure_detail(&key), item);
            }
        }
        _ => {}
    }
}

/// Masks every string and number under a secret-named key; nesting beyond
/// the depth limit is dropped like everywhere else in the document.
fn mask_json_values(value: &mut serde_json::Value, depth: usize, numbers: bool, key: &str) {
    use serde_json::Value;
    if depth > MAX_JSON_DEPTH {
        *value = Value::Null;
        return;
    }
    match value {
        Value::String(text) if is_benign_value(key, text) => {}
        Value::String(_) => *value = Value::String(MASK.to_owned()),
        Value::Number(_) if numbers => *value = Value::String(MASK.to_owned()),
        Value::Array(items) => {
            for item in items {
                mask_json_values(item, depth + 1, numbers, key);
            }
        }
        Value::Object(map) => {
            for item in map.values_mut() {
                mask_json_values(item, depth + 1, numbers, key);
            }
        }
        Value::Number(_) | Value::Bool(_) | Value::Null => {}
    }
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

/// Scrubs the last bytes of a stream and keeps its tail, within the same
/// escaped bound as [`trim_to_bound`]. `bytes` is the end of the stream;
/// `cut_at_front` says earlier bytes were dropped before it.
///
/// A cut front may begin in the middle of a token, and a credential cut in
/// two is no longer a credential shape, so when the front was cut the text
/// up to the first whitespace is dropped before scrubbing. The whole
/// remainder is then scrubbed and flattened, and only afterwards cut to its
/// last bytes, so a credential straddling the final cut is already masked.
/// Answers the text and whether anything was left out; an omitted front
/// shows as a leading `…`.
#[must_use]
pub fn scrub_tail(bytes: &[u8], cut_at_front: bool) -> (String, bool) {
    let lossy = String::from_utf8_lossy(bytes);
    let mut text: &str = &lossy;
    if cut_at_front {
        text = text
            .find(char::is_whitespace)
            .map_or("", |index| &text[index..]);
    }
    let scrubbed =
        flatten_control_characters(&redact_credentials(&flatten_control_characters(text)));
    let mut escaped = 0;
    let mut start = 0;
    let mut cut = false;
    for (index, c) in scrubbed.char_indices().rev() {
        escaped += match c {
            '"' | '\\' | '\n' => 2,
            other => other.len_utf8(),
        };
        if escaped > RESULT_STRING_BOUND {
            start = index + c.len_utf8();
            cut = true;
            break;
        }
    }
    let kept = &scrubbed[start..];
    let truncated = cut_at_front || cut;
    if truncated {
        (format!("…{kept}"), true)
    } else {
        (kept.to_owned(), false)
    }
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

    /// Item 2 of #445: colour codes and control bytes between a credential's
    /// name and value. Fake values only.
    #[test]
    fn terminal_noise_cannot_hide_a_credential() {
        let cases = [
            ("\u{1b}[1mPassword:\u{1b}[0m hunter2", "Password: ***"),
            ("--password\u{1b}[0m hunter2", "--password ***"),
            ("--password\u{b}hunter2", "--password ***"),
            ("token\u{1b}[0m=hunter2", "token=***"),
            ("mysql\u{1b}[0m -phunter2", "mysql -p***"),
            ("Bearer\u{1b}[0m abcdefgh12", "Bearer ***"),
            ("\u{9b}1mtoken=hunter2", "token=***"),
            ("\u{1b}]0;title\u{7}password=hunter2", "password=***"),
            ("\u{1b}]8;;http://h\u{1b}\\password=hunter2", "password=***"),
            ("password=\u{1b}[1mhunter2\u{1b}[0m", "password=***"),
            ("Cookie:\u{1b}[0m sid=hunter2", "Cookie: ***"),
        ];
        for (input, expected) in cases {
            for out in [
                redact_credentials(input),
                redact_secret_pairs(input),
                scrub_failure_detail(input),
            ] {
                assert_eq!(out, expected, "input {input:?}");
            }
            let stored = scrub_failure_detail(input);
            assert_eq!(scrub_failure_detail(&stored), stored, "{input:?}");
        }
        // The schemeless `user:pass@` scan is part of `redact_credentials` only.
        assert_eq!(redact_credentials("x\u{0}u:p@h"), "x ***@h");
        assert_eq!(scrub_failure_detail("x\u{0}u:p@h"), "x ***@h");
        // An unterminated OSC ends at the line end and swallows nothing else.
        assert_eq!(
            redact_credentials("a\u{1b}]0;title\nb token=hunter2"),
            "a\nb token=***"
        );
        // Ordinary output keeps its tabs and carriage returns for callers.
        assert_eq!(redact_credentials("a\tb\r\nc"), "a\tb\r\nc");
    }

    /// Item 3 of #445: PEM bodies whose END line is missing (or whose BEGIN
    /// is). Fake values only.
    #[test]
    fn pem_bodies_without_end_are_masked() {
        let body = "MIIfake1234567890abcdefghijklmnopqrstuvwxyz0123";
        let masked = [
            // Proc-Type / DEK-Info headers, a blank line, then the body.
            format!(
                "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,0123456789ABCDEF\n\n{body}\nabcdEFGH5678==\nafter"
            ),
            // A blank line after BEGIN.
            format!("-----BEGIN PRIVATE KEY-----\n\n{body}\nZm9v==\nafter"),
            // PGP armor headers.
            format!(
                "-----BEGIN PGP PRIVATE KEY BLOCK-----\nVersion: GnuPG v2\nComment: fake\n\n{body}\n=abcd\nafter"
            ),
            // Written out inside JSON text.
            format!(
                "{{\"k\":\"-----BEGIN PRIVATE KEY-----\\nVersion: x\\n\\n{body}\\nZm9v1234\"}}"
            ),
        ];
        let expected = ["***\nafter", "***\nafter", "***\nafter", "{\"k\":\"***\"}"];
        for (input, expected) in masked.iter().zip(expected) {
            assert_eq!(redact_credentials(input), expected, "input {input:?}");
        }
        let cases = [
            // Indented YAML block.
            (
                format!("key: |\n  -----BEGIN PRIVATE KEY-----\n  {body}\n  Zm9v1234\nnext: x"),
                "key: |\n  ***\nnext: x",
            ),
            // A key joined with spaces on the fence line.
            (
                format!("k=-----BEGIN PRIVATE KEY----- {body} Zm9v1234 end"),
                "k=*** end",
            ),
            // An indented body before an END with no BEGIN.
            (
                format!("  {body}\n  Zm9v1234==\n  -----END PRIVATE KEY-----\nafter"),
                "***\nafter",
            ),
            // A prefixed first body line.
            (
                format!("stderr: {body}\nZm9v1234==\n-----END PRIVATE KEY-----\nafter"),
                "stderr: ***\nafter",
            ),
            // The closing quote of a JSON string ends the body.
            (
                format!("[\"-----BEGIN PRIVATE KEY-----\\n{body}\"]"),
                "[\"***\"]",
            ),
            // A plain word is prose, not key material.
            (
                "-----BEGIN PRIVATE KEY-----\ndone\nnext".into(),
                "***\ndone\nnext",
            ),
            (
                "done\n-----END PRIVATE KEY-----\nnext".into(),
                "done\n***\nnext",
            ),
            (
                "bad key: expected -----BEGIN PRIVATE KEY----- header\nnext line".into(),
                "bad key: expected *** header\nnext line",
            ),
        ];
        for (input, expected) in cases {
            let out = redact_credentials(&input);
            assert_eq!(out, expected, "input {input:?}");
            assert_eq!(redact_credentials(&out), out, "not idempotent: {input:?}");
        }
    }

    /// Items 4 and 5 of #445: `htpasswd` value-taking flags in a cluster, and
    /// its argv written out as text. Fake values only.
    #[test]
    fn htpasswd_clusters_and_text_argv_are_masked() {
        let cases = [
            (
                "htpasswd -bC 10 /etc/f bob fakepw1",
                "htpasswd -bC 10 /etc/f bob ***",
            ),
            (
                "htpasswd -bC10 /etc/f bob fakepw1",
                "htpasswd -bC10 /etc/f bob ***",
            ),
            ("htpasswd -nbC 10 bob fakepw1", "htpasswd -nbC 10 bob ***"),
            (
                "htpasswd -C 10 -b /etc/f bob fakepw1",
                "htpasswd -C 10 -b /etc/f bob ***",
            ),
            (
                "htpasswd -bB /etc/f bob fakepw1",
                "htpasswd -bB /etc/f bob ***",
            ),
            (
                "[\"htpasswd\",\"-b\",\"/etc/f\",\"bob\",\"fakepw1\"]",
                "[\"htpasswd\",\"-b\",\"/etc/f\",\"bob\",\"***\"]",
            ),
            (
                "['htpasswd', '-nb', 'bob', 'fakepw1']",
                "['htpasswd', '-nb', 'bob', '***']",
            ),
            (
                "[\"htpasswd\", \"-bC\", \"10\", \"/etc/f\", \"bob\", \"fakepw1\"]",
                "[\"htpasswd\", \"-bC\", \"10\", \"/etc/f\", \"bob\", \"***\"]",
            ),
            (
                "[\"htpasswd\",\"-i\",\"/etc/f\",\"bob\"]",
                "[\"htpasswd\",\"-i\",\"/etc/f\",\"bob\"]",
            ),
        ];
        for (input, expected) in cases {
            let out = redact_credentials(input);
            assert_eq!(out, expected, "input {input:?}");
            assert_eq!(redact_credentials(&out), out, "not idempotent: {input:?}");
        }
        let mut parsed = serde_json::json!(["htpasswd", "-bC", "10", "/etc/f", "bob", "fakepw1"]);
        redact_json_strings(&mut parsed);
        assert_eq!(
            parsed,
            serde_json::json!(["htpasswd", "-bC", "10", "/etc/f", "bob", "***"])
        );
        let mut parsed = serde_json::json!(["htpasswd", "-bC10", "/etc/f", "bob", "fakepw1"]);
        redact_json_strings(&mut parsed);
        assert_eq!(
            parsed,
            serde_json::json!(["htpasswd", "-bC10", "/etc/f", "bob", "***"])
        );
    }

    /// Item 6 of #445: escaped quotes in JSON text and quoted values. Fake
    /// values only.
    #[test]
    fn escaped_quotes_do_not_end_a_value() {
        let cases = [
            (
                r#"{"Cookie": "sid=\"fake1\"; a=fake2"}"#,
                r#"{"Cookie": "***"}"#,
            ),
            (
                r#"{"msg":"password=\"fake1\""}"#,
                r#"{"msg":"password=\"***\""}"#,
            ),
            (r#"password="FAKE\"PW1" x"#, r#"password="***" x"#),
            (r"-H 'Cookie: sid=\'fake1\'; a=b' x", "-H 'Cookie: ***' x"),
            (
                r#"{"Authorization": "Basic \"fake1\" tail"}"#,
                r#"{"Authorization": "***"}"#,
            ),
            ("password=\"fake1\\\nnext x", "password=\"***\nnext x"),
        ];
        for (input, expected) in cases {
            let out = redact_credentials(input);
            assert_eq!(out, expected, "input {input:?}");
            assert_eq!(redact_credentials(&out), out, "not idempotent: {input:?}");
        }
    }

    /// Item 7 of #445: a command name glued to a quote. Fake values only.
    #[test]
    fn a_quote_glued_to_the_command_name_is_skipped() {
        let cases = [
            ("cmd=\"mysql -pfake1\"", "cmd=\"mysql -p***\""),
            (
                "MYSQL_CMD=\"mysql -uroot -pfake1\" x",
                "MYSQL_CMD=\"mysql -uroot -p***\" x",
            ),
            (
                "--cmd=\"sshpass -p fake1 ssh h\"",
                "--cmd=\"sshpass -p *** ssh h\"",
            ),
            ("cmd='curl -u bob:fake1 h'", "cmd='curl -u *** h'"),
            (
                r#"{"cmd": "x", "run":\"mysql -pfake1\"}"#,
                r#"{"cmd": "x", "run":\"mysql -p***\"}"#,
            ),
        ];
        for (input, expected) in cases {
            let out = redact_credentials(input);
            assert_eq!(out, expected, "input {input:?}");
            assert_eq!(redact_credentials(&out), out, "not idempotent: {input:?}");
        }
    }

    /// Item 8 of #445. Fake values only.
    #[test]
    fn minor_scrubber_gaps_are_closed() {
        let cases = [
            ("PASS: s3cretvalue", "PASS: ***"),
            ("PASS: tests/foo.sh", "PASS: tests/foo.sh"),
            ("pass: tests/foo.sh", "pass: tests/foo.sh"),
            ("PASS: test_login", "PASS: test_login"),
            ("PASS: ok", "PASS: ok"),
            ("pass: s3cretvalue", "pass: ***"),
            ("-----BEGIN PRIVATE KEY-----\ndone\nnext", "***\ndone\nnext"),
        ];
        for (input, expected) in cases {
            let out = redact_credentials(input);
            assert_eq!(out, expected, "input {input:?}");
            assert_eq!(redact_credentials(&out), out, "not idempotent: {input:?}");
        }
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
            // Space-separated CLI flags.
            (
                "login --user bob --password fakepw1 --host h",
                "login --user bob --password *** --host h",
            ),
            ("run --api-key 'fake key 2' now", "run --api-key '***' now"),
            ("x --TOKEN\tfaketab3", "x --TOKEN\t***"),
            // Bare `name: value`: quoted, YAML-shaped, or credential-like.
            ("password: fakeyaml4\nuser: bob", "password: ***\nuser: bob"),
            ("  - db_token: fake5 # c", "  - db_token: *** # c"),
            (
                "auth failed, secret: \"fake6\"",
                "auth failed, secret: \"***\"",
            ),
            ("bad password: fake1234xyz", "bad password: ***"),
            // `Bearer` across any whitespace, and short mixed tokens.
            ("Bearer\tfaketab7", "Bearer\t***"),
            ("Bearer\nfakenl0123", "Bearer\n***"),
            ("Bearer ab12", "Bearer ***"),
            ("Bearer a1-b", "Bearer ***"),
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
            "a bearer of news and Bearer abc",
            "invalid token: expired",
            "bad password: required",
            "the secret: unknown, error: bad credentials: none",
            "run --no-password --token-file /x --password --next",
            "usage: tool --password <value>",
            "password:",
            "Password: incorrect",
            "token: expired\nsecret: not found",
            "run --no-password file.txt",
            "token bearer\n\nSomething happened",
            "Bearer\nof news",
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
        // One very long line of bare keys must not be quadratic.
        let started = std::time::Instant::now();
        let long = "x password: ab ".repeat(70_000);
        let _ = redact_credentials(&long);
        assert!(
            started.elapsed() < std::time::Duration::from_secs(2),
            "{:?}",
            started.elapsed()
        );
        for unit in [
            "--password ",
            "Bearer\n",
            "password: ",
            "--token ",
            "bearer \t",
        ] {
            let _ = redact_credentials(&unit.repeat(100_000));
        }
    }

    /// Fake values only.
    #[test]
    fn backlog_shapes_are_masked() {
        let github = format!("ghp_{}", "a1B2".repeat(9));
        let pat = format!("github_pat_{}_{}", "A1b2C3".repeat(4), "x9".repeat(20));
        let openai = format!("sk-proj-{}", "Ab1-".repeat(12));
        let slack = "xoxb-1234567890-abcdefghij";
        let cases: Vec<(String, String)> = vec![
            // Short flags in a known-command context.
            ("mysql -u root -pfakeSecret1 db".into(), "mysql -u root -p*** db".into()),
            ("mysqldump -h h -p'fake pw' db".into(), "mysqldump -h h -p'***' db".into()),
            ("sshpass -p fakepw1 ssh -p 22 host".into(), "sshpass -p *** ssh -p 22 host".into()),
            ("sshpass -pfakepw1 ssh host".into(), "sshpass -p*** ssh host".into()),
            ("ssh-keygen -t ed25519 -N fakepass1 -f k".into(), "ssh-keygen -t ed25519 -N *** -f k".into()),
            ("ssh-keygen -p -P oldfake -N newfake".into(), "ssh-keygen -p -P *** -N ***".into()),
            ("curl -u bob:fakepw1 https://h/x".into(), "curl -u *** https://h/x".into()),
            ("curl -sSu bob:fakepw1 https://h".into(), "curl -sSu *** https://h".into()),
            ("curl -ubob:fakepw1 h".into(), "curl -u*** h".into()),
            ("curl --user bob:fakepw1 h".into(), "curl --user *** h".into()),
            ("curl -b 'sid=fake1' h".into(), "curl -b '***' h".into()),
            ("htpasswd -b /etc/pw bob fakepw1".into(), "htpasswd -b /etc/pw bob ***".into()),
            ("htpasswd -nb bob fakepw1 | head".into(), "htpasswd -nb bob *** | head".into()),
            ("docker login -u bob -p fakepw1 reg".into(), "docker login -u bob -p *** reg".into()),
            ("mysql \\\n  -pfakepw1 db".into(), "mysql \\\n  -p*** db".into()),
            ("ls; mysql -pfakepw1".into(), "ls; mysql -p***".into()),
            // Cookies.
            ("Cookie: sid=fake1; theme=x\nnext".into(), "Cookie: ***\nnext".into()),
            ("Set-Cookie: sid=fake1; Path=/".into(), "Set-Cookie: ***".into()),
            ("Proxy-Authorization: Basic fake".into(), "Proxy-Authorization: ***".into()),
            ("-H 'Cookie: sid=fake1' x".into(), "-H 'Cookie: ***' x".into()),
            // PEM.
            (
                "k:\n-----BEGIN RSA PRIVATE KEY-----\nMIIfake\nabc\n-----END RSA PRIVATE KEY-----\nafter".into(),
                "k:\n***\nafter".into(),
            ),
            (
                "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk".into(),
                "***".into(),
            ),
            // Provider tokens.
            (format!("tok {github} end"), "tok *** end".into()),
            (pat.clone(), "***".into()),
            (format!("OPENAI={openai}"), "OPENAI=***".into()),
            ("id AKIAIOSFODNN7EXAMPLE.".into(), "id ***.".into()),
            ("tmp ASIAIOSFODNN7EXAMPLE".into(), "tmp ***".into()),
            (format!("{slack} x"), "*** x".into()),
            ("gho_".to_owned() + &"Z9".repeat(18), "***".into()),
            // Standalone Basic.
            ("sent Basic dXNlcjpwYXNzd29yZA== ok".into(), "sent Basic *** ok".into()),
            ("basic dXNlcjpwYXNz.".into(), "basic ***.".into()),
            // Space before the colon, new key names.
            ("password : fakeyaml4\nuser: bob".into(), "password : ***\nuser: bob".into()),
            ("\"password\" : \"fake1\"".into(), "\"password\" : \"***\"".into()),
            ("db_pass=fakepw1 x".into(), "db_pass=*** x".into()),
            ("DB_PWD=fakepw1".into(), "DB_PWD=***".into()),
            ("pwd=fakepw1;uid=x".into(), "pwd=***;uid=x".into()),
            ("session=fake1 x".into(), "session=*** x".into()),
            ("userSession: fakesid99".into(), "userSession: ***".into()),
            ("aws_access_key_id=fakeid1".into(), "aws_access_key_id=***".into()),
            ("accessKeyId: fakeid1".into(), "accessKeyId: ***".into()),
            ("secretAccessKey=fake1".into(), "secretAccessKey=***".into()),
            ("run --pass fakepw1 x".into(), "run --pass *** x".into()),
            // JSON argv.
            ("[\"tool\", \"--password\", \"fake1\", \"-v\"]".into(), "[\"tool\", \"--password\", \"***\", \"-v\"]".into()),
            ("['--token','fake1']".into(), "['--token','***']".into()),
        ];
        for (input, expected) in cases {
            let out = redact_credentials(&input);
            assert_eq!(out, expected, "input {input:?}");
            assert_eq!(redact_credentials(&out), out, "not idempotent: {input:?}");
        }
    }

    #[test]
    fn backlog_rules_keep_ordinary_text_and_commands() {
        for text in [
            "mkdir -p /x/y",
            "ssh -p 2222 host",
            "scp -P 2222 a b:c",
            "mysql -u root -p db",
            "mysql -P 3306 -h h",
            "mysql -p",
            "sshpass -f pwfile ssh -p 22 host",
            "ssh-keygen -p -f key",
            "ssh-keygen -t ed25519 -N \"\" -f key",
            "curl -s -o out.txt https://h/x",
            "curl -b cookies.txt h",
            "htpasswd -c /etc/pw bob",
            "docker run -p 80:80 nginx",
            "docker run -p 3306:3306 mysql:8",
            "docker login reg -u bob",
            "echo hi; ssh -p 22 h",
            "cp -p a b | tee -p x",
            "max_tokens=4096 token_count: 12",
            "max_tokens: 4096",
            "bypass=1 compass: north obsession=2 overpass=x",
            "the task-force-sk-learning risk-sk-assessment-plan-2024-q3-roadmap-items",
            "PWD=/home/dev OLDPWD=/tmp pwd=~/x",
            "pass=12 fail=0 passed=3",
            "Basic setup Basic Authentication Basic configuration",
            "basic: yes, Basic info",
            "cookie jar, cookies: 3, Cookies are tasty",
            "Set-Cookies are listed below",
            "session expired, session: closed\nsession: active",
            "-----BEGIN CERTIFICATE-----\nMIIfake\n-----END CERTIFICATE-----",
            "-----BEGIN PUBLIC KEY-----\nMIIfake\n-----END PUBLIC KEY-----",
            "the marker -----BEGIN PRIVATE is cut",
            "ghp_short gho_ xoxb-1 xapp- AKIA1234 ASIAN sk-short sk-abcdefgh",
            "AKIAIOSFODNN7EXAMPLEX1 xAKIAIOSFODNN7EXAMPLE github_pat_x",
            "[\"--no-password\", \"x\"]",
            "[\"--token-file\", \"x\"]",
            "[\"--password\", \"-v\"]",
            "[\"ssh\", \"-p\", \"22\", \"host\"]",
            "password :",
        ] {
            assert_eq!(redact_credentials(text), text, "{text:?}");
        }
    }

    #[test]
    fn review_findings_are_masked_or_kept() {
        let masked = [
            ("pwd=/a/token=fake1 x", "pwd=/a/token=*** x"),
            ("cmd=mysql -pfake1 db", "cmd=mysql -p*** db"),
            ("{\"cmd\":\"mysql -pfake1\"}", "{\"cmd\":\"mysql -p***\"}"),
            ("[\"mysql\",\"-pfake1\"]", "[\"mysql\",\"-p***\"]"),
            (
                "[\"sshpass\",\"-p\",\"fake1\",\"ssh\",\"-p\",\"22\"]",
                "[\"sshpass\",\"-p\",\"***\",\"ssh\",\"-p\",\"22\"]",
            ),
            (
                "[\"curl\", \"-u\", \"a:fake1\", \"h\"]",
                "[\"curl\", \"-u\", \"***\", \"h\"]",
            ),
            (
                "tail:\nMIIfake1234\nabcdEFGH5678==\n-----END RSA PRIVATE KEY-----\nok",
                "tail:\n***\nok",
            ),
            (
                "x:\\nMIIfake12\\nabcd5678==\\n-----END PRIVATE KEY-----\\ny",
                "x:\\n***\\ny",
            ),
            (
                "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk=\nAAAAB3Nz\n\nafter",
                "***\n\nafter",
            ),
            (
                "bad key: expected -----BEGIN OPENSSH PRIVATE KEY----- header\nnext line here",
                "bad key: expected *** header\nnext line here",
            ),
            (
                "Cookie: sid=\"fake1\"; auth=fake2\nnext",
                "Cookie: ***\nnext",
            ),
            (
                "-H 'Cookie: sid=\"fake1\"; a=fake2' x",
                "-H 'Cookie: ***' x",
            ),
            ("curl --user=bob:fake1 h", "curl --user=*** h"),
            ("curl --proxy-user=bob:fake1 h", "curl --proxy-user=*** h"),
            (
                "docker --config /x login -u b -p fake1 r",
                "docker --config /x login -u b -p *** r",
            ),
            ("docker -H h login -p fake1", "docker -H h login -p ***"),
            ("mysql -pfake1\\\r\n db", "mysql -p***\\\r\n db"),
            ("mysql -pfake1\\\n db", "mysql -p***\\\n db"),
            (
                "JSESSIONID=fake1 sessid: fake2abcd",
                "JSESSIONID=*** sessid: ***",
            ),
        ];
        for (input, expected) in masked {
            let out = redact_credentials(input);
            assert_eq!(out, expected, "input {input:?}");
            assert_eq!(redact_credentials(&out), out, "{input:?}");
        }
        for text in [
            "PASS: tests/foo.sh\nPASS: other_test\nFAIL: x",
            "pass: ./t/a.t",
            "Basic tests/integration",
            "docker -H h run -p 80:80 nginx",
            "docker --config /x ps",
        ] {
            assert_eq!(redact_credentials(text), text, "{text:?}");
        }
        let mut value = serde_json::json!({
            "pwd": "/x", "pass": "12", "session": {"n": 5},
            "ht": ["htpasswd", "-b", "f", "bob", "fakepw1"],
            "ht2": ["htpasswd", "-nb", "bob", "fakepw2"],
            "key": ["-----BEGIN RSA PRIVATE KEY-----", "MIIfake1", "abcd5678", "-----END RSA PRIVATE KEY-----", "after"],
            "cu": ["curl", "--user=a:fakepw3", "h"],
            "dk": ["docker", "--config", "/x", "login", "-p", "fakepw4"],
        });
        redact_json_strings(&mut value);
        let text = value.to_string();
        assert!(
            !text.contains("fakepw") && !text.contains("MIIfake"),
            "{text}"
        );
        assert_eq!(value["pwd"], "/x");
        assert_eq!(value["pass"], "12");
        assert_eq!(value["session"], serde_json::json!({"n": 5}));
        assert_eq!(value["key"][4], "after");
    }

    #[test]
    fn json_argv_arrays_and_pass_counts() {
        let mut value = serde_json::json!({
            "argv": ["mysql", "-pfakepw1", "db"],
            "cmd": ["sshpass", "-p", "fakepw2", "ssh", "-p", "22", "h"],
            "curl": ["curl", "-u", "bob:fakepw3", "--user", "x:y", "h"],
            "long": ["tool", "--password", "fakepw4", "--token-file", "f"],
            "docker": ["docker", "login", "-p", "fakepw5"],
            "run": ["docker", "run", "-p", "80:80", "nginx"],
            "ssh": ["ssh", "-p", "2222", "h"],
            "summary": {"pass": 12, "fail": 0},
            "creds": {"pass": "fakepw6", "session": {"id": "fake7"}},
        });
        redact_json_strings(&mut value);
        let text = value.to_string();
        assert!(
            !text.contains("fakepw") && !text.contains("fake7"),
            "{text}"
        );
        assert_eq!(value["argv"], serde_json::json!(["mysql", "-p***", "db"]));
        assert_eq!(value["ssh"], serde_json::json!(["ssh", "-p", "2222", "h"]));
        assert_eq!(
            value["run"],
            serde_json::json!(["docker", "run", "-p", "80:80", "nginx"])
        );
        assert_eq!(
            value["cmd"],
            serde_json::json!(["sshpass", "-p", "***", "ssh", "-p", "22", "h"])
        );
        assert_eq!(value["summary"], serde_json::json!({"pass": 12, "fail": 0}));
        assert_eq!(value["creds"]["pass"], "***");
    }

    /// Every new rule on 1 MB of its own trigger: a quadratic rule takes
    /// minutes here.
    #[test]
    #[allow(clippy::too_many_lines)]
    fn backlog_rules_are_linear() {
        use std::fmt::Write as _;
        let units = [
            "-----BEGIN PRIVATE KEY-----",
            "-----BEGIN X PRIVATE KEY-----a-----END X PRIVATE KEY-----",
            "-----BEGIN ",
            "-----BEGIN CERTIFICATE-----",
            "ghp_",
            "ghp_ghp_",
            "github_pat_",
            "sk-",
            "sk-sk-1",
            "AKIA",
            "AKIAIOSFODNN7EXAMPLE",
            "xoxb-",
            "xapp-1-",
            "Basic ",
            "basic dXNlcjpwYXNz ",
            "Cookie: ",
            "Set-Cookie:",
            "password : ",
            "  :",
            "mysql -p ",
            "mysql -p",
            "sshpass -p ",
            "ssh-keygen -N ",
            "curl -u ",
            "curl -sSu ",
            "htpasswd -b ",
            "htpasswd -b \"",
            "docker login -p ",
            "docker ",
            "mysql ",
            "\"--password\",",
            "\"--password\"",
            "[\"--password\", \"",
            "-p-p",
            "pass=1 ",
            "accessKeyId=",
            "/pwd=",
            "pwd=~",
            "PWD=C:/",
            "pwd=/pass=1",
            "-----END PRIVATE KEY-----",
            "AAAA\n-----END PRIVATE KEY-----",
            "AAAA\\n-----END RSA PRIVATE KEY-----",
            "-----BEGIN PRIVATE KEY-----\nAAAA\n",
            "cmd=mysql -p ",
            "[\"mysql\",\"-pX\"],",
            "[\"sshpass\",\"-p\",\"X\"],",
            "[\"htpasswd\",\"-b\",\"f\",",
            "docker -H h ",
            "curl --user=",
            "Cookie: \"",
            "é-----BEGIN é",
            "\u{1b}[",
            "\u{1b}[1m",
            "\u{1b}]0;",
            "\u{1b}]0;\u{1b}",
            "\u{9b}",
            "\u{1b}[0mtoken\u{1b}[0m=",
            "\u{b}",
            "-----BEGIN PRIVATE KEY-----\nVersion: x\n\n",
            "-----BEGIN PRIVATE KEY-----\nProc-Type: ",
            "-----BEGIN PRIVATE KEY----- AAAAAAAAAAAAAAAAAAAAAA ",
            "-----BEGIN PRIVATE KEY-----\n  AAAAAAAAAAAAAAAAAAAAAA\n",
            "-----BEGIN PRIVATE KEY-----\n\n\n\n",
            "-----BEGIN PRIVATE KEY-----\nstderr: AAAAAAAAAAAAAAAAAAAAAAAA\n",
            "stderr: AAAAAAAAAAAAAAAAAAAAAAAA\n-----END PRIVATE KEY-----\n",
            "  AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n",
            "  AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n  -----END PRIVATE KEY-----\n",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\\n",
            "\\n-----END PRIVATE KEY-----\\n",
            "htpasswd -bC ",
            "htpasswd -bC10 u ",
            "[\"htpasswd\",\"-bC\",\"10\",",
            "[\"htpasswd\",\"-nb\",\"u\"],",
            "'htpasswd', '-b', ",
            "\\\"",
            "password=\\\"",
            "password=\"\\\"",
            "{\"Cookie\": \"\\\"",
            "Cookie: '\\'",
            "cmd=\"mysql ",
            "cmd=\"mysql -p\"",
            "\"",
            "PASS: ",
            "pass=tests/a.sh pass=",
            "pass=a/b pass=",
            "pass: tests/a.sh pass: ",
            "Version: ",
        ];
        let mut texts: Vec<(String, String)> = units
            .iter()
            .map(|unit| ((*unit).to_owned(), unit.repeat(1_048_576 / unit.len() + 1)))
            .collect();
        // Item 1 of #445: distinct PEM labels, which no per-unit repeat can
        // express. With no END, with a far END of the first label only, and
        // each with its own END.
        let distinct = |end: bool| {
            let mut text = String::new();
            let mut i = 0;
            while text.len() < 1_048_576 {
                let _ = writeln!(text, "-----BEGIN K{i} PRIVATE KEY-----");
                if end {
                    let _ = write!(text, "AAAA\n-----END K{i} PRIVATE KEY-----\n");
                }
                i += 1;
            }
            text
        };
        texts.push(("distinct BEGIN labels".into(), distinct(false)));
        texts.push(("distinct BEGIN/END labels".into(), distinct(true)));
        texts.push((
            "distinct labels, one far END".into(),
            distinct(false) + "-----END K0 PRIVATE KEY-----",
        ));
        texts.push((
            "distinct END labels".into(),
            distinct(false).replace("BEGIN", "END"),
        ));
        for (unit, text) in texts {
            let started = std::time::Instant::now();
            let _ = redact_credentials(&text);
            assert!(
                started.elapsed() < std::time::Duration::from_secs(3),
                "{unit:?}: {:?}",
                started.elapsed()
            );
        }
    }

    /// Random fragment soup: the scrubber never panics (multibyte text
    /// included) and a second pass changes nothing.
    #[test]
    #[allow(clippy::too_many_lines)]
    fn the_scrubber_is_idempotent_and_total_on_random_fragments() {
        let fragments = [
            "password",
            " : ",
            ":",
            "=",
            " ",
            "\t",
            "\n",
            "\\\n",
            "-p",
            "-pX",
            "-P",
            "-N ",
            "-u ",
            "-b ",
            "--password ",
            "--token",
            "\"",
            "'",
            ",",
            "[",
            "]",
            ";",
            "|",
            "&",
            "(",
            ")",
            "`",
            "mysql ",
            "sshpass ",
            "ssh-keygen ",
            "curl ",
            "htpasswd ",
            "-b ",
            "-nb ",
            "docker ",
            "login ",
            "ssh ",
            "Basic ",
            "dXNlcjpwYXNz",
            "Bearer ",
            "Cookie: ",
            "Set-Cookie: ",
            "Authorization: ",
            "-----BEGIN PRIVATE KEY-----",
            "-----END PRIVATE KEY-----",
            "-----BEGIN RSA PRIVATE KEY-----",
            "ghp_",
            "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8",
            "sk-",
            "AKIA",
            "IOSFODNN7EXAMPLE",
            "xoxb-",
            "1234567890-abc",
            "pass",
            "pwd",
            "session",
            "cookie",
            "accessKeyId",
            "é",
            "ß",
            "\u{3000}",
            "日本",
            "***",
            "x",
            "1",
            "<v>",
            "--no-token ",
            "@",
            "://",
            "/",
            "\u{1b}[1m",
            "\u{1b}[0m",
            "\u{1b}[38;5;196m",
            "\u{1b}]0;title\u{7}",
            "\u{1b}]8;;http://h\u{1b}\\",
            "\u{1b}",
            "\u{1b}[",
            "\u{9b}1m",
            "\u{b}",
            "\u{0}",
            "\u{7f}",
            "\r\n",
            "\r",
            "\\\"",
            "\\n",
            "Version: ",
            "Proc-Type: 4,ENCRYPTED",
            "  ",
            "stderr: ",
            "-bC ",
            "-bC10 ",
            "-nb ",
            "PASS: ",
            "cmd=\"",
            "test",
            "tests/a.sh",
            "-----BEGIN PGP PRIVATE KEY BLOCK-----",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "=",
        ];
        let mut state = 0x2545_f491_4f6c_dd1d_u64;
        let mut next = move || {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (state >> 33) as usize
        };
        let cases = std::env::var("FLEET_REDACT_FUZZ_CASES")
            .ok()
            .and_then(|cases| cases.parse().ok())
            .unwrap_or(20_000);
        for _ in 0..cases {
            let count = next() % 24 + 1;
            let text: String = (0..count)
                .map(|_| fragments[next() % fragments.len()])
                .collect();
            let once = redact_credentials(&text);
            assert_eq!(redact_credentials(&once), once, "{text:?} -> {once:?}");
            let stored = scrub_failure_detail(&text);
            assert_eq!(
                scrub_failure_detail(&stored),
                stored,
                "stored form: {text:?} -> {stored:?}"
            );
            let mut value = serde_json::json!([text.clone(), text.clone(), {"k": text.clone()}]);
            redact_json_strings(&mut value);
            let first = value.clone();
            redact_json_strings(&mut value);
            assert_eq!(value, first, "json form: {text:?}");
        }
    }

    #[test]
    fn json_strings_are_scrubbed_bounded_and_depth_limited() {
        let mut value = serde_json::json!({
            "remote": "https://user:hunter2pw@host.invalid/r",
            "token=fakekeyvalue": ["Bearer fakebearer9", {"big": "x".repeat(10_000)}],
            "n": 7,
        });
        redact_json_strings(&mut value);
        let text = value.to_string();
        assert!(
            !text.contains("hunter2") && !text.contains("fakebearer9"),
            "{text}"
        );
        assert!(!text.contains("fakekeyvalue"), "{text}");
        assert!(text.len() < 4_000, "{}", text.len());
        assert_eq!(value["n"], 7);

        // Structured secrets: the value is masked by its key's name, and a
        // name that merely contains a secret word is left alone.
        let mut structured = serde_json::json!({
            "password": "fake-structured-pw",
            "db": { "api_key": ["fake-key-1", 42], "tokens": 3, "ok": true },
            "token": null,
            "detail": "fine",
        });
        redact_json_strings(&mut structured);
        let text = structured.to_string();
        assert!(!text.contains("fake-"), "{text}");
        assert!(!text.contains("42"), "{text}");
        assert_eq!(structured["db"]["tokens"], 3);
        assert_eq!(structured["db"]["ok"], true);
        assert_eq!(structured["token"], serde_json::Value::Null);
        assert_eq!(structured["detail"], "fine");

        let mut deep = serde_json::json!("leaf");
        for _ in 0..40 {
            deep = serde_json::json!([deep]);
        }
        redact_json_strings(&mut deep);
        assert!(deep.to_string().len() < 100);
    }

    #[test]
    fn scrub_tail_keeps_the_end_and_never_half_keeps_a_credential() {
        let small = scrub_tail(b"line one\nline two\n", false);
        assert_eq!(small, ("line one\nline two\n".to_owned(), false));

        let long = format!("{}\nthe end\n", "x ".repeat(5_000));
        let (text, truncated) = scrub_tail(long.as_bytes(), false);
        assert!(truncated);
        assert!(
            text.starts_with('…') && text.ends_with("the end\n"),
            "{text:?}"
        );
        assert!(text.len() <= RESULT_STRING_BOUND + 4);

        // A front cut inside a credential drops the fragment.
        let front = b"ssword123@host.invalid/r tail text\n";
        let (text, truncated) = scrub_tail(front, true);
        assert!(truncated);
        assert!(!text.contains("ssword123"), "{text:?}");
        assert!(text.contains("tail text"));

        // A credential that ends up straddling the final cut is scrubbed
        // before the cut.
        let secret = "https://user:hunter2pw@host.invalid/r";
        let straddle = format!("{} {secret} {}", "a".repeat(2_000), "b ".repeat(1_400));
        let (text, _) = scrub_tail(straddle.as_bytes(), false);
        assert!(
            !text.contains("hunter2") && !text.contains("user:"),
            "{text:?}"
        );

        // Hostile terminal bytes are flattened; escapes cannot double the bound.
        let (text, _) = scrub_tail(&b"\x1b[31m\"\\\n".repeat(2_000), false);
        assert!(!text.chars().any(|c| c.is_control() && c != '\n'));
        let escaped: usize = text
            .chars()
            .map(|c| {
                if matches!(c, '"' | '\\' | '\n') {
                    2
                } else {
                    c.len_utf8()
                }
            })
            .sum();
        assert!(escaped <= RESULT_STRING_BOUND + 3, "{escaped}");

        // No whitespace after a cut front: nothing is kept.
        assert_eq!(scrub_tail(&[b'a'; 100], true), ("…".to_owned(), true));
    }
}
