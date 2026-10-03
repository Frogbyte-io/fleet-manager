//! Everything the suite prints passes through here. The repository and its
//! Actions logs are public, so token secrets, token ids, host addresses,
//! node names, and fingerprints are replaced with placeholders, and any
//! IPv4 address (a guest's DHCP lease, say) is masked as well.

/// Replaces configured values and IPv4 addresses in text.
#[derive(Clone, Debug, Default)]
pub struct Redactor {
    /// Needle → placeholder, longest needle first.
    pairs: Vec<(String, String)>,
    /// Short identifiers (node names) masked only as whole words, so a
    /// node called `pve` does not shred `pveVersion`.
    words: Vec<(String, String)>,
}

impl Redactor {
    /// Adds one value to mask. Values shorter than three characters are
    /// ignored: masking them would shred unrelated text.
    pub fn mask(&mut self, value: &str, placeholder: &str) {
        let value = value.trim();
        if value.len() < 3 || self.pairs.iter().any(|(needle, _)| needle == value) {
            return;
        }
        self.pairs.push((value.to_owned(), placeholder.to_owned()));
        // A fingerprint is also printed with colons: mask both spellings.
        if value.len() == 64 && value.chars().all(|c| c.is_ascii_hexdigit()) {
            let colons = value
                .as_bytes()
                .chunks(2)
                .map(|pair| String::from_utf8_lossy(pair).into_owned())
                .collect::<Vec<_>>()
                .join(":");
            self.pairs.push((colons.clone(), placeholder.to_owned()));
            self.pairs
                .push((colons.to_lowercase(), placeholder.to_owned()));
            self.pairs
                .push((value.to_lowercase(), placeholder.to_owned()));
        }
        self.pairs
            .sort_by_key(|pair| std::cmp::Reverse(pair.0.len()));
    }

    /// Adds one identifier masked only where it stands as a whole word.
    pub fn mask_word(&mut self, value: &str, placeholder: &str) {
        let value = value.trim();
        if value.is_empty() || self.words.iter().any(|(needle, _)| needle == value) {
            return;
        }
        self.words.push((value.to_owned(), placeholder.to_owned()));
        self.words
            .sort_by_key(|pair| std::cmp::Reverse(pair.0.len()));
    }

    /// The text with every configured value and IPv4 address masked.
    #[must_use]
    pub fn redact(&self, text: &str) -> String {
        let mut out = text.to_owned();
        for (needle, placeholder) in &self.pairs {
            if out.contains(needle.as_str()) {
                out = out.replace(needle.as_str(), placeholder);
            }
        }
        for (needle, placeholder) in &self.words {
            out = replace_word(&out, needle, placeholder);
        }
        mask_ipv4(&out)
    }

    /// One printable line: redacted, control characters flattened.
    #[must_use]
    pub fn line(&self, text: &str) -> String {
        self.redact(text)
            .chars()
            .map(|c| if c.is_control() { ' ' } else { c })
            .collect()
    }
}

/// Replaces `needle` where neither neighbour is an identifier character.
#[must_use]
pub fn replace_word(text: &str, needle: &str, placeholder: &str) -> String {
    let is_ident = |c: char| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.';
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find(needle) {
        let before = rest[..at]
            .chars()
            .next_back()
            .or_else(|| out.chars().next_back());
        let after = rest[at + needle.len()..].chars().next();
        let (head, tail) = rest.split_at(at);
        out.push_str(head);
        if before.is_some_and(is_ident) || after.is_some_and(is_ident) {
            out.push_str(needle);
        } else {
            out.push_str(placeholder);
        }
        rest = &tail[needle.len()..];
    }
    out.push_str(rest);
    out
}

/// Masks dotted-quad IPv4 addresses.
#[must_use]
pub fn mask_ipv4(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut index = 0;
    while index < bytes.len() {
        let at_boundary =
            index == 0 || !(bytes[index - 1].is_ascii_alphanumeric() || bytes[index - 1] == b'.');
        if at_boundary
            && bytes[index].is_ascii_digit()
            && let Some(end) = ipv4_end(bytes, index)
        {
            out.push_str("<redacted-ipv4>");
            index = end;
            continue;
        }
        // Copy one UTF-8 character.
        let width = utf8_width(bytes[index]);
        out.push_str(&text[index..index + width]);
        index += width;
    }
    out
}

/// The end of a dotted quad starting at `start`, when one starts there.
fn ipv4_end(bytes: &[u8], start: usize) -> Option<usize> {
    let mut index = start;
    for octet in 0..4 {
        let digits_start = index;
        while index < bytes.len() && bytes[index].is_ascii_digit() && index - digits_start < 3 {
            index += 1;
        }
        if index == digits_start {
            return None;
        }
        let value: u32 = std::str::from_utf8(&bytes[digits_start..index])
            .ok()?
            .parse()
            .ok()?;
        if value > 255 {
            return None;
        }
        if octet < 3 {
            if bytes.get(index) != Some(&b'.') {
                return None;
            }
            index += 1;
        }
    }
    if bytes.get(index).is_some_and(|next| next.is_ascii_digit()) {
        return None;
    }
    Some(index)
}

fn utf8_width(first: u8) -> usize {
    match first {
        0x00..=0x7F => 1,
        0xC0..=0xDF => 2,
        0xE0..=0xEF => 3,
        _ => 4,
    }
}
