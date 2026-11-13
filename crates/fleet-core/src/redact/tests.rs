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
    // Quadratic code takes tens of seconds on these inputs in a debug
    // build. A size ratio, not a wall-clock limit, so a loaded host does
    // not fail it.
    for unit in ["@", "a@", "a:@"] {
        assert_scales_linearly(unit, &|size| unit.repeat(size / unit.len() + 1));
    }
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
    assert_eq!(redact_credentials("x\u{0}u:p@h"), "***@h");
    assert_eq!(scrub_failure_detail("x\u{0}u:p@h"), "***@h");
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
        format!("{{\"k\":\"-----BEGIN PRIVATE KEY-----\\nVersion: x\\n\\n{body}\\nZm9v1234\"}}"),
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

/// Findings of the Opus audit of #447. Fake values only.
#[test]
#[allow(clippy::too_many_lines)]
fn audit_findings_are_masked_or_kept() {
    let cases = [
        // A control character inside a value, or as a separator.
        ("password=fa\u{7}kepw1", "password=***"),
        ("--password\0fakepw1", "--password ***"),
        ("--password\rfakepw1", "--password ***"),
        ("token:\rfakepw1x", "token: ***"),
        // A bare ESC is a control, not a two-byte sequence.
        ("\u{1b}password=fakepw1", "password=***"),
        // Escapes written out in JSON text.
        (
            r#"{"log":"token\u001b[0m=fakepw1"}"#,
            r#"{"log":"token=***"}"#,
        ),
        (
            r#"{"log":"\u001b]0;t\u0007token=fakepw1"}"#,
            r#"{"log":"token=***"}"#,
        ),
        // JSON inside a JSON string.
        (
            r#"{"log":"{\"password\":\"fakepw1\"}"}"#,
            r#"{"log":"{\"password\":\"***\"}"}"#,
        ),
        (
            r#"[\"--password\", \"fakepw1\"]"#,
            r#"[\"--password\", \"***\"]"#,
        ),
        // A header value that opens with an escaped quote runs to the line end.
        (
            "Authorization: \\\"fakepw1\\\"'rest more",
            "Authorization: ***",
        ),
        // A fence in the middle of a line has no indentation.
        ("got: -----END PRIVATE KEY-----", "got: ***"),
        // Test logs: names are kept, secrets under `pass` are not.
        ("PASS: cat-prints-a-file", "PASS: cat-prints-a-file"),
        (
            "--- PASS: ExampleParse (0.00s)",
            "--- PASS: ExampleParse (0.00s)",
        ),
        ("PASS: t0001-init", "PASS: t0001-init"),
        ("pass=aB3/xY9+qZ", "pass=***"),
        ("run --pass aB3/xY9+qZ== x", "run --pass *** x"),
        ("pass=Latest#2024", "pass=***"),
        // htpasswd: a line continuation, the SUSE name, a glued `=[`.
        (
            "htpasswd -b /etc/f \\\n  bob fakepw1",
            "htpasswd -b /etc/f \\\n  bob ***",
        ),
        ("htpasswd2 -nb bob fakepw1", "htpasswd2 -nb bob ***"),
        (
            "args=['htpasswd','-nb','bob','fakepw1']",
            "args=['htpasswd','-nb','bob','***']",
        ),
        (
            "argv=[\"mysql\",\"-pfakepw1\"]",
            "argv=[\"mysql\",\"-p***\"]",
        ),
        // Second audit: NUL-separated argv keeps its masks.
        (
            "mysql\0--password\0fakepw1\0--host\0db\0",
            "mysql --password *** --host db ",
        ),
        (
            "sshpass\0-p\0fakepw1\0ssh\0host\0",
            "sshpass -p *** ssh host ",
        ),
        ("\u{7f}\u{7f}\u{7f}\u{7f}mysql -pfakepw1", "mysql -p***"),
        // Removing one escape can join the pieces of another.
        (r"token\u001b\u001b[0m[0m=fakepw1", "token=***"),
        ("token\\u001b\0[0m=fakepw1", "token=***"),
        // CRLF continuation.
        (
            "htpasswd -b /etc/f \\\r\n  bob fakepw1",
            "htpasswd -b /etc/f \\\r\n  bob ***",
        ),
        // Test-log paths need a known extension.
        ("pass: aB3/xY9.qZ", "pass: ***"),
    ];
    for (input, expected) in cases {
        let out = redact_credentials(input);
        assert_eq!(out, expected, "input {input:?}");
        assert_eq!(redact_credentials(&out), out, "not idempotent: {input:?}");
        let stored = scrub_failure_detail(input);
        assert_eq!(scrub_failure_detail(&stored), stored, "stored: {input:?}");
    }
    for (input, expected) in [
        (
            serde_json::json!(["\u{1b}[0msshpass", "-p", "fakepw1"]),
            serde_json::json!(["sshpass", "-p", "***"]),
        ),
        (
            serde_json::json!({"pass\u{1b}[0mword": "fakepw1", "pass": "aB3/xY9+qZ"}),
            serde_json::json!({"password": "***", "pass": "***"}),
        ),
        (
            serde_json::json!({"pass": "Test1234!"}),
            serde_json::json!({"pass": "***"}),
        ),
        (
            serde_json::json!({"pass\u{7}word": "fakepw1", "to\u{7f}ken": "fakepw1"}),
            serde_json::json!({"password": "***", "token": "***"}),
        ),
        (
            serde_json::json!(["--password\u{0}", "fakepw1"]),
            serde_json::json!(["--password", "***"]),
        ),
        (
            serde_json::json!(["htpasswd", "-b", "f", "\\", "bob", "fakepw1"]),
            serde_json::json!(["htpasswd", "-b", "f", "\\", "bob", "***"]),
        ),
    ] {
        let mut value = input.clone();
        redact_json_strings(&mut value);
        assert_eq!(value, expected, "input {input}");
        let first = value.clone();
        redact_json_strings(&mut value);
        assert_eq!(value, first, "not idempotent: {input}");
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
    assert_scales_linearly("=a token=", &|size| {
        "=a".repeat(size / 5) + &"token=".repeat(size / 10)
    });
    // One very long line of bare keys must not be quadratic.
    assert_scales_linearly("x password: ab ", &|size| {
        "x password: ab ".repeat(size / 15)
    });
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

/// The shortest of `runs` timings of the scrub of `text`.
fn fastest_scrub(text: &str, runs: usize) -> std::time::Duration {
    (0..runs)
        .map(|_| {
            let started = std::time::Instant::now();
            let _ = redact_credentials(text);
            started.elapsed()
        })
        .min()
        .expect("at least one run")
}

/// The scrub is linear: four times the input takes about four times as
/// long, where a quadratic rule takes sixteen. `make(size)` builds a text
/// of about `size` bytes with its own generator (not a prefix of a larger
/// one), so what a long text adds (a join of nested escapes, a late END)
/// is timed at both sizes. A ratio of the fastest of several runs, not a
/// wall-clock limit alone, so a loaded host, which slows both sizes, does
/// not fail the test; the ceiling is far past any linear time and far
/// below a quadratic one.
fn assert_scales_linearly(what: &str, make: &dyn Fn(usize) -> String) {
    const SMALL: usize = 128 * 1024;
    let (small, big) = (make(SMALL), make(4 * SMALL));
    // A loaded host can slow one run only; a quadratic rule is over the
    // limit in every attempt.
    let mut last = String::new();
    for _ in 0..3 {
        let small_time = fastest_scrub(&small, 3);
        let big_time = fastest_scrub(&big, 2);
        // Below 20 ms the small run says nothing about the ratio.
        let floor = small_time.max(std::time::Duration::from_millis(20));
        let allowed = floor * 8 + std::time::Duration::from_millis(50);
        if big_time < allowed && big_time < std::time::Duration::from_secs(30) {
            return;
        }
        last = format!(
            "{what:?}: {} bytes took {big_time:?}, {SMALL} bytes {small_time:?}",
            big.len()
        );
    }
    panic!("{last}");
}

/// Every new rule on 1 MB of its own trigger: a quadratic rule takes
/// minutes here.
#[test]
#[allow(clippy::too_many_lines)]
fn backlog_rules_are_linear() {
    use std::fmt::Write as _;
    let units = [
        "-----BEGIN PRIVATE KEY-----",
        // #450: log-prefixed fences and bodies, blank lines, END-only keys.
        "web-1  | -----BEGIN PRIVATE KEY-----\nweb-1  |\n\n\n",
        "web-1  | AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\n",
        "web-1  | -----END PRIVATE KEY-----\n",
        // #540: a different prefix on each body line of an END-only key.
        "2024-01-01T00:00:01Z web-2 | AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n2024-01-01T00:00:02Z web-1 | -----END PRIVATE KEY-----\n",
        // #548: timestamps after the separator, and foreign lines
        // between the key lines of an END-only key.
        "web-1  | 2024-01-01T00:00:01Z AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\ndb-1   | 2024-01-01T00:00:02Z x\ndb-1   | y\ndb-1   | z\nweb-1  | 2024-01-01T00:00:03Z -----END PRIVATE KEY-----\n",
        "2024-01-01T00:00:01.000000001Z stdout F AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n2024-01-01T00:00:02Z stdout F -----END PRIVATE KEY-----\n",
        "web-1  | AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\ndb-1   | x\nweb-1  | -----END PRIVATE KEY-----\n",
        "\\u001b\\u001b[0m[0m",
        "\\e[pa ",
        "\u{1b}[pa ",
        "pass\u{7}word=x\0 -p ",
        "htpasswd -b f bob {\"pass\":\"x ",
        "\u{201c}mysql -p\u{201d} \u{201c}",
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
        "\\u001b[",
        "\\u001b]0;",
        "\\u001b",
        "\\x1b]",
        "\u{1b}[1m\0",
        "a\u{7}b ",
        "password=a\u{7}",
        "--password\0",
        "\\u001b\\u001b[0m[0m",
        "\\u001b\u{7f}[",
        "token\u{1b}\0[0m=",
        "\r\n",
        "\r",
        "[\\\"--password\\\", \\\"",
        "{\\\"password\\\":",
        "htpasswd \\\n",
        "args=['htpasswd',",
        "PASS: a-b ",
        "PASS: Test",
        "pass: a/b.sh ",
        "got: -----END PRIVATE KEY-----",
        "  -----END PRIVATE KEY-----\n",
        "-----BEGIN PRIVATE KEY----- AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA ",
    ];
    for unit in units {
        assert_scales_linearly(unit, &|size| unit.repeat(size / unit.len() + 1));
    }
    // Item 1 of #445: distinct PEM labels, which no per-unit repeat can
    // express. With no END, with a far END of the first label only, and
    // each with its own END.
    let distinct = |size: usize, end: bool| {
        let mut text = String::new();
        let mut i = 0;
        while text.len() < size {
            let _ = writeln!(text, "-----BEGIN K{i} PRIVATE KEY-----");
            if end {
                let _ = write!(text, "AAAA\n-----END K{i} PRIVATE KEY-----\n");
            }
            i += 1;
        }
        text
    };
    // #450: escapes nested as deep as the text is long.
    for open in ["\\u001b", "\\e"] {
        assert_scales_linearly(&format!("{open} nested"), &|size| {
            let half = size / (open.len() + 3) / 2;
            format!("token{}{}=x", open.repeat(half), "[0m".repeat(half))
        });
    }
    assert_scales_linearly("distinct BEGIN labels", &|size| distinct(size, false));
    assert_scales_linearly("distinct BEGIN/END labels", &|size| distinct(size, true));
    assert_scales_linearly("distinct labels, one far END", &|size| {
        distinct(size, false) + "-----END K0 PRIVATE KEY-----"
    });
    // #548: many interleaved key lines of two streams and one END at the
    // end.
    assert_scales_linearly("interleaved key lines, one END", &|size| {
        let unit = "web-1  | 2024-01-01T00:00:01Z AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\ndb-1   | 2024-01-01T00:00:02Z x\n";
        unit.repeat(size / unit.len() + 1)
            + "web-1  | 2024-01-01T00:00:03Z -----END PRIVATE KEY-----\n"
    });
    assert_scales_linearly("distinct END labels", &|size| {
        distinct(size, false).replace("BEGIN", "END")
    });
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
        "\\u001b[1m",
        "\\u001b]0;t",
        "\\u0007",
        "\\u001b",
        "\\e",
        "[0m",
        "\u{1b}[p",
        "\u{7}",
        "\0",
        "\u{201c}",
        "\u{201d}",
        "$'",
        "web-1  | ",
        "web-1  |\n",
        "\"\\\\\",",
        "[\\\"",
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
    let mut state = std::env::var("FLEET_REDACT_FUZZ_SEED")
        .ok()
        .and_then(|seed| seed.parse().ok())
        .unwrap_or(0x2545_f491_4f6c_dd1d_u64);
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
        let count = next() % 40 + 1;
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
        // The text as strings, as an argv made of its words, and as a key.
        let words: Vec<&str> = text.split(' ').collect();
        let mut value = serde_json::json!([
            text.clone(),
            text.clone(),
            {"k": text.clone(), text.clone(): "fakevalue1"},
            words,
        ]);
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

/// Every case: scrubbed to the expected text, and scrubbing that again (and
/// the stored form) changes nothing.
fn assert_scrubbed(cases: &[(String, &str)]) {
    for (input, expected) in cases {
        let out = redact_credentials(input);
        assert_eq!(&out, expected, "input {input:?}");
        assert_eq!(redact_credentials(&out), out, "not idempotent: {input:?}");
        let stored = scrub_failure_detail(input);
        assert_eq!(scrub_failure_detail(&stored), stored, "stored: {input:?}");
    }
}

/// #540: an END-only key whose body lines carry a different prefix each.
#[test]
fn end_only_pem_bodies_behind_varying_prefixes_are_masked() {
    let one = "MIIfake1234567890abcdefghijklmnopqrstuvwxyz0123";
    let two = "Zm9vYmFyZmFrZWtleTEyMzQ1Njc4OTBhYmNkZWZnaGlqa2xt";
    let three = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU2Nzg5";
    assert_scrubbed(&[
            (
                format!(
                    "2024-01-01T00:00:01Z app[1]: {one}\n2024-01-01T00:00:02Z app[1]: {two}\n2024-01-01T00:00:03Z app[1]: {three}\n2024-01-01T00:00:04Z app[1]: -----END PRIVATE KEY-----\n2024-01-01T00:00:05Z app[1]: after"
                ),
                "2024-01-01T00:00:01Z app[1]: ***\n2024-01-01T00:00:05Z app[1]: after",
            ),
            (
                format!(
                    "web-2  | {one}\nweb-1  | {two}\nweb-2  | {three}\nweb-1  | -----END PRIVATE KEY-----\nweb-1  | after"
                ),
                "web-2  | ***\nweb-1  | after",
            ),
            // Found by comparing against the walk without the fallback: prose
            // between key lines must not unmask what that walk masked.
            (
                "[4] FAKEkeyline0000000000000000000000001\r\n[7] listening on port 8080\r\n[3] -----END PRIVATE KEY-----\r\n[1] FAKEkeyline0000000000000000000000002\r\n[9] short\r\n[9] -----END PRIVATE KEY-----".to_owned(),
                "[4] FAKEkeyline0000000000000000000000001\r\n[7] listening on port 8080\r\n[3] ***\r\n***",
            ),
            // A short line with a prefix of its own is not part of the key.
            (
                format!("web-2  | port: 8080\nweb-1  | replicas: 3\nweb-2  | {three}\nweb-1  | -----END PRIVATE KEY-----\nweb-1  | after"),
                "web-2  | port: 8080\nweb-1  | replicas: 3\n***\nweb-1  | after",
            ),
            // The walk without the fallback masks from the `[1]` run here; the
            // one with it stops at the short line: the earlier start wins.
            (
                "2024-01-01T00:00:08Z web-1 | request id=abc123 ok\n2024-01-01T00:00:05Z web-1 | FAKEkey000000000000002\n  done\n2024-01-01T00:00:01Z web-1 | -----END RSA PRIVATE KEY-----\nlast".to_owned(),
                "2024-01-01T00:00:08Z web-1 | request id=abc123 ok\n***\nlast",
            ),
        ]);
}

/// #548: the timestamp follows the separator (`docker compose logs -t`,
/// `kubectl logs --timestamps`, CRI), and other services write between
/// the lines of an END-only key.
#[test]
fn end_only_pem_bodies_with_stamped_prefixes_and_foreign_lines_are_masked() {
    let one = "MIIfake1234567890abcdefghijklmnopqrstuvwxyz0123";
    let two = "Zm9vYmFyZmFrZWtleTEyMzQ1Njc4OTBhYmNkZWZnaGlqa2xt";
    let three = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU2Nzg5";
    let join = |lines: &[&str]| lines.join("\n");
    assert_scrubbed(&[
        (
            join(&[
                &format!("web-1  | 2024-01-01T00:00:01.123456Z {one}"),
                &format!("web-1  | 2024-01-01T00:00:02.223456Z {two}"),
                &format!("web-1  | 2024-01-01T00:00:03.323456Z {three}"),
                "web-1  | 2024-01-01T00:00:04.423456Z -----END PRIVATE KEY-----",
                "web-1  | 2024-01-01T00:00:05.523456Z after",
            ]),
            "web-1  | 2024-01-01T00:00:01.123456Z ***\nweb-1  | 2024-01-01T00:00:05.523456Z after",
        ),
        (
            join(&[
                &format!("2024-01-01T00:00:01Z {one}"),
                &format!("2024-01-01T00:00:02Z {two}"),
                "2024-01-01T00:00:03Z -----END PRIVATE KEY-----",
                "2024-01-01T00:00:04Z after",
            ]),
            "2024-01-01T00:00:01Z ***\n2024-01-01T00:00:04Z after",
        ),
        (
            join(&[
                &format!("2024-01-01T00:00:01.000000001Z stdout F {one}"),
                &format!("2024-01-01T00:00:02.000000001Z stdout P {two}"),
                &format!("2024-01-01T00:00:03.000000001Z stdout F {three}"),
                "2024-01-01T00:00:04.000000001Z stdout F -----END PRIVATE KEY-----",
                "2024-01-01T00:00:05.000000001Z stdout F after",
            ]),
            "2024-01-01T00:00:01.000000001Z stdout F ***\n2024-01-01T00:00:05.000000001Z stdout F after",
        ),
        // Another service writes between the key lines.
        (
            join(&[
                &format!("web-1  | {one}"),
                "db-1   | LOG: checkpoint starting",
                &format!("web-1  | {two}"),
                "db-1   | LOG: checkpoint complete",
                &format!("web-1  | {three}"),
                "web-1  | -----END PRIVATE KEY-----",
                "web-1  | after",
            ]),
            "***\nweb-1  | after",
        ),
        (
            join(&[
                &format!("web-1  | 2024-01-01T00:00:01Z {one}"),
                "db-1   | 2024-01-01T00:00:02Z checkpoint starting",
                &format!("web-1  | 2024-01-01T00:00:03Z {two}"),
                "db-1   | 2024-01-01T00:00:04Z checkpoint complete",
                "web-1  | 2024-01-01T00:00:05Z -----END PRIVATE KEY-----",
                "web-1  | 2024-01-01T00:00:06Z after",
            ]),
            "web-1  | 2024-01-01T00:00:01Z ***\nweb-1  | 2024-01-01T00:00:06Z after",
        ),
        // No full key line of the stream before the foreign line: only the
        // lines of the stream are the key.
        (
            join(&[
                "db-1   | LOG: checkpoint starting",
                &format!("web-1  | {two}"),
                "web-1  | -----END PRIVATE KEY-----",
                "web-1  | after",
            ]),
            "db-1   | LOG: checkpoint starting\n***\nweb-1  | after",
        ),
    ]);
    // Ordinary stamped logs around a lone fence are left alone.
    let benign = "web-1  | 2024-01-01T00:00:01Z listening on port 8080\nweb-1  | 2024-01-01T00:00:02Z ready\n";
    assert_eq!(redact_credentials(benign), benign);
}

/// Review of #552: the delimiter fallback keeps priority on the BEGIN
/// path, long service names and `kubectl --prefix` keep the timestamp out
/// of the prefix budget, hex-only lines do not anchor a skip.
#[test]
fn stamped_prefixes_review_cases() {
    let one = "MIIfake1234567890abcdefghijklmnopqrstuvwxyz0123";
    let two = "Zm9vYmFyZmFrZWtleTEyMzQ1Njc4OTBhYmNkZWZnaGlqa2xt";
    // BEGIN without END: a body line cut by an escaped newline.
    let begin = format!(
        "2024-01-01T00:00:01Z web-1  | -----BEGIN PRIVATE KEY-----\r\n2024-01-01T00:00:02Z web-1  | LJxhRtXDDHq \\nweb-1  | {two}\r\n2024-01-01T00:00:03Z web-1  | done"
    );
    let out = redact_credentials(&begin);
    assert!(
        !out.contains("LJxhRtXDDHq") && !out.contains(two),
        "{out:?}"
    );
    let name = "long-service-name-1";
    let pad = " ".repeat(2);
    let end = format!(
        "{name}{pad}| 2024-01-01T00:00:01.123456789Z {one}\n{name}{pad}| 2024-01-01T00:00:02.123456789Z {two}\n{name}{pad}| 2024-01-01T00:00:03.123456789Z -----END PRIVATE KEY-----\n{name}{pad}| 2024-01-01T00:00:04Z after"
    );
    let out = redact_credentials(&end);
    assert!(!out.contains(two) && out.contains("after"), "{out:?}");
    let kube = format!(
        "[pod/web-7d9f8b6c5-x2x4q/container] 2024-01-01T00:00:01Z {one}\n[pod/web-7d9f8b6c5-x2x4q/container] 2024-01-01T00:00:02Z {two}\n[pod/web-7d9f8b6c5-x2x4q/container] 2024-01-01T00:00:03Z -----END PRIVATE KEY-----\n[pod/web-7d9f8b6c5-x2x4q/container] 2024-01-01T00:00:04Z after"
    );
    let out = redact_credentials(&kube);
    assert!(!out.contains(two) && out.contains("after"), "{out:?}");
    let short_kube = kube.replace("web-7d9f8b6c5-x2x4q/container", "p/c");
    let out = redact_credentials(&short_kube);
    assert!(!out.contains(two) && out.contains("after"), "{out:?}");
    // A hex-only line (a SHA) or a banner does not anchor a skip.
    let sha = "0123456789abcdef0123456789abcdef";
    let sha40 = "0123456789abcdef0123456789abcdef01234567";
    for anchor in [&sha[..20], sha, sha40, "===================="] {
        let text = format!(
            "web-1  | {anchor}\ndb-1   | LOG: x\nweb-1  | -----END PRIVATE KEY-----\nweb-1  | after"
        );
        let out = redact_credentials(&text);
        assert!(out.contains(anchor), "{out:?}");
    }
}

/// Review of #552: a long stamped prefix on a BEGIN-without-END key.
#[test]
fn a_long_stamped_prefix_on_a_begin_only_key_masks_the_body() {
    let text = "2024-01-01T00:00:01.123456789+02:00 postgres-exporter-1    | -----BEGIN RSA PRIVATE KEY-----\nFMI+ekQm+eYxyFt3\\n2024-01-01T00:00:02.123456789+02:00 db-1   | container started";
    let out = redact_credentials(text);
    assert!(!out.contains("FMI+ekQm+eYxyFt3"), "{out:?}");
}

/// Item 1 of #450: a key behind a per-line log prefix, blank lines after
/// BEGIN and inside the body. Fake values only.
#[test]
fn pem_bodies_behind_log_prefixes_are_masked() {
    let one = "MIIfake1234567890abcdefghijklmnopqrstuvwxyz0123";
    let two = "Zm9vYmFyZmFrZWtleTEyMzQ1Njc4OTBhYmNkZWZnaGlqa2xt";
    assert_scrubbed(&[
        (
            format!(
                "web-1  | -----BEGIN PRIVATE KEY-----\nweb-1  | {one}\nweb-1  | {two}\nweb-1  | Zm9v==\nweb-1  | done"
            ),
            "web-1  | ***\nweb-1  | done",
        ),
        (
            format!(
                "app: -----BEGIN PRIVATE KEY-----\napp: {one}\napp: {two}\napp: Zm9v==\napp: done"
            ),
            "app: ***\napp: done",
        ),
        // The prefix of a blank line has its trailing blank trimmed.
        (
            format!(
                "web-1  | -----BEGIN PRIVATE KEY-----\nweb-1  |\nweb-1  | {one}\nweb-1  |\nweb-1  | {two}\nweb-1  | Zm9v==\nweb-1  | done"
            ),
            "web-1  | ***\nweb-1  | done",
        ),
        // Interleaved services and timestamped prefixes: the prefix differs
        // per line.
        (
            format!(
                "web-1  | -----BEGIN PRIVATE KEY-----\nweb-2  | {one}\nweb-1  | {two}\nweb-1  | server started ok"
            ),
            "web-1  | ***\nweb-1  | server started ok",
        ),
        (
            format!(
                "2024-01-01T00:00:00Z app[1]: -----BEGIN PRIVATE KEY-----\n2024-01-01T00:00:01Z app[1]: {one}\n2024-01-01T00:00:02Z app[1]: {two}\n2024-01-01T00:00:03Z app[1]: server started ok"
            ),
            "2024-01-01T00:00:00Z app[1]: ***\n2024-01-01T00:00:03Z app[1]: server started ok",
        ),
        // An END with no BEGIN.
        (
            format!(
                "web-1  | {one}\nweb-1  | {two}\nweb-1  | -----END PRIVATE KEY-----\nweb-1  | after"
            ),
            "***\nweb-1  | after",
        ),
        // Two blank lines after BEGIN.
        (
            format!("-----BEGIN PRIVATE KEY-----\n\n\n{one}\n{two}\nZm9v==\nafter"),
            "***\nafter",
        ),
        // A blank line inside the body.
        (
            format!("-----BEGIN PRIVATE KEY-----\n{one}\n\n{two}\nZm9v==\nafter"),
            "***\nafter",
        ),
        // Three blank lines end the key; prose after a blank line is kept.
        (
            format!("-----BEGIN PRIVATE KEY-----\n{one}\n\n\n\n{two}\nafter"),
            &format!("***\n\n\n\n{two}\nafter"),
        ),
        (
            format!("-----BEGIN PRIVATE KEY-----\n{one}\n\nnext step: ok"),
            "***\n\nnext step: ok",
        ),
    ]);
}

/// Item 2 of #450: a soft control read both ways masks both readings.
#[test]
fn mixed_soft_controls_mask_every_reading() {
    assert_scrubbed(&[
        (
            "mysql --password\0A1fake pass\u{7}word=B1fake pass\u{7}word=C1fake".into(),
            "mysql --password*** password=*** password=***",
        ),
        (
            "pass\u{7}word=B1fake mysql\0--password\0A1fake".into(),
            "password=*** mysql--password***",
        ),
        // NUL-separated environ and cmdline (`/proc/*/environ`): every
        // secret is masked, and what follows a mask is kept.
        (
            "DB_PASSWORD=fakeaaa1\0API_TOKEN=fakebbb2\0HOME=/root".into(),
            "DB_PASSWORD=*** API_TOKEN=*** HOME=/root",
        ),
        (
            "PGPASSWORD=fakeaaa1\0PATH=/bin\0GITHUB_TOKEN=ghp_fakebbb2\0LANG=C\0".into(),
            "PGPASSWORD=*** PATH=/bin GITHUB_TOKEN=*** LANG=C ",
        ),
        (
            "mysql\0-ufoo\0-pfakeaaa1\0--password=fakebbb2\0db".into(),
            "mysql -ufoo -p*** --password=*** ***",
        ),
        (
            "curl\0-u\0bob:fakeaaa1\0--header\0Authorization: Bearer fakebbb2abc\0http://h".into(),
            "curl -u *** --header Authorization: ***",
        ),
        // One reading only is unchanged.
        ("--password\0fakepw1".into(), "--password ***"),
        ("x\u{0}u:p@h".into(), "***@h"),
    ]);
}

/// Item 3 of #450: escapes nested deeper than any fixed number of passes.
#[test]
fn deeply_nested_escapes_are_stripped() {
    for depth in [6, 7, 40, 500] {
        for (open, close) in [
            ("\\u001b", "[0m"),
            ("\\x1b", "[0m"),
            ("\\033", "[1;31m"),
            ("\\e", "[0m"),
        ] {
            let input = format!("token{}{}=fakepw1", open.repeat(depth), close.repeat(depth));
            assert_scrubbed(&[(input, "token=***")]);
        }
    }
    // Mixed with soft controls and raw escapes between the pieces.
    let input = format!(
        "token{}{}=fakepw1",
        "\\u001b\0".repeat(8),
        "[0m\u{7f}".repeat(8)
    );
    assert_scrubbed(&[(input, "token=***")]);
    let input = format!(
        "token{}{}=fakepw1",
        "\\u001b\u{1b}[0m".repeat(9),
        "[0m".repeat(9)
    );
    assert_scrubbed(&[(input, "token=***")]);
}

/// Item 4 of #450: the argv continuation element, `ESC [ letter`,
/// `$'...'` and typographic quotes. Fake values only.
#[test]
fn residual_shapes_from_the_second_audit_are_masked() {
    assert_scrubbed(&[
        (
            r#"["htpasswd","-b","f","\\","bob","PW1fake"]"#.into(),
            r#"["htpasswd","-b","f","\\","bob","***"]"#,
        ),
        // `ESC [` and a letter is a CSI final or the start of a word.
        ("\u{1b}[password=X1fake".into(), "password=***"),
        ("\u{1b}[Kpassword=X1fake".into(), "password=***"),
        ("\u{1b}[mtoken=X1fake".into(), "token=***"),
        ("\\u001b[password=X1fake".into(), "password=***"),
        // With parameters too, and the written-out `\e` only as a short CSI.
        ("\u{1b}[1;31password=fake1".into(), "password=***"),
        ("\\e[1;31password=fake1".into(), "\\e[1;31password=***"),
        ("\\e[1;31mtoken=fake1 ok".into(), "token=*** ok"),
        (
            "printf '\\e]0;title\\a' && echo ok rest".into(),
            "printf '\\e]0;title\\a' && echo ok rest",
        ),
        ("C:\\Users\\e]x\\file".into(), "C:\\Users\\e]x\\file"),
        // An apostrophe inside a value does not end it.
        ("password=don\u{2019}tleak1".into(), "password=***"),
        (
            "password=\u{201c}don\u{2019}t leak\u{201d} x".into(),
            "password=\u{201c}***\u{201d} x",
        ),
        // An unclosed typographic quote is an ordinary character.
        (
            "htpasswd -b \u{201c}f bob fakepw1".into(),
            "htpasswd -b \u{201c}f bob ***",
        ),
        // The `"\\"` element continues the command only inside an array.
        (
            r#"htpasswd -b f bob "\\""#.into(),
            r#"htpasswd -b f bob "***""#,
        ),
        (
            r#"["htpasswd","-b","f","bob","\\"]"#.into(),
            r#"["htpasswd","-b","f","bob","***"]"#,
        ),
        ("cmd=$'mysql -pfakepw1'".into(), "cmd=$'mysql -p***'"),
        (
            "\u{201c}mysql -pfakepw1\u{201d} x".into(),
            "\u{201c}mysql -p*** x",
        ),
        (
            "mysql \u{201c}-pfakepw1\u{201d}".into(),
            "mysql \u{201c}-p***",
        ),
        (
            "password=\u{201c}hunter two\u{201d} rest".into(),
            "password=\u{201c}***\u{201d} rest",
        ),
        (
            "\u{201c}password\u{201d}: \u{201c}hunter two\u{201d} rest".into(),
            "\u{201c}password\u{201d}: \u{201c}***\u{201d} rest",
        ),
    ]);
}

/// Item 5 of #450: the `PASS:` test-log trade-off and an `htpasswd`
/// password with a quote inside it.
#[test]
fn test_log_names_and_odd_htpasswd_arguments() {
    assert_scrubbed(&[
        // Test names with digits and separators are kept (documented
        // trade-off), and so is a secret of that shape.
        ("PASS: hunter2_secret".into(), "PASS: hunter2_secret"),
        ("PASS: test_utf8_2".into(), "PASS: test_utf8_2"),
        ("PASS: io-uring-v2".into(), "PASS: io-uring-v2"),
        ("PASS: http2-push".into(), "PASS: http2-push"),
        ("PASS: parse_ipv4_addr".into(), "PASS: parse_ipv4_addr"),
        ("PASS: sha256-sum".into(), "PASS: sha256-sum"),
        ("PASS: ext4-resize.sh".into(), "PASS: ext4-resize.sh"),
        ("PASS: abc-1.2.3".into(), "PASS: abc-1.2.3"),
        ("PASS: t0001-init".into(), "PASS: t0001-init"),
        ("PASS: cat-prints-a-file".into(), "PASS: cat-prints-a-file"),
        // Kept on purpose: indistinguishable from a test name.
        ("PASS: my_secret_value".into(), "PASS: my_secret_value"),
        (
            "htpasswd -b f bob {\"pass\":\"x1fake rest".into(),
            "htpasswd -b f bob {\"pass\":\"***",
        ),
        (
            "sh -c \"htpasswd -b f bob pw1fake\" tail".into(),
            "sh -c \"htpasswd -b f bob ***\" tail",
        ),
    ]);
}
