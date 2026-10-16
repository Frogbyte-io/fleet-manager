//! `fleetctl accounts` (FM-1001): grammar, request shapes, the write-only
//! token, and the renderer.

use fleetctl::accounts::AccountsAction;
use serde_json::json;

const TOKEN: &str = "never-printed-token-0001";

fn args(words: &[&str]) -> Vec<String> {
    words.iter().map(ToString::to_string).collect()
}

fn action(words: &[&str]) -> AccountsAction {
    match fleetctl::parse(&args(words)).expect("parses").command {
        fleetctl::Command::Accounts(action) => action,
        other => panic!("not an accounts command: {other:?}"),
    }
}

#[test]
fn the_grammar_covers_every_verb() {
    assert_eq!(
        action(&["accounts", "list", "--kind", "coolify"]),
        AccountsAction::List {
            kind: Some("coolify".to_owned()),
            limit: None,
            cursor: None,
        }
    );
    assert_eq!(
        action(&["accounts", "probe", "acc-1"]),
        AccountsAction::Probe {
            id: "acc-1".to_owned()
        }
    );
    assert!(matches!(
        action(&[
            "accounts",
            "create",
            "--kind",
            "cloudflare",
            "--label",
            "dns",
            "--account-id",
            "abc123"
        ]),
        AccountsAction::Create { .. }
    ));
    assert!(matches!(
        action(&["accounts", "update", "acc-1", "--rotate-token"]),
        AccountsAction::Update {
            rotate_token: true,
            ..
        }
    ));
}

#[test]
fn undocumented_forms_are_refused() {
    for words in [
        vec!["accounts"],
        vec!["accounts", "get"],
        vec!["accounts", "get", "-x"],
        vec!["accounts", "create", "--label", "x"],
        vec!["accounts", "create", "--kind", "coolify"],
        // The token is never a command-line argument.
        vec![
            "accounts", "create", "--kind", "coolify", "--label", "x", "--token", "t",
        ],
        vec!["accounts", "update", "acc-1", "--token", "t"],
        vec!["accounts", "delete", "acc-1", "--force"],
        vec!["accounts", "list", "--label"],
    ] {
        assert!(fleetctl::parse(&args(&words)).is_err(), "{words:?}");
    }
}

#[test]
fn only_create_and_rotation_carry_the_token_and_it_goes_in_the_body_only() {
    let create = AccountsAction::Create {
        kind: "coolify".to_owned(),
        label: "prod".to_owned(),
        base_url: Some("https://coolify.example.test".to_owned()),
        account_id: None,
        notes: None,
    };
    let (method, path, query, body) = fleetctl::accounts_request_for_test(&create, TOKEN).unwrap();
    assert_eq!(
        (method.as_str(), path.as_str()),
        ("POST", "/api/v1/external-accounts")
    );
    assert!(query.is_empty());
    assert_eq!(body.unwrap()["token"], TOKEN);

    let update = |rotate_token| AccountsAction::Update {
        id: "acc-1".to_owned(),
        label: Some("new".to_owned()),
        base_url: None,
        account_id: None,
        notes: None,
        rotate_token,
    };
    let (method, path, _, body) =
        fleetctl::accounts_request_for_test(&update(false), TOKEN).unwrap();
    assert_eq!(
        (method.as_str(), path.as_str()),
        ("PATCH", "/api/v1/external-accounts/acc-1")
    );
    assert!(body.unwrap().get("token").is_none());
    let (_, _, _, body) = fleetctl::accounts_request_for_test(&update(true), TOKEN).unwrap();
    assert_eq!(body.unwrap()["token"], TOKEN);

    for read in [
        AccountsAction::List {
            kind: None,
            limit: None,
            cursor: None,
        },
        AccountsAction::Get { id: "a".to_owned() },
        AccountsAction::Delete { id: "a".to_owned() },
        AccountsAction::Probe { id: "a".to_owned() },
    ] {
        let (_, path, _, body) = fleetctl::accounts_request_for_test(&read, TOKEN).unwrap();
        assert!(body.is_none(), "{path}");
        assert!(!path.contains(TOKEN));
    }
}

#[test]
fn text_output_shows_probe_status_and_permissions_but_the_response_has_no_token() {
    let account = json!({"data": {
        "id": "acc-1", "kind": "coolify", "label": "prod", "baseUrl": "https://c.example.test",
        "notes": "main", "createdAt": 1, "updatedAt": 2,
        "lastProbe": {"status": "insufficient_permission", "detail": "missing: deploy",
            "granted": ["read", "write"], "missing": ["deploy"], "checkedAt": 3}
    }});
    let text = fleetctl::render_accounts_for_test(&account);
    assert!(text.contains("insufficient_permission"), "{text}");
    assert!(text.contains("granted: read, write"), "{text}");
    assert!(text.contains("missing: deploy"), "{text}");
    assert!(!text.contains(TOKEN));

    let list =
        json!({"items": [account["data"].clone()], "page": {"limit": 50, "nextCursor": null}});
    assert!(fleetctl::render_accounts_for_test(&list).contains("prod"));
    let empty = json!({"items": [], "page": {"limit": 50, "nextCursor": null}});
    assert_eq!(fleetctl::render_accounts_for_test(&empty), "(no accounts)");
}

#[test]
fn list_paging_flags_reach_the_query() {
    let list = action(&["accounts", "list", "--limit", "5", "--cursor", "acc-9"]);
    let (_, path, query, _) = fleetctl::accounts_request_for_test(&list, TOKEN).unwrap();
    assert_eq!(path, "/api/v1/external-accounts");
    assert_eq!(
        query,
        [
            ("limit".to_owned(), "5".to_owned()),
            ("cursor".to_owned(), "acc-9".to_owned())
        ]
    );
    assert!(fleetctl::parse(&args(&["accounts", "list", "--limit", "abc"])).is_err());
}

#[test]
fn ids_are_percent_encoded_in_paths() {
    let get = AccountsAction::Get {
        id: "a/b?c#d e".to_owned(),
    };
    let (_, path, _, _) = fleetctl::accounts_request_for_test(&get, TOKEN).unwrap();
    assert_eq!(path, "/api/v1/external-accounts/a%2Fb%3Fc%23d%20e");
    let probe = AccountsAction::Probe {
        id: "../x".to_owned(),
    };
    let (_, path, _, _) = fleetctl::accounts_request_for_test(&probe, TOKEN).unwrap();
    assert_eq!(path, "/api/v1/external-accounts/..%2Fx/probe");
}

#[test]
fn text_output_strips_control_characters_and_shows_unverified() {
    let account = json!({"data": {
        "id": "acc-1", "kind": "coolify", "label": "evil\u{1b}[31mred\nname",
        "baseUrl": "https://c.example.test", "notes": "a\u{7}b\rc",
        "lastProbe": {"status": "ok", "detail": "fine\u{1b}[2J", "granted": ["read"],
            "missing": [], "unverified": ["write", "deploy"], "checkedAt": 3}
    }});
    let text = fleetctl::render_accounts_for_test(&account);
    assert!(!text.contains('\u{1b}'), "{text:?}");
    assert!(!text.contains('\u{7}'), "{text:?}");
    assert!(!text.contains('\r'), "{text:?}");
    assert_eq!(text.lines().count(), 5, "{text:?}");
    assert!(text.contains("unverified: write, deploy"), "{text}");
}
