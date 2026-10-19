//! The delegated token format and hashing (ADR 0011): 32 CSPRNG bytes, a
//! fixed shape, a SHA-256 durable form, and a constant-time comparison.

use fleet_application::credentials::CredentialCrypto as _;
use fleet_auth::DelegatedTokenCrypto;
use fleet_auth::delegated::is_token_shaped;

#[test]
fn tokens_are_fresh_32_byte_values_in_a_fixed_shape() {
    let crypto = DelegatedTokenCrypto::new();
    let first = crypto.generate_token();
    let second = crypto.generate_token();
    assert_ne!(first, second);
    for token in [&first, &second] {
        assert!(is_token_shaped(token), "{token}");
        assert_eq!(token.len(), "fmdc1.".len() + 64);
    }
    // 64 distinct tokens: a constant or counter would collide or repeat.
    let all: std::collections::HashSet<String> = (0..64).map(|_| crypto.generate_token()).collect();
    assert_eq!(all.len(), 64);
}

#[test]
fn only_the_exact_shape_is_token_shaped() {
    let good = format!("fmdc1.{}", "0123456789abcdef".repeat(4));
    assert!(is_token_shaped(&good));
    for bad in [
        String::new(),
        "fmdc1.".to_owned(),
        format!("fmdc2.{}", "a".repeat(64)),
        format!("fmdc1.{}", "A".repeat(64)),
        format!("fmdc1.{}", "a".repeat(63)),
        format!("fmdc1.{}", "a".repeat(65)),
        format!("fmdc1.{}g", "a".repeat(63)),
        format!(" {good}"),
        format!("{good} "),
        format!("fmenr1.{}", "a".repeat(64)),
    ] {
        assert!(!is_token_shaped(&bad), "{bad:?}");
    }
}

#[test]
fn the_durable_form_is_the_sha256_of_the_token() {
    let crypto = DelegatedTokenCrypto::new();
    // SHA-256("abc"), the published test vector.
    assert_eq!(
        crypto.hash_token("abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    let token = crypto.generate_token();
    let hash = crypto.hash_token(&token);
    assert_eq!(hash.len(), 64);
    assert!(!hash.contains(&token));
    assert_eq!(hash, crypto.hash_token(&token));
}

#[test]
fn hash_comparison_accepts_only_equal_hashes() {
    let crypto = DelegatedTokenCrypto::new();
    let hash = crypto.hash_token("one");
    assert!(crypto.hashes_equal(&hash, &hash.clone()));
    assert!(!crypto.hashes_equal(&hash, &crypto.hash_token("two")));
    assert!(!crypto.hashes_equal(&hash, &hash[..63]));
    assert!(!crypto.hashes_equal(&hash, ""));
    // One bit away in the last position.
    let mut near = hash.clone().into_bytes();
    let last = near.len() - 1;
    near[last] ^= 1;
    assert!(!crypto.hashes_equal(&hash, &String::from_utf8(near).unwrap()));
}
