//! The built-in pin table (#600): a release is chosen from the machine's
//! `os/family` and `host/architecture` facts, and every platform without a
//! pin says why.

use fleet_provider_skills_manager::{NoReleasePin, PINNED_CLI_VERSION, release_pin};

#[test]
fn linux_x86_64_and_its_alias_pick_the_x64_asset() {
    for arch in ["x86_64", "amd64", "X86_64"] {
        let pin = release_pin(Some("Linux"), Some(arch)).unwrap();
        assert_eq!(pin.asset, "skills-manager-cli-Linux-x64", "{arch}");
        assert_eq!(pin.version, PINNED_CLI_VERSION);
        assert_eq!(
            pin.url,
            "https://github.com/xingkongliang/skills-manager/releases/download/v1.40.0/skills-manager-cli-Linux-x64"
        );
        assert_eq!(
            pin.sha256,
            "6edb154b290803cd652fa047cac2d980fd94dc75c1f16bd9acb7a0536544e61b"
        );
    }
}

#[test]
fn linux_aarch64_and_its_alias_pick_the_arm64_asset() {
    for arch in ["aarch64", "arm64"] {
        let pin = release_pin(Some("linux"), Some(arch)).unwrap();
        assert_eq!(pin.asset, "skills-manager-cli-Linux-arm64", "{arch}");
        assert!(pin.url.ends_with("/v1.40.0/skills-manager-cli-Linux-arm64"));
        assert_eq!(
            pin.sha256,
            "377e3538ce74a13118ba0c30ebaaff597c7be4f0bb2bec2598ea0da27064a187"
        );
    }
}

#[test]
fn every_pin_is_a_lowercase_sha256_over_https() {
    for arch in ["x86_64", "aarch64"] {
        let pin = release_pin(Some("Linux"), Some(arch)).unwrap();
        assert!(pin.url.starts_with("https://github.com/"));
        assert_eq!(pin.sha256.len(), 64);
        assert!(
            pin.sha256
                .chars()
                .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
        );
    }
}

#[test]
fn an_unknown_architecture_is_skipped_with_a_reason() {
    let error = release_pin(Some("Linux"), Some("riscv64")).unwrap_err();
    assert_eq!(
        error,
        NoReleasePin::UnsupportedArchitecture {
            architecture: "riscv64".to_owned()
        }
    );
    assert!(error.to_string().contains("riscv64"));
}

#[test]
fn windows_and_macos_are_skipped_with_a_reason() {
    for family in ["Windows", "Darwin"] {
        let error = release_pin(Some(family), Some("x86_64")).unwrap_err();
        assert!(
            matches!(&error, NoReleasePin::UnsupportedOs { family: reported } if reported == family),
            "{family}"
        );
        assert!(error.to_string().contains("only Linux is pinned"));
    }
}

#[test]
fn missing_facts_are_skipped_with_a_reason() {
    assert_eq!(
        release_pin(None, Some("x86_64")),
        Err(NoReleasePin::UnknownPlatform)
    );
    assert_eq!(
        release_pin(Some("Linux"), None),
        Err(NoReleasePin::UnknownPlatform)
    );
}

#[test]
fn a_hostile_fact_is_bounded_in_the_reason() {
    let hostile = format!("evil\n{}", "x".repeat(500));
    let error = release_pin(Some("Linux"), Some(&hostile)).unwrap_err();
    let NoReleasePin::UnsupportedArchitecture { architecture } = error else {
        panic!("expected an unsupported architecture");
    };
    assert!(architecture.len() <= 64);
    assert!(!architecture.contains('\n'));
}
