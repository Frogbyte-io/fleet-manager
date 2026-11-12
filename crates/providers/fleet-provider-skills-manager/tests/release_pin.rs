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
fn windows_x86_64_and_its_alias_pick_the_windows_x64_asset() {
    // The probe reports `Windows` and maps `AMD64` to `x86_64`; the alias
    // and the case of the family do not matter.
    for (family, arch) in [
        ("Windows", "x86_64"),
        ("windows", "amd64"),
        ("WINDOWS", "AMD64"),
    ] {
        let pin = release_pin(Some(family), Some(arch)).unwrap();
        assert_eq!(
            pin.asset, "skills-manager-cli-Windows-x64.exe",
            "{family} {arch}"
        );
        assert_eq!(pin.version, PINNED_CLI_VERSION);
        assert_eq!(
            pin.url,
            "https://github.com/xingkongliang/skills-manager/releases/download/v1.40.0/skills-manager-cli-Windows-x64.exe"
        );
        // The GitHub release API's digest for the v1.40.0 asset (ADR 0021).
        assert_eq!(
            pin.sha256,
            "03d8bf92f3bd4a70f9bcad2d908bf1c04d1e72deebf3e800b27e78dabb09e370"
        );
    }
}

#[test]
fn windows_arm64_is_skipped_as_an_unsupported_architecture() {
    // Upstream publishes no Windows arm64 asset; x64 emulation is not
    // attempted (ADR 0021 decision 5).
    for arch in ["aarch64", "arm64", "ARM64"] {
        let error = release_pin(Some("Windows"), Some(arch)).unwrap_err();
        assert_eq!(
            error,
            NoReleasePin::UnsupportedArchitecture {
                family: "Windows".to_owned(),
                architecture: arch.to_owned(),
            }
        );
        let reason = error.to_string();
        assert!(reason.contains("Windows"), "{reason}");
        assert!(
            reason.contains("the pinned Windows assets are x86_64"),
            "{reason}"
        );
    }
}

#[test]
fn every_pin_is_a_lowercase_sha256_over_https() {
    for (family, arch) in [
        ("Linux", "x86_64"),
        ("Linux", "aarch64"),
        ("Windows", "x86_64"),
    ] {
        let pin = release_pin(Some(family), Some(arch)).unwrap();
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
            family: "Linux".to_owned(),
            architecture: "riscv64".to_owned()
        }
    );
    assert!(error.to_string().contains("riscv64"));
    assert!(
        error
            .to_string()
            .contains("the pinned Linux assets are x86_64 and aarch64")
    );
}

#[test]
fn macos_and_other_families_are_skipped_with_a_reason() {
    for family in ["Darwin", "FreeBSD"] {
        let error = release_pin(Some(family), Some("x86_64")).unwrap_err();
        assert!(
            matches!(&error, NoReleasePin::UnsupportedOs { family: reported } if reported == family),
            "{family}"
        );
        assert!(
            error
                .to_string()
                .contains("only Linux and Windows are pinned")
        );
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
    let NoReleasePin::UnsupportedArchitecture { architecture, .. } = error else {
        panic!("expected an unsupported architecture");
    };
    assert!(architecture.len() <= 64);
    assert!(!architecture.contains('\n'));
}
