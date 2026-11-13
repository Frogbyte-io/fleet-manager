use super::*;

#[test]
fn keys_lose_their_comments_and_anything_that_is_not_a_public_key() {
    let text = "ssh-ed25519 AAAAC3Nza host@example comment\n\
                    \n-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjE=\n\
                    ssh-ed25519 AAAAC3Nza again\n\
                    not-a-key AAAA\n\
                    ecdsa-sha2-nistp256 AAAAE2Vj\n\
                    no-blob-here\n";
    assert_eq!(
        normalize_public_keys(text),
        ["ssh-ed25519 AAAAC3Nza", "ecdsa-sha2-nistp256 AAAAE2Vj"]
    );
}

#[test]
fn the_fingerprint_is_the_unpadded_sha256_of_the_blob() {
    // "hello" as the blob: sha256 = LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ
    assert_eq!(
        fingerprint("ssh-ed25519 aGVsbG8="),
        "SHA256:LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ"
    );
}

#[tokio::test]
async fn an_explicit_file_is_the_only_source_and_more_than_four_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let one = dir.path().join("lab.pub");
    std::fs::write(&one, "ssh-ed25519 AAAAC3Nza lab@host\n").unwrap();
    assert_eq!(
        ControllerKeys::new(Some(one)).public_keys().await.unwrap(),
        ["ssh-ed25519 AAAAC3Nza"]
    );
    let many = dir.path().join("many.pub");
    let text = (0..5)
        .map(|n| format!("ssh-ed25519 AAAA{n}\n"))
        .collect::<String>();
    std::fs::write(&many, text).unwrap();
    let error = ControllerKeys::new(Some(many))
        .public_keys()
        .await
        .unwrap_err();
    assert_eq!(error.reason, "too_many_ssh_keys");
    assert!(error.detail.contains("FLEET_LAB_LOGIN_PUBLIC_KEY_FILE"));
    let empty = dir.path().join("empty.pub");
    std::fs::write(&empty, "-----BEGIN OPENSSH PRIVATE KEY-----\n").unwrap();
    let error = ControllerKeys::new(Some(empty))
        .public_keys()
        .await
        .unwrap_err();
    assert_eq!(error.reason, "no_ssh_key");
    let missing = ControllerKeys::new(Some(dir.path().join("absent.pub")))
        .public_keys()
        .await
        .unwrap_err();
    assert_eq!(missing.reason, "no_ssh_key");
}

#[tokio::test]
async fn describe_names_fingerprints_never_keys() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("lab.pub");
    std::fs::write(&file, "ssh-ed25519 aGVsbG8= secret-comment\n").unwrap();
    let line = ControllerKeys::new(Some(file)).describe().await;
    assert!(
        line.contains("1 key(s)") && line.contains("SHA256:LPJN"),
        "{line}"
    );
    assert!(!line.contains("aGVsbG8") && !line.contains("secret-comment"));
}
