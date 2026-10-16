//! Records scrubbed contract fixtures from a real Coolify instance.
//!
//! Ignored by default: it needs a live instance and a token with the `read`
//! ability only (do not use `read:sensitive`, `write`, `deploy`, or `root`).
//! The run is GET-only and the output is scrubbed (see `scrub.rs`): secrets
//! are dropped, names, hosts, addresses, and uuids become stable
//! pseudonyms, unknown strings become `[scrubbed]`, and the result is
//! refused if it still carries the token or a credential shape. Review the
//! files before committing them: the repository is public.
//!
//! ```text
//! FLEET_COOLIFY_BASE_URL=https://coolify.example.com \
//! FLEET_COOLIFY_TOKEN=... \
//! FLEET_COOLIFY_CAPTURE_DIR=crates/providers/fleet-provider-coolify/tests/fixtures/recorded \
//!   cargo test -p fleet-provider-coolify --test capture -- --ignored --nocapture
//! ```
//!
//! Put the version the instance reports in the directory name, then point
//! the contract tests at it.

#[tokio::test]
#[ignore = "needs a live Coolify instance and a read token"]
async fn capture_scrubbed_fixtures_from_a_live_instance() {
    let base = std::env::var("FLEET_COOLIFY_BASE_URL").expect("FLEET_COOLIFY_BASE_URL");
    let token = std::env::var("FLEET_COOLIFY_TOKEN").expect("FLEET_COOLIFY_TOKEN");
    let dir = std::env::var("FLEET_COOLIFY_CAPTURE_DIR").expect("FLEET_COOLIFY_CAPTURE_DIR");
    let files = fleet_provider_coolify::scrub::capture(base.trim_end_matches('/'), &token)
        .await
        .expect("capture");
    std::fs::create_dir_all(&dir).expect("create the capture directory");
    for (name, body) in files {
        let path = std::path::Path::new(&dir).join(&name);
        std::fs::write(&path, body).expect("write a fixture");
        println!("wrote {}", path.display());
    }
}
