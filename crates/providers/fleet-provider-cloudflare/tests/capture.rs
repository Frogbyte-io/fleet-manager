//! Records scrubbed contract fixtures from a real Cloudflare account.
//!
//! Ignored by default: it needs a live token. Use a token with `Zone:Read`
//! and `DNS:Read` only (never `DNS:Edit`); the run is GET-only. The output
//! is scrubbed: ids, zone and record names, and addresses become stable
//! pseudonyms, free text becomes `[scrubbed]`, and the run is refused if
//! the output still contains the token. Review the files before committing:
//! the repository is public.
//!
//! ```text
//! FLEET_CLOUDFLARE_TOKEN=... \
//! FLEET_CLOUDFLARE_CAPTURE_DIR=crates/providers/fleet-provider-cloudflare/tests/fixtures/recorded \
//!   cargo test -p fleet-provider-cloudflare --test capture -- --ignored --nocapture
//! ```

use std::collections::BTreeMap;

use serde_json::{Value, json};

/// Pseudonyms for strings, stable within one run.
#[derive(Default)]
struct Pseudonyms {
    seen: BTreeMap<String, String>,
}

impl Pseudonyms {
    fn name(&mut self, kind: &str, real: &str) -> String {
        let next = self.seen.len() + 1;
        self.seen
            .entry(format!("{kind}:{real}"))
            .or_insert_with(|| format!("{kind}-{next:04}"))
            .clone()
    }
}

fn scrub_value(pseudonyms: &mut Pseudonyms, key: &str, value: &Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(k, v)| (k.clone(), scrub_value(pseudonyms, k, v)))
                .collect(),
        ),
        Value::Array(items) => Value::Array(
            items
                .iter()
                .map(|v| scrub_value(pseudonyms, key, v))
                .collect(),
        ),
        Value::String(text) => match key {
            "id" | "zone_id" => json!(pseudonyms.name("id", text)),
            "name" | "zone_name" => {
                json!(format!("{}.example.invalid", pseudonyms.name("host", text)))
            }
            "type" | "status" | "created_on" | "modified_on" => json!(text),
            // Contents, comments, account names, name servers, and the rest.
            _ => json!("[scrubbed]"),
        },
        other => other.clone(),
    }
}

async fn get(client: &reqwest::Client, token: &str, path: &str) -> Value {
    let response = client
        .get(format!("https://api.cloudflare.com/client/v4{path}"))
        .bearer_auth(token)
        .send()
        .await
        .expect("request");
    serde_json::from_str(&response.text().await.expect("body")).expect("json")
}

#[tokio::test]
#[ignore = "needs a live Cloudflare token with read access"]
async fn capture_scrubbed_fixtures_from_a_live_account() {
    let token = std::env::var("FLEET_CLOUDFLARE_TOKEN").expect("FLEET_CLOUDFLARE_TOKEN");
    let dir = std::env::var("FLEET_CLOUDFLARE_CAPTURE_DIR").expect("FLEET_CLOUDFLARE_CAPTURE_DIR");
    let client = reqwest::Client::new();
    let mut pseudonyms = Pseudonyms::default();
    let zones = get(&client, &token, "/zones?per_page=5").await;
    let mut files = vec![(
        "zones.json".to_owned(),
        scrub_value(&mut pseudonyms, "", &zones),
    )];
    if let Some(zone_id) = zones["result"][0]["id"].as_str() {
        let records = get(
            &client,
            &token,
            &format!("/zones/{zone_id}/dns_records?per_page=20"),
        )
        .await;
        files.push((
            "records.json".to_owned(),
            scrub_value(&mut pseudonyms, "", &records),
        ));
    }
    std::fs::create_dir_all(&dir).expect("create the capture directory");
    for (name, body) in files {
        let text = serde_json::to_string_pretty(&body).expect("serialize");
        assert!(!text.contains(&token), "{name} still contains the token");
        let path = std::path::Path::new(&dir).join(&name);
        std::fs::write(&path, text).expect("write a fixture");
        println!("wrote {}", path.display());
    }
}
