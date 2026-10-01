//! The harness's own PVE access, separate from Fleet: it tags scratch
//! guests, reads PVE's task records as independent evidence, and destroys
//! leftovers (Fleet has no destroy operation). It speaks through the
//! provider's pinned-fingerprint transport with the target's admin token,
//! and every mutating call checks the VMID range first.

use std::sync::Arc;
use std::time::{Duration, Instant};

use fleet_core::SensitiveString;
use fleet_provider_proxmox::{
    PveCredentials, PveHttpMethod, PveHttpRequest, PveTransport as _, ReqwestPveTransport,
};
use serde_json::{Value, json};

use super::config::{Target, VmidRange};

/// One guest from `/cluster/resources?type=vm`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VmResource {
    /// The VMID.
    pub vmid: u32,
    /// The hosting node.
    pub node: String,
    /// `qemu` or `lxc`.
    pub kind: String,
    /// The display name, when set.
    pub name: Option<String>,
    /// The tags, split.
    pub tags: Vec<String>,
    /// Whether it is a template.
    pub template: bool,
    /// The config lock (`clone`, `backup`, ...), when held.
    pub lock: Option<String>,
    /// `running`, `stopped`, ...
    pub status: Option<String>,
}

impl VmResource {
    /// Parses one resource entry; entries without a VMID or node are not
    /// guests the suite can act on.
    #[must_use]
    pub fn parse(entry: &Value) -> Option<Self> {
        let vmid = u32::try_from(entry.get("vmid")?.as_u64()?).ok()?;
        let node = entry.get("node")?.as_str()?.to_owned();
        let text = |key: &str| {
            entry
                .get(key)
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
        };
        Some(Self {
            vmid,
            node,
            kind: text("type").unwrap_or_else(|| "qemu".to_owned()),
            name: text("name"),
            tags: text("tags")
                .map(|tags| split_tags(&tags))
                .unwrap_or_default(),
            template: entry
                .get("template")
                .is_some_and(|value| value.as_u64() == Some(1) || value.as_bool() == Some(true)),
            lock: text("lock"),
            status: text("status"),
        })
    }
}

/// PVE stores tags `;`-separated but accepts `,` and spaces on input.
#[must_use]
pub fn split_tags(raw: &str) -> Vec<String> {
    raw.split([';', ',', ' '])
        .map(str::trim)
        .filter(|tag| !tag.is_empty())
        .map(str::to_lowercase)
        .collect()
}

/// A finished PVE task.
#[derive(Clone, Debug)]
pub struct TaskEnd {
    /// PVE's `exitstatus` (`OK`, or the error text).
    pub exitstatus: String,
}

/// The harness's privileged PVE client for one target.
pub struct PveAdmin {
    host: String,
    port: u16,
    fingerprint: String,
    credentials: Arc<PveCredentials>,
    range: VmidRange,
    transport: ReqwestPveTransport,
}

impl std::fmt::Debug for PveAdmin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PveAdmin")
            .field("range", &self.range)
            .finish_non_exhaustive()
    }
}

/// Percent-encodes one path or query component.
#[must_use]
pub fn encode(component: &str) -> String {
    percent_encoding::utf8_percent_encode(component, percent_encoding::NON_ALPHANUMERIC).to_string()
}

impl PveAdmin {
    /// The client for one target's admin token.
    #[must_use]
    pub fn new(target: &Target) -> Self {
        Self {
            host: target.host.clone(),
            port: target.port,
            fingerprint: target.fingerprint.clone(),
            credentials: Arc::new(PveCredentials {
                token_id: target.token.id.clone(),
                token: SensitiveString::new(target.token.secret.expose().to_owned()),
            }),
            range: target.range,
            transport: ReqwestPveTransport::new(),
        }
    }

    /// The range every mutation is checked against.
    #[must_use]
    pub fn range(&self) -> VmidRange {
        self.range
    }

    fn request(&self, method: PveHttpMethod, path: &str) -> PveHttpRequest {
        PveHttpRequest {
            host: self.host.clone(),
            port: self.port,
            path: format!("/api2/json{path}"),
            pinned_fingerprint: Some(self.fingerprint.clone()),
            credentials: self.credentials.clone(),
            method,
        }
    }

    async fn call(
        &self,
        method: PveHttpMethod,
        path: &str,
        body: Option<Value>,
    ) -> Result<Value, String> {
        let request = self.request(method, path);
        let response = match body {
            Some(body) => {
                self.transport
                    .execute_with_body(request, body.to_string().into_bytes())
                    .await
            }
            None => self.transport.execute(request).await,
        }
        .map_err(|error| format!("{method:?} {path}: {error}"))?;
        let text = String::from_utf8_lossy(&response.body);
        if !(200..300).contains(&response.status) {
            let bounded: String = text.chars().take(300).collect();
            return Err(format!(
                "{method:?} {path}: HTTP {} {bounded}",
                response.status
            ));
        }
        let value: Value = serde_json::from_str(&text)
            .map_err(|error| format!("{method:?} {path}: the answer is not JSON: {error}"))?;
        Ok(value.get("data").cloned().unwrap_or(Value::Null))
    }

    /// A read.
    ///
    /// # Errors
    ///
    /// Transport, HTTP, or payload failures.
    pub async fn get(&self, path: &str) -> Result<Value, String> {
        self.call(PveHttpMethod::Get, path, None).await
    }

    /// Every guest in the cluster.
    ///
    /// # Errors
    ///
    /// Transport, HTTP, or payload failures.
    pub async fn resources(&self) -> Result<Vec<VmResource>, String> {
        let data = self.get("/cluster/resources?type=vm").await?;
        Ok(data
            .as_array()
            .map(|entries| entries.iter().filter_map(VmResource::parse).collect())
            .unwrap_or_default())
    }

    /// One guest, when it exists.
    ///
    /// # Errors
    ///
    /// Transport, HTTP, or payload failures.
    pub async fn resource(&self, vmid: u32) -> Result<Option<VmResource>, String> {
        Ok(self
            .resources()
            .await?
            .into_iter()
            .find(|resource| resource.vmid == vmid))
    }

    /// Polls one task until it stops or the bound passes.
    ///
    /// # Errors
    ///
    /// Read failures, a malformed UPID, or the bound passing.
    pub async fn wait_task(&self, upid: &str, bound: Duration) -> Result<TaskEnd, String> {
        let node = upid
            .split(':')
            .nth(1)
            .filter(|node| !node.is_empty())
            .ok_or_else(|| "the UPID names no node".to_owned())?;
        let path = format!("/nodes/{}/tasks/{}/status", encode(node), encode(upid));
        let started = Instant::now();
        loop {
            let status = self.get(&path).await?;
            if status.get("status").and_then(Value::as_str) == Some("stopped") {
                return Ok(TaskEnd {
                    exitstatus: status
                        .get("exitstatus")
                        .and_then(Value::as_str)
                        .unwrap_or("unknown")
                        .to_owned(),
                });
            }
            if started.elapsed() > bound {
                return Err(format!("the task did not stop within {}s", bound.as_secs()));
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }

    /// Whether one task is still running right now.
    ///
    /// # Errors
    ///
    /// Read failures or a malformed UPID.
    pub async fn task_running(&self, upid: &str) -> Result<bool, String> {
        let node = upid
            .split(':')
            .nth(1)
            .ok_or_else(|| "the UPID names no node".to_owned())?;
        let status = self
            .get(&format!(
                "/nodes/{}/tasks/{}/status",
                encode(node),
                encode(upid)
            ))
            .await?;
        Ok(status.get("status").and_then(Value::as_str) == Some("running"))
    }

    /// PVE's own task records for one guest and task type, newest first.
    ///
    /// # Errors
    ///
    /// Read failures.
    pub async fn tasks(&self, node: &str, vmid: u32, kind: &str) -> Result<Vec<Value>, String> {
        let data = self
            .get(&format!(
                "/nodes/{}/tasks?vmid={vmid}&typefilter={}&limit=50&source=all",
                encode(node),
                encode(kind)
            ))
            .await?;
        Ok(data.as_array().cloned().unwrap_or_default())
    }

    /// The guest's current power state.
    ///
    /// # Errors
    ///
    /// Read failures.
    pub async fn power_state(&self, node: &str, vmid: u32) -> Result<String, String> {
        let status = self
            .get(&format!(
                "/nodes/{}/qemu/{vmid}/status/current",
                encode(node)
            ))
            .await?;
        Ok(status
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_owned())
    }

    /// The guest's snapshot names (without PVE's `current` pseudo-entry).
    ///
    /// # Errors
    ///
    /// Read failures.
    pub async fn snapshots(&self, node: &str, vmid: u32) -> Result<Vec<String>, String> {
        let data = self
            .get(&format!("/nodes/{}/qemu/{vmid}/snapshot", encode(node)))
            .await?;
        Ok(data
            .as_array()
            .map(|entries| {
                entries
                    .iter()
                    .filter_map(|entry| entry.get("name").and_then(Value::as_str))
                    .filter(|name| *name != "current")
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default())
    }

    /// Whether the guest agent answers a ping.
    pub async fn agent_ping(&self, node: &str, vmid: u32) -> bool {
        self.call(
            PveHttpMethod::Post,
            &format!("/nodes/{}/qemu/{vmid}/agent/ping", encode(node)),
            Some(json!({})),
        )
        .await
        .is_ok()
    }

    /// Tags one scratch guest `fleet-acceptance`.
    ///
    /// # Errors
    ///
    /// The range refusal, or the update failing.
    pub async fn tag(&self, node: &str, vmid: u32, tag: &str) -> Result<(), String> {
        let vmid = self.range.check(vmid)?;
        let answer = self
            .call(
                PveHttpMethod::Post,
                &format!("/nodes/{}/qemu/{vmid}/config", encode(node)),
                Some(json!({ "tags": tag })),
            )
            .await?;
        if let Some(upid) = answer.as_str() {
            let end = self.wait_task(upid, Duration::from_secs(120)).await?;
            if end.exitstatus != "OK" {
                return Err(format!("tagging VMID {vmid} ended {}", end.exitstatus));
            }
        }
        Ok(())
    }

    /// Stops (if needed) and destroys one guest the sweep classified as the
    /// suite's own. The range is re-checked here, so no caller can bypass it.
    ///
    /// # Errors
    ///
    /// The range refusal, or a stop/destroy failure.
    pub async fn destroy(&self, resource: &VmResource) -> Result<(), String> {
        let vmid = self.range.check(resource.vmid)?;
        let node = encode(&resource.node);
        let kind = if resource.kind == "lxc" {
            "lxc"
        } else {
            "qemu"
        };
        // A guest under a config lock (a clone still copying) cannot be
        // destroyed yet: wait for the lock to clear.
        let started = Instant::now();
        let mut current = resource.clone();
        while current.lock.is_some() {
            if started.elapsed() > Duration::from_secs(900) {
                return Err(format!(
                    "VMID {vmid} stayed locked ({}) for 15 minutes",
                    current.lock.unwrap_or_default()
                ));
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
            match self.resource(vmid).await? {
                Some(next) => current = next,
                None => return Ok(()),
            }
        }
        if current.status.as_deref() == Some("running") {
            let answer = self
                .call(
                    PveHttpMethod::Post,
                    &format!("/nodes/{node}/{kind}/{vmid}/status/stop"),
                    Some(json!({})),
                )
                .await?;
            if let Some(upid) = answer.as_str() {
                self.wait_task(upid, Duration::from_secs(180)).await?;
            }
        }
        let answer = self
            .call(
                PveHttpMethod::Delete,
                &format!("/nodes/{node}/{kind}/{vmid}?purge=1&destroy-unreferenced-disks=1"),
                None,
            )
            .await?;
        if let Some(upid) = answer.as_str() {
            let end = self.wait_task(upid, Duration::from_secs(600)).await?;
            if end.exitstatus != "OK" {
                return Err(format!("destroying VMID {vmid} ended {}", end.exitstatus));
            }
        }
        Ok(())
    }
}
