//! Fleet-assigned build addresses (#337).
//!
//! During an image build the Proxmox builder's communicator dials whatever
//! address the build guest's QEMU agent reports, so a recipe, which controls
//! the guest, chooses where the controller connects. The structural fix is to
//! stop asking the guest: the operator names a pool of addresses, Fleet gives
//! each `proxmox-clone` build one, puts it into the guest through cloud-init
//! (`ipconfig`), and sets the communicator host to it itself in the copy it
//! writes for Packer (`ssh_host`, `winrm_host`). The plugin then skips the
//! guest-agent lookup altogether (`commHost` in
//! packer-plugin-proxmox v1.2.4 returns a configured host as a constant).
//!
//! This module holds the pure rules: the pool's validation, and the rewrite of
//! the recipe copy. Allocation (a transaction) lives behind the application's
//! `BuildAddressPort`.
//!
//! `proxmox-iso` builds cannot receive an address this way: an installer picks
//! its own. They stay under the documented residual risk, or are refused when
//! the operator asks for that.

use std::net::Ipv4Addr;

use serde_json::{Map, Value};

/// The largest pool accepted. Allocation scans the range inside a
/// transaction, so it stays small; a build needs one address.
pub const MAX_BUILD_ADDRESS_POOL_SIZE: u32 = 1024;
/// The most DNS servers accepted (Proxmox takes a few).
pub const MAX_BUILD_ADDRESS_DNS_SERVERS: usize = 3;

/// The build needs an address and the pool has none free.
pub const REASON_POOL_EXHAUSTED: &str = "build_address_pool_exhausted";
/// An ISO build is refused while a pool is configured and the operator asked
/// for that.
pub const REASON_ISO_REFUSED: &str = "build_address_iso_refused";
/// A builder is neither `proxmox-clone` nor `proxmox-iso`, so Fleet cannot say
/// whether it can take an address; refused while a pool is configured.
pub const REASON_BUILDER_UNSUPPORTED: &str = "build_address_builder_unsupported";
/// The allocation transaction failed.
pub const REASON_ALLOCATION_FAILED: &str = "build_address_allocation_failed";
/// The assignment's audit event could not be written.
pub const REASON_AUDIT_FAILED: &str = "build_address_audit_failed";

/// The stable build-time reasons of this module.
pub const BUILD_ADDRESS_REASONS: [&str; 5] = [
    REASON_POOL_EXHAUSTED,
    REASON_ISO_REFUSED,
    REASON_BUILDER_UNSUPPORTED,
    REASON_ALLOCATION_FAILED,
    REASON_AUDIT_FAILED,
];

/// A pool setting breaks a rule. Names the rule only, never the value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BuildAddressPoolError {
    /// The rule that failed.
    pub rule: &'static str,
}

impl std::fmt::Display for BuildAddressPoolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.rule)
    }
}

impl std::error::Error for BuildAddressPoolError {}

/// The operator's build address pool: an IPv4 network, the inclusive range
/// inside it Fleet may hand out, the gateway, and optional DNS servers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BuildAddressPool {
    network: u32,
    prefix: u8,
    first: u32,
    last: u32,
    gateway: Ipv4Addr,
    dns: Vec<Ipv4Addr>,
    refuse_iso: bool,
}

const fn err(rule: &'static str) -> BuildAddressPoolError {
    BuildAddressPoolError { rule }
}

/// Address blocks a build must never be pointed at, as inclusive ranges:
/// "this network", loopback, link-local (cloud metadata lives there),
/// multicast, and the reserved and broadcast space above it.
const FORBIDDEN_RANGES: [(u32, u32); 4] = [
    (0x0000_0000, 0x00ff_ffff),
    (0x7f00_0000, 0x7fff_ffff),
    (0xa9fe_0000, 0xa9fe_ffff),
    (0xe000_0000, 0xffff_ffff),
];

fn forbidden(first: u32, last: u32) -> bool {
    FORBIDDEN_RANGES
        .iter()
        .any(|&(low, high)| first <= high && last >= low)
}

fn parse_v4(text: &str, rule: &'static str) -> Result<u32, BuildAddressPoolError> {
    text.trim()
        .parse::<Ipv4Addr>()
        .map(u32::from)
        .map_err(|_| err(rule))
}

impl BuildAddressPool {
    /// Validates a pool.
    ///
    /// `cidr` is `a.b.c.d/len` with the network address exactly (no host
    /// bits), `len` from 8 to 30. `range` is `first-last`, inclusive, inside
    /// the network and not its network or broadcast address. `gateway` is
    /// inside the network and outside the range. `dns` is an optional list of
    /// IPv4 addresses separated by spaces or commas.
    ///
    /// # Errors
    /// Names the rule that failed, never the value.
    pub fn parse(
        cidr: &str,
        range: &str,
        gateway: &str,
        dns: Option<&str>,
        refuse_iso: bool,
    ) -> Result<Self, BuildAddressPoolError> {
        let (address, length) = cidr
            .trim()
            .split_once('/')
            .ok_or(err("the pool must be a CIDR such as a.b.c.d/24"))?;
        let address = parse_v4(address, "the pool network must be an IPv4 address")?;
        let prefix: u8 = length
            .parse()
            .map_err(|_| err("the pool prefix length must be a number"))?;
        if !(8..=30).contains(&prefix) {
            return Err(err("the pool prefix length must be from 8 to 30"));
        }
        let mask = u32::MAX << (32 - u32::from(prefix));
        if address & mask != address {
            return Err(err(
                "the pool CIDR must name the network address (no host bits set)",
            ));
        }
        let network = address;
        let broadcast = network | !mask;
        let (first, last) = range
            .trim()
            .split_once('-')
            .ok_or(err("the pool range must be first-last"))?;
        let first = parse_v4(first, "the pool range must hold IPv4 addresses")?;
        let last = parse_v4(last, "the pool range must hold IPv4 addresses")?;
        if first > last {
            return Err(err("the pool range must start at or below its end"));
        }
        if first <= network || last >= broadcast {
            return Err(err(
                "the pool range must lie inside the CIDR, excluding its network and broadcast addresses",
            ));
        }
        if last - first + 1 > MAX_BUILD_ADDRESS_POOL_SIZE {
            return Err(err("the pool range is too large (at most 1024 addresses)"));
        }
        if forbidden(network, broadcast) {
            return Err(err(
                "the pool must not be the unspecified, loopback, link-local, multicast, or reserved space",
            ));
        }
        let gateway_value = parse_v4(gateway, "the pool gateway must be an IPv4 address")?;
        if gateway_value & mask != network || gateway_value == network || gateway_value == broadcast
        {
            return Err(err(
                "the pool gateway must be a host address inside the CIDR",
            ));
        }
        if (first..=last).contains(&gateway_value) {
            return Err(err("the pool gateway must lie outside the pool range"));
        }
        let mut servers = Vec::new();
        if let Some(list) = dns {
            for item in list
                .split(|c: char| c == ',' || c.is_whitespace())
                .filter(|item| !item.is_empty())
            {
                let server = parse_v4(item, "the pool DNS servers must be IPv4 addresses")?;
                if forbidden(server, server) {
                    return Err(err(
                        "a pool DNS server must not be an unspecified, loopback, link-local, or multicast address",
                    ));
                }
                servers.push(Ipv4Addr::from(server));
            }
            if servers.len() > MAX_BUILD_ADDRESS_DNS_SERVERS {
                return Err(err("the pool takes at most 3 DNS servers"));
            }
        }
        Ok(Self {
            network,
            prefix,
            first,
            last,
            gateway: Ipv4Addr::from(gateway_value),
            dns: servers,
            refuse_iso,
        })
    }

    /// Every address Fleet may hand out, lowest first.
    pub fn candidates(&self) -> impl Iterator<Item = Ipv4Addr> + use<> {
        (self.first..=self.last).map(Ipv4Addr::from)
    }

    /// How many addresses the pool holds.
    #[must_use]
    pub const fn size(&self) -> u32 {
        self.last - self.first + 1
    }

    /// Whether the address is one the pool hands out.
    #[must_use]
    pub fn contains(&self, address: Ipv4Addr) -> bool {
        (self.first..=self.last).contains(&u32::from(address))
    }

    /// The gateway.
    #[must_use]
    pub const fn gateway(&self) -> Ipv4Addr {
        self.gateway
    }

    /// The prefix length.
    #[must_use]
    pub const fn prefix(&self) -> u8 {
        self.prefix
    }

    /// The DNS servers, possibly none.
    #[must_use]
    pub fn dns(&self) -> &[Ipv4Addr] {
        &self.dns
    }

    /// Whether `proxmox-iso` builds are refused while the pool is set.
    #[must_use]
    pub const fn refuses_iso(&self) -> bool {
        self.refuse_iso
    }

    /// The `network/len` text, for summaries.
    #[must_use]
    pub fn cidr(&self) -> String {
        format!("{}/{}", Ipv4Addr::from(self.network), self.prefix)
    }

    /// The inclusive `first-last` text, for summaries.
    #[must_use]
    pub fn range(&self) -> String {
        format!(
            "{}-{}",
            Ipv4Addr::from(self.first),
            Ipv4Addr::from(self.last)
        )
    }

    /// The `address/len` form the Proxmox API and Packer take.
    #[must_use]
    pub fn with_prefix(&self, address: Ipv4Addr) -> String {
        format!("{address}/{}", self.prefix)
    }
}

/// How the pool treats a builder.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BuilderKind {
    Clone,
    Iso,
}

fn builder_kind(builder: &Value) -> Result<BuilderKind, &'static str> {
    let Some(object) = builder.as_object() else {
        return Err(REASON_BUILDER_UNSUPPORTED);
    };
    // Any spelling of the key counts: only an exact, literal type is
    // classified, so a variant Packer might read differently is refused.
    let mut types = object
        .iter()
        .filter(|(key, _)| key.eq_ignore_ascii_case("type"));
    match (types.next(), types.next()) {
        (Some((key, Value::String(kind))), None) if key == "type" => match kind.as_str() {
            "proxmox-clone" => Ok(BuilderKind::Clone),
            "proxmox-iso" => Ok(BuilderKind::Iso),
            _ => Err(REASON_BUILDER_UNSUPPORTED),
        },
        _ => Err(REASON_BUILDER_UNSUPPORTED),
    }
}

fn builders(root: &Value) -> Result<&[Value], &'static str> {
    let Value::Object(object) = root else {
        return Err(REASON_BUILDER_UNSUPPORTED);
    };
    match object.get("builders") {
        None => Ok(&[]),
        Some(Value::Array(builders)) => Ok(builders),
        Some(_) => Err(REASON_BUILDER_UNSUPPORTED),
    }
}

/// How many addresses a build of this recipe needs: one per `proxmox-clone`
/// builder.
///
/// # Errors
/// [`REASON_BUILDER_UNSUPPORTED`] for a builder that is not literally
/// `proxmox-clone` or `proxmox-iso` (or for content that is not a JSON object
/// with a builder list), and [`REASON_ISO_REFUSED`] for a `proxmox-iso`
/// builder when the pool refuses them. An ISO builder is otherwise left alone.
pub fn build_addresses_needed(
    content: &str,
    pool: &BuildAddressPool,
) -> Result<usize, &'static str> {
    let root: Value = serde_json::from_str(content).map_err(|_| REASON_BUILDER_UNSUPPORTED)?;
    let mut needed = 0;
    for builder in builders(&root)? {
        match builder_kind(builder)? {
            BuilderKind::Clone => needed += 1,
            BuilderKind::Iso if pool.refuses_iso() => return Err(REASON_ISO_REFUSED),
            BuilderKind::Iso => {}
        }
    }
    Ok(needed)
}

/// Removes every key spelled like `name` in any letter case, so the keys
/// Fleet inserts are the only copy Packer's case-insensitive decoder sees.
fn remove_any_case(object: &mut Map<String, Value>, name: &str) {
    let keys: Vec<String> = object
        .keys()
        .filter(|key| key.eq_ignore_ascii_case(name))
        .cloned()
        .collect();
    for key in keys {
        object.remove(&key);
    }
}

/// The copy of the recipe Fleet writes for Packer when a pool is set: each
/// `proxmox-clone` builder, in order, gets the next address, with
/// - `ssh_host` and `winrm_host` set to it, so the communicator dials it and
///   never asks the guest agent;
/// - `ipconfig[0]` replaced by `{ip: address/len, gateway}`, so cloud-init
///   puts the guest there (other `ipconfig` entries are kept);
/// - `nameserver` set when the pool has DNS servers.
///
/// Any other spelling of those keys is removed first. The stored version, its
/// digest, and the build gate's input are not touched: the recipe still may
/// not set a host.
///
/// # Errors
/// The reasons of [`build_addresses_needed`] (with the pool's ISO setting),
/// or [`REASON_ALLOCATION_FAILED`] when `addresses` does not hold exactly one
/// address per clone builder, or one outside the pool.
pub fn with_build_addresses(
    content: &str,
    pool: &BuildAddressPool,
    addresses: &[Ipv4Addr],
) -> Result<String, &'static str> {
    let needed = build_addresses_needed(content, pool)?;
    if addresses.len() != needed || addresses.iter().any(|a| !pool.contains(*a)) {
        return Err(REASON_ALLOCATION_FAILED);
    }
    let mut root: Value = serde_json::from_str(content).map_err(|_| REASON_BUILDER_UNSUPPORTED)?;
    let mut next = addresses.iter();
    if let Some(Value::Array(builders)) = root.get_mut("builders") {
        for builder in builders {
            if builder_kind(builder)? != BuilderKind::Clone {
                continue;
            }
            let address = next.next().ok_or(REASON_ALLOCATION_FAILED)?;
            let Value::Object(object) = builder else {
                return Err(REASON_BUILDER_UNSUPPORTED);
            };
            let existing = object
                .iter()
                .find(|(key, _)| key.eq_ignore_ascii_case("ipconfig"))
                .map(|(_, value)| value.clone());
            for name in ["ssh_host", "winrm_host", "ipconfig"] {
                remove_any_case(object, name);
            }
            let mut ipconfig = match existing {
                Some(Value::Array(entries)) => entries,
                _ => Vec::new(),
            };
            let entry = serde_json::json!({
                "ip": pool.with_prefix(*address),
                "gateway": pool.gateway().to_string(),
            });
            if ipconfig.is_empty() {
                ipconfig.push(entry);
            } else {
                ipconfig[0] = entry;
            }
            object.insert("ipconfig".to_owned(), Value::Array(ipconfig));
            object.insert("ssh_host".to_owned(), Value::String(address.to_string()));
            object.insert("winrm_host".to_owned(), Value::String(address.to_string()));
            if !pool.dns().is_empty() {
                remove_any_case(object, "nameserver");
                let servers: Vec<String> = pool.dns().iter().map(ToString::to_string).collect();
                object.insert("nameserver".to_owned(), Value::String(servers.join(" ")));
            }
        }
    }
    serde_json::to_string(&root).map_err(|_| REASON_ALLOCATION_FAILED)
}

/// The operator-facing explanation of a build-time reason of this module.
#[must_use]
pub fn build_address_reason_message(reason: &str) -> &'static str {
    match reason {
        REASON_POOL_EXHAUSTED => {
            "every address in the build address pool is held by another running build; \
             retry when one finishes, or enlarge the pool"
        }
        REASON_ISO_REFUSED => {
            "a proxmox-iso builder cannot be given a Fleet-assigned address (an installer \
             picks its own), and the operator asked to refuse such builds while a build \
             address pool is set"
        }
        REASON_BUILDER_UNSUPPORTED => {
            "a build address pool is set, and the recipe has a builder that is not \
             literally proxmox-clone or proxmox-iso"
        }
        REASON_AUDIT_FAILED => "the address assignment could not be recorded in the audit log",
        _ => "the build address could not be allocated",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pool() -> BuildAddressPool {
        BuildAddressPool::parse(
            "192.0.2.0/24",
            "192.0.2.100-192.0.2.103",
            "192.0.2.1",
            Some("192.0.2.2, 192.0.2.3"),
            false,
        )
        .unwrap()
    }

    fn a(last: u8) -> Ipv4Addr {
        Ipv4Addr::new(192, 0, 2, last)
    }

    #[test]
    fn a_valid_pool_hands_out_its_range_in_order() {
        let pool = pool();
        assert_eq!(pool.size(), 4);
        assert_eq!(
            pool.candidates().collect::<Vec<_>>(),
            vec![a(100), a(101), a(102), a(103)]
        );
        assert!(pool.contains(a(103)) && !pool.contains(a(104)) && !pool.contains(a(99)));
        assert_eq!(pool.with_prefix(a(100)), "192.0.2.100/24");
        assert_eq!(pool.cidr(), "192.0.2.0/24");
        assert_eq!(pool.range(), "192.0.2.100-192.0.2.103");
        assert_eq!(pool.dns(), &[a(2), a(3)]);
    }

    #[test]
    fn invalid_pools_name_a_rule_and_never_the_value() {
        let cases = [
            ("192.0.2.0", "192.0.2.10-192.0.2.20", "192.0.2.1"),
            ("192.0.2.5/24", "192.0.2.10-192.0.2.20", "192.0.2.1"),
            ("192.0.2.0/31", "192.0.2.10-192.0.2.20", "192.0.2.1"),
            ("192.0.2.0/7", "192.0.2.10-192.0.2.20", "192.0.2.1"),
            ("2001:db8::/64", "192.0.2.10-192.0.2.20", "192.0.2.1"),
            ("192.0.2.0/24", "192.0.2.20-192.0.2.10", "192.0.2.1"),
            ("192.0.2.0/24", "192.0.2.0-192.0.2.20", "192.0.2.1"),
            ("192.0.2.0/24", "192.0.2.10-192.0.2.255", "192.0.2.1"),
            ("192.0.2.0/24", "192.0.3.10-192.0.3.20", "192.0.2.1"),
            ("192.0.2.0/24", "192.0.2.10-192.0.2.20", "192.0.2.15"),
            ("192.0.2.0/24", "192.0.2.10-192.0.2.20", "198.51.100.1"),
            ("192.0.2.0/24", "192.0.2.10-192.0.2.20", "192.0.2.255"),
            ("192.0.2.0/24", "192.0.2.10", "192.0.2.1"),
            ("10.0.0.0/8", "10.0.0.2-10.0.8.2", "10.0.0.1"),
            // Loopback, link-local, multicast, and "this network".
            ("127.0.0.0/8", "127.0.0.2-127.0.0.9", "127.0.0.1"),
            ("169.254.0.0/16", "169.254.1.2-169.254.1.9", "169.254.0.1"),
            ("224.0.0.0/8", "224.0.0.2-224.0.0.9", "224.0.0.1"),
            ("0.0.0.0/8", "0.0.0.2-0.0.0.9", "0.0.0.1"),
        ];
        for (cidr, range, gateway) in cases {
            let error = BuildAddressPool::parse(cidr, range, gateway, None, false)
                .expect_err(&format!("{cidr} {range} {gateway} must be refused"));
            let text = error.to_string();
            assert!(
                !text.contains("192.0.2") && !text.contains("127.0") && !text.contains("169.254"),
                "{text}"
            );
        }
        for dns in [
            "not-an-ip",
            "127.0.0.1",
            "2001:db8::1",
            "192.0.2.2 192.0.2.3 192.0.2.4 192.0.2.5",
        ] {
            assert!(
                BuildAddressPool::parse(
                    "192.0.2.0/24",
                    "192.0.2.10-192.0.2.20",
                    "192.0.2.1",
                    Some(dns),
                    false
                )
                .is_err(),
                "{dns}"
            );
        }
    }

    #[test]
    fn a_pool_that_straddles_link_local_space_is_refused() {
        // A /8 whose range reaches 169.254/16.
        assert!(
            BuildAddressPool::parse(
                "169.0.0.0/8",
                "169.254.1.2-169.254.1.9",
                "169.0.0.1",
                None,
                false
            )
            .is_err()
        );
    }

    #[test]
    fn a_blank_dns_list_means_none() {
        let pool = BuildAddressPool::parse(
            "192.0.2.0/24",
            "192.0.2.10-192.0.2.20",
            "192.0.2.1",
            Some("  "),
            false,
        )
        .unwrap();
        assert!(pool.dns().is_empty());
    }

    const RUNBOOK_LIKE: &str = r#"{"builders":[{"type":"proxmox-clone","node":"pve","clone_vm_id":9000,
        "network_adapters":[{"model":"virtio","bridge":"vmbr0"}],"ipconfig":[{"ip":"dhcp"}],
        "communicator":"ssh","ssh_username":"fleet"}],"provisioners":[{"type":"shell","inline":["true"]}]}"#;

    #[test]
    fn clone_builders_get_a_static_address_and_the_communicator_host() {
        let out = with_build_addresses(RUNBOOK_LIKE, &pool(), &[a(101)]).unwrap();
        let value: Value = serde_json::from_str(&out).unwrap();
        let builder = &value["builders"][0];
        assert_eq!(builder["ssh_host"], "192.0.2.101");
        assert_eq!(builder["winrm_host"], "192.0.2.101");
        assert_eq!(
            builder["ipconfig"],
            serde_json::json!([{ "ip": "192.0.2.101/24", "gateway": "192.0.2.1" }])
        );
        assert_eq!(builder["nameserver"], "192.0.2.2 192.0.2.3");
        // Everything else is untouched.
        assert_eq!(builder["clone_vm_id"], 9000);
        assert_eq!(value["provisioners"][0]["inline"][0], "true");
    }

    #[test]
    fn without_dns_the_recipes_own_nameserver_stays() {
        let pool = BuildAddressPool::parse(
            "192.0.2.0/24",
            "192.0.2.10-192.0.2.20",
            "192.0.2.1",
            None,
            false,
        )
        .unwrap();
        let content = r#"{"builders":[{"type":"proxmox-clone","nameserver":"192.0.2.9"}]}"#;
        let out = with_build_addresses(content, &pool, &[a(10)]).unwrap();
        let value: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(value["builders"][0]["nameserver"], "192.0.2.9");
    }

    #[test]
    fn case_variants_of_the_keys_fleet_sets_are_replaced_not_duplicated() {
        let content = r#"{"builders":[{"type":"proxmox-clone","IPCONFIG":"{{user `x`}}","NameServer":"192.0.2.9","Ssh_Host":"x"}]}"#;
        let out = with_build_addresses(content, &pool(), &[a(100)]).unwrap();
        let value: Value = serde_json::from_str(&out).unwrap();
        let keys: Vec<&String> = value["builders"][0].as_object().unwrap().keys().collect();
        for name in ["ipconfig", "nameserver", "ssh_host"] {
            assert_eq!(
                keys.iter().filter(|k| k.eq_ignore_ascii_case(name)).count(),
                1,
                "{name}: {keys:?}"
            );
        }
        assert_eq!(value["builders"][0]["ssh_host"], "192.0.2.100");
        assert_eq!(value["builders"][0]["nameserver"], "192.0.2.2 192.0.2.3");
    }

    #[test]
    fn only_the_first_nic_is_replaced_and_each_clone_builder_gets_its_own_address() {
        let content = r#"{"builders":[
            {"type":"proxmox-clone","ipconfig":[{"ip":"dhcp"},{"ip":"192.0.2.9/24"}]},
            {"type":"proxmox-clone"}]}"#;
        assert_eq!(build_addresses_needed(content, &pool()), Ok(2));
        let out = with_build_addresses(content, &pool(), &[a(100), a(102)]).unwrap();
        let value: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(value["builders"][0]["ipconfig"][0]["ip"], "192.0.2.100/24");
        assert_eq!(value["builders"][0]["ipconfig"][1]["ip"], "192.0.2.9/24");
        assert_eq!(value["builders"][1]["ssh_host"], "192.0.2.102");
    }

    #[test]
    fn iso_builders_are_left_alone_unless_the_pool_refuses_them() {
        let content = r#"{"builders":[{"type":"proxmox-iso","node":"pve"}]}"#;
        assert_eq!(build_addresses_needed(content, &pool()), Ok(0));
        let out = with_build_addresses(content, &pool(), &[]).unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&out).unwrap(),
            serde_json::from_str::<Value>(content).unwrap()
        );
        let strict = BuildAddressPool::parse(
            "192.0.2.0/24",
            "192.0.2.10-192.0.2.20",
            "192.0.2.1",
            None,
            true,
        )
        .unwrap();
        assert_eq!(
            build_addresses_needed(content, &strict),
            Err(REASON_ISO_REFUSED)
        );
    }

    #[test]
    fn a_builder_fleet_cannot_classify_is_refused() {
        for content in [
            r#"{"builders":[{"node":"pve"}]}"#,
            r#"{"builders":[{"type":"qemu"}]}"#,
            r#"{"builders":[{"type":"PROXMOX-CLONE"}]}"#,
            r#"{"builders":[{"Type":"proxmox-clone"}]}"#,
            r#"{"builders":[{"type":"{{user `t`}}"}]}"#,
            r#"{"builders":[{"type":7}]}"#,
            r#"{"builders":["proxmox-clone"]}"#,
            r#"{"builders":{"type":"proxmox-clone"}}"#,
            "[]",
            "not json",
        ] {
            assert_eq!(
                build_addresses_needed(content, &pool()),
                Err(REASON_BUILDER_UNSUPPORTED),
                "{content}"
            );
        }
        assert_eq!(build_addresses_needed(r#"{"builders":[]}"#, &pool()), Ok(0));
    }

    #[test]
    fn the_address_list_must_match_the_builders_and_the_pool() {
        for addresses in [vec![], vec![a(100), a(101)], vec![a(5)]] {
            assert_eq!(
                with_build_addresses(RUNBOOK_LIKE, &pool(), &addresses),
                Err(REASON_ALLOCATION_FAILED)
            );
        }
    }

    #[test]
    fn every_reason_has_a_message() {
        for reason in BUILD_ADDRESS_REASONS {
            assert!(!build_address_reason_message(reason).is_empty());
        }
    }
}
