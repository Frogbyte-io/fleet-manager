//! The Registry types Fleet ships (FM-1011, ADR 0016): `domain` and
//! `service`.
//!
//! Built-ins are versioned like built-in skills (ADR 0012): the definitions
//! below are the single source, [`BUILTIN_REGISTRY_TYPES_VERSION`] names
//! them, and a test pins their digest so a change forces a version bump.
//! They resolve without any file in the repository and a repository cannot
//! redefine them.

use serde_json::json;

use crate::{kinds::RegistryTypeSpec, registry::BuiltinRegistryType};

/// The version of the built-in Registry type definitions. Bump it whenever
/// a definition changes; the digest test in `tests/registry_builtin.rs`
/// fails until the pinned digest and this constant move together.
pub const BUILTIN_REGISTRY_TYPES_VERSION: u32 = 1;

fn spec(value: serde_json::Value) -> RegistryTypeSpec {
    serde_json::from_value(value).expect("a built-in Registry type definition must be valid")
}

/// The built-in types, in a stable order.
///
/// # Panics
///
/// Panics only if a built-in definition in this file is malformed.
#[must_use]
pub fn builtin_registry_types() -> Vec<BuiltinRegistryType> {
    let login = "Where the login lives, for example 1Password (Webhuset vault). Never the credential itself.";
    vec![
        BuiltinRegistryType {
            name: "domain".to_owned(),
            spec: spec(json!({
                "displayName": "Domain",
                "key": "fqdn",
                "fields": {
                    "fqdn": {"type": "hostname", "required": true, "description": "The fully qualified domain name."},
                    "registrar": {
                        "type": "enum",
                        "suggestions": ["Hostinger", "Webhuset", "Porkbun", "GoDaddy", "Cloudflare", "Namecheap"],
                        "description": "Where the domain is registered."
                    },
                    "registrarAccount": {"type": "string", "description": "The registrar account name or label, not its credential."},
                    "dnsHost": {"type": "string", "description": "Who serves the zone."},
                    "nameservers": {"type": "list", "items": "hostname", "description": "The delegated nameservers."},
                    "expires": {"type": "date", "description": "When the registration expires."},
                    "autoRenew": {"type": "boolean", "description": "Whether the registrar renews it automatically."},
                    "loginAt": {"type": "string", "description": login}
                },
                "relations": ["resolves-to", "hosted-on", "used-by", "depends-on"]
            })),
        },
        BuiltinRegistryType {
            name: "service".to_owned(),
            spec: spec(json!({
                "displayName": "Service",
                "key": "slug",
                "fields": {
                    "slug": {"type": "string", "required": true, "description": "A short stable identifier."},
                    "name": {"type": "string", "required": true, "description": "The service's display name."},
                    "vendor": {"type": "string", "description": "Who provides it."},
                    "purpose": {"type": "text", "description": "What the service is used for."},
                    "plan": {"type": "string", "description": "The subscription plan or tier."},
                    "cost": {"type": "money", "description": "The cost per billing period, as `<amount> <ISO 4217 code>`."},
                    "billingPeriod": {
                        "type": "enum",
                        "suggestions": ["monthly", "yearly", "other"],
                        "description": "How often the cost recurs."
                    },
                    "billingOwner": {"type": "string", "description": "Who pays for it."},
                    "renewal": {"type": "date", "description": "The next renewal date."},
                    "hostingProvider": {"type": "string", "description": "Where the service runs, if self-hosted."},
                    "region": {"type": "string", "description": "The region or location."},
                    "loginAt": {"type": "string", "description": login},
                    "url": {"type": "url", "description": "The service's address."}
                },
                "relations": ["used-by", "hosted-on", "depends-on", "serves"]
            })),
        },
    ]
}
