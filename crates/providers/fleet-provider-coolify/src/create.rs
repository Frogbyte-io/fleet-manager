//! Creation calls over Coolify's REST API (FM-1035): a one-click service or
//! a public Git application.
//!
//! A separate client surface from read discovery ([`crate::discovery`],
//! GET-only), lifecycle, and settings; it shares their sender, so the same
//! rules hold: https only (a loopback address excepted), no redirects, a
//! bounded body, classified failures. The set of requests is closed: a
//! [`Route`] is a variant, and nothing is interpolated into a path.
//!
//! # Routes (coollabsio/coolify `routes/api.php`, v4.2.0 to v4.4.6)
//!
//! | call | request | ability |
//! | --- | --- | --- |
//! | list applications | `GET /applications` | `read` |
//! | list services | `GET /services` | `read` |
//! | create a one-click service | `POST /services` | `write` |
//! | create a public Git application | `POST /applications/public` | `write` |
//!
//! Both creations answer `201` with `{"uuid": ..., "domains": ...}`. Fleet
//! sends `instant_deploy: false`: the first deployment is a separate,
//! reported step. Private repositories (`/applications/private-github-app`,
//! `/applications/private-deploy-key`) and image applications are not used.
//! A creation body carries no secret (a template has none), so Coolify's own
//! validation message may be shown, scrubbed and bounded.

use std::time::Duration;

use async_trait::async_trait;
use fleet_application::coolify::lifecycle::{
    LifecycleFailure, LifecycleFailureClass, LifecycleResource,
};
use fleet_application::site_templates::{
    ApplicationCreate, CoolifyCreatePort, MarkedResource, ServiceCreate,
};
use fleet_core::SensitiveString;
use serde_json::{Map, Value, json};

use crate::REQUEST_TIMEOUT;
use crate::lifecycle::{Request, send_request};

/// The most bytes read from a list answer.
const LIST_BODY: usize = 8 * 1024 * 1024;
/// The most bytes read from a creation answer.
const CREATE_BODY: usize = 256 * 1024;
/// How long a creation may take.
const CREATE_TIMEOUT: Duration = Duration::from_secs(60);

/// The only requests this client sends.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Route {
    /// `GET /applications`.
    ListApplications,
    /// `GET /services`.
    ListServices,
    /// `POST /services`.
    CreateService,
    /// `POST /applications/public`.
    CreateApplication,
}

impl Route {
    /// The HTTP method.
    #[must_use]
    pub fn method(self) -> reqwest::Method {
        match self {
            Self::ListApplications | Self::ListServices => reqwest::Method::GET,
            Self::CreateService | Self::CreateApplication => reqwest::Method::POST,
        }
    }

    /// The request path.
    #[must_use]
    pub fn path(self) -> &'static str {
        match self {
            Self::ListApplications => "/api/v1/applications",
            Self::ListServices | Self::CreateService => "/api/v1/services",
            Self::CreateApplication => "/api/v1/applications/public",
        }
    }

    fn is_write(self) -> bool {
        matches!(self, Self::CreateService | Self::CreateApplication)
    }
}

/// The creation client over HTTP.
#[derive(Debug, Default)]
pub struct CoolifyHttpCreate;

async fn call(
    base_url: &str,
    token: &SensitiveString,
    route: Route,
    body: Option<String>,
) -> Result<String, LifecycleFailure> {
    send_request(
        base_url,
        token,
        &Request {
            method: route.method(),
            path: route.path().to_owned(),
            body,
            timeout: if route.is_write() {
                CREATE_TIMEOUT
            } else {
                REQUEST_TIMEOUT
            },
            needs: if route.is_write() {
                "creating a resource needs the write ability"
            } else {
                "reading resources needs the read ability"
            },
            quiet: false,
        },
        if route.is_write() {
            CREATE_BODY
        } else {
            LIST_BODY
        },
    )
    .await
}

fn json_of(text: &str) -> Result<Value, LifecycleFailure> {
    serde_json::from_str(text).map_err(|_| {
        LifecycleFailure::new(
            LifecycleFailureClass::Unavailable,
            "the answer is not the documented JSON",
        )
    })
}

fn safe_uuid(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= 64
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
}

/// The listed item whose `description` equals `marker`, with its name and
/// environment id so the caller can check it is the resource it expects.
fn find_marked(list: &Value, marker: &str) -> Option<MarkedResource> {
    let item = list
        .as_array()?
        .iter()
        .find(|item| item.get("description").and_then(Value::as_str) == Some(marker))?;
    let uuid = item.get("uuid")?.as_str().filter(|uuid| safe_uuid(uuid))?;
    Some(MarkedResource {
        uuid: uuid.to_owned(),
        name: item
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        environment_id: item.get("environment_id").and_then(Value::as_i64),
    })
}

fn uuid_of_creation(text: &str) -> Result<String, LifecycleFailure> {
    json_of(text)?
        .get("uuid")
        .and_then(Value::as_str)
        .filter(|uuid| safe_uuid(uuid))
        .map(str::to_owned)
        .ok_or_else(|| {
            LifecycleFailure::new(
                LifecycleFailureClass::Unavailable,
                "the answer carried no usable uuid",
            )
        })
}

fn service_body(create: &ServiceCreate) -> String {
    let mut body = Map::new();
    body.insert("type".to_owned(), json!(create.service_type));
    body.insert("name".to_owned(), json!(create.name));
    body.insert("description".to_owned(), json!(create.description));
    body.insert("project_uuid".to_owned(), json!(create.project_uuid));
    body.insert(
        "environment_name".to_owned(),
        json!(create.environment_name),
    );
    body.insert("server_uuid".to_owned(), json!(create.server_uuid));
    if let Some(destination) = &create.destination_uuid {
        body.insert("destination_uuid".to_owned(), json!(destination));
    }
    body.insert(
        "urls".to_owned(),
        json!([{ "name": create.url.0, "url": create.url.1 }]),
    );
    body.insert("instant_deploy".to_owned(), json!(false));
    Value::Object(body).to_string()
}

fn application_body(create: &ApplicationCreate) -> String {
    let mut body = Map::new();
    body.insert("git_repository".to_owned(), json!(create.git_repository));
    body.insert("git_branch".to_owned(), json!(create.git_branch));
    body.insert("build_pack".to_owned(), json!(create.build_pack));
    body.insert(
        "ports_exposes".to_owned(),
        json!(create.ports_exposes.to_string()),
    );
    body.insert("is_static".to_owned(), json!(create.is_static));
    body.insert("name".to_owned(), json!(create.name));
    body.insert("description".to_owned(), json!(create.description));
    body.insert("project_uuid".to_owned(), json!(create.project_uuid));
    body.insert(
        "environment_name".to_owned(),
        json!(create.environment_name),
    );
    body.insert("server_uuid".to_owned(), json!(create.server_uuid));
    if let Some(destination) = &create.destination_uuid {
        body.insert("destination_uuid".to_owned(), json!(destination));
    }
    body.insert("domains".to_owned(), json!(create.domain));
    body.insert("instant_deploy".to_owned(), json!(false));
    Value::Object(body).to_string()
}

#[async_trait]
impl CoolifyCreatePort for CoolifyHttpCreate {
    async fn find_by_marker(
        &self,
        base_url: &str,
        token: &SensitiveString,
        resource: LifecycleResource,
        marker: &str,
    ) -> Result<Option<MarkedResource>, LifecycleFailure> {
        let route = match resource {
            LifecycleResource::Application => Route::ListApplications,
            LifecycleResource::Service => Route::ListServices,
            LifecycleResource::Database => {
                return Err(LifecycleFailure::new(
                    LifecycleFailureClass::Invalid,
                    "a database is not a site",
                ));
            }
        };
        let text = call(base_url, token, route, None).await?;
        Ok(find_marked(&json_of(&text)?, marker))
    }

    async fn create_service(
        &self,
        base_url: &str,
        token: &SensitiveString,
        create: &ServiceCreate,
    ) -> Result<String, LifecycleFailure> {
        let text = call(
            base_url,
            token,
            Route::CreateService,
            Some(service_body(create)),
        )
        .await?;
        uuid_of_creation(&text)
    }

    async fn create_application(
        &self,
        base_url: &str,
        token: &SensitiveString,
        create: &ApplicationCreate,
    ) -> Result<String, LifecycleFailure> {
        let text = call(
            base_url,
            token,
            Route::CreateApplication,
            Some(application_body(create)),
        )
        .await?;
        uuid_of_creation(&text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_route_set_is_closed_and_fixed() {
        let all = [
            Route::ListApplications,
            Route::ListServices,
            Route::CreateService,
            Route::CreateApplication,
        ];
        let seen: Vec<(String, &str)> = all
            .iter()
            .map(|route| (route.method().to_string(), route.path()))
            .collect();
        assert_eq!(
            seen,
            [
                ("GET".to_owned(), "/api/v1/applications"),
                ("GET".to_owned(), "/api/v1/services"),
                ("POST".to_owned(), "/api/v1/services"),
                ("POST".to_owned(), "/api/v1/applications/public"),
            ]
        );
    }

    #[test]
    fn bodies_never_ask_for_an_instant_deploy_and_carry_the_marker() {
        let service = service_body(&ServiceCreate {
            service_type: "ghost".to_owned(),
            name: "blog".to_owned(),
            description: "fleet-deploy:abc".to_owned(),
            project_uuid: "p".to_owned(),
            environment_name: "production".to_owned(),
            server_uuid: "s".to_owned(),
            destination_uuid: None,
            url: ("ghost".to_owned(), "https://blog.example.test".to_owned()),
        });
        let value: Value = serde_json::from_str(&service).unwrap();
        assert_eq!(value["instant_deploy"], json!(false));
        assert_eq!(value["urls"][0]["name"], "ghost");
        assert_eq!(value["description"], "fleet-deploy:abc");
        assert!(value.get("destination_uuid").is_none());
        let app = application_body(&ApplicationCreate {
            git_repository: "https://example.test/o/r".to_owned(),
            git_branch: "main".to_owned(),
            build_pack: "nixpacks".to_owned(),
            ports_exposes: 3000,
            is_static: false,
            name: "site".to_owned(),
            description: "fleet-deploy:abc".to_owned(),
            project_uuid: "p".to_owned(),
            environment_name: "production".to_owned(),
            server_uuid: "s".to_owned(),
            destination_uuid: Some("d".to_owned()),
            domain: "https://site.example.test".to_owned(),
        });
        let value: Value = serde_json::from_str(&app).unwrap();
        assert_eq!(value["instant_deploy"], json!(false));
        assert_eq!(value["ports_exposes"], "3000");
        assert_eq!(value["domains"], "https://site.example.test");
        assert_eq!(value["destination_uuid"], "d");
    }

    #[test]
    fn a_marker_finds_exactly_one_resource() {
        let list = json!([
            {"uuid": "a1", "description": "something else"},
            {"uuid": "b2", "name": "site", "environment_id": 4, "description": "fleet-deploy:abc"},
            {"uuid": "c3", "description": null},
        ]);
        assert_eq!(
            find_marked(&list, "fleet-deploy:abc"),
            Some(MarkedResource {
                uuid: "b2".to_owned(),
                name: "site".to_owned(),
                environment_id: Some(4)
            })
        );
        assert_eq!(find_marked(&list, "fleet-deploy:zzz"), None);
        assert_eq!(find_marked(&json!({"message": "x"}), "m"), None);
    }

    #[test]
    fn a_creation_answer_needs_a_safe_uuid() {
        assert_eq!(
            uuid_of_creation(r#"{"uuid":"abc123","domains":""}"#).unwrap(),
            "abc123"
        );
        assert!(uuid_of_creation(r#"{"uuid":"../x"}"#).is_err());
        assert!(uuid_of_creation("not json").is_err());
    }
}
