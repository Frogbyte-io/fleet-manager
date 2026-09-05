//! A minimal JSON-over-HTTP POST client for the node surface.
//!
//! `fleetd` talks to exactly four HTTP endpoints (enroll, challenge,
//! session, and the WebSocket upgrade), all JSON-in/JSON-out with no
//! redirects, cookies, or compression. A general HTTP client would be
//! weight without benefit; these are the documented, bounded requests the
//! enrollment contract (`proto/README.md`) describes.

use std::io::{Read as _, Write as _};
use std::net::TcpStream;
use std::time::Duration;

/// A parsed controller base URL: host and port only (plain HTTP; TLS
/// termination is the deployment's reverse proxy in trusted-LAN mode).
#[derive(Clone, Debug)]
pub struct Controller {
    host: String,
    port: u16,
}
impl Controller {
    /// Parses a base URL like `http://host:8080`, `https://host`, or
    /// `host:8080`. Schemes other than http are rejected: the trusted-LAN
    /// controller does not terminate TLS itself.
    ///
    /// # Errors
    ///
    /// Fails on a URL this client cannot speak.
    pub fn parse(base: &str) -> Result<Self, String> {
        let without_scheme = base
            .strip_prefix("http://")
            .ok_or_else(|| format!("the controller base must be an http:// URL, not {base:?}"))?;
        let without_scheme = without_scheme.trim_end_matches('/');
        let (host, port) = without_scheme
            .rsplit_once(':')
            .ok_or_else(|| format!("the controller base must include a port, not {base:?}"))?;
        if host.is_empty() || host.contains('/') {
            return Err(format!("the controller base host is malformed: {base:?}"));
        }
        let port = port
            .parse()
            .map_err(|_| format!("the controller base port is not a number: {base:?}"))?;
        Ok(Self {
            host: host.to_owned(),
            port,
        })
    }

    /// The WebSocket URL of the gateway route.
    #[must_use]
    pub fn gateway_url(&self) -> String {
        format!("ws://{}:{}/api/node/v1/connect", self.host, self.port)
    }

    /// A raw connection for surfaces beyond `post_json` (the daemon's own
    /// unprivileged GET for the local status surface).
    ///
    /// # Errors
    ///
    /// Fails on transport errors.
    pub fn connect_raw(&self) -> Result<TcpStream, String> {
        self.connect()
    }

    /// The base URL this controller was parsed from.
    #[must_use]
    pub fn base_url(&self) -> String {
        format!("http://{}:{}", self.host, self.port)
    }

    /// The host this controller was parsed from.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The port this controller was parsed from.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.port
    }

    fn connect(&self) -> Result<TcpStream, String> {
        TcpStream::connect((self.host.as_str(), self.port))
            .map_err(|error| format!("cannot reach {}:{}: {error}", self.host, self.port))
    }

    /// POSTs a JSON body and returns `(status, body)` on any answer.
    ///
    /// # Errors
    ///
    /// Fails on transport errors; HTTP statuses are answers, not errors.
    pub fn post_json(
        &self,
        path: &str,
        body: &serde_json::Value,
        timeout: Duration,
    ) -> Result<(u16, serde_json::Value), String> {
        let payload = serde_json::to_string(body).map_err(|error| error.to_string())?;
        let mut stream = self.connect()?;
        stream
            .set_read_timeout(Some(timeout))
            .map_err(|error| format!("cannot set the read timeout: {error}"))?;
        stream
            .set_write_timeout(Some(timeout))
            .map_err(|error| format!("cannot set the write timeout: {error}"))?;
        let request = format!(
            "POST {path} HTTP/1.1\r\nHost: {}:{}\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{payload}",
            self.host,
            self.port,
            payload.len()
        );
        stream
            .write_all(request.as_bytes())
            .map_err(|error| format!("the request failed: {error}"))?;
        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .map_err(|error| format!("the response failed: {error}"))?;
        parse_response(&response)
    }
}

/// Splits an HTTP response into its status and JSON body.
fn parse_response(raw: &[u8]) -> Result<(u16, serde_json::Value), String> {
    let text = String::from_utf8_lossy(raw);
    let (head, body) = text
        .split_once("\r\n\r\n")
        .ok_or_else(|| "the response has no body separator".to_owned())?;
    let status: u16 = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .ok_or_else(|| "the response has no status line".to_owned())?;
    let body = body.trim();
    let json = if body.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_str(body).map_err(|error| format!("the response is not JSON: {error}"))?
    };
    Ok((status, json))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_controller_base_parses_and_builds_the_gateway_url() {
        let controller = Controller::parse("http://127.0.0.1:8080/").unwrap();
        assert_eq!(
            controller.gateway_url(),
            "ws://127.0.0.1:8080/api/node/v1/connect"
        );
        assert!(Controller::parse("https://fleet.example.com").is_err());
        assert!(Controller::parse("no-scheme").is_err());
        assert!(Controller::parse("http://no-port").is_err());
    }
}
