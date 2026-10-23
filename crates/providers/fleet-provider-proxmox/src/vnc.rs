//! The PVE VNC console channel (FM-495).
//!
//! `POST /nodes/{node}/qemu/{vmid}/vncproxy` (with `websocket=1` and
//! `generate-password=1`) opens a one-shot VNC listener on the node and
//! answers a port, a ticket, and an eight-character password. The WebSocket
//! `GET .../vncwebsocket?port=&vncticket=` then reaches that listener; the
//! API token authenticates the upgrade and the ticket binds it to the port
//! (live spike, PVE 8.4 and 9.2: both are required, `VM.Console` on
//! `/vms/{vmid}` is the only privilege).
//!
//! The channel returned here has already completed the RFB version and VNC
//! authentication exchange with PVE, using the one-time password. Whoever
//! holds it speaks plain RFB from `ClientInit` onward and never sees the
//! API token, the ticket, or the password. The WebSocket reuses the same
//! pinned-fingerprint TLS policy as every other call.

use std::fmt;
use std::time::Duration;

use async_trait::async_trait;
use fleet_core::SensitiveString;

use crate::{
    ProxmoxClient, PveApiError, PveHttpMethod, PveHttpRequest, PveTransportError, urlencode,
};

/// The largest WebSocket message the channel accepts. Real traffic is far
/// smaller: noVNC negotiates compressed encodings, and a viewer asks for
/// incremental updates.
pub const MAX_MESSAGE_BYTES: usize = 8 * 1024 * 1024;

/// How long the RFB version and authentication exchange may take.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// The `vncproxy` answer. Every field is secret-bearing except the port;
/// the type is deliberately not `Clone` and redacts in `Debug`.
pub struct PveVncProxy {
    /// The node-local TCP port of the one-shot listener.
    pub port: u16,
    /// The ticket that binds the WebSocket to the port.
    pub ticket: SensitiveString,
    /// The one-time VNC password (eight characters).
    pub password: SensitiveString,
}

impl fmt::Debug for PveVncProxy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PveVncProxy")
            .field("port", &self.port)
            .field("ticket", &"<redacted>")
            .field("password", &"<redacted>")
            .finish()
    }
}

/// A binary message stream to one PVE WebSocket. The real implementation is
/// the pinned TLS WebSocket; tests implement it in memory.
#[async_trait]
pub trait PveSocket: fmt::Debug + Send {
    /// The next binary message, or `None` once the peer closed. Cancel-safe:
    /// a dropped call loses no message.
    ///
    /// # Errors
    ///
    /// Fails on a transport error or an oversized message.
    async fn recv(&mut self) -> Result<Option<Vec<u8>>, PveTransportError>;

    /// Sends one binary message.
    ///
    /// # Errors
    ///
    /// Fails when the peer is gone.
    async fn send(&mut self, data: Vec<u8>) -> Result<(), PveTransportError>;

    /// Closes the socket, best effort.
    async fn close(&mut self);
}

/// A socket that replays bytes read past the handshake before reading on.
#[derive(Debug)]
struct Prebuffered {
    pending: Option<Vec<u8>>,
    inner: Box<dyn PveSocket>,
}

#[async_trait]
impl PveSocket for Prebuffered {
    async fn recv(&mut self) -> Result<Option<Vec<u8>>, PveTransportError> {
        if let Some(pending) = self.pending.take() {
            return Ok(Some(pending));
        }
        self.inner.recv().await
    }

    async fn send(&mut self, data: Vec<u8>) -> Result<(), PveTransportError> {
        self.inner.send(data).await
    }

    async fn close(&mut self) {
        self.inner.close().await;
    }
}

/// The pinned WebSocket over TLS.
pub(crate) struct TlsSocket {
    pub(crate) inner:
        tokio_tungstenite::WebSocketStream<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>,
}

impl fmt::Debug for TlsSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TlsSocket")
    }
}

fn socket_error(error: &tokio_tungstenite::tungstenite::Error) -> PveTransportError {
    // The error text of the websocket library can echo the request URL
    // (which carries the ticket) for malformed requests; only the
    // variant's kind is reported.
    let kind = match error {
        tokio_tungstenite::tungstenite::Error::ConnectionClosed
        | tokio_tungstenite::tungstenite::Error::AlreadyClosed => "the socket is closed",
        tokio_tungstenite::tungstenite::Error::Io(_) => "an I/O error ended the socket",
        tokio_tungstenite::tungstenite::Error::Capacity(_) => "a message exceeded the bound",
        tokio_tungstenite::tungstenite::Error::Protocol(_) => "a WebSocket protocol error",
        _ => "the WebSocket failed",
    };
    PveTransportError::Connect {
        detail: kind.to_owned(),
    }
}

#[async_trait]
impl PveSocket for TlsSocket {
    async fn recv(&mut self) -> Result<Option<Vec<u8>>, PveTransportError> {
        use futures_util::StreamExt as _;
        use tokio_tungstenite::tungstenite::Message;
        loop {
            match self.inner.next().await {
                None
                | Some(
                    Ok(Message::Close(_))
                    | Err(
                        tokio_tungstenite::tungstenite::Error::ConnectionClosed
                        | tokio_tungstenite::tungstenite::Error::AlreadyClosed,
                    ),
                ) => return Ok(None),
                Some(Ok(Message::Binary(bytes))) => return Ok(Some(bytes.to_vec())),
                // Control frames are answered by the library on the next
                // read/write; text frames are not part of the RFB stream.
                Some(Ok(_)) => {}
                Some(Err(error)) => return Err(socket_error(&error)),
            }
        }
    }

    async fn send(&mut self, data: Vec<u8>) -> Result<(), PveTransportError> {
        use futures_util::SinkExt as _;
        self.inner
            .send(tokio_tungstenite::tungstenite::Message::Binary(data.into()))
            .await
            .map_err(|error| socket_error(&error))
    }

    async fn close(&mut self) {
        let _ = self.inner.close(None).await;
    }
}

/// Reads exactly `count` bytes, pulling messages as needed and keeping any
/// surplus in `buffer`.
async fn read_exact(
    socket: &mut dyn PveSocket,
    buffer: &mut Vec<u8>,
    count: usize,
) -> Result<Vec<u8>, PveApiError> {
    while buffer.len() < count {
        match socket.recv().await.map_err(PveApiError::Transport)? {
            Some(bytes) => buffer.extend_from_slice(&bytes),
            None => {
                return Err(PveApiError::InvalidPayload {
                    detail: "PVE closed the console during the VNC handshake".to_owned(),
                });
            }
        }
    }
    let rest = buffer.split_off(count);
    Ok(std::mem::replace(buffer, rest))
}

/// The VNC authentication response: the challenge DES-encrypted with the
/// password as the key. RFC 6143 section 7.2.2: the key is the first eight
/// password bytes, zero padded, with the bits of every byte reversed.
#[must_use]
// The `des` 0.8 block API is expressed in `generic_array` 0.14 types, which
// that crate deprecates in favor of 1.x; there is no non-deprecated spelling
// until `des` moves.
#[allow(deprecated)]
pub fn vnc_auth_response(password: &str, challenge: &[u8; 16]) -> [u8; 16] {
    use des::Des;
    use des::cipher::generic_array::GenericArray;
    use des::cipher::{BlockEncrypt as _, KeyInit as _};

    let mut key = [0_u8; 8];
    for (slot, byte) in key.iter_mut().zip(password.bytes()) {
        *slot = byte.reverse_bits();
    }
    let cipher = Des::new(GenericArray::from_slice(&key));
    let mut response = *challenge;
    // Two 8-byte blocks, ECB.
    let (first, second) = response.split_at_mut(8);
    cipher.encrypt_block(GenericArray::from_mut_slice(first));
    cipher.encrypt_block(GenericArray::from_mut_slice(second));
    response
}

/// Runs the RFB 3.8 version and VNC-authentication exchange against PVE.
async fn authenticate(
    socket: &mut dyn PveSocket,
    password: &SensitiveString,
) -> Result<Vec<u8>, PveApiError> {
    let invalid = |detail: &str| PveApiError::InvalidPayload {
        detail: detail.to_owned(),
    };
    let mut buffer = Vec::new();
    let version = read_exact(socket, &mut buffer, 12).await?;
    let minor = std::str::from_utf8(&version)
        .ok()
        .and_then(|text| text.strip_prefix("RFB 003."))
        .and_then(|text| text.trim_end().parse::<u32>().ok())
        .ok_or_else(|| invalid("PVE did not answer with an RFB version"))?;
    if minor < 7 {
        return Err(invalid("PVE offered an RFB version older than 3.7"));
    }
    // RFB 3.7 and 3.8 share the security-type negotiation; 3.8 only adds a
    // reason string on failure. Answer with 3.8.
    socket
        .send(b"RFB 003.008\n".to_vec())
        .await
        .map_err(PveApiError::Transport)?;
    let count = read_exact(socket, &mut buffer, 1).await?[0];
    if count == 0 {
        return Err(invalid("PVE refused the VNC connection"));
    }
    let types = read_exact(socket, &mut buffer, usize::from(count)).await?;
    if !types.contains(&2) {
        return Err(invalid("PVE did not offer VNC authentication"));
    }
    socket.send(vec![2]).await.map_err(PveApiError::Transport)?;
    let challenge: [u8; 16] = read_exact(socket, &mut buffer, 16)
        .await?
        .try_into()
        .map_err(|_| invalid("the VNC challenge was not 16 bytes"))?;
    socket
        .send(vnc_auth_response(password.expose(), &challenge).to_vec())
        .await
        .map_err(PveApiError::Transport)?;
    let result = read_exact(socket, &mut buffer, 4).await?;
    if result != [0, 0, 0, 0] {
        return Err(invalid("PVE refused the one-time VNC password"));
    }
    Ok(buffer)
}

impl ProxmoxClient {
    /// Opens the VNC proxy for one QEMU guest: the `vncproxy` call, the
    /// pinned WebSocket, and the VNC authentication, in that order and
    /// back to back (the PVE listener is one-shot and short-lived).
    /// Requires `VM.Console` on the guest; a refusal is
    /// [`PveApiError::Forbidden`] carrying PVE's own words.
    ///
    /// # Errors
    ///
    /// Fails with [`PveApiError`] on auth, privilege, HTTP, payload,
    /// handshake, or transport failures.
    pub async fn vnc_connect(
        &self,
        request: PveHttpRequest,
        node: &str,
        vmid: u32,
    ) -> Result<Box<dyn PveSocket>, PveApiError> {
        let proxy_path = format!("/api2/json/nodes/{}/qemu/{vmid}/vncproxy", urlencode(node));
        let data = self
            .call_with_body(
                request.clone(),
                &proxy_path,
                &serde_json::json!({"websocket": 1, "generate-password": 1}),
            )
            .await?;
        let proxy = parse_vnc_proxy(&data)?;
        let socket_request = PveHttpRequest {
            path: format!(
                "/api2/json/nodes/{}/qemu/{vmid}/vncwebsocket?port={}&vncticket={}",
                urlencode(node),
                proxy.port,
                urlencode(proxy.ticket.expose())
            ),
            method: PveHttpMethod::Get,
            ..request
        };
        let mut socket = self
            .transport
            .connect_websocket(socket_request)
            .await
            .map_err(|error| match error {
                PveTransportError::UpgradeRefused { status: 401 } => PveApiError::Auth,
                PveTransportError::UpgradeRefused { status: 403 } => PveApiError::Forbidden {
                    detail: format!("the VNC WebSocket was refused for /vms/{vmid} (VM.Console)"),
                },
                PveTransportError::UpgradeRefused { status } => PveApiError::Http {
                    status,
                    detail: "the VNC WebSocket upgrade was refused".to_owned(),
                },
                other => PveApiError::Transport(other),
            })?;
        let leftover = match tokio::time::timeout(
            HANDSHAKE_TIMEOUT,
            authenticate(&mut *socket, &proxy.password),
        )
        .await
        {
            Ok(Ok(leftover)) => leftover,
            Ok(Err(error)) => {
                socket.close().await;
                return Err(error);
            }
            Err(_) => {
                socket.close().await;
                return Err(PveApiError::InvalidPayload {
                    detail: "the VNC handshake timed out".to_owned(),
                });
            }
        };
        Ok(Box::new(Prebuffered {
            pending: (!leftover.is_empty()).then_some(leftover),
            inner: socket,
        }))
    }
}

/// Parses the `vncproxy` answer, tolerating a numeric or stringly port.
fn parse_vnc_proxy(data: &serde_json::Value) -> Result<PveVncProxy, PveApiError> {
    let invalid = |detail: &str| PveApiError::InvalidPayload {
        detail: detail.to_owned(),
    };
    let port = data
        .get("port")
        .and_then(|value| {
            value
                .as_u64()
                .or_else(|| value.as_str().and_then(|text| text.parse().ok()))
        })
        .and_then(|port| u16::try_from(port).ok())
        .ok_or_else(|| invalid("the vncproxy answer has no usable port"))?;
    let text = |key: &str| {
        data.get(key)
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.is_empty() && value.len() <= 1024)
            .map(|value| SensitiveString::new(value.to_owned()))
    };
    let ticket = text("ticket").ok_or_else(|| invalid("the vncproxy answer has no ticket"))?;
    let password = text("password").ok_or_else(|| {
        invalid("the vncproxy answer has no one-time password; the PVE version cannot generate one")
    })?;
    Ok(PveVncProxy {
        port,
        ticket,
        password,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_des_response_matches_the_rfc_6143_construction() {
        // Known answer: password "password", challenge of sixteen zero
        // bytes. DES with the bit-reversed key, ECB, two blocks.
        let response = vnc_auth_response("password", &[0; 16]);
        assert_eq!(response[..8], response[8..], "equal blocks, equal output");
        assert_ne!(response, [0; 16]);
        // The password is truncated to eight bytes and zero padded.
        assert_eq!(
            vnc_auth_response("password-and-more", &[7; 16]),
            vnc_auth_response("password", &[7; 16])
        );
        assert_ne!(
            vnc_auth_response("passwore", &[7; 16]),
            vnc_auth_response("password", &[7; 16])
        );
    }

    #[test]
    fn the_vncproxy_answer_parses_and_redacts() {
        let proxy = parse_vnc_proxy(&serde_json::json!({
            "port": "5900", "ticket": "PVEVNC:abc::def", "password": "abcd1234",
            "cert": "-----BEGIN CERTIFICATE-----", "user": "u@pve!t", "upid": "UPID:x"
        }))
        .unwrap();
        assert_eq!(proxy.port, 5900);
        let shown = format!("{proxy:?}");
        assert!(!shown.contains("abcd1234") && !shown.contains("PVEVNC"));
        assert!(parse_vnc_proxy(&serde_json::json!({"port": 5900, "ticket": "t"})).is_err());
        assert!(parse_vnc_proxy(&serde_json::json!({"ticket": "t", "password": "p"})).is_err());
    }
}
