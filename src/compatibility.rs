//! Release-maintained support. Keep a generation only while its handlers exist.
use crate::{bad, ApiError, Result};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
// Short invitation/admission extensions are capability-gated; API 2 remains implemented.
pub const SERVER_PROTOCOLS: &[u32] = &[2];
const LEGACY_PEER_PROTOCOLS: &[u32] = &[1];
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClientCompatibility {
    pub app_version: String,
    pub server_protocols: Vec<u32>,
    pub peer_protocols: Vec<u32>,
}
fn generations(values: &[u32]) -> bool {
    !values.is_empty()
        && values.len() <= 8
        && values.iter().enumerate().all(|(index, value)| {
            *value > 0 && *value <= 1_000_000 && !values[..index].contains(value)
        })
}
fn incompatible(code: &'static str) -> ApiError {
    ApiError(StatusCode::CONFLICT, code)
}
fn common(a: &[u32], b: &[u32]) -> Option<u32> {
    a.iter().filter(|v| b.contains(v)).copied().max()
}
pub fn check_client(client: Option<&ClientCompatibility>) -> Result<u32> {
    if let Some(c) = client {
        if c.app_version.is_empty()
            || c.app_version.len() > 64
            || !c.app_version.as_bytes()[0].is_ascii_digit()
            || !c
                .app_version
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".+-".contains(&b))
            || !generations(&c.server_protocols)
            || !generations(&c.peer_protocols)
        {
            return Err(bad());
        }
    }
    common(
        SERVER_PROTOCOLS,
        client.map_or(&[2], |c| c.server_protocols.as_slice()),
    )
    .ok_or_else(|| incompatible("CLIENT_PROTOCOL_UNSUPPORTED"))
}
pub fn check_pair(
    host: Option<&ClientCompatibility>,
    guest: Option<&ClientCompatibility>,
) -> Result<(u32, u32)> {
    let server = check_client(guest)?;
    check_client(host).map_err(|_| incompatible("HOST_PROTOCOL_UNSUPPORTED"))?;
    let host = host.map_or(LEGACY_PEER_PROTOCOLS, |c| c.peer_protocols.as_slice());
    let guest = guest.map_or(LEGACY_PEER_PROTOCOLS, |c| c.peer_protocols.as_slice());
    let peer = common(host, guest).ok_or_else(|| incompatible("PEER_PROTOCOL_UNSUPPORTED"))?;
    Ok((server, peer))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn client() -> ClientCompatibility {
        ClientCompatibility {
            app_version: "0.5.0".into(),
            server_protocols: vec![2],
            peer_protocols: vec![1],
        }
    }
    #[test]
    fn malformed_and_removed_generations_are_rejected() {
        let mut c = client();
        c.server_protocols = vec![2, 2];
        assert!(check_client(Some(&c)).is_err());
        c = client();
        c.app_version = "<script>".into();
        assert!(check_client(Some(&c)).is_err());
        c = client();
        c.peer_protocols = vec![];
        assert!(check_client(Some(&c)).is_err());
        c = client();
        c.server_protocols = vec![3];
        assert_eq!(
            check_client(Some(&c)).unwrap_err().1,
            "CLIENT_PROTOCOL_UNSUPPORTED"
        );
        assert_eq!(check_pair(None, None).unwrap(), (2, 1));
        assert_eq!(
            check_pair(Some(&c), None).unwrap_err().1,
            "HOST_PROTOCOL_UNSUPPORTED"
        );
    }
}
