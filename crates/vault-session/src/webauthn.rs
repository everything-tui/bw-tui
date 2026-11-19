//! WebAuthn / FIDO2 two-factor (provider 7) support.
//!
//! # Status
//!
//! * **Always available (no feature flag):** parsing the server challenge
//!   ([`parse_request`]) and building the login token Bitwarden expects
//!   ([`assertion_token`]). This lets users complete 2FA by pasting an assertion
//!   produced by another tool.
//! * **`webauthn` feature:** CTAP-HID framing scaffolding ([`ctap`]). The
//!   authenticator conversation itself ([`perform_assertion`]) is **not
//!   implemented yet** and returns [`WebAuthnError::NotImplemented`].
//!
//! # Roadmap to a real implementation
//!
//! 1. Enumerate HID devices with usage page `0xF1D0` (e.g. the `hidapi` crate).
//! 2. `CTAPHID_INIT` to obtain a channel id ([`ctap::init_request`]).
//! 3. `authenticatorGetAssertion` (CTAP2 CBOR, command `0x02`) with
//!    `rpId`, `clientDataHash = SHA-256(client_data_json)` and `allowList`.
//! 4. Wrap the response with [`assertion_token`] and send it as `twoFactorToken`
//!    for provider 7.

use base64::Engine;
use serde_json::{json, Value};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum WebAuthnError {
    #[error("WebAuthn / FIDO2 hardware keys are not supported in this build")]
    Unsupported,
    #[error("WebAuthn authenticator support is not implemented yet: {0}")]
    NotImplemented(&'static str),
    #[error("invalid WebAuthn challenge: {0}")]
    InvalidChallenge(String),
}

/// Parsed `PublicKeyCredentialRequestOptions`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebAuthnRequest {
    /// base64url challenge as sent by the server.
    pub challenge: String,
    pub rp_id: Option<String>,
    /// base64url credential ids.
    pub allow_credentials: Vec<String>,
    pub timeout_ms: Option<u64>,
    pub user_verification: Option<String>,
}

/// Authenticator output (all values base64url without padding).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebAuthnAssertion {
    pub credential_id: String,
    pub authenticator_data: String,
    pub client_data_json: String,
    pub signature: String,
    pub user_handle: Option<String>,
}

/// True when this build can talk to a hardware authenticator.
pub fn is_supported() -> bool {
    // Hardware access is scaffolding only for now.
    false
}

pub fn parse_request(challenge: &Value) -> Result<WebAuthnRequest, WebAuthnError> {
    let obj = challenge
        .as_object()
        .ok_or_else(|| WebAuthnError::InvalidChallenge("not a JSON object".into()))?;
    let challenge_str = obj
        .get("challenge")
        .and_then(|v| v.as_str())
        .ok_or_else(|| WebAuthnError::InvalidChallenge("missing challenge".into()))?
        .to_string();
    let allow_credentials = obj
        .get("allowCredentials")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|c| c.get("id").and_then(|i| i.as_str()).map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    Ok(WebAuthnRequest {
        challenge: challenge_str,
        rp_id: obj.get("rpId").and_then(|v| v.as_str()).map(str::to_string),
        allow_credentials,
        timeout_ms: obj.get("timeout").and_then(|v| v.as_u64()),
        user_verification: obj
            .get("userVerification")
            .and_then(|v| v.as_str())
            .map(str::to_string),
    })
}

/// `clientDataJSON` for a `webauthn.get` ceremony.
pub fn client_data_json(challenge: &str, origin: &str) -> String {
    json!({
        "type": "webauthn.get",
        "challenge": challenge,
        "origin": origin,
        "crossOrigin": false,
    })
    .to_string()
}

/// JSON `twoFactorToken` for provider 7 (`PublicKeyCredential` as serialized by the web vault).
pub fn assertion_token(a: &WebAuthnAssertion) -> String {
    json!({
        "id": a.credential_id,
        "rawId": a.credential_id,
        "type": "public-key",
        "extensions": {},
        "response": {
            "authenticatorData": a.authenticator_data,
            "clientDataJson": a.client_data_json,
            "signature": a.signature,
            "userHandle": a.user_handle,
        }
    })
    .to_string()
}

/// Base64url (no padding) helper for callers assembling an assertion.
#[allow(dead_code)]
pub fn b64url(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Run `authenticatorGetAssertion` against a connected key. **Stub.**
pub fn perform_assertion(
    _request: &WebAuthnRequest,
    _origin: &str,
) -> Result<WebAuthnAssertion, WebAuthnError> {
    if cfg!(feature = "webauthn") {
        Err(WebAuthnError::NotImplemented(
            "CTAP2 transport (HID) is scaffolded but not wired to hardware",
        ))
    } else {
        Err(WebAuthnError::Unsupported)
    }
}

/// CTAP-HID framing scaffolding (feature `webauthn`).
#[cfg(feature = "webauthn")]
#[allow(dead_code)]
pub mod ctap {
    /// HID report size for FIDO devices.
    pub const HID_REPORT_SIZE: usize = 64;
    pub const BROADCAST_CID: u32 = 0xFFFF_FFFF;
    pub const CMD_INIT: u8 = 0x06;
    pub const CMD_CBOR: u8 = 0x10;
    pub const CMD_ERROR: u8 = 0x3F;

    /// Split `payload` into CTAPHID init + continuation packets.
    pub fn frame(cid: u32, cmd: u8, payload: &[u8]) -> Vec<[u8; HID_REPORT_SIZE]> {
        let mut packets = Vec::new();
        let mut init = [0u8; HID_REPORT_SIZE];
        init[..4].copy_from_slice(&cid.to_be_bytes());
        init[4] = 0x80 | cmd;
        init[5..7].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        let first = payload.len().min(HID_REPORT_SIZE - 7);
        init[7..7 + first].copy_from_slice(&payload[..first]);
        packets.push(init);
        let mut offset = first;
        let mut seq = 0u8;
        while offset < payload.len() {
            let mut cont = [0u8; HID_REPORT_SIZE];
            cont[..4].copy_from_slice(&cid.to_be_bytes());
            cont[4] = seq;
            let n = (payload.len() - offset).min(HID_REPORT_SIZE - 5);
            cont[5..5 + n].copy_from_slice(&payload[offset..offset + n]);
            packets.push(cont);
            offset += n;
            seq = seq.wrapping_add(1);
        }
        packets
    }

    /// `CTAPHID_INIT` request on the broadcast channel with an 8-byte nonce.
    pub fn init_request(nonce: [u8; 8]) -> Vec<[u8; HID_REPORT_SIZE]> {
        frame(BROADCAST_CID, CMD_INIT, &nonce)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn init_is_single_packet() {
            let p = init_request([1; 8]);
            assert_eq!(p.len(), 1);
            assert_eq!(&p[0][..4], &BROADCAST_CID.to_be_bytes());
            assert_eq!(p[0][4], 0x80 | CMD_INIT);
            assert_eq!(&p[0][5..7], &[0, 8]);
        }

        #[test]
        fn long_payload_uses_continuation() {
            let payload = vec![7u8; 150];
            let p = frame(1, CMD_CBOR, &payload);
            assert_eq!(p.len(), 3);
            assert_eq!(p[1][4], 0);
            assert_eq!(p[2][4], 1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_challenge() {
        let v = json!({
            "challenge": "abc",
            "rpId": "example.com",
            "timeout": 60000,
            "userVerification": "discouraged",
            "allowCredentials": [{"id": "cred1", "type": "public-key"}]
        });
        let r = parse_request(&v).unwrap();
        assert_eq!(r.challenge, "abc");
        assert_eq!(r.rp_id.as_deref(), Some("example.com"));
        assert_eq!(r.allow_credentials, vec!["cred1"]);
    }

    #[test]
    fn rejects_missing_challenge() {
        assert!(parse_request(&json!({})).is_err());
    }

    #[test]
    fn token_is_json_with_response() {
        let t = assertion_token(&WebAuthnAssertion {
            credential_id: "id".into(),
            authenticator_data: "ad".into(),
            client_data_json: "cd".into(),
            signature: "sig".into(),
            user_handle: None,
        });
        let v: Value = serde_json::from_str(&t).unwrap();
        assert_eq!(v["response"]["signature"], "sig");
        assert_eq!(v["type"], "public-key");
    }

    #[test]
    fn assertion_is_stubbed() {
        let req = WebAuthnRequest {
            challenge: "c".into(),
            rp_id: None,
            allow_credentials: vec![],
            timeout_ms: None,
            user_verification: None,
        };
        assert!(perform_assertion(&req, "https://x").is_err());
    }
}
