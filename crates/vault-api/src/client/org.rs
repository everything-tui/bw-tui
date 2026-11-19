//! Organization sharing, bulk cipher, archive and emergency-access endpoints.

use reqwest::header::AUTHORIZATION;
use serde::Serialize;

use super::VaultClient;
use crate::error::{ApiError, Result};
use crate::models::Cipher;
use crate::org_models::*;

/// HTTP statuses that mean "this verb/route is not available" (try the POST twin).
fn is_route_missing(status: u16) -> bool {
    matches!(status, 404 | 405)
}

/// True when an API error means the server has no such route (e.g. archive on Vaultwarden).
pub fn is_unsupported_route(err: &ApiError) -> bool {
    matches!(err, ApiError::Api { status, .. } if matches!(*status, 404 | 405 | 501))
}

impl VaultClient {
    // ── Single-cipher sharing / collections ─────────────────────────────────

    /// Share a personal cipher with an organization (`PUT /ciphers/{id}/share`).
    ///
    /// The cipher payload must already be encrypted for the organization key.
    pub async fn share_cipher(&self, id: &str, req: &CipherShareRequest) -> Result<Cipher> {
        let resp = self
            .http
            .put(self.api(&format!("/ciphers/{id}/share")))
            .header(AUTHORIZATION, self.bearer()?)
            .json(req)
            .send()
            .await?;
        self.json(resp).await
    }

    /// Share using a pre-built JSON body (cipher already re-encrypted).
    pub async fn share_cipher_json(&self, id: &str, body: &serde_json::Value) -> Result<Cipher> {
        let resp = self
            .http
            .put(self.api(&format!("/ciphers/{id}/share")))
            .header(AUTHORIZATION, self.bearer()?)
            .json(body)
            .send()
            .await?;
        self.json(resp).await
    }

    /// Create a cipher directly in an organization/collections (`POST /ciphers/create`).
    pub async fn create_cipher_with_collections(&self, req: &CipherShareRequest) -> Result<Cipher> {
        let resp = self
            .http
            .post(self.api("/ciphers/create"))
            .header(AUTHORIZATION, self.bearer()?)
            .json(req)
            .send()
            .await?;
        self.json(resp).await
    }

    /// Replace the collection set of an organization cipher (`PUT /ciphers/{id}/collections`).
    pub async fn update_cipher_collections(
        &self,
        id: &str,
        collection_ids: &[String],
    ) -> Result<()> {
        let body = CipherCollectionsRequest {
            collection_ids: collection_ids.to_vec(),
        };
        self.put_or_post_empty(&format!("/ciphers/{id}/collections"), &body)
            .await
    }

    // ── Bulk cipher operations ──────────────────────────────────────────────

    /// Soft-delete many ciphers (`PUT /ciphers/delete`).
    pub async fn bulk_soft_delete_ciphers(&self, ids: &[String]) -> Result<()> {
        self.put_or_post_empty("/ciphers/delete", &Self::ids_body(ids))
            .await
    }

    /// Permanently delete many ciphers (`DELETE /ciphers`).
    pub async fn bulk_delete_ciphers(&self, ids: &[String]) -> Result<()> {
        let resp = self
            .http
            .delete(self.api("/ciphers"))
            .header(AUTHORIZATION, self.bearer()?)
            .json(&Self::ids_body(ids))
            .send()
            .await?;
        if is_route_missing(resp.status().as_u16()) {
            // Some servers only expose the POST form.
            let resp = self
                .http
                .post(self.api("/ciphers/delete"))
                .header(AUTHORIZATION, self.bearer()?)
                .json(&Self::ids_body(ids))
                .send()
                .await?;
            return self.empty(resp).await;
        }
        self.empty(resp).await
    }

    /// Restore many ciphers from the trash (`PUT /ciphers/restore`).
    pub async fn bulk_restore_ciphers(&self, ids: &[String]) -> Result<()> {
        self.put_or_post_empty("/ciphers/restore", &Self::ids_body(ids))
            .await
    }

    /// Move many ciphers to a folder, or unfile them with `None` (`PUT /ciphers/move`).
    pub async fn bulk_move_ciphers(&self, ids: &[String], folder_id: Option<&str>) -> Result<()> {
        let body = CipherMoveRequest {
            ids: ids.to_vec(),
            folder_id: folder_id.map(str::to_string),
        };
        self.put_or_post_empty("/ciphers/move", &body).await
    }

    /// Share many personal ciphers with an organization (`PUT /ciphers/share`).
    pub async fn bulk_share_ciphers(&self, req: &CipherBulkShareRequest) -> Result<()> {
        self.put_or_post_empty("/ciphers/share", req).await
    }

    // ── Archive ─────────────────────────────────────────────────────────────

    /// Archive a cipher (`PUT /ciphers/{id}/archive`). Not all servers implement this.
    pub async fn archive_cipher(&self, id: &str) -> Result<()> {
        self.put_empty_no_body(&format!("/ciphers/{id}/archive"))
            .await
    }

    /// Unarchive a cipher (`PUT /ciphers/{id}/unarchive`).
    pub async fn unarchive_cipher(&self, id: &str) -> Result<()> {
        self.put_empty_no_body(&format!("/ciphers/{id}/unarchive"))
            .await
    }

    /// Archive many ciphers (`PUT /ciphers/archive`).
    pub async fn bulk_archive_ciphers(&self, ids: &[String]) -> Result<()> {
        self.put_or_post_empty("/ciphers/archive", &Self::ids_body(ids))
            .await
    }

    /// Unarchive many ciphers (`PUT /ciphers/unarchive`).
    pub async fn bulk_unarchive_ciphers(&self, ids: &[String]) -> Result<()> {
        self.put_or_post_empty("/ciphers/unarchive", &Self::ids_body(ids))
            .await
    }

    // ── Users ───────────────────────────────────────────────────────────────

    /// Fetch another user's RSA public key (`GET /users/{id}/public-key`).
    pub async fn get_user_public_key(&self, user_id: &str) -> Result<UserPublicKey> {
        let resp = self
            .http
            .get(self.api(&format!("/users/{user_id}/public-key")))
            .header(AUTHORIZATION, self.bearer()?)
            .send()
            .await?;
        self.json(resp).await
    }

    // ── Emergency access ────────────────────────────────────────────────────

    /// Contacts the current user has designated (`GET /emergency-access/trusted`).
    pub async fn list_emergency_trusted(&self) -> Result<Vec<EmergencyAccessEntry>> {
        let resp = self
            .http
            .get(self.api("/emergency-access/trusted"))
            .header(AUTHORIZATION, self.bearer()?)
            .send()
            .await?;
        let list: ListResponse<EmergencyAccessEntry> = self.json(resp).await?;
        Ok(list.data)
    }

    /// Accounts that granted the current user emergency access (`GET /emergency-access/granted`).
    pub async fn list_emergency_granted(&self) -> Result<Vec<EmergencyAccessEntry>> {
        let resp = self
            .http
            .get(self.api("/emergency-access/granted"))
            .header(AUTHORIZATION, self.bearer()?)
            .send()
            .await?;
        let list: ListResponse<EmergencyAccessEntry> = self.json(resp).await?;
        Ok(list.data)
    }

    /// Fetch one emergency-access record (`GET /emergency-access/{id}`).
    pub async fn get_emergency_access(&self, id: &str) -> Result<EmergencyAccessEntry> {
        let resp = self
            .http
            .get(self.api(&format!("/emergency-access/{id}")))
            .header(AUTHORIZATION, self.bearer()?)
            .send()
            .await?;
        self.json(resp).await
    }

    /// Invite a trusted contact (`POST /emergency-access/invite`).
    pub async fn invite_emergency_contact(
        &self,
        email: &str,
        access_type: EmergencyAccessType,
        wait_time_days: u32,
    ) -> Result<()> {
        let body = EmergencyAccessInviteRequest {
            email: email.to_string(),
            access_type: access_type.as_u8(),
            wait_time_days,
        };
        self.post_empty("/emergency-access/invite", &body).await
    }

    /// Change type / wait time (`PUT /emergency-access/{id}`).
    pub async fn update_emergency_access(
        &self,
        id: &str,
        req: &EmergencyAccessUpdateRequest,
    ) -> Result<()> {
        self.put_or_post_empty(&format!("/emergency-access/{id}"), req)
            .await
    }

    /// Remove a grant (`DELETE /emergency-access/{id}`).
    pub async fn delete_emergency_access(&self, id: &str) -> Result<()> {
        let resp = self
            .http
            .delete(self.api(&format!("/emergency-access/{id}")))
            .header(AUTHORIZATION, self.bearer()?)
            .send()
            .await?;
        self.empty(resp).await
    }

    /// Resend an invitation email (`POST /emergency-access/{id}/reinvite`).
    pub async fn reinvite_emergency_contact(&self, id: &str) -> Result<()> {
        self.post_empty_no_body(&format!("/emergency-access/{id}/reinvite"))
            .await
    }

    /// Accept an invitation with the emailed token (`POST /emergency-access/{id}/accept`).
    pub async fn accept_emergency_invite(&self, id: &str, token: &str) -> Result<()> {
        let body = EmergencyAccessAcceptRequest {
            token: token.to_string(),
        };
        self.post_empty(&format!("/emergency-access/{id}/accept"), &body)
            .await
    }

    /// Confirm an accepted contact by uploading the encrypted user key
    /// (`POST /emergency-access/{id}/confirm`).
    pub async fn confirm_emergency_contact(&self, id: &str, encrypted_key: &str) -> Result<()> {
        let body = EmergencyAccessConfirmRequest {
            key: encrypted_key.to_string(),
        };
        self.post_empty(&format!("/emergency-access/{id}/confirm"), &body)
            .await
    }

    /// Start recovery as a grantee (`POST /emergency-access/{id}/initiate`).
    pub async fn initiate_emergency_recovery(&self, id: &str) -> Result<()> {
        self.post_empty_no_body(&format!("/emergency-access/{id}/initiate"))
            .await
    }

    /// Approve a recovery request as grantor (`POST /emergency-access/{id}/approve`).
    pub async fn approve_emergency_recovery(&self, id: &str) -> Result<()> {
        self.post_empty_no_body(&format!("/emergency-access/{id}/approve"))
            .await
    }

    /// Reject a recovery request as grantor (`POST /emergency-access/{id}/reject`).
    pub async fn reject_emergency_recovery(&self, id: &str) -> Result<()> {
        self.post_empty_no_body(&format!("/emergency-access/{id}/reject"))
            .await
    }

    /// View the grantor's vault after approval (`POST /emergency-access/{id}/view`).
    pub async fn view_emergency_vault(&self, id: &str) -> Result<EmergencyAccessView> {
        let resp = self
            .http
            .post(self.api(&format!("/emergency-access/{id}/view")))
            .header(AUTHORIZATION, self.bearer()?)
            .send()
            .await?;
        self.json(resp).await
    }

    // ── helpers ─────────────────────────────────────────────────────────────

    fn ids_body(ids: &[String]) -> CipherIdsRequest {
        CipherIdsRequest {
            ids: ids.to_vec(),
            organization_id: None,
        }
    }

    /// `PUT path` with JSON; on 404/405 retry as `POST` (older Vaultwarden / proxies).
    async fn put_or_post_empty<B: Serialize + ?Sized>(&self, path: &str, body: &B) -> Result<()> {
        let resp = self
            .http
            .put(self.api(path))
            .header(AUTHORIZATION, self.bearer()?)
            .json(body)
            .send()
            .await?;
        if is_route_missing(resp.status().as_u16()) {
            let resp = self
                .http
                .post(self.api(path))
                .header(AUTHORIZATION, self.bearer()?)
                .json(body)
                .send()
                .await?;
            return self.empty(resp).await;
        }
        self.empty(resp).await
    }

    async fn put_empty_no_body(&self, path: &str) -> Result<()> {
        let resp = self
            .http
            .put(self.api(path))
            .header(AUTHORIZATION, self.bearer()?)
            .send()
            .await?;
        self.empty(resp).await
    }

    async fn post_empty<B: Serialize + ?Sized>(&self, path: &str, body: &B) -> Result<()> {
        let resp = self
            .http
            .post(self.api(path))
            .header(AUTHORIZATION, self.bearer()?)
            .json(body)
            .send()
            .await?;
        self.empty(resp).await
    }

    async fn post_empty_no_body(&self, path: &str) -> Result<()> {
        let resp = self
            .http
            .post(self.api(path))
            .header(AUTHORIZATION, self.bearer()?)
            .send()
            .await?;
        self.empty(resp).await
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::mpsc;

    use super::*;
    use crate::client::ClientConfig;
    use crate::models::CipherRequest;

    /// Serve one canned response per entry, forwarding `(request_line, body)` for each request.
    fn mock_server(
        responses: Vec<(u16, &'static str)>,
    ) -> (String, mpsc::Receiver<(String, String)>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            for (status, body) in responses {
                let (mut stream, _) = listener.accept().unwrap();
                let mut buf = Vec::new();
                let mut chunk = [0u8; 1024];
                let header_end = loop {
                    let n = stream.read(&mut chunk).unwrap();
                    buf.extend_from_slice(&chunk[..n]);
                    if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        break pos + 4;
                    }
                    if n == 0 {
                        break buf.len();
                    }
                };
                let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
                let content_len = head
                    .lines()
                    .find_map(|l| {
                        let l = l.to_ascii_lowercase();
                        l.strip_prefix("content-length:")
                            .and_then(|v| v.trim().parse::<usize>().ok())
                    })
                    .unwrap_or(0);
                while buf.len() < header_end + content_len {
                    let n = stream.read(&mut chunk).unwrap();
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                }
                let req_body = String::from_utf8_lossy(&buf[header_end..]).to_string();
                let request_line = head.lines().next().unwrap_or("").to_string();
                let _ = tx.send((request_line, req_body));
                let resp = format!(
                    "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(resp.as_bytes()).unwrap();
            }
        });
        (format!("http://{addr}"), rx)
    }

    fn client_for(url: &str) -> VaultClient {
        let mut c = VaultClient::new(ClientConfig::new_unchecked(url)).unwrap();
        c.set_tokens("tok".into(), None);
        c
    }

    #[tokio::test]
    async fn share_cipher_puts_to_share_endpoint() {
        let (url, rx) = mock_server(vec![(200, r#"{"id":"c1","type":1,"name":"n"}"#)]);
        let client = client_for(&url);
        let req = CipherShareRequest {
            cipher: CipherRequest {
                cipher_type: 1,
                name: "enc".into(),
                organization_id: Some("org1".into()),
                encrypted_for: "u".into(),
                ..Default::default()
            },
            collection_ids: vec!["col1".into()],
        };
        let cipher = client.share_cipher("c1", &req).await.unwrap();
        assert_eq!(cipher.id.as_deref(), Some("c1"));
        let (line, body) = rx.recv().unwrap();
        assert_eq!(line, "PUT /api/ciphers/c1/share HTTP/1.1");
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["collectionIds"][0], "col1");
        assert_eq!(v["cipher"]["organizationId"], "org1");
    }

    #[tokio::test]
    async fn bulk_move_falls_back_to_post_on_405() {
        let (url, rx) = mock_server(vec![(405, "no"), (200, "{}")]);
        let client = client_for(&url);
        client
            .bulk_move_ciphers(&["a".into(), "b".into()], Some("f1"))
            .await
            .unwrap();
        let (l1, _) = rx.recv().unwrap();
        let (l2, b2) = rx.recv().unwrap();
        assert_eq!(l1, "PUT /api/ciphers/move HTTP/1.1");
        assert_eq!(l2, "POST /api/ciphers/move HTTP/1.1");
        let v: serde_json::Value = serde_json::from_str(&b2).unwrap();
        assert_eq!(v["folderId"], "f1");
        assert_eq!(v["ids"].as_array().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn emergency_trusted_list_parses() {
        let body = r#"{"data":[{"id":"e1","status":0,"type":0,"waitTimeDays":3,"email":"x@y.z"}],"object":"list"}"#;
        let (url, rx) = mock_server(vec![(200, body)]);
        let client = client_for(&url);
        let list = client.list_emergency_trusted().await.unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].id, "e1");
        let (line, _) = rx.recv().unwrap();
        assert_eq!(line, "GET /api/emergency-access/trusted HTTP/1.1");
    }

    #[test]
    fn unsupported_route_detection() {
        assert!(is_unsupported_route(&ApiError::Api {
            status: 404,
            message: String::new()
        }));
        assert!(!is_unsupported_route(&ApiError::Api {
            status: 400,
            message: String::new()
        }));
    }
}
