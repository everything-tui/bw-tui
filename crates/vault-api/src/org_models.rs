//! Organization sharing, bulk cipher operations, archive and emergency-access models.

use serde::{Deserialize, Serialize};

use crate::models::CipherRequest;

/// Attachment metadata re-encrypted for a new owner key (`attachments2` on share).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AttachmentRekey {
    pub file_name: String,
    pub key: String,
}

/// Body for `PUT /ciphers/{id}/share` and `POST /ciphers/create` (org / collection create).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CipherShareRequest {
    pub cipher: CipherRequest,
    pub collection_ids: Vec<String>,
}

/// One cipher inside a bulk share request (`PUT /ciphers/share`): cipher payload plus its id.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BulkShareCipher {
    pub id: String,
    #[serde(flatten)]
    pub cipher: CipherRequest,
}

/// Body for `PUT /ciphers/share`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CipherBulkShareRequest {
    pub ciphers: Vec<BulkShareCipher>,
    pub collection_ids: Vec<String>,
}

/// Body for `PUT /ciphers/{id}/collections`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CipherCollectionsRequest {
    pub collection_ids: Vec<String>,
}

/// Body for bulk delete / restore / archive: `{ "ids": [...] }`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CipherIdsRequest {
    pub ids: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization_id: Option<String>,
}

/// Body for `PUT /ciphers/move`. `folder_id: None` serializes as `null` (unfile).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CipherMoveRequest {
    pub ids: Vec<String>,
    pub folder_id: Option<String>,
}

/// Response of `GET /users/{id}/public-key`.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserPublicKey {
    #[serde(default)]
    pub user_id: Option<String>,
    /// Base64 SPKI DER.
    pub public_key: String,
}

/// Generic `{ "data": [...], "object": "list" }` envelope.
#[derive(Debug, Clone, Deserialize)]
pub struct ListResponse<T> {
    #[serde(default = "Vec::new")]
    pub data: Vec<T>,
}

/// Emergency-access grant type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmergencyAccessType {
    /// Grantee may view the vault.
    View,
    /// Grantee may take over the account (reset master password).
    Takeover,
}

impl EmergencyAccessType {
    pub fn as_u8(self) -> u8 {
        match self {
            Self::View => 0,
            Self::Takeover => 1,
        }
    }

    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::View),
            1 => Some(Self::Takeover),
            _ => None,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::View => "View",
            Self::Takeover => "Takeover",
        }
    }
}

/// Emergency-access lifecycle status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmergencyAccessStatus {
    Invited,
    Accepted,
    Confirmed,
    RecoveryInitiated,
    RecoveryApproved,
}

impl EmergencyAccessStatus {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Invited),
            1 => Some(Self::Accepted),
            2 => Some(Self::Confirmed),
            3 => Some(Self::RecoveryInitiated),
            4 => Some(Self::RecoveryApproved),
            _ => None,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Invited => "Invited",
            Self::Accepted => "Accepted",
            Self::Confirmed => "Confirmed",
            Self::RecoveryInitiated => "Recovery initiated",
            Self::RecoveryApproved => "Recovery approved",
        }
    }
}

/// One row from `GET /emergency-access/trusted` or `/granted`.
///
/// For *trusted* contacts, `grantee_id` / `email` describe the contact.
/// For *granted* access, `grantor_id` / `email` describe the account owner.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EmergencyAccessEntry {
    pub id: String,
    #[serde(default)]
    pub status: u8,
    #[serde(default, rename = "type")]
    pub access_type: u8,
    #[serde(default)]
    pub wait_time_days: u32,
    #[serde(default)]
    pub grantee_id: Option<String>,
    #[serde(default)]
    pub grantor_id: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub creation_date: Option<String>,
    #[serde(default)]
    pub revision_date: Option<String>,
}

impl EmergencyAccessEntry {
    pub fn status_kind(&self) -> Option<EmergencyAccessStatus> {
        EmergencyAccessStatus::from_u8(self.status)
    }

    pub fn type_kind(&self) -> Option<EmergencyAccessType> {
        EmergencyAccessType::from_u8(self.access_type)
    }
}

/// Body for `POST /emergency-access/invite`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EmergencyAccessInviteRequest {
    pub email: String,
    #[serde(rename = "type")]
    pub access_type: u8,
    pub wait_time_days: u32,
}

/// Body for `PUT /emergency-access/{id}`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EmergencyAccessUpdateRequest {
    #[serde(rename = "type")]
    pub access_type: u8,
    pub wait_time_days: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_encrypted: Option<String>,
}

/// Body for `POST /emergency-access/{id}/accept`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EmergencyAccessAcceptRequest {
    pub token: String,
}

/// Body for `POST /emergency-access/{id}/confirm`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EmergencyAccessConfirmRequest {
    /// Grantor user key encrypted with the grantee's RSA public key.
    pub key: String,
}

/// Response of `POST /emergency-access/{id}/view`.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EmergencyAccessView {
    /// Grantor user key encrypted with the grantee's RSA public key.
    pub key_encrypted: String,
    #[serde(default)]
    pub ciphers: Vec<crate::models::Cipher>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bulk_share_cipher_flattens_id_and_cipher() {
        let item = BulkShareCipher {
            id: "abc".into(),
            cipher: CipherRequest {
                cipher_type: 1,
                name: "2.x|y|z".into(),
                encrypted_for: "u".into(),
                ..Default::default()
            },
        };
        let v = serde_json::to_value(&item).unwrap();
        assert_eq!(v["id"], "abc");
        assert_eq!(v["type"], 1);
        assert_eq!(v["name"], "2.x|y|z");
        assert_eq!(v["encryptedFor"], "u");
    }

    #[test]
    fn share_request_uses_camel_case_collection_ids() {
        let req = CipherShareRequest {
            cipher: CipherRequest {
                organization_id: Some("org".into()),
                ..Default::default()
            },
            collection_ids: vec!["c1".into()],
        };
        let v = serde_json::to_value(&req).unwrap();
        assert_eq!(v["collectionIds"][0], "c1");
        assert_eq!(v["cipher"]["organizationId"], "org");
    }

    #[test]
    fn move_request_serializes_null_folder() {
        let v = serde_json::to_value(CipherMoveRequest {
            ids: vec!["a".into()],
            folder_id: None,
        })
        .unwrap();
        assert!(v["folderId"].is_null());
    }

    #[test]
    fn emergency_list_deserializes() {
        let json = r#"{"data":[{"id":"1","status":2,"type":1,"waitTimeDays":7,
            "granteeId":"g","email":"a@b.c","name":"A","object":"emergencyAccessGranteeDetails"}],
            "object":"list"}"#;
        let list: ListResponse<EmergencyAccessEntry> = serde_json::from_str(json).unwrap();
        assert_eq!(list.data.len(), 1);
        let e = &list.data[0];
        assert_eq!(e.status_kind(), Some(EmergencyAccessStatus::Confirmed));
        assert_eq!(e.type_kind(), Some(EmergencyAccessType::Takeover));
        assert_eq!(e.wait_time_days, 7);
    }
}
