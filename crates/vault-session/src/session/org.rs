//! Organization features: sharing, collections, org/collection create, bulk operations,
//! archive and emergency access.

use std::collections::{HashMap, HashSet};

use vault_api::{
    is_unsupported_route, ApiError, BulkShareCipher, CipherBulkShareRequest, CipherShareRequest,
    EmergencyAccessEntry, EmergencyAccessType, EmergencyAccessUpdateRequest,
};
use vault_crypto::{
    decrypt_private_key, public_key_der_from_b64, rsa_encrypt_user_key, unwrap_org_key,
    SymmetricCryptoKey,
};

use super::{
    encrypt_card, encrypt_identity, encrypt_login, encrypt_note, encrypt_ssh_key, Session,
};
use crate::decrypt::decrypt_cipher;
use crate::error::{Result, SessionError};
use crate::fingerprint::fingerprint_phrase_from_public_der;
use crate::models::*;
use crate::org_share::{
    reencrypt_cipher_for_org, seal_new_cipher, CollectionChoice, EmergencyAccessOverview,
    OrgCollectionGroup, OrgPlacement,
};

/// Longest wait time Bitwarden / Vaultwarden accept for emergency access.
const EMERGENCY_MAX_WAIT_DAYS: u32 = 90;

fn dedup_ids(ids: &[String]) -> Vec<String> {
    let mut seen = HashSet::new();
    ids.iter()
        .filter(|i| !i.is_empty() && seen.insert((*i).clone()))
        .cloned()
        .collect()
}

fn map_archive_err(e: ApiError) -> SessionError {
    if is_unsupported_route(&e) {
        SessionError::Other(
            "this server does not support archiving items (no /ciphers/*/archive endpoint)".into(),
        )
    } else {
        e.into()
    }
}

impl Session {
    // ── Settings ────────────────────────────────────────────────────────────

    /// Whether new items get their own random cipher key (default: on).
    pub fn item_keys_on_create(&self) -> bool {
        self.item_keys_on_create
    }

    /// Toggle per-item cipher keys for newly created items.
    pub fn set_item_keys_on_create(&mut self, on: bool) {
        self.item_keys_on_create = on;
    }

    // ── Permissions / pickers ───────────────────────────────────────────────

    pub fn organization(&self, id: &str) -> Option<&DecryptedOrganization> {
        self.index.organizations.iter().find(|o| o.id == id)
    }

    pub fn collection(&self, id: &str) -> Option<&DecryptedCollection> {
        self.index.collections.iter().find(|c| c.id == id)
    }

    /// Whether the current user may edit this item (re-encrypt + save).
    ///
    /// Uses the server's per-cipher `edit` flag when present, otherwise derives it from the
    /// organization role and collection permissions. Items that cannot be decrypted are never
    /// editable.
    pub fn can_edit_item(&self, id: &str) -> bool {
        let Some(raw) = self.index.raw_ciphers.get(id) else {
            return false;
        };
        if self.resolve_item_cipher_key(id).is_err() {
            return false;
        }
        if let Some(edit) = raw.server_can_edit() {
            return edit;
        }
        let Some(org_id) = raw.organization_id.as_deref() else {
            return true;
        };
        if self
            .organization(org_id)
            .is_some_and(|o| o.can_edit_any_collection())
        {
            return true;
        }
        let known: Vec<&DecryptedCollection> = raw
            .collection_ids
            .iter()
            .flatten()
            .filter_map(|cid| self.collection(cid))
            .collect();
        // No collection info (older server / unsynced): let the server decide.
        known.is_empty() || known.iter().any(|c| !c.read_only)
    }

    /// Error unless [`Self::can_edit_item`] allows editing `item`.
    pub(super) fn ensure_item_editable(&self, item: &DecryptedItem) -> Result<()> {
        if self.can_edit_item(&item.id) {
            Ok(())
        } else {
            Err(SessionError::OrgEditUnsupported)
        }
    }

    fn choice_for(&self, c: &DecryptedCollection, selected: bool) -> Option<CollectionChoice> {
        let org_id = c.organization_id.as_deref()?;
        let org_name = self
            .organization(org_id)
            .map(|o| o.name.clone())
            .unwrap_or_else(|| org_id.to_string());
        Some(CollectionChoice {
            id: c.id.clone(),
            name: c.name.clone(),
            organization_id: org_id.to_string(),
            organization_name: org_name,
            read_only: c.read_only,
            hide_passwords: c.hide_passwords,
            selected,
        })
    }

    /// All collections of an organization (read-only ones included; filter with
    /// [`CollectionChoice::writable`]).
    pub fn collection_choices(&self, organization_id: &str) -> Vec<CollectionChoice> {
        let mut out: Vec<_> = self
            .index
            .collections
            .iter()
            .filter(|c| c.organization_id.as_deref() == Some(organization_id))
            .filter_map(|c| self.choice_for(c, false))
            .collect();
        out.sort_by_key(|a| a.name.to_lowercase());
        out
    }

    /// Organizations (with decryptable key) the user can share to / create items in, each
    /// with its writable collections. Empty orgs (no writable collection) are omitted.
    pub fn share_targets(&self) -> Vec<OrgCollectionGroup> {
        let mut groups: Vec<OrgCollectionGroup> = self
            .index
            .organizations
            .iter()
            .filter(|o| o.is_usable() && self.index.org_keys.contains_key(&o.id))
            .filter_map(|o| {
                let collections: Vec<_> = self
                    .collection_choices(&o.id)
                    .into_iter()
                    .filter(|c| c.writable() || o.can_edit_any_collection())
                    .collect();
                if collections.is_empty() {
                    None
                } else {
                    Some(OrgCollectionGroup {
                        organization_id: o.id.clone(),
                        organization_name: o.name.clone(),
                        collections,
                    })
                }
            })
            .collect();
        groups.sort_by(|a, b| {
            a.organization_name
                .to_lowercase()
                .cmp(&b.organization_name.to_lowercase())
        });
        groups
    }

    /// Picker for "edit collections": every collection of the item's organization with the
    /// item's current membership pre-selected.
    pub fn item_collection_picker(&self, item_id: &str) -> Result<Vec<CollectionChoice>> {
        let raw = self
            .index
            .raw_ciphers
            .get(item_id)
            .ok_or(SessionError::NotFound)?;
        let org_id = raw
            .organization_id
            .as_deref()
            .ok_or_else(|| SessionError::Other("item does not belong to an organization".into()))?;
        let current: HashSet<&str> = raw
            .collection_ids
            .iter()
            .flatten()
            .map(String::as_str)
            .collect();
        let mut out = self.collection_choices(org_id);
        for c in &mut out {
            c.selected = current.contains(c.id.as_str());
        }
        Ok(out)
    }

    /// Validate an org placement (key, membership, collections, write access).
    fn validate_placement(&self, p: &OrgPlacement) -> Result<()> {
        let org = self
            .organization(&p.organization_id)
            .ok_or_else(|| SessionError::Other("unknown organization".into()))?;
        if !org.is_usable() {
            return Err(SessionError::Other(format!(
                "organization \"{}\" is disabled or membership is not confirmed",
                org.name
            )));
        }
        if !self.index.org_keys.contains_key(&p.organization_id) {
            return Err(SessionError::Other(format!(
                "no decryptable key for organization \"{}\"",
                org.name
            )));
        }
        if p.collection_ids.is_empty() {
            return Err(SessionError::Other("select at least one collection".into()));
        }
        for cid in &p.collection_ids {
            let c = self
                .collection(cid)
                .ok_or_else(|| SessionError::Other(format!("unknown collection {cid}")))?;
            if c.organization_id.as_deref() != Some(p.organization_id.as_str()) {
                return Err(SessionError::Other(format!(
                    "collection \"{}\" is not part of organization \"{}\"",
                    c.name, org.name
                )));
            }
            if c.read_only && !org.can_edit_any_collection() {
                return Err(SessionError::Other(format!(
                    "collection \"{}\" is read-only",
                    c.name
                )));
            }
        }
        Ok(())
    }

    /// Org-owned creation check: restricted item types apply, the personal-vault policy
    /// does not.
    fn check_org_item_creation_allowed(&self, item_type: ItemType, p: &OrgPlacement) -> Result<()> {
        self.validate_placement(p)?;
        if let Some(n) = item_type.as_u8() {
            if self.restricted_item_type_numbers().contains(&n) {
                return Err(SessionError::PolicyViolation(format!(
                    "creating {} items is restricted",
                    item_type.label()
                )));
            }
        }
        Ok(())
    }

    // ── Create (personal or org / collection) with optional item keys ───────

    async fn create_cipher_generic<F>(
        &mut self,
        item_type: ItemType,
        placement: Option<&OrgPlacement>,
        build: F,
    ) -> Result<String>
    where
        F: FnOnce(&SymmetricCryptoKey, &str) -> Result<vault_api::CipherRequest>,
    {
        self.ensure_online()?;
        let base_key = match placement {
            None => {
                self.check_item_creation_allowed(item_type)?;
                self.user_key.as_ref().ok_or(SessionError::Locked)?.clone()
            }
            Some(p) => {
                if self.user_key.is_none() {
                    return Err(SessionError::Locked);
                }
                self.check_org_item_creation_allowed(item_type, p)?;
                self.index.org_keys[&p.organization_id].clone()
            }
        };
        let user_id = self.user_id()?.to_string();
        let mut req = seal_new_cipher(&base_key, self.item_keys_on_create, |k| build(k, &user_id))?;
        let created = match placement {
            None => self.client.create_cipher(&req).await?,
            Some(p) => {
                req.organization_id = Some(p.organization_id.clone());
                self.client
                    .create_cipher_with_collections(&CipherShareRequest {
                        cipher: req,
                        collection_ids: p.collection_ids.clone(),
                    })
                    .await?
            }
        };
        let id = created.id.clone().unwrap_or_default();
        self.sync().await?;
        Ok(id)
    }

    /// Create a login, personal (`None`) or in an organization + collections.
    pub async fn create_login_in(
        &mut self,
        draft: &LoginDraft,
        placement: Option<&OrgPlacement>,
    ) -> Result<String> {
        self.create_cipher_generic(ItemType::Login, placement, |k, uid| {
            encrypt_login(draft, k, uid)
        })
        .await
    }

    pub async fn create_note_in(
        &mut self,
        draft: &NoteDraft,
        placement: Option<&OrgPlacement>,
    ) -> Result<String> {
        self.create_cipher_generic(ItemType::SecureNote, placement, |k, uid| {
            encrypt_note(draft, k, uid)
        })
        .await
    }

    pub async fn create_card_in(
        &mut self,
        draft: &CardDraft,
        placement: Option<&OrgPlacement>,
    ) -> Result<String> {
        self.create_cipher_generic(ItemType::Card, placement, |k, uid| {
            encrypt_card(draft, k, uid)
        })
        .await
    }

    pub async fn create_identity_in(
        &mut self,
        draft: &IdentityDraft,
        placement: Option<&OrgPlacement>,
    ) -> Result<String> {
        self.create_cipher_generic(ItemType::Identity, placement, |k, uid| {
            encrypt_identity(draft, k, uid)
        })
        .await
    }

    pub async fn create_ssh_key_in(
        &mut self,
        draft: &SshKeyDraft,
        placement: Option<&OrgPlacement>,
    ) -> Result<String> {
        self.create_cipher_generic(ItemType::SshKey, placement, |k, uid| {
            encrypt_ssh_key(draft, k, uid)
        })
        .await
    }

    // ── Share / collections ─────────────────────────────────────────────────

    fn build_share_request(
        &self,
        id: &str,
        organization_id: &str,
        collection_ids: &[String],
    ) -> Result<vault_api::CipherRequest> {
        let placement = OrgPlacement::new(organization_id, collection_ids.to_vec());
        self.validate_placement(&placement)?;
        let raw = self
            .index
            .raw_ciphers
            .get(id)
            .ok_or(SessionError::NotFound)?;
        if raw.organization_id.is_some() {
            return Err(SessionError::Other(
                "item already belongs to an organization".into(),
            ));
        }
        let user_key = self.user_key.as_ref().ok_or(SessionError::Locked)?;
        let org_key = &self.index.org_keys[organization_id];
        let user_id = self.user_id()?;
        let mut req = reencrypt_cipher_for_org(raw, user_key, org_key, user_id)?;
        req.organization_id = Some(organization_id.to_string());
        Ok(req)
    }

    /// Share a personal item with an organization (`PUT /ciphers/{id}/share`), re-encrypting
    /// it for the organization key and assigning it to `collection_ids`.
    pub async fn share_item_to_org(
        &mut self,
        id: &str,
        organization_id: &str,
        collection_ids: &[String],
    ) -> Result<()> {
        self.ensure_online()?;
        let ids = dedup_ids(collection_ids);
        let cipher = self.build_share_request(id, organization_id, &ids)?;
        self.client
            .share_cipher(
                id,
                &CipherShareRequest {
                    cipher,
                    collection_ids: ids,
                },
            )
            .await?;
        self.sync().await?;
        Ok(())
    }

    /// Replace the collections of an organization item (`PUT /ciphers/{id}/collections`).
    pub async fn set_item_collections(
        &mut self,
        id: &str,
        collection_ids: &[String],
    ) -> Result<()> {
        self.ensure_online()?;
        let ids = dedup_ids(collection_ids);
        let raw = self
            .index
            .raw_ciphers
            .get(id)
            .ok_or(SessionError::NotFound)?;
        let org_id = raw
            .organization_id
            .clone()
            .ok_or_else(|| SessionError::Other("item does not belong to an organization".into()))?;
        self.validate_placement(&OrgPlacement::new(org_id, ids.clone()))?;
        self.client.update_cipher_collections(id, &ids).await?;
        self.sync().await?;
        Ok(())
    }

    // ── Bulk operations ─────────────────────────────────────────────────────

    /// Dedup + verify every id exists. Returns `Ok(vec![])` for empty input.
    fn bulk_ids(&self, ids: &[String]) -> Result<Vec<String>> {
        let ids = dedup_ids(ids);
        for id in &ids {
            if !self.index.raw_ciphers.contains_key(id) {
                return Err(SessionError::NotFound);
            }
        }
        Ok(ids)
    }

    /// Move items to the trash. Returns the number of items affected.
    pub async fn bulk_soft_delete(&mut self, ids: &[String]) -> Result<usize> {
        self.ensure_online()?;
        let ids = self.bulk_ids(ids)?;
        if ids.is_empty() {
            return Ok(0);
        }
        self.client.bulk_soft_delete_ciphers(&ids).await?;
        self.sync().await?;
        Ok(ids.len())
    }

    /// Permanently delete items.
    pub async fn bulk_hard_delete(&mut self, ids: &[String]) -> Result<usize> {
        self.ensure_online()?;
        let ids = self.bulk_ids(ids)?;
        if ids.is_empty() {
            return Ok(0);
        }
        self.client.bulk_delete_ciphers(&ids).await?;
        self.sync().await?;
        Ok(ids.len())
    }

    /// Restore items from the trash.
    pub async fn bulk_restore(&mut self, ids: &[String]) -> Result<usize> {
        self.ensure_online()?;
        let ids = self.bulk_ids(ids)?;
        if ids.is_empty() {
            return Ok(0);
        }
        self.client.bulk_restore_ciphers(&ids).await?;
        self.sync().await?;
        Ok(ids.len())
    }

    /// Move items to a folder (`None` = no folder).
    pub async fn bulk_move_to_folder(
        &mut self,
        ids: &[String],
        folder_id: Option<&str>,
    ) -> Result<usize> {
        self.ensure_online()?;
        let ids = self.bulk_ids(ids)?;
        if ids.is_empty() {
            return Ok(0);
        }
        if let Some(fid) = folder_id {
            if !self.index.folders.iter().any(|f| f.id == fid) {
                return Err(SessionError::Other(format!("unknown folder {fid}")));
            }
        }
        self.client.bulk_move_ciphers(&ids, folder_id).await?;
        self.sync().await?;
        Ok(ids.len())
    }

    /// Share many personal items with one organization / collection set.
    ///
    /// All items are validated and re-encrypted locally first; nothing is sent when any item
    /// fails (for example: already in an org, undecryptable).
    pub async fn bulk_share_to_org(
        &mut self,
        ids: &[String],
        organization_id: &str,
        collection_ids: &[String],
    ) -> Result<usize> {
        self.ensure_online()?;
        let ids = self.bulk_ids(ids)?;
        if ids.is_empty() {
            return Ok(0);
        }
        let cols = dedup_ids(collection_ids);
        let mut ciphers = Vec::with_capacity(ids.len());
        for id in &ids {
            let cipher = self.build_share_request(id, organization_id, &cols)?;
            ciphers.push(BulkShareCipher {
                id: id.clone(),
                cipher,
            });
        }
        self.client
            .bulk_share_ciphers(&CipherBulkShareRequest {
                ciphers,
                collection_ids: cols,
            })
            .await?;
        self.sync().await?;
        Ok(ids.len())
    }

    // ── Archive ─────────────────────────────────────────────────────────────

    /// True when the server marked the item archived (`archivedDate`).
    pub fn item_archived(&self, id: &str) -> bool {
        self.index
            .raw_ciphers
            .get(id)
            .is_some_and(|c| c.is_archived())
    }

    /// Items currently archived (always empty on servers without archive support).
    pub fn archived_items(&self) -> Vec<&DecryptedItem> {
        self.index
            .items
            .iter()
            .filter(|i| !i.deleted && self.item_archived(&i.id))
            .collect()
    }

    /// Items that are neither deleted nor archived — the default vault listing filter.
    pub fn unarchived_items(&self) -> Vec<&DecryptedItem> {
        self.index
            .items
            .iter()
            .filter(|i| !i.deleted && !self.item_archived(&i.id))
            .collect()
    }

    /// Archive an item. Fails with a clear message when the server lacks archive support.
    pub async fn archive_item(&mut self, id: &str) -> Result<()> {
        self.ensure_online()?;
        if !self.index.raw_ciphers.contains_key(id) {
            return Err(SessionError::NotFound);
        }
        self.client
            .archive_cipher(id)
            .await
            .map_err(map_archive_err)?;
        self.sync().await?;
        Ok(())
    }

    pub async fn unarchive_item(&mut self, id: &str) -> Result<()> {
        self.ensure_online()?;
        if !self.index.raw_ciphers.contains_key(id) {
            return Err(SessionError::NotFound);
        }
        self.client
            .unarchive_cipher(id)
            .await
            .map_err(map_archive_err)?;
        self.sync().await?;
        Ok(())
    }

    pub async fn bulk_archive(&mut self, ids: &[String]) -> Result<usize> {
        self.ensure_online()?;
        let ids = self.bulk_ids(ids)?;
        if ids.is_empty() {
            return Ok(0);
        }
        self.client
            .bulk_archive_ciphers(&ids)
            .await
            .map_err(map_archive_err)?;
        self.sync().await?;
        Ok(ids.len())
    }

    pub async fn bulk_unarchive(&mut self, ids: &[String]) -> Result<usize> {
        self.ensure_online()?;
        let ids = self.bulk_ids(ids)?;
        if ids.is_empty() {
            return Ok(0);
        }
        self.client
            .bulk_unarchive_ciphers(&ids)
            .await
            .map_err(map_archive_err)?;
        self.sync().await?;
        Ok(ids.len())
    }

    // ── Emergency access ────────────────────────────────────────────────────

    /// Trusted contacts and granted accesses.
    pub async fn emergency_access_list(&self) -> Result<EmergencyAccessOverview> {
        self.ensure_online()?;
        let trusted = self.client.list_emergency_trusted().await?;
        let granted = self.client.list_emergency_granted().await?;
        Ok(EmergencyAccessOverview { trusted, granted })
    }

    /// Invite a trusted contact who may recover this vault after `wait_time_days`.
    pub async fn emergency_invite(
        &self,
        email: &str,
        access_type: EmergencyAccessType,
        wait_time_days: u32,
    ) -> Result<()> {
        self.ensure_online()?;
        let email = email.trim();
        if !email.contains('@') || email.len() < 3 {
            return Err(SessionError::Other("enter a valid email address".into()));
        }
        if !(1..=EMERGENCY_MAX_WAIT_DAYS).contains(&wait_time_days) {
            return Err(SessionError::Other(format!(
                "wait time must be between 1 and {EMERGENCY_MAX_WAIT_DAYS} days"
            )));
        }
        self.client
            .invite_emergency_contact(email, access_type, wait_time_days)
            .await?;
        Ok(())
    }

    /// Change access type / wait time of an existing grant.
    pub async fn emergency_update(
        &self,
        id: &str,
        access_type: EmergencyAccessType,
        wait_time_days: u32,
    ) -> Result<()> {
        self.ensure_online()?;
        if !(1..=EMERGENCY_MAX_WAIT_DAYS).contains(&wait_time_days) {
            return Err(SessionError::Other(format!(
                "wait time must be between 1 and {EMERGENCY_MAX_WAIT_DAYS} days"
            )));
        }
        self.client
            .update_emergency_access(
                id,
                &EmergencyAccessUpdateRequest {
                    access_type: access_type.as_u8(),
                    wait_time_days,
                    key_encrypted: None,
                },
            )
            .await?;
        Ok(())
    }

    pub async fn emergency_reinvite(&self, id: &str) -> Result<()> {
        self.ensure_online()?;
        self.client.reinvite_emergency_contact(id).await?;
        Ok(())
    }

    /// Remove a grant (as grantor revoking, or as grantee declining).
    pub async fn emergency_remove(&self, id: &str) -> Result<()> {
        self.ensure_online()?;
        self.client.delete_emergency_access(id).await?;
        Ok(())
    }

    /// Accept an invitation (grantee side) using the token from the invitation email.
    pub async fn emergency_accept(&self, id: &str, token: &str) -> Result<()> {
        self.ensure_online()?;
        self.client
            .accept_emergency_invite(id, token.trim())
            .await?;
        Ok(())
    }

    async fn emergency_grantee_public_key(&self, grantee_id: &str) -> Result<String> {
        Ok(self
            .client
            .get_user_public_key(grantee_id)
            .await?
            .public_key)
    }

    /// Fingerprint phrase of a contact's public key — compare out-of-band before confirming.
    pub async fn emergency_grantee_fingerprint(&self, grantee_id: &str) -> Result<String> {
        self.ensure_online()?;
        let pk = self.emergency_grantee_public_key(grantee_id).await?;
        let der = public_key_der_from_b64(&pk)?;
        Ok(fingerprint_phrase_from_public_der(&der))
    }

    /// Confirm an accepted contact by sharing this account's user key, encrypted with the
    /// contact's public key. Returns the contact's fingerprint phrase for the UI to display.
    pub async fn emergency_confirm(&self, id: &str) -> Result<String> {
        self.ensure_online()?;
        let user_key = self.user_key.as_ref().ok_or(SessionError::Locked)?;
        let entry = self.client.get_emergency_access(id).await?;
        let grantee_id = entry
            .grantee_id
            .as_deref()
            .ok_or_else(|| SessionError::Other("contact has not accepted the invitation".into()))?;
        let pk = self.emergency_grantee_public_key(grantee_id).await?;
        let encrypted = rsa_encrypt_user_key(user_key, &pk)?;
        self.client
            .confirm_emergency_contact(id, &encrypted)
            .await?;
        let der = public_key_der_from_b64(&pk)?;
        Ok(fingerprint_phrase_from_public_der(&der))
    }

    /// Start recovery of a vault we were granted access to (grantee side).
    pub async fn emergency_initiate(&self, id: &str) -> Result<()> {
        self.ensure_online()?;
        self.client.initiate_emergency_recovery(id).await?;
        Ok(())
    }

    /// Approve a recovery request before the wait time elapses (grantor side).
    pub async fn emergency_approve(&self, id: &str) -> Result<()> {
        self.ensure_online()?;
        self.client.approve_emergency_recovery(id).await?;
        Ok(())
    }

    pub async fn emergency_reject(&self, id: &str) -> Result<()> {
        self.ensure_online()?;
        self.client.reject_emergency_recovery(id).await?;
        Ok(())
    }

    /// Fetch and decrypt the grantor's personal vault (read-only "view" recovery).
    ///
    /// Organization-owned items are skipped because their keys are not shared.
    pub async fn emergency_view_items(&self, id: &str) -> Result<Vec<DecryptedItem>> {
        self.ensure_online()?;
        let user_key = self.user_key.as_ref().ok_or(SessionError::Locked)?;
        let private_enc = self
            .private_key_enc
            .as_deref()
            .ok_or_else(|| SessionError::Other("missing account keys".into()))?;
        let view = self.client.view_emergency_vault(id).await?;
        let private_der = decrypt_private_key(private_enc, user_key)?;
        let grantor_key = unwrap_org_key(&view.key_encrypted, &private_der)?;
        let no_org_keys: HashMap<String, SymmetricCryptoKey> = HashMap::new();
        Ok(view
            .ciphers
            .iter()
            .filter(|c| c.organization_id.is_none())
            .filter_map(|c| decrypt_cipher(c, &grantor_key, &no_org_keys).ok())
            .collect())
    }

    /// Convenience: look up one entry in a list returned by [`Self::emergency_access_list`].
    pub fn find_emergency_entry<'a>(
        entries: &'a [EmergencyAccessEntry],
        id: &str,
    ) -> Option<&'a EmergencyAccessEntry> {
        entries.iter().find(|e| e.id == id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dedup_ids_keeps_order_and_drops_empty() {
        let ids = vec!["a".into(), "b".into(), "a".into(), "".into(), "c".into()];
        assert_eq!(dedup_ids(&ids), vec!["a", "b", "c"]);
    }

    fn org(id: &str, org_type: u8) -> DecryptedOrganization {
        DecryptedOrganization {
            id: id.into(),
            name: format!("Org {id}"),
            org_type: Some(org_type),
            status: Some(2),
            enabled: true,
            edit_any_collection: false,
            create_new_collections: false,
        }
    }

    fn coll(id: &str, org: &str, read_only: bool) -> DecryptedCollection {
        DecryptedCollection {
            id: id.into(),
            name: format!("Coll {id}"),
            organization_id: Some(org.into()),
            read_only,
            hide_passwords: false,
            manage: None,
        }
    }

    fn raw_cipher(
        id: &str,
        org: Option<&str>,
        cols: &[&str],
        extra: serde_json::Value,
    ) -> vault_api::Cipher {
        let mut v = serde_json::json!({"id": id, "type": 1, "name": "2.x|y|z"});
        if let Some(o) = org {
            v["organizationId"] = o.into();
        }
        v["collectionIds"] = cols.iter().map(|c| serde_json::Value::from(*c)).collect();
        if let Some(obj) = extra.as_object() {
            for (k, val) in obj {
                v[k] = val.clone();
            }
        }
        serde_json::from_value(v).unwrap()
    }

    fn test_session() -> (Session, tempfile::TempDir) {
        use vault_crypto::generate_user_key;
        let tmp = tempfile::tempdir().unwrap();
        let mut s = Session::with_data_dir("http://127.0.0.1:1", tmp.path().join("p")).unwrap();
        s.user_key = Some(generate_user_key());
        s.user_id = Some("u1".into());
        s.status = crate::SessionStatus::Unlocked;
        s.index.organizations = vec![org("o1", 2), org("admin", 1)];
        s.index.collections = vec![
            coll("rw", "o1", false),
            coll("ro", "o1", true),
            coll("adm-ro", "admin", true),
        ];
        s.index.org_keys.insert("o1".into(), generate_user_key());
        s.index.org_keys.insert("admin".into(), generate_user_key());
        (s, tmp)
    }

    #[test]
    fn can_edit_item_follows_server_flag_then_collection_permissions() {
        let (mut s, _t) = test_session();
        let uk = s.user_key.clone().unwrap();
        let enc_name = vault_crypto::encrypt_with_key("n", &s.index.org_keys["o1"]).unwrap();
        let mut put = |s: &mut Session, id: &str, org: Option<&str>, cols: &[&str], extra| {
            let mut c = raw_cipher(id, org, cols, extra);
            c.name = if org.is_some() {
                enc_name.clone()
            } else {
                vault_crypto::encrypt_with_key("n", &uk).unwrap()
            };
            s.index.raw_ciphers.insert(id.into(), c);
        };
        put(&mut s, "personal", None, &[], serde_json::json!({}));
        put(&mut s, "rw", Some("o1"), &["rw"], serde_json::json!({}));
        put(&mut s, "ro", Some("o1"), &["ro"], serde_json::json!({}));
        put(
            &mut s,
            "ro-flag-true",
            Some("o1"),
            &["ro"],
            serde_json::json!({"edit": true}),
        );
        put(
            &mut s,
            "rw-flag-false",
            Some("o1"),
            &["rw"],
            serde_json::json!({"edit": false}),
        );
        put(
            &mut s,
            "unknown-cols",
            Some("o1"),
            &["zzz"],
            serde_json::json!({}),
        );

        assert!(s.can_edit_item("personal"));
        assert!(s.can_edit_item("rw"));
        assert!(!s.can_edit_item("ro"));
        assert!(s.can_edit_item("ro-flag-true"));
        assert!(!s.can_edit_item("rw-flag-false"));
        assert!(s.can_edit_item("unknown-cols"));
        assert!(!s.can_edit_item("missing"));
    }

    #[test]
    fn share_targets_lists_writable_collections_per_org() {
        let (s, _t) = test_session();
        let groups = s.share_targets();
        // "admin" org: admins may write to any collection, even read-only ones.
        assert_eq!(groups.len(), 2);
        let o1 = groups.iter().find(|g| g.organization_id == "o1").unwrap();
        assert_eq!(o1.collections.len(), 1);
        assert_eq!(o1.collections[0].id, "rw");
        let adm = groups
            .iter()
            .find(|g| g.organization_id == "admin")
            .unwrap();
        assert_eq!(adm.collections[0].id, "adm-ro");
    }

    #[test]
    fn placement_validation_rejects_bad_targets() {
        let (s, _t) = test_session();
        let ok = OrgPlacement::new("o1", vec!["rw".into()]);
        assert!(s.validate_placement(&ok).is_ok());
        assert!(s
            .validate_placement(&OrgPlacement::new("o1", vec![]))
            .is_err());
        assert!(s
            .validate_placement(&OrgPlacement::new("o1", vec!["ro".into()]))
            .is_err());
        assert!(s
            .validate_placement(&OrgPlacement::new("o1", vec!["adm-ro".into()]))
            .is_err());
        assert!(s
            .validate_placement(&OrgPlacement::new("nope", vec!["rw".into()]))
            .is_err());
        // Admin may use a read-only collection.
        assert!(s
            .validate_placement(&OrgPlacement::new("admin", vec!["adm-ro".into()]))
            .is_ok());
    }

    #[test]
    fn item_collection_picker_marks_current_membership() {
        let (mut s, _t) = test_session();
        s.index.raw_ciphers.insert(
            "c".into(),
            raw_cipher("c", Some("o1"), &["rw"], serde_json::json!({})),
        );
        let picker = s.item_collection_picker("c").unwrap();
        assert_eq!(picker.len(), 2);
        assert!(picker.iter().find(|c| c.id == "rw").unwrap().selected);
        assert!(!picker.iter().find(|c| c.id == "ro").unwrap().selected);
        s.index.raw_ciphers.insert(
            "p".into(),
            raw_cipher("p", None, &[], serde_json::json!({})),
        );
        assert!(s.item_collection_picker("p").is_err());
    }

    #[test]
    fn archive_helpers_use_archived_date() {
        let (mut s, _t) = test_session();
        s.index.raw_ciphers.insert(
            "a".into(),
            raw_cipher(
                "a",
                None,
                &[],
                serde_json::json!({"archivedDate": "2025-01-01T00:00:00Z"}),
            ),
        );
        s.index.raw_ciphers.insert(
            "b".into(),
            raw_cipher("b", None, &[], serde_json::json!({})),
        );
        assert!(s.item_archived("a"));
        assert!(!s.item_archived("b"));
        assert!(!s.item_archived("missing"));
    }

    #[test]
    fn offline_blocks_bulk_and_org_mutations() {
        let (mut s, _t) = test_session();
        s.offline = true;
        block_on(async {
            assert!(matches!(
                s.bulk_soft_delete(&["x".into()]).await,
                Err(SessionError::Offline)
            ));
            assert!(matches!(
                s.share_item_to_org("x", "o1", &["rw".into()]).await,
                Err(SessionError::Offline)
            ));
            assert!(matches!(
                s.emergency_access_list().await,
                Err(SessionError::Offline)
            ));
        });
    }

    #[test]
    fn online_bulk_rejects_unknown_ids_and_validates_before_network() {
        let (mut s, _t) = test_session();
        block_on(async {
            // Unknown id → NotFound before any request is attempted.
            assert!(matches!(
                s.bulk_restore(&["ghost".into()]).await,
                Err(SessionError::NotFound)
            ));
            // Empty selection is a no-op.
            assert_eq!(s.bulk_archive(&[]).await.unwrap(), 0);
            // Placement errors surface before the network too.
            s.index.raw_ciphers.insert(
                "p".into(),
                raw_cipher("p", None, &[], serde_json::json!({})),
            );
            let err = s
                .bulk_share_to_org(&["p".into()], "o1", &["ro".into()])
                .await
                .unwrap_err();
            assert!(matches!(err, SessionError::Other(ref m) if m.contains("read-only")));
            let err = s
                .create_login_in(
                    &LoginDraft::default(),
                    Some(&OrgPlacement::new("o1", vec!["ro".into()])),
                )
                .await
                .unwrap_err();
            assert!(matches!(err, SessionError::Other(ref m) if m.contains("read-only")));
        });
    }

    #[test]
    fn emergency_invite_validates_input() {
        let (s, _t) = test_session();
        block_on(async {
            assert!(s
                .emergency_invite("not-an-email", EmergencyAccessType::View, 7)
                .await
                .is_err());
            assert!(s
                .emergency_invite("a@b.c", EmergencyAccessType::View, 0)
                .await
                .is_err());
            assert!(s
                .emergency_invite("a@b.c", EmergencyAccessType::Takeover, 91)
                .await
                .is_err());
        });
    }

    fn block_on<F: std::future::Future>(fut: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(fut)
    }

    #[test]
    fn archive_error_maps_unsupported_route() {
        let e = map_archive_err(ApiError::Api {
            status: 404,
            message: String::new(),
        });
        assert!(matches!(e, SessionError::Other(ref m) if m.contains("does not support")));
        let e = map_archive_err(ApiError::Api {
            status: 400,
            message: "bad".into(),
        });
        assert!(matches!(e, SessionError::Api(_)));
    }
}
