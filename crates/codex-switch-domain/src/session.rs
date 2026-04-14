use chrono::{DateTime, Utc};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{CredentialMode, ProfileId, SourceType};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthMode {
    ChatGpt,
    ApiKey,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileEntry {
    pub relative_path: String,
    pub contents: String,
    pub permissions: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialRef {
    pub service: String,
    pub account: String,
    pub label: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SecretRecord {
    pub reference: CredentialRef,
    pub secret: SecretString,
}

impl PartialEq for SecretRecord {
    fn eq(&self, other: &Self) -> bool {
        self.reference == other.reference
            && self.secret.expose_secret() == other.secret.expose_secret()
    }
}

impl Eq for SecretRecord {}

impl Serialize for SecretRecord {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        #[derive(Serialize)]
        struct WireRecord<'a> {
            reference: &'a CredentialRef,
            secret: &'a str,
        }

        WireRecord { reference: &self.reference, secret: self.secret.expose_secret() }
            .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SecretRecord {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct WireRecord {
            reference: CredentialRef,
            secret: String,
        }

        let wire = WireRecord::deserialize(deserializer)?;
        Ok(Self { reference: wire.reference, secret: SecretString::new(wire.secret.into()) })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SystemEntry {
    pub reference: CredentialRef,
    pub masked_value_hint: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetectedSession {
    pub codex_home: String,
    pub auth_mode: AuthMode,
    pub account_label_masked: String,
    pub account_fingerprint: String,
    pub source_type: SourceType,
    pub credential_mode: CredentialMode,
    pub file_entries: Vec<FileEntry>,
    pub system_entries: Vec<SystemEntry>,
    pub last_refresh_at: Option<DateTime<Utc>>,
    pub live_fingerprint: String,
}

impl DetectedSession {
    #[must_use]
    pub fn compute_live_fingerprint(
        source_type: SourceType,
        account_fingerprint: &str,
        file_entries: &[FileEntry],
        system_entries: &[SystemEntry],
    ) -> String {
        let mut hasher = Sha256::new();
        hasher.update(format!("{source_type:?}:{account_fingerprint}"));
        for file in file_entries {
            hasher.update(file.relative_path.as_bytes());
            hasher.update(file.contents.as_bytes());
        }
        for system in system_entries {
            hasher.update(system.reference.service.as_bytes());
            hasher.update(system.reference.account.as_bytes());
            hasher.update(system.masked_value_hint.as_bytes());
        }
        hex::encode(hasher.finalize())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotProvenance {
    pub operating_system: String,
    pub system_store_name: Option<String>,
}

impl Default for SnapshotProvenance {
    fn default() -> Self {
        Self { operating_system: "unknown".to_string(), system_store_name: None }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileVaultManifest {
    pub schema_version: u32,
    pub profile_id: ProfileId,
    pub encrypted: bool,
    pub file_entries: Vec<String>,
    pub system_entries: Vec<CredentialRef>,
    pub vault_fingerprint: String,
    #[serde(default)]
    pub provenance: SnapshotProvenance,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretSnapshot {
    pub manifest: ProfileVaultManifest,
    pub file_entries: Vec<FileEntry>,
    pub system_records: Vec<SecretRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CurrentBinding {
    pub active_profile_id: Option<ProfileId>,
    pub live_fingerprint_at_bind: Option<String>,
    pub last_sync_fingerprint: Option<String>,
    pub last_check_at: Option<DateTime<Utc>>,
}

impl Default for CurrentBinding {
    fn default() -> Self {
        Self {
            active_profile_id: None,
            live_fingerprint_at_bind: None,
            last_sync_fingerprint: None,
            last_check_at: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwitchPhase {
    Started,
    BackedUp,
    AppliedSystemSecrets,
    AppliedFiles,
    BindingUpdated,
    Validated,
    RolledBack,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwitchTransaction {
    pub txn_id: Uuid,
    pub source_profile_id: Option<ProfileId>,
    pub source_live_fingerprint: String,
    pub target_profile_id: ProfileId,
    pub started_at: DateTime<Utc>,
    pub backup_paths: Vec<String>,
    pub backup_system_entries: Vec<CredentialRef>,
    pub backup_system_records: Vec<SecretRecord>,
    pub phase: SwitchPhase,
    pub rollback_required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportEnvelope {
    pub schema_version: u32,
    pub profile_meta_json: String,
    pub snapshot_json: String,
}

#[must_use]
pub fn mask_account_label(raw: &str) -> String {
    if raw.is_empty() {
        return "unknown".to_string();
    }

    if let Some((local, domain)) = raw.split_once('@') {
        let prefix = local.chars().take(2).collect::<String>();
        return format!("{prefix}***@{domain}");
    }

    if raw.len() <= 8 {
        let suffix = raw.chars().rev().take(2).collect::<String>();
        let suffix = suffix.chars().rev().collect::<String>();
        return format!("acct_***{suffix}");
    }

    let suffix = raw.chars().rev().take(4).collect::<String>();
    let suffix = suffix.chars().rev().collect::<String>();
    format!("acct_****{suffix}")
}

#[must_use]
pub fn fingerprint_account(raw: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(raw.as_bytes());
    let digest = hex::encode(hasher.finalize());
    digest[..16].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mask_account_label_preserves_domain_shape() {
        assert_eq!(mask_account_label("person@example.com"), "pe***@example.com");
    }

    #[test]
    fn live_fingerprint_changes_when_file_content_changes() {
        let file_entries = vec![FileEntry {
            relative_path: "auth.json".to_string(),
            contents: "alpha".to_string(),
            permissions: Some(0o600),
        }];
        let one = DetectedSession::compute_live_fingerprint(
            SourceType::ChatGpt,
            "acct-a",
            &file_entries,
            &[],
        );
        let two = DetectedSession::compute_live_fingerprint(
            SourceType::ChatGpt,
            "acct-a",
            &[FileEntry {
                relative_path: "auth.json".to_string(),
                contents: "beta".to_string(),
                permissions: Some(0o600),
            }],
            &[],
        );
        assert_ne!(one, two);
    }

    #[test]
    fn legacy_manifest_defaults_unknown_provenance() {
        let manifest: ProfileVaultManifest = serde_json::from_str(
            r#"{
                "schema_version": 1,
                "profile_id": "123e4567-e89b-12d3-a456-426614174000",
                "encrypted": false,
                "file_entries": ["auth.json"],
                "system_entries": [],
                "vault_fingerprint": "fingerprint"
            }"#,
        )
        .expect("manifest");

        assert_eq!(manifest.provenance.operating_system, "unknown");
        assert_eq!(manifest.provenance.system_store_name, None);
    }
}
