use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub type ProfileId = Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialMode {
    File,
    System,
    Mixed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceType {
    ChatGpt,
    ApiKey,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthStatus {
    Healthy,
    Drifted,
    Invalid,
    Missing,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileHealth {
    pub status: HealthStatus,
    pub detail: String,
    pub checked_at: Option<DateTime<Utc>>,
}

impl ProfileHealth {
    #[must_use]
    pub fn unknown() -> Self {
        Self {
            status: HealthStatus::Unknown,
            detail: "Health has not been checked yet.".to_string(),
            checked_at: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileMeta {
    pub id: ProfileId,
    pub name: String,
    pub account_label_masked: String,
    pub account_fingerprint: String,
    pub source_type: SourceType,
    pub credential_mode: CredentialMode,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub last_synced_at: Option<DateTime<Utc>>,
    pub is_default: bool,
    pub health: ProfileHealth,
    pub note: Option<String>,
}

impl ProfileMeta {
    #[must_use]
    pub fn new(
        name: String,
        account_label_masked: String,
        account_fingerprint: String,
        source_type: SourceType,
        credential_mode: CredentialMode,
        note: Option<String>,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            name,
            account_label_masked,
            account_fingerprint,
            source_type,
            credential_mode,
            created_at: Utc::now(),
            last_used_at: None,
            last_synced_at: None,
            is_default: false,
            health: ProfileHealth::unknown(),
            note,
        }
    }
}
