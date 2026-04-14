use codex_switch_domain::{CredentialMode, DetectedSession, Result, SessionDetector, SystemEntry};

use crate::{credential_file::FileCredentialStore, inspect::inspect_auth_json};

pub struct AuthJsonSessionDetector {
    file_store: FileCredentialStore,
}

impl AuthJsonSessionDetector {
    #[must_use]
    pub fn new(file_store: FileCredentialStore) -> Self {
        Self { file_store }
    }
}

impl SessionDetector for AuthJsonSessionDetector {
    fn detect(&self) -> Result<DetectedSession> {
        let file_entries = self.file_store.detect_entries()?;
        let auth_entry = file_entries
            .iter()
            .find(|entry| entry.relative_path == "auth.json")
            .expect("auth entry exists");
        let inspection = inspect_auth_json(&auth_entry.contents)?;
        let system_entries = Vec::<SystemEntry>::new();
        let live_fingerprint = DetectedSession::compute_live_fingerprint(
            inspection.source_type,
            &inspection.account_fingerprint,
            &file_entries,
            &system_entries,
        );

        Ok(DetectedSession {
            codex_home: self.file_store.auth_path().parent().unwrap().display().to_string(),
            auth_mode: inspection.auth_mode,
            account_label_masked: inspection.account_label_masked,
            account_fingerprint: inspection.account_fingerprint,
            source_type: inspection.source_type,
            credential_mode: CredentialMode::File,
            file_entries,
            system_entries,
            last_refresh_at: inspection.last_refresh_at,
            live_fingerprint,
        })
    }
}
