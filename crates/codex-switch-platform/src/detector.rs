use codex_switch_domain::{
    CredentialMode, DetectedSession, OfficialCredentialStore, Result, SessionDetector, SystemEntry,
};

use crate::{
    credential_file::FileCredentialStore, credential_registry::CredentialDiscoveryRegistry,
    inspect::inspect_auth_json,
};

pub struct AuthJsonSessionDetector {
    file_store: FileCredentialStore,
    registry: CredentialDiscoveryRegistry,
    system_stores: Vec<Box<dyn OfficialCredentialStore>>,
}

impl AuthJsonSessionDetector {
    #[must_use]
    pub fn new(file_store: FileCredentialStore) -> Self {
        Self {
            file_store,
            registry: CredentialDiscoveryRegistry::default(),
            system_stores: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_registry(
        file_store: FileCredentialStore,
        registry: CredentialDiscoveryRegistry,
        system_stores: Vec<Box<dyn OfficialCredentialStore>>,
    ) -> Self {
        Self { file_store, registry, system_stores }
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
        let system_entries = self.discover_system_entries(&inspection);
        let live_fingerprint = DetectedSession::compute_live_fingerprint(
            inspection.source_type,
            &inspection.account_fingerprint,
            &file_entries,
            &system_entries,
        );
        let credential_mode = match (!file_entries.is_empty(), !system_entries.is_empty()) {
            (true, true) => CredentialMode::Mixed,
            (true, false) => CredentialMode::File,
            (false, true) => CredentialMode::System,
            (false, false) => CredentialMode::File,
        };

        Ok(DetectedSession {
            codex_home: self.file_store.auth_path().parent().unwrap().display().to_string(),
            auth_mode: inspection.auth_mode,
            account_label_masked: inspection.account_label_masked,
            account_fingerprint: inspection.account_fingerprint,
            source_type: inspection.source_type,
            credential_mode,
            file_entries,
            system_entries,
            last_refresh_at: inspection.last_refresh_at,
            live_fingerprint,
        })
    }
}

impl AuthJsonSessionDetector {
    fn discover_system_entries(
        &self,
        inspection: &crate::inspect::AuthInspection,
    ) -> Vec<SystemEntry> {
        let mut entries = Vec::new();
        for store in &self.system_stores {
            entries.extend(self.registry.discover(inspection, store.as_ref()));
        }
        dedupe_system_entries(entries)
    }
}

fn dedupe_system_entries(entries: Vec<SystemEntry>) -> Vec<SystemEntry> {
    let mut seen = std::collections::BTreeSet::new();
    let mut deduped = Vec::new();
    for entry in entries {
        let key = format!(
            "{}:{}:{}",
            entry.reference.service,
            entry.reference.account,
            entry.reference.label.as_deref().unwrap_or_default()
        );
        if seen.insert(key) {
            deduped.push(entry);
        }
    }
    deduped
}

#[cfg(test)]
mod tests {
    use std::fs;

    use codex_switch_domain::{
        CredentialRef, OfficialCredentialStore, Result, SecretRecord, SwitchError,
    };
    use secrecy::SecretString;
    use tempfile::tempdir;

    use super::*;
    use crate::credential_registry::{CredentialDiscoveryRegistry, CredentialDiscoveryRule};

    #[derive(Debug)]
    struct MockStore {
        available: Vec<SecretRecord>,
    }

    impl OfficialCredentialStore for MockStore {
        fn kind(&self) -> CredentialMode {
            CredentialMode::System
        }

        fn store_name(&self) -> &'static str {
            "mock_system_store"
        }

        fn is_available(&self) -> bool {
            true
        }

        fn read(&self, refs: &[CredentialRef]) -> Result<Vec<SecretRecord>> {
            let mut matched = Vec::new();
            for wanted in refs {
                if let Some(record) =
                    self.available.iter().find(|record| &record.reference == wanted)
                {
                    matched.push(record.clone());
                }
            }
            if matched.is_empty() {
                Err(SwitchError::CredentialUnavailable("No matching system credential".to_string()))
            } else {
                Ok(matched)
            }
        }

        fn write(&self, _records: &[SecretRecord]) -> Result<()> {
            Ok(())
        }

        fn delete(&self, _refs: &[CredentialRef]) -> Result<()> {
            Ok(())
        }
    }

    #[test]
    fn detector_reports_mixed_mode_when_system_credentials_are_discovered() {
        let temp = tempdir().expect("tempdir");
        let codex_home = temp.path().join("codex-home");
        fs::create_dir_all(&codex_home).expect("codex_home");
        fs::write(
            codex_home.join("auth.json"),
            r#"{
                "auth_mode":"chatgpt",
                "last_refresh":"2026-04-13T00:00:00Z",
                "tokens": {
                    "id_token":"aaa.eyJlbWFpbCI6InBlcnNvbkBleGFtcGxlLmNvbSIsInN1YiI6ImFjY3RfMTIzIn0.ccc",
                    "access_token":"access",
                    "refresh_token":"refresh",
                    "account_id":"acct_123"
                }
            }"#,
        )
        .expect("auth");

        let detector = AuthJsonSessionDetector::with_registry(
            FileCredentialStore::new(codex_home),
            CredentialDiscoveryRegistry::new(vec![CredentialDiscoveryRule {
                name: "openai-account".to_string(),
                source_type: Some(codex_switch_domain::SourceType::ChatGpt),
                service: "openai".to_string(),
                account: "{account_id}".to_string(),
                label: Some("Primary session".to_string()),
            }]),
            vec![Box::new(MockStore {
                available: vec![SecretRecord {
                    reference: CredentialRef {
                        service: "openai".to_string(),
                        account: "acct_123".to_string(),
                        label: Some("Primary session".to_string()),
                    },
                    secret: SecretString::new("secret-token".into()),
                }],
            })],
        );

        let detected = detector.detect().expect("detected");

        assert_eq!(detected.credential_mode, CredentialMode::Mixed);
        assert_eq!(detected.system_entries.len(), 1);
    }
}
