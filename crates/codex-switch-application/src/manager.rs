use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use chrono::Utc;
use codex_switch_domain::{
    CurrentBinding, DetectedSession, HealthStatus, OfficialCredentialStore, ProfileHealth,
    ProfileId, ProfileMeta, Result, SecretRecord, SecretSnapshot, SessionDetector, SwitchError,
    SwitchPhase, SwitchTransaction, traits::ProfileVault as _,
};
use codex_switch_platform::{
    AuthJsonSessionDetector, FileCredentialStore, GlobalSwitchLock, LinuxKeyringCredentialStore,
    LocalProfileVault, MacKeychainCredentialStore, PathResolver, WindowsCredentialStore,
    fs_secure::{atomic_write, ensure_dir, list_json_files, secure_delete},
    locator::AppPaths,
};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Default)]
pub struct ManagerOptions {
    pub codex_home_override: Option<PathBuf>,
    pub data_dir_override: Option<PathBuf>,
    pub local_passphrase: Option<SecretString>,
}

#[derive(Debug, Clone)]
pub struct SaveProfileRequest {
    pub name: String,
    pub note: Option<String>,
    pub make_default: bool,
}

#[derive(Debug, Clone)]
pub struct UseProfileRequest {
    pub name: String,
    pub make_default: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct CurrentStatus {
    pub live_session: DetectedSession,
    pub active_profile: Option<ProfileMeta>,
    pub binding: CurrentBinding,
}

#[derive(Debug, Clone, Serialize)]
pub struct CheckReport {
    pub profile: ProfileMeta,
    pub detail: String,
    pub drifted: bool,
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct AppConfig {
    default_profile_id: Option<ProfileId>,
}

pub struct ManagerService {
    paths: AppPaths,
    detector: AuthJsonSessionDetector,
    file_store: FileCredentialStore,
    vault: LocalProfileVault,
    system_stores: Vec<Box<dyn OfficialCredentialStore>>,
    local_encryption_enabled: bool,
}

impl std::fmt::Debug for ManagerService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ManagerService")
            .field("paths", &self.paths)
            .field("local_encryption_enabled", &self.local_encryption_enabled)
            .finish()
    }
}

impl ManagerService {
    pub fn new(options: ManagerOptions) -> Result<Self> {
        let paths = PathResolver::discover(options.codex_home_override, options.data_dir_override)?;
        let file_store = FileCredentialStore::new(paths.codex_home.clone());
        let detector = AuthJsonSessionDetector::new(file_store.clone());
        let vault = LocalProfileVault::new(
            paths.profiles_dir.clone(),
            paths.vault_dir.clone(),
            paths.exports_dir.clone(),
            options.local_passphrase.clone(),
        );
        let service = Self {
            paths,
            detector,
            file_store,
            vault,
            system_stores: vec![
                Box::new(MacKeychainCredentialStore),
                Box::new(LinuxKeyringCredentialStore),
                Box::new(WindowsCredentialStore),
            ],
            local_encryption_enabled: options.local_passphrase.is_some(),
        };
        service.ensure_layout()?;
        Ok(service)
    }

    pub fn detect(&self) -> Result<DetectedSession> {
        self.detector.detect()
    }

    pub fn save_profile(&self, request: SaveProfileRequest) -> Result<ProfileMeta> {
        self.ensure_layout()?;
        self.recover_interrupted_transactions()?;
        if self.find_profile_by_name_optional(&request.name)?.is_some() {
            return Err(SwitchError::Conflict(format!(
                "A profile named '{}' already exists",
                request.name
            )));
        }

        let live = self.detect()?;
        let mut profile = ProfileMeta::new(
            request.name,
            live.account_label_masked.clone(),
            live.account_fingerprint.clone(),
            live.source_type,
            live.credential_mode,
            request.note,
        );
        profile.is_default = request.make_default;
        profile.health = ProfileHealth {
            status: HealthStatus::Healthy,
            detail: "Profile snapshot saved from the current live session.".to_string(),
            checked_at: Some(Utc::now()),
        };

        let snapshot = self.snapshot_from_detected(&live, profile.id)?;
        self.vault.save(&profile, &snapshot)?;
        if request.make_default {
            self.set_default_profile(Some(profile.id))?;
            profile = self.read_profile_by_id(profile.id)?;
        }
        self.append_audit(
            "save",
            &format!("Saved profile '{}' for {}", profile.name, profile.account_label_masked),
        )?;
        Ok(profile)
    }

    pub fn list_profiles(&self) -> Result<Vec<ProfileMeta>> {
        self.ensure_layout()?;
        self.read_profiles()
    }

    pub fn current_status(&self) -> Result<CurrentStatus> {
        self.ensure_layout()?;
        let live_session = self.detect()?;
        let binding = self.read_binding()?;
        let active_profile = binding
            .active_profile_id
            .and_then(|profile_id| self.read_profile_by_id(profile_id).ok());
        Ok(CurrentStatus { live_session, active_profile, binding })
    }

    pub fn use_profile(&self, request: UseProfileRequest) -> Result<ProfileMeta> {
        self.ensure_layout()?;
        self.recover_interrupted_transactions()?;
        let _guard = GlobalSwitchLock::acquire(self.lock_path())?;

        let source_binding = self.read_binding()?;
        let source_live = self.detect()?;
        let mut target_profile = self.find_profile_by_name(&request.name)?;
        let snapshot = self.load_snapshot(target_profile.id)?;
        let system_backup = self.read_system_records(&source_live.system_entries)?;
        let mut txn = SwitchTransaction {
            txn_id: Uuid::new_v4(),
            source_profile_id: source_binding.active_profile_id,
            source_live_fingerprint: source_live.live_fingerprint.clone(),
            target_profile_id: target_profile.id,
            started_at: Utc::now(),
            backup_paths: self.union_relative_paths(&source_live, &snapshot),
            backup_system_entries: source_live
                .system_entries
                .iter()
                .map(|entry| entry.reference.clone())
                .collect(),
            backup_system_records: system_backup,
            phase: SwitchPhase::Started,
            rollback_required: true,
        };
        self.write_transaction(&txn)?;
        self.backup_current_files(&txn.backup_paths, txn.txn_id)?;
        txn.phase = SwitchPhase::BackedUp;
        self.write_transaction(&txn)?;

        let switch_result: Result<()> = (|| {
            self.write_system_records(&snapshot.system_records)?;
            txn.phase = SwitchPhase::AppliedSystemSecrets;
            self.write_transaction(&txn)?;

            self.file_store.write_entries(&snapshot.file_entries)?;
            txn.phase = SwitchPhase::AppliedFiles;
            self.write_transaction(&txn)?;

            let binding = CurrentBinding {
                active_profile_id: Some(target_profile.id),
                live_fingerprint_at_bind: Some(snapshot.manifest.vault_fingerprint.clone()),
                last_sync_fingerprint: Some(snapshot.manifest.vault_fingerprint.clone()),
                last_check_at: Some(Utc::now()),
            };
            self.write_binding(&binding)?;
            txn.phase = SwitchPhase::BindingUpdated;
            self.write_transaction(&txn)?;

            if request.make_default {
                self.set_default_profile(Some(target_profile.id))?;
            }

            let validated = self.detect()?;
            if validated.live_fingerprint != snapshot.manifest.vault_fingerprint {
                return Err(SwitchError::ValidationFailed(format!(
                    "Post-switch validation failed for profile '{}'",
                    target_profile.name
                )));
            }

            txn.phase = SwitchPhase::Validated;
            txn.rollback_required = false;
            self.write_transaction(&txn)?;
            Ok(())
        })();

        if let Err(error) = switch_result {
            let rollback = self.rollback_transaction(&txn);
            return match rollback {
                Ok(()) => {
                    self.delete_transaction_artifacts(txn.txn_id)?;
                    Err(error)
                }
                Err(rollback_error) => Err(SwitchError::RollbackFailed(format!(
                    "{error}; rollback also failed: {rollback_error}"
                ))),
            };
        }

        self.delete_transaction_artifacts(txn.txn_id)?;
        target_profile.last_used_at = Some(Utc::now());
        target_profile.health = ProfileHealth {
            status: HealthStatus::Healthy,
            detail: "Profile is active and matches the live session.".to_string(),
            checked_at: Some(Utc::now()),
        };
        self.vault.write_profile_meta(&target_profile)?;
        self.append_audit("use", &format!("Switched to profile '{}'", target_profile.name))?;
        Ok(target_profile)
    }

    pub fn check_profile(&self, name: &str) -> Result<CheckReport> {
        self.ensure_layout()?;
        let mut profile = self.find_profile_by_name(name)?;
        let snapshot = self.load_snapshot(profile.id)?;
        let binding = self.read_binding()?;

        let (status, detail, drifted) = if binding.active_profile_id == Some(profile.id) {
            let live = self.detect()?;
            if live.live_fingerprint == snapshot.manifest.vault_fingerprint {
                (
                    HealthStatus::Healthy,
                    "Active profile matches the current live session.".to_string(),
                    false,
                )
            } else {
                (
                    HealthStatus::Drifted,
                    "The active profile differs from the current live session. Run `sync` to capture the refresh.".to_string(),
                    true,
                )
            }
        } else {
            (
                HealthStatus::Healthy,
                "Stored snapshot is structurally valid. No live comparison was possible because the profile is not active.".to_string(),
                false,
            )
        };

        profile.health =
            ProfileHealth { status, detail: detail.clone(), checked_at: Some(Utc::now()) };
        self.vault.write_profile_meta(&profile)?;
        Ok(CheckReport { profile, detail, drifted })
    }

    pub fn sync_active_profile(&self) -> Result<ProfileMeta> {
        self.ensure_layout()?;
        let binding = self.read_binding()?;
        let active_profile_id = binding.active_profile_id.ok_or_else(|| {
            SwitchError::State("No active profile is bound to the current live session".to_string())
        })?;
        let live = self.detect()?;
        let mut profile = self.read_profile_by_id(active_profile_id)?;
        let snapshot = self.snapshot_from_detected(&live, profile.id)?;
        profile.account_label_masked = live.account_label_masked.clone();
        profile.account_fingerprint = live.account_fingerprint.clone();
        profile.source_type = live.source_type;
        profile.credential_mode = live.credential_mode;
        profile.last_synced_at = Some(Utc::now());
        profile.health = ProfileHealth {
            status: HealthStatus::Healthy,
            detail: "Profile was refreshed from the current live session.".to_string(),
            checked_at: Some(Utc::now()),
        };
        self.vault.save(&profile, &snapshot)?;

        let updated_binding = CurrentBinding {
            active_profile_id: Some(profile.id),
            live_fingerprint_at_bind: Some(live.live_fingerprint.clone()),
            last_sync_fingerprint: Some(live.live_fingerprint.clone()),
            last_check_at: Some(Utc::now()),
        };
        self.write_binding(&updated_binding)?;
        self.append_audit("sync", &format!("Synced profile '{}' from live session", profile.name))?;
        Ok(profile)
    }

    pub fn rename_profile(&self, old_name: &str, new_name: &str) -> Result<ProfileMeta> {
        if self.find_profile_by_name_optional(new_name)?.is_some() {
            return Err(SwitchError::Conflict(format!(
                "A profile named '{}' already exists",
                new_name
            )));
        }
        let mut profile = self.find_profile_by_name(old_name)?;
        profile.name = new_name.to_string();
        self.vault.write_profile_meta(&profile)?;
        self.append_audit("rename", &format!("Renamed profile '{}' to '{}'", old_name, new_name))?;
        Ok(profile)
    }

    pub fn delete_profile(&self, name: &str) -> Result<()> {
        self.ensure_layout()?;
        let profile = self.find_profile_by_name(name)?;
        let mut binding = self.read_binding()?;
        if binding.active_profile_id == Some(profile.id) {
            binding = CurrentBinding::default();
            self.write_binding(&binding)?;
        }

        let config = self.read_config()?;
        if config.default_profile_id == Some(profile.id) {
            self.set_default_profile(None)?;
        }

        secure_delete(&self.paths.profiles_dir.join(profile.id.to_string()))?;
        secure_delete(&self.paths.vault_dir.join(format!("{}.bin", profile.id)))?;
        self.append_audit("delete", &format!("Deleted profile '{}'", profile.name))?;
        Ok(())
    }

    pub fn export_profile(
        &self,
        name: &str,
        passphrase: SecretString,
        output: Option<&Path>,
    ) -> Result<PathBuf> {
        let profile = self.find_profile_by_name(name)?;
        self.vault.export(&profile.id, passphrase, output)
    }

    pub fn import_profile(&self, path: &Path, passphrase: SecretString) -> Result<ProfileMeta> {
        self.ensure_layout()?;
        let (mut profile, mut snapshot) = self.vault.import(path, passphrase)?;
        if self.read_profile_by_id(profile.id).is_ok() {
            let new_id = Uuid::new_v4();
            profile.id = new_id;
            snapshot.manifest.profile_id = new_id;
        }
        profile.name = self.unique_import_name(&profile.name)?;
        profile.is_default = false;
        profile.health = ProfileHealth {
            status: HealthStatus::Healthy,
            detail: "Imported profile archive is ready to use.".to_string(),
            checked_at: Some(Utc::now()),
        };
        self.vault.save(&profile, &snapshot)?;
        self.append_audit("import", &format!("Imported profile '{}'", profile.name))?;
        Ok(profile)
    }

    pub fn load_snapshot(&self, profile_id: ProfileId) -> Result<SecretSnapshot> {
        self.vault.load(&profile_id)
    }

    pub fn read_audit_log(&self) -> Result<String> {
        if !self.paths.audit_log_file.exists() {
            return Ok(String::new());
        }
        Ok(fs::read_to_string(&self.paths.audit_log_file)?)
    }

    fn ensure_layout(&self) -> Result<()> {
        ensure_dir(&self.paths.data_dir)?;
        ensure_dir(&self.paths.profiles_dir)?;
        ensure_dir(&self.paths.vault_dir)?;
        ensure_dir(&self.paths.exports_dir)?;
        ensure_dir(&self.paths.tx_dir)?;
        ensure_dir(&self.paths.locks_dir)?;
        ensure_dir(&self.paths.logs_dir)?;
        Ok(())
    }

    fn read_profiles(&self) -> Result<Vec<ProfileMeta>> {
        let mut profiles = Vec::new();
        if !self.paths.profiles_dir.exists() {
            return Ok(profiles);
        }
        for entry in fs::read_dir(&self.paths.profiles_dir)? {
            let entry = entry?;
            let meta_path = entry.path().join("meta.json");
            if meta_path.exists() {
                let contents = fs::read_to_string(meta_path)?;
                profiles.push(serde_json::from_str(&contents)?);
            }
        }
        profiles.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(profiles)
    }

    fn find_profile_by_name(&self, name: &str) -> Result<ProfileMeta> {
        self.find_profile_by_name_optional(name)?
            .ok_or_else(|| SwitchError::NotFound(format!("Profile '{}' was not found", name)))
    }

    fn find_profile_by_name_optional(&self, name: &str) -> Result<Option<ProfileMeta>> {
        Ok(self.read_profiles()?.into_iter().find(|profile| profile.name == name))
    }

    fn read_profile_by_id(&self, profile_id: ProfileId) -> Result<ProfileMeta> {
        self.vault.read_profile_meta(&profile_id)
    }

    fn read_binding(&self) -> Result<CurrentBinding> {
        if !self.paths.current_binding_file.exists() {
            return Ok(CurrentBinding::default());
        }
        let contents = fs::read_to_string(&self.paths.current_binding_file)?;
        Ok(serde_json::from_str(&contents)?)
    }

    fn write_binding(&self, binding: &CurrentBinding) -> Result<()> {
        atomic_write(&self.paths.current_binding_file, &serde_json::to_vec_pretty(binding)?)
    }

    fn read_config(&self) -> Result<AppConfig> {
        if !self.paths.config_file.exists() {
            return Ok(AppConfig::default());
        }
        let contents = fs::read_to_string(&self.paths.config_file)?;
        Ok(serde_json::from_str(&contents)?)
    }

    fn write_config(&self, config: &AppConfig) -> Result<()> {
        atomic_write(&self.paths.config_file, &serde_json::to_vec_pretty(config)?)
    }

    fn set_default_profile(&self, default_profile_id: Option<ProfileId>) -> Result<()> {
        let profiles = self.read_profiles()?;
        for mut profile in profiles {
            profile.is_default = Some(profile.id) == default_profile_id;
            self.vault.write_profile_meta(&profile)?;
        }
        self.write_config(&AppConfig { default_profile_id })
    }

    fn append_audit(&self, action: &str, detail: &str) -> Result<()> {
        ensure_dir(&self.paths.logs_dir)?;
        let mut file =
            OpenOptions::new().create(true).append(true).open(&self.paths.audit_log_file)?;
        writeln!(file, "{}\t{}\t{}", Utc::now().to_rfc3339(), action, detail)?;
        Ok(())
    }

    fn snapshot_from_detected(
        &self,
        live: &DetectedSession,
        profile_id: ProfileId,
    ) -> Result<SecretSnapshot> {
        let refs =
            live.system_entries.iter().map(|entry| entry.reference.clone()).collect::<Vec<_>>();
        let system_records = self.read_system_records(&live.system_entries)?;
        Ok(SecretSnapshot {
            manifest: codex_switch_domain::ProfileVaultManifest {
                schema_version: 1,
                profile_id,
                encrypted: self.local_encryption_enabled,
                file_entries: live
                    .file_entries
                    .iter()
                    .map(|entry| entry.relative_path.clone())
                    .collect(),
                system_entries: refs,
                vault_fingerprint: live.live_fingerprint.clone(),
            },
            file_entries: live.file_entries.clone(),
            system_records,
        })
    }

    fn read_system_records(
        &self,
        entries: &[codex_switch_domain::SystemEntry],
    ) -> Result<Vec<SecretRecord>> {
        if entries.is_empty() {
            return Ok(Vec::new());
        }
        let refs = entries.iter().map(|entry| entry.reference.clone()).collect::<Vec<_>>();
        self.current_system_store()?.read(&refs)
    }

    fn write_system_records(&self, records: &[SecretRecord]) -> Result<()> {
        if records.is_empty() {
            return Ok(());
        }
        self.current_system_store()?.write(records)
    }

    fn current_system_store(&self) -> Result<&dyn OfficialCredentialStore> {
        self.system_stores
            .iter()
            .find(|store| store.is_available())
            .map(|store| store.as_ref())
            .ok_or_else(|| {
                SwitchError::CredentialUnavailable(
                    "No system credential store is available on this platform".to_string(),
                )
            })
    }

    fn lock_path(&self) -> PathBuf {
        self.paths.locks_dir.join("switch.lock")
    }

    fn transaction_file_path(&self, txn_id: Uuid) -> PathBuf {
        self.paths.tx_dir.join(format!("{txn_id}.json"))
    }

    fn transaction_backup_root(&self, txn_id: Uuid) -> PathBuf {
        self.paths.tx_dir.join(txn_id.to_string()).join("backup")
    }

    fn write_transaction(&self, txn: &SwitchTransaction) -> Result<()> {
        atomic_write(&self.transaction_file_path(txn.txn_id), &serde_json::to_vec_pretty(txn)?)
    }

    fn delete_transaction_artifacts(&self, txn_id: Uuid) -> Result<()> {
        secure_delete(&self.transaction_file_path(txn_id))?;
        secure_delete(&self.paths.tx_dir.join(txn_id.to_string()))
    }

    fn recover_interrupted_transactions(&self) -> Result<()> {
        for path in list_json_files(&self.paths.tx_dir)? {
            let contents = fs::read_to_string(&path)?;
            let txn: SwitchTransaction = serde_json::from_str(&contents)?;
            if txn.rollback_required {
                self.rollback_transaction(&txn)?;
                self.append_audit(
                    "recover",
                    &format!("Recovered interrupted switch {}", txn.txn_id),
                )?;
            }
            self.delete_transaction_artifacts(txn.txn_id)?;
        }
        Ok(())
    }

    fn backup_current_files(&self, relative_paths: &[String], txn_id: Uuid) -> Result<()> {
        let backup_root = self.transaction_backup_root(txn_id);
        ensure_dir(&backup_root)?;
        for relative_path in relative_paths {
            let source = self.paths.codex_home.join(relative_path);
            if !source.exists() {
                continue;
            }
            let backup_path = backup_root.join(relative_path);
            if let Some(parent) = backup_path.parent() {
                ensure_dir(parent)?;
            }
            fs::copy(source, backup_path)?;
        }
        Ok(())
    }

    fn rollback_transaction(&self, txn: &SwitchTransaction) -> Result<()> {
        if !txn.backup_system_records.is_empty() {
            self.write_system_records(&txn.backup_system_records)?;
        }
        let backup_root = self.transaction_backup_root(txn.txn_id);
        for relative_path in &txn.backup_paths {
            let source = backup_root.join(relative_path);
            let destination = self.paths.codex_home.join(relative_path);
            if source.exists() {
                atomic_write(&destination, &fs::read(source)?)?;
            } else if destination.exists() {
                secure_delete(&destination)?;
            }
        }
        let restored_binding = CurrentBinding {
            active_profile_id: txn.source_profile_id,
            live_fingerprint_at_bind: txn
                .source_profile_id
                .map(|_| txn.source_live_fingerprint.clone()),
            last_sync_fingerprint: txn
                .source_profile_id
                .map(|_| txn.source_live_fingerprint.clone()),
            last_check_at: Some(Utc::now()),
        };
        self.write_binding(&restored_binding)?;
        let live = self.detect()?;
        if live.live_fingerprint != txn.source_live_fingerprint {
            return Err(SwitchError::RollbackFailed(
                "Rollback restored files, but live fingerprint no longer matches the pre-switch state"
                    .to_string(),
            ));
        }
        Ok(())
    }

    fn union_relative_paths(
        &self,
        source_live: &DetectedSession,
        snapshot: &SecretSnapshot,
    ) -> Vec<String> {
        let mut paths = source_live
            .file_entries
            .iter()
            .map(|entry| entry.relative_path.clone())
            .collect::<Vec<_>>();
        for relative_path in snapshot.file_entries.iter().map(|entry| entry.relative_path.clone()) {
            if !paths.contains(&relative_path) {
                paths.push(relative_path);
            }
        }
        paths
    }

    fn unique_import_name(&self, requested_name: &str) -> Result<String> {
        if self.find_profile_by_name_optional(requested_name)?.is_none() {
            return Ok(requested_name.to_string());
        }

        let imported = format!("{requested_name}-imported");
        if self.find_profile_by_name_optional(&imported)?.is_none() {
            return Ok(imported);
        }

        let mut index = 2;
        loop {
            let candidate = format!("{requested_name}-imported-{index}");
            if self.find_profile_by_name_optional(&candidate)?.is_none() {
                return Ok(candidate);
            }
            index += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use base64::Engine as _;
    use codex_switch_platform::inspect::inspect_auth_json;
    use secrecy::SecretString;
    use tempfile::tempdir;

    use super::*;
    use codex_switch_domain::SourceType;

    fn sample_auth(account: &str, last_refresh: &str) -> String {
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(r#"{"email":"person@example.com"}"#);
        format!(
            r#"{{
                "auth_mode":"chatgpt",
                "last_refresh":"{last_refresh}",
                "tokens": {{
                    "id_token":"aaa.{payload}.ccc",
                    "access_token":"access-{account}",
                    "refresh_token":"refresh-{account}",
                    "account_id":"{account}"
                }}
            }}"#
        )
    }

    #[test]
    fn save_use_sync_and_export_round_trip() {
        let temp = tempdir().expect("tempdir");
        let codex_home = temp.path().join("codex-home");
        let app_home = temp.path().join("app-home");
        fs::create_dir_all(&codex_home).expect("codex_home");
        fs::write(codex_home.join("auth.json"), sample_auth("acct-alpha", "2026-04-13T00:00:00Z"))
            .expect("auth");

        let manager = ManagerService::new(ManagerOptions {
            codex_home_override: Some(codex_home.clone()),
            data_dir_override: Some(app_home.clone()),
            local_passphrase: None,
        })
        .expect("manager");

        let saved = manager
            .save_profile(SaveProfileRequest {
                name: "alpha".to_string(),
                note: Some("personal".to_string()),
                make_default: true,
            })
            .expect("save");
        assert_eq!(saved.name, "alpha");

        fs::write(codex_home.join("auth.json"), sample_auth("acct-beta", "2026-04-13T01:00:00Z"))
            .expect("auth2");

        let second = manager
            .save_profile(SaveProfileRequest {
                name: "beta".to_string(),
                note: None,
                make_default: false,
            })
            .expect("save");
        assert_eq!(second.name, "beta");

        manager
            .use_profile(UseProfileRequest { name: "alpha".to_string(), make_default: false })
            .expect("use");

        let current = manager.current_status().expect("current");
        assert_eq!(current.live_session.account_fingerprint, saved.account_fingerprint);

        fs::write(
            codex_home.join("auth.json"),
            sample_auth("acct-alpha-new", "2026-04-13T02:00:00Z"),
        )
        .expect("auth3");
        let synced = manager.sync_active_profile().expect("sync");
        let report = manager.check_profile("alpha").expect("check");
        assert_eq!(synced.name, "alpha");
        assert!(!report.drifted);

        let archive = manager
            .export_profile("alpha", SecretString::new("export-pass".into()), None)
            .expect("export");
        let imported = manager
            .import_profile(&archive, SecretString::new("export-pass".into()))
            .expect("import");
        assert_eq!(imported.name, "alpha-imported");
    }

    #[test]
    fn check_profile_flags_drift_for_active_profile() {
        let temp = tempdir().expect("tempdir");
        let codex_home = temp.path().join("codex-home");
        let app_home = temp.path().join("app-home");
        fs::create_dir_all(&codex_home).expect("codex_home");
        fs::write(codex_home.join("auth.json"), sample_auth("acct-alpha", "2026-04-13T00:00:00Z"))
            .expect("auth");
        let manager = ManagerService::new(ManagerOptions {
            codex_home_override: Some(codex_home.clone()),
            data_dir_override: Some(app_home.clone()),
            local_passphrase: None,
        })
        .expect("manager");
        manager
            .save_profile(SaveProfileRequest {
                name: "alpha".to_string(),
                note: None,
                make_default: false,
            })
            .expect("save");
        manager
            .use_profile(UseProfileRequest { name: "alpha".to_string(), make_default: false })
            .expect("use");
        fs::write(
            codex_home.join("auth.json"),
            sample_auth("acct-alpha-drifted", "2026-04-13T03:00:00Z"),
        )
        .expect("mutate");

        let report = manager.check_profile("alpha").expect("report");
        assert!(report.drifted);
    }

    #[test]
    fn detect_uses_same_shape_as_live_auth_file() {
        let temp = tempdir().expect("tempdir");
        let auth_path = temp.path().join("auth.json");
        let contents = sample_auth("acct-shape", "2026-04-13T00:00:00Z");
        fs::write(&auth_path, &contents).expect("write");
        let inspection = inspect_auth_json(&contents).expect("inspect");
        assert_eq!(inspection.source_type, SourceType::ChatGpt);
        assert_eq!(inspection.account_label_masked, "pe***@example.com");
    }
}
