use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use chrono::Utc;
use codex_switch_domain::session::mask_account_label;
use codex_switch_domain::{
    AuthMode, CurrentBinding, DetectedSession, HealthStatus, OfficialCredentialStore,
    ProfileHealth, ProfileId, ProfileMeta, Result, SecretRecord, SecretSnapshot, SessionDetector,
    SwitchError, SwitchPhase, SwitchTransaction, traits::ProfileVault as _,
};
use codex_switch_platform::{
    AuthJsonSessionDetector, CredentialDiscoveryRegistry, CredentialDiscoveryRule,
    CredentialDiscoveryTraceEntry, CredentialDiscoveryTraceStatus, FileCredentialStore,
    GlobalSwitchLock, LinuxKeyringCredentialStore, LocalProfileVault, MacKeychainCredentialStore,
    PathResolver, WindowsCredentialStore, default_store_diagnostics,
    fs_secure::{atomic_write, ensure_dir, list_json_files, secure_delete},
    inspect::inspect_auth_json,
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
    pub live_session: LiveSessionSummary,
    pub active_profile: Option<ProfileMeta>,
    pub binding: CurrentBinding,
    pub sync_state: CurrentSyncState,
}

#[derive(Debug, Clone, Serialize)]
pub struct RedactedFileEntry {
    pub relative_path: String,
    pub permissions: Option<u32>,
    pub byte_length: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct RedactedSystemEntry {
    pub service: String,
    pub account_label_masked: String,
    pub label: Option<String>,
    pub masked_value_hint: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct LiveSessionSummary {
    pub codex_home: String,
    pub auth_mode: AuthMode,
    pub account_label_masked: String,
    pub account_fingerprint: String,
    pub source_type: codex_switch_domain::SourceType,
    pub credential_mode: codex_switch_domain::CredentialMode,
    pub file_entries: Vec<RedactedFileEntry>,
    pub system_entries: Vec<RedactedSystemEntry>,
    pub last_refresh_at: Option<chrono::DateTime<Utc>>,
    pub live_fingerprint: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CurrentSyncStatus {
    NoActiveProfile,
    InSync,
    NeedsSync,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CurrentSyncState {
    pub status: CurrentSyncStatus,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CheckReport {
    pub profile: ProfileMeta,
    pub detail: String,
    pub drifted: bool,
    pub preflight: ProfilePreflightReport,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProfilePreflightReport {
    pub ready: bool,
    pub required_file_entries: usize,
    pub required_system_entries: usize,
    pub blockers: Vec<String>,
    pub warnings: Vec<String>,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DoctorPathStatus {
    pub path: String,
    pub exists: bool,
    pub readable: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct DoctorLiveSessionStatus {
    pub detected: bool,
    pub detail: String,
    pub account_label_masked: Option<String>,
    pub source_type: Option<codex_switch_domain::SourceType>,
    pub credential_mode: Option<codex_switch_domain::CredentialMode>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DoctorProfileReadiness {
    pub profile_name: String,
    pub account_label_masked: String,
    pub credential_mode: codex_switch_domain::CredentialMode,
    pub status: String,
    pub blocker_count: usize,
    pub warning_count: usize,
    pub detail: String,
    pub blockers: Vec<String>,
    pub warnings: Vec<String>,
    pub source_operating_system: String,
    pub source_system_store_name: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DoctorStoreUsageSummary {
    pub store_name: String,
    pub profile_count: usize,
    pub ready_count: usize,
    pub warning_count: usize,
    pub blocked_count: usize,
    pub supported: Option<bool>,
    pub available: Option<bool>,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DoctorValidationStatus {
    Ready,
    FileOnly,
    Blocked,
}

#[derive(Debug, Clone, Serialize)]
pub struct DoctorValidationSummary {
    pub status: DoctorValidationStatus,
    pub detail: String,
    pub active_store_name: Option<String>,
    pub ready_profile_count: usize,
    pub warning_profile_count: usize,
    pub blocked_profile_count: usize,
    pub mixed_profile_count: usize,
    pub next_steps: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DoctorValidationCoverageSummary {
    pub file_backed_recorded: bool,
    pub mixed_mode_required: bool,
    pub mixed_mode_recorded: bool,
    pub covered_platform_count: usize,
    pub total_platform_count: usize,
    pub missing_platforms: Vec<String>,
    pub detail: String,
    pub next_target: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DoctorPlatformEvidence {
    pub operating_system: String,
    pub evidence_count: usize,
    pub latest_recorded_at: Option<chrono::DateTime<Utc>>,
    pub latest_validation_status: Option<DoctorValidationStatus>,
    pub latest_store_name: Option<String>,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DoctorReport {
    pub operating_system: String,
    pub codex_home: String,
    pub data_dir: String,
    pub auth_file: DoctorPathStatus,
    pub discovery_rule_count: usize,
    pub live_session: DoctorLiveSessionStatus,
    pub discovery_trace: DiscoveryTraceReport,
    pub switch_probes: SwitchProbeReport,
    pub stores: Vec<codex_switch_platform::StoreDiagnostic>,
    pub recovery: RecoveryStatus,
    pub profile_readiness: Vec<DoctorProfileReadiness>,
    pub store_usage: Vec<DoctorStoreUsageSummary>,
    pub validation: DoctorValidationSummary,
    pub validation_coverage: DoctorValidationCoverageSummary,
    pub validation_evidence: Vec<DoctorPlatformEvidence>,
    pub recommended_actions: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProbeStatus {
    pub ok: bool,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SwitchProbeReport {
    pub data_dir_write: ProbeStatus,
    pub lock_acquire: ProbeStatus,
    pub atomic_swap: ProbeStatus,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DiscoveryTraceReport {
    pub matched_count: usize,
    pub missing_input_count: usize,
    pub lookup_missed_count: usize,
    pub blocked_count: usize,
    pub entries: Vec<CredentialDiscoveryTraceEntry>,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PendingTransactionSummary {
    pub txn_id: String,
    pub started_at: chrono::DateTime<Utc>,
    pub phase: SwitchPhase,
    pub rollback_required: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct RecoveryStatus {
    pub pending_count: usize,
    pub rollback_required_count: usize,
    pub transactions: Vec<PendingTransactionSummary>,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RecoveryReport {
    pub recovered_count: usize,
    pub removed_count: usize,
    pub transactions: Vec<PendingTransactionSummary>,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DiagnosticBundle {
    pub schema_version: u32,
    pub generated_at: chrono::DateTime<Utc>,
    pub local_encryption_enabled: bool,
    pub doctor: DoctorReport,
    pub current: Option<CurrentStatus>,
    pub profiles: Vec<ProfileMeta>,
    pub audit_log_tail: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct AppConfig {
    default_profile_id: Option<ProfileId>,
    #[serde(default)]
    credential_discovery_rules: Vec<CredentialDiscoveryRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ValidationEvidenceRecord {
    recorded_at: chrono::DateTime<Utc>,
    operating_system: String,
    validation_status: DoctorValidationStatus,
    active_store_name: Option<String>,
    live_session_detected: bool,
    bundle_path: String,
    ready_profile_count: usize,
    warning_profile_count: usize,
    blocked_profile_count: usize,
    mixed_profile_count: usize,
}

pub struct ManagerService {
    paths: AppPaths,
    detector: AuthJsonSessionDetector,
    discovery_registry: CredentialDiscoveryRegistry,
    file_store: FileCredentialStore,
    vault: LocalProfileVault,
    system_stores: Vec<Box<dyn OfficialCredentialStore>>,
    discovery_rule_count: usize,
    local_encryption_enabled: bool,
}

impl std::fmt::Debug for ManagerService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ManagerService")
            .field("paths", &self.paths)
            .field("discovery_rule_count", &self.discovery_rule_count)
            .field("local_encryption_enabled", &self.local_encryption_enabled)
            .finish()
    }
}

impl ManagerService {
    const DIAGNOSTIC_BUNDLE_SCHEMA_VERSION: u32 = 1;

    pub fn new(options: ManagerOptions) -> Result<Self> {
        let paths = PathResolver::discover(options.codex_home_override, options.data_dir_override)?;
        let registry = Self::load_discovery_registry(&paths.config_file)?;
        Self::from_parts(
            paths,
            options.local_passphrase,
            registry,
            default_system_stores(),
            default_system_stores(),
        )
    }

    fn from_parts(
        paths: AppPaths,
        local_passphrase: Option<SecretString>,
        registry: CredentialDiscoveryRegistry,
        system_stores: Vec<Box<dyn OfficialCredentialStore>>,
        detector_system_stores: Vec<Box<dyn OfficialCredentialStore>>,
    ) -> Result<Self> {
        let discovery_rule_count = registry.rule_count();
        let file_store = FileCredentialStore::new(paths.codex_home.clone());
        let detector = AuthJsonSessionDetector::with_registry(
            file_store.clone(),
            registry.clone(),
            detector_system_stores,
        );
        let vault = LocalProfileVault::new(
            paths.profiles_dir.clone(),
            paths.vault_dir.clone(),
            paths.exports_dir.clone(),
            local_passphrase.clone(),
        );
        let service = Self {
            paths,
            detector,
            discovery_registry: registry,
            file_store,
            vault,
            system_stores,
            discovery_rule_count,
            local_encryption_enabled: local_passphrase.is_some(),
        };
        service.ensure_layout()?;
        Ok(service)
    }

    pub fn detect(&self) -> Result<DetectedSession> {
        self.detector.detect()
    }

    pub fn detect_report(&self) -> Result<LiveSessionSummary> {
        self.detect().map(|session| Self::summarize_detected(&session))
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
        let sync_state =
            self.build_current_sync_state(&live_session, &binding, active_profile.as_ref());
        Ok(CurrentStatus {
            live_session: Self::summarize_detected(&live_session),
            active_profile,
            binding,
            sync_state,
        })
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

        let (healthy_detail, drifted, is_active) = if binding.active_profile_id == Some(profile.id)
        {
            let live = self.detect()?;
            if live.live_fingerprint == snapshot.manifest.vault_fingerprint {
                ("Active profile matches the current live session.".to_string(), false, true)
            } else {
                (
                    "The active profile differs from the current live session. Run `sync` to capture the refresh.".to_string(),
                    true,
                    true,
                )
            }
        } else {
            (
                "Stored snapshot is structurally valid. No live comparison was possible because the profile is not active.".to_string(),
                false,
                false,
            )
        };

        let preflight = self.build_profile_preflight(&snapshot, drifted);
        let health =
            self.derive_checked_profile_health(&preflight, drifted, is_active, &healthy_detail);
        let detail = health.detail.clone();
        profile.health = health;
        self.vault.write_profile_meta(&profile)?;
        Ok(CheckReport { profile, detail, drifted, preflight })
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

    pub fn doctor_report(&self) -> Result<DoctorReport> {
        self.ensure_layout()?;
        let auth_path = self.file_store.auth_path();
        let auth_file_exists = auth_path.exists();
        let auth_file_readable = auth_path.is_file() && fs::read_to_string(&auth_path).is_ok();
        let live_detection = self.detect();
        let live_session = match &live_detection {
            Ok(session) => DoctorLiveSessionStatus {
                detected: true,
                detail: "Live session detected from the current local state.".to_string(),
                account_label_masked: Some(session.account_label_masked.clone()),
                source_type: Some(session.source_type),
                credential_mode: Some(session.credential_mode),
            },
            Err(error) => DoctorLiveSessionStatus {
                detected: false,
                detail: error.to_string(),
                account_label_masked: None,
                source_type: None,
                credential_mode: None,
            },
        };
        let stores = default_store_diagnostics();
        let discovery_trace = self.build_discovery_trace();
        let switch_probes = self.run_switch_probes();
        let recovery = self.inspect_recovery_status()?;
        let binding = self.read_binding()?;
        let profile_readiness =
            self.build_doctor_profile_readiness(&binding, live_detection.as_ref().ok())?;
        let store_usage = Self::build_doctor_store_usage(&profile_readiness, &stores);
        let validation_evidence = self.build_validation_evidence()?;
        let validation = self.build_doctor_validation_summary(
            auth_file_exists,
            &live_session,
            &switch_probes,
            &recovery,
            &profile_readiness,
        );
        let validation_coverage =
            self.build_validation_coverage(&validation, &self.read_validation_evidence_records()?);
        let recommended_actions = self.build_doctor_recommendations(
            auth_file_exists,
            &live_session,
            &discovery_trace,
            &switch_probes,
            &stores,
            &recovery,
            &profile_readiness,
            &store_usage,
            &validation,
            &validation_coverage,
            &validation_evidence,
        );

        Ok(DoctorReport {
            operating_system: std::env::consts::OS.to_string(),
            codex_home: self.paths.codex_home.display().to_string(),
            data_dir: self.paths.data_dir.display().to_string(),
            auth_file: DoctorPathStatus {
                path: auth_path.display().to_string(),
                exists: auth_file_exists,
                readable: auth_file_readable,
            },
            discovery_rule_count: self.discovery_rule_count,
            live_session,
            discovery_trace,
            switch_probes,
            stores,
            recovery,
            profile_readiness,
            store_usage,
            validation,
            validation_coverage,
            validation_evidence,
            recommended_actions,
        })
    }

    pub fn recover_pending_transactions(&self) -> Result<RecoveryReport> {
        self.ensure_layout()?;
        let _guard = GlobalSwitchLock::acquire(self.lock_path())?;
        let transactions = self.read_pending_transactions()?;
        let summaries = transactions.iter().map(Self::summarize_transaction).collect::<Vec<_>>();
        let mut recovered_count = 0usize;
        let mut removed_count = 0usize;

        for txn in &transactions {
            if txn.rollback_required {
                self.rollback_transaction(txn)?;
                self.append_audit(
                    "recover",
                    &format!("Recovered interrupted switch {}", txn.txn_id),
                )?;
                recovered_count += 1;
            }
            self.delete_transaction_artifacts(txn.txn_id)?;
            removed_count += 1;
        }

        let detail = if removed_count == 0 {
            "No interrupted switch transactions were waiting for recovery.".to_string()
        } else if recovered_count == removed_count {
            format!("Recovered and cleared {removed_count} interrupted switch transaction(s).")
        } else {
            format!(
                "Cleared {removed_count} interrupted switch transaction(s), including {recovered_count} rollback restoration(s)."
            )
        };

        Ok(RecoveryReport { recovered_count, removed_count, transactions: summaries, detail })
    }

    pub fn export_diagnostic_bundle(&self, output: Option<&Path>) -> Result<PathBuf> {
        self.ensure_layout()?;
        let doctor = self.doctor_report()?;
        let current = self.current_status().ok();
        let profiles = self.list_profiles()?;
        let bundle = DiagnosticBundle {
            schema_version: Self::DIAGNOSTIC_BUNDLE_SCHEMA_VERSION,
            generated_at: Utc::now(),
            local_encryption_enabled: self.local_encryption_enabled,
            doctor,
            current,
            profiles,
            audit_log_tail: self.recent_audit_entries(50)?,
        };

        let destination = output.map(PathBuf::from).unwrap_or_else(|| {
            let timestamp = bundle.generated_at.format("%Y%m%dT%H%M%SZ");
            self.paths.exports_dir.join(format!("diagnostic-bundle-{timestamp}.json"))
        });
        let payload = serde_json::to_vec_pretty(&bundle)?;
        atomic_write(&destination, &payload)?;
        self.record_validation_evidence(&bundle, &destination)?;
        self.append_audit(
            "bundle",
            &format!("Exported diagnostic bundle to {}", destination.display()),
        )?;
        Ok(destination)
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

    pub fn set_default_profile_by_name(&self, name: &str) -> Result<ProfileMeta> {
        self.ensure_layout()?;
        let profile = self.find_profile_by_name(name)?;
        self.set_default_profile(Some(profile.id))?;
        let updated = self.read_profile_by_id(profile.id)?;
        self.append_audit("default", &format!("Set profile '{}' as default", updated.name))?;
        Ok(updated)
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
        let preflight = self.build_profile_preflight(&snapshot, false);
        profile.health = self.derive_imported_profile_health(&preflight);
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
        ensure_dir(&self.paths.validation_dir)?;
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

    fn build_current_sync_state(
        &self,
        live_session: &DetectedSession,
        binding: &CurrentBinding,
        active_profile: Option<&ProfileMeta>,
    ) -> CurrentSyncState {
        if binding.active_profile_id.is_none() {
            return CurrentSyncState {
                status: CurrentSyncStatus::NoActiveProfile,
                detail: "No active profile is currently bound to the live session.".to_string(),
            };
        }

        if active_profile.is_none() {
            return CurrentSyncState {
                status: CurrentSyncStatus::Unknown,
                detail: "The current binding points to a profile that is no longer available."
                    .to_string(),
            };
        }

        let baseline = binding
            .last_sync_fingerprint
            .as_deref()
            .or(binding.live_fingerprint_at_bind.as_deref());

        match baseline {
            Some(fingerprint) if fingerprint == live_session.live_fingerprint => CurrentSyncState {
                status: CurrentSyncStatus::InSync,
                detail: "The active profile is synced with the current live session.".to_string(),
            },
            Some(_) => CurrentSyncState {
                status: CurrentSyncStatus::NeedsSync,
                detail:
                    "The live session has changed since the active profile was last synced. Run sync to capture refreshed credentials."
                        .to_string(),
            },
            None => CurrentSyncState {
                status: CurrentSyncStatus::Unknown,
                detail: "The active profile is bound, but no sync baseline is available yet."
                    .to_string(),
            },
        }
    }

    fn summarize_detected(session: &DetectedSession) -> LiveSessionSummary {
        LiveSessionSummary {
            codex_home: session.codex_home.clone(),
            auth_mode: session.auth_mode,
            account_label_masked: session.account_label_masked.clone(),
            account_fingerprint: session.account_fingerprint.clone(),
            source_type: session.source_type,
            credential_mode: session.credential_mode,
            file_entries: session
                .file_entries
                .iter()
                .map(|entry| RedactedFileEntry {
                    relative_path: entry.relative_path.clone(),
                    permissions: entry.permissions,
                    byte_length: entry.contents.len(),
                })
                .collect(),
            system_entries: session
                .system_entries
                .iter()
                .map(|entry| RedactedSystemEntry {
                    service: entry.reference.service.clone(),
                    account_label_masked: mask_account_label(&entry.reference.account),
                    label: entry.reference.label.clone(),
                    masked_value_hint: entry.masked_value_hint.clone(),
                })
                .collect(),
            last_refresh_at: session.last_refresh_at,
            live_fingerprint: session.live_fingerprint.clone(),
        }
    }

    fn build_doctor_recommendations(
        &self,
        auth_file_exists: bool,
        live_session: &DoctorLiveSessionStatus,
        discovery_trace: &DiscoveryTraceReport,
        switch_probes: &SwitchProbeReport,
        stores: &[codex_switch_platform::StoreDiagnostic],
        recovery: &RecoveryStatus,
        profile_readiness: &[DoctorProfileReadiness],
        store_usage: &[DoctorStoreUsageSummary],
        validation: &DoctorValidationSummary,
        validation_coverage: &DoctorValidationCoverageSummary,
        validation_evidence: &[DoctorPlatformEvidence],
    ) -> Vec<String> {
        let mut recommendations = Vec::new();

        if !auth_file_exists {
            recommendations.push(
                "Run one official login on this machine so the client can create auth.json."
                    .to_string(),
            );
        }

        if !live_session.detected {
            recommendations.push(
                "Re-run detect or doctor after the official client has completed a login."
                    .to_string(),
            );
        }

        if !stores.iter().any(|store| store.available) {
            recommendations.push(
                "No supported system credential store is currently available, so file-backed sessions will be the most reliable path."
                    .to_string(),
            );
        }

        recommendations.push(validation_coverage.next_target.clone());

        match validation.status {
            DoctorValidationStatus::Ready => recommendations.push(
                "This machine is ready for platform validation. Run a switch round-trip, then export a diagnostic bundle as evidence."
                    .to_string(),
            ),
            DoctorValidationStatus::FileOnly => recommendations.push(
                "This machine is ready for file-backed validation, but mixed-mode validation should wait for a machine with the target system credential store."
                    .to_string(),
            ),
            DoctorValidationStatus::Blocked => recommendations.push(
                "This machine is not ready for a validation pass yet. Clear the blocking auth or switch-probe issues first."
                    .to_string(),
            ),
        }

        recommendations.push(
            "If your official service/account names differ from the defaults, add credential_discovery_rules to config.json."
                .to_string(),
        );

        if live_session.detected
            && discovery_trace.lookup_missed_count > 0
            && discovery_trace.matched_count == 0
        {
            recommendations.push(
                "Review the discovery trace to see which service/account combinations were attempted but not found in the system store."
                    .to_string(),
            );
        }

        if live_session.detected && discovery_trace.missing_input_count > 0 {
            recommendations.push(
                "Some discovery rules could not expand because auth.json does not contain every expected identity field."
                    .to_string(),
            );
        }

        if !switch_probes.data_dir_write.ok
            || !switch_probes.lock_acquire.ok
            || !switch_probes.atomic_swap.ok
        {
            recommendations.push(
                "One or more non-destructive switch probes failed. Review data-dir, lock, and atomic-swap readiness before switching profiles on this machine."
                    .to_string(),
            );
        }

        if recovery.pending_count > 0 {
            recommendations.push(
                "Interrupted switch state was found. Run recover before saving or switching profiles again."
                    .to_string(),
            );
        }

        let blocked_profiles =
            profile_readiness.iter().filter(|profile| profile.status == "blocked").count();
        let warning_profiles =
            profile_readiness.iter().filter(|profile| profile.status == "warning").count();

        if blocked_profiles > 0 {
            recommendations.push(format!(
                "{blocked_profiles} blocked profile inventory entr{} need machine-specific attention before switching.",
                if blocked_profiles == 1 { "y" } else { "ies" }
            ));
        }

        if warning_profiles > 0 {
            recommendations.push(format!(
                "{warning_profiles} saved profile{} have compatibility warnings. Review the profile inventory or run check <name> before switching.",
                if warning_profiles == 1 { "" } else { "s" }
            ));
        }

        for usage in store_usage
            .iter()
            .filter(|usage| usage.store_name != "file_only" && usage.blocked_count > 0)
        {
            recommendations.push(format!(
                "{} currently has {} blocked saved profile(s). Review the store summary before switching those profiles on this machine.",
                usage.store_name,
                usage.blocked_count
            ));
        }

        let missing_platforms = validation_evidence
            .iter()
            .filter(|entry| entry.evidence_count == 0)
            .map(|entry| entry.operating_system.as_str())
            .collect::<Vec<_>>();
        if !missing_platforms.is_empty() {
            recommendations.push(format!(
                "Validation evidence is still missing for: {}.",
                missing_platforms.join(", ")
            ));
        }

        recommendations
    }

    fn build_validation_evidence(&self) -> Result<Vec<DoctorPlatformEvidence>> {
        use std::collections::BTreeMap;

        let records = self.read_validation_evidence_records()?;
        let mut grouped: BTreeMap<String, Vec<ValidationEvidenceRecord>> = BTreeMap::new();
        for record in records {
            grouped.entry(record.operating_system.clone()).or_default().push(record);
        }
        for platform in ["macos", "windows", "linux"] {
            grouped.entry(platform.to_string()).or_default();
        }

        Ok(grouped
            .into_iter()
            .map(|(operating_system, mut records)| {
                records.sort_by_key(|record| record.recorded_at);
                let latest = records.last();
                let detail = if let Some(latest) = latest {
                    format!(
                        "Latest evidence captured at {} with status {:?} via {}.",
                        latest.recorded_at.to_rfc3339(),
                        latest.validation_status,
                        latest.active_store_name.as_deref().unwrap_or("file-backed")
                    )
                } else {
                    format!(
                        "No validation evidence has been recorded for {} yet.",
                        operating_system
                    )
                };

                DoctorPlatformEvidence {
                    operating_system,
                    evidence_count: records.len(),
                    latest_recorded_at: latest.map(|record| record.recorded_at),
                    latest_validation_status: latest.map(|record| record.validation_status),
                    latest_store_name: latest.and_then(|record| record.active_store_name.clone()),
                    detail,
                }
            })
            .collect())
    }

    fn build_validation_coverage(
        &self,
        validation: &DoctorValidationSummary,
        records: &[ValidationEvidenceRecord],
    ) -> DoctorValidationCoverageSummary {
        use std::collections::BTreeSet;

        let tracked_platforms = ["macos", "windows", "linux"];
        let covered_platforms =
            records.iter().map(|record| record.operating_system.clone()).collect::<BTreeSet<_>>();
        let missing_platforms = tracked_platforms
            .into_iter()
            .filter(|platform| !covered_platforms.contains(*platform))
            .map(str::to_string)
            .collect::<Vec<_>>();
        let file_backed_recorded = records.iter().any(|record| {
            matches!(
                record.validation_status,
                DoctorValidationStatus::FileOnly | DoctorValidationStatus::Ready
            )
        });
        let mixed_mode_required = validation.mixed_profile_count > 0;
        let mixed_mode_recorded =
            records.iter().any(|record| record.validation_status == DoctorValidationStatus::Ready);
        let current_os = std::env::consts::OS.to_string();
        let current_platform_recorded = covered_platforms.contains(&current_os);

        let detail = if !file_backed_recorded {
            "No file-backed validation evidence has been recorded yet.".to_string()
        } else if mixed_mode_required && !mixed_mode_recorded {
            "File-backed validation evidence exists, but mixed-mode evidence is still missing."
                .to_string()
        } else if !missing_platforms.is_empty() {
            format!(
                "Validation evidence covers current file-backed{} requirements, but platform evidence is still missing for: {}.",
                if mixed_mode_required { " and mixed-mode" } else { "" },
                missing_platforms.join(", ")
            )
        } else {
            format!(
                "Validation evidence covers current file-backed{} requirements across all three platforms.",
                if mixed_mode_required { " and mixed-mode" } else { "" }
            )
        };

        let next_target = if !file_backed_recorded {
            if validation.status == DoctorValidationStatus::Blocked {
                "File-backed validation evidence is still missing. Unblock this machine or use another ready machine, then export a diagnostic bundle.".to_string()
            } else {
                "File-backed validation evidence is still missing. Run a file-backed validation pass on this machine and export a diagnostic bundle.".to_string()
            }
        } else if mixed_mode_required && !mixed_mode_recorded {
            if validation.status == DoctorValidationStatus::Ready {
                "This machine can close the mixed-mode evidence gap. Run a mixed-mode switch round-trip and export a diagnostic bundle.".to_string()
            } else {
                "Mixed-mode evidence is still missing. Use a machine with the target system credential store to run one mixed-mode validation pass and export a diagnostic bundle.".to_string()
            }
        } else if !missing_platforms.is_empty() {
            if !current_platform_recorded && validation.status != DoctorValidationStatus::Blocked {
                format!(
                    "This machine can fill the missing {} evidence gap. Run a validation pass and export a diagnostic bundle.",
                    current_os
                )
            } else {
                format!(
                    "Validation evidence is still missing for: {}. Use the next ready machine in that list to run a validation pass and export a diagnostic bundle.",
                    missing_platforms.join(", ")
                )
            }
        } else {
            format!(
                "Validation evidence covers current file-backed{} requirements across all three platforms.",
                if mixed_mode_required { " and mixed-mode" } else { "" }
            )
        };

        DoctorValidationCoverageSummary {
            file_backed_recorded,
            mixed_mode_required,
            mixed_mode_recorded,
            covered_platform_count: covered_platforms.len().min(3),
            total_platform_count: 3,
            missing_platforms,
            detail,
            next_target,
        }
    }

    fn build_doctor_validation_summary(
        &self,
        auth_file_exists: bool,
        live_session: &DoctorLiveSessionStatus,
        switch_probes: &SwitchProbeReport,
        recovery: &RecoveryStatus,
        profile_readiness: &[DoctorProfileReadiness],
    ) -> DoctorValidationSummary {
        let ready_profile_count =
            profile_readiness.iter().filter(|profile| profile.status == "ready").count();
        let warning_profile_count =
            profile_readiness.iter().filter(|profile| profile.status == "warning").count();
        let blocked_profile_count =
            profile_readiness.iter().filter(|profile| profile.status == "blocked").count();
        let mixed_profile_count = profile_readiness
            .iter()
            .filter(|profile| profile.credential_mode != codex_switch_domain::CredentialMode::File)
            .count();
        let active_store_name = self.current_system_store_name();
        let switch_ready = switch_probes.data_dir_write.ok
            && switch_probes.lock_acquire.ok
            && switch_probes.atomic_swap.ok;
        let status = if !auth_file_exists || !live_session.detected || !switch_ready {
            DoctorValidationStatus::Blocked
        } else if active_store_name.is_some() {
            DoctorValidationStatus::Ready
        } else {
            DoctorValidationStatus::FileOnly
        };

        let detail = match status {
            DoctorValidationStatus::Ready => {
                if mixed_profile_count > 0 {
                    format!(
                        "This machine is ready for file-backed and mixed-mode validation. {} saved profile(s) currently depend on a system credential store.",
                        mixed_profile_count
                    )
                } else {
                    "This machine is ready for a file-backed validation pass, and a system credential store is available for mixed-mode testing when needed."
                        .to_string()
                }
            }
            DoctorValidationStatus::FileOnly => {
                "This machine is ready for file-backed validation, but no active system credential store is available for mixed-mode verification."
                    .to_string()
            }
            DoctorValidationStatus::Blocked => {
                "This machine is not ready for a validation pass yet because the live session or switch prerequisites are incomplete."
                    .to_string()
            }
        };

        let mut next_steps = Vec::new();
        match status {
            DoctorValidationStatus::Blocked => {
                if !auth_file_exists {
                    next_steps.push(
                        "Complete one official login on this machine so auth.json exists before recording validation evidence."
                            .to_string(),
                    );
                }
                if !live_session.detected {
                    next_steps.push(
                        "Re-run doctor after the official client has a detectable live session on this machine."
                            .to_string(),
                    );
                }
                if !switch_ready {
                    next_steps.push(
                        "Fix the failing switch probes before running profile-switch validation on this machine."
                            .to_string(),
                    );
                }
                if recovery.pending_count > 0 {
                    next_steps.push(
                        "Run recover so interrupted switch state does not pollute platform validation results."
                            .to_string(),
                    );
                }
            }
            DoctorValidationStatus::FileOnly => {
                next_steps.push(
                    "Use this machine for file-backed save/use/check/sync validation first."
                        .to_string(),
                );
                next_steps.push(
                    "Export a diagnostic bundle after the file-backed validation pass so the results can be compared across platforms."
                        .to_string(),
                );
                if mixed_profile_count > 0 {
                    next_steps.push(format!(
                        "{mixed_profile_count} mixed-mode profile(s) still need validation on a machine where the target system credential store is available."
                    ));
                }
            }
            DoctorValidationStatus::Ready => {
                next_steps.push(
                    "Run a save -> use -> use-back switch round-trip on this machine and confirm doctor stays green."
                        .to_string(),
                );
                next_steps.push(
                    "Export a diagnostic bundle after the switch pass to preserve the validation evidence for this platform."
                        .to_string(),
                );
                if mixed_profile_count > 0 {
                    next_steps.push(format!(
                        "Include at least one mixed-mode profile in the validation pass because {mixed_profile_count} saved profile(s) depend on system credentials."
                    ));
                }
                if warning_profile_count > 0 {
                    next_steps.push(
                        "Review warning profiles with check <name> before counting them as fully validated."
                            .to_string(),
                    );
                }
            }
        }

        DoctorValidationSummary {
            status,
            detail,
            active_store_name,
            ready_profile_count,
            warning_profile_count,
            blocked_profile_count,
            mixed_profile_count,
            next_steps,
        }
    }

    fn build_doctor_profile_readiness(
        &self,
        binding: &CurrentBinding,
        live_session: Option<&DetectedSession>,
    ) -> Result<Vec<DoctorProfileReadiness>> {
        let mut readiness = Vec::new();
        for profile in self.read_profiles()? {
            match self.load_snapshot(profile.id) {
                Ok(snapshot) => {
                    let drifted = binding.active_profile_id == Some(profile.id)
                        && live_session
                            .map(|live| {
                                live.live_fingerprint != snapshot.manifest.vault_fingerprint
                            })
                            .unwrap_or(false);
                    let preflight = self.build_profile_preflight(&snapshot, drifted);
                    let status = if !preflight.ready {
                        "blocked"
                    } else if !preflight.warnings.is_empty() {
                        "warning"
                    } else {
                        "ready"
                    };
                    readiness.push(DoctorProfileReadiness {
                        profile_name: profile.name,
                        account_label_masked: profile.account_label_masked,
                        credential_mode: profile.credential_mode,
                        status: status.to_string(),
                        blocker_count: preflight.blockers.len(),
                        warning_count: preflight.warnings.len(),
                        detail: preflight.detail,
                        blockers: preflight.blockers,
                        warnings: preflight.warnings,
                        source_operating_system: snapshot.manifest.provenance.operating_system,
                        source_system_store_name: snapshot.manifest.provenance.system_store_name,
                    });
                }
                Err(error) => {
                    readiness.push(DoctorProfileReadiness {
                        profile_name: profile.name,
                        account_label_masked: profile.account_label_masked,
                        credential_mode: profile.credential_mode,
                        status: "blocked".to_string(),
                        blocker_count: 1,
                        warning_count: 0,
                        detail: format!(
                            "Profile snapshot could not be loaded on this machine: {error}"
                        ),
                        blockers: vec![format!(
                            "Profile snapshot could not be loaded on this machine: {error}"
                        )],
                        warnings: Vec::new(),
                        source_operating_system: "unknown".to_string(),
                        source_system_store_name: None,
                    });
                }
            }
        }
        Ok(readiness)
    }

    fn build_doctor_store_usage(
        profile_readiness: &[DoctorProfileReadiness],
        stores: &[codex_switch_platform::StoreDiagnostic],
    ) -> Vec<DoctorStoreUsageSummary> {
        use std::collections::BTreeMap;

        #[derive(Default)]
        struct Counts {
            profile_count: usize,
            ready_count: usize,
            warning_count: usize,
            blocked_count: usize,
        }

        let mut grouped: BTreeMap<String, Counts> = BTreeMap::new();
        for profile in profile_readiness {
            let key =
                profile.source_system_store_name.clone().unwrap_or_else(|| "file_only".to_string());
            let counts = grouped.entry(key).or_default();
            counts.profile_count += 1;
            match profile.status.as_str() {
                "ready" => counts.ready_count += 1,
                "warning" => counts.warning_count += 1,
                _ => counts.blocked_count += 1,
            }
        }

        grouped
            .into_iter()
            .map(|(store_name, counts)| {
                let diagnostic = stores.iter().find(|store| store.name == store_name);
                let (supported, available, detail) = if store_name == "file_only" {
                    (
                        Some(true),
                        Some(true),
                        format!(
                            "{} saved profile(s) are file-backed only; ready={} warning={} blocked={}.",
                            counts.profile_count,
                            counts.ready_count,
                            counts.warning_count,
                            counts.blocked_count
                        ),
                    )
                } else if let Some(diagnostic) = diagnostic {
                    (
                        Some(diagnostic.supported),
                        Some(diagnostic.available),
                        format!(
                            "{} saved profile(s) depend on {}; ready={} warning={} blocked={}. {}",
                            counts.profile_count,
                            store_name,
                            counts.ready_count,
                            counts.warning_count,
                            counts.blocked_count,
                            diagnostic.detail
                        ),
                    )
                } else {
                    (
                        None,
                        None,
                        format!(
                            "{} saved profile(s) depend on {}; ready={} warning={} blocked={}. No runtime diagnostic is available for this store name.",
                            counts.profile_count,
                            store_name,
                            counts.ready_count,
                            counts.warning_count,
                            counts.blocked_count
                        ),
                    )
                };

                DoctorStoreUsageSummary {
                    store_name,
                    profile_count: counts.profile_count,
                    ready_count: counts.ready_count,
                    warning_count: counts.warning_count,
                    blocked_count: counts.blocked_count,
                    supported,
                    available,
                    detail,
                }
            })
            .collect()
    }

    fn record_validation_evidence(
        &self,
        bundle: &DiagnosticBundle,
        destination: &Path,
    ) -> Result<()> {
        let record = ValidationEvidenceRecord {
            recorded_at: bundle.generated_at,
            operating_system: bundle.doctor.operating_system.clone(),
            validation_status: bundle.doctor.validation.status,
            active_store_name: bundle.doctor.validation.active_store_name.clone(),
            live_session_detected: bundle.doctor.live_session.detected,
            bundle_path: destination.display().to_string(),
            ready_profile_count: bundle.doctor.validation.ready_profile_count,
            warning_profile_count: bundle.doctor.validation.warning_profile_count,
            blocked_profile_count: bundle.doctor.validation.blocked_profile_count,
            mixed_profile_count: bundle.doctor.validation.mixed_profile_count,
        };
        let record_path = self.paths.validation_dir.join(format!(
            "validation-evidence-{}-{}.json",
            record.recorded_at.format("%Y%m%dT%H%M%SZ"),
            Uuid::new_v4()
        ));
        atomic_write(&record_path, &serde_json::to_vec_pretty(&record)?)
    }

    fn read_validation_evidence_records(&self) -> Result<Vec<ValidationEvidenceRecord>> {
        let mut records = Vec::new();
        for path in list_json_files(&self.paths.validation_dir)? {
            let contents = fs::read_to_string(path)?;
            records.push(serde_json::from_str(&contents)?);
        }
        Ok(records)
    }

    fn run_switch_probes(&self) -> SwitchProbeReport {
        let data_dir_write = self.probe_data_dir_write();
        let lock_acquire = self.probe_lock_acquire();
        let atomic_swap = self.probe_atomic_swap();
        let ok_count = [data_dir_write.ok, lock_acquire.ok, atomic_swap.ok]
            .into_iter()
            .filter(|ok| *ok)
            .count();
        let detail = format!("{ok_count}/3 non-destructive switch probes succeeded.");

        SwitchProbeReport { data_dir_write, lock_acquire, atomic_swap, detail }
    }

    fn probe_data_dir_write(&self) -> ProbeStatus {
        let probe_path = self.paths.data_dir.join(format!(".probe-write-{}", Uuid::new_v4()));
        match atomic_write(&probe_path, b"probe") {
            Ok(()) => {
                let _ = secure_delete(&probe_path);
                ProbeStatus {
                    ok: true,
                    detail: format!(
                        "Able to create and remove a probe file in {}.",
                        self.paths.data_dir.display()
                    ),
                }
            }
            Err(error) => ProbeStatus {
                ok: false,
                detail: format!(
                    "Could not write a probe file in {}: {error}",
                    self.paths.data_dir.display()
                ),
            },
        }
    }

    fn probe_lock_acquire(&self) -> ProbeStatus {
        match GlobalSwitchLock::acquire(self.lock_path()) {
            Ok(_guard) => ProbeStatus {
                ok: true,
                detail: format!(
                    "Successfully acquired and released {}.",
                    self.lock_path().display()
                ),
            },
            Err(error) => ProbeStatus {
                ok: false,
                detail: format!("Could not acquire {}: {error}", self.lock_path().display()),
            },
        }
    }

    fn probe_atomic_swap(&self) -> ProbeStatus {
        if !self.paths.codex_home.exists() {
            return ProbeStatus {
                ok: false,
                detail: format!(
                    "{} does not exist, so atomic swap cannot be rehearsed.",
                    self.paths.codex_home.display()
                ),
            };
        }

        let source = self.paths.codex_home.join(format!(".probe-source-{}", Uuid::new_v4()));
        let target = self.paths.codex_home.join(format!(".probe-target-{}", Uuid::new_v4()));
        let result = (|| -> Result<()> {
            atomic_write(&source, b"probe")?;
            fs::rename(&source, &target)?;
            secure_delete(&target)?;
            Ok(())
        })();

        let _ = secure_delete(&source);
        let _ = secure_delete(&target);

        match result {
            Ok(()) => ProbeStatus {
                ok: true,
                detail: format!(
                    "Successfully created, renamed, and removed a probe file under {}.",
                    self.paths.codex_home.display()
                ),
            },
            Err(error) => ProbeStatus {
                ok: false,
                detail: format!(
                    "Could not complete an atomic swap rehearsal under {}: {error}",
                    self.paths.codex_home.display()
                ),
            },
        }
    }

    fn build_discovery_trace(&self) -> DiscoveryTraceReport {
        let Ok(auth_contents) = fs::read_to_string(self.file_store.auth_path()) else {
            return DiscoveryTraceReport {
                matched_count: 0,
                missing_input_count: 0,
                lookup_missed_count: 0,
                blocked_count: 0,
                entries: Vec::new(),
                detail: "No auth.json was available for discovery tracing.".to_string(),
            };
        };
        let Ok(inspection) = inspect_auth_json(&auth_contents) else {
            return DiscoveryTraceReport {
                matched_count: 0,
                missing_input_count: 0,
                lookup_missed_count: 0,
                blocked_count: 0,
                entries: Vec::new(),
                detail: "auth.json exists, but discovery tracing could not parse it.".to_string(),
            };
        };
        let store = self
            .system_stores
            .iter()
            .find(|store| store.is_available())
            .map(|store| store.as_ref());
        let entries = self.discovery_registry.trace(&inspection, store);
        let matched_count = entries
            .iter()
            .filter(|entry| entry.status == CredentialDiscoveryTraceStatus::Matched)
            .count();
        let missing_input_count = entries
            .iter()
            .filter(|entry| entry.status == CredentialDiscoveryTraceStatus::MissingInput)
            .count();
        let lookup_missed_count = entries
            .iter()
            .filter(|entry| entry.status == CredentialDiscoveryTraceStatus::LookupMissed)
            .count();
        let blocked_count = entries
            .iter()
            .filter(|entry| {
                matches!(
                    entry.status,
                    CredentialDiscoveryTraceStatus::MissingInput
                        | CredentialDiscoveryTraceStatus::StoreUnavailable
                        | CredentialDiscoveryTraceStatus::SourceTypeMismatch
                        | CredentialDiscoveryTraceStatus::DuplicateCandidate
                )
            })
            .count();
        let detail = if entries.is_empty() {
            "No credential discovery rules were available to trace.".to_string()
        } else {
            format!(
                "Traced {} discovery rule(s): {} matched, {} missed lookups, {} blocked before lookup.",
                entries.len(),
                matched_count,
                lookup_missed_count,
                blocked_count
            )
        };

        DiscoveryTraceReport {
            matched_count,
            missing_input_count,
            lookup_missed_count,
            blocked_count,
            entries,
            detail,
        }
    }

    fn build_profile_preflight(
        &self,
        snapshot: &SecretSnapshot,
        drifted: bool,
    ) -> ProfilePreflightReport {
        let probes = self.run_switch_probes();
        let mut blockers = Vec::new();
        let mut warnings = Vec::new();

        if !probes.data_dir_write.ok {
            blockers.push(probes.data_dir_write.detail.clone());
        }
        if !probes.lock_acquire.ok {
            blockers.push(probes.lock_acquire.detail.clone());
        }
        if !probes.atomic_swap.ok {
            blockers.push(probes.atomic_swap.detail.clone());
        }

        if !snapshot.system_records.is_empty() {
            if let Err(error) = self.current_system_store() {
                blockers.push(format!(
                    "This profile requires {} system credential entry(s), but no system credential store is available: {error}",
                    snapshot.system_records.len()
                ));
            } else {
                if snapshot.manifest.provenance.operating_system != "unknown"
                    && snapshot.manifest.provenance.operating_system != std::env::consts::OS
                {
                    warnings.push(format!(
                        "This profile's system credentials were captured on {}, and the current machine is {}. Validate the switched session carefully on this platform.",
                        snapshot.manifest.provenance.operating_system,
                        std::env::consts::OS
                    ));
                }

                if let (Some(saved_store_name), Some(current_store_name)) = (
                    snapshot.manifest.provenance.system_store_name.as_deref(),
                    self.current_system_store_name().as_deref(),
                ) {
                    if saved_store_name != current_store_name {
                        warnings.push(format!(
                            "This profile's system credentials were captured using {saved_store_name}, but the current machine is using {current_store_name}. Re-check the session after switching and run sync if it refreshes locally."
                        ));
                    }
                }
            }
        }

        if snapshot.file_entries.is_empty() {
            warnings.push(
                "This profile snapshot does not include any file-backed credential entries."
                    .to_string(),
            );
        }

        if drifted {
            warnings.push(
                "This active profile currently differs from the live session. Run sync before switching away if you want to keep the refreshed state."
                    .to_string(),
            );
        }

        let ready = blockers.is_empty();
        let detail = if ready {
            format!(
                "Profile is ready to switch on this machine. It needs {} file entry and {} system entry.",
                snapshot.file_entries.len(),
                snapshot.system_records.len()
            )
        } else {
            format!(
                "Profile is not ready to switch on this machine because {} blocker(s) were found.",
                blockers.len()
            )
        };

        ProfilePreflightReport {
            ready,
            required_file_entries: snapshot.file_entries.len(),
            required_system_entries: snapshot.system_records.len(),
            blockers,
            warnings,
            detail,
        }
    }

    fn derive_checked_profile_health(
        &self,
        preflight: &ProfilePreflightReport,
        drifted: bool,
        is_active: bool,
        healthy_detail: &str,
    ) -> ProfileHealth {
        let status = if !preflight.ready {
            HealthStatus::Invalid
        } else if drifted {
            HealthStatus::Drifted
        } else {
            HealthStatus::Healthy
        };

        let detail = match status {
            HealthStatus::Invalid => {
                let prefix = if is_active {
                    "Active profile is not ready to switch on this machine."
                } else {
                    "Profile is not ready to switch on this machine."
                };
                self.compose_detail(prefix, preflight)
            }
            HealthStatus::Drifted | HealthStatus::Healthy => {
                self.compose_detail(healthy_detail, preflight)
            }
            HealthStatus::Missing | HealthStatus::Unknown => {
                self.compose_detail(healthy_detail, preflight)
            }
        };

        ProfileHealth { status, detail, checked_at: Some(Utc::now()) }
    }

    fn derive_imported_profile_health(&self, preflight: &ProfilePreflightReport) -> ProfileHealth {
        let status = if preflight.ready { HealthStatus::Healthy } else { HealthStatus::Invalid };
        let prefix = if preflight.ready {
            "Imported profile archive is ready to use on this machine."
        } else {
            "Imported profile archive is not ready on this machine."
        };
        let detail = self.compose_detail(prefix, preflight);
        ProfileHealth { status, detail, checked_at: Some(Utc::now()) }
    }

    fn compose_detail(&self, prefix: &str, preflight: &ProfilePreflightReport) -> String {
        if !preflight.ready {
            if let Some(blocker) = preflight.blockers.first() {
                return format!("{prefix} Blocker: {blocker}");
            }
            return format!("{prefix} {}", preflight.detail);
        }

        if let Some(warning) = preflight.warnings.first() {
            return format!("{prefix} Warning: {warning}");
        }

        prefix.to_string()
    }

    fn recent_audit_entries(&self, limit: usize) -> Result<Vec<String>> {
        let log = self.read_audit_log()?;
        let mut lines = log
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(ToOwned::to_owned)
            .collect::<Vec<_>>();
        if lines.len() > limit {
            lines = lines.split_off(lines.len() - limit);
        }
        Ok(lines)
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
        let mut config = self.read_config()?;
        let profiles = self.read_profiles()?;
        for mut profile in profiles {
            profile.is_default = Some(profile.id) == default_profile_id;
            self.vault.write_profile_meta(&profile)?;
        }
        config.default_profile_id = default_profile_id;
        self.write_config(&config)
    }

    fn load_discovery_registry(config_file: &Path) -> Result<CredentialDiscoveryRegistry> {
        if !config_file.exists() {
            return Ok(CredentialDiscoveryRegistry::default());
        }

        let contents = fs::read_to_string(config_file)?;
        let config: AppConfig = serde_json::from_str(&contents)?;
        let mut rules = CredentialDiscoveryRegistry::standard_rules();
        rules.extend(config.credential_discovery_rules);
        Ok(CredentialDiscoveryRegistry::new(rules))
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
                provenance: codex_switch_domain::SnapshotProvenance {
                    operating_system: std::env::consts::OS.to_string(),
                    system_store_name: if live.system_entries.is_empty() {
                        None
                    } else {
                        self.current_system_store_name()
                    },
                },
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

    fn current_system_store_name(&self) -> Option<String> {
        self.system_stores
            .iter()
            .find(|store| store.is_available())
            .map(|store| store.store_name().to_string())
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
        for txn in self.read_pending_transactions()? {
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

    fn inspect_recovery_status(&self) -> Result<RecoveryStatus> {
        let transactions = self.read_pending_transactions()?;
        let rollback_required_count =
            transactions.iter().filter(|txn| txn.rollback_required).count();
        let detail = if transactions.is_empty() {
            "No interrupted switch transactions are waiting for recovery.".to_string()
        } else {
            format!(
                "{} interrupted switch transaction(s) are waiting for cleanup or rollback.",
                transactions.len()
            )
        };

        Ok(RecoveryStatus {
            pending_count: transactions.len(),
            rollback_required_count,
            transactions: transactions.iter().map(Self::summarize_transaction).collect(),
            detail,
        })
    }

    fn read_pending_transactions(&self) -> Result<Vec<SwitchTransaction>> {
        let mut transactions: Vec<SwitchTransaction> = Vec::new();
        for path in list_json_files(&self.paths.tx_dir)? {
            let contents = fs::read_to_string(&path)?;
            transactions.push(serde_json::from_str(&contents)?);
        }
        transactions.sort_by_key(|txn| txn.started_at);
        Ok(transactions)
    }

    fn summarize_transaction(txn: &SwitchTransaction) -> PendingTransactionSummary {
        PendingTransactionSummary {
            txn_id: txn.txn_id.to_string(),
            started_at: txn.started_at,
            phase: txn.phase,
            rollback_required: txn.rollback_required,
        }
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

fn default_system_stores() -> Vec<Box<dyn OfficialCredentialStore>> {
    vec![
        Box::new(MacKeychainCredentialStore),
        Box::new(LinuxKeyringCredentialStore),
        Box::new(WindowsCredentialStore),
    ]
}

#[cfg(test)]
mod tests {
    use std::fs;

    use base64::Engine as _;
    use codex_switch_domain::{
        CredentialMode, CredentialRef, OfficialCredentialStore, Result as DomainResult,
        SecretRecord, SwitchError,
    };
    use codex_switch_platform::inspect::inspect_auth_json;
    use codex_switch_platform::{
        CredentialDiscoveryRegistry, CredentialDiscoveryRule, CredentialDiscoveryTraceStatus,
    };
    use secrecy::SecretString;
    use tempfile::tempdir;

    use super::*;
    use codex_switch_domain::SourceType;

    #[derive(Debug)]
    struct MockStore {
        name: String,
        enabled: bool,
        available: Vec<SecretRecord>,
    }

    impl OfficialCredentialStore for MockStore {
        fn kind(&self) -> CredentialMode {
            CredentialMode::System
        }

        fn store_name(&self) -> &'static str {
            Box::leak(self.name.clone().into_boxed_str())
        }

        fn is_available(&self) -> bool {
            self.enabled
        }

        fn read(&self, refs: &[CredentialRef]) -> DomainResult<Vec<SecretRecord>> {
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

        fn write(&self, _records: &[SecretRecord]) -> DomainResult<()> {
            Ok(())
        }

        fn delete(&self, _refs: &[CredentialRef]) -> DomainResult<()> {
            Ok(())
        }
    }

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

    fn manager_with_registry(
        codex_home: PathBuf,
        app_home: PathBuf,
        registry: CredentialDiscoveryRegistry,
        detector_records: Vec<SecretRecord>,
    ) -> ManagerService {
        manager_with_store_mode(
            codex_home,
            app_home,
            registry,
            detector_records.clone(),
            detector_records,
            "mock_system_store",
            "mock_system_store",
            true,
        )
    }

    fn manager_with_store_mode(
        codex_home: PathBuf,
        app_home: PathBuf,
        registry: CredentialDiscoveryRegistry,
        system_records: Vec<SecretRecord>,
        detector_records: Vec<SecretRecord>,
        system_store_name: &str,
        detector_store_name: &str,
        enabled: bool,
    ) -> ManagerService {
        let paths = PathResolver::discover(Some(codex_home), Some(app_home)).expect("paths");
        ManagerService::from_parts(
            paths,
            None,
            registry,
            vec![Box::new(MockStore {
                name: system_store_name.to_string(),
                enabled,
                available: system_records,
            })],
            vec![Box::new(MockStore {
                name: detector_store_name.to_string(),
                enabled,
                available: detector_records,
            })],
        )
        .expect("manager")
    }

    fn write_validation_evidence(
        app_home: &Path,
        operating_system: &str,
        validation_status: DoctorValidationStatus,
        active_store_name: Option<&str>,
    ) {
        fs::create_dir_all(app_home.join("validation")).expect("validation dir");
        let record = ValidationEvidenceRecord {
            recorded_at: chrono::DateTime::parse_from_rfc3339("2026-04-17T08:00:00Z")
                .expect("timestamp")
                .with_timezone(&Utc),
            operating_system: operating_system.to_string(),
            validation_status,
            active_store_name: active_store_name.map(|value| value.to_string()),
            live_session_detected: true,
            bundle_path: format!("/tmp/{operating_system}-bundle.json"),
            ready_profile_count: 1,
            warning_profile_count: 0,
            blocked_profile_count: 0,
            mixed_profile_count: usize::from(validation_status == DoctorValidationStatus::Ready),
        };
        let path = app_home
            .join("validation")
            .join(format!("validation-evidence-{operating_system}.json"));
        fs::write(path, serde_json::to_vec_pretty(&record).expect("record json"))
            .expect("record write");
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
        let alpha_snapshot = manager.load_snapshot(saved.id).expect("alpha snapshot");

        let archive = manager
            .export_profile("alpha", SecretString::new("export-pass".into()), None)
            .expect("export");
        let imported = manager
            .import_profile(&archive, SecretString::new("export-pass".into()))
            .expect("import");
        assert_eq!(imported.name, "alpha-imported");
        let imported_snapshot = manager.load_snapshot(imported.id).expect("imported snapshot");
        assert_eq!(imported_snapshot.manifest.provenance, alpha_snapshot.manifest.provenance);
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
    fn check_profile_reports_preflight_ready_for_file_profile() {
        let temp = tempdir().expect("tempdir");
        let codex_home = temp.path().join("codex-home");
        let app_home = temp.path().join("app-home");
        fs::create_dir_all(&codex_home).expect("codex_home");
        fs::write(codex_home.join("auth.json"), sample_auth("acct-alpha", "2026-04-13T00:00:00Z"))
            .expect("auth");
        let manager = ManagerService::new(ManagerOptions {
            codex_home_override: Some(codex_home),
            data_dir_override: Some(app_home),
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

        let report = manager.check_profile("alpha").expect("check");

        assert!(report.preflight.ready);
        assert!(report.preflight.blockers.is_empty());
        assert_eq!(report.preflight.required_file_entries, 1);
        assert_eq!(report.preflight.required_system_entries, 0);
    }

    #[test]
    fn check_profile_reports_preflight_blocker_when_system_store_is_missing() {
        let temp = tempdir().expect("tempdir");
        let codex_home = temp.path().join("codex-home");
        let app_home = temp.path().join("app-home");
        fs::create_dir_all(&codex_home).expect("codex_home");
        fs::write(codex_home.join("auth.json"), sample_auth("acct-custom", "2026-04-13T06:00:00Z"))
            .expect("auth");
        let registry = CredentialDiscoveryRegistry::new(vec![CredentialDiscoveryRule {
            name: "custom-account-id".to_string(),
            source_type: Some(SourceType::ChatGpt),
            service: "custom-openai".to_string(),
            account: "{account_id}".to_string(),
            label: Some("Desktop Session".to_string()),
        }]);
        let system_record = SecretRecord {
            reference: CredentialRef {
                service: "custom-openai".to_string(),
                account: "acct-custom".to_string(),
                label: Some("Desktop Session".to_string()),
            },
            secret: SecretString::new("custom-secret-token".into()),
        };

        let writer = manager_with_store_mode(
            codex_home.clone(),
            app_home.clone(),
            registry.clone(),
            vec![system_record.clone()],
            vec![system_record.clone()],
            "mock_system_store",
            "mock_system_store",
            true,
        );
        writer
            .save_profile(SaveProfileRequest {
                name: "alpha".to_string(),
                note: None,
                make_default: false,
            })
            .expect("save");

        let checker = manager_with_store_mode(
            codex_home,
            app_home,
            registry,
            Vec::new(),
            Vec::new(),
            "mock_system_store",
            "mock_system_store",
            false,
        );

        let report = checker.check_profile("alpha").expect("check");

        assert!(!report.preflight.ready);
        assert_eq!(report.preflight.required_system_entries, 1);
        assert_eq!(report.profile.health.status, HealthStatus::Invalid);
        assert!(report.profile.health.detail.contains("not ready to switch on this machine"));
        assert!(
            report
                .preflight
                .blockers
                .iter()
                .any(|blocker| blocker.contains("system credential store"))
        );
    }

    #[test]
    fn current_status_marks_active_profile_as_needing_sync_after_live_refresh() {
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
            sample_auth("acct-alpha-refreshed", "2026-04-13T04:00:00Z"),
        )
        .expect("mutate");

        let current = manager.current_status().expect("current");

        assert_eq!(current.sync_state.status, CurrentSyncStatus::NeedsSync);
        assert!(current.sync_state.detail.contains("sync"));
    }

    #[test]
    fn save_profile_records_snapshot_provenance() {
        let temp = tempdir().expect("tempdir");
        let codex_home = temp.path().join("codex-home");
        let app_home = temp.path().join("app-home");
        fs::create_dir_all(&codex_home).expect("codex_home");
        fs::write(codex_home.join("auth.json"), sample_auth("acct-alpha", "2026-04-13T00:00:00Z"))
            .expect("auth");

        let manager = ManagerService::new(ManagerOptions {
            codex_home_override: Some(codex_home),
            data_dir_override: Some(app_home),
            local_passphrase: None,
        })
        .expect("manager");
        let saved = manager
            .save_profile(SaveProfileRequest {
                name: "alpha".to_string(),
                note: None,
                make_default: false,
            })
            .expect("save");

        let snapshot = manager.load_snapshot(saved.id).expect("snapshot");

        assert_eq!(snapshot.manifest.provenance.operating_system, std::env::consts::OS);
        assert_eq!(snapshot.manifest.provenance.system_store_name, None);
    }

    #[test]
    fn check_profile_warns_when_snapshot_came_from_different_system_store() {
        let temp = tempdir().expect("tempdir");
        let codex_home = temp.path().join("codex-home");
        let app_home = temp.path().join("app-home");
        fs::create_dir_all(&codex_home).expect("codex_home");
        fs::write(codex_home.join("auth.json"), sample_auth("acct-custom", "2026-04-13T06:00:00Z"))
            .expect("auth");
        let registry = CredentialDiscoveryRegistry::new(vec![CredentialDiscoveryRule {
            name: "custom-account-id".to_string(),
            source_type: Some(SourceType::ChatGpt),
            service: "custom-openai".to_string(),
            account: "{account_id}".to_string(),
            label: Some("Desktop Session".to_string()),
        }]);
        let system_record = SecretRecord {
            reference: CredentialRef {
                service: "custom-openai".to_string(),
                account: "acct-custom".to_string(),
                label: Some("Desktop Session".to_string()),
            },
            secret: SecretString::new("custom-secret-token".into()),
        };

        let writer = manager_with_store_mode(
            codex_home.clone(),
            app_home.clone(),
            registry.clone(),
            vec![system_record.clone()],
            vec![system_record.clone()],
            "macos_keychain",
            "macos_keychain",
            true,
        );
        writer
            .save_profile(SaveProfileRequest {
                name: "alpha".to_string(),
                note: None,
                make_default: false,
            })
            .expect("save");

        let checker = manager_with_store_mode(
            codex_home,
            app_home,
            registry,
            vec![system_record],
            Vec::new(),
            "linux_keyring",
            "linux_keyring",
            true,
        );

        let report = checker.check_profile("alpha").expect("check");

        assert!(report.preflight.ready);
        assert!(
            report
                .preflight
                .warnings
                .iter()
                .any(|warning| warning.contains("macos_keychain")
                    && warning.contains("linux_keyring"))
        );
        assert_eq!(report.profile.health.status, HealthStatus::Healthy);
        assert!(report.profile.health.detail.contains("Warning:"));
    }

    #[test]
    fn import_profile_marks_blocked_snapshot_as_invalid() {
        let temp = tempdir().expect("tempdir");
        let writer_codex_home = temp.path().join("writer-codex-home");
        let writer_app_home = temp.path().join("writer-app-home");
        let checker_codex_home = temp.path().join("checker-codex-home");
        let checker_app_home = temp.path().join("checker-app-home");
        fs::create_dir_all(&writer_codex_home).expect("writer_codex_home");
        fs::create_dir_all(&checker_codex_home).expect("checker_codex_home");
        fs::write(
            writer_codex_home.join("auth.json"),
            sample_auth("acct-custom", "2026-04-13T06:00:00Z"),
        )
        .expect("auth");
        let registry = CredentialDiscoveryRegistry::new(vec![CredentialDiscoveryRule {
            name: "custom-account-id".to_string(),
            source_type: Some(SourceType::ChatGpt),
            service: "custom-openai".to_string(),
            account: "{account_id}".to_string(),
            label: Some("Desktop Session".to_string()),
        }]);
        let system_record = SecretRecord {
            reference: CredentialRef {
                service: "custom-openai".to_string(),
                account: "acct-custom".to_string(),
                label: Some("Desktop Session".to_string()),
            },
            secret: SecretString::new("custom-secret-token".into()),
        };

        let writer = manager_with_store_mode(
            writer_codex_home,
            writer_app_home,
            registry.clone(),
            vec![system_record.clone()],
            vec![system_record.clone()],
            "mock_system_store",
            "mock_system_store",
            true,
        );
        writer
            .save_profile(SaveProfileRequest {
                name: "alpha".to_string(),
                note: None,
                make_default: false,
            })
            .expect("save");
        let archive = writer
            .export_profile("alpha", SecretString::new("export-pass".into()), None)
            .expect("export");

        fs::write(
            checker_codex_home.join("auth.json"),
            sample_auth("acct-fallback", "2026-04-13T07:00:00Z"),
        )
        .expect("checker auth");
        let checker = manager_with_store_mode(
            checker_codex_home,
            checker_app_home,
            registry,
            Vec::new(),
            Vec::new(),
            "mock_system_store",
            "mock_system_store",
            false,
        );

        let imported = checker
            .import_profile(&archive, SecretString::new("export-pass".into()))
            .expect("import");

        assert_eq!(imported.health.status, HealthStatus::Invalid);
        assert!(
            imported
                .health
                .detail
                .contains("Imported profile archive is not ready on this machine")
        );
        let persisted = checker
            .list_profiles()
            .expect("profiles")
            .into_iter()
            .find(|profile| profile.id == imported.id)
            .expect("persisted");
        assert_eq!(persisted.health.status, HealthStatus::Invalid);
    }

    #[test]
    fn current_status_returns_to_in_sync_after_syncing_active_profile() {
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
            sample_auth("acct-alpha-refreshed", "2026-04-13T05:00:00Z"),
        )
        .expect("mutate");
        manager.sync_active_profile().expect("sync");

        let current = manager.current_status().expect("current");

        assert_eq!(current.sync_state.status, CurrentSyncStatus::InSync);
        assert!(current.sync_state.detail.contains("synced"));
    }

    #[test]
    fn can_set_default_profile_without_switching_active_session() {
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
            .expect("save alpha");

        fs::write(codex_home.join("auth.json"), sample_auth("acct-beta", "2026-04-13T01:00:00Z"))
            .expect("auth2");
        manager
            .save_profile(SaveProfileRequest {
                name: "beta".to_string(),
                note: None,
                make_default: false,
            })
            .expect("save beta");

        let live_before = manager.detect().expect("live before");
        let updated = manager.set_default_profile_by_name("alpha").expect("set default");
        let current = manager.current_status().expect("current");
        let profiles = manager.list_profiles().expect("profiles");

        assert_eq!(updated.name, "alpha");
        assert!(updated.is_default);
        assert!(current.active_profile.is_none());
        assert_eq!(current.live_session.live_fingerprint, live_before.live_fingerprint);
        assert_eq!(profiles.iter().filter(|profile| profile.is_default).count(), 1);
    }

    #[test]
    fn loads_custom_discovery_rules_from_config_for_detection() {
        let temp = tempdir().expect("tempdir");
        let codex_home = temp.path().join("codex-home");
        let app_home = temp.path().join("app-home");
        fs::create_dir_all(&codex_home).expect("codex_home");
        fs::write(codex_home.join("auth.json"), sample_auth("acct-custom", "2026-04-13T06:00:00Z"))
            .expect("auth");
        fs::create_dir_all(&app_home).expect("app_home");
        fs::write(
            app_home.join("config.json"),
            serde_json::to_vec_pretty(&AppConfig {
                default_profile_id: None,
                credential_discovery_rules: vec![CredentialDiscoveryRule {
                    name: "custom-openai".to_string(),
                    source_type: Some(SourceType::ChatGpt),
                    service: "custom-openai".to_string(),
                    account: "{account_id}".to_string(),
                    label: Some("Desktop Session".to_string()),
                }],
            })
            .expect("config"),
        )
        .expect("write config");

        let registry = ManagerService::load_discovery_registry(&app_home.join("config.json"))
            .expect("registry");
        let manager = manager_with_registry(
            codex_home,
            app_home,
            registry,
            vec![SecretRecord {
                reference: CredentialRef {
                    service: "custom-openai".to_string(),
                    account: "acct-custom".to_string(),
                    label: Some("Desktop Session".to_string()),
                },
                secret: SecretString::new("custom-secret-token".into()),
            }],
        );

        let detected = manager.detect().expect("detected");

        assert_eq!(detected.credential_mode, CredentialMode::Mixed);
        assert_eq!(detected.system_entries.len(), 1);
        assert_eq!(detected.system_entries[0].reference.service, "custom-openai");
    }

    #[test]
    fn set_default_profile_preserves_custom_discovery_rules_in_config() {
        let temp = tempdir().expect("tempdir");
        let codex_home = temp.path().join("codex-home");
        let app_home = temp.path().join("app-home");
        fs::create_dir_all(&codex_home).expect("codex_home");
        fs::write(codex_home.join("auth.json"), sample_auth("acct-alpha", "2026-04-13T00:00:00Z"))
            .expect("auth");
        fs::create_dir_all(&app_home).expect("app_home");
        let original_rule = CredentialDiscoveryRule {
            name: "custom-openai".to_string(),
            source_type: Some(SourceType::ChatGpt),
            service: "custom-openai".to_string(),
            account: "{account_id}".to_string(),
            label: Some("Desktop Session".to_string()),
        };
        fs::write(
            app_home.join("config.json"),
            serde_json::to_vec_pretty(&AppConfig {
                default_profile_id: None,
                credential_discovery_rules: vec![original_rule.clone()],
            })
            .expect("config"),
        )
        .expect("write config");

        let manager = ManagerService::new(ManagerOptions {
            codex_home_override: Some(codex_home),
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

        manager.set_default_profile_by_name("alpha").expect("set default");
        let config = manager.read_config().expect("config");

        assert_eq!(config.credential_discovery_rules, vec![original_rule]);
        assert!(config.default_profile_id.is_some());
    }

    #[test]
    fn doctor_report_flags_missing_auth_file_and_recommends_official_login() {
        let temp = tempdir().expect("tempdir");
        let codex_home = temp.path().join("codex-home");
        let app_home = temp.path().join("app-home");
        fs::create_dir_all(&codex_home).expect("codex_home");

        let manager = ManagerService::new(ManagerOptions {
            codex_home_override: Some(codex_home),
            data_dir_override: Some(app_home),
            local_passphrase: None,
        })
        .expect("manager");

        let report = manager.doctor_report().expect("doctor");

        assert!(!report.auth_file.exists);
        assert!(!report.live_session.detected);
        assert!(
            report
                .recommended_actions
                .iter()
                .any(|action| action.contains("official") || action.contains("log"))
        );
    }

    #[test]
    fn doctor_report_counts_custom_discovery_rules() {
        let temp = tempdir().expect("tempdir");
        let codex_home = temp.path().join("codex-home");
        let app_home = temp.path().join("app-home");
        fs::create_dir_all(&codex_home).expect("codex_home");
        fs::create_dir_all(&app_home).expect("app_home");
        fs::write(codex_home.join("auth.json"), sample_auth("acct-alpha", "2026-04-13T00:00:00Z"))
            .expect("auth");
        fs::write(
            app_home.join("config.json"),
            serde_json::to_vec_pretty(&AppConfig {
                default_profile_id: None,
                credential_discovery_rules: vec![CredentialDiscoveryRule {
                    name: "custom-openai".to_string(),
                    source_type: Some(SourceType::ChatGpt),
                    service: "custom-openai".to_string(),
                    account: "{account_id}".to_string(),
                    label: Some("Desktop Session".to_string()),
                }],
            })
            .expect("config"),
        )
        .expect("write config");

        let manager = ManagerService::new(ManagerOptions {
            codex_home_override: Some(codex_home),
            data_dir_override: Some(app_home),
            local_passphrase: None,
        })
        .expect("manager");

        let report = manager.doctor_report().expect("doctor");

        assert_eq!(
            report.discovery_rule_count,
            CredentialDiscoveryRegistry::standard_rules().len() + 1
        );
        assert_eq!(report.stores.len(), 3);
    }

    #[test]
    fn doctor_report_includes_discovery_trace_statuses() {
        let temp = tempdir().expect("tempdir");
        let codex_home = temp.path().join("codex-home");
        let app_home = temp.path().join("app-home");
        fs::create_dir_all(&codex_home).expect("codex_home");
        fs::write(codex_home.join("auth.json"), sample_auth("acct-custom", "2026-04-13T06:00:00Z"))
            .expect("auth");

        let manager = manager_with_registry(
            codex_home,
            app_home,
            CredentialDiscoveryRegistry::new(vec![
                CredentialDiscoveryRule {
                    name: "custom-account-id".to_string(),
                    source_type: Some(SourceType::ChatGpt),
                    service: "custom-openai".to_string(),
                    account: "{account_id}".to_string(),
                    label: Some("Desktop Session".to_string()),
                },
                CredentialDiscoveryRule {
                    name: "custom-subject".to_string(),
                    source_type: Some(SourceType::ChatGpt),
                    service: "custom-openai".to_string(),
                    account: "{subject}".to_string(),
                    label: Some("Desktop Session".to_string()),
                },
            ]),
            vec![SecretRecord {
                reference: CredentialRef {
                    service: "custom-openai".to_string(),
                    account: "acct-custom".to_string(),
                    label: Some("Desktop Session".to_string()),
                },
                secret: SecretString::new("custom-secret-token".into()),
            }],
        );

        let report = manager.doctor_report().expect("doctor");
        let json = serde_json::to_string(&report).expect("json");

        assert_eq!(report.discovery_trace.matched_count, 1);
        assert_eq!(report.discovery_trace.missing_input_count, 1);
        assert!(
            report
                .discovery_trace
                .entries
                .iter()
                .any(|entry| entry.status == CredentialDiscoveryTraceStatus::Matched)
        );
        assert!(
            report
                .discovery_trace
                .entries
                .iter()
                .any(|entry| entry.status == CredentialDiscoveryTraceStatus::MissingInput)
        );
        assert!(
            report
                .discovery_trace
                .entries
                .iter()
                .any(|entry| entry.account_label_masked.as_deref() == Some("acct_****stom"))
        );
        assert!(!json.contains("acct-custom"));
    }

    #[test]
    fn doctor_report_includes_switch_probe_results() {
        let temp = tempdir().expect("tempdir");
        let codex_home = temp.path().join("codex-home");
        let app_home = temp.path().join("app-home");
        fs::create_dir_all(&codex_home).expect("codex_home");
        fs::write(codex_home.join("auth.json"), sample_auth("acct-alpha", "2026-04-13T00:00:00Z"))
            .expect("auth");

        let manager = ManagerService::new(ManagerOptions {
            codex_home_override: Some(codex_home),
            data_dir_override: Some(app_home),
            local_passphrase: None,
        })
        .expect("manager");

        let report = manager.doctor_report().expect("doctor");

        assert!(report.switch_probes.data_dir_write.ok);
        assert!(report.switch_probes.lock_acquire.ok);
        assert!(report.switch_probes.atomic_swap.ok);
    }

    #[test]
    fn doctor_report_includes_profile_readiness_inventory() {
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
            .expect("save alpha");

        fs::write(codex_home.join("auth.json"), sample_auth("acct-custom", "2026-04-13T06:00:00Z"))
            .expect("auth custom");
        let registry = CredentialDiscoveryRegistry::new(vec![CredentialDiscoveryRule {
            name: "custom-account-id".to_string(),
            source_type: Some(SourceType::ChatGpt),
            service: "custom-openai".to_string(),
            account: "{account_id}".to_string(),
            label: Some("Desktop Session".to_string()),
        }]);
        let system_record = SecretRecord {
            reference: CredentialRef {
                service: "custom-openai".to_string(),
                account: "acct-custom".to_string(),
                label: Some("Desktop Session".to_string()),
            },
            secret: SecretString::new("custom-secret-token".into()),
        };
        let writer = manager_with_store_mode(
            codex_home.clone(),
            app_home.clone(),
            registry.clone(),
            vec![system_record.clone()],
            vec![system_record.clone()],
            "macos_keychain",
            "macos_keychain",
            true,
        );
        writer
            .save_profile(SaveProfileRequest {
                name: "beta".to_string(),
                note: None,
                make_default: false,
            })
            .expect("save beta");

        let checker = manager_with_store_mode(
            codex_home,
            app_home,
            registry,
            vec![system_record],
            Vec::new(),
            "linux_keyring",
            "linux_keyring",
            true,
        );

        let report = checker.doctor_report().expect("doctor");

        assert_eq!(report.profile_readiness.len(), 2);
        assert_eq!(report.profile_readiness[0].profile_name, "alpha");
        assert_eq!(report.profile_readiness[0].status, "ready");
        assert_eq!(report.profile_readiness[1].profile_name, "beta");
        assert_eq!(report.profile_readiness[1].status, "warning");
        assert_eq!(report.profile_readiness[1].warning_count, 1);
    }

    #[test]
    fn doctor_report_recommends_reviewing_blocked_profiles() {
        let temp = tempdir().expect("tempdir");
        let codex_home = temp.path().join("codex-home");
        let app_home = temp.path().join("app-home");
        fs::create_dir_all(&codex_home).expect("codex_home");
        fs::write(codex_home.join("auth.json"), sample_auth("acct-custom", "2026-04-13T06:00:00Z"))
            .expect("auth");
        let registry = CredentialDiscoveryRegistry::new(vec![CredentialDiscoveryRule {
            name: "custom-account-id".to_string(),
            source_type: Some(SourceType::ChatGpt),
            service: "custom-openai".to_string(),
            account: "{account_id}".to_string(),
            label: Some("Desktop Session".to_string()),
        }]);
        let system_record = SecretRecord {
            reference: CredentialRef {
                service: "custom-openai".to_string(),
                account: "acct-custom".to_string(),
                label: Some("Desktop Session".to_string()),
            },
            secret: SecretString::new("custom-secret-token".into()),
        };

        let writer = manager_with_store_mode(
            codex_home.clone(),
            app_home.clone(),
            registry.clone(),
            vec![system_record.clone()],
            vec![system_record.clone()],
            "macos_keychain",
            "macos_keychain",
            true,
        );
        writer
            .save_profile(SaveProfileRequest {
                name: "beta".to_string(),
                note: None,
                make_default: false,
            })
            .expect("save beta");

        let checker = manager_with_store_mode(
            codex_home,
            app_home,
            registry,
            Vec::new(),
            Vec::new(),
            "linux_keyring",
            "linux_keyring",
            false,
        );

        let report = checker.doctor_report().expect("doctor");

        assert!(report.profile_readiness.iter().any(|profile| profile.status == "blocked"));
        assert!(report.recommended_actions.iter().any(|action| {
            action.contains("blocked profile") || action.contains("profile inventory")
        }));
    }

    #[test]
    fn doctor_report_includes_store_usage_summary() {
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
            .expect("save alpha");

        fs::write(codex_home.join("auth.json"), sample_auth("acct-custom", "2026-04-13T06:00:00Z"))
            .expect("auth custom");
        let registry = CredentialDiscoveryRegistry::new(vec![CredentialDiscoveryRule {
            name: "custom-account-id".to_string(),
            source_type: Some(SourceType::ChatGpt),
            service: "custom-openai".to_string(),
            account: "{account_id}".to_string(),
            label: Some("Desktop Session".to_string()),
        }]);
        let system_record = SecretRecord {
            reference: CredentialRef {
                service: "custom-openai".to_string(),
                account: "acct-custom".to_string(),
                label: Some("Desktop Session".to_string()),
            },
            secret: SecretString::new("custom-secret-token".into()),
        };
        let writer = manager_with_store_mode(
            codex_home.clone(),
            app_home.clone(),
            registry.clone(),
            vec![system_record.clone()],
            vec![system_record.clone()],
            "macos_keychain",
            "macos_keychain",
            true,
        );
        writer
            .save_profile(SaveProfileRequest {
                name: "beta".to_string(),
                note: None,
                make_default: false,
            })
            .expect("save beta");

        let checker = manager_with_store_mode(
            codex_home,
            app_home,
            registry,
            vec![system_record],
            Vec::new(),
            "linux_keyring",
            "linux_keyring",
            true,
        );

        let report = checker.doctor_report().expect("doctor");
        let file_only = report
            .store_usage
            .iter()
            .find(|entry| entry.store_name == "file_only")
            .expect("file_only");
        let macos = report
            .store_usage
            .iter()
            .find(|entry| entry.store_name == "macos_keychain")
            .expect("macos");

        assert_eq!(file_only.profile_count, 1);
        assert_eq!(file_only.ready_count, 1);
        assert_eq!(macos.profile_count, 1);
        assert_eq!(macos.warning_count, 1);
    }

    #[test]
    fn doctor_report_recommends_reviewing_blocked_store_dependencies() {
        let temp = tempdir().expect("tempdir");
        let codex_home = temp.path().join("codex-home");
        let app_home = temp.path().join("app-home");
        fs::create_dir_all(&codex_home).expect("codex_home");
        fs::write(codex_home.join("auth.json"), sample_auth("acct-custom", "2026-04-13T06:00:00Z"))
            .expect("auth");
        let registry = CredentialDiscoveryRegistry::new(vec![CredentialDiscoveryRule {
            name: "custom-account-id".to_string(),
            source_type: Some(SourceType::ChatGpt),
            service: "custom-openai".to_string(),
            account: "{account_id}".to_string(),
            label: Some("Desktop Session".to_string()),
        }]);
        let system_record = SecretRecord {
            reference: CredentialRef {
                service: "custom-openai".to_string(),
                account: "acct-custom".to_string(),
                label: Some("Desktop Session".to_string()),
            },
            secret: SecretString::new("custom-secret-token".into()),
        };

        let writer = manager_with_store_mode(
            codex_home.clone(),
            app_home.clone(),
            registry.clone(),
            vec![system_record.clone()],
            vec![system_record.clone()],
            "macos_keychain",
            "macos_keychain",
            true,
        );
        writer
            .save_profile(SaveProfileRequest {
                name: "beta".to_string(),
                note: None,
                make_default: false,
            })
            .expect("save beta");

        let checker = manager_with_store_mode(
            codex_home,
            app_home,
            registry,
            Vec::new(),
            Vec::new(),
            "linux_keyring",
            "linux_keyring",
            false,
        );

        let report = checker.doctor_report().expect("doctor");

        assert!(
            report
                .store_usage
                .iter()
                .any(|entry| { entry.store_name == "macos_keychain" && entry.blocked_count == 1 })
        );
        assert!(
            report
                .recommended_actions
                .iter()
                .any(|action| { action.contains("macos_keychain") && action.contains("blocked") })
        );
    }

    #[test]
    fn doctor_report_marks_validation_as_blocked_without_live_session() {
        let temp = tempdir().expect("tempdir");
        let codex_home = temp.path().join("codex-home");
        let app_home = temp.path().join("app-home");
        fs::create_dir_all(&codex_home).expect("codex_home");

        let manager = manager_with_store_mode(
            codex_home,
            app_home,
            CredentialDiscoveryRegistry::default(),
            Vec::new(),
            Vec::new(),
            "mock_system_store",
            "mock_system_store",
            false,
        );

        let report = manager.doctor_report().expect("doctor");

        assert_eq!(report.validation.status, DoctorValidationStatus::Blocked);
        assert!(report.validation.detail.contains("not ready"));
        assert!(
            report
                .validation
                .next_steps
                .iter()
                .any(|step| { step.contains("official login") || step.contains("live session") })
        );
    }

    #[test]
    fn doctor_report_marks_validation_as_file_only_without_system_store() {
        let temp = tempdir().expect("tempdir");
        let codex_home = temp.path().join("codex-home");
        let app_home = temp.path().join("app-home");
        fs::create_dir_all(&codex_home).expect("codex_home");
        fs::write(codex_home.join("auth.json"), sample_auth("acct-alpha", "2026-04-13T00:00:00Z"))
            .expect("auth");

        let manager = manager_with_store_mode(
            codex_home,
            app_home,
            CredentialDiscoveryRegistry::default(),
            Vec::new(),
            Vec::new(),
            "mock_system_store",
            "mock_system_store",
            false,
        );
        manager
            .save_profile(SaveProfileRequest {
                name: "alpha".to_string(),
                note: None,
                make_default: false,
            })
            .expect("save");

        let report = manager.doctor_report().expect("doctor");

        assert_eq!(report.validation.status, DoctorValidationStatus::FileOnly);
        assert_eq!(report.validation.active_store_name, None);
        assert_eq!(report.validation.mixed_profile_count, 0);
        assert!(report.validation.detail.contains("file-backed"));
    }

    #[test]
    fn doctor_report_marks_validation_as_ready_when_mixed_mode_can_be_verified() {
        let temp = tempdir().expect("tempdir");
        let codex_home = temp.path().join("codex-home");
        let app_home = temp.path().join("app-home");
        fs::create_dir_all(&codex_home).expect("codex_home");
        fs::write(codex_home.join("auth.json"), sample_auth("acct-custom", "2026-04-13T06:00:00Z"))
            .expect("auth");
        let registry = CredentialDiscoveryRegistry::new(vec![CredentialDiscoveryRule {
            name: "custom-account-id".to_string(),
            source_type: Some(SourceType::ChatGpt),
            service: "custom-openai".to_string(),
            account: "{account_id}".to_string(),
            label: Some("Desktop Session".to_string()),
        }]);
        let system_record = SecretRecord {
            reference: CredentialRef {
                service: "custom-openai".to_string(),
                account: "acct-custom".to_string(),
                label: Some("Desktop Session".to_string()),
            },
            secret: SecretString::new("custom-secret-token".into()),
        };
        let manager = manager_with_store_mode(
            codex_home,
            app_home,
            registry,
            vec![system_record.clone()],
            vec![system_record],
            "linux_keyring",
            "linux_keyring",
            true,
        );
        manager
            .save_profile(SaveProfileRequest {
                name: "alpha".to_string(),
                note: None,
                make_default: false,
            })
            .expect("save");

        let report = manager.doctor_report().expect("doctor");

        assert_eq!(report.validation.status, DoctorValidationStatus::Ready);
        assert_eq!(report.validation.active_store_name.as_deref(), Some("linux_keyring"));
        assert_eq!(report.validation.mixed_profile_count, 1);
        assert!(report.validation.next_steps.iter().any(|step| step.contains("diagnostic bundle")));
        assert!(report.validation.next_steps.iter().any(|step| step.contains("mixed")));
    }

    #[test]
    fn current_status_serialization_redacts_live_auth_contents() {
        let temp = tempdir().expect("tempdir");
        let codex_home = temp.path().join("codex-home");
        let app_home = temp.path().join("app-home");
        fs::create_dir_all(&codex_home).expect("codex_home");
        fs::write(codex_home.join("auth.json"), sample_auth("acct-alpha", "2026-04-13T00:00:00Z"))
            .expect("auth");

        let manager = ManagerService::new(ManagerOptions {
            codex_home_override: Some(codex_home),
            data_dir_override: Some(app_home),
            local_passphrase: None,
        })
        .expect("manager");

        let current = manager.current_status().expect("current");
        let json = serde_json::to_string(&current).expect("json");

        assert!(!json.contains("refresh-acct-alpha"));
        assert!(!json.contains("access-acct-alpha"));
        assert!(!json.contains("\"contents\""));
        assert!(json.contains("\"byte_length\""));
    }

    #[test]
    fn detect_report_masks_system_entry_accounts() {
        let temp = tempdir().expect("tempdir");
        let codex_home = temp.path().join("codex-home");
        let app_home = temp.path().join("app-home");
        fs::create_dir_all(&codex_home).expect("codex_home");
        fs::write(codex_home.join("auth.json"), sample_auth("acct-custom", "2026-04-13T06:00:00Z"))
            .expect("auth");

        let manager = manager_with_registry(
            codex_home,
            app_home,
            CredentialDiscoveryRegistry::new(vec![CredentialDiscoveryRule {
                name: "custom-openai".to_string(),
                source_type: Some(SourceType::ChatGpt),
                service: "custom-openai".to_string(),
                account: "person@example.com".to_string(),
                label: Some("Desktop Session".to_string()),
            }]),
            vec![SecretRecord {
                reference: CredentialRef {
                    service: "custom-openai".to_string(),
                    account: "person@example.com".to_string(),
                    label: Some("Desktop Session".to_string()),
                },
                secret: SecretString::new("custom-secret-token".into()),
            }],
        );

        let report = manager.detect_report().expect("report");
        let json = serde_json::to_string(&report).expect("json");

        assert!(!json.contains("person@example.com"));
        assert!(json.contains("pe***@example.com"));
        assert!(!json.contains("custom-secret-token"));
    }

    #[test]
    fn export_diagnostic_bundle_writes_redacted_json() {
        let temp = tempdir().expect("tempdir");
        let codex_home = temp.path().join("codex-home");
        let app_home = temp.path().join("app-home");
        fs::create_dir_all(&codex_home).expect("codex_home");
        fs::write(codex_home.join("auth.json"), sample_auth("acct-alpha", "2026-04-13T00:00:00Z"))
            .expect("auth");

        let manager = ManagerService::new(ManagerOptions {
            codex_home_override: Some(codex_home),
            data_dir_override: Some(app_home.clone()),
            local_passphrase: None,
        })
        .expect("manager");
        manager
            .save_profile(SaveProfileRequest {
                name: "alpha".to_string(),
                note: Some("personal".to_string()),
                make_default: true,
            })
            .expect("save");

        let bundle_path = manager.export_diagnostic_bundle(None).expect("bundle");
        let contents = fs::read_to_string(&bundle_path).expect("bundle contents");

        assert!(bundle_path.starts_with(app_home.join("exports")));
        assert!(contents.contains("\"doctor\""));
        assert!(contents.contains("\"profiles\""));
        assert!(!contents.contains("refresh-acct-alpha"));
        assert!(!contents.contains("access-acct-alpha"));
        assert!(!contents.contains("\"contents\""));
    }

    #[test]
    fn export_diagnostic_bundle_records_validation_evidence() {
        let temp = tempdir().expect("tempdir");
        let codex_home = temp.path().join("codex-home");
        let app_home = temp.path().join("app-home");
        fs::create_dir_all(&codex_home).expect("codex_home");
        fs::write(codex_home.join("auth.json"), sample_auth("acct-alpha", "2026-04-13T00:00:00Z"))
            .expect("auth");

        let manager = manager_with_store_mode(
            codex_home,
            app_home.clone(),
            CredentialDiscoveryRegistry::default(),
            Vec::new(),
            Vec::new(),
            "mock_system_store",
            "mock_system_store",
            false,
        );

        let bundle_path = manager.export_diagnostic_bundle(None).expect("bundle");
        let evidence_files = list_json_files(&app_home.join("validation")).expect("evidence files");

        assert_eq!(evidence_files.len(), 1);
        let evidence_json = fs::read_to_string(&evidence_files[0]).expect("evidence json");
        let evidence: serde_json::Value =
            serde_json::from_str(&evidence_json).expect("evidence value");
        assert_eq!(evidence["validation_status"], "file_only");
        assert!(evidence_json.contains(&bundle_path.display().to_string()));
        assert!(evidence_json.contains(std::env::consts::OS));
    }

    #[test]
    fn doctor_report_includes_validation_evidence_matrix_after_bundle_export() {
        let temp = tempdir().expect("tempdir");
        let codex_home = temp.path().join("codex-home");
        let app_home = temp.path().join("app-home");
        fs::create_dir_all(&codex_home).expect("codex_home");
        fs::write(codex_home.join("auth.json"), sample_auth("acct-alpha", "2026-04-13T00:00:00Z"))
            .expect("auth");

        let manager = manager_with_store_mode(
            codex_home,
            app_home,
            CredentialDiscoveryRegistry::default(),
            Vec::new(),
            Vec::new(),
            "mock_system_store",
            "mock_system_store",
            false,
        );
        manager.export_diagnostic_bundle(None).expect("bundle");

        let report = manager.doctor_report().expect("doctor");
        let current_platform = report
            .validation_evidence
            .iter()
            .find(|entry| entry.operating_system == std::env::consts::OS)
            .expect("current platform");

        assert_eq!(report.validation_evidence.len(), 3);
        assert_eq!(current_platform.evidence_count, 1);
        assert_eq!(
            current_platform.latest_validation_status,
            Some(DoctorValidationStatus::FileOnly)
        );
        assert!(current_platform.detail.contains("Latest evidence captured"));
    }

    #[test]
    fn doctor_report_recommends_missing_validation_platform_evidence() {
        let temp = tempdir().expect("tempdir");
        let codex_home = temp.path().join("codex-home");
        let app_home = temp.path().join("app-home");
        fs::create_dir_all(&codex_home).expect("codex_home");
        fs::write(codex_home.join("auth.json"), sample_auth("acct-alpha", "2026-04-13T00:00:00Z"))
            .expect("auth");

        let manager = manager_with_store_mode(
            codex_home,
            app_home,
            CredentialDiscoveryRegistry::default(),
            Vec::new(),
            Vec::new(),
            "mock_system_store",
            "mock_system_store",
            false,
        );
        manager.export_diagnostic_bundle(None).expect("bundle");

        let report = manager.doctor_report().expect("doctor");
        let missing_platforms = ["macos", "windows", "linux"]
            .into_iter()
            .filter(|platform| *platform != std::env::consts::OS)
            .collect::<Vec<_>>();

        assert!(report.recommended_actions.iter().any(|action| {
            action.contains("Validation evidence is still missing")
                && missing_platforms.iter().any(|platform| action.contains(platform))
        }));
    }

    #[test]
    fn doctor_report_flags_missing_file_backed_validation_coverage() {
        let temp = tempdir().expect("tempdir");
        let codex_home = temp.path().join("codex-home");
        let app_home = temp.path().join("app-home");
        fs::create_dir_all(&codex_home).expect("codex_home");
        fs::write(codex_home.join("auth.json"), sample_auth("acct-alpha", "2026-04-13T00:00:00Z"))
            .expect("auth");

        let manager = manager_with_store_mode(
            codex_home,
            app_home,
            CredentialDiscoveryRegistry::default(),
            Vec::new(),
            Vec::new(),
            "mock_system_store",
            "mock_system_store",
            false,
        );
        manager
            .save_profile(SaveProfileRequest {
                name: "alpha".to_string(),
                note: None,
                make_default: false,
            })
            .expect("save");

        let report = manager.doctor_report().expect("doctor");

        assert!(!report.validation_coverage.file_backed_recorded);
        assert!(!report.validation_coverage.mixed_mode_required);
        assert!(!report.validation_coverage.mixed_mode_recorded);
        assert!(report.validation_coverage.missing_platforms.len() == 3);
        assert!(
            report
                .validation_coverage
                .next_target
                .contains("file-backed validation pass on this machine")
        );
    }

    #[test]
    fn doctor_report_flags_missing_mixed_mode_validation_coverage() {
        let temp = tempdir().expect("tempdir");
        let codex_home = temp.path().join("codex-home");
        let app_home = temp.path().join("app-home");
        fs::create_dir_all(&codex_home).expect("codex_home");
        fs::write(codex_home.join("auth.json"), sample_auth("acct-custom", "2026-04-13T06:00:00Z"))
            .expect("auth");

        let registry = CredentialDiscoveryRegistry::new(vec![CredentialDiscoveryRule {
            name: "custom-account-id".to_string(),
            source_type: Some(SourceType::ChatGpt),
            service: "custom-openai".to_string(),
            account: "{account_id}".to_string(),
            label: Some("Desktop Session".to_string()),
        }]);
        let system_record = SecretRecord {
            reference: CredentialRef {
                service: "custom-openai".to_string(),
                account: "acct-custom".to_string(),
                label: Some("Desktop Session".to_string()),
            },
            secret: SecretString::new("custom-secret-token".into()),
        };
        let manager = manager_with_store_mode(
            codex_home,
            app_home.clone(),
            registry,
            vec![system_record.clone()],
            vec![system_record],
            "linux_keyring",
            "linux_keyring",
            true,
        );
        manager
            .save_profile(SaveProfileRequest {
                name: "alpha".to_string(),
                note: None,
                make_default: false,
            })
            .expect("save");

        write_validation_evidence(
            &app_home,
            std::env::consts::OS,
            DoctorValidationStatus::FileOnly,
            None,
        );

        let report = manager.doctor_report().expect("doctor");

        assert!(report.validation_coverage.file_backed_recorded);
        assert!(report.validation_coverage.mixed_mode_required);
        assert!(!report.validation_coverage.mixed_mode_recorded);
        assert!(report.validation_coverage.next_target.contains("mixed-mode evidence gap"));
    }

    #[test]
    fn doctor_report_marks_validation_coverage_complete_when_all_platforms_are_recorded() {
        let temp = tempdir().expect("tempdir");
        let codex_home = temp.path().join("codex-home");
        let app_home = temp.path().join("app-home");
        fs::create_dir_all(&codex_home).expect("codex_home");
        fs::write(codex_home.join("auth.json"), sample_auth("acct-custom", "2026-04-13T06:00:00Z"))
            .expect("auth");

        let registry = CredentialDiscoveryRegistry::new(vec![CredentialDiscoveryRule {
            name: "custom-account-id".to_string(),
            source_type: Some(SourceType::ChatGpt),
            service: "custom-openai".to_string(),
            account: "{account_id}".to_string(),
            label: Some("Desktop Session".to_string()),
        }]);
        let system_record = SecretRecord {
            reference: CredentialRef {
                service: "custom-openai".to_string(),
                account: "acct-custom".to_string(),
                label: Some("Desktop Session".to_string()),
            },
            secret: SecretString::new("custom-secret-token".into()),
        };
        let manager = manager_with_store_mode(
            codex_home,
            app_home.clone(),
            registry,
            vec![system_record.clone()],
            vec![system_record],
            "linux_keyring",
            "linux_keyring",
            true,
        );
        manager
            .save_profile(SaveProfileRequest {
                name: "alpha".to_string(),
                note: None,
                make_default: false,
            })
            .expect("save");

        write_validation_evidence(
            &app_home,
            "macos",
            DoctorValidationStatus::Ready,
            Some("mac_keychain"),
        );
        write_validation_evidence(&app_home, "windows", DoctorValidationStatus::FileOnly, None);
        write_validation_evidence(&app_home, "linux", DoctorValidationStatus::FileOnly, None);

        let report = manager.doctor_report().expect("doctor");

        assert!(report.validation_coverage.file_backed_recorded);
        assert!(report.validation_coverage.mixed_mode_recorded);
        assert!(report.validation_coverage.mixed_mode_required);
        assert!(report.validation_coverage.missing_platforms.is_empty());
        assert!(report.validation_coverage.detail.contains("covers current"));
    }

    #[test]
    fn doctor_report_surfaces_pending_recovery_transactions() {
        let temp = tempdir().expect("tempdir");
        let codex_home = temp.path().join("codex-home");
        let app_home = temp.path().join("app-home");
        fs::create_dir_all(&codex_home).expect("codex_home");
        fs::create_dir_all(app_home.join("tx")).expect("tx_dir");
        fs::write(codex_home.join("auth.json"), sample_auth("acct-alpha", "2026-04-13T00:00:00Z"))
            .expect("auth");

        let manager = ManagerService::new(ManagerOptions {
            codex_home_override: Some(codex_home.clone()),
            data_dir_override: Some(app_home.clone()),
            local_passphrase: None,
        })
        .expect("manager");
        let live = manager.detect().expect("live");
        let txn = SwitchTransaction {
            txn_id: Uuid::new_v4(),
            source_profile_id: None,
            source_live_fingerprint: live.live_fingerprint,
            target_profile_id: Uuid::new_v4(),
            started_at: Utc::now(),
            backup_paths: vec!["auth.json".to_string()],
            backup_system_entries: Vec::new(),
            backup_system_records: Vec::new(),
            phase: SwitchPhase::AppliedFiles,
            rollback_required: true,
        };
        fs::write(
            app_home.join("tx").join(format!("{}.json", txn.txn_id)),
            serde_json::to_vec_pretty(&txn).expect("txn json"),
        )
        .expect("write txn");

        let report = manager.doctor_report().expect("doctor");

        assert_eq!(report.recovery.pending_count, 1);
        assert_eq!(report.recovery.rollback_required_count, 1);
        assert!(report.recommended_actions.iter().any(|action| action.contains("recover")));
    }

    #[test]
    fn recover_pending_transactions_restores_auth_file_and_cleans_artifacts() {
        let temp = tempdir().expect("tempdir");
        let codex_home = temp.path().join("codex-home");
        let app_home = temp.path().join("app-home");
        let backup_auth = sample_auth("acct-alpha", "2026-04-13T00:00:00Z");
        let switched_auth = sample_auth("acct-beta", "2026-04-13T01:00:00Z");
        fs::create_dir_all(&codex_home).expect("codex_home");
        fs::write(codex_home.join("auth.json"), &backup_auth).expect("auth");

        let manager = ManagerService::new(ManagerOptions {
            codex_home_override: Some(codex_home.clone()),
            data_dir_override: Some(app_home.clone()),
            local_passphrase: None,
        })
        .expect("manager");
        let live = manager.detect().expect("live");
        fs::write(codex_home.join("auth.json"), &switched_auth).expect("mutate auth");

        let txn_id = Uuid::new_v4();
        let backup_root = app_home.join("tx").join(txn_id.to_string()).join("backup");
        fs::create_dir_all(&backup_root).expect("backup root");
        fs::write(backup_root.join("auth.json"), &backup_auth).expect("backup auth");
        let txn = SwitchTransaction {
            txn_id,
            source_profile_id: None,
            source_live_fingerprint: live.live_fingerprint,
            target_profile_id: Uuid::new_v4(),
            started_at: Utc::now(),
            backup_paths: vec!["auth.json".to_string()],
            backup_system_entries: Vec::new(),
            backup_system_records: Vec::new(),
            phase: SwitchPhase::AppliedFiles,
            rollback_required: true,
        };
        fs::write(
            app_home.join("tx").join(format!("{}.json", txn.txn_id)),
            serde_json::to_vec_pretty(&txn).expect("txn json"),
        )
        .expect("write txn");

        let report = manager.recover_pending_transactions().expect("recover");

        assert_eq!(report.recovered_count, 1);
        assert!(!app_home.join("tx").join(format!("{}.json", txn.txn_id)).exists());
        assert!(!app_home.join("tx").join(txn.txn_id.to_string()).exists());
        assert_eq!(fs::read_to_string(codex_home.join("auth.json")).expect("auth"), backup_auth);
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
