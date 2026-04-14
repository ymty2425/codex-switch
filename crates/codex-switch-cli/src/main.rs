use std::{env, path::PathBuf};

use clap::{Parser, Subcommand};
use codex_switch_application::{
    CheckReport, CurrentStatus, DoctorReport, LiveSessionSummary, ManagerOptions, ManagerService,
    RecoveryReport, SaveProfileRequest, UseProfileRequest,
};
use codex_switch_domain::{ProfileMeta, Result, SwitchError};
use secrecy::SecretString;
use serde::Serialize;

#[derive(Debug, Parser)]
#[command(name = "codex-switch")]
#[command(about = "Manage multiple official Codex local sessions without re-authenticating")]
struct Cli {
    #[arg(long)]
    json: bool,
    #[arg(long)]
    codex_home: Option<PathBuf>,
    #[arg(long)]
    data_dir: Option<PathBuf>,
    #[arg(long, default_value = "CODEX_SWITCH_MASTER_PASSPHRASE")]
    local_passphrase_env: String,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    Detect,
    Doctor,
    Bundle {
        #[arg(long)]
        output: Option<PathBuf>,
    },
    Recover,
    Save {
        name: String,
        #[arg(long)]
        note: Option<String>,
        #[arg(long)]
        default: bool,
    },
    List,
    Use {
        name: String,
        #[arg(long)]
        default: bool,
    },
    Current,
    Check {
        name: String,
    },
    Sync,
    Rename {
        old: String,
        new: String,
    },
    Delete {
        name: String,
    },
    Export {
        name: String,
        #[arg(long)]
        output: Option<PathBuf>,
        #[arg(long, default_value = "CODEX_SWITCH_PASSPHRASE")]
        passphrase_env: String,
    },
    Import {
        path: PathBuf,
        #[arg(long, default_value = "CODEX_SWITCH_PASSPHRASE")]
        passphrase_env: String,
    },
}

#[derive(Debug, Serialize)]
struct MessageEnvelope<T: Serialize> {
    action: &'static str,
    data: T,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    let manager = ManagerService::new(ManagerOptions {
        codex_home_override: cli.codex_home,
        data_dir_override: cli.data_dir,
        local_passphrase: read_optional_secret(&cli.local_passphrase_env),
    })?;

    match cli.command {
        Commands::Detect => {
            let report = manager.detect_report()?;
            if cli.json {
                print_result(true, "detect", &report)
            } else {
                print_detect(&report);
                Ok(())
            }
        }
        Commands::Doctor => {
            let report = manager.doctor_report()?;
            if cli.json {
                print_result(true, "doctor", &report)
            } else {
                print_doctor(&report);
                Ok(())
            }
        }
        Commands::Bundle { output } => {
            let bundle_path = manager.export_diagnostic_bundle(output.as_deref())?;
            if cli.json {
                print_result(true, "bundle", &serde_json::json!({ "bundle": bundle_path }))
            } else {
                println!("{}", bundle_path.display());
                Ok(())
            }
        }
        Commands::Recover => {
            let report = manager.recover_pending_transactions()?;
            if cli.json {
                print_result(true, "recover", &report)
            } else {
                print_recover(&report);
                Ok(())
            }
        }
        Commands::Save { name, note, default } => {
            let profile =
                manager.save_profile(SaveProfileRequest { name, note, make_default: default })?;
            print_result(cli.json, "save", &profile)
        }
        Commands::List => {
            let profiles = manager.list_profiles()?;
            if cli.json {
                print_result(true, "list", &profiles)
            } else {
                print_profiles(&profiles);
                Ok(())
            }
        }
        Commands::Use { name, default } => {
            let profile = manager.use_profile(UseProfileRequest { name, make_default: default })?;
            print_result(cli.json, "use", &profile)
        }
        Commands::Current => {
            let current = manager.current_status()?;
            if cli.json {
                print_result(true, "current", &current)
            } else {
                print_current(&current);
                Ok(())
            }
        }
        Commands::Check { name } => {
            let report = manager.check_profile(&name)?;
            if cli.json {
                print_result(true, "check", &report)
            } else {
                print_check(&report);
                Ok(())
            }
        }
        Commands::Sync => print_result(cli.json, "sync", &manager.sync_active_profile()?),
        Commands::Rename { old, new } => {
            let profile = manager.rename_profile(&old, &new)?;
            print_result(cli.json, "rename", &profile)
        }
        Commands::Delete { name } => {
            manager.delete_profile(&name)?;
            if cli.json {
                print_result(
                    true,
                    "delete",
                    &serde_json::json!({ "deleted": name, "status": "ok" }),
                )
            } else {
                println!("Deleted profile '{name}'.");
                Ok(())
            }
        }
        Commands::Export { name, output, passphrase_env } => {
            let passphrase = read_required_secret(&passphrase_env)?;
            let archive = manager.export_profile(&name, passphrase, output.as_deref())?;
            if cli.json {
                print_result(true, "export", &serde_json::json!({ "archive": archive }))
            } else {
                println!("{}", archive.display());
                Ok(())
            }
        }
        Commands::Import { path, passphrase_env } => {
            let passphrase = read_required_secret(&passphrase_env)?;
            let profile = manager.import_profile(&path, passphrase)?;
            print_result(cli.json, "import", &profile)
        }
    }
}

fn read_optional_secret(env_name: &str) -> Option<SecretString> {
    env::var(env_name)
        .ok()
        .filter(|value| !value.is_empty())
        .map(|value| SecretString::new(value.into()))
}

fn read_required_secret(env_name: &str) -> Result<SecretString> {
    read_optional_secret(env_name).ok_or_else(|| {
        SwitchError::CredentialUnavailable(format!(
            "Missing passphrase in environment variable {env_name}"
        ))
    })
}

fn print_result<T: Serialize>(json: bool, action: &'static str, value: &T) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(&MessageEnvelope { action, data: value })?);
    } else {
        println!("{}", serde_json::to_string_pretty(value)?);
    }
    Ok(())
}

fn print_profiles(profiles: &[ProfileMeta]) {
    if profiles.is_empty() {
        println!("No profiles saved yet.");
        return;
    }

    for profile in profiles {
        let default_marker = if profile.is_default { "*" } else { " " };
        println!(
            "{default_marker} {}  {}  {:?}  {:?}  {:?}  {}",
            profile.name,
            profile.account_label_masked,
            profile.source_type,
            profile.credential_mode,
            profile.health.status,
            profile.created_at.to_rfc3339()
        );
    }
}

fn print_current(current: &CurrentStatus) {
    println!("Live account: {}", current.live_session.account_label_masked);
    println!("Live fingerprint: {}", current.live_session.account_fingerprint);
    println!("Live source: {:?}", current.live_session.source_type);
    println!("Live credential mode: {:?}", current.live_session.credential_mode);
    if let Some(profile) = &current.active_profile {
        println!("Active profile: {}", profile.name);
        println!("Active profile mode: {:?}", profile.credential_mode);
    } else {
        println!("Active profile: none");
    }
    println!("Sync status: {:?}", current.sync_state.status);
    println!("{}", current.sync_state.detail);
}

fn print_detect(report: &LiveSessionSummary) {
    println!("Live account: {}", report.account_label_masked);
    println!("Live fingerprint: {}", report.account_fingerprint);
    println!("Auth mode: {:?}", report.auth_mode);
    println!("Live source: {:?}", report.source_type);
    println!("Live credential mode: {:?}", report.credential_mode);
    println!("Codex home: {}", report.codex_home);
    if !report.file_entries.is_empty() {
        println!("File entries:");
        for entry in &report.file_entries {
            println!(
                "- {}  bytes={} permissions={:?}",
                entry.relative_path, entry.byte_length, entry.permissions
            );
        }
    }
    if !report.system_entries.is_empty() {
        println!("System entries:");
        for entry in &report.system_entries {
            println!(
                "- {} / {}  {}",
                entry.service, entry.account_label_masked, entry.masked_value_hint
            );
        }
    }
}

fn print_check(report: &CheckReport) {
    println!("Profile: {}", report.profile.name);
    println!("Credential mode: {:?}", report.profile.credential_mode);
    println!("Status: {:?}", report.profile.health.status);
    println!("{}", report.detail);
}

fn print_doctor(report: &DoctorReport) {
    println!("OS: {}", report.operating_system);
    println!("CODEX_HOME: {}", report.codex_home);
    println!("Data dir: {}", report.data_dir);
    println!(
        "Auth file: {}  exists={} readable={}",
        report.auth_file.path, report.auth_file.exists, report.auth_file.readable
    );
    println!("Discovery rules: {}", report.discovery_rule_count);
    println!("Live session detected: {}", report.live_session.detected);
    println!("{}", report.live_session.detail);
    if let Some(account) = &report.live_session.account_label_masked {
        println!("Detected account: {account}");
    }
    println!("{}", report.discovery_trace.detail);
    for entry in &report.discovery_trace.entries {
        println!(
            "Trace {}  status={:?} service={} account={}  {}",
            entry.rule_name,
            entry.status,
            entry.service.as_deref().unwrap_or("-"),
            entry.account_label_masked.as_deref().unwrap_or("-"),
            entry.detail
        );
    }
    println!("{}", report.switch_probes.detail);
    println!(
        "Probe data_dir_write ok={}  {}",
        report.switch_probes.data_dir_write.ok, report.switch_probes.data_dir_write.detail
    );
    println!(
        "Probe lock_acquire ok={}  {}",
        report.switch_probes.lock_acquire.ok, report.switch_probes.lock_acquire.detail
    );
    println!(
        "Probe atomic_swap ok={}  {}",
        report.switch_probes.atomic_swap.ok, report.switch_probes.atomic_swap.detail
    );
    for store in &report.stores {
        println!(
            "Store {}  supported={} available={}  {}",
            store.name, store.supported, store.available, store.detail
        );
    }
    println!(
        "Pending transactions: {}  rollback_required={}",
        report.recovery.pending_count, report.recovery.rollback_required_count
    );
    println!("{}", report.recovery.detail);
    for txn in &report.recovery.transactions {
        println!(
            "Transaction {}  phase={:?} rollback_required={} started_at={}",
            txn.txn_id,
            txn.phase,
            txn.rollback_required,
            txn.started_at.to_rfc3339()
        );
    }
    if !report.recommended_actions.is_empty() {
        println!("Recommendations:");
        for action in &report.recommended_actions {
            println!("- {action}");
        }
    }
}

fn print_recover(report: &RecoveryReport) {
    println!("Recovered: {}", report.recovered_count);
    println!("Removed transactions: {}", report.removed_count);
    println!("{}", report.detail);
    if !report.transactions.is_empty() {
        println!("Transactions:");
        for txn in &report.transactions {
            println!(
                "- {}  phase={:?} rollback_required={} started_at={}",
                txn.txn_id,
                txn.phase,
                txn.rollback_required,
                txn.started_at.to_rfc3339()
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    #[test]
    fn reads_optional_secret_from_environment() {
        let key = format!("CODEX_SWITCH_TEST_SECRET_{}", std::process::id());
        unsafe { env::set_var(&key, "secret-value") };
        let value = read_optional_secret(&key).expect("secret");
        assert_eq!(value.expose_secret(), "secret-value");
        unsafe { env::remove_var(&key) };
    }
}
