use codex_switch_application::{
    CheckReport, CurrentStatus, DoctorReport, ManagerOptions, ManagerService, SaveProfileRequest,
    UseProfileRequest,
};
use codex_switch_domain::ProfileMeta;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Serialize)]
struct DashboardData {
    current: CurrentStatus,
    doctor: DoctorReport,
    profiles: Vec<ProfileMeta>,
    logs: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SaveProfilePayload {
    name: String,
    note: Option<String>,
    make_default: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UseProfilePayload {
    name: String,
    make_default: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RenameProfilePayload {
    old_name: String,
    new_name: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExportProfilePayload {
    name: String,
    passphrase: String,
    output: Option<PathBuf>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ImportProfilePayload {
    path: PathBuf,
    passphrase: String,
}

type CommandResult<T> = std::result::Result<T, String>;

fn manager() -> CommandResult<ManagerService> {
    ManagerService::new(ManagerOptions::default()).map_err(|error| error.to_string())
}

fn load_dashboard(manager: &ManagerService) -> CommandResult<DashboardData> {
    Ok(DashboardData {
        current: manager.current_status().map_err(|error| error.to_string())?,
        doctor: manager.doctor_report().map_err(|error| error.to_string())?,
        profiles: manager.list_profiles().map_err(|error| error.to_string())?,
        logs: manager.read_audit_log().map_err(|error| error.to_string())?,
    })
}

#[tauri::command]
fn dashboard() -> CommandResult<DashboardData> {
    let manager = manager()?;
    load_dashboard(&manager)
}

#[tauri::command]
fn save_profile(payload: SaveProfilePayload) -> CommandResult<DashboardData> {
    let manager = manager()?;
    manager
        .save_profile(SaveProfileRequest {
            name: payload.name,
            note: payload.note,
            make_default: payload.make_default,
        })
        .map_err(|error| error.to_string())?;
    load_dashboard(&manager)
}

#[tauri::command]
fn use_profile(payload: UseProfilePayload) -> CommandResult<DashboardData> {
    let manager = manager()?;
    manager
        .use_profile(UseProfileRequest { name: payload.name, make_default: payload.make_default })
        .map_err(|error| error.to_string())?;
    load_dashboard(&manager)
}

#[tauri::command]
fn check_profile(name: String) -> CommandResult<CheckReport> {
    manager()?.check_profile(&name).map_err(|error| error.to_string())
}

#[tauri::command]
fn sync_active_profile() -> CommandResult<DashboardData> {
    let manager = manager()?;
    manager.sync_active_profile().map_err(|error| error.to_string())?;
    load_dashboard(&manager)
}

#[tauri::command]
fn rename_profile(payload: RenameProfilePayload) -> CommandResult<DashboardData> {
    let manager = manager()?;
    manager
        .rename_profile(&payload.old_name, &payload.new_name)
        .map_err(|error| error.to_string())?;
    load_dashboard(&manager)
}

#[tauri::command]
fn delete_profile(name: String) -> CommandResult<DashboardData> {
    let manager = manager()?;
    manager.delete_profile(&name).map_err(|error| error.to_string())?;
    load_dashboard(&manager)
}

#[tauri::command]
fn set_default_profile(name: String) -> CommandResult<DashboardData> {
    let manager = manager()?;
    manager.set_default_profile_by_name(&name).map_err(|error| error.to_string())?;
    load_dashboard(&manager)
}

#[tauri::command]
fn export_profile(payload: ExportProfilePayload) -> CommandResult<String> {
    manager()?
        .export_profile(
            &payload.name,
            SecretString::new(payload.passphrase.into()),
            payload.output.as_deref(),
        )
        .map(|path| path.display().to_string())
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn import_profile(payload: ImportProfilePayload) -> CommandResult<DashboardData> {
    let manager = manager()?;
    manager
        .import_profile(&payload.path, SecretString::new(payload.passphrase.into()))
        .map_err(|error| error.to_string())?;
    load_dashboard(&manager)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            dashboard,
            save_profile,
            use_profile,
            check_profile,
            sync_active_profile,
            rename_profile,
            delete_profile,
            set_default_profile,
            export_profile,
            import_profile
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
