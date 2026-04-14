use codex_switch_application::{
    CheckReport, CurrentStatus, ManagerOptions, ManagerService, SaveProfileRequest,
    UseProfileRequest,
};
use codex_switch_domain::ProfileMeta;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
struct DashboardData {
    current: CurrentStatus,
    profiles: Vec<ProfileMeta>,
    logs: String,
}

#[derive(Debug, Deserialize)]
struct SaveProfilePayload {
    name: String,
    note: Option<String>,
    make_default: bool,
}

#[derive(Debug, Deserialize)]
struct UseProfilePayload {
    name: String,
    make_default: bool,
}

type CommandResult<T> = std::result::Result<T, String>;

fn manager() -> CommandResult<ManagerService> {
    ManagerService::new(ManagerOptions::default()).map_err(|error| error.to_string())
}

fn load_dashboard(manager: &ManagerService) -> CommandResult<DashboardData> {
    Ok(DashboardData {
        current: manager.current_status().map_err(|error| error.to_string())?,
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

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            dashboard,
            save_profile,
            use_profile,
            check_profile,
            sync_active_profile
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
