use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoreDiagnostic {
    pub name: String,
    pub supported: bool,
    pub available: bool,
    pub detail: String,
}

#[must_use]
pub fn default_store_diagnostics() -> Vec<StoreDiagnostic> {
    vec![diagnose_macos_keychain(), diagnose_linux_keyring(), diagnose_windows_credential_manager()]
}

fn diagnose_macos_keychain() -> StoreDiagnostic {
    if !cfg!(target_os = "macos") {
        return StoreDiagnostic {
            name: "macos_keychain".to_string(),
            supported: false,
            available: false,
            detail: "Available only on macOS.".to_string(),
        };
    }

    match which::which("security") {
        Ok(path) => StoreDiagnostic {
            name: "macos_keychain".to_string(),
            supported: true,
            available: true,
            detail: format!("Keychain CLI available at {}.", path.display()),
        },
        Err(_) => StoreDiagnostic {
            name: "macos_keychain".to_string(),
            supported: true,
            available: false,
            detail: "The macOS security CLI was not found in PATH.".to_string(),
        },
    }
}

fn diagnose_linux_keyring() -> StoreDiagnostic {
    if !cfg!(target_os = "linux") {
        return StoreDiagnostic {
            name: "linux_keyring".to_string(),
            supported: false,
            available: false,
            detail: "Available only on Linux.".to_string(),
        };
    }

    match which::which("secret-tool") {
        Ok(path) => StoreDiagnostic {
            name: "linux_keyring".to_string(),
            supported: true,
            available: true,
            detail: format!("Secret Service CLI available at {}.", path.display()),
        },
        Err(_) => StoreDiagnostic {
            name: "linux_keyring".to_string(),
            supported: true,
            available: false,
            detail: "secret-tool is missing, so Secret Service integration is unavailable."
                .to_string(),
        },
    }
}

fn diagnose_windows_credential_manager() -> StoreDiagnostic {
    if !cfg!(target_os = "windows") {
        return StoreDiagnostic {
            name: "windows_credential_manager".to_string(),
            supported: false,
            available: false,
            detail: "Available only on Windows.".to_string(),
        };
    }

    StoreDiagnostic {
        name: "windows_credential_manager".to_string(),
        supported: true,
        available: false,
        detail:
            "A Windows-specific runtime implementation is still needed before Credential Manager can be used."
                .to_string(),
    }
}
