use std::process::Command;

use codex_switch_domain::{
    CredentialMode, CredentialRef, OfficialCredentialStore, Result, SecretRecord, SwitchError,
};
use secrecy::ExposeSecret;

#[derive(Debug, Default)]
pub struct MacKeychainCredentialStore;

impl MacKeychainCredentialStore {
    fn ensure_supported() -> Result<()> {
        if cfg!(target_os = "macos") {
            Ok(())
        } else {
            Err(SwitchError::UnsupportedPlatform(
                "macOS Keychain is only available on macOS".to_string(),
            ))
        }
    }
}

impl OfficialCredentialStore for MacKeychainCredentialStore {
    fn kind(&self) -> CredentialMode {
        CredentialMode::System
    }

    fn store_name(&self) -> &'static str {
        "macos_keychain"
    }

    fn is_available(&self) -> bool {
        cfg!(target_os = "macos")
    }

    fn read(&self, refs: &[CredentialRef]) -> Result<Vec<SecretRecord>> {
        Self::ensure_supported()?;
        let mut records = Vec::new();
        for reference in refs {
            let output = Command::new("security")
                .arg("find-generic-password")
                .arg("-s")
                .arg(&reference.service)
                .arg("-a")
                .arg(&reference.account)
                .arg("-w")
                .output()?;
            if !output.status.success() {
                return Err(SwitchError::CredentialUnavailable(format!(
                    "Keychain entry {}:{} not available",
                    reference.service, reference.account
                )));
            }
            let secret = String::from_utf8_lossy(&output.stdout).trim().to_string();
            records.push(SecretRecord {
                reference: reference.clone(),
                secret: secrecy::SecretString::new(secret.into()),
            });
        }
        Ok(records)
    }

    fn write(&self, records: &[SecretRecord]) -> Result<()> {
        Self::ensure_supported()?;
        for record in records {
            let output = Command::new("security")
                .arg("add-generic-password")
                .arg("-U")
                .arg("-s")
                .arg(&record.reference.service)
                .arg("-a")
                .arg(&record.reference.account)
                .arg("-w")
                .arg(record.secret.expose_secret())
                .output()?;
            if !output.status.success() {
                return Err(SwitchError::CredentialUnavailable(format!(
                    "Failed to write Keychain entry {}:{}",
                    record.reference.service, record.reference.account
                )));
            }
        }
        Ok(())
    }

    fn delete(&self, refs: &[CredentialRef]) -> Result<()> {
        Self::ensure_supported()?;
        for reference in refs {
            let _ = Command::new("security")
                .arg("delete-generic-password")
                .arg("-s")
                .arg(&reference.service)
                .arg("-a")
                .arg(&reference.account)
                .output()?;
        }
        Ok(())
    }
}
