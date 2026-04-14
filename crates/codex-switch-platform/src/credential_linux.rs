use std::process::Command;

use codex_switch_domain::{
    CredentialMode, CredentialRef, OfficialCredentialStore, Result, SecretRecord, SwitchError,
};
use secrecy::ExposeSecret;

#[derive(Debug, Default)]
pub struct LinuxKeyringCredentialStore;

impl LinuxKeyringCredentialStore {
    fn ensure_supported() -> Result<()> {
        if cfg!(target_os = "linux") {
            Ok(())
        } else {
            Err(SwitchError::UnsupportedPlatform(
                "Linux keyring integration is only available on Linux".to_string(),
            ))
        }
    }
}

impl OfficialCredentialStore for LinuxKeyringCredentialStore {
    fn kind(&self) -> CredentialMode {
        CredentialMode::System
    }

    fn is_available(&self) -> bool {
        cfg!(target_os = "linux") && which::which("secret-tool").is_ok()
    }

    fn read(&self, refs: &[CredentialRef]) -> Result<Vec<SecretRecord>> {
        Self::ensure_supported()?;
        if !self.is_available() {
            return Err(SwitchError::CredentialUnavailable(
                "secret-tool is not available".to_string(),
            ));
        }
        let mut records = Vec::new();
        for reference in refs {
            let output = Command::new("secret-tool")
                .arg("lookup")
                .arg("service")
                .arg(&reference.service)
                .arg("account")
                .arg(&reference.account)
                .output()?;
            if !output.status.success() {
                return Err(SwitchError::CredentialUnavailable(format!(
                    "Secret Service entry {}:{} not available",
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
        if !self.is_available() {
            return Err(SwitchError::CredentialUnavailable(
                "secret-tool is not available".to_string(),
            ));
        }
        for record in records {
            let status = Command::new("secret-tool")
                .arg("store")
                .arg("--label")
                .arg(record.reference.label.clone().unwrap_or_else(|| "Codex Switch".to_string()))
                .arg("service")
                .arg(&record.reference.service)
                .arg("account")
                .arg(&record.reference.account)
                .stdin(std::process::Stdio::piped())
                .spawn()
                .and_then(|mut child| {
                    if let Some(mut stdin) = child.stdin.take() {
                        use std::io::Write;
                        stdin.write_all(record.secret.expose_secret().as_bytes())?;
                    }
                    child.wait()
                })?;
            if !status.success() {
                return Err(SwitchError::CredentialUnavailable(format!(
                    "Failed to write Secret Service entry {}:{}",
                    record.reference.service, record.reference.account
                )));
            }
        }
        Ok(())
    }

    fn delete(&self, refs: &[CredentialRef]) -> Result<()> {
        Self::ensure_supported()?;
        if !self.is_available() {
            return Ok(());
        }
        for reference in refs {
            let _ = Command::new("secret-tool")
                .arg("clear")
                .arg("service")
                .arg(&reference.service)
                .arg("account")
                .arg(&reference.account)
                .status()?;
        }
        Ok(())
    }
}
