use codex_switch_domain::{
    CredentialMode, CredentialRef, OfficialCredentialStore, Result, SecretRecord, SwitchError,
};

#[derive(Debug, Default)]
pub struct WindowsCredentialStore;

impl OfficialCredentialStore for WindowsCredentialStore {
    fn kind(&self) -> CredentialMode {
        CredentialMode::System
    }

    fn is_available(&self) -> bool {
        cfg!(target_os = "windows")
    }

    fn read(&self, _refs: &[CredentialRef]) -> Result<Vec<SecretRecord>> {
        Err(SwitchError::CredentialUnavailable(
            "Windows Credential Manager integration requires a Windows build".to_string(),
        ))
    }

    fn write(&self, _records: &[SecretRecord]) -> Result<()> {
        Err(SwitchError::CredentialUnavailable(
            "Windows Credential Manager integration requires a Windows build".to_string(),
        ))
    }

    fn delete(&self, _refs: &[CredentialRef]) -> Result<()> {
        Err(SwitchError::CredentialUnavailable(
            "Windows Credential Manager integration requires a Windows build".to_string(),
        ))
    }
}
