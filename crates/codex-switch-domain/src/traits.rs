use std::path::{Path, PathBuf};

use secrecy::SecretString;

use crate::{
    Result,
    profile::{CredentialMode, ProfileId, ProfileMeta},
    session::{CredentialRef, DetectedSession, SecretRecord, SecretSnapshot},
};

pub trait SessionDetector: Send + Sync {
    fn detect(&self) -> Result<DetectedSession>;
}

pub trait OfficialCredentialStore: Send + Sync {
    fn kind(&self) -> CredentialMode;
    fn is_available(&self) -> bool;
    fn read(&self, refs: &[CredentialRef]) -> Result<Vec<SecretRecord>>;
    fn write(&self, records: &[SecretRecord]) -> Result<()>;
    fn delete(&self, refs: &[CredentialRef]) -> Result<()>;
}

pub trait ProfileVault: Send + Sync {
    fn save(&self, profile: &ProfileMeta, snapshot: &SecretSnapshot) -> Result<()>;
    fn load(&self, profile_id: &ProfileId) -> Result<SecretSnapshot>;
    fn export(
        &self,
        profile_id: &ProfileId,
        passphrase: SecretString,
        output: Option<&Path>,
    ) -> Result<PathBuf>;
    fn import(
        &self,
        archive: &Path,
        passphrase: SecretString,
    ) -> Result<(ProfileMeta, SecretSnapshot)>;
}
