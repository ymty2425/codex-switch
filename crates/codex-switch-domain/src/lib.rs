pub mod errors;
pub mod profile;
pub mod session;
pub mod traits;

pub use errors::{Result, SwitchError};
pub use profile::{
    CredentialMode, HealthStatus, ProfileHealth, ProfileId, ProfileMeta, SourceType,
};
pub use session::{
    AuthMode, CredentialRef, CurrentBinding, DetectedSession, ExportEnvelope, FileEntry,
    ProfileVaultManifest, SecretRecord, SecretSnapshot, SnapshotProvenance, SwitchPhase,
    SwitchTransaction, SystemEntry,
};
pub use traits::{OfficialCredentialStore, ProfileVault, SessionDetector};
