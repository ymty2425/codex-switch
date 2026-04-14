use thiserror::Error;

pub type Result<T> = std::result::Result<T, SwitchError>;

#[derive(Debug, Error)]
pub enum SwitchError {
    #[error("unsupported platform: {0}")]
    UnsupportedPlatform(String),
    #[error("credential store unavailable: {0}")]
    CredentialUnavailable(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("conflict: {0}")]
    Conflict(String),
    #[error("validation failed: {0}")]
    ValidationFailed(String),
    #[error("rollback failed: {0}")]
    RollbackFailed(String),
    #[error("io error: {0}")]
    Io(String),
    #[error("serialization error: {0}")]
    Serialization(String),
    #[error("crypto error: {0}")]
    Crypto(String),
    #[error("state error: {0}")]
    State(String),
}

impl From<std::io::Error> for SwitchError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value.to_string())
    }
}

impl From<serde_json::Error> for SwitchError {
    fn from(value: serde_json::Error) -> Self {
        Self::Serialization(value.to_string())
    }
}

impl From<toml::de::Error> for SwitchError {
    fn from(value: toml::de::Error) -> Self {
        Self::Serialization(value.to_string())
    }
}
