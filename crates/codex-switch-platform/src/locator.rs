use std::path::PathBuf;

use directories::ProjectDirs;

use codex_switch_domain::{Result, SwitchError};

#[derive(Debug, Clone)]
pub struct AppPaths {
    pub codex_home: PathBuf,
    pub data_dir: PathBuf,
    pub profiles_dir: PathBuf,
    pub vault_dir: PathBuf,
    pub exports_dir: PathBuf,
    pub validation_dir: PathBuf,
    pub tx_dir: PathBuf,
    pub locks_dir: PathBuf,
    pub logs_dir: PathBuf,
    pub config_file: PathBuf,
    pub current_binding_file: PathBuf,
    pub audit_log_file: PathBuf,
}

pub struct PathResolver;

impl PathResolver {
    pub fn discover(
        codex_home_override: Option<PathBuf>,
        data_dir_override: Option<PathBuf>,
    ) -> Result<AppPaths> {
        let codex_home = codex_home_override
            .or_else(|| std::env::var_os("CODEX_HOME").map(PathBuf::from))
            .unwrap_or_else(Self::default_codex_home);

        let data_dir = data_dir_override.unwrap_or_else(Self::default_data_dir);
        if data_dir.as_os_str().is_empty() {
            return Err(SwitchError::ValidationFailed(
                "Could not determine application data directory".to_string(),
            ));
        }

        Ok(AppPaths {
            codex_home,
            profiles_dir: data_dir.join("profiles"),
            vault_dir: data_dir.join("vault"),
            exports_dir: data_dir.join("exports"),
            validation_dir: data_dir.join("validation"),
            tx_dir: data_dir.join("tx"),
            locks_dir: data_dir.join("locks"),
            logs_dir: data_dir.join("logs"),
            config_file: data_dir.join("config.json"),
            current_binding_file: data_dir.join("current_binding.json"),
            audit_log_file: data_dir.join("logs").join("audit.log"),
            data_dir,
        })
    }

    fn default_codex_home() -> PathBuf {
        if cfg!(windows) {
            std::env::var_os("USERPROFILE")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("."))
                .join(".codex")
        } else {
            std::env::var_os("HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("."))
                .join(".codex")
        }
    }

    fn default_data_dir() -> PathBuf {
        ProjectDirs::from("", "", "codex-switch")
            .map(|dirs| dirs.data_dir().to_path_buf())
            .unwrap_or_else(|| {
                std::env::temp_dir().join("codex-switch").join(std::process::id().to_string())
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discover_prefers_explicit_codex_home() {
        let paths = PathResolver::discover(
            Some(PathBuf::from("/tmp/custom-codex")),
            Some(PathBuf::from("/tmp/codex-switch")),
        )
        .expect("paths");
        assert_eq!(paths.codex_home, PathBuf::from("/tmp/custom-codex"));
        assert_eq!(paths.vault_dir, PathBuf::from("/tmp/codex-switch/vault"));
    }
}
