use std::{fs, path::PathBuf};

use codex_switch_domain::{Result, SwitchError, session::FileEntry};

use crate::fs_secure::{atomic_write, set_private_permissions};

#[derive(Debug, Clone)]
pub struct FileCredentialStore {
    codex_home: PathBuf,
}

impl FileCredentialStore {
    #[must_use]
    pub fn new(codex_home: PathBuf) -> Self {
        Self { codex_home }
    }

    #[must_use]
    pub fn auth_path(&self) -> PathBuf {
        self.codex_home.join("auth.json")
    }

    pub fn detect_entries(&self) -> Result<Vec<FileEntry>> {
        let auth_path = self.auth_path();
        if !auth_path.exists() {
            return Err(SwitchError::NotFound(format!(
                "Official auth file not found at {}",
                auth_path.display()
            )));
        }
        let contents = fs::read_to_string(&auth_path)?;
        Ok(vec![FileEntry {
            relative_path: "auth.json".to_string(),
            contents,
            permissions: Some(0o600),
        }])
    }

    pub fn write_entries(&self, entries: &[FileEntry]) -> Result<()> {
        for entry in entries {
            let path = self.codex_home.join(&entry.relative_path);
            atomic_write(&path, entry.contents.as_bytes())?;
            set_private_permissions(&path)?;
        }
        Ok(())
    }

    pub fn backup_entries(
        &self,
        relative_paths: &[String],
        destination: &std::path::Path,
    ) -> Result<Vec<String>> {
        let mut backups = Vec::new();
        for relative_path in relative_paths {
            let source = self.codex_home.join(relative_path);
            if !source.exists() {
                continue;
            }
            let backup_path = destination.join(relative_path);
            if let Some(parent) = backup_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::copy(&source, &backup_path)?;
            backups.push(relative_path.clone());
        }
        Ok(backups)
    }
}
