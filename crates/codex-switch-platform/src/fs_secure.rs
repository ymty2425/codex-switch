use std::{
    fs,
    path::{Path, PathBuf},
};

use codex_switch_domain::{Result, SwitchError};
use uuid::Uuid;

pub fn ensure_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

pub fn ensure_parent_dir(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        ensure_dir(parent)?;
    }
    Ok(())
}

pub fn atomic_write(path: &Path, contents: &[u8]) -> Result<()> {
    ensure_parent_dir(path)?;
    let temp_name = format!(
        ".{}.tmp-{}",
        path.file_name().and_then(|name| name.to_str()).unwrap_or("swap"),
        Uuid::new_v4()
    );
    let temp_path = path.parent().unwrap_or_else(|| Path::new(".")).join(temp_name);
    fs::write(&temp_path, contents)?;
    set_private_permissions(&temp_path)?;
    fs::rename(temp_path, path)?;
    set_private_permissions(path)?;
    Ok(())
}

pub fn read_to_string(path: &Path) -> Result<String> {
    fs::read_to_string(path).map_err(Into::into)
}

pub fn copy_file(source: &Path, destination: &Path) -> Result<()> {
    ensure_parent_dir(destination)?;
    fs::copy(source, destination)?;
    set_private_permissions(destination)?;
    Ok(())
}

pub fn secure_delete(path: &Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    if path.is_dir() {
        fs::remove_dir_all(path)?;
    } else {
        fs::remove_file(path)?;
    }
    Ok(())
}

pub fn set_private_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(windows)]
    {
        let _ = path;
    }
    Ok(())
}

pub fn list_json_files(path: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    if !path.exists() {
        return Ok(files);
    }
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let entry_path = entry.path();
        if entry_path.extension().and_then(|ext| ext.to_str()) == Some("json") {
            files.push(entry_path);
        }
    }
    files.sort();
    Ok(files)
}

pub fn require_exists(path: &Path, description: &str) -> Result<()> {
    if path.exists() {
        Ok(())
    } else {
        Err(SwitchError::NotFound(format!("{description}: {}", path.display())))
    }
}
