use std::{fs::OpenOptions, path::PathBuf};

use codex_switch_domain::Result;
use fs4::fs_std::FileExt;

use crate::fs_secure::ensure_parent_dir;

pub struct GlobalSwitchLock {
    file: std::fs::File,
    _path: PathBuf,
}

impl GlobalSwitchLock {
    pub fn acquire(path: PathBuf) -> Result<Self> {
        ensure_parent_dir(&path)?;
        let file =
            OpenOptions::new().create(true).read(true).write(true).truncate(false).open(&path)?;
        file.lock_exclusive()?;
        Ok(Self { file, _path: path })
    }
}

impl Drop for GlobalSwitchLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}
