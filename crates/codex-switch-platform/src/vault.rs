use std::{
    fs,
    path::{Path, PathBuf},
};

use aes_gcm_siv::{
    Aes256GcmSiv, Nonce,
    aead::{Aead, KeyInit},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use codex_switch_domain::{
    ProfileVault, Result, SwitchError,
    profile::{ProfileId, ProfileMeta},
    session::{ExportEnvelope, SecretSnapshot},
};
use pbkdf2::pbkdf2_hmac;
use rand::{RngCore, rngs::OsRng};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

use crate::fs_secure::{atomic_write, ensure_dir};

#[derive(Debug, Clone)]
pub struct LocalProfileVault {
    profiles_dir: PathBuf,
    vault_dir: PathBuf,
    exports_dir: PathBuf,
    local_passphrase: Option<SecretString>,
}

#[derive(Debug, Serialize, Deserialize)]
struct StoredSecretEnvelope {
    encrypted: bool,
    salt_b64: Option<String>,
    nonce_b64: Option<String>,
    payload_b64: String,
}

impl LocalProfileVault {
    #[must_use]
    pub fn new(
        profiles_dir: PathBuf,
        vault_dir: PathBuf,
        exports_dir: PathBuf,
        local_passphrase: Option<SecretString>,
    ) -> Self {
        Self { profiles_dir, vault_dir, exports_dir, local_passphrase }
    }

    #[must_use]
    pub fn vault_path(&self, profile_id: &ProfileId) -> PathBuf {
        self.vault_dir.join(format!("{profile_id}.bin"))
    }

    #[must_use]
    pub fn profile_meta_path(&self, profile_id: &ProfileId) -> PathBuf {
        self.profiles_dir.join(profile_id.to_string()).join("meta.json")
    }

    pub fn write_profile_meta(&self, profile: &ProfileMeta) -> Result<()> {
        let meta_path = self.profile_meta_path(&profile.id);
        let contents = serde_json::to_vec_pretty(profile)?;
        atomic_write(&meta_path, &contents)
    }

    pub fn read_profile_meta(&self, profile_id: &ProfileId) -> Result<ProfileMeta> {
        let path = self.profile_meta_path(profile_id);
        let contents = fs::read_to_string(path)?;
        Ok(serde_json::from_str(&contents)?)
    }

    fn encode_payload(
        &self,
        plaintext: &[u8],
        passphrase: Option<&SecretString>,
    ) -> Result<StoredSecretEnvelope> {
        if let Some(passphrase) = passphrase {
            let mut salt = [0_u8; 16];
            let mut nonce = [0_u8; 12];
            OsRng.fill_bytes(&mut salt);
            OsRng.fill_bytes(&mut nonce);
            let key = derive_key(passphrase.expose_secret(), &salt);
            let cipher = Aes256GcmSiv::new_from_slice(&key)
                .map_err(|err| SwitchError::Crypto(err.to_string()))?;
            let ciphertext = cipher
                .encrypt(Nonce::from_slice(&nonce), plaintext)
                .map_err(|err| SwitchError::Crypto(err.to_string()))?;
            Ok(StoredSecretEnvelope {
                encrypted: true,
                salt_b64: Some(STANDARD.encode(salt)),
                nonce_b64: Some(STANDARD.encode(nonce)),
                payload_b64: STANDARD.encode(ciphertext),
            })
        } else {
            Ok(StoredSecretEnvelope {
                encrypted: false,
                salt_b64: None,
                nonce_b64: None,
                payload_b64: STANDARD.encode(plaintext),
            })
        }
    }

    fn decode_payload(
        &self,
        envelope: StoredSecretEnvelope,
        passphrase: Option<&SecretString>,
    ) -> Result<Vec<u8>> {
        if !envelope.encrypted {
            return STANDARD
                .decode(envelope.payload_b64)
                .map_err(|err| SwitchError::Crypto(err.to_string()));
        }
        let passphrase = passphrase.ok_or_else(|| {
            SwitchError::CredentialUnavailable(
                "A passphrase is required to decrypt this profile vault".to_string(),
            )
        })?;
        let salt = STANDARD
            .decode(
                envelope.salt_b64.ok_or_else(|| SwitchError::Crypto("Missing salt".to_string()))?,
            )
            .map_err(|err| SwitchError::Crypto(err.to_string()))?;
        let nonce = STANDARD
            .decode(
                envelope
                    .nonce_b64
                    .ok_or_else(|| SwitchError::Crypto("Missing nonce".to_string()))?,
            )
            .map_err(|err| SwitchError::Crypto(err.to_string()))?;
        let ciphertext = STANDARD
            .decode(envelope.payload_b64)
            .map_err(|err| SwitchError::Crypto(err.to_string()))?;
        let key = derive_key(passphrase.expose_secret(), &salt);
        let cipher = Aes256GcmSiv::new_from_slice(&key)
            .map_err(|err| SwitchError::Crypto(err.to_string()))?;
        cipher
            .decrypt(Nonce::from_slice(&nonce), ciphertext.as_ref())
            .map_err(|err| SwitchError::Crypto(err.to_string()))
    }
}

impl ProfileVault for LocalProfileVault {
    fn save(&self, profile: &ProfileMeta, snapshot: &SecretSnapshot) -> Result<()> {
        ensure_dir(&self.profiles_dir)?;
        ensure_dir(&self.vault_dir)?;
        self.write_profile_meta(profile)?;
        let snapshot_json = serde_json::to_vec(snapshot)?;
        let encoded = self.encode_payload(&snapshot_json, self.local_passphrase.as_ref())?;
        let serialized = serde_json::to_vec(&encoded)?;
        atomic_write(&self.vault_path(&profile.id), &serialized)
    }

    fn load(&self, profile_id: &ProfileId) -> Result<SecretSnapshot> {
        let contents = fs::read(self.vault_path(profile_id))?;
        let envelope: StoredSecretEnvelope = serde_json::from_slice(&contents)?;
        let plaintext = self.decode_payload(envelope, self.local_passphrase.as_ref())?;
        Ok(serde_json::from_slice(&plaintext)?)
    }

    fn export(
        &self,
        profile_id: &ProfileId,
        passphrase: SecretString,
        output: Option<&Path>,
    ) -> Result<PathBuf> {
        ensure_dir(&self.exports_dir)?;
        let profile = self.read_profile_meta(profile_id)?;
        let snapshot = self.load(profile_id)?;
        let envelope = ExportEnvelope {
            schema_version: 1,
            profile_meta_json: serde_json::to_string(&profile)?,
            snapshot_json: serde_json::to_string(&snapshot)?,
        };
        let plaintext = serde_json::to_vec(&envelope)?;
        let encoded = self.encode_payload(&plaintext, Some(&passphrase))?;
        let target = output
            .map(Path::to_path_buf)
            .unwrap_or_else(|| self.exports_dir.join(format!("{}.cxswitch", profile.name)));
        atomic_write(&target, &serde_json::to_vec_pretty(&encoded)?)?;
        Ok(target)
    }

    fn import(
        &self,
        archive: &Path,
        passphrase: SecretString,
    ) -> Result<(ProfileMeta, SecretSnapshot)> {
        let contents = fs::read(archive)?;
        let envelope: StoredSecretEnvelope = serde_json::from_slice(&contents)?;
        let plaintext = self.decode_payload(envelope, Some(&passphrase))?;
        let export: ExportEnvelope = serde_json::from_slice(&plaintext)?;
        let profile: ProfileMeta = serde_json::from_str(&export.profile_meta_json)?;
        let snapshot: SecretSnapshot = serde_json::from_str(&export.snapshot_json)?;
        Ok((profile, snapshot))
    }
}

fn derive_key(passphrase: &str, salt: &[u8]) -> [u8; 32] {
    let mut key = [0_u8; 32];
    pbkdf2_hmac::<sha2::Sha256>(passphrase.as_bytes(), salt, 100_000, &mut key);
    key
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use tempfile::tempdir;
    use uuid::Uuid;

    use super::*;
    use codex_switch_domain::{
        profile::{CredentialMode, ProfileHealth, SourceType},
        session::{CredentialRef, ProfileVaultManifest},
    };

    #[test]
    fn export_round_trip_requires_passphrase() {
        let temp = tempdir().expect("tempdir");
        let profile_id = Uuid::new_v4();
        let vault = LocalProfileVault::new(
            temp.path().join("profiles"),
            temp.path().join("vault"),
            temp.path().join("exports"),
            None,
        );
        let profile = ProfileMeta {
            id: profile_id,
            name: "personal".to_string(),
            account_label_masked: "pe***@example.com".to_string(),
            account_fingerprint: "abcd1234".to_string(),
            source_type: SourceType::ChatGpt,
            credential_mode: CredentialMode::File,
            created_at: Utc::now(),
            last_used_at: None,
            last_synced_at: None,
            is_default: false,
            health: ProfileHealth::unknown(),
            note: None,
        };
        let snapshot = SecretSnapshot {
            manifest: ProfileVaultManifest {
                schema_version: 1,
                profile_id,
                encrypted: false,
                file_entries: vec!["auth.json".to_string()],
                system_entries: vec![CredentialRef {
                    service: "svc".to_string(),
                    account: "acct".to_string(),
                    label: None,
                }],
                vault_fingerprint: "fingerprint".to_string(),
            },
            file_entries: vec![],
            system_records: vec![],
        };
        vault.save(&profile, &snapshot).expect("save");
        let archive =
            vault.export(&profile_id, SecretString::new("secret".into()), None).expect("export");
        let (imported_profile, _) =
            vault.import(&archive, SecretString::new("secret".into())).expect("import");
        assert_eq!(imported_profile.name, "personal");
    }
}
