use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use cyclar_protocol::sign_device_registration;
use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::api::CentralApi;

#[derive(Clone, Serialize, Deserialize)]
pub struct HostIdentity {
    pub server_url: String,
    pub device_id: Uuid,
    pub alias: u64,
    pub temporary_password: String,
    pub device_token: String,
    pub server_public_key: String,
    signing_key: String,
    #[serde(default)]
    pub key_epoch: u64,
}

impl HostIdentity {
    /// Write the host secret only to the local controlling terminal. Standard
    /// output/error may be collected as service logs and must not receive it.
    #[cfg(unix)]
    pub fn show_secret_on_tty(&self) -> Result<()> {
        let mut tty = OpenOptions::new()
            .write(true)
            .open("/dev/tty")
            .context("no local controlling terminal for secret display")?;
        writeln!(
            tty,
            "Cyclar — ID {} · secret temporaire : {}",
            self.alias, self.temporary_password
        )?;
        tty.flush()?;
        Ok(())
    }

    pub fn signing_key(&self) -> Result<SigningKey> {
        let bytes = URL_SAFE_NO_PAD
            .decode(&self.signing_key)
            .context("invalid local identity")?;
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| anyhow!("invalid local key length"))?;
        Ok(SigningKey::from_bytes(&bytes))
    }

    pub fn load_or_register(
        path: &Path,
        server_url: &str,
        name: &str,
        api: &CentralApi,
    ) -> Result<Self> {
        if path.exists() {
            if fs::symlink_metadata(path)?.file_type().is_symlink() {
                bail!("identity file must not be a symbolic link");
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = fs::metadata(path)?.permissions().mode();
                if mode & 0o077 != 0 {
                    bail!(
                        "identity file {} is readable by other users; restrict it to mode 0600",
                        path.display()
                    );
                }
            }
            let bytes =
                fs::read(path).with_context(|| format!("cannot read {}", path.display()))?;
            let identity: Self =
                serde_json::from_slice(&bytes).context("invalid local identity file")?;
            if identity.server_url != server_url {
                bail!(
                    "existing identity belongs to {}; choose its server or another --state path",
                    identity.server_url
                );
            }
            identity.signing_key()?;
            return Ok(identity);
        }
        let signing_key = SigningKey::generate(&mut OsRng);
        let request = sign_device_registration(&signing_key, name, std::env::consts::OS);
        let response = api.register(&request)?;
        let identity = Self {
            server_url: server_url.to_owned(),
            device_id: response.device_id,
            alias: response.alias,
            temporary_password: response.temporary_password,
            device_token: response.device_token,
            server_public_key: response.server_public_key,
            signing_key: URL_SAFE_NO_PAD.encode(signing_key.to_bytes()),
            key_epoch: 0,
        };
        identity.persist(path)?;
        Ok(identity)
    }

    pub fn persist(&self, path: &Path) -> Result<()> {
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let parent_existed = parent.exists();
        fs::create_dir_all(parent)
            .with_context(|| format!("cannot create {}", parent.display()))?;
        #[cfg(unix)]
        if !parent_existed {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
        }
        #[cfg(not(unix))]
        let _ = parent_existed;
        let temporary_path = path.with_extension(format!("{}.tmp", std::process::id()));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&temporary_path)
            .context("cannot create identity file")?;
        let bytes = serde_json::to_vec_pretty(self)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary_path, path).context("cannot persist identity file")?;
        Ok(())
    }
}

pub fn default_state_path() -> PathBuf {
    if let Some(base) = std::env::var_os("XDG_STATE_HOME") {
        return PathBuf::from(base).join("cyclar/host.json");
    }
    if cfg!(windows) {
        if let Some(base) = std::env::var_os("LOCALAPPDATA") {
            return PathBuf::from(base).join("Cyclar/host.json");
        }
    }
    if let Some(home) = std::env::var_os("HOME") {
        return PathBuf::from(home).join(".local/state/cyclar/host.json");
    }
    PathBuf::from("cyclar-host.json")
}
