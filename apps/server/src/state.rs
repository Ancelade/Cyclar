use anyhow::{Context, Result};
use argon2::{
    password_hash::{
        rand_core::OsRng as PasswordOsRng, PasswordHash, PasswordHasher, PasswordVerifier,
        SaltString,
    },
    Argon2,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::{rngs::OsRng, RngCore};
use redb::{Database, TableDefinition};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    path::Path,
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

const SNAPSHOT: TableDefinition<&str, &[u8]> = TableDefinition::new("snapshot");

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct PersistentState {
    pub schema_version: u32,
    pub next_alias: u64,
    pub users: BTreeMap<Uuid, User>,
    pub devices: BTreeMap<Uuid, Device>,
    pub sessions: BTreeMap<Uuid, RemoteSession>,
    pub web_sessions: BTreeMap<String, WebSession>,
    pub audit: Vec<AuditEvent>,
}

impl PersistentState {
    pub fn fresh() -> Self {
        Self {
            schema_version: 1,
            next_alias: 100_000_000,
            ..Self::default()
        }
    }

    pub fn audit(
        &mut self,
        actor: impl Into<String>,
        action: impl Into<String>,
        target: impl Into<String>,
        outcome: impl Into<String>,
    ) {
        self.audit.push(AuditEvent {
            at: now(),
            actor: actor.into(),
            action: action.into(),
            target: target.into(),
            outcome: outcome.into(),
        });
        let overflow = self.audit.len().saturating_sub(2_000);
        if overflow > 0 {
            self.audit.drain(..overflow);
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub display_name: String,
    pub role: Role,
    pub enabled: bool,
    pub password_hash: String,
    pub created_at: u64,
    pub revoked_at: u64,
}

#[derive(Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Admin,
    User,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Device {
    pub id: Uuid,
    pub alias: u64,
    pub name: String,
    pub platform: String,
    pub public_key: String,
    pub device_token_digest: String,
    pub temporary_password_hash: String,
    pub permanent_password_hash: Option<String>,
    pub created_at: u64,
    pub last_seen: Option<u64>,
    pub listen_address: Option<String>,
    pub agent_version: Option<String>,
    pub revoked: bool,
    pub key_epoch: u64,
    #[serde(default)]
    pub secret_epoch: u64,
}

impl Device {
    pub fn online(&self) -> bool {
        !self.revoked
            && self
                .last_seen
                .is_some_and(|last| now().saturating_sub(last) < 45)
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct RemoteSession {
    pub id: Uuid,
    pub host_device_id: Uuid,
    #[serde(default)]
    pub host_key_epoch: u64,
    pub controller_public_key: String,
    pub capabilities: Vec<cyclar_protocol::Capability>,
    pub created_at: u64,
    pub expires_at: u64,
    pub renewal_token_digest: String,
    pub closed_at: Option<u64>,
}

impl RemoteSession {
    pub fn active(&self) -> bool {
        self.closed_at.is_none() && self.expires_at > now()
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct WebSession {
    pub user_id: Uuid,
    pub csrf: String,
    pub expires_at: u64,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub at: u64,
    pub actor: String,
    pub action: String,
    pub target: String,
    pub outcome: String,
}

pub struct Store {
    db: Database,
    state: Mutex<PersistentState>,
}

impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        let db =
            Database::create(path).with_context(|| format!("open database {}", path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                .with_context(|| format!("protect database {}", path.display()))?;
        }
        {
            let tx = db.begin_write()?;
            tx.open_table(SNAPSHOT)?;
            tx.commit()?;
        }
        let mut state: PersistentState = {
            let tx = db.begin_read()?;
            let table = tx.open_table(SNAPSHOT)?;
            match table.get("state")? {
                Some(value) => serde_json::from_slice(value.value()).context("decode state")?,
                None => PersistentState::fresh(),
            }
        };
        // Presence is a live observation, not proof that an agent survived a server restart.
        for device in state.devices.values_mut() {
            device.listen_address = None;
        }
        Ok(Self {
            db,
            state: Mutex::new(state),
        })
    }

    pub fn read<T>(&self, f: impl FnOnce(&PersistentState) -> T) -> T {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        f(&state)
    }

    pub fn update<T>(&self, f: impl FnOnce(&mut PersistentState) -> Result<T>) -> Result<T> {
        let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let mut draft = guard.clone();
        let result = f(&mut draft)?;
        if draft.sessions.len() > 2_000 {
            let mut finished: Vec<_> = draft
                .sessions
                .values()
                .filter(|session| !session.active())
                .map(|session| (session.created_at, session.id))
                .collect();
            finished.sort_unstable();
            for (_, id) in finished.into_iter().take(draft.sessions.len() - 2_000) {
                draft.sessions.remove(&id);
            }
        }
        let bytes = serde_json::to_vec(&draft)?;
        let tx = self.db.begin_write()?;
        {
            let mut table = tx.open_table(SNAPSHOT)?;
            table.insert("state", bytes.as_slice())?;
        }
        tx.commit()?;
        *guard = draft;
        Ok(result)
    }

    /// Update volatile presence without rewriting the complete on-disk snapshot.
    /// The next durable mutation checkpoints this state transactionally.
    pub fn update_volatile<T>(
        &self,
        f: impl FnOnce(&mut PersistentState) -> Result<T>,
    ) -> Result<T> {
        let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        f(&mut guard)
    }
}

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn random_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn temporary_password() -> String {
    const CHARS: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
    let mut result = String::with_capacity(19);
    let mut bytes = [0u8; 18];
    OsRng.fill_bytes(&mut bytes);
    for (index, byte) in bytes.into_iter().enumerate() {
        if index == 6 || index == 12 {
            result.push('-');
        }
        result.push(CHARS[usize::from(byte) % CHARS.len()] as char);
    }
    result
}

pub fn token_digest(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

pub fn hash_password(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut PasswordOsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|err| anyhow::anyhow!("password hashing failed: {err}"))
}

pub fn verify_password(hash: &str, password: &str) -> bool {
    PasswordHash::new(hash).ok().is_some_and(|parsed| {
        Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_hash_never_equals_plaintext() {
        let hash = hash_password("secret-cyclAR").unwrap();
        assert_ne!(hash, "secret-cyclAR");
        assert!(verify_password(&hash, "secret-cyclAR"));
        assert!(!verify_password(&hash, "wrong"));
    }

    #[test]
    fn generated_secrets_are_distinct_and_long() {
        let a = temporary_password();
        let b = temporary_password();
        assert_ne!(a, b);
        assert_eq!(a.len(), 20);
        assert_ne!(random_token(), random_token());
    }

    #[cfg(unix)]
    #[test]
    fn database_file_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("server.redb");
        let _store = Store::open(&path).unwrap();
        assert_eq!(
            std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
