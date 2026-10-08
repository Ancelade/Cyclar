//! Offline backup and restore of the complete central authority identity.
//!
//! Stop `serve` before calling either function. redb locks its open database,
//! and copying a live database can produce an inconsistent backup. SHA-256
//! detects accidental corruption; the manifest is not an authenticity proof.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};
use uuid::Uuid;

const FORMAT_VERSION: u32 = 1;
const MANIFEST_NAME: &str = "manifest.json";
const SERVER_KEY: &str = "server-key";
const DATABASE: &str = "cyclar.redb";
const FILES: [&str; 2] = [SERVER_KEY, DATABASE];
const MAX_MANIFEST_BYTES: u64 = 16 * 1024;
const BUFFER_BYTES: usize = 64 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupManifest {
    format_version: u32,
    product: String,
    producer_version: String,
    files: Vec<FileRecord>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileRecord {
    name: String,
    size: u64,
    sha256: String,
}

struct StagingDir {
    path: PathBuf,
    committed: bool,
}

impl Drop for StagingDir {
    fn drop(&mut self) {
        if !self.committed {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

fn parent_dir(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn ensure_absent(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => bail!("destination already exists: {}", path.display()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("inspect destination {}", path.display())),
    }
}

fn require_directory(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect directory {}", path.display()))?;
    if !metadata.file_type().is_dir() {
        bail!("not a regular directory: {}", path.display());
    }
    Ok(())
}

fn require_file(path: &Path) -> Result<u64> {
    let metadata =
        fs::symlink_metadata(path).with_context(|| format!("inspect file {}", path.display()))?;
    if !metadata.file_type().is_file() {
        bail!("not a regular file: {}", path.display());
    }
    Ok(metadata.len())
}

fn create_private_dir(path: &Path) -> Result<()> {
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(path)
        .with_context(|| format!("create directory {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn create_private_file(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options
        .open(path)
        .with_context(|| format!("create file {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    Ok(file)
}

fn create_staging(parent: &Path) -> Result<StagingDir> {
    require_directory(parent)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if fs::metadata(parent)?.permissions().mode() & 0o022 != 0 {
            bail!("destination parent must not be writable by group or other users");
        }
    }
    for _ in 0..10 {
        let path = parent.join(format!(".cyclar-stage-{}", Uuid::new_v4()));
        match create_private_dir(&path) {
            Ok(()) => {
                return Ok(StagingDir {
                    path,
                    committed: false,
                })
            }
            Err(error) if path.exists() => {
                drop(error);
                continue;
            }
            Err(error) => return Err(error),
        }
    }
    bail!("could not create a unique staging directory")
}

fn sync_dir(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        File::open(path)
            .with_context(|| format!("open directory {}", path.display()))?
            .sync_all()
            .with_context(|| format!("sync directory {}", path.display()))?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn copy_and_hash(source: &Path, destination: &Path, name: &str) -> Result<FileRecord> {
    require_file(source)?;
    let mut input = File::open(source).with_context(|| format!("read {}", source.display()))?;
    let mut output = create_private_file(destination)?;
    let mut hasher = Sha256::new();
    let mut size = 0u64;
    let mut buffer = [0u8; BUFFER_BYTES];
    loop {
        let count = input.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        output.write_all(&buffer[..count])?;
        hasher.update(&buffer[..count]);
        size = size
            .checked_add(count as u64)
            .context("file size overflow")?;
    }
    output.sync_all()?;
    Ok(FileRecord {
        name: name.to_owned(),
        size,
        sha256: hex::encode(hasher.finalize()),
    })
}

fn hash_file(path: &Path) -> Result<(u64, String)> {
    require_file(path)?;
    let mut input = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut size = 0u64;
    let mut buffer = [0u8; BUFFER_BYTES];
    loop {
        let count = input.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
        size = size
            .checked_add(count as u64)
            .context("file size overflow")?;
    }
    Ok((size, hex::encode(hasher.finalize())))
}

fn write_manifest(path: &Path, manifest: &BackupManifest) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(manifest)?;
    if bytes.len() as u64 > MAX_MANIFEST_BYTES {
        bail!("backup manifest is too large");
    }
    let mut file = create_private_file(path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(())
}

fn read_and_verify(source: &Path) -> Result<BackupManifest> {
    require_directory(source)?;
    let manifest_path = source.join(MANIFEST_NAME);
    let size = require_file(&manifest_path)?;
    if size == 0 || size > MAX_MANIFEST_BYTES {
        bail!("invalid backup manifest size");
    }
    let manifest: BackupManifest =
        serde_json::from_reader(File::open(&manifest_path)?).context("invalid backup manifest")?;
    if manifest.format_version != FORMAT_VERSION || manifest.product != "cyclar-server" {
        bail!("unsupported backup format or product");
    }
    if manifest.files.len() != FILES.len() {
        bail!("backup manifest has an unexpected file list");
    }
    for name in FILES {
        let mut records = manifest.files.iter().filter(|record| record.name == name);
        let record = records
            .next()
            .context("backup manifest is missing a required file")?;
        if records.next().is_some()
            || record.sha256.len() != 64
            || !record
                .sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            bail!("backup manifest contains invalid file metadata");
        }
        let (actual_size, actual_hash) = hash_file(&source.join(name))?;
        if record.size != actual_size || record.sha256 != actual_hash {
            bail!("backup checksum mismatch for {name}");
        }
    }
    if manifest
        .files
        .iter()
        .any(|record| !FILES.contains(&record.name.as_str()))
    {
        bail!("backup manifest contains an unexpected file");
    }
    let key_size = require_file(&source.join(SERVER_KEY))?;
    if key_size != 32 || require_file(&source.join(DATABASE))? == 0 {
        bail!("backup identity or database has an invalid size");
    }
    Ok(manifest)
}

fn commit(mut staging: StagingDir, destination: &Path) -> Result<()> {
    // std::fs::rename has no cross-platform NOREPLACE flag. The immediate
    // existence check prevents normal overwrites; the restricted parent on
    // Unix prevents an untrusted user racing this check with an empty dir.
    // Another process running with the same filesystem identity can still
    // race the rename, so backup destinations must remain under sole control
    // of the operator until publication completes.
    ensure_absent(destination)?;
    fs::rename(&staging.path, destination)
        .with_context(|| format!("publish directory {}", destination.display()))?;
    staging.committed = true;
    sync_dir(parent_dir(destination))?;
    Ok(())
}

/// Copy the database and signing key into a new, versioned backup directory.
/// `serve` must be stopped before this call. Existing destinations are refused.
pub fn create_backup(data_dir: &Path, destination: &Path) -> Result<()> {
    require_directory(data_dir)?;
    ensure_absent(destination)?;
    if require_file(&data_dir.join(SERVER_KEY))? != 32
        || require_file(&data_dir.join(DATABASE))? == 0
    {
        bail!("server identity or database has an invalid size");
    }
    let staging = create_staging(parent_dir(destination))?;
    let mut files = Vec::with_capacity(FILES.len());
    for name in FILES {
        files.push(copy_and_hash(
            &data_dir.join(name),
            &staging.path.join(name),
            name,
        )?);
    }
    let manifest = BackupManifest {
        format_version: FORMAT_VERSION,
        product: "cyclar-server".to_owned(),
        producer_version: env!("CARGO_PKG_VERSION").to_owned(),
        files,
    };
    write_manifest(&staging.path.join(MANIFEST_NAME), &manifest)?;
    sync_dir(&staging.path)?;
    commit(staging, destination)
}

/// Verify checksums before restoring a backup to a new data directory.
/// `serve` must be stopped. Existing destinations are refused.
pub fn restore_backup(source: &Path, destination_data_dir: &Path) -> Result<()> {
    ensure_absent(destination_data_dir)?;
    let manifest = read_and_verify(source)?;
    let staging = create_staging(parent_dir(destination_data_dir))?;
    for record in &manifest.files {
        let copied = copy_and_hash(
            &source.join(&record.name),
            &staging.path.join(&record.name),
            &record.name,
        )?;
        if copied.size != record.size || copied.sha256 != record.sha256 {
            bail!("backup changed while it was being restored");
        }
    }
    // `check` validates the restored redb schema and an active administrator
    // before a verified, but otherwise malformed, backup becomes visible.
    crate::check(&staging.path)?;
    sync_dir(&staging.path)?;
    commit(staging, destination_data_dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server_fixture(root: &Path) -> PathBuf {
        let source = root.join("live");
        create_private_dir(&source).unwrap();
        let mut key = create_private_file(&source.join(SERVER_KEY)).unwrap();
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        key.write_all(&signing_key.to_bytes()).unwrap();
        key.sync_all().unwrap();
        let store = crate::state::Store::open(&source.join(DATABASE)).unwrap();
        let password_hash = crate::state::hash_password(&crate::state::random_token()).unwrap();
        store
            .update(|db| {
                let id = Uuid::new_v4();
                db.users.insert(
                    id,
                    crate::state::User {
                        id,
                        username: "backup-admin".to_owned(),
                        display_name: "Backup Admin".to_owned(),
                        role: crate::state::Role::Admin,
                        enabled: true,
                        password_hash,
                        created_at: crate::state::now(),
                        revoked_at: 0,
                    },
                );
                Ok(())
            })
            .unwrap();
        drop(store);
        source
    }

    #[test]
    fn backup_and_restore_preserve_identity_and_permissions() {
        let root = tempfile::tempdir().unwrap();
        let source = server_fixture(root.path());
        let backup = root.path().join("backup");
        let restored = root.path().join("restored");
        create_backup(&source, &backup).unwrap();
        restore_backup(&backup, &restored).unwrap();
        assert_eq!(
            fs::read(source.join(SERVER_KEY)).unwrap(),
            fs::read(restored.join(SERVER_KEY)).unwrap()
        );
        assert_eq!(
            fs::read(source.join(DATABASE)).unwrap(),
            fs::read(backup.join(DATABASE)).unwrap()
        );
        crate::check(&restored).unwrap();
        let restored_store = crate::state::Store::open(&restored.join(DATABASE)).unwrap();
        assert_eq!(restored_store.read(|db| db.users.len()), 1);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for dir in [&backup, &restored] {
                assert_eq!(
                    fs::metadata(dir).unwrap().permissions().mode() & 0o777,
                    0o700
                );
                for name in [SERVER_KEY, DATABASE, MANIFEST_NAME]
                    .into_iter()
                    .filter(|name| dir.join(name).exists())
                {
                    assert_eq!(
                        fs::metadata(dir.join(name)).unwrap().permissions().mode() & 0o777,
                        0o600
                    );
                }
            }
        }
    }

    #[test]
    fn backup_refuses_missing_key_and_existing_destination() {
        let root = tempfile::tempdir().unwrap();
        let source = server_fixture(root.path());
        fs::remove_file(source.join(SERVER_KEY)).unwrap();
        let backup = root.path().join("backup");
        assert!(create_backup(&source, &backup).is_err());
        assert!(!backup.exists());
        create_private_dir(&backup).unwrap();
        let marker = backup.join("marker");
        fs::write(&marker, b"keep").unwrap();
        assert!(create_backup(&source, &backup).is_err());
        assert_eq!(fs::read(&marker).unwrap(), b"keep");
    }

    #[test]
    fn restore_rejects_corruption_missing_key_and_overwrite() {
        let root = tempfile::tempdir().unwrap();
        let source = server_fixture(root.path());
        let backup = root.path().join("backup");
        create_backup(&source, &backup).unwrap();
        let restored = root.path().join("restored");
        fs::write(backup.join(DATABASE), b"corrupted").unwrap();
        assert!(restore_backup(&backup, &restored).is_err());
        assert!(!restored.exists());

        let clean_backup = root.path().join("clean-backup");
        create_backup(&source, &clean_backup).unwrap();
        fs::remove_file(clean_backup.join(SERVER_KEY)).unwrap();
        assert!(restore_backup(&clean_backup, &restored).is_err());
        assert!(!restored.exists());

        let intact_backup = root.path().join("intact-backup");
        create_backup(&source, &intact_backup).unwrap();
        create_private_dir(&restored).unwrap();
        let marker = restored.join("marker");
        fs::write(&marker, b"keep").unwrap();
        assert!(restore_backup(&intact_backup, &restored).is_err());
        assert_eq!(fs::read(&marker).unwrap(), b"keep");
    }

    #[test]
    fn restore_rejects_invalid_database_even_when_manifest_matches() {
        let root = tempfile::tempdir().unwrap();
        let source = server_fixture(root.path());
        let backup = root.path().join("backup");
        create_backup(&source, &backup).unwrap();
        let invalid_database = b"not a redb database";
        fs::write(backup.join(DATABASE), invalid_database).unwrap();
        let manifest_path = backup.join(MANIFEST_NAME);
        let mut manifest: BackupManifest =
            serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
        let database_record = manifest
            .files
            .iter_mut()
            .find(|record| record.name == DATABASE)
            .unwrap();
        database_record.size = invalid_database.len() as u64;
        database_record.sha256 = hex::encode(Sha256::digest(invalid_database));
        fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();

        let restored = root.path().join("restored");
        assert!(restore_backup(&backup, &restored).is_err());
        assert!(!restored.exists());
    }
}
