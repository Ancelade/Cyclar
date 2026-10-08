//! On-demand, bounded file transfer primitives.
//!
//! Constructing a [`FileOffer`] reads filesystem metadata only. File bytes are
//! opened and read only after the recipient requests the content. The caller
//! must carry offers, chunks, resume proofs, and the final digest through an
//! authenticated, encrypted session with the `file_transfer` capability.

#![forbid(unsafe_code)]

use blake3::Hasher;
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use tempfile::{Builder, NamedTempFile};
use thiserror::Error;
use uuid::Uuid;

mod wire;
pub use wire::{TransferMessage, MAX_TRANSFER_FRAME_BYTES};

pub const MAX_CHUNK_BYTES: usize = 256 * 1024;
const HASH_BUFFER_BYTES: usize = 64 * 1024;

#[derive(Debug, Error)]
pub enum TransferError {
    #[error("unsafe or unsupported file name")]
    UnsafeName,
    #[error("symbolic links are not allowed")]
    Symlink,
    #[error("expected a regular file")]
    NotRegularFile,
    #[error("expected an existing directory")]
    NotDirectory,
    #[error("invalid transfer identifier")]
    InvalidTransferId,
    #[error("the source no longer matches the offer")]
    SourceChanged,
    #[error("chunk belongs to another transfer")]
    WrongTransfer,
    #[error("chunk offset is not the next expected offset")]
    BadOffset,
    #[error("chunk is empty or exceeds the size limit")]
    InvalidChunkSize,
    #[error("chunk or file integrity check failed")]
    IntegrityMismatch,
    #[error("file transfer is incomplete")]
    Incomplete,
    #[error("the receiver cannot continue after a filesystem error")]
    Poisoned,
    #[error("the destination already exists")]
    DestinationExists,
    #[error("transfer authorization was revoked before publication")]
    AuthorizationRevoked,
    #[error("malformed transfer frame")]
    MalformedFrame,
    #[error("transfer frame exceeds the size limit")]
    FrameTooLarge,
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Metadata for a file whose content has not yet been read or sent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileOffer {
    pub transfer_id: Uuid,
    pub file_name: String,
    pub size: u64,
}

impl FileOffer {
    /// Inspect metadata only. No content is opened, hashed, or copied here.
    pub fn from_path(path: &Path) -> Result<Self, TransferError> {
        reject_symlink_components(path)?;
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.is_file() {
            return Err(TransferError::NotRegularFile);
        }
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(TransferError::UnsafeName)?
            .to_owned();
        validate_file_name(&file_name)?;
        Ok(Self {
            transfer_id: Uuid::new_v4(),
            file_name,
            size: metadata.len(),
        })
    }

    /// Validate untrusted offer metadata before creating a destination file.
    pub fn validate(&self) -> Result<(), TransferError> {
        if self.transfer_id.is_nil() {
            return Err(TransferError::InvalidTransferId);
        }
        validate_file_name(&self.file_name)
    }
}

/// One bounded, sequential content block. Network framing must impose the
/// size limit before allocating `data`; this struct is transport neutral.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileChunk {
    pub transfer_id: Uuid,
    pub offset: u64,
    pub data: Vec<u8>,
    pub blake3: [u8; 32],
}

/// The receiver's confirmed prefix. The sender checks this hash before
/// resuming, so a stale or corrupt partial file cannot silently continue.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResumeProof {
    pub transfer_id: Uuid,
    pub offset: u64,
    pub prefix_blake3: [u8; 32],
}

impl ResumeProof {
    /// Initial request when no bytes have been received yet.
    pub fn empty(transfer_id: Uuid) -> Self {
        Self {
            transfer_id,
            offset: 0,
            prefix_blake3: *blake3::hash(b"").as_bytes(),
        }
    }
}

pub struct FileSender {
    path: PathBuf,
    file: File,
    offer: FileOffer,
    offset: u64,
    hasher: Hasher,
}

impl FileSender {
    /// Open content only after the recipient has requested an offer.
    pub fn open(path: &Path, offer: FileOffer) -> Result<Self, TransferError> {
        offer.validate()?;
        let file = open_matching_source(path, &offer)?;
        Ok(Self {
            path: path.to_owned(),
            file,
            offer,
            offset: 0,
            hasher: Hasher::new(),
        })
    }

    pub fn offer(&self) -> &FileOffer {
        &self.offer
    }

    pub fn offset(&self) -> u64 {
        self.offset
    }

    /// Read at most `MAX_CHUNK_BYTES`. Returns `None` after the offered size.
    pub fn read_next_chunk(&mut self) -> Result<Option<FileChunk>, TransferError> {
        self.read_next_chunk_with_limit(MAX_CHUNK_BYTES)
    }

    /// Read a smaller block to let high-priority session traffic share the
    /// transport. `max_bytes` must be between 1 and `MAX_CHUNK_BYTES`.
    pub fn read_next_chunk_with_limit(
        &mut self,
        max_bytes: usize,
    ) -> Result<Option<FileChunk>, TransferError> {
        if max_bytes == 0 || max_bytes > MAX_CHUNK_BYTES {
            return Err(TransferError::InvalidChunkSize);
        }
        if self.offset == self.offer.size {
            return Ok(None);
        }
        if self.file.metadata()?.len() != self.offer.size {
            return Err(TransferError::SourceChanged);
        }
        let remaining = (self.offer.size - self.offset).min(max_bytes as u64) as usize;
        let mut data = vec![0u8; remaining];
        self.file.read_exact(&mut data).map_err(|error| {
            if error.kind() == std::io::ErrorKind::UnexpectedEof {
                TransferError::SourceChanged
            } else {
                TransferError::Io(error)
            }
        })?;
        let digest = *blake3::hash(&data).as_bytes();
        let chunk = FileChunk {
            transfer_id: self.offer.transfer_id,
            offset: self.offset,
            data,
            blake3: digest,
        };
        self.hasher.update(&chunk.data);
        self.offset += chunk.data.len() as u64;
        Ok(Some(chunk))
    }

    /// Re-read the requested prefix in bounded buffers and compare its hash.
    /// The old sender state is retained if verification fails.
    pub fn resume_from(&mut self, proof: &ResumeProof) -> Result<(), TransferError> {
        if proof.transfer_id != self.offer.transfer_id {
            return Err(TransferError::WrongTransfer);
        }
        if proof.offset > self.offer.size {
            return Err(TransferError::BadOffset);
        }
        let mut file = open_matching_source(&self.path, &self.offer)?;
        let mut hasher = Hasher::new();
        hash_exact_prefix(&mut file, proof.offset, &mut hasher)
            .map_err(|_| TransferError::SourceChanged)?;
        if hasher.finalize().as_bytes() != &proof.prefix_blake3 {
            return Err(TransferError::IntegrityMismatch);
        }
        self.file = file;
        self.hasher = hasher;
        self.offset = proof.offset;
        Ok(())
    }

    /// Digest of exactly the bytes read for this transfer, including any
    /// prefix verified during resume.
    pub fn final_digest(&self) -> Result<[u8; 32], TransferError> {
        if self.offset != self.offer.size {
            return Err(TransferError::Incomplete);
        }
        if self.file.metadata()?.len() != self.offer.size {
            return Err(TransferError::SourceChanged);
        }
        Ok(*self.hasher.finalize().as_bytes())
    }
}

pub struct FileReceiver {
    offer: FileOffer,
    destination_dir: PathBuf,
    temp: NamedTempFile,
    offset: u64,
    hasher: Hasher,
    poisoned: bool,
}

impl FileReceiver {
    /// Create a temporary file in a trusted destination directory. The offer
    /// name is never used as a path until the final no-clobber publication.
    pub fn new(destination_dir: &Path, offer: FileOffer) -> Result<Self, TransferError> {
        offer.validate()?;
        reject_symlink_components(destination_dir)?;
        if !fs::symlink_metadata(destination_dir)?.is_dir() {
            return Err(TransferError::NotDirectory);
        }
        let destination_dir = destination_dir.canonicalize()?;
        let temp = Builder::new()
            .prefix(".cyclar-transfer-")
            .tempfile_in(&destination_dir)?;
        Ok(Self {
            offer,
            destination_dir,
            temp,
            offset: 0,
            hasher: Hasher::new(),
            poisoned: false,
        })
    }

    pub fn offer(&self) -> &FileOffer {
        &self.offer
    }

    pub fn offset(&self) -> u64 {
        self.offset
    }

    /// Accept only the next block, after checking its transfer ID, bounds and
    /// block hash. A write failure poisons the receiver instead of claiming a
    /// resumable offset that may not match the partially written bytes.
    pub fn write_chunk(&mut self, chunk: &FileChunk) -> Result<(), TransferError> {
        if self.poisoned {
            return Err(TransferError::Poisoned);
        }
        if chunk.transfer_id != self.offer.transfer_id {
            return Err(TransferError::WrongTransfer);
        }
        if chunk.offset != self.offset {
            return Err(TransferError::BadOffset);
        }
        if chunk.data.is_empty()
            || chunk.data.len() > MAX_CHUNK_BYTES
            || (chunk.data.len() as u64) > self.offer.size - self.offset
        {
            return Err(TransferError::InvalidChunkSize);
        }
        if blake3::hash(&chunk.data).as_bytes() != &chunk.blake3 {
            return Err(TransferError::IntegrityMismatch);
        }
        if let Err(error) = self.temp.as_file_mut().write_all(&chunk.data) {
            self.poisoned = true;
            return Err(TransferError::Io(error));
        }
        self.hasher.update(&chunk.data);
        self.offset += chunk.data.len() as u64;
        Ok(())
    }

    /// Re-read the temporary file before advertising a resumable prefix.
    pub fn resume_proof(&mut self) -> Result<ResumeProof, TransferError> {
        let actual = self.rehash_temp()?;
        if actual != *self.hasher.finalize().as_bytes() {
            self.poisoned = true;
            return Err(TransferError::IntegrityMismatch);
        }
        Ok(ResumeProof {
            transfer_id: self.offer.transfer_id,
            offset: self.offset,
            prefix_blake3: actual,
        })
    }

    /// Verify the complete temporary file and publish it without replacing
    /// any existing entry. A failed integrity check deletes the temp file.
    pub fn finish(self, expected_digest: [u8; 32]) -> Result<PathBuf, TransferError> {
        self.finish_with_authorization(expected_digest, || Ok(()))
    }

    /// Run the final authorization check immediately before publication.
    /// The callback's return value stays alive until publication finishes;
    /// callers may return a lock guard that serializes revocation with this
    /// step. A failed callback removes the temporary file without publishing.
    pub fn finish_with_authorization<G>(
        mut self,
        expected_digest: [u8; 32],
        authorize: impl FnOnce() -> Result<G, TransferError>,
    ) -> Result<PathBuf, TransferError> {
        if self.offset != self.offer.size {
            return Err(TransferError::Incomplete);
        }
        let actual = self.rehash_temp()?;
        if actual != expected_digest || actual != *self.hasher.finalize().as_bytes() {
            return Err(TransferError::IntegrityMismatch);
        }
        self.temp.as_file().sync_all()?;
        let _authorization_guard = authorize()?;
        let destination = self.destination_dir.join(&self.offer.file_name);
        match self.temp.persist_noclobber(&destination) {
            Ok(_) => Ok(destination),
            Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {
                Err(TransferError::DestinationExists)
            }
            Err(error) => Err(TransferError::Io(error.error)),
        }
    }

    fn rehash_temp(&mut self) -> Result<[u8; 32], TransferError> {
        if self.poisoned {
            return Err(TransferError::Poisoned);
        }
        let result: Result<[u8; 32], TransferError> = (|| {
            let file = self.temp.as_file_mut();
            file.flush()?;
            if file.metadata()?.len() != self.offset {
                return Err(TransferError::IntegrityMismatch);
            }
            file.seek(SeekFrom::Start(0))?;
            let mut hasher = Hasher::new();
            hash_exact_prefix(file, self.offset, &mut hasher)
                .map_err(|_| TransferError::IntegrityMismatch)?;
            file.seek(SeekFrom::Start(self.offset))?;
            Ok(*hasher.finalize().as_bytes())
        })();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
}

fn hash_exact_prefix(file: &mut File, length: u64, hasher: &mut Hasher) -> std::io::Result<()> {
    let mut buffer = [0u8; HASH_BUFFER_BYTES];
    let mut remaining = length;
    while remaining > 0 {
        let limit = remaining.min(buffer.len() as u64) as usize;
        file.read_exact(&mut buffer[..limit])?;
        hasher.update(&buffer[..limit]);
        remaining -= limit as u64;
    }
    Ok(())
}

fn open_matching_source(path: &Path, offer: &FileOffer) -> Result<File, TransferError> {
    reject_symlink_components(path)?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(TransferError::UnsafeName)?;
    if name != offer.file_name {
        return Err(TransferError::SourceChanged);
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(TransferError::NotRegularFile);
    }
    if metadata.len() != offer.size {
        return Err(TransferError::SourceChanged);
    }
    // On non-Unix targets this catches ordinary symlinks, though the caller
    // must keep the source directory trusted to close local replacement races.
    if fs::symlink_metadata(path)?.file_type().is_symlink() {
        return Err(TransferError::Symlink);
    }
    Ok(file)
}

fn reject_symlink_components(path: &Path) -> Result<(), TransferError> {
    for ancestor in path.ancestors() {
        if ancestor.as_os_str().is_empty() {
            continue;
        }
        if fs::symlink_metadata(ancestor)?.file_type().is_symlink() {
            return Err(TransferError::Symlink);
        }
    }
    Ok(())
}

fn validate_file_name(name: &str) -> Result<(), TransferError> {
    if name.is_empty()
        || name.len() > 255
        || name == "."
        || name == ".."
        || name.ends_with(' ')
        || name.ends_with('.')
        || name.chars().any(|ch| {
            ch.is_control() || matches!(ch, '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|')
        })
    {
        return Err(TransferError::UnsafeName);
    }
    let stem = name
        .split('.')
        .next()
        .unwrap_or_default()
        .to_ascii_uppercase();
    if matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || (stem.len() == 4
            && (stem.starts_with("COM") || stem.starts_with("LPT"))
            && matches!(stem.as_bytes()[3], b'1'..=b'9'))
    {
        return Err(TransferError::UnsafeName);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source_file(directory: &Path, size: usize) -> PathBuf {
        let path = directory.join("payload.bin");
        let data: Vec<u8> = (0..size).map(|index| (index % 251) as u8).collect();
        fs::write(&path, data).unwrap();
        path
    }

    #[test]
    fn offer_is_metadata_only_and_transfer_is_verified() {
        let source_dir = tempfile::tempdir().unwrap();
        let destination_dir = tempfile::tempdir().unwrap();
        let path = source_file(source_dir.path(), MAX_CHUNK_BYTES * 2 + 19);
        let offer = FileOffer::from_path(&path).unwrap();
        assert_eq!(offer.file_name, "payload.bin");
        assert_eq!(offer.size, (MAX_CHUNK_BYTES * 2 + 19) as u64);
        let wire = serde_json::to_value(&offer).unwrap();
        assert!(wire.get("digest").is_none());

        let mut sender = FileSender::open(&path, offer.clone()).unwrap();
        let mut receiver = FileReceiver::new(destination_dir.path(), offer).unwrap();
        let mut count = 0;
        while let Some(chunk) = sender.read_next_chunk().unwrap() {
            assert!(chunk.data.len() <= MAX_CHUNK_BYTES);
            receiver.write_chunk(&chunk).unwrap();
            count += 1;
        }
        assert_eq!(count, 3);
        let destination = receiver.finish(sender.final_digest().unwrap()).unwrap();
        assert_eq!(fs::read(destination).unwrap(), fs::read(path).unwrap());
    }

    #[test]
    fn resume_accepts_only_the_matching_prefix() {
        let source_dir = tempfile::tempdir().unwrap();
        let destination_dir = tempfile::tempdir().unwrap();
        let path = source_file(source_dir.path(), MAX_CHUNK_BYTES + 31);
        let offer = FileOffer::from_path(&path).unwrap();
        let mut first_sender = FileSender::open(&path, offer.clone()).unwrap();
        let mut receiver = FileReceiver::new(destination_dir.path(), offer.clone()).unwrap();
        receiver
            .write_chunk(&first_sender.read_next_chunk().unwrap().unwrap())
            .unwrap();
        let proof = receiver.resume_proof().unwrap();
        assert_eq!(proof.offset, MAX_CHUNK_BYTES as u64);

        let mut resumed_sender = FileSender::open(&path, offer).unwrap();
        let mut altered_proof = proof.clone();
        altered_proof.prefix_blake3[0] ^= 1;
        assert!(matches!(
            resumed_sender.resume_from(&altered_proof),
            Err(TransferError::IntegrityMismatch)
        ));
        assert_eq!(resumed_sender.offset(), 0);
        resumed_sender.resume_from(&proof).unwrap();
        while let Some(chunk) = resumed_sender.read_next_chunk().unwrap() {
            receiver.write_chunk(&chunk).unwrap();
        }
        let destination = receiver
            .finish(resumed_sender.final_digest().unwrap())
            .unwrap();
        assert_eq!(fs::read(destination).unwrap(), fs::read(path).unwrap());
    }

    #[test]
    fn small_chunks_preserve_integrity_and_revocation_prevents_publication() {
        let source_dir = tempfile::tempdir().unwrap();
        let destination_dir = tempfile::tempdir().unwrap();
        let path = source_file(source_dir.path(), 16 * 1024 + 17);
        let offer = FileOffer::from_path(&path).unwrap();
        let mut sender = FileSender::open(&path, offer.clone()).unwrap();
        let mut receiver = FileReceiver::new(destination_dir.path(), offer).unwrap();
        assert!(matches!(
            sender.read_next_chunk_with_limit(0),
            Err(TransferError::InvalidChunkSize)
        ));
        while let Some(chunk) = sender.read_next_chunk_with_limit(16 * 1024).unwrap() {
            assert!(chunk.data.len() <= 16 * 1024);
            receiver.write_chunk(&chunk).unwrap();
        }
        let digest = sender.final_digest().unwrap();
        let mut checked = false;
        assert!(matches!(
            receiver.finish_with_authorization(digest, || {
                checked = true;
                Err::<(), _>(TransferError::AuthorizationRevoked)
            }),
            Err(TransferError::AuthorizationRevoked)
        ));
        assert!(checked);
        assert!(!destination_dir.path().join("payload.bin").exists());
    }

    #[test]
    fn corrupt_chunks_and_final_digest_never_publish() {
        let source_dir = tempfile::tempdir().unwrap();
        let destination_dir = tempfile::tempdir().unwrap();
        let path = source_file(source_dir.path(), 19);
        let offer = FileOffer::from_path(&path).unwrap();
        let mut sender = FileSender::open(&path, offer.clone()).unwrap();
        let mut receiver = FileReceiver::new(destination_dir.path(), offer).unwrap();
        let chunk = sender.read_next_chunk().unwrap().unwrap();
        let mut corrupt = chunk.clone();
        corrupt.data[0] ^= 1;
        assert!(matches!(
            receiver.write_chunk(&corrupt),
            Err(TransferError::IntegrityMismatch)
        ));
        assert_eq!(receiver.offset(), 0);
        receiver.write_chunk(&chunk).unwrap();
        assert!(matches!(
            receiver.finish([0; 32]),
            Err(TransferError::IntegrityMismatch)
        ));
        assert!(!destination_dir.path().join("payload.bin").exists());
    }

    #[test]
    fn zero_byte_file_and_existing_destination() {
        let source_dir = tempfile::tempdir().unwrap();
        let destination_dir = tempfile::tempdir().unwrap();
        let path = source_file(source_dir.path(), 0);
        let offer = FileOffer::from_path(&path).unwrap();
        let mut sender = FileSender::open(&path, offer.clone()).unwrap();
        assert!(sender.read_next_chunk().unwrap().is_none());
        let receiver = FileReceiver::new(destination_dir.path(), offer.clone()).unwrap();
        let destination = receiver.finish(sender.final_digest().unwrap()).unwrap();
        assert_eq!(fs::metadata(&destination).unwrap().len(), 0);

        let receiver = FileReceiver::new(destination_dir.path(), offer).unwrap();
        assert!(matches!(
            receiver.finish(*blake3::hash(b"").as_bytes()),
            Err(TransferError::DestinationExists)
        ));
        assert_eq!(fs::metadata(destination).unwrap().len(), 0);
    }

    #[test]
    fn unsafe_names_and_symlinks_are_rejected() {
        let directory = tempfile::tempdir().unwrap();
        for name in [
            "../escape",
            "/absolute",
            "..\\escape",
            "CON.txt",
            "bad:name",
            "bad*name",
            "trailing.",
        ] {
            let offer = FileOffer {
                transfer_id: Uuid::new_v4(),
                file_name: name.into(),
                size: 1,
            };
            assert!(matches!(
                FileReceiver::new(directory.path(), offer),
                Err(TransferError::UnsafeName)
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let path = source_file(directory.path(), 1);
            let link = directory.path().join("linked.bin");
            symlink(&path, &link).unwrap();
            assert!(matches!(
                FileOffer::from_path(&link),
                Err(TransferError::Symlink)
            ));
            let dir_link = directory.path().join("dir-link");
            symlink(directory.path(), &dir_link).unwrap();
            let offer = FileOffer::from_path(&path).unwrap();
            assert!(matches!(
                FileReceiver::new(&dir_link, offer),
                Err(TransferError::Symlink)
            ));
        }
    }
}
