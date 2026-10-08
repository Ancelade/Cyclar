# Cyclar file transfer core

This crate implements an on-demand, single-file transfer. `FileOffer::from_path`
reads metadata only. The file is opened for content only when
`FileSender::open` is called after the recipient requests it.

```rust,no_run
use cyclar_transfer::{FileOffer, FileReceiver, FileSender};
use std::path::Path;

# fn transfer() -> Result<(), cyclar_transfer::TransferError> {
let source = Path::new("/trusted/source/document.bin");
let destination_dir = Path::new("/trusted/downloads");
let offer = FileOffer::from_path(source)?;

// Send only `offer` first. Open and stream bytes after explicit authorization.
let mut sender = FileSender::open(source, offer.clone())?;
let mut receiver = FileReceiver::new(destination_dir, offer)?;
while let Some(chunk) = sender.read_next_chunk()? {
    receiver.write_chunk(&chunk)?;
}
let path = receiver.finish(sender.final_digest()?)?;
# let _ = path;
# Ok(())
# }
```

Chunks are at most 256 KiB. Each carries a BLAKE3 digest, and the receiver
checks the complete temporary file against the sender's final digest before
publishing it. `resume_proof` rehashes the received prefix; `resume_from`
rehashes the source prefix before continuing at that offset. A temporary file
is published with `tempfile::persist_noclobber`, which never replaces an
existing destination. Names containing separators, traversal, Windows device
names, control characters, or incompatible trailing characters are refused.
`read_next_chunk_with_limit(16 * 1024)` emits smaller blocks so the session
writer can release its lock frequently for keyboard and mouse traffic.

`TransferMessage` provides a compact, versioned binary frame for the session
transport: `Offer`, `Request`, `Chunk`, `Complete`, and `Abort`. An initial
request uses `ResumeProof::empty(transfer_id)`; later requests use the
receiver's verified prefix. The largest encoded frame is
`MAX_TRANSFER_FRAME_BYTES` (262,209 bytes). The outer session protocol should
check that limit before allocating a frame, then call `TransferMessage::decode`.

The required order is **Offer → explicit receiver approval/Request → Chunk* →
Complete**. The offer contains only a random transfer ID, a validated basename
and size; it contains neither file contents nor a precomputed full-file hash.
The sender compares the source prefix against `ResumeProof` before restarting
at an offset, and the receiver checks both each chunk and the final temporary
file. A mismatched prefix or final digest aborts publication. The receiver
rejects path separators, traversal, symlinks and existing destinations. The
receiving application must choose the destination directory locally; it must
never accept an arbitrary directory path from the sender.
Before publishing, the receiving application should use
`finish_with_authorization(digest, callback)`. The callback runs after the
potentially long final hash and disk sync, immediately before publication. It
may return a lock guard held through publication to serialize local revocation
with that final step. Denial deletes the temporary file.

The transfer state and temporary file live in the receiver object, so network
reconnects can resume while that object remains alive. Resume after process
restart is not implemented. The caller must use an authenticated end-to-end
encrypted session, enforce the `file_transfer` capability, and apply a size
limit to transport frames **before** allocating a `FileChunk`. Hashes detect
corruption but do not authenticate a peer on their own. Source and destination
directories must be trusted against local replacement races, especially on
platforms without `O_NOFOLLOW`. Atomic publication and crash durability depend
on the filesystem and platform; `persist_noclobber` documents its guarantees
and limits. This crate handles one regular file per offer; folder trees,
platform-specific drag-and-drop and clipboard integration are separate work.
