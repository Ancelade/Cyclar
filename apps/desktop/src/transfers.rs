//! Host-side transfer admission and recovery within a running process.
//! Receiving is impossible until a local user selects an existing directory.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Result};
use cyclar_transfer::{FileChunk, FileOffer, FileReceiver, TransferError, TransferMessage};
use uuid::Uuid;

use crate::packet::Packet;
use crate::secure::SecureWriter;

const RETAIN_FOR: Duration = Duration::from_secs(60 * 60);
const MAX_PENDING: usize = 16;
const MAX_RECEIPTS: usize = 128;

type Writer = Arc<Mutex<SecureWriter>>;

struct Pending {
    offer: FileOffer,
    controller_key: String,
    session_id: Uuid,
    writer: Writer,
    active: Arc<AtomicBool>,
    receiver: Option<FileReceiver>,
    created_at: Instant,
}

struct Receipt {
    offer: FileOffer,
    controller_key: String,
    digest: [u8; 32],
    completed_at: Instant,
}

#[derive(Default)]
struct TransferState {
    pending: HashMap<Uuid, Pending>,
    receipts: HashMap<Uuid, Receipt>,
    busy: HashSet<Uuid>,
}

#[derive(Default)]
pub struct TransferHub {
    state: Mutex<TransferState>,
}

pub enum OfferState {
    AwaitingApproval,
    Resuming,
    AlreadyCompleted,
}

pub struct PendingOffer {
    pub transfer_id: Uuid,
    pub session_id: Uuid,
    pub file_name: String,
    pub size: u64,
}

pub fn send_transfer(writer: &Writer, message: TransferMessage) -> Result<()> {
    let packet = Packet::Transfer(message).encode()?;
    writer
        .lock()
        .map_err(|_| anyhow!("session writer unavailable"))?
        .send(&packet)
}

impl TransferHub {
    pub fn list_pending(&self) -> Vec<PendingOffer> {
        let Ok(state) = self.state.lock() else {
            return Vec::new();
        };
        state
            .pending
            .values()
            .filter(|entry| entry.receiver.is_none() && entry.active.load(Ordering::Relaxed))
            .map(|entry| PendingOffer {
                transfer_id: entry.offer.transfer_id,
                session_id: entry.session_id,
                file_name: entry.offer.file_name.clone(),
                size: entry.offer.size,
            })
            .collect()
    }

    pub fn offer(
        &self,
        offer: FileOffer,
        controller_key: &str,
        session_id: Uuid,
        writer: Writer,
        active: Arc<AtomicBool>,
    ) -> Result<OfferState> {
        offer.validate()?;
        if !active.load(Ordering::Relaxed) {
            bail!("session is closed");
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow!("transfer state unavailable"))?;
        state.pending.retain(|_, entry| {
            entry.active.load(Ordering::Relaxed) || entry.created_at.elapsed() < RETAIN_FOR
        });
        state
            .receipts
            .retain(|_, receipt| receipt.completed_at.elapsed() < RETAIN_FOR);
        if let Some(receipt) = state.receipts.get(&offer.transfer_id) {
            if receipt.controller_key != controller_key || receipt.offer != offer {
                bail!("transfer identity mismatch");
            }
            let digest = receipt.digest;
            drop(state);
            send_transfer(
                &writer,
                TransferMessage::Complete {
                    transfer_id: offer.transfer_id,
                    digest,
                },
            )?;
            return Ok(OfferState::AlreadyCompleted);
        }
        if state.busy.contains(&offer.transfer_id) {
            bail!("transfer is being verified");
        }
        if let Some(mut entry) = state.pending.remove(&offer.transfer_id) {
            state.busy.insert(offer.transfer_id);
            drop(state);
            let checked = (|| -> Result<Option<cyclar_transfer::ResumeProof>> {
                if entry.controller_key != controller_key || entry.offer != offer {
                    bail!("transfer identity mismatch");
                }
                entry.session_id = session_id;
                entry.writer = writer.clone();
                entry.active = active;
                match entry.receiver.as_mut() {
                    Some(receiver) => Ok(Some(receiver.resume_proof()?)),
                    None => Ok(None),
                }
            })();
            let mut state = self
                .state
                .lock()
                .map_err(|_| anyhow!("transfer state unavailable"))?;
            state.busy.remove(&offer.transfer_id);
            let still_active = entry.active.load(Ordering::Relaxed);
            if still_active {
                state.pending.insert(offer.transfer_id, entry);
            }
            drop(state);
            if !still_active {
                bail!("session closed during transfer verification");
            }
            if let Some(proof) = checked? {
                send_transfer(&writer, TransferMessage::Request(proof))?;
                return Ok(OfferState::Resuming);
            }
            return Ok(OfferState::AwaitingApproval);
        }
        if state.pending.len() + state.busy.len() >= MAX_PENDING {
            bail!("too many pending file offers");
        }
        state.pending.insert(
            offer.transfer_id,
            Pending {
                offer,
                controller_key: controller_key.to_owned(),
                session_id,
                writer,
                active,
                receiver: None,
                created_at: Instant::now(),
            },
        );
        Ok(OfferState::AwaitingApproval)
    }

    pub fn approve(&self, transfer_id: Uuid, destination_dir: &Path) -> Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow!("transfer state unavailable"))?;
        if state.busy.contains(&transfer_id) {
            bail!("transfer is being verified");
        }
        let entry = state
            .pending
            .get_mut(&transfer_id)
            .ok_or_else(|| anyhow!("file offer not found"))?;
        if !entry.active.load(Ordering::Relaxed) {
            bail!("controller disconnected; wait for reconnection");
        }
        if entry.receiver.is_some() {
            bail!("file offer already approved");
        }
        let mut receiver = FileReceiver::new(destination_dir, entry.offer.clone())?;
        let proof = receiver.resume_proof()?;
        entry.receiver = Some(receiver);
        let writer = entry.writer.clone();
        let active = entry.active.clone();
        drop(state);
        if !active.load(Ordering::Relaxed) {
            bail!("session closed during local approval");
        }
        send_transfer(&writer, TransferMessage::Request(proof))
    }

    pub fn write_chunk(&self, session_id: Uuid, chunk: &FileChunk) -> Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow!("transfer state unavailable"))?;
        if state.busy.contains(&chunk.transfer_id) {
            bail!("transfer is being verified");
        }
        let entry = state
            .pending
            .get_mut(&chunk.transfer_id)
            .ok_or_else(|| anyhow!("unrequested file chunk"))?;
        if entry.session_id != session_id || !entry.active.load(Ordering::Relaxed) {
            bail!("file chunk belongs to another session");
        }
        entry
            .receiver
            .as_mut()
            .ok_or_else(|| anyhow!("file transfer has no local approval"))?
            .write_chunk(chunk)
            .map_err(Into::into)
    }

    pub fn finish<G, F>(
        &self,
        session_id: Uuid,
        transfer_id: Uuid,
        digest: [u8; 32],
        authorize: F,
    ) -> Result<(PathBuf, Writer)>
    where
        F: FnOnce() -> std::result::Result<G, TransferError>,
    {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow!("transfer state unavailable"))?;
        if state.busy.contains(&transfer_id) {
            bail!("transfer is being verified");
        }
        let entry = state
            .pending
            .get(&transfer_id)
            .ok_or_else(|| anyhow!("unknown file transfer"))?;
        if entry.session_id != session_id || !entry.active.load(Ordering::Relaxed) {
            bail!("file transfer belongs to another session");
        }
        if entry.receiver.is_none() {
            bail!("file transfer has no local approval");
        }
        let mut entry = state
            .pending
            .remove(&transfer_id)
            .ok_or_else(|| anyhow!("unknown file transfer"))?;
        let receiver = entry
            .receiver
            .take()
            .ok_or_else(|| anyhow!("file transfer has no local approval"))?;
        state.busy.insert(transfer_id);
        drop(state);
        let published = receiver.finish_with_authorization(digest, authorize);
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow!("transfer state unavailable"))?;
        state.busy.remove(&transfer_id);
        let path = published?;
        if state.receipts.len() >= MAX_RECEIPTS {
            if let Some(oldest) = state
                .receipts
                .iter()
                .min_by_key(|(_, receipt)| receipt.completed_at)
                .map(|(id, _)| *id)
            {
                state.receipts.remove(&oldest);
            }
        }
        state.receipts.insert(
            transfer_id,
            Receipt {
                offer: entry.offer,
                controller_key: entry.controller_key,
                digest,
                completed_at: Instant::now(),
            },
        );
        Ok((path, entry.writer))
    }

    pub fn abort(&self, session_id: Uuid, transfer_id: Uuid) {
        if let Ok(mut state) = self.state.lock() {
            if state
                .pending
                .get(&transfer_id)
                .is_some_and(|entry| entry.session_id == session_id)
            {
                state.pending.remove(&transfer_id);
            }
        }
    }

    pub fn on_disconnect(&self, session_id: Uuid) {
        if let Ok(mut state) = self.state.lock() {
            for entry in state
                .pending
                .values_mut()
                .filter(|entry| entry.session_id == session_id)
            {
                entry.active.store(false, Ordering::Relaxed);
            }
        }
    }

    pub fn revoke_session(&self, session_id: Uuid) {
        if let Ok(mut state) = self.state.lock() {
            state
                .pending
                .retain(|_, entry| entry.session_id != session_id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::net::{TcpListener, TcpStream};
    use std::thread;
    use std::time::{SystemTime, UNIX_EPOCH};

    use cyclar_protocol::{encode_public_key, sign_grant, Capability, GrantClaims};
    use cyclar_transfer::{FileSender, MAX_TRANSFER_FRAME_BYTES};
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;

    use crate::secure::{accept_host, connect_controller};

    #[test]
    fn approved_file_crosses_noise_and_is_published_only_after_integrity_check() {
        let root = std::env::temp_dir().join(format!("cyclar-transfer-test-{}", Uuid::new_v4()));
        let destination = root.join("destination");
        fs::create_dir_all(&destination).unwrap();
        let source = root.join("sample.bin");
        let original: Vec<u8> = (0..100_000).map(|index| (index % 251) as u8).collect();
        fs::write(&source, &original).unwrap();
        let offer = FileOffer::from_path(&source).unwrap();

        let server = SigningKey::generate(&mut OsRng);
        let host = SigningKey::generate(&mut OsRng);
        let controller = SigningKey::generate(&mut OsRng);
        let host_id = Uuid::new_v4();
        let session_id = Uuid::new_v4();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let grant = sign_grant(
            &GrantClaims {
                session_id,
                host_device_id: host_id,
                controller_public_key: encode_public_key(&controller.verifying_key()),
                capabilities: vec![Capability::View, Capability::FileTransfer],
                issued_at: now,
                expires_at: now + 30,
                nonce: Uuid::new_v4(),
                host_key_epoch: 0,
            },
            &server,
        )
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server_key = encode_public_key(&server.verifying_key());
        let host_key = encode_public_key(&host.verifying_key());
        let controller_key = encode_public_key(&controller.verifying_key());
        let destination_for_host = destination.clone();
        let expected_id = offer.transfer_id;
        let host_thread = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let peer = accept_host(stream, &host, &server_key, host_id, 0).unwrap();
            assert!(peer.can_file_transfer);
            let mut reader = peer.reader;
            let writer = Arc::new(Mutex::new(peer.writer));
            let packet = Packet::decode(
                &reader
                    .receive_bounded(MAX_TRANSFER_FRAME_BYTES + 1)
                    .unwrap(),
            )
            .unwrap();
            let Packet::Transfer(TransferMessage::Offer(received)) = packet else {
                panic!("missing file offer")
            };
            assert_eq!(received.transfer_id, expected_id);
            let hub = TransferHub::default();
            let active = Arc::new(AtomicBool::new(true));
            assert!(matches!(
                hub.offer(
                    received,
                    &controller_key,
                    session_id,
                    writer.clone(),
                    active
                )
                .unwrap(),
                OfferState::AwaitingApproval
            ));
            assert_eq!(hub.list_pending().len(), 1);
            assert!(!destination_for_host.join("sample.bin").exists());
            hub.approve(expected_id, &destination_for_host).unwrap();
            loop {
                let packet = Packet::decode(
                    &reader
                        .receive_bounded(MAX_TRANSFER_FRAME_BYTES + 1)
                        .unwrap(),
                )
                .unwrap();
                match packet {
                    Packet::Transfer(TransferMessage::Chunk(chunk)) => {
                        hub.write_chunk(session_id, &chunk).unwrap()
                    }
                    Packet::Transfer(TransferMessage::Complete {
                        transfer_id,
                        digest,
                    }) => {
                        let (published, ack_writer) = hub
                            .finish(session_id, transfer_id, digest, || Ok(()))
                            .unwrap();
                        assert_eq!(published, destination_for_host.join("sample.bin"));
                        send_transfer(
                            &ack_writer,
                            TransferMessage::Complete {
                                transfer_id,
                                digest,
                            },
                        )
                        .unwrap();
                        break;
                    }
                    _ => panic!("unexpected transfer packet"),
                }
            }
        });

        let stream = TcpStream::connect(address).unwrap();
        let mut peer =
            connect_controller(stream, &grant, session_id, &host_key, &controller, now + 30)
                .unwrap();
        peer.writer
            .send(
                &Packet::Transfer(TransferMessage::Offer(offer.clone()))
                    .encode()
                    .unwrap(),
            )
            .unwrap();
        let packet = Packet::decode(&peer.reader.receive().unwrap()).unwrap();
        let Packet::Transfer(TransferMessage::Request(proof)) = packet else {
            panic!("missing approved request")
        };
        let mut sender = FileSender::open(&source, offer.clone()).unwrap();
        sender.resume_from(&proof).unwrap();
        while let Some(chunk) = sender.read_next_chunk_with_limit(16 * 1024).unwrap() {
            peer.writer
                .send(
                    &Packet::Transfer(TransferMessage::Chunk(chunk))
                        .encode()
                        .unwrap(),
                )
                .unwrap();
        }
        let digest = sender.final_digest().unwrap();
        peer.writer
            .send(
                &Packet::Transfer(TransferMessage::Complete {
                    transfer_id: expected_id,
                    digest,
                })
                .encode()
                .unwrap(),
            )
            .unwrap();
        let packet = Packet::decode(&peer.reader.receive().unwrap()).unwrap();
        assert_eq!(
            packet,
            Packet::Transfer(TransferMessage::Complete {
                transfer_id: expected_id,
                digest
            })
        );
        host_thread.join().unwrap();
        assert_eq!(fs::read(destination.join("sample.bin")).unwrap(), original);
        fs::remove_dir_all(root).unwrap();
    }
}
