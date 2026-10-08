//! Versioned binary frames for the encrypted session's file channel.

use crate::{
    validate_file_name, FileChunk, FileOffer, ResumeProof, TransferError, MAX_CHUNK_BYTES,
};
use uuid::Uuid;

const MAGIC: &[u8; 4] = b"CTF\x01";
const OFFER: u8 = 1;
const REQUEST: u8 = 2;
const CHUNK: u8 = 3;
const COMPLETE: u8 = 4;
const ABORT: u8 = 5;

/// Maximum plaintext length, including the header of the largest chunk.
pub const MAX_TRANSFER_FRAME_BYTES: usize = MAX_CHUNK_BYTES + 4 + 1 + 16 + 8 + 32 + 4;

/// A small protocol nested inside an authenticated, encrypted session.
///
/// The `Offer` has no file bytes. `Request` is the receiver's verified prefix
/// proof; only after it arrives may the sender open and read the offered file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransferMessage {
    Offer(FileOffer),
    Request(ResumeProof),
    Chunk(FileChunk),
    Complete { transfer_id: Uuid, digest: [u8; 32] },
    Abort { transfer_id: Uuid },
}

impl TransferMessage {
    pub fn encode(&self) -> Result<Vec<u8>, TransferError> {
        let mut output = Vec::new();
        output.extend_from_slice(MAGIC);
        match self {
            Self::Offer(offer) => {
                offer.validate()?;
                output.push(OFFER);
                output.extend_from_slice(offer.transfer_id.as_bytes());
                output.extend_from_slice(&offer.size.to_be_bytes());
                let name = offer.file_name.as_bytes();
                output.extend_from_slice(&(name.len() as u16).to_be_bytes());
                output.extend_from_slice(name);
            }
            Self::Request(proof) => {
                ensure_id(proof.transfer_id)?;
                output.push(REQUEST);
                output.extend_from_slice(proof.transfer_id.as_bytes());
                output.extend_from_slice(&proof.offset.to_be_bytes());
                output.extend_from_slice(&proof.prefix_blake3);
            }
            Self::Chunk(chunk) => {
                ensure_id(chunk.transfer_id)?;
                if chunk.data.is_empty() || chunk.data.len() > MAX_CHUNK_BYTES {
                    return Err(TransferError::InvalidChunkSize);
                }
                if blake3::hash(&chunk.data).as_bytes() != &chunk.blake3 {
                    return Err(TransferError::IntegrityMismatch);
                }
                output.push(CHUNK);
                output.extend_from_slice(chunk.transfer_id.as_bytes());
                output.extend_from_slice(&chunk.offset.to_be_bytes());
                output.extend_from_slice(&chunk.blake3);
                output.extend_from_slice(&(chunk.data.len() as u32).to_be_bytes());
                output.extend_from_slice(&chunk.data);
            }
            Self::Complete {
                transfer_id,
                digest,
            } => {
                ensure_id(*transfer_id)?;
                output.push(COMPLETE);
                output.extend_from_slice(transfer_id.as_bytes());
                output.extend_from_slice(digest);
            }
            Self::Abort { transfer_id } => {
                ensure_id(*transfer_id)?;
                output.push(ABORT);
                output.extend_from_slice(transfer_id.as_bytes());
            }
        }
        if output.len() > MAX_TRANSFER_FRAME_BYTES {
            return Err(TransferError::FrameTooLarge);
        }
        Ok(output)
    }

    /// Reject an oversized frame before allocating a chunk or filename.
    pub fn decode(bytes: &[u8]) -> Result<Self, TransferError> {
        if bytes.len() > MAX_TRANSFER_FRAME_BYTES {
            return Err(TransferError::FrameTooLarge);
        }
        if !bytes.starts_with(MAGIC) {
            return Err(TransferError::MalformedFrame);
        }
        let mut reader = Reader {
            bytes,
            offset: MAGIC.len(),
        };
        let kind = reader.take(1)?[0];
        let message = match kind {
            OFFER => {
                let transfer_id = reader.uuid()?;
                let size = reader.u64()?;
                let name_len = reader.u16()? as usize;
                if name_len == 0 || name_len > 255 {
                    return Err(TransferError::UnsafeName);
                }
                let file_name = std::str::from_utf8(reader.take(name_len)?)
                    .map_err(|_| TransferError::UnsafeName)?
                    .to_owned();
                validate_file_name(&file_name)?;
                Self::Offer(FileOffer {
                    transfer_id,
                    file_name,
                    size,
                })
            }
            REQUEST => Self::Request(ResumeProof {
                transfer_id: reader.uuid()?,
                offset: reader.u64()?,
                prefix_blake3: reader.array::<32>()?,
            }),
            CHUNK => {
                let transfer_id = reader.uuid()?;
                let offset = reader.u64()?;
                let digest = reader.array::<32>()?;
                let length = reader.u32()? as usize;
                if length == 0 || length > MAX_CHUNK_BYTES {
                    return Err(TransferError::InvalidChunkSize);
                }
                let data = reader.take(length)?.to_vec();
                if blake3::hash(&data).as_bytes() != &digest {
                    return Err(TransferError::IntegrityMismatch);
                }
                Self::Chunk(FileChunk {
                    transfer_id,
                    offset,
                    data,
                    blake3: digest,
                })
            }
            COMPLETE => Self::Complete {
                transfer_id: reader.uuid()?,
                digest: reader.array::<32>()?,
            },
            ABORT => Self::Abort {
                transfer_id: reader.uuid()?,
            },
            _ => return Err(TransferError::MalformedFrame),
        };
        if reader.offset != bytes.len() {
            return Err(TransferError::MalformedFrame);
        }
        Ok(message)
    }
}

fn ensure_id(id: Uuid) -> Result<(), TransferError> {
    if id.is_nil() {
        Err(TransferError::InvalidTransferId)
    } else {
        Ok(())
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl Reader<'_> {
    fn take(&mut self, length: usize) -> Result<&[u8], TransferError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(TransferError::MalformedFrame)?;
        let result = self
            .bytes
            .get(self.offset..end)
            .ok_or(TransferError::MalformedFrame)?;
        self.offset = end;
        Ok(result)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], TransferError> {
        self.take(N)?
            .try_into()
            .map_err(|_| TransferError::MalformedFrame)
    }

    fn uuid(&mut self) -> Result<Uuid, TransferError> {
        let id = Uuid::from_bytes(self.array::<16>()?);
        ensure_id(id)?;
        Ok(id)
    }

    fn u16(&mut self) -> Result<u16, TransferError> {
        Ok(u16::from_be_bytes(self.array::<2>()?))
    }

    fn u32(&mut self) -> Result<u32, TransferError> {
        Ok(u32::from_be_bytes(self.array::<4>()?))
    }

    fn u64(&mut self) -> Result<u64, TransferError> {
        Ok(u64::from_be_bytes(self.array::<8>()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_frames_roundtrip() {
        let id = Uuid::from_u128(7);
        let data = vec![42u8; MAX_CHUNK_BYTES];
        let messages = [
            TransferMessage::Offer(FileOffer {
                transfer_id: id,
                file_name: "exemple.bin".into(),
                size: 7,
            }),
            TransferMessage::Request(ResumeProof::empty(id)),
            TransferMessage::Chunk(FileChunk {
                transfer_id: id,
                offset: 0,
                blake3: *blake3::hash(&data).as_bytes(),
                data,
            }),
            TransferMessage::Complete {
                transfer_id: id,
                digest: [3; 32],
            },
            TransferMessage::Abort { transfer_id: id },
        ];
        for message in messages {
            let encoded = message.encode().unwrap();
            assert!(encoded.len() <= MAX_TRANSFER_FRAME_BYTES);
            assert_eq!(TransferMessage::decode(&encoded).unwrap(), message);
        }
    }

    #[test]
    fn malformed_or_oversized_frames_are_rejected() {
        let id = Uuid::from_u128(9);
        let offer = TransferMessage::Offer(FileOffer {
            transfer_id: id,
            file_name: "safe.txt".into(),
            size: 1,
        });
        let mut valid = offer.encode().unwrap();
        valid.push(1);
        assert!(matches!(
            TransferMessage::decode(&valid),
            Err(TransferError::MalformedFrame)
        ));
        assert!(matches!(
            TransferMessage::decode(&vec![0; MAX_TRANSFER_FRAME_BYTES + 1]),
            Err(TransferError::FrameTooLarge)
        ));
        let mut valid = offer.encode().unwrap();
        // Change the first byte of the offered filename to a path separator.
        valid[4 + 1 + 16 + 8 + 2] = b'/';
        assert!(matches!(
            TransferMessage::decode(&valid),
            Err(TransferError::UnsafeName)
        ));
        let chunk = TransferMessage::Chunk(FileChunk {
            transfer_id: id,
            offset: 0,
            data: vec![1],
            blake3: *blake3::hash(&[1]).as_bytes(),
        });
        let mut valid = chunk.encode().unwrap();
        *valid.last_mut().unwrap() ^= 1;
        assert!(matches!(
            TransferMessage::decode(&valid),
            Err(TransferError::IntegrityMismatch)
        ));
    }
}
