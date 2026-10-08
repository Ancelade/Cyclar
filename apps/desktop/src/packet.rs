//! Bounded application messages inside the authenticated session channel.

use anyhow::{bail, Result};
use cyclar_transfer::{TransferMessage, MAX_TRANSFER_FRAME_BYTES};

use crate::secure::MAX_MESSAGE;

#[derive(Debug, PartialEq, Eq)]
pub enum Packet {
    Policy {
        input_allowed: bool,
    },
    Video {
        width: u16,
        height: u16,
        jpeg: Vec<u8>,
    },
    Motion {
        x: u16,
        y: u16,
    },
    Button {
        button: u8,
        pressed: bool,
    },
    Key {
        keycode: u8,
        pressed: bool,
    },
    Renewal {
        grant: String,
    },
    Close,
    Transfer(TransferMessage),
}

impl Packet {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        match self {
            Self::Policy { input_allowed } => {
                bytes.extend_from_slice(&[1, u8::from(*input_allowed)])
            }
            Self::Video {
                width,
                height,
                jpeg,
            } => {
                if *width == 0 || *height == 0 || jpeg.is_empty() {
                    bail!("invalid video frame");
                }
                bytes.push(2);
                bytes.extend_from_slice(&width.to_be_bytes());
                bytes.extend_from_slice(&height.to_be_bytes());
                bytes.extend_from_slice(jpeg);
            }
            Self::Motion { x, y } => {
                bytes.push(3);
                bytes.extend_from_slice(&x.to_be_bytes());
                bytes.extend_from_slice(&y.to_be_bytes());
            }
            Self::Button { button, pressed } => {
                bytes.extend_from_slice(&[4, *button, u8::from(*pressed)])
            }
            Self::Key { keycode, pressed } => {
                bytes.extend_from_slice(&[5, *keycode, u8::from(*pressed)])
            }
            Self::Renewal { grant } => {
                if grant.is_empty() || grant.len() > 16 * 1024 {
                    bail!("invalid renewal grant");
                }
                bytes.push(6);
                bytes.extend_from_slice(grant.as_bytes());
            }
            Self::Close => bytes.push(7),
            Self::Transfer(message) => {
                bytes.push(8);
                bytes.extend_from_slice(&message.encode()?);
            }
        }
        if bytes.len() > MAX_MESSAGE {
            bail!("session message too large");
        }
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let Some((&kind, payload)) = bytes.split_first() else {
            bail!("empty session message")
        };
        match kind {
            1 if payload.len() == 1 && payload[0] <= 1 => Ok(Self::Policy {
                input_allowed: payload[0] == 1,
            }),
            2 if payload.len() >= 6 => {
                let width = u16::from_be_bytes([payload[0], payload[1]]);
                let height = u16::from_be_bytes([payload[2], payload[3]]);
                if width == 0 || height == 0 {
                    bail!("invalid video dimensions")
                }
                Ok(Self::Video {
                    width,
                    height,
                    jpeg: payload[4..].to_vec(),
                })
            }
            3 if payload.len() == 4 => Ok(Self::Motion {
                x: u16::from_be_bytes([payload[0], payload[1]]),
                y: u16::from_be_bytes([payload[2], payload[3]]),
            }),
            4 if payload.len() == 2 && (1..=5).contains(&payload[0]) && payload[1] <= 1 => {
                Ok(Self::Button {
                    button: payload[0],
                    pressed: payload[1] == 1,
                })
            }
            5 if payload.len() == 2 && payload[1] <= 1 => Ok(Self::Key {
                keycode: payload[0],
                pressed: payload[1] == 1,
            }),
            6 if !payload.is_empty() && payload.len() <= 16 * 1024 => Ok(Self::Renewal {
                grant: String::from_utf8(payload.to_vec())?,
            }),
            7 if payload.is_empty() => Ok(Self::Close),
            8 if payload.len() <= MAX_TRANSFER_FRAME_BYTES => {
                Ok(Self::Transfer(TransferMessage::decode(payload)?))
            }
            _ => bail!("invalid or unsupported session message"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cyclar_transfer::FileOffer;
    use uuid::Uuid;

    #[test]
    fn rejects_malformed_or_unsupported_packets() {
        for bytes in [
            vec![],
            vec![2, 0, 0, 0, 1, 8],
            vec![4, 9, 1],
            vec![7, 0],
            vec![255],
        ] {
            assert!(Packet::decode(&bytes).is_err(), "accepted {bytes:?}");
        }
    }

    #[test]
    fn input_packets_round_trip() {
        let packet = Packet::Motion { x: 321, y: 654 };
        assert_eq!(Packet::decode(&packet.encode().unwrap()).unwrap(), packet);
    }

    #[test]
    fn transfer_offer_round_trips_without_file_bytes() {
        let offer = FileOffer {
            transfer_id: Uuid::new_v4(),
            file_name: "rapport.txt".into(),
            size: 5_000_000_000,
        };
        let packet = Packet::Transfer(TransferMessage::Offer(offer));
        let encoded = packet.encode().unwrap();
        assert!(encoded.len() < 128);
        assert_eq!(Packet::decode(&encoded).unwrap(), packet);
    }
}
