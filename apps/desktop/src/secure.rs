//! Authenticated direct-session transport using Noise NN over TCP.
//!
//! The server-signed grant is the Noise prologue. Ed25519 signatures over the
//! grant and both Noise handshake messages bind the ephemeral Noise exchange
//! to the endpoint identities named by the central authority. Snow owns key
//! derivation and AEAD; this module only frames bounded application messages.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use cyclar_protocol::{decode_public_key, verify_grant, Capability};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use snow::{Builder, HandshakeState, StatelessTransportState};
use uuid::Uuid;

const NOISE_PATTERN: &str = "Noise_NN_25519_ChaChaPoly_SHA256";
const MAX_HANDSHAKE: usize = 16 * 1024;
const NOISE_HANDSHAKE_BUFFER: usize = 1024;
const CHUNK_DATA: usize = 60_000;
const NOISE_TAG: usize = 16;
pub const MAX_MESSAGE: usize = 8 * 1024 * 1024;
const CONTROLLER_DOMAIN: &[u8] = b"cyclar-controller-noise-nn-v1";
const HOST_DOMAIN: &[u8] = b"cyclar-host-noise-nn-v1";

#[derive(Serialize, Deserialize)]
struct ControllerHello {
    grant: String,
    noise_message: String,
    signature: String,
}

#[derive(Serialize, Deserialize)]
struct HostHello {
    noise_message: String,
    signature: String,
}

pub struct SecureReader {
    stream: TcpStream,
    noise: Arc<StatelessTransportState>,
    sequence: u64,
}

pub struct SecureWriter {
    stream: TcpStream,
    noise: Arc<StatelessTransportState>,
    sequence: u64,
}

pub struct SecurePeer {
    pub reader: SecureReader,
    pub writer: SecureWriter,
    pub session_id: Uuid,
    pub expires_at: u64,
    pub can_input: bool,
    pub can_file_transfer: bool,
    pub controller_public_key: String,
}

fn decode_signature(value: &str) -> Result<Signature> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .context("invalid base64url signature")?;
    let bytes: [u8; 64] = bytes
        .try_into()
        .map_err(|_| anyhow!("invalid signature length"))?;
    Ok(Signature::from_bytes(&bytes))
}

fn verifying_key(value: &str) -> Result<VerifyingKey> {
    decode_public_key(value).map_err(|_| anyhow!("invalid Ed25519 public key"))
}

fn transcript(domain: &[u8], session_id: Uuid, parts: &[&[u8]]) -> Vec<u8> {
    let mut output = Vec::with_capacity(
        domain.len() + 16 + parts.iter().map(|part| part.len() + 8).sum::<usize>(),
    );
    output.extend_from_slice(domain);
    output.extend_from_slice(session_id.as_bytes());
    for part in parts {
        output.extend_from_slice(&(part.len() as u64).to_be_bytes());
        output.extend_from_slice(part);
    }
    output
}

fn noise_handshake(grant: &str, initiator: bool) -> Result<HandshakeState> {
    let params = NOISE_PATTERN.parse().context("invalid Noise pattern")?;
    let builder = Builder::new(params)
        .prologue(grant.as_bytes())
        .context("invalid Noise prologue")?;
    if initiator {
        builder
            .build_initiator()
            .context("Noise initiator unavailable")
    } else {
        builder
            .build_responder()
            .context("Noise responder unavailable")
    }
}

fn write_handshake<T: Serialize>(stream: &mut TcpStream, message: &T) -> Result<()> {
    let bytes = serde_json::to_vec(message)?;
    if bytes.len() > MAX_HANDSHAKE {
        bail!("handshake too large");
    }
    stream.write_all(&(bytes.len() as u32).to_be_bytes())?;
    stream.write_all(&bytes)?;
    Ok(())
}

fn read_handshake<T: for<'a> Deserialize<'a>>(stream: &mut TcpStream) -> Result<T> {
    let mut header = [0; 4];
    stream.read_exact(&mut header)?;
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 || length > MAX_HANDSHAKE {
        bail!("invalid handshake length");
    }
    let mut bytes = vec![0; length];
    stream.read_exact(&mut bytes)?;
    serde_json::from_slice(&bytes).context("invalid handshake message")
}

fn decode_noise_message(value: &str) -> Result<Vec<u8>> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .context("invalid Noise handshake encoding")?;
    if bytes.is_empty() || bytes.len() > NOISE_HANDSHAKE_BUFFER {
        bail!("Noise handshake message size out of bounds");
    }
    Ok(bytes)
}

fn secure_peer(
    stream: TcpStream,
    session_id: Uuid,
    expires_at: u64,
    can_input: bool,
    can_file_transfer: bool,
    controller_public_key: String,
    noise: StatelessTransportState,
) -> Result<SecurePeer> {
    stream.set_nodelay(true)?;
    let reader_stream = stream.try_clone()?;
    let noise = Arc::new(noise);
    Ok(SecurePeer {
        reader: SecureReader {
            stream: reader_stream,
            noise: noise.clone(),
            sequence: 0,
        },
        writer: SecureWriter {
            stream,
            noise,
            sequence: 0,
        },
        session_id,
        expires_at,
        can_input,
        can_file_transfer,
        controller_public_key,
    })
}

pub fn accept_host(
    mut stream: TcpStream,
    host_signing_key: &SigningKey,
    server_public_key: &str,
    host_device_id: Uuid,
    host_key_epoch: u64,
) -> Result<SecurePeer> {
    stream.set_read_timeout(Some(Duration::from_secs(8)))?;
    stream.set_write_timeout(Some(Duration::from_secs(8)))?;
    let hello: ControllerHello = read_handshake(&mut stream)?;
    let server_key = verifying_key(server_public_key)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let claims = verify_grant(
        &hello.grant,
        &server_key,
        host_device_id,
        host_key_epoch,
        now,
    )
    .map_err(|_| anyhow!("session grant rejected"))?;
    if !claims.allows(Capability::View) {
        bail!("view capability denied");
    }
    let first_message = decode_noise_message(&hello.noise_message)?;
    let signed = transcript(
        CONTROLLER_DOMAIN,
        claims.session_id,
        &[hello.grant.as_bytes(), &first_message],
    );
    verifying_key(&claims.controller_public_key)?
        .verify(&signed, &decode_signature(&hello.signature)?)
        .context("controller identity proof failed")?;

    let mut noise = noise_handshake(&hello.grant, false)?;
    let mut payload = [0u8; NOISE_HANDSHAKE_BUFFER];
    if noise
        .read_message(&first_message, &mut payload)
        .context("invalid first Noise message")?
        != 0
    {
        bail!("unexpected Noise handshake payload");
    }
    let mut second_message = [0u8; NOISE_HANDSHAKE_BUFFER];
    let written = noise
        .write_message(&[], &mut second_message)
        .context("Noise handshake failed")?;
    let second_message = &second_message[..written];
    let signed = transcript(
        HOST_DOMAIN,
        claims.session_id,
        &[hello.grant.as_bytes(), &first_message, second_message],
    );
    write_handshake(
        &mut stream,
        &HostHello {
            noise_message: URL_SAFE_NO_PAD.encode(second_message),
            signature: URL_SAFE_NO_PAD.encode(host_signing_key.sign(&signed).to_bytes()),
        },
    )?;
    let transport = noise
        .into_stateless_transport_mode()
        .context("Noise transport unavailable")?;
    stream.set_read_timeout(None)?;
    stream.set_write_timeout(None)?;
    secure_peer(
        stream,
        claims.session_id,
        claims.expires_at,
        claims.allows(Capability::Input),
        claims.allows(Capability::FileTransfer),
        claims.controller_public_key,
        transport,
    )
}

pub fn connect_controller(
    mut stream: TcpStream,
    grant: &str,
    session_id: Uuid,
    host_public_key: &str,
    controller_signing_key: &SigningKey,
    expires_at: u64,
) -> Result<SecurePeer> {
    stream.set_read_timeout(Some(Duration::from_secs(8)))?;
    stream.set_write_timeout(Some(Duration::from_secs(8)))?;
    let mut noise = noise_handshake(grant, true)?;
    let mut first_message = [0u8; NOISE_HANDSHAKE_BUFFER];
    let written = noise
        .write_message(&[], &mut first_message)
        .context("Noise handshake failed")?;
    let first_message = &first_message[..written];
    let signed = transcript(
        CONTROLLER_DOMAIN,
        session_id,
        &[grant.as_bytes(), first_message],
    );
    write_handshake(
        &mut stream,
        &ControllerHello {
            grant: grant.to_owned(),
            noise_message: URL_SAFE_NO_PAD.encode(first_message),
            signature: URL_SAFE_NO_PAD.encode(controller_signing_key.sign(&signed).to_bytes()),
        },
    )?;
    let hello: HostHello = read_handshake(&mut stream)?;
    let second_message = decode_noise_message(&hello.noise_message)?;
    let signed = transcript(
        HOST_DOMAIN,
        session_id,
        &[grant.as_bytes(), first_message, &second_message],
    );
    verifying_key(host_public_key)?
        .verify(&signed, &decode_signature(&hello.signature)?)
        .context("host identity proof failed")?;
    let mut payload = [0u8; NOISE_HANDSHAKE_BUFFER];
    if noise
        .read_message(&second_message, &mut payload)
        .context("invalid second Noise message")?
        != 0
    {
        bail!("unexpected Noise handshake payload");
    }
    let transport = noise
        .into_stateless_transport_mode()
        .context("Noise transport unavailable")?;
    stream.set_read_timeout(None)?;
    stream.set_write_timeout(None)?;
    secure_peer(
        stream,
        session_id,
        expires_at,
        true,
        true,
        URL_SAFE_NO_PAD.encode(controller_signing_key.verifying_key().to_bytes()),
        transport,
    )
}

impl SecureWriter {
    pub fn send(&mut self, plaintext: &[u8]) -> Result<()> {
        if plaintext.is_empty() || plaintext.len() > MAX_MESSAGE {
            bail!("message size out of bounds");
        }
        let mut chunks = plaintext.chunks(CHUNK_DATA).peekable();
        while let Some(data) = chunks.next() {
            let mut input = Vec::with_capacity(data.len() + 1);
            input.push(u8::from(chunks.peek().is_none()));
            input.extend_from_slice(data);
            let mut ciphertext = vec![0; input.len() + NOISE_TAG];
            let length = self
                .noise
                .write_message(self.sequence, &input, &mut ciphertext)
                .context("Noise encryption failed")?;
            self.sequence = self
                .sequence
                .checked_add(1)
                .ok_or_else(|| anyhow!("Noise nonce exhausted"))?;
            self.stream.write_all(&(length as u16).to_be_bytes())?;
            self.stream.write_all(&ciphertext[..length])?;
        }
        Ok(())
    }

    pub fn shutdown(&self) {
        let _ = self.stream.shutdown(std::net::Shutdown::Both);
    }
}

impl SecureReader {
    pub fn receive(&mut self) -> Result<Vec<u8>> {
        self.receive_bounded(MAX_MESSAGE)
    }

    pub fn receive_bounded(&mut self, max_plaintext: usize) -> Result<Vec<u8>> {
        let max_plaintext = max_plaintext.min(MAX_MESSAGE);
        let mut output = Vec::new();
        loop {
            let mut header = [0; 2];
            self.stream.read_exact(&mut header)?;
            let length = u16::from_be_bytes(header) as usize;
            if !(NOISE_TAG + 1..=CHUNK_DATA.min(max_plaintext) + NOISE_TAG + 1).contains(&length) {
                bail!("encrypted chunk size out of bounds");
            }
            let mut ciphertext = vec![0; length];
            self.stream.read_exact(&mut ciphertext)?;
            let mut plaintext = vec![0; length - NOISE_TAG];
            let count = self
                .noise
                .read_message(self.sequence, &ciphertext, &mut plaintext)
                .context("Noise authentication failed")?;
            self.sequence = self
                .sequence
                .checked_add(1)
                .ok_or_else(|| anyhow!("Noise nonce exhausted"))?;
            if count == 0 || plaintext[0] > 1 {
                bail!("invalid encrypted chunk marker");
            }
            let data = &plaintext[1..count];
            if output.len() + data.len() > max_plaintext {
                bail!("session message too large");
            }
            output.extend_from_slice(data);
            if plaintext[0] == 1 {
                if output.is_empty() {
                    bail!("empty session message");
                }
                return Ok(output);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    use cyclar_protocol::{encode_public_key, sign_grant, GrantClaims};
    use rand_core::OsRng;

    fn signed_fixture() -> (SigningKey, SigningKey, SigningKey, Uuid, Uuid, u64, String) {
        let server = SigningKey::generate(&mut OsRng);
        let host = SigningKey::generate(&mut OsRng);
        let controller = SigningKey::generate(&mut OsRng);
        let host_id = Uuid::new_v4();
        let session_id = Uuid::new_v4();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let token = sign_grant(
            &GrantClaims {
                session_id,
                host_device_id: host_id,
                controller_public_key: encode_public_key(&controller.verifying_key()),
                capabilities: vec![Capability::View, Capability::Input],
                issued_at: now,
                expires_at: now + 30,
                nonce: Uuid::new_v4(),
                host_key_epoch: 0,
            },
            &server,
        )
        .unwrap();
        (server, host, controller, host_id, session_id, now, token)
    }

    #[test]
    fn signed_noise_channel_transfers_large_frames_bidirectionally() {
        let (server, host, controller, host_id, session_id, now, token) = signed_fixture();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server_public = encode_public_key(&server.verifying_key());
        let host_public = encode_public_key(&host.verifying_key());
        let host_thread = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut peer = accept_host(stream, &host, &server_public, host_id, 0).unwrap();
            assert_eq!(peer.reader.receive().unwrap(), b"control message");
            peer.writer.send(&vec![0x5a; 200_000]).unwrap();
        });
        let stream = TcpStream::connect(address).unwrap();
        let mut peer = connect_controller(
            stream,
            &token,
            session_id,
            &host_public,
            &controller,
            now + 30,
        )
        .unwrap();
        peer.writer.send(b"control message").unwrap();
        assert_eq!(peer.reader.receive().unwrap(), vec![0x5a; 200_000]);
        host_thread.join().unwrap();
    }

    #[test]
    fn grant_rejects_a_different_controller_key() {
        let (server, host, _controller, host_id, session_id, now, token) = signed_fixture();
        let rogue = SigningKey::generate(&mut OsRng);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server_public = encode_public_key(&server.verifying_key());
        let host_public = encode_public_key(&host.verifying_key());
        let host_thread = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            assert!(accept_host(stream, &host, &server_public, host_id, 0).is_err());
        });
        let stream = TcpStream::connect(address).unwrap();
        assert!(
            connect_controller(stream, &token, session_id, &host_public, &rogue, now + 30).is_err()
        );
        host_thread.join().unwrap();
    }

    #[test]
    fn noise_transport_rejects_ciphertext_tampering() {
        let mut client = noise_handshake("signed grant", true).unwrap();
        let mut host = noise_handshake("signed grant", false).unwrap();
        let mut first = [0u8; NOISE_HANDSHAKE_BUFFER];
        let first_len = client.write_message(&[], &mut first).unwrap();
        host.read_message(&first[..first_len], &mut []).unwrap();
        let mut second = [0u8; NOISE_HANDSHAKE_BUFFER];
        let second_len = host.write_message(&[], &mut second).unwrap();
        client.read_message(&second[..second_len], &mut []).unwrap();
        let client = client.into_stateless_transport_mode().unwrap();
        let host = host.into_stateless_transport_mode().unwrap();
        let mut encrypted = [0u8; 64];
        let count = client
            .write_message(0, b"important", &mut encrypted)
            .unwrap();
        encrypted[0] ^= 1;
        assert!(host
            .read_message(0, &encrypted[..count], &mut [0u8; 64])
            .is_err());
    }
}
