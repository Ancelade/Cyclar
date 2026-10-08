//! A bounded WSS fallback carrying the existing end-to-end Noise byte stream.
//! The central relay authenticates the join but only forwards opaque chunks.

use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    mpsc, Arc,
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use ed25519_dalek::{Signer, SigningKey};
use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::tungstenite::{
    client::IntoClientRequest,
    http::{header::AUTHORIZATION, HeaderValue},
    protocol::{Message, WebSocketConfig},
};
use uuid::Uuid;

const RELAY_DOMAIN: &[u8] = b"CYCLAR-RELAY-JOIN-V1\0";
const MAX_RELAY_FRAME: usize = 65_536;
const PUMP_SLICE: usize = 16 * 1024;

#[derive(Clone, Copy)]
pub enum RelayRole {
    Host,
    Controller,
}

impl RelayRole {
    pub fn path(self) -> &'static str {
        match self {
            Self::Host => "host",
            Self::Controller => "controller",
        }
    }

    fn byte(self) -> u8 {
        match self {
            Self::Host => 1,
            Self::Controller => 2,
        }
    }
}

pub enum LocalEndpoint {
    Existing(TcpStream),
    Connect(SocketAddr),
}

struct RelayParams {
    url: String,
    bearer: String,
    session_id: Uuid,
    role: RelayRole,
    signing_key: SigningKey,
    local: LocalEndpoint,
    expires_at: Option<Arc<AtomicU64>>,
}

pub struct RelayBridge {
    session_id: Uuid,
    ready: mpsc::Receiver<std::result::Result<(), String>>,
    running: Arc<AtomicBool>,
    thread: JoinHandle<()>,
}

impl RelayBridge {
    pub fn session_id(&self) -> Uuid {
        self.session_id
    }
    pub fn wait_ready(&self, timeout: Duration) -> Result<()> {
        match self.ready.recv_timeout(timeout) {
            Ok(Ok(())) => Ok(()),
            Ok(Err(message)) => Err(anyhow!(message)),
            Err(_) => bail!("relay pairing timed out"),
        }
    }

    pub fn is_finished(&self) -> bool {
        self.thread.is_finished()
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
    }
}

impl Drop for RelayBridge {
    fn drop(&mut self) {
        self.stop();
    }
}

pub fn local_pair() -> Result<(TcpStream, TcpStream)> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let app = TcpStream::connect(listener.local_addr()?)?;
    let (bridge, _) = listener.accept()?;
    app.set_nodelay(true)?;
    bridge.set_nodelay(true)?;
    Ok((app, bridge))
}

pub fn join(
    url: String,
    bearer: String,
    session_id: Uuid,
    role: RelayRole,
    signing_key: SigningKey,
    local: LocalEndpoint,
    expires_at: Option<Arc<AtomicU64>>,
) -> RelayBridge {
    let params = RelayParams {
        url,
        bearer,
        session_id,
        role,
        signing_key,
        local,
        expires_at,
    };
    let (ready_tx, ready) = mpsc::channel();
    let running = Arc::new(AtomicBool::new(true));
    let worker_running = running.clone();
    let thread = thread::spawn(move || {
        let result = (|| -> Result<()> {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            runtime.block_on(run_bridge(params, worker_running, ready_tx.clone()))
        })();
        if let Err(error) = result {
            let message = error.to_string();
            let _ = ready_tx.send(Err(message.clone()));
            eprintln!("Relais de session {session_id} interrompu : {message}");
        }
    });
    RelayBridge {
        session_id,
        ready,
        running,
        thread,
    }
}

fn proof_message(session_id: Uuid, role: RelayRole, nonce: &[u8; 32]) -> Vec<u8> {
    let mut message = Vec::with_capacity(RELAY_DOMAIN.len() + 16 + 1 + 32);
    message.extend_from_slice(RELAY_DOMAIN);
    message.extend_from_slice(session_id.as_bytes());
    message.push(role.byte());
    message.extend_from_slice(nonce);
    message
}

async fn run_bridge(
    params: RelayParams,
    running: Arc<AtomicBool>,
    ready_tx: mpsc::Sender<std::result::Result<(), String>>,
) -> Result<()> {
    let RelayParams {
        url,
        bearer,
        session_id,
        role,
        signing_key,
        local,
        expires_at,
    } = params;
    validate_relay_url(&url)?;
    let mut request = url.into_client_request().context("invalid relay URL")?;
    request.headers_mut().insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {bearer}"))
            .context("invalid relay authorization")?,
    );
    let config = WebSocketConfig::default()
        .read_buffer_size(PUMP_SLICE)
        .write_buffer_size(PUMP_SLICE)
        .max_write_buffer_size(256 * 1024)
        .max_message_size(Some(MAX_RELAY_FRAME))
        .max_frame_size(Some(MAX_RELAY_FRAME));
    let (mut websocket, _) = tokio::time::timeout(
        Duration::from_secs(10),
        tokio_tungstenite::connect_async_with_config(request, Some(config), true),
    )
    .await
    .context("relay connection timed out")?
    .context("relay connection failed")?;
    let nonce = read_binary(&mut websocket, Duration::from_secs(10)).await?;
    let nonce: [u8; 32] = nonce
        .try_into()
        .map_err(|_| anyhow!("invalid relay challenge"))?;
    let signature = signing_key.sign(&proof_message(session_id, role, &nonce));
    websocket
        .send(Message::Binary(signature.to_bytes().to_vec().into()))
        .await
        .context("relay proof failed")?;
    let ready = read_binary(&mut websocket, Duration::from_secs(20)).await?;
    if ready.as_slice() != [1] {
        bail!("relay did not confirm pairing");
    }

    let mut local = match local {
        LocalEndpoint::Existing(stream) => {
            stream.set_nonblocking(true)?;
            tokio::net::TcpStream::from_std(stream)?
        }
        LocalEndpoint::Connect(address) => tokio::net::TcpStream::connect(address)
            .await
            .context("local Noise endpoint unavailable")?,
    };
    local.set_nodelay(true)?;
    let _ = ready_tx.send(Ok(()));
    let mut buffer = [0u8; PUMP_SLICE];
    loop {
        tokio::select! {
            read = local.read(&mut buffer) => {
                let count = read.context("local Noise read failed")?;
                if count == 0 { let _ = websocket.close(None).await; break; }
                websocket.send(Message::Binary(buffer[..count].to_vec().into())).await
                    .context("relay uplink failed")?;
            }
            received = websocket.next() => {
                match received {
                    Some(Ok(Message::Binary(bytes))) if !bytes.is_empty() && bytes.len() <= MAX_RELAY_FRAME => {
                        local.write_all(&bytes).await.context("local Noise write failed")?;
                    }
                    Some(Ok(Message::Ping(_))) => { websocket.flush().await?; }
                    Some(Ok(Message::Pong(_))) => {},
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Ok(_)) => bail!("non-binary relay payload"),
                    Some(Err(error)) => return Err(error).context("relay downlink failed"),
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(200)) => {
                let expired = expires_at.as_ref().is_some_and(|value| now_seconds() >= value.load(Ordering::Relaxed));
                if !running.load(Ordering::Relaxed) || expired {
                    let _ = websocket.close(None).await;
                    break;
                }
            }
        }
    }
    let _ = local.shutdown().await;
    Ok(())
}

fn validate_relay_url(raw: &str) -> Result<()> {
    let url = reqwest::Url::parse(raw).context("invalid relay URL")?;
    match url.scheme() {
        "wss" => Ok(()),
        "ws" if matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "::1")) => Ok(()),
        "ws" => bail!("unencrypted WebSocket is allowed only on loopback"),
        _ => bail!("relay URL must use WSS"),
    }
}

async fn read_binary(
    websocket: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    timeout: Duration,
) -> Result<Vec<u8>> {
    tokio::time::timeout(timeout, async {
        loop {
            match websocket.next().await {
                Some(Ok(Message::Binary(bytes))) if bytes.len() <= MAX_RELAY_FRAME => {
                    return Ok(bytes.to_vec())
                }
                Some(Ok(Message::Ping(_))) => {
                    websocket.flush().await?;
                }
                Some(Ok(Message::Pong(_))) => {}
                Some(Ok(Message::Close(_))) | None => bail!("relay closed before pairing"),
                Some(Ok(_)) => bail!("invalid relay handshake message"),
                Some(Err(error)) => return Err(error).context("relay handshake failed"),
            }
        }
    })
    .await
    .context("relay handshake timed out")?
}

fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Verifier;
    use rand_core::OsRng;
    use std::io;

    #[test]
    fn relay_proof_binds_session_role_and_nonce() {
        let key = SigningKey::generate(&mut OsRng);
        let session = Uuid::new_v4();
        let nonce = [17u8; 32];
        let signature = key.sign(&proof_message(session, RelayRole::Host, &nonce));
        assert!(key
            .verifying_key()
            .verify(&proof_message(session, RelayRole::Host, &nonce), &signature)
            .is_ok());
        assert!(key
            .verifying_key()
            .verify(
                &proof_message(session, RelayRole::Controller, &nonce),
                &signature
            )
            .is_err());
        assert!(key
            .verifying_key()
            .verify(
                &proof_message(Uuid::new_v4(), RelayRole::Host, &nonce),
                &signature
            )
            .is_err());
    }

    #[test]
    fn local_bridge_pair_is_full_duplex() {
        let (mut app, mut bridge) = local_pair().unwrap();
        use io::{Read as _, Write as _};
        app.write_all(b"control").unwrap();
        let mut bytes = [0; 7];
        bridge.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"control");
        bridge.write_all(b"screen").unwrap();
        app.read_exact(&mut bytes[..6]).unwrap();
        assert_eq!(&bytes[..6], b"screen");
    }

    #[test]
    fn relay_bearer_requires_wss_or_loopback() {
        assert!(validate_relay_url("ws://example.net/api/v1/relay").is_err());
        assert!(validate_relay_url("wss://example.net/api/v1/relay").is_ok());
        assert!(validate_relay_url("ws://127.0.0.1:8080/api/v1/relay").is_ok());
    }

    #[test]
    fn websocket_bridge_proves_identity_and_preserves_bounded_noise_bytes() {
        use io::{Read as _, Write as _};
        use tokio_tungstenite::accept_async;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let session_id = Uuid::new_v4();
        let server = thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async move {
                let listener = tokio::net::TcpListener::from_std(listener).unwrap();
                let (stream, _) = listener.accept().await.unwrap();
                let mut websocket = accept_async(stream).await.unwrap();
                let nonce = [9u8; 32];
                websocket
                    .send(Message::Binary(nonce.to_vec().into()))
                    .await
                    .unwrap();
                let Some(Ok(Message::Binary(proof))) = websocket.next().await else {
                    panic!("missing relay proof")
                };
                let proof: [u8; 64] = proof.as_ref().try_into().unwrap();
                let proof = ed25519_dalek::Signature::from_bytes(&proof);
                verifying_key
                    .verify(
                        &proof_message(session_id, RelayRole::Controller, &nonce),
                        &proof,
                    )
                    .unwrap();
                websocket
                    .send(Message::Binary(vec![1].into()))
                    .await
                    .unwrap();
                let mut total = 0usize;
                while total < 100_000 {
                    match websocket.next().await {
                        Some(Ok(Message::Binary(bytes))) => {
                            assert!(!bytes.is_empty() && bytes.len() <= PUMP_SLICE);
                            total += bytes.len();
                            websocket.send(Message::Binary(bytes)).await.unwrap();
                        }
                        other => panic!("unexpected relay frame: {other:?}"),
                    }
                }
                websocket.close(None).await.unwrap();
            });
        });

        let (mut app, bridge_socket) = local_pair().unwrap();
        app.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let bridge = join(
            format!("ws://{address}/api/v1/relay"),
            "fixture".to_owned(),
            session_id,
            RelayRole::Controller,
            signing_key,
            LocalEndpoint::Existing(bridge_socket),
            None,
        );
        bridge.wait_ready(Duration::from_secs(5)).unwrap();
        let mut reader = app.try_clone().unwrap();
        let expected = vec![0x5a; 100_000];
        let expected_for_sender = expected.clone();
        let sending = thread::spawn(move || app.write_all(&expected_for_sender).unwrap());
        let mut actual = vec![0; expected.len()];
        reader.read_exact(&mut actual).unwrap();
        assert_eq!(actual, expected);
        sending.join().unwrap();
        bridge.stop();
        server.join().unwrap();
    }

    #[test]
    fn bridge_closes_when_lease_expires() {
        use tokio_tungstenite::accept_async;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async move {
                let listener = tokio::net::TcpListener::from_std(listener).unwrap();
                let (stream, _) = listener.accept().await.unwrap();
                let mut websocket = accept_async(stream).await.unwrap();
                websocket
                    .send(Message::Binary(vec![3; 32].into()))
                    .await
                    .unwrap();
                let Some(Ok(Message::Binary(_))) = websocket.next().await else {
                    panic!("missing proof")
                };
                websocket
                    .send(Message::Binary(vec![1].into()))
                    .await
                    .unwrap();
                let _ = tokio::time::timeout(Duration::from_secs(3), websocket.next()).await;
            });
        });
        let (_app, bridge_socket) = local_pair().unwrap();
        let bridge = join(
            format!("ws://{address}/api/v1/relay"),
            "fixture".to_owned(),
            Uuid::new_v4(),
            RelayRole::Controller,
            SigningKey::generate(&mut OsRng),
            LocalEndpoint::Existing(bridge_socket),
            Some(Arc::new(AtomicU64::new(now_seconds()))),
        );
        bridge.wait_ready(Duration::from_secs(5)).unwrap();
        thread::sleep(Duration::from_millis(700));
        assert!(bridge.is_finished());
        server.join().unwrap();
    }
}
