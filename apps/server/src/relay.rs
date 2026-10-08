//! Bounded, opaque WebSocket relay for the already encrypted Noise TCP stream.
//!
//! This module deliberately does not register a route. The application must
//! attach `websocket` and place an `Arc<RelayHub>` in `AppState` only when its
//! native clients implement the same challenge/READY protocol.

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        ConnectInfo, Path, State,
    },
    http::{header, HeaderMap, StatusCode},
    response::Response,
};
use cyclar_protocol::{decode_public_key, Uuid, VerifyingKey};
use ed25519_dalek::Signature;
use futures_util::{
    stream::{SplitSink, SplitStream},
    SinkExt, StreamExt,
};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::sync::{oneshot, watch, OwnedSemaphorePermit, Semaphore};

use crate::{state::now, AppState};

/// One binary WebSocket message is an arbitrary ordered slice of the Noise
/// byte stream. No media packet, key, or application message is decoded here.
pub const MAX_FRAME_BYTES: usize = 64 * 1024;
pub const DEFAULT_MAX_SESSIONS: usize = 256;
const MAX_BYTES_PER_SECOND: u64 = 64 * 1024 * 1024;
const AUTH_TIMEOUT: Duration = Duration::from_secs(5);
const PAIR_TIMEOUT: Duration = Duration::from_secs(15);
const SEND_TIMEOUT: Duration = Duration::from_secs(5);
const RECHECK_INTERVAL: Duration = Duration::from_secs(5);
const TRANSCRIPT_DOMAIN: &[u8] = b"CYCLAR-RELAY-JOIN-V1\0";
const READY: [u8; 1] = [1];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum JoinRole {
    Host,
    Controller,
}

impl JoinRole {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "host" => Some(Self::Host),
            "controller" => Some(Self::Controller),
            _ => None,
        }
    }

    const fn byte(self) -> u8 {
        match self {
            Self::Host => 1,
            Self::Controller => 2,
        }
    }
}

#[derive(Clone)]
struct Admission {
    session_id: Uuid,
    role: JoinRole,
    verifying_key: VerifyingKey,
    token_hash: [u8; 32],
    host_device_id: Uuid,
    host_key_epoch: u64,
}

struct Paired {
    socket: WebSocket,
    admission: Admission,
    cancelled: watch::Receiver<bool>,
}

enum Slot {
    Waiting {
        ticket: Uuid,
        role: JoinRole,
        sender: oneshot::Sender<Paired>,
    },
    Active {
        ticket: Uuid,
        cancel: watch::Sender<bool>,
    },
}

enum Join {
    Waiting {
        ticket: Uuid,
        receiver: oneshot::Receiver<Paired>,
    },
    Matched {
        ticket: Uuid,
        sender: oneshot::Sender<Paired>,
        cancelled: watch::Receiver<bool>,
    },
}

/// One slot per session (waiting or paired). There is also a separate global
/// cap on concurrent challenge handshakes, so stalled upgrades are bounded.
pub struct RelayHub {
    slots: Mutex<HashMap<Uuid, Slot>>,
    handshakes: Arc<Semaphore>,
    max_sessions: usize,
}

impl Default for RelayHub {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_SESSIONS)
    }
}

impl RelayHub {
    pub fn new(max_sessions: usize) -> Self {
        assert!(max_sessions > 0, "relay session limit must be positive");
        Self {
            slots: Mutex::new(HashMap::new()),
            handshakes: Arc::new(Semaphore::new(max_sessions.saturating_mul(2))),
            max_sessions,
        }
    }

    pub fn session_count(&self) -> usize {
        self.slots
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .len()
    }

    /// Called by session/device revocation handlers for immediate shutdown.
    /// The five-second state check remains a fail-safe when this hook is not
    /// called or when a revocation races the transport task.
    pub fn cancel(&self, session_id: Uuid) {
        let slot = self
            .slots
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .remove(&session_id);
        if let Some(Slot::Active { cancel, .. }) = slot {
            let _ = cancel.send(true);
        }
    }

    fn join(&self, session_id: Uuid, role: JoinRole) -> Result<Join, ()> {
        let mut slots = self.slots.lock().unwrap_or_else(|error| error.into_inner());
        match slots.remove(&session_id) {
            None if slots.len() < self.max_sessions => {
                let (sender, receiver) = oneshot::channel();
                let ticket = Uuid::new_v4();
                slots.insert(
                    session_id,
                    Slot::Waiting {
                        ticket,
                        role,
                        sender,
                    },
                );
                Ok(Join::Waiting { ticket, receiver })
            }
            Some(Slot::Waiting {
                ticket,
                role: waiting_role,
                sender,
            }) if role != waiting_role => {
                let (cancel, cancelled) = watch::channel(false);
                slots.insert(session_id, Slot::Active { ticket, cancel });
                Ok(Join::Matched {
                    ticket,
                    sender,
                    cancelled,
                })
            }
            Some(slot) => {
                slots.insert(session_id, slot);
                Err(())
            }
            None => Err(()),
        }
    }

    fn remove_if_ticket(&self, session_id: Uuid, ticket: Uuid) {
        let mut slots = self.slots.lock().unwrap_or_else(|error| error.into_inner());
        if slots.get(&session_id).is_some_and(|slot| match slot {
            Slot::Waiting {
                ticket: current, ..
            }
            | Slot::Active {
                ticket: current, ..
            } => *current == ticket,
        }) {
            slots.remove(&session_id);
        }
    }
}

/// GET `/api/v1/relay/{session_id}/{role}`. Mount this only after the native
/// client has a WSS bridge and the operator has configured a trusted TLS proxy
/// for non-loopback access. Bearer tokens are accepted only in HTTP headers.
pub async fn websocket(
    State(state): State<Arc<AppState>>,
    Path((session_id, role)): Path<(Uuid, String)>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Result<Response, StatusCode> {
    if !state.behind_tls_proxy && !remote.ip().is_loopback() {
        return Err(StatusCode::UPGRADE_REQUIRED);
    }
    let role = JoinRole::parse(&role).ok_or(StatusCode::NOT_FOUND)?;
    let bearer = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .filter(|value| !value.is_empty() && value.len() <= 128)
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let admission = admission(&state, session_id, role, bearer).ok_or(StatusCode::UNAUTHORIZED)?;
    let handshake_permit = state
        .relay_hub
        .handshakes
        .clone()
        .try_acquire_owned()
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    Ok(ws
        .max_frame_size(MAX_FRAME_BYTES)
        .max_message_size(MAX_FRAME_BYTES)
        .write_buffer_size(MAX_FRAME_BYTES)
        .max_write_buffer_size(MAX_FRAME_BYTES * 3)
        .on_upgrade(move |socket| async move {
            handle_upgrade(state, admission, socket, handshake_permit).await;
        }))
}

fn token_hash(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

fn hash_matches(stored_hex: &str, supplied: &[u8; 32]) -> bool {
    let Ok(stored) = hex::decode(stored_hex) else {
        return false;
    };
    stored.len() == 32 && bool::from(stored.as_slice().ct_eq(supplied.as_slice()))
}

fn admission(state: &AppState, session_id: Uuid, role: JoinRole, token: &str) -> Option<Admission> {
    let supplied = token_hash(token);
    let (key, host_device_id, host_key_epoch) = state.store.read(|db| {
        let session = db.sessions.get(&session_id)?;
        let device = db.devices.get(&session.host_device_id)?;
        let fresh = device
            .last_seen
            .is_some_and(|last| now().saturating_sub(last) < 45);
        if session.closed_at.is_some()
            || session.expires_at <= now()
            || device.revoked
            || !fresh
            || device.key_epoch != session.host_key_epoch
        {
            return None;
        }
        let (digest, key) = match role {
            JoinRole::Host => (&device.device_token_digest, &device.public_key),
            JoinRole::Controller => (
                &session.renewal_token_digest,
                &session.controller_public_key,
            ),
        };
        if !hash_matches(digest, &supplied) {
            return None;
        }
        Some((key.clone(), device.id, device.key_epoch))
    })?;
    Some(Admission {
        session_id,
        role,
        verifying_key: decode_public_key(&key).ok()?,
        token_hash: supplied,
        host_device_id,
        host_key_epoch,
    })
}

fn still_authorized(state: &AppState, participant: &Admission) -> bool {
    state.store.read(|db| {
        let Some(session) = db.sessions.get(&participant.session_id) else {
            return false;
        };
        let Some(device) = db.devices.get(&session.host_device_id) else {
            return false;
        };
        let fresh = device
            .last_seen
            .is_some_and(|last| now().saturating_sub(last) < 45);
        if session.closed_at.is_some()
            || session.expires_at <= now()
            || device.revoked
            || !fresh
            || device.id != participant.host_device_id
            || device.key_epoch != participant.host_key_epoch
            || session.host_key_epoch != participant.host_key_epoch
        {
            return false;
        }
        let (digest, key) = match participant.role {
            JoinRole::Host => (&device.device_token_digest, &device.public_key),
            JoinRole::Controller => (
                &session.renewal_token_digest,
                &session.controller_public_key,
            ),
        };
        hash_matches(digest, &participant.token_hash)
            && decode_public_key(key).is_ok_and(|current| current == participant.verifying_key)
    })
}

fn transcript(session_id: Uuid, role: JoinRole, nonce: &[u8; 32]) -> Vec<u8> {
    let mut message = Vec::with_capacity(TRANSCRIPT_DOMAIN.len() + 16 + 1 + 32);
    message.extend_from_slice(TRANSCRIPT_DOMAIN);
    message.extend_from_slice(session_id.as_bytes());
    message.push(role.byte());
    message.extend_from_slice(nonce);
    message
}

async fn handle_upgrade(
    state: Arc<AppState>,
    participant: Admission,
    mut socket: WebSocket,
    _handshake_permit: OwnedSemaphorePermit,
) {
    let mut nonce = [0u8; 32];
    OsRng.fill_bytes(&mut nonce);
    let proof = async {
        socket.send(Message::binary(nonce.to_vec())).await.ok()?;
        match socket.recv().await? {
            Ok(Message::Binary(bytes)) if bytes.len() == 64 => {
                let signature = Signature::from_slice(&bytes).ok()?;
                participant
                    .verifying_key
                    .verify_strict(
                        &transcript(participant.session_id, participant.role, &nonce),
                        &signature,
                    )
                    .ok()?;
                Some(())
            }
            _ => None,
        }
    };
    if !matches!(
        tokio::time::timeout(AUTH_TIMEOUT, proof).await,
        Ok(Some(()))
    ) || !still_authorized(&state, &participant)
    {
        let _ = socket.close().await;
        return;
    }
    drop(_handshake_permit);
    let session_id = participant.session_id;
    match state.relay_hub.join(session_id, participant.role) {
        Ok(Join::Waiting { ticket, receiver }) => {
            match tokio::time::timeout(PAIR_TIMEOUT, receiver).await {
                Ok(Ok(other)) => {
                    bridge(state.clone(), socket, participant, other).await;
                }
                _ => {
                    let _ = socket.close().await;
                }
            }
            state.relay_hub.remove_if_ticket(session_id, ticket);
        }
        Ok(Join::Matched {
            ticket,
            sender,
            cancelled,
        }) => {
            let pair = Paired {
                socket,
                admission: participant,
                cancelled,
            };
            if sender.send(pair).is_err() {
                state.relay_hub.remove_if_ticket(session_id, ticket);
            }
        }
        Err(()) => {
            let _ = socket.close().await;
        }
    }
}

async fn bridge(state: Arc<AppState>, first: WebSocket, first_auth: Admission, second: Paired) {
    let (mut host, host_auth, mut controller, controller_auth) = match first_auth.role {
        JoinRole::Host => (first, first_auth, second.socket, second.admission),
        JoinRole::Controller => (second.socket, second.admission, first, first_auth),
    };
    if host_auth.role != JoinRole::Host
        || controller_auth.role != JoinRole::Controller
        || !still_authorized(&state, &host_auth)
        || !still_authorized(&state, &controller_auth)
    {
        let _ = host.close().await;
        let _ = controller.close().await;
        return;
    }
    if host.send(Message::binary(READY.to_vec())).await.is_err()
        || controller
            .send(Message::binary(READY.to_vec()))
            .await
            .is_err()
    {
        return;
    }
    let (host_sink, host_stream) = host.split();
    let (controller_sink, controller_stream) = controller.split();
    // Each pump holds at most one 64 KiB frame while its destination is
    // backpressured. There is no unbounded application queue or media buffer.
    let host_to_controller = pump(host_stream, controller_sink);
    let controller_to_host = pump(controller_stream, host_sink);
    tokio::pin!(host_to_controller, controller_to_host);
    let mut cancelled = second.cancelled;
    let monitor = async {
        loop {
            if !still_authorized(&state, &host_auth) || !still_authorized(&state, &controller_auth)
            {
                return;
            }
            // Wake at the lease boundary if it is sooner than the normal
            // five-second inspection. A renewal is observed at that wake-up.
            let delay = state.store.read(|db| {
                db.sessions
                    .get(&host_auth.session_id)
                    .map(|session| {
                        session
                            .expires_at
                            .saturating_sub(now())
                            .clamp(1, RECHECK_INTERVAL.as_secs())
                    })
                    .unwrap_or(1)
            });
            tokio::time::sleep(Duration::from_secs(delay)).await;
        }
    };
    tokio::select! {
        _ = &mut host_to_controller => {},
        _ = &mut controller_to_host => {},
        _ = cancelled.changed() => {},
        _ = monitor => {},
    }
}

type WsSink = SplitSink<WebSocket, Message>;
type WsStream = SplitStream<WebSocket>;

struct RateBudget {
    started: Instant,
    used: u64,
}

impl RateBudget {
    fn new() -> Self {
        Self {
            started: Instant::now(),
            used: 0,
        }
    }

    fn accept(&mut self, bytes: usize, at: Instant) -> bool {
        if at.duration_since(self.started) >= Duration::from_secs(1) {
            self.started = at;
            self.used = 0;
        }
        self.used = self.used.saturating_add(bytes as u64);
        self.used <= MAX_BYTES_PER_SECOND
    }
}

async fn pump(mut source: WsStream, mut destination: WsSink) -> Result<(), ()> {
    let mut budget = RateBudget::new();
    while let Some(message) = source.next().await {
        match message.map_err(|_| ())? {
            Message::Binary(bytes) if !bytes.is_empty() && bytes.len() <= MAX_FRAME_BYTES => {
                if !budget.accept(bytes.len(), Instant::now()) {
                    return Err(());
                }
                tokio::time::timeout(SEND_TIMEOUT, destination.send(Message::Binary(bytes)))
                    .await
                    .map_err(|_| ())?
                    .map_err(|_| ())?;
            }
            Message::Ping(_) | Message::Pong(_) => {}
            Message::Close(_) => return Ok(()),
            _ => return Err(()),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::BTreeMap, sync::atomic::AtomicU64};

    use axum::{http::HeaderValue, routing::get, Router};
    use ed25519_dalek::{Signer, SigningKey};
    use tokio::net::TcpListener;
    use tokio_tungstenite::{
        connect_async,
        tungstenite::{client::IntoClientRequest, Message as ClientMessage},
        MaybeTlsStream, WebSocketStream,
    };

    use crate::state::{token_digest, Device, RemoteSession, Store};
    use cyclar_desktop::{relay as desktop_relay, secure as desktop_secure};
    use cyclar_protocol::{encode_public_key, sign_grant, Capability, GrantClaims};

    type ClientSocket = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

    fn fixture() -> (
        tempfile::TempDir,
        Arc<AppState>,
        SigningKey,
        SigningKey,
        Uuid,
    ) {
        let directory = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(&directory.path().join("relay-test.redb")).unwrap());
        let host_key = SigningKey::from_bytes(&[21; 32]);
        let controller_key = SigningKey::from_bytes(&[22; 32]);
        let host_id = Uuid::new_v4();
        let session_id = Uuid::new_v4();
        store
            .update(|db| {
                db.devices.insert(
                    host_id,
                    Device {
                        id: host_id,
                        alias: 123_456_789,
                        name: "Test host".into(),
                        platform: "linux".into(),
                        public_key: cyclar_protocol::encode_public_key(&host_key.verifying_key()),
                        device_token_digest: token_digest("test-host-token"),
                        temporary_password_hash: String::new(),
                        permanent_password_hash: None,
                        created_at: now(),
                        last_seen: Some(now()),
                        listen_address: None,
                        agent_version: Some("test".into()),
                        revoked: false,
                        key_epoch: 0,
                        secret_epoch: 0,
                    },
                );
                db.sessions.insert(
                    session_id,
                    RemoteSession {
                        id: session_id,
                        host_device_id: host_id,
                        host_key_epoch: 0,
                        controller_public_key: cyclar_protocol::encode_public_key(
                            &controller_key.verifying_key(),
                        ),
                        capabilities: vec![cyclar_protocol::Capability::View],
                        created_at: now(),
                        expires_at: now() + 60,
                        renewal_token_digest: token_digest("test-controller-token"),
                        closed_at: None,
                    },
                );
                Ok(())
            })
            .unwrap();
        let state = Arc::new(AppState {
            store,
            signing_key: SigningKey::from_bytes(&[23; 32]),
            secure_cookies: false,
            behind_tls_proxy: false,
            attempts: Mutex::new(BTreeMap::new()),
            last_presence_checkpoint: AtomicU64::new(0),
            password_slots: Arc::new(Semaphore::new(4)),
            relay_hub: Arc::new(RelayHub::new(2)),
        });
        (directory, state, host_key, controller_key, session_id)
    }

    async fn test_server(state: Arc<AppState>) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        // The route is mounted only in this test router, never in production.
        let router = Router::new()
            .route("/api/v1/relay/{session_id}/{role}", get(websocket))
            .with_state(state);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            axum::serve(
                listener,
                router.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .unwrap();
        });
        (address, task)
    }

    fn client_request(
        address: SocketAddr,
        id: Uuid,
        role: &str,
        token: &str,
    ) -> axum::http::Request<()> {
        let mut request = format!("ws://{address}/api/v1/relay/{id}/{role}")
            .into_client_request()
            .unwrap();
        request.headers_mut().insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        );
        request
    }

    async fn connect_and_prove(
        address: SocketAddr,
        id: Uuid,
        role: JoinRole,
        token: &str,
        key: &SigningKey,
    ) -> ClientSocket {
        let role_name = match role {
            JoinRole::Host => "host",
            JoinRole::Controller => "controller",
        };
        let (mut socket, _) = connect_async(client_request(address, id, role_name, token))
            .await
            .unwrap();
        let challenge = tokio::time::timeout(Duration::from_secs(3), socket.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let ClientMessage::Binary(bytes) = challenge else {
            panic!("expected relay nonce")
        };
        let nonce: [u8; 32] = bytes.as_ref().try_into().unwrap();
        let signature = key.sign(&transcript(id, role, &nonce));
        socket
            .send(ClientMessage::Binary(signature.to_bytes().to_vec().into()))
            .await
            .unwrap();
        socket
    }

    async fn receive_binary(socket: &mut ClientSocket) -> Vec<u8> {
        let message = tokio::time::timeout(Duration::from_secs(3), socket.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        match message {
            ClientMessage::Binary(bytes) => bytes.to_vec(),
            _ => panic!("expected binary relay frame"),
        }
    }

    #[test]
    fn challenge_binds_role_session_and_nonce() {
        let key = SigningKey::from_bytes(&[17; 32]);
        let session = Uuid::from_u128(1);
        let nonce = [5; 32];
        let signature = key.sign(&transcript(session, JoinRole::Host, &nonce));
        let verifier = key.verifying_key();
        assert!(verifier
            .verify_strict(&transcript(session, JoinRole::Host, &nonce), &signature)
            .is_ok());
        assert!(verifier
            .verify_strict(
                &transcript(session, JoinRole::Controller, &nonce),
                &signature
            )
            .is_err());
        assert!(verifier
            .verify_strict(
                &transcript(Uuid::from_u128(2), JoinRole::Host, &nonce),
                &signature
            )
            .is_err());
        assert!(verifier
            .verify_strict(&transcript(session, JoinRole::Host, &[6; 32]), &signature)
            .is_err());
    }

    #[test]
    fn bearer_digest_is_constant_time_compared() {
        let digest = token_hash("development-only-token");
        assert!(hash_matches(&hex::encode(digest), &digest));
        assert!(!hash_matches(&hex::encode([0u8; 32]), &digest));
        assert!(!hash_matches("broken", &digest));
    }

    #[test]
    fn hub_enforces_one_pair_and_session_quota() {
        let hub = RelayHub::new(1);
        let id = Uuid::from_u128(1);
        let waiting = hub.join(id, JoinRole::Host).unwrap();
        assert_eq!(hub.session_count(), 1);
        assert!(hub.join(Uuid::from_u128(2), JoinRole::Host).is_err());
        assert!(hub.join(id, JoinRole::Host).is_err());
        let matching = hub.join(id, JoinRole::Controller).unwrap();
        assert_eq!(hub.session_count(), 1);
        assert!(hub.join(id, JoinRole::Controller).is_err());
        let ticket = match matching {
            Join::Matched { ticket, .. } => ticket,
            _ => panic!("expected matched relay slot"),
        };
        // The waiting end has no socket in this unit test, and dropping its
        // receiver simulates a disconnected client.
        drop(waiting);
        hub.remove_if_ticket(id, ticket);
        assert_eq!(hub.session_count(), 0);
    }

    #[test]
    fn relay_bandwidth_budget_is_bounded_and_recovers() {
        let mut budget = RateBudget::new();
        let started = budget.started;
        assert!(budget.accept(MAX_BYTES_PER_SECOND as usize, started));
        assert!(!budget.accept(1, started));
        assert!(budget.accept(1, started + Duration::from_secs(1)));
    }

    #[test]
    fn authorization_recheck_rejects_expiry_revocation_and_key_epoch_change() {
        let (_directory, state, _host_key, _controller_key, session_id) = fixture();
        let host = admission(&state, session_id, JoinRole::Host, "test-host-token").unwrap();
        let controller = admission(
            &state,
            session_id,
            JoinRole::Controller,
            "test-controller-token",
        )
        .unwrap();
        assert!(still_authorized(&state, &host));
        assert!(still_authorized(&state, &controller));

        state
            .store
            .update_volatile(|db| {
                db.sessions.get_mut(&session_id).unwrap().expires_at = now().saturating_sub(1);
                Ok(())
            })
            .unwrap();
        assert!(!still_authorized(&state, &host));
        assert!(!still_authorized(&state, &controller));

        state
            .store
            .update_volatile(|db| {
                let session = db.sessions.get_mut(&session_id).unwrap();
                session.expires_at = now() + 60;
                db.devices.get_mut(&session.host_device_id).unwrap().revoked = true;
                Ok(())
            })
            .unwrap();
        assert!(!still_authorized(&state, &host));
        assert!(!still_authorized(&state, &controller));

        state
            .store
            .update_volatile(|db| {
                let session = db.sessions.get(&session_id).unwrap();
                let device = db.devices.get_mut(&session.host_device_id).unwrap();
                device.revoked = false;
                device.key_epoch += 1;
                Ok(())
            })
            .unwrap();
        assert!(!still_authorized(&state, &host));
        assert!(!still_authorized(&state, &controller));
    }

    #[tokio::test]
    async fn loopback_pair_forwards_opaque_bytes_and_cancel_closes_both() {
        let (_directory, state, host_key, controller_key, session_id) = fixture();
        let (address, server) = test_server(state.clone()).await;
        let mut host = connect_and_prove(
            address,
            session_id,
            JoinRole::Host,
            "test-host-token",
            &host_key,
        )
        .await;
        let mut controller = connect_and_prove(
            address,
            session_id,
            JoinRole::Controller,
            "test-controller-token",
            &controller_key,
        )
        .await;
        assert_eq!(receive_binary(&mut host).await, READY);
        assert_eq!(receive_binary(&mut controller).await, READY);
        assert_eq!(state.relay_hub.session_count(), 1);

        let payload = vec![0, 255, 0, 1, 42, 17];
        controller
            .send(ClientMessage::Binary(payload.clone().into()))
            .await
            .unwrap();
        assert_eq!(receive_binary(&mut host).await, payload);
        let reply = vec![0x80, 0, 0xff];
        host.send(ClientMessage::Binary(reply.clone().into()))
            .await
            .unwrap();
        assert_eq!(receive_binary(&mut controller).await, reply);

        state.relay_hub.cancel(session_id);
        assert_eq!(state.relay_hub.session_count(), 0);
        assert!(tokio::time::timeout(Duration::from_secs(3), host.next())
            .await
            .is_ok());
        assert!(
            tokio::time::timeout(Duration::from_secs(3), controller.next())
                .await
                .is_ok()
        );
        server.abort();
    }

    #[tokio::test]
    async fn loopback_rejects_wrong_role_token_and_signature() {
        let (_directory, state, _host_key, _controller_key, session_id) = fixture();
        let (address, server) = test_server(state.clone()).await;
        assert!(connect_async(client_request(
            address,
            session_id,
            "viewer",
            "test-host-token"
        ))
        .await
        .is_err());
        assert!(connect_async(client_request(
            address,
            session_id,
            "controller",
            "wrong-token"
        ))
        .await
        .is_err());
        let rogue_key = SigningKey::from_bytes(&[99; 32]);
        let mut rogue = connect_and_prove(
            address,
            session_id,
            JoinRole::Host,
            "test-host-token",
            &rogue_key,
        )
        .await;
        let message = tokio::time::timeout(Duration::from_secs(3), rogue.next())
            .await
            .unwrap();
        assert!(
            !matches!(message, Some(Ok(ClientMessage::Binary(bytes))) if bytes.as_ref() == READY)
        );
        assert_eq!(state.relay_hub.session_count(), 0);
        server.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn desktop_noise_stream_survives_real_wss_relay() {
        let (_directory, state, host_key, controller_key, session_id) = fixture();
        let (address, server) = test_server(state.clone()).await;
        let (host_id, expires_at) = state.store.read(|db| {
            let session = db.sessions.get(&session_id).unwrap();
            (session.host_device_id, session.expires_at)
        });
        let issued_at = now().saturating_sub(1);
        let claims = GrantClaims {
            session_id,
            host_device_id: host_id,
            controller_public_key: encode_public_key(&controller_key.verifying_key()),
            capabilities: vec![Capability::View],
            issued_at,
            expires_at,
            nonce: Uuid::new_v4(),
            host_key_epoch: 0,
        };
        let grant = sign_grant(&claims, &state.signing_key).unwrap();
        let server_public = encode_public_key(&state.signing_key.verifying_key());
        let host_public = encode_public_key(&host_key.verifying_key());
        let (host_app, host_bridge_socket) = desktop_relay::local_pair().unwrap();
        let (controller_app, controller_bridge_socket) = desktop_relay::local_pair().unwrap();
        let host_bridge = desktop_relay::join(
            format!("ws://{address}/api/v1/relay/{session_id}/host"),
            "test-host-token".into(),
            session_id,
            desktop_relay::RelayRole::Host,
            host_key.clone(),
            desktop_relay::LocalEndpoint::Existing(host_bridge_socket),
            None,
        );
        let controller_bridge = desktop_relay::join(
            format!("ws://{address}/api/v1/relay/{session_id}/controller"),
            "test-controller-token".into(),
            session_id,
            desktop_relay::RelayRole::Controller,
            controller_key.clone(),
            desktop_relay::LocalEndpoint::Existing(controller_bridge_socket),
            None,
        );
        host_bridge.wait_ready(Duration::from_secs(15)).unwrap();
        controller_bridge
            .wait_ready(Duration::from_secs(15))
            .unwrap();

        let host_job = std::thread::spawn(move || -> anyhow::Result<()> {
            let mut peer =
                desktop_secure::accept_host(host_app, &host_key, &server_public, host_id, 0)?;
            let message = peer.reader.receive()?;
            anyhow::ensure!(
                message == b"through-relay",
                "host received unexpected plaintext"
            );
            peer.writer.send(b"noise-reply")?;
            Ok(())
        });
        let controller_job = std::thread::spawn(move || -> anyhow::Result<()> {
            let mut peer = desktop_secure::connect_controller(
                controller_app,
                &grant,
                session_id,
                &host_public,
                &controller_key,
                expires_at,
            )?;
            peer.writer.send(b"through-relay")?;
            let message = peer.reader.receive()?;
            anyhow::ensure!(
                message == b"noise-reply",
                "controller received unexpected plaintext"
            );
            Ok(())
        });
        let exchange = tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
            host_job.join().expect("host thread panicked")?;
            controller_job.join().expect("controller thread panicked")?;
            Ok(())
        });
        let result = tokio::time::timeout(Duration::from_secs(15), exchange).await;
        if result.is_err() {
            host_bridge.stop();
            controller_bridge.stop();
            state.relay_hub.cancel(session_id);
            panic!("Noise exchange stalled over the WSS relay");
        }
        result.unwrap().unwrap().unwrap();
        state.relay_hub.cancel(session_id);
        for _ in 0..30 {
            if host_bridge.is_finished() && controller_bridge.is_finished() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(host_bridge.is_finished() && controller_bridge.is_finished());
        server.abort();
    }
}
