use std::collections::HashMap;
use std::fs::OpenOptions;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    Arc, Mutex, RwLock,
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use cyclar_protocol::{verify_grant, Capability, Uuid};
use cyclar_transfer::{TransferMessage, MAX_TRANSFER_FRAME_BYTES};

use crate::api::CentralApi;
use crate::identity::HostIdentity;
use crate::packet::Packet;
use crate::relay::{self, LocalEndpoint, RelayRole};
use crate::secure::accept_host;
use crate::transfers::{send_transfer, OfferState, PendingOffer, TransferHub};
use crate::x11::{self, Capture, Input};

pub struct HostOptions {
    pub server_url: String,
    pub listen: SocketAddr,
    pub advertise: Option<String>,
    pub state_path: PathBuf,
    pub name: String,
    pub view_only: bool,
    pub allow_files: bool,
    pub relay_only: bool,
}

struct SessionAccess {
    active: Arc<AtomicBool>,
    gate: Arc<RwLock<()>>,
}

type ActiveSessions = Arc<Mutex<HashMap<Uuid, SessionAccess>>>;
type SeenSessions = Arc<Mutex<HashMap<Uuid, u64>>>;
type InputOwner = Arc<Mutex<Option<Uuid>>>;

#[derive(Clone)]
struct HostShared {
    sessions: ActiveSessions,
    seen: SeenSessions,
    input_owner: InputOwner,
    shutdown: Arc<AtomicBool>,
    view_only: bool,
    allow_files: bool,
    transfers: Arc<TransferHub>,
}

struct SessionRuntime {
    active: Arc<AtomicBool>,
    shutdown: Arc<AtomicBool>,
    input_allowed: bool,
    file_allowed: bool,
    transfers: Arc<TransferHub>,
    gate: Arc<RwLock<()>>,
}

pub struct HostHandle {
    pub identity: HostIdentity,
    state_path: PathBuf,
    shutdown: Arc<AtomicBool>,
    active_sessions: ActiveSessions,
    transfers: Arc<TransferHub>,
    thread: Option<JoinHandle<()>>,
}

impl HostHandle {
    pub fn shutdown_flag(&self) -> Arc<AtomicBool> {
        self.shutdown.clone()
    }

    pub fn participants(&self) -> usize {
        self.active_sessions
            .lock()
            .map(|sessions| sessions.len())
            .unwrap_or(0)
    }

    pub fn session_ids(&self) -> Vec<Uuid> {
        self.active_sessions
            .lock()
            .map(|sessions| sessions.keys().copied().collect())
            .unwrap_or_default()
    }

    pub fn terminate_session(&self, session_id: Uuid) -> bool {
        if let Ok(sessions) = self.active_sessions.lock() {
            if let Some(access) = sessions.get(&session_id) {
                if let Ok(_guard) = access.gate.write() {
                    access.active.store(false, Ordering::Relaxed);
                }
                self.transfers.revoke_session(session_id);
                return true;
            }
        }
        false
    }

    pub fn pending_files(&self) -> Vec<PendingOffer> {
        self.transfers.list_pending()
    }

    pub fn approve_file(&self, transfer_id: Uuid, destination_dir: &Path) -> Result<()> {
        self.transfers.approve(transfer_id, destination_dir)
    }

    pub fn rotate_temporary_password(&mut self) -> Result<()> {
        OpenOptions::new()
            .write(true)
            .open("/dev/tty")
            .context("a local terminal is required before rotating a displayed secret")?;
        let api = CentralApi::new(&self.identity.server_url)?;
        let secret =
            api.rotate_temporary_password(self.identity.device_id, &self.identity.device_token)?;
        if secret.is_empty() {
            bail!("central returned an empty temporary password");
        }
        self.identity.temporary_password = secret;
        let saved = self.identity.persist(&self.state_path);
        let displayed = self.identity.show_secret_on_tty();
        if let Err(error) = saved {
            bail!("central rotated the password, but local identity persistence failed: {error}");
        }
        if displayed.is_err() {
            println!("Mot de passe renouvelé et sauvegardé ; affichez-le depuis un terminal local avec secret.");
        }
        Ok(())
    }

    pub fn set_permanent_password(&self, password: Option<&str>) -> Result<()> {
        if password.is_some_and(|secret| secret.len() < 16 || secret.len() > 256) {
            bail!("permanent password must be between 16 and 256 UTF-8 bytes");
        }
        CentralApi::new(&self.identity.server_url)?.set_permanent_password(
            self.identity.device_id,
            &self.identity.device_token,
            password,
        )
    }

    pub fn stop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Ok(sessions) = self.active_sessions.lock() {
            for (session_id, access) in sessions.iter() {
                if let Ok(_guard) = access.gate.write() {
                    access.active.store(false, Ordering::Relaxed);
                }
                self.transfers.revoke_session(*session_id);
            }
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for HostHandle {
    fn drop(&mut self) {
        self.stop();
    }
}

pub fn start(options: HostOptions) -> Result<HostHandle> {
    x11::check_available()?;
    if !options.view_only {
        Input::new()
            .context("input backend unavailable; use --view-only to receive without control")?;
    }
    let api = CentralApi::new(&options.server_url)?;
    let identity = HostIdentity::load_or_register(
        &options.state_path,
        &options.server_url,
        &options.name,
        &api,
    )?;
    if options.relay_only && options.advertise.is_some() {
        bail!("--relay-only cannot be combined with --advertise");
    }
    let listen = if options.relay_only {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), options.listen.port())
    } else {
        options.listen
    };
    let listener = TcpListener::bind(listen).context("cannot bind the session listener")?;
    listener.set_nonblocking(true)?;
    let bound_address = listener.local_addr()?;
    let relay_connect_address = if bound_address.ip().is_unspecified() {
        SocketAddr::new(
            if bound_address.is_ipv6() {
                IpAddr::V6(Ipv6Addr::LOCALHOST)
            } else {
                IpAddr::V4(Ipv4Addr::LOCALHOST)
            },
            bound_address.port(),
        )
    } else {
        bound_address
    };
    let advertise = options.advertise.unwrap_or_else(|| {
        if bound_address.ip().is_unspecified() {
            format!("127.0.0.1:{}", bound_address.port())
        } else {
            bound_address.to_string()
        }
    });
    if advertise.parse::<SocketAddr>().is_err() {
        bail!("--advertise must be a numeric IP address and TCP port");
    }
    api.heartbeat(
        identity.device_id,
        &identity.device_token,
        if options.relay_only {
            None
        } else {
            Some(&advertise)
        },
    )
    .context("central server did not accept the initial heartbeat")?;
    if options.relay_only {
        println!(
            "Cyclar hôte actif — ID {} — relais WSS uniquement ; port local {}.",
            identity.alias, relay_connect_address
        );
    } else {
        println!(
            "Cyclar hôte actif — ID {} — adresse {}",
            identity.alias, advertise
        );
    }
    if identity.show_secret_on_tty().is_err() {
        println!("Secret disponible uniquement sur un terminal local interactif.");
    }
    if !options.relay_only && (advertise.starts_with("127.") || advertise.starts_with("[::1]")) {
        println!("Adresse locale seulement. Utilisez --advertise <IP:port> pour un contrôleur distant joignable.");
    }
    if options.view_only {
        println!("Mode lecture seule : les entrées distantes sont refusées localement.");
    } else {
        println!("Contrôle X11 activé pour les sessions autorisées ; tapez quit pour arrêter localement.");
    }
    if options.allow_files {
        println!("Offres de fichiers activées : chaque fichier exige la commande locale approve.");
    }

    let active_sessions: ActiveSessions = Arc::new(Mutex::new(HashMap::new()));
    let seen_sessions: SeenSessions = Arc::new(Mutex::new(HashMap::new()));
    let input_owner: InputOwner = Arc::new(Mutex::new(None));
    let transfers = Arc::new(TransferHub::default());
    let shutdown = Arc::new(AtomicBool::new(false));
    let running = shutdown.clone();
    let identity_for_thread = identity.clone();
    let sessions_for_thread = active_sessions.clone();
    let shared = HostShared {
        sessions: active_sessions.clone(),
        seen: seen_sessions.clone(),
        input_owner: input_owner.clone(),
        shutdown: shutdown.clone(),
        view_only: options.view_only,
        allow_files: options.allow_files,
        transfers: transfers.clone(),
    };
    let thread = thread::spawn(move || {
        let pending_handshakes = Arc::new(AtomicUsize::new(0));
        let mut relay_attempts: HashMap<Uuid, Instant> = HashMap::new();
        let mut relay_bridges: Vec<relay::RelayBridge> = Vec::new();
        let mut last_heartbeat = Instant::now() - Duration::from_secs(10);
        while !running.load(Ordering::Relaxed) {
            if last_heartbeat.elapsed() >= Duration::from_secs(10) {
                match api.heartbeat(
                    identity_for_thread.device_id,
                    &identity_for_thread.device_token,
                    if options.relay_only {
                        None
                    } else {
                        Some(&advertise)
                    },
                ) {
                    Ok(()) => {}
                    Err(error) => eprintln!(
                        "Central indisponible : {error}; les baux non renouvelés expireront."
                    ),
                }
                if let Ok(ids) = api.active_sessions(
                    identity_for_thread.device_id,
                    &identity_for_thread.device_token,
                ) {
                    if let Ok(active) = sessions_for_thread.lock() {
                        for (session_id, access) in active.iter() {
                            if !ids.contains(session_id) {
                                if let Ok(_guard) = access.gate.write() {
                                    access.active.store(false, Ordering::Relaxed);
                                }
                                shared.transfers.revoke_session(*session_id);
                            }
                        }
                    }
                    relay_bridges.retain(|bridge| {
                        ids.contains(&bridge.session_id()) && !bridge.is_finished()
                    });
                    relay_attempts.retain(|id, started| {
                        ids.contains(id) && started.elapsed() < Duration::from_secs(60)
                    });
                    for session_id in ids {
                        if sessions_for_thread
                            .lock()
                            .is_ok_and(|sessions| sessions.contains_key(&session_id))
                            || relay_bridges.iter().any(|bridge| {
                                bridge.session_id() == session_id && !bridge.is_finished()
                            })
                            || relay_attempts
                                .get(&session_id)
                                .is_some_and(|started| started.elapsed() < Duration::from_secs(20))
                        {
                            continue;
                        }
                        let (url, key) = match (
                            api.relay_url(session_id, RelayRole::Host.path()),
                            identity_for_thread.signing_key(),
                        ) {
                            (Ok(url), Ok(key)) => (url, key),
                            _ => {
                                eprintln!("Relais hôte indisponible pour la session {session_id}.");
                                continue;
                            }
                        };
                        let bridge = relay::join(
                            url,
                            identity_for_thread.device_token.clone(),
                            session_id,
                            RelayRole::Host,
                            key,
                            LocalEndpoint::Connect(relay_connect_address),
                            None,
                        );
                        relay_attempts.insert(session_id, Instant::now());
                        relay_bridges.push(bridge);
                    }
                }
                last_heartbeat = Instant::now();
            }
            match listener.accept() {
                Ok((stream, remote)) => {
                    if pending_handshakes.load(Ordering::Relaxed) >= 8 {
                        drop(stream);
                        continue;
                    }
                    pending_handshakes.fetch_add(1, Ordering::Relaxed);
                    let pending = pending_handshakes.clone();
                    let identity = identity_for_thread.clone();
                    let shared = shared.clone();
                    thread::spawn(move || {
                        if let Err(error) = serve_peer(stream, remote, identity, shared) {
                            eprintln!("Connexion rejetée/interrompue : {error}");
                        }
                        pending.fetch_sub(1, Ordering::Relaxed);
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(50))
                }
                Err(error) => {
                    eprintln!("Échec du listener : {error}");
                    thread::sleep(Duration::from_secs(1));
                }
            }
        }
    });
    Ok(HostHandle {
        identity,
        state_path: options.state_path,
        shutdown,
        active_sessions,
        transfers,
        thread: Some(thread),
    })
}

fn serve_peer(
    stream: TcpStream,
    remote: SocketAddr,
    identity: HostIdentity,
    shared: HostShared,
) -> Result<()> {
    if shared
        .sessions
        .lock()
        .map_err(|_| anyhow!("session state unavailable"))?
        .len()
        >= 4
    {
        bail!("maximum of four concurrent controllers reached");
    }
    let signing_key = identity.signing_key()?;
    let peer = accept_host(
        stream,
        &signing_key,
        &identity.server_public_key,
        identity.device_id,
        identity.key_epoch,
    )?;
    let now = now_seconds();
    {
        let mut seen = shared
            .seen
            .lock()
            .map_err(|_| anyhow!("replay cache unavailable"))?;
        seen.retain(|_, expires_at| *expires_at > now);
        if seen.insert(peer.session_id, peer.expires_at).is_some() {
            bail!("session grant replay detected");
        }
    }
    let active = Arc::new(AtomicBool::new(true));
    let gate = Arc::new(RwLock::new(()));
    shared
        .sessions
        .lock()
        .map_err(|_| anyhow!("session state unavailable"))?
        .insert(
            peer.session_id,
            SessionAccess {
                active: active.clone(),
                gate: gate.clone(),
            },
        );
    let input_allowed = if peer.can_input && !shared.view_only {
        let mut owner = shared
            .input_owner
            .lock()
            .map_err(|_| anyhow!("input state unavailable"))?;
        if owner.is_none() {
            *owner = Some(peer.session_id);
            true
        } else {
            false
        }
    } else {
        false
    };
    let file_allowed = peer.can_file_transfer && shared.allow_files;
    println!(
        "Contrôleur connecté depuis {remote}; session {} ({} participants).",
        peer.session_id,
        shared.sessions.lock().map(|state| state.len()).unwrap_or(0)
    );
    let session_id = peer.session_id;
    let result = stream_session(
        peer,
        &identity,
        SessionRuntime {
            active: active.clone(),
            shutdown: shared.shutdown.clone(),
            input_allowed,
            file_allowed,
            transfers: shared.transfers.clone(),
            gate: gate.clone(),
        },
    );
    if let Ok(_guard) = gate.write() {
        active.store(false, Ordering::Relaxed);
    }
    shared.transfers.on_disconnect(session_id);
    if let Ok(mut state) = shared.sessions.lock() {
        state.remove(&session_id);
    }
    if let Ok(mut owner) = shared.input_owner.lock() {
        if *owner == Some(session_id) {
            *owner = None;
        }
    }
    println!("Contrôleur déconnecté; session {session_id}.");
    result
}

fn stream_session(
    peer: crate::secure::SecurePeer,
    identity: &HostIdentity,
    runtime: SessionRuntime,
) -> Result<()> {
    let SessionRuntime {
        active,
        shutdown,
        input_allowed,
        file_allowed,
        transfers,
        gate,
    } = runtime;
    let session_id = peer.session_id;
    let expires_at = Arc::new(AtomicU64::new(peer.expires_at));
    let writer = Arc::new(Mutex::new(peer.writer));
    writer
        .lock()
        .map_err(|_| anyhow!("session writer unavailable"))?
        .send(&Packet::Policy { input_allowed }.encode()?)?;
    let mut reader = peer.reader;
    let reader_active = active.clone();
    let reader_expiry = expires_at.clone();
    let reader_writer = writer.clone();
    let reader_transfers = transfers.clone();
    let reader_gate = gate.clone();
    let file_allowed = Arc::new(AtomicBool::new(file_allowed));
    let reader_file_allowed = file_allowed.clone();
    let server_public_key = identity.server_public_key.clone();
    let device_id = identity.device_id;
    let key_epoch = identity.key_epoch;
    let controller_public_key = peer.controller_public_key;
    thread::spawn(move || {
        let mut input = if input_allowed {
            Input::new().ok()
        } else {
            None
        };
        while reader_active.load(Ordering::Relaxed)
            && now_seconds() < reader_expiry.load(Ordering::Relaxed)
        {
            match reader
                .receive_bounded(MAX_TRANSFER_FRAME_BYTES + 1)
                .and_then(|message| Packet::decode(&message))
            {
                Ok(
                    packet @ (Packet::Motion { .. } | Packet::Button { .. } | Packet::Key { .. }),
                ) => {
                    if !reader_active.load(Ordering::Relaxed)
                        || now_seconds() >= reader_expiry.load(Ordering::Relaxed)
                    {
                        break;
                    }
                    if let Some(ref mut backend) = input {
                        if let Err(error) = backend.apply(packet) {
                            eprintln!("Entrée distante refusée : {error}");
                        }
                    }
                }
                Ok(Packet::Renewal { grant }) => {
                    if !reader_active.load(Ordering::Relaxed)
                        || now_seconds() >= reader_expiry.load(Ordering::Relaxed)
                    {
                        break;
                    }
                    let verified = decode_server_key(&server_public_key).and_then(|key| {
                        verify_grant(&grant, &key, device_id, key_epoch, now_seconds())
                            .map_err(|_| anyhow!("renewal grant rejected"))
                    });
                    match verified {
                        Ok(claims)
                            if claims.session_id == session_id
                                && claims.controller_public_key == controller_public_key
                                && claims.allows(Capability::View) =>
                        {
                            if !claims.allows(Capability::Input) {
                                input.take(); // Drop releases held keys and buttons immediately.
                            }
                            if !claims.allows(Capability::FileTransfer) {
                                if let Ok(_guard) = reader_gate.write() {
                                    reader_file_allowed.store(false, Ordering::Relaxed);
                                }
                                reader_transfers.revoke_session(session_id);
                            }
                            reader_expiry.fetch_max(claims.expires_at, Ordering::Relaxed);
                        }
                        _ => {
                            eprintln!("Renouvellement de session rejeté.");
                            break;
                        }
                    }
                }
                Ok(Packet::Transfer(message)) => {
                    if !reader_active.load(Ordering::Relaxed)
                        || now_seconds() >= reader_expiry.load(Ordering::Relaxed)
                    {
                        break;
                    }
                    if !reader_file_allowed.load(Ordering::Relaxed) {
                        eprintln!("Transfert refusé : capacité ou consentement local absent.");
                        break;
                    }
                    if let Err(error) = handle_file_message(
                        message,
                        FileSessionContext {
                            session_id,
                            controller_key: &controller_public_key,
                            writer: &reader_writer,
                            active: &reader_active,
                            expires_at: &reader_expiry,
                            file_allowed: &reader_file_allowed,
                            gate: &reader_gate,
                            transfers: &reader_transfers,
                        },
                    ) {
                        eprintln!("Transfert refusé : {error}");
                    }
                }
                Ok(Packet::Close) => break,
                Ok(_) => break,
                Err(_) => break,
            }
        }
        if let Some(ref mut backend) = input {
            backend.release_all();
        }
        reader_active.store(false, Ordering::Relaxed);
    });

    let capture = Capture::new()?;
    while active.load(Ordering::Relaxed)
        && !shutdown.load(Ordering::Relaxed)
        && now_seconds() < expires_at.load(Ordering::Relaxed)
    {
        let started = Instant::now();
        let packet = capture.frame()?;
        if now_seconds() >= expires_at.load(Ordering::Relaxed) {
            break;
        }
        writer
            .lock()
            .map_err(|_| anyhow!("session writer unavailable"))?
            .send(&packet.encode()?)?;
        let elapsed = started.elapsed();
        if elapsed < Duration::from_millis(200) {
            thread::sleep(Duration::from_millis(200) - elapsed);
        }
    }
    if let Ok(mut writer) = writer.lock() {
        let _ = writer.send(&Packet::Close.encode()?);
        writer.shutdown();
    }
    if now_seconds() >= expires_at.load(Ordering::Relaxed) {
        println!("Le bail de la session {session_id} a expiré.");
    }
    Ok(())
}

fn decode_server_key(encoded: &str) -> Result<ed25519_dalek::VerifyingKey> {
    cyclar_protocol::decode_public_key(encoded).map_err(|_| anyhow!("invalid server key"))
}

struct FileSessionContext<'a> {
    session_id: Uuid,
    controller_key: &'a str,
    writer: &'a Arc<Mutex<crate::secure::SecureWriter>>,
    active: &'a Arc<AtomicBool>,
    expires_at: &'a Arc<AtomicU64>,
    file_allowed: &'a Arc<AtomicBool>,
    gate: &'a Arc<RwLock<()>>,
    transfers: &'a TransferHub,
}

fn handle_file_message(message: TransferMessage, context: FileSessionContext<'_>) -> Result<()> {
    let FileSessionContext {
        session_id,
        controller_key,
        writer,
        active,
        expires_at,
        file_allowed,
        gate,
        transfers,
    } = context;
    let transfer_id = match &message {
        TransferMessage::Offer(offer) => offer.transfer_id,
        TransferMessage::Request(proof) => proof.transfer_id,
        TransferMessage::Chunk(chunk) => chunk.transfer_id,
        TransferMessage::Complete { transfer_id, .. } | TransferMessage::Abort { transfer_id } => {
            *transfer_id
        }
    };
    let result = (|| -> Result<()> {
        match message {
            TransferMessage::Offer(offer) => {
                let status = transfers.offer(
                    offer.clone(),
                    controller_key,
                    session_id,
                    writer.clone(),
                    active.clone(),
                )?;
                match status {
                OfferState::AwaitingApproval => println!(
                    "Fichier proposé : {} ({} octets), session {}. Tapez approve {} <dossier> pour l'accepter.",
                    offer.file_name, offer.size, session_id, offer.transfer_id
                ),
                OfferState::Resuming => println!("Reprise du transfert {}.", offer.transfer_id),
                OfferState::AlreadyCompleted => println!("Transfert {} déjà achevé ; accusé de réception renvoyé.", offer.transfer_id),
            }
                Ok(())
            }
            TransferMessage::Chunk(chunk) => transfers.write_chunk(session_id, &chunk),
            TransferMessage::Complete {
                transfer_id,
                digest,
            } => {
                let (path, ack_writer) =
                    transfers.finish(session_id, transfer_id, digest, || {
                        let guard = gate
                            .read()
                            .map_err(|_| cyclar_transfer::TransferError::AuthorizationRevoked)?;
                        if active.load(Ordering::Relaxed)
                            && file_allowed.load(Ordering::Relaxed)
                            && now_seconds() < expires_at.load(Ordering::Relaxed)
                        {
                            Ok(guard)
                        } else {
                            Err(cyclar_transfer::TransferError::AuthorizationRevoked)
                        }
                    })?;
                println!("Fichier reçu et vérifié : {}", path.display());
                send_transfer(
                    &ack_writer,
                    TransferMessage::Complete {
                        transfer_id,
                        digest,
                    },
                )
            }
            TransferMessage::Abort { transfer_id } => {
                transfers.abort(session_id, transfer_id);
                println!("Transfert {transfer_id} annulé par le contrôleur.");
                Ok(())
            }
            TransferMessage::Request(_) => bail!("file request in wrong direction"),
        }
    })();
    if result.is_err() {
        transfers.abort(session_id, transfer_id);
        let _ = send_transfer(writer, TransferMessage::Abort { transfer_id });
    }
    result
}

fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(u64::MAX)
}
