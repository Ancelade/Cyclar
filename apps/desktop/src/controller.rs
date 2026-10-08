use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc, Mutex, OnceLock,
};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use cyclar_protocol::{Capability, SessionRequest, SessionResponse};
use ed25519_dalek::SigningKey;
use rand_core::OsRng;

use crate::api::CentralApi;
use crate::packet::Packet;
use crate::relay::{self, LocalEndpoint, RelayRole};
use crate::secure::{connect_controller, SecurePeer};
use crate::x11::{self, OutgoingFile};

static CONTROLLER_KEY: OnceLock<SigningKey> = OnceLock::new();

pub fn connect(
    api: &CentralApi,
    alias: u64,
    password: String,
    view_only: bool,
    send_file: Option<PathBuf>,
) -> Result<()> {
    x11::check_available().context("viewer unavailable")?;
    let outgoing = send_file
        .map(|path| x11::prepare_outgoing(alias, path))
        .transpose()?;
    let signing_key = CONTROLLER_KEY.get_or_init(|| SigningKey::generate(&mut OsRng));
    let mut capabilities = if view_only {
        vec![Capability::View]
    } else {
        vec![Capability::View, Capability::Input]
    };
    if outgoing.is_some() {
        capabilities.push(Capability::FileTransfer);
    }
    let request = SessionRequest {
        alias,
        password,
        controller_public_key: URL_SAFE_NO_PAD.encode(signing_key.verifying_key().to_bytes()),
        capabilities,
    };
    let response = api.request_session(&request)?;
    let session_id = response.session_id;
    let close_token = response.renewal_token.clone();
    let result = run_authorized(api, response, signing_key, outgoing);
    if let Err(error) = api.close_session(session_id, &close_token) {
        eprintln!("Clôture centrale différée : {error}");
    }
    result
}

fn try_direct(response: &SessionResponse, signing_key: &SigningKey) -> Result<SecurePeer> {
    let address = response
        .host_address
        .as_deref()
        .ok_or_else(|| anyhow!("aucune adresse directe publiée"))?;
    let address: SocketAddr = address
        .parse()
        .context("adresse directe de l'hôte invalide")?;
    let stream = TcpStream::connect_timeout(&address, Duration::from_secs(6))
        .with_context(|| format!("hôte injoignable à {address}"))?;
    connect_controller(
        stream,
        &response.grant,
        response.session_id,
        &response.host_public_key,
        signing_key,
        response.expires_at,
    )
    .context("poignée directe refusée")
}

fn run_authorized(
    api: &CentralApi,
    response: SessionResponse,
    signing_key: &SigningKey,
    outgoing: Option<OutgoingFile>,
) -> Result<()> {
    let (peer, relay_bridge) = match try_direct(&response, signing_key) {
        Ok(peer) => (peer, None),
        Err(error) => {
            eprintln!("Chemin direct indisponible : {error}. Essai du relais WSS.");
            let (local_app, local_bridge) = relay::local_pair()?;
            let bridge = relay::join(
                api.relay_url(response.session_id, RelayRole::Controller.path())?,
                response.renewal_token.clone(),
                response.session_id,
                RelayRole::Controller,
                (*signing_key).clone(),
                LocalEndpoint::Existing(local_bridge),
                None,
            );
            bridge.wait_ready(Duration::from_secs(25))?;
            let fresh = api.renew_session(response.session_id, &response.renewal_token)?;
            let peer = connect_controller(
                local_app,
                &fresh.grant,
                response.session_id,
                &response.host_public_key,
                signing_key,
                fresh.expires_at,
            )
            .context("poignée Noise via relais refusée")?;
            (peer, Some(bridge))
        }
    };

    let writer = Arc::new(Mutex::new(peer.writer));
    let expires_at = Arc::new(AtomicU64::new(peer.expires_at));
    let active = Arc::new(AtomicBool::new(true));
    let renew_api = api.clone();
    let renew_writer = writer.clone();
    let renew_expiry = expires_at.clone();
    let renew_active = active.clone();
    let session_id = response.session_id;
    let renewal_token = response.renewal_token;
    let renewal = thread::spawn(move || {
        while renew_active.load(Ordering::Relaxed) {
            let remaining = renew_expiry
                .load(Ordering::Relaxed)
                .saturating_sub(now_seconds());
            if remaining == 0 {
                break;
            }
            if remaining > 10 {
                thread::sleep(Duration::from_secs((remaining - 10).min(3)));
                continue;
            }
            match renew_api.renew_session(session_id, &renewal_token) {
                Ok(renewed) => {
                    let packet = Packet::Renewal {
                        grant: renewed.grant,
                    };
                    let bytes = match packet.encode() {
                        Ok(bytes) => bytes,
                        Err(_) => break,
                    };
                    let sent = renew_writer
                        .lock()
                        .map_err(|_| anyhow!("writer poisoned"))
                        .and_then(|mut writer| writer.send(&bytes));
                    if sent.is_err() {
                        break;
                    }
                    renew_expiry.fetch_max(renewed.expires_at, Ordering::Relaxed);
                }
                Err(error) => {
                    eprintln!("Renouvellement impossible : {error}; la session expirera sans nouveau bail.");
                    thread::sleep(Duration::from_secs(3));
                }
            }
        }
    });
    let result = x11::view(
        peer.reader,
        writer.clone(),
        expires_at,
        active.clone(),
        outgoing,
    );
    active.store(false, Ordering::Relaxed);
    if let Ok(writer) = writer.lock() {
        writer.shutdown();
    }
    let _ = renewal.join();
    drop(relay_bridge);
    result
}

fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(u64::MAX)
}
