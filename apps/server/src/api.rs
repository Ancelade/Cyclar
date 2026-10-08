use crate::{
    state::{
        hash_password, now, random_token, temporary_password, token_digest, verify_password,
        Device, RemoteSession,
    },
    AppState,
};
use axum::{
    extract::{ConnectInfo, Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use cyclar_protocol::{
    decode_public_key, sign_grant, verify_device_registration, Capability,
    DeviceRegistrationRequest, DeviceRegistrationResponse, GrantClaims, HeartbeatRequest,
    SessionRenewalResponse, SessionRequest, SessionResponse,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    net::SocketAddr,
    sync::{atomic::Ordering, Arc, OnceLock},
};
use subtle::ConstantTimeEq;
use uuid::Uuid;

#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: &'static str,
}

impl ApiError {
    pub fn bad_request(message: &'static str) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code: "bad_request",
            message,
        }
    }

    pub fn unauthorized() -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            code: "unauthorized",
            message: "Authentification requise ou invalide.",
        }
    }

    pub fn forbidden() -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            code: "forbidden",
            message: "Accès refusé.",
        }
    }

    pub fn not_found() -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            code: "not_found",
            message: "Ressource introuvable.",
        }
    }

    pub fn conflict(message: &'static str) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            code: "conflict",
            message,
        }
    }

    pub fn too_many_requests() -> Self {
        Self {
            status: StatusCode::TOO_MANY_REQUESTS,
            code: "rate_limited",
            message: "Trop de tentatives. Réessayez plus tard.",
        }
    }

    pub fn unsupported() -> Self {
        Self {
            status: StatusCode::UNPROCESSABLE_ENTITY,
            code: "unsupported_capability",
            message: "Cette capacité n'est pas disponible sur ce serveur.",
        }
    }

    pub fn internal() -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "internal_error",
            message: "Erreur interne du serveur.",
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(json!({"error":{"code":self.code,"message":self.message}})),
        )
            .into_response()
    }
}

type ApiResult<T> = Result<T, ApiError>;

pub(crate) async fn hash_password_bounded(state: &AppState, password: String) -> ApiResult<String> {
    let permit = state
        .password_slots
        .clone()
        .try_acquire_owned()
        .map_err(|_| ApiError::too_many_requests())?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        hash_password(&password)
    })
    .await
    .map_err(|_| ApiError::internal())?
    .map_err(|_| ApiError::internal())
}

pub(crate) async fn verify_password_bounded(
    state: &AppState,
    hash: String,
    password: String,
) -> ApiResult<bool> {
    let permit = state
        .password_slots
        .clone()
        .try_acquire_owned()
        .map_err(|_| ApiError::too_many_requests())?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        verify_password(&hash, &password)
    })
    .await
    .map_err(|_| ApiError::internal())
}

fn valid_label(input: &str, max: usize) -> bool {
    !input.trim().is_empty() && input.chars().count() <= max && !input.chars().any(char::is_control)
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
}

fn digest_matches(expected: &str, supplied: &str) -> bool {
    bool::from(expected.as_bytes().ct_eq(token_digest(supplied).as_bytes()))
}

fn device_from_bearer(state: &AppState, id: Uuid, headers: &HeaderMap) -> ApiResult<Device> {
    let token = bearer(headers).ok_or_else(ApiError::unauthorized)?;
    state
        .store
        .read(|db| {
            db.devices
                .get(&id)
                .filter(|device| {
                    !device.revoked && digest_matches(&device.device_token_digest, token)
                })
                .cloned()
        })
        .ok_or_else(ApiError::unauthorized)
}

pub(crate) fn limit(
    state: &AppState,
    remote: SocketAddr,
    action: &str,
    identity: &str,
    allowed: u32,
    window_secs: u64,
    consume: bool,
) -> ApiResult<()> {
    if identity.len() > 64 {
        return Err(ApiError::bad_request("Identifiant trop long."));
    }
    let key = format!("{}:{action}:{identity}", remote.ip());
    let mut guard = state.attempts.lock().unwrap_or_else(|e| e.into_inner());
    if guard.len() >= 10_000 {
        guard.retain(|_, (_, until)| *until > now());
        if guard.len() >= 10_000 {
            return Err(ApiError::too_many_requests());
        }
    }
    if !consume && !guard.contains_key(&key) {
        return Ok(());
    }
    let entry = guard.entry(key).or_insert((0, now() + window_secs));
    if entry.1 <= now() {
        *entry = (0, now() + window_secs);
    }
    if entry.0 >= allowed {
        return Err(ApiError::too_many_requests());
    }
    if consume {
        entry.0 += 1;
    }
    Ok(())
}

pub async fn health() -> Json<Value> {
    Json(json!({"status":"ok","service":"cyclar-server","version":env!("CARGO_PKG_VERSION")}))
}

pub async fn server_identity(State(state): State<Arc<AppState>>) -> Json<Value> {
    Json(
        json!({"public_key":cyclar_protocol::encode_public_key(&state.signing_key.verifying_key()),"protocol_major":1}),
    )
}

pub async fn register_device(
    State(state): State<Arc<AppState>>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    Json(req): Json<DeviceRegistrationRequest>,
) -> ApiResult<(StatusCode, Json<DeviceRegistrationResponse>)> {
    if !state.behind_tls_proxy {
        limit(&state, remote, "register", "all", 12, 3600, true)?;
    }
    if !valid_label(&req.name, 80) || !valid_label(&req.platform, 48) {
        return Err(ApiError::bad_request("Nom ou plateforme invalide."));
    }
    verify_device_registration(&req)
        .map_err(|_| ApiError::bad_request("Preuve d'identité machine invalide."))?;
    let id = Uuid::new_v4();
    let secret = temporary_password();
    let token = random_token();
    let password_hash = hash_password_bounded(&state, secret.clone()).await?;
    let response = state
        .store
        .update(|db| {
            if db
                .devices
                .values()
                .any(|device| device.public_key == req.public_key && !device.revoked)
            {
                anyhow::bail!("duplicate public key");
            }
            let alias = db.next_alias;
            if alias > 999_999_999 {
                anyhow::bail!("alias space exhausted");
            }
            db.next_alias += 1;
            db.devices.insert(
                id,
                Device {
                    id,
                    alias,
                    name: req.name.trim().to_owned(),
                    platform: req.platform.trim().to_owned(),
                    public_key: req.public_key.clone(),
                    device_token_digest: token_digest(&token),
                    temporary_password_hash: password_hash,
                    permanent_password_hash: None,
                    created_at: now(),
                    last_seen: None,
                    listen_address: None,
                    agent_version: None,
                    revoked: false,
                    key_epoch: 0,
                    secret_epoch: 0,
                },
            );
            db.audit("device", "device.register", alias.to_string(), "success");
            Ok(DeviceRegistrationResponse {
                device_id: id,
                alias,
                temporary_password: secret,
                device_token: token,
                server_public_key: cyclar_protocol::encode_public_key(
                    &state.signing_key.verifying_key(),
                ),
            })
        })
        .map_err(|error| {
            if error.to_string().contains("duplicate public key") {
                ApiError::conflict("Cette identité machine est déjà inscrite.")
            } else {
                tracing::error!(%error, "device registration persistence failed");
                ApiError::internal()
            }
        })?;
    Ok((StatusCode::CREATED, Json(response)))
}

pub async fn heartbeat(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Json(req): Json<HeartbeatRequest>,
) -> ApiResult<Json<Value>> {
    device_from_bearer(&state, id, &headers)?;
    if req.agent_version.chars().count() > 40
        || req
            .listen_address
            .as_ref()
            .is_some_and(|addr| addr.len() > 256 || addr.parse::<SocketAddr>().is_err())
    {
        return Err(ApiError::bad_request(
            "Adresse ou version d'agent invalide.",
        ));
    }
    let touch = |db: &mut crate::state::PersistentState| {
        let device = db
            .devices
            .get_mut(&id)
            .ok_or_else(|| anyhow::anyhow!("device missing"))?;
        if device.revoked {
            anyhow::bail!("device revoked");
        }
        device.last_seen = Some(now());
        device.listen_address = req.listen_address;
        device.agent_version = Some(req.agent_version);
        Ok(())
    };
    let checkpoint_at = state.last_presence_checkpoint.load(Ordering::Relaxed);
    if now().saturating_sub(checkpoint_at) >= 60 {
        state
            .store
            .update(touch)
            .map_err(|_| ApiError::internal())?;
        state
            .last_presence_checkpoint
            .store(now(), Ordering::Relaxed);
    } else {
        state
            .store
            .update_volatile(touch)
            .map_err(|_| ApiError::internal())?;
    }
    Ok(Json(json!({"status":"online","server_time":now()})))
}

pub async fn host_sessions(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> ApiResult<Json<Value>> {
    device_from_bearer(&state, id, &headers)?;
    let ids: Vec<Uuid> = state.store.read(|db| {
        let Some(device) = db.devices.get(&id) else {
            return Vec::new();
        };
        db.sessions
            .values()
            .filter(|session| {
                session.host_device_id == id
                    && session.host_key_epoch == device.key_epoch
                    && session.active()
            })
            .map(|session| session.id)
            .collect()
    });
    Ok(Json(json!({"active_session_ids":ids})))
}

pub async fn rotate_temporary_password(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> ApiResult<Json<Value>> {
    let device = device_from_bearer(&state, id, &headers)?;
    let secret = temporary_password();
    let hash = hash_password_bounded(&state, secret.clone()).await?;
    state
        .store
        .update(|db| {
            let item = db
                .devices
                .get_mut(&id)
                .ok_or_else(|| anyhow::anyhow!("device missing"))?;
            if item.revoked || item.device_token_digest != device.device_token_digest {
                anyhow::bail!("device revoked or rotated");
            }
            item.temporary_password_hash = hash;
            item.secret_epoch = item.secret_epoch.saturating_add(1);
            db.audit(
                "device",
                "device.password.rotate",
                id.to_string(),
                "success",
            );
            Ok(())
        })
        .map_err(|_| ApiError::internal())?;
    Ok(Json(json!({"temporary_password":secret})))
}

#[derive(Deserialize)]
pub struct PermanentPasswordRequest {
    password: Option<String>,
}

pub async fn set_permanent_password(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Json(req): Json<PermanentPasswordRequest>,
) -> ApiResult<StatusCode> {
    let device = device_from_bearer(&state, id, &headers)?;
    if req
        .password
        .as_ref()
        .is_some_and(|pwd| pwd.len() < 16 || pwd.len() > 256)
    {
        return Err(ApiError::bad_request(
            "Le mot de passe permanent doit contenir entre 16 et 256 caractères.",
        ));
    }
    let hash = match req.password {
        Some(password) => Some(hash_password_bounded(&state, password).await?),
        None => None,
    };
    state
        .store
        .update(|db| {
            let item = db
                .devices
                .get_mut(&id)
                .ok_or_else(|| anyhow::anyhow!("device missing"))?;
            if item.revoked || item.device_token_digest != device.device_token_digest {
                anyhow::bail!("device revoked or rotated");
            }
            item.permanent_password_hash = hash;
            item.secret_epoch = item.secret_epoch.saturating_add(1);
            db.audit(
                "device",
                "device.password.permanent",
                id.to_string(),
                "success",
            );
            Ok(())
        })
        .map_err(|_| ApiError::internal())?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn request_session(
    State(state): State<Arc<AppState>>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    Json(req): Json<SessionRequest>,
) -> ApiResult<Json<SessionResponse>> {
    if !state.behind_tls_proxy {
        limit(&state, remote, "auth-global", "all", 256, 900, true)?;
    }
    limit(
        &state,
        remote,
        "session",
        &req.alias.to_string(),
        8,
        900,
        false,
    )?;
    if req.password.len() > 256
        || req.password.is_empty()
        || req.capabilities.is_empty()
        || req.capabilities.len() > 8
    {
        return Err(ApiError::bad_request("Demande de session invalide."));
    }
    decode_public_key(&req.controller_public_key)
        .map_err(|_| ApiError::bad_request("Clé du contrôleur invalide."))?;
    if req.capabilities.iter().any(|cap| {
        !matches!(
            cap,
            Capability::View | Capability::Input | Capability::FileTransfer
        )
    }) {
        return Err(ApiError::unsupported());
    }
    if !req.capabilities.contains(&Capability::View) {
        return Err(ApiError::bad_request(
            "La capacité view est requise pour une session distante.",
        ));
    }
    if req
        .capabilities
        .iter()
        .collect::<std::collections::HashSet<_>>()
        .len()
        != req.capabilities.len()
    {
        return Err(ApiError::bad_request("Capacités dupliquées."));
    }
    let device = state.store.read(|db| {
        db.devices
            .values()
            .find(|device| device.alias == req.alias)
            .cloned()
    });
    static DUMMY_HASH: OnceLock<String> = OnceLock::new();
    let dummy = DUMMY_HASH.get_or_init(|| {
        hash_password("unused-authentication-sentinel").expect("Argon2 initialization")
    });
    let valid = if let Some(device) = &device {
        let temporary = verify_password_bounded(
            &state,
            device.temporary_password_hash.clone(),
            req.password.clone(),
        )
        .await?;
        if temporary {
            true
        } else if let Some(hash) = &device.permanent_password_hash {
            verify_password_bounded(&state, hash.clone(), req.password.clone()).await?
        } else {
            false
        }
    } else {
        let _ = verify_password_bounded(&state, dummy.clone(), req.password.clone()).await?;
        false
    };
    if !valid {
        limit(
            &state,
            remote,
            "session",
            &req.alias.to_string(),
            8,
            900,
            true,
        )?;
        state
            .store
            .update(|db| {
                db.audit(
                    format!("ip:{}", remote.ip()),
                    "session.authenticate",
                    req.alias.to_string(),
                    "denied",
                );
                Ok(())
            })
            .map_err(|_| ApiError::internal())?;
        return Err(ApiError::unauthorized());
    }
    let device = device.ok_or_else(ApiError::unauthorized)?;
    if device.revoked || !device.online() {
        return Err(ApiError::conflict("Machine indisponible."));
    }
    let session_id = Uuid::new_v4();
    let renewal_token = random_token();
    let issued_at = now();
    let expires_at = issued_at + 30;
    let claims = GrantClaims {
        session_id,
        host_device_id: device.id,
        controller_public_key: req.controller_public_key.clone(),
        capabilities: req.capabilities.clone(),
        issued_at,
        expires_at,
        nonce: Uuid::new_v4(),
        host_key_epoch: device.key_epoch,
    };
    let grant = sign_grant(&claims, &state.signing_key).map_err(|_| ApiError::internal())?;
    state
        .store
        .update(|db| {
            let current = db
                .devices
                .get(&device.id)
                .ok_or_else(|| anyhow::anyhow!("device missing"))?;
            if current.revoked
                || current.key_epoch != device.key_epoch
                || current.secret_epoch != device.secret_epoch
            {
                anyhow::bail!("device state changed");
            }
            db.sessions.insert(
                session_id,
                RemoteSession {
                    id: session_id,
                    host_device_id: device.id,
                    host_key_epoch: device.key_epoch,
                    controller_public_key: req.controller_public_key,
                    capabilities: req.capabilities,
                    created_at: issued_at,
                    expires_at,
                    renewal_token_digest: token_digest(&renewal_token),
                    closed_at: None,
                },
            );
            db.audit(
                format!("ip:{}", remote.ip()),
                "session.authorize",
                session_id.to_string(),
                "success",
            );
            Ok(())
        })
        .map_err(|_| ApiError::conflict("La machine a changé d'état. Réessayez."))?;
    Ok(Json(SessionResponse {
        session_id,
        grant,
        expires_at,
        host_address: device.listen_address,
        host_public_key: device.public_key,
        renewal_token,
    }))
}

pub async fn renew_session(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> ApiResult<Json<SessionRenewalResponse>> {
    let token = bearer(&headers).ok_or_else(ApiError::unauthorized)?;
    let session = state
        .store
        .read(|db| {
            db.sessions
                .get(&id)
                .filter(|session| digest_matches(&session.renewal_token_digest, token))
                .cloned()
        })
        .ok_or_else(ApiError::unauthorized)?;
    if !session.active() {
        return Err(ApiError::forbidden());
    }
    let device = state
        .store
        .read(|db| db.devices.get(&session.host_device_id).cloned())
        .ok_or_else(ApiError::not_found)?;
    if !device.online() || device.key_epoch != session.host_key_epoch {
        return Err(ApiError::conflict("Machine indisponible."));
    }
    let issued_at = now();
    let expires_at = issued_at + 30;
    let grant = sign_grant(
        &GrantClaims {
            session_id: id,
            host_device_id: device.id,
            controller_public_key: session.controller_public_key.clone(),
            capabilities: session.capabilities.clone(),
            issued_at,
            expires_at,
            nonce: Uuid::new_v4(),
            host_key_epoch: device.key_epoch,
        },
        &state.signing_key,
    )
    .map_err(|_| ApiError::internal())?;
    state
        .store
        .update(|db| {
            let current_device = db
                .devices
                .get(&session.host_device_id)
                .ok_or_else(|| anyhow::anyhow!("device missing"))?;
            if current_device.revoked || current_device.key_epoch != session.host_key_epoch {
                anyhow::bail!("device revoked");
            }
            let item = db
                .sessions
                .get_mut(&id)
                .ok_or_else(|| anyhow::anyhow!("session missing"))?;
            if item.closed_at.is_some() || !digest_matches(&item.renewal_token_digest, token) {
                anyhow::bail!("session revoked");
            }
            item.expires_at = expires_at;
            Ok(())
        })
        .map_err(|_| ApiError::forbidden())?;
    Ok(Json(SessionRenewalResponse { grant, expires_at }))
}

pub async fn close_session(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> ApiResult<StatusCode> {
    let token = bearer(&headers).ok_or_else(ApiError::unauthorized)?;
    state
        .store
        .update(|db| {
            let session = db
                .sessions
                .get_mut(&id)
                .ok_or_else(|| anyhow::anyhow!("session missing"))?;
            if !digest_matches(&session.renewal_token_digest, token) {
                anyhow::bail!("bad token");
            }
            session.closed_at = Some(now());
            db.audit("controller", "session.close", id.to_string(), "success");
            Ok(())
        })
        .map_err(|_| ApiError::unauthorized())?;
    state.relay_hub.cancel(id);
    Ok(StatusCode::NO_CONTENT)
}
