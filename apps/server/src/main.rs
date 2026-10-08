#![forbid(unsafe_code)]

mod api;
mod backup;
mod relay;
mod state;
mod web;

use anyhow::{bail, Context, Result};
use axum::{
    body::Body,
    extract::DefaultBodyLimit,
    http::{header, HeaderValue, Request},
    middleware::{self, Next},
    response::Response,
    routing::{get, post},
    Router,
};
use clap::{Parser, Subcommand};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use state::{hash_password, now, Role, Store, User};
use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::{self, BufRead, IsTerminal, Write},
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::atomic::AtomicU64,
    sync::{Arc, Mutex},
};
use tokio::sync::Semaphore;
use tower_http::trace::TraceLayer;
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

#[derive(Parser)]
#[command(
    name = "cyclar-server",
    version,
    about = "Serveur central auto-hébergé Cyclar"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Initialise l'identité du serveur et son premier administrateur.
    Init {
        #[arg(long, default_value = "./cyclar-data")]
        data_dir: PathBuf,
        #[arg(long)]
        admin_user: String,
    },
    /// Lance l'API et le panel intégré.
    Serve {
        #[arg(long, default_value = "./cyclar-data")]
        data_dir: PathBuf,
        #[arg(long, default_value = "127.0.0.1:8080")]
        listen: SocketAddr,
        /// Uniquement en développement HTTP local. En production, HTTPS est requis.
        #[arg(long)]
        insecure_cookies: bool,
        /// Confirme que seul un proxy TLS de confiance expose cette écoute non locale.
        #[arg(long)]
        behind_tls_proxy: bool,
    },
    /// Vérifie la lisibilité de la base et de l'identité.
    Check {
        #[arg(long, default_value = "./cyclar-data")]
        data_dir: PathBuf,
    },
    /// Sauvegarde hors ligne base, identité et manifeste vers un nouveau dossier.
    Backup {
        #[arg(long, default_value = "./cyclar-data")]
        data_dir: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Restaure hors ligne une sauvegarde vérifiée vers un nouveau dossier de données.
    Restore {
        #[arg(long = "from")]
        source: PathBuf,
        #[arg(long, default_value = "./cyclar-data")]
        data_dir: PathBuf,
    },
}

pub struct AppState {
    pub store: Arc<Store>,
    pub signing_key: SigningKey,
    pub secure_cookies: bool,
    pub behind_tls_proxy: bool,
    pub attempts: Mutex<BTreeMap<String, (u32, u64)>>,
    pub last_presence_checkpoint: AtomicU64,
    pub password_slots: Arc<Semaphore>,
    pub relay_hub: Arc<relay::RelayHub>,
}

fn key_path(dir: &Path) -> PathBuf {
    dir.join("server-key")
}

fn db_path(dir: &Path) -> PathBuf {
    dir.join("cyclar.redb")
}

fn read_key(dir: &Path) -> Result<SigningKey> {
    let bytes = fs::read(key_path(dir)).context("lecture de l'identité du serveur")?;
    let key: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("clé privée de serveur invalide"))?;
    Ok(SigningKey::from_bytes(&key))
}

fn write_key(dir: &Path, key: &SigningKey) -> Result<()> {
    let path = key_path(dir);
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&path)
        .with_context(|| format!("création de {}", path.display()))?;
    file.write_all(&key.to_bytes())?;
    file.sync_all()?;
    Ok(())
}

fn init(data_dir: &Path, admin_user: &str) -> Result<()> {
    let username = admin_user.trim().to_lowercase();
    if username.len() < 3
        || username.len() > 48
        || !username
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    {
        bail!("identifiant administrateur invalide (3 à 48 caractères ASCII, lettres, chiffres, _ ou -)");
    }
    if key_path(data_dir).exists() || db_path(data_dir).exists() {
        bail!("le répertoire de données contient déjà une identité ou une base ; initialisation refusée");
    }
    fs::create_dir_all(data_dir).context("création du répertoire de données")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(data_dir, fs::Permissions::from_mode(0o700))?;
    }
    let password = if io::stdin().is_terminal() {
        rpassword::prompt_password("Mot de passe administrateur (16 caractères minimum) : ")?
    } else {
        let mut line = String::new();
        io::stdin().lock().read_line(&mut line)?;
        line
    };
    let password = password.trim_end_matches(['\r', '\n']);
    if password.len() < 16 || password.len() > 256 {
        bail!("le mot de passe doit contenir entre 16 et 256 caractères");
    }
    let hash = hash_password(password)?;
    let key = SigningKey::generate(&mut OsRng);
    write_key(data_dir, &key)?;
    let store = Store::open(&db_path(data_dir))?;
    store.update(|db| {
        let id = Uuid::new_v4();
        db.users.insert(
            id,
            User {
                id,
                username: username.clone(),
                display_name: username.clone(),
                role: Role::Admin,
                enabled: true,
                password_hash: hash,
                created_at: now(),
                revoked_at: 0,
            },
        );
        db.audit("bootstrap", "account.create", id.to_string(), "success");
        Ok(())
    })?;
    eprintln!("Serveur initialisé. Administrateur : {username}");
    Ok(())
}

fn check(data_dir: &Path) -> Result<()> {
    let _key = read_key(data_dir)?;
    let store = Store::open(&db_path(data_dir))?;
    store.read(|db| -> Result<()> {
        if db.schema_version != 1 {
            bail!(
                "version de schéma non prise en charge : {}",
                db.schema_version
            );
        }
        if !db
            .users
            .values()
            .any(|user| user.role == Role::Admin && user.enabled)
        {
            bail!("aucun administrateur actif");
        }
        let mut aliases = std::collections::HashSet::new();
        for device in db.devices.values() {
            if !aliases.insert(device.alias) {
                bail!("alias machine en double");
            }
        }
        Ok(())
    })?;
    println!("Données et identité vérifiées.");
    Ok(())
}

async fn security_headers(request: Request<Body>, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'none'; style-src 'self'; img-src 'self' data:; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"),
    );
    headers.insert(
        header::STRICT_TRANSPORT_SECURITY,
        HeaderValue::from_static("max-age=31536000; includeSubDomains"),
    );
    response
}

fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/healthz", get(api::health))
        .route("/assets/style.css", get(web::stylesheet))
        .route("/login", get(web::login_page).post(web::login))
        .route("/logout", post(web::logout))
        .route("/", get(web::dashboard))
        .route("/devices", get(web::devices))
        .route("/devices/{id}/revoke", post(web::revoke_device))
        .route("/sessions", get(web::sessions))
        .route("/sessions/{id}/close", post(web::close_session_admin))
        .route("/users", get(web::users).post(web::create_user))
        .route(
            "/users/{id}/edit",
            get(web::edit_user_page).post(web::update_user),
        )
        .route(
            "/users/{id}/logout-all",
            post(web::logout_all_user_sessions),
        )
        .route("/users/{id}/disable", post(web::disable_user))
        .route("/audit", get(web::audit))
        .route("/api/v1/server", get(api::server_identity))
        .route("/api/v1/devices", post(api::register_device))
        .route("/api/v1/devices/{id}/heartbeat", post(api::heartbeat))
        .route("/api/v1/devices/{id}/sessions", get(api::host_sessions))
        .route(
            "/api/v1/devices/{id}/rotate-temporary-password",
            post(api::rotate_temporary_password),
        )
        .route(
            "/api/v1/devices/{id}/permanent-password",
            post(api::set_permanent_password),
        )
        .route("/api/v1/sessions/request", post(api::request_session))
        .route("/api/v1/sessions/{id}/renew", post(api::renew_session))
        .route(
            "/api/v1/sessions/{id}",
            axum::routing::delete(api::close_session),
        )
        .route("/api/v1/relay/{session_id}/{role}", get(relay::websocket))
        .layer(DefaultBodyLimit::max(16 * 1024))
        .layer(middleware::from_fn(security_headers))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,tower_http=warn")),
        )
        .init();
    match Cli::parse().command {
        Command::Init {
            data_dir,
            admin_user,
        } => init(&data_dir, &admin_user),
        Command::Check { data_dir } => check(&data_dir),
        Command::Backup { data_dir, output } => {
            check(&data_dir)?;
            backup::create_backup(&data_dir, &output)?;
            println!("Sauvegarde créée : {}", output.display());
            Ok(())
        }
        Command::Restore { source, data_dir } => {
            backup::restore_backup(&source, &data_dir)?;
            check(&data_dir)?;
            println!("Restauration vérifiée : {}", data_dir.display());
            Ok(())
        }
        Command::Serve {
            data_dir,
            listen,
            insecure_cookies,
            behind_tls_proxy,
        } => {
            if !listen.ip().is_loopback() && (!behind_tls_proxy || insecure_cookies) {
                bail!("une écoute non locale exige --behind-tls-proxy et des cookies Secure");
            }
            check(&data_dir)?;
            let store = Arc::new(Store::open(&db_path(&data_dir))?);
            let state = Arc::new(AppState {
                store,
                signing_key: read_key(&data_dir)?,
                secure_cookies: !insecure_cookies,
                behind_tls_proxy,
                attempts: Mutex::new(BTreeMap::new()),
                last_presence_checkpoint: AtomicU64::new(0),
                password_slots: Arc::new(Semaphore::new(4)),
                relay_hub: Arc::new(relay::RelayHub::default()),
            });
            let listener = tokio::net::TcpListener::bind(listen)
                .await
                .with_context(|| format!("écoute sur {listen}"))?;
            tracing::info!(%listen, "Cyclar prêt");
            axum::serve(
                listener,
                router(state).into_make_service_with_connect_info::<SocketAddr>(),
            )
            .with_graceful_shutdown(async {
                let _ = tokio::signal::ctrl_c().await;
            })
            .await?;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::{to_bytes, Body},
        extract::ConnectInfo,
        http::{Method, Request, StatusCode},
    };
    use cyclar_protocol::{
        encode_public_key, sign_device_registration, verify_grant_capability, Capability,
        DeviceRegistrationRequest, DeviceRegistrationResponse, HeartbeatRequest, SessionRequest,
        SessionResponse,
    };
    use tower::ServiceExt;

    fn json_request<T: serde::Serialize>(method: Method, path: &str, value: &T) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(path)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::to_vec(value).unwrap()))
            .unwrap()
    }

    fn remote(mut request: Request<Body>) -> Request<Body> {
        request.extensions_mut().insert(ConnectInfo(
            "127.0.0.1:50000".parse::<SocketAddr>().unwrap(),
        ));
        request
    }

    async fn response_json<T: serde::de::DeserializeOwned>(response: Response) -> T {
        let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn device_to_signed_session_and_revocation() {
        let dir = tempfile::tempdir().unwrap();
        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let store = Arc::new(Store::open(&dir.path().join("test.redb")).unwrap());
        let state = Arc::new(AppState {
            store: store.clone(),
            signing_key: signing_key.clone(),
            secure_cookies: false,
            behind_tls_proxy: false,
            attempts: Mutex::new(BTreeMap::new()),
            last_presence_checkpoint: AtomicU64::new(0),
            password_slots: Arc::new(Semaphore::new(4)),
            relay_hub: Arc::new(relay::RelayHub::default()),
        });
        let app = router(state);
        let host_key = SigningKey::from_bytes(&[8; 32]);
        let registration: DeviceRegistrationRequest =
            sign_device_registration(&host_key, "Poste de recette", "linux-x11");
        let mut forged = registration.clone();
        forged.name = "Poste usurpé".into();
        let rejected = app
            .clone()
            .oneshot(remote(json_request(
                Method::POST,
                "/api/v1/devices",
                &forged,
            )))
            .await
            .unwrap();
        assert_eq!(rejected.status(), StatusCode::BAD_REQUEST);
        let response = app
            .clone()
            .oneshot(remote(json_request(
                Method::POST,
                "/api/v1/devices",
                &registration,
            )))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        let registered: DeviceRegistrationResponse = response_json(response).await;
        assert_eq!(registered.alias, 100_000_000);
        let second_key = SigningKey::from_bytes(&[11; 32]);
        let second_registration = sign_device_registration(&second_key, "Autre poste", "linux-x11");
        let response = app
            .clone()
            .oneshot(remote(json_request(
                Method::POST,
                "/api/v1/devices",
                &second_registration,
            )))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        let second: DeviceRegistrationResponse = response_json(response).await;
        assert_ne!(registered.alias, second.alias);
        assert_ne!(registered.device_id, second.device_id);

        let heartbeat = HeartbeatRequest {
            listen_address: Some("127.0.0.1:41337".into()),
            agent_version: "test".into(),
        };
        let mut request = json_request(
            Method::POST,
            &format!("/api/v1/devices/{}/heartbeat", registered.device_id),
            &heartbeat,
        );
        request.headers_mut().insert(
            header::AUTHORIZATION,
            format!("Bearer {}", registered.device_token)
                .parse()
                .unwrap(),
        );
        let response = app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let controller_key = SigningKey::from_bytes(&[9; 32]);
        let mut session_request = SessionRequest {
            alias: registered.alias,
            password: "invalid".into(),
            controller_public_key: encode_public_key(&controller_key.verifying_key()),
            capabilities: vec![
                Capability::View,
                Capability::Input,
                Capability::FileTransfer,
            ],
        };
        let response = app
            .clone()
            .oneshot(remote(json_request(
                Method::POST,
                "/api/v1/sessions/request",
                &session_request,
            )))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        session_request.password = registered.temporary_password;
        let response = app
            .clone()
            .oneshot(remote(json_request(
                Method::POST,
                "/api/v1/sessions/request",
                &session_request,
            )))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let session: SessionResponse = response_json(response).await;
        let claims = verify_grant_capability(
            &session.grant,
            &signing_key.verifying_key(),
            registered.device_id,
            0,
            now(),
            Capability::Input,
        )
        .unwrap();
        assert_eq!(claims.session_id, session.session_id);
        assert!(claims.allows(Capability::FileTransfer));
        assert_eq!(session.host_address.as_deref(), Some("127.0.0.1:41337"));

        let mut renewal = Request::builder()
            .method(Method::POST)
            .uri(format!("/api/v1/sessions/{}/renew", session.session_id))
            .body(Body::empty())
            .unwrap();
        renewal.headers_mut().insert(
            header::AUTHORIZATION,
            format!("Bearer {}", session.renewal_token).parse().unwrap(),
        );
        let response = app.clone().oneshot(renewal).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let relay_only = HeartbeatRequest {
            listen_address: None,
            agent_version: "test".into(),
        };
        let mut heartbeat = json_request(
            Method::POST,
            &format!("/api/v1/devices/{}/heartbeat", registered.device_id),
            &relay_only,
        );
        heartbeat.headers_mut().insert(
            header::AUTHORIZATION,
            format!("Bearer {}", registered.device_token)
                .parse()
                .unwrap(),
        );
        assert_eq!(
            app.clone().oneshot(heartbeat).await.unwrap().status(),
            StatusCode::OK
        );
        let relay_response = app
            .clone()
            .oneshot(remote(json_request(
                Method::POST,
                "/api/v1/sessions/request",
                &session_request,
            )))
            .await
            .unwrap();
        assert_eq!(relay_response.status(), StatusCode::OK);
        let relay_session: SessionResponse = response_json(relay_response).await;
        assert!(relay_session.host_address.is_none());

        let mut rotate = Request::builder()
            .method(Method::POST)
            .uri(format!(
                "/api/v1/devices/{}/rotate-temporary-password",
                registered.device_id
            ))
            .body(Body::empty())
            .unwrap();
        rotate.headers_mut().insert(
            header::AUTHORIZATION,
            format!("Bearer {}", registered.device_token)
                .parse()
                .unwrap(),
        );
        let rotated = app.clone().oneshot(rotate).await.unwrap();
        assert_eq!(rotated.status(), StatusCode::OK);
        let rotated: serde_json::Value = response_json(rotated).await;
        let new_password = rotated["temporary_password"].as_str().unwrap().to_owned();
        assert_ne!(new_password, session_request.password);
        let old_secret = app
            .clone()
            .oneshot(remote(json_request(
                Method::POST,
                "/api/v1/sessions/request",
                &session_request,
            )))
            .await
            .unwrap();
        assert_eq!(old_secret.status(), StatusCode::UNAUTHORIZED);
        session_request.password = new_password;
        let new_secret = app
            .clone()
            .oneshot(remote(json_request(
                Method::POST,
                "/api/v1/sessions/request",
                &session_request,
            )))
            .await
            .unwrap();
        assert_eq!(new_secret.status(), StatusCode::OK);

        store
            .update(|db| {
                db.devices.get_mut(&registered.device_id).unwrap().revoked = true;
                Ok(())
            })
            .unwrap();
        let mut renewal = Request::builder()
            .method(Method::POST)
            .uri(format!("/api/v1/sessions/{}/renew", session.session_id))
            .body(Body::empty())
            .unwrap();
        renewal.headers_mut().insert(
            header::AUTHORIZATION,
            format!("Bearer {}", session.renewal_token).parse().unwrap(),
        );
        let response = app.oneshot(renewal).await.unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn panel_requires_csrf_and_admin_can_manage_accounts() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(&dir.path().join("panel.redb")).unwrap());
        let admin_id = Uuid::new_v4();
        store
            .update(|db| {
                db.users.insert(
                    admin_id,
                    User {
                        id: admin_id,
                        username: "admin".into(),
                        display_name: "Admin".into(),
                        role: Role::Admin,
                        enabled: true,
                        password_hash: hash_password("example-test-password-1")?,
                        created_at: now(),
                        revoked_at: 0,
                    },
                );
                Ok(())
            })
            .unwrap();
        let state = Arc::new(AppState {
            store: store.clone(),
            signing_key: SigningKey::from_bytes(&[10; 32]),
            secure_cookies: false,
            behind_tls_proxy: false,
            attempts: Mutex::new(BTreeMap::new()),
            last_presence_checkpoint: AtomicU64::new(0),
            password_slots: Arc::new(Semaphore::new(4)),
            relay_hub: Arc::new(relay::RelayHub::default()),
        });
        let app = router(state);
        let login_page = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/login")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(login_page.status(), StatusCode::OK);
        let login_cookie = login_page
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        let login_csrf = login_cookie.split_once('=').unwrap().1;

        let bad = remote(
            Request::builder()
                .method(Method::POST)
                .uri("/login")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, &login_cookie)
                .body(Body::from(
                    "username=admin&password=example-test-password-1&csrf=wrong",
                ))
                .unwrap(),
        );
        assert_eq!(
            app.clone().oneshot(bad).await.unwrap().status(),
            StatusCode::FORBIDDEN
        );

        let body = format!("username=admin&password=example-test-password-1&csrf={login_csrf}");
        let good = remote(
            Request::builder()
                .method(Method::POST)
                .uri("/login")
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .header(header::COOKIE, &login_cookie)
                .body(Body::from(body))
                .unwrap(),
        );
        let response = app.clone().oneshot(good).await.unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let session_cookie = response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .find(|value| value.starts_with("cyclar_session="))
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        let users = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/users")
                    .header(header::COOKIE, &session_cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(users.status(), StatusCode::OK);

        let csrf = store.read(|db| db.web_sessions.values().next().unwrap().csrf.clone());
        let create_body = format!("csrf={csrf}&username=alice&display_name=Alice&role=user&password=example-test-password-2");
        let create = Request::builder()
            .method(Method::POST)
            .uri("/users")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::COOKIE, &session_cookie)
            .body(Body::from(create_body))
            .unwrap();
        assert_eq!(
            app.clone().oneshot(create).await.unwrap().status(),
            StatusCode::SEE_OTHER
        );
        let alice = store.read(|db| {
            db.users
                .values()
                .find(|user| user.username == "alice")
                .unwrap()
                .id
        });
        let edit = Request::builder()
            .method(Method::POST)
            .uri(format!("/users/{alice}/edit"))
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::COOKIE, &session_cookie)
            .body(Body::from(format!(
                "csrf={csrf}&username=alice2&display_name=Alice+Deux&role=admin&enabled=true"
            )))
            .unwrap();
        assert_eq!(
            app.clone().oneshot(edit).await.unwrap().status(),
            StatusCode::SEE_OTHER
        );
        assert!(store.read(|db| db
            .users
            .get(&alice)
            .is_some_and(|user| user.username == "alice2" && user.role == Role::Admin)));
        let duplicate = Request::builder()
            .method(Method::POST)
            .uri(format!("/users/{alice}/edit"))
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::COOKIE, &session_cookie)
            .body(Body::from(format!(
                "csrf={csrf}&username=admin&display_name=Alice&role=admin&enabled=true"
            )))
            .unwrap();
        assert_eq!(
            app.clone().oneshot(duplicate).await.unwrap().status(),
            StatusCode::CONFLICT
        );
        let forged_self_demote = Request::builder()
            .method(Method::POST)
            .uri(format!("/users/{admin_id}/edit"))
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::COOKIE, &session_cookie)
            .body(Body::from(format!(
                "csrf={csrf}&username=admin&display_name=Admin&role=user&enabled=true"
            )))
            .unwrap();
        assert_eq!(
            app.clone()
                .oneshot(forged_self_demote)
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );

        let alice_token = "alice-test-session";
        store
            .update(|db| {
                db.web_sessions.insert(
                    state::token_digest(alice_token),
                    state::WebSession {
                        user_id: alice,
                        csrf: state::random_token(),
                        expires_at: now() + 8 * 60 * 60,
                    },
                );
                Ok(())
            })
            .unwrap();
        let alice_cookie = format!("cyclar_session={alice_token}");
        let alice_page = Request::builder()
            .uri("/users")
            .header(header::COOKIE, &alice_cookie)
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            app.clone().oneshot(alice_page).await.unwrap().status(),
            StatusCode::OK
        );
        let logout_alice = Request::builder()
            .method(Method::POST)
            .uri(format!("/users/{alice}/logout-all"))
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::COOKIE, &session_cookie)
            .body(Body::from(format!("csrf={csrf}")))
            .unwrap();
        assert_eq!(
            app.clone().oneshot(logout_alice).await.unwrap().status(),
            StatusCode::SEE_OTHER
        );
        let alice_page = Request::builder()
            .uri("/users")
            .header(header::COOKIE, &alice_cookie)
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            app.clone().oneshot(alice_page).await.unwrap().status(),
            StatusCode::SEE_OTHER
        );

        let disable = Request::builder()
            .method(Method::POST)
            .uri(format!("/users/{alice}/disable"))
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::COOKIE, &session_cookie)
            .body(Body::from(format!("csrf={csrf}")))
            .unwrap();
        assert_eq!(
            app.clone().oneshot(disable).await.unwrap().status(),
            StatusCode::SEE_OTHER
        );
        assert!(!store.read(|db| db.users.get(&alice).unwrap().enabled));

        let self_disable = Request::builder()
            .method(Method::POST)
            .uri(format!("/users/{admin_id}/disable"))
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::COOKIE, &session_cookie)
            .body(Body::from(format!("csrf={csrf}")))
            .unwrap();
        assert_eq!(
            app.clone().oneshot(self_disable).await.unwrap().status(),
            StatusCode::FORBIDDEN
        );
        let logout_self = Request::builder()
            .method(Method::POST)
            .uri(format!("/users/{admin_id}/logout-all"))
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::COOKIE, &session_cookie)
            .body(Body::from(format!("csrf={csrf}")))
            .unwrap();
        assert_eq!(
            app.clone().oneshot(logout_self).await.unwrap().status(),
            StatusCode::SEE_OTHER
        );
        let admin_page = Request::builder()
            .uri("/users")
            .header(header::COOKIE, &session_cookie)
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            app.oneshot(admin_page).await.unwrap().status(),
            StatusCode::SEE_OTHER
        );
    }
}
