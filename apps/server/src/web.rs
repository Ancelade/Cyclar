use crate::{
    api::ApiError,
    state::{hash_password, now, random_token, token_digest, AuditEvent, Role, User, WebSession},
    AppState,
};
use axum::{
    extract::{ConnectInfo, Form, Path, State},
    http::{header, HeaderMap, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
};
use maud::{html, Markup, DOCTYPE};
use serde::Deserialize;
use std::{
    net::SocketAddr,
    sync::{Arc, OnceLock},
};
use subtle::ConstantTimeEq;
use thiserror::Error;
use uuid::Uuid;

const CSS: &str = include_str!("style.css");
const SESSION_SECONDS: u64 = 8 * 60 * 60;

pub async fn stylesheet() -> ([(header::HeaderName, &'static str); 1], &'static str) {
    ([(header::CONTENT_TYPE, "text/css; charset=utf-8")], CSS)
}

fn cookie_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .find_map(|part| {
            let (key, value) = part.trim().split_once('=')?;
            (key == name).then_some(value)
        })
}

fn session_cookie_name(secure: bool) -> &'static str {
    if secure {
        "__Host-cyclar"
    } else {
        "cyclar_session"
    }
}

fn login_csrf_cookie_name(secure: bool) -> &'static str {
    if secure {
        "__Host-cyclar_login_csrf"
    } else {
        "cyclar_login_csrf"
    }
}

fn set_cookie(name: &str, value: &str, secure: bool, max_age: u64) -> String {
    format!(
        "{name}={value}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age}{}",
        if secure { "; Secure" } else { "" }
    )
}

#[derive(Clone)]
struct Auth {
    user: User,
    csrf: String,
    digest: String,
}

#[derive(Clone, Copy)]
enum AccessError {
    LoginRequired,
    AdminRequired,
    InvalidCsrf,
}

impl IntoResponse for AccessError {
    fn into_response(self) -> Response {
        match self {
            Self::LoginRequired => Redirect::to("/login").into_response(),
            Self::AdminRequired => {
                (StatusCode::FORBIDDEN, "Accès administrateur requis").into_response()
            }
            Self::InvalidCsrf => {
                (StatusCode::FORBIDDEN, "Jeton anti-CSRF invalide").into_response()
            }
        }
    }
}

fn auth(state: &AppState, headers: &HeaderMap) -> Option<Auth> {
    let token = cookie_value(headers, session_cookie_name(state.secure_cookies))?;
    let digest = token_digest(token);
    state.store.read(|db| {
        let session = db.web_sessions.get(&digest)?;
        if session.expires_at < now() {
            return None;
        }
        let user = db.users.get(&session.user_id)?;
        if !user.enabled || user.revoked_at > session.expires_at.saturating_sub(SESSION_SECONDS) {
            return None;
        }
        Some(Auth {
            user: user.clone(),
            csrf: session.csrf.clone(),
            digest,
        })
    })
}

fn admin(state: &AppState, headers: &HeaderMap) -> Result<Auth, AccessError> {
    let auth = auth(state, headers).ok_or(AccessError::LoginRequired)?;
    if auth.user.role != Role::Admin {
        return Err(AccessError::AdminRequired);
    }
    Ok(auth)
}

fn csrf_ok(expected: &str, supplied: &str) -> bool {
    bool::from(expected.as_bytes().ct_eq(supplied.as_bytes()))
}

fn require_csrf(auth: &Auth, token: &str) -> Result<(), AccessError> {
    if csrf_ok(&auth.csrf, token) {
        Ok(())
    } else {
        Err(AccessError::InvalidCsrf)
    }
}

fn page(title: &str, section: &str, user: Option<&User>, content: Markup) -> Html<String> {
    let markup = html! {
        (DOCTYPE)
        html lang="fr" {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width,initial-scale=1";
                meta name="color-scheme" content="light";
                title { (title) " · Cyclar" }
                link rel="stylesheet" href="/assets/style.css";
            }
            body {
                @if let Some(user) = user {
                    div class="app-shell" {
                        aside class="sidebar" {
                            a class="brand" href="/" { span class="brand-icon" { "◉" } span { "Cyclar" small { "Self-hosted. In control." } } }
                            nav aria-label="Navigation principale" {
                                (nav_link("Tableau de bord", "/", "⌂", section == "dashboard"))
                                (nav_link("Machines", "/devices", "▣", section == "devices"))
                                (nav_link("Sessions", "/sessions", "◉", section == "sessions"))
                                (nav_link("Utilisateurs", "/users", "♙", section == "users"))
                                (nav_link("Journal", "/audit", "≡", section == "audit"))
                            }
                            div class="sidebar-foot" {
                                span class="status-dot" {} " Serveur en ligne"
                                small { "Cyclar " (env!("CARGO_PKG_VERSION")) }
                            }
                        }
                        div class="main-shell" {
                            header class="topbar" {
                                span class="topbar-title" { "Espace d'administration" }
                                div class="topbar-user" { span class="avatar" { (user.username.chars().next().unwrap_or('A').to_ascii_uppercase()) } span { (user.display_name) small { "Administrateur" } } }
                            }
                            main class="content" { (content) }
                        }
                    }
                } @else {
                    main class="login-shell" { (content) }
                }
            }
        }
    };
    Html(markup.into_string())
}

fn nav_link(label: &str, href: &str, icon: &str, active: bool) -> Markup {
    html! {
        a class=(if active { "active" } else { "" }) href=(href) aria-current=(if active { "page" } else { "false" }) {
            span class="nav-icon" aria-hidden="true" { (icon) } (label)
        }
    }
}

fn heading(title: &str, subtitle: &str) -> Markup {
    html! { div class="page-heading" { div { h1 { (title) } p { (subtitle) } } } }
}

fn csrf_input(csrf: &str) -> Markup {
    html! { input type="hidden" name="csrf" value=(csrf); }
}

fn badge(ok: bool, good: &str, bad: &str) -> Markup {
    html! { span class=(if ok { "badge badge-good" } else { "badge badge-muted" }) {
        span class="badge-dot" {} @if ok { (good) } @else { (bad) }
    } }
}

fn relative_time(ts: Option<u64>) -> String {
    let Some(ts) = ts else {
        return "Jamais".into();
    };
    let elapsed = now().saturating_sub(ts);
    if elapsed < 60 {
        format!("Il y a {elapsed} s")
    } else if elapsed < 3600 {
        format!("Il y a {} min", elapsed / 60)
    } else if elapsed < 86_400 {
        format!("Il y a {} h", elapsed / 3600)
    } else {
        format!("Il y a {} j", elapsed / 86_400)
    }
}

pub async fn login_page(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if auth(&state, &headers).is_some() {
        return Redirect::to("/").into_response();
    }
    let token = random_token();
    let content = html! {
        div class="login-card" {
            div class="login-brand" { span class="brand-icon" { "◉" } " Cyclar" }
            h1 { "Bienvenue" }
            p { "Connectez-vous à votre serveur auto-hébergé." }
            form method="post" action="/login" {
                input type="hidden" name="csrf" value=(token);
                label for="username" { "Identifiant" }
                input id="username" name="username" required autocomplete="username" autofocus;
                label for="password" { "Mot de passe" }
                input id="password" name="password" type="password" required autocomplete="current-password";
                button class="button primary full" type="submit" { "Se connecter" }
            }
            p class="hint" { "Le premier compte est créé localement avec " code { "cyclar-server init" } "." }
        }
    };
    let mut response = page("Connexion", "", None, content).into_response();
    let cookie = set_cookie(
        login_csrf_cookie_name(state.secure_cookies),
        &token,
        state.secure_cookies,
        600,
    );
    if let Ok(value) = cookie.parse() {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
    response
}

#[derive(Deserialize)]
pub struct LoginForm {
    username: String,
    password: String,
    csrf: String,
}

pub async fn login(
    State(state): State<Arc<AppState>>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> Response {
    let Some(cookie) = cookie_value(&headers, login_csrf_cookie_name(state.secure_cookies)) else {
        return (StatusCode::FORBIDDEN, "Jeton de connexion manquant").into_response();
    };
    if !csrf_ok(cookie, &form.csrf) {
        return (StatusCode::FORBIDDEN, "Jeton de connexion invalide").into_response();
    }
    if form.username.len() > 48 || form.password.len() > 256 {
        return (
            StatusCode::BAD_REQUEST,
            "Identifiant ou mot de passe trop long",
        )
            .into_response();
    }
    if (!state.behind_tls_proxy
        && crate::api::limit(&state, remote, "auth-global", "all", 256, 900, true).is_err())
        || crate::api::limit(
            &state,
            remote,
            "login",
            &form.username.trim().to_lowercase(),
            8,
            900,
            false,
        )
        .is_err()
    {
        return ApiError::too_many_requests().into_response();
    }
    let username = form.username.trim().to_lowercase();
    let user = state.store.read(|db| {
        db.users
            .values()
            .find(|user| user.username == username && user.enabled)
            .cloned()
    });
    static DUMMY_HASH: OnceLock<String> = OnceLock::new();
    let dummy = DUMMY_HASH
        .get_or_init(|| hash_password("unused-account-sentinel").expect("Argon2 initialization"));
    let valid = if let Some(user) = &user {
        match crate::api::verify_password_bounded(
            &state,
            user.password_hash.clone(),
            form.password.clone(),
        )
        .await
        {
            Ok(valid) => valid,
            Err(error) => return error.into_response(),
        }
    } else {
        if let Err(error) =
            crate::api::verify_password_bounded(&state, dummy.clone(), form.password.clone()).await
        {
            return error.into_response();
        }
        false
    };
    if !valid {
        let _ = crate::api::limit(&state, remote, "login", &username, 8, 900, true);
        let _ = state.store.update(|db| {
            db.audit(
                format!("ip:{}", remote.ip()),
                "account.login",
                username,
                "denied",
            );
            Ok(())
        });
        let content = html! {
            div class="login-card" {
                div class="login-brand" { span class="brand-icon" { "◉" } " Cyclar" }
                h1 { "Connexion refusée" }
                p { "Identifiant ou mot de passe incorrect." }
                a class="button primary full" href="/login" { "Réessayer" }
            }
        };
        return (
            StatusCode::UNAUTHORIZED,
            page("Connexion", "", None, content),
        )
            .into_response();
    }
    let user = user.expect("valid implies user");
    let token = random_token();
    let session = WebSession {
        user_id: user.id,
        csrf: random_token(),
        expires_at: now() + SESSION_SECONDS,
    };
    if state
        .store
        .update(|db| {
            db.web_sessions.insert(token_digest(&token), session);
            db.audit(
                user.username,
                "account.login",
                user.id.to_string(),
                "success",
            );
            Ok(())
        })
        .is_err()
    {
        return ApiError::internal().into_response();
    }
    let mut response = Redirect::to("/").into_response();
    if let Ok(value) = set_cookie(
        session_cookie_name(state.secure_cookies),
        &token,
        state.secure_cookies,
        SESSION_SECONDS,
    )
    .parse()
    {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
    if let Ok(value) = set_cookie(
        login_csrf_cookie_name(state.secure_cookies),
        "",
        state.secure_cookies,
        0,
    )
    .parse()
    {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
    response
}

#[derive(Deserialize)]
pub struct CsrfForm {
    csrf: String,
}

pub async fn logout(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<CsrfForm>,
) -> Response {
    let Some(auth) = auth(&state, &headers) else {
        return Redirect::to("/login").into_response();
    };
    if let Err(error) = require_csrf(&auth, &form.csrf) {
        return error.into_response();
    }
    if state
        .store
        .update(|db| {
            db.web_sessions.remove(&auth.digest);
            db.audit(
                auth.user.username,
                "account.logout",
                auth.user.id.to_string(),
                "success",
            );
            Ok(())
        })
        .is_err()
    {
        return ApiError::internal().into_response();
    }
    let mut response = Redirect::to("/login").into_response();
    if let Ok(value) = set_cookie(
        session_cookie_name(state.secure_cookies),
        "",
        state.secure_cookies,
        0,
    )
    .parse()
    {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
    response
}

pub async fn dashboard(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let auth = match admin(&state, &headers) {
        Ok(auth) => auth,
        Err(error) => return error.into_response(),
    };
    let (devices, sessions, users, audits) = state.store.read(|db| {
        (
            db.devices.values().cloned().collect::<Vec<_>>(),
            db.sessions.values().cloned().collect::<Vec<_>>(),
            db.users.values().cloned().collect::<Vec<_>>(),
            db.audit.iter().rev().take(6).cloned().collect::<Vec<_>>(),
        )
    });
    let online = devices.iter().filter(|device| device.online()).count();
    let active = sessions.iter().filter(|session| session.active()).count();
    let relay_rendezvous = state.relay_hub.session_count();
    let content = html! {
        (heading("Tableau de bord", "État réel de votre serveur et de vos connexions."))
        div class="stat-grid" {
            (stat_card("Machines connectées", online, format!("sur {} machines", devices.len()), "▣"))
            (stat_card("Sessions actives", active, "Connexions autorisées".into(), "◉"))
            (stat_card("Rendez-vous relais", relay_rendezvous, "En attente ou appairés".into(), "⇄"))
            (stat_card("Utilisateurs", users.iter().filter(|user| user.enabled).count(), "Comptes actifs".into(), "♙"))
        }
        div class="dashboard-grid" {
            section class="panel" {
                div class="panel-title" { h2 { "Machines" } a href="/devices" { "Tout voir →" } }
                @if devices.is_empty() {
                    (empty_state("Aucune machine inscrite", "Démarrez un hôte léger pour obtenir son ID et son secret."))
                } @else {
                    div class="table-wrap" { table {
                        thead { tr { th { "Machine" } th { "ID" } th { "Statut" } th { "Dernier contact" } } }
                        tbody { @for device in devices.iter().take(6) {
                            tr { td { strong { (&device.name) } small { (&device.platform) } } td class="mono" { (device.alias) } td { (badge(device.online(), "En ligne", "Hors ligne")) } td { (relative_time(device.last_seen)) } }
                        } }
                    } }
                }
            }
            section class="panel" {
                div class="panel-title" { h2 { "Événements récents" } a href="/audit" { "Journal →" } }
                @if audits.is_empty() { (empty_state("Aucun événement", "Le journal apparaîtra au fil de l'utilisation.")) }
                @else { ul class="activity-list" { @for event in audits { li { span class="activity-dot" {} div { strong { (event.action) } small { (event.target) " · " (relative_time(Some(event.at))) } } } } } }
            }
        }
        section class="notice" { strong { "Sécurité par défaut" } p { "Toute nouvelle session exige une autorisation signée par ce serveur. Les fonctions non disponibles ne sont pas annoncées comme actives." } }
        form method="post" action="/logout" class="logout-form" { (csrf_input(&auth.csrf)) button class="text-button" type="submit" { "Se déconnecter" } }
    };
    page("Tableau de bord", "dashboard", Some(&auth.user), content).into_response()
}

fn stat_card(label: &str, value: usize, detail: String, icon: &str) -> Markup {
    html! { div class="stat-card" { div class="stat-icon" aria-hidden="true" { (icon) } div { small { (label) } strong { (value) } span { (detail) } } } }
}

fn empty_state(title: &str, body: &str) -> Markup {
    html! { div class="empty-state" { strong { (title) } p { (body) } } }
}

pub async fn devices(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let auth = match admin(&state, &headers) {
        Ok(auth) => auth,
        Err(error) => return error.into_response(),
    };
    let devices = state
        .store
        .read(|db| db.devices.values().cloned().collect::<Vec<_>>());
    let content = html! {
        (heading("Machines", "Identités, présence et révocation des postes inscrits."))
        section class="panel" {
            div class="panel-title" { h2 { "Parc enregistré" } span class="count" { (devices.len()) " machines" } }
            @if devices.is_empty() { (empty_state("Aucune machine", "Démarrez cyclAR-host et connectez-le à cette instance.")) }
            @else { div class="table-wrap" { table {
                thead { tr { th { "Machine" } th { "ID public" } th { "État" } th { "Agent" } th { "Dernier contact" } th { "Action" } } }
                tbody { @for device in devices {
                    tr {
                        td { strong { (&device.name) } small { (&device.platform) } }
                        td class="mono" { (device.alias) }
                        td { @if device.revoked { (badge(false, "", "Révoquée")) } @else { (badge(device.online(), "En ligne", "Hors ligne")) } }
                        td { (device.agent_version.as_deref().unwrap_or("—")) }
                        td { (relative_time(device.last_seen)) }
                        td { @if !device.revoked { form method="post" action=(format!("/devices/{}/revoke",device.id)) {
                            (csrf_input(&auth.csrf)) button class="danger-link" type="submit" { "Révoquer" }
                        } } }
                    }
                } }
            } } }
        }
    };
    page("Machines", "devices", Some(&auth.user), content).into_response()
}

pub async fn revoke_device(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Form(form): Form<CsrfForm>,
) -> Response {
    let auth = match admin(&state, &headers) {
        Ok(auth) => auth,
        Err(error) => return error.into_response(),
    };
    if let Err(error) = require_csrf(&auth, &form.csrf) {
        return error.into_response();
    }
    let result = state.store.update(|db| {
        ensure_active_admin(db, auth.user.id)?;
        let device = db
            .devices
            .get_mut(&id)
            .ok_or(AdminTargetError::DeviceNotFound)?;
        device.revoked = true;
        device.key_epoch = device.key_epoch.saturating_add(1);
        let mut closed_session_ids = Vec::new();
        for session in db
            .sessions
            .values_mut()
            .filter(|session| session.host_device_id == id)
        {
            session.closed_at = Some(now());
            closed_session_ids.push(session.id);
        }
        db.audit(
            auth.user.username,
            "device.revoke",
            id.to_string(),
            "success",
        );
        Ok(closed_session_ids)
    });
    match result {
        Ok(closed_session_ids) => {
            for session_id in closed_session_ids {
                state.relay_hub.cancel(session_id);
            }
            Redirect::to("/devices").into_response()
        }
        Err(error) => admin_action_error(error),
    }
}

pub async fn sessions(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let auth = match admin(&state, &headers) {
        Ok(auth) => auth,
        Err(error) => return error.into_response(),
    };
    let (sessions, devices) = state.store.read(|db| {
        (
            db.sessions.values().rev().cloned().collect::<Vec<_>>(),
            db.devices.clone(),
        )
    });
    let content = html! {
        (heading("Sessions", "Sessions autorisées et arrêt immédiat côté central."))
        section class="panel" {
            div class="panel-title" { h2 { "Historique récent" } span class="count" { (sessions.len()) " sessions" } }
            @if sessions.is_empty() { (empty_state("Aucune session", "Les connexions apparaîtront ici une fois autorisées.")) }
            @else { div class="table-wrap" { table {
                thead { tr { th { "Machine" } th { "Session" } th { "Capacités" } th { "État" } th { "Créée" } th { "Action" } } }
                tbody { @for session in sessions.iter().take(100) {
                    tr {
                        td { strong { (devices.get(&session.host_device_id).map(|device| device.name.as_str()).unwrap_or("Machine retirée")) } }
                        td class="mono short-id" { (&session.id.to_string()[..8]) }
                        td { @for cap in &session.capabilities { span class="cap" { (format!("{cap:?}")) } } }
                        td { (badge(session.active(), "Active", "Terminée")) }
                        td { (relative_time(Some(session.created_at))) }
                        td { @if session.active() { form method="post" action=(format!("/sessions/{}/close",session.id)) {
                            (csrf_input(&auth.csrf)) button class="danger-link" type="submit" { "Arrêter" }
                        } } }
                    }
                } }
            } } }
        }
    };
    page("Sessions", "sessions", Some(&auth.user), content).into_response()
}

pub async fn close_session_admin(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Form(form): Form<CsrfForm>,
) -> Response {
    let auth = match admin(&state, &headers) {
        Ok(auth) => auth,
        Err(error) => return error.into_response(),
    };
    if let Err(error) = require_csrf(&auth, &form.csrf) {
        return error.into_response();
    }
    let result = state.store.update(|db| {
        ensure_active_admin(db, auth.user.id)?;
        let session = db
            .sessions
            .get_mut(&id)
            .ok_or(AdminTargetError::SessionNotFound)?;
        session.closed_at = Some(now());
        db.audit(
            auth.user.username,
            "session.revoke",
            id.to_string(),
            "success",
        );
        Ok(())
    });
    match result {
        Ok(()) => {
            state.relay_hub.cancel(id);
            Redirect::to("/sessions").into_response()
        }
        Err(error) => admin_action_error(error),
    }
}

pub async fn users(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let auth = match admin(&state, &headers) {
        Ok(auth) => auth,
        Err(error) => return error.into_response(),
    };
    let users = state
        .store
        .read(|db| db.users.values().cloned().collect::<Vec<_>>());
    let content = html! {
        (heading("Utilisateurs", "Créez des comptes et retirez immédiatement leurs accès."))
        div class="two-column" {
            section class="panel" {
                div class="panel-title" { h2 { "Comptes" } span class="count" { (users.len()) " comptes" } }
                div class="table-wrap" { table {
                    thead { tr { th { "Utilisateur" } th { "Rôle" } th { "État" } th { "Action" } } }
                    tbody { @for user in &users {
                        tr {
                            td { strong { (&user.display_name) } small { (&user.username) } }
                            td { @if user.role == Role::Admin { "Administrateur" } @else { "Utilisateur" } }
                            td { (badge(user.enabled, "Actif", "Désactivé")) }
                            td {
                                a class="text-button" href=(format!("/users/{}/edit", user.id)) { "Modifier" }
                                form method="post" action=(format!("/users/{}/logout-all", user.id)) {
                                    (csrf_input(&auth.csrf))
                                    button class="text-button" type="submit" { "Sessions web" }
                                }
                                @if user.enabled && user.id != auth.user.id {
                                    form method="post" action=(format!("/users/{}/disable",user.id)) {
                                        (csrf_input(&auth.csrf)) button class="danger-link" type="submit" { "Désactiver" }
                                    }
                                }
                            }
                        }
                    } }
                } }
            }
            section class="panel form-panel" {
                h2 { "Ajouter un utilisateur" }
                p { "Choisissez un mot de passe d'au moins 16 caractères." }
                form method="post" action="/users" {
                    (csrf_input(&auth.csrf))
                    label for="username" { "Identifiant" }
                    input id="username" name="username" minlength="3" maxlength="48" pattern="[A-Za-z0-9_-]+" required autocomplete="off";
                    label for="display_name" { "Nom affiché" }
                    input id="display_name" name="display_name" maxlength="80" required;
                    label for="role" { "Rôle" }
                    select id="role" name="role" { option value="user" { "Utilisateur" } option value="admin" { "Administrateur" } }
                    label for="password" { "Mot de passe initial" }
                    input id="password" name="password" type="password" minlength="16" maxlength="256" required autocomplete="new-password";
                    button class="button primary" type="submit" { "Créer le compte" }
                }
            }
        }
    };
    page("Utilisateurs", "users", Some(&auth.user), content).into_response()
}

#[derive(Deserialize)]
pub struct CreateUserForm {
    csrf: String,
    username: String,
    display_name: String,
    role: String,
    password: String,
}

#[derive(Debug, Error)]
enum UserMutationError {
    #[error("utilisateur introuvable")]
    NotFound,
    #[error("identifiant déjà utilisé")]
    UsernameTaken,
    #[error("le dernier administrateur actif doit être conservé")]
    LastAdmin,
    #[error("le compte administrateur courant ne peut pas être désactivé ou rétrogradé")]
    CurrentAdmin,
    #[error("les droits administrateur du demandeur ont changé")]
    ActorNoLongerAdmin,
}

#[derive(Debug, Error)]
enum AdminTargetError {
    #[error("machine introuvable")]
    DeviceNotFound,
    #[error("session introuvable")]
    SessionNotFound,
}

fn ensure_active_admin(db: &crate::state::PersistentState, id: Uuid) -> anyhow::Result<()> {
    if db
        .users
        .get(&id)
        .is_some_and(|user| user.enabled && user.role == Role::Admin)
    {
        Ok(())
    } else {
        Err(UserMutationError::ActorNoLongerAdmin.into())
    }
}

fn user_mutation_error(error: anyhow::Error) -> Response {
    match error.downcast_ref::<UserMutationError>() {
        Some(UserMutationError::NotFound) => {
            (StatusCode::NOT_FOUND, "Utilisateur introuvable").into_response()
        }
        Some(UserMutationError::UsernameTaken) => {
            (StatusCode::CONFLICT, "Identifiant déjà utilisé").into_response()
        }
        Some(UserMutationError::LastAdmin) => (
            StatusCode::CONFLICT,
            "Conservez au moins un administrateur actif",
        )
            .into_response(),
        Some(UserMutationError::CurrentAdmin) => (
            StatusCode::FORBIDDEN,
            "Impossible de désactiver ou rétrograder votre compte",
        )
            .into_response(),
        Some(UserMutationError::ActorNoLongerAdmin) => (
            StatusCode::FORBIDDEN,
            "Vos droits administrateur ont changé",
        )
            .into_response(),
        None => ApiError::internal().into_response(),
    }
}

fn admin_action_error(error: anyhow::Error) -> Response {
    if let Some(target) = error.downcast_ref::<AdminTargetError>() {
        return match target {
            AdminTargetError::DeviceNotFound => {
                (StatusCode::NOT_FOUND, "Machine introuvable").into_response()
            }
            AdminTargetError::SessionNotFound => {
                (StatusCode::NOT_FOUND, "Session introuvable").into_response()
            }
        };
    }
    user_mutation_error(error)
}

fn valid_username(username: &str) -> bool {
    (3..=48).contains(&username.len())
        && username
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}

fn valid_display_name(display_name: &str) -> bool {
    !display_name.trim().is_empty()
        && display_name.chars().count() <= 80
        && !display_name.chars().any(char::is_control)
}

pub async fn create_user(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<CreateUserForm>,
) -> Response {
    let auth = match admin(&state, &headers) {
        Ok(auth) => auth,
        Err(error) => return error.into_response(),
    };
    if let Err(error) = require_csrf(&auth, &form.csrf) {
        return error.into_response();
    }
    let username = form.username.trim().to_lowercase();
    if !valid_username(&username)
        || !valid_display_name(&form.display_name)
        || form.password.len() < 16
        || form.password.len() > 256
    {
        return (StatusCode::BAD_REQUEST, "Champs utilisateur invalides").into_response();
    }
    let role = match form.role.as_str() {
        "admin" => Role::Admin,
        "user" => Role::User,
        _ => return (StatusCode::BAD_REQUEST, "Rôle invalide").into_response(),
    };
    let hash = match crate::api::hash_password_bounded(&state, form.password).await {
        Ok(hash) => hash,
        Err(error) => return error.into_response(),
    };
    let result = state.store.update(|db| {
        ensure_active_admin(db, auth.user.id)?;
        if db.users.values().any(|user| user.username == username) {
            return Err(UserMutationError::UsernameTaken.into());
        }
        let id = Uuid::new_v4();
        db.users.insert(
            id,
            User {
                id,
                username: username.clone(),
                display_name: form.display_name.trim().to_owned(),
                role,
                enabled: true,
                password_hash: hash,
                created_at: now(),
                revoked_at: 0,
            },
        );
        db.audit(
            auth.user.username,
            "account.create",
            id.to_string(),
            "success",
        );
        Ok(())
    });
    match result {
        Ok(()) => Redirect::to("/users").into_response(),
        Err(error) => user_mutation_error(error),
    }
}

pub async fn edit_user_page(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Response {
    let auth = match admin(&state, &headers) {
        Ok(auth) => auth,
        Err(error) => return error.into_response(),
    };
    let Some(target) = state.store.read(|db| db.users.get(&id).cloned()) else {
        return (StatusCode::NOT_FOUND, "Utilisateur introuvable").into_response();
    };
    let is_current = id == auth.user.id;
    let content = html! {
        (heading("Modifier un utilisateur", "Nom, rôle et état du compte."))
        section class="panel form-panel" {
            h2 { (&target.display_name) }
            form method="post" action=(format!("/users/{id}/edit")) {
                (csrf_input(&auth.csrf))
                label for="username" { "Identifiant" }
                input id="username" name="username" value=(&target.username) minlength="3" maxlength="48" pattern="[A-Za-z0-9_-]+" required autocomplete="off";
                label for="display_name" { "Nom affiché" }
                input id="display_name" name="display_name" value=(&target.display_name) maxlength="80" required;
                @if is_current {
                    p { "Votre compte administrateur actif ne peut pas être désactivé ou rétrogradé depuis cette session." }
                    input type="hidden" name="role" value="admin";
                    input type="hidden" name="enabled" value="true";
                } @else {
                    label for="role" { "Rôle" }
                    select id="role" name="role" {
                        option value="user" selected[target.role == Role::User] { "Utilisateur" }
                        option value="admin" selected[target.role == Role::Admin] { "Administrateur" }
                    }
                    label for="enabled" { "État" }
                    select id="enabled" name="enabled" {
                        option value="true" selected[target.enabled] { "Actif" }
                        option value="false" selected[!target.enabled] { "Désactivé" }
                    }
                }
                button class="button primary" type="submit" { "Enregistrer" }
            }
            form method="post" action=(format!("/users/{id}/logout-all")) {
                (csrf_input(&auth.csrf))
                button class="text-button" type="submit" { "Déconnecter toutes les sessions web" }
            }
            p { a href="/users" { "Retour aux utilisateurs" } }
        }
    };
    page(
        "Modifier un utilisateur",
        "users",
        Some(&auth.user),
        content,
    )
    .into_response()
}

#[derive(Deserialize)]
pub struct EditUserForm {
    csrf: String,
    username: String,
    display_name: String,
    role: String,
    enabled: String,
}

pub async fn update_user(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Form(form): Form<EditUserForm>,
) -> Response {
    let auth = match admin(&state, &headers) {
        Ok(auth) => auth,
        Err(error) => return error.into_response(),
    };
    if let Err(error) = require_csrf(&auth, &form.csrf) {
        return error.into_response();
    }
    let username = form.username.trim().to_lowercase();
    if !valid_username(&username) || !valid_display_name(&form.display_name) {
        return (StatusCode::BAD_REQUEST, "Nom ou identifiant invalide").into_response();
    }
    let role = match form.role.as_str() {
        "admin" => Role::Admin,
        "user" => Role::User,
        _ => return (StatusCode::BAD_REQUEST, "Rôle invalide").into_response(),
    };
    let enabled = match form.enabled.as_str() {
        "true" => true,
        "false" => false,
        _ => return (StatusCode::BAD_REQUEST, "État invalide").into_response(),
    };
    let display_name = form.display_name.trim().to_owned();
    let result = state.store.update(|db| {
        ensure_active_admin(db, auth.user.id)?;
        if db
            .users
            .values()
            .any(|user| user.id != id && user.username == username)
        {
            return Err(UserMutationError::UsernameTaken.into());
        }
        let target = db.users.get(&id).ok_or(UserMutationError::NotFound)?;
        if id == auth.user.id && (role != Role::Admin || !enabled) {
            return Err(UserMutationError::CurrentAdmin.into());
        }
        let active_admins = db
            .users
            .values()
            .filter(|user| user.enabled && user.role == Role::Admin)
            .count();
        if target.enabled
            && target.role == Role::Admin
            && (!enabled || role != Role::Admin)
            && active_admins <= 1
        {
            return Err(UserMutationError::LastAdmin.into());
        }
        let target = db.users.get_mut(&id).ok_or(UserMutationError::NotFound)?;
        let permissions_changed = target.enabled != enabled || target.role != role;
        target.username = username;
        target.display_name = display_name;
        target.role = role;
        target.enabled = enabled;
        if permissions_changed || !enabled {
            target.revoked_at = now();
            db.web_sessions.retain(|_, session| session.user_id != id);
        }
        db.audit(
            auth.user.username,
            "account.update",
            id.to_string(),
            "success",
        );
        Ok(())
    });
    match result {
        Ok(()) => Redirect::to("/users").into_response(),
        Err(error) => user_mutation_error(error),
    }
}

pub async fn logout_all_user_sessions(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Form(form): Form<CsrfForm>,
) -> Response {
    let auth = match admin(&state, &headers) {
        Ok(auth) => auth,
        Err(error) => return error.into_response(),
    };
    if let Err(error) = require_csrf(&auth, &form.csrf) {
        return error.into_response();
    }
    let result = state.store.update(|db| {
        ensure_active_admin(db, auth.user.id)?;
        if !db.users.contains_key(&id) {
            return Err(UserMutationError::NotFound.into());
        }
        db.web_sessions.retain(|_, session| session.user_id != id);
        db.audit(
            auth.user.username,
            "account.sessions.revoke",
            id.to_string(),
            "success",
        );
        Ok(())
    });
    if let Err(error) = result {
        return user_mutation_error(error);
    }
    if id == auth.user.id {
        let mut response = Redirect::to("/login").into_response();
        if let Ok(value) = set_cookie(
            session_cookie_name(state.secure_cookies),
            "",
            state.secure_cookies,
            0,
        )
        .parse()
        {
            response.headers_mut().append(header::SET_COOKIE, value);
        }
        response
    } else {
        Redirect::to("/users").into_response()
    }
}

pub async fn disable_user(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    Form(form): Form<CsrfForm>,
) -> Response {
    let auth = match admin(&state, &headers) {
        Ok(auth) => auth,
        Err(error) => return error.into_response(),
    };
    if let Err(error) = require_csrf(&auth, &form.csrf) {
        return error.into_response();
    }
    let result = state.store.update(|db| {
        ensure_active_admin(db, auth.user.id)?;
        if id == auth.user.id {
            return Err(UserMutationError::CurrentAdmin.into());
        }
        let active_admins = db
            .users
            .values()
            .filter(|user| user.enabled && user.role == Role::Admin)
            .count();
        let user = db.users.get_mut(&id).ok_or(UserMutationError::NotFound)?;
        if user.enabled && user.role == Role::Admin && active_admins <= 1 {
            return Err(UserMutationError::LastAdmin.into());
        }
        user.enabled = false;
        user.revoked_at = now();
        db.web_sessions.retain(|_, session| session.user_id != id);
        db.audit(
            auth.user.username,
            "account.disable",
            id.to_string(),
            "success",
        );
        Ok(())
    });
    match result {
        Ok(()) => Redirect::to("/users").into_response(),
        Err(error) => user_mutation_error(error),
    }
}

pub async fn audit(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    let auth = match admin(&state, &headers) {
        Ok(auth) => auth,
        Err(error) => return error.into_response(),
    };
    let events: Vec<AuditEvent> = state
        .store
        .read(|db| db.audit.iter().rev().take(200).cloned().collect());
    let content = html! {
        (heading("Journal de sécurité", "Événements d'accès et d'administration sans contenu utilisateur."))
        section class="panel" {
            @if events.is_empty() { (empty_state("Aucun événement", "Le journal sera alimenté par les opérations réelles.")) }
            @else { div class="table-wrap" { table {
                thead { tr { th { "Quand" } th { "Acteur" } th { "Action" } th { "Cible" } th { "Résultat" } } }
                tbody { @for event in events {
                    tr {
                        td { (relative_time(Some(event.at))) }
                        td { (&event.actor) }
                        td class="mono" { (&event.action) }
                        td class="mono" { (&event.target) }
                        td { (&event.outcome) }
                    }
                } }
            } } }
        }
    };
    page("Journal", "audit", Some(&auth.user), content).into_response()
}
