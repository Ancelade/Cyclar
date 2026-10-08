//! Wire contracts and host-verifiable session grants.
//!
//! Public keys are 32-byte Ed25519 keys encoded as unpadded base64url.
//! A grant is `cg1.<base64url claims>.<base64url Ed25519 signature>`.
//! The fixed-width claims encoding is defined below and is independent of
//! JSON field order, process architecture, and Serde implementation details.
//! Grants authenticate authorization only. A session must separately prove
//! possession of its endpoint keys and encrypt all session content end to end.

#![forbid(unsafe_code)]

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signature, Signer};
use serde::{Deserialize, Serialize};
use std::fmt;

pub use ed25519_dalek::{SigningKey, VerifyingKey};
pub use uuid::Uuid;

const GRANT_MAGIC: &[u8; 13] = b"CYCLAR-GRANT\x01";
const REGISTRATION_MAGIC: &[u8] = b"CYCLAR-DEVICE-REGISTRATION\x01";
const GRANT_PREFIX: &str = "cg1.";
const CLAIMS_LEN: usize = GRANT_MAGIC.len() + 16 + 16 + 32 + 2 + 8 + 8 + 16 + 8;
const MAX_GRANT_TOKEN_LEN: usize = 512;
const CAPABILITY_MASK: u16 = 0x00ff;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceRegistrationRequest {
    pub name: String,
    pub platform: String,
    pub public_key: String,
    /// Unpadded base64url Ed25519 signature proving possession of `public_key`.
    pub proof: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceRegistrationResponse {
    pub device_id: Uuid,
    pub alias: u64,
    pub temporary_password: String,
    pub device_token: String,
    pub server_public_key: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeartbeatRequest {
    pub listen_address: Option<String>,
    pub agent_version: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionRequest {
    pub alias: u64,
    pub password: String,
    pub controller_public_key: String,
    pub capabilities: Vec<Capability>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionResponse {
    pub session_id: Uuid,
    pub grant: String,
    /// Expiration of the signed grant, in Unix seconds.
    pub expires_at: u64,
    pub host_address: Option<String>,
    pub host_public_key: String,
    pub renewal_token: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionRenewalResponse {
    pub grant: String,
    pub expires_at: u64,
}

// These responses contain bearer secrets. Debug output must not disclose them.
impl fmt::Debug for DeviceRegistrationRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeviceRegistrationRequest")
            .field("name", &self.name)
            .field("platform", &self.platform)
            .field("public_key", &self.public_key)
            .field("proof", &"[REDACTED]")
            .finish()
    }
}

impl fmt::Debug for DeviceRegistrationResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeviceRegistrationResponse")
            .field("device_id", &self.device_id)
            .field("alias", &self.alias)
            .field("temporary_password", &"[REDACTED]")
            .field("device_token", &"[REDACTED]")
            .field("server_public_key", &self.server_public_key)
            .finish()
    }
}

impl fmt::Debug for SessionRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionRequest")
            .field("alias", &self.alias)
            .field("password", &"[REDACTED]")
            .field("controller_public_key", &self.controller_public_key)
            .field("capabilities", &self.capabilities)
            .finish()
    }
}

impl fmt::Debug for SessionResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionResponse")
            .field("session_id", &self.session_id)
            .field("grant", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .field("host_address", &self.host_address)
            .field("host_public_key", &self.host_public_key)
            .field("renewal_token", &"[REDACTED]")
            .finish()
    }
}

impl fmt::Debug for SessionRenewalResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionRenewalResponse")
            .field("grant", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Session capabilities are independent; a grant only permits listed actions.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    View,
    Input,
    ClipboardText,
    FileTransfer,
    SystemAudio,
    UsbForward,
    Elevate,
    SessionManage,
}

impl Capability {
    const ALL: [Self; 8] = [
        Self::View,
        Self::Input,
        Self::ClipboardText,
        Self::FileTransfer,
        Self::SystemAudio,
        Self::UsbForward,
        Self::Elevate,
        Self::SessionManage,
    ];

    const fn bit(self) -> u16 {
        match self {
            Self::View => 1 << 0,
            Self::Input => 1 << 1,
            Self::ClipboardText => 1 << 2,
            Self::FileTransfer => 1 << 3,
            Self::SystemAudio => 1 << 4,
            Self::UsbForward => 1 << 5,
            Self::Elevate => 1 << 6,
            Self::SessionManage => 1 << 7,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantClaims {
    pub session_id: Uuid,
    pub host_device_id: Uuid,
    pub controller_public_key: String,
    pub capabilities: Vec<Capability>,
    /// Seconds since the Unix epoch.
    pub issued_at: u64,
    /// Seconds since the Unix epoch; exclusive validity bound.
    pub expires_at: u64,
    pub nonce: Uuid,
    pub host_key_epoch: u64,
}

impl GrantClaims {
    pub fn allows(&self, capability: Capability) -> bool {
        self.capabilities.contains(&capability)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GrantError {
    InvalidToken,
    InvalidPublicKey,
    InvalidProof,
    InvalidClaims,
    InvalidSignature,
    WrongHost,
    WrongKeyEpoch,
    NotYetValid,
    Expired,
    MissingCapability,
}

impl fmt::Display for GrantError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidToken => "invalid grant token",
            Self::InvalidPublicKey => "invalid Ed25519 public key",
            Self::InvalidProof => "invalid device registration proof",
            Self::InvalidClaims => "invalid grant claims",
            Self::InvalidSignature => "invalid grant signature",
            Self::WrongHost => "grant is for another host",
            Self::WrongKeyEpoch => "grant uses another host key epoch",
            Self::NotYetValid => "grant is not yet valid",
            Self::Expired => "grant has expired",
            Self::MissingCapability => "grant lacks the required capability",
        })
    }
}

impl std::error::Error for GrantError {}

pub fn encode_public_key(key: &VerifyingKey) -> String {
    URL_SAFE_NO_PAD.encode(key.to_bytes())
}

pub fn decode_public_key(encoded: &str) -> Result<VerifyingKey, GrantError> {
    // A 32-byte unpadded base64url key has exactly 43 characters.
    if encoded.len() != 43 {
        return Err(GrantError::InvalidPublicKey);
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| GrantError::InvalidPublicKey)?;
    if URL_SAFE_NO_PAD.encode(&decoded) != encoded {
        return Err(GrantError::InvalidPublicKey);
    }
    let bytes: [u8; 32] = decoded
        .try_into()
        .map_err(|_| GrantError::InvalidPublicKey)?;
    let key = VerifyingKey::from_bytes(&bytes).map_err(|_| GrantError::InvalidPublicKey)?;
    if key.is_weak() {
        return Err(GrantError::InvalidPublicKey);
    }
    Ok(key)
}

/// Construct an enrollment request proving possession of the announced key.
///
/// The display name and platform bytes are signed exactly as provided. The
/// server must still apply its own input limits and output escaping.
pub fn sign_device_registration(
    signing_key: &SigningKey,
    name: &str,
    platform: &str,
) -> DeviceRegistrationRequest {
    let verifying_key = signing_key.verifying_key();
    let message = registration_message(name, platform, &verifying_key);
    let signature = signing_key.sign(&message);
    DeviceRegistrationRequest {
        name: name.to_owned(),
        platform: platform.to_owned(),
        public_key: encode_public_key(&verifying_key),
        proof: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
    }
}

/// Verify an enrollment request using only its announced public key.
///
/// This proves key possession, not permission to claim an existing device ID.
/// Re-enrollment must additionally check the registry's stored key or a
/// separately authorized recovery procedure.
pub fn verify_device_registration(
    request: &DeviceRegistrationRequest,
) -> Result<VerifyingKey, GrantError> {
    let key = decode_public_key(&request.public_key)?;
    if request.proof.len() != 86 {
        return Err(GrantError::InvalidProof);
    }
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(&request.proof)
        .map_err(|_| GrantError::InvalidProof)?;
    if signature_bytes.len() != 64 || URL_SAFE_NO_PAD.encode(&signature_bytes) != request.proof {
        return Err(GrantError::InvalidProof);
    }
    let signature =
        Signature::from_slice(&signature_bytes).map_err(|_| GrantError::InvalidProof)?;
    let message = registration_message(&request.name, &request.platform, &key);
    key.verify_strict(&message, &signature)
        .map_err(|_| GrantError::InvalidSignature)?;
    Ok(key)
}

fn registration_message(name: &str, platform: &str, public_key: &VerifyingKey) -> Vec<u8> {
    let name_bytes = name.as_bytes();
    let platform_bytes = platform.as_bytes();
    let mut message = Vec::new();
    message.extend_from_slice(REGISTRATION_MAGIC);
    message.extend_from_slice(&(name_bytes.len() as u64).to_be_bytes());
    message.extend_from_slice(name_bytes);
    message.extend_from_slice(&(platform_bytes.len() as u64).to_be_bytes());
    message.extend_from_slice(platform_bytes);
    message.extend_from_slice(public_key.as_bytes());
    message
}

/// Sign a canonical, versioned, fixed-width grant for a particular host.
pub fn sign_grant(claims: &GrantClaims, signing_key: &SigningKey) -> Result<String, GrantError> {
    let bytes = encode_claims(claims)?;
    let signature = signing_key.sign(&bytes);
    Ok(format!(
        "{GRANT_PREFIX}{}.{}",
        URL_SAFE_NO_PAD.encode(bytes),
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    ))
}

/// Verify signature, host audience, key epoch, and time before using a grant.
///
/// `now_unix_seconds` must come from a trustworthy local clock. The caller must
/// also ensure the controller proves possession of `controller_public_key` over
/// the encrypted session channel and must reject locally revoked sessions.
pub fn verify_grant(
    token: &str,
    verifying_key: &VerifyingKey,
    expected_host_device_id: Uuid,
    expected_host_key_epoch: u64,
    now_unix_seconds: u64,
) -> Result<GrantClaims, GrantError> {
    if token.len() > MAX_GRANT_TOKEN_LEN || verifying_key.is_weak() {
        return Err(GrantError::InvalidToken);
    }
    let body = token
        .strip_prefix(GRANT_PREFIX)
        .ok_or(GrantError::InvalidToken)?;
    let (claims_b64, signature_b64) = body.split_once('.').ok_or(GrantError::InvalidToken)?;
    if signature_b64.contains('.') {
        return Err(GrantError::InvalidToken);
    }
    let claims_bytes = URL_SAFE_NO_PAD
        .decode(claims_b64)
        .map_err(|_| GrantError::InvalidToken)?;
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(signature_b64)
        .map_err(|_| GrantError::InvalidToken)?;
    if claims_bytes.len() != CLAIMS_LEN
        || signature_bytes.len() != 64
        || URL_SAFE_NO_PAD.encode(&claims_bytes) != claims_b64
        || URL_SAFE_NO_PAD.encode(&signature_bytes) != signature_b64
    {
        return Err(GrantError::InvalidToken);
    }
    let signature =
        Signature::from_slice(&signature_bytes).map_err(|_| GrantError::InvalidToken)?;
    verifying_key
        .verify_strict(&claims_bytes, &signature)
        .map_err(|_| GrantError::InvalidSignature)?;
    let claims = decode_claims(&claims_bytes)?;
    if claims.host_device_id != expected_host_device_id {
        return Err(GrantError::WrongHost);
    }
    if claims.host_key_epoch != expected_host_key_epoch {
        return Err(GrantError::WrongKeyEpoch);
    }
    if now_unix_seconds < claims.issued_at {
        return Err(GrantError::NotYetValid);
    }
    if now_unix_seconds >= claims.expires_at {
        return Err(GrantError::Expired);
    }
    Ok(claims)
}

/// Verify the grant and require one specific capability for an action.
pub fn verify_grant_capability(
    token: &str,
    verifying_key: &VerifyingKey,
    expected_host_device_id: Uuid,
    expected_host_key_epoch: u64,
    now_unix_seconds: u64,
    required: Capability,
) -> Result<GrantClaims, GrantError> {
    let claims = verify_grant(
        token,
        verifying_key,
        expected_host_device_id,
        expected_host_key_epoch,
        now_unix_seconds,
    )?;
    if !claims.allows(required) {
        return Err(GrantError::MissingCapability);
    }
    Ok(claims)
}

// V1 canonical claim encoding:
// magic/version[13] | session UUID[16] | host UUID[16] |
// controller Ed25519 public key[32] | capability bitmask BE[2] |
// issued_at BE[8] | expires_at BE[8] | nonce UUID[16] |
// host_key_epoch BE[8]. No variable-length or architecture-native fields.
fn encode_claims(claims: &GrantClaims) -> Result<[u8; CLAIMS_LEN], GrantError> {
    if claims.session_id.is_nil()
        || claims.host_device_id.is_nil()
        || claims.nonce.is_nil()
        || claims.expires_at <= claims.issued_at
        || claims.capabilities.is_empty()
    {
        return Err(GrantError::InvalidClaims);
    }
    let controller_key = decode_public_key(&claims.controller_public_key)?;
    let mut capabilities = 0u16;
    for capability in &claims.capabilities {
        let bit = capability.bit();
        if capabilities & bit != 0 {
            return Err(GrantError::InvalidClaims);
        }
        capabilities |= bit;
    }
    let mut output = [0u8; CLAIMS_LEN];
    let mut cursor = 0usize;
    for chunk in [
        GRANT_MAGIC.as_slice(),
        claims.session_id.as_bytes(),
        claims.host_device_id.as_bytes(),
        controller_key.as_bytes(),
        &capabilities.to_be_bytes(),
        &claims.issued_at.to_be_bytes(),
        &claims.expires_at.to_be_bytes(),
        claims.nonce.as_bytes(),
        &claims.host_key_epoch.to_be_bytes(),
    ] {
        output[cursor..cursor + chunk.len()].copy_from_slice(chunk);
        cursor += chunk.len();
    }
    Ok(output)
}

fn decode_claims(bytes: &[u8]) -> Result<GrantClaims, GrantError> {
    if bytes.len() != CLAIMS_LEN || !bytes.starts_with(GRANT_MAGIC) {
        return Err(GrantError::InvalidClaims);
    }
    let mut cursor = GRANT_MAGIC.len();
    let session_id = Uuid::from_bytes(take::<16>(bytes, &mut cursor)?);
    let host_device_id = Uuid::from_bytes(take::<16>(bytes, &mut cursor)?);
    let controller_key_bytes = take::<32>(bytes, &mut cursor)?;
    let controller_key = VerifyingKey::from_bytes(&controller_key_bytes)
        .map_err(|_| GrantError::InvalidPublicKey)?;
    if controller_key.is_weak() {
        return Err(GrantError::InvalidPublicKey);
    }
    let bits = u16::from_be_bytes(take::<2>(bytes, &mut cursor)?);
    if bits == 0 || bits & !CAPABILITY_MASK != 0 {
        return Err(GrantError::InvalidClaims);
    }
    let capabilities = Capability::ALL
        .into_iter()
        .filter(|capability| bits & capability.bit() != 0)
        .collect();
    let issued_at = u64::from_be_bytes(take::<8>(bytes, &mut cursor)?);
    let expires_at = u64::from_be_bytes(take::<8>(bytes, &mut cursor)?);
    let nonce = Uuid::from_bytes(take::<16>(bytes, &mut cursor)?);
    let host_key_epoch = u64::from_be_bytes(take::<8>(bytes, &mut cursor)?);
    if session_id.is_nil() || host_device_id.is_nil() || nonce.is_nil() || expires_at <= issued_at {
        return Err(GrantError::InvalidClaims);
    }
    Ok(GrantClaims {
        session_id,
        host_device_id,
        controller_public_key: encode_public_key(&controller_key),
        capabilities,
        issued_at,
        expires_at,
        nonce,
        host_key_epoch,
    })
}

fn take<const N: usize>(bytes: &[u8], cursor: &mut usize) -> Result<[u8; N], GrantError> {
    let end = cursor.checked_add(N).ok_or(GrantError::InvalidClaims)?;
    let range = bytes.get(*cursor..end).ok_or(GrantError::InvalidClaims)?;
    *cursor = end;
    range.try_into().map_err(|_| GrantError::InvalidClaims)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (SigningKey, GrantClaims) {
        let server = SigningKey::from_bytes(&[7; 32]);
        let controller = SigningKey::from_bytes(&[9; 32]);
        let claims = GrantClaims {
            session_id: Uuid::from_u128(1),
            host_device_id: Uuid::from_u128(2),
            controller_public_key: encode_public_key(&controller.verifying_key()),
            capabilities: vec![Capability::View, Capability::Input],
            issued_at: 1_000,
            expires_at: 1_030,
            nonce: Uuid::from_u128(3),
            host_key_epoch: 4,
        };
        (server, claims)
    }

    #[test]
    fn registration_proof_binds_identity_and_metadata() {
        let owner = SigningKey::from_bytes(&[13; 32]);
        let imposter = SigningKey::from_bytes(&[14; 32]);
        let request = sign_device_registration(&owner, "Poste atelier", "linux");
        assert_eq!(
            verify_device_registration(&request),
            Ok(owner.verifying_key())
        );
        assert_eq!(
            serde_json::to_value(&request).unwrap()["proof"],
            request.proof
        );
        assert!(!format!("{request:?}").contains(&request.proof));

        let mut changed = request.clone();
        changed.name = "Autre poste".into();
        assert_eq!(
            verify_device_registration(&changed),
            Err(GrantError::InvalidSignature)
        );
        changed = request.clone();
        changed.platform = "windows".into();
        assert_eq!(
            verify_device_registration(&changed),
            Err(GrantError::InvalidSignature)
        );
        changed = request.clone();
        changed.public_key = encode_public_key(&imposter.verifying_key());
        assert_eq!(
            verify_device_registration(&changed),
            Err(GrantError::InvalidSignature)
        );
        changed = request.clone();
        changed.proof.replace_range(..1, "!");
        assert_eq!(
            verify_device_registration(&changed),
            Err(GrantError::InvalidProof)
        );
    }

    #[test]
    fn stable_wire_names() {
        assert_eq!(
            serde_json::to_string(&Capability::ClipboardText).unwrap(),
            "\"clipboard_text\""
        );
        let request = SessionRequest {
            alias: 123,
            password: "secret".into(),
            controller_public_key: "public".into(),
            capabilities: vec![Capability::View],
        };
        let json = serde_json::to_value(&request).unwrap();
        assert_eq!(json["controller_public_key"], "public");
        assert_eq!(json["capabilities"][0], "view");
        assert!(!format!("{request:?}").contains("secret"));
    }

    #[test]
    fn signed_grant_roundtrip_and_capability() {
        let (server, claims) = fixture();
        let grant = sign_grant(&claims, &server).unwrap();
        let verified = verify_grant_capability(
            &grant,
            &server.verifying_key(),
            claims.host_device_id,
            claims.host_key_epoch,
            1_010,
            Capability::Input,
        )
        .unwrap();
        assert_eq!(verified, claims);
        assert_eq!(sign_grant(&claims, &server).unwrap(), grant);
        assert_eq!(
            verify_grant_capability(
                &grant,
                &server.verifying_key(),
                claims.host_device_id,
                claims.host_key_epoch,
                1_010,
                Capability::Elevate,
            ),
            Err(GrantError::MissingCapability)
        );
    }

    #[test]
    fn tampered_claim_or_signature_is_rejected() {
        let (server, claims) = fixture();
        let grant = sign_grant(&claims, &server).unwrap();
        let body = grant.strip_prefix(GRANT_PREFIX).unwrap();
        let (claims_b64, signature_b64) = body.split_once('.').unwrap();
        let mut payload = URL_SAFE_NO_PAD.decode(claims_b64).unwrap();
        payload[GRANT_MAGIC.len() + 1] ^= 1;
        let tampered_claims = format!(
            "{GRANT_PREFIX}{}.{}",
            URL_SAFE_NO_PAD.encode(payload),
            signature_b64
        );
        assert_eq!(
            verify_grant(
                &tampered_claims,
                &server.verifying_key(),
                claims.host_device_id,
                4,
                1_010
            ),
            Err(GrantError::InvalidSignature)
        );
        let mut signature = URL_SAFE_NO_PAD.decode(signature_b64).unwrap();
        signature[0] ^= 1;
        let tampered_signature = format!(
            "{GRANT_PREFIX}{claims_b64}.{}",
            URL_SAFE_NO_PAD.encode(signature)
        );
        assert_eq!(
            verify_grant(
                &tampered_signature,
                &server.verifying_key(),
                claims.host_device_id,
                4,
                1_010
            ),
            Err(GrantError::InvalidSignature)
        );
    }

    #[test]
    fn audience_epoch_and_time_are_enforced() {
        let (server, claims) = fixture();
        let grant = sign_grant(&claims, &server).unwrap();
        let key = server.verifying_key();
        assert_eq!(
            verify_grant(&grant, &key, Uuid::from_u128(99), 4, 1_010),
            Err(GrantError::WrongHost)
        );
        assert_eq!(
            verify_grant(&grant, &key, claims.host_device_id, 5, 1_010),
            Err(GrantError::WrongKeyEpoch)
        );
        assert_eq!(
            verify_grant(&grant, &key, claims.host_device_id, 4, 999),
            Err(GrantError::NotYetValid)
        );
        assert_eq!(
            verify_grant(&grant, &key, claims.host_device_id, 4, 1_030),
            Err(GrantError::Expired)
        );
    }

    #[test]
    fn invalid_claims_and_redacted_secrets() {
        let (server, mut claims) = fixture();
        claims.capabilities.push(Capability::View);
        assert_eq!(sign_grant(&claims, &server), Err(GrantError::InvalidClaims));
        let response = SessionResponse {
            session_id: claims.session_id,
            grant: "grant-secret".into(),
            expires_at: 1_030,
            host_address: None,
            host_public_key: "public".into(),
            renewal_token: "renewal-secret".into(),
        };
        let debug = format!("{response:?}");
        assert!(!debug.contains("grant-secret"));
        assert!(!debug.contains("renewal-secret"));
        assert!(serde_json::to_value(&response)
            .unwrap()
            .get("renewal_token")
            .is_some());
    }
}
