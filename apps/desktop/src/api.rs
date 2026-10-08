use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use cyclar_protocol::{
    DeviceRegistrationRequest, DeviceRegistrationResponse, HeartbeatRequest,
    SessionRenewalResponse, SessionRequest, SessionResponse,
};
use reqwest::{blocking::Client, StatusCode, Url};
use serde::de::DeserializeOwned;
use uuid::Uuid;

#[derive(Clone)]
pub struct CentralApi {
    base: Url,
    http: Client,
}

impl CentralApi {
    pub fn new(base: &str) -> Result<Self> {
        let mut url = Url::parse(base).context("invalid server URL")?;
        if url.query().is_some() || url.fragment().is_some() {
            bail!("server URL must not contain a query or fragment");
        }
        if !url.username().is_empty() || url.password().is_some() {
            bail!("server URL must not embed credentials");
        }
        match url.scheme() {
            "https" => {}
            "http" if matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "::1")) => {}
            "http" => bail!("HTTP is allowed only for a loopback development server; use HTTPS"),
            _ => bail!("server URL must use HTTPS"),
        }
        if !url.path().ends_with('/') {
            let path = format!("{}/", url.path());
            url.set_path(&path);
        }
        let http = Client::builder().timeout(Duration::from_secs(10)).build()?;
        Ok(Self { base: url, http })
    }

    fn endpoint(&self, path: &str) -> Result<Url> {
        self.base.join(path).context("invalid API endpoint")
    }

    pub fn relay_url(&self, session_id: Uuid, role: &str) -> Result<String> {
        if role != "host" && role != "controller" {
            bail!("invalid relay role");
        }
        let mut url = self.endpoint(&format!("api/v1/relay/{session_id}/{role}"))?;
        let scheme = if self.base.scheme() == "https" {
            "wss"
        } else {
            "ws"
        };
        url.set_scheme(scheme)
            .map_err(|_| anyhow!("invalid relay scheme"))?;
        Ok(url.to_string())
    }

    fn response<T: DeserializeOwned>(response: reqwest::blocking::Response) -> Result<T> {
        let status = response.status();
        if !status.is_success() {
            // The server deliberately uses structured, non-secret error messages.
            let body = response.text().unwrap_or_default();
            let message = serde_json::from_str::<serde_json::Value>(&body)
                .ok()
                .and_then(|value| {
                    value
                        .get("message")
                        .and_then(|value| value.as_str())
                        .map(str::to_owned)
                })
                .unwrap_or_else(|| {
                    status
                        .canonical_reason()
                        .unwrap_or("request failed")
                        .to_owned()
                });
            bail!("server returned {status}: {message}");
        }
        response.json().context("invalid server response")
    }

    pub fn register(
        &self,
        request: &DeviceRegistrationRequest,
    ) -> Result<DeviceRegistrationResponse> {
        let response = self
            .http
            .post(self.endpoint("api/v1/devices")?)
            .json(request)
            .send()
            .context("device registration failed")?;
        Self::response(response)
    }

    pub fn heartbeat(
        &self,
        device_id: Uuid,
        device_token: &str,
        listen_address: Option<&str>,
    ) -> Result<()> {
        let response = self
            .http
            .post(self.endpoint(&format!("api/v1/devices/{device_id}/heartbeat"))?)
            .bearer_auth(device_token)
            .json(&HeartbeatRequest {
                listen_address: listen_address.map(str::to_owned),
                agent_version: env!("CARGO_PKG_VERSION").to_owned(),
            })
            .send()
            .context("heartbeat failed")?;
        if response.status() == StatusCode::NO_CONTENT || response.status().is_success() {
            Ok(())
        } else {
            let status = response.status();
            Err(anyhow!("heartbeat rejected: {status}"))
        }
    }

    pub fn request_session(&self, request: &SessionRequest) -> Result<SessionResponse> {
        let response = self
            .http
            .post(self.endpoint("api/v1/sessions/request")?)
            .json(request)
            .send()
            .context("session request failed")?;
        Self::response(response)
    }

    pub fn renew_session(
        &self,
        session_id: Uuid,
        renewal_token: &str,
    ) -> Result<SessionRenewalResponse> {
        let response = self
            .http
            .post(self.endpoint(&format!("api/v1/sessions/{session_id}/renew"))?)
            .bearer_auth(renewal_token)
            .send()
            .context("session renewal failed")?;
        Self::response(response)
    }

    pub fn close_session(&self, session_id: Uuid, renewal_token: &str) -> Result<()> {
        let response = self
            .http
            .delete(self.endpoint(&format!("api/v1/sessions/{session_id}"))?)
            .bearer_auth(renewal_token)
            .send()
            .context("session closure failed")?;
        if response.status().is_success() {
            Ok(())
        } else {
            bail!("server rejected session closure: {}", response.status())
        }
    }

    pub fn active_sessions(&self, device_id: Uuid, device_token: &str) -> Result<Vec<Uuid>> {
        #[derive(serde::Deserialize)]
        struct ActiveSessions {
            active_session_ids: Vec<Uuid>,
        }
        let response = self
            .http
            .get(self.endpoint(&format!("api/v1/devices/{device_id}/sessions"))?)
            .bearer_auth(device_token)
            .send()
            .context("session status failed")?;
        Ok(Self::response::<ActiveSessions>(response)?.active_session_ids)
    }

    pub fn rotate_temporary_password(&self, device_id: Uuid, device_token: &str) -> Result<String> {
        #[derive(serde::Deserialize)]
        struct Rotated {
            temporary_password: String,
        }
        let response = self
            .http
            .post(self.endpoint(&format!(
                "api/v1/devices/{device_id}/rotate-temporary-password"
            ))?)
            .bearer_auth(device_token)
            .send()
            .context("temporary password rotation failed")?;
        Ok(Self::response::<Rotated>(response)?.temporary_password)
    }

    pub fn set_permanent_password(
        &self,
        device_id: Uuid,
        device_token: &str,
        password: Option<&str>,
    ) -> Result<()> {
        let response = self
            .http
            .post(self.endpoint(&format!("api/v1/devices/{device_id}/permanent-password"))?)
            .bearer_auth(device_token)
            .json(&serde_json::json!({"password": password}))
            .send()
            .context("permanent password update failed")?;
        if response.status().is_success() {
            Ok(())
        } else {
            bail!(
                "server rejected permanent password update: {}",
                response.status()
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_plaintext_remote_server() {
        assert!(CentralApi::new("http://example.net:8080").is_err());
        assert!(CentralApi::new("http://127.0.0.1:8080").is_ok());
        assert!(CentralApi::new("https://example.net").is_ok());
    }

    #[test]
    fn relay_url_keeps_server_path_and_uses_websocket_tls() {
        let api = CentralApi::new("https://example.net/cyclar/").unwrap();
        let url = api.relay_url(Uuid::nil(), "host").unwrap();
        assert_eq!(
            url,
            "wss://example.net/cyclar/api/v1/relay/00000000-0000-0000-0000-000000000000/host"
        );
        assert!(api.relay_url(Uuid::nil(), "other").is_err());
    }
}
