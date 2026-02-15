use std::collections::BTreeMap;

use async_trait::async_trait;
use reqwest::StatusCode;
use sha2::{Digest, Sha256};
use tokio::time::{timeout, Duration};

use crate::audit::AuditEventRecord;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WebhookDeliveryState {
    pub delivered: bool,
    pub attempts: u8,
    pub last_status_code: Option<u16>,
    pub last_error: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WebhookSinkConfig {
    pub url: String,
    pub signing_secret: String,
    pub max_retries: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DeliveryErrorCode {
    TransportError,
    Timeout,
}

impl DeliveryErrorCode {
    fn as_str(self) -> &'static str {
        match self {
            DeliveryErrorCode::TransportError => "transport_error",
            DeliveryErrorCode::Timeout => "timeout",
        }
    }
}

const WEBHOOK_REQUEST_TIMEOUT_MS: u64 = 1500;

pub fn webhook_sink_from_env() -> Option<WebhookSinkConfig> {
    let url = std::env::var("AUDIT_EVENTS_WEBHOOK_URL").ok()?;
    let signing_secret = std::env::var("AUDIT_EVENTS_WEBHOOK_SECRET").ok()?;
    let max_retries = std::env::var("AUDIT_EVENTS_WEBHOOK_MAX_RETRIES")
        .ok()
        .and_then(|v| v.parse::<u8>().ok())
        .unwrap_or(2);

    Some(WebhookSinkConfig {
        url,
        signing_secret,
        max_retries,
    })
}

pub async fn deliver_with_retries(
    event: &AuditEventRecord,
    config: &WebhookSinkConfig,
) -> WebhookDeliveryState {
    let transport = ReqwestWebhookTransport::new();
    deliver_with_transport(event, config, &transport).await
}

pub fn delivery_metadata(state: &WebhookDeliveryState) -> BTreeMap<String, String> {
    let mut metadata = BTreeMap::new();
    metadata.insert("webhook_delivered".to_string(), state.delivered.to_string());
    metadata.insert("webhook_attempts".to_string(), state.attempts.to_string());
    if let Some(status) = state.last_status_code {
        metadata.insert("webhook_last_status".to_string(), status.to_string());
    }
    if let Some(error) = &state.last_error {
        metadata.insert("webhook_last_error".to_string(), error.clone());
    }
    metadata
}

fn signature_header_value(secret: &str, payload: &str) -> String {
    format!(
        "sha256={}",
        hmac_sha256_hex(secret.as_bytes(), payload.as_bytes())
    )
}

fn hmac_sha256_hex(key: &[u8], data: &[u8]) -> String {
    const BLOCK_SIZE: usize = 64;

    let mut key_block = [0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        let digest = Sha256::digest(key);
        key_block[..digest.len()].copy_from_slice(&digest);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    let mut o_key_pad = [0u8; BLOCK_SIZE];
    let mut i_key_pad = [0u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        o_key_pad[i] = key_block[i] ^ 0x5c;
        i_key_pad[i] = key_block[i] ^ 0x36;
    }

    let mut inner = Sha256::new();
    inner.update(i_key_pad);
    inner.update(data);
    let inner_hash = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(o_key_pad);
    outer.update(inner_hash);
    hex::encode(outer.finalize())
}

#[async_trait]
trait WebhookTransport {
    async fn send(
        &self,
        url: &str,
        payload: &str,
        signature: &str,
    ) -> Result<u16, DeliveryErrorCode>;
}

struct ReqwestWebhookTransport {
    client: reqwest::Client,
}

impl ReqwestWebhookTransport {
    fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
        }
    }
}

#[async_trait]
impl WebhookTransport for ReqwestWebhookTransport {
    async fn send(
        &self,
        url: &str,
        payload: &str,
        signature: &str,
    ) -> Result<u16, DeliveryErrorCode> {
        let request = self
            .client
            .post(url)
            .header("content-type", "application/json")
            .header("x-ericauth-signature", signature)
            .body(payload.to_string());

        let response = match timeout(
            Duration::from_millis(WEBHOOK_REQUEST_TIMEOUT_MS),
            request.send(),
        )
        .await
        {
            Ok(Ok(response)) => response,
            Ok(Err(error)) => {
                if error.is_timeout() {
                    return Err(DeliveryErrorCode::Timeout);
                }

                return Err(DeliveryErrorCode::TransportError);
            }
            Err(_) => return Err(DeliveryErrorCode::Timeout),
        };

        Ok(response.status().as_u16())
    }
}

async fn deliver_with_transport<T: WebhookTransport + Sync>(
    event: &AuditEventRecord,
    config: &WebhookSinkConfig,
    transport: &T,
) -> WebhookDeliveryState {
    let payload = match serde_json::to_string(event) {
        Ok(payload) => payload,
        Err(e) => {
            return WebhookDeliveryState {
                delivered: false,
                attempts: 0,
                last_status_code: None,
                last_error: Some(format!("serialization_error:{e}")),
            }
        }
    };
    let signature = signature_header_value(&config.signing_secret, &payload);
    let max_attempts = config.max_retries.saturating_add(1);

    for attempt in 1..=max_attempts {
        match transport.send(&config.url, &payload, &signature).await {
            Ok(status) if StatusCode::from_u16(status).is_ok_and(|v| v.is_success()) => {
                return WebhookDeliveryState {
                    delivered: true,
                    attempts: attempt,
                    last_status_code: Some(status),
                    last_error: None,
                }
            }
            Ok(status) if StatusCode::from_u16(status).is_ok_and(|v| v.is_client_error()) => {
                return WebhookDeliveryState {
                    delivered: false,
                    attempts: attempt,
                    last_status_code: Some(status),
                    last_error: Some("client_error".to_string()),
                }
            }
            Ok(status) => {
                if attempt == max_attempts {
                    return WebhookDeliveryState {
                        delivered: false,
                        attempts: attempt,
                        last_status_code: Some(status),
                        last_error: Some("server_error".to_string()),
                    };
                }
            }
            Err(error) => {
                if attempt == max_attempts {
                    return WebhookDeliveryState {
                        delivered: false,
                        attempts: attempt,
                        last_status_code: None,
                        last_error: Some(error.as_str().to_string()),
                    };
                }
            }
        }
    }

    WebhookDeliveryState {
        delivered: false,
        attempts: max_attempts,
        last_status_code: None,
        last_error: Some("retry_exhausted".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::atomic::{AtomicUsize, Ordering};

    struct FlakyTransport {
        attempts: AtomicUsize,
    }

    struct AlwaysTransportError;

    #[async_trait]
    impl WebhookTransport for AlwaysTransportError {
        async fn send(
            &self,
            _url: &str,
            _payload: &str,
            _signature: &str,
        ) -> Result<u16, DeliveryErrorCode> {
            Err(DeliveryErrorCode::TransportError)
        }
    }

    struct TimeoutThenSuccessTransport {
        attempts: AtomicUsize,
    }

    #[async_trait]
    impl WebhookTransport for TimeoutThenSuccessTransport {
        async fn send(
            &self,
            _url: &str,
            _payload: &str,
            _signature: &str,
        ) -> Result<u16, DeliveryErrorCode> {
            let attempt = self.attempts.fetch_add(1, Ordering::SeqCst);
            if attempt == 0 {
                return Err(DeliveryErrorCode::Timeout);
            }

            Ok(202)
        }
    }

    #[async_trait]
    impl WebhookTransport for FlakyTransport {
        async fn send(
            &self,
            _url: &str,
            _payload: &str,
            signature: &str,
        ) -> Result<u16, DeliveryErrorCode> {
            assert!(signature.starts_with("sha256="));
            assert_eq!(signature.len(), 71);

            let attempt = self.attempts.fetch_add(1, Ordering::SeqCst);
            if attempt < 2 {
                return Ok(500);
            }

            Ok(202)
        }
    }

    fn sample_event() -> AuditEventRecord {
        AuditEventRecord {
            id: "evt_123".to_string(),
            event_type: "auth.login".to_string(),
            outcome: "success".to_string(),
            actor: Some("user@example.com".to_string()),
            client_ip: Some("127.0.0.1".to_string()),
            user_agent: Some("test-agent".to_string()),
            created_at: "2026-02-14T00:00:00Z".to_string(),
            metadata: BTreeMap::new(),
        }
    }

    #[test]
    fn test_signature_header_is_hmac_sha256() {
        let payload = "{\"id\":\"evt_123\"}";
        let signature = signature_header_value("secret", payload);
        assert_eq!(
            signature,
            "sha256=74f0752302e330522929ca247951d6b7a29cd88f2bfe8851d1181f2c7e0c42d1"
        );
    }

    #[tokio::test]
    async fn test_delivery_retries_failed_attempts_then_succeeds() {
        let event = sample_event();
        let config = WebhookSinkConfig {
            url: "https://siem.example.com/hooks/audit".to_string(),
            signing_secret: "secret".to_string(),
            max_retries: 2,
        };
        let transport = FlakyTransport {
            attempts: AtomicUsize::new(0),
        };

        let state = deliver_with_transport(&event, &config, &transport).await;

        assert!(state.delivered);
        assert_eq!(state.attempts, 3);
        assert_eq!(state.last_status_code, Some(202));
        assert_eq!(state.last_error, None);
    }

    #[tokio::test]
    async fn test_delivery_metadata_sanitizes_transport_error_details() {
        let event = sample_event();
        let config = WebhookSinkConfig {
            url: "https://siem.example.com/hooks/audit".to_string(),
            signing_secret: "secret".to_string(),
            max_retries: 1,
        };
        let transport = AlwaysTransportError;

        let state = deliver_with_transport(&event, &config, &transport).await;
        let metadata = delivery_metadata(&state);

        assert!(!state.delivered);
        assert_eq!(state.attempts, 2);
        assert_eq!(
            metadata.get("webhook_last_error").map(String::as_str),
            Some("transport_error")
        );
    }

    #[tokio::test]
    async fn test_delivery_retries_timeout_then_succeeds() {
        let event = sample_event();
        let config = WebhookSinkConfig {
            url: "https://siem.example.com/hooks/audit".to_string(),
            signing_secret: "secret".to_string(),
            max_retries: 2,
        };
        let transport = TimeoutThenSuccessTransport {
            attempts: AtomicUsize::new(0),
        };

        let state = deliver_with_transport(&event, &config, &transport).await;

        assert!(state.delivered);
        assert_eq!(state.attempts, 2);
        assert_eq!(state.last_status_code, Some(202));
        assert_eq!(state.last_error, None);
    }
}
