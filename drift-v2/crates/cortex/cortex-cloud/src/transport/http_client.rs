//! HTTP client with retry, exponential backoff, timeout, and gzip compression.

use std::time::Duration;

use cortex_core::errors::{CloudError, CortexError, CortexResult};
use serde::{de::DeserializeOwned, Serialize};

use super::protocol::{CloudRequest, CloudResponse};

/// Configuration for the HTTP transport layer.
#[derive(Debug, Clone)]
pub struct HttpClientConfig {
    /// Base URL of the cloud API.
    pub base_url: String,
    /// Request timeout.
    pub timeout: Duration,
    /// Maximum number of retry attempts.
    pub max_retries: u32,
    /// Initial backoff duration (doubles each retry).
    pub initial_backoff: Duration,
    /// Maximum backoff duration.
    pub max_backoff: Duration,
}

impl Default for HttpClientConfig {
    fn default() -> Self {
        Self {
            base_url: String::new(),
            timeout: Duration::from_secs(30),
            max_retries: 3,
            initial_backoff: Duration::from_millis(500),
            max_backoff: Duration::from_secs(30),
        }
    }
}

/// Convert a string into a CloudError::NetworkError.
fn net_err(reason: String) -> CortexError {
    CloudError::NetworkError { reason }.into()
}

/// HTTP transport client. Wraps reqwest (when the `cloud` feature is
/// enabled) with retry logic and backoff.
#[derive(Debug)]
pub struct HttpClient {
    config: HttpClientConfig,
    bearer_token: Option<String>,
}

impl HttpClient {
    pub fn new(config: HttpClientConfig) -> Self {
        Self {
            config,
            bearer_token: None,
        }
    }

    /// Set the bearer token for authenticated requests.
    pub fn set_bearer_token(&mut self, token: String) {
        self.bearer_token = Some(token);
    }

    /// Clear the bearer token.
    pub fn clear_bearer_token(&mut self) {
        self.bearer_token = None;
    }

    /// POST a request with retry and backoff.
    pub fn post<Req: Serialize, Resp: DeserializeOwned>(
        &self,
        path: &str,
        payload: &Req,
    ) -> CortexResult<CloudResponse<Resp>> {
        let _request = CloudRequest::new(payload);
        let _url = format!("{}{}", self.config.base_url, path);

        #[cfg(feature = "cloud")]
        {
            self.do_request::<Resp>(reqwest::Method::POST, &_url, Some(&_request))
        }

        #[cfg(not(feature = "cloud"))]
        {
            Err(net_err("cloud feature not enabled".into()))
        }
    }

    /// GET a resource with retry and backoff.
    pub fn get<Resp: DeserializeOwned>(&self, path: &str) -> CortexResult<CloudResponse<Resp>> {
        let _url = format!("{}{}", self.config.base_url, path);

        #[cfg(feature = "cloud")]
        {
            self.do_request::<Resp>(reqwest::Method::GET, &_url, None::<&()>)
        }

        #[cfg(not(feature = "cloud"))]
        {
            Err(net_err("cloud feature not enabled".into()))
        }
    }

    /// Unified retry loop for any HTTP method.
    #[cfg(feature = "cloud")]
    fn do_request<Resp: DeserializeOwned>(
        &self,
        method: reqwest::Method,
        url: &str,
        body: Option<&impl Serialize>,
    ) -> CortexResult<CloudResponse<Resp>> {
        let client = reqwest::blocking::Client::builder()
            .timeout(self.config.timeout)
            .gzip(true)
            .build()
            .map_err(|e: reqwest::Error| net_err(e.to_string()))?;

        let mut backoff = self.config.initial_backoff;
        let mut last_err = String::new();

        for attempt in 0..=self.config.max_retries {
            if attempt > 0 {
                tracing::debug!(
                    "cloud: retry attempt {}/{} after {:?}",
                    attempt,
                    self.config.max_retries,
                    backoff
                );
                std::thread::sleep(backoff);
                backoff = (backoff * 2).min(self.config.max_backoff);
            }

            let mut req = client.request(method.clone(), url);
            if let Some(b) = body {
                req = req.json(b);
            }
            if let Some(ref token) = self.bearer_token {
                req = req.bearer_auth(token);
            }

            match req.send() {
                Ok(resp) => {
                    let status = resp.status();
                    if status.is_success() {
                        return resp
                            .json::<CloudResponse<Resp>>()
                            .map_err(|e: reqwest::Error| {
                                net_err(format!("deserialization failed: {e}"))
                            });
                    }
                    if status.is_client_error() {
                        let body_text = resp.text().unwrap_or_default();
                        return Err(net_err(format!("HTTP {status}: {body_text}")));
                    }
                    last_err = format!("HTTP {status}");
                }
                Err(e) => {
                    last_err = e.to_string();
                }
            }
        }

        Err(net_err(format!(
            "all {} retries exhausted: {last_err}",
            self.config.max_retries
        )))
    }
}
