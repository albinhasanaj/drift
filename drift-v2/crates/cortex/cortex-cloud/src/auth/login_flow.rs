//! Authentication flows: browser-based OAuth or API key.
//!
//! C-01: OAuth browser-based login flow implementation.
//! C-02: OAuth token refresh via refresh_token grant.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::time::Duration;

use cortex_core::errors::{CloudError, CortexResult};
use tracing::{debug, info, warn};

use super::token_manager::AuthToken;

/// Supported authentication methods.
#[derive(Debug, Clone)]
pub enum AuthMethod {
    /// Static API key (simplest).
    ApiKey(String),
    /// OAuth2 with browser-based login.
    OAuth {
        client_id: String,
        auth_url: String,
        token_url: String,
    },
}

/// Default local callback port for OAuth redirect.
const OAUTH_CALLBACK_PORT: u16 = 19876;
/// How long to wait for the browser callback before timing out.
const OAUTH_CALLBACK_TIMEOUT: Duration = Duration::from_secs(120);

/// Handles the login flow and produces an [`AuthToken`].
#[derive(Debug)]
pub struct LoginFlow {
    method: AuthMethod,
}

impl LoginFlow {
    pub fn new(method: AuthMethod) -> Self {
        Self { method }
    }

    /// Authenticate and return a token.
    ///
    /// For API key auth, wraps the key in a non-expiring token.
    /// For OAuth, starts a local HTTP server, opens the browser, waits for
    /// the redirect with the auth code, and exchanges it for tokens.
    pub fn authenticate(&self) -> CortexResult<AuthToken> {
        match &self.method {
            AuthMethod::ApiKey(key) => Ok(AuthToken {
                access_token: key.clone(),
                refresh_token: None,
                // API keys don't expire (effectively infinite).
                expires_in_secs: u64::MAX,
            }),
            AuthMethod::OAuth {
                client_id,
                auth_url,
                token_url,
            } => {
                // C-01: Full OAuth browser-based login flow.
                info!("starting OAuth browser-based login flow");

                // 1. Start a local HTTP server for the callback.
                let listener = TcpListener::bind(format!("127.0.0.1:{OAUTH_CALLBACK_PORT}"))
                    .map_err(|e| CloudError::AuthFailed {
                        reason: format!("failed to bind callback server on port {OAUTH_CALLBACK_PORT}: {e}"),
                    })?;
                listener
                    .set_nonblocking(false)
                    .map_err(|e| CloudError::AuthFailed {
                        reason: format!("failed to configure callback server: {e}"),
                    })?;

                let redirect_uri = format!("http://127.0.0.1:{OAUTH_CALLBACK_PORT}/callback");
                let state = uuid::Uuid::new_v4().to_string();

                // 2. Build the authorization URL and open the browser.
                let auth_redirect = format!(
                    "{}?client_id={}&redirect_uri={}&response_type=code&state={}&scope=openid%20profile",
                    auth_url,
                    urlencoded(client_id),
                    urlencoded(&redirect_uri),
                    urlencoded(&state),
                );

                info!(url = %auth_redirect, "opening browser for OAuth login");

                // Try to open the browser. If it fails, print the URL for manual copy.
                if open_browser(&auth_redirect).is_err() {
                    warn!("could not open browser — please visit this URL manually:\n{auth_redirect}");
                }

                // 3. Wait for the redirect with the auth code.
                // Set a timeout so we don't block forever.
                listener
                    .set_nonblocking(false)
                    .ok();
                let _ = std::net::TcpStream::connect_timeout(
                    &format!("127.0.0.1:{OAUTH_CALLBACK_PORT}").parse().unwrap(),
                    Duration::from_millis(1),
                );

                let code = wait_for_callback(&listener, &state, OAUTH_CALLBACK_TIMEOUT)?;
                debug!(code_len = code.len(), "received authorization code");

                // 4. Exchange the code for tokens at token_url.
                let token = exchange_code_for_token(
                    token_url,
                    client_id,
                    &code,
                    &redirect_uri,
                )?;

                info!("OAuth login successful");
                Ok(token)
            }
        }
    }

    /// Refresh an existing token using the refresh_token grant.
    pub fn refresh(&self, refresh_token: &str) -> CortexResult<AuthToken> {
        match &self.method {
            AuthMethod::ApiKey(_) => {
                // API keys don't need refresh.
                self.authenticate()
            }
            AuthMethod::OAuth {
                client_id,
                token_url,
                ..
            } => {
                // C-02: OAuth token refresh via refresh_token grant.
                info!("refreshing OAuth token");

                let body = format!(
                    "grant_type=refresh_token&client_id={}&refresh_token={}",
                    urlencoded(client_id),
                    urlencoded(refresh_token),
                );

                let token = post_token_request(token_url, &body)?;
                info!("OAuth token refresh successful");
                Ok(token)
            }
        }
    }
}

/// URL-encode a string (minimal implementation for OAuth parameters).
fn urlencoded(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                result.push(b as char);
            }
            _ => {
                result.push_str(&format!("%{:02X}", b));
            }
        }
    }
    result
}

/// Try to open a URL in the default browser.
fn open_browser(url: &str) -> std::io::Result<()> {
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open").arg(url).spawn()?;
    }
    #[cfg(target_os = "linux")]
    {
        std::process::Command::new("xdg-open").arg(url).spawn()?;
    }
    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("cmd")
            .args(["/C", "start", url])
            .spawn()?;
    }
    Ok(())
}

/// Wait for the OAuth callback on the local HTTP server.
/// Extracts the `code` query parameter from the redirect URL.
fn wait_for_callback(
    listener: &TcpListener,
    expected_state: &str,
    timeout: Duration,
) -> CortexResult<String> {
    // Set a read timeout on accepted connections.
    let start = std::time::Instant::now();

    loop {
        if start.elapsed() > timeout {
            return Err(CloudError::AuthFailed {
                reason: "OAuth callback timed out — no browser redirect received".into(),
            }
            .into());
        }

        // Accept with a short poll interval.
        listener.set_nonblocking(true).ok();
        let stream = match listener.accept() {
            Ok((stream, _)) => stream,
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(100));
                continue;
            }
            Err(e) => {
                return Err(CloudError::AuthFailed {
                    reason: format!("callback server accept failed: {e}"),
                }
                .into());
            }
        };

        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .ok();

        let mut reader = BufReader::new(&stream);
        let mut request_line = String::new();
        if reader.read_line(&mut request_line).is_err() {
            continue;
        }

        // Parse: GET /callback?code=xxx&state=yyy HTTP/1.1
        if let Some(query) = extract_query_string(&request_line) {
            let params = parse_query_params(&query);
            let code = params.get("code").cloned();
            let state = params.get("state").cloned();

            // Send a response to the browser.
            let response_body = if code.is_some() {
                "<html><body><h2>Authentication successful!</h2><p>You can close this tab.</p></body></html>"
            } else {
                "<html><body><h2>Authentication failed.</h2><p>No authorization code received.</p></body></html>"
            };

            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                response_body.len(),
                response_body
            );

            if let Ok(mut writer) = stream.try_clone() {
                let _ = writer.write_all(response.as_bytes());
                let _ = writer.flush();
            }

            // Validate state parameter to prevent CSRF.
            if let Some(ref returned_state) = state {
                if returned_state != expected_state {
                    return Err(CloudError::AuthFailed {
                        reason: "OAuth state mismatch — possible CSRF attack".into(),
                    }
                    .into());
                }
            }

            if let Some(code) = code {
                return Ok(code);
            }

            // Check for error parameter.
            if let Some(error) = params.get("error") {
                return Err(CloudError::AuthFailed {
                    reason: format!("OAuth error: {error}"),
                }
                .into());
            }
        }
    }
}

/// Extract query string from an HTTP request line.
/// Input: "GET /callback?code=xxx&state=yyy HTTP/1.1\r\n"
fn extract_query_string(request_line: &str) -> Option<String> {
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        return None;
    }
    let path = parts[1];
    path.find('?').map(|idx| path[idx + 1..].to_string())
}

/// Parse URL query parameters into a HashMap.
fn parse_query_params(query: &str) -> std::collections::HashMap<String, String> {
    query
        .split('&')
        .filter_map(|pair| {
            let mut parts = pair.splitn(2, '=');
            let key = parts.next()?.to_string();
            let value = parts.next().unwrap_or("").to_string();
            Some((key, value))
        })
        .collect()
}

/// Exchange an authorization code for tokens via HTTP POST.
/// Uses a minimal HTTP client built on std::net::TcpStream.
fn exchange_code_for_token(
    token_url: &str,
    client_id: &str,
    code: &str,
    redirect_uri: &str,
) -> CortexResult<AuthToken> {
    let body = format!(
        "grant_type=authorization_code&client_id={}&code={}&redirect_uri={}",
        urlencoded(client_id),
        urlencoded(code),
        urlencoded(redirect_uri),
    );

    post_token_request(token_url, &body)
}

/// POST a token request and parse the JSON response into an AuthToken.
fn post_token_request(token_url: &str, body: &str) -> CortexResult<AuthToken> {
    // Parse the URL to extract host and path.
    let url = token_url.trim();
    let (scheme, rest) = url
        .split_once("://")
        .unwrap_or(("https", url));
    let (host_port, path) = rest
        .split_once('/')
        .map(|(h, p)| (h, format!("/{p}")))
        .unwrap_or((rest, "/".to_string()));

    let port = if host_port.contains(':') {
        host_port
            .split(':')
            .next_back()
            .and_then(|p| p.parse::<u16>().ok())
            .unwrap_or(if scheme == "https" { 443 } else { 80 })
    } else if scheme == "https" {
        443
    } else {
        80
    };
    let host = host_port.split(':').next().unwrap_or(host_port);

    // For HTTPS we'd need TLS — fall back to reporting the need for the `cloud` feature.
    if scheme == "https" {
        #[cfg(not(feature = "cloud"))]
        {
            return Err(CloudError::AuthFailed {
                reason: "HTTPS token exchange requires the 'cloud' feature (reqwest). \
                         Enable it with: cortex-cloud = { features = [\"cloud\"] }"
                    .into(),
            }
            .into());
        }
        #[cfg(feature = "cloud")]
        {
            // With reqwest available, use it for HTTPS.
            return exchange_via_reqwest(token_url, body);
        }
    }

    // HTTP (non-TLS) — use std::net directly (useful for local dev/testing).
    let addr = format!("{host}:{port}");
    let mut stream = std::net::TcpStream::connect_timeout(
        &addr.parse().map_err(|e| CloudError::AuthFailed {
            reason: format!("invalid token URL address '{addr}': {e}"),
        })?,
        Duration::from_secs(10),
    )
    .map_err(|e| CloudError::NetworkError {
        reason: format!("failed to connect to token endpoint: {e}"),
    })?;

    let request = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        path, host_port, body.len(), body
    );

    stream
        .write_all(request.as_bytes())
        .map_err(|e| CloudError::NetworkError {
            reason: format!("failed to send token request: {e}"),
        })?;

    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .ok();

    let mut response = String::new();
    let reader = BufReader::new(&stream);
    for line in reader.lines() {
        match line {
            Ok(l) => response.push_str(&l),
            Err(_) => break,
        }
    }

    parse_token_response(&response)
}

/// Parse an OAuth token response JSON into an AuthToken.
fn parse_token_response(response: &str) -> CortexResult<AuthToken> {
    // Find the JSON body (after the HTTP headers).
    let json_start = response.find('{');
    let json_end = response.rfind('}');

    let json_str = match (json_start, json_end) {
        (Some(start), Some(end)) if end >= start => &response[start..=end],
        _ => {
            return Err(CloudError::AuthFailed {
                reason: format!("no JSON in token response: {}", &response[..response.len().min(200)]),
            }
            .into());
        }
    };

    let parsed: serde_json::Value = serde_json::from_str(json_str).map_err(|e| {
        CloudError::AuthFailed {
            reason: format!("failed to parse token response: {e}"),
        }
    })?;

    // Check for error response.
    if let Some(error) = parsed.get("error").and_then(|v| v.as_str()) {
        let desc = parsed
            .get("error_description")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown error");
        return Err(CloudError::AuthFailed {
            reason: format!("token endpoint error: {error} — {desc}"),
        }
        .into());
    }

    let access_token = parsed
        .get("access_token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| CloudError::AuthFailed {
            reason: "no access_token in token response".into(),
        })?
        .to_string();

    let refresh_token = parsed
        .get("refresh_token")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let expires_in_secs = parsed
        .get("expires_in")
        .and_then(|v| v.as_u64())
        .unwrap_or(3600);

    Ok(AuthToken {
        access_token,
        refresh_token,
        expires_in_secs,
    })
}

/// Exchange code via reqwest when the `cloud` feature is enabled.
#[cfg(feature = "cloud")]
fn exchange_via_reqwest(token_url: &str, body: &str) -> CortexResult<AuthToken> {
    let rt = tokio::runtime::Handle::try_current()
        .or_else(|_| {
            tokio::runtime::Runtime::new().map(|rt| rt.handle().clone())
        })
        .map_err(|e| CloudError::AuthFailed {
            reason: format!("failed to create tokio runtime for OAuth: {e}"),
        })?;

    rt.block_on(async {
        let client = reqwest::Client::new();
        let resp = client
            .post(token_url)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(body.to_string())
            .send()
            .await
            .map_err(|e| CloudError::NetworkError {
                reason: format!("token request failed: {e}"),
            })?;

        let text = resp.text().await.map_err(|e| CloudError::NetworkError {
            reason: format!("failed to read token response: {e}"),
        })?;

        parse_token_response(&text)
    })
}
