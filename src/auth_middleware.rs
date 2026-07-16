use axum::{
    Json,
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Redirect, Response},
};
use serde_json::json;

use crate::handlers::extract_session_id;
use crate::state::AppState;

/// Middleware that requires authentication for protected routes.
/// If the user is not authenticated, redirects to /login carrying the
/// original path as `?redirect=` so login can return the user to where
/// they came from.
/// Also updates the session's last_activity for sliding window expiration.
pub async fn require_auth(
    State(state): State<AppState>,
    request: Request<Body>,
    next: Next,
) -> Response {
    // Skip the authentication gate when credentials are not configured
    if !state.config.is_auth_enabled() {
        return next.run(request).await;
    }

    // Read the session identifier from the incoming cookies
    let headers = request.headers();
    let session_id = extract_session_id(headers);

    if let Some(id) = session_id {
        if state.session_store.get(&id).is_some() {
            state.session_store.touch(&id);
            return next.run(request).await;
        }
        tracing::debug!("Session expired or not found, redirecting to login");
    } else {
        tracing::debug!("No session cookie, redirecting to login");
    }

    // C-03: Capture the original request path so /login can send the user
    // back after authenticating. Without this, an invite link such as
    //   /c/<uuid>#key=<base64>
    // followed by an unauthenticated bounce to /login dropped the room
    // path entirely; after login the user landed on `/`, losing both the
    // room reference and (worse) the URL bar still carried the E2E key.
    //
    // RFC 3986: the fragment is client-only and never reaches us; the
    // client-side login-stash.js handles preserving and scrubbing it.
    // We only forward path + query, which we already trust.
    let original = request
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());
    redirect_to_login(&original)
}

/// Middleware for API routes that require authentication.
/// Returns 401 Unauthorized instead of redirecting.
pub async fn require_auth_api(
    State(state): State<AppState>,
    request: Request<Body>,
    next: Next,
) -> Response {
    // Skip the authentication gate when credentials are not configured
    if !state.config.is_auth_enabled() {
        return next.run(request).await;
    }

    // Read the session identifier from the incoming cookies
    let headers = request.headers();
    let session_id = extract_session_id(headers);

    match session_id {
        Some(id) => {
            // Validate that the session exists and remains within its TTL
            if let Some(_session) = state.session_store.get(&id) {
                // Refresh the activity timestamp for sliding expiration
                state.session_store.touch(&id);
                // Session is valid; continue to the downstream handler
                next.run(request).await
            } else {
                // Session is missing or expired; return an explicit failure
                (
                    StatusCode::UNAUTHORIZED,
                    Json(json!({
                        "error": "Session expired",
                        "code": "SESSION_EXPIRED"
                    })),
                )
                    .into_response()
            }
        }
        None => {
            // No session cookie was presented
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({
                    "error": "Authentication required",
                    "code": "AUTH_REQUIRED"
                })),
            )
                .into_response()
        }
    }
}

/// Helper to create a redirect response to the login page, optionally
/// carrying the original path as `?redirect=` so login can route the user
/// back after authenticating.
///
/// Open-redirect guard: only relative paths starting with a single `/` are
/// forwarded. `//` (protocol-relative URL), schemes, and empty strings fall
/// back to a bare `/login`. login_submit applies the same filter on the
/// other side of the round-trip as defence in depth.
fn redirect_to_login(original_path: &str) -> Response {
    if original_path.is_empty()
        || !original_path.starts_with('/')
        || original_path.starts_with("//")
    {
        return Redirect::to("/login").into_response();
    }
    let encoded = urlencoding::encode(original_path);
    Redirect::to(&format!("/login?redirect={}", encoded)).into_response()
}

/// Middleware that redirects authenticated users away from login page.
/// Used for the login page itself - if already logged in, go to homepage.
pub async fn redirect_if_authenticated(
    State(state): State<AppState>,
    request: Request<Body>,
    next: Next,
) -> Response {
    // Skip the redirect logic when authentication is disabled
    if !state.config.is_auth_enabled() {
        // If no authentication is configured, render the login page as-is
        return next.run(request).await;
    }

    // Check whether the requester already holds a valid session
    let headers = request.headers();
    if let Some(session_id) = extract_session_id(headers) {
        if state.session_store.get(&session_id).is_some() {
            // Already authenticated, redirect to the landing page
            return Redirect::to("/").into_response();
        }
    }

    // Otherwise, allow the login page to render
    next.run(request).await
}

#[cfg(test)]
mod tests {
    //! Tests for redirect path preservation (C-03).
    //!
    //! The middleware needs the full AppState + axum router machinery to
    //! exercise the auth gate, so we spin up a bound listener and issue raw
    //! HTTP requests — same pattern used by src/handlers/websocket.rs#tests.
    use super::*;
    use crate::config::Config;
    use crate::state::AppState;
    use axum::{Router, middleware, routing::get};
    use std::net::SocketAddr;

    fn auth_test_config() -> Config {
        // Pre-baked Argon2id hash for password "test-only" so is_auth_enabled
        // returns true. Real value irrelevant — we never authenticate here.
        let hash = "$argon2id$v=19$m=47104,t=1,p=1$YWJjZGVmZ2hpamtsbW5vcA$\
             aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789abcdef0123456789abcdef01"
            .to_string();
        Config {
            host: [127, 0, 0, 1],
            port: 0,
            ws_conn_burst_size: 100,
            ws_conn_period_secs: 60,
            room_token_burst_size: 100,
            room_token_period_secs: 600,
            msg_rate_limit: 30,
            msg_rate_window_secs: 1,
            room_msg_rate_limit: 120,
            room_byte_rate_limit: 8 * 1024 * 1024,
            commit_rate_limit: 12,
            commit_rate_window_secs: 60,
            proposal_rate_limit: 8,
            proposal_rate_window_secs: 60,
            frame_rate_limit: 120,
            protocol_error_limit: 10,
            pow_min_difficulty: 12,
            pow_max_difficulty: 18,
            challenge_ttl_secs: 300,
            jwt_token_ttl_secs: 30,
            jwt_issuer: crate::jwt::DEFAULT_JWT_ISSUER.to_string(),
            max_ws_connection_age_secs: 1800,
            ws_reconnect_grace_secs: 20,
            ecdh_burst_limit: 8,
            ecdh_burst_window_secs: 60,
            room_cleanup_interval_secs: 60,
            challenge_cleanup_interval_secs: 60,
            password_hashes: vec![hash],
            session_ttl_secs: 86400,
            login_burst_size: 5,
            login_period_secs: 900,
            trusted_proxies: vec![],
            replay_cache_max_per_room: 10000,
            force_secure_cookies: false,
            max_image_size: 300 * 1024,
            force_http: false,
            website_dir: None,
            allow_anonymous: false,
            cors_allowed_origins: vec!["https://localhost:3000".to_string()],
            group_chat_enabled: true,
        }
    }

    async fn spawn_protected() -> SocketAddr {
        let state = AppState::new(1000, auth_test_config());
        // Dummy protected handler — we only care about the redirect headers.
        let app: Router = Router::new()
            .route("/c/:room_id", get(|| async { "ok" }))
            .layer(middleware::from_fn_with_state(state.clone(), require_auth))
            .with_state(state);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        addr
    }

    /// Issue a GET and return `(status, location_header)`.
    async fn get_with_path(addr: SocketAddr, path: &str) -> (u16, Option<String>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let req = format!(
            "GET {path} HTTP/1.1\r\n\
             Host: {addr}\r\n\
             Connection: close\r\n\
             \r\n"
        );
        stream.write_all(req.as_bytes()).await.unwrap();
        let mut buf = Vec::new();
        let _ = stream.read_to_end(&mut buf).await;
        let head = String::from_utf8_lossy(&buf).to_string();
        let status = head
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let location = head
            .lines()
            .find(|l| l.to_ascii_lowercase().starts_with("location:"))
            .map(|l| l.split_once(':').unwrap().1.trim().to_string());
        (status, location)
    }

    #[tokio::test]
    async fn unauth_redirects_to_login_with_original_path_encoded() {
        // C-03: a bare /c/<uuid> request without session must redirect to
        // /login?redirect=%2Fc%2F<uuid> so the static login.js can populate
        // the form's redirect_url and the bootstrap fragment can be stashed.
        // Without this, post-login redirect lands on `/` and the user loses
        // the room reference entirely.
        let addr = spawn_protected().await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let (status, location) =
            get_with_path(addr, "/c/550e8400-e29b-41d4-a716-446655440000").await;
        assert_eq!(status, 303);
        let loc = location.expect("missing Location header");
        assert_eq!(
            loc,
            "/login?redirect=%2Fc%2F550e8400-e29b-41d4-a716-446655440000"
        );
    }

    #[tokio::test]
    async fn unauth_preserves_query_string_in_redirect() {
        // Path-and-query: query (if any) must be carried along so the
        // eventual chat page receives the same room context after login.
        let addr = spawn_protected().await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let (status, location) = get_with_path(addr, "/c/abc?debug=1").await;
        assert_eq!(status, 303);
        let loc = location.expect("missing Location header");
        // The query string `?debug=1` is part of the original URI and must
        // appear inside the percent-encoded `redirect` value.
        assert!(
            loc.starts_with("/login?redirect=%2Fc%2Fabc%3Fdebug%3D1"),
            "got: {loc}"
        );
    }
}
