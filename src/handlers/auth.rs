use axum::{
    extract::{Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
    Form,
};
use axum_extra::extract::cookie::{Cookie, SameSite};
use serde::Deserialize;

use crate::auth::{
    generate_csrf_token, generate_session_token, verify_csrf_token, verify_password,
};
use crate::state::AppState;

/// Cookie name for the session
pub const SESSION_COOKIE_NAME: &str = "pinchat_session";
/// Cookie name for CSRF token
pub const CSRF_COOKIE_NAME: &str = "csrf_token";

/// Query parameters for login page
#[derive(Deserialize, Default)]
pub struct LoginQuery {
    /// URL to redirect to after successful login
    #[serde(default)]
    redirect: Option<String>,
}

/// Form data for login
#[derive(Deserialize)]
pub struct LoginForm {
    password: String,
    csrf_token: String,
    #[serde(default)]
    redirect_url: Option<String>,
}

/// Determine if cookies should have the Secure flag set.
///
/// Returns true if:
/// 1. FORCE_SECURE_COOKIES=true is set (for TLS-terminating proxies), OR
/// 2. Local TLS certificates exist (direct HTTPS termination)
///
/// SECURITY: When behind a reverse proxy (nginx, CloudFlare, AWS ALB),
/// set FORCE_SECURE_COOKIES=true to ensure cookies are only sent over HTTPS.
/// Without this, cookies could leak over HTTP if the proxy misconfigures.
fn should_use_secure_cookies(force_secure: bool) -> bool {
    if force_secure {
        return true;
    }
    // Fallback: check for local TLS certificates
    use std::path::Path;
    let cert_exists = Path::new("certs/cert.pem").exists();
    let key_exists = Path::new("certs/key.pem").exists();
    cert_exists && key_exists
}

/// Login page handler - serves the login HTML with CSRF token
pub async fn login_page(
    State(state): State<AppState>,
    Query(query): Query<LoginQuery>,
) -> impl IntoResponse {
    // Generate CSRF token
    let csrf_token = generate_csrf_token(&state.csrf_secret);
    let use_secure = should_use_secure_cookies(state.config.force_secure_cookies);

    // Create CSRF cookie; HttpOnly because the token is injected into the HTML form
    // Client scripts do not require access because the server validates that the cookie
    // matches the submitted form field
    let csrf_cookie = Cookie::build((CSRF_COOKIE_NAME, csrf_token.clone()))
        .path("/")
        .same_site(SameSite::Strict)
        .secure(use_secure)
        .http_only(true)
        .max_age(time::Duration::minutes(15))
        .build();

    // Clear any stale session cookie to ensure clean state
    let clear_session = Cookie::build((SESSION_COOKIE_NAME, ""))
        .path("/")
        .same_site(SameSite::Strict)
        .secure(use_secure)
        .http_only(true)
        .max_age(time::Duration::ZERO)
        .build();

    // Sanitize redirect URL to prevent open redirect attacks
    // Only allow relative URLs starting with /
    let redirect_url = query
        .redirect
        .filter(|url| url.starts_with('/') && !url.starts_with("//"))
        .unwrap_or_default();

    // Read login.html template and inject CSRF token and redirect URL
    let html = include_str!("../../static/login.html")
        .replace("{{csrf_token}}", &csrf_token)
        .replace("{{redirect_url}}", &redirect_url);

    let mut headers = HeaderMap::new();
    headers.append(header::SET_COOKIE, csrf_cookie.to_string().parse().unwrap());
    headers.append(
        header::SET_COOKIE,
        clear_session.to_string().parse().unwrap(),
    );

    (StatusCode::OK, headers, Html(html))
}

/// Login form submission handler
pub async fn login_submit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> Response {
    // Check if auth is enabled
    if !state.config.is_auth_enabled() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "Authentication not configured",
        )
            .into_response();
    }

    // Verify CSRF token from cookie matches form field
    let all_cookies = headers.get(header::COOKIE).and_then(|h| h.to_str().ok());

    tracing::debug!("All cookies received: {:?}", all_cookies);
    tracing::debug!("Form CSRF token: {}", form.csrf_token);

    let csrf_cookie = all_cookies.and_then(|cookies| {
        cookies.split(';').find_map(|c| {
            let c = c.trim();
            if c.starts_with(&format!("{}=", CSRF_COOKIE_NAME)) {
                Some(
                    c.trim_start_matches(&format!("{}=", CSRF_COOKIE_NAME))
                        .to_string(),
                )
            } else {
                None
            }
        })
    });

    match csrf_cookie {
        Some(cookie_token) => {
            // Verify both tokens are valid and match
            if !verify_csrf_token(&cookie_token, &state.csrf_secret) {
                tracing::warn!("Invalid CSRF cookie token");
                return login_error_response(
                    "Invalid security token. Please refresh the page.",
                    &state.csrf_secret,
                    state.config.force_secure_cookies,
                );
            }
            if cookie_token != form.csrf_token {
                tracing::warn!("CSRF token mismatch");
                return login_error_response(
                    "Security token mismatch. Please refresh the page.",
                    &state.csrf_secret,
                    state.config.force_secure_cookies,
                );
            }
        }
        None => {
            tracing::warn!("Missing CSRF cookie");
            return login_error_response(
                "Missing security token. Please enable cookies.",
                &state.csrf_secret,
                state.config.force_secure_cookies,
            );
        }
    }

    // Verify password
    if !verify_password(&form.password, &state.config.password_hashes) {
        tracing::warn!("Failed login attempt");
        return login_error_response(
            "Invalid password",
            &state.csrf_secret,
            state.config.force_secure_cookies,
        );
    }

    // Create session
    let session_id = generate_session_token();
    state.session_store.create(session_id);

    let use_secure = should_use_secure_cookies(state.config.force_secure_cookies);
    tracing::info!(
        "Successful login, session created. Secure cookies: {}, session_id: {}",
        use_secure,
        session_id
    );

    // Create session cookie
    // Development mode omits the Secure flag to allow browsers to send the cookie over HTTP
    let session_cookie = Cookie::build((SESSION_COOKIE_NAME, session_id.to_string()))
        .path("/")
        .same_site(SameSite::Strict)
        .secure(use_secure)
        .http_only(true)
        .max_age(time::Duration::seconds(
            state.config.session_ttl_secs as i64,
        ))
        .build();

    // Clear CSRF cookie (no longer needed)
    // Must match same attributes as original cookie for proper deletion
    let clear_csrf = Cookie::build((CSRF_COOKIE_NAME, ""))
        .path("/")
        .same_site(SameSite::Strict)
        .secure(use_secure)
        .http_only(true)
        .max_age(time::Duration::ZERO)
        .build();

    let session_cookie_str = session_cookie.to_string();
    let clear_csrf_str = clear_csrf.to_string();

    tracing::debug!("Session cookie header: {}", session_cookie_str);
    tracing::debug!("Clear CSRF cookie header: {}", clear_csrf_str);

    // Determine redirect URL (with security validation)
    // Only allow relative URLs starting with / to prevent open redirect attacks
    let redirect_target = form
        .redirect_url
        .filter(|url| !url.is_empty() && url.starts_with('/') && !url.starts_with("//"))
        .unwrap_or_else(|| "/".to_string());

    tracing::debug!("Redirecting to: {}", redirect_target);

    // Redirect to target URL (homepage or original page)
    // Use HeaderMap to properly support multiple Set-Cookie headers
    let mut headers = HeaderMap::new();
    headers.insert(header::LOCATION, redirect_target.parse().unwrap());
    headers.append(header::SET_COOKIE, session_cookie_str.parse().unwrap());
    headers.append(header::SET_COOKIE, clear_csrf_str.parse().unwrap());

    (StatusCode::SEE_OTHER, headers).into_response()
}

/// Logout handler
pub async fn logout(State(state): State<AppState>, headers: HeaderMap) -> Response {
    // Extract session ID from cookie and delete session
    if let Some(session_id) = extract_session_id(&headers) {
        state.session_store.delete(&session_id);
        tracing::info!("Session deleted on logout");
    }

    let use_secure = should_use_secure_cookies(state.config.force_secure_cookies);

    // Clear session cookie
    // Must match same attributes as original cookie for proper deletion on all browsers
    let clear_session = Cookie::build((SESSION_COOKIE_NAME, ""))
        .path("/")
        .same_site(SameSite::Strict)
        .secure(use_secure)
        .http_only(true)
        .max_age(time::Duration::ZERO)
        .build();

    // Redirect to login
    (
        StatusCode::SEE_OTHER,
        [
            (header::SET_COOKIE, clear_session.to_string()),
            (header::LOCATION, "/login".to_string()),
        ],
    )
        .into_response()
}

/// Helper to extract session ID from cookies
pub fn extract_session_id(headers: &HeaderMap) -> Option<uuid::Uuid> {
    headers
        .get(header::COOKIE)
        .and_then(|h| h.to_str().ok())
        .and_then(|cookies| {
            cookies.split(';').find_map(|c| {
                let c = c.trim();
                if c.starts_with(&format!("{}=", SESSION_COOKIE_NAME)) {
                    let id_str = c.trim_start_matches(&format!("{}=", SESSION_COOKIE_NAME));
                    uuid::Uuid::parse_str(id_str).ok()
                } else {
                    None
                }
            })
        })
}

/// Helper to create an error response for login failures
/// Generates a new CSRF token so the user can retry
fn login_error_response(
    message: &str,
    csrf_secret: &[u8; 32],
    force_secure_cookies: bool,
) -> Response {
    let csrf_token = generate_csrf_token(csrf_secret);
    let use_secure = should_use_secure_cookies(force_secure_cookies);

    let csrf_cookie = Cookie::build((CSRF_COOKIE_NAME, csrf_token.clone()))
        .path("/")
        .same_site(SameSite::Strict)
        .secure(use_secure)
        .http_only(true)
        .max_age(time::Duration::minutes(15))
        .build();

    let html = include_str!("../../static/login.html")
        .replace("{{csrf_token}}", &csrf_token)
        .replace(
            "<!-- error_placeholder -->",
            &format!(r#"<div class="login-error-message">{}</div>"#, message),
        );

    (
        StatusCode::UNAUTHORIZED,
        [(header::SET_COOKIE, csrf_cookie.to_string())],
        Html(html),
    )
        .into_response()
}
