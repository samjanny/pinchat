use axum::{
    Form,
    extract::{Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
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

/// Returns true when `url` is safe to emit verbatim as a `Location` value.
///
/// Audit M-3: the previous test was `starts_with('/') && !starts_with("//")`,
/// which accepts `/\evil.com`. Per the WHATWG URL specification a relative
/// reference beginning `/\` enters "special authority ignore slashes" state
/// exactly as `//` does, so Chrome, Firefox and Safari all resolve it to the
/// scheme-relative form and navigate off-origin with the address bar showing
/// the attacker's host. Backslashes are normalised to forward slashes for
/// special schemes, so the character has to be refused outright rather than
/// only in the leading position.
///
/// Control characters are screened for a second reason. `HeaderValue` refuses
/// them and the call sites used to `.unwrap()` that conversion, so a form
/// field carrying `%0d%0a` passed the old filter and panicked the handler
/// task. Rejecting here means the value is always a legal header value by the
/// time it reaches the response, and a lax intermediary is never handed a
/// response-splitting payload either.
fn is_safe_redirect_target(url: &str) -> bool {
    let Some(rest) = url.strip_prefix('/') else {
        return false;
    };

    // Scheme-relative, in either spelling the URL parser accepts.
    if rest.starts_with('/') || rest.starts_with('\\') {
        return false;
    }

    // A backslash further along cannot reintroduce an authority by itself, but
    // nothing this application generates contains one and parsers disagree on
    // how they normalise it. Refuse the whole class.
    if url.contains('\\') {
        return false;
    }

    // CR, LF, TAB, NUL and the rest of C0/C1.
    !url.chars().any(char::is_control)
}

/// Login page handler - redirects to static HTML
/// CSRF token is obtained via /api/csrf endpoint
pub async fn login_page(
    State(state): State<AppState>,
    Query(query): Query<LoginQuery>,
) -> impl IntoResponse {
    let use_secure = should_use_secure_cookies(state.config.force_secure_cookies);

    // Clear any stale session cookie to ensure clean state
    let clear_session = Cookie::build((SESSION_COOKIE_NAME, ""))
        .path("/")
        .same_site(SameSite::Strict)
        .secure(use_secure)
        .http_only(true)
        .max_age(time::Duration::ZERO)
        .build();

    // Sanitize redirect URL to prevent open redirect attacks.
    // Only same-origin relative paths survive; see is_safe_redirect_target.
    let redirect_url = query
        .redirect
        .filter(|url| is_safe_redirect_target(url))
        .unwrap_or_default();

    let mut headers = HeaderMap::new();
    headers.append(
        header::SET_COOKIE,
        clear_session.to_string().parse().unwrap(),
    );

    // Redirect to static login page with optional redirect parameter
    let location = if redirect_url.is_empty() {
        "/static/login.html".to_string()
    } else {
        format!(
            "/static/login.html?redirect={}",
            urlencoding::encode(&redirect_url)
        )
    };
    // is_safe_redirect_target already guarantees this converts, and the
    // urlencoding pass above guarantees it for the query form. Degrade to the
    // bare login page rather than panicking should either invariant weaken.
    headers.insert(
        header::LOCATION,
        HeaderValue::from_str(&location)
            .unwrap_or_else(|_| HeaderValue::from_static("/static/login.html")),
    );

    (StatusCode::SEE_OTHER, headers)
}

/// CSRF token API endpoint
/// Returns a new CSRF token and sets the corresponding cookie
pub async fn get_csrf_token(State(state): State<AppState>) -> impl IntoResponse {
    let csrf_token = generate_csrf_token(&state.csrf_secret);
    let use_secure = should_use_secure_cookies(state.config.force_secure_cookies);

    // Create CSRF cookie
    let csrf_cookie = Cookie::build((CSRF_COOKIE_NAME, csrf_token.clone()))
        .path("/")
        .same_site(SameSite::Strict)
        .secure(use_secure)
        .http_only(true)
        .max_age(time::Duration::minutes(15))
        .build();

    let mut headers = HeaderMap::new();
    headers.append(header::SET_COOKIE, csrf_cookie.to_string().parse().unwrap());
    headers.insert(header::CONTENT_TYPE, "application/json".parse().unwrap());

    // Return token in JSON response
    (
        StatusCode::OK,
        headers,
        format!(r#"{{"csrf_token":"{}"}}"#, csrf_token),
    )
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

    tracing::debug!("Processing login submission");

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
        "Successful login, session created. Secure cookies: {}",
        use_secure
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

    // Determine redirect URL (with security validation).
    // Only same-origin relative paths survive; see is_safe_redirect_target.
    let redirect_target = form
        .redirect_url
        .filter(|url| !url.is_empty() && is_safe_redirect_target(url))
        .unwrap_or_else(|| "/".to_string());

    tracing::debug!("Redirecting to: {}", redirect_target);

    // Redirect to target URL (homepage or original page)
    // Use HeaderMap to properly support multiple Set-Cookie headers
    let mut headers = HeaderMap::new();
    // Audit L-6: this was `.parse().unwrap()`. `redirect_target` is now
    // control-character free by construction, but a fallback beats a panicking
    // worker task if that ever stops being true.
    headers.insert(
        header::LOCATION,
        HeaderValue::from_str(&redirect_target).unwrap_or_else(|_| HeaderValue::from_static("/")),
    );
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
/// Redirects back to login page with error parameter
fn login_error_response(
    message: &str,
    _csrf_secret: &[u8; 32],
    _force_secure_cookies: bool,
) -> Response {
    // Redirect back to static login page with error message
    let location = format!("/static/login.html?error={}", urlencoding::encode(message));

    (StatusCode::SEE_OTHER, [(header::LOCATION, location)]).into_response()
}

#[cfg(test)]
mod tests {
    use super::is_safe_redirect_target;
    use axum::http::HeaderValue;

    #[test]
    fn accepts_ordinary_relative_paths() {
        for url in [
            "/",
            "/c/2f8a1b3c-0000-4000-8000-000000000000",
            "/static/chat.html?room=abc",
            "/logout",
        ] {
            assert!(is_safe_redirect_target(url), "{url} should be accepted");
        }
    }

    #[test]
    fn rejects_absolute_and_scheme_relative() {
        for url in [
            "//evil.example",
            "///evil.example",
            "https://evil.example",
            "http://evil.example",
            "evil.example",
            "",
        ] {
            assert!(!is_safe_redirect_target(url), "{url} should be rejected");
        }
    }

    #[test]
    fn rejects_backslash_authority() {
        // Audit M-3 regression. WHATWG URL parsing enters the same
        // "special authority ignore slashes" state for a leading `/\` as it
        // does for `//`, so Chrome, Firefox and Safari all resolve these to an
        // off-origin scheme-relative URL. The previous filter
        // (`starts_with('/') && !starts_with("//")`) accepted every one.
        for url in [
            r"/\evil.example",
            r"/\/evil.example",
            r"/\\evil.example",
            r"/path\..\evil",
        ] {
            assert!(!is_safe_redirect_target(url), "{url} should be rejected");
        }
    }

    #[test]
    fn rejects_control_characters() {
        // Audit L-6 regression. These used to reach HeaderValue::from_str via
        // an `.unwrap()` and panic the handler task: a form field carrying
        // `%0d%0a` decodes to a bare CRLF and passed the old filter untouched.
        for url in [
            "/\r\nX-Injected: 1",
            "/\n/",
            "/\tfoo",
            "/\u{0}",
            "/a\u{7f}b",
        ] {
            assert!(!is_safe_redirect_target(url), "{url:?} should be rejected");
        }
    }

    #[test]
    fn accepted_targets_are_always_valid_header_values() {
        // The property both call sites depend on: everything this predicate
        // accepts converts cleanly, so the fallbacks are belt-and-braces
        // rather than live code paths.
        for url in [
            "/",
            "/c/room?x=1",
            "/static/login.html?redirect=%2Fc%2Fx",
            "/a b",
        ] {
            assert!(is_safe_redirect_target(url), "{url} should be accepted");
            assert!(
                HeaderValue::from_str(url).is_ok(),
                "{url} must be a legal header value"
            );
        }
    }
}
