use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Redirect, Response},
    Json,
};
use serde_json::json;

use crate::handlers::extract_session_id;
use crate::state::AppState;

/// Middleware that requires authentication for protected routes.
/// If the user is not authenticated, redirects to /login.
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

    match session_id {
        Some(id) => {
            // Validate that the session exists and remains within its TTL
            if let Some(_session) = state.session_store.get(&id) {
                // Refresh the activity timestamp for sliding expiration
                state.session_store.touch(&id);
                // Session is valid; continue to the downstream handler
                next.run(request).await
            } else {
                // Session is missing or expired; redirect to a fresh login
                tracing::debug!("Session expired or not found, redirecting to login");
                redirect_to_login()
            }
        }
        None => {
            // No session cookie was presented
            tracing::debug!("No session cookie, redirecting to login");
            redirect_to_login()
        }
    }
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

/// Helper to create a redirect response to login page
fn redirect_to_login() -> Response {
    Redirect::to("/login").into_response()
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
