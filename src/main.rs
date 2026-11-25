mod auth;
mod auth_middleware;
mod challenge_cache;
mod cleanup;
mod config;
mod handlers;
mod http_server;
mod ip_hash;
mod jwt;
mod models;
mod pow;
mod pow_session;
mod rate_limit;
mod rate_limit_extractor;
mod session;
mod state;
mod ws_transport;

use axum::{
    Router,
    extract::DefaultBodyLimit,
    http::{HeaderValue, Method, header},
    middleware::{self, Next},
    response::Response,
    routing::{get, post},
};
use axum_server::tls_rustls::RustlsConfig;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::Duration;
use tower::ServiceBuilder;
use tower_http::{
    cors::{AllowOrigin, CorsLayer},
    services::ServeDir,
    trace::{DefaultMakeSpan, TraceLayer},
};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::auth_middleware::{redirect_if_authenticated, require_auth, require_auth_api};
use crate::cleanup::start_cleanup_task;
use crate::config::Config;
use crate::handlers::{
    create_room, generate_ws_token, get_csrf_token, homepage, login_page, login_submit, logout,
    require_ws_token, room_page, ws_handler,
};
use crate::rate_limit::{Quota, RetentionSweeper, ip_quota_layer};
use crate::state::AppState;

/// The Content Security Policy, in its two forms.
struct ContentSecurityPolicy {
    /// Every page but the login page: no form may be submitted. The forms of
    /// the homepage and the room page are handled by scripts
    /// (`@submit.prevent`) and never submitted by the browser.
    pages: HeaderValue,
    /// The login page, whose form the browser submits to `/login`.
    login: HeaderValue,
}

/// Paths that serve the login page, the only page with a form the browser
/// submits.
const LOGIN_PAGE_PATHS: [&str; 2] = ["/login", "/static/login.html"];

/// Set once at startup, from the checked `CSP_WS_HOST`.
static CSP: OnceLock<ContentSecurityPolicy> = OnceLock::new();

/// Build the policy. `ws_hosts` comes from `config::csp_ws_hosts`, which
/// accepts only WebSocket origins, so it cannot end a directive or add one.
/// Development mode adds localhost endpoints for local testing.
fn build_csp(ws_hosts: &str, development: bool) -> ContentSecurityPolicy {
    let connect_src = if development {
        format!("'self' ws://localhost:* wss://localhost:* {}", ws_hosts)
    } else {
        format!("'self' {}", ws_hosts)
    };
    let policy = |form_action: &str| {
        let value = format!(
            "default-src 'self'; \
             script-src 'self'; \
             style-src 'self'; \
             img-src 'self' blob:; \
             connect-src {}; \
             frame-ancestors 'none'; \
             base-uri 'self'; \
             form-action {};",
            connect_src, form_action
        );
        HeaderValue::from_str(&value).expect("the policy is built from checked parts")
    };
    ContentSecurityPolicy {
        pages: policy("'none'"),
        login: policy("'self'"),
    }
}

/// Security headers middleware
/// Adds CSP, X-Frame-Options, X-Content-Type-Options for defense-in-depth
async fn add_security_headers(req: axum::extract::Request, next: Next) -> Response {
    // Set at startup; the default only serves tests that build the router
    // without running `run`.
    let csp = CSP.get_or_init(|| build_csp("'self'", false));
    let csp = if LOGIN_PAGE_PATHS.contains(&req.uri().path()) {
        csp.login.clone()
    } else {
        csp.pages.clone()
    };

    let mut response = next.run(req).await;

    let headers = response.headers_mut();

    // Content Security Policy
    // - default-src 'self': Restrict all resources to the application origin
    // - script-src 'self': Allow only self-hosted scripts (Alpine.js is self-hosted)
    // - style-src 'self': Permit only self-hosted stylesheets; inline styles are blocked
    // - connect-src: Limit connections to the application origin and configured WS host
    // - frame-ancestors 'none': Prevent clickjacking by disallowing framing
    // - form-action: 'none', except on the login page ('self')
    // Inline styles have been moved to CSS files to satisfy CSP enforcement
    headers.insert(header::CONTENT_SECURITY_POLICY, csp);

    // X-Frame-Options: Prevent embedding in iframes (clickjacking protection)
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));

    // X-Content-Type-Options: Prevent MIME-type sniffing
    headers.insert(
        header::HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );

    // X-XSS-Protection: Enable legacy browser filtering for compatibility
    headers.insert(
        header::HeaderName::from_static("x-xss-protection"),
        HeaderValue::from_static("1; mode=block"),
    );

    // Referrer-Policy: Suppress referrer information on outbound requests
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );

    // HSTS: Enforce HTTPS for one year; only takes effect when the site is served over HTTPS
    // Browsers ignore this header over HTTP, so it is safe to include unconditionally
    headers.insert(
        header::STRICT_TRANSPORT_SECURITY,
        HeaderValue::from_static("max-age=31536000; includeSubDomains"),
    );

    // X-Robots-Tag: keep search engines from indexing the service during the beta.
    // Paired with robots.txt (Disallow: /) and per-page <meta name="robots"> for
    // defense in depth against crawlers that honour one signal but not the others.
    headers.insert(
        header::HeaderName::from_static("x-robots-tag"),
        HeaderValue::from_static("noindex, nofollow"),
    );

    response
}

/// Room creation and WebSocket token endpoints.
///
/// Layer order matters. The session check is the outer layer and the quota
/// the inner one, so a request without a valid session is refused before it
/// reaches the bucket. With the quota outside, anyone who shared an address
/// with a user (an office NAT, a VPN, a Tor exit) could spend that user's
/// budget without knowing the site password. Both endpoints draw from the
/// same bucket.
///
/// The token endpoint is POST (not GET) so the request cannot be forged as a
/// top-level navigation; CSRF double-submit gating is applied inside the
/// handlers.
/// The WebSocket endpoint.
///
/// It is authenticated by a single-use JWT sent in the Sec-WebSocket-Protocol
/// header instead of the session cookie; the token comes from /api/ws-token,
/// which requires a session. As above, the check is the outer layer and the
/// quota the inner one: an upgrade without a valid token for the room is
/// refused before it reaches the bucket, so only requests that could be
/// accepted count against the address they come from.
fn limited_websocket_routes(
    app_state: &AppState,
    quota: Quota,
    sweeper: &mut RetentionSweeper,
) -> Router {
    let quota_layer = ip_quota_layer!(app_state, quota, sweeper);
    Router::new()
        .route("/ws/:room_id", get(ws_handler))
        // route_layer, not layer: a layer also wraps the router's fallback,
        // and require_ws_token takes the room ID from the path, so every
        // address that matches no route used to answer 500 instead of 404.
        .route_layer(quota_layer)
        .route_layer(middleware::from_fn_with_state(
            app_state.clone(),
            require_ws_token,
        ))
        .with_state(app_state.clone())
}

fn limited_api_routes(
    app_state: &AppState,
    quota: Quota,
    sweeper: &mut RetentionSweeper,
) -> Router {
    let quota_layer = ip_quota_layer!(app_state, quota, sweeper);
    Router::new()
        .route("/api/rooms", post(create_room))
        .route("/api/ws-token/:room_id", post(generate_ws_token))
        // Only for these routes, not for the fallback; see above.
        .route_layer(quota_layer)
        .route_layer(middleware::from_fn_with_state(
            app_state.clone(),
            require_auth_api,
        ))
        .with_state(app_state.clone())
}

/// Upper bound of what the kernel may queue for one connection, in each
/// direction.
///
/// Left to itself the kernel grows both buffers of a socket to several
/// megabytes, and that memory is charged to this process like any other.
/// Towards a peer that reads slowly it is the send buffer that grows. The
/// receive buffer grows while the relay reads fast and then holds whatever
/// the peer goes on sending once the relay stops reading that connection,
/// which it does on purpose when a message has to wait for memory: without
/// a bound, the wait would only move the bytes from the relay to the kernel.
/// A fixed size turns the growth off: a connection costs this much and no
/// more, and a write to a peer that does not read stops making progress
/// sooner. The kernel doubles the value it is given, for its own
/// bookkeeping.
///
/// What a connection costs in the kernel is the largest per-connection cost
/// of the relay, so this decides how many connections fit in its memory
/// (see `MAX_WS_CONNECTIONS`). Measured with peers that stop reading and
/// peers that keep sending while the relay waits, 128 KiB came to about
/// 210 KiB in each direction. Smaller is not free: at 32 KiB a 3.7 MB
/// message over loopback (a relay on the same host as its proxy, with no
/// container network in between) took 1.4 to 1.8 seconds instead of 10 to
/// 30 milliseconds, because the window no longer held one of loopback's
/// 64 KiB segments and every step waited for a delayed acknowledgement.
/// Over a container bridge (1500 bytes) 32, 64 and 128 KiB all took 10 to
/// 30 milliseconds. 64 KiB is the smallest size that is fast on both, and
/// costs at most 256 KiB a connection.
const SOCKET_BUFFER: usize = 64 * 1024;

/// Applied to the listening socket, which every accepted socket copies.
fn bound_socket_buffers<S: std::os::fd::AsFd>(listener: &S) {
    let socket = socket2::SockRef::from(listener);
    if socket.set_send_buffer_size(SOCKET_BUFFER).is_err()
        || socket.set_recv_buffer_size(SOCKET_BUFFER).is_err()
    {
        tracing::error!("Could not bound the socket buffers");
    }
}

/// Largest request body any route takes. The login form and the room
/// settings are a few hundred bytes; axum's default was 2 MB, held in memory
/// for a body that trickles in until the connection's age ends it (see
/// `http_server.rs`).
const MAX_REQUEST_BODY: usize = 16 * 1024;

/// Have the allocator hand large blocks straight back to the system.
///
/// glibc serves a large allocation with a mapping of its own and unmaps it
/// when it is freed, but only until the first such block has been freed:
/// from then on it raises the size above which it does so, up to 32 MiB on
/// 64-bit systems, and keeps what is freed below that size for later use.
/// For a relay that means the memory of the largest burst of images it has
/// ever carried stays with the process. Naming the threshold switches the
/// adjustment off; the value is the one glibc starts from.
#[cfg(all(target_os = "linux", target_env = "gnu"))]
fn return_freed_memory_to_the_system() {
    // SAFETY: mallopt takes plain integers and changes one setting of the
    // allocator. It runs first thing in `main`, before any other thread.
    unsafe {
        libc::mallopt(libc::M_MMAP_THRESHOLD, 128 * 1024);
    }
}

#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
fn return_freed_memory_to_the_system() {}

fn main() {
    return_freed_memory_to_the_system();
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("the runtime could not be started")
        .block_on(run());
}

async fn run() {
    use std::env;

    // Load .env file if present; a missing file is tolerated
    let _ = dotenvy::dotenv();

    // Read PRIVACY_MODE from the environment variable
    let privacy_mode = env::var("PRIVACY_MODE").unwrap_or_else(|_| "strict".to_string());

    // Configure logging according to the selected privacy mode
    match privacy_mode.as_str() {
        "strict" => {
            // Suppress operational logs and emit only panics
            tracing_subscriber::registry()
                .with(tracing_subscriber::EnvFilter::new("error"))
                .with(
                    tracing_subscriber::fmt::layer()
                        .with_target(false)
                        .without_time(),
                )
                .init();
            eprintln!("🔒 Privacy mode: STRICT (zero operational logs)");
        }
        "minimal" => {
            // Emit warnings and errors without metadata for constrained logging
            tracing_subscriber::registry()
                .with(tracing_subscriber::EnvFilter::new("pinchat=warn"))
                .with(
                    tracing_subscriber::fmt::layer()
                        .with_target(false)
                        .without_time(),
                )
                .init();
            eprintln!("⚠️  Privacy mode: MINIMAL");
        }
        "development" => {
            // Full logs for local development
            tracing_subscriber::registry()
                .with(
                    tracing_subscriber::EnvFilter::try_from_default_env()
                        .unwrap_or_else(|_| "pinchat=debug,tower_http=debug".into()),
                )
                .with(tracing_subscriber::fmt::layer())
                .init();
            eprintln!("🔧 Privacy mode: DEVELOPMENT (full debug logs)");
        }
        _ => {
            eprintln!("❌ Invalid PRIVACY_MODE='{}', using STRICT", privacy_mode);
            tracing_subscriber::registry()
                .with(tracing_subscriber::EnvFilter::new("error"))
                .with(
                    tracing_subscriber::fmt::layer()
                        .with_target(false)
                        .without_time(),
                )
                .init();
            eprintln!("🔒 Privacy mode: STRICT (zero operational logs)");
        }
    }

    tracing::info!("Starting PinChat server...");

    // Read MAX_TOTAL_ROOMS configuration
    let max_rooms = env::var("MAX_TOTAL_ROOMS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(config::DEFAULT_MAX_TOTAL_ROOMS);

    tracing::info!("Maximum concurrent rooms: {}", max_rooms);

    // Load configuration from environment variables
    let config = Config::from_env();
    tracing::info!("Configuration loaded: rate limits, PoW difficulty, TTLs");

    // Fail closed by default when authentication is not configured.
    // Anonymous mode must be explicitly enabled via ALLOW_ANONYMOUS=true
    // (development mode remains permissive for local workflows).
    if !config.is_auth_enabled() && !config.allow_anonymous && privacy_mode != "development" {
        eprintln!("❌ FATAL: Authentication is not configured.");
        eprintln!("   Set PINCHAT_PASSWORD_HASHES with at least one Argon2id hash, or");
        eprintln!("   explicitly opt in to anonymous mode with ALLOW_ANONYMOUS=true.");
        std::process::exit(1);
    }

    // Reverse-proxy mode has preconditions that are easy to miss and costly
    // when missed (see Config::reverse_proxy_misconfiguration). Refuse to
    // start rather than run degraded; development mode stays permissive.
    let proxy_problem = if privacy_mode == "development" {
        None
    } else {
        config.reverse_proxy_misconfiguration()
    };
    if let Some(problem) = proxy_problem {
        eprintln!("FATAL: {}", problem);
        std::process::exit(1);
    }

    // The WebSocket origins the CSP adds. The value is written into the
    // policy, so anything but an origin is refused at startup.
    match config::csp_ws_hosts(
        env::var("CSP_WS_HOST").ok().as_deref(),
        privacy_mode == "development",
    ) {
        Ok(ws_hosts) => {
            let _ = CSP.set(build_csp(&ws_hosts, privacy_mode == "development"));
        }
        Err(problem) => {
            eprintln!("FATAL: {}", problem);
            std::process::exit(1);
        }
    }

    // Initialize the application state
    let app_state = AppState::new(max_rooms, config.clone());

    // Start the cleanup task (expired rooms and anti-replay cache)
    start_cleanup_task(app_state.clone(), config.room_cleanup_interval_secs);

    // Start challenge cache cleanup task (configurable interval)
    {
        let challenge_cache = app_state.challenge_cache.clone();
        let cleanup_interval = config.challenge_cleanup_interval_secs;
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(cleanup_interval));
            loop {
                interval.tick().await;
                challenge_cache.cleanup_expired();
            }
        });
        tracing::info!(
            "Challenge cache cleanup task started ({}s interval)",
            cleanup_interval
        );
    }

    // Per-client quotas, keyed by HMAC(IP). Semantics, keying and retention
    // are documented in rate_limit.rs. The sweeper deletes buckets that are
    // full again, which is what bounds how long a hashed address is kept.
    let mut rate_limit_sweeper = RetentionSweeper::default();
    let quota = |window_variable: &str, burst: u32, window_secs: u64| {
        let (quota, clamped) = Quota::new(burst, window_secs);
        if clamped {
            // Visible in every privacy mode: this changes a limit the
            // operator configured.
            eprintln!(
                "WARNING: {}={} would keep a hashed client address longer than the {} minutes stated in the privacy policy; using {}s.",
                window_variable,
                window_secs,
                rate_limit::MAX_RETENTION.as_secs() / 60,
                quota.window.as_secs()
            );
        }
        tracing::info!(
            "{}: {} requests per {}s per client, hashed address kept at most {}s after the last request",
            window_variable,
            quota.burst,
            quota.window.as_secs(),
            quota.retention().as_secs()
        );
        quota
    };

    // Room creation and WebSocket token endpoints: session auth, then one
    // shared bucket per client.
    let rate_limited_api = limited_api_routes(
        &app_state,
        quota(
            "ROOM_TOKEN_PERIOD_SECS",
            config.room_token_burst_size,
            config.room_token_period_secs,
        ),
        &mut rate_limit_sweeper,
    );

    // Configure CORS using CORS_ALLOWED_ORIGINS env var (comma-separated).
    // Defaults to "https://localhost:3000" when the variable is absent.
    let allowed_origin_values: Vec<HeaderValue> = config
        .cors_allowed_origins
        .iter()
        .filter_map(|s| s.parse::<HeaderValue>().ok())
        .collect();
    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::list(allowed_origin_values))
        .allow_methods([Method::GET, Method::POST])
        .allow_headers([
            header::CONTENT_TYPE,
            header::HeaderName::from_static("x-pow-nonce"),
            header::HeaderName::from_static("x-pow-challenge"),
            header::HeaderName::from_static("x-pow-difficulty"),
            header::HeaderName::from_static("x-csrf-token"),
            header::HeaderName::from_static("x-pinchat-resume-token"),
            header::HeaderName::from_static("x-pinchat-creator-bootstrap"),
            header::HeaderName::from_static("x-pinchat-mls-control-seq"),
        ]);

    // Login attempts (brute force protection). This quota necessarily runs
    // before authentication, so clients behind one address share it.
    let login_rate_limiter = ServiceBuilder::new().layer(ip_quota_layer!(
        app_state,
        quota(
            "LOGIN_PERIOD_SECS",
            config.login_burst_size,
            config.login_period_secs
        ),
        rate_limit_sweeper
    ));

    // Start session cleanup task
    {
        let session_store = app_state.session_store.clone();
        let cleanup_interval = 60u64; // Every minute
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(cleanup_interval));
            loop {
                interval.tick().await;
                let cleaned = session_store.cleanup_expired();
                if cleaned > 0 {
                    tracing::debug!("Cleaned up {} expired sessions", cleaned);
                }
            }
        });
        tracing::info!("Session cleanup task started (60s interval)");
    }

    // Start consumed JWT tokens cleanup task (single-use enforcement)
    {
        let app_state_clone = app_state.clone();
        let cleanup_interval = 60u64; // Every minute
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(cleanup_interval));
            loop {
                interval.tick().await;
                let cleaned = app_state_clone.cleanup_consumed_tokens();
                if cleaned > 0 {
                    tracing::debug!("Cleaned up {} expired consumed tokens", cleaned);
                }
            }
        });
        tracing::info!("Consumed tokens cleanup task started (60s interval)");
    }

    // Build the router

    // Build static file service with optional custom website directory
    // When WEBSITE_DIR is set, files are served from there first, falling back to /static
    // Note: When no custom dir is set, we use fallback to itself for type consistency
    // (the overhead is negligible - fallback only triggers on 404)
    let static_service = if let Some(ref website_dir) = config.website_dir {
        tracing::info!(
            "Custom website directory: {} (fallback: static/)",
            website_dir
        );
        ServeDir::new(website_dir).fallback(ServeDir::new("static"))
    } else {
        ServeDir::new("static").fallback(ServeDir::new("static"))
    };

    // Public routes (no auth required)
    let public_routes = Router::new()
        // Login routes with rate limiting
        .route(
            "/login",
            get(login_page).layer(middleware::from_fn_with_state(
                app_state.clone(),
                redirect_if_authenticated,
            )),
        )
        .route("/login", post(login_submit).layer(login_rate_limiter))
        // CSRF token API (for static login page)
        .route("/api/csrf", get(get_csrf_token))
        // Crawler directives: during the beta we tell well-behaved bots to stay away.
        // The X-Robots-Tag header sent by add_security_headers is the primary control;
        // robots.txt is the classic companion for bots that only check that file.
        .route(
            "/robots.txt",
            get(|| async { "User-agent: *\nDisallow: /\n" }),
        )
        // Serve static files (CSS, JS, HTML)
        .nest_service("/static", static_service)
        .with_state(app_state.clone());

    // Protected routes (require authentication)
    let protected_routes = Router::new()
        .route("/", get(homepage))
        .route("/c/:room_id", get(room_page))
        .route("/logout", post(logout))
        .layer(middleware::from_fn_with_state(
            app_state.clone(),
            require_auth,
        ))
        .with_state(app_state.clone());

    // Build main app
    let mut app = Router::new()
        .merge(public_routes)
        .merge(protected_routes)
        .layer(cors);

    // WebSocket upgrades. Restrictive (configurable) to prevent connection
    // flooding abuse.
    let rate_limited_websocket = limited_websocket_routes(
        &app_state,
        quota(
            "WS_CONN_PERIOD_SECS",
            config.ws_conn_burst_size,
            config.ws_conn_period_secs,
        ),
        &mut rate_limit_sweeper,
    );

    rate_limit_sweeper.spawn(rate_limit::SWEEP_INTERVAL);
    tracing::info!(
        "Rate limit retention sweep started ({}s interval)",
        rate_limit::SWEEP_INTERVAL.as_secs()
    );

    // Merge routers
    app = app.merge(rate_limited_api);
    app = app.merge(rate_limited_websocket);

    // Add security headers middleware (CSP, X-Frame-Options, etc.)
    app = app.layer(middleware::from_fn(add_security_headers));
    app = app.layer(DefaultBodyLimit::max(MAX_REQUEST_BODY));

    // Add TraceLayer only in development mode (for privacy)
    if privacy_mode == "development" {
        app = app.layer(
            TraceLayer::new_for_http()
                .make_span_with(DefaultMakeSpan::default().include_headers(false)),
        );
    }

    // Configure the address from environment variables
    let addr = SocketAddr::from((config.host, config.port));

    // Check whether TLS certificates are present
    let cert_path = PathBuf::from("certs/cert.pem");
    let key_path = PathBuf::from("certs/key.pem");
    let certs_exist = cert_path.exists() && key_path.exists();

    // Use HTTPS unless FORCE_HTTP=true (for reverse proxy setups)
    if certs_exist && !config.force_http {
        // Start the server with HTTPS
        tracing::info!("Starting HTTPS server on https://{}", addr);

        let tls_config = match RustlsConfig::from_pem_file(&cert_path, &key_path).await {
            Ok(config) => config,
            Err(e) => {
                tracing::error!("Failed to load TLS certificates: {}", e);
                std::process::exit(1);
            }
        };

        http_server::offer_http1_only(&tls_config);

        let listener = match tokio::net::TcpListener::bind(addr).await {
            Ok(l) => l,
            Err(e) => {
                tracing::error!("Failed to bind to {}: {}", addr, e);
                std::process::exit(1);
            }
        };
        bound_socket_buffers(&listener);

        http_server::serve(
            listener,
            Some(tls_config),
            app,
            http_server::Limits::from_config(&config),
            config.trusted_proxies.clone(),
            app_state.ip_hash_secret,
        )
        .await;
    } else {
        // HTTP mode - allowed if FORCE_HTTP=true (reverse proxy) or PRIVACY_MODE=development
        if !config.force_http && privacy_mode != "development" {
            eprintln!("❌ FATAL: TLS certificates not found at certs/cert.pem and certs/key.pem");
            eprintln!("   PinChat requires HTTPS in production to protect passwords and sessions.");
            eprintln!("   ");
            eprintln!("   To fix this:");
            eprintln!(
                "   1. Generate certificates: mkdir -p certs && openssl req -x509 -newkey rsa:4096 -keyout certs/key.pem -out certs/cert.pem -days 365 -nodes"
            );
            eprintln!("   2. Or set PRIVACY_MODE=development for local testing (insecure!)");
            eprintln!(
                "   3. Or set FORCE_HTTP=true if running behind a TLS-terminating reverse proxy"
            );
            std::process::exit(1);
        }

        if config.force_http {
            // FORCE_HTTP mode - for reverse proxy setups
            tracing::info!(
                "Starting HTTP server on http://{} (FORCE_HTTP=true, TLS handled by reverse proxy)",
                addr
            );
            eprintln!("ℹ️  Starting HTTP server (FORCE_HTTP=true)");
            eprintln!("   TLS termination expected to be handled by reverse proxy.");
            if !config.force_secure_cookies && privacy_mode == "development" {
                eprintln!(
                    "   ⚠️  FORCE_SECURE_COOKIES not set - cookies may not have Secure flag!"
                );
            }
        } else {
            // Development mode only - HTTP without TLS
            eprintln!("⚠️  WARNING: Starting HTTP server WITHOUT TLS (PRIVACY_MODE=development)");
            eprintln!("   Passwords and sessions are transmitted in cleartext!");
            eprintln!("   DO NOT use this in production.");
            tracing::warn!("Starting INSECURE HTTP server (development mode only)");
        }

        let listener = match tokio::net::TcpListener::bind(addr).await {
            Ok(l) => l,
            Err(e) => {
                tracing::error!("Failed to bind to {}: {}", addr, e);
                std::process::exit(1);
            }
        };

        bound_socket_buffers(&listener);

        http_server::serve(
            listener,
            None,
            app,
            http_server::Limits::from_config(&config),
            config.trusted_proxies.clone(),
            app_state.ip_hash_secret,
        )
        .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        extract::ConnectInfo,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;
    use uuid::Uuid;

    const CLIENT: [u8; 4] = [203, 0, 113, 5];

    async fn post_api(app: &Router, path: &str, session: Option<Uuid>) -> StatusCode {
        let mut builder = Request::builder().method("POST").uri(path);
        if let Some(session) = session {
            builder = builder.header(
                header::COOKIE,
                format!("{}={}", crate::handlers::auth::SESSION_COOKIE_NAME, session),
            );
        }
        let mut request = builder.body(Body::empty()).unwrap();
        request
            .extensions_mut()
            .insert(ConnectInfo(SocketAddr::from((CLIENT, 40000))));
        app.clone().oneshot(request).await.unwrap().status()
    }

    fn gated_state() -> AppState {
        let mut config = Config::for_tests();
        // Any entry turns the password gate on; no login happens here.
        config.password_hashes = vec!["placeholder".to_string()];
        config.allow_anonymous = false;
        AppState::new(10, config)
    }

    #[tokio::test]
    async fn requests_without_a_session_cannot_spend_the_api_quota() {
        let state = gated_state();
        let mut sweeper = RetentionSweeper::default();
        let (quota, _) = Quota::new(2, 600);
        let app = limited_api_routes(&state, quota, &mut sweeper);
        let token_path = format!("/api/ws-token/{}", Uuid::new_v4());

        // Far more than the burst, from the address the user will come from.
        for _ in 0..10 {
            assert_eq!(
                post_api(&app, "/api/rooms", None).await,
                StatusCode::UNAUTHORIZED
            );
            assert_eq!(
                post_api(&app, &token_path, None).await,
                StatusCode::UNAUTHORIZED
            );
            assert_eq!(
                post_api(&app, "/api/rooms", Some(Uuid::new_v4())).await,
                StatusCode::UNAUTHORIZED,
                "an unknown session id is not a session"
            );
        }
        assert_eq!(
            sweeper.sweep_all(),
            0,
            "refused requests must not even create a bucket"
        );

        // The user behind the same address still has the whole budget. The
        // handlers reject these bodiless requests, but not as rate limited.
        let session = Uuid::new_v4();
        state.session_store.create(session);
        let first = post_api(&app, "/api/rooms", Some(session)).await;
        let second = post_api(&app, &token_path, Some(session)).await;
        for status in [first, second] {
            assert_ne!(status, StatusCode::UNAUTHORIZED);
            assert_ne!(status, StatusCode::TOO_MANY_REQUESTS);
        }

        // Both endpoints draw from one bucket, and it is now empty.
        assert_eq!(
            post_api(&app, "/api/rooms", Some(session)).await,
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(
            post_api(&app, &token_path, Some(session)).await,
            StatusCode::TOO_MANY_REQUESTS
        );
        // An exhausted bucket still refuses a session-less request as
        // unauthenticated, without telling it anything about the quota.
        assert_eq!(
            post_api(&app, "/api/rooms", None).await,
            StatusCode::UNAUTHORIZED
        );
    }

    #[tokio::test]
    async fn an_address_that_matches_no_route_is_not_found() {
        let state = gated_state();
        let mut sweeper = RetentionSweeper::default();
        let (quota, _) = Quota::new(2, 600);
        let app = Router::new()
            .merge(limited_api_routes(&state, quota, &mut sweeper))
            .merge(limited_websocket_routes(&state, quota, &mut sweeper));
        for path in ["/favicon.ico", "/robots.txt", "/ws", "/api/nothing"] {
            for method in ["GET", "POST"] {
                let mut request = Request::builder()
                    .method(method)
                    .uri(path)
                    .body(Body::empty())
                    .unwrap();
                request
                    .extensions_mut()
                    .insert(ConnectInfo(SocketAddr::from((CLIENT, 40000))));
                let status = app.clone().oneshot(request).await.unwrap().status();
                assert_eq!(status, StatusCode::NOT_FOUND, "{method} {path}");
            }
        }
        assert_eq!(
            sweeper.sweep_all(),
            0,
            "an unknown address must not spend a quota"
        );
    }

    async fn upgrade(app: &Router, room_id: Uuid, token: Option<&str>) -> StatusCode {
        let protocol = match token {
            Some(token) => format!("pinchat.v1, pinchat.v1.jwt.{token}"),
            None => "pinchat.v1".to_string(),
        };
        let mut request = Request::builder()
            .uri(format!("/ws/{room_id}"))
            .header(header::ORIGIN, "https://localhost:3000")
            .header(header::CONNECTION, "upgrade")
            .header(header::UPGRADE, "websocket")
            .header("sec-websocket-version", "13")
            .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
            .header("sec-websocket-protocol", protocol)
            .body(Body::empty())
            .unwrap();
        request
            .extensions_mut()
            .insert(ConnectInfo(SocketAddr::from((CLIENT, 40000))));
        app.clone().oneshot(request).await.unwrap().status()
    }

    #[tokio::test]
    async fn upgrades_without_a_valid_token_cannot_spend_the_connection_quota() {
        use crate::jwt::{WsTokenClaims, sign_token};

        let state = AppState::new(10, Config::for_tests());
        let mut sweeper = RetentionSweeper::default();
        let (quota, _) = Quota::new(2, 600);
        let app = limited_websocket_routes(&state, quota, &mut sweeper);

        let room_id = Uuid::new_v4();
        let other_room = Uuid::new_v4();
        let claims = WsTokenClaims::new(room_id, 30, &state.config.jwt_issuer);
        let token = sign_token(&claims, &state.jwt_secret).unwrap();
        let forged = sign_token(&claims, &[7u8; 32]).unwrap();

        // Far more than the burst, from the address the user will come from.
        for _ in 0..10 {
            assert_eq!(upgrade(&app, room_id, None).await, StatusCode::UNAUTHORIZED);
            assert_eq!(
                upgrade(&app, room_id, Some("not-a-token")).await,
                StatusCode::UNAUTHORIZED
            );
            assert_eq!(
                upgrade(&app, room_id, Some(&forged)).await,
                StatusCode::UNAUTHORIZED,
                "a token signed with another key is not a token"
            );
            assert_eq!(
                upgrade(&app, other_room, Some(&token)).await,
                StatusCode::FORBIDDEN,
                "a token for another room is not a token for this one"
            );
        }
        assert_eq!(
            sweeper.sweep_all(),
            0,
            "refused upgrades must not even create a bucket"
        );

        // The user behind the same address still has the whole budget. A
        // request made without a real connection cannot be upgraded, so the
        // handler refuses these, but not as unauthenticated or rate limited.
        for _ in 0..2 {
            let status = upgrade(&app, room_id, Some(&token)).await;
            assert_ne!(status, StatusCode::UNAUTHORIZED);
            assert_ne!(status, StatusCode::TOO_MANY_REQUESTS);
        }
        assert_eq!(
            upgrade(&app, room_id, Some(&token)).await,
            StatusCode::TOO_MANY_REQUESTS
        );
        // An exhausted bucket still refuses a token-less upgrade as
        // unauthenticated, without telling it anything about the quota.
        assert_eq!(upgrade(&app, room_id, None).await, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn only_the_login_page_may_submit_a_form() {
        let app = Router::new()
            .route("/", get(|| async { "page" }))
            .route("/login", get(|| async { "login" }))
            .route("/static/:file", get(|| async { "file" }))
            .layer(middleware::from_fn(add_security_headers));
        let policy = |path: &'static str| {
            let app = app.clone();
            async move {
                let request = Request::builder().uri(path).body(Body::empty()).unwrap();
                let response = app.oneshot(request).await.unwrap();
                response.headers()[header::CONTENT_SECURITY_POLICY]
                    .to_str()
                    .unwrap()
                    .to_string()
            }
        };
        for path in [
            "/",
            "/static/index.html",
            "/static/chat.html",
            "/static/privacy.html",
            "/static/terms.html",
        ] {
            let csp = policy(path).await;
            assert!(csp.contains("form-action 'none';"), "{path}: {csp}");
        }
        for path in ["/login", "/static/login.html"] {
            let csp = policy(path).await;
            assert!(csp.contains("form-action 'self';"), "{path}: {csp}");
        }
    }

    #[test]
    fn the_ws_hosts_cannot_add_a_directive() {
        let ws_hosts = config::csp_ws_hosts(Some("wss://relay.example:8443"), false).unwrap();
        let csp = build_csp(&ws_hosts, false);
        let pages = csp.pages.to_str().unwrap();
        assert!(pages.contains("connect-src 'self' wss://relay.example:8443;"));
        assert_eq!(pages.matches(';').count(), 8, "{pages}");
        assert!(config::csp_ws_hosts(Some("wss://a; frame-ancestors *"), false).is_err());
    }

    #[tokio::test]
    async fn anonymous_mode_keeps_the_api_quota_for_every_client() {
        // Without a password gate there is no session to check, and the
        // quota is the only limit on room and token requests.
        let state = AppState::new(10, Config::for_tests());
        let mut sweeper = RetentionSweeper::default();
        let (quota, _) = Quota::new(2, 600);
        let app = limited_api_routes(&state, quota, &mut sweeper);

        for _ in 0..2 {
            assert_ne!(
                post_api(&app, "/api/rooms", None).await,
                StatusCode::TOO_MANY_REQUESTS
            );
        }
        assert_eq!(
            post_api(&app, "/api/rooms", None).await,
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(sweeper.sweep_all(), 1);
    }
}
