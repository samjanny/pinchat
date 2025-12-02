mod auth;
mod auth_middleware;
mod challenge_cache;
mod cleanup;
mod config;
mod handlers;
mod ip_hash;
mod jwt;
mod models;
mod pow;
mod rate_limit_extractor;
mod session;
mod state;

use axum::{
    http::{header, HeaderValue, Method},
    middleware::{self, Next},
    response::Response,
    routing::{get, post},
    Router,
};
use axum_server::tls_rustls::RustlsConfig;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tower::ServiceBuilder;
use tower_governor::{governor::GovernorConfigBuilder, GovernorLayer};
use tower_http::{
    cors::CorsLayer,
    services::ServeDir,
    trace::{DefaultMakeSpan, TraceLayer},
};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::auth_middleware::{redirect_if_authenticated, require_auth, require_auth_api};
use crate::cleanup::start_cleanup_task;
use crate::config::Config;
use crate::handlers::{
    create_room, generate_ws_token, get_csrf_token, homepage, login_page, login_submit, logout,
    room_page, ws_handler,
};
use crate::rate_limit_extractor::HmacIpKeyExtractor;
use crate::state::AppState;

/// Build CSP header value based on environment
/// In production, restricts WebSocket to specific host via CSP_WS_HOST env var
fn build_csp_header() -> String {
    // Default policy allows WebSocket connections to the same host; configure
    // CSP_WS_HOST (e.g., wss://yourdomain.com) to permit additional origins in production
    let ws_hosts = std::env::var("CSP_WS_HOST").unwrap_or_else(|_| "'self'".to_string());

    // Development mode includes localhost endpoints to support local testing
    let connect_src = if std::env::var("PRIVACY_MODE").unwrap_or_default() == "development" {
        format!("'self' ws://localhost:* wss://localhost:* {}", ws_hosts)
    } else {
        format!("'self' {}", ws_hosts)
    };

    format!(
        "default-src 'self'; \
         script-src 'self'; \
         style-src 'self'; \
         img-src 'self' data: blob:; \
         connect-src {}; \
         frame-ancestors 'none'; \
         base-uri 'self'; \
         form-action 'self';",
        connect_src
    )
}

/// Security headers middleware
/// Adds CSP, X-Frame-Options, X-Content-Type-Options for defense-in-depth
async fn add_security_headers(req: axum::extract::Request, next: Next) -> Response {
    // Cache CSP header (computed once per process)
    static CSP_HEADER: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    let csp = CSP_HEADER.get_or_init(build_csp_header);

    let mut response = next.run(req).await;

    let headers = response.headers_mut();

    // Content Security Policy
    // - default-src 'self': Restrict all resources to the application origin
    // - script-src 'self': Allow only self-hosted scripts (Alpine.js is self-hosted)
    // - style-src 'self': Permit only self-hosted stylesheets; inline styles are blocked
    // - connect-src: Limit connections to the application origin and configured WS host
    // - frame-ancestors 'none': Prevent clickjacking by disallowing framing
    // Inline styles have been moved to CSS files to satisfy CSP enforcement
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_str(csp)
            .unwrap_or_else(|_| HeaderValue::from_static("default-src 'self'")),
    );

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

    response
}

#[tokio::main]
async fn main() {
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
        .unwrap_or_else(|_| "1000".to_string())
        .parse::<usize>()
        .unwrap_or(1000);

    tracing::info!("Maximum concurrent rooms: {}", max_rooms);

    // Load configuration from environment variables
    let config = Config::from_env();
    tracing::info!("Configuration loaded: rate limits, PoW difficulty, TTLs");

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

    // Configure rate limiting for room creation and token generation
    // Layer 1: IP-based rate limiting with HMAC(IP) for privacy
    // Restrictive limit (configurable) to prevent abuse while allowing legitimate use
    let governor_config = Arc::new(
        GovernorConfigBuilder::default()
            .key_extractor(HmacIpKeyExtractor::new(Arc::new(app_state.clone())))
            .per_second(0) // Disable per-second limit
            .burst_size(config.room_token_burst_size) // Configurable burst size
            .period(Duration::from_secs(config.room_token_period_secs)) // Configurable period
            .finish()
            .unwrap(),
    );

    let rate_limiter = ServiceBuilder::new().layer(GovernorLayer {
        config: governor_config,
    });

    // Configure CORS
    let cors = CorsLayer::new()
        .allow_origin("https://localhost:3000".parse::<HeaderValue>().unwrap())
        .allow_methods([Method::GET, Method::POST])
        .allow_headers([
            header::CONTENT_TYPE,
            header::HeaderName::from_static("x-pow-nonce"),
            header::HeaderName::from_static("x-pow-challenge"),
            header::HeaderName::from_static("x-pow-difficulty"),
        ]);

    // Configure rate limiting for login endpoint (brute force protection)
    let login_governor_config = Arc::new(
        GovernorConfigBuilder::default()
            .key_extractor(HmacIpKeyExtractor::new(Arc::new(app_state.clone())))
            .per_second(0)
            .burst_size(config.login_burst_size) // 5 attempts
            .period(Duration::from_secs(config.login_period_secs)) // per 15 minutes
            .finish()
            .unwrap(),
    );

    let login_rate_limiter = ServiceBuilder::new().layer(GovernorLayer {
        config: login_governor_config,
    });

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

    // Build the router

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
        // Serve static files (CSS, JS, HTML)
        .nest_service("/static", ServeDir::new("static"))
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

    // Apply rate limiting to room creation endpoint (with auth)
    let rate_limited_create_room = Router::new()
        .route("/api/rooms", post(create_room))
        .layer(middleware::from_fn_with_state(
            app_state.clone(),
            require_auth_api,
        ))
        .layer(rate_limiter.clone())
        .with_state(app_state.clone());

    // Apply rate limiting to WebSocket token endpoint (with auth)
    let rate_limited_ws_token = Router::new()
        .route("/api/ws-token/:room_id", get(generate_ws_token))
        .layer(middleware::from_fn_with_state(
            app_state.clone(),
            require_auth_api,
        ))
        .layer(rate_limiter.clone())
        .with_state(app_state.clone());

    // Apply rate limiting to WebSocket upgrade endpoint (with auth)
    // Restrictive (configurable) to prevent connection flooding abuse
    let ws_governor_config = Arc::new(
        GovernorConfigBuilder::default()
            .key_extractor(HmacIpKeyExtractor::new(Arc::new(app_state.clone())))
            .per_second(0)
            .burst_size(config.ws_conn_burst_size) // Configurable connections per period
            .period(Duration::from_secs(config.ws_conn_period_secs)) // Configurable period
            .finish()
            .unwrap(),
    );

    let ws_rate_limiter = ServiceBuilder::new().layer(GovernorLayer {
        config: ws_governor_config,
    });

    // Note: WebSocket endpoint uses JWT token authentication (passed as query param)
    // instead of session cookie auth. The token is obtained from /api/ws-token
    // which already requires session authentication.
    let rate_limited_websocket = Router::new()
        .route("/ws/:room_id", get(ws_handler))
        .layer(ws_rate_limiter)
        .with_state(app_state);

    // Merge routers
    app = app.merge(rate_limited_create_room);
    app = app.merge(rate_limited_ws_token);
    app = app.merge(rate_limited_websocket);

    // Add security headers middleware (CSP, X-Frame-Options, etc.)
    app = app.layer(middleware::from_fn(add_security_headers));

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

        if let Err(e) = axum_server::bind_rustls(addr, tls_config)
            .serve(app.into_make_service_with_connect_info::<SocketAddr>())
            .await
        {
            tracing::error!("Server error: {}", e);
        }
    } else {
        // HTTP mode - allowed if FORCE_HTTP=true (reverse proxy) or PRIVACY_MODE=development
        if !config.force_http && privacy_mode != "development" {
            eprintln!("❌ FATAL: TLS certificates not found at certs/cert.pem and certs/key.pem");
            eprintln!("   PinChat requires HTTPS in production to protect passwords and sessions.");
            eprintln!("   ");
            eprintln!("   To fix this:");
            eprintln!("   1. Generate certificates: mkdir -p certs && openssl req -x509 -newkey rsa:4096 -keyout certs/key.pem -out certs/cert.pem -days 365 -nodes");
            eprintln!("   2. Or set PRIVACY_MODE=development for local testing (insecure!)");
            eprintln!("   3. Or set FORCE_HTTP=true if running behind a TLS-terminating reverse proxy");
            std::process::exit(1);
        }

        if config.force_http {
            // FORCE_HTTP mode - for reverse proxy setups
            tracing::info!("Starting HTTP server on http://{} (FORCE_HTTP=true, TLS handled by reverse proxy)", addr);
            eprintln!("ℹ️  Starting HTTP server (FORCE_HTTP=true)");
            eprintln!("   TLS termination expected to be handled by reverse proxy.");
            if !config.force_secure_cookies {
                eprintln!("   ⚠️  FORCE_SECURE_COOKIES not set - cookies may not have Secure flag!");
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

        if let Err(e) = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        {
            tracing::error!("Server error: {}", e);
        }
    }
}
