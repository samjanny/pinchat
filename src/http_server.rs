//! The relay's HTTP listener: accepting connections, TLS, and HTTP/1.1 up
//! to the WebSocket upgrade.
//!
//! # Why it is the relay's own
//!
//! `axum::serve` and `axum_server` served every connection with hyper's
//! defaults and no limit of their own. Without a timer hyper's header read
//! timeout never ran, a request head could take about 400 KB of buffer, and
//! nothing bounded how many connections were open or for how long. A
//! connection that sent part of a request head and stopped, or nothing at
//! all after its TLS handshake, was kept for ever: 300 of each took 125 MiB
//! and were all still open 70 seconds later, and about 1250 such
//! connections reached a 512 MiB ceiling. None of it was counted by the
//! WebSocket admission control, which starts at the upgrade.
//!
//! # What bounds a connection before its upgrade
//!
//! - **How many.** It holds one of `MAX_HTTP_CONNECTIONS` slots from the
//!   moment it is accepted. When all are taken the relay accepts nothing
//!   until one is free: new connections wait in the kernel's accept queue
//!   instead of being refused, so a burst of page loads is slowed, not
//!   broken.
//! - **How many from one address.** A connection from a client address (an
//!   IPv6 /64, and [`PREFIX_SHARE`] times as many for its /48, as for
//!   WebSocket connections) also holds one of
//!   `MAX_HTTP_CONNECTIONS_PER_ADDRESS`; one beyond it is closed as soon as
//!   it is accepted. A connection from a trusted proxy counts in the total
//!   only: it carries many clients, and the proxy has limits of its own.
//! - **How long.** The TLS handshake has [`TLS_HANDSHAKE_TIMEOUT`]. A request
//!   head has [`HEADER_READ_TIMEOUT`], counted from the moment the
//!   connection is idle, so the same time also closes a kept-alive
//!   connection that sends nothing more. [`MAX_AGE`] after it was accepted
//!   the connection reads no further request, and the one in progress has
//!   [`SHUTDOWN_GRACE`] to finish; that bounds a request body that trickles
//!   in and a response to a peer that does not read it. A trusted proxy
//!   sends whole request heads and buffers bodies and responses itself, so
//!   its connections are only closed after [`PROXY_IDLE_TIMEOUT`] without a
//!   request, which is longer than nginx keeps an idle upstream connection
//!   (60 seconds): nginx closes first, and never sends a request on a
//!   connection the relay is closing.
//! - **How much.** A request head may take [`MAX_HEAD`] bytes; a longer one
//!   is answered with 431 and the connection closed. Request bodies are
//!   bounded by the router (`MAX_REQUEST_BODY` in main.rs).
//! - **HTTP/1.1 only.** HTTP/2 would carry many requests on one connection,
//!   none of them bounded by the above. The browser client does not need
//!   it: its WebSockets use HTTP/1.1, and behind a reverse proxy the proxy
//!   speaks HTTP/1.1 to the relay. Over TLS only `http/1.1` is offered in
//!   ALPN.
//!
//! An upgraded connection gives both slots back the moment it is upgraded;
//! from then on it is counted by the WebSocket admission control
//! (`MAX_WS_CONNECTIONS`). See "Relay Memory" in SECURITY.md for what a
//! connection costs.

use crate::config::Config;
use crate::ip_hash::{hash_ip, hash_ipv6_prefix48, is_trusted_proxy};
use axum::Router;
use axum::extract::ConnectInfo;
use axum_server::accept::Accept;
use axum_server::tls_rustls::{RustlsAcceptor, RustlsConfig};
use dashmap::DashMap;
use hyper::server::conn::http1;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::service::TowerToHyperService;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::Instant;
use tower::Layer;

/// Time for a TLS handshake.
pub const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Time for a request head, counted from the moment the connection is idle:
/// accepted, or done with its previous request.
pub const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a connection from a trusted proxy may stay without a request.
pub const PROXY_IDLE_TIMEOUT: Duration = Duration::from_secs(75);
/// Age at which a connection that was not upgraded reads no more requests.
pub const MAX_AGE: Duration = Duration::from_secs(60);
/// Time the request in progress then has to finish.
pub const SHUTDOWN_GRACE: Duration = Duration::from_secs(30);
/// Largest request head, the most hyper buffers for a connection. As much
/// as nginx accepts by default (four buffers of 8 KiB), so that the relay
/// refuses nothing its proxy passes on.
pub const MAX_HEAD: usize = 32 * 1024;
/// Connections of one IPv6 /48, in addresses' worth (see `app_state.rs`,
/// `PREFIX_SHARE_FACTOR`, the same factor for WebSocket connections).
pub const PREFIX_SHARE: usize = 4;

/// The bounds of a connection before its upgrade.
#[derive(Debug, Clone)]
pub struct Limits {
    pub max_connections: usize,
    pub max_per_address: usize,
    pub tls_handshake_timeout: Duration,
    pub header_read_timeout: Duration,
    pub proxy_idle_timeout: Duration,
    pub max_age: Duration,
    pub shutdown_grace: Duration,
    pub max_head: usize,
}

impl Limits {
    pub fn from_config(config: &Config) -> Self {
        Self {
            max_connections: config.max_http_connections,
            max_per_address: config.max_http_connections_per_address,
            tls_handshake_timeout: TLS_HANDSHAKE_TIMEOUT,
            header_read_timeout: HEADER_READ_TIMEOUT,
            proxy_idle_timeout: PROXY_IDLE_TIMEOUT,
            max_age: MAX_AGE,
            shutdown_grace: SHUTDOWN_GRACE,
            max_head: MAX_HEAD,
        }
    }
}

/// Offer only HTTP/1.1 in the TLS handshake (see the module documentation).
pub fn offer_http1_only(tls: &RustlsConfig) {
    let mut server_config = (*tls.get_inner()).clone();
    server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
    tls.reload_from_config(Arc::new(server_config));
}

/// Counts the connections that have not been upgraded.
struct Gate {
    slots: Arc<Semaphore>,
    max_per_address: usize,
    /// Open connections per keyed address hash and per keyed /48 hash.
    /// An entry lives while one of its connections does.
    held: Arc<DashMap<String, usize>>,
    trusted_proxies: Vec<String>,
    ip_hash_secret: [u8; 32],
}

/// What a connection holds until it ends or is upgraded.
struct Admission {
    _slot: OwnedSemaphorePermit,
    keys: Vec<String>,
    held: Arc<DashMap<String, usize>>,
    from_proxy: bool,
}

impl Drop for Admission {
    fn drop(&mut self) {
        for key in &self.keys {
            if let Some(mut count) = self.held.get_mut(key) {
                *count = count.saturating_sub(1);
            }
            self.held.remove_if(key, |_, count| *count == 0);
        }
    }
}

impl Gate {
    /// Admit a connection from `peer`, which already holds `slot`, or
    /// `None` if its address or its /48 is at its limit.
    fn admit(&self, peer: IpAddr, slot: OwnedSemaphorePermit) -> Option<Admission> {
        let peer = peer.to_canonical();
        let mut admission = Admission {
            _slot: slot,
            keys: Vec::with_capacity(2),
            held: self.held.clone(),
            from_proxy: is_trusted_proxy(&peer, &self.trusted_proxies),
        };
        if admission.from_proxy {
            return Some(admission);
        }
        let ip = peer.to_string();
        let mut limits = vec![(hash_ip(&ip, &self.ip_hash_secret), self.max_per_address)];
        if let Some(prefix) = hash_ipv6_prefix48(&ip, &self.ip_hash_secret) {
            limits.push((prefix, self.max_per_address.saturating_mul(PREFIX_SHARE)));
        }
        for (key, limit) in limits {
            {
                let mut count = self.held.entry(key.clone()).or_insert(0);
                if *count >= limit {
                    drop(count);
                    // Dropping `admission` gives back what was taken.
                    self.held.remove_if(&key, |_, count| *count == 0);
                    return None;
                }
                *count += 1;
            }
            admission.keys.push(key);
        }
        Some(admission)
    }

    #[cfg(test)]
    fn open(&self, key: &str) -> usize {
        self.held.get(key).map_or(0, |count| *count)
    }
}

/// Accept connections on `listener` and serve `router` on them, over TLS
/// when `tls` is given, until the process ends.
pub async fn serve(
    listener: TcpListener,
    tls: Option<RustlsConfig>,
    router: Router,
    limits: Limits,
    trusted_proxies: Vec<String>,
    ip_hash_secret: [u8; 32],
) {
    let gate = Arc::new(Gate {
        slots: Arc::new(Semaphore::new(limits.max_connections)),
        max_per_address: limits.max_per_address,
        held: Arc::new(DashMap::new()),
        trusted_proxies,
        ip_hash_secret,
    });
    let acceptor =
        tls.map(|tls| RustlsAcceptor::new(tls).handshake_timeout(limits.tls_handshake_timeout));
    let limits = Arc::new(limits);
    loop {
        // Wait for a slot before accepting: beyond the total, connections
        // queue in the kernel instead of costing anything here.
        let slot = gate
            .slots
            .clone()
            .acquire_owned()
            .await
            .expect("the connection semaphore is never closed");
        let (stream, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(error) => {
                if !is_connection_error(&error) {
                    // Most likely out of file descriptors; give it a moment.
                    tracing::error!("Failed to accept a connection: {}", error);
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                continue;
            }
        };
        let Some(admission) = gate.admit(peer.ip(), slot) else {
            tracing::debug!("HTTP connection refused: its address holds all it may");
            continue;
        };
        tokio::spawn(connection(
            stream,
            peer,
            admission,
            acceptor.clone(),
            router.clone(),
            limits.clone(),
        ));
    }
}

fn is_connection_error(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::ConnectionReset
    )
}

async fn connection(
    stream: TcpStream,
    peer: SocketAddr,
    admission: Admission,
    acceptor: Option<RustlsAcceptor>,
    router: Router,
    limits: Arc<Limits>,
) {
    let accepted_at = Instant::now();
    match acceptor {
        Some(acceptor) => {
            if let Ok((stream, ())) = acceptor.accept(stream, ()).await {
                serve_http(stream, peer, &admission, router, &limits, accepted_at).await;
            }
        }
        None => serve_http(stream, peer, &admission, router, &limits, accepted_at).await,
    }
    // `admission` is dropped here: when the connection ends, or the moment
    // it has been upgraded and handed over to the WebSocket handler.
}

async fn serve_http<IO>(
    io: IO,
    peer: SocketAddr,
    admission: &Admission,
    router: Router,
    limits: &Limits,
    accepted_at: Instant,
) where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let service = TowerToHyperService::new(axum::Extension(ConnectInfo(peer)).layer(router));
    let mut builder = http1::Builder::new();
    builder
        .timer(TokioTimer::new())
        .max_buf_size(limits.max_head)
        .header_read_timeout(if admission.from_proxy {
            limits.proxy_idle_timeout
        } else {
            limits.header_read_timeout
        });
    let connection = builder
        .serve_connection(TokioIo::new(io), service)
        .with_upgrades();
    tokio::pin!(connection);

    if admission.from_proxy {
        let _ = connection.await;
        return;
    }
    tokio::select! {
        _ = connection.as_mut() => return,
        _ = tokio::time::sleep_until(accepted_at + limits.max_age) => {}
    }
    connection.as_mut().graceful_shutdown();
    let _ = tokio::time::timeout(limits.shutdown_grace, connection).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::{get, post};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn test_limits() -> Limits {
        Limits {
            max_connections: 16,
            max_per_address: 16,
            tls_handshake_timeout: Duration::from_secs(10),
            header_read_timeout: Duration::from_secs(10),
            proxy_idle_timeout: Duration::from_secs(10),
            max_age: Duration::from_secs(60),
            shutdown_grace: Duration::from_secs(10),
            max_head: MAX_HEAD,
        }
    }

    fn app() -> Router {
        Router::new()
            .route("/", get(|| async { "ok" }))
            .route("/echo", post(|body: String| async move { body }))
            .route(
                "/upgrade",
                get(|mut request: axum::extract::Request| async move {
                    let on_upgrade = hyper::upgrade::on(&mut request);
                    tokio::spawn(async move {
                        if let Ok(upgraded) = on_upgrade.await {
                            // Hold the upgraded connection for a while.
                            let _upgraded = upgraded;
                            tokio::time::sleep(Duration::from_secs(5)).await;
                        }
                    });
                    axum::response::Response::builder()
                        .status(axum::http::StatusCode::SWITCHING_PROTOCOLS)
                        .header("connection", "upgrade")
                        .header("upgrade", "test")
                        .body(axum::body::Body::empty())
                        .unwrap()
                }),
            )
    }

    async fn start(limits: Limits, trusted_proxies: Vec<String>) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve(
            listener,
            None,
            app(),
            limits,
            trusted_proxies,
            [9u8; 32],
        ));
        addr
    }

    /// Read until the peer closes, or give up after `within`. Returns what
    /// was read, or `None` if the connection was still open.
    async fn read_to_close(stream: &mut TcpStream, within: Duration) -> Option<Vec<u8>> {
        let mut received = Vec::new();
        let deadline = Instant::now() + within;
        loop {
            let mut buf = [0u8; 4096];
            match tokio::time::timeout_at(deadline, stream.read(&mut buf)).await {
                Err(_) => return None,
                Ok(Ok(0)) | Ok(Err(_)) => return Some(received),
                Ok(Ok(n)) => received.extend_from_slice(&buf[..n]),
            }
        }
    }

    async fn get_ok(addr: SocketAddr) -> TcpStream {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();
        let mut buf = [0u8; 256];
        let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
            .await
            .expect("a response")
            .unwrap();
        assert!(buf[..n].starts_with(b"HTTP/1.1 200"), "{:?}", &buf[..n]);
        stream
    }

    #[tokio::test]
    async fn a_partial_request_head_and_an_idle_connection_are_closed_in_time() {
        let mut limits = test_limits();
        limits.header_read_timeout = Duration::from_millis(400);
        let addr = start(limits, vec![]).await;

        let mut partial = TcpStream::connect(addr).await.unwrap();
        partial
            .write_all(b"GET / HTTP/1.1\r\nHost: x\r\nX-Pad: aaaa")
            .await
            .unwrap();
        let mut idle = TcpStream::connect(addr).await.unwrap();
        // A kept-alive connection after its request is idle too.
        let mut kept_alive = get_ok(addr).await;

        let started = Instant::now();
        for stream in [&mut partial, &mut idle, &mut kept_alive] {
            assert!(
                read_to_close(stream, Duration::from_secs(3))
                    .await
                    .is_some(),
                "a connection that sends no complete request head must be closed"
            );
        }
        assert!(started.elapsed() >= Duration::from_millis(300));
    }

    #[tokio::test]
    async fn an_oversized_request_head_is_refused() {
        let addr = start(test_limits(), vec![]).await;
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let mut head = b"GET / HTTP/1.1\r\nHost: x\r\nX-Pad: ".to_vec();
        head.extend(std::iter::repeat_n(b'a', MAX_HEAD + 1024));
        // The relay stops reading once the buffer is full; whatever part of
        // the write it took, the answer is the same.
        let _ = stream.write_all(&head).await;
        let received = read_to_close(&mut stream, Duration::from_secs(3))
            .await
            .expect("the connection is closed");
        assert!(
            received.starts_with(b"HTTP/1.1 431") || received.is_empty(),
            "{:?}",
            String::from_utf8_lossy(&received)
        );
        // A head that fits is fine.
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let mut head = b"GET / HTTP/1.1\r\nHost: x\r\nX-Pad: ".to_vec();
        head.extend(std::iter::repeat_n(b'a', 16 * 1024));
        head.extend_from_slice(b"\r\n\r\n");
        stream.write_all(&head).await.unwrap();
        let mut buf = [0u8; 64];
        let n = stream.read(&mut buf).await.unwrap();
        assert!(buf[..n].starts_with(b"HTTP/1.1 200"));
    }

    #[tokio::test]
    async fn connections_beyond_the_address_limit_are_closed_at_once() {
        let mut limits = test_limits();
        limits.max_per_address = 2;
        let addr = start(limits, vec![]).await;

        let _first = get_ok(addr).await;
        let _second = get_ok(addr).await;
        let mut third = TcpStream::connect(addr).await.unwrap();
        assert!(
            read_to_close(&mut third, Duration::from_secs(2))
                .await
                .is_some_and(|received| received.is_empty()),
            "a third connection from the address is closed without an answer"
        );
        drop(_first);
        // The slot comes back when a connection ends.
        tokio::time::sleep(Duration::from_millis(200)).await;
        let _again = get_ok(addr).await;
    }

    #[tokio::test]
    async fn connections_from_a_trusted_proxy_count_only_in_the_total() {
        let mut limits = test_limits();
        limits.max_per_address = 1;
        let addr = start(limits, vec!["127.0.0.1".to_string()]).await;
        let _held: Vec<_> = futures::future::join_all((0..4).map(|_| get_ok(addr))).await;
    }

    #[tokio::test]
    async fn beyond_the_total_new_connections_wait_instead_of_failing() {
        let mut limits = test_limits();
        limits.max_connections = 2;
        limits.max_per_address = 2;
        let addr = start(limits, vec![]).await;

        let first = get_ok(addr).await;
        let _second = get_ok(addr).await;
        let mut third = TcpStream::connect(addr).await.unwrap();
        third
            .write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();
        let mut buf = [0u8; 64];
        assert!(
            tokio::time::timeout(Duration::from_millis(500), third.read(&mut buf))
                .await
                .is_err(),
            "nothing is served beyond the total"
        );
        drop(first);
        let n = tokio::time::timeout(Duration::from_secs(5), third.read(&mut buf))
            .await
            .expect("served once a slot is free")
            .unwrap();
        assert!(buf[..n].starts_with(b"HTTP/1.1 200"));
    }

    #[tokio::test]
    async fn an_upgraded_connection_gives_its_slot_back() {
        let mut limits = test_limits();
        limits.max_connections = 1;
        limits.max_per_address = 1;
        let addr = start(limits, vec![]).await;

        let mut upgraded = TcpStream::connect(addr).await.unwrap();
        upgraded
            .write_all(
                b"GET /upgrade HTTP/1.1\r\nHost: x\r\nConnection: upgrade\r\nUpgrade: test\r\n\r\n",
            )
            .await
            .unwrap();
        let mut buf = [0u8; 128];
        let n = upgraded.read(&mut buf).await.unwrap();
        assert!(buf[..n].starts_with(b"HTTP/1.1 101"));

        // The upgraded connection is still open, and the only slot is free.
        let _next = get_ok(addr).await;
        assert!(
            tokio::time::timeout(Duration::from_millis(100), upgraded.read(&mut buf))
                .await
                .is_err(),
            "the upgraded connection stays open"
        );
    }

    #[tokio::test]
    async fn a_request_body_that_trickles_in_ends_with_the_connection_age() {
        let mut limits = test_limits();
        limits.max_age = Duration::from_millis(500);
        limits.shutdown_grace = Duration::from_millis(300);
        let addr = start(limits, vec![]).await;

        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(b"POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 1000\r\n\r\nabc")
            .await
            .unwrap();
        let started = Instant::now();
        assert!(
            read_to_close(&mut stream, Duration::from_secs(3))
                .await
                .is_some(),
            "the connection is closed after its age and the grace period"
        );
        assert!(started.elapsed() >= Duration::from_millis(600));
    }

    #[tokio::test]
    async fn http2_is_not_spoken() {
        let addr = start(test_limits(), vec![]).await;
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
            .await
            .unwrap();
        let received = read_to_close(&mut stream, Duration::from_secs(3))
            .await
            .expect("closed");
        assert!(!received.starts_with(b"\x00"), "no HTTP/2 frame comes back");
    }

    #[test]
    fn the_slash_48_holds_four_addresses_worth() {
        let gate = Gate {
            slots: Arc::new(Semaphore::new(1000)),
            max_per_address: 2,
            held: Arc::new(DashMap::new()),
            trusted_proxies: vec!["2001:db8:ffff::1".to_string()],
            ip_hash_secret: [5u8; 32],
        };
        let slot = || gate.slots.clone().try_acquire_owned().unwrap();
        let mut admitted = Vec::new();
        for i in 0..20 {
            let peer: IpAddr = format!("2001:db8:1:{i:x}::1").parse().unwrap();
            for _ in 0..3 {
                if let Some(admission) = gate.admit(peer, slot()) {
                    admitted.push(admission);
                }
            }
        }
        assert_eq!(
            admitted.len(),
            2 * PREFIX_SHARE,
            "eight connections for the /48"
        );
        let prefix = hash_ipv6_prefix48("2001:db8:1::1", &[5u8; 32]).unwrap();
        assert_eq!(gate.open(&prefix), 8);
        // Another /48, and a trusted proxy in any number.
        assert!(
            gate.admit("2001:db8:2::1".parse().unwrap(), slot())
                .is_some()
        );
        let proxied: Vec<_> = (0..10)
            .map(|_| gate.admit("2001:db8:ffff::1".parse().unwrap(), slot()))
            .collect();
        assert!(proxied.iter().all(Option::is_some));

        drop(admitted);
        assert_eq!(gate.open(&prefix), 0);
        assert!(gate.held.is_empty(), "entries go with their connections");
    }
}
