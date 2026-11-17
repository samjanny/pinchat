//! Per-client request quotas for the HTTP endpoints.
//!
//! # Semantics
//!
//! Every quota is a token bucket described by two numbers, `burst` and
//! `window`: a client may spend `burst` requests at once, and the bucket
//! refills evenly so that a full `burst` is available again one `window`
//! after it was emptied. Sustained throughput is therefore `burst` requests
//! per `window`, which is what `.env.example` documents ("100 requests per 10
//! minutes").
//!
//! The limiter library takes the interval after which *one* request is
//! replenished, not the window. Passing the window there gave "burst, then
//! one request per window": 100 room or token requests and afterwards a
//! single one every ten minutes, so a client that once spent its burst, or a
//! group of users behind one address, stayed locked out for hours.
//! [`Quota::replenish_interval`] is the conversion.
//!
//! # Keying
//!
//! Buckets are keyed by HMAC(client IP) and are shared by everyone behind
//! that address. That is deliberate: with a shared site password a session
//! is free to mint, so a per-session bucket would hand an abuser a fresh
//! budget on every login. The consequence is that users behind one NAT, VPN
//! or Tor exit share one budget. To keep that from being exploitable without
//! credentials, the API quotas run *behind* the session check (see
//! `main.rs`): a request without a valid session is refused before it can
//! spend the budget of the people it shares an address with. The login
//! endpoint cannot be protected that way, it is the authentication step.
//!
//! # Retention
//!
//! A bucket is the only per-client state the server keeps between requests.
//! Its key is a keyed hash of the address and its value encodes when the
//! bucket will be full again. The limiter library stores that instant one
//! replenish interval late, so it lies at most one `window` plus one
//! replenish interval after the last accepted request. [`RetentionSweeper`]
//! deletes every bucket whose instant has passed, so a client's hashed
//! address survives its last request by at most [`Quota::retention`]. The
//! privacy policy promises fifteen minutes; [`Quota::new`] shortens the
//! window where needed so that the promise holds for any configuration.

use std::time::Duration;

/// How often full buckets are deleted.
pub const SWEEP_INTERVAL: Duration = Duration::from_secs(30);

/// Upper bound on how long a hashed client address may outlive the client's
/// last request. This is the figure stated in `static/privacy.html`; change
/// the two together.
pub const MAX_RETENTION: Duration = Duration::from_secs(15 * 60);

/// A token bucket: `burst` requests, refilled evenly over `window`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Quota {
    pub burst: u32,
    pub window: Duration,
}

impl Quota {
    /// Build a quota from configuration values. A window whose retention
    /// would exceed [`MAX_RETENTION`] is shortened to the longest one that
    /// fits; the second value reports whether that happened so the caller
    /// can tell the operator.
    ///
    /// # Panics
    /// If `burst` or `window_secs` is zero. Configuration validation rejects
    /// both before this is reached.
    pub fn new(burst: u32, window_secs: u64) -> (Self, bool) {
        assert!(burst > 0, "quota burst must be greater than 0");
        assert!(window_secs > 0, "quota window must be greater than 0");
        let requested = Duration::from_secs(window_secs);
        let window = requested.min(Self::max_window(burst));
        (Self { burst, window }, window != requested)
    }

    /// Longest window, in whole seconds, whose retention stays within
    /// [`MAX_RETENTION`] for the given burst.
    ///
    /// Retention is `window * (burst + 1) / burst` plus one sweep interval,
    /// so small bursts leave less room: 725 s for a burst of 5, 861 s for a
    /// burst of 100.
    pub fn max_window(burst: u32) -> Duration {
        let budget = (MAX_RETENTION - SWEEP_INTERVAL).as_secs();
        let burst = u64::from(burst);
        Duration::from_secs(budget * burst / (burst + 1))
    }

    /// Interval after which one request is replenished.
    pub fn replenish_interval(&self) -> Duration {
        (self.window / self.burst).max(Duration::from_nanos(1))
    }

    /// Longest time a client's bucket can outlive its last accepted request:
    /// the window, the one replenish interval the library adds to the stored
    /// instant, and the wait for the next sweep.
    pub fn retention(&self) -> Duration {
        self.window + self.replenish_interval() + SWEEP_INTERVAL
    }
}

/// Deletes rate-limit buckets that are full again.
///
/// Without it the limiter never forgets a key: every hashed address that
/// ever reached a limited endpoint stayed in memory, with the time of its
/// last request, until the process was restarted.
#[derive(Default)]
pub struct RetentionSweeper {
    sweeps: Vec<Box<dyn Fn() -> usize + Send + Sync>>,
}

impl RetentionSweeper {
    /// Register one limiter store. The closure deletes the store's stale
    /// buckets and returns how many are left.
    pub fn register(&mut self, sweep: impl Fn() -> usize + Send + Sync + 'static) {
        self.sweeps.push(Box::new(sweep));
    }

    /// Sweep every registered store once. Returns the number of buckets that
    /// remain, across all stores.
    pub fn sweep_all(&self) -> usize {
        self.sweeps.iter().map(|sweep| sweep()).sum()
    }

    /// Sweep on a fixed interval for the lifetime of the process.
    pub fn spawn(self, interval: Duration) {
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            loop {
                ticker.tick().await;
                self.sweep_all();
            }
        });
    }
}

/// Build the rate-limit layer for one quota, keyed by HMAC(client IP), and
/// register its store with a [`RetentionSweeper`].
///
/// A macro and not a function because the layer's middleware type parameter
/// comes from a crate this one does not depend on directly, so it cannot be
/// named in a signature. Everything is inferred at the expansion site.
macro_rules! ip_quota_layer {
    ($state:expr, $quota:expr, $sweeper:expr) => {{
        let quota: $crate::rate_limit::Quota = $quota;
        let config = ::std::sync::Arc::new(
            ::tower_governor::governor::GovernorConfigBuilder::default()
                .key_extractor($crate::rate_limit_extractor::HmacIpKeyExtractor::new(
                    ::std::sync::Arc::new($state.clone()),
                ))
                .period(quota.replenish_interval())
                .burst_size(quota.burst)
                .finish()
                .expect("quota burst and window are validated as non-zero"),
        );
        let limiter = config.limiter().clone();
        $sweeper.register(move || {
            limiter.retain_recent();
            limiter.shrink_to_fit();
            limiter.len()
        });
        ::tower_governor::GovernorLayer { config }
    }};
}
pub(crate) use ip_quota_layer;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::state::AppState;
    use axum::{
        Router,
        body::Body,
        extract::ConnectInfo,
        http::{Request, StatusCode},
        routing::get,
    };
    use std::net::SocketAddr;
    use tower::ServiceExt;

    async fn hit(app: &Router, client: [u8; 4]) -> StatusCode {
        let mut request = Request::builder().uri("/").body(Body::empty()).unwrap();
        request
            .extensions_mut()
            .insert(ConnectInfo(SocketAddr::from((client, 40000))));
        app.clone().oneshot(request).await.unwrap().status()
    }

    fn limited_app(quota: Quota) -> (Router, RetentionSweeper) {
        let state = AppState::new(10, Config::for_tests());
        let mut sweeper = RetentionSweeper::default();
        let app = Router::new()
            .route("/", get(|| async { "ok" }))
            .layer(ip_quota_layer!(state, quota, sweeper));
        (app, sweeper)
    }

    #[test]
    fn documented_defaults_refill_a_full_burst_per_window() {
        let (room_token, clamped) = Quota::new(100, 600);
        assert!(!clamped);
        assert_eq!(room_token.replenish_interval(), Duration::from_secs(6));

        let (ws, clamped) = Quota::new(30, 60);
        assert!(!clamped);
        assert_eq!(ws.replenish_interval(), Duration::from_secs(2));

        let (login, clamped) = Quota::new(5, 720);
        assert!(!clamped);
        assert_eq!(login.replenish_interval(), Duration::from_secs(144));

        for quota in [room_token, ws, login] {
            assert!(quota.retention() <= MAX_RETENTION);
        }
    }

    #[test]
    fn window_is_shortened_so_retention_stays_within_the_published_bound() {
        // The figure published in static/privacy.html.
        assert_eq!(MAX_RETENTION, Duration::from_secs(900));

        let (quota, clamped) = Quota::new(5, 900);
        assert!(clamped, "5 per 15 minutes would be kept for 18.5 minutes");
        assert_eq!(quota.window, Duration::from_secs(725));

        let (quota, clamped) = Quota::new(100, 86_400);
        assert!(clamped);
        assert_eq!(quota.window, Duration::from_secs(861));

        // Whatever the operator configures, the bound holds, and the window
        // is not shortened more than necessary.
        for burst in [1, 2, 3, 5, 30, 100, 1_000, u32::MAX] {
            for window_secs in [1, 59, 600, 725, 726, 870, 900, 3_600, u64::from(u32::MAX)] {
                let (quota, clamped) = Quota::new(burst, window_secs);
                assert!(
                    quota.retention() <= MAX_RETENTION,
                    "burst {burst}, window {window_secs}s is kept for {:?}",
                    quota.retention()
                );
                if clamped {
                    let one_second_more = Quota {
                        burst,
                        window: quota.window + Duration::from_secs(1),
                    };
                    assert!(one_second_more.retention() > MAX_RETENTION);
                } else {
                    assert_eq!(quota.window, Duration::from_secs(window_secs));
                }
            }
        }
    }

    #[test]
    fn replenish_interval_is_never_zero() {
        let (quota, _) = Quota::new(u32::MAX, 1);
        assert!(quota.replenish_interval() > Duration::ZERO);
    }

    #[tokio::test]
    async fn bucket_refills_one_request_per_replenish_interval() {
        // 3 requests per 1500 ms: one request back every 500 ms.
        let quota = Quota {
            burst: 3,
            window: Duration::from_millis(1500),
        };
        let (app, _sweeper) = limited_app(quota);
        let client = [203, 0, 113, 7];

        for _ in 0..3 {
            assert_eq!(hit(&app, client).await, StatusCode::OK);
        }
        assert_eq!(hit(&app, client).await, StatusCode::TOO_MANY_REQUESTS);

        // One interval later exactly one request is back, not the whole
        // burst and not nothing. Under the old semantics the next request
        // was only accepted a full window (1500 ms) after the burst.
        tokio::time::sleep(Duration::from_millis(650)).await;
        assert_eq!(hit(&app, client).await, StatusCode::OK);
        assert_eq!(hit(&app, client).await, StatusCode::TOO_MANY_REQUESTS);

        // A full window after the last accepted request the burst is back.
        tokio::time::sleep(Duration::from_millis(1600)).await;
        for _ in 0..3 {
            assert_eq!(hit(&app, client).await, StatusCode::OK);
        }
        assert_eq!(hit(&app, client).await, StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn clients_have_independent_buckets() {
        let quota = Quota {
            burst: 1,
            window: Duration::from_secs(60),
        };
        let (app, _sweeper) = limited_app(quota);
        assert_eq!(hit(&app, [203, 0, 113, 1]).await, StatusCode::OK);
        assert_eq!(
            hit(&app, [203, 0, 113, 1]).await,
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(hit(&app, [203, 0, 113, 2]).await, StatusCode::OK);
    }

    #[tokio::test]
    async fn sweeper_forgets_a_client_within_the_retention_bound() {
        // 2 requests per 1200 ms: replenish interval 600 ms. A drained
        // bucket is deletable 1800 ms after its last accepted request (the
        // window plus one interval), a single request after 1200 ms.
        let quota = Quota {
            burst: 2,
            window: Duration::from_millis(1200),
        };
        let (app, sweeper) = limited_app(quota);

        // Two clients drain their buckets; a third makes a single request.
        for client in [[198, 51, 100, 1], [198, 51, 100, 2]] {
            assert_eq!(hit(&app, client).await, StatusCode::OK);
            assert_eq!(hit(&app, client).await, StatusCode::OK);
        }
        assert_eq!(hit(&app, [198, 51, 100, 3]).await, StatusCode::OK);

        // While the buckets are not full the keys must stay, or the sweep
        // would hand every client a fresh burst.
        assert_eq!(sweeper.sweep_all(), 3);
        assert_eq!(
            hit(&app, [198, 51, 100, 1]).await,
            StatusCode::TOO_MANY_REQUESTS
        );

        tokio::time::sleep(Duration::from_millis(1400)).await;
        assert_eq!(
            sweeper.sweep_all(),
            2,
            "the single-request client is forgotten first"
        );

        // Past the window plus one replenish interval nothing is left.
        tokio::time::sleep(Duration::from_millis(600)).await;
        assert_eq!(
            sweeper.sweep_all(),
            0,
            "no hashed address may outlive Quota::retention"
        );

        // Forgetting a full bucket changes nothing for the client.
        assert_eq!(hit(&app, [198, 51, 100, 1]).await, StatusCode::OK);
    }

    #[tokio::test]
    async fn refused_requests_do_not_extend_retention() {
        // 1 request per 300 ms: deletable 600 ms after the accepted request.
        let quota = Quota {
            burst: 1,
            window: Duration::from_millis(300),
        };
        let (app, sweeper) = limited_app(quota);
        let client = [198, 51, 100, 9];
        assert_eq!(hit(&app, client).await, StatusCode::OK);

        // Hammering a drained bucket must not keep the key alive.
        let deadline = tokio::time::Instant::now() + Duration::from_millis(250);
        while tokio::time::Instant::now() < deadline {
            assert_eq!(hit(&app, client).await, StatusCode::TOO_MANY_REQUESTS);
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(sweeper.sweep_all(), 1);
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert_eq!(sweeper.sweep_all(), 0);
    }
}
