use dashmap::DashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use uuid::Uuid;

/// Represents an authenticated session
///
/// A session lasts `SESSION_TTL_SECS` from the login that created it, the
/// Max-Age of the cookie the browser was given, and activity does not extend
/// it. The cookie is not issued again on activity, so a browser drops it at
/// that point anyway. The server used to slide the expiry forward on every
/// request instead: a session id that had leaked stayed valid for as long
/// as someone kept using it, with no upper bound.
#[derive(Clone)]
pub struct Session {
    pub created_at: Instant,
}

impl Session {
    pub fn new(_id: Uuid) -> Self {
        Self {
            created_at: Instant::now(),
        }
    }

    /// Check if the session has expired based on TTL, counted from login
    pub fn is_expired(&self, ttl: Duration) -> bool {
        self.created_at.elapsed() > ttl
    }
}

/// In-memory session store using DashMap for concurrent access
#[derive(Clone)]
pub struct SessionStore {
    sessions: Arc<DashMap<Uuid, Session>>,
    ttl: Duration,
}

impl SessionStore {
    pub fn new(ttl_secs: u64) -> Self {
        Self {
            sessions: Arc::new(DashMap::new()),
            ttl: Duration::from_secs(ttl_secs),
        }
    }

    /// Create a new session and store it
    pub fn create(&self, session_id: Uuid) -> Session {
        let session = Session::new(session_id);
        self.sessions.insert(session_id, session.clone());
        session
    }

    /// Get a session by ID, returning None if not found or past its TTL
    pub fn get(&self, session_id: &Uuid) -> Option<Session> {
        self.sessions.get(session_id).and_then(|session| {
            if session.is_expired(self.ttl) {
                None
            } else {
                Some(session.clone())
            }
        })
    }

    /// Delete a session
    pub fn delete(&self, session_id: &Uuid) -> bool {
        self.sessions.remove(session_id).is_some()
    }

    /// Remove all sessions that have exceeded their TTL
    pub fn cleanup_expired(&self) -> usize {
        let before = self.sessions.len();
        self.sessions
            .retain(|_, session| !session.is_expired(self.ttl));
        before - self.sessions.len()
    }

    /// Get the number of active sessions
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    /// Check if there are no sessions
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;

    #[test]
    fn test_create_and_get_session() {
        let store = SessionStore::new(3600); // 1 hour TTL
        let session_id = Uuid::new_v4();

        let _session = store.create(session_id);

        let retrieved = store.get(&session_id);
        assert!(retrieved.is_some());
    }

    #[test]
    fn test_delete_session() {
        let store = SessionStore::new(3600);
        let session_id = Uuid::new_v4();

        store.create(session_id);
        assert!(store.get(&session_id).is_some());

        assert!(store.delete(&session_id));
        assert!(store.get(&session_id).is_none());
    }

    #[test]
    fn test_session_expiration() {
        let store = SessionStore::new(1); // 1 second TTL
        let session_id = Uuid::new_v4();

        store.create(session_id);
        assert!(store.get(&session_id).is_some());

        sleep(Duration::from_secs(2));
        assert!(store.get(&session_id).is_none());
    }

    #[test]
    fn activity_does_not_extend_a_session_past_its_lifetime() {
        let store = SessionStore::new(2); // 2 second TTL
        let session_id = Uuid::new_v4();

        store.create(session_id);

        // Looked up every half second, as the middleware does on every
        // request (see auth_middleware.rs for the request-level test).
        for _ in 0..3 {
            sleep(Duration::from_millis(500));
            assert!(store.get(&session_id).is_some());
        }
        sleep(Duration::from_millis(700));
        assert!(
            store.get(&session_id).is_none(),
            "a session must end SESSION_TTL_SECS after login, however busy"
        );
    }

    #[test]
    fn test_cleanup_expired() {
        let store = SessionStore::new(1); // 1 second TTL

        store.create(Uuid::new_v4());
        store.create(Uuid::new_v4());
        assert_eq!(store.len(), 2);

        sleep(Duration::from_secs(2));

        let cleaned = store.cleanup_expired();
        assert_eq!(cleaned, 2);
        assert!(store.is_empty());
    }
}
