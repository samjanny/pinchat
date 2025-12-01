//! Challenge cache for Proof-of-Work validation
//!
//! This module provides a cache of issued PoW challenges indexed by HMAC(IP).
//! Prevents offline challenge fabrication attacks by validating that challenges
//! were actually issued by this server to the specific requesting IP.
//!
//! Security properties:
//! - One challenge per IP (indexed by HMAC(IP))
//! - TTL-based expiration (5 minutes default)
//! - One-time use (challenge deleted after successful validation)
//! - Global capacity limit with LRU eviction (prevents memory exhaustion)
//! - Rainbow table protection (HMAC with secret key)

use crate::pow::PowChallenge;
use dashmap::DashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

/// Entry in the challenge cache
#[derive(Debug, Clone)]
pub struct ChallengeEntry {
    /// The PoW challenge
    pub challenge: PowChallenge,

    /// When this challenge expires
    pub expires_at: SystemTime,
}

impl ChallengeEntry {
    /// Create a new challenge entry with specified TTL
    pub fn new(challenge: PowChallenge, ttl: Duration) -> Self {
        Self {
            challenge,
            expires_at: SystemTime::now() + ttl,
        }
    }

    /// Check if this entry has expired
    pub fn is_expired(&self) -> bool {
        SystemTime::now() > self.expires_at
    }
}

/// Default maximum number of entries in the cache
const DEFAULT_MAX_CAPACITY: usize = 10_000;

/// Thread-safe cache of PoW challenges indexed by HMAC(IP)
///
/// The cache key is HMAC-SHA256(client_ip, secret_key) which provides:
/// - Privacy: IP addresses not stored in cleartext
/// - Security: Rainbow table attacks infeasible due to secret key
/// - Isolation: One challenge per IP, no sharing possible
#[derive(Clone)]
pub struct ChallengeCache {
    /// Map of HMAC(IP) -> ChallengeEntry
    cache: Arc<DashMap<String, ChallengeEntry>>,

    /// TTL for challenges (configurable)
    ttl: Duration,

    /// Maximum number of entries allowed in cache
    max_capacity: usize,
}

impl ChallengeCache {
    /// Create a new empty challenge cache with specified TTL and max capacity
    pub fn new(ttl_secs: u64, max_capacity: usize) -> Self {
        Self {
            cache: Arc::new(DashMap::new()),
            ttl: Duration::from_secs(ttl_secs),
            max_capacity,
        }
    }

    /// Store a challenge for a specific IP hash
    ///
    /// If a challenge already exists for this IP, it is replaced.
    /// This prevents challenge accumulation and enforces one-challenge-per-IP.
    ///
    /// If the cache is at capacity, expired entries are cleaned first.
    /// If still at capacity, the oldest entry is evicted (LRU-style).
    pub fn store(&self, ip_hash: String, challenge: PowChallenge) {
        // Check if we're at capacity (only if this is a new key)
        if !self.cache.contains_key(&ip_hash) && self.cache.len() >= self.max_capacity {
            // First try cleaning expired entries
            self.cleanup_expired();

            // If still at capacity, evict oldest entry
            if self.cache.len() >= self.max_capacity {
                self.evict_oldest();
            }
        }

        let entry = ChallengeEntry::new(challenge, self.ttl);
        self.cache.insert(ip_hash, entry);

        tracing::debug!(
            "Challenge stored for IP hash (expires in {}s, cache size: {})",
            self.ttl.as_secs(),
            self.cache.len()
        );
    }

    /// Evict the oldest entry from the cache (by expiration time)
    fn evict_oldest(&self) {
        let oldest = self
            .cache
            .iter()
            .min_by_key(|e| e.value().expires_at)
            .map(|e| e.key().clone());

        if let Some(key) = oldest {
            self.cache.remove(&key);
            tracing::debug!("Evicted oldest challenge entry (cache at capacity)");
        }
    }

    /// Retrieve and remove a challenge for validation (one-time use)
    ///
    /// Returns `Some(challenge)` if:
    /// - Challenge exists for this IP hash
    /// - Challenge has not expired
    ///
    /// The challenge is removed from the cache after retrieval to ensure
    /// one-time use and prevent replay attacks.
    pub fn take(&self, ip_hash: &str) -> Option<PowChallenge> {
        // Remove the entry from cache (one-time use)
        let entry = self.cache.remove(ip_hash)?;

        // Check if expired
        if entry.1.is_expired() {
            tracing::warn!("Challenge expired for IP hash");
            return None;
        }

        tracing::debug!("Challenge retrieved and consumed (one-time use)");
        Some(entry.1.challenge)
    }

    /// Remove expired challenges from the cache
    ///
    /// This should be called periodically (e.g., every minute) to prevent
    /// memory accumulation from expired entries.
    ///
    /// Returns the number of expired entries removed.
    pub fn cleanup_expired(&self) -> usize {
        let mut removed = 0;

        // Collect expired keys
        let expired_keys: Vec<String> = self
            .cache
            .iter()
            .filter(|entry| entry.value().is_expired())
            .map(|entry| entry.key().clone())
            .collect();

        // Remove expired entries
        for key in expired_keys {
            self.cache.remove(&key);
            removed += 1;
        }

        if removed > 0 {
            tracing::info!("Cleaned up {} expired challenge(s)", removed);
        }

        removed
    }

    /// Get the current number of cached challenges
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.cache.len()
    }

    /// Check if the cache is empty
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }
}

impl Default for ChallengeCache {
    fn default() -> Self {
        Self::new(300, DEFAULT_MAX_CAPACITY) // 5 minutes TTL, 10k max entries
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_store_and_take() {
        let cache = ChallengeCache::new(300, 1000); // 5 minute TTL, 1k capacity
        let challenge = PowChallenge::new(12);
        let ip_hash = "test_hash_123".to_string();

        // Store challenge
        cache.store(ip_hash.clone(), challenge.clone());
        assert_eq!(cache.len(), 1);

        // Take challenge (one-time use)
        let retrieved = cache.take(&ip_hash);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().challenge, challenge.challenge);

        // Second take should fail (already consumed)
        let second_take = cache.take(&ip_hash);
        assert!(second_take.is_none());
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_one_challenge_per_ip() {
        let cache = ChallengeCache::new(300, 1000); // 5 minute TTL, 1k capacity
        let ip_hash = "test_hash_456".to_string();

        let challenge1 = PowChallenge::new(12);
        let challenge2 = PowChallenge::new(12);

        // Store first challenge
        cache.store(ip_hash.clone(), challenge1);
        assert_eq!(cache.len(), 1);

        // Store second challenge (should replace first)
        cache.store(ip_hash.clone(), challenge2.clone());
        assert_eq!(cache.len(), 1);

        // Take should return second challenge
        let retrieved = cache.take(&ip_hash).unwrap();
        assert_eq!(retrieved.challenge, challenge2.challenge);
    }

    #[test]
    fn test_expired_challenge() {
        let cache = ChallengeCache::new(300, 1000); // 5 minute TTL, 1k capacity
        let challenge = PowChallenge::new(12);
        let ip_hash = "test_hash_789".to_string();

        // Create entry with past expiration
        let entry = ChallengeEntry {
            challenge,
            expires_at: SystemTime::now() - Duration::from_secs(1),
        };

        cache.cache.insert(ip_hash.clone(), entry);

        // Take should return None for expired challenge
        let retrieved = cache.take(&ip_hash);
        assert!(retrieved.is_none());
    }

    #[test]
    fn test_cleanup_expired() {
        let cache = ChallengeCache::new(300, 1000); // 5 minute TTL, 1k capacity

        // Add expired entry
        let expired_entry = ChallengeEntry {
            challenge: PowChallenge::new(12),
            expires_at: SystemTime::now() - Duration::from_secs(1),
        };
        cache.cache.insert("expired".to_string(), expired_entry);

        // Add valid entry
        cache.store("valid".to_string(), PowChallenge::new(12));

        assert_eq!(cache.len(), 2);

        // Cleanup should remove only expired entry
        let removed = cache.cleanup_expired();
        assert_eq!(removed, 1);
        assert_eq!(cache.len(), 1);
        assert!(cache.cache.contains_key("valid"));
        assert!(!cache.cache.contains_key("expired"));
    }

    #[test]
    fn test_capacity_eviction() {
        let cache = ChallengeCache::new(300, 3); // Small capacity for testing

        // Fill cache to capacity
        cache.store("ip1".to_string(), PowChallenge::new(12));
        cache.store("ip2".to_string(), PowChallenge::new(12));
        cache.store("ip3".to_string(), PowChallenge::new(12));
        assert_eq!(cache.len(), 3);

        // Adding a 4th entry should evict the oldest
        cache.store("ip4".to_string(), PowChallenge::new(12));
        assert_eq!(cache.len(), 3); // Still at capacity

        // ip1 should have been evicted (oldest)
        assert!(!cache.cache.contains_key("ip1"));
        assert!(cache.cache.contains_key("ip4"));
    }

    #[test]
    fn test_capacity_with_same_ip_no_eviction() {
        let cache = ChallengeCache::new(300, 2); // Small capacity

        // Fill cache
        cache.store("ip1".to_string(), PowChallenge::new(12));
        cache.store("ip2".to_string(), PowChallenge::new(12));
        assert_eq!(cache.len(), 2);

        // Updating existing IP should not trigger eviction
        cache.store("ip1".to_string(), PowChallenge::new(12));
        assert_eq!(cache.len(), 2);
        assert!(cache.cache.contains_key("ip1"));
        assert!(cache.cache.contains_key("ip2"));
    }
}
