//! Proof-of-work challenges: handed out without keeping anything, accepted
//! once.
//!
//! A challenge is the string `{id}-{expires}-d{difficulty}-{tag}`: a random
//! UUID, the Unix time at which it stops being accepted, the difficulty, and
//! an HMAC-SHA256 tag over those three and over the keyed hash of the client
//! address it was given to. The key is drawn at random when the process
//! starts. The client solves SHA-256(challenge || nonce) over the whole
//! string and sends the string back with its nonce (see `pow_session.rs`),
//! so the server learns from the tag that it issued the challenge, to that
//! address, at that difficulty, and from `expires` whether it is still
//! valid. The difficulty is part of the hashed bytes, as before (audit H-1).
//!
//! # Why nothing is kept when a challenge is issued
//!
//! Issued challenges used to be kept in a map of at most 10000 entries keyed
//! by HMAC(IP) and a cookie. Asking for a challenge costs nothing, so a burst
//! of requests from many addresses (12000 /64s of a single IPv6 /48 in two
//! seconds) filled it, and every insert into the full map evicted the entry
//! closest to expiry: the challenge an honest client was still solving. Its
//! solution was then refused. Each such insert also scanned the whole map
//! twice. A per-address cap would have left a map that enough addresses can
//! still fill, and a choice between refusing new clients and evicting
//! existing ones; a challenge that carries its own proof of issue leaves
//! nothing to fill.
//!
//! # What is kept
//!
//! The id of every challenge that was solved, until the challenge expires,
//! so that one solution buys one room or one token. Only a correct solution
//! is recorded, so every entry costs a proof of work and a request of the
//! room and token quota. The record holds at most `max_solved` ids. If more
//! challenges than that are solved within one challenge lifetime, the oldest
//! id is forgotten, and that challenge could be used once more until it
//! expires; nobody is refused because of it. The ids are random and say
//! nothing about the client.

use crate::pow::PowChallenge;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::{HashSet, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

/// Separates challenge tags from every other use of an HMAC in the relay.
const TAG_CONTEXT: &[u8] = b"pinchat pow challenge v1\n";

/// Why a presented solution was not accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowRejection {
    /// No challenge this server issued to this client and that is still
    /// valid: missing, malformed, forged, for another address, expired or
    /// already used. The client is given a new one.
    Unknown,
    /// A valid challenge, but easier than the server now requires.
    DifficultyTooLow,
    /// A valid challenge, and the nonce does not solve it. The challenge is
    /// not used up by a wrong answer.
    WrongSolution,
}

/// Default number of solved challenges remembered at once.
const DEFAULT_MAX_SOLVED: usize = 10_000;

/// Issues proof-of-work challenges and accepts each solution once.
///
/// The name is historical: issued challenges are no longer cached (see the
/// module documentation).
pub struct ChallengeCache {
    /// Key of the challenge tags, per process.
    key: [u8; 32],

    /// How long a challenge is accepted after it was issued.
    ttl: Duration,

    /// Ids of solved challenges that have not expired yet.
    solved: Mutex<Solved>,

    /// Most ids `solved` holds.
    max_solved: usize,
}

#[derive(Default)]
struct Solved {
    ids: HashSet<u128>,
    /// The same ids with their expiry, in the order they were solved.
    order: VecDeque<(u128, u64)>,
}

impl Solved {
    fn forget_oldest(&mut self) {
        if let Some((id, _)) = self.order.pop_front() {
            self.ids.remove(&id);
        }
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

impl ChallengeCache {
    /// A fresh key, challenges valid for `ttl_secs`, and room for
    /// `max_solved` solved challenges.
    pub fn new(ttl_secs: u64, max_solved: usize) -> Self {
        Self {
            key: rand::random(),
            ttl: Duration::from_secs(ttl_secs),
            solved: Mutex::new(Solved::default()),
            max_solved: max_solved.max(1),
        }
    }

    fn tag(&self, signed: &str, client: &str) -> String {
        let mut mac = HmacSha256::new_from_slice(&self.key).expect("HMAC can take key of any size");
        mac.update(TAG_CONTEXT);
        mac.update(signed.as_bytes());
        mac.update(b"\n");
        mac.update(client.as_bytes());
        hex::encode(mac.finalize().into_bytes())
    }

    /// Issue a challenge for the client whose keyed address hash is
    /// `client`. Nothing is stored.
    pub fn issue(&self, client: &str, difficulty: u8) -> PowChallenge {
        self.issue_at(client, difficulty, unix_now())
    }

    fn issue_at(&self, client: &str, difficulty: u8, now: u64) -> PowChallenge {
        let signed = format!(
            "{}-{}-d{}",
            Uuid::new_v4(),
            now + self.ttl.as_secs(),
            difficulty
        );
        let tag = self.tag(&signed, client);
        PowChallenge {
            challenge: format!("{signed}-{tag}"),
            mask: PowChallenge::generate_mask(difficulty),
            difficulty,
        }
    }

    /// Accept `nonce` as the solution of `presented`, a challenge issued to
    /// `client`, if it solves it at `min_difficulty` or above and has not
    /// been used. On success the challenge is used up.
    pub fn accept(
        &self,
        client: &str,
        presented: Option<&str>,
        nonce: u64,
        min_difficulty: u8,
    ) -> Result<(), PowRejection> {
        self.accept_at(client, presented, nonce, min_difficulty, unix_now())
    }

    fn accept_at(
        &self,
        client: &str,
        presented: Option<&str>,
        nonce: u64,
        min_difficulty: u8,
        now: u64,
    ) -> Result<(), PowRejection> {
        let presented = presented.ok_or(PowRejection::Unknown)?;
        let (signed, tag) = presented.rsplit_once('-').ok_or(PowRejection::Unknown)?;
        if !bool::from(tag.as_bytes().ct_eq(self.tag(signed, client).as_bytes())) {
            return Err(PowRejection::Unknown);
        }
        // From here on the fields were written by this server.
        let (rest, difficulty) = signed.rsplit_once("-d").ok_or(PowRejection::Unknown)?;
        let (id, expires) = rest.rsplit_once('-').ok_or(PowRejection::Unknown)?;
        let difficulty: u8 = difficulty.parse().map_err(|_| PowRejection::Unknown)?;
        let expires: u64 = expires.parse().map_err(|_| PowRejection::Unknown)?;
        let id = Uuid::parse_str(id)
            .map_err(|_| PowRejection::Unknown)?
            .as_u128();
        if now > expires {
            return Err(PowRejection::Unknown);
        }
        if difficulty < min_difficulty {
            return Err(PowRejection::DifficultyTooLow);
        }
        let challenge = PowChallenge {
            challenge: presented.to_string(),
            mask: String::new(),
            difficulty,
        };
        if !challenge.verify(nonce) {
            return Err(PowRejection::WrongSolution);
        }

        let mut solved = self.solved.lock().unwrap_or_else(|e| e.into_inner());
        if solved.ids.contains(&id) {
            return Err(PowRejection::Unknown);
        }
        while solved
            .order
            .front()
            .is_some_and(|(_, expiry)| *expiry < now)
        {
            solved.forget_oldest();
        }
        if solved.ids.len() >= self.max_solved {
            tracing::warn!("Solved-challenge record full; forgetting the oldest");
            solved.forget_oldest();
        }
        solved.ids.insert(id);
        solved.order.push_back((id, expires));
        Ok(())
    }

    /// Forget the solved challenges that have expired. Called periodically
    /// (`CHALLENGE_CLEANUP_INTERVAL_SECS`). Returns how many were removed.
    pub fn cleanup_expired(&self) -> usize {
        self.cleanup_expired_at(unix_now())
    }

    fn cleanup_expired_at(&self, now: u64) -> usize {
        let mut solved = self.solved.lock().unwrap_or_else(|e| e.into_inner());
        let Solved { ids, order } = &mut *solved;
        let before = order.len();
        order.retain(|(id, expiry)| {
            let keep = *expiry >= now;
            if !keep {
                ids.remove(id);
            }
            keep
        });
        let removed = before - order.len();
        if removed > 0 {
            tracing::debug!("Forgot {} expired solved challenge(s)", removed);
        }
        removed
    }

    /// Number of solved challenges remembered.
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.solved
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .ids
            .len()
    }

    /// Whether no solved challenge is remembered.
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for ChallengeCache {
    fn default() -> Self {
        Self::new(300, DEFAULT_MAX_SOLVED) // 5 minutes TTL
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALICE: &str = "hash-of-alice";
    const MALLORY: &str = "hash-of-mallory";

    fn solve(challenge: &PowChallenge) -> u64 {
        (0..).find(|nonce| challenge.verify(*nonce)).unwrap()
    }

    fn wrong(challenge: &PowChallenge) -> u64 {
        (0..).find(|nonce| !challenge.verify(*nonce)).unwrap()
    }

    #[test]
    fn a_solution_is_accepted_once() {
        let cache = ChallengeCache::new(300, 1000);
        let challenge = cache.issue(ALICE, 4);
        assert!(challenge.challenge.contains("-d4-"));
        assert!(cache.is_empty(), "issuing stores nothing");
        let nonce = solve(&challenge);

        assert_eq!(
            cache.accept(ALICE, Some(&challenge.challenge), nonce, 4),
            Ok(())
        );
        assert_eq!(cache.len(), 1);
        assert_eq!(
            cache.accept(ALICE, Some(&challenge.challenge), nonce, 4),
            Err(PowRejection::Unknown),
            "a used challenge is not accepted again"
        );
    }

    #[test]
    fn a_wrong_answer_does_not_use_the_challenge_up() {
        let cache = ChallengeCache::new(300, 1000);
        let challenge = cache.issue(ALICE, 4);
        assert_eq!(
            cache.accept(ALICE, Some(&challenge.challenge), wrong(&challenge), 4),
            Err(PowRejection::WrongSolution)
        );
        assert!(cache.is_empty(), "only a correct solution is recorded");
        assert_eq!(
            cache.accept(ALICE, Some(&challenge.challenge), solve(&challenge), 4),
            Ok(())
        );
    }

    #[test]
    fn a_challenge_is_bound_to_the_client_and_to_its_fields() {
        let cache = ChallengeCache::new(300, 1000);
        let challenge = cache.issue(ALICE, 4);
        let nonce = solve(&challenge);
        assert_eq!(
            cache.accept(MALLORY, Some(&challenge.challenge), nonce, 4),
            Err(PowRejection::Unknown),
            "solved for another address"
        );

        // Any edit of the signed part breaks the tag, including an easier
        // difficulty or a later expiry.
        let (signed, tag) = challenge.challenge.rsplit_once('-').unwrap();
        let (rest, _) = signed.rsplit_once("-d").unwrap();
        let (id, expires) = rest.rsplit_once('-').unwrap();
        let later: u64 = expires.parse::<u64>().unwrap() + 3600;
        for forged in [
            format!("{id}-{expires}-d1-{tag}"),
            format!("{id}-{later}-d4-{tag}"),
            format!("{}-{expires}-d4-{tag}", Uuid::new_v4()),
            format!("{signed}-{}", "0".repeat(64)),
            signed.to_string(),
            String::new(),
            "-".to_string(),
        ] {
            let forged_challenge = PowChallenge {
                challenge: forged.clone(),
                mask: String::new(),
                difficulty: 1,
            };
            assert_eq!(
                cache.accept(ALICE, Some(&forged), solve(&forged_challenge), 1),
                Err(PowRejection::Unknown),
                "{forged:?}"
            );
        }
        assert_eq!(
            cache.accept(ALICE, None, nonce, 4),
            Err(PowRejection::Unknown)
        );
        // Another process (another key) did not issue it either.
        let restarted = ChallengeCache::new(300, 1000);
        assert_eq!(
            restarted.accept(ALICE, Some(&challenge.challenge), nonce, 4),
            Err(PowRejection::Unknown)
        );
        assert_eq!(
            cache.accept(ALICE, Some(&challenge.challenge), nonce, 4),
            Ok(())
        );
    }

    #[test]
    fn a_challenge_expires_after_its_lifetime() {
        let cache = ChallengeCache::new(300, 1000);
        let issued_at = 1_000_000;
        let challenge = cache.issue_at(ALICE, 4, issued_at);
        let nonce = solve(&challenge);
        assert_eq!(
            cache.accept_at(ALICE, Some(&challenge.challenge), nonce, 4, issued_at + 301),
            Err(PowRejection::Unknown)
        );
        assert_eq!(
            cache.accept_at(ALICE, Some(&challenge.challenge), nonce, 4, issued_at + 300),
            Ok(())
        );
    }

    #[test]
    fn an_easier_challenge_than_required_is_refused() {
        let cache = ChallengeCache::new(300, 1000);
        let challenge = cache.issue(ALICE, 4);
        let nonce = solve(&challenge);
        assert_eq!(
            cache.accept(ALICE, Some(&challenge.challenge), nonce, 5),
            Err(PowRejection::DifficultyTooLow)
        );
        assert_eq!(
            cache.accept(ALICE, Some(&challenge.challenge), nonce, 4),
            Ok(())
        );
    }

    /// Audit T-03: a burst of challenge requests from other addresses used
    /// to evict the challenge an honest client was solving.
    #[test]
    fn a_flood_of_challenge_requests_cannot_take_an_honest_clients_challenge() {
        let cache = ChallengeCache::new(300, 10_000);
        let honest = cache.issue(ALICE, 4);
        for i in 0..20_000 {
            cache.issue(&format!("flood-{i}"), 4);
        }
        assert!(cache.is_empty(), "the flood left nothing behind");
        assert_eq!(
            cache.accept(ALICE, Some(&honest.challenge), solve(&honest), 4),
            Ok(())
        );
    }

    #[test]
    fn the_record_of_solved_challenges_is_bounded_and_swept() {
        let cache = ChallengeCache::new(300, 3);
        let now = 1_000_000;
        let challenges: Vec<_> = (0..5).map(|_| cache.issue_at(ALICE, 2, now)).collect();
        for challenge in &challenges {
            assert_eq!(
                cache.accept_at(ALICE, Some(&challenge.challenge), solve(challenge), 2, now),
                Ok(())
            );
            assert!(cache.len() <= 3);
        }
        // The newest are still refused a second time.
        let last = &challenges[4];
        assert_eq!(
            cache.accept_at(ALICE, Some(&last.challenge), solve(last), 2, now),
            Err(PowRejection::Unknown)
        );

        assert_eq!(cache.cleanup_expired_at(now + 300), 0);
        assert_eq!(cache.cleanup_expired_at(now + 301), 3);
        assert!(cache.is_empty());
    }
}
