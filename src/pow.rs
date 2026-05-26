use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Proof-of-Work challenge with configurable difficulty
#[derive(Debug, Clone)]
pub struct PowChallenge {
    /// Challenge string. The difficulty is embedded in the challenge bytes
    /// themselves (format: `{uuid}-{ts}-d{difficulty}`) so the SHA-256 input
    /// is bound to the difficulty level. A precomputed nonce for some
    /// other (uuid, ts, difficulty) triple cannot satisfy this challenge.
    ///
    /// Audit H-1 (block-release): without difficulty inside the hashed
    /// challenge bytes, a server that briefly served a low-difficulty
    /// challenge and later raised the difficulty could in principle have
    /// its high-difficulty path satisfied by a low-difficulty nonce IF the
    /// challenge string were ever reused. Embedding the difficulty makes
    /// challenges from different difficulty levels structurally distinct
    /// inputs to SHA-256.
    pub challenge: String,

    /// Hexadecimal mask for the client's convenience — derived from
    /// `difficulty` at construction time and sent down the wire so the
    /// browser can short-circuit nonce search without recomputing the mask.
    ///
    /// SECURITY: `verify` does NOT trust this field. It always re-derives
    /// the mask from `difficulty` (see `build_mask_bytes`). The `mask`
    /// field is purely an outbound convenience and an attacker tampering
    /// with it post-issue would only change what the client renders, not
    /// what the server accepts.
    pub mask: String,

    /// Difficulty level (number of bits that must match)
    pub difficulty: u8,
}

impl PowChallenge {
    /// Creates a new PoW challenge with specified difficulty
    ///
    /// # Arguments
    /// * `difficulty` - Number of bits that must match (0-256)
    ///
    /// # Examples
    /// ```
    /// let challenge = PowChallenge::new(12); // 12-bit difficulty (~30ms to solve)
    /// ```
    pub fn new(difficulty: u8) -> Self {
        let id = Uuid::new_v4();
        // Embed difficulty in the challenge bytes (audit H-1). The verifier
        // re-derives the mask from `self.difficulty`; the `mask` field is
        // a wire-protocol convenience for the client and is never trusted
        // by `verify`.
        let challenge = format!("{}-{}-d{}", id, chrono::Utc::now().timestamp(), difficulty);

        Self {
            challenge,
            mask: Self::generate_mask(difficulty),
            difficulty,
        }
    }

    /// Generates a binary mask based on difficulty level
    ///
    /// # Arguments
    /// * `difficulty` - Number of leading bits that must be 1
    ///
    /// # Returns
    /// 32-byte mask (SHA-256 output size). The high `difficulty` bits are 1,
    /// the rest are 0.
    ///
    /// # Examples
    /// - difficulty = 8  → mask = [0xFF, 0x00, ..., 0x00] (first byte must be 0xFF)
    /// - difficulty = 12 → mask = [0xFF, 0xF0, ..., 0x00] (first 12 bits must be 1)
    fn build_mask_bytes(difficulty: u8) -> [u8; 32] {
        let difficulty = difficulty.min(255);

        let full_bytes = (difficulty / 8) as usize;
        let remaining_bits = difficulty % 8;

        let mut mask = [0u8; 32];
        for byte in mask.iter_mut().take(full_bytes) {
            *byte = 0xFF;
        }
        if remaining_bits > 0 && full_bytes < 32 {
            mask[full_bytes] = 0xFF << (8 - remaining_bits);
        }
        mask
    }

    /// Hex form of the mask, retained for compatibility with tests and any
    /// external callers that introspect the mask. NOT consulted by `verify`.
    pub fn generate_mask(difficulty: u8) -> String {
        hex::encode(Self::build_mask_bytes(difficulty))
    }

    /// Verifies a PoW solution.
    ///
    /// # Arguments
    /// * `nonce` - The nonce value to verify
    ///
    /// # Returns
    /// `true` if the nonce produces a valid hash, `false` otherwise.
    ///
    /// # Algorithm
    /// 1. Re-derive the 32-byte mask from `self.difficulty` (NOT from any
    ///    cached field — audit H-1 defense-in-depth). The challenge string
    ///    already embeds the difficulty (see `new()`), so the SHA-256 input
    ///    is bound to the same difficulty the mask enforces.
    /// 2. Compute SHA-256(challenge || nonce).
    /// 3. Verify `(hash & mask) == mask` — the high `difficulty` bits of the
    ///    hash must all be 1.
    pub fn verify(&self, nonce: u64) -> bool {
        let mask = Self::build_mask_bytes(self.difficulty);

        let mut hasher = Sha256::new();
        hasher.update(format!("{}{}", self.challenge, nonce));
        let hash = hasher.finalize();

        mask.iter()
            .zip(hash.iter())
            .all(|(mask_byte, hash_byte)| *mask_byte == (mask_byte & hash_byte))
    }
}

/// Calculates dynamic PoW difficulty based on server load
///
/// # Arguments
/// * `current_rooms` - Current number of active rooms
/// * `max_rooms` - Maximum allowed rooms
///
/// # Returns
/// Difficulty level (15-20 bits)
///
/// # Difficulty Scaling (Realistic for Web Clients)
/// Timing estimates based on typical browser Web Worker performance (~50k-200k hash/sec):
///
/// - 0-30% usage:   15 bits (~0.6s avg, ~2s slow)       - Baseline protection
/// - 31-50% usage:  16 bits (~1.3s avg, ~4s slow)       - Light load
/// - 51-70% usage:  17 bits (~2.6s avg, ~8s slow)       - Medium load
/// - 71-85% usage:  18 bits (~5s avg, ~15s slow)        - High load
/// - 86-95% usage:  19 bits (~10s avg, ~30s slow)       - Near capacity
/// - 95-100% usage: 20 bits (~20s avg, ~60s slow)       - At capacity (maximum protection)
///
/// # Rationale
/// - Provides DoS protection without excessive user friction
/// - Scales with server load to discourage attacks during high usage
/// - Realistic timings for web browsers (not native code benchmarks)
/// - Mobile-friendly: baseline 15 bits solvable in ~2s on slow devices
/// - Balance: security vs UX (users only solve once per room creation)
pub fn calculate_difficulty(
    current_rooms: usize,
    max_rooms: usize,
    min_difficulty: u8,
    max_difficulty: u8,
) -> u8 {
    if max_rooms == 0 {
        return min_difficulty; // Default baseline difficulty
    }

    let usage_pct = (current_rooms * 100) / max_rooms;

    // Calculate step size for difficulty scaling (5 steps = 6 tiers)
    let steps = 5;
    let difficulty_range = max_difficulty.saturating_sub(min_difficulty);
    let step_size = if difficulty_range >= steps {
        difficulty_range / steps
    } else {
        1 // Minimum step size
    };

    match usage_pct {
        0..=30 => min_difficulty, // Baseline protection
        31..=50 => min_difficulty.saturating_add(step_size).min(max_difficulty), // Light load
        51..=70 => min_difficulty
            .saturating_add(step_size * 2)
            .min(max_difficulty), // Medium load
        71..=85 => min_difficulty
            .saturating_add(step_size * 3)
            .min(max_difficulty), // High load
        86..=95 => min_difficulty
            .saturating_add(step_size * 4)
            .min(max_difficulty), // Near capacity
        _ => max_difficulty,      // At capacity (max protection)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mask_generation() {
        // 8-bit difficulty: the first byte should be 0xFF
        let mask_8 = PowChallenge::generate_mask(8);
        assert_eq!(&mask_8[0..2], "ff");
        assert_eq!(&mask_8[2..4], "00");

        // 16-bit difficulty: the first two bytes should be 0xFFFF
        let mask_16 = PowChallenge::generate_mask(16);
        assert_eq!(&mask_16[0..4], "ffff");
        assert_eq!(&mask_16[4..6], "00");
    }

    #[test]
    fn test_pow_verification() {
        // Create a low-difficulty challenge for deterministic testing
        let challenge = PowChallenge::new(4); // 4 bits is intentionally permissive

        // Brute-force to find a valid nonce
        let mut nonce = 0u64;
        let found = loop {
            if challenge.verify(nonce) {
                break true;
            }
            nonce += 1;
            if nonce > 10000 {
                break false; // Safety limit to keep the test bounded
            }
        };

        assert!(
            found,
            "Should find valid nonce within 10000 attempts for 4-bit difficulty"
        );
    }

    #[test]
    fn test_difficulty_calculation() {
        // Test the default difficulty range (15-20 bits)
        assert_eq!(calculate_difficulty(0, 1000, 15, 20), 15); // 0% → 15 bits (baseline)
        assert_eq!(calculate_difficulty(300, 1000, 15, 20), 15); // 30% → 15 bits
        assert_eq!(calculate_difficulty(400, 1000, 15, 20), 16); // 40% → 16 bits
        assert_eq!(calculate_difficulty(600, 1000, 15, 20), 17); // 60% → 17 bits
        assert_eq!(calculate_difficulty(800, 1000, 15, 20), 18); // 80% → 18 bits
        assert_eq!(calculate_difficulty(900, 1000, 15, 20), 19); // 90% → 19 bits
        assert_eq!(calculate_difficulty(980, 1000, 15, 20), 20); // 98% → 20 bits (max)

        // Test a custom difficulty range (10-15 bits)
        assert_eq!(calculate_difficulty(0, 1000, 10, 15), 10); // 0% → 10 bits (baseline)
        assert_eq!(calculate_difficulty(980, 1000, 10, 15), 15); // 98% → 15 bits (max)

        // Edge case: fixed difficulty
        assert_eq!(calculate_difficulty(0, 1000, 18, 18), 18); // Always 18
        assert_eq!(calculate_difficulty(900, 1000, 18, 18), 18); // Always 18
    }

    #[test]
    fn test_invalid_nonce_rejected() {
        let challenge = PowChallenge::new(8);

        // Nonce 0 is extremely unlikely to be valid for 8-bit difficulty
        assert!(!challenge.verify(0));
    }

    // Audit H-1 regression tests ---------------------------------------------

    #[test]
    fn test_difficulty_embedded_in_challenge_string() {
        // The challenge bytes themselves must commit to the difficulty so
        // SHA-256(challenge || nonce) for difficulty=12 is structurally
        // different from SHA-256 for difficulty=18, even with the same UUID.
        let c12 = PowChallenge::new(12);
        let c18 = PowChallenge::new(18);
        assert!(
            c12.challenge.ends_with("-d12"),
            "challenge must end with -d{{difficulty}} (got {})",
            c12.challenge
        );
        assert!(
            c18.challenge.ends_with("-d18"),
            "challenge must end with -d{{difficulty}} (got {})",
            c18.challenge
        );
    }

    #[test]
    fn test_verify_ignores_tampered_mask_field() {
        // The `mask` field is sent down the wire as a convenience for the
        // client. If anything ever round-trips it through untrusted input,
        // verify() must NOT consult it — the mask must be re-derived from
        // self.difficulty every call.
        //
        // Find a nonce that satisfies a 4-bit challenge, then swap the mask
        // field for a permissive (0-bit) mask. verify() with difficulty=4
        // should still reject any nonce that doesn't actually clear 4 bits.
        let mut c = PowChallenge::new(4);

        // Tamper: replace the mask with all zeros (would accept any nonce
        // if verify trusted the field).
        c.mask = hex::encode([0u8; 32]);

        // A nonce that fails the 4-bit mask must still be rejected.
        // (Most nonces do; we just need one that statistically fails.)
        // We re-derive what 4-bit verification *should* return using a
        // fresh challenge with an untouched mask:
        let fresh = PowChallenge {
            challenge: c.challenge.clone(),
            mask: PowChallenge::generate_mask(4),
            difficulty: 4,
        };
        // Find one rejected nonce on `fresh` and assert it is also rejected
        // on the mask-tampered struct `c`.
        let rejected = (0u64..256)
            .find(|n| !fresh.verify(*n))
            .expect("at least one nonce must fail 4-bit verification");
        assert!(
            !c.verify(rejected),
            "verify must ignore tampered mask and re-derive from difficulty"
        );
    }

    #[test]
    fn test_low_difficulty_nonce_fails_high_difficulty_challenge() {
        // A nonce that satisfies a 4-bit challenge MUST NOT satisfy a fresh
        // 16-bit challenge — both because the challenge strings differ
        // (different UUIDs and embedded difficulty) and because the
        // re-derived 16-bit mask is strictly stricter than the 4-bit mask.
        let low = PowChallenge::new(4);
        let mut nonce = 0u64;
        let low_solution = loop {
            if low.verify(nonce) {
                break nonce;
            }
            nonce += 1;
            assert!(nonce < 10_000, "should find a 4-bit nonce quickly");
        };

        let high = PowChallenge::new(16);
        assert!(
            !high.verify(low_solution),
            "4-bit nonce must not satisfy a 16-bit challenge \
             (different challenge bytes + stricter mask)"
        );
    }
}
