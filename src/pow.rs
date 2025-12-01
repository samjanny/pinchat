use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Proof-of-Work challenge with configurable difficulty
#[derive(Debug, Clone)]
pub struct PowChallenge {
    /// Challenge string (UUID + timestamp)
    pub challenge: String,

    /// Hexadecimal mask for validation
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
        let challenge = format!("{}-{}", id, chrono::Utc::now().timestamp());
        let mask = Self::generate_mask(difficulty);

        Self {
            challenge,
            mask,
            difficulty,
        }
    }

    /// Generates a binary mask based on difficulty level
    ///
    /// # Arguments
    /// * `difficulty` - Number of leading bits that must be 1
    ///
    /// # Returns
    /// Hexadecimal string representing the 32-byte mask
    ///
    /// # Examples
    /// - difficulty = 8  → mask = "FF000000..." (first byte must be 0xFF)
    /// - difficulty = 12 → mask = "FFF00000..." (first 12 bits must be 1)
    pub fn generate_mask(difficulty: u8) -> String {
        let difficulty = difficulty.min(255); // Cap at SHA-256 output size (255 = max u8)

        let full_bytes = (difficulty / 8) as usize;
        let remaining_bits = difficulty % 8;

        let mut mask = vec![0xFF; full_bytes];

        if remaining_bits > 0 {
            // Create a partial byte with the required leading ones
            // Example: remaining_bits=3 yields 0b11100000 (0xE0)
            let partial_byte = 0xFF << (8 - remaining_bits);
            mask.push(partial_byte);
        }

        // Pad to 32 bytes (SHA-256 output size)
        mask.resize(32, 0x00);

        hex::encode(mask)
    }

    /// Verifies a PoW solution
    ///
    /// # Arguments
    /// * `nonce` - The nonce value to verify
    ///
    /// # Returns
    /// `true` if the nonce produces a valid hash, `false` otherwise
    ///
    /// # Algorithm
    /// 1. Compute SHA-256(challenge || nonce)
    /// 2. Apply bitwise AND between hash and mask
    /// 3. Check if (hash & mask) == mask
    pub fn verify(&self, nonce: u64) -> bool {
        // Compute the hash for challenge + nonce
        let mut hasher = Sha256::new();
        hasher.update(format!("{}{}", self.challenge, nonce));
        let hash = hasher.finalize();

        // Decode mask from hex
        let mask_bytes = match hex::decode(&self.mask) {
            Ok(bytes) => bytes,
            Err(_) => return false,
        };

        // Verify: (hash & mask) == mask
        mask_bytes
            .iter()
            .zip(hash.iter())
            .all(|(mask_byte, hash_byte)| mask_byte == &(mask_byte & hash_byte))
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
}
