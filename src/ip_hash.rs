//! IP address hashing with HMAC-SHA256 for privacy protection
//!
//! This module provides unified IP address hashing across all components:
//! - Challenge cache (prevents PoW bypass and rainbow table attacks)
//! - Rate limiting (prevents privacy leaks)
//!
//! Security properties:
//! - Uses HMAC-SHA256 with secret key (prevents rainbow table attacks)
//! - Secret key generated on each server boot (fresh key per restart)
//! - Supports trusted proxies for X-Forwarded-For when configured
//! - Development mode shows cleartext IPs for debugging (PRIVACY_MODE=development)

use axum::extract::ConnectInfo;
use axum::http::HeaderMap;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::net::{IpAddr, SocketAddr};

type HmacSha256 = Hmac<Sha256>;

/// Extract client IP considering trusted proxies
///
/// If the direct connection comes from a trusted proxy, extracts the real client IP
/// from X-Forwarded-For header. Otherwise returns the TCP connection IP.
///
/// # Security
/// - Only trusts X-Forwarded-For when connection is from a trusted proxy
/// - Takes the rightmost IP that is NOT a trusted proxy (closest to client)
/// - Validates IP format to prevent injection attacks
pub fn extract_client_ip_with_proxy(
    connect_info: &ConnectInfo<SocketAddr>,
    headers: &HeaderMap,
    trusted_proxies: &[String],
) -> String {
    let direct_ip = connect_info.0.ip();

    // If no trusted proxies configured, always use direct IP
    if trusted_proxies.is_empty() {
        return direct_ip.to_string();
    }

    // Check if direct connection is from a trusted proxy
    if !is_trusted_proxy(&direct_ip, trusted_proxies) {
        // Direct connection is not from trusted proxy, ignore X-Forwarded-For
        return direct_ip.to_string();
    }

    // Connection is from trusted proxy, check X-Forwarded-For
    if let Some(xff) = headers.get("x-forwarded-for") {
        if let Ok(xff_str) = xff.to_str() {
            // X-Forwarded-For format: "client, proxy1, proxy2, ..."
            // We want the rightmost IP that is NOT a trusted proxy
            let ips: Vec<&str> = xff_str.split(',').map(|s| s.trim()).collect();

            // Walk from right to left, find first non-proxy IP
            for ip_str in ips.iter().rev() {
                if let Ok(ip) = ip_str.parse::<IpAddr>() {
                    if !is_trusted_proxy(&ip, trusted_proxies) {
                        return ip.to_string();
                    }
                }
            }
        }
    }

    // Fallback to direct IP if X-Forwarded-For is missing or invalid
    direct_ip.to_string()
}

/// Check if an IP address is in the trusted proxy list
///
/// Supports both exact IP matches and CIDR notation (e.g., "10.0.0.0/8")
fn is_trusted_proxy(ip: &IpAddr, trusted_proxies: &[String]) -> bool {
    for proxy in trusted_proxies {
        // Check for CIDR notation
        if proxy.contains('/') {
            if let Some(matches) = ip_in_cidr(ip, proxy) {
                if matches {
                    return true;
                }
            }
        } else {
            // Exact IP match
            if let Ok(proxy_ip) = proxy.parse::<IpAddr>() {
                if ip == &proxy_ip {
                    return true;
                }
            }
        }
    }
    false
}

/// Check if an IP is within a CIDR range
fn ip_in_cidr(ip: &IpAddr, cidr: &str) -> Option<bool> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return None;
    }

    let network_ip: IpAddr = parts[0].parse().ok()?;
    let prefix_len: u8 = parts[1].parse().ok()?;

    match (ip, &network_ip) {
        (IpAddr::V4(ip4), IpAddr::V4(net4)) => {
            if prefix_len > 32 {
                return None;
            }
            let mask = if prefix_len == 0 {
                0
            } else {
                !0u32 << (32 - prefix_len)
            };
            let ip_bits = u32::from(*ip4);
            let net_bits = u32::from(*net4);
            Some((ip_bits & mask) == (net_bits & mask))
        }
        (IpAddr::V6(ip6), IpAddr::V6(net6)) => {
            if prefix_len > 128 {
                return None;
            }
            let ip_bits = u128::from(*ip6);
            let net_bits = u128::from(*net6);
            let mask = if prefix_len == 0 {
                0
            } else {
                !0u128 << (128 - prefix_len)
            };
            Some((ip_bits & mask) == (net_bits & mask))
        }
        _ => None, // IPv4/IPv6 mismatch
    }
}

/// Compute HMAC-SHA256 hash of IP address
///
/// Returns hex-encoded hash string for use as cache/map key
///
/// # Privacy Protection
/// - Uses HMAC with secret key to prevent rainbow table attacks
/// - IPv4 address space is only ~4 billion addresses
/// - Plain SHA-256 vulnerable to rainbow tables (~4GB, 30 min on GPU)
/// - HMAC with secret key makes precomputation infeasible
///
/// # Development Mode
/// When PRIVACY_MODE environment variable is set to "development",
/// returns the cleartext IP for debugging purposes.
pub fn hash_ip(ip: &str, secret: &[u8; 32]) -> String {
    // Development mode: return cleartext IP for debugging
    if std::env::var("PRIVACY_MODE").unwrap_or_default() == "development" {
        tracing::debug!("PRIVACY_MODE=development: Using cleartext IP: {}", ip);
        return ip.to_string();
    }

    // Production mode: return HMAC-SHA256(IP)
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC can take key of any size");
    mac.update(ip.as_bytes());
    let result = mac.finalize();
    hex::encode(result.into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};

    static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    #[test]
    fn test_hash_ip_deterministic() {
        let _env_guard = ENV_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
        unsafe { std::env::remove_var("PRIVACY_MODE"); }

        let secret = [0u8; 32];
        let ip = "192.168.1.100";

        let hash1 = hash_ip(ip, &secret);
        let hash2 = hash_ip(ip, &secret);

        assert_eq!(hash1, hash2, "Same IP should produce same hash");
    }

    #[test]
    fn test_hash_ip_different_ips() {
        let secret = [0u8; 32];

        let hash1 = hash_ip("192.168.1.100", &secret);
        let hash2 = hash_ip("192.168.1.101", &secret);

        assert_ne!(
            hash1, hash2,
            "Different IPs should produce different hashes"
        );
    }

    #[test]
    fn test_hash_ip_different_secrets() {
        let secret1 = [0u8; 32];
        let secret2 = [1u8; 32];
        let ip = "192.168.1.100";

        let hash1 = hash_ip(ip, &secret1);
        let hash2 = hash_ip(ip, &secret2);

        assert_ne!(
            hash1, hash2,
            "Different secrets should produce different hashes"
        );
    }

    #[test]
    fn test_development_mode() {
        let _env_guard = ENV_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
        // std::env setters are now unsafe; wrap for explicit opt-in during test
        unsafe { std::env::set_var("PRIVACY_MODE", "development"); }

        let secret = [0u8; 32];
        let ip = "192.168.1.100";

        let result = hash_ip(ip, &secret);

        assert_eq!(result, ip, "Development mode should return cleartext IP");

        unsafe { std::env::remove_var("PRIVACY_MODE"); }
    }

    #[test]
    fn test_ip_in_cidr_ipv4() {
        // IP within range
        let ip: IpAddr = "192.168.1.50".parse().unwrap();
        assert_eq!(ip_in_cidr(&ip, "192.168.1.0/24"), Some(true));

        // IP outside range
        let ip: IpAddr = "192.168.2.50".parse().unwrap();
        assert_eq!(ip_in_cidr(&ip, "192.168.1.0/24"), Some(false));

        // Broader CIDR
        let ip: IpAddr = "10.50.100.200".parse().unwrap();
        assert_eq!(ip_in_cidr(&ip, "10.0.0.0/8"), Some(true));

        // IP outside broader CIDR
        let ip: IpAddr = "11.0.0.1".parse().unwrap();
        assert_eq!(ip_in_cidr(&ip, "10.0.0.0/8"), Some(false));
    }

    #[test]
    fn test_ip_in_cidr_ipv6() {
        let ip: IpAddr = "2001:db8::1".parse().unwrap();
        assert_eq!(ip_in_cidr(&ip, "2001:db8::/32"), Some(true));

        let ip: IpAddr = "2001:db9::1".parse().unwrap();
        assert_eq!(ip_in_cidr(&ip, "2001:db8::/32"), Some(false));
    }

    #[test]
    fn test_ip_in_cidr_mismatch() {
        // IPv4 address with IPv6 CIDR
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        assert_eq!(ip_in_cidr(&ip, "2001:db8::/32"), None);

        // IPv6 address with IPv4 CIDR
        let ip: IpAddr = "2001:db8::1".parse().unwrap();
        assert_eq!(ip_in_cidr(&ip, "192.168.1.0/24"), None);
    }

    #[test]
    fn test_ip_in_cidr_invalid() {
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        // Invalid CIDR format
        assert_eq!(ip_in_cidr(&ip, "192.168.1.0"), None);
        assert_eq!(ip_in_cidr(&ip, "192.168.1.0/"), None);
        assert_eq!(ip_in_cidr(&ip, "/24"), None);

        // Invalid prefix length
        assert_eq!(ip_in_cidr(&ip, "192.168.1.0/33"), None);
    }

    #[test]
    fn test_is_trusted_proxy_exact_match() {
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let trusted = vec!["10.0.0.1".to_string()];
        assert!(is_trusted_proxy(&ip, &trusted));

        let ip: IpAddr = "10.0.0.2".parse().unwrap();
        assert!(!is_trusted_proxy(&ip, &trusted));
    }

    #[test]
    fn test_is_trusted_proxy_cidr() {
        let trusted = vec!["10.0.0.0/8".to_string(), "192.168.0.0/16".to_string()];

        let ip: IpAddr = "10.50.100.200".parse().unwrap();
        assert!(is_trusted_proxy(&ip, &trusted));

        let ip: IpAddr = "192.168.50.1".parse().unwrap();
        assert!(is_trusted_proxy(&ip, &trusted));

        let ip: IpAddr = "172.16.0.1".parse().unwrap();
        assert!(!is_trusted_proxy(&ip, &trusted));
    }

    #[test]
    fn test_is_trusted_proxy_empty() {
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        let trusted: Vec<String> = vec![];
        assert!(!is_trusted_proxy(&ip, &trusted));
    }
}
