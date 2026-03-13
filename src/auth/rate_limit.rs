//! Simple in-memory rate limiter for auth endpoints.
//!
//! Uses a sliding window approach: each IP address is tracked with a list of
//! request timestamps. Old entries outside the window are pruned on each check.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::Instant;

/// In-memory rate limiter using a sliding window per IP address.
pub struct RateLimiter {
    /// Map of IP addresses to their recent request timestamps.
    requests: Mutex<HashMap<IpAddr, Vec<Instant>>>,
}

impl RateLimiter {
    /// Creates a new empty rate limiter.
    #[must_use]
    pub fn new() -> Self {
        Self {
            requests: Mutex::new(HashMap::new()),
        }
    }

    /// Checks whether a request from the given IP is allowed.
    ///
    /// Returns `true` if the request is within the rate limit, `false` if it
    /// should be rejected. Automatically cleans up timestamps older than
    /// `window_secs`.
    #[must_use]
    pub fn check_rate_limit(&self, ip: IpAddr, max_requests: u32, window_secs: u64) -> bool {
        let now = Instant::now();
        let window = std::time::Duration::from_secs(window_secs);

        let mut map = self
            .requests
            .lock()
            .expect("invariant: rate limiter mutex is not poisoned");

        let timestamps = map.entry(ip).or_default();

        // Remove entries older than the window
        timestamps.retain(|&t| now.duration_since(t) < window);

        if timestamps.len() >= max_requests as usize {
            return false;
        }

        timestamps.push(now);
        true
    }

    /// Removes all tracked entries. Useful for testing.
    #[allow(dead_code)]
    pub fn clear(&self) {
        let mut map = self
            .requests
            .lock()
            .expect("invariant: rate limiter mutex is not poisoned");
        map.clear();
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn allows_requests_within_limit() {
        let limiter = RateLimiter::new();
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        for _ in 0..5 {
            assert!(limiter.check_rate_limit(ip, 5, 60));
        }
        // 6th request should be rejected
        assert!(!limiter.check_rate_limit(ip, 5, 60));
    }

    #[test]
    fn different_ips_are_independent() {
        let limiter = RateLimiter::new();
        let ip1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

        for _ in 0..5 {
            assert!(limiter.check_rate_limit(ip1, 5, 60));
        }
        assert!(!limiter.check_rate_limit(ip1, 5, 60));

        // ip2 should still be allowed
        assert!(limiter.check_rate_limit(ip2, 5, 60));
    }

    #[test]
    fn clear_resets_all_state() {
        let limiter = RateLimiter::new();
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        for _ in 0..5 {
            let _ = limiter.check_rate_limit(ip, 5, 60);
        }
        assert!(!limiter.check_rate_limit(ip, 5, 60));

        limiter.clear();
        assert!(limiter.check_rate_limit(ip, 5, 60));
    }
}
