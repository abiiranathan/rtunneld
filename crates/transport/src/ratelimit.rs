#![forbid(unsafe_code)]
#![deny(clippy::all, clippy::pedantic)]

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::Instant;

/// Token-bucket per-IP rate limiter protecting pre-authentication and enrollment endpoints.
pub struct RateLimiter {
    capacity: f64,
    refill_rate: f64,
    buckets: Mutex<HashMap<IpAddr, (f64, Instant)>>,
}

impl RateLimiter {
    /// Creates a token-bucket rate limiter with the specified burst capacity and refill rate per second.
    #[must_use]
    pub fn new(capacity: u32, refill_rate_per_sec: u32) -> Self {
        Self {
            capacity: f64::from(capacity),
            refill_rate: f64::from(refill_rate_per_sec),
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Evaluates whether an incoming connection from the given IP address is accepted.
    ///
    /// # Panics
    ///
    /// Panics if the per-IP bucket map mutex is poisoned.
    #[must_use]
    pub fn check(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let mut lock = self.buckets.lock().expect("lock acquired");
        let (tokens, last_refill) = lock.entry(ip).or_insert((self.capacity, now));

        let elapsed = now.duration_since(*last_refill).as_secs_f64();
        *tokens = elapsed
            .mul_add(self.refill_rate, *tokens)
            .min(self.capacity);
        *last_refill = now;

        let allowed = if *tokens >= 1.0 {
            *tokens -= 1.0;
            true
        } else {
            false
        };
        drop(lock);

        allowed
    }
}
