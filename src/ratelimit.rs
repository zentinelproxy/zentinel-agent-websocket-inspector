//! Rate limiting for WebSocket connections.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Rate limiter configuration.
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Maximum messages per second (0 = unlimited)
    pub max_messages_per_sec: u32,
    /// Maximum bytes per second (0 = unlimited)
    pub max_bytes_per_sec: u64,
    /// Burst allowance (extra messages allowed in burst)
    pub burst: u32,
    /// Window duration for rate calculation
    pub window: Duration,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_messages_per_sec: 0,
            max_bytes_per_sec: 0,
            burst: 10,
            window: Duration::from_secs(1),
        }
    }
}

impl RateLimitConfig {
    /// Check if rate limiting is enabled.
    pub fn is_enabled(&self) -> bool {
        self.max_messages_per_sec > 0 || self.max_bytes_per_sec > 0
    }
}

/// Per-connection rate limit state.
#[derive(Debug, Clone)]
struct ConnectionState {
    /// Message count in current window
    message_count: u32,
    /// Bytes count in current window
    bytes_count: u64,
    /// When the current window started
    window_start: Instant,
    /// Burst tokens available
    burst_tokens: u32,
}

impl ConnectionState {
    fn new(burst: u32) -> Self {
        Self {
            message_count: 0,
            bytes_count: 0,
            window_start: Instant::now(),
            burst_tokens: burst,
        }
    }

    /// Reset the window if it has expired.
    fn maybe_reset_window(&mut self, window: Duration, burst: u32) {
        if self.window_start.elapsed() >= window {
            self.message_count = 0;
            self.bytes_count = 0;
            self.window_start = Instant::now();
            // Replenish burst tokens
            self.burst_tokens = burst;
        }
    }
}

/// Result of a rate limit check.
#[derive(Debug, Clone)]
pub struct RateLimitResult {
    /// Whether the message is allowed
    pub allowed: bool,
    /// Current message count
    pub message_count: u32,
    /// Current bytes count
    pub bytes_count: u64,
    /// Which limit was exceeded (if any)
    pub exceeded: Option<RateLimitExceeded>,
}

/// Which rate limit was exceeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitExceeded {
    Messages,
    Bytes,
}

impl RateLimitResult {
    fn allowed(message_count: u32, bytes_count: u64) -> Self {
        Self {
            allowed: true,
            message_count,
            bytes_count,
            exceeded: None,
        }
    }

    fn denied(message_count: u32, bytes_count: u64, exceeded: RateLimitExceeded) -> Self {
        Self {
            allowed: false,
            message_count,
            bytes_count,
            exceeded: Some(exceeded),
        }
    }
}

/// Rate limiter for WebSocket connections.
pub struct RateLimiter {
    config: RateLimitConfig,
    /// Per-connection state, keyed by correlation_id
    state: Arc<RwLock<HashMap<String, ConnectionState>>>,
}

impl RateLimiter {
    /// Create a new rate limiter.
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            state: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// A limiter with new limits that shares this one's per-connection
    /// counters, so changing the limits does not start every connection on a
    /// fresh window.
    pub fn with_config(&self, config: RateLimitConfig) -> Self {
        Self {
            config,
            state: Arc::clone(&self.state),
        }
    }

    /// Check if a message is allowed and record it.
    pub async fn check_and_record(
        &self,
        connection_id: &str,
        message_bytes: u64,
    ) -> RateLimitResult {
        if !self.config.is_enabled() {
            return RateLimitResult::allowed(0, 0);
        }

        let mut state = self.state.write().await;
        let conn_state = state
            .entry(connection_id.to_string())
            .or_insert_with(|| ConnectionState::new(self.config.burst));

        // Reset window if expired
        conn_state.maybe_reset_window(self.config.window, self.config.burst);

        // Check message rate limit
        // Allow base rate + burst allowance per window
        if self.config.max_messages_per_sec > 0 {
            let limit = self.config.max_messages_per_sec + self.config.burst;
            if conn_state.message_count >= limit {
                return RateLimitResult::denied(
                    conn_state.message_count,
                    conn_state.bytes_count,
                    RateLimitExceeded::Messages,
                );
            }
        }

        // Check bytes rate limit
        if self.config.max_bytes_per_sec > 0
            && conn_state.bytes_count + message_bytes > self.config.max_bytes_per_sec
        {
            return RateLimitResult::denied(
                conn_state.message_count,
                conn_state.bytes_count,
                RateLimitExceeded::Bytes,
            );
        }

        // Record the message
        conn_state.message_count += 1;
        conn_state.bytes_count += message_bytes;

        // Consume burst token if over base limit
        if self.config.max_messages_per_sec > 0
            && conn_state.message_count > self.config.max_messages_per_sec
            && conn_state.burst_tokens > 0
        {
            conn_state.burst_tokens -= 1;
        }

        RateLimitResult::allowed(conn_state.message_count, conn_state.bytes_count)
    }

    /// Remove state for a closed connection.
    pub async fn remove_connection(&self, connection_id: &str) {
        let mut state = self.state.write().await;
        state.remove(connection_id);
    }

    /// Clean up expired connection states.
    pub async fn cleanup_expired(&self) {
        let mut state = self.state.write().await;
        let expired_threshold = self.config.window * 2;
        state.retain(|_, conn| conn.window_start.elapsed() < expired_threshold);
    }
}

impl Clone for RateLimiter {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            state: Arc::clone(&self.state),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_rate_limit_disabled() {
        let limiter = RateLimiter::new(RateLimitConfig::default());
        let result = limiter.check_and_record("conn1", 100).await;
        assert!(result.allowed);
    }

    #[tokio::test]
    async fn test_message_rate_limit() {
        let config = RateLimitConfig {
            max_messages_per_sec: 3,
            max_bytes_per_sec: 0,
            burst: 0,
            window: Duration::from_secs(1),
        };
        let limiter = RateLimiter::new(config);

        // First 3 messages should be allowed
        for i in 1..=3 {
            let result = limiter.check_and_record("conn1", 10).await;
            assert!(result.allowed, "Message {} should be allowed", i);
        }

        // 4th message should be denied
        let result = limiter.check_and_record("conn1", 10).await;
        assert!(!result.allowed);
        assert_eq!(result.exceeded, Some(RateLimitExceeded::Messages));
    }

    #[tokio::test]
    async fn test_bytes_rate_limit() {
        let config = RateLimitConfig {
            max_messages_per_sec: 0,
            max_bytes_per_sec: 1000,
            burst: 0,
            window: Duration::from_secs(1),
        };
        let limiter = RateLimiter::new(config);

        // First message with 500 bytes - allowed
        let result = limiter.check_and_record("conn1", 500).await;
        assert!(result.allowed);

        // Second message with 400 bytes - allowed (900 total)
        let result = limiter.check_and_record("conn1", 400).await;
        assert!(result.allowed);

        // Third message with 200 bytes - denied (would be 1100)
        let result = limiter.check_and_record("conn1", 200).await;
        assert!(!result.allowed);
        assert_eq!(result.exceeded, Some(RateLimitExceeded::Bytes));
    }

    #[tokio::test]
    async fn test_burst_allowance() {
        let config = RateLimitConfig {
            max_messages_per_sec: 2,
            max_bytes_per_sec: 0,
            burst: 2, // Allow 2 extra in burst
            window: Duration::from_secs(1),
        };
        let limiter = RateLimiter::new(config);

        // Should allow 4 messages (2 base + 2 burst)
        for i in 1..=4 {
            let result = limiter.check_and_record("conn1", 10).await;
            assert!(result.allowed, "Message {} should be allowed", i);
        }

        // 5th message should be denied
        let result = limiter.check_and_record("conn1", 10).await;
        assert!(!result.allowed);
    }

    #[tokio::test]
    async fn test_separate_connections() {
        let config = RateLimitConfig {
            max_messages_per_sec: 2,
            max_bytes_per_sec: 0,
            burst: 0,
            window: Duration::from_secs(1),
        };
        let limiter = RateLimiter::new(config);

        // conn1: use up limit
        limiter.check_and_record("conn1", 10).await;
        limiter.check_and_record("conn1", 10).await;
        let result = limiter.check_and_record("conn1", 10).await;
        assert!(!result.allowed);

        // conn2: should still be allowed
        let result = limiter.check_and_record("conn2", 10).await;
        assert!(result.allowed);
    }

    #[tokio::test]
    async fn test_window_reset() {
        let config = RateLimitConfig {
            max_messages_per_sec: 2,
            max_bytes_per_sec: 0,
            burst: 0,
            window: Duration::from_millis(100),
        };
        let limiter = RateLimiter::new(config);

        // Use up the limit
        limiter.check_and_record("conn1", 10).await;
        limiter.check_and_record("conn1", 10).await;
        let result = limiter.check_and_record("conn1", 10).await;
        assert!(!result.allowed);

        // Wait for window to expire
        tokio::time::sleep(Duration::from_millis(150)).await;

        // Should be allowed again
        let result = limiter.check_and_record("conn1", 10).await;
        assert!(result.allowed);
        assert_eq!(result.message_count, 1);
    }

    #[tokio::test]
    async fn test_remove_connection() {
        let config = RateLimitConfig {
            max_messages_per_sec: 2,
            max_bytes_per_sec: 0,
            burst: 0,
            window: Duration::from_secs(1),
        };
        let limiter = RateLimiter::new(config);

        // Use up some quota
        limiter.check_and_record("conn1", 10).await;

        // Remove connection
        limiter.remove_connection("conn1").await;

        // Should start fresh
        let result = limiter.check_and_record("conn1", 10).await;
        assert!(result.allowed);
        assert_eq!(result.message_count, 1);
    }
}
