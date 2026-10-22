//! Configuration for the WebSocket Inspector agent.

use std::path::PathBuf;

/// Configuration for the WebSocket Inspector agent.
#[derive(Debug, Clone, PartialEq)]
pub struct WsInspectorConfig {
    // Content filtering (all default: true)
    /// Enable XSS detection in text frames
    pub xss_detection: bool,
    /// Enable SQL injection detection in text frames
    pub sqli_detection: bool,
    /// Enable command injection detection in text frames
    pub command_injection: bool,
    /// Custom regex patterns to block
    pub custom_patterns: Vec<String>,

    // Schema validation (all default: false/None)
    /// Path to JSON Schema file for message validation
    pub json_schema: Option<PathBuf>,
    /// Enable MessagePack message decoding and validation
    pub msgpack_validation: bool,

    // Rate limiting (default: 0 = unlimited)
    /// Maximum messages per second per connection (0 = unlimited)
    pub max_messages_per_sec: u32,
    /// Maximum bytes per second per connection (0 = unlimited)
    pub max_bytes_per_sec: u64,
    /// Burst allowance for rate limiting
    pub rate_limit_burst: u32,

    // Size limits (default: 0 = unlimited)
    /// Maximum text frame size in bytes (0 = unlimited)
    pub max_text_frame_size: usize,
    /// Maximum binary frame size in bytes (0 = unlimited)
    pub max_binary_frame_size: usize,
    /// Maximum total message size for fragmented messages (0 = unlimited)
    pub max_message_size: usize,

    // General
    /// Block mode: true = block violations, false = detect-only (log but allow)
    pub block_mode: bool,
    /// Fail open: allow frames on processing errors
    pub fail_open: bool,
    /// Log all frames for debugging
    pub log_frames: bool,
    /// Inspect binary frames (in addition to text frames)
    pub inspect_binary: bool,
}

impl Default for WsInspectorConfig {
    fn default() -> Self {
        Self {
            // Content filtering enabled by default
            xss_detection: true,
            sqli_detection: true,
            command_injection: true,
            custom_patterns: Vec::new(),

            // Schema validation disabled by default
            json_schema: None,
            msgpack_validation: false,

            // Rate limiting disabled by default
            max_messages_per_sec: 0,
            max_bytes_per_sec: 0,
            rate_limit_burst: 10,

            // Size limits disabled by default
            max_text_frame_size: 0,
            max_binary_frame_size: 0,
            max_message_size: 0,

            // General defaults
            block_mode: true,
            fail_open: false,
            log_frames: false,
            inspect_binary: false,
        }
    }
}

impl WsInspectorConfig {
    /// Check if any content filtering is enabled
    pub fn has_content_filtering(&self) -> bool {
        self.xss_detection
            || self.sqli_detection
            || self.command_injection
            || !self.custom_patterns.is_empty()
    }

    /// Check if rate limiting is enabled
    pub fn has_rate_limiting(&self) -> bool {
        self.max_messages_per_sec > 0 || self.max_bytes_per_sec > 0
    }

    /// Check if any size limits are set
    pub fn has_size_limits(&self) -> bool {
        self.max_text_frame_size > 0 || self.max_binary_frame_size > 0 || self.max_message_size > 0
    }

    /// Check if schema validation is enabled
    pub fn has_schema_validation(&self) -> bool {
        self.json_schema.is_some() || self.msgpack_validation
    }
}
