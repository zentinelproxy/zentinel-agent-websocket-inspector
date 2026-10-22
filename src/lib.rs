//! WebSocket Inspector Agent for Zentinel proxy.
//!
//! Provides security controls for WebSocket traffic including:
//! - Content filtering (XSS, SQLi, command injection)
//! - JSON Schema validation
//! - MessagePack validation
//! - Rate limiting
//! - Size limits

pub mod config;
pub mod fingerprint;
pub mod inspection;
pub mod ratelimit;
pub mod validation;

use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use config::WsInspectorConfig;
use fingerprint::config_fingerprint;
use inspection::{ContentInspector, Detection};
use ratelimit::{RateLimitConfig, RateLimitExceeded, RateLimiter};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};
use validation::{JsonSchemaValidator, MsgpackValidator};
use zentinel_agent_protocol::v2::{
    AgentCapabilities, AgentFeatures, AgentHandlerV2, AgentLimits, CounterMetric, DrainReason,
    GaugeMetric, HealthStatus, MetricsReport, ShutdownReason,
};
use zentinel_agent_protocol::{
    AgentResponse, AuditMetadata, EventType, RequestBodyChunkEvent, RequestCompleteEvent,
    RequestHeadersEvent, ResponseBodyChunkEvent, ResponseHeadersEvent, WebSocketDecision,
    WebSocketFrameEvent,
};

pub use config::WsInspectorConfig as Config;

use serde::Deserialize;

/// JSON configuration structure for on_configure().
/// Maps kebab-case JSON keys to WsInspectorConfig fields.
///
/// Every field is optional: a key that is absent keeps the value the agent is
/// currently running with (its flags, or an earlier configure). Unknown keys
/// are rejected so that a misspelled setting cannot silently fall back.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "kebab-case", default, deny_unknown_fields)]
pub struct WsInspectorConfigJson {
    /// Enable XSS detection in text frames
    pub xss_detection: Option<bool>,
    /// Enable SQL injection detection in text frames
    pub sqli_detection: Option<bool>,
    /// Enable command injection detection in text frames
    pub command_injection: Option<bool>,
    /// Custom regex patterns to block. A single string (one pattern, which is
    /// what a one-argument KDL node becomes) or a list.
    pub custom_patterns: Option<StringOrList>,
    /// Path to a JSON Schema file for message validation
    pub json_schema: Option<PathBuf>,
    /// Block mode: true = block violations, false = detect-only
    pub block_mode: Option<bool>,
    /// Fail open: allow frames on processing errors
    pub fail_open: Option<bool>,
    /// Maximum text frame size in bytes (0 = unlimited)
    pub max_text_frame_size: Option<usize>,
    /// Maximum binary frame size in bytes (0 = unlimited)
    pub max_binary_frame_size: Option<usize>,
    /// Maximum total message size (0 = unlimited)
    pub max_message_size: Option<usize>,
    /// Maximum messages per second per connection (0 = unlimited)
    pub max_messages_per_sec: Option<u32>,
    /// Maximum bytes per second per connection (0 = unlimited)
    pub max_bytes_per_sec: Option<u64>,
    /// Burst allowance for rate limiting
    pub rate_limit_burst: Option<u32>,
    /// Log all frames for debugging
    pub log_frames: Option<bool>,
    /// Inspect binary frames as well as text frames
    pub inspect_binary: Option<bool>,
    /// Enable MessagePack message decoding and validation
    pub msgpack_validation: Option<bool>,
}

/// A list setting that may arrive as one string or as an array of strings.
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum StringOrList {
    One(String),
    Many(Vec<String>),
}

impl StringOrList {
    fn into_vec(self) -> Vec<String> {
        match self {
            StringOrList::One(s) => vec![s],
            StringOrList::Many(v) => v,
        }
    }
}

impl WsInspectorConfigJson {
    /// Apply JSON config values to an existing WsInspectorConfig.
    /// Only overrides fields that are explicitly set (Some).
    ///
    /// Fails, leaving `config` untouched, when a value cannot be used: an
    /// invalid custom pattern, or a non-empty pattern list that is empty once
    /// blank entries are dropped.
    pub fn apply_to(&self, config: &mut WsInspectorConfig) -> anyhow::Result<()> {
        let mut next = config.clone();
        if let Some(v) = self.xss_detection {
            next.xss_detection = v;
        }
        if let Some(v) = self.sqli_detection {
            next.sqli_detection = v;
        }
        if let Some(v) = self.command_injection {
            next.command_injection = v;
        }
        if let Some(ref v) = self.custom_patterns {
            let raw = v.clone().into_vec();
            let patterns: Vec<String> = raw
                .iter()
                .map(|p| p.trim().to_string())
                .filter(|p| !p.is_empty())
                .collect();
            if patterns.is_empty() && !raw.is_empty() {
                anyhow::bail!("custom-patterns contains only empty entries");
            }
            for (i, pattern) in patterns.iter().enumerate() {
                if let Err(e) = regex::Regex::new(pattern) {
                    anyhow::bail!("custom-patterns[{i}] is not a valid regex: {e}");
                }
            }
            next.custom_patterns = patterns;
        }
        if let Some(ref v) = self.json_schema {
            next.json_schema = Some(v.clone());
        }
        if let Some(v) = self.block_mode {
            next.block_mode = v;
        }
        if let Some(v) = self.fail_open {
            next.fail_open = v;
        }
        if let Some(v) = self.max_text_frame_size {
            next.max_text_frame_size = v;
        }
        if let Some(v) = self.max_binary_frame_size {
            next.max_binary_frame_size = v;
        }
        if let Some(v) = self.max_message_size {
            next.max_message_size = v;
        }
        if let Some(v) = self.max_messages_per_sec {
            next.max_messages_per_sec = v;
        }
        if let Some(v) = self.max_bytes_per_sec {
            next.max_bytes_per_sec = v;
        }
        if let Some(v) = self.rate_limit_burst {
            next.rate_limit_burst = v;
        }
        if let Some(v) = self.log_frames {
            next.log_frames = v;
        }
        if let Some(v) = self.inspect_binary {
            next.inspect_binary = v;
        }
        if let Some(v) = self.msgpack_validation {
            next.msgpack_validation = v;
        }
        *config = next;
        Ok(())
    }
}

/// Names of the settings that differ between `old` and `new`.
fn changed_settings(old: &WsInspectorConfig, new: &WsInspectorConfig) -> Vec<&'static str> {
    let mut changed = Vec::new();
    macro_rules! cmp {
        ($($field:ident => $name:literal),* $(,)?) => {
            $(if old.$field != new.$field { changed.push($name); })*
        };
    }
    cmp!(
        xss_detection => "xss-detection",
        sqli_detection => "sqli-detection",
        command_injection => "command-injection",
        custom_patterns => "custom-patterns",
        json_schema => "json-schema",
        msgpack_validation => "msgpack-validation",
        max_messages_per_sec => "max-messages-per-sec",
        max_bytes_per_sec => "max-bytes-per-sec",
        rate_limit_burst => "rate-limit-burst",
        max_text_frame_size => "max-text-frame-size",
        max_binary_frame_size => "max-binary-frame-size",
        max_message_size => "max-message-size",
        block_mode => "block-mode",
        fail_open => "fail-open",
        log_frames => "log-frames",
        inspect_binary => "inspect-binary",
    );
    changed
}

/// WebSocket opcode string values
mod opcode {
    pub const CONTINUATION: &str = "continuation";
    pub const TEXT: &str = "text";
    pub const BINARY: &str = "binary";
    pub const CLOSE: &str = "close";
    pub const PING: &str = "ping";
    pub const PONG: &str = "pong";
}

/// WebSocket close codes (RFC 6455)
mod close_code {
    pub const POLICY_VIOLATION: u16 = 1008;
    pub const MESSAGE_TOO_BIG: u16 = 1009;
}

/// Internal state that can be reconfigured at runtime.
struct InspectorState {
    config: WsInspectorConfig,
    content_inspector: ContentInspector,
    json_validator: Option<JsonSchemaValidator>,
    msgpack_validator: Option<MsgpackValidator>,
    rate_limiter: RateLimiter,
    /// Canonical hash of the last configuration accepted from the proxy.
    config_hash: Option<u64>,
}

/// WebSocket Inspector Agent.
pub struct WsInspectorAgent {
    state: RwLock<InspectorState>,
    /// Metrics: total frames processed.
    frames_total: AtomicU64,
    /// Metrics: total frames blocked.
    frames_blocked: AtomicU64,
    /// Metrics: total frames dropped (XSS, SQLi, etc.).
    frames_dropped: AtomicU64,
    /// Metrics: total rate limit violations.
    rate_limit_violations: AtomicU64,
    /// Metrics: total size limit violations.
    size_limit_violations: AtomicU64,
    /// Metrics: total bytes inspected.
    bytes_inspected: AtomicU64,
    /// Whether the agent is draining (not accepting new requests).
    draining: Arc<RwLock<bool>>,
}

impl WsInspectorAgent {
    /// Create a new WebSocket Inspector agent.
    pub fn new(config: WsInspectorConfig) -> anyhow::Result<Self> {
        let state = Self::build_state(config)?;
        Ok(Self {
            state: RwLock::new(state),
            frames_total: AtomicU64::new(0),
            frames_blocked: AtomicU64::new(0),
            frames_dropped: AtomicU64::new(0),
            rate_limit_violations: AtomicU64::new(0),
            size_limit_violations: AtomicU64::new(0),
            bytes_inspected: AtomicU64::new(0),
            draining: Arc::new(RwLock::new(false)),
        })
    }

    /// Build the internal state from configuration.
    fn build_state(config: WsInspectorConfig) -> anyhow::Result<InspectorState> {
        let content_inspector = ContentInspector::new(config.clone());

        // Load JSON Schema if configured
        let json_validator = if let Some(ref path) = config.json_schema {
            Some(JsonSchemaValidator::from_file(path)?)
        } else {
            None
        };

        // Create MessagePack validator if enabled
        let msgpack_validator = if config.msgpack_validation {
            Some(if let Some(ref jv) = json_validator {
                MsgpackValidator::with_schema(jv.clone())
            } else {
                MsgpackValidator::new()
            })
        } else {
            None
        };

        // Create rate limiter
        let rate_limiter = RateLimiter::new(RateLimitConfig {
            max_messages_per_sec: config.max_messages_per_sec,
            max_bytes_per_sec: config.max_bytes_per_sec,
            burst: config.rate_limit_burst,
            ..Default::default()
        });

        Ok(InspectorState {
            config,
            content_inspector,
            json_validator,
            msgpack_validator,
            rate_limiter,
            config_hash: None,
        })
    }

    /// Reconfigure the agent with a configuration received from the proxy.
    ///
    /// The proxy sends the same `config { }` block on every connection, so
    /// this must be idempotent: an identical document (by canonical hash) or
    /// one that leaves the effective settings unchanged does nothing. When
    /// settings do change, only the parts they affect are rebuilt, and the
    /// rate limiter keeps its per-connection counters.
    ///
    /// Returns the names of the settings that changed. On error nothing is
    /// changed.
    async fn reconfigure(&self, raw: serde_json::Value) -> anyhow::Result<Vec<&'static str>> {
        let hash = config_fingerprint(&raw);
        let mut state = self.state.write().await;
        if state.config_hash == Some(hash) {
            return Ok(Vec::new());
        }

        let json_config: WsInspectorConfigJson = serde_json::from_value(raw)
            .map_err(|e| anyhow::anyhow!("invalid configuration: {e}"))?;
        let mut next = state.config.clone();
        json_config.apply_to(&mut next)?;
        let changed = changed_settings(&state.config, &next);
        if changed.is_empty() {
            state.config_hash = Some(hash);
            return Ok(changed);
        }

        // Build everything that can fail before touching the running state.
        let json_validator = if next.json_schema != state.config.json_schema {
            match next.json_schema {
                Some(ref path) => Some(JsonSchemaValidator::from_file(path)?),
                None => None,
            }
        } else {
            state.json_validator.clone()
        };

        state.msgpack_validator = if next.msgpack_validation {
            Some(if let Some(ref jv) = json_validator {
                MsgpackValidator::with_schema(jv.clone())
            } else {
                MsgpackValidator::new()
            })
        } else {
            None
        };
        state.json_validator = json_validator;
        state.content_inspector = ContentInspector::new(next.clone());

        if changed.iter().any(|c| {
            matches!(
                *c,
                "max-messages-per-sec" | "max-bytes-per-sec" | "rate-limit-burst"
            )
        }) {
            // New limits, same counters: a reconfigure must not hand every
            // connection a fresh window.
            state.rate_limiter = state.rate_limiter.with_config(RateLimitConfig {
                max_messages_per_sec: next.max_messages_per_sec,
                max_bytes_per_sec: next.max_bytes_per_sec,
                burst: next.rate_limit_burst,
                ..Default::default()
            });
        }

        state.config = next;
        state.config_hash = Some(hash);
        Ok(changed)
    }

    /// Check if agent is draining.
    async fn is_draining(&self) -> bool {
        *self.draining.read().await
    }

    /// Process a WebSocket frame and return a decision.
    async fn process_frame(&self, event: &WebSocketFrameEvent) -> AgentResponse {
        // Increment total frames counter
        self.frames_total.fetch_add(1, Ordering::Relaxed);

        // Check if draining
        if self.is_draining().await {
            debug!("Agent is draining, allowing frame");
            return AgentResponse::websocket_allow();
        }

        let correlation_id = &event.correlation_id;
        let direction = if event.client_to_server {
            "client→server"
        } else {
            "server→client"
        };

        // Acquire read lock for accessing state
        let state = self.state.read().await;

        if state.config.log_frames {
            info!(
                correlation_id = %correlation_id,
                opcode = %event.opcode,
                direction = direction,
                frame_index = event.frame_index,
                fin = event.fin,
                data_len = event.data.len(),
                "WebSocket frame"
            );
        }

        // Decode frame data from base64
        let data = match BASE64.decode(&event.data) {
            Ok(d) => d,
            Err(e) => {
                warn!(error = %e, "Failed to decode frame data");
                return Self::handle_error_static(state.config.fail_open, "decode-error");
            }
        };

        // Track bytes inspected
        self.bytes_inspected
            .fetch_add(data.len() as u64, Ordering::Relaxed);

        // Check size limits
        if let Some(response) = self.check_size_limits(&state.config, &event.opcode, data.len()) {
            return response;
        }

        // Check rate limits
        let result = state
            .rate_limiter
            .check_and_record(correlation_id, data.len() as u64)
            .await;

        if !result.allowed {
            self.rate_limit_violations.fetch_add(1, Ordering::Relaxed);
            let exceeded_type = match result.exceeded {
                Some(RateLimitExceeded::Messages) => "messages",
                Some(RateLimitExceeded::Bytes) => "bytes",
                None => "unknown",
            };

            debug!(
                correlation_id = %correlation_id,
                exceeded = exceeded_type,
                message_count = result.message_count,
                bytes_count = result.bytes_count,
                "Rate limit exceeded"
            );

            if state.config.block_mode {
                self.frames_blocked.fetch_add(1, Ordering::Relaxed);
                return AgentResponse::default_allow()
                    .with_websocket_decision(WebSocketDecision::Close {
                        code: close_code::POLICY_VIOLATION,
                        reason: format!("Rate limit exceeded: {}", exceeded_type),
                    })
                    .with_audit(AuditMetadata {
                        tags: vec!["ws-rate-limit".to_string()],
                        ..Default::default()
                    });
            } else {
                return AgentResponse::websocket_allow().with_audit(AuditMetadata {
                    tags: vec!["ws-rate-limit".to_string(), "detect-only".to_string()],
                    ..Default::default()
                });
            }
        }

        // Skip inspection for control frames
        if is_control_frame(&event.opcode) {
            return AgentResponse::websocket_allow();
        }

        // Inspect content based on opcode
        let mut all_detections = Vec::new();
        let mut validation_errors = Vec::new();

        match event.opcode.as_str() {
            opcode::TEXT | opcode::CONTINUATION => {
                // Text frame - inspect as string
                if let Ok(text) = std::str::from_utf8(&data) {
                    // Content inspection
                    let detections = state.content_inspector.inspect_text(text);
                    all_detections.extend(detections);

                    // JSON Schema validation
                    if let Some(ref validator) = state.json_validator {
                        let result = validator.validate_str(text);
                        if !result.valid {
                            validation_errors.extend(result.errors);
                        }
                    }
                }
            }
            opcode::BINARY => {
                // Binary frame
                // Content inspection (if enabled for binary)
                let detections = state.content_inspector.inspect_binary(&data);
                all_detections.extend(detections);

                // MessagePack validation
                if let Some(ref validator) = state.msgpack_validator {
                    let result = validator.validate(&data);
                    if !result.valid {
                        validation_errors.extend(result.errors);
                    }
                }
            }
            _ => {}
        }

        // Build response based on detections
        if !all_detections.is_empty() {
            return self.handle_detections(&state.config, &all_detections, correlation_id);
        }

        if !validation_errors.is_empty() {
            return self.handle_validation_errors(
                &state.config,
                &validation_errors,
                correlation_id,
            );
        }

        AgentResponse::websocket_allow()
    }

    /// Check size limits for a frame.
    fn check_size_limits(
        &self,
        config: &WsInspectorConfig,
        opcode: &str,
        size: usize,
    ) -> Option<AgentResponse> {
        let limit = match opcode {
            opcode::TEXT | opcode::CONTINUATION => config.max_text_frame_size,
            opcode::BINARY => config.max_binary_frame_size,
            _ => 0,
        };

        if limit > 0 && size > limit {
            self.size_limit_violations.fetch_add(1, Ordering::Relaxed);
            debug!(
                opcode = opcode,
                size = size,
                limit = limit,
                "Frame exceeds size limit"
            );

            if config.block_mode {
                self.frames_blocked.fetch_add(1, Ordering::Relaxed);
                return Some(
                    AgentResponse::default_allow()
                        .with_websocket_decision(WebSocketDecision::Close {
                            code: close_code::MESSAGE_TOO_BIG,
                            reason: "Message too large".to_string(),
                        })
                        .with_audit(AuditMetadata {
                            tags: vec!["ws-size-limit".to_string()],
                            ..Default::default()
                        }),
                );
            } else {
                return Some(AgentResponse::websocket_allow().with_audit(AuditMetadata {
                    tags: vec!["ws-size-limit".to_string(), "detect-only".to_string()],
                    ..Default::default()
                }));
            }
        }

        None
    }

    /// Handle content detections.
    fn handle_detections(
        &self,
        config: &WsInspectorConfig,
        detections: &[Detection],
        correlation_id: &str,
    ) -> AgentResponse {
        let tags: Vec<String> = detections
            .iter()
            .map(|d| d.detection_type.audit_tag().to_string())
            .collect();

        let rule_ids: Vec<String> = detections.iter().map(|d| d.pattern_id.clone()).collect();

        info!(
            correlation_id = %correlation_id,
            detections = ?rule_ids,
            "Content detections found"
        );

        if config.block_mode {
            self.frames_dropped.fetch_add(1, Ordering::Relaxed);
            self.frames_blocked.fetch_add(1, Ordering::Relaxed);
            AgentResponse::default_allow()
                .with_websocket_decision(WebSocketDecision::Drop)
                .with_audit(AuditMetadata {
                    tags,
                    rule_ids,
                    ..Default::default()
                })
        } else {
            let mut tags = tags;
            tags.push("detect-only".to_string());
            AgentResponse::websocket_allow().with_audit(AuditMetadata {
                tags,
                rule_ids,
                ..Default::default()
            })
        }
    }

    /// Handle schema validation errors.
    fn handle_validation_errors(
        &self,
        config: &WsInspectorConfig,
        errors: &[String],
        correlation_id: &str,
    ) -> AgentResponse {
        info!(
            correlation_id = %correlation_id,
            errors = ?errors,
            "Schema validation failed"
        );

        if config.block_mode {
            self.frames_dropped.fetch_add(1, Ordering::Relaxed);
            self.frames_blocked.fetch_add(1, Ordering::Relaxed);
            AgentResponse::default_allow()
                .with_websocket_decision(WebSocketDecision::Drop)
                .with_audit(AuditMetadata {
                    tags: vec!["ws-schema-invalid".to_string()],
                    reason_codes: errors.to_vec(),
                    ..Default::default()
                })
        } else {
            AgentResponse::websocket_allow().with_audit(AuditMetadata {
                tags: vec!["ws-schema-invalid".to_string(), "detect-only".to_string()],
                reason_codes: errors.to_vec(),
                ..Default::default()
            })
        }
    }

    /// Handle processing errors (static version).
    fn handle_error_static(fail_open: bool, error_type: &str) -> AgentResponse {
        if fail_open {
            AgentResponse::websocket_allow().with_audit(AuditMetadata {
                tags: vec!["ws-error".to_string(), "fail-open".to_string()],
                reason_codes: vec![error_type.to_string()],
                ..Default::default()
            })
        } else {
            AgentResponse::default_allow()
                .with_websocket_decision(WebSocketDecision::Drop)
                .with_audit(AuditMetadata {
                    tags: vec!["ws-error".to_string()],
                    reason_codes: vec![error_type.to_string()],
                    ..Default::default()
                })
        }
    }
}

/// Check if opcode is a control frame (close, ping, pong)
fn is_control_frame(opcode: &str) -> bool {
    matches!(opcode, opcode::CLOSE | opcode::PING | opcode::PONG)
}

#[async_trait]
impl AgentHandlerV2 for WsInspectorAgent {
    /// Return agent capabilities for v2 protocol.
    fn capabilities(&self) -> AgentCapabilities {
        AgentCapabilities::new(
            "ws-inspector",
            "WebSocket Inspector Agent",
            env!("CARGO_PKG_VERSION"),
        )
        .with_event(EventType::WebSocketFrame)
        .with_event(EventType::Configure)
        .with_features(AgentFeatures {
            streaming_body: false,
            websocket: true,
            guardrails: false,
            config_push: true,
            metrics_export: true,
            concurrent_requests: 100,
            cancellation: true,
            flow_control: false,
            health_reporting: true,
        })
        .with_limits(AgentLimits {
            max_body_size: 0, // Not used for WebSocket
            max_concurrency: 100,
            preferred_chunk_size: 64 * 1024,
            max_memory: None,
            max_processing_time_ms: Some(5000),
        })
    }

    /// Return current health status.
    fn health_status(&self) -> HealthStatus {
        HealthStatus::healthy("ws-inspector".to_string())
    }

    /// Return metrics report.
    fn metrics_report(&self) -> Option<MetricsReport> {
        let mut report = MetricsReport::new("ws-inspector", 10_000);

        report.counters.push(CounterMetric::new(
            "ws_inspector_frames_total",
            self.frames_total.load(Ordering::Relaxed),
        ));

        report.counters.push(CounterMetric::new(
            "ws_inspector_frames_blocked_total",
            self.frames_blocked.load(Ordering::Relaxed),
        ));

        report.counters.push(CounterMetric::new(
            "ws_inspector_frames_dropped_total",
            self.frames_dropped.load(Ordering::Relaxed),
        ));

        report.counters.push(CounterMetric::new(
            "ws_inspector_rate_limit_violations_total",
            self.rate_limit_violations.load(Ordering::Relaxed),
        ));

        report.counters.push(CounterMetric::new(
            "ws_inspector_size_limit_violations_total",
            self.size_limit_violations.load(Ordering::Relaxed),
        ));

        report.counters.push(CounterMetric::new(
            "ws_inspector_bytes_inspected_total",
            self.bytes_inspected.load(Ordering::Relaxed),
        ));

        // Gauge for draining status
        let draining = match self.draining.try_read() {
            Ok(guard) => {
                if *guard {
                    1.0
                } else {
                    0.0
                }
            }
            Err(_) => 0.0, // If we can't get the lock, assume not draining
        };
        report
            .gauges
            .push(GaugeMetric::new("ws_inspector_draining", draining));

        Some(report)
    }

    /// Handle configuration updates from proxy.
    ///
    /// Called once per proxy connection with the agent's `config { }` block.
    /// The configuration itself is never logged (it may hold secrets); its
    /// hash and the names of the changed settings are.
    async fn on_configure(&self, config: serde_json::Value, version: Option<String>) -> bool {
        let hash = format!("{:016x}", config_fingerprint(&config));
        match self.reconfigure(config).await {
            Ok(changed) if changed.is_empty() => {
                debug!(config_version = ?version, config_hash = %hash, "Configuration unchanged");
                true
            }
            Ok(changed) => {
                info!(
                    config_version = ?version,
                    config_hash = %hash,
                    changed = ?changed,
                    "Configuration applied"
                );
                true
            }
            Err(e) => {
                warn!(
                    config_version = ?version,
                    config_hash = %hash,
                    error = %e,
                    "Configuration rejected"
                );
                false
            }
        }
    }

    /// Handle shutdown request.
    async fn on_shutdown(&self, reason: ShutdownReason, grace_period_ms: u64) {
        info!(
            reason = ?reason,
            grace_period_ms = grace_period_ms,
            "Received shutdown request"
        );

        // Set draining to stop accepting new requests
        *self.draining.write().await = true;
    }

    /// Handle drain request.
    async fn on_drain(&self, duration_ms: u64, reason: DrainReason) {
        info!(
            duration_ms = duration_ms,
            reason = ?reason,
            "Received drain request"
        );

        // Set draining flag
        *self.draining.write().await = true;
    }

    async fn on_request_headers(&self, _event: RequestHeadersEvent) -> AgentResponse {
        // WebSocket inspector only handles WebSocket frames
        AgentResponse::default_allow()
    }

    async fn on_request_body_chunk(&self, _event: RequestBodyChunkEvent) -> AgentResponse {
        AgentResponse::default_allow()
    }

    async fn on_response_headers(&self, _event: ResponseHeadersEvent) -> AgentResponse {
        AgentResponse::default_allow()
    }

    async fn on_response_body_chunk(&self, _event: ResponseBodyChunkEvent) -> AgentResponse {
        AgentResponse::default_allow()
    }

    async fn on_request_complete(&self, _event: RequestCompleteEvent) -> AgentResponse {
        AgentResponse::default_allow()
    }

    async fn on_websocket_frame(&self, event: WebSocketFrameEvent) -> AgentResponse {
        self.process_frame(&event).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> WsInspectorConfig {
        WsInspectorConfig {
            xss_detection: true,
            sqli_detection: true,
            command_injection: true,
            block_mode: true,
            ..Default::default()
        }
    }

    fn make_text_frame(data: &str, client_to_server: bool) -> WebSocketFrameEvent {
        WebSocketFrameEvent {
            correlation_id: "test-123".to_string(),
            opcode: "text".to_string(),
            data: BASE64.encode(data),
            client_to_server,
            frame_index: 0,
            fin: true,
            route_id: None,
            client_ip: "127.0.0.1".to_string(),
        }
    }

    #[tokio::test]
    async fn test_clean_message() {
        let agent = WsInspectorAgent::new(test_config()).unwrap();
        let event = make_text_frame("Hello, world!", true);
        let response = AgentHandlerV2::on_websocket_frame(&agent, event).await;

        assert!(matches!(
            response.websocket_decision,
            Some(WebSocketDecision::Allow)
        ));
    }

    #[tokio::test]
    async fn test_xss_detection() {
        let agent = WsInspectorAgent::new(test_config()).unwrap();
        let event = make_text_frame("<script>alert(1)</script>", true);
        let response = AgentHandlerV2::on_websocket_frame(&agent, event).await;

        assert!(matches!(
            response.websocket_decision,
            Some(WebSocketDecision::Drop)
        ));
        assert!(response.audit.tags.contains(&"ws-xss".to_string()));
    }

    #[tokio::test]
    async fn test_sqli_detection() {
        let agent = WsInspectorAgent::new(test_config()).unwrap();
        let event = make_text_frame("UNION SELECT * FROM users", true);
        let response = AgentHandlerV2::on_websocket_frame(&agent, event).await;

        assert!(matches!(
            response.websocket_decision,
            Some(WebSocketDecision::Drop)
        ));
        assert!(response.audit.tags.contains(&"ws-sqli".to_string()));
    }

    #[tokio::test]
    async fn test_detect_only_mode() {
        let config = WsInspectorConfig {
            xss_detection: true,
            block_mode: false, // Detect only
            ..Default::default()
        };
        let agent = WsInspectorAgent::new(config).unwrap();
        let event = make_text_frame("<script>alert(1)</script>", true);
        let response = AgentHandlerV2::on_websocket_frame(&agent, event).await;

        // Should allow but with detection tags
        assert!(matches!(
            response.websocket_decision,
            Some(WebSocketDecision::Allow)
        ));
        assert!(response.audit.tags.contains(&"ws-xss".to_string()));
        assert!(response.audit.tags.contains(&"detect-only".to_string()));
    }

    #[tokio::test]
    async fn test_size_limit() {
        let config = WsInspectorConfig {
            max_text_frame_size: 10, // Very small limit
            block_mode: true,
            ..Default::default()
        };
        let agent = WsInspectorAgent::new(config).unwrap();
        let event = make_text_frame("This message is way too long", true);
        let response = AgentHandlerV2::on_websocket_frame(&agent, event).await;

        assert!(matches!(
            response.websocket_decision,
            Some(WebSocketDecision::Close { code: 1009, .. })
        ));
        assert!(response.audit.tags.contains(&"ws-size-limit".to_string()));
    }

    #[tokio::test]
    async fn test_disabled_detection() {
        let config = WsInspectorConfig {
            xss_detection: false,
            sqli_detection: false,
            command_injection: false,
            ..Default::default()
        };
        let agent = WsInspectorAgent::new(config).unwrap();
        let event = make_text_frame("<script>UNION SELECT; ls</script>", true);
        let response = AgentHandlerV2::on_websocket_frame(&agent, event).await;

        // Should allow since all detection is disabled
        assert!(matches!(
            response.websocket_decision,
            Some(WebSocketDecision::Allow)
        ));
    }

    #[tokio::test]
    async fn test_on_configure_updates_settings() {
        // Start with XSS detection enabled
        let config = WsInspectorConfig {
            xss_detection: true,
            block_mode: true,
            ..Default::default()
        };
        let agent = WsInspectorAgent::new(config).unwrap();

        // Verify XSS is blocked initially
        let event = make_text_frame("<script>alert(1)</script>", true);
        let response = AgentHandlerV2::on_websocket_frame(&agent, event.clone()).await;
        assert!(matches!(
            response.websocket_decision,
            Some(WebSocketDecision::Drop)
        ));

        // Configure to disable XSS detection (v2 API)
        let config_json = serde_json::json!({
            "xss-detection": false
        });
        let result =
            AgentHandlerV2::on_configure(&agent, config_json, Some("1.0".to_string())).await;
        assert!(result); // Should return true on success

        // Verify XSS is now allowed
        let event = make_text_frame("<script>alert(1)</script>", true);
        let response = AgentHandlerV2::on_websocket_frame(&agent, event).await;
        assert!(matches!(
            response.websocket_decision,
            Some(WebSocketDecision::Allow)
        ));
    }

    #[tokio::test]
    async fn test_on_configure_block_mode() {
        let config = WsInspectorConfig {
            xss_detection: true,
            block_mode: true, // Initially blocking
            ..Default::default()
        };
        let agent = WsInspectorAgent::new(config).unwrap();

        // Verify XSS is blocked initially
        let event = make_text_frame("<script>alert(1)</script>", true);
        let response = AgentHandlerV2::on_websocket_frame(&agent, event.clone()).await;
        assert!(matches!(
            response.websocket_decision,
            Some(WebSocketDecision::Drop)
        ));

        // Configure to detect-only mode (v2 API)
        let config_json = serde_json::json!({
            "block-mode": false
        });
        let result = AgentHandlerV2::on_configure(&agent, config_json, None).await;
        assert!(result); // Should return true on success

        // Verify XSS is detected but allowed (detect-only mode)
        let event = make_text_frame("<script>alert(1)</script>", true);
        let response = AgentHandlerV2::on_websocket_frame(&agent, event).await;
        assert!(matches!(
            response.websocket_decision,
            Some(WebSocketDecision::Allow)
        ));
        assert!(response.audit.tags.contains(&"ws-xss".to_string()));
        assert!(response.audit.tags.contains(&"detect-only".to_string()));
    }

    #[tokio::test]
    async fn test_on_configure_invalid_json() {
        let config = WsInspectorConfig::default();
        let agent = WsInspectorAgent::new(config).unwrap();

        // Send invalid config type (array instead of object) - v2 API
        let config_json = serde_json::json!([1, 2, 3]);
        let result = AgentHandlerV2::on_configure(&agent, config_json, None).await;

        // Should return false on invalid config
        assert!(!result);
    }

    /// Rate-limit decision for one frame on the test connection.
    async fn send_one(agent: &WsInspectorAgent) -> Option<WebSocketDecision> {
        let event = make_text_frame("hello", true);
        AgentHandlerV2::on_websocket_frame(agent, event)
            .await
            .websocket_decision
    }

    fn limited_agent() -> WsInspectorAgent {
        // 3 messages/s + burst 0: the 4th frame within a second is closed.
        WsInspectorAgent::new(WsInspectorConfig {
            max_messages_per_sec: 3,
            rate_limit_burst: 0,
            ..Default::default()
        })
        .unwrap()
    }

    fn is_allowed(d: &Option<WebSocketDecision>) -> bool {
        matches!(d, Some(WebSocketDecision::Allow))
    }

    #[tokio::test]
    async fn test_identical_configure_keeps_rate_limit_counters() {
        let agent = limited_agent();
        let block = serde_json::json!({
            "max-messages-per-sec": 3,
            "rate-limit-burst": 0,
            "xss-detection": true
        });
        assert!(AgentHandlerV2::on_configure(&agent, block.clone(), None).await);
        for _ in 0..3 {
            assert!(is_allowed(&send_one(&agent).await));
        }
        // The proxy opens another pooled connection (or reconnects) and sends
        // the same block again: the connection at its limit must stay there.
        assert!(AgentHandlerV2::on_configure(&agent, block.clone(), None).await);
        // Same settings, different key order: still a no-op.
        let reordered = serde_json::json!({
            "xss-detection": true,
            "rate-limit-burst": 0,
            "max-messages-per-sec": 3
        });
        assert!(AgentHandlerV2::on_configure(&agent, reordered, None).await);
        assert!(!is_allowed(&send_one(&agent).await));
    }

    #[tokio::test]
    async fn test_changed_limits_keep_rate_limit_counters() {
        let agent = limited_agent();
        for _ in 0..3 {
            assert!(is_allowed(&send_one(&agent).await));
        }
        // Raising the limit by one allows exactly one more frame this window.
        let block = serde_json::json!({ "max-messages-per-sec": 4 });
        assert!(AgentHandlerV2::on_configure(&agent, block, None).await);
        assert!(is_allowed(&send_one(&agent).await));
        assert!(!is_allowed(&send_one(&agent).await));
    }

    #[tokio::test]
    async fn test_partial_configure_keeps_cli_values() {
        let agent = WsInspectorAgent::new(WsInspectorConfig {
            max_messages_per_sec: 50,
            max_text_frame_size: 1024,
            custom_patterns: vec!["secret".to_string()],
            block_mode: false,
            ..Default::default()
        })
        .unwrap();
        assert!(
            AgentHandlerV2::on_configure(&agent, serde_json::json!({"log-frames": true}), None)
                .await
        );
        let state = agent.state.read().await;
        assert_eq!(state.config.max_messages_per_sec, 50);
        assert_eq!(state.config.max_text_frame_size, 1024);
        assert_eq!(state.config.custom_patterns, vec!["secret".to_string()]);
        assert!(!state.config.block_mode);
        assert!(state.config.log_frames);
    }

    #[tokio::test]
    async fn test_unknown_key_rejected_and_nothing_changes() {
        let agent = WsInspectorAgent::new(WsInspectorConfig {
            max_messages_per_sec: 50,
            ..Default::default()
        })
        .unwrap();
        // A misspelling of max-messages-per-sec next to a valid key.
        let block = serde_json::json!({
            "max-message-per-sec": 1,
            "block-mode": false
        });
        assert!(!AgentHandlerV2::on_configure(&agent, block, None).await);
        let state = agent.state.read().await;
        assert_eq!(state.config.max_messages_per_sec, 50);
        assert!(state.config.block_mode);
    }

    #[tokio::test]
    async fn test_custom_patterns_from_kdl_shapes() {
        let agent = WsInspectorAgent::new(WsInspectorConfig::default()).unwrap();
        // One argument in KDL arrives as a string.
        let one = serde_json::json!({"custom-patterns": "password=\\w+"});
        assert!(AgentHandlerV2::on_configure(&agent, one, None).await);
        let event = make_text_frame("password=hunter2", true);
        let response = AgentHandlerV2::on_websocket_frame(&agent, event).await;
        assert!(!is_allowed(&response.websocket_decision));

        let many = serde_json::json!({"custom-patterns": ["a+b", "c+d"]});
        assert!(AgentHandlerV2::on_configure(&agent, many, None).await);
        assert_eq!(agent.state.read().await.config.custom_patterns.len(), 2);

        // A list that is empty after parsing, and an invalid regex, are
        // rejected rather than replacing the active patterns.
        for bad in [
            serde_json::json!({"custom-patterns": ["", "  "]}),
            serde_json::json!({"custom-patterns": "(unclosed"}),
        ] {
            assert!(!AgentHandlerV2::on_configure(&agent, bad, None).await);
            assert_eq!(agent.state.read().await.config.custom_patterns.len(), 2);
        }
    }

    #[test]
    fn test_capabilities() {
        let config = WsInspectorConfig::default();
        let agent = WsInspectorAgent::new(config).unwrap();
        let caps = agent.capabilities();

        assert_eq!(caps.agent_id, "ws-inspector");
        assert_eq!(caps.name, "WebSocket Inspector Agent");
        assert!(caps.supports_event(EventType::WebSocketFrame));
        assert!(caps.features.websocket);
        assert!(caps.features.metrics_export);
        assert!(caps.features.health_reporting);
    }

    #[test]
    fn test_health_status() {
        let config = WsInspectorConfig::default();
        let agent = WsInspectorAgent::new(config).unwrap();
        let health = agent.health_status();

        assert!(health.is_healthy());
        assert_eq!(health.agent_id, "ws-inspector");
    }

    #[test]
    fn test_metrics_report() {
        let config = WsInspectorConfig::default();
        let agent = WsInspectorAgent::new(config).unwrap();
        let report = agent.metrics_report();

        assert!(report.is_some());
        let report = report.unwrap();
        assert_eq!(report.agent_id, "ws-inspector");
        assert!(!report.counters.is_empty());
        assert!(!report.gauges.is_empty());
    }
}
