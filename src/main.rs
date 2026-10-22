//! WebSocket Inspector Agent CLI for Zentinel proxy.

use anyhow::{Context, Result};
use clap::Parser;
use std::path::PathBuf;
use tracing::info;
use tracing_subscriber::{fmt, EnvFilter};
use zentinel_agent_protocol::v2::{GrpcAgentServerV2, UdsAgentServerV2};
use zentinel_agent_websocket_inspector::{config::WsInspectorConfig, WsInspectorAgent};

/// WebSocket Inspector Agent for Zentinel proxy
///
/// Provides security controls for WebSocket traffic including content filtering,
/// schema validation, rate limiting, and size limits.
#[derive(Parser, Debug)]
#[command(name = "zentinel-websocket-inspector-agent")]
#[command(version, about, long_about = None)]
struct Args {
    /// Unix socket path for agent communication (UDS transport)
    #[arg(long, env = "AGENT_SOCKET", default_value = "/tmp/zentinel-ws.sock")]
    socket: String,

    /// gRPC address to listen on (e.g., "0.0.0.0:50051").
    /// If specified, the agent will use gRPC transport instead of UDS.
    #[arg(long, env = "WS_GRPC_ADDRESS")]
    grpc_address: Option<String>,

    /// Enable XSS detection in text frames
    #[arg(long, env = "WS_XSS", default_value = "true")]
    xss_detection: bool,

    /// Enable SQL injection detection in text frames
    #[arg(long, env = "WS_SQLI", default_value = "true")]
    sqli_detection: bool,

    /// Enable command injection detection in text frames
    #[arg(long, env = "WS_CMD", default_value = "true")]
    command_injection: bool,

    /// Custom regex patterns to block (comma-separated)
    #[arg(long, env = "WS_PATTERNS", default_value = "")]
    custom_patterns: String,

    /// Path to JSON Schema file for message validation
    #[arg(long, env = "WS_JSON_SCHEMA")]
    json_schema: Option<PathBuf>,

    /// Enable MessagePack message validation
    #[arg(long, env = "WS_MSGPACK", default_value = "false")]
    msgpack_validation: bool,

    /// Maximum messages per second per connection (0 = unlimited)
    #[arg(long, env = "WS_RATE_MESSAGES", default_value = "0")]
    max_messages_per_sec: u32,

    /// Maximum bytes per second per connection (0 = unlimited)
    #[arg(long, env = "WS_RATE_BYTES", default_value = "0")]
    max_bytes_per_sec: u64,

    /// Burst allowance for rate limiting
    #[arg(long, env = "WS_RATE_BURST", default_value = "10")]
    rate_limit_burst: u32,

    /// Maximum text frame size in bytes (0 = unlimited)
    #[arg(long, env = "WS_MAX_TEXT", default_value = "0")]
    max_text_frame_size: usize,

    /// Maximum binary frame size in bytes (0 = unlimited)
    #[arg(long, env = "WS_MAX_BINARY", default_value = "0")]
    max_binary_frame_size: usize,

    /// Maximum total message size for fragmented messages (0 = unlimited)
    #[arg(long, env = "WS_MAX_MESSAGE", default_value = "0")]
    max_message_size: usize,

    /// Block mode: true = block violations, false = detect-only
    #[arg(long, env = "WS_BLOCK_MODE", default_value = "true")]
    block_mode: bool,

    /// Allow frames on processing errors
    #[arg(long, env = "WS_FAIL_OPEN", default_value = "false")]
    fail_open: bool,

    /// Log all WebSocket frames
    #[arg(long, env = "WS_LOG_FRAMES", default_value = "false")]
    log_frames: bool,

    /// Inspect binary frames (in addition to text frames)
    #[arg(long, env = "WS_INSPECT_BINARY", default_value = "false")]
    inspect_binary: bool,

    /// Enable verbose debug logging
    #[arg(long, short, env = "VERBOSE", default_value = "false")]
    verbose: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize logging
    let filter = if args.verbose {
        EnvFilter::new("debug")
    } else {
        EnvFilter::new("info")
    };

    fmt().with_env_filter(filter).with_target(false).init();

    // Parse custom patterns
    let custom_patterns: Vec<String> = if args.custom_patterns.is_empty() {
        Vec::new()
    } else {
        args.custom_patterns
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    };

    // Build config
    let config = WsInspectorConfig {
        xss_detection: args.xss_detection,
        sqli_detection: args.sqli_detection,
        command_injection: args.command_injection,
        custom_patterns,
        json_schema: args.json_schema,
        msgpack_validation: args.msgpack_validation,
        max_messages_per_sec: args.max_messages_per_sec,
        max_bytes_per_sec: args.max_bytes_per_sec,
        rate_limit_burst: args.rate_limit_burst,
        max_text_frame_size: args.max_text_frame_size,
        max_binary_frame_size: args.max_binary_frame_size,
        max_message_size: args.max_message_size,
        block_mode: args.block_mode,
        fail_open: args.fail_open,
        log_frames: args.log_frames,
        inspect_binary: args.inspect_binary,
    };

    info!("Starting WebSocket Inspector Agent");
    info!("  Socket: {}", args.socket);
    info!("  XSS detection: {}", config.xss_detection);
    info!("  SQLi detection: {}", config.sqli_detection);
    info!("  Command injection: {}", config.command_injection);

    if !config.custom_patterns.is_empty() {
        info!("  Custom patterns: {}", config.custom_patterns.len());
    }

    if config.json_schema.is_some() {
        info!("  JSON Schema validation: enabled");
    }

    if config.msgpack_validation {
        info!("  MessagePack validation: enabled");
    }

    if config.has_rate_limiting() {
        info!(
            "  Rate limit: {} msg/s, {} bytes/s (burst: {})",
            config.max_messages_per_sec, config.max_bytes_per_sec, config.rate_limit_burst
        );
    }

    if config.has_size_limits() {
        info!(
            "  Size limits: text={}, binary={}, message={}",
            config.max_text_frame_size, config.max_binary_frame_size, config.max_message_size
        );
    }

    info!("  Block mode: {}", config.block_mode);
    info!("  Fail open: {}", config.fail_open);

    let agent = WsInspectorAgent::new(config)?;

    // Determine transport mode based on CLI args
    if let Some(grpc_addr) = args.grpc_address {
        // gRPC transport (v2 protocol)
        info!("Starting WebSocket Inspector Agent (gRPC v2)");
        info!("  gRPC address: {}", grpc_addr);

        let addr = grpc_addr
            .parse()
            .context("Invalid gRPC address format (expected host:port)")?;

        let server = GrpcAgentServerV2::new("ws-inspector", Box::new(agent));

        info!("WebSocket Inspector agent ready and listening on gRPC");

        server
            .run(addr)
            .await
            .context("Failed to run WebSocket Inspector gRPC server")?;
    } else {
        // UDS transport (v2 protocol)
        info!("Starting WebSocket Inspector Agent (UDS v2)");
        info!("  Socket: {}", args.socket);

        let server = UdsAgentServerV2::new("ws-inspector", &args.socket, Box::new(agent));
        server.run().await?;
    }

    Ok(())
}
