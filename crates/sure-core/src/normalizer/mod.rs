//! Source-specific event normalizers.
//!
//! Each integration adapter (Cursor, Claude Code, etc.) produces raw events in
//! its own shape. The normalizers in this module convert those raw events into
//! the SURE event protocol (`EventEnvelope`).
//!
//! `codex` is the one exception to "its own shape": Codex's hook payload is
//! Codex's documented shape, and `integrations/codex/scripts/sure-hook.*`
//! forwards it unchanged. See `codex.rs` for what that costs (no timestamp, and
//! four of twelve events with an honest SURE counterpart).

pub mod claude_code;
pub mod codex;
pub mod cursor;
pub mod miqi;
