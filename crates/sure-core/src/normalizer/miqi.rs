//! MiQi harness normalizer: raw MiQi events → SURE event protocol.
//!
//! MiQi (the MiqroForge desktop agent) sends its events through
//! `sure hook ingest --source miqi` from its own plugin layer — Python module
//! hooks call the CLI with the event on stdin — rather than through a shell
//! launcher in a harness config file the way Cursor's and Claude Code's hooks
//! do. The event shape is MiQi's own and matches the fixtures in
//! `integrations/miqi/fixtures/`.
//!
//! # Capability tier
//!
//! MiQi is **Observed** (tier 1): the integration records what the agent did,
//! after the fact. The decision path (see `assess_miqi_tool` in
//! [`sure_core::hook_protection`]) exists and is real, but v1 of the harness
//! does not act on the answer — reading a decision and ignoring it is not
//! protection — so this integration cannot honestly claim Protected (tier 2).

use serde::Deserialize;
use serde_json::Value;
use sure_domain::capability::CapabilityTier;
use sure_protocol::event::EventEnvelope;

/// A raw event from the MiQi harness.
///
/// Shape matches the fixtures in `integrations/miqi/fixtures/`. `args` is
/// optional and v1 of the integration sends no arguments — MiQi's own layer
/// leaves tool arguments out of the event, so a request from this harness
/// carries a tool name and a session and no command line.
#[derive(Debug, Clone, Deserialize)]
pub struct MiqiRawEvent {
    pub event: String,
    pub harness_session_id: String,
    pub timestamp_utc: String,
    pub source: String,
    #[serde(default)]
    pub project_root: Option<String>,
    #[serde(default)]
    pub tool: Option<String>,
    #[serde(default)]
    pub args: Option<Value>,
    #[serde(default)]
    pub result: Option<Value>,
    #[serde(default)]
    pub error: Option<Value>,
    #[serde(default)]
    pub path: Option<String>,
}

/// Why a MiQi raw event could not be normalized.
#[derive(Debug, Clone, PartialEq)]
pub enum MiqiNormalizeError {
    /// The text was not valid JSON.
    NotJson { message: String },
    /// The event type is not one MiQi is known to produce.
    UnknownEventType { event: String },
    /// The source field is not "miqi".
    WrongSource { source: String },
}

impl std::fmt::Display for MiqiNormalizeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotJson { message } => {
                write!(f, "the MiQi event is not valid JSON: {message}")
            }
            Self::UnknownEventType { event } => write!(
                f,
                "the MiQi event type '{event}' is not one SURE knows how to map"
            ),
            Self::WrongSource { source } => write!(
                f,
                "the MiQi event declares source '{source}', but 'miqi' was expected"
            ),
        }
    }
}

impl std::error::Error for MiqiNormalizeError {}

/// Convert a raw MiQi JSON event into a SURE [`EventEnvelope`].
///
/// # Capability tier
///
/// MiQi is **Observed** (tier 1); see the module comment for why tier 2 is not
/// claimed.
pub fn normalize(text: &str) -> Result<EventEnvelope, MiqiNormalizeError> {
    let raw: MiqiRawEvent =
        serde_json::from_str(text).map_err(|error| MiqiNormalizeError::NotJson {
            message: error.to_string(),
        })?;

    if raw.source != "miqi" {
        return Err(MiqiNormalizeError::WrongSource { source: raw.source });
    }

    let event_type = map_event_type(&raw.event)?;
    let mut envelope = EventEnvelope::new("miqi", event_type, &raw.timestamp_utc)
        .with_capability_tier(CapabilityTier::Observed)
        .with_session_id(&raw.harness_session_id);

    if let Some(ref project_root) = raw.project_root {
        envelope = envelope.with_project_root(project_root.clone());
    }

    let payload = build_payload(raw);
    envelope = envelope.with_payload(payload);

    Ok(envelope)
}

fn map_event_type(miqi_event: &str) -> Result<&'static str, MiqiNormalizeError> {
    match miqi_event {
        "SessionStart" => Ok("session.started"),
        "PreToolUse" => Ok("tool.requested"),
        "PostToolUse" => Ok("tool.completed"),
        "Stop" => Ok("session.stopped"),
        other => Err(MiqiNormalizeError::UnknownEventType {
            event: other.to_owned(),
        }),
    }
}

fn build_payload(raw: MiqiRawEvent) -> Value {
    let mut map = serde_json::Map::new();

    if let Some(tool) = raw.tool {
        map.insert("tool".to_owned(), Value::String(tool));
    }
    if let Some(args) = raw.args {
        map.insert("args".to_owned(), args);
    }
    if let Some(result) = raw.result {
        map.insert("result".to_owned(), result);
    }
    if let Some(error) = raw.error {
        map.insert("error".to_owned(), error);
    }
    if let Some(path) = raw.path {
        map.insert("path".to_owned(), Value::String(path));
    }

    // Preserve the original event type for audit.
    map.insert("miqi_event".to_owned(), Value::String(raw.event));

    Value::Object(map)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use sure_testkit::repository_root;

    fn fixture(name: &str) -> String {
        let path = repository_root()
            .join("integrations")
            .join("miqi")
            .join("fixtures")
            .join(name);
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
    }

    #[test]
    fn session_start_maps_correctly() {
        let text = fixture("session-start.json");
        let envelope = normalize(&text).expect("valid fixture");
        assert_eq!(envelope.event_type, "session.started");
        assert_eq!(envelope.source, "miqi");
        assert_eq!(envelope.session_id.as_deref(), Some("c:s1"));
        assert_eq!(
            envelope.project_root.as_deref(),
            Some("D:\\work\\演示 项目")
        );
        assert_eq!(envelope.timestamp, "2026-10-12T09:00:00Z");
        assert_eq!(envelope.capability_tier, Some(CapabilityTier::Observed));
        assert_eq!(
            envelope.payload["miqi_event"],
            Value::String("SessionStart".to_owned())
        );
    }

    #[test]
    fn pre_tool_use_maps_correctly() {
        let text = fixture("pre-tool-use.json");
        let envelope = normalize(&text).expect("valid fixture");
        assert_eq!(envelope.event_type, "tool.requested");
        assert_eq!(envelope.payload["tool"], Value::String("exec".to_owned()));
        // v1 sends no arguments; the request carries the tool name alone.
        assert!(envelope.payload.get("args").is_none());
    }

    #[test]
    fn post_tool_use_maps_correctly() {
        let text = fixture("post-tool-use.json");
        let envelope = normalize(&text).expect("valid fixture");
        assert_eq!(envelope.event_type, "tool.completed");
        assert_eq!(envelope.payload["result"], Value::String("ok".to_owned()));
    }

    #[test]
    fn stop_maps_correctly() {
        let text = fixture("stop.json");
        let envelope = normalize(&text).expect("valid fixture");
        assert_eq!(envelope.event_type, "session.stopped");
    }

    #[test]
    fn unknown_event_type_is_rejected() {
        let text = r#"{"event":"UnknownThing","harness_session_id":"c:s1","timestamp_utc":"2026-10-12T09:00:00Z","source":"miqi"}"#;
        let err = normalize(text).unwrap_err();
        assert!(matches!(err, MiqiNormalizeError::UnknownEventType { .. }));
        assert!(err.to_string().contains("UnknownThing"));
    }

    #[test]
    fn wrong_source_is_rejected() {
        let text = r#"{"event":"SessionStart","harness_session_id":"c:s1","timestamp_utc":"2026-10-12T09:00:00Z","source":"not-miqi"}"#;
        let err = normalize(text).unwrap_err();
        assert!(matches!(err, MiqiNormalizeError::WrongSource { .. }));
    }

    #[test]
    fn invalid_json_is_rejected() {
        let err = normalize("{not json").unwrap_err();
        assert!(matches!(err, MiqiNormalizeError::NotJson { .. }));
    }

    #[test]
    fn normalized_envelope_passes_ingestion() {
        let text = fixture("session-start.json");
        let envelope = normalize(&text).expect("valid fixture");
        let json = envelope.to_json().expect("serializes");
        let ingested = crate::harness_event::ingest_event_str(&json).expect("ingests");
        assert_eq!(ingested.envelope.event_type, "session.started");
        assert_eq!(ingested.envelope.source, "miqi");
    }

    #[test]
    fn all_fixture_events_ingest_successfully() {
        for name in [
            "session-start.json",
            "pre-tool-use.json",
            "post-tool-use.json",
            "stop.json",
        ] {
            let text = fixture(name);
            let envelope = normalize(&text).unwrap_or_else(|e| panic!("{name}: {e}"));
            let json = envelope.to_json().unwrap_or_else(|e| panic!("{name}: {e}"));
            crate::harness_event::ingest_event_str(&json)
                .unwrap_or_else(|e| panic!("{name} ingestion: {e}"));
        }
    }
}
