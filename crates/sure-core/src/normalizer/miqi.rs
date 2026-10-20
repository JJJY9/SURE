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
    /// 2026-10-20: agent completion claims (see claim_capture). MiQi sends
    /// these in its own field names; the payload keys SURE reads are `id`,
    /// `claim_text` and `claim_type`.
    #[serde(default)]
    pub claim_id: Option<String>,
    #[serde(default)]
    pub claim_text: Option<String>,
    #[serde(default)]
    pub claim_type: Option<String>,
    /// 2026-10-20 (P3): a successful exec, classified by MiQi itself into one
    /// of test/build/compile/run/git. Only the normalized label is sent; the
    /// command line never leaves MiQi. `target` is a short label (`pytest`,
    /// `cargo build`, `git commit`), and `success` is always true today —
    /// failed executions are not sent at all.
    #[serde(default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub target: Option<String>,
    #[serde(default)]
    pub success: Option<bool>,
    #[serde(default)]
    pub subcommand: Option<String>,
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

    let event_type = map_event_type(&raw.event, raw.tool.as_deref(), raw.kind.as_deref())?;
    let mut envelope = EventEnvelope::new("miqi", event_type, &raw.timestamp_utc)
        .with_capability_tier(CapabilityTier::Observed)
        .with_session_id(&raw.harness_session_id);

    if let Some(ref project_root) = raw.project_root {
        envelope = envelope.with_project_root(project_root.clone());
    }

    let payload = build_payload(raw, event_type);
    envelope = envelope.with_payload(payload);

    Ok(envelope)
}

fn map_event_type(
    miqi_event: &str,
    tool: Option<&str>,
    kind: Option<&str>,
) -> Result<&'static str, MiqiNormalizeError> {
    match miqi_event {
        "SessionStart" => Ok("session.started"),
        "PreToolUse" => Ok("tool.requested"),
        // 2026-10-20: a completed write is a file observation, not just a
        // tool completion. claim_checker's `file_changed` looks for the
        // `file.*` family with a Write projection; without this mapping a
        // write could never confirm the agent's file_changed claim.
        "PostToolUse" => match tool {
            Some("write_file" | "edit_file" | "apply_patch") => Ok("file.written"),
            _ => Ok("tool.completed"),
        },
        "Stop" => Ok("session.stopped"),
        // 2026-10-20: completion claims (claim_capture::AGENT_CLAIM_EVENT_TYPE).
        "AgentClaim" => Ok(crate::claim_capture::AGENT_CLAIM_EVENT_TYPE),
        // 2026-10-20 (P3): a successful exec, classified by MiQi into one of
        // five families. claim_checker requires the event type to sit in the
        // family it checks (`test.` / `git.` / `build.|compile.|run.`) and the
        // projection to carry `target`/`success` (and `subcommand` for git).
        // An unknown kind is refused, not guessed — the same fail-closed rule
        // as every other event name.
        "ExecClassified" => match kind {
            Some("test") => Ok("test.ran"),
            Some("build") => Ok("build.ran"),
            Some("compile") => Ok("compile.ran"),
            Some("run") => Ok("run.ran"),
            Some("git") => Ok("git.command"),
            other => Err(MiqiNormalizeError::UnknownEventType {
                event: format!("ExecClassified(kind={})", other.unwrap_or("<missing>")),
            }),
        },
        other => Err(MiqiNormalizeError::UnknownEventType {
            event: other.to_owned(),
        }),
    }
}

fn build_payload(raw: MiqiRawEvent, event_type: &str) -> Value {
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
    // A completed write is projected as File{operation: Write} (the event type
    // already contains "write"; the flag keeps the payload self-describing).
    if event_type == "file.written" {
        map.insert("written".to_owned(), Value::Bool(true));
    }
    // Claim capture reads exactly these three payload keys.
    if let Some(claim_id) = raw.claim_id {
        map.insert("id".to_owned(), Value::String(claim_id));
    }
    if let Some(claim_text) = raw.claim_text {
        map.insert("claim_text".to_owned(), Value::String(claim_text));
    }
    if let Some(claim_type) = raw.claim_type {
        map.insert("claim_type".to_owned(), Value::String(claim_type));
    }
    // P3: the build/test/git projections read these three keys. The command
    // line itself is never part of the event (MiQi classifies locally and
    // sends the label only).
    if let Some(target) = raw.target {
        map.insert("target".to_owned(), Value::String(target));
    }
    if let Some(success) = raw.success {
        map.insert("success".to_owned(), Value::Bool(success));
    }
    if let Some(subcommand) = raw.subcommand {
        map.insert("subcommand".to_owned(), Value::String(subcommand));
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
    fn agent_claim_maps_to_the_claim_event() {
        let text = fixture("agent-claim.json");
        let envelope = normalize(&text).expect("valid fixture");
        assert_eq!(envelope.event_type, "agent.claim");
        // claim_capture reads exactly these payload keys.
        assert_eq!(envelope.payload["id"], Value::String("claim-1".to_owned()));
        assert_eq!(
            envelope.payload["claim_text"],
            Value::String("ran cargo test; 42 passed".to_owned())
        );
        assert_eq!(
            envelope.payload["claim_type"],
            Value::String("test_ran".to_owned())
        );
    }

    #[test]
    fn post_tool_use_write_maps_to_file_written() {
        let text = fixture("post-tool-use-write.json");
        let envelope = normalize(&text).expect("valid fixture");
        // claim_checker's file_changed looks for the file.* family with a
        // Write projection; a write that stayed tool.completed could never
        // confirm the claim.
        assert_eq!(envelope.event_type, "file.written");
        assert_eq!(envelope.payload["written"], Value::Bool(true));
        assert_eq!(
            envelope.payload["path"],
            Value::String("D:\\work\\演示 项目\\src\\email\\send.rs".to_owned())
        );
    }

    #[test]
    fn non_write_post_tool_use_stays_tool_completed() {
        let text = r#"{"event":"PostToolUse","harness_session_id":"c:s1","timestamp_utc":"2026-10-12T09:00:09Z","source":"miqi","tool":"exec","result":"ok"}"#;
        let envelope = normalize(text).expect("valid event");
        assert_eq!(envelope.event_type, "tool.completed");
    }

    #[test]
    fn exec_classified_maps_to_claim_families() {
        let text = fixture("exec-classified-test.json");
        let envelope = normalize(&text).expect("valid fixture");
        // claim_checker's test_ran requires the test.* family and a Test
        // projection; both come from MiQi's locally classified label — the
        // command line itself is never part of the event.
        assert_eq!(envelope.event_type, "test.ran");
        assert_eq!(
            envelope.payload["target"],
            Value::String("unittest".to_owned())
        );
        assert_eq!(envelope.payload["success"], Value::Bool(true));
        assert!(envelope.payload.get("command").is_none());
        assert!(envelope.payload.get("args").is_none());
    }

    #[test]
    fn exec_classified_git_carries_subcommand() {
        let text = r#"{"event":"ExecClassified","harness_session_id":"c:s1","timestamp_utc":"2026-10-20T07:30:00Z","source":"miqi","project_root":"D:\\work","kind":"git","target":"git commit","success":true,"subcommand":"commit"}"#;
        let envelope = normalize(text).expect("valid event");
        assert_eq!(envelope.event_type, "git.command");
        assert_eq!(
            envelope.payload["subcommand"],
            Value::String("commit".to_owned())
        );
    }

    #[test]
    fn exec_classified_unknown_kind_is_refused() {
        let text = r#"{"event":"ExecClassified","harness_session_id":"c:s1","timestamp_utc":"2026-10-20T07:30:00Z","source":"miqi","kind":"deploy","target":"deploy"}"#;
        let err = normalize(text).unwrap_err();
        assert!(matches!(err, MiqiNormalizeError::UnknownEventType { .. }));
        assert!(err.to_string().contains("deploy"));
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
            "post-tool-use-write.json",
            "agent-claim.json",
            "exec-classified-test.json",
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
