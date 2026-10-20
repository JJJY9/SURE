//! `sure hook ingest`, and what it does in this build.
//!
//! # Why this is a module rather than an arm of `commands.rs`
//!
//! The same reason `crate::check` is one: [`Command::report`] is a match from a
//! command to a value, and the looking happens here so the match stays readable.
//!
//! # What the hook does
//!
//! 1. Read the raw JSON event from stdin.
//! 2. Normalise it with the harness-specific normaliser.
//! 3. Validate it via the existing ingestion path.
//! 4. Persist it via the existing session event store.
//! 5. For `pre-tool-use` events, evaluate a protection decision using the
//!    existing execution-safety machinery and return it as a structured JSON
//!    response — spending a one-time allowance the user recorded for exactly
//!    this request, if there is one, and answering with what SURE would then do
//!    (see [`with_any_allowance`]).
//! 6. Write that decision down beside the event it was about, so that it is
//!    still there after this process exits (see [`record_the_decision`]):
//!    `sure history` shows it and `sure history delete` removes it with the
//!    session it belongs to.
//!
//! `sure hook allow-once` is the other half of step 5: it is the command a
//! person runs to give the answer a hook cannot ask for, and it writes one row
//! to SURE's store. A hook is a fresh process per event, so that row is the only
//! place a one-time grant can live; see `sure_core::allowance`.
//!
//! # A project root SURE cannot use, and what SURE decided about it
//!
//! The event names the project it is about, and every question below the naming
//! reads that name as one location: the settings question asks whether the file
//! that decides what SURE may record and run is inside it
//! ([`Paths::ensure_settings_outside`]), and the store keys the session, the
//! event and the fingerprint by it ([`Paths::ensure_outside`]). A `project_root`
//! that is not an absolute path answers neither: it means "wherever this process
//! happens to be", and for a hook that is wherever the harness started SURE.
//!
//! **The decision (P15-T035): SURE refuses the event** — exit 5, no `decision`
//! field, nothing recorded — on every platform, before the settings file is read
//! and before anything is written. The refusal's own words are
//! [`sure_core::paths::PathError`]'s.
//!
//! The two answers not taken are worse, and both were argued rather than
//! dismissed. *Resolving* the path against the current directory would put a
//! location in the evidence that SURE inferred rather than read, and would make
//! which project an event is recorded under depend on where the harness started
//! the process; `crate::check`'s `project_of` refuses to do exactly that to a
//! path a **person** typed ("SURE does not silently repair an argument"), and an
//! event gets no more repair than an argument does. *Skipping the settings
//! question and answering the event anyway* would send a harness an `allow`
//! about a project SURE cannot place — and it could not record the event either,
//! because `Store::open` asks the same question of the same root and refuses it,
//! so the answer would be the only thing left and it would be about nothing.
//! That is the false green this repository exists to refuse.
//!
//! **Which way it errs: toward no evidence and a visible refusal.** On a
//! `SessionStart` there is no action a decision could have blocked, so the cost
//! of refusing is that session's history and one sentence on stderr; the cost of
//! the alternatives is a stored project root naming a directory the user never
//! meant. What a `SessionStart` gets from each harness package this repository
//! ships, and the source for each, is
//! `docs/integrations/HOOK_FAILURE_SEMANTICS.md` §2.3.

use std::io::{self, Read};
use std::path::Path;

use sure_core::allowance;
use sure_core::config::Authority;
use sure_core::config::ProtectionMode;
use sure_core::diagnostics::Timestamp;
use sure_core::execution::{ExecutionMode, ExecutionPermissions};
use sure_core::fingerprint::{FingerprintOptions, project_fingerprint};
use sure_core::full_recording::{
    self, DEFAULT_FULL_RECORDING_RETENTION_DAYS, FullRecordingConsent,
};
use sure_core::harness_event::ingest_event_str;
use sure_core::hook_protection::{
    Assessment, Danger, ProtectionDecision, ToolRequest, acts_a_tool_could_be_held_for,
    allowance_could_not_be_spent_reason, allowance_reason, allowance_unreadable_reason,
    assess_claude_code_tool, assess_cursor_tool, assess_miqi_tool,
};
use sure_core::ids::{EventId, FingerprintId};
use sure_core::normalizer::{claude_code, codex, cursor, miqi};
use sure_core::paths::Paths;
use sure_core::protection_history::{DecisionRecord, NotRecorded, not_recorded_reason};
use sure_core::session_event_store::SessionEventStore;
use sure_core::store::Store;

use crate::cli::HookAction;
use crate::commands::Named;
use crate::report::{Failed, HookAllowance, Report};

/// Run a hook action and produce a report.
///
/// `named` is what the caller named on the command line — the store directory
/// and the settings file, each `None` for the platform's own location. See
/// [`sure_core::paths::Paths::discover_with`]. A harness launcher that wants a
/// hook's events to land somewhere other than the user's own store names it
/// there, in the command it runs; nothing in the project can.
///
/// **This is the one command that reads a settings file the caller named**, and
/// it does so for the reason the rest of this module exists: it is the only
/// process that opens a full recording, so it is the only process by which the
/// consent path can be driven at all — `fixtures/privacy/manifest.json`'s
/// recording case is a real `sure hook ingest` pointed at a settings file that
/// grants one. What that file may grant is exactly what the user's own file may
/// grant, because the same reader reads it at the same layer; and it is refused
/// outright, before any decision, when the project being judged could have
/// written it ([`sure_core::paths::Paths::ensure_settings_outside`]), because a
/// hook's command line is a line a project's own harness configuration can
/// write.
#[must_use]
pub fn run(action: &HookAction, named: Named<'_>) -> Report {
    match action {
        HookAction::Ingest { source, event_kind } => {
            let mut stdin = String::new();
            if let Err(error) = io::stdin().read_to_string(&mut stdin) {
                return failed("SURE could not read standard input.", error.to_string());
            }

            let event_text = without_byte_order_mark(&stdin);
            if event_text.trim().is_empty() {
                return failed(
                    "No event was read from standard input.",
                    "The harness did not provide an event.".to_owned(),
                );
            }

            run_ingest(source.as_deref(), event_kind.as_deref(), event_text, named)
        }
        HookAction::AllowOnce {
            tool,
            command,
            path,
            project,
            minutes,
        } => run_allow_once(
            tool,
            command.as_deref(),
            path.as_deref(),
            project.as_deref(),
            *minutes,
            named,
        ),
    }
}

/// Record one one-time allowance, for one request, as the user typed it.
///
/// Nothing about the subject is read here. Whether it is a broad delete, a force
/// push or a read of credentials is decided when a request arrives
/// ([`sure_core::hook_protection`]), because that is the only moment at which
/// there is a request to read, and a command line this function refused to
/// record would be a second rule about what is dangerous. What this function
/// *does* refuse is a window SURE will not record, a project and a tool whose
/// settings leave nothing an allowance for that tool could ever spend, and a
/// request with no words in it: the first two are
/// [`run_allow_once_with_paths`]'s, the third the grammar's as well.
///
/// The settings and the tool are read while the subject is not, and the
/// difference is what is knowable now rather than what would be convenient:
/// `--project` names the directory every future request from that project is
/// answered against and `--tool` names the harness tool it has to carry, so the
/// execution mode, the permissions and the protection mode in force, and the
/// action kind the tool maps to, are all available at this moment — and together
/// they decide whether a request matching both can be held for one of the three
/// acts an allowance covers. A grant written where none can be is a grant spent
/// by nothing, and `P13-T010` is the task that made the writer say so instead of
/// promising that the first matching request would spend it. Reading the
/// settings here describes them and grants nothing: what may run is still the
/// arbitrated answer of `Authority`, and a project file cannot raise it
/// (`P13-T009`).
///
/// The *tool* is read, and it is not the subject: the two are separate halves of
/// what a grant matches. A tool name is the harness's own vocabulary, and SURE
/// answers it **in the vocabulary that claims it** — the reading that keeps
/// Claude Code's `Edit` a change to a project file instead of also reading it
/// through Cursor's unrecognised-name fallback, which is the shape that let the
/// writer record a grant for `Edit` and then have no request from either harness
/// spend it (`P13-T010`'s second send-back). A name neither vocabulary claims
/// is `ArbitraryCommand`, so a user may still cover a tool SURE has never heard
/// of, and that is the one arm where a grant can be recorded for words no
/// request carries — the wasted minute rather than the wrong answer. The
/// **subject** stays unread: whether `rm -rf build/` or `.env` is dangerous is
/// decided when a request arrives, and a command line this function refused to
/// record would be a second rule about what is dangerous. So what the user reads
/// is what the settings in force leave for *their tool*, and a grant recorded
/// for words SURE would never name as dangerous is one it is never spent on —
/// which is the residual `docs/security/PROTECTION_MODE.md` states and this
/// command cannot close.
///
/// The project is the one caller-side fact this command takes as given, because
/// nothing else can supply it: [`run_allow_once_with_paths`] stores the grant
/// against `--project`, and a grant recorded for a different directory than the
/// one a request arrives from is spendable by nothing. What the user reads names
/// the directory, so that mistake is visible while it can still be corrected.
fn run_allow_once(
    tool: &str,
    command: Option<&str>,
    path: Option<&str>,
    project: Option<&Path>,
    minutes: u32,
    named: Named<'_>,
) -> Report {
    let Some(subject) = command.or(path) else {
        // clap asks for exactly one of `--command` and `--path`, so this is
        // unreachable from a command line; it is here because an answer is
        // better than a panic if the grammar ever changes.
        return failed(
            "No request was named.",
            "Name the request with --command for a shell tool, or --path for a tool that names \
             a file."
                .to_owned(),
        );
    };

    let project_root = match project {
        Some(dir) => dir.to_string_lossy().into_owned(),
        None => match std::env::current_dir() {
            Ok(cwd) => cwd.to_string_lossy().into_owned(),
            Err(error) => {
                return failed(
                    "SURE could not read the current directory.",
                    format!("{error}. Name the project with --project."),
                );
            }
        },
    };

    let paths = match Paths::discover_with(named.store, named.settings_file) {
        Ok(paths) => paths,
        Err(error) => {
            return failed(
                "SURE could not discover its data directories.",
                error.to_string(),
            );
        }
    };

    run_allow_once_with_paths(tool, subject, &project_root, minutes, &paths)
}

/// [`run_allow_once`], with the locations already resolved.
///
/// The same split [`run_ingest`] has and for the same reason: what the command
/// *decides* is testable against locations a test named, and the only part that
/// reaches the machine's own files is the wrapper above.
fn run_allow_once_with_paths(
    tool: &str,
    subject: &str,
    project_root: &str,
    minutes: u32,
    paths: &Paths,
) -> Report {
    if !allowance::window_is_allowed(minutes) {
        return failed(
            "SURE will not record an allowance lasting that long.",
            format!(
                "--minutes must be between 1 and {}, and {} is what SURE records when the \
                 duration is not given. An allowance is a single use of one request, and one \
                 SURE records for longer than that is a standing permission with a shorter \
                 name.",
                allowance::MAX_MINUTES,
                allowance::DEFAULT_MINUTES
            ),
        );
    }

    // The settings in force, read before anything is written, because they decide
    // whether a grant written now can be spent at all: a danger is named only for
    // a request SURE holds, and whether a request is held is a question about the
    // mode, the permissions and the protection mode rather than about the words.
    // Refusing is the direction that fails closed, and the sentence names the
    // setting to change rather than the refusal alone.
    //
    // The question is asked of the **tool the user named**, which is the other
    // half of the same rule and the half that was missing: a grant is spent by a
    // request that matches the tool and the words, so a project in which a read
    // of credentials is within reach of an allowance is still one where a grant
    // for `Shell` is spent by nothing (`P13-T010`, second dispatch). Only the
    // tool is narrowed. The subject is still unread, because there is no request
    // to read it against; the tool is not the subject, it is the name the
    // harness will send back.
    //
    // Where the settings come from, refused if the project they are about could
    // write them — the same question `run_ingest_with_paths` asks, asked here
    // because this command names its project on the command line rather than
    // reading one out of an event. Before `load_execution_config`, which is the
    // read that would otherwise obey the file: a grant recorded under settings
    // the project wrote is a grant the project wrote.
    //
    // The refusal is answered as a failure rather than as a verdict — exit 5,
    // `outcome: "failed"`, no `decision` field, nothing recorded — and it is the
    // same answer at both sites, for the reasons written out at the site below
    // and argued in `docs/integrations/HOOK_FAILURE_SEMANTICS.md` §2.4. A
    // `decision` here would be a verdict about a request SURE has not looked at.
    if let Err(error) = paths.ensure_settings_outside(Path::new(project_root)) {
        return failed(
            "SURE did not read the settings it was pointed at.",
            error.to_string(),
        );
    }

    // The window is checked first so that a duration SURE does not record is
    // answered as that, whatever the project says: it is the one refusal a user
    // can fix without looking at anything but the command line they typed.
    let (mode, permissions, protection) = load_execution_config(project_root, paths);
    if let Some(reason) = allowance_could_not_be_spent_reason(tool, mode, &permissions, protection)
    {
        return failed(
            "SURE will not record an allowance that no request could spend.",
            reason,
        );
    }

    let project_path = Path::new(project_root);
    let store_handle = match Store::open(paths, project_path) {
        Ok(store_handle) => store_handle,
        Err(error) => {
            return failed("SURE could not open its record store.", error.to_string());
        }
    };

    // The fingerprint is a note about which revision of the project this was
    // recorded against; the allowance is *not* scoped by it. An allowance keyed
    // to a fingerprint would stop being spendable the moment the agent wrote a
    // line of code, which is the moment the request it was recorded for tends to
    // arrive.
    let fingerprint = match project_fingerprint(project_path, &FingerprintOptions::default()) {
        Ok(fingerprint) => fingerprint,
        Err(error) => return failed("SURE could not fingerprint the project.", error.to_string()),
    };

    let now_ms = Timestamp::now().as_millis();
    match allowance::record(
        &store_handle,
        project_root,
        &fingerprint.id,
        tool,
        subject,
        minutes,
        now_ms,
    ) {
        Ok(grant) => Report::HookAllowance(Box::new(HookAllowance {
            tool: tool.to_owned(),
            subject: subject.to_owned(),
            project: project_root.to_owned(),
            minutes,
            grant,
            not_after_ms: now_ms.saturating_add(i64::from(minutes) * 60_000),
            // The acts reachable under the settings just read **by a request
            // naming this tool**, carried into the sentence so that a
            // confirmation cannot name an act those settings make unreachable —
            // for the tool it is about. Non-empty, because the refusal above
            // returned on the empty answer.
            acts: acts_a_tool_could_be_held_for(tool, mode, &permissions, protection),
        })),
        Err(error) => failed("SURE could not record the allowance.", error.to_string()),
    }
}

/// The event text as SURE should read it off standard input.
///
/// Windows PowerShell 5.1 writes a UTF-8 byte-order mark in front of every
/// payload it pipes to a native command, whatever `$OutputEncoding` is set to
/// (measured 2026-09-18 against `powershell.exe`, with standard input as a pipe
/// and as a redirected file: the first three bytes were `EF BB BF`, while
/// `pwsh` 7 wrote none). A byte-order mark is not JSON, so without this every
/// event arriving from the Windows default shell would be refused as invalid —
/// and the Codex, Cursor and Claude Code launchers all reach SURE through that
/// pipe. The mark says nothing about the event, so dropping a leading one
/// invents nothing; everything after it is passed on exactly as it arrived.
fn without_byte_order_mark(text: &str) -> &str {
    text.strip_prefix('\u{feff}').unwrap_or(text)
}

fn run_ingest(
    source: Option<&str>,
    event_kind: Option<&str>,
    stdin: &str,
    named: Named<'_>,
) -> Report {
    let paths = match Paths::discover_with(named.store, named.settings_file) {
        Ok(p) => p,
        Err(error) => {
            return failed(
                "SURE could not discover its data directories.",
                error.to_string(),
            );
        }
    };
    run_ingest_with_paths(source, event_kind, stdin, &paths)
}

fn run_ingest_with_paths(
    source: Option<&str>,
    event_kind: Option<&str>,
    stdin: &str,
    paths: &Paths,
) -> Report {
    // Normalise based on source.
    let envelope = match source {
        Some("cursor") => match cursor::normalize(stdin) {
            Ok(envelope) => envelope,
            Err(error) => return failed("The event could not be normalised.", error.to_string()),
        },
        Some("claude-code") => match claude_code::normalize(stdin) {
            Ok(envelope) => envelope,
            Err(error) => return failed("The event could not be normalised.", error.to_string()),
        },
        // Codex's payload carries `hook_event_name`, so `--source codex` needs
        // no event-kind argument: the event names itself and SURE reads the
        // name Codex sent rather than one the manifest repeated. Four of the
        // twelve events Codex sends map; the rest are refused by name, with the
        // reason, in `crates/sure-core/src/normalizer/codex.rs` and in the table
        // in `integrations/codex/README.md`.
        Some("codex") => match codex::normalize(stdin) {
            Ok(envelope) => envelope,
            Err(error) => return failed("The event could not be normalised.", error.to_string()),
        },
        // MiQi's events are MiQi's own shape, sent from its plugin layer
        // rather than from a shell launcher in a harness config file;
        // `integrations/miqi/README.md` records the shape and what v1 of the
        // integration does not send.
        Some("miqi") => match miqi::normalize(stdin) {
            Ok(envelope) => envelope,
            Err(error) => return failed("The event could not be normalised.", error.to_string()),
        },
        Some(other) => {
            return failed(
                "The event source is not supported.",
                format!("Source '{other}' is not one SURE knows how to ingest."),
            );
        }
        None => {
            return failed(
                "No source was given.",
                "Use --source <name> to tell SURE which harness sent the event.".to_owned(),
            );
        }
    };

    // Validate via the existing ingestion path.
    let json = match envelope.to_json() {
        Ok(json) => json,
        Err(error) => {
            return failed(
                "The normalised event could not be serialised.",
                error.to_string(),
            );
        }
    };

    let ingested = match ingest_event_str(&json) {
        Ok(ingested) => ingested,
        Err(error) => return failed("The event did not pass validation.", error.to_string()),
    };

    // Determine project root for store and config.
    let project_root = envelope.project_root.clone().unwrap_or_else(|| {
        std::env::current_dir()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|_| String::from("."))
    });

    // The settings this event is about to be decided and recorded under, refused
    // if the project that sent it could have written them. Here, before the
    // event is written and before any decision, because both of those read the
    // file: the recording's consent and the permissions a request is judged
    // against are the user's own word, and a file inside the project is the
    // judged thing's word wearing the user's name.
    //
    // A hook's command line is written in a project's harness configuration —
    // Claude Code's `.claude/settings.json` and Cursor's hooks file both name
    // the command SURE is run as, in the project's own directory — so a hook is
    // exactly the agent-facing path where `--settings-file` could be pointed at
    // a file the project wrote. The refusal is what makes it not a way to
    // escalate, and it is the same rule `sure check` asks before it records a
    // goal: `PathError::SettingsInsideProject`'s own words, in both.
    //
    // The project root comes from the event, so it is the harness's claim about
    // which project this is. That is the right root to hold the file to: a
    // settings file inside the project the event says it is about is a file that
    // project can write, whoever sent the event.
    //
    // This is also the point at which a root that is not absolute stops the
    // event, and that is a decision rather than a side effect of asking the
    // question here (P15-T035). The root above is read by two questions and both
    // need one location: this one, and the store's key for the session and the
    // event. Resolving a relative root against the current directory would
    // record a project SURE inferred rather than read, and would make which
    // project an event belongs to depend on where the harness started the hook;
    // answering the event without placing it is not available either, because
    // `Store::open` asks the same question of the same root and refuses it, so
    // the decision would be the only thing left and it would be about nothing.
    // So SURE refuses, and the refusal errs toward no evidence plus a visible
    // sentence rather than toward a green answer over an unknown project. The
    // harness-by-harness consequence, and the source for each, is
    // `docs/integrations/HOOK_FAILURE_SEMANTICS.md` §2.3.
    //
    // The shape both of these refusals take is a **failure, not a verdict**:
    // `Report::Failed` → exit 5, `outcome: "failed"`, no `decision` field, and
    // nothing recorded. It is not a `block`, because SURE stopped before it read
    // the settings, so it has read none of the mode, the permissions or the
    // request this event names: `block`'s sentence about the execution mode
    // would be a verdict about a mode SURE never saw. Recording nothing is the
    // other half of the same rule — `record_the_decision` writes down every
    // decision the rule reached, so a `block` here would have to write a session
    // and a tool request under the settings SURE refused to read. §2.4 argues
    // it, including the case against, and
    // `a_hook_event_that_names_a_settings_file_inside_the_project_is_refused`
    // in `crates/sure-cli/tests/cli_contract.rs` holds the shape against a
    // process rather than against this sentence.
    if let Err(error) = paths.ensure_settings_outside(Path::new(&project_root)) {
        return failed(
            "SURE did not read the settings it was pointed at.",
            error.to_string(),
        );
    }

    // Best-effort persistence. The harness cares most about the decision for
    // pre-tool-use; a store failure should not block the operation.
    //
    // The result is kept rather than discarded because the *decision* row, two
    // steps below, hangs from this event and needs the fingerprint it was
    // written with. A discarded result here would mean a second fingerprinting
    // of the same project, and a decision row whose `project_fingerprint` could
    // differ from the event's for the same moment.
    let event_id = EventId::generate();
    let event_write = persist_event_with_paths(&ingested, &project_root, &event_id, paths);

    // Evaluate protection for pre-tool-use events.
    let is_pre_tool_use =
        event_kind == Some("pre-tool-use") || envelope.event_type == "tool.requested";

    if is_pre_tool_use {
        // The tool name, the path and the command are the request's own words —
        // the normaliser lifts `path` from the payload the harness sent, and
        // `args` is the harness's own arguments object, where a shell tool's
        // command line lives (`normalizer::{cursor,claude_code}`). They are
        // handed to the rule as data (P13-T004); the rule classifies the path
        // and reads the command with `safety::read_simple_command`, which
        // refuses any line with more than one reading, and never echoes either
        // one back inside a sentence SURE writes.
        let request = ToolRequest::of(
            envelope
                .payload
                .get("tool")
                .and_then(|v| v.as_str())
                .unwrap_or(""),
        )
        .and_path(envelope.payload.get("path").and_then(|v| v.as_str()))
        .and_command(
            envelope
                .payload
                .get("args")
                .and_then(|args| args.get("command"))
                .and_then(|v| v.as_str()),
        );

        let (mode, permissions, protection) = load_execution_config(&project_root, paths);

        let assessment = match source {
            // Codex is documented to name its shell tool `Bash` and to match its
            // patch tool as `Edit` or `Write`, which is the vocabulary this
            // classifier already recognises. A Codex name outside it — a local
            // function such as `update_plan`, or an MCP tool — falls to the
            // classifier's unknown branch, which fails closed rather than
            // passing. `integrations/codex/README.md` records that limitation
            // and why the decision is advisory on this harness.
            Some("claude-code" | "codex") => {
                assess_claude_code_tool(&request, mode, &permissions, protection)
            }
            Some("miqi") => assess_miqi_tool(&request, mode, &permissions, protection),
            // `Some("cursor")`, and anything else: the match above has already
            // refused a source SURE does not know.
            _ => assess_cursor_tool(&request, mode, &permissions, protection),
        };
        return Report::HookDecision(record_the_decision(
            with_any_allowance(&assessment, &request, &project_root, paths),
            assessment.danger,
            request.tool,
            &event_id,
            &event_write,
            &project_root,
            paths,
        ));
    }

    // For non-pre-tool-use events, report success.
    Report::HookDecision(sure_core::hook_protection::ProtectionDecision::allow())
}

/// A decision, and the one-time allowance it spent if it spent one.
///
/// The two travel together because the second is the only thing that tells an
/// allow-once from an ordinary allow: both are
/// [`ProtectionDecisionKind::Allow`](sure_core::hook_protection::ProtectionDecisionKind::Allow),
/// so a caller that lost the row id could not tell them apart afterwards
/// (`sure_core::protection_history`). Nothing else about the decision depends on
/// it, and the exit code never does.
struct Decided {
    /// What SURE would do about the request.
    decision: ProtectionDecision,
    /// The row id of the grant this decision spent, if it spent one.
    allowance: Option<i64>,
}

/// The decision, with a recorded one-time allowance spent on it when one covers
/// the request.
///
/// This is the whole of the override path, and it can only ever make the answer
/// **more permissive for one request that SURE itself named as dangerous**. Two
/// things keep it that shape:
///
/// * a danger is attached to a held request only, and only for three acts (see
///   [`sure_core::hook_protection::Danger`]), so a request held for any other
///   reason — the execution mode, a settings file SURE could not read, a
///   migration, a whole-location change strict holds — has nothing to spend;
/// * the spend is one store transaction that re-reads the grants, so two hooks
///   racing on one allowance cannot both spend it.
///
/// Every failure here is answered with the hold, never with the allowance: a
/// store SURE cannot read is a store whose allowances it does not know, and
/// answering "no allowance" and answering "allow" are the two ways to get that
/// wrong. The sentence differs between them, because a user who recorded an
/// allowance a minute ago should be able to tell "there was none" from "SURE
/// could not look".
fn with_any_allowance(
    assessment: &Assessment,
    request: &ToolRequest<'_>,
    project_root: &str,
    paths: &Paths,
) -> Decided {
    let unspent = |decision: ProtectionDecision| Decided {
        decision,
        allowance: None,
    };
    let (Some(danger), Some(subject)) = (assessment.danger, request.subject()) else {
        return unspent(assessment.decision.clone());
    };

    let store = match Store::open(paths, Path::new(project_root)) {
        Ok(store) => store,
        Err(_) => {
            return unspent(ProtectionDecision::block(allowance_unreadable_reason(
                danger,
            )));
        }
    };

    match store.spend_allowance(
        project_root,
        request.tool,
        subject,
        Timestamp::now().as_millis(),
    ) {
        Ok(Some(grant)) => Decided {
            decision: ProtectionDecision::allow_with(allowance_reason(danger)),
            allowance: Some(grant),
        },
        Ok(None) => unspent(assessment.decision.clone()),
        Err(_) => unspent(ProtectionDecision::block(allowance_unreadable_reason(
            danger,
        ))),
    }
}

/// The decision a harness is answered with, with the audit row written beside it.
///
/// Every decision the rule reached for a tool request is written down — allows
/// included, and that is a decision rather than an oversight. A row only for
/// what was held would leave the question a user actually asks (`what has SURE
/// been letting through here?`) answerable only by absence, and absence is also
/// what a decision SURE never reached looks like. One rule with no exceptions is
/// the one a reader can check.
///
/// **It is written after the decision, never as part of it.** The exit code a
/// launcher reads comes from the kind ([`crate::report`]), so a row this
/// function could not write must not become a status the harness acts on:
/// losing the record is bad, and turning a warn or an allow into a failure
/// because a bookkeeping write failed is a hook that fails closed on a machine
/// whose store is full. The kind is therefore copied through untouched and the
/// failure is *said*, in the reason the user reads, by
/// [`sure_core::protection_history::not_recorded_reason`]. The silence the brief
/// warns about — "the record is missing and nothing said so" — is the one
/// outcome this function cannot produce: every path that does not write the row
/// adds a sentence saying it did not.
///
/// A success adds nothing to the reason. The sentence a user reads is about the
/// request, and "SURE also wrote this down" on every one of a session's tool
/// calls would be a line of noise in a harness's transcript; `sure history` is
/// the surface for what was kept.
#[allow(clippy::too_many_arguments)]
fn record_the_decision(
    decided: Decided,
    danger: Option<Danger>,
    tool: &str,
    event_id: &EventId,
    event_write: &Result<FingerprintId, String>,
    project_root: &str,
    paths: &Paths,
) -> ProtectionDecision {
    let Decided {
        decision,
        allowance,
    } = decided;

    let Ok(fingerprint) = event_write else {
        return not_recorded(decision, NotRecorded::EventMissing);
    };

    let store = match Store::open(paths, Path::new(project_root)) {
        Ok(store) => store,
        // The same store the event went into, over the same paths: a failure
        // here is one an event write would have hit too, but it is reported
        // rather than assumed.
        Err(_) => return not_recorded(decision, NotRecorded::WriteFailed),
    };

    let record = DecisionRecord::of(event_id.clone(), &decision, danger, tool, allowance);
    match SessionEventStore::new(&store).persist_decision(&record, project_root, fingerprint) {
        Ok(Some(_)) => decision,
        // The event is not in the store, so there is nothing for the decision to
        // hang from and the row is not written — see `persist_decision`.
        Ok(None) => not_recorded(decision, NotRecorded::EventMissing),
        Err(_) => not_recorded(decision, NotRecorded::WriteFailed),
    }
}

/// The same decision, with a sentence about the audit row added to its reason.
///
/// The reason and nothing else: the kind is the answer, and it is returned
/// unchanged so that the exit code a launcher reads is the one the rule reached.
/// A decision with no reason of its own gets this sentence as its reason, which
/// is the only honest thing to put there — the alternative is a block that says
/// nothing at all.
fn not_recorded(decision: ProtectionDecision, why: NotRecorded) -> ProtectionDecision {
    let note = not_recorded_reason(why);
    let reason = match decision.reason {
        Some(reason) => format!("{reason}\n\n{note}"),
        None => note.to_owned(),
    };
    ProtectionDecision {
        decision: decision.decision,
        reason: Some(reason),
    }
}

fn persist_event_with_paths(
    ingested: &sure_core::harness_event::IngestedEvent,
    project_root: &str,
    event_id: &EventId,
    paths: &Paths,
) -> Result<sure_core::ids::FingerprintId, String> {
    let project_path = Path::new(project_root);
    let store = Store::open(paths, project_path).map_err(|e| e.to_string())?;
    let session_store = SessionEventStore::new(&store);

    let fingerprint = match project_fingerprint(project_path, &FingerprintOptions::default()) {
        Ok(fp) => fp,
        Err(e) => return Err(e.to_string()),
    };

    session_store
        .persist(ingested, project_root, &fingerprint.id, event_id)
        .map_err(|e| e.to_string())?;

    // 2026-10-20: an agent completion claim is also a Claim document, not only
    // an event. claim_checker reads Claim documents, so without this call the
    // event would be recorded and never checked (capture_agent_claim used to
    // have no production caller at all). Best-effort: a malformed claim is
    // ignored here — the event is already persisted and the hook's decision
    // must not change because of it.
    if ingested.envelope.event_type == sure_core::claim_capture::AGENT_CLAIM_EVENT_TYPE {
        let _ = sure_core::claim_capture::capture_agent_claim(
            ingested,
            &store,
            project_root,
            &fingerprint.id,
        );
    }

    // Best-effort full recording. Failure must not affect the hook decision.
    //
    // Both recording settings are read through one `Authority::load`, because
    // they are two questions about the same two files and reading them is the
    // same read: whether to record at all, and how long to keep it. A second
    // load would be a second chance for the two answers to come from different
    // reads of files that can change under a long-running process.
    //
    // The consent is `Authority::full_recording`, and not the project's own
    // `privacy.full_recording`, because recording more is not running more: the
    // setting is a *request*, and only the user's own file can grant it. A
    // repository the user merely opened would otherwise turn the recording of
    // their own machine's activity on — the sentence
    // `docs/architecture/CONFIG_REFERENCE.md` used to carry about this call
    // site. A project's `true` leaves a refused
    // `ProjectRequest::FullRecording` in `Authority::privileges`, which is where
    // a report reads what was asked for.
    //
    // The retention is arbitrated the way every other setting in
    // `sure_core::config` is: the user may name any duration, and a project may
    // only shorten it. A project asking to keep the data for longer is not
    // obeyed and does not raise the number — `Authority` records it as a refused
    // `ProjectRequest::ExtendedRetention`, and what is written is the shorter
    // period. "Recording more is not running more", and keeping it longer is not
    // either.
    //
    // The fallbacks are the *defaults*, and they are the only thing here that
    // resolves on failure. A configuration file that will not parse is a run
    // whose settings SURE does not know, and the safe direction for both of
    // these is the lesser one: falling back to the projection is the same as the
    // default, but falling back to whatever the project asked for would let an
    // unreadable user file become a longer retention than SURE's own, or a full
    // recording of a session the user never agreed to.
    let settings = Authority::load(project_path, &paths.user_config_file()).ok();
    let consent = match settings.as_ref() {
        Some(authority) if authority.full_recording() => FullRecordingConsent::Full,
        _ => FullRecordingConsent::ProjectionOnly,
    };
    let retention_days = settings
        .as_ref()
        .map_or(DEFAULT_FULL_RECORDING_RETENTION_DAYS, |authority| {
            authority.full_recording_retention_days().value
        });
    let _ = full_recording::persist_full_recording(
        &store,
        ingested,
        event_id,
        project_root,
        &fingerprint.id,
        consent,
        retention_days,
    );

    Ok(fingerprint.id)
}

/// The settings a decision is made under: execution mode, permissions, and the
/// protection mode in force.
///
/// The protection mode is the **arbitrated** one, through the same
/// [`Authority::load`] `sure check` reads its settings through and for the same
/// reason: a restriction resolved from one file would be a second rule, and a
/// report of what the project's file asked for rather than what the user's
/// settings permit would be a false statement about the user's own policy. A
/// project may ask for *more* protection than the user set and is named as the
/// reason; it may not ask for less. See `docs/architecture/CONFIG_AUTHORITY.md`.
///
/// A file that will not parse leaves SURE not knowing what the user set, and
/// the answer is the firmer one rather than the default: running under
/// `standard` while the user believes `strict` is in force is the failure the
/// authority layer exists to prevent. `strict` is the firmest mode this release
/// implements, and it is still an answer where stopping would be none — a hook
/// that failed outright would leave a Tier 1 harness to fall open.
///
/// The execution settings are arbitrated here too, and they are the sharper half
/// of the same rule. `execution.mode: host_confirmed` and
/// `execution.allow_network: true` in a project file are *requests*
/// (`Config::requested_privileges`), and a project file cannot grant itself one:
/// [`Authority::execution_mode`] answers the user's own mode and
/// [`Authority::permissions`] the permissions the two files add up to, so a
/// project that asks to run code on a machine whose user never allowed it is
/// refused in the same place every other request is refused. Before this, this
/// function built the permission set by hand out of the project's own file, and
/// a repository the user merely opened decided that their hooks ran its code.
///
/// The failure arm is the same shape as the protection arm and for the same
/// reason: an unreadable file is a run whose settings SURE does not know, and
/// the answer to "what may run" is then `inspect_only` — the mode SURE uses
/// unasked — rather than the project's ask.
fn load_execution_config(
    project_root: &str,
    paths: &Paths,
) -> (ExecutionMode, ExecutionPermissions, ProtectionMode) {
    let path = Path::new(project_root);
    match Authority::load(path, &paths.user_config_file()) {
        Ok(authority) => (
            authority.execution_mode(),
            authority.permissions(),
            authority.protection().value,
        ),
        Err(_) => (
            ExecutionMode::InspectOnly,
            ExecutionPermissions::inspect_only(),
            ProtectionMode::Strict,
        ),
    }
}

fn failed(what: &'static str, detail: String) -> Report {
    Report::Failed(Box::new(Failed {
        command: "hook",
        what,
        detail,
    }))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use sure_core::hook_protection::{
        Danger, ProtectionDecisionKind, allowance_reason, danger_reason,
    };
    use sure_testkit::repository_root;

    fn fixture(name: &str) -> String {
        let path = repository_root()
            .join("integrations")
            .join("cursor")
            .join("fixtures")
            .join(name);
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
    }

    fn claude_fixture(name: &str) -> String {
        let path = repository_root()
            .join("integrations")
            .join("claude-code")
            .join("fixtures")
            .join(name);
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
    }

    fn miqi_fixture(name: &str) -> String {
        let path = repository_root()
            .join("integrations")
            .join("miqi")
            .join("fixtures")
            .join(name);
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
    }

    /// Locations for an event this test ingests, so that the row it produces
    /// lands in a store this test named rather than in the store on the machine
    /// running the suite.
    ///
    /// `sure hook ingest` takes the same thing as `--store-dir`, on the command
    /// line; a unit test reaches it as the named roots of [`Paths::from_roots`].
    /// The events below are the fixtures under `integrations/`, so a row written
    /// to the real store would be an event from a fixture added to somebody's
    /// history, for as long as that machine lives.
    fn store_of_our_own(name: &str) -> Paths {
        let root = scratch_hook_dir(name);
        Paths::from_roots(root.join("data"), root.join("config"))
            .expect("the scratch locations are absolute")
    }

    /// A store of our own, and a project directory of our own beside it, for an
    /// event whose project root has to be a path SURE can use.
    ///
    /// The project is a directory of its own beside the roots rather than the
    /// scratch root itself, because a settings file the project could have
    /// written is refused before the event is recorded
    /// (`Paths::ensure_settings_outside`, P15-T025): with the config root inside
    /// the project, a test would assert about that refusal instead of about the
    /// decision. `codex_session_start_allows_without_a_decision` says the same
    /// of its own scratch tree, for the same reason.
    fn roots_and_project_of_our_own(name: &str) -> (Paths, String) {
        let tmp = scratch_hook_dir(name);
        let _ = std::fs::remove_dir_all(&tmp);
        let project = tmp.join("project");
        std::fs::create_dir_all(&project).expect("create the project directory");
        let paths = Paths::from_roots(tmp.join("data"), tmp.join("config")).expect("paths");
        (paths, project.to_string_lossy().into_owned())
    }

    /// One of the shipped events, with the project it names rewritten to a
    /// directory this test made.
    ///
    /// `integrations/cursor/fixtures/session-start.json` and
    /// `integrations/claude-code/fixtures/session-start.json` keep
    /// `"project_root": "C:\\Users\\dev\\sample-project"`, and they keep it:
    /// they are shipped example inputs a reader opens, and the example worth
    /// shipping in a Windows-primary repository is a Windows path.
    ///
    /// That value is not what these tests are about. An event's project root is
    /// read as a path — the settings question asks whether the file that decides
    /// what SURE may record and run is inside it, and the store keys the session
    /// by it — and `C:\Users\dev\sample-project` is absolute on Windows and
    /// relative everywhere else. A test that read the fixture verbatim therefore
    /// passed on Windows and was refused with `PathError::NotAbsolute` on macOS
    /// and Linux (`P15-T025` put the refusal on this path; `P15-T035` repaired
    /// the two tests). Rewriting this one field, in the shape the adapted codex
    /// test already used (`codex_event_at`), is what makes the fixture's own
    /// value stop being load-bearing: every other field, including the harness's
    /// spelling of the event, still comes from the file verbatim.
    fn session_event_at(text: &str, project_root: &str) -> String {
        let mut value: serde_json::Value = serde_json::from_str(text).expect("fixture is JSON");
        value["project_root"] = serde_json::Value::String(project_root.to_owned());
        value.to_string()
    }

    #[test]
    fn cursor_pre_tool_use_returns_decision() {
        let text = fixture("pre-tool-use.json");
        let report = run_ingest_with_paths(
            Some("cursor"),
            Some("pre-tool-use"),
            &text,
            &store_of_our_own("cursor-pre-tool-use"),
        );
        let decision = match &report {
            Report::HookDecision(d) => d,
            other => panic!("expected HookDecision, got {other:?}"),
        };
        // Default config is inspect_only, so Shell (ArbitraryCommand) is blocked.
        assert_eq!(
            decision.decision,
            sure_core::hook_protection::ProtectionDecisionKind::Block
        );
        assert!(decision.reason.is_some());
    }

    #[test]
    fn cursor_session_start_allows_without_decision() {
        let text = fixture("session-start.json");
        let (paths, project) = roots_and_project_of_our_own("cursor-session-start");
        let report = run_ingest_with_paths(
            Some("cursor"),
            Some("session-start"),
            &session_event_at(&text, &project),
            &paths,
        );
        let decision = match &report {
            Report::HookDecision(d) => d,
            other => panic!("expected HookDecision, got {other:?}"),
        };
        assert_eq!(
            decision.decision,
            sure_core::hook_protection::ProtectionDecisionKind::Allow
        );
    }

    #[test]
    fn miqi_agent_claim_is_captured_as_a_claim_document() {
        // 2026-10-20: before this wiring, agent.claim events were persisted as
        // events and never became Claim documents, so claim_checker always saw
        // an empty claim list.
        let text = miqi_fixture("agent-claim.json");
        let (paths, project) = roots_and_project_of_our_own("miqi-agent-claim");
        let report = run_ingest_with_paths(
            Some("miqi"),
            None,
            &session_event_at(&text, &project),
            &paths,
        );
        assert!(matches!(report, Report::HookDecision(_)), "{report:?}");

        let store = Store::open(&paths, Path::new(&project)).expect("store");
        let fingerprint =
            project_fingerprint(Path::new(&project), &FingerprintOptions::default())
                .expect("fingerprint");
        let claims =
            sure_core::claim_checker::check_claims_in_store(&store, &project, &fingerprint.id)
                .expect("claims");
        assert_eq!(claims.len(), 1, "the claim was not captured: {claims:?}");
        assert_eq!(claims[0].id, "claim-1");
        assert_eq!(claims[0].claim_text, "ran cargo test; 42 passed");
        assert_eq!(claims[0].claim_type, "test_ran");
        // No test.* event was recorded, so the claim cannot be confirmed — the
        // honest reading, not a pass.
        assert_eq!(
            claims[0].assessment,
            sure_core::evidence::ClaimAssessment::CannotConfirm
        );
    }

    #[test]
    fn missing_source_fails() {        // The four refusals below happen before SURE reaches a store at all —
        // there is nothing to read, nothing to normalise, nothing to record — so
        // they name none, which is also the honest statement that the store is
        // not what they are about.
        let report = run_ingest(None, Some("pre-tool-use"), "{}", Named::default());
        assert!(
            matches!(report, Report::Failed(_)),
            "expected Failed, got {report:?}"
        );
    }

    #[test]
    fn unsupported_source_fails() {
        let report = run_ingest(
            Some("unknown"),
            Some("pre-tool-use"),
            "{}",
            Named::default(),
        );
        assert!(
            matches!(report, Report::Failed(_)),
            "expected Failed, got {report:?}"
        );
    }

    #[test]
    fn invalid_json_fails() {
        let report = run_ingest(
            Some("cursor"),
            Some("pre-tool-use"),
            "{not json",
            Named::default(),
        );
        assert!(
            matches!(report, Report::Failed(_)),
            "expected Failed, got {report:?}"
        );
    }

    #[test]
    fn empty_stdin_fails() {
        let report = run_ingest(Some("cursor"), Some("pre-tool-use"), "", Named::default());
        assert!(
            matches!(report, Report::Failed(_)),
            "expected Failed, got {report:?}"
        );
    }

    #[test]
    fn claude_code_session_start_allows_without_decision() {
        let text = claude_fixture("session-start.json");
        let (paths, project) = roots_and_project_of_our_own("claude-code-session-start");
        let report = run_ingest_with_paths(
            Some("claude-code"),
            Some("session-start"),
            &session_event_at(&text, &project),
            &paths,
        );
        let decision = match &report {
            Report::HookDecision(d) => d,
            other => panic!("expected HookDecision, got {other:?}"),
        };
        assert_eq!(
            decision.decision,
            sure_core::hook_protection::ProtectionDecisionKind::Allow
        );
    }

    #[test]
    fn claude_code_pre_tool_use_uses_protection_decision() {
        let text = claude_fixture("pre-tool-use.json");
        let report = run_ingest_with_paths(
            Some("claude-code"),
            Some("pre-tool-use"),
            &text,
            &store_of_our_own("claude-code-pre-tool-use"),
        );
        let decision = match &report {
            Report::HookDecision(d) => d,
            other => panic!("expected HookDecision, got {other:?}"),
        };
        // Default config is InspectOnly; Bash maps to ArbitraryCommand, which is
        // denied in InspectOnly.
        assert_eq!(
            decision.decision,
            sure_core::hook_protection::ProtectionDecisionKind::Block
        );
        assert!(
            decision
                .reason
                .as_deref()
                .expect("blocked decision should have a reason")
                .contains("execution mode")
        );
    }

    #[test]
    fn claude_code_invalid_json_fails() {
        let report = run_ingest(
            Some("claude-code"),
            Some("pre-tool-use"),
            "{not json",
            Named::default(),
        );
        assert!(
            matches!(report, Report::Failed(_)),
            "expected Failed, got {report:?}"
        );
    }

    // --- full recording opt-in integration tests --------------------------------

    use sure_core::full_recording::full_recordings_for_project;
    use sure_protocol::event::EventEnvelope;

    fn scratch_hook_dir(name: &str) -> std::path::PathBuf {
        repository_root()
            .join("target")
            .join("tmp")
            .join(name)
            .join(format!("{}", std::process::id()))
    }

    fn make_claude_event(
        project_root: &std::path::Path,
    ) -> sure_core::harness_event::IngestedEvent {
        let envelope = EventEnvelope::new("claude-code", "tool.completed", "2026-09-18T12:00:00Z")
            .with_capability_tier(sure_core::capability::CapabilityTier::Observed)
            .with_session_id("test-session")
            .with_project_root(project_root.to_string_lossy().into_owned())
            .with_payload(serde_json::json!({"tool": "Bash", "output": "hello"}));

        ingest_event_str(&envelope.to_json().expect("envelope serialises")).expect("event ingests")
    }

    /// Persist one event into a project whose settings files the caller wrote,
    /// and read back the full recordings that came of it.
    ///
    /// The recordings and not the decision: a projection is written through this
    /// call whether or not a full recording was consented to, so "was the
    /// transcript kept" is a question only these rows answer. The row also
    /// carries the retention that was decided when it was written, which is the
    /// only way to see the number rather than the setting.
    fn recordings_after_one_event(
        name: &str,
        user_yaml: Option<&str>,
        project_yaml: &str,
    ) -> Vec<sure_core::full_recording::StoredFullRecording> {
        let tmp = scratch_hook_dir(name);
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).expect("create scratch");

        let project = tmp.join("project");
        std::fs::create_dir_all(&project).expect("create project");
        std::fs::write(project.join("sure.yaml"), project_yaml).expect("write config");

        let paths = Paths::from_roots(tmp.join("data"), tmp.join("config")).expect("paths");
        if let Some(user_yaml) = user_yaml {
            let user_config = paths.user_config_file();
            std::fs::create_dir_all(
                user_config
                    .parent()
                    .expect("the settings file lives in a directory"),
            )
            .expect("create settings directory");
            std::fs::write(&user_config, user_yaml).expect("write the user's own settings");
        }

        let ingested = make_claude_event(&project);
        let event_id = EventId::generate();
        let fingerprint =
            persist_event_with_paths(&ingested, &project.to_string_lossy(), &event_id, &paths)
                .expect("persist succeeds");

        let store = Store::open_at(&paths.store_file()).expect("store opens");
        let recordings = full_recordings_for_project(&store, &fingerprint, 10).expect("query");
        if !recordings.is_empty() {
            assert_eq!(recordings[0].event_type, "tool.completed");
            assert_eq!(recordings[0].source, "claude-code");
            assert_eq!(recordings[0].event_id, Some(event_id.as_str().to_owned()));
        }
        recordings
    }

    #[test]
    fn full_recording_is_stored_when_the_user_opted_in() {
        // The consent is the user's own, in the user's own file — which is what
        // `privacy.full_recording` being a *request* means
        // (`Authority::full_recording`).
        let recordings = recordings_after_one_event(
            "hook-full-recording-opted-in",
            Some("privacy:\n  full_recording: true\n"),
            "",
        );
        assert_eq!(
            recordings.len(),
            1,
            "the user asked for a full recording and none was kept"
        );
    }

    #[test]
    fn a_project_file_cannot_turn_on_full_recording() {
        // The other half of the same rule, and the half that used to be wrong:
        // this call site read `privacy.full_recording` out of the project's file
        // alone, so a repository the user merely opened turned the recording of
        // their own machine's activity on.
        let recordings = recordings_after_one_event(
            "hook-full-recording-project-only",
            None,
            "privacy:\n  full_recording: true\n",
        );
        assert!(
            recordings.is_empty(),
            "a project file turned full recording on"
        );
    }

    #[test]
    fn a_project_file_cannot_outlast_the_users_retention() {
        // Retention, the setting beside it, through the same call and the same
        // single `Authority::load`: the user's file names three days and the
        // project's names thirty, and the deadline on the row that was written
        // is the user's. A build that obeyed the project would write thirty and
        // a build that silently kept three while reporting thirty would pass a
        // test that only read `Authority::full_recording_retention_days`.
        let recordings = recordings_after_one_event(
            "hook-retention-arbitrated",
            Some("privacy:\n  full_recording: true\n  full_recording_retention_days: 3\n"),
            "privacy:\n  full_recording: true\n  full_recording_retention_days: 30\n",
        );
        assert_eq!(
            recordings.len(),
            1,
            "the user opted in and nothing was kept"
        );

        // 3 days = 259_200_000 ms, with a minute of tolerance for clock drift.
        let now = Timestamp::now().as_millis();
        let three_days = now + 259_200_000;
        assert!(
            recordings[0].retained_until_ms >= three_days - 60_000
                && recordings[0].retained_until_ms <= three_days + 60_000,
            "the recording is kept until {} — the project's thirty days, not the \
             user's three",
            recordings[0].retained_until_ms
        );
    }

    #[test]
    fn full_recording_is_not_stored_when_not_opted_in() {
        let tmp = scratch_hook_dir("hook-full-recording-opted-out");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).expect("create scratch");

        let project = tmp.join("project");
        std::fs::create_dir_all(&project).expect("create project");
        std::fs::write(
            project.join("sure.yaml"),
            "privacy:\n  full_recording: false\n",
        )
        .expect("write config");

        let data = tmp.join("data");
        let config = tmp.join("config");
        let paths = Paths::from_roots(data, config).expect("paths are valid");

        let ingested = make_claude_event(&project);
        let event_id = EventId::generate();

        let fingerprint =
            persist_event_with_paths(&ingested, &project.to_string_lossy(), &event_id, &paths)
                .expect("persist succeeds");

        let store = Store::open_at(&paths.store_file()).expect("store opens");
        let recordings = full_recordings_for_project(&store, &fingerprint, 10).expect("query");

        assert!(
            recordings.is_empty(),
            "no full recording should exist when opt-in is false"
        );
    }

    #[test]
    fn claude_code_check_repair_recheck_round_trip() {
        let tmp = scratch_hook_dir("claude-e2e-check-repair-recheck");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).expect("create scratch");

        let project = tmp.join("project");
        std::fs::create_dir_all(&project).expect("create project");

        let data = tmp.join("data");
        let config = tmp.join("config");
        let paths = Paths::from_roots(data, config).expect("paths are valid");

        let project_root = project.to_string_lossy().into_owned();
        let session_id = "claude-e2e-session";

        let session_start = serde_json::json!({
            "event": "SessionStart",
            "harness_session_id": session_id,
            "project_root": &project_root,
            "timestamp_utc": "2026-09-18T12:00:00Z",
            "source": "claude-code",
        })
        .to_string();

        let check_pre = serde_json::json!({
            "event": "PreToolUse",
            "harness_session_id": session_id,
            "project_root": &project_root,
            "tool": "Bash",
            "args": {"command": "npm test", "workdir": &project_root},
            "timestamp_utc": "2026-09-18T12:01:00Z",
            "source": "claude-code",
        })
        .to_string();

        let check_post = serde_json::json!({
            "event": "PostToolUse",
            "harness_session_id": session_id,
            "project_root": &project_root,
            "tool": "Bash",
            "args": {"command": "npm test", "workdir": &project_root},
            "error": {"exit_code": 1, "message": "tests failed"},
            "timestamp_utc": "2026-09-18T12:01:05Z",
            "source": "claude-code",
        })
        .to_string();

        let repair_pre = serde_json::json!({
            "event": "PreToolUse",
            "harness_session_id": session_id,
            "project_root": &project_root,
            "tool": "Edit",
            "args": {"old_string": "bad", "new_string": "good"},
            "path": "src/lib.rs",
            "timestamp_utc": "2026-09-18T12:02:00Z",
            "source": "claude-code",
        })
        .to_string();

        let repair_post = serde_json::json!({
            "event": "PostToolUse",
            "harness_session_id": session_id,
            "project_root": &project_root,
            "tool": "Edit",
            "args": {"old_string": "bad", "new_string": "good"},
            "path": "src/lib.rs",
            "result": {"ok": true},
            "timestamp_utc": "2026-09-18T12:02:05Z",
            "source": "claude-code",
        })
        .to_string();

        let recheck_pre = serde_json::json!({
            "event": "PreToolUse",
            "harness_session_id": session_id,
            "project_root": &project_root,
            "tool": "Bash",
            "args": {"command": "npm test", "workdir": &project_root},
            "timestamp_utc": "2026-09-18T12:03:00Z",
            "source": "claude-code",
        })
        .to_string();

        let recheck_post = serde_json::json!({
            "event": "PostToolUse",
            "harness_session_id": session_id,
            "project_root": &project_root,
            "tool": "Bash",
            "args": {"command": "npm test", "workdir": &project_root},
            "result": {"exit_code": 0, "stdout": "Tests: 5 passed, 5 total", "stderr": ""},
            "timestamp_utc": "2026-09-18T12:03:05Z",
            "source": "claude-code",
        })
        .to_string();

        let stop = serde_json::json!({
            "event": "Stop",
            "harness_session_id": session_id,
            "project_root": &project_root,
            "timestamp_utc": "2026-09-18T12:04:00Z",
            "source": "claude-code",
        })
        .to_string();

        let events = [
            ("session-start", session_start),
            ("pre-tool-use", check_pre),
            ("post-tool-use", check_post),
            ("pre-tool-use", repair_pre),
            ("post-tool-use", repair_post),
            ("pre-tool-use", recheck_pre),
            ("post-tool-use", recheck_post),
            ("stop", stop),
        ];

        for (kind, json) in &events {
            let report = run_ingest_with_paths(Some("claude-code"), Some(kind), json, &paths);
            if *kind == "pre-tool-use" {
                let decision = match &report {
                    Report::HookDecision(d) => d,
                    other => panic!("expected HookDecision for {kind}, got {other:?}"),
                };
                assert_eq!(
                    decision.decision,
                    sure_core::hook_protection::ProtectionDecisionKind::Block,
                    "pre-tool-use should be blocked in InspectOnly mode"
                );
                assert!(
                    decision.reason.is_some(),
                    "blocked decision should have a reason"
                );
            } else {
                let decision = match &report {
                    Report::HookDecision(d) => d,
                    other => panic!("expected HookDecision for {kind}, got {other:?}"),
                };
                assert_eq!(
                    decision.decision,
                    sure_core::hook_protection::ProtectionDecisionKind::Allow,
                    "non-pre-tool-use should be allowed"
                );
            }
        }

        // Open the store and verify persisted events.
        let store = Store::open(&paths, &project).expect("store opens");
        let session_store = SessionEventStore::new(&store);

        let sessions = session_store
            .sessions_past_retention(i64::MAX)
            .expect("query sessions");
        assert_eq!(sessions.len(), 1, "exactly one session should exist");
        assert_eq!(
            sessions[0].harness_session_id.as_deref(),
            Some(session_id),
            "session id should match"
        );

        let stored_events = session_store
            .events_for_session(sessions[0].row_id)
            .expect("query events");
        assert_eq!(stored_events.len(), 8, "all 8 events should be stored");

        let expected_types = [
            "session.started",
            "tool.requested",
            "tool.completed",
            "tool.requested",
            "tool.completed",
            "tool.requested",
            "tool.completed",
            "session.stopped",
        ];

        // events_for_session returns newest first, so reverse to match insertion order.
        let mut ordered_events = stored_events;
        ordered_events.reverse();

        for (i, expected) in expected_types.iter().enumerate() {
            assert_eq!(
                ordered_events[i].event_type, *expected,
                "event {i} should have type {expected}"
            );
        }

        // Verify no full recordings were stored (default is off).
        let fingerprint =
            project_fingerprint(&project, &FingerprintOptions::default()).expect("fingerprint");
        let recordings =
            full_recordings_for_project(&store, &fingerprint.id, 10).expect("query recordings");
        assert!(
            recordings.is_empty(),
            "no full recording should exist when opt-in is false (default)"
        );
    }

    #[test]
    fn cursor_check_repair_recheck_round_trip() {
        let tmp = scratch_hook_dir("cursor-e2e-check-repair-recheck");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).expect("create scratch");

        let project = tmp.join("project");
        std::fs::create_dir_all(&project).expect("create project");

        let data = tmp.join("data");
        let config = tmp.join("config");
        let paths = Paths::from_roots(data, config).expect("paths are valid");

        let project_root = project.to_string_lossy().into_owned();
        let session_id = "cursor-e2e-session";

        let session_start = serde_json::json!({
            "event": "sessionStart",
            "harness_session_id": session_id,
            "project_root": &project_root,
            "timestamp_utc": "2026-09-18T12:00:00Z",
            "source": "cursor",
        })
        .to_string();

        // Read is allowed in InspectOnly.
        let read_pre = serde_json::json!({
            "event": "preToolUse",
            "harness_session_id": session_id,
            "project_root": &project_root,
            "tool": "Read",
            "args": {"path": "src/lib.rs"},
            "timestamp_utc": "2026-09-18T12:00:30Z",
            "source": "cursor",
        })
        .to_string();

        let check_pre = serde_json::json!({
            "event": "preToolUse",
            "harness_session_id": session_id,
            "project_root": &project_root,
            "tool": "Shell",
            "args": {"command": "npm test", "workdir": &project_root},
            "timestamp_utc": "2026-09-18T12:01:00Z",
            "source": "cursor",
        })
        .to_string();

        let check_post = serde_json::json!({
            "event": "postToolUse",
            "harness_session_id": session_id,
            "project_root": &project_root,
            "tool": "Shell",
            "args": {"command": "npm test", "workdir": &project_root},
            "error": {"exit_code": 1, "message": "tests failed"},
            "timestamp_utc": "2026-09-18T12:01:05Z",
            "source": "cursor",
        })
        .to_string();

        let repair_pre = serde_json::json!({
            "event": "preToolUse",
            "harness_session_id": session_id,
            "project_root": &project_root,
            "tool": "Write",
            "args": {"content": "good"},
            "path": "src/lib.rs",
            "timestamp_utc": "2026-09-18T12:02:00Z",
            "source": "cursor",
        })
        .to_string();

        let repair_post = serde_json::json!({
            "event": "postToolUse",
            "harness_session_id": session_id,
            "project_root": &project_root,
            "tool": "Write",
            "args": {"content": "good"},
            "path": "src/lib.rs",
            "result": {"ok": true},
            "timestamp_utc": "2026-09-18T12:02:05Z",
            "source": "cursor",
        })
        .to_string();

        let recheck_pre = serde_json::json!({
            "event": "preToolUse",
            "harness_session_id": session_id,
            "project_root": &project_root,
            "tool": "Shell",
            "args": {"command": "npm test", "workdir": &project_root},
            "timestamp_utc": "2026-09-18T12:03:00Z",
            "source": "cursor",
        })
        .to_string();

        let recheck_post = serde_json::json!({
            "event": "postToolUse",
            "harness_session_id": session_id,
            "project_root": &project_root,
            "tool": "Shell",
            "args": {"command": "npm test", "workdir": &project_root},
            "result": {"exit_code": 0, "stdout": "Tests: 5 passed, 5 total", "stderr": ""},
            "timestamp_utc": "2026-09-18T12:03:05Z",
            "source": "cursor",
        })
        .to_string();

        let stop = serde_json::json!({
            "event": "stop",
            "harness_session_id": session_id,
            "project_root": &project_root,
            "timestamp_utc": "2026-09-18T12:04:00Z",
            "source": "cursor",
        })
        .to_string();

        let events = [
            ("session-start", session_start, None),
            (
                "pre-tool-use",
                read_pre,
                Some(ProtectionDecisionKind::Allow),
            ),
            (
                "pre-tool-use",
                check_pre,
                Some(ProtectionDecisionKind::Block),
            ),
            ("post-tool-use", check_post, None),
            (
                "pre-tool-use",
                repair_pre,
                Some(ProtectionDecisionKind::Block),
            ),
            ("post-tool-use", repair_post, None),
            (
                "pre-tool-use",
                recheck_pre,
                Some(ProtectionDecisionKind::Block),
            ),
            ("post-tool-use", recheck_post, None),
            ("stop", stop, None),
        ];

        for (kind, json, expected) in &events {
            let report = run_ingest_with_paths(Some("cursor"), Some(kind), json, &paths);
            let decision = match &report {
                Report::HookDecision(d) => d,
                other => panic!("expected HookDecision for {kind}, got {other:?}"),
            };

            if let Some(expected_kind) = expected {
                assert_eq!(
                    decision.decision,
                    *expected_kind,
                    "{kind} should be {:?} in InspectOnly mode",
                    expected_kind.as_str()
                );
                if *expected_kind == ProtectionDecisionKind::Block {
                    assert!(
                        decision.reason.is_some(),
                        "blocked decision should have a reason"
                    );
                }
            } else {
                assert_eq!(
                    decision.decision,
                    ProtectionDecisionKind::Allow,
                    "non-pre-tool-use should be allowed"
                );
            }
        }

        // Open the store and verify persisted events.
        let store = Store::open(&paths, &project).expect("store opens");
        let session_store = SessionEventStore::new(&store);

        let sessions = session_store
            .sessions_past_retention(i64::MAX)
            .expect("query sessions");
        assert_eq!(sessions.len(), 1, "exactly one session should exist");
        assert_eq!(
            sessions[0].harness_session_id.as_deref(),
            Some(session_id),
            "session id should match"
        );

        let stored_events = session_store
            .events_for_session(sessions[0].row_id)
            .expect("query events");
        assert_eq!(stored_events.len(), 9, "all 9 events should be stored");

        let expected_types = [
            "session.started",
            "tool.requested",
            "tool.requested",
            "tool.completed",
            "tool.requested",
            "tool.completed",
            "tool.requested",
            "tool.completed",
            "session.stopped",
        ];

        // events_for_session returns newest first, so reverse to match insertion order.
        let mut ordered_events = stored_events;
        ordered_events.reverse();

        for (i, expected) in expected_types.iter().enumerate() {
            assert_eq!(
                ordered_events[i].event_type, *expected,
                "event {i} should have type {expected}"
            );
        }

        // Verify no full recordings were stored (default is off).
        let fingerprint =
            project_fingerprint(&project, &FingerprintOptions::default()).expect("fingerprint");
        let recordings =
            full_recordings_for_project(&store, &fingerprint.id, 10).expect("query recordings");
        assert!(
            recordings.is_empty(),
            "no full recording should exist when opt-in is false (default)"
        );
    }

    // --- codex --------------------------------------------------------------
    //
    // Every test here runs through `run_ingest_with_paths` with a scratch
    // `Paths`, like the two round trips above, so none of them open or write
    // the machine's real store. That is no longer the only way to keep them off
    // it: `sure hook ingest --store-dir DIR` names the store on the command
    // line, which is what `tests/cli_contract.rs` drives against a real process
    // and a store it names. Both are the same mechanism from two sides, and the
    // process that has none of it — a hook a harness starts with no argument —
    // gets the platform's own location, which is where a user's history belongs.

    fn codex_fixture(name: &str) -> String {
        let path = repository_root()
            .join("integrations")
            .join("codex")
            .join("fixtures")
            .join(name);
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
    }

    /// A Codex fixture with its `cwd` pointed at a real scratch directory.
    ///
    /// The payload's `cwd` becomes the event's project root, and the store keys
    /// a session by project, so a fixture pointed at a path that does not exist
    /// would persist nothing and prove nothing. The field names still come from
    /// the fixture; only the value of `cwd` is replaced.
    fn codex_event_at(name: &str, project_root: &str) -> String {
        let mut value: serde_json::Value =
            serde_json::from_str(&codex_fixture(name)).expect("fixture is JSON");
        value["cwd"] = serde_json::Value::String(project_root.to_owned());
        value.to_string()
    }

    #[test]
    fn codex_session_start_allows_without_a_decision() {
        let tmp = scratch_hook_dir("codex-session-start");
        let _ = std::fs::remove_dir_all(&tmp);
        // The project is a directory of its own beside the roots rather than the
        // scratch root itself, because a settings file the project could have
        // written is refused before the event is recorded
        // (`Paths::ensure_settings_outside`, P15-T025) — with the config root
        // inside the project, this test would assert about that refusal instead
        // of about the decision.
        let project = tmp.join("project");
        std::fs::create_dir_all(&project).expect("create project");
        let paths = Paths::from_roots(tmp.join("data"), tmp.join("config")).expect("paths");

        let report = run_ingest_with_paths(
            Some("codex"),
            None,
            &codex_event_at("session-start.json", &project.to_string_lossy()),
            &paths,
        );
        let decision = match &report {
            Report::HookDecision(d) => d,
            other => panic!("expected HookDecision, got {other:?}"),
        };
        assert_eq!(decision.decision, ProtectionDecisionKind::Allow);
    }

    #[test]
    fn codex_pre_tool_use_gets_a_protection_decision() {
        let tmp = scratch_hook_dir("codex-pre-tool-use");
        let _ = std::fs::remove_dir_all(&tmp);
        // Beside the roots, not the scratch root itself: see
        // `codex_session_start_allows_without_a_decision`.
        let project = tmp.join("project");
        std::fs::create_dir_all(&project).expect("create project");
        let paths = Paths::from_roots(tmp.join("data"), tmp.join("config")).expect("paths");

        // Codex's documented shell tool name is `Bash`, which the shared
        // classifier already knows. The scratch project has no `sure.yaml`, so
        // the mode is the safest one and a shell command is blocked.
        let report = run_ingest_with_paths(
            Some("codex"),
            None,
            &codex_event_at("pre-tool-use.json", &project.to_string_lossy()),
            &paths,
        );
        let decision = match &report {
            Report::HookDecision(d) => d,
            other => panic!("expected HookDecision, got {other:?}"),
        };
        assert_eq!(decision.decision, ProtectionDecisionKind::Block);
        assert!(decision.reason.is_some());
    }

    #[test]
    fn codex_tool_name_outside_the_classifier_vocabulary_fails_closed() {
        let tmp = scratch_hook_dir("codex-unknown-tool");
        let _ = std::fs::remove_dir_all(&tmp);
        // Beside the roots, not the scratch root itself: see
        // `codex_session_start_allows_without_a_decision`.
        let project = tmp.join("project");
        std::fs::create_dir_all(&project).expect("create project");
        let paths = Paths::from_roots(tmp.join("data"), tmp.join("config")).expect("paths");

        // A Codex local function tool, not one of the names the classifier was
        // written for. It must not read as "nothing to object to".
        let mut value: serde_json::Value =
            serde_json::from_str(&codex_fixture("pre-tool-use.json")).expect("fixture is JSON");
        value["cwd"] = serde_json::Value::String(project.to_string_lossy().into_owned());
        value["tool_name"] = serde_json::Value::String("update_plan".to_owned());

        let report = run_ingest_with_paths(Some("codex"), None, &value.to_string(), &paths);
        let decision = match &report {
            Report::HookDecision(d) => d,
            other => panic!("expected HookDecision, got {other:?}"),
        };
        assert_eq!(decision.decision, ProtectionDecisionKind::Block);
    }

    #[test]
    fn codex_stop_is_refused_and_writes_nothing() {
        let tmp = scratch_hook_dir("codex-stop-refused");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).expect("create scratch");
        let project = tmp.join("project");
        std::fs::create_dir_all(&project).expect("create project");
        let paths = Paths::from_roots(tmp.join("data"), tmp.join("config")).expect("paths");
        let project_root = project.to_string_lossy().into_owned();

        // `Stop` ends a turn, not a session, and SURE has no turn-end event
        // type. The refusal has to be visible and it has to leave no row
        // behind: an event SURE cannot mean must not become evidence.
        let refused = run_ingest_with_paths(
            Some("codex"),
            None,
            &codex_event_at("stop-not-mapped.json", &project_root),
            &paths,
        );
        match &refused {
            Report::Failed(failure) => {
                assert!(
                    failure.detail.contains("turn"),
                    "the refusal must name why: {}",
                    failure.detail
                );
                assert!(
                    failure.detail.contains("Nothing was recorded"),
                    "the refusal must say nothing was recorded: {}",
                    failure.detail
                );
            }
            other => panic!("expected Failed for Stop, got {other:?}"),
        }

        // One mapped event, then read the store back: exactly one row, and it
        // is the mapped one.
        let accepted = run_ingest_with_paths(
            Some("codex"),
            None,
            &codex_event_at("session-end.json", &project_root),
            &paths,
        );
        assert!(
            matches!(accepted, Report::HookDecision(_)),
            "expected the mapped event to ingest, got {accepted:?}"
        );

        let store = Store::open(&paths, &project).expect("store opens");
        let session_store = SessionEventStore::new(&store);
        let sessions = session_store
            .sessions_past_retention(i64::MAX)
            .expect("query sessions");
        assert_eq!(sessions.len(), 1, "one session should exist");
        let stored = session_store
            .events_for_session(sessions[0].row_id)
            .expect("query events");
        assert_eq!(stored.len(), 1, "Stop must not have left a row behind");
        assert_eq!(stored[0].event_type, "session.stopped");
    }

    #[test]
    fn codex_session_events_round_trip_into_one_session() {
        let tmp = scratch_hook_dir("codex-e2e-round-trip");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).expect("create scratch");
        let project = tmp.join("project");
        std::fs::create_dir_all(&project).expect("create project");
        let paths = Paths::from_roots(tmp.join("data"), tmp.join("config")).expect("paths");
        let project_root = project.to_string_lossy().into_owned();

        // No event-kind argument: this is what `integrations/codex/hooks/hooks.json`
        // invokes, because the payload carries `hook_event_name` itself.
        for name in [
            "session-start.json",
            "pre-tool-use.json",
            "post-tool-use.json",
            "session-end.json",
        ] {
            let report = run_ingest_with_paths(
                Some("codex"),
                None,
                &codex_event_at(name, &project_root),
                &paths,
            );
            assert!(
                matches!(report, Report::HookDecision(_)),
                "{name} should have ingested, got {report:?}"
            );
        }

        let store = Store::open(&paths, &project).expect("store opens");
        let session_store = SessionEventStore::new(&store);
        let sessions = session_store
            .sessions_past_retention(i64::MAX)
            .expect("query sessions");
        assert_eq!(
            sessions.len(),
            1,
            "all four events share one Codex session id, so they are one session"
        );
        assert_eq!(
            sessions[0].harness_session_id.as_deref(),
            Some("codex-session-001")
        );

        let mut stored = session_store
            .events_for_session(sessions[0].row_id)
            .expect("query events");
        assert_eq!(stored.len(), 4, "all four mapped events should be stored");
        stored.reverse();
        let types: Vec<&str> = stored.iter().map(|e| e.event_type.as_str()).collect();
        assert_eq!(
            types,
            vec![
                "session.started",
                "tool.requested",
                "tool.completed",
                "session.stopped"
            ]
        );
    }

    #[test]
    fn only_a_leading_byte_order_mark_is_not_part_of_the_event() {
        assert_eq!(without_byte_order_mark("\u{feff}{}"), "{}");
        assert_eq!(without_byte_order_mark("{}"), "{}");
        // One inside the payload belongs to the payload, and is left alone.
        assert_eq!(
            without_byte_order_mark("{\"text\":\"\u{feff}\"}"),
            "{\"text\":\"\u{feff}\"}"
        );
    }

    #[test]
    fn codex_payload_behind_a_byte_order_mark_still_ingests() {
        let tmp = scratch_hook_dir("codex-byte-order-mark");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).expect("create scratch");
        let project = tmp.join("project");
        std::fs::create_dir_all(&project).expect("create project");
        let paths = Paths::from_roots(tmp.join("data"), tmp.join("config")).expect("paths");

        // What Windows PowerShell 5.1 pipes in front of the event, measured on
        // 2026-09-18: a UTF-8 byte-order mark, then the payload.
        let marked = format!(
            "\u{feff}{}",
            codex_event_at("session-start.json", &project.to_string_lossy())
        );

        // Handed over as-is it is not JSON, which is the failure `run()` exists
        // to avoid.
        match run_ingest_with_paths(Some("codex"), None, &marked, &paths) {
            Report::Failed(failure) => assert!(
                failure.detail.contains("not valid JSON"),
                "a byte-order mark should be the reason the payload is refused: {}",
                failure.detail
            ),
            other => panic!("expected the marked payload to be refused, got {other:?}"),
        }

        // Handed over the way `run()` hands it over, it ingests, and the store
        // holds the one event.
        let report = run_ingest_with_paths(
            Some("codex"),
            None,
            without_byte_order_mark(&marked),
            &paths,
        );
        assert!(
            matches!(report, Report::HookDecision(_)),
            "the payload behind the mark should ingest, got {report:?}"
        );
        let store = Store::open(&paths, &project).expect("store opens");
        let session_store = SessionEventStore::new(&store);
        let sessions = session_store
            .sessions_past_retention(i64::MAX)
            .expect("query sessions");
        assert_eq!(sessions.len(), 1, "the marked payload is one session");
        let stored = session_store
            .events_for_session(sessions[0].row_id)
            .expect("query events");
        assert_eq!(stored.len(), 1, "and one event");
    }

    // --- the protection mode, through the command a harness runs ---------------

    /// A project with its own `sure.yaml`, and locations of SURE's own that this
    /// test may write to.
    ///
    /// The user's layer is the point of the second return value: on this machine
    /// it is `%APPDATA%\SURE\sure.yaml`, which belongs to the person running the
    /// suite and is not a test's to write. [`Paths::from_roots`] puts it inside
    /// the scratch directory instead, so the arbitration below can be tested
    /// without touching, or depending on, anybody's real settings.
    fn a_project_with(name: &str, project_yaml: &str) -> (std::path::PathBuf, Paths) {
        let tmp = scratch_hook_dir(name);
        let _ = std::fs::remove_dir_all(&tmp);
        let project = tmp.join("project");
        std::fs::create_dir_all(&project).expect("create project");
        std::fs::write(project.join("sure.yaml"), project_yaml).expect("write project config");
        let paths = Paths::from_roots(tmp.join("data"), tmp.join("config")).expect("paths");
        (project, paths)
    }

    /// Name host execution in the **user's** own settings file, inside the
    /// scratch directory the test owns.
    ///
    /// This is where `execution.mode` comes from and nowhere else. A project's
    /// `sure.yaml` naming `host_confirmed` is a *request*
    /// (`Config::requested_privileges`) and is refused like every other request
    /// — `Authority::execution_mode` says *"a project file cannot move it in
    /// either direction"* — so a test that wrote the mode into the project's file
    /// would be testing nothing about the mode:
    /// `a_project_asking_to_run_its_own_code_is_refused` is that test, and it is
    /// the one that keeps this helper honest.
    ///
    /// The file goes to `paths.user_config_file()`, which `Paths::from_roots`
    /// has put inside the scratch directory: on a real machine it is
    /// `%APPDATA%\SURE\sure.yaml`, which belongs to the person running the suite.
    fn a_user_who_allowed_project_code(paths: &Paths) {
        let user_config = paths.user_config_file();
        std::fs::create_dir_all(
            user_config
                .parent()
                .expect("the settings file lives in a directory"),
        )
        .expect("create settings directory");
        std::fs::write(&user_config, "execution:\n  mode: host_confirmed\n")
            .expect("write the user's own settings");
    }

    /// A Cursor `preToolUse` event naming one tool and, when it names one, one
    /// path: the request the rule is asked about, in the shape the harness sends.
    fn cursor_request_at(project: &std::path::Path, tool: &str, path: Option<&str>) -> String {
        serde_json::json!({
            "event": "preToolUse",
            "harness_session_id": "p13t004",
            "project_root": project.to_string_lossy(),
            "tool": tool,
            "path": path,
            "timestamp_utc": "2026-09-19T09:00:00Z",
            "source": "cursor",
        })
        .to_string()
    }

    /// Run `sure hook ingest` for one request and hand back the action SURE
    /// would take and the sentence it gives for it.
    fn run_cursor_request(
        project: &std::path::Path,
        paths: &Paths,
        tool: &str,
        path: Option<&str>,
    ) -> (ProtectionDecisionKind, String) {
        let text = cursor_request_at(project, tool, path);
        let report = run_ingest_with_paths(Some("cursor"), Some("pre-tool-use"), &text, paths);
        match &report {
            Report::HookDecision(decision) => (
                decision.decision,
                decision
                    .reason
                    .clone()
                    .expect("the rule answers a request with an action and a reason"),
            ),
            other => panic!("expected HookDecision, got {other:?}"),
        }
    }

    #[test]
    fn the_same_read_is_allowed_under_standard_and_held_under_strict() {
        // A read of a secret is the operation from `PROTECTION_MODE.md`'s own
        // list — "secret/config areas" — that reaches the rule through the
        // command a harness actually runs, and it is the pair the criterion is
        // about: same request, same execution mode, two protection modes.
        let (standard_project, standard_paths) =
            a_project_with("p13t004-standard-read", "protection:\n  mode: standard\n");
        let (action, reason) =
            run_cursor_request(&standard_project, &standard_paths, "Read", Some(".env"));
        assert_eq!(action, ProtectionDecisionKind::Allow);
        assert!(
            !reason.is_empty(),
            "an allow the rule reached says what it looked at"
        );

        let (strict_project, strict_paths) =
            a_project_with("p13t004-strict-read", "protection:\n  mode: strict\n");
        let (action, reason) =
            run_cursor_request(&strict_project, &strict_paths, "Read", Some(".env"));
        assert_eq!(action, ProtectionDecisionKind::Block);
        assert!(
            reason.contains("credentials"),
            "the reason says what the file is, not which setting asked: {reason}"
        );
        assert!(
            !reason.contains("protection.mode"),
            "the reason is about the user's work, not about policy jargon: {reason}"
        );
    }

    #[test]
    fn strict_holds_only_what_the_document_names() {
        // The other half of the pair: strict must not invent a rule. An ordinary
        // read is allowed under both modes, so the mode's difference is the
        // categories the document names and nothing else.
        let (project, paths) =
            a_project_with("p13t004-strict-ordinary", "protection:\n  mode: strict\n");
        let (action, _) = run_cursor_request(&project, &paths, "Read", Some("src/lib.rs"));
        assert_eq!(action, ProtectionDecisionKind::Allow);
    }

    #[test]
    fn the_default_mode_is_standard_and_the_project_file_reaches_the_rule() {
        // No `sure.yaml` at all: the documented default is standard, and a read
        // of a secret is allowed under it. That is what makes the strict case
        // above attributable to the file rather than to the absence of one.
        let tmp = scratch_hook_dir("p13t004-no-project-config");
        let _ = std::fs::remove_dir_all(&tmp);
        let project = tmp.join("project");
        std::fs::create_dir_all(&project).expect("create project");
        let paths = Paths::from_roots(tmp.join("data"), tmp.join("config")).expect("paths");

        let (action, _) = run_cursor_request(&project, &paths, "Read", Some(".env"));
        assert_eq!(action, ProtectionDecisionKind::Allow);
    }

    #[test]
    fn a_project_file_cannot_lower_the_mode_the_user_set() {
        // The user's own settings file says strict; the project's file says
        // standard. Restrictions take the stricter of the two layers
        // (`config/authority.rs`), so the answer is the user's, and the reason
        // must be the one the user's policy produces.
        let (project, paths) =
            a_project_with("p13t004-arbitrated", "protection:\n  mode: standard\n");
        let user_config = paths.user_config_file();
        std::fs::create_dir_all(
            user_config
                .parent()
                .expect("the settings file lives in a directory"),
        )
        .expect("create settings directory");
        std::fs::write(&user_config, "protection:\n  mode: strict\n")
            .expect("write the user's own settings");

        let (action, reason) = run_cursor_request(&project, &paths, "Read", Some(".env"));
        assert_eq!(
            action,
            ProtectionDecisionKind::Block,
            "a project file cannot loosen what the user set"
        );
        assert!(reason.contains("credentials"), "{reason}");

        // And the project's own `standard` is what governs once the user's layer
        // is gone — so the block above is the user's line, not a project file
        // that was ignored.
        std::fs::remove_file(&user_config).expect("remove the user's settings");
        let (action, _) = run_cursor_request(&project, &paths, "Read", Some(".env"));
        assert_eq!(action, ProtectionDecisionKind::Allow);
    }

    #[test]
    fn a_refused_protection_mode_falls_to_the_firmest_one_this_build_has() {
        // `custom` is refused by the settings reader — this release has no rule
        // editor — so the hook never decides under it. What it does instead is
        // the firmer implemented mode rather than the default: a settings file
        // SURE cannot read must not leave the user with less protection than
        // they asked for. The assertion below is the one that tells those two
        // apart, because `standard` would allow this read.
        let (project, paths) = a_project_with("p13t004-custom", "protection:\n  mode: custom\n");
        let (action, reason) = run_cursor_request(&project, &paths, "Read", Some(".env"));
        assert_eq!(
            action,
            ProtectionDecisionKind::Block,
            "a refused mode may not resolve to the default"
        );
        assert!(reason.contains("credentials"), "{reason}");
    }

    // --- the execution settings, arbitrated before a hook decides --------------
    //
    // `execution.mode` and the permission set are the user's to grant and the
    // project's to ask for (`Authority::execution_mode`, `Authority::permissions`),
    // and the pair is computed in one place so that a decision cannot be taken
    // under one file's mode and another file's permissions. These two tests are
    // the same request answered both ways, which is what makes the first
    // attributable to the configuration rather than to a rule that refuses
    // everything.

    #[test]
    fn a_project_asking_to_run_its_own_code_is_refused() {
        // The defect this task exists for, at the boundary a harness reaches: a
        // project file naming `host_confirmed`, `allow_dependency_install` and
        // `allow_network` asks for three permissions and gets none of them. The
        // answer is the execution-mode refusal, not the danger hold — a
        // repository cannot be run on a machine whose user never agreed to run
        // anything by naming a mode in `sure.yaml`.
        let (project, paths) = a_project_with(
            "p13t009-project-only",
            "execution:\n  mode: host_confirmed\n  allow_dependency_install: true\n  \
             allow_network: true\n",
        );

        let (action, reason) = run_shell_request(&project, &paths, "Shell", "rm -rf build/");
        assert_eq!(action, ProtectionDecisionKind::Block);
        assert!(
            reason.contains("does not permit this action"),
            "the ask was not answered as a refusal: {reason}"
        );
        assert!(
            !reason.contains("names a whole location"),
            "the mode refused, and the reason names a danger SURE only reads off a \
             consent hold: {reason}"
        );

        // And an allowance is not a way round it. The writer refuses to record
        // one at all — the words are the user's own, but this project's settings
        // leave nothing a grant could be spent on — and the very next identical
        // request is still refused, out of a store with no grant in it. This is
        // the shape of the failure the fix closes: before it, this request needed
        // only a one-time allowance to run the project's code.
        //
        // The premise `P13-T010` inverted sits in the line below, and it is
        // inverted rather than deleted. Until this task the writer recorded the
        // grant and this test asserted it was still there afterwards
        // (`outstanding_grants(..).len() == 1`): a row nothing could ever spend,
        // and — measured, second dispatch — a row no command in this build
        // would even show a user, because `sure history` lists sessions and has
        // no allowance surface at all (`crate::cli`'s `HistoryAction`). The
        // property the assertion was there for is unchanged and is now asserted
        // against the store directly — nothing was spent on a request the mode
        // had already refused — and it is the stronger form, because a grant
        // that was never written cannot be spent by anything.
        let refused = run_allow_once_with_paths(
            "Shell",
            "rm -rf build/",
            &project.to_string_lossy(),
            allowance::DEFAULT_MINUTES,
            &paths,
        );
        match refused {
            Report::Failed(failure) => {
                assert!(
                    failure
                        .detail
                        .contains("`execution.mode` is `inspect_only`"),
                    "the refusal does not name the setting a user would change: {}",
                    failure.detail
                );
            }
            other => panic!("a grant nothing here could spend was answered with {other:?}"),
        }
        assert!(
            outstanding_grants(&paths, &project).is_empty(),
            "the writer refused a grant and wrote a row anyway"
        );

        let (action, reason) = run_shell_request(&project, &paths, "Shell", "rm -rf build/");
        assert_eq!(
            action,
            ProtectionDecisionKind::Block,
            "a recorded allowance let the project's code run under a mode the user \
             never granted"
        );
        assert!(
            reason.contains("does not permit this action"),
            "the refusal changed shape after a grant for it was refused: {reason}"
        );
        assert!(
            outstanding_grants(&paths, &project).is_empty(),
            "an allowance was spent on a request the mode had already refused"
        );
    }

    #[test]
    fn a_user_who_allowed_project_code_is_what_puts_the_hook_in_host_confirmed_mode() {
        // The same project, the same request, and the user's own file naming the
        // mode. Now the answer is the consent hold with the danger named — which
        // is what makes the refusal above a statement about the configuration
        // rather than about a rule that holds every shell request.
        let (project, paths) = a_project_with(
            "p13t009-user-granted",
            "execution:\n  mode: host_confirmed\n  allow_dependency_install: true\n  \
             allow_network: true\n",
        );
        a_user_who_allowed_project_code(&paths);

        let (action, reason) = run_shell_request(&project, &paths, "Shell", "rm -rf build/");
        assert_eq!(action, ProtectionDecisionKind::Block);
        assert!(
            reason.contains("names a whole location"),
            "the user allowed project code and the request was refused for the mode: \
             {reason}"
        );

        allow_once(&paths, &project, "Shell", "rm -rf build/");
        let (action, _) = run_shell_request(&project, &paths, "Shell", "rm -rf build/");
        assert_eq!(
            action,
            ProtectionDecisionKind::Allow,
            "the user granted the mode and the allowance was not honoured"
        );
    }

    // --- the three dangers, and the one-time allowance that answers one -------
    //
    // Everything here runs through `run_ingest_with_paths` and
    // `run_allow_once_with_paths` — the same bodies a harness's `sure hook
    // ingest` and a user's `sure hook allow-once` reach, minus the argument
    // vector — against locations this test named. The process-level side of the
    // writer is in `tests/cli_contract.rs`, which runs the binary.

    /// A Cursor `preToolUse` event for a shell tool: the command line travels in
    /// the harness's own `args` object, which is where a shell tool's words
    /// live on both integrations.
    fn cursor_shell_request_at(project: &std::path::Path, tool: &str, command: &str) -> String {
        serde_json::json!({
            "event": "preToolUse",
            "harness_session_id": "p13t005",
            "project_root": project.to_string_lossy(),
            "tool": tool,
            "args": {"command": command},
            "timestamp_utc": "2026-09-19T10:00:00Z",
            "source": "cursor",
        })
        .to_string()
    }

    /// Run one shell request and hand back what SURE answered and said.
    fn run_shell_request(
        project: &std::path::Path,
        paths: &Paths,
        tool: &str,
        command: &str,
    ) -> (ProtectionDecisionKind, String) {
        let text = cursor_shell_request_at(project, tool, command);
        let report = run_ingest_with_paths(Some("cursor"), Some("pre-tool-use"), &text, paths);
        match &report {
            Report::HookDecision(decision) => (
                decision.decision,
                decision
                    .reason
                    .clone()
                    .expect("the rule answers a request with an action and a reason"),
            ),
            other => panic!("expected HookDecision, got {other:?}"),
        }
    }

    /// Record an allowance the way `sure hook allow-once` records one, and
    /// require that it was recorded.
    fn allow_once(paths: &Paths, project: &std::path::Path, tool: &str, subject: &str) -> i64 {
        let report = run_allow_once_with_paths(
            tool,
            subject,
            &project.to_string_lossy(),
            allowance::DEFAULT_MINUTES,
            paths,
        );
        match report {
            Report::HookAllowance(recorded) => recorded.grant,
            other => panic!("expected a recorded allowance, got {other:?}"),
        }
    }

    /// Every grant in a store that no request has spent.
    ///
    /// Read the way [`sure_core::allowance::outstanding`] reads, so that a test
    /// asking "was this spent" is asking the same question the decision path
    /// asks rather than a second one that happens to agree.
    fn outstanding_grants(paths: &Paths, project: &std::path::Path) -> Vec<i64> {
        let store = Store::open(paths, project).expect("the store opens");
        let rows = store
            .history(
                &sure_core::store::HistoryFilter {
                    project_fingerprint: None,
                    kind: Some(sure_core::store::RecordKind::Allowance),
                    include_recordings: false,
                },
                allowance::SCAN_LIMIT,
            )
            .expect("the rows read back");

        let mut spent: Vec<i64> = Vec::new();
        let mut grants: Vec<i64> = Vec::new();
        for row in rows {
            match allowance::read_back(row.clone()) {
                Ok(allowance::AllowanceRecord::Grant(_)) => grants.push(row.id),
                Ok(allowance::AllowanceRecord::Spent(use_of)) => spent.push(use_of.grant),
                Err(error) => panic!("an unreadable allowance row: {error}"),
            }
        }
        grants.retain(|id| !spent.contains(id));
        grants
    }

    #[test]
    fn a_broad_delete_is_held_and_an_allowance_for_it_lets_one_through() {
        // The acceptance, through the command a harness runs. `rm -rf build/`
        // is the classifier's own destructive `rm` row with an operand that
        // names a whole location, and the mode is the one a user who has agreed
        // to run project code is in — so the answer before the allowance is the
        // consent hold, said in the user's terms.
        let (project, paths) = a_project_with("p13t005-broad-delete", "");
        a_user_who_allowed_project_code(&paths);

        let (action, reason) = run_shell_request(&project, &paths, "Shell", "rm -rf build/");
        assert_eq!(action, ProtectionDecisionKind::Block);
        assert!(
            reason.contains("names a whole location"),
            "the hold does not say what the command would do: {reason}"
        );
        assert!(
            reason.ends_with("SURE does not allow it."),
            "the hold is not in the voice this build answers in: {reason}"
        );

        // The user records an allowance for exactly this request.
        let grant = allow_once(&paths, &project, "Shell", "rm -rf build/");
        assert!(grant > 0, "an allowance is a stored row");

        let (action, reason) = run_shell_request(&project, &paths, "Shell", "rm -rf build/");
        assert_eq!(
            action,
            ProtectionDecisionKind::Allow,
            "the recorded allowance did not let this one request through"
        );
        assert_eq!(
            reason,
            allowance_reason(Danger::BroadDelete),
            "the sentence is not the one a spent allowance produces"
        );
        assert!(
            reason.contains("SURE would let this one through"),
            "the answer claims more than SURE can confirm: {reason}"
        );

        // And it is spent: the same words again are held exactly as before.
        let (action, reason) = run_shell_request(&project, &paths, "Shell", "rm -rf build/");
        assert_eq!(
            action,
            ProtectionDecisionKind::Block,
            "one allowance covered two requests"
        );
        assert!(reason.contains("names a whole location"), "{reason}");
    }

    #[test]
    fn an_allowance_covers_one_request_and_not_its_neighbours() {
        let (project, paths) = a_project_with("p13t005-one-request", "");
        a_user_who_allowed_project_code(&paths);
        allow_once(&paths, &project, "Shell", "rm -rf build/");

        // A different command, the same tool.
        let (action, _) = run_shell_request(&project, &paths, "Shell", "rm -rf dist/");
        assert_eq!(
            action,
            ProtectionDecisionKind::Block,
            "another command was covered"
        );

        // The same command, claimed by a different tool.
        let (action, _) = run_shell_request(&project, &paths, "Bash", "rm -rf build/");
        assert_eq!(
            action,
            ProtectionDecisionKind::Block,
            "another tool was covered"
        );

        // Neither of those spent it, so the request it was recorded for is the
        // one that does. Exact matching is the whole of the scoping, and the
        // order of these three assertions is what shows it.
        let (action, _) = run_shell_request(&project, &paths, "Shell", "rm -rf build/");
        assert_eq!(action, ProtectionDecisionKind::Allow);
    }

    #[test]
    fn a_force_push_is_held_and_an_allowance_for_it_lets_one_through() {
        let (project, paths) = a_project_with("p13t005-force-push", "");
        a_user_who_allowed_project_code(&paths);

        let (action, reason) = run_shell_request(&project, &paths, "Shell", "git push --force");
        assert_eq!(action, ProtectionDecisionKind::Block);
        assert!(
            reason.contains("replace commits that were already published"),
            "a force push is not named for what it does: {reason}"
        );

        allow_once(&paths, &project, "Shell", "git push --force");
        let (action, reason) = run_shell_request(&project, &paths, "Shell", "git push --force");
        assert_eq!(action, ProtectionDecisionKind::Allow);
        assert_eq!(reason, allowance_reason(Danger::ForcePush));

        // An ordinary push is another request: it is not a force push, so it is
        // not named as a danger and no allowance is spent on it.
        let (action, reason) = run_shell_request(&project, &paths, "Shell", "git push origin main");
        assert_eq!(
            action,
            ProtectionDecisionKind::Block,
            "every shell request is held; the question is which sentence it gets"
        );
        assert!(
            !reason.contains("replace commits"),
            "an ordinary push was named as a force push: {reason}"
        );
    }

    #[test]
    fn a_read_of_credentials_is_held_under_strict_and_an_allowance_for_it_lets_one_through() {
        let (project, paths) =
            a_project_with("p13t005-sensitive-read", "protection:\n  mode: strict\n");

        let (action, reason) = run_cursor_request(&project, &paths, "Read", Some(".env"));
        assert_eq!(action, ProtectionDecisionKind::Block);
        assert!(reason.contains("credentials or keys"), "{reason}");

        allow_once(&paths, &project, "Read", ".env");
        let (action, reason) = run_cursor_request(&project, &paths, "Read", Some(".env"));
        assert_eq!(action, ProtectionDecisionKind::Allow);
        assert_eq!(reason, allowance_reason(Danger::SensitiveRead));

        // The next read of the same file is held again.
        let (action, _) = run_cursor_request(&project, &paths, "Read", Some(".env"));
        assert_eq!(action, ProtectionDecisionKind::Block);
    }

    #[test]
    fn an_allowance_is_not_spent_by_a_request_that_was_never_held() {
        // The property that keeps an allowance from becoming a setting: it can
        // only ever change an answer SURE reached about one dangerous request.
        // An ordinary read is allowed by the rule itself, and the grant is still
        // there afterwards — which is how this test tells "the allowance was not
        // needed" from "the allowance was quietly used up".
        let (project, paths) = a_project_with("p13t005-unspent", "protection:\n  mode: strict\n");
        let grant = allow_once(&paths, &project, "Read", ".env");

        let (action, reason) = run_cursor_request(&project, &paths, "Read", Some("src/lib.rs"));
        assert_eq!(action, ProtectionDecisionKind::Allow);
        assert_ne!(
            reason,
            allowance_reason(Danger::SensitiveRead),
            "an ordinary read was answered with the allowance's sentence"
        );
        assert_eq!(
            outstanding_grants(&paths, &project),
            vec![grant],
            "an ordinary read spent the allowance"
        );

        // And the request it was recorded for is still the one that spends it.
        let (action, _) = run_cursor_request(&project, &paths, "Read", Some(".env"));
        assert_eq!(action, ProtectionDecisionKind::Allow);
        assert!(
            outstanding_grants(&paths, &project).is_empty(),
            "the grant was not spent by the request it named"
        );
    }

    #[test]
    fn a_hold_sure_cannot_tie_to_an_allowance_is_never_letting_one_through() {
        // A shell request SURE cannot read has no danger, so no allowance can
        // cover it — the answer is the consent hold it has always been. This is
        // the limit of the override stated as a test: a command line with more
        // than one reading is never let through by a grant.
        let (project, paths) = a_project_with("p13t005-unreadable", "");
        a_user_who_allowed_project_code(&paths);
        for line in [
            "rm -rf \"my dir\"",
            "rm -rf / && echo done",
            "git push --force; echo done",
        ] {
            let (action, reason) = run_shell_request(&project, &paths, "Shell", line);
            assert_eq!(
                action,
                ProtectionDecisionKind::Block,
                "{line} is a line SURE can read in one way only? {reason}"
            );
            assert!(
                !reason.contains("You recorded a one-time allowance"),
                "{line} was let through by an allowance: {reason}"
            );
        }

        // And a destructive command whose operands name files rather than a
        // location is held for consent and is not named as a broad delete, so
        // an allowance recorded for its exact words cannot let it through
        // either. That is the fail-closed direction: SURE does not call a
        // command dangerous on a guess, and it does not spend a grant on one
        // either.
        let (action, reason) = run_shell_request(&project, &paths, "Shell", "rm -rf build");
        assert_eq!(action, ProtectionDecisionKind::Block);
        assert!(!reason.contains("names a whole location"), "{reason}");
        allow_once(&paths, &project, "Shell", "rm -rf build");
        let (action, reason) = run_shell_request(&project, &paths, "Shell", "rm -rf build");
        assert_eq!(
            action,
            ProtectionDecisionKind::Block,
            "an allowance let through a request SURE never named as dangerous"
        );
        assert!(!reason.contains("one-time allowance"), "{reason}");
    }

    #[test]
    fn a_decision_that_could_not_be_recorded_keeps_the_answer_and_says_so() {
        // `record_the_decision`'s two ways of not writing the row, called rather
        // than reached: a store SURE cannot open fails the event write too, so
        // an integration test can only ever reach the first arm — and the second
        // is the one a full disk or a store somebody else holds the lock on
        // takes. What both must keep is the decision, because the kind is what
        // [`crate::report`] turns into the number a launcher reads.
        let (project, paths) = a_project_with("p13t006-unrecorded", "");
        a_user_who_allowed_project_code(&paths);
        let project_root = project.to_string_lossy().into_owned();
        let held = || ProtectionDecision::block(danger_reason(Danger::BroadDelete));

        let no_event = record_the_decision(
            Decided {
                decision: held(),
                allowance: None,
            },
            Some(Danger::BroadDelete),
            "Shell",
            &EventId::generate(),
            &Err("the store refused the event".to_owned()),
            &project_root,
            &paths,
        );
        assert_eq!(
            no_event.decision,
            ProtectionDecisionKind::Block,
            "a row that could not be written changed the answer a launcher reads"
        );
        let reason = no_event.reason.expect("a reason");
        assert!(
            reason.contains("was not stored") && reason.contains("The decision above stands."),
            "a decision with nothing to hang from is not explained: {reason}"
        );

        // The event went in and the store will not open for the row: the store
        // inside the project is refused by `Paths::ensure_outside`, which is the
        // one way this path fails that a test can arrange without a broken disk.
        let inside =
            Paths::from_roots(project.join("data"), project.join("config")).expect("paths");
        let refused = record_the_decision(
            Decided {
                decision: ProtectionDecision::allow(),
                allowance: None,
            },
            None,
            "Read",
            &EventId::generate(),
            &Ok(FingerprintId::generate()),
            &project_root,
            &inside,
        );
        assert_eq!(
            refused.decision,
            ProtectionDecisionKind::Allow,
            "a store SURE could not open turned an allow into something else"
        );
        assert_eq!(
            refused.reason.as_deref(),
            Some(not_recorded_reason(NotRecorded::WriteFailed)),
            "a decision with no reason of its own does not get the sentence about the missing row"
        );
    }

    #[test]
    fn a_store_sure_cannot_read_holds_the_request_and_says_so() {
        // A store inside the project it is recording about is refused by
        // `Paths::ensure_outside`, which is the one way this path fails that a
        // test can arrange without a broken disk. The answer must be the hold,
        // and the sentence must be the one that says SURE could not look —
        // "there is no allowance" would be a claim about a store it never read.
        let tmp = scratch_hook_dir("p13t005-store-unreadable");
        let _ = std::fs::remove_dir_all(&tmp);
        let project = tmp.join("project");
        std::fs::create_dir_all(&project).expect("create project");
        std::fs::write(project.join("sure.yaml"), "").expect("write project config");
        // The *store* is inside the project, so every store this path opens is
        // refused; the user's own file is beside the project and not inside it,
        // because since P15-T025 a settings file the project could have written
        // is refused before the store is reached — which is a different failure
        // than the one this test is about. The mode still has to be the user's,
        // because a request that needs consent is the only kind an allowance can
        // be recorded for.
        let paths = Paths::from_roots(project.join("data"), tmp.join("config"))
            .expect("the roots are absolute");
        a_user_who_allowed_project_code(&paths);

        let (action, reason) = run_shell_request(&project, &paths, "Shell", "rm -rf build/");
        assert_eq!(action, ProtectionDecisionKind::Block);
        assert!(
            reason.contains("could not read its record of one-time allowances"),
            "a store SURE cannot read is reported as something else: {reason}"
        );
        assert!(
            !reason.contains("one-time allowance for this exact request"),
            "a request was let through on a store SURE never read: {reason}"
        );
    }

    #[test]
    fn the_writer_refuses_a_window_it_will_not_record() {
        let (project, paths) = a_project_with("p13t005-window", "");
        // A mode a grant can be spent under, so that the refusal this test is
        // about is the window's. Without it this project is `inspect_only` and
        // `P13-T010` made the writer refuse that too, which would be a green
        // assertion about the wrong refusal.
        a_user_who_allowed_project_code(&paths);
        let too_short = run_allow_once_with_paths(
            "Shell",
            "rm -rf build/",
            &project.to_string_lossy(),
            0,
            &paths,
        );
        match too_short {
            Report::Failed(failure) => {
                assert!(
                    failure.detail.contains('1') && failure.detail.contains("1440"),
                    "the refusal does not say what SURE will record: {}",
                    failure.detail
                );
            }
            other => panic!("an allowance of no minutes was answered with {other:?}"),
        }
        let too_long = run_allow_once_with_paths(
            "Shell",
            "rm -rf build/",
            &project.to_string_lossy(),
            allowance::MAX_MINUTES + 1,
            &paths,
        );
        assert!(
            matches!(too_long, Report::Failed(_)),
            "a standing permission was recorded as a one-time allowance"
        );
        assert!(
            outstanding_grants(&paths, &project).is_empty(),
            "a refused window still wrote a row"
        );

        // The bound itself is recorded, so the refusal is about the bound and
        // not about the writer being unwilling to record anything at all.
        let longest = run_allow_once_with_paths(
            "Shell",
            "rm -rf build/",
            &project.to_string_lossy(),
            allowance::MAX_MINUTES,
            &paths,
        );
        assert!(
            matches!(longest, Report::HookAllowance(_)),
            "the longest window SURE documents was refused: {longest:?}"
        );
    }

    // --- what the writer reads before it writes (`P13-T010`) ------------------

    #[test]
    fn a_refused_grant_is_never_written_and_a_written_one_can_be_spent() {
        // The two halves of acceptance line 4, in one place, over two projects
        // that differ in nothing but their settings — so the difference in what
        // happens is attributable to the settings and not to the words.
        //
        // The first is the default one: no user settings file, and a project file
        // that says nothing, which is `inspect_only` and `standard`. Nothing this
        // project sends can be held for a danger, so the writer refuses and the
        // store is left with no allowance row in it at all. This is not an edge
        // case: it is what every user of this build gets, because nothing in it
        // writes `%APPDATA%\SURE\sure.yaml`.
        let (refusing, refusing_paths) = a_project_with("p13t010-refused", "");
        let refused = run_allow_once_with_paths(
            "Shell",
            "rm -rf build/",
            &refusing.to_string_lossy(),
            allowance::DEFAULT_MINUTES,
            &refusing_paths,
        );
        match &refused {
            Report::Failed(failure) => {
                assert!(
                    failure.what.contains("no request could spend"),
                    "the refusal does not say what it refused: {}",
                    failure.what
                );
                assert!(
                    failure.detail.contains("execution.mode")
                        && failure.detail.contains("inspect_only")
                        && failure.detail.contains("host_confirmed"),
                    "the refusal does not name the setting and what to do with it: {}",
                    failure.detail
                );
                assert!(
                    !failure.detail.contains("custom"),
                    "the refusal named a mode no settings file can hold: {}",
                    failure.detail
                );
            }
            other => panic!("a grant nothing here could spend was answered with {other:?}"),
        }
        assert!(
            outstanding_grants(&refusing_paths, &refusing).is_empty(),
            "the writer refused the grant and wrote a row anyway"
        );

        // And the store proves it after the fact, not just at the moment of the
        // refusal: a request SURE already refuses spends nothing, because there
        // is nothing to spend. The assertion is the one the previous task's test
        // made about the same store, stated against an empty one.
        let _ = run_shell_request(&refusing, &refusing_paths, "Shell", "rm -rf build/");
        assert!(
            outstanding_grants(&refusing_paths, &refusing).is_empty(),
            "a grant was spent on a request the mode had already refused"
        );

        // The second project holds something: strict protection holds a read of
        // a file credentials live in, and the permission to read is one every
        // run has. The writer records, and the request it was recorded for
        // spends the row — which is what "a matching request can actually spend
        // it" means, read out of the store rather than out of the sentence.
        let (spending, spending_paths) =
            a_project_with("p13t010-written", "protection:\n  mode: strict\n");
        let grant = allow_once(&spending_paths, &spending, "Read", ".env");
        assert_eq!(
            outstanding_grants(&spending_paths, &spending),
            vec![grant],
            "the writer recorded a grant that is not in the store"
        );
        let (action, _) = run_cursor_request(&spending, &spending_paths, "Read", Some(".env"));
        assert_eq!(
            action,
            ProtectionDecisionKind::Allow,
            "a grant written for this project was not spent by the request it names"
        );
        assert!(
            outstanding_grants(&spending_paths, &spending).is_empty(),
            "the request it named did not spend the grant"
        );
    }

    #[test]
    fn a_grant_carries_the_acts_the_settings_in_force_leave_for_it() {
        // Acceptance line 3's first half, at the value the sentence is built
        // from.
        //
        // **Changed by `P13-T010`'s second dispatch, and the change is the
        // point.** This test used to build the project below — strict
        // protection, nothing else — and record a grant for **`Shell`,
        // `rm -rf build/`**, asserting `acts == vec![Danger::SensitiveRead]`.
        // That grant was written and could never be spent: under
        // `inspect_only` a shell request is refused by the mode before its
        // danger is read, and the only act these settings leave belongs to a
        // read. The assertion was true of the *project* and false of the
        // *grant*. Now the same command is refused rather than recorded, and
        // the acts idea is under test on a tool that can reach an act.
        let (project, paths) = a_project_with("p13t010-acts", "protection:\n  mode: strict\n");

        // The tool that can reach the act these settings leave: strict holds a
        // read of a file credentials live in, and every run may read. A
        // confirmation that offered a broad delete or a force push here would be
        // offering an outcome these settings make unreachable.
        let recorded = run_allow_once_with_paths(
            "Read",
            ".env",
            &project.to_string_lossy(),
            allowance::DEFAULT_MINUTES,
            &paths,
        );
        match recorded {
            Report::HookAllowance(recorded) => assert_eq!(
                recorded.acts,
                vec![Danger::SensitiveRead],
                "the confirmation would offer an act these settings cannot hold"
            ),
            other => panic!("a tool that can reach this project's act answered with {other:?}"),
        }

        // And the tool that cannot reach one is refused, on the same settings:
        // the sentence and the list are the same question, so a grant for a
        // tool with no act is one the writer will not write.
        let refused = run_allow_once_with_paths(
            "Shell",
            "rm -rf build/",
            &project.to_string_lossy(),
            allowance::DEFAULT_MINUTES,
            &paths,
        );
        match refused {
            Report::Failed(failure) => {
                assert!(
                    failure.detail.contains("Shell"),
                    "the refusal does not name the tool the grant was for: {}",
                    failure.detail
                );
                assert!(
                    !failure.detail.contains("Set `protection.mode: strict`"),
                    "the refusal offers a change that would leave this grant unspendable: {}",
                    failure.detail
                );
            }
            other => panic!("a grant nothing could spend was answered with {other:?}"),
        }
        assert_eq!(
            outstanding_grants(&paths, &project).len(),
            1,
            "the read's grant is the only row this project should hold"
        );

        // And the other project leaves two: with the user's own mode in force a
        // command reaches the consent hold, and a read of a file of credentials
        // is not held at all under standard protection, so the act strict holds
        // is the one that is missing.
        let (project, paths) = a_project_with("p13t010-acts-user", "");
        a_user_who_allowed_project_code(&paths);
        let recorded = run_allow_once_with_paths(
            "Shell",
            "rm -rf build/",
            &project.to_string_lossy(),
            allowance::DEFAULT_MINUTES,
            &paths,
        );
        match recorded {
            Report::HookAllowance(recorded) => assert_eq!(
                recorded.acts,
                vec![Danger::BroadDelete, Danger::ForcePush],
                "the confirmation would offer an act these settings cannot hold"
            ),
            other => panic!("a project that can spend a grant answered with {other:?}"),
        }

        // And the whole cycle, because a grant is only worth what a request can
        // spend: the row is in the store, the request it names takes it, and the
        // same words a second time are held again. This is the case the fix must
        // not narrow — a project where the named tool reaches an act — and it is
        // the one the writer's narrowing had to leave alone.
        assert_eq!(
            outstanding_grants(&paths, &project).len(),
            1,
            "the recorded grant is not in the store"
        );
        let (action, reason) = run_shell_request(&project, &paths, "Shell", "rm -rf build/");
        assert_eq!(
            action,
            ProtectionDecisionKind::Allow,
            "the grant was not spent by the request it names"
        );
        assert_eq!(reason, allowance_reason(Danger::BroadDelete));
        assert!(
            outstanding_grants(&paths, &project).is_empty(),
            "the request it named did not spend the grant"
        );
        let (action, _) = run_shell_request(&project, &paths, "Shell", "rm -rf build/");
        assert_eq!(
            action,
            ProtectionDecisionKind::Block,
            "one allowance covered two requests"
        );
    }

    /// The defect `P13-T010`'s second send-back measured, driven the way it was
    /// measured and left here as the test that will not let it come back.
    ///
    /// The tool name is `Edit`, which is Claude Code's word for a change to a
    /// project file and a word Cursor's vocabulary does not carry. Read as the
    /// union over both harnesses' tables — what this writer did before the fix —
    /// `Edit` was also read as Cursor's unrecognised-name fallback, an arbitrary
    /// command, and taking the more permissive of the two readings is what the
    /// writer recorded a grant for. Measured on the tip before this change, on
    /// this exact setup: `allow-once --tool Edit --path src/lib.rs` **recorded**
    /// `acts = [BroadDelete, ForcePush]`, told the user that
    /// `execution.mode: host_confirmed` would put it within reach — and then
    /// neither a Claude Code `Edit`/`src/lib.rs` request nor a Cursor one spent
    /// it. The grant stayed outstanding. Acceptance line 3, falsified by the
    /// store read-back it prescribes.
    ///
    /// What the test asserts is therefore two things about one store: the
    /// writer refuses, and the requests that were supposed to spend the grant it
    /// used to write spend nothing because there is nothing to spend.
    ///
    /// **Which refusal, and why `P13-T011` moved it.** The sentence this test
    /// used to assert was `P13-T010`'s: the action needs a permission *no
    /// setting in this build grants*, so the refusal named no setting at all.
    /// `P13-T011` decided that the user's own settings file may grant that
    /// permission — `execution.allow_project_write`, which a project's
    /// `sure.yaml` cannot — so the sentence names it now, and the assertion that
    /// the build's own limit is the reason is false of this build. It is
    /// replaced by the assertion that is true of it, on the same setup:
    /// measured with a user file naming `mode: host_confirmed` and no
    /// `allow_project_write`, `allow-once --tool Edit --path src/lib.rs` refuses
    /// with *"A request naming it is one that would change files inside your
    /// project, and the permissions in force do not grant SURE that"*, followed
    /// by `execution.allow_project_write: true` in the user's own file **and**
    /// `protection.mode: strict` as the remedy. The half of the test below it is
    /// untouched, because the writer still refuses: with the permission not in
    /// force, no request naming `Edit` can be held for any act, so the row the
    /// old union-reading would have written is still not written. That is the
    /// defect coming back that this test exists to catch, and it is caught the
    /// same way under either sentence.
    #[test]
    fn edit_is_read_in_the_vocabulary_that_claims_it_and_a_grant_for_it_is_refused() {
        // The settings the defect was measured under: the user's own file
        // naming `host_confirmed`, so `run_project_code` is granted and the
        // old sentence's advice has been taken. Nothing about the project file,
        // which is the default one.
        let (project, paths) = a_project_with("p13t010-edit", "");
        a_user_who_allowed_project_code(&paths);

        let refused = run_allow_once_with_paths(
            "Edit",
            "src/lib.rs",
            &project.to_string_lossy(),
            allowance::DEFAULT_MINUTES,
            &paths,
        );
        match &refused {
            Report::Failed(failure) => {
                // What an `Edit` is read as: a change to this project's files,
                // and not the shell command Cursor's unrecognised-name fallback
                // would also have made of the name.
                assert!(
                    failure
                        .detail
                        .contains("would change files inside your project"),
                    "the refusal does not say what an `Edit` would do: {}",
                    failure.detail
                );
                // The remedy, and both halves of it: the permission, in the
                // file that can grant it — named as the file, because a
                // project's cannot — and the mode that holds a change naming a
                // whole location, which is the only act a grant could be spent
                // on here.
                for needed in [
                    "execution.allow_project_write: true",
                    "a project's `sure.yaml` cannot grant this one",
                    "sure doctor",
                    "and set `protection.mode: strict`",
                    "Nothing was written",
                ] {
                    assert!(
                        failure.detail.contains(needed),
                        "the refusal does not say {needed:?}: {}",
                        failure.detail
                    );
                }
                // And what it must not say: the build's own limit, which is
                // what this sentence said before `P13-T011`, and the mode,
                // which is not the cause — `decide` never consults the mode
                // about a change, because writing a file does not run the
                // project's code.
                for absent in [
                    "No setting in this build grants it",
                    "host_confirmed",
                    "`execution.mode`",
                ] {
                    assert!(
                        !failure.detail.contains(absent),
                        "the refusal names {absent}, which is not the cause: {}",
                        failure.detail
                    );
                }
            }
            other => panic!("a grant no request could spend was answered with {other:?}"),
        }
        assert!(
            outstanding_grants(&paths, &project).is_empty(),
            "the writer refused the grant and wrote a row anyway"
        );

        // And the two requests the old grant was recorded for: a Claude Code
        // `PreToolUse` naming `Edit`, which is the harness the name belongs to,
        // and a Cursor one, which is the harness whose fallback the union read
        // it through. Neither spends anything, because the row the union would
        // have written is the row this writer refuses to write.
        let claude_edit = serde_json::json!({
            "event": "PreToolUse",
            "harness_session_id": "p13t010-edit",
            "project_root": project.to_string_lossy(),
            "tool": "Edit",
            "path": "src/lib.rs",
            "timestamp_utc": "2026-09-19T09:00:00Z",
            "source": "claude-code",
        })
        .to_string();
        let claude = run_ingest_with_paths(
            Some("claude-code"),
            Some("pre-tool-use"),
            &claude_edit,
            &paths,
        );
        match &claude {
            Report::HookDecision(decision) => assert_ne!(
                decision.decision,
                ProtectionDecisionKind::Allow,
                "a request the settings in force refuse was allowed"
            ),
            other => panic!("expected HookDecision, got {other:?}"),
        }
        let (cursor_action, _) = run_cursor_request(&project, &paths, "Edit", Some("src/lib.rs"));
        assert_ne!(
            cursor_action,
            ProtectionDecisionKind::Allow,
            "a request the settings in force refuse was allowed"
        );
        assert!(
            outstanding_grants(&paths, &project).is_empty(),
            "a request spent an allowance this writer never wrote"
        );
    }
}
