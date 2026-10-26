//! What a command hands back, and the two ways of writing it down.
//!
//! # One result, two renderers, no third path
//!
//! [`Report`] is the CLI's result vocabulary. Every command produces exactly one
//! of its variants, and each variant has a [`Report::human`] arm and a
//! [`Report::machine`] arm. The two matches are exhaustive and independent: a
//! new variant does not compile until both are written, so there is no state of
//! the world in which a result is renderable one way and not the other.
//!
//! They are independent on purpose. Deriving the human form from the JSON, or
//! the JSON from the human text, is the tempting shortcut and it is the reason
//! "human and machine output are separated" needs saying at all — one path would
//! then be a formatting of the other, and a field could exist in the form a
//! script reads while being absent from the form a person reads, with no test
//! able to name the difference.
//!
//! # The exit status
//!
//! Nothing else in this program decides one. [`Report::exit_code`] is the whole
//! mapping, and `docs/architecture/CLI.md` lists the same codes. A script that
//! reads only the exit status and a person who reads only the prose are looking
//! at the same decision.
//!
//! # The machine-readable frame
//!
//! One JSON object on one line, always with `sure_version`, `protocol_version`,
//! `command`, `outcome` and `exit_code`. The first two are there so that a bug
//! report containing a captured response says which build produced it — the two
//! things that make a stored answer unreadable are a newer SURE and a newer
//! protocol, and a response that does not name either invites the reader to
//! assume the current ones. `command` and `outcome` are what a reader switches
//! on, and `exit_code` is the same decision the process returned, so that a
//! script reading only the body and a script reading only the status are told
//! the same thing.
//!
//! Everything else a command found goes under `details`, one key, written by
//! that command's own module.
//!
//! This frame is **not** one of the seven documents in
//! `docs/architecture/PROTOCOL.md`. Those are statements about a project or an
//! event, each with a schema in `schemas/`; this is the envelope a command
//! answers in. `docs/architecture/PROTOCOL.md` records the distinction, because
//! a sentence there says "everything SURE writes" and a CLI response is written.
//!
//! # The one frame that is not this envelope
//!
//! [`Report::Mcp`] — one Model Context Protocol message on its way to a
//! harness — carries the message itself, because a JSON-RPC message is not a
//! CLI response and the caller reading it is reading `id` and `result`, not
//! `sure_version` and `command`. Wrapping one in the other would put SURE's
//! envelope between an MCP client and the protocol it speaks, and the whole
//! point of the bridge is that it speaks the protocol rather than a dialect of
//! it. It is the only variant with a frame of its own. What this envelope
//! exists for is still in the answer, where it belongs: every tool result
//! carries the command's own frame, unmodified, under `structuredContent.sure`.

use std::io::{self, Write};

use serde_json::json;

/// The exit statuses SURE is allowed to produce.
///
/// The same table is in `docs/architecture/CLI.md`. Two codes are reserved
/// before anything can return them, because a script written against a future
/// release should not have to be rewritten when that release reuses a number
/// for something else.
pub mod exit {
    /// The command did what it says it does.
    pub const OK: u8 = 0;
    /// The command ran, and the answer is not a clean one.
    ///
    /// `sure doctor` returns this when it finds something wrong with this
    /// installation, and `sure check`, `sure recheck` and `sure repair` return
    /// it when the project was checked and is not clean. That is one code for
    /// two things on purpose: what a caller does with it is the same — stop —
    /// and the report says which it was. What must never be merged is this and
    /// [`UNAVAILABLE`]: "the project has problems" and "SURE cannot do that
    /// here" need opposite responses from the person reading them, and one
    /// status for both is how a tool that is broken gets read as a project that
    /// is clean.
    pub const NOT_GREEN: u8 = 1;
    /// The command line was wrong.
    pub const USAGE: u8 = 2;
    /// The command exists, and this build cannot carry it out.
    ///
    /// Distinct from [`FAILED`] because the remedy is: this is not a bug report,
    /// and the answer is a newer build rather than a fixed one.
    pub const UNAVAILABLE: u8 = 3;
    /// SURE declined, and can say why in the user's own terms.
    ///
    /// Reserved. It is what a refusal that is a *decision* rather than a
    /// failure returns — a project configuration asking for authority it cannot
    /// be granted, or a location inside the project. `docs/adr/0011` and
    /// `docs/architecture/CONFIG_AUTHORITY.md` are where those decisions live.
    #[allow(
        dead_code,
        reason = "reserved by docs/architecture/CLI.md; nothing refuses yet"
    )]
    pub const REFUSED: u8 = 4;
    /// The command tried and did not finish.
    pub const FAILED: u8 = 5;
}

/// A command this build recognises and cannot yet carry out.
///
/// Every field is a `&'static str`, for the same reason
/// `sure_core::diagnostics`' messages are: a sentence SURE says about itself is
/// fixed, so no call site can paraphrase it into something weaker, and no
/// project-controlled text can be interpolated into it.
///
/// # Why there is no phase in here
///
/// The obvious third field is "which phase implements this", and it was
/// written and then removed. It is a promise SURE cannot keep — no test can
/// check that a phase lands — and for at least one command there is no phase to
/// name: `sure history` is in the documented surface
/// (`docs/architecture/STORAGE_AND_DATA_PATHS.md`) and no task in
/// `tasks/tasks.json` owns it. A field whose value is sometimes invented is
/// worse than a field that is absent, because a reader cannot tell the two
/// apart. Where a command is scheduled is `tasks/tasks.json`'s business, and
/// `docs/architecture/CLI.md` says so.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotYet {
    /// The command, as the user typed it, taken from the grammar rather than
    /// retyped — see `Command::name`.
    pub command: &'static str,
    /// What the command will do, once this build can. Phrased to follow
    /// "It will …".
    pub does: &'static str,
    /// What SURE did instead. A sentence, ending in a full stop.
    pub instead: &'static str,
}

/// A goal SURE wrote down for the project, as part of a run that went on to
/// check it.
///
/// # Why this is carried rather than reported on its own
///
/// Because something happened that the check's own result does not contain.
/// `sure check --goal "…"` writes the goal down **and then checks against it**:
/// it is the one command on this surface whose side effect is not visible in its
/// output unless the report says so. A run whose output did not mention the
/// write would leave a user unable to tell whether their words are in the
/// history, which is the shape of failure this program exists to find.
///
/// Until `P7-T010` this was a [`Report`] variant of its own and a run stopped
/// here with status 3, because there was no pipeline to continue into. Now it is
/// a field of [`CheckReport`]: the write still happens first, and the run still
/// says what it wrote, but the command the user asked for now also happens and
/// its status is the run's own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoalRecorded {
    /// The goal, as the record holds it. Not the words as the user typed them,
    /// and not a summary of them either; see `cli.rs`.
    ///
    /// The two texts are one text unless the store's redaction removed a
    /// credential-shaped value on the way in, and the report prints this one
    /// because the sentence above it is about the record — `P15-T024`, and
    /// `docs/architecture/PROJECT_INTENT.md` for the decision and the case
    /// against it. `crate::check`'s `record_goal` reads the row back and puts
    /// what it holds here, rather than redacting the words a second time.
    pub goal: String,
    /// The requirement's identifier, so that a later report can say whether the
    /// goal it compared against is the one this run recorded.
    pub requirement_id: String,
    /// Where the words came from.
    ///
    /// The domain's own enum rather than its wire name, so that the sentence a
    /// person reads and the field a script reads are two renderings of one
    /// value rather than two strings that have to be kept in step. The user
    /// asked for the goal; where it came from is what makes it usable as one,
    /// so it is a field rather than something the prose asserts on its own.
    pub source: sure_core::intent::IntentSource,
    /// The project the goal is about.
    pub project_root: String,
    /// The project state it was recorded against.
    ///
    /// The whole fingerprint rather than the identifier the store was handed,
    /// because the identifier is minted per run and means nothing on its own —
    /// what says *which* state this was is the kind and the digest. Both are
    /// printed, and the identifier goes in the frame for a script that wants to
    /// line this up with anything else the same run produced.
    pub project_state: sure_core::vocabulary::ProjectFingerprint,
    /// The store row it was written as.
    pub record: i64,
}

/// What one run of `sure check`, `sure recheck` or `sure repair` found.
///
/// # Why the pipeline's own result is the payload
///
/// Because the report *is* the run's result. Every field a reader needs —
/// the findings, what was checked, what was not and why, the overall verdict and
/// the per-stage record — is in [`sure_core::pipeline::PipelineOutcome`], and a
/// struct here that restated them would be a second place for them to be wrong.
/// What this type adds is the two things the pipeline does not know: which
/// command the user typed, and what that command wrote to their history on the
/// way.
///
/// # Why the three commands share one variant
///
/// Because they share one run. `sure recheck` is `sure check` plus a comparison
/// with the previous run and `sure repair` is `sure check` plus a repair
/// contract; all three reach the same orchestrator (`P7-T010`'s acceptance asks
/// for exactly that) and they differ in how far down the twelve stages they go.
/// Three variants would be three renderings of one result, free to drift.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckReport {
    /// The command the user typed, from the grammar rather than retyped — see
    /// `Command::name`.
    pub command: &'static str,
    /// The project directory the run was about, as SURE resolved it.
    pub project: String,
    /// What the twelve stages did, in order.
    pub run: sure_core::pipeline::PipelineOutcome,
    /// The privacy mode this run was under, where it came from, and the provider
    /// its configuration names.
    ///
    /// Held on the report rather than re-derived by each renderer, because the
    /// value has to be the *arbitrated* one (`sure_core::config::authority`) and
    /// a renderer that read a file itself would report one layer's answer as
    /// though it were the user's policy. See `sure_core::privacy`.
    pub privacy: sure_core::privacy::PrivacyStatement,
    /// Whether a model was consulted, as this run's own record says.
    ///
    /// Read from the run rather than from a constant: see
    /// `sure_core::privacy::ModelUse` for why a build that later asks a model
    /// something would otherwise keep saying the reassuring thing.
    pub model_use: sure_core::privacy::ModelUse,
    /// The goal this run recorded, when the user gave one on the command line.
    ///
    /// `Some` only when `--goal` was passed, and `Some` means the row exists:
    /// a run that could not write it is a [`Report::Failed`] and never reaches
    /// this type.
    pub recorded_goal: Option<GoalRecorded>,
    /// What this machine's own settings allowed this run to do, and what they
    /// refused.
    ///
    /// Held on the report for the reason `privacy` above is: it is the
    /// *arbitrated* answer — the user's own file against the project's — and a
    /// renderer that read a file itself would report one layer's answer as
    /// though it were the policy in force. The difference from `privacy` is what
    /// it is for: the privacy statement says what may be kept and what may leave
    /// the machine, and this says what the run was allowed to *do*. Both were
    /// reachable from the frame and neither was in the words a person reads,
    /// which is what `crate::grants` exists to fix.
    pub grants: crate::grants::Grants,
}

impl CheckReport {
    /// Whether the run finished.
    #[must_use]
    pub const fn finished(&self) -> bool {
        self.run.finished()
    }

    /// Whether the run finished and found the project clean.
    #[must_use]
    pub fn is_green(&self) -> bool {
        self.run.is_green()
    }
}

/// A command that tried and did not finish.
///
/// The counterpart to [`NotYet`]: that one is a command this build cannot carry
/// out at all, and this one is a command that ran, met something it could not
/// get past, and stopped. The two are different answers — the first is a newer
/// build, the second is a bug report or a broken installation — which is why
/// they are different variants and different exit statuses.
///
/// `what` is a `&'static str` for [`NotYet`]'s reason: a sentence SURE says about
/// itself is fixed, so no call site can paraphrase it into something weaker.
/// `detail` is the underlying error's own message, which is where project- and
/// machine-controlled text belongs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failed {
    /// The command, from the grammar rather than retyped — see `Command::name`.
    pub command: &'static str,
    /// What did not happen, in a fixed sentence that says nothing was written
    /// when that is so.
    pub what: &'static str,
    /// What went wrong, in the words of the thing that went wrong.
    pub detail: String,
}

/// One one-time allowance, as `sure hook allow-once` wrote it down.
///
/// The subject is the user's own words — they typed them on this command line —
/// so this report may name them back; nothing here came from a harness, and
/// nothing about a project's files reaches it. The row id is carried so a user
/// can find the grant afterwards in `sure history`, and the window's end is
/// carried so that a grant that was never spent is visible as what it was.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookAllowance {
    /// The tool name, exactly as the user typed it.
    pub tool: String,
    /// The command line or path, exactly as the user typed it.
    pub subject: String,
    /// The project the allowance is for: the directory a request has to arrive
    /// from for the grant to be spendable.
    ///
    /// Named in what the user reads, and that is the point of carrying it here:
    /// a grant recorded from the wrong directory is spendable by nothing, and
    /// the only moment at which a user can notice that is now.
    pub project: String,
    /// How long the allowance lasts, in minutes.
    pub minutes: u32,
    /// The store row the grant was written as.
    pub grant: i64,
    /// When it stops being usable, in milliseconds since the epoch.
    pub not_after_ms: i64,
    /// Which of the three acts a request **naming this tool** could be held for
    /// under the settings in force when this was recorded.
    ///
    /// Carried because the sentence a user reads must not name an act those
    /// settings make unreachable — and "unreachable" is about the tool as well
    /// as about the settings: a grant is spent by a request that matches the
    /// tool and the words, so an act strict holds a *read* for is one a grant
    /// recorded for `Shell` can never be spent on. The facts behind the list are
    /// the mode, the permissions, the protection mode and the action kind the
    /// tool maps to, and
    /// [`sure_core::hook_protection::acts_a_tool_could_be_held_for`] answers
    /// them from the rule itself. `sure hook allow-once` refuses to record at all
    /// when the answer is empty, so this is non-empty in every report that
    /// carries it.
    pub acts: Vec<sure_core::hook_protection::Danger>,
}

/// What `sure config set` did to the user's own settings file.
///
/// # Why the three endings are one type
///
/// Because a person cannot tell them apart from the file. A written setting, a
/// setting that was already there, and a setting this build refused all leave the
/// same bytes on disk when the refusal is correct — nothing written — and the
/// difference between the first two is invisible even to a reader of the file. So
/// the difference is carried here, where the renderer has to state it, rather
/// than left for a person to work out by opening the file and comparing it with
/// what they remember.
///
/// # Why the grants are on it
///
/// The command's answer is not "the file changed", it is "this is what your
/// settings now allow", and that second half is read back through the same
/// reader every run uses. It is `Option` because the reading back is a separate
/// step that can fail after a write succeeded, and the one thing this report may
/// not do is make a failed read look like a successful one: the error is carried
/// and stated, so "SURE wrote it and could not tell you what it now allows" is
/// a thing a person can read rather than a silence they can misread.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettingsChange {
    /// The command the user typed, so the frame names it — `config set`.
    pub command: &'static str,
    /// The setting, as the user typed it.
    pub setting: String,
    /// The value, as the user typed it or as SURE read it back.
    pub value: String,
    /// The file, in the operating system's own terms.
    pub settings_file: String,
    /// Which of the three things happened.
    pub outcome: SettingsOutcome,
    /// What the user's settings allow, read back through `Authority::load`.
    pub grants: Option<crate::grants::Grants>,
    /// Why the reading back failed, when it did.
    pub grants_error: Option<String>,
}

/// Which of the three things `sure config set` did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SettingsOutcome {
    /// The setting was written, and the file now says what the user asked for.
    Written,
    /// The file already said it, and was left byte-for-byte as it was.
    ///
    /// Not a failure, and not a write: a command that rewrote a file to say what
    /// it already said would be a command that loses somebody's comments the
    /// first time they run it twice.
    AlreadySaid,
    /// Nothing was written, and this is why.
    ///
    /// `what` is a sentence SURE wrote about itself and `detail` is whatever it
    /// was told, kept apart for [`Failed`]'s reason: a reader deciding whether
    /// to file a bug should not have to parse prose to find out.
    Refused {
        /// The sentence a person is owed, in SURE's own words.
        what: String,
        /// The underlying reason, when there is one to quote — the reader's own
        /// complaint about the file, or the operating system's about the write.
        detail: Option<String>,
    },
}

/// One Model Context Protocol message, on its way to the caller.
///
/// # Why a protocol message is a [`Report`]
///
/// `sure mcp serve` speaks JSON-RPC over standard input and output, and
/// `crates/sure-cli/tests/cli_contract.rs` admits exactly one module in this
/// crate that names a process stream. Routing each message through the same
/// `Report` → [`Format`](crate::output::Format) path every other command takes
/// is what keeps both rules true at once: the bridge never writes to a stream,
/// and there is still no second way out of this program. A bridge that opened
/// its own path to stdout would be the first exception to the rule that makes
/// "human and machine output are separated" checkable.
///
/// The cost is that this is the one variant whose machine form is not the CLI
/// envelope — see the module comment. It is a message, and the caller reads it
/// as one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpMessage {
    /// The message, exactly as it goes on the wire.
    pub message: serde_json::Value,
}

impl McpMessage {
    /// Whether this message tells the caller SURE could not answer.
    ///
    /// Two shapes say so, and both are decided here rather than at the two
    /// places that build them, so that the outcome, the exit status and
    /// `isError` cannot drift apart:
    ///
    /// 1. a JSON-RPC **error object**, which is what the protocol has for a
    ///    request that was malformed, a method that is not here, or arguments
    ///    SURE will not accept;
    /// 2. a **tool result with `isError`**, which is how every tool whose
    ///    command this build cannot carry out answers.
    ///
    /// The second is the one that matters most in this build, and the one a
    /// predicate that only looked for `error` would get wrong: it would call
    /// `sure check is not implemented in this build` an `ok` message. That is
    /// SURE's own false green, told to an agent, which is the one thing this
    /// program exists to prevent.
    #[must_use]
    pub fn is_error(&self) -> bool {
        if self
            .message
            .get("error")
            .is_some_and(|error| !error.is_null())
        {
            return true;
        }
        self.message
            .get("result")
            .and_then(|result| result.get("isError"))
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false)
    }
}

/// What one run of `sure mcp serve` did, up to the moment its caller closed it.
///
/// # Why the bridge reports a session rather than a result
///
/// Every other command answers a question and stops. This one runs for as long
/// as its caller wants it to, so what it has to say at the end is what
/// happened on the way: whether a handshake completed, and how much of the
/// protocol went past. None of those numbers is a claim about a project — the
/// claims are in the tool results, each in the words of the command it ran.
///
/// The counts are bounded by the session and mean nothing else: a request
/// answered is a response written, whether the answer was a result or an error
/// object, and `errors` counts the ones that were errors. That is the pair a
/// person reads to tell "the harness asked for five things and SURE answered"
/// from "the harness asked for five things and SURE refused four".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpSession {
    /// Whether a caller completed the handshake.
    pub initialized: bool,
    /// The protocol revision the caller asked for, if it named one.
    ///
    /// Kept even when SURE answers with its own revision, because "which
    /// version did it ask for" is the first question a person has when two
    /// sides disagree, and the answer is not recoverable afterwards.
    pub requested_protocol_version: Option<String>,
    /// The revision SURE answered with.
    pub agreed_protocol_version: Option<String>,
    /// Requests answered, with a result or with an error object.
    pub answered: u64,
    /// Notifications received, which are answered with nothing at all.
    pub notifications: u64,
    /// `tools/call` requests received.
    pub tool_calls: u64,
    /// Messages answered with an error.
    pub errors: u64,
}

/// The result of one command.
///
/// Boxed where the payload is large, so that a variant carrying a page of
/// findings does not make every `Report` a page wide. Clippy enforces the
/// general rule; the box here is the answer to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Report {
    /// `sure version`.
    Version,
    /// `sure protocol`.
    Protocol,
    /// `sure protocol --speaks N`, carrying what SURE can say to that caller.
    Handshake(sure_core::Handshake),
    /// `sure doctor`, carrying what it found.
    Doctor(Box<sure_core::doctor::DoctorReport>),
    /// `sure check`, `sure recheck` or `sure repair`, carrying what the twelve
    /// stages of `docs/architecture/CHECK_PIPELINE.md` did.
    Check(Box<CheckReport>),
    /// `sure history`, carrying what it found or what it removed.
    ///
    /// One variant for the three subcommands this build carries out, for
    /// [`Self::Check`]'s reason: they are three readings of one store, they
    /// differ only in what they did to it, and a variant each would be three
    /// renderings free to drift. Which command the user typed is on the report,
    /// so the frame names the command that was run rather than the group.
    History(Box<crate::history::HistoryReport>),
    /// `sure config set`, carrying what it wrote and what the settings now allow.
    ///
    /// Its own variant rather than a [`Self::Failed`] for a refusal, because the
    /// three endings are three different answers about a file the user owns and
    /// the person reading them has to be able to tell which one happened: a
    /// write, a no-op, and a refusal are not "worked" and "did not work".
    Settings(Box<SettingsChange>),
    /// `sure config show`, carrying the settings in effect and their layers.
    ConfigShow(Box<crate::config_show::ConfigShowReport>),
    /// `sure explain`, carrying one recorded finding or check result.
    Explain(Box<crate::explain::ExplainReport>),
    /// A command whose work lands in a later phase.
    Unavailable(NotYet),
    /// A command that tried and did not finish.
    Failed(Box<Failed>),
    /// `sure hook ingest`, carrying a protection decision for a pre-action hook.
    ///
    /// The machine form is the decision JSON that the harness reads from stdout.
    HookDecision(sure_core::hook_protection::ProtectionDecision),
    /// `sure hook allow-once`, carrying the one-time allowance it recorded.
    ///
    /// Not a decision and not a setting: a grant the user made, on the command
    /// line, for one request SURE would otherwise hold. See
    /// `crate::hook::run_allow_once` for what is written and
    /// `sure_core::allowance` for what spending it means.
    HookAllowance(Box<HookAllowance>),
    /// `sure mcp serve`, carrying one Model Context Protocol message for the
    /// caller.
    ///
    /// The machine form is the message itself; see [`McpMessage`].
    Mcp(Box<McpMessage>),
    /// `sure mcp serve`, carrying what the session did before it ended.
    McpSession(Box<McpSession>),
}

impl Report {
    /// The `outcome` value of the machine-readable frame.
    ///
    /// A closed set, and the same strings
    /// `docs/architecture/CLI.md` documents. A reader switches on this;
    /// adding a variant here is adding a case every reader must handle, which
    /// is why it is a short list.
    ///
    /// Not `const`, and the one reason is [`Self::Mcp`]: whether a protocol
    /// message is an error is read out of the message, and
    /// `serde_json::Value`'s accessors are not `const`. The other arms were
    /// `const` while that was free; keeping it would have meant a second copy
    /// of the predicate here for the compiler's benefit.
    #[must_use]
    pub fn outcome(&self) -> &'static str {
        match self {
            Self::Version | Self::Protocol => "ok",
            // A refusal to speak a caller's protocol is not this build failing;
            // it is this build saying it cannot carry that out, which is what
            // `unavailable` means everywhere else on this surface. The message
            // says which side has to change.
            Self::Handshake(handshake) => {
                if handshake.is_agreed() {
                    "ok"
                } else {
                    "unavailable"
                }
            }
            // A doctor that found something wrong ran perfectly well, and this
            // says what its answer was rather than what the run did. It reads
            // the same predicate as `exit_code`, so the two cannot disagree;
            // they are both here because one is read by a person's script and
            // the other by anything that can read a status.
            Self::Doctor(report) => {
                if report.is_well() {
                    "ok"
                } else {
                    "not_green"
                }
            }
            // A run that finished and found the project clean is `ok`, and one
            // that finished and did not is `not_green` — the same pair `doctor`
            // uses above, and read off the same kind of predicate, so the outcome
            // and the status cannot disagree. A run that did not finish is
            // `failed`: see the arm below.
            Self::Check(report) => {
                if !report.finished() {
                    "failed"
                } else if report.is_green() {
                    "ok"
                } else {
                    "not_green"
                }
            }
            // A history report is an answer about this machine's own store —
            // what is in it, or what was taken out of it. It is never
            // `not_green`: that is a statement about a project, and this command
            // never looks at one. A history command that could not finish is a
            // [`Self::Failed`], which is the arm below.
            Self::History(_) => "ok",
            // A settings write is a report about a file the user owns, never
            // about a project: like a history report, and unlike a check, it is
            // never `not_green` — that is a statement about a project, and this
            // command looks at one only to know which file must *not* be
            // written. A refusal is `failed` rather than `unavailable`, which is
            // the distinction the statuses document: the command was understood
            // and this build declined to carry this one out, which is a thing to
            // look at rather than a newer build to fetch.
            Self::Settings(change) => match change.outcome {
                SettingsOutcome::Written | SettingsOutcome::AlreadySaid => "ok",
                SettingsOutcome::Refused { .. } => "failed",
            },
            Self::ConfigShow(_) | Self::Explain(_) => "ok",
            Self::Unavailable(_) => "unavailable",
            // A command that did not finish has not answered, and saying
            // `not_green` would read as "the project has problems" — which is a
            // statement about a project SURE never got to look at.
            Self::Failed(_) => "failed",
            // A hook decision is an answer: the command ran and produced a result.
            // `not_green` for block because the answer is "do not proceed".
            Self::HookDecision(decision) => match decision.decision {
                sure_core::hook_protection::ProtectionDecisionKind::Allow
                | sure_core::hook_protection::ProtectionDecisionKind::Warn => "ok",
                sure_core::hook_protection::ProtectionDecisionKind::Block => "not_green",
            },
            // A recorded allowance is an answer about this machine's own store:
            // what was written, and when it stops being usable. Like a history
            // report, and unlike a hook decision, it is never `not_green` — that
            // is a statement about a project, and this command does not look at
            // one. A write that did not land is a [`Self::Failed`], below.
            Self::HookAllowance(_) => "ok",
            // A protocol message is answered for the caller rather than
            // reported to a user, and its outcome is the message's own: an
            // error — a JSON-RPC error object, or a tool result carrying
            // `isError` — says SURE could not answer, which is `unavailable`
            // everywhere else on this surface. Never `failed`: nothing about
            // this process went wrong, and never `not_green`: that is a
            // statement about a project, and this is a statement about a
            // request.
            Self::Mcp(message) => {
                if message.is_error() {
                    "unavailable"
                } else {
                    "ok"
                }
            }
            // A session that ran and ended because its caller stopped asking
            // did what it says it does. A session that ended any other way is a
            // [`Self::Failed`], because the only other ending is a stream that
            // could not be read or written.
            Self::McpSession(_) => "ok",
        }
    }

    /// The status this program exits with.
    ///
    /// Not `const`, for [`Self::outcome`]'s reason.
    #[must_use]
    pub fn exit_code(&self) -> u8 {
        match self {
            Self::Version | Self::Protocol => exit::OK,
            // 3, not 4. `docs/architecture/CLI.md` reserves 4 for a refusal that
            // is a *decision about authority* — a project asking for privileges
            // it cannot be granted — where the user is the one who changes the
            // answer. This is not a decision about anything the user configured:
            // it is this build saying it cannot speak that protocol, and for one
            // of the two directions the remedy is literally a newer build, which
            // is what 3 is documented to mean.
            Self::Handshake(handshake) => {
                if handshake.is_agreed() {
                    exit::OK
                } else {
                    exit::UNAVAILABLE
                }
            }
            Self::Doctor(report) => {
                if report.is_well() {
                    exit::OK
                } else {
                    exit::NOT_GREEN
                }
            }
            // The three statuses `docs/architecture/CLI.md` gives a check: 0 for
            // a clean project, 1 for a project that was checked and is not clean,
            // 5 for a run that tried and did not finish. **1 and 3 are never
            // merged.** A project with problems is 1 — SURE did its job and the
            // answer is bad — and 3 stays for a command this build cannot carry
            // out, which is a different thing to say to a script: 3 means "ask a
            // newer SURE", and 1 means "look at the project".
            Self::Check(report) => {
                if !report.finished() {
                    exit::FAILED
                } else if report.is_green() {
                    exit::OK
                } else {
                    exit::NOT_GREEN
                }
            }
            // 0, including for a history that turned out to be empty and for a
            // delete whose scope matched nothing. Both are the whole of what the
            // user asked: a listing of nothing is a listing, and "remove every
            // session about this project" is satisfied when there are none. What
            // must never be 0 is a delete that *could not* happen — the store
            // unreadable, a row that would not go — and that is a
            // [`Self::Failed`], below.
            Self::History(_) => exit::OK,
            // 0 for both of the endings where the file says what the user asked
            // for — including the no-op, because what the user asked for is
            // true either way and a script that ran `config set` twice must not
            // read the second run as a failure. 5 for a refusal: SURE was asked
            // to do something, understood it, and did not do it.
            //
            // **Not 4.** `exit::REFUSED` is reserved for a refusal that is a
            // decision about authority, and this command exists on the other
            // side of that decision: it is how a user *makes* the grant that
            // `REFUSED` documents the absence of. Spending the code here would
            // make "your project asked for something it cannot have" and "you
            // asked for a setting this build will not write" the same status.
            Self::Settings(change) => match change.outcome {
                SettingsOutcome::Written | SettingsOutcome::AlreadySaid => exit::OK,
                SettingsOutcome::Refused { .. } => exit::FAILED,
            },
            Self::ConfigShow(_) | Self::Explain(_) => exit::OK,
            Self::Unavailable(_) => exit::UNAVAILABLE,
            Self::Failed(_) => exit::FAILED,
            // 0 for allow/warn so the launcher does not block the operation.
            // 1 for block so the launcher can relay the refusal.
            Self::HookDecision(decision) => match decision.decision {
                sure_core::hook_protection::ProtectionDecisionKind::Allow
                | sure_core::hook_protection::ProtectionDecisionKind::Warn => exit::OK,
                sure_core::hook_protection::ProtectionDecisionKind::Block => exit::NOT_GREEN,
            },
            // 0, and it is a user's own command that asked: the allowance is
            // written, or this is a [`Self::Failed`] above. Nothing about a
            // harness has been decided here, so no other status would be a
            // statement about this run.
            Self::HookAllowance(_) => exit::OK,
            // 3 rather than 0 for a message that says SURE could not answer, so
            // that the status and the outcome keep telling one story: `ok` is
            // the only outcome that may exit 0. It is not 1, because 1 says a
            // project has problems and a protocol error says nothing about any
            // project — and not 5, because nothing about this run went wrong; a
            // caller asked for something SURE does not do.
            Self::Mcp(message) => {
                if message.is_error() {
                    exit::UNAVAILABLE
                } else {
                    exit::OK
                }
            }
            Self::McpSession(_) => exit::OK,
        }
    }

    /// Whether the human form is an answer rather than a complaint.
    ///
    /// The one place that decides which stream the human form takes, so that
    /// the decision cannot differ between two call sites. An answer goes to
    /// stdout and a complaint to stderr, which is what makes
    /// `sure history > out.txt` leave the complaint on the terminal.
    ///
    /// `outcome()` is not the same question. A doctor report that found a
    /// problem is still an *answer* — `sure doctor > report.txt` has to put the
    /// report in the file, and the exit status is what carries the bad news. A
    /// complaint is SURE saying it could not do the thing at all.
    ///
    /// A handshake that did not agree is a complaint by that rule: there is no
    /// report to put in a file, and a caller that piped the output somewhere
    /// meant to read whether the two can talk. The *machine* form still goes to
    /// stdout, because a script asked for it in so many words.
    #[must_use]
    pub const fn is_an_answer(&self) -> bool {
        match self {
            Self::Version | Self::Protocol | Self::Doctor(_) => true,
            Self::Handshake(handshake) => handshake.is_agreed(),
            // A check that finished is an answer, exactly as a doctor report that
            // found a problem is one: `sure check > report.txt` has to put the
            // report in the file and let the exit status carry the bad news. A
            // check that did **not** finish is a complaint — there is no report
            // to file, and a person who piped the output meant to read why it
            // stopped.
            Self::Check(report) => report.finished(),
            // A history report is the answer to a question about this machine's
            // own store, and `sure history > history.txt` has to put it in the
            // file. `sure history delete` is the same: the sentences saying what
            // went are the point of the command, and a person who piped them
            // meant to keep them.
            Self::History(_) => true,
            // A write and a no-op are both answers: `sure config set … >
            // note.txt` has to put the sentence in the file, because the
            // sentence is the whole of what the command was asked for and there
            // is no other record of which of the two happened. A refusal is a
            // complaint, by the same rule every other refusal on this surface
            // follows: there is nothing to file, and a person who piped the
            // output meant to read why.
            Self::Settings(change) => !matches!(change.outcome, SettingsOutcome::Refused { .. }),
            Self::ConfigShow(_) | Self::Explain(_) => true,
            Self::Unavailable(_) | Self::Failed(_) => false,
            // A hook decision is an answer: the command ran and produced a result.
            Self::HookDecision(_) => true,
            // The same, for the user's own command: `sure hook allow-once >
            // allowance.txt` has to put the sentence in the file, because the
            // sentence is the whole of what the command was asked for.
            Self::HookAllowance(_) => true,
            // A protocol message is the session's answer to its caller, and it
            // goes to stdout whether or not it carries an error: an MCP client
            // reads refusals there too, and a refusal sent anywhere else is a
            // client waiting for an answer that never comes. Which is also why
            // the bridge writes this variant on the machine path only — see
            // `crate::mcp`.
            Self::Mcp(_) => true,
            // The other way round, and for a reason from the protocol rather
            // than from this crate: the specification says the server MUST NOT
            // write anything to its standard output that is not a valid MCP
            // message. The summary of a session is not one, so it is a
            // diagnostic — stderr, which is where `is_an_answer` sends the
            // human form of anything that is not an answer. A caller that ran
            // `sure --format json mcp serve` gets the envelope on stdout
            // instead; `docs/architecture/MCP_BRIDGE.md` says so, and the
            // harness integrations do not do it.
            Self::McpSession(_) => false,
        }
    }

    /// Write the human form.
    ///
    /// Takes the stream rather than reaching for one, so that
    /// [`Format::emit`](crate::output::Format::emit) is the only place in the
    /// crate that names `io::stdout` or `io::stderr`.
    ///
    /// # Errors
    ///
    /// Any failure from `out`.
    pub fn human(&self, out: &mut impl Write) -> io::Result<()> {
        match self {
            Self::Version => writeln!(out, "{}", sure_core::version_string()),
            // What an adapter needs in order to decide whether it can talk to
            // this build, and nothing else.
            Self::Protocol => writeln!(
                out,
                "Harness protocol version {}.",
                sure_core::PROTOCOL_VERSION
            ),
            // One sentence, whichever way it went, and it is the handshake's own
            // — the same sentence the event reader's refusal builds on. A
            // renderer that wrote its own could word the same answer another
            // way, and the two would then be two explanations of one rule.
            Self::Handshake(handshake) => writeln!(out, "{handshake}"),
            Self::Doctor(report) => crate::doctor::human(report, out),
            // The command's own module renders it, for the reason `doctor` above
            // does: the words a user reads for a report of this shape belong with
            // the command that produced it rather than in the type that carries
            // it.
            Self::Check(report) => crate::check::human(report, out),
            Self::History(report) => crate::history::human(report, out),
            // The command's own module renders it, for the reason `doctor` and
            // `check` above do, and one more that is particular to this one:
            // the sentence that says whether the file was written is the
            // acceptance criterion for the command, so it belongs beside the
            // code that decided which of the three things happened rather than
            // in a renderer that has to reconstruct it.
            Self::Settings(change) => crate::settings::human(change, out),
            Self::ConfigShow(report) => report.human(out),
            Self::Explain(report) => report.human(out),
            Self::Failed(failure) => {
                writeln!(
                    out,
                    "sure {command} could not finish.",
                    command = failure.command
                )?;
                writeln!(out)?;
                writeln!(out, "{}", failure.what)?;
                writeln!(out)?;
                writeln!(out, "{}", failure.detail)?;
                writeln!(out)?;
                writeln!(
                    out,
                    "SURE exited with status {}, which is what it returns when it tried and did \
                     not finish. That is not the same as a command this build cannot carry out, \
                     and not the same as a wrong command line.",
                    exit::FAILED
                )
            }
            Self::Unavailable(not_yet) => {
                let NotYet {
                    command,
                    does,
                    instead,
                } = not_yet;
                writeln!(out, "sure {command} is not implemented in this build.")?;
                writeln!(out)?;
                writeln!(out, "It will {does}. This build stops before that.")?;
                writeln!(out)?;
                writeln!(
                    out,
                    "{instead} SURE exited with status {} rather than {}, because work that was \
                     not done and work that succeeded must never look alike to a script.",
                    exit::UNAVAILABLE,
                    exit::OK
                )
            }
            Self::HookDecision(decision) => match decision.decision {
                sure_core::hook_protection::ProtectionDecisionKind::Allow => {
                    // An allow the rule reached carries the sentence it reached
                    // it with, and a user who reads the reason can tell a
                    // request SURE examined and found nothing in from one it
                    // never saw. `reason: None` is that second case — a
                    // lifecycle event, not a tool request — and it keeps the
                    // sentence it has always had.
                    match decision.reason.as_deref() {
                        Some(reason) => writeln!(out, "SURE allows this tool request. {reason}"),
                        None => writeln!(out, "SURE allows this tool request."),
                    }
                }
                sure_core::hook_protection::ProtectionDecisionKind::Warn => {
                    writeln!(
                        out,
                        "SURE advises caution: {}",
                        decision
                            .reason
                            .as_deref()
                            .unwrap_or("This action needs approval.")
                    )
                }
                sure_core::hook_protection::ProtectionDecisionKind::Block => {
                    writeln!(
                        out,
                        "SURE blocks this tool request: {}",
                        decision
                            .reason
                            .as_deref()
                            .unwrap_or("The current execution mode does not permit this action.")
                    )
                }
            },
            // What the user asked for is one sentence, and the conditions on it
            // are the rest: the grant covers one request that SURE itself holds
            // for one of the three dangerous acts *reachable under the settings
            // in force*, and it is spent by a request whose tool and words match
            // this one exactly. Every sentence is *would* rather than *will*:
            // both integrations are Observed (Tier 1), and this build cannot
            // confirm that a harness reads the answer — see
            // `docs/security/PROTECTION_MODE.md`.
            //
            // `P13-T010` rewrote this. It used to say that the first matching
            // request spends the grant and that SURE would let it through if it
            // named it as one of the three acts — unconditionally, and it was
            // the same in every project. Both halves were too much: a matching
            // request SURE does not hold spends nothing (the grant survives
            // it), and an act the settings in force cannot hold a request for
            // can never be the one a request is let through on. The acts now
            // come from `HookAllowance::acts`, which is what the writer read off
            // the settings, and the spend condition is stated as a condition.
            Self::HookAllowance(allowance) => {
                writeln!(
                    out,
                    "SURE recorded a one-time allowance for tool '{}', for the request '{}'.",
                    allowance.tool, allowance.subject
                )?;
                writeln!(out)?;
                writeln!(
                    out,
                    "It is for '{}' and it lasts {}. It is spent by the first request that \
                     matches both the tool and the words exactly and that SURE holds for one of \
                     the acts an allowance covers: under the settings in force when it was \
                     recorded, a request SURE would hold is one it would {}. A matching request \
                     SURE does not hold — one it allows outright, or one it refuses for another \
                     reason — spends nothing and leaves the allowance where it is.",
                    allowance.project,
                    minutes(allowance.minutes),
                    sure_core::hook_protection::Danger::in_a_sentence(&allowance.acts)
                )?;
                writeln!(out)?;
                writeln!(
                    out,
                    "SURE would then let that one request through. Any other request is held \
                     exactly as it was before, and a second request with the same words is not \
                     covered. Whether the request you named is one of those is decided when it \
                     arrives: this command does not read the words it is given for what they \
                     would do."
                )
            }
            // A protocol message has no human form: it is JSON-RPC and its
            // reader is a program. The arm is here because every variant has
            // both, and it writes the message itself rather than a rendering of
            // it, so that even a call site that took the human path by mistake
            // would put a line on the stream its caller can still parse.
            Self::Mcp(message) => writeln!(out, "{}", message.message),
            Self::McpSession(session) => {
                writeln!(
                    out,
                    "SURE spoke the Model Context Protocol on this process's standard input and \
                     output, and the caller closed them."
                )?;
                writeln!(out)?;
                match &session.agreed_protocol_version {
                    Some(agreed) => writeln!(out, "  handshake         agreed to speak {agreed}")?,
                    // The plainest true sentence available. A caller that never
                    // completed a handshake was answered, and answered with a
                    // refusal, but nothing agreed on a version.
                    None => writeln!(out, "  handshake         the caller never completed one")?,
                }
                // Kept beside the version SURE answered with, because a person
                // asking "why did it refuse my version" is asking for both.
                if let Some(requested) = &session.requested_protocol_version {
                    writeln!(out, "  caller asked for  {requested}")?;
                }
                writeln!(out, "  requests answered {}", session.answered)?;
                writeln!(out, "  notifications     {}", session.notifications)?;
                writeln!(out, "  tool calls        {}", session.tool_calls)?;
                writeln!(out, "  errors            {}", session.errors)?;
                writeln!(out)?;
                writeln!(
                    out,
                    "None of this is a claim about a project: it says how much of the protocol \
                     went past, and what went past inside each tool result was that command's own \
                     report, in that command's own words."
                )?;
                writeln!(out)?;
                writeln!(
                    out,
                    "SURE exited with status {}, which is what it returns when a session ends \
                     because its caller stopped asking. That is not a claim that a project is \
                     clean: the bridge itself checked nothing.",
                    exit::OK
                )
            }
        }
    }

    /// The human form, as a string.
    ///
    /// For the one caller that needs the words rather than a stream:
    /// `sure mcp serve` puts a command's own answer inside a tool result, and it
    /// has to be the same sentence the command line would have printed. A second
    /// rendering written in the bridge would be a second explanation of one
    /// refusal, free to drift from the first — and the refusal is the whole of
    /// what several of the tools answer today.
    ///
    /// Infallible, and says so by returning a `String` rather than a `Result`:
    /// [`Report::human`]'s only error is the writer's, and the writer here is a
    /// `Vec<u8>`, whose `write` returns `Ok` unconditionally. The lossy
    /// conversion is a total function over bytes this function has just written
    /// from `&str`s and integers — which is UTF-8 by construction — rather than
    /// a way of hiding a failure.
    #[must_use]
    pub fn human_text(&self) -> String {
        let mut buffer = Vec::new();
        let _ = self.human(&mut buffer);
        String::from_utf8_lossy(&buffer).into_owned()
    }

    /// Write the machine-readable form: one object, one line, no newline.
    ///
    /// # Errors
    ///
    /// Any failure from `out`, and any failure to serialize. Serialization
    /// cannot fail for a frame built here out of strings and integers, but it
    /// returns a `Result` all the same, and swallowing one would be the
    /// habit that gets a real failure dropped later.
    pub fn machine(&self, out: &mut impl Write) -> io::Result<()> {
        let frame = self.frame();
        serde_json::to_writer(&mut *out, &frame).map_err(io::Error::other)
    }

    /// The frame [`Report::machine`] writes.
    ///
    /// Public for the one caller that needs the value rather than the bytes:
    /// `sure mcp serve` puts a command's own frame, unmodified, inside a tool
    /// result, so that a caller reading a tool result is reading exactly what
    /// `sure … --format json` would have printed. Rendering it to a stream and
    /// parsing it back would be the same value with a way to be different.
    ///
    /// # Why `exit_code` is always here
    ///
    /// It was first written only for a refusal, on the idea that a field should
    /// appear when it says something. That is the wrong test for this one: it is
    /// one of the two things a caller switches on, and a frame where it is
    /// sometimes `null` is a frame a script has to special-case. The status the
    /// process returned is a fact about every run, so it is in every frame.
    #[must_use]
    pub fn frame(&self) -> serde_json::Value {
        // The one variant whose machine form is not this envelope: a protocol
        // message *is* the message, `id` and `result` and all, and it is
        // returned here before the envelope is built rather than assembled and
        // then replaced. See the module comment; the fields the envelope exists
        // for are inside the tool results, under `structuredContent.sure`.
        if let Self::Mcp(message) = self {
            return message.message.clone();
        }
        let mut frame = json!({
            "sure_version": env!("CARGO_PKG_VERSION"),
            "protocol_version": sure_core::PROTOCOL_VERSION,
            "command": self.command(),
            "outcome": self.outcome(),
            "exit_code": self.exit_code(),
        });
        match self {
            Self::Unavailable(not_yet) => {
                frame["does"] = json!(not_yet.does);
                frame["instead"] = json!(not_yet.instead);
            }
            // Everything a doctor run found, under one key, so that the fields
            // above keep meaning exactly what the module documentation says
            // they mean.
            Self::Doctor(report) => frame["details"] = crate::doctor::machine(report),
            // A caller that asked whether it can talk needs the two numbers side
            // by side and which side has to move. Deliberately no sentence here:
            // the frame is what a script reads, and a script that acts on prose
            // is a script that breaks when the prose is improved.
            Self::Handshake(handshake) => {
                frame["details"] = json!({
                    "sure_speaks": handshake.sure_speaks(),
                    "caller_speaks": handshake.caller_speaks(),
                    "agreed": handshake.is_agreed(),
                    "update": match handshake {
                        sure_core::Handshake::Agreed { .. } => None,
                        sure_core::Handshake::CallerIsOlder { .. } => Some("caller"),
                        sure_core::Handshake::CallerIsNewer { .. } => Some("sure"),
                    },
                });
            }
            // Everything the run found, under the one key, built by the command's
            // own module so that the shape a script reads is decided beside the
            // prose a person reads.
            Self::Check(report) => frame["details"] = crate::check::machine(report),
            // What the history command found, or removed, under the one key.
            // Built by the command's own module for the reason the arm above
            // gives, and built from the same values the human form renders, so
            // that a script and a person are reading one result.
            Self::History(report) => frame["details"] = crate::history::machine(report),
            // What was written and what the settings now allow, built by the
            // command's own module so that the shape a script reads is decided
            // beside the prose a person reads.
            Self::Settings(change) => frame["details"] = crate::settings::machine(change),
            Self::ConfigShow(report) => frame["details"] = report.machine(),
            Self::Explain(report) => frame["details"] = report.machine(),
            // The failure's own words. `what` is a sentence SURE wrote about
            // itself and `detail` is whatever went wrong, kept apart here for
            // the same reason they are apart in the struct: a reader deciding
            // whether to file a bug should not have to parse prose to find out.
            Self::Failed(failure) => {
                frame["details"] = json!({
                    "what": failure.what,
                    "detail": failure.detail,
                });
            }
            Self::Version | Self::Protocol => {}
            // Returned before the envelope was built, above. The arm is here
            // because the match is exhaustive, and it deliberately does
            // nothing: an envelope built for a message and then thrown away
            // would be work whose only purpose was to be discarded.
            Self::Mcp(_) => {}
            Self::HookDecision(decision) => {
                frame["decision"] = json!(decision.decision.as_str());
                if let Some(ref reason) = decision.reason {
                    frame["reason"] = json!(reason);
                }
            }
            // The grant the user just recorded, built from the same values the
            // human form renders. `grant` is the store row, so a script can find
            // the row again, `not_after_ms` is when the window closes, and
            // `acts` is what the settings in force leave for a request to be
            // held for — the three facts about an allowance that a reader
            // outside SURE has no other way to learn. `acts` is a list of the
            // stored names (`Danger::wire_name`), not the sentences the human
            // form writes, for the reason the enum gives: a script reads this,
            // and a sentence may be reworded.
            Self::HookAllowance(allowance) => {
                frame["details"] = json!({
                    "tool": allowance.tool,
                    "subject": allowance.subject,
                    "project": allowance.project,
                    "minutes": allowance.minutes,
                    "grant": allowance.grant,
                    "not_after_ms": allowance.not_after_ms,
                    "acts": allowance
                        .acts
                        .iter()
                        .map(|danger| danger.wire_name())
                        .collect::<Vec<_>>(),
                });
            }
            // The session summary is a report like any other and keeps the
            // envelope, so that `sure --format json mcp serve` writes something
            // a reader can line up with every other frame. See
            // `Report::is_an_answer` for why the bridge itself writes this one
            // on the human path, and `docs/architecture/MCP_BRIDGE.md` for the
            // rule a caller has to keep.
            Self::McpSession(session) => {
                frame["details"] = json!({
                    "initialized": session.initialized,
                    "requested_protocol_version": session.requested_protocol_version,
                    "agreed_protocol_version": session.agreed_protocol_version,
                    "answered": session.answered,
                    "notifications": session.notifications,
                    "tool_calls": session.tool_calls,
                    "errors": session.errors,
                });
            }
        }
        frame
    }

    /// Which command produced this.
    ///
    /// An exhaustive match with no fallback arm, so a new report cannot be
    /// added without naming the command it answers.
    #[must_use]
    pub const fn command(&self) -> &'static str {
        match self {
            Self::Version => "version",
            Self::Protocol | Self::Handshake(_) => "protocol",
            Self::Doctor(_) => "doctor",
            // The command the user typed, taken from the report rather than
            // fixed here: `sure check`, `sure recheck` and `sure repair` share
            // this variant, and a frame that said `check` for all three would
            // name a command the user did not run.
            Self::Check(report) => report.command,
            // The command the user typed, taken from the report rather than
            // fixed here, for the same reason as the arm above: `list`, `show`
            // and `delete` share this variant, and a frame that said `history`
            // for all three would not name the one that was run — which matters
            // most for the one that deletes.
            Self::History(report) => report.command,
            // The command the user typed, taken from the report rather than
            // fixed here: the frame names `config set` rather than `config`,
            // for the same reason the arm above names `history delete` rather
            // than `history`. The rest of `sure config` still refuses, and a
            // frame that said `config` for a write would name a surface that
            // does not exist.
            Self::Settings(change) => change.command,
            Self::ConfigShow(_) => "config show",
            Self::Explain(_) => "explain",
            Self::Unavailable(not_yet) => not_yet.command,
            Self::Failed(failure) => failure.command,
            Self::HookDecision(_) => "hook",
            // The same command name for the other half of `sure hook`: this is a
            // subcommand of the entry point a harness calls, and the frame names
            // the command the user typed, which is `hook` either way.
            Self::HookAllowance(_) => "hook",
            // The command a user types, for both of the bridge's reports: the
            // session and the messages in it are `sure mcp serve`, and a frame
            // that named anything else would name a command that does not exist
            // on this surface. The tool a message answers for is inside the
            // message, under `structuredContent.tool`.
            Self::Mcp(_) | Self::McpSession(_) => "mcp",
        }
    }
}

/// A number of minutes as a user reads it.
///
/// `1 minutes` is the kind of line that makes a reader stop trusting the rest of
/// the sentence, and the allowance's window is the one number a user has to act
/// on before it closes.
fn minutes(count: u32) -> String {
    if count == 1 {
        "1 minute".to_owned()
    } else {
        format!("{count} minutes")
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn text(report: &Report, machine: bool) -> String {
        let mut buffer = Vec::new();
        if machine {
            report.machine(&mut buffer).unwrap();
        } else {
            report.human(&mut buffer).unwrap();
        }
        String::from_utf8(buffer).unwrap()
    }

    fn a_refusal() -> NotYet {
        NotYet {
            command: "history",
            does: "show what SURE has recorded, on this machine and for this project",
            instead: "Nothing was read from the history, and nothing was deleted.",
        }
    }

    /// A doctor report carrying the given problems.
    ///
    /// Built rather than produced by `sure_core::doctor::examine`, because what
    /// is under test in this module is the frame, the status and the stream —
    /// not what happens to be in a temporary directory. `is_well` is decided by
    /// `problems` alone, so this is enough to drive both outcomes, and the
    /// end-to-end shape is `tests/cli_contract.rs`'s subject.
    fn a_doctor_report(problems: Vec<sure_core::doctor::Problem>) -> Report {
        use sure_core::doctor::{Build, DoctorReport, Places, StoreState};

        Report::Doctor(Box::new(DoctorReport {
            build: Build {
                version: "0.0.0-test".to_owned(),
                protocol_version: 1,
                os: "test",
                arch: "test",
                target_env: "test",
                running_from: None,
            },
            places: Places::Unknown {
                what: "its evidence and history",
                detail: "not this test's subject".to_owned(),
            },
            store: StoreState::NotLookedFor,
            tools: Vec::new(),
            // Empty for the same reason the locations above are unknown: this
            // fixture exists to drive the frame, the status and the stream, and
            // what a machine happens to have installed is not this test's
            // subject. The shape of a filled-in report is `doctor.rs`'s own
            // tests and `tests/cli_contract.rs`'s.
            toolchain: Vec::new(),
            container: sure_core::container::Availability::Absent,
            providers: Vec::new(),
            integrations: Vec::new(),
            problems,
            not_checked: Vec::new(),
        }))
    }

    fn a_problem() -> sure_core::doctor::Problem {
        sure_core::doctor::Problem {
            what: "SURE has recorded history on this machine and cannot read it.",
            detail: "the file is not a database".to_owned(),
        }
    }

    /// A goal SURE wrote into the user's history at the start of a run.
    fn a_recorded_goal() -> GoalRecorded {
        GoalRecorded {
            goal: "make the upload reject a file over 10 MB".to_owned(),
            requirement_id: "goal".to_owned(),
            source: sure_core::intent::IntentSource::ExplicitUserGoal,
            project_root: "C:\\work\\thing".to_owned(),
            project_state: sure_core::vocabulary::ProjectFingerprint::content("2f9c1a04"),
            record: 7,
        }
    }

    /// Every stage, recorded as having run.
    ///
    /// Built rather than taken from a real run because what these tests decide
    /// is the frame, the status and the stream — the stage log's own content is
    /// `sure_core::pipeline`'s subject and `tests/check_pipeline.rs`'s. A stage
    /// log with nothing in it would make `PipelineOutcome::stage` unreachable,
    /// which is why it is built from `Stage::ALL` rather than left empty.
    fn every_stage_ran() -> Vec<sure_core::pipeline::StageRecord> {
        sure_core::pipeline::Stage::ALL
            .iter()
            .map(|&stage| sure_core::pipeline::StageRecord {
                stage,
                outcome: sure_core::pipeline::StageOutcome::Ran {
                    detail: format!("{} did its work.", stage.title()),
                },
            })
            .collect()
    }

    /// A finished check of a project this build reports as not clean.
    ///
    /// `clean` decides whether the run's single planned check passed, which is
    /// the difference between exit 0 and exit 1. It is the same run either way:
    /// the schedule, the stage log and the project state are unchanged, because
    /// the only thing that differs between a clean project and an unclean one is
    /// what the checks found.
    fn a_check_run(clean: bool) -> sure_core::pipeline::RunOutcome {
        use sure_core::evidence::EvidenceClass;
        use sure_core::execution::{ActionKind, ExecutionMode};
        use sure_core::planned_work::{CheckOperation, PlannedWork, PrecomputedEvidence};
        use sure_core::schedule::{CheckProposal, CheckReason, PlanBuilder};
        use sure_core::severity::Severity;
        use sure_core::status::CheckResult;

        let mode = ExecutionMode::InspectOnly;
        let mut builder = PlanBuilder::new(mode, mode.baseline_permissions());
        builder
            .propose(PlannedWork::new(
                CheckProposal::new(
                    sure_core::checks::check_id("sure.test", "read-the-manifest"),
                    "Read the project's manifest",
                    Severity::Note,
                    false,
                    EvidenceClass::ObservedFact,
                    CheckReason::FilePresent {
                        path: "package.json".to_owned(),
                    },
                    &[ActionKind::ReadFile],
                ),
                // Nothing here runs a check: this stands in for a scheduled result
                // so that the report's frame and stream can be graded. The most
                // conservative thing an unrun check can say about itself.
                CheckOperation::Precomputed(PrecomputedEvidence::candidate(
                    "this fixture builds a plan and observes nothing",
                )),
            ))
            .unwrap();
        let schedule = builder.build();

        let state = sure_core::vocabulary::ProjectFingerprint::content("2f9c1a04");
        let id = schedule.checks()[0].proposal().id().clone();
        let results = if clean {
            vec![CheckResult::pass(
                id,
                "Read the project's manifest",
                Severity::Note,
                false,
                EvidenceClass::ObservedFact,
                state.id.clone(),
            )]
        } else {
            Vec::new()
        };
        let report =
            sure_core::aggregation::aggregate_run(&schedule, &results, &[], &state.id).unwrap();
        let capability = sure_core::capability::CapabilityReport::cli();
        let coverage = sure_core::coverage_summary::summarize(&schedule, &report, &capability);
        let intent = sure_core::intent::ProjectIntent::empty();
        let not_checked = if clean {
            Vec::new()
        } else {
            report.results().to_vec()
        };
        let verdict = sure_core::project_verdict::build_verdict(
            state.id.clone(),
            report.aggregate().clone(),
            intent.clone(),
            capability,
            Vec::new(),
            not_checked,
            Vec::new(),
        );

        sure_core::pipeline::RunOutcome {
            project_root: "C:\\work\\thing".to_owned(),
            mode,
            permissions: mode.baseline_permissions(),
            project_state: state,
            support: sure_core::vocabulary::ProjectSupport::new(
                sure_core::vocabulary::SupportLevel::InspectOnly,
                "the test fixture is a project SURE can read and cannot run.",
            ),
            intent_caveat: intent.caveat(),
            intent,
            schedule,
            report,
            coverage,
            verdict,
            candidates: sure_core::pipeline::Candidates::default(),
            claims: Vec::new(),
            repairs: Vec::new(),
            lifecycle: None,
        }
    }

    /// `sure check PATH` over a project that is not clean, with the goal the user
    /// typed on the command line in it.
    fn a_check() -> Report {
        Report::Check(Box::new(CheckReport {
            command: "check",
            project: "C:\\work\\thing".to_owned(),
            run: sure_core::pipeline::PipelineOutcome {
                purpose: sure_core::pipeline::Purpose::Check,
                stages: every_stage_ran(),
                run: Some(a_check_run(false)),
                stopped_at: None,
            },
            privacy: no_settings_file(),
            model_use: sure_core::privacy::ModelUse::NoProvider,
            recorded_goal: Some(a_recorded_goal()),
            grants: no_grants(),
        }))
    }

    /// `sure check PATH` over a clean project.
    fn a_clean_check() -> Report {
        Report::Check(Box::new(CheckReport {
            command: "check",
            project: "C:\\work\\thing".to_owned(),
            run: sure_core::pipeline::PipelineOutcome {
                purpose: sure_core::pipeline::Purpose::Check,
                stages: every_stage_ran(),
                run: Some(a_check_run(true)),
                stopped_at: None,
            },
            privacy: no_settings_file(),
            model_use: sure_core::privacy::ModelUse::NoProvider,
            recorded_goal: None,
            grants: no_grants(),
        }))
    }

    /// `sure check PATH` over a project SURE could not read.
    fn a_check_that_did_not_finish() -> Report {
        let mut stages = every_stage_ran();
        let stopped = sure_core::pipeline::Stage::Discover;
        stages.truncate(stopped.number() as usize - 1);
        stages.push(sure_core::pipeline::StageRecord {
            stage: stopped,
            outcome: sure_core::pipeline::StageOutcome::Unfinished {
                detail: "the directory could not be read".to_owned(),
            },
        });
        Report::Check(Box::new(CheckReport {
            command: "check",
            project: "C:\\work\\thing".to_owned(),
            run: sure_core::pipeline::PipelineOutcome {
                purpose: sure_core::pipeline::Purpose::Check,
                stages,
                run: None,
                stopped_at: Some(stopped),
            },
            privacy: no_settings_file(),
            model_use: sure_core::privacy::ModelUse::NoProvider,
            recorded_goal: None,
            grants: no_grants(),
        }))
    }

    /// The statement for a run whose machine has no settings file at all.
    ///
    /// The fields are written out here rather than read through
    /// `PrivacyStatement::of`, because there is no file for these fixtures to
    /// read: what they need is the value a machine that has never been
    /// configured produces, and writing it as the default is the same value
    /// without a filesystem. The arbitration itself is tested where it lives —
    /// `crates/sure-core/src/privacy.rs` — rather than a second time here.
    fn no_settings_file() -> sure_core::privacy::PrivacyStatement {
        use sure_core::config::{AnalysisProvider, PrivacyMode};
        sure_core::privacy::PrivacyStatement {
            mode: PrivacyMode::default(),
            mode_set_by: None,
            project_mode: PrivacyMode::default(),
            provider: AnalysisProvider::default(),
        }
    }

    /// What the settings allow on a machine with no settings file.
    ///
    /// Built through [`crate::grants::Grants::of`] rather than written out field
    /// by field, because the value these tests are about is the one the product
    /// derives: a literal here would be a second answer to "what does a machine
    /// with nothing configured allow", free to disagree with the first.
    fn no_grants() -> crate::grants::Grants {
        let authority = sure_core::config::Authority::new(
            None,
            sure_core::config::LoadedConfig {
                config: sure_core::config::Config::default(),
                source: sure_core::config::ConfigSource::NoFile,
                searched: std::path::PathBuf::from("sure.yaml"),
            },
        );
        crate::grants::Grants::of(&authority, std::path::Path::new("sure.yaml"))
    }

    /// A command that tried and did not finish.
    fn a_failure() -> Report {
        Report::Failed(Box::new(Failed {
            command: "check",
            what: "Nothing was recorded and nothing was checked.",
            detail: "the store is locked by another process".to_owned(),
        }))
    }

    /// A one-time allowance the user recorded, as `sure hook allow-once` reports
    /// one. The words are a user's own — this report never carries a harness's.
    ///
    /// The two acts are the ones a project that may run its own code reaches a
    /// hold through: the subject is a shell command, which is held for a danger
    /// only where `execution.mode` lets project code run, so a report carrying
    /// this subject cannot also carry `SensitiveRead` — that one comes through
    /// strict mode's read rule and a shell request never reaches it.
    fn a_recorded_allowance() -> Report {
        Report::HookAllowance(Box::new(HookAllowance {
            tool: "Bash".to_owned(),
            subject: "rm -rf build/".to_owned(),
            project: "C:\\work\\app".to_owned(),
            minutes: sure_core::allowance::DEFAULT_MINUTES,
            grant: 41,
            not_after_ms: 1_700_001_800_000,
            acts: vec![
                sure_core::hook_protection::Danger::BroadDelete,
                sure_core::hook_protection::Danger::ForcePush,
            ],
        }))
    }

    /// A JSON-RPC error object: a request SURE would not carry out.
    fn a_protocol_error() -> Report {
        Report::Mcp(Box::new(McpMessage {
            message: json!({
                "jsonrpc": "2.0",
                "id": 2,
                "error": {
                    "code": -32602,
                    "message": "Unknown tool: sure_wibble",
                },
            }),
        }))
    }

    /// A response carrying a tool result, either way round.
    ///
    /// Built here rather than by running the bridge, because what this module
    /// decides is the outcome and the stream of a message; what the bridge puts
    /// in one is `crate::mcp`'s subject and `tests/mcp_protocol.rs`'s.
    fn a_tool_result(is_error: bool) -> Report {
        Report::Mcp(Box::new(McpMessage {
            message: json!({
                "jsonrpc": "2.0",
                "id": 3,
                "result": {
                    "content": [{"type": "text", "text": "Nothing was checked."}],
                    "structuredContent": {
                        "tool": "sure_check",
                        "sure": {"command": "check", "outcome": "unavailable", "exit_code": 3},
                    },
                    "isError": is_error,
                },
            }),
        }))
    }

    /// A session that ended because its caller closed standard input.
    fn a_session() -> Report {
        Report::McpSession(Box::new(McpSession {
            initialized: true,
            requested_protocol_version: Some("2025-11-25".to_owned()),
            agreed_protocol_version: Some("2025-11-25".to_owned()),
            answered: 3,
            notifications: 1,
            tool_calls: 2,
            errors: 2,
        }))
    }

    /// A session whose caller never sent `initialize`.
    fn a_session_that_never_handshook() -> Report {
        Report::McpSession(Box::new(McpSession {
            initialized: false,
            requested_protocol_version: None,
            agreed_protocol_version: None,
            answered: 1,
            notifications: 0,
            tool_calls: 0,
            errors: 1,
        }))
    }

    /// Every report this build can produce.
    ///
    /// Every *shape* of report, which is what the frame, the outcome and the
    /// stream are decided by — not every value any of them can carry. The one
    /// shape with a value worth varying is the handshake, where both directions
    /// are here because both have to be renderable.
    fn every_report() -> Vec<Report> {
        vec![
            Report::Version,
            Report::Protocol,
            Report::Handshake(sure_core::negotiate(sure_core::PROTOCOL_VERSION)),
            Report::Handshake(sure_core::negotiate(sure_core::PROTOCOL_VERSION + 1)),
            Report::Handshake(sure_core::negotiate(0)),
            a_doctor_report(Vec::new()),
            a_doctor_report(vec![a_problem()]),
            a_clean_check(),
            a_check(),
            a_check_that_did_not_finish(),
            a_failure(),
            Report::Unavailable(a_refusal()),
            Report::HookDecision(sure_core::hook_protection::ProtectionDecision::allow()),
            Report::HookDecision(sure_core::hook_protection::ProtectionDecision::warn(
                "This action needs explicit approval before it can run.",
            )),
            Report::HookDecision(sure_core::hook_protection::ProtectionDecision::block(
                "The current execution mode does not permit this action.",
            )),
            a_recorded_allowance(),
            a_protocol_error(),
            a_tool_result(false),
            a_tool_result(true),
            a_session(),
            a_session_that_never_handshook(),
        ]
    }

    /// Every report whose machine form is the CLI envelope.
    ///
    /// [`Report::Mcp`] is not one of them: its machine form is the JSON-RPC
    /// message itself, which is the exception the module comment records and the
    /// reason the bridge needs no second path out of the program. The fields
    /// the envelope exists for are still in the answer — every tool result
    /// carries the command's own frame under `structuredContent.sure` — but
    /// they are not in *this* frame. So the two tests that assert the envelope
    /// holds for every report hold it for every report that has one, by name
    /// rather than by quietly skipping a variant.
    fn reports_in_the_cli_envelope() -> Vec<Report> {
        every_report()
            .into_iter()
            .filter(|report| !matches!(report, Report::Mcp(_)))
            .collect()
    }

    #[test]
    fn the_machine_form_is_one_line() {
        // A pipeline reading a stream of responses splits on newlines, so a
        // pretty-printed frame would be a frame and a half of somebody's output.
        for report in every_report() {
            let written = text(&report, true);
            assert!(
                !written.contains('\n'),
                "the machine form of {report:?} is not one line: {written}"
            );
        }
    }

    #[test]
    fn the_machine_form_names_the_build_and_the_protocol() {
        // The two facts that decide whether a captured response can still be
        // read. A frame without them is one a reader has to guess about.
        for report in reports_in_the_cli_envelope() {
            let frame: serde_json::Value = serde_json::from_str(&text(&report, true)).unwrap();
            assert_eq!(
                frame["protocol_version"],
                json!(sure_core::PROTOCOL_VERSION)
            );
            assert_eq!(
                frame["sure_version"],
                json!(env!("CARGO_PKG_VERSION")),
                "the frame's version is not this build's"
            );
            assert_eq!(frame["command"], json!(report.command()));
            assert_eq!(frame["outcome"], json!(report.outcome()));
            assert_eq!(frame["exit_code"], json!(report.exit_code()));
        }
    }

    #[test]
    fn every_frame_carries_the_status_the_process_returns() {
        // Including the ones that are fine. A field that is present only when
        // something went wrong is a field every reader has to guard, and the
        // status is a fact about every run.
        for report in reports_in_the_cli_envelope() {
            let frame: serde_json::Value = serde_json::from_str(&text(&report, true)).unwrap();
            assert!(
                frame["exit_code"].is_u64(),
                "{} produced a frame with no exit_code: {frame}",
                report.command()
            );
        }
    }

    #[test]
    fn a_doctor_report_that_found_a_problem_is_still_an_answer() {
        // The stream depends on whether SURE could do the thing, not on whether
        // the news is good. `sure doctor > report.txt` has to put the report in
        // the file; the status is what carries the bad news.
        let unhappy = a_doctor_report(vec![a_problem()]);
        assert!(unhappy.is_an_answer());
        assert_eq!(unhappy.outcome(), "not_green");
        assert_eq!(unhappy.exit_code(), exit::NOT_GREEN);
        assert_ne!(
            unhappy.exit_code(),
            exit::UNAVAILABLE,
            "a doctor that found a problem did not fail to run"
        );

        let happy = a_doctor_report(Vec::new());
        assert!(happy.is_an_answer());
        assert_eq!(happy.outcome(), "ok");
        assert_eq!(happy.exit_code(), exit::OK);
    }

    #[test]
    fn a_doctor_report_carries_what_it_found_in_one_place() {
        // The frame's fixed fields keep meaning what the module says they mean,
        // and everything a command found goes under `details`.
        let frame: serde_json::Value =
            serde_json::from_str(&text(&a_doctor_report(Vec::new()), true)).unwrap();
        let details = &frame["details"];
        assert!(details.is_object(), "doctor reported nothing: {frame}");
        for key in [
            "build",
            "places",
            "store",
            "tools",
            "problems",
            "not_checked",
        ] {
            assert!(
                details.get(key).is_some(),
                "a doctor report with no {key:?} is one a reader cannot use: {details}"
            );
        }
    }

    #[test]
    fn the_version_in_the_frame_is_the_one_the_version_command_prints() {
        // Two spellings of one fact. The prose says "SURE 0.1.2" and
        // the frame says "0.1.2", and if they were allowed to drift
        // the machine form would be the one that is wrong without anyone
        // noticing, because it is the one nobody reads.
        let printed = text(&Report::Version, false);
        let printed = printed.trim();
        assert!(
            printed.ends_with(env!("CARGO_PKG_VERSION")),
            "\"{printed}\" does not name this build"
        );
    }

    #[test]
    fn every_refusal_says_what_sure_did_instead_and_what_it_costs() {
        let written = text(&Report::Unavailable(a_refusal()), false);
        for needed in [
            "Nothing was read from the history, and nothing was deleted.",
            "status 3",
            "rather than 0",
            "not implemented in this build",
        ] {
            assert!(
                written.contains(needed),
                "the refusal does not say {needed:?}:\n{written}"
            );
        }
    }

    #[test]
    fn an_answer_and_a_complaint_are_not_the_same_thing() {
        // The stream the human form takes. `sure check > report.txt` must leave
        // the complaint on the terminal.
        assert!(Report::Version.is_an_answer());
        assert!(Report::Protocol.is_an_answer());
        assert!(a_doctor_report(Vec::new()).is_an_answer());
        assert!(
            Report::Handshake(sure_core::negotiate(sure_core::PROTOCOL_VERSION)).is_an_answer()
        );
        assert!(
            !Report::Handshake(sure_core::negotiate(sure_core::PROTOCOL_VERSION + 1))
                .is_an_answer()
        );
        assert!(!Report::Unavailable(a_refusal()).is_an_answer());
        // A check that ran is an answer whether or not the news is good, and a
        // check that did not finish is a complaint: there is no report to file.
        assert!(a_check().is_an_answer());
        assert!(a_clean_check().is_an_answer());
        assert!(!a_check_that_did_not_finish().is_an_answer());
        assert!(!a_failure().is_an_answer());
    }

    #[test]
    fn a_project_that_was_checked_and_is_not_clean_exits_one_and_never_three() {
        // The rule `docs/architecture/CLI.md` states and this test exists to
        // hold: 1 and 3 are never merged. Status 1 is "SURE did its job and the
        // answer is bad" and status 3 is "this build cannot carry the command
        // out". A script that saw 3 for a project with problems would go looking
        // for a newer SURE instead of at the project.
        let report = a_check();

        assert_eq!(report.exit_code(), exit::NOT_GREEN);
        assert_ne!(report.exit_code(), exit::UNAVAILABLE);
        assert_ne!(report.exit_code(), exit::OK);
        assert_ne!(report.exit_code(), exit::FAILED);
        assert_eq!(report.outcome(), "not_green");
        assert_eq!(report.command(), "check");
    }

    #[test]
    fn a_clean_project_exits_zero() {
        // The other end of the same rule, and the one a false green would break
        // first: 0 is reachable, and it is reachable only through the pipeline's
        // own answer rather than through anything this module decides.
        let report = a_clean_check();

        assert_eq!(report.exit_code(), exit::OK);
        assert_eq!(report.outcome(), "ok");
    }

    #[test]
    fn a_run_that_tried_and_did_not_finish_exits_five() {
        // Not 3: this build can carry the command out and something went wrong
        // trying. Not 1: nothing was established about the project, and saying
        // "not clean" would be a claim about a project SURE never read.
        let report = a_check_that_did_not_finish();

        assert_eq!(report.exit_code(), exit::FAILED);
        assert_ne!(report.exit_code(), exit::UNAVAILABLE);
        assert_ne!(report.exit_code(), exit::NOT_GREEN);
        assert_eq!(report.outcome(), "failed");
    }

    #[test]
    fn a_goal_recorded_before_the_check_is_in_the_run_s_own_report() {
        // The one place a command changes something its output would not
        // otherwise contain. A report that checked the project and said nothing
        // about the write would leave a user unable to tell whether their words
        // are in their history.
        let report = a_check();

        let written = text(&report, false);
        assert!(
            written.contains("make the upload reject a file over 10 MB"),
            "the report does not say what was recorded:\n{written}"
        );
        // The domain's own sentence about the label, not a second wording.
        assert!(
            written.contains(sure_core::intent::IntentSource::ExplicitUserGoal.plain_description()),
            "the report does not say what the source is worth:\n{written}"
        );

        let frame: serde_json::Value = serde_json::from_str(&text(&report, true)).unwrap();
        let goal = &frame["details"]["recorded_goal"];
        assert_eq!(goal["record"], json!(7));
        assert_eq!(goal["requirement_id"], json!("goal"));
        // The wire name in the frame, the sentence in the prose: one value, two
        // renderings, and the reader switches on the machine one.
        assert_eq!(goal["source"], json!("explicit_user_goal"));
        // Which state, in the two fields that answer it: a digest two runs can
        // compare, and the kind that says how it was computed.
        assert_eq!(goal["project_state"]["digest"], json!("2f9c1a04"));
        assert_eq!(goal["project_state"]["kind"], json!("content"));
        assert!(
            goal["project_state"]["id"]
                .as_str()
                .is_some_and(|id| !id.is_empty()),
            "the run's own fingerprint identity is missing from the frame: {goal}"
        );
    }

    #[test]
    fn a_check_that_recorded_no_goal_answers_with_null_and_not_a_placeholder() {
        // The absence of a write is a fact about the run, and a frame that
        // carried a placeholder goal would read as one that was stored. The key
        // is present and `null`, which is how this frame spells "did not
        // happen" everywhere else — `reason` and `stopped_at` are the same.
        let frame: serde_json::Value = serde_json::from_str(&text(&a_clean_check(), true)).unwrap();
        assert!(
            frame["details"]["recorded_goal"].is_null(),
            "a run with no --goal reported one: {frame}"
        );
    }

    #[test]
    fn a_command_that_did_not_finish_is_not_a_command_that_cannot_be_carried_out() {
        // Two answers that look alike from a distance and need opposite
        // responses: "wait for a newer build" and "something is broken, here is
        // what". One status for both is how a broken tool gets read as a tool
        // with nothing to do.
        let report = a_failure();

        assert_eq!(report.exit_code(), exit::FAILED);
        assert_ne!(report.exit_code(), exit::UNAVAILABLE);
        assert_ne!(report.exit_code(), exit::OK);
        assert_eq!(report.outcome(), "failed");
        assert_eq!(report.command(), "check");

        let written = text(&report, false);
        assert!(
            written.contains("the store is locked by another process"),
            "the failure does not carry what went wrong:\n{written}"
        );
        assert!(
            written.contains("Nothing was recorded and nothing was checked."),
            "the failure does not say what did not happen:\n{written}"
        );
        assert!(
            written.contains(&exit::FAILED.to_string()),
            "the failure does not say what it exits with:\n{written}"
        );
        assert!(
            !written.contains("not implemented in this build"),
            "a run that tried must not be worded as a command this build lacks:\n{written}"
        );

        let frame: serde_json::Value = serde_json::from_str(&text(&report, true)).unwrap();
        assert_eq!(
            frame["details"]["detail"],
            json!("the store is locked by another process")
        );
        assert_eq!(
            frame["details"]["what"],
            json!("Nothing was recorded and nothing was checked.")
        );
    }

    #[test]
    fn a_handshake_that_did_not_agree_stops_a_caller_and_says_which_side_moves() {
        // The reason the handshake exists: an adapter that is told "no" has to
        // be able to tell whether to update itself or SURE, and it has to be
        // stopped from sending anything in the meantime. Status 3 is what stops
        // it, and it is not 0.
        for caller in [0, sure_core::PROTOCOL_VERSION + 1] {
            let report = Report::Handshake(sure_core::negotiate(caller));
            assert_eq!(report.exit_code(), exit::UNAVAILABLE);
            assert_ne!(report.exit_code(), exit::OK);
            assert_eq!(report.outcome(), "unavailable");
            assert!(!report.is_an_answer());
            assert_eq!(report.command(), "protocol");

            let sentence = text(&report, false);
            assert!(
                sentence.contains(&caller.to_string()),
                "the caller is not told what it spoke: {sentence}"
            );
            assert!(
                sentence.contains(&format!("speaks {}", sure_core::PROTOCOL_VERSION)),
                "the caller is not told what SURE speaks: {sentence}"
            );

            let frame: serde_json::Value = serde_json::from_str(&text(&report, true)).unwrap();
            let expected = if caller < sure_core::PROTOCOL_VERSION {
                "caller"
            } else {
                "sure"
            };
            assert_eq!(
                frame["details"]["update"], expected,
                "the frame does not say which side has to move: {frame}"
            );
            assert_eq!(frame["details"]["caller_speaks"], json!(caller));
            assert_eq!(frame["details"]["agreed"], json!(false));
        }
    }

    #[test]
    fn a_handshake_that_agreed_is_an_answer_a_caller_can_act_on() {
        // The other half, and the one a working adapter sees on every run: exit
        // 0, on stdout, with both numbers present so that a caller can check
        // what it was told rather than take it on faith.
        let report = Report::Handshake(sure_core::negotiate(sure_core::PROTOCOL_VERSION));

        assert_eq!(report.exit_code(), exit::OK);
        assert_eq!(report.outcome(), "ok");
        assert!(report.is_an_answer());

        let frame: serde_json::Value = serde_json::from_str(&text(&report, true)).unwrap();
        assert_eq!(frame["details"]["agreed"], json!(true));
        assert_eq!(
            frame["details"]["sure_speaks"],
            json!(sure_core::PROTOCOL_VERSION)
        );
        assert!(
            frame["details"]["update"].is_null(),
            "an agreement says nothing has to be updated: {frame}"
        );
        assert!(
            frame["details"]["caller_speaks"].is_null(),
            "the agreed version is SURE's own and is already in the frame: {frame}"
        );
    }

    #[test]
    fn nothing_that_is_unavailable_exits_zero() {
        // The whole point of the exit status. A command SURE cannot carry out
        // that exited 0 would be SURE's own false green, produced by the
        // program that exists to prevent them.
        let report = Report::Unavailable(a_refusal());
        assert_eq!(report.exit_code(), exit::UNAVAILABLE);
        assert_ne!(report.exit_code(), exit::OK);
        assert_eq!(report.outcome(), "unavailable");
    }

    #[test]
    fn every_outcome_name_is_one_of_the_documented_ones() {
        const DOCUMENTED: &[&str] = &["ok", "not_green", "unavailable", "failed"];
        for report in every_report() {
            assert!(
                DOCUMENTED.contains(&report.outcome()),
                "{} is not an outcome docs/architecture/CLI.md lists",
                report.outcome()
            );
        }
    }

    #[test]
    fn the_outcome_and_the_status_tell_the_same_story() {
        // Two spellings of one decision, and they must not drift. `ok` is the
        // only outcome that may exit 0; everything else stops a script.
        for report in every_report() {
            let clean = report.outcome() == "ok";
            assert_eq!(
                clean,
                report.exit_code() == exit::OK,
                "{} says {:?} and exits {}",
                report.command(),
                report.outcome(),
                report.exit_code()
            );
        }
    }

    #[test]
    fn a_message_that_says_sure_could_not_answer_is_not_ok() {
        // The bridge's version of the rule this whole program exists for, and
        // the reason `McpMessage::is_error` reads a tool result's `isError` and
        // not only a JSON-RPC error object: every tool whose command this build
        // cannot carry out answers with a result carrying `isError`, and a
        // predicate that looked only for an error object would call
        // "sure check is not implemented in this build" an `ok` message that
        // exits 0. That is SURE's own false green, told to an agent.
        for refused in [a_protocol_error(), a_tool_result(true)] {
            assert_eq!(refused.outcome(), "unavailable");
            assert_eq!(refused.exit_code(), exit::UNAVAILABLE);
            assert_ne!(refused.exit_code(), exit::OK);
            assert_ne!(
                refused.exit_code(),
                exit::NOT_GREEN,
                "a protocol refusal is not a statement about a project"
            );
            assert_ne!(
                refused.exit_code(),
                exit::FAILED,
                "nothing about a refusal is a run that went wrong"
            );
        }
        let answered = a_tool_result(false);
        assert_eq!(answered.outcome(), "ok");
        assert_eq!(answered.exit_code(), exit::OK);
    }

    #[test]
    fn the_machine_form_of_a_message_is_the_message_itself() {
        // The documented exception to the envelope, asserted so that it stays a
        // decision. A frame that grew a `sure_version` and tucked the message
        // under `details` would be unreadable to every MCP client, and no other
        // test in this file would notice.
        let report = a_tool_result(true);
        let Report::Mcp(message) = &report else {
            panic!("this builder makes a message");
        };
        let frame: serde_json::Value = serde_json::from_str(&text(&report, true)).unwrap();
        assert_eq!(&frame, &message.message);
        assert_eq!(frame["jsonrpc"], json!("2.0"));
        assert!(
            frame.get("sure_version").is_none() && frame.get("exit_code").is_none(),
            "the CLI envelope was wrapped around a protocol message: {frame}"
        );
    }

    #[test]
    fn a_message_has_no_human_form_and_is_not_rendered_as_one() {
        // A protocol message is JSON-RPC and its reader is a program, so the
        // human rendering is the message. It is written that way rather than
        // left as an empty arm so that a call site which took the human path by
        // mistake would still put a parseable line on the stream.
        let report = a_tool_result(false);
        assert_eq!(text(&report, false).trim_end(), text(&report, true));
        assert_eq!(report.command(), "mcp");
    }

    #[test]
    fn the_session_summary_is_a_diagnostic_and_a_message_is_not() {
        // Which stream, decided once by `is_an_answer` and for a reason that
        // comes from the protocol rather than from this crate: the
        // specification says an MCP server MUST NOT write anything to its
        // standard output that is not a valid MCP message. A summary of the
        // session is not one, so it is a diagnostic. A message — including one
        // that refuses the caller — is exactly what the caller is reading
        // stdout for.
        assert!(!a_session().is_an_answer());
        assert!(!a_session_that_never_handshook().is_an_answer());
        assert!(a_tool_result(false).is_an_answer());
        assert!(a_protocol_error().is_an_answer());
    }

    #[test]
    fn a_session_summary_does_not_claim_anything_about_a_project() {
        // The one thing a status-looking report must not do. It names the
        // version that was agreed and what went past, and it says in the
        // user's own words that none of it is a verdict.
        let written = text(&a_session(), false);
        for needed in [
            "agreed to speak 2025-11-25",
            "requests answered 3",
            "not a claim that a project is clean",
            "status 0",
        ] {
            assert!(
                written.contains(needed),
                "the session summary does not say {needed:?}:\n{written}"
            );
        }
        assert_eq!(a_session().exit_code(), exit::OK);
        assert_eq!(a_session().command(), "mcp");

        // A caller that never handshook gets the true sentence rather than the
        // one that would claim a version was agreed.
        let never = text(&a_session_that_never_handshook(), false);
        assert!(
            never.contains("the caller never completed one"),
            "a session with no handshake claims one:\n{never}"
        );
        assert!(
            !never.contains("agreed to speak"),
            "a session with no handshake claims a version:\n{never}"
        );
    }

    #[test]
    fn a_recorded_allowance_names_the_acts_the_settings_left_for_it() {
        // The confirmation is the only thing the user has to go on, and
        // `P13-T010` is about the half of it that was unconditional: it promised
        // that the first matching request would be let through without saying
        // that SURE has to hold that request for one of three acts, and it named
        // the acts a project could not hold a request for. So this asserts both
        // halves — the spend condition is stated as a condition, and the acts
        // named are the ones the writer actually read off the settings.
        let written = text(&a_recorded_allowance(), false);
        for needed in [
            "delete a whole location",
            "overwrite published commits",
            "spent by the first request that matches both the tool and the words exactly",
            "spends nothing and leaves the allowance where it is",
            "decided when it arrives",
            // Acceptance line 4's reading, in the sentence and not only in the
            // hand-back: the acts are read off the settings in force *when the
            // grant is recorded*, because a user who changes their settings
            // afterwards has changed what the grant can be spent on.
            "under the settings in force when it was recorded",
        ] {
            assert!(
                written.contains(needed),
                "the confirmation does not say {needed:?}:\n{written}"
            );
        }
        assert!(
            !written.contains("read a file of credentials"),
            "the confirmation named an act the settings in force cannot hold \
             a request for:\n{written}"
        );

        // And a report carrying one act names one act. The fixture above is a
        // shell subject, which cannot also carry the read; this is the project
        // where the read is the only act left.
        let read_only = Report::HookAllowance(Box::new(HookAllowance {
            tool: "Read".to_owned(),
            subject: ".env".to_owned(),
            project: "C:\\work\\app".to_owned(),
            minutes: sure_core::allowance::DEFAULT_MINUTES,
            grant: 42,
            not_after_ms: 1_700_001_800_000,
            acts: vec![sure_core::hook_protection::Danger::SensitiveRead],
        }));
        let written = text(&read_only, false);
        assert!(
            written.contains("read a file of credentials"),
            "the confirmation dropped the act the settings left:\n{written}"
        );
        assert!(
            !written.contains("delete a whole location"),
            "the confirmation named an act the settings cannot hold a request \
             for:\n{written}"
        );

        // The machine form carries the same three acts under their stored
        // names, which is what a script has instead of a sentence.
        let frame = a_recorded_allowance().frame();
        assert_eq!(
            frame["details"]["acts"],
            json!(["broad_delete", "force_push"]),
            "the frame does not name the acts the settings left"
        );
        assert_eq!(a_recorded_allowance().exit_code(), exit::OK);
    }
}
