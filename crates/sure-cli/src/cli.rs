//! The command surface, as a grammar.
//!
//! `docs/architecture/CLI.md` is the authority for what these commands mean and
//! which phase implements each one. This module is only the shape: what SURE
//! accepts, and what it refuses before a command body is ever reached.
//!
//! # Why the grammar is one type
//!
//! [`Command`] is the whole surface in one enum, and
//! [`Command::report`](crate::commands::Command::report) matches on it
//! exhaustively. Adding a command to the grammar therefore cannot leave the
//! build compiling with no answer about whether this build implements it: the
//! match stops compiling until the new arm says.
//!
//! # What is deliberately not here
//!
//! No command carries a flag that only a later phase can honour. A grammar that
//! accepts `--deep` and does nothing with it is the CLI teaching a user that
//! SURE understood them when it did not, and the user has no way to tell.
//! Arguments arrive with the phase that can act on them.

use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};

use crate::output::Format;

/// `sure`.
#[derive(Debug, Parser)]
#[command(
    name = "sure",
    version,
    about = "SURE — Software Understanding & Reality Evaluation",
    long_about = "AI says it's done. Be SURE.\n\n\
                  SURE checks what was actually built, records what it found, and says what it \
                  could not confirm. Every result is a record with evidence behind it, or it is \
                  not reported.",
    // A bare `sure` did nothing, so it is not a success. clap writes the help
    // to stderr and exits 2, which is the same answer a wrong flag gets.
    arg_required_else_help = true
)]
pub struct Cli {
    /// How to write results. `human` is for reading, `json` is for scripts.
    ///
    /// Global, so it is accepted before or after the command name. It is the
    /// only place the choice is made: nothing else in this binary decides which
    /// of the two output paths runs, and
    /// `tests/cli_contract.rs` checks that no other module writes to stdout.
    #[arg(long, value_enum, default_value_t = Format::Human, global = true)]
    pub format: Format,

    /// Keep this run's record store in DIR instead of the platform's per-user
    /// location. DIR must be an absolute path.
    ///
    /// Global, and named only on a command line: this is how a test, a script or
    /// a user keeps a run's evidence away from the machine's own store. SURE
    /// reads no file and no environment variable for it — a checked project's
    /// own configuration could set either, and a store a project can point
    /// somewhere is a store a project can point at a place it can write. See
    /// `sure_core::paths`'s module documentation, and `sure doctor`, which
    /// reports which location this run used.
    ///
    /// The location is checked like any other: a directory inside the project
    /// being checked is refused when the run opens a store there — `sure check`
    /// opens one only when it is already there, so it meets the refusal exactly
    /// then — and a relative or empty path is refused before SURE runs anything
    /// at all. `docs/architecture/CLI.md` records the three measured states.
    #[arg(long, value_name = "DIR", global = true, value_parser = a_store_directory)]
    pub store_dir: Option<PathBuf>,

    /// Read this run's user-level settings from FILE instead of the platform's
    /// per-user location. FILE must be an absolute path.
    ///
    /// A **testing and automation** surface rather than something a user needs:
    /// the settings file is `%APPDATA%\SURE\sure.yaml` on Windows and the
    /// equivalent per-user configuration directory elsewhere, and a person who
    /// wants to change a setting edits that file. This option exists so that a
    /// test, a script or a harness can run SURE under settings it wrote, without
    /// touching the file of whoever is running it — which is how the privacy
    /// corpus drives a full recording through a real process
    /// (`fixtures/privacy/manifest.json`), and how a suite can drive both the
    /// default answer and a consented one on one machine.
    ///
    /// It grants nothing the user's own file could not: the file is read at the
    /// same layer, by the same reader (`sure_core::config::authority`), so a
    /// project's `sure.yaml` still cannot turn recording on or let SURE run
    /// project code through it. Like `--store-dir` it comes from this process's
    /// argument vector and from nowhere else — there is no environment variable
    /// for either, because a checked project's harness configuration can set the
    /// environment of the processes it starts. And it cannot be used to take
    /// authority from the project: a file inside the project being judged is
    /// refused before a run reads it, and `docs/architecture/CLI.md` says so.
    #[arg(long, value_name = "FILE", global = true, value_parser = a_settings_file)]
    pub settings_file: Option<PathBuf>,

    /// Read user-declared check commands from FILE instead of planning a
    /// discovered stack's checks. FILE must be an absolute path outside the
    /// project.
    ///
    /// The file names a program and its arguments per role (`test`, `build`,
    /// `lint`, `typecheck`); SURE never splits a shell string. This is for a
    /// project whose build system SURE does not discover — a Makefile, a shell
    /// script — where the person running SURE is the only one who can say what
    /// command answers a role. A role the file omits is recorded as not
    /// declared rather than silently dropped.
    #[arg(long, value_name = "FILE", global = true, value_parser = a_commands_file)]
    pub commands_file: Option<PathBuf>,

    /// The command to run.
    #[command(subcommand)]
    pub command: Command,
}

/// A store directory as a caller names it: absolute, or refused here.
///
/// Refused at the grammar rather than later because a relative path is a wrong
/// command line, not a run that failed: whether such a path was inside the
/// project would depend on which directory SURE happened to be started in, and
/// the answer to a question like that is not a verdict. The rule is
/// [`sure_core::paths::store_directory`]'s — one implementation, called from the
/// run-time resolution as well — and the message is [`sure_core::paths::PathError`]'s
/// own, so the reason is stated in the same words wherever it is refused. The
/// status for it is the wrong-command-line status, not a status that says SURE
/// tried something.
fn a_store_directory(text: &str) -> Result<PathBuf, String> {
    sure_core::paths::store_directory(Path::new(text)).map_err(|error| error.to_string())
}

/// A settings file as a caller names it: absolute, or refused here.
///
/// The same rule and the same reasoning as [`a_store_directory`], from the same
/// module: a relative settings file would be resolved against the current
/// directory, so whether it was inside the project being judged would depend on
/// where SURE happened to be started — and this is the file that decides what the
/// run may do, so "inside the project" is the one answer that must not be a
/// matter of chance. The check that the file is not inside the project is *not*
/// here: the project is not known until a command knows it, and it is
/// [`sure_core::paths::Paths::ensure_settings_outside`]'s, called where it is.
fn a_settings_file(text: &str) -> Result<PathBuf, String> {
    sure_core::paths::settings_file(Path::new(text)).map_err(|error| error.to_string())
}

/// A commands file as a caller names it: absolute, or refused here.
///
/// The same location rule as a settings file, and the same reason: SURE cannot
/// decide whether a relative path is inside the project until it has the
/// project, so it refuses the relative path at the grammar.
fn a_commands_file(text: &str) -> Result<PathBuf, String> {
    sure_core::paths::settings_file(Path::new(text)).map_err(|error| error.to_string())
}

/// Every command SURE accepts.
///
/// `docs/architecture/CLI.md` lists the same set in the same order. The doc and
/// this enum are two views of one list, and `tests/cli_contract.rs` checks they
/// agree by asking this build what it parses.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Check a project and report what was found.
    Check {
        /// The project to check. Default: the current directory.
        path: Option<PathBuf>,

        /// What you want the project to do, in your own words.
        ///
        /// This is the one channel the project cannot write, and the reason it
        /// exists: a goal found in a README or in `sure.yaml` is documentation,
        /// because the agent whose work is being checked can edit both. A goal
        /// typed here is a user requirement, and SURE may compare the project
        /// against it — see `docs/architecture/PROJECT_INTENT.md`.
        ///
        /// The wording is kept exactly as given. SURE does not summarize it,
        /// rewrap it or trim it, because a goal that lost a clause on the way in
        /// is a requirement the user never stated.
        #[arg(long, value_name = "TEXT")]
        goal: Option<String>,
    },

    /// Check a project again, after a repair, and compare with last time.
    Recheck {
        /// The project to re-check. Default: the current directory.
        path: Option<PathBuf>,
    },

    /// Turn what was found into instructions a coding agent can act on.
    Repair {
        /// The project to produce repair instructions for. Default: the
        /// current directory.
        path: Option<PathBuf>,
    },

    /// Record that you reviewed a finding and accept the risk it describes.
    ///
    /// Only a finding no check can settle may be accepted (ADR 0019): a
    /// candidate a scanner inferred, or a model opinion. A failing test, a
    /// checker error and a check that did not run are defects and gaps to fix,
    /// and SURE refuses to record them as accepted risks.
    ///
    /// The decision is written to your own store outside the project, so the
    /// project — which the agent under judgement can edit — cannot add, remove
    /// or soften one. It names the finding's evidence: if that evidence changes,
    /// the acceptance stops applying and the finding comes back for review.
    #[command(group(
        clap::ArgGroup::new("acknowledge-action")
            .required(true)
            .multiple(false)
    ))]
    Acknowledge {
        /// The project the finding belongs to. Default: the current directory.
        path: Option<PathBuf>,

        /// The finding id to accept, as `sure check` printed it (`fnd_…`).
        #[arg(long, value_name = "ID", group = "acknowledge-action")]
        finding: Option<String>,

        /// A report written by `sure check --format json`, where the finding id
        /// was printed.
        ///
        /// A plain `sure check` records nothing, so its finding ids exist only
        /// in the report it printed. Name the file the report was written to and
        /// the id resolves against it; without this flag the id is looked up in
        /// this project's recorded findings, which `sure repair` and `sure
        /// recheck` write.
        #[arg(long, value_name = "FILE", requires = "finding")]
        from: Option<PathBuf>,

        /// Why you accepted it. Required with --finding, and recorded with the
        /// decision so a reader later knows what was reviewed.
        #[arg(long, value_name = "TEXT", requires = "finding")]
        reason: Option<String>,

        /// List what this project has accepted, and why.
        #[arg(long, group = "acknowledge-action")]
        list: bool,

        /// Remove one recorded acceptance by its record id.
        #[arg(long, value_name = "RECORD", group = "acknowledge-action")]
        undo: Option<i64>,
    },

    /// Look at what SURE has recorded.
    History {
        /// What to do with the history. Default: `list`.
        #[command(subcommand)]
        action: Option<HistoryAction>,
    },

    /// Report on this machine: where SURE keeps things, and what it found.
    Doctor,

    /// Look at the configuration SURE is using, and where it came from.
    Config {
        /// What to show. Default: a summary of every layer.
        #[command(subcommand)]
        action: Option<ConfigAction>,
    },

    /// The entry points a coding harness calls.
    Hook {
        /// What the harness wants SURE to do.
        #[command(subcommand)]
        action: HookAction,
    },

    /// Explain one recorded finding or check result in plain language.
    Explain {
        /// The finding id, check-result id, or store row. Default: the most
        /// recent recorded finding; if none, the most recent check result.
        id: Option<String>,
    },

    /// Speak the Model Context Protocol to a coding harness on standard input
    /// and standard output.
    ///
    /// Listed by `docs/architecture/MCP_BRIDGE.md` and named by the harness
    /// integrations as `sure mcp serve`. See `crate::mcp` for what this build
    /// answers a caller and why it is written through the same dispatch as
    /// every other command.
    Mcp {
        /// What SURE should do with the MCP bridge.
        #[command(subcommand)]
        action: McpAction,
    },

    /// Print the version of the harness protocol this build speaks.
    Protocol {
        /// Check whether this build can talk to a caller that speaks this
        /// protocol version.
        ///
        /// A caller that already knows what it was built against asks with
        /// this, and SURE answers — so that the rule about which versions can
        /// talk lives in one place instead of in every adapter's language. See
        /// `sure_protocol::handshake`.
        #[arg(long, value_name = "VERSION")]
        speaks: Option<u32>,
    },

    /// Print the version of this build.
    Version,
}

/// What `sure history` can be asked to do.
#[derive(Debug, Clone, Subcommand)]
pub enum HistoryAction {
    /// List the sessions SURE has recorded on this machine, newest first.
    ///
    /// A session is what a harness's work was recorded as: one per conversation
    /// with an agent, one per project. The list says what is there and what is
    /// not — that there are none is an answer, not an empty table.
    List {
        /// How many sessions to show. The listing always says how many the
        /// store holds, so a page is never mistaken for the whole history.
        #[arg(
            long,
            value_name = "N",
            default_value_t = crate::history::DEFAULT_LIMIT,
            value_parser = clap::value_parser!(u64).range(1..)
        )]
        limit: u64,
    },
    /// Show one session, and the events recorded in it.
    Show {
        /// SURE's own session id, as `sure history` prints it.
        ///
        /// Required. `sure history show` with nothing to show would be a
        /// listing under a name that promises one session, and the id is the
        /// one thing a user can copy out of the listing.
        id: String,
    },
    /// Delete sessions, and everything recorded in them.
    ///
    /// **Exactly one scope is required, and nothing prompts.** The scope is on
    /// the command line, so a script can run this and a person can read what it
    /// will do before it does it, and neither can delete by accident by
    /// answering a question SURE asked. `docs/architecture/CLI.md` records the
    /// decision.
    #[command(group(
        clap::ArgGroup::new("scope")
            .required(true)
            .multiple(false)
            .args(["all", "session", "project"])
    ))]
    Delete {
        /// Every session in this store.
        #[arg(long)]
        all: bool,

        /// One session, by SURE's session id.
        #[arg(long, value_name = "SURE_SESSION_ID")]
        session: Option<String>,

        /// Every session recorded against one project root, exactly as
        /// `sure history` prints it.
        #[arg(long, value_name = "PROJECT_ROOT")]
        project: Option<String>,
    },
    /// Write the history out as JSON (not implemented in this build).
    Export,
}

/// What `sure config` can be asked to do.
#[derive(Debug, Subcommand)]
pub enum ConfigAction {
    /// Show where SURE keeps its files on this machine (not implemented in this build).
    Paths,
    /// Show the settings in effect and which layer each came from.
    Show {
        /// The project whose `sure.yaml` is read. Default: the user's own
        /// settings only; the project layer is not read.
        path: Option<PathBuf>,
    },
    /// Report problems in the configuration without checking the project (not implemented in this build).
    Validate,
    /// Write one setting into your own settings file, outside every project.
    ///
    /// # Why this exists, and why it is here rather than in a file editor
    ///
    /// Full recording and every execution mode other than `inspect_only` are
    /// granted by the user's own settings file and by nothing else: a checked
    /// project's `sure.yaml` may ask for them and can never grant them
    /// (`Layer::can_grant`). Before this command there was no way for a person
    /// to act on that sentence — the file had no writer, and nothing told them
    /// where it would be. A rule a user cannot satisfy is not a rule, it is a
    /// refusal with no remedy, and SURE would report a setting as not in force
    /// and name no way to put it in force.
    ///
    /// This command writes **only that file**, only on request, and only the
    /// settings it can prove a run reads from it. Whether the path it writes is
    /// even allowed is the same question a run asks about the file it reads
    /// (`Paths::ensure_settings_outside`), so no path of this command reaches a
    /// project's own `sure.yaml`, and a setting whose value a run reads from the
    /// project's file is refused rather than written where it would do nothing.
    /// The reasoning per setting, and the edit's safety net, are in
    /// `crate::settings`.
    Set {
        /// The setting to write, as `<group>.<name>` — `execution.mode`, for
        /// instance. `sure config set` with no settings refuses and lists the
        /// ones it will write.
        #[arg(value_name = "SETTING")]
        setting: String,
        /// What to set it to: `true` or `false`, one of a setting's own words,
        /// or a whole number of days.
        #[arg(value_name = "VALUE")]
        value: String,
    },
}

/// What a harness can ask `sure mcp` to do.
///
/// `serve` is not optional, for `sure hook`'s reason: a `sure mcp` that ran
/// nothing would be a harness reading "SURE is listening" out of a process that
/// had already exited. `sure mcp` on its own is a wrong command line, status 2.
#[derive(Debug, Subcommand)]
pub enum McpAction {
    /// Speak MCP over standard input and output until the caller closes it.
    ///
    /// The caller launches this process; SURE never listens on anything. See
    /// `crate::mcp::serve` for the transport and the handshake, and
    /// `docs/architecture/MCP_BRIDGE.md` for what each tool answers today.
    Serve,
}

/// What a harness can ask `sure hook` to do.
#[derive(Debug, Subcommand)]
pub enum HookAction {
    /// Take one harness event and record it.
    ///
    /// The harness writes JSON to stdin. The event is normalised, validated,
    /// and persisted. For `pre-tool-use` events a protection decision is also
    /// evaluated and written to stdout as JSON.
    Ingest {
        /// Which harness sent the event.
        #[arg(long, value_name = "NAME")]
        source: Option<String>,

        /// The kind of event, as named by the harness.
        event_kind: Option<String>,
    },
    /// Record a one-time allowance for one request SURE would otherwise hold.
    ///
    /// The tool and the subject are the harness's own words, spelled exactly as
    /// the harness sends them: the command line for a shell tool, the path for
    /// a tool that names one. The first request that matches both **exactly**
    /// spends the allowance, and nothing else about SURE changes — the
    /// allowance covers the three acts `docs/security/THREAT_MODEL.md` calls
    /// dangerous and no others, and it is never a way to run under execution
    /// settings the user did not change.
    ///
    /// This is a command a **person** runs. Nothing a project's files or an
    /// agent's output can say records an allowance, because a hook cannot ask a
    /// user for consent and this is that answer, given by a user, on purpose.
    ///
    /// Both integrations are capability tier 1 (Observed): SURE records what it
    /// would do, and cannot confirm what a harness does with the answer. See
    /// `docs/security/PROTECTION_MODE.md`.
    #[command(group(
        clap::ArgGroup::new("subject")
            .required(true)
            .multiple(false)
            .args(["command", "path"])
    ))]
    AllowOnce {
        /// The tool name, exactly as the harness sends it.
        #[arg(long, value_name = "NAME")]
        tool: String,

        /// The command line, exactly as the harness would send it.
        #[arg(long, value_name = "WORDS")]
        command: Option<String>,

        /// The path, exactly as the harness would send it.
        #[arg(long, value_name = "PATH")]
        path: Option<String>,

        /// The project the allowance is for. Default: the current directory.
        ///
        /// It has to be the directory the harness reports as the request's
        /// project — the one `sure hook ingest` reads out of the event — or the
        /// two are different projects and the allowance is never spent. Run
        /// this from the project, or name it here.
        #[arg(long, value_name = "DIR")]
        project: Option<PathBuf>,

        /// How long the allowance lasts, in minutes. One day is the longest
        /// SURE records, and thirty minutes is what it records when the user
        /// does not say.
        #[arg(
            long,
            value_name = "MINUTES",
            default_value_t = sure_core::allowance::DEFAULT_MINUTES
        )]
        minutes: u32,
    },
}

impl Command {
    /// The command as a user would type it.
    ///
    /// Used for the `command` field of the machine-readable frame and for the
    /// first line of a refusal, so the two cannot name different things.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Check { .. } => "check",
            Self::Recheck { .. } => "recheck",
            Self::Repair { .. } => "repair",
            Self::Acknowledge { .. } => "acknowledge",
            Self::History { .. } => "history",
            Self::Doctor => "doctor",
            Self::Config { .. } => "config",
            Self::Hook { .. } => "hook",
            Self::Explain { .. } => "explain",
            Self::Mcp { .. } => "mcp",
            Self::Protocol { .. } => "protocol",
            Self::Version => "version",
        }
    }
}
