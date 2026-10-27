//! What each command does in this build.
//!
//! # One match, and no default arm
//!
//! [`Command::report`] is the only dispatch in the program, and it matches every
//! variant of `Command` by name. There is no `_ =>` and no `unreachable!()`.
//! That is the whole design: a command added to the grammar stops this file
//! compiling until somebody decides whether this build implements it, and the
//! answer is either a real result or a [`NotYet`].
//!
//! The alternative — a default arm returning "not implemented" — would let a
//! command ship as a stub that nobody chose to make a stub, and `sure check`
//! answering "not implemented" forever would look exactly like `sure check`
//! answering "not implemented until P2".
//!
//! # Where the command names come from
//!
//! [`not_yet`] takes the `&Command` rather than a name, and asks it. A refusal
//! that retyped "check" could name a command other than the one the user typed,
//! and nothing would catch it. The one command whose name is not its own is
//! `history`, which can be asked to do things with different consequences; see
//! [`crate::history::name`].
//!
//! # Why so few commands work
//!
//! The ones that do answer questions about SURE or about this machine rather
//! than about a project: `version`, `protocol` and `doctor`; then `hook`, which
//! records what a harness sends; `mcp`, which is the bridge a harness speaks to;
//! and `history`, which is what this machine has recorded. Every other command
//! needs the check engine. Saying so is not a gap in this task; it is the task.
//! `docs/architecture/CLI.md` records what each command is for, and this file is
//! where the ones that cannot run say so to the user rather than to a reader of
//! the docs.
//!
//! `history` is the one of those that a user reaches for *because* of what SURE
//! kept, which makes it the one place where this build's output is about
//! somebody's own data rather than about their project. `crate::history` is
//! where what it may show, and what it may remove, is decided.
//!
//! # Where `sure mcp serve` sits
//!
//! It is the one command that is carried out *and* whose work is mostly other
//! commands'. It speaks the Model Context Protocol, and each of the tools it
//! exposes is one [`Command`] value put through [`Command::report`] — the same
//! dispatch every other command goes through, so the MCP surface cannot check,
//! repair or report anything by a path of its own, and cannot answer a caller
//! with words the command line would not use. When a tool's command is not
//! implemented in this build, the tool call is a *tool error carrying that
//! command's refusal*, not a refusal of `sure mcp`: the caller asked for a
//! check, and telling it that the bridge is missing would name the wrong thing.
//!
//! The arm below therefore has two jobs at once, and they are worth separating:
//! it decides that MCP is implemented (rather than a [`NotYet`]), and it hands
//! the session to [`crate::mcp`], which decides what every message in it
//! answers. What it must never do is answer a tool call itself.

use std::path::Path;

use sure_core::pipeline::Purpose;

/// The two locations a caller can name on the command line, and nothing else.
///
/// A value rather than two arguments passed to every command, because the two
/// are both `Option<&Path>` and a command that swapped them would compile: the
/// settings file would be created as a store directory and the store's directory
/// would be read as settings. Naming the fields is what makes a call site say
/// which is which.
///
/// `None` in either field means the platform's own location, which is what a
/// caller who names nothing gets. Both values come from the process's own
/// argument vector — `--store-dir` and `--settings-file` — and from nowhere
/// else; `sure_core::paths` says why there is no environment variable for
/// either.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Named<'a> {
    /// The directory this run's record store lives in.
    pub store: Option<&'a Path>,
    /// The file this run reads its user-level settings from.
    ///
    /// The file that may grant what the user's own settings file may grant, and
    /// the one `crate::mcp` refuses outright: see [`Command::report`].
    pub settings_file: Option<&'a Path>,
    /// The file this run reads user-declared check commands from, if any.
    pub commands_file: Option<&'a Path>,
}

impl<'a> Named<'a> {
    /// A run that named a store directory and no settings file.
    #[must_use]
    pub fn store(store: &'a Path) -> Self {
        Self {
            store: Some(store),
            settings_file: None,
            commands_file: None,
        }
    }
}

use crate::cli::{Command, ConfigAction};
use crate::report::{NotYet, Report};

/// The commands this build carries out.
///
/// Every other command answers [`Report::Unavailable`]. Written as a list
/// rather than derived at run time, because deriving it would mean *running*
/// each command to find out what it does — `sure doctor` examines this machine
/// and `sure check` will one day read a project, and a status question must not
/// cause either. A test,
/// `the_commands_this_build_implements_are_exactly_these_three`, asks the
/// dispatch what it answers for every command in the grammar and fails when
/// this list and the dispatch disagree, so the two cannot drift apart quietly.
/// `mcp` is the one name that test cannot ask about, because asking would start
/// a session that reads standard input; it is removed by name there, and what
/// it answers is checked over a pipe instead.
///
/// `sure mcp serve` answers a caller's `sure_status` from this list rather than
/// from one of its own: a tool that said "checking works" while `sure check`
/// refused would be SURE's own false green, told to an agent.
///
/// `mcp` is in the list because it is true, not because a caller needs telling:
/// the caller is already speaking to it through this process. It is listed
/// under the name a user types, which is what a caller comparing this list
/// against `sure --help` will find there.
pub const IMPLEMENTED: &[&str] = &[
    "check", "doctor", "explain", "history", "hook", "mcp", "protocol", "recheck", "repair",
    "version",
];

/// Invocations that work while the command they belong to does not.
///
/// [`IMPLEMENTED`] holds command *names*, and a name is a claim about a whole
/// documented surface: `sure check` is in it because every form of `sure check`
/// this build accepts does what `docs/architecture/CLI.md` says it does. `sure
/// config set` writes one setting and `sure config show` reads the settings in
/// effect, and `sure config` itself, `sure config paths` and `sure config
/// validate` still answer [`Report::Unavailable`].
///
/// So `config` is **not** in [`IMPLEMENTED`], and the reason is not tidiness.
/// That list is what `sure mcp` reports to an agent as `commands_implemented`
/// and what every tool description reads to decide whether to say its command
/// works. Putting `config` there would tell an agent that every form of `sure
/// config` answers, while `config paths` and `config validate` still refuse.
/// Leaving it out is the same fact in the safe direction, and this constant is
/// where the safe direction is made precise rather than merely cautious: the
/// invocations below really do work, and a reader who wants to know which ones
/// asks here instead of concluding that nothing in `config` does.
///
/// # What keeps this honest
///
/// A list of invocations that work is exactly the kind of list that goes stale
/// silently, so a test drives each entry through [`Command::report`] and fails
/// unless it is a report this build produced rather than a refusal —
/// `an_invocation_this_build_implements_in_part_really_answers`. The same test
/// proves every entry's command name is absent from [`IMPLEMENTED`] (so an entry
/// here can never be a weaker duplicate of a claim there) and present in the
/// grammar (so a literal here is tied to a command that exists).
pub const IMPLEMENTED_IN_PART: &[&str] = &["config set", "config show"];

/// The implemented commands that this build's own tests must not ask.
///
/// Not a second list of what works — [`IMPLEMENTED`] is that, and this is a
/// subset of it. It is the answer to "why is this name missing from the
/// invocations the tests drive?", asked once so that a name cannot go missing
/// for a reason nobody wrote down. The test
/// `the_commands_this_build_implements_are_exactly_these_three` proves every
/// name here is in [`IMPLEMENTED`], that every other name in it *is* driven,
/// and that each of these is a command the grammar really has.
///
/// `check`, `recheck` and `repair` each run the whole pipeline over a project,
/// and the project is the whole of their answer: a run of one here would check
/// this crate's own directory, which is what none of these tests is about. They
/// are driven instead by `tests/cli_contract.rs`, against a project it makes.
/// See `every_command` in the tests below.
pub const NOT_ASKED_HERE: &[&str] = &["check", "recheck", "repair"];

impl Command {
    /// What SURE does about this command, in this build.
    ///
    /// `named` is what the caller named on the command line — the store
    /// directory and the settings file, each `None` for the platform's own
    /// location. Both come from [`crate::cli::Cli`] and from nowhere else, they
    /// mean what [`sure_core::paths::Paths::discover_with`] says they mean, and
    /// they are passed down rather than discovered again here so that one run
    /// cannot read one store and write another, or decide under one settings
    /// file and record under another.
    ///
    /// **One command refuses the settings file outright, and this is where that
    /// is said**: [`crate::mcp`], whose own documentation argues it. Every other
    /// command reads it the way it reads the platform's own, and refuses it when
    /// the project being judged could write it
    /// ([`sure_core::paths::Paths::ensure_settings_outside`]).
    #[must_use]
    pub fn report(&self, named: Named<'_>) -> Report {
        match self {
            // The three this build can answer. All three are questions about
            // SURE or about this machine rather than about a project, which is
            // why none of them needs a check engine.
            Self::Version => Report::Version,
            // Asked with nothing, this is what SURE speaks. Asked with
            // `--speaks`, it is whether SURE can talk to that caller — and the
            // answer is `sure_core::negotiate`'s, the same function the event
            // reader uses to refuse a document. A CLI that decided this for
            // itself could tell an adapter yes and then refuse its events.
            Self::Protocol { speaks: None } => Report::Protocol,
            Self::Protocol {
                speaks: Some(caller),
            } => Report::Handshake(sure_core::negotiate(*caller)),
            // The examination happens here rather than in `Report`, so that the
            // report stays a value — something a test can build and a renderer
            // can read — instead of a thing that goes and looks.
            Self::Doctor => Report::Doctor(Box::new(sure_core::doctor::examine_this_machine_with(
                named.store,
                named.settings_file,
            ))),

            // The three commands that put a project through the check pipeline.
            // One arm each rather than one arm matching all three, because the
            // *purpose* is the only thing that differs between them and it is a
            // value — [`sure_core::pipeline::Purpose`] — so the difference is
            // stated here, in the shape the orchestrator takes, rather than
            // depending on a string a renderer would have to interpret.
            //
            // `sure check --goal` is the one command on the surface with a side
            // effect a user cannot see in the output: the goal goes into their
            // history before the check runs. That decision is `crate::check`'s,
            // and it is written down there.
            Self::Check { path, goal } => {
                crate::check::run(Purpose::Check, path.as_deref(), goal.as_deref(), named)
            }
            Self::Recheck { path } => {
                crate::check::run(Purpose::Recheck, path.as_deref(), None, named)
            }
            Self::Repair { path } => {
                crate::check::run(Purpose::Repair, path.as_deref(), None, named)
            }

            // The whole inspect-and-delete surface. It goes through
            // `crate::history` for `Self::Doctor`'s reason — the work belongs one
            // level in and what comes back is a value — and for one more: what a
            // session is, what a delete reaches, and what a retention deadline
            // means are all questions about the store rather than about the
            // command line, and the answers live in `sure_core` where the rest of
            // the store's callers can reach them too.
            Self::History { action } => crate::history::run(action.as_ref(), named.store),
            // The two halves of a surface that is half-built, and the split is
            // the point rather than an accident of this match: `sure config set`
            // writes one setting into a file the user owns, and the three
            // read-only subcommands still refuse. Naming `config` in
            // [`IMPLEMENTED`] would be SURE's own false green told to an agent —
            // `sure mcp` reads that list out as `commands_implemented` and into
            // every tool description — so the implemented invocation is recorded
            // in [`IMPLEMENTED_IN_PART`] instead, where it is a fact about one
            // invocation rather than a claim about a command. See that constant
            // for the whole of the argument.
            Self::Config { action } => match action {
                Some(ConfigAction::Set { setting, value }) => {
                    crate::settings::set(setting, value, named)
                }
                Some(ConfigAction::Show { path }) => {
                    crate::config_show::show(path.as_deref(), named)
                }
                None | Some(ConfigAction::Paths | ConfigAction::Validate) => not_yet(
                    self,
                    "show the settings in effect and which layer each one came from",
                    "No configuration was read.",
                ),
            },
            Self::Hook { action } => crate::hook::run(action, named),

            // A command this build carries out, and the first one that runs for
            // as long as its caller wants it to rather than until it has an
            // answer. The decision this arm records is *why it is an arm and not
            // a [`NotYet`]*: `sure mcp serve` really does serve — it speaks the
            // Model Context Protocol, negotiates a version, and answers
            // `tools/list` and `tools/call` — and the tools it exposes route to
            // the commands above and below through this same dispatch. So a
            // tool whose command is not implemented answers with *that*
            // command's refusal, in that command's words, as a tool error; a
            // refusal of `sure mcp` would be a second, weaker sentence about the
            // same missing work, and the caller would be told about the bridge
            // instead of about the check. `crate::mcp` is where that is written
            // down.
            //
            // The session itself is run here rather than in [`Report`] for
            // [`Self::Doctor`]'s reason: the match holds a report, and the work
            // belongs one level in. What comes back is a summary of the session,
            // not a claim about any project.
            Self::Mcp { action } => crate::mcp::run(action, named),
            Self::Explain { id } => crate::explain::explain(id.as_deref(), named),
        }
    }
}

/// Build the refusal for one command.
fn not_yet(command: &Command, does: &'static str, instead: &'static str) -> Report {
    Report::Unavailable(NotYet {
        command: command.name(),
        does,
        instead,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::cli::{ConfigAction, HistoryAction, HookAction, McpAction};

    /// A store directory this test names, so that nothing below reads or writes
    /// the store the machine running the suite really uses.
    ///
    /// Under the workspace's git-ignored `target/tmp`, by way of
    /// `sure_testkit::scratch`, which holds the reasoning every one of these
    /// helpers used to repeat. Nothing is created inside it: a store SURE has
    /// never written looks exactly like that, and `sure doctor` reports it
    /// rather than creating it.
    fn a_store_of_our_own() -> PathBuf {
        sure_testkit::scratch::directory("sure commands", "store")
    }

    /// Every invocation the grammar accepts, built by hand.
    ///
    /// By hand rather than by walking clap's `CommandFactory`, because this is
    /// the list of *commands* and a list derived from the parser would share a
    /// source of truth with the thing it checks.
    ///
    /// # Where these run
    ///
    /// Every report below is asked with [`a_store_of_our_own`], so nothing in
    /// this file reads or writes the store the machine running the suite really
    /// uses. That used to be impossible — on Windows the data directory comes
    /// from `SHGetKnownFolderPath`, which ignores `LOCALAPPDATA`, so there was no
    /// environment variable a test could set — and it is what `--store-dir` is
    /// for: a location the caller names on the command line, which a checked
    /// project cannot set. See `sure_core::paths`.
    ///
    /// # What is deliberately not in this list
    ///
    /// `Check`, `Recheck` and `Repair`. Each runs the whole pipeline over a
    /// project, and the project would be this crate's own directory, which is
    /// what none of these tests is about; they are driven against a project
    /// `tests/cli_contract.rs` makes. They are named in [`NOT_ASKED_HERE`], and
    /// the test below subtracts them rather than assuming them: a command that
    /// stopped being implemented while staying out of this list would be caught
    /// there, and one that is implemented and *not* in that list has to appear
    /// here.
    ///
    /// `Check` with a goal that has words in it belongs to that same reason: a
    /// goal goes into the store before the check runs, so a test that added it
    /// here would be putting an invented requirement into somebody's history.
    /// The goal path is driven against a store the test names, in
    /// `crate::check`'s tests and in `tests/cli_contract.rs`.
    ///
    /// `HistoryAction::Show` and `HistoryAction::Delete`, for two different
    /// reasons, and neither is "history is not implemented" — the three
    /// invocations above are here, and the name `history` is therefore in
    /// [`IMPLEMENTED`] on their evidence.
    ///
    /// `Show` is out because against a store this test has never written it is a
    /// status-5 failure by design: `sure history show` for an id that is not
    /// there did try and did not finish, which is what status 5 is for. Every
    /// invocation in this list is one that *answers*, and an invocation that
    /// always fails would need an arm of its own in the match below — an
    /// exception that would then hide a real failure if one appeared.
    ///
    /// `Delete` is out because it is the destructive one, and a list shared by
    /// several tests is the wrong place for an invocation whose whole job is
    /// removal: the day somebody gives `a_store_of_our_own` something to lose,
    /// this list would start emptying it as a side effect of a check about
    /// command names. It is driven in `crate::history`'s tests and in
    /// `tests/cli_contract.rs`, against a store the test names and fills.
    ///
    /// `Mcp`. Every command in this list is asked once and answers, but
    /// `sure mcp serve` reads standard input until its caller closes it — in a
    /// test binary whose stdin is not a pipe, adding it here would block the
    /// suite rather than check anything, and a run of it would write a protocol
    /// into whatever stdout the harness had. Its behaviour is driven instead by
    /// `tests/mcp_protocol.rs`, which gives it a stdin and a stdout of its own.
    /// What this list still owes MCP is the check below: `Mcp` is **not** in
    /// [`IMPLEMENTED`] because it is not in this list, and the two must agree.
    fn every_command() -> Vec<Command> {
        vec![
            Command::History { action: None },
            Command::History {
                action: Some(HistoryAction::List {
                    limit: crate::history::DEFAULT_LIMIT,
                }),
            },
            Command::History {
                action: Some(HistoryAction::Export),
            },
            Command::Doctor,
            Command::Config { action: None },
            Command::Config {
                action: Some(ConfigAction::Paths),
            },
            Command::Config {
                action: Some(ConfigAction::Show { path: None }),
            },
            Command::Config {
                action: Some(ConfigAction::Validate),
            },
            Command::Hook {
                action: HookAction::Ingest {
                    source: None,
                    event_kind: None,
                },
            },
            Command::Explain { id: None },
            Command::Protocol { speaks: None },
            Command::Protocol {
                speaks: Some(sure_core::PROTOCOL_VERSION),
            },
            Command::Protocol {
                speaks: Some(sure_core::PROTOCOL_VERSION + 1),
            },
            Command::Protocol { speaks: Some(0) },
            Command::Version,
        ]
    }

    #[test]
    fn every_command_this_build_cannot_carry_out_says_so_and_exits_non_zero() {
        // The load-bearing test of this task. A command that reached a user as
        // a success without doing anything is SURE's own false green, and SURE
        // is the program that exists to find those.
        let store = a_store_of_our_own();
        for command in every_command() {
            let report = command.report(Named::store(&store));
            match &report {
                Report::Unavailable(not_yet) => {
                    assert_eq!(
                        not_yet.command.split(' ').next(),
                        Some(command.name()),
                        "{command:?} is refused under a different name than it was asked by"
                    );
                    assert_eq!(report.exit_code(), crate::report::exit::UNAVAILABLE);
                    assert_ne!(report.exit_code(), crate::report::exit::OK);
                    assert!(
                        !not_yet.does.is_empty(),
                        "{command:?} says nothing about itself"
                    );
                    assert!(
                        !not_yet.instead.is_empty(),
                        "{command:?} does not say what SURE did instead"
                    );
                    assert!(
                        not_yet.instead.ends_with('.'),
                        "{command:?} does not finish its sentence: {:?}",
                        not_yet.instead
                    );
                }
                // Neither a refusal nor a report: the command ran and answered.
                // What it answered is held to its own contract below, and to
                // `a_command_that_runs_never_answers_a_question_it_was_not_asked`
                // for the name it answers under.
                //
                // `History` is in this arm and not in the one below because it
                // really did answer: the three invocations in [`every_command`]
                // read a store directory this test named, found no file there,
                // and said so. That is an answer about this machine, and it is
                // the one this build gives a user who has recorded nothing.
                Report::Version
                | Report::Protocol
                | Report::Handshake(_)
                | Report::Doctor(_)
                | Report::History(_)
                | Report::ConfigShow(_)
                | Report::Explain(_) => {}
                // `hook ingest` reads stdin and may return a decision or a failure
                // when stdin is empty. It is in this list because the grammar
                // accepts it, and its own tests cover the success paths.
                Report::HookDecision(_) => {}
                Report::Failed(failure) if failure.command == "hook" => {}
                // `explain` with a store this test never wrote is a status-5
                // failure by design: it looked and found nothing to explain.
                // Its success path is driven against a store its own tests fill.
                Report::Failed(failure) if failure.command == "explain" => {}
                // Neither shape is reachable from [`every_command`], and that is
                // asserted rather than ignored: the list holds no invocation that
                // writes to the store, so a report of either shape appearing here
                // means somebody added one — and a test that quietly skipped it
                // would be the only thing standing between an invented
                // requirement and the history of the machine running the suite.
                //
                // `Mcp` and `McpSession` join them for a different reason: they
                // are unreachable from here because `every_command` holds no
                // session (see its comment), not because a session would have a
                // side effect. A session is not a claim about a project — it is
                // the transport — and it is checked over a pipe rather than in
                // this list. Reaching this arm would mean a command that is not
                // `mcp` had answered with the bridge's own report.
                // `Check` joins them: it is implemented and it is not in this
                // list, so a report of that shape here means the list grew an
                // invocation that reads the store this machine really uses.
                // `HookAllowance` joins it for the same reason and one more:
                // `hook allow-once` writes a row, so no invocation of it belongs
                // in a list this test holds to leaving the machine as it found
                // it. Its own tests cover the write, against stores they name.
                // `Settings` joins them for a third version of the same reason:
                // `config set` writes a file, and it writes the *user's own*
                // — which for a caller that named no `--settings-file` is the
                // one the person running the suite really uses. No invocation
                // of it can belong in `every_command`, and the entry in
                // [`IMPLEMENTED_IN_PART`] is driven against a settings file the
                // test names instead.
                Report::Check(_)
                | Report::Settings(_)
                | Report::Failed(_)
                | Report::Mcp(_)
                | Report::McpSession(_)
                | Report::HookAllowance(_) => {
                    panic!(
                        "{command:?} produced {report:?}, and nothing in this list may have a \
                     side effect or a failure. See `every_command`."
                    )
                }
            }
        }
    }

    #[test]
    fn a_goal_with_no_words_reaches_the_check_and_fails_rather_than_being_a_wrong_command_line() {
        // The one way this file can exercise the `--goal` path at all — see
        // `every_command` for why a goal with words in it is not here. A goal
        // with no words in it is refused before SURE looks for its store, so this
        // run leaves the machine as it found it — and the store it is given is
        // one this test named, so the machine's own is not read either — and it
        // still goes through the dispatch: the grammar's variant, the arm, and
        // `crate::check`.
        //
        // Status 5, not 2 and not 3. 2 would mean SURE did not accept the command
        // line, and it did: `--goal ""` is a goal, and an empty one. 3 would mean
        // this build cannot record a goal, and it can — `crate::check`'s tests
        // record them against locations they name. What happened is that SURE was
        // asked to do something and could not finish it.
        let report = Command::Check {
            path: None,
            goal: Some(String::new()),
        }
        .report(Named::store(&a_store_of_our_own()));

        let failure = match &report {
            Report::Failed(failure) => failure,
            other => panic!("an empty goal was answered with {other:?}"),
        };
        assert_eq!(failure.command, "check");
        assert_eq!(report.exit_code(), crate::report::exit::FAILED);
        assert_ne!(report.exit_code(), crate::report::exit::UNAVAILABLE);
        assert_ne!(report.exit_code(), crate::report::exit::USAGE);
        assert!(
            failure.what.contains("Nothing was recorded"),
            "the user is not told whether their history changed: {:?}",
            failure.what
        );
        assert!(
            failure.what.ends_with('.') && failure.detail.ends_with('.'),
            "a sentence a user reads has to finish: {failure:?}"
        );
    }

    #[test]
    fn the_commands_this_build_implements_are_exactly_these_three() {
        // Stated as a list, so that making a fourth command work is a change to
        // this test rather than a side effect somebody notices later. If a
        // command starts working without this list moving, something returned a
        // success it had not earned.
        //
        // By name, once each: a command can be asked more than one way —
        // `sure protocol` with and without `--speaks` — and a name appearing
        // twice says nothing more than it appearing once.
        //
        // The name still says "three" from the task that wrote it, when `doctor`,
        // `protocol` and `version` were the whole list; `hook` and then `mcp`
        // joined it. It is left alone because `progress/DECISIONS.md` names it
        // and `progress/` is not this task's to edit — but a reader should take
        // the list below, not the number in the name, as the claim.
        let store = a_store_of_our_own();
        let mut implemented: Vec<&str> = every_command()
            .iter()
            // `config show` answers, but it answers as `config`, and that name
            // is deliberately absent from [`IMPLEMENTED`] because `config paths`
            // and `config validate` still refuse. The invocation is measured by
            // the `IMPLEMENTED_IN_PART` test below instead.
            .filter(|command| !matches!(command, Command::Config { .. }))
            .filter(|command| {
                !matches!(command.report(Named::store(&store)), Report::Unavailable(_))
            })
            .map(Command::name)
            .collect();
        implemented.sort_unstable();
        implemented.dedup();

        // Four names in [`IMPLEMENTED`] are not in [`every_command`], and each is
        // excepted for a reason that is written where the list is: `mcp`, because
        // a session reads stdin — **calling `report()` on it here would start
        // that session** — and `check`, `recheck` and `repair`, because their run
        // opens the store this machine really uses. An exception made by asking
        // is no exception, so they are made by name, and what this checks is that
        // naming them cannot hide anything:
        //
        //   * the subtraction proves every name in [`IMPLEMENTED`] is either one
        //     the test drives or one of the four, exactly once each — so a name
        //     cannot appear twice, and cannot be missing from both;
        //   * the equality proves no name the test *does* drive is implemented
        //     and absent from [`IMPLEMENTED`] — a command that started working
        //     without the list moving fails here;
        //   * the names are asked of the grammar, so a literal in either list is
        //     tied to a command rather than to a string that looks like one.
        //
        // What is *not* checked here is that the three pipeline commands really
        // work: that is `crate::check`'s tests, which drive them against
        // locations they name, and `tests/cli_contract.rs`, which drives the
        // built binary. What this test owns is the claim that nothing in
        // [`IMPLEMENTED`] is there by accident.
        let mut expected: Vec<&str> = IMPLEMENTED
            .iter()
            .copied()
            .filter(|name| *name != "mcp" && !NOT_ASKED_HERE.contains(name))
            .collect();
        expected.sort_unstable();
        let mut exceptions: Vec<&str> = std::iter::once("mcp")
            .chain(NOT_ASKED_HERE.iter().copied())
            .collect();
        exceptions.sort_unstable();

        assert_eq!(
            exceptions.len() + expected.len(),
            IMPLEMENTED.len(),
            "a name in IMPLEMENTED is either driven by `every_command` or excepted, \
             never both and never neither: implemented={IMPLEMENTED:?} \
             exceptions={exceptions:?} expected={expected:?}"
        );
        for name in &exceptions {
            assert!(
                IMPLEMENTED.contains(name),
                "{name} is excepted from the tests and is not implemented, so the \
                 exception has outlived the thing it excepted"
            );
        }
        assert_eq!(
            Command::Mcp {
                action: McpAction::Serve
            }
            .name(),
            "mcp",
            "the name this test excepts is not the name the command answers under"
        );
        for (name, command) in [
            (
                "check",
                Command::Check {
                    path: None,
                    goal: None,
                },
            ),
            ("recheck", Command::Recheck { path: None }),
            ("repair", Command::Repair { path: None }),
        ] {
            assert!(
                NOT_ASKED_HERE.contains(&name),
                "{name} is driven by `every_command` under a name this test does not \
                 except, so a run of the suite reads this machine's store"
            );
            assert_eq!(
                command.name(),
                name,
                "the excepted name is not the name the command answers under"
            );
        }
        assert_eq!(implemented, expected);
    }

    #[test]
    fn an_invocation_this_build_implements_in_part_really_answers() {
        // [`IMPLEMENTED_IN_PART`] is a claim that one invocation works while its
        // command name is absent from [`IMPLEMENTED`]. Both halves are checked
        // here, because either one alone is a way to be wrong quietly: a list of
        // names nothing drives is a wish, and a name in both lists is a
        // contradiction a reader would resolve in whichever direction suited
        // them.
        //
        // Driven through the dispatch with a settings file and a store this test
        // names, both under the workspace's git-ignored `target/tmp`, so that
        // the entry is proved by running it rather than by reading the match.
        // The setting it writes is one a machine with no file does not already
        // have — `host_confirmed` against the `inspect_only` default — so the
        // report is a write rather than a no-op, which is the ending that
        // actually touches the file the test made.
        let directory = sure_testkit::scratch::directory("sure commands", "config-set");
        let settings = directory.join("SURE").join("sure.yaml");
        let project = directory.join("project");
        std::fs::create_dir_all(&project).unwrap();

        for entry in IMPLEMENTED_IN_PART {
            let mut words = entry.split(' ');
            let name = words.next().expect("an entry names a command");
            let setting = words.next();
            assert!(
                !IMPLEMENTED.contains(&name),
                "{entry} is in IMPLEMENTED_IN_PART and its command {name} is in IMPLEMENTED, so \
                 one of the two lists is saying something the other denies"
            );
            assert!(
                words.next().is_none() && setting.is_some(),
                "{entry} is not `<command> <subcommand>`, which is the only shape this test knows \
                 how to drive"
            );

            // The name is asked of the grammar rather than trusted as a string:
            // a literal here that no command answers to would be a claim about
            // nothing. The invocation is built per entry because `config set`
            // writes and `config show` reads, and driving one as the other would
            // prove the wrong thing.
            let command = match *entry {
                "config set" => Command::Config {
                    action: Some(ConfigAction::Set {
                        setting: "execution.mode".to_owned(),
                        value: "host_confirmed".to_owned(),
                    }),
                },
                "config show" => Command::Config {
                    action: Some(ConfigAction::Show { path: None }),
                },
                other => panic!("{other} is in IMPLEMENTED_IN_PART and this test cannot build it"),
            };
            assert_eq!(
                command.name(),
                name,
                "{entry} names a command the grammar does not have"
            );

            let report = command.report(Named {
                store: Some(&directory.join("store")),
                settings_file: Some(&settings),
                commands_file: None,
            });

            match (&report, *entry) {
                (Report::Settings(_), "config set") => {}
                (Report::ConfigShow(_), "config show") => {}
                (other, _) => panic!(
                    "{entry} is listed as implemented in part and answered {other:?}, which is \
                     what this build says about work it did not do"
                ),
            }
            assert_eq!(
                report.command(),
                *entry,
                "the frame does not name the invocation that was run"
            );
            assert_eq!(report.exit_code(), crate::report::exit::OK);
            if *entry == "config set" {
                assert!(
                    std::fs::read_to_string(&settings)
                        .expect("the entry is implemented, so it wrote the file it was given")
                        .contains("host_confirmed"),
                    "{entry} answered without writing what it was asked for"
                );
            }
        }
    }

    #[test]
    fn a_command_that_runs_never_answers_a_question_it_was_not_asked() {
        // The refusals are held to the command they were asked by; the commands
        // that work have to be held to the same rule, and `Report::command` is
        // where that name lives. A `sure doctor` frame that said `version` would
        // be a script reading the wrong answer.
        //
        // The first word has to match, not the whole name: `sure history delete`
        // answers as "history delete", because the subcommand is part of what
        // the user asked for and a report that dropped it would be answering
        // about the wrong thing. See [`crate::history::name`].
        let store = a_store_of_our_own();
        for command in every_command() {
            assert_eq!(
                command
                    .report(Named::store(&store))
                    .command()
                    .split(' ')
                    .next(),
                Some(command.name()),
                "{command:?} answers under a different name than it was asked by"
            );
        }
    }

    #[test]
    fn a_doctor_that_found_a_problem_does_not_exit_zero() {
        // The false-green rule applied to this machine's own state. The core
        // decides what a problem is; what this asserts is that the CLI cannot
        // turn one into a success on the way out. The store is one this test
        // names, so the answer does not depend on — and does not read — the
        // installation of whoever is running the suite.
        let report = Command::Doctor.report(Named::store(&a_store_of_our_own()));
        let Report::Doctor(doctor) = &report else {
            panic!("sure doctor is implemented");
        };
        if doctor.is_well() {
            assert_eq!(report.exit_code(), crate::report::exit::OK);
        } else {
            assert_eq!(report.exit_code(), crate::report::exit::NOT_GREEN);
            assert_ne!(report.exit_code(), crate::report::exit::OK);
        }
    }

    #[test]
    fn asking_whether_a_caller_can_talk_asks_the_rule_rather_than_restating_it() {
        // The CLI does not own this decision and this test is written so that it
        // cannot quietly take it over: for a spread of versions, what the
        // command answers is what `sure_core::negotiate` says — the same
        // function the event reader refuses a document with. A comparison
        // written here instead would agree with it today and stop agreeing the
        // day one of them changed.
        for caller in [
            0,
            sure_core::PROTOCOL_VERSION.saturating_sub(1),
            sure_core::PROTOCOL_VERSION,
            sure_core::PROTOCOL_VERSION + 1,
            99,
        ] {
            let report = Command::Protocol {
                speaks: Some(caller),
            }
            .report(Named::store(&a_store_of_our_own()));
            let Report::Handshake(handshake) = &report else {
                panic!("`sure protocol --speaks {caller}` did not answer with a handshake");
            };
            assert_eq!(*handshake, sure_core::negotiate(caller));
            assert_eq!(
                report.exit_code(),
                if handshake.is_agreed() {
                    crate::report::exit::OK
                } else {
                    crate::report::exit::UNAVAILABLE
                },
                "protocol {caller} was answered with the wrong status"
            );
            assert_ne!(
                report.exit_code(),
                crate::report::exit::FAILED,
                "a version SURE will not speak is not SURE failing at its own job"
            );
        }
    }

    #[test]
    fn asking_for_the_protocol_without_a_version_is_still_just_the_version() {
        // The two forms of one command: `--speaks` is what turns a statement
        // into a negotiation, and asking for neither must not become a
        // handshake against a version nobody named.
        let report = Command::Protocol { speaks: None }.report(Named::store(&a_store_of_our_own()));
        assert_eq!(report, Report::Protocol);
        assert_eq!(report.exit_code(), crate::report::exit::OK);
    }

    #[test]
    fn a_history_subcommand_is_answered_under_its_own_name() {
        // A user who typed the destructive one must not be answered about the
        // harmless one. Driven through the dispatch rather than through the
        // naming helper, because what matters is the name the user actually
        // reads — in the first line of a refusal and in the `command` field of
        // the machine frame — and a test of the helper alone would pass while
        // the dispatch passed something else.
        //
        // The store is one this test named and has never written, so `sure
        // history` here answers that there is nothing, and `delete` finds
        // nothing to remove: the invocation is destructive in shape and inert in
        // fact, which is the only way an invocation of it belongs in a test whose
        // subject is a string.
        let store = a_store_of_our_own();
        for (action, expected) in [
            (None, "history"),
            (
                Some(HistoryAction::List {
                    limit: crate::history::DEFAULT_LIMIT,
                }),
                "history",
            ),
            (
                Some(HistoryAction::Show {
                    id: "no-such-session".to_owned(),
                }),
                "history show",
            ),
            (
                Some(HistoryAction::Delete {
                    all: true,
                    session: None,
                    project: None,
                }),
                "history delete",
            ),
            (Some(HistoryAction::Export), "history export"),
        ] {
            let command = Command::History {
                action: action.clone(),
            };
            let report = command.report(Named::store(&store));
            assert_eq!(
                report.command(),
                expected,
                "{action:?} answered under the wrong name"
            );
            assert_eq!(
                report.command().split(' ').next(),
                Some(command.name()),
                "{action:?} answered under a different command than it was asked by"
            );
        }
    }

    #[test]
    fn a_history_the_user_has_none_of_is_an_answer_and_not_a_refusal() {
        // The two ways this command could give a false impression, checked
        // against each other. A refusal would say this build cannot show a
        // history, which is false — it can, and it did. A blank success would
        // leave the user unsure whether SURE looked. What it does instead is
        // answer in words, with status 0 and nothing on the way out that a script
        // would read as a failure.
        let store = a_store_of_our_own();
        let report = Command::History { action: None }.report(Named::store(&store));
        assert!(
            matches!(&report, Report::History(_)),
            "a history that is empty was answered with {report:?}"
        );
        assert!(report.is_an_answer());
        assert_eq!(report.exit_code(), crate::report::exit::OK);
        assert_ne!(report.exit_code(), crate::report::exit::UNAVAILABLE);
        assert_ne!(report.exit_code(), crate::report::exit::FAILED);

        // And the same run left the store directory exactly as it was. A command
        // that reports an empty history by creating the store it looked in has
        // changed the thing it was reporting on, and the file it left is the
        // evidence of a run that claimed to find nothing.
        let left_behind: Vec<_> = std::fs::read_dir(&store)
            .unwrap_or_else(|error| panic!("cannot read {}: {error}", store.display()))
            .map(|entry| entry.map(|entry| entry.file_name()))
            .collect::<Result<_, _>>()
            .unwrap_or_else(|error| panic!("cannot read {}: {error}", store.display()));
        assert!(
            left_behind.is_empty(),
            "`sure history` created {left_behind:?} in a store directory it was asked to \
             report on"
        );
    }

    #[test]
    fn a_delete_that_matched_nothing_says_so_rather_than_claiming_a_deletion() {
        // The user's next question after `sure history delete` is whether it
        // worked, and "it did nothing" has to be distinguishable from "it worked"
        // in the answer — in the machine frame as well as in the sentence, since
        // a script cannot read a sentence.
        let store = a_store_of_our_own();
        let report = Command::History {
            action: Some(HistoryAction::Delete {
                all: true,
                session: None,
                project: None,
            }),
        }
        .report(Named::store(&store));
        let Report::History(history) = &report else {
            panic!("a delete that matched nothing was answered with {report:?}");
        };
        let crate::history::HistoryOutcome::Deleted { deleted, .. } = &history.outcome else {
            panic!("a delete answered with {:?}", history.outcome);
        };
        assert!(
            deleted.is_empty(),
            "a delete against a store that was never written removed something: {deleted:?}"
        );
    }
}
