#![forbid(unsafe_code)]
//! The `sure` command line entry point.
//!
//! This file is deliberately thin. It parses, asks the command what happened,
//! writes the answer down one of the two ways, and exits. Every decision it
//! could make lives one level in, where a test can reach it:
//!
//! | Decision | Where |
//! | --- | --- |
//! | what the command line accepts | [`cli`] |
//! | what a command does in this build | [`commands`] |
//! | how a result is written | [`report`] |
//! | what `sure doctor` says, in both forms | [`doctor`] |
//! | what `sure check --goal` stores, and what it refuses to claim | [`check`] |
//! | which stream, and which of the two paths | [`output`] |
//! | where this run's store goes, and the default | `sure_core::paths` |
//! | the exit status | `report::Report::exit_code` |
//!
//! `docs/architecture/CLI.md` is the contract a user reads.
//!
//! # Why the parse error is handled here rather than by `clap::Parser::parse`
//!
//! `parse` exits the process itself, which would put a status code in a
//! library's hands. Every status this program returns is listed in
//! `docs/architecture/CLI.md`, and one of them being clap's decision rather
//! than SURE's is how a documented table quietly becomes wrong. `try_parse`
//! hands the error back, and [`status_of`] is the whole of the mapping.

use std::process::ExitCode;

use clap::Parser;

use sure_cli::cli::Cli;
use sure_cli::commands::Named;
use sure_cli::report::exit;

fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => {
            // clap decides what the message says and which stream it goes to;
            // SURE decides what the process returns.
            let _ = error.print();
            return ExitCode::from(status_of(&error));
        }
    };
    ExitCode::from(run(&cli))
}

/// Run the parsed command and return the status to exit with.
fn run(cli: &Cli) -> u8 {
    // The one place the two locations a caller can name are read out of the
    // command line, and the only things passed down with a command. They are
    // values in this process's argument vector: no file the checked project can
    // write and no environment variable can reach either — see
    // `sure_core::paths`.
    let named = Named {
        store: cli.store_dir.as_deref(),
        settings_file: cli.settings_file.as_deref(),
        commands_file: cli.commands_file.as_deref(),
    };
    let report = cli.command.report(named);
    match cli.format.emit(&report) {
        Ok(()) => report.exit_code(),
        Err(error) => {
            // The command did its work and the answer did not reach the user.
            // Reporting success here would be exactly the failure this program
            // exists to find, so it is reported as a failure of SURE's own.
            sure_cli::output::write_stream_failure(&error);
            exit::FAILED
        }
    }
}

/// The status for a command line clap would not accept.
///
/// clap reports `--help` and `--version` through the same type with a status of
/// zero: they are things the user asked for, not mistakes. Anything else is a
/// wrong command line, and a wrong command line is not a successful run — which
/// is why a bare `sure` is one of them.
fn status_of(error: &clap::Error) -> u8 {
    match error.exit_code() {
        0 => exit::OK,
        _ => exit::USAGE,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use clap::CommandFactory;
    use sure_cli::cli::Cli;
    use sure_cli::output::Format;

    #[test]
    fn the_long_help_leads_with_the_product_promise() {
        let help = Cli::command().render_long_help().to_string();
        assert!(
            help.contains(sure_core::PROMISE),
            "the help no longer states what SURE is for:\n{help}"
        );
    }

    #[test]
    fn the_long_help_leads_with_the_language_rule() {
        // `docs/product/UX_AND_LANGUAGE.md`: translate the consequence, do not
        // lead with jargon. The product name expands to three words nobody
        // says out loud, so the help has to say what SURE is for in the same
        // breath.
        let help = Cli::command().render_long_help().to_string();
        assert!(help.contains("checks what was actually built"), "{help}");
    }

    #[test]
    fn the_grammar_is_the_one_docs_architecture_cli_md_lists() {
        // The doc and the grammar are two views of one list, and this is the
        // check that they are the same list: a command documented and not
        // accepted is a user typing something SURE does not recognise.
        //
        // A transcription of §The commands in that doc, in the doc's order,
        // because the doc is what a user reads and this is what a build can be
        // asked. `mcp` is in both: the table lists `sure mcp serve`, so the
        // grammar accepting it is not a command nobody documented.
        const DOCUMENTED: &[&str] = &[
            "check", "recheck", "repair", "history", "doctor", "config", "hook", "explain", "mcp",
            "protocol", "version",
        ];
        let command = Cli::command();
        let parsed: Vec<&str> = command
            .get_subcommands()
            .map(clap::Command::get_name)
            .collect();
        for name in DOCUMENTED {
            assert!(
                parsed.contains(name),
                "docs/architecture/CLI.md lists `sure {name}` and the grammar does not accept it"
            );
        }
        assert_eq!(
            parsed.len(),
            DOCUMENTED.len(),
            "the grammar accepts a command the doc does not list: {parsed:?}"
        );
    }

    #[test]
    fn every_subcommand_has_a_subcommand_of_its_own_where_the_doc_says_it_does() {
        // `hook` with no subcommand is not a command, because a hook that ran
        // nothing would be reported to the harness as an event handled.
        let command = Cli::command();
        let hook = command
            .get_subcommands()
            .find(|sub| sub.get_name() == "hook")
            .expect("hook is a command");
        assert!(
            hook.get_subcommands().any(|sub| sub.get_name() == "ingest"),
            "`sure hook` no longer accepts `ingest`"
        );
        // `hook allow-once` is in the doc's table beside `hook ingest`, and the
        // two are the whole of what the entry point a harness calls will do: one
        // records an event, the other records the user's answer to a request the
        // hook could not ask about.
        assert!(
            hook.get_subcommands()
                .any(|sub| sub.get_name() == "allow-once"),
            "`sure hook` no longer accepts `allow-once`"
        );
        for optional in ["history", "config"] {
            let sub = command
                .get_subcommands()
                .find(|sub| sub.get_name() == optional)
                .expect("a command");
            assert!(
                !sub.get_subcommands().next().is_none(),
                "`sure {optional}` no longer lists what it can be asked to do"
            );
        }
    }

    #[test]
    fn a_bare_sure_is_not_a_success() {
        // `sure` on its own did nothing. Exiting 0 would let a script that
        // invoked the wrong thing read it as a clean run.
        let error = Cli::try_parse_from(["sure"]).expect_err("a bare `sure` does nothing");
        assert_ne!(
            status_of(&error),
            exit::OK,
            "a bare `sure` was reported as a successful run"
        );
    }

    #[test]
    fn help_and_version_are_not_usage_errors() {
        // They are things the user asked for. `status_of` separates them from a
        // wrong command line, and both branches are checked here rather than
        // discovered later in somebody's shell script.
        for args in [["sure", "--help"], ["sure", "--version"]] {
            let error = Cli::try_parse_from(args).expect_err("clap reports these as errors");
            assert_eq!(
                status_of(&error),
                exit::OK,
                "{args:?} was reported as a wrong command line"
            );
        }
    }

    #[test]
    fn the_two_ways_of_asking_for_the_version_agree_about_the_version() {
        // `sure --version` is clap's, rendered as `<name> <version>`;
        // `sure version` is SURE's, rendered by `version_string`. The prefixes
        // differ by design and the *number* must not, so that is what is
        // compared — two spellings of one fact is where drift starts.
        let from_clap = Cli::command().render_version();
        let from_sure = sure_core::version_string();
        assert!(
            from_sure.ends_with(env!("CARGO_PKG_VERSION")),
            "\"{from_sure}\" does not name this build"
        );
        assert!(
            from_clap.contains(env!("CARGO_PKG_VERSION")),
            "\"{from_clap}\" does not name this build"
        );
    }

    #[test]
    fn the_format_flag_is_accepted_before_and_after_the_command() {
        // It is global, so both spellings work. A user who puts it in what the
        // help does not call the wrong place should not get a usage error for a
        // flag the help advertises.
        for args in [
            ["sure", "--format", "json", "version"],
            ["sure", "version", "--format", "json"],
        ] {
            let cli = Cli::try_parse_from(args).expect("the format flag is global");
            assert_eq!(cli.format, Format::Json);
        }
    }

    #[test]
    fn the_default_format_is_the_one_a_person_reads() {
        let cli = Cli::try_parse_from(["sure", "version"]).unwrap();
        assert_eq!(cli.format, Format::Human);
    }

    #[test]
    fn an_unknown_command_or_flag_is_refused_rather_than_ignored() {
        // The CLI's own version of a false green. A `--strict` that SURE
        // accepted and did nothing with would leave the user believing a
        // stricter check ran than the one that did, and nothing in the output
        // would say otherwise.
        for args in [
            &["sure", "check", "--deep"][..],
            &["sure", "chekc"][..],
            &["sure", "check", "--format", "yaml"][..],
        ] {
            assert!(
                Cli::try_parse_from(args).is_err(),
                "{args:?} was accepted and does nothing"
            );
        }
    }
}
