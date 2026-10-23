//! The command line contract, checked where a user meets it: the process.
//!
//! # Why this file runs the binary
//!
//! The two acceptance criteria — that the commands parse, and that the human
//! and machine-readable output paths are separated — are claims about what a
//! *process* does. Which stream a byte went to, and what status the process
//! returned, are not observable from inside: the unit tests in `src/` check the
//! decisions, and this file checks that the decisions are what a shell sees.
//!
//! A test that called the renderers directly would pass while the binary wrote
//! both of them to stdout, which is precisely the failure the criterion exists
//! to rule out.
//!
//! # What is asserted
//!
//! 1. the status, for every command the docs list;
//! 2. that the human form of a refusal goes to stderr and the machine form to
//!    stdout, and that neither writes to the other's stream;
//! 3. that the machine form is one line of JSON, so a pipeline can read a
//!    stream of responses;
//! 4. that a command with nothing to do never exits 0 — SURE's own false green;
//! 5. that nothing in the crate can write to a stream outside `output.rs`;
//! 6. that the store's location is the caller's to name and no one else's, and
//!    that a full run of this file leaves the store of the person running it
//!    byte-identical.
//!
//! # Where these runs keep their evidence
//!
//! **Every process this file starts names a store with `--store-dir`**, in a
//! directory of its own under `target/tmp` — see [`a_store_of_our_own`]. Before
//! that flag existed, the runs that write (`sure check --goal`, `sure hook
//! ingest`) wrote the store of whoever ran the suite, and there was no
//! environment variable that could have stopped them: on Windows the per-user
//! data directory comes from `SHGetKnownFolderPath`, which ignores
//! `LOCALAPPDATA`. One test here names no store at all, and it is the one that
//! checks a caller who names nothing still gets the platform's own location; it
//! reads that store and compares its bytes before and after, so a redirect that
//! had been dropped fails a test rather than editing a history.

// The workspace forbids `unwrap`, `expect` and `panic` in shipped code, because
// a panic is a message nobody chose. A test is the one place they are the point:
// the panic *is* the report, and it names the value that was wrong.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use sure_core::config::{Authority, ProtectionMode};
use sure_core::execution::{ExecutionMode, ExecutionPermissions, Permission};
use sure_core::hook_protection::{Danger, ProtectionDecisionKind};
use sure_core::paths::Paths;
use sure_core::protection_history;
use sure_core::session_event_store::SessionEventStore;
use sure_core::store::{HistoryFilter, RecordKind, Store, StoredRecord};
use sure_protocol::documents::DocumentKind;

/// The binary this package builds, as cargo hands it to its integration tests.
const SURE: &str = env!("CARGO_BIN_EXE_sure");

/// What one run of the binary did.
struct Run {
    status: i32,
    stdout: String,
    stderr: String,
}

impl Run {
    /// What the process left behind.
    fn of(output: &Output) -> Self {
        Self {
            status: output.status.code().expect("the process exited on its own"),
            stdout: String::from_utf8(output.stdout.clone()).expect("stdout is utf-8"),
            stderr: String::from_utf8(output.stderr.clone()).expect("stderr is utf-8"),
        }
    }

    fn succeeded(&self) -> bool {
        self.status == 0
    }
}

/// A directory of this test's own, under the workspace's git-ignored `target/tmp`.
///
/// The reasoning lives with the helper rather than here, because it is the same
/// reasoning in twenty-five files: see `sure_testkit::scratch`. Every call in
/// one run shares a directory of that run's own, named for the process, and the
/// directory handed back is created by this call and by nothing else.
fn a_directory_of_our_own(what: &str) -> PathBuf {
    sure_testkit::scratch::directory("sure cli contract", what)
}

/// A store directory for one process to use.
///
/// **Every process this file starts names one.** A test that ran the default
/// would read — and `sure check --goal`, and `sure hook ingest`, would *write* —
/// `%LOCALAPPDATA%\SURE\sure.db`, the store of the person running the suite: an
/// invented requirement in somebody's history, and a test result that depends on
/// what is in it. `--store-dir` is the mechanism, and it is a value in the
/// child's own argument vector, so nothing in the project a test points SURE at
/// can change where the row goes.
///
/// The directory is created and left empty: a store SURE has never written looks
/// like exactly that, and a test that wants one *written* says so itself.
///
/// It sits beside [`a_project_of_our_own`] rather than inside it, and that is not
/// a coincidence: a store inside the project it is recording about is refused by
/// `Paths::ensure_outside`, so nesting the two would make these tests exercise a
/// refusal instead of a redirect.
fn a_store_of_our_own() -> PathBuf {
    a_directory_of_our_own("store")
}

/// A project for a check to be about, with something in it to read.
///
/// Under the same `target/tmp` root as the stores and never the repository
/// itself: these tests write nothing into the project, but a test that pointed
/// SURE at this repository would be checking the tree its own results come from.
fn a_project_of_our_own() -> PathBuf {
    let project = a_directory_of_our_own("project");
    std::fs::write(project.join("README.md"), "# a small project\n")
        .unwrap_or_else(|error| panic!("cannot write into {}: {error}", project.display()));
    project
}

/// The same, with a stack SURE recognises and a command it will plan a check for.
///
/// [`a_project_of_our_own`] is a README and nothing else: no stack, no declared
/// command, so no check, so no finding, so nothing for the repair loop to carry.
/// A test about what a finding is carried *through* needs a project that produces
/// one, and building it here rather than pointing at `fixtures/` keeps this
/// file's rule — every project these tests run against is one they made under
/// `target/tmp`.
///
/// The declared scripts are never run **as this test runs it**: a run starts in
/// `inspect_only`, which admits no command that starts a process, so what the
/// scripts do is irrelevant here and their names are what matter. Since
/// `P18-T007` wired the runner, that is a fact about the mode a run starts in
/// rather than about the build — see the module comment above
/// `a_run_a_user_did_not_grant_starts_nothing` in `sure-core/src/pipeline.rs`
/// for the measured form of it.
fn a_project_with_a_declared_command_that_never_runs() -> PathBuf {
    let project = a_directory_of_our_own("node-project");
    // The shape the node proposer reads: a root manifest that names a package
    // manager and a workspace, and a member that declares a `test` script. A
    // manifest on its own proposes nothing — the manager is what says which
    // command runs a script, and `Managers::agreed` answers `None` without it —
    // which is how this helper was written the first two times and why the parts
    // that matter are named here.
    let root = serde_json::json!({
        "name": "a-project-with-a-declared-test",
        "version": "0.0.0",
        "private": true,
        "packageManager": "npm@10.9.0",
        "workspaces": ["packages/*"],
        "scripts": { "start": "node scripts/demo.js" },
    });
    std::fs::write(project.join("package.json"), format!("{root}\n"))
        .unwrap_or_else(|error| panic!("cannot write into {}: {error}", project.display()));
    let member = project.join("packages").join("only");
    std::fs::create_dir_all(&member)
        .unwrap_or_else(|error| panic!("cannot create {}: {error}", member.display()));
    let manifest = serde_json::json!({
        "name": "@a-project/only",
        "version": "0.0.0",
        "private": true,
        "scripts": { "test": "node tests/only.js" },
    });
    std::fs::write(member.join("package.json"), format!("{manifest}\n"))
        .unwrap_or_else(|error| panic!("cannot write into {}: {error}", member.display()));

    // A second member, so that `repair_impact` has a regression check to add:
    // its rule reaches a check that runs project code and carries a deterministic
    // class, and one member's test check is exactly that for the other member's
    // finding. With a single member the selected list would equal the seed and the
    // assertion about widening below would be checking nothing.
    let second = project.join("packages").join("also");
    std::fs::create_dir_all(&second)
        .unwrap_or_else(|error| panic!("cannot create {}: {error}", second.display()));
    let manifest = serde_json::json!({
        "name": "@a-project/also",
        "version": "0.0.0",
        "private": true,
        "scripts": { "test": "node tests/also.js" },
    });
    std::fs::write(second.join("package.json"), format!("{manifest}\n"))
        .unwrap_or_else(|error| panic!("cannot write into {}: {error}", second.display()));
    project
}

/// The same, with the store named by the caller of this function.
///
/// This is how every process in this file is started, apart from the one that
/// deliberately names no store. A spawn that went straight to `Command::new(SURE)`
/// would be a spawn with the machine's own store.
fn sure_in_a_store(store: &Path) -> Command {
    let mut command = Command::new(SURE);
    command.arg("--store-dir").arg(store);
    // No test wants a child of this file waiting on this process's standard
    // input; the one test that pipes an event in says so itself.
    command.stdin(Stdio::null());
    command
}

/// The same, with no store named at all, so that the default is what runs.
///
/// One test uses this, the one that checks a caller who names nothing still gets
/// the platform's own location. It reads the store on this machine rather than
/// writing to it — `sure doctor` has its own tests for not creating a store —
/// and it takes the store's bytes before and after, so a diagnostic that had
/// started writing would fail here rather than quietly edit somebody's history.
fn sure_without_a_store() -> Command {
    let mut command = Command::new(SURE);
    command.stdin(Stdio::null());
    command
}

/// Run the binary in a store of this test's own, and collect what it did.
fn run(args: &[&str]) -> Run {
    run_in_a_store(&a_store_of_our_own(), args)
}

/// The same, in a store the caller named.
fn run_in_a_store(store: &Path, args: &[&str]) -> Run {
    let mut command = sure_in_a_store(store);
    command.args(args);
    Run::of(
        &command
            .output()
            .unwrap_or_else(|error| panic!("could not run {SURE}: {error}")),
    )
}

/// The store the person running the suite really uses: its path, and its bytes.
///
/// Read through the same `Paths::discover` a command that names no store uses,
/// so this is exactly the file a spawn that forgot `--store-dir` would write.
/// `bytes` is `None` on a machine that has no store yet, which the comparison
/// below understands rather than treats as a failure.
struct MachineStore {
    path: PathBuf,
    bytes: Option<Vec<u8>>,
}

fn the_store_on_this_machine() -> MachineStore {
    let path = Paths::discover()
        .expect("this machine reports a per-user location for SURE's files")
        .store_file();
    let bytes = std::fs::read(&path).ok();
    MachineStore { path, bytes }
}

/// Assert that nothing since `before` touched the store on this machine.
///
/// What it can see: this test, and every process this file starts. What it
/// cannot see: a write from a test binary that has not run yet, or from a `sure`
/// process somebody started by hand. A full `cargo test --workspace` covers the
/// first and a digest of this file taken before and after that run covers both —
/// this is the assertion that catches the inside of one binary.
fn assert_untouched(before: &MachineStore, when: &str) {
    let now = the_store_on_this_machine();
    assert_eq!(
        now.path,
        before.path,
        "the store SURE uses moved {when}: {} rather than {}",
        now.path.display(),
        before.path.display()
    );
    match (&before.bytes, &now.bytes) {
        (None, None) => {}
        (Some(was), Some(is)) => assert!(
            was == is,
            "{} was {} bytes {when} and is {} bytes now, so something in this suite wrote the \
             store of the person running it. Every process this file starts names a store with \
             `--store-dir`, and a named store is not this file: if one of them reached it, the \
             mechanism is not in force. If they all named one, the writer came from outside \
             this file — another test binary, a `sure` process somebody started, or a harness \
             hook — and the digest of this file taken across the whole workspace run is what \
             shows it.",
            before.path.display(),
            was.len(),
            is.len()
        ),
        (None, Some(_)) => panic!(
            "{} did not exist {when} and exists now, so something created the store of the \
             person running this suite",
            before.path.display()
        ),
        (Some(_), None) => panic!("{} existed {when} and is gone now", before.path.display()),
    }
}

/// Every command `docs/architecture/CLI.md` lists, with arguments that reach it.
///
/// A command that needs a subcommand is given one, so that this list tests the
/// command rather than the grammar's refusal to run half of one — and a
/// subcommand that needs an argument is given one for the same reason.
/// `sure history delete` takes a scope and nothing else, and the scope here is
/// `--all` against a store this file named and never wrote, so the invocation is
/// destructive in shape and inert in fact.
const EVERY_COMMAND: &[&[&str]] = &[
    &["check"],
    &["recheck"],
    &["repair"],
    &["history"],
    &["history", "list"],
    &["history", "list", "--limit", "1"],
    &["history", "show", "no-such-session"],
    &["history", "delete", "--all"],
    &["history", "export"],
    &["doctor"],
    &["config"],
    &["config", "paths"],
    &["config", "show"],
    &["config", "validate"],
    &["hook", "ingest"],
    // A one-time allowance, asked against the store this file named and against
    // the directory the child process starts in — the default for `--project`,
    // and a directory that is not the store. Since `P13-T010` the command reads
    // the settings in force before it writes, and that directory declares none:
    // no request there can be held for any of the three acts an allowance
    // covers, so this invocation is refused and writes nothing at all. Its own
    // tests, below and in `crate::hook`, are where an allowance really being
    // written is checked, against a `--project` whose settings leave one
    // spendable.
    &[
        "hook",
        "allow-once",
        "--tool",
        "Bash",
        "--command",
        "npm test",
    ],
    &["explain"],
    &["protocol"],
    &["version"],
];

/// The commands this build cannot carry out.
///
/// Every other command in [`EVERY_COMMAND`] runs, and what it answers is checked
/// by a test of its own. What this list is *for* is the status: a command here
/// must exit 3 and nothing else, and a command not here must never exit 3 —
/// which is what stops a command quietly going back to refusing, and what stops
/// a command that cannot run being reported as one that did.
///
/// `sure history list` and `sure history delete` were here, and are not any
/// more: the inspect-and-delete surface is what a user needs most from a
/// history, and it is now carried out. `sure history export` is the one
/// subcommand of that surface still refused, and the reason is in
/// `crate::history`.
const REFUSED: &[&[&str]] = &[
    &["history", "export"],
    &["explain"],
    &["config"],
    &["config", "paths"],
    &["config", "show"],
    &["config", "validate"],
];

/// The commands whose answer is the same on every machine, and so is a status
/// this file can demand.
///
/// `doctor` and `history` are not, and that is the point of both: `doctor`
/// reports on the machine it runs on, and a machine where SURE found something
/// wrong about its own files earns status 1; `history` reports on what that
/// machine has recorded, and a machine with nothing recorded is a different
/// answer from one with sessions. Demanding 0 here would turn this file into a
/// claim about the machine running it, which is a claim about a machine and not
/// about SURE.
const ALWAYS_OK: &[&[&str]] = &[&["protocol"], &["version"]];

#[test]
fn every_documented_command_parses() {
    // The first acceptance criterion, literally. `parse` here means the process
    // reached its own code: a command line clap rejects exits 2 and prints
    // "unrecognized subcommand", and both are checked for rather than assumed.
    for args in EVERY_COMMAND {
        let run = run(args);
        assert_ne!(
            run.status,
            2,
            "`sure {}` was not accepted:\n{}",
            args.join(" "),
            run.stderr
        );
        assert!(
            !run.stderr.contains("unrecognized subcommand")
                && !run.stderr.contains("unexpected argument"),
            "`sure {}` was rejected by the parser:\n{}",
            args.join(" "),
            run.stderr
        );
    }
}

#[test]
fn no_command_this_build_cannot_carry_out_reports_success() {
    // The criterion this file exists for. Every command here is recognised and
    // cannot do its job yet, so every one of them must say so with the status
    // that means "this build cannot carry that out" — never 0, and never a
    // status that means something else. A script that ran `sure config validate`
    // in CI today must fail the build, not pass it.
    for args in REFUSED {
        let run = run(args);
        assert_ne!(
            run.status,
            0,
            "`sure {}` exited 0 without doing anything:\nstdout: {}\nstderr: {}",
            args.join(" "),
            run.stdout,
            run.stderr
        );
        assert_eq!(
            run.status,
            3,
            "`sure {}` failed with {}, which is not the status for a command that \
             exists and cannot run:\n{}",
            args.join(" "),
            run.status,
            run.stderr
        );
    }
}

#[test]
fn every_command_this_build_carries_out_runs_rather_than_refusing() {
    // The other half of the same criterion, and the half that did not exist
    // while almost nothing ran: a command that is **not** on the refused list
    // must not answer with a refusal. Without this the list above could grow a
    // name it has no business holding — a command could go back to saying "this
    // build cannot carry that out" and the test above would still pass, because
    // it only ever looks at the names it was given.
    //
    // Status 3 and the refusal's sentence are checked separately, because they
    // are two ways a user learns the same wrong thing: one from `$?` in a
    // script, one from the terminal.
    for args in EVERY_COMMAND {
        if REFUSED.contains(args) {
            continue;
        }
        let run = run(args);
        assert_ne!(
            run.status,
            3,
            "`sure {}` returned 3, which says this build cannot carry it out:\n{}",
            args.join(" "),
            run.stderr
        );
        assert!(
            !run.stderr.contains("is not implemented in this build"),
            "`sure {}` is worded as a command this build lacks:\n{}",
            args.join(" "),
            run.stderr
        );
    }
}

#[test]
fn the_commands_that_work_report_success() {
    // The other half. A build where nothing exits 0 is a build that has stopped
    // answering, and the previous test would be satisfied by it.
    for args in ALWAYS_OK {
        let run = run(args);
        assert!(
            run.succeeded(),
            "`sure {}` did not succeed:\n{}",
            args.join(" "),
            run.stderr
        );
        assert!(!run.stdout.trim().is_empty(), "it printed nothing");
    }
}

#[test]
fn a_doctor_report_is_an_answer_however_it_turns_out() {
    // `sure doctor` is the first command whose status depends on what it found,
    // so it is the first place where the two ways of reading a result can come
    // apart: the status says whether the answer was clean, and the streams say
    // whether there was an answer at all. Both are checked against the frame the
    // same run produced, rather than against what this machine happens to hold.
    let human = run(&["doctor"]);
    assert!(
        matches!(human.status, 0 | 1),
        "`sure doctor` exited {}. It either answered (0) or answered that something is \
         wrong (1); anything else means it did not run:\n{}",
        human.status,
        human.stderr
    );
    assert!(
        human.stderr.is_empty(),
        "the report went to standard error, so `sure doctor > report.txt` would leave \
         the file empty:\n{}",
        human.stderr
    );
    assert!(!human.stdout.trim().is_empty(), "it printed nothing");

    let machine = run(&["--format", "json", "doctor"]);
    let frame: serde_json::Value = serde_json::from_str(machine.stdout.trim())
        .unwrap_or_else(|error| panic!("`sure --format json doctor` is not JSON: {error}"));
    assert_eq!(
        machine.status, human.status,
        "the two paths disagree about the status:\n{}",
        machine.stdout
    );
    assert_eq!(
        frame["outcome"].as_str(),
        Some(if human.status == 0 { "ok" } else { "not_green" }),
        "the body and the status disagree about the same run: {frame}"
    );
    assert_eq!(
        frame["exit_code"].as_i64(),
        Some(i64::from(human.status)),
        "the frame's own status is not the one the process returned: {frame}"
    );
    // The reason a script can act on, and the reason the status is 1: a machine
    // that is clean reports no problems, and the frame is where that list is.
    let problems = frame["details"]["problems"]
        .as_array()
        .expect("a doctor frame lists what it found wrong, even when the list is empty");
    assert_eq!(
        problems.is_empty(),
        human.status == 0,
        "the status and the problems disagree: {frame}"
    );
}

#[test]
fn the_protocol_version_sure_reports_is_the_one_it_will_talk_to() {
    // The handshake rule is exact equality, so the number SURE prints and the
    // number that gets a yes have to be the same number. Taken from the frame
    // rather than written here: a copy in this file would keep passing after the
    // two had drifted apart, and a build that announced one version while
    // accepting another is the failure a handshake exists to prevent.
    let reported: serde_json::Value =
        serde_json::from_str(run(&["--format", "json", "protocol"]).stdout.trim())
            .expect("`sure protocol` answers with a frame");
    let speaks = u32::try_from(reported["protocol_version"].as_u64().expect("a version"))
        .expect("a protocol version this build can speak");

    let agreed = run(&["protocol", "--speaks", &speaks.to_string()]);
    assert!(
        agreed.succeeded(),
        "this build speaks protocol {speaks} and would not agree to talk to it:\n{}",
        agreed.stderr
    );
    assert!(
        agreed.stderr.is_empty(),
        "a caller that can talk to SURE was handed a complaint as well as an answer, and a \
         complaint on that stream is how an adapter decides to give up:\n{}",
        agreed.stderr
    );
    assert!(!agreed.stdout.trim().is_empty(), "it printed nothing");

    // Both directions of the refusal, because they are not the same answer. A
    // build that said no to everything would pass a check that only ever asked
    // about one number, and a caller told the wrong direction retries with the
    // fix that cannot work.
    assert!(
        speaks > 0,
        "the older-caller direction has no version below {speaks} to be asked about"
    );
    for (other, moves) in [(speaks + 1, "sure"), (speaks - 1, "caller")] {
        let other_text = other.to_string();
        let args = ["protocol", "--speaks", other_text.as_str()];

        let refused = run(&args);
        assert_eq!(
            refused.status, 3,
            "`sure protocol --speaks {other}` returned {}. A protocol this build will not \
             speak is a command it cannot carry out; a caller that read 0 would send events \
             SURE then refuses:\n{}",
            refused.status, refused.stderr
        );
        assert!(
            refused.stdout.is_empty(),
            "the complaint went to standard output, where a caller reading an answer would \
             take it for one:\n{}",
            refused.stdout
        );
        assert!(
            refused.stderr.contains(&other_text) && refused.stderr.contains(&speaks.to_string()),
            "`sure protocol --speaks {other}` does not name both versions, so the person \
             reading it cannot tell which one to change:\n{}",
            refused.stderr
        );

        let mut machine: Vec<&str> = vec!["--format", "json"];
        machine.extend_from_slice(&args);
        let frame = run(&machine);
        assert_eq!(frame.status, refused.status, "{}", frame.stdout);
        let frame: serde_json::Value =
            serde_json::from_str(frame.stdout.trim()).expect("one frame");
        assert_eq!(frame["outcome"].as_str(), Some("unavailable"), "{frame}");
        assert_eq!(
            frame["details"]["agreed"],
            serde_json::json!(false),
            "{frame}"
        );
        assert_eq!(
            frame["details"]["update"].as_str(),
            Some(moves),
            "the frame does not say which side has to move: {frame}"
        );
        assert_eq!(
            frame["details"]["caller_speaks"].as_u64(),
            Some(u64::from(other))
        );
        assert_eq!(
            frame["details"]["sure_speaks"].as_u64(),
            Some(u64::from(speaks))
        );
    }
}

#[test]
fn a_refusal_reads_on_the_terminal_and_leaves_standard_output_empty() {
    // `sure check > report.txt` has to put a report in the file and leave the
    // complaint where the person can see it. For a command that produced
    // nothing, the file must therefore be empty rather than full of prose.
    for args in REFUSED {
        let run = run(args);
        assert!(
            run.stdout.is_empty(),
            "`sure {}` wrote to standard output when it had no answer:\n{}",
            args.join(" "),
            run.stdout
        );
        assert!(
            run.stderr.contains("is not implemented in this build"),
            "`sure {}` did not say what was wrong:\n{}",
            args.join(" "),
            run.stderr
        );
    }
}

#[test]
fn the_machine_form_is_one_object_on_one_line_of_standard_output() {
    // A pipeline reads a stream of responses by splitting on newlines, so the
    // machine form is one line, always, and never carries a complaint from
    // somewhere else in the program.
    for args in EVERY_COMMAND {
        let mut machine: Vec<&str> = vec!["--format", "json"];
        machine.extend_from_slice(args);
        let run = run(&machine);

        assert!(
            run.stderr.is_empty(),
            "`sure {} --format json` wrote to standard error, which a script did not ask \
             for:\n{}",
            args.join(" "),
            run.stderr
        );
        assert_eq!(
            run.stdout.lines().count(),
            1,
            "`sure {} --format json` wrote {} lines:\n{}",
            args.join(" "),
            run.stdout.lines().count(),
            run.stdout
        );
        assert!(run.stdout.ends_with('\n'), "the line is not terminated");

        let frame: serde_json::Value = serde_json::from_str(run.stdout.trim())
            .unwrap_or_else(|error| panic!("`sure {}` is not JSON: {error}", args.join(" ")));
        assert_eq!(
            frame["command"].as_str().map(|name| name.split(' ').next()),
            Some(Some(args[0])),
            "the frame names a different command than the one that ran"
        );
        assert!(
            frame["protocol_version"].is_u64() && frame["sure_version"].is_string(),
            "the frame does not say which build and protocol produced it: {frame}"
        );
    }
}

#[test]
fn a_goal_with_no_words_is_a_failure_and_not_a_wrong_command_line() {
    // The half of the goal's process-level coverage that writes nothing; the
    // half that writes is `a_named_store_directory_is_the_one_a_real_run_writes_to`
    // below. A goal with no words in it is refused before SURE looks for its
    // store at all, so the store this run was given stays as empty as it was —
    // which is the assertion at the end, and it is the one that says the refusal
    // happened before the row rather than after it.
    //
    // Status 5, and the two statuses it is not: 2 would mean the parser rejected
    // the command line, and `--goal ""` is accepted — an empty goal is a goal
    // with nothing in it, which is a thing a user can type. 3 would mean this
    // build cannot record a goal, and it can. 5 is "it tried and did not finish",
    // which is what happened.
    let store = a_store_of_our_own();
    for args in [
        &["check", "--goal", ""][..],
        &["check", "--goal", "   "][..],
    ] {
        let human = run_in_a_store(&store, args);
        assert_eq!(
            human.status,
            5,
            "`sure {}` returned {}. A goal with no words in it is a run that could not \
             finish:\n{}",
            args.join(" "),
            human.status,
            human.stderr
        );
        assert!(
            human.stdout.is_empty(),
            "the complaint went to standard output, where `sure check > report.txt` would \
             put it in the file and read as a report:\n{}",
            human.stdout
        );
        assert!(
            human.stderr.contains("could not finish"),
            "`sure check --goal ''` does not say it did not finish:\n{}",
            human.stderr
        );
        // The promise a user has to be able to rely on without reading the code:
        // a run that failed did not change their history.
        assert!(
            human.stderr.contains("Nothing was recorded"),
            "`sure check --goal ''` does not say whether the history changed:\n{}",
            human.stderr
        );
        assert!(
            !human.stderr.contains("is not implemented in this build"),
            "a run that tried is worded as a command this build lacks:\n{}",
            human.stderr
        );

        let mut machine: Vec<&str> = vec!["--format", "json"];
        machine.extend_from_slice(args);
        let machine = run_in_a_store(&store, &machine);
        assert_eq!(machine.status, human.status, "{}", machine.stdout);
        let frame: serde_json::Value =
            serde_json::from_str(machine.stdout.trim()).expect("one frame");
        assert_eq!(frame["outcome"].as_str(), Some("failed"), "{frame}");
        assert_eq!(frame["exit_code"].as_i64(), Some(5), "{frame}");
        assert_eq!(frame["command"].as_str(), Some("check"), "{frame}");
        assert_eq!(
            frame["details"]["what"].as_str(),
            human
                .stderr
                .lines()
                .find(|line| line.contains("Nothing was recorded"))
                .map(str::trim),
            "the two paths disagree about what did not happen: {frame}"
        );
        assert!(
            frame["details"]["detail"]
                .as_str()
                .is_some_and(|detail| !detail.is_empty()),
            "the frame does not say what stopped the run: {frame}"
        );
    }

    // And the store this run was given is still empty: a goal with no words in
    // it is refused before SURE opens anything, so there is no database to clean
    // up and nothing a later run would find.
    assert!(
        !store.join("sure.db").exists(),
        "a goal with no words in it created the store SURE was told to use"
    );
    assert!(
        !store.join("sure.db-wal").exists() && !store.join("sure.db-shm").exists(),
        "a goal with no words in it left a journal beside where the store would go"
    );
}

// --- the history: inspecting it, and being rid of it --------------------

/// The store file a run given this directory writes.
fn store_file(store: &Path) -> PathBuf {
    store.join("sure.db")
}

/// `sure history`, as a script reads it.
///
/// The frame's `details`, which is where every field below is read from. The
/// run is asserted to have answered rather than refused first, because a
/// refusal's `details` is not a history and a test that read one would be
/// asserting about the wrong object.
fn history_frame(store: &Path, args: &[&str]) -> serde_json::Value {
    let mut full: Vec<&str> = vec!["--format", "json", "history"];
    full.extend_from_slice(args);
    let run = run_in_a_store(store, &full);
    assert_ne!(
        run.status,
        3,
        "`sure history {}` says this build cannot carry it out:\n{}",
        args.join(" "),
        run.stderr
    );
    let frame: serde_json::Value =
        serde_json::from_str(run.stdout.trim()).unwrap_or_else(|error| {
            panic!(
                "`sure --format json history {}` is not one frame: {error}\nstdout:\n{}",
                args.join(" "),
                run.stdout
            )
        });
    assert_eq!(
        frame["exit_code"].as_i64(),
        Some(i64::from(run.status)),
        "the frame and the process disagree about the same run: {frame}"
    );
    frame
}

/// Record one real event with `sure hook ingest`, in a session of its own.
///
/// The binary rather than a row written here: what the history has to be able to
/// read is what SURE actually wrote, and an event this test inserted by hand
/// would be the test's idea of an event.
///
/// `afterFileEdit` is not a `pre-tool-use` event, so the run records the event
/// and allows — no protection decision, and therefore no second thing this
/// helper's callers have to think about.
fn record_one_event(store: &Path, project: &Path, harness_session: &str) {
    let payload = serde_json::json!({
        "event": "afterFileEdit",
        "harness_session_id": harness_session,
        "project_root": project.to_str().expect("this test's paths are utf-8"),
        "timestamp_utc": "2026-09-19T12:01:00Z",
        "source": "cursor",
        "path": "src/lib.rs",
    })
    .to_string();

    let mut command = sure_in_a_store(store);
    command.args(["hook", "ingest", "--source", "cursor"]);
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("a child process");
    let mut stdin = child.stdin.take().expect("the pipe");
    stdin.write_all(payload.as_bytes()).expect("write to stdin");
    drop(stdin);

    let output = child.wait_with_output().expect("the child exits");
    assert_eq!(
        output.status.code(),
        Some(0),
        "`sure hook ingest` did not record the event, so there is no history to test:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// A settings file of this test's own, under the same scratch root as the stores
/// and projects.
///
/// Written where the run that reads it will *not* be refused it: a settings file
/// inside the project a run is told about is refused by
/// `Paths::ensure_settings_outside`, which is the rule
/// `a_project_cannot_set_a_settings_file_through_the_environment` and the
/// privacy corpus's own case exercise. A test about what a settings file grants
/// needs one the run will read, so the file goes beside the store and the project
/// rather than inside either.
///
/// The name is the platform's own file name because that is the name the flag
/// stands in for; the *directory* is this test's, and it is never
/// `%APPDATA%\SURE`. Nothing in this file writes there: the file the person
/// running the suite may have is read by `Authority::load` and by nothing else,
/// and no test asserts anything about its contents.
fn a_settings_file_of_our_own(yaml: &str) -> PathBuf {
    let file = a_directory_of_our_own("settings").join("sure.yaml");
    std::fs::write(&file, yaml)
        .unwrap_or_else(|error| panic!("cannot write {}: {error}", file.display()));
    file
}

/// One real `sure hook ingest`, in a store and project the caller named, with an
/// optional settings file named on the command line.
///
/// `afterFileEdit` is not a `pre-tool-use` event, so the run records and allows —
/// the decision path is not what these tests are about. The event carries no
/// secret: these tests read back whether a recording was written, and a payload
/// with a credential in it would make that about redaction instead.
///
/// The settings path goes into the argument vector, beside `--store-dir`, and
/// nothing here sets an environment variable: see
/// `ingest_one_event_through_the_environment` for the one test that does, and for
/// why it expects the variable to be ignored.
fn ingest_one_event(
    store: &Path,
    project: &Path,
    settings: Option<&Path>,
    harness_session: &str,
) -> Run {
    let mut command = sure_in_a_store(store);
    if let Some(file) = settings {
        command.arg("--settings-file").arg(file);
    }
    ingest_with(store, project, harness_session, command)
}

/// The same, with the settings file named through the environment instead.
///
/// The surface a checked project's harness configuration can reach and the
/// argument vector is not. A test that used this and got a recording would have
/// proved that a project can choose the file that decides whether it is
/// recorded.
fn ingest_one_event_through_the_environment(
    store: &Path,
    project: &Path,
    variable: &str,
    settings: &Path,
    harness_session: &str,
) -> Run {
    let mut command = sure_in_a_store(store);
    command.env(variable, settings);
    ingest_with(store, project, harness_session, command)
}

/// The event, the pipe and the wait the three callers above share.
fn ingest_with(_store: &Path, project: &Path, harness_session: &str, mut command: Command) -> Run {
    let payload = serde_json::json!({
        "event": "afterFileEdit",
        "harness_session_id": harness_session,
        "project_root": project.to_str().expect("this test's paths are utf-8"),
        "timestamp_utc": "2026-09-19T12:02:00Z",
        "source": "cursor",
        "path": "src/lib.rs",
    })
    .to_string();

    command.args(["hook", "ingest", "--source", "cursor"]);
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("a child process");
    let mut stdin = child.stdin.take().expect("the pipe");
    stdin.write_all(payload.as_bytes()).expect("write to stdin");
    drop(stdin);

    Run::of(&child.wait_with_output().expect("the child exits"))
}

/// How many full recordings a store holds, and how many events.
///
/// Read from the file the child wrote rather than from what it said, and zero
/// for a store that was never created: "no recording" and "no store" are the
/// same answer to the question these tests ask, and only one of them means the
/// run happened.
fn recordings_in(store: &Path) -> usize {
    records_of_kind(store, RecordKind::Recording)
}

fn events_in(store: &Path) -> usize {
    records_of_kind(store, RecordKind::Document(DocumentKind::Event))
}

/// Rows of one kind, recordings included so that the counting is by the same
/// filter either way: a helper that hid recordings from one call and not the
/// other would make the two counts incomparable.
fn records_of_kind(store: &Path, kind: RecordKind) -> usize {
    if !store_file(store).is_file() {
        return 0;
    }
    open_the_store(store)
        .history(
            &HistoryFilter {
                include_recordings: true,
                ..HistoryFilter::default()
            },
            100,
        )
        .expect("a store this suite's own process wrote")
        .iter()
        .filter(|row| row.kind == kind)
        .count()
}

/// The store, opened by this process.
///
/// Read back rather than taken on trust: `sure history` says what it removed,
/// and a test that believed it would be checking a report against itself. What
/// the assertions below read is the file the child process wrote.
fn open_the_store(store: &Path) -> Store {
    let file = store_file(store);
    Store::open_at(&file).unwrap_or_else(|error| panic!("cannot open {}: {error}", file.display()))
}

#[test]
fn a_history_with_nothing_in_it_says_so_rather_than_printing_an_empty_table() {
    // The first thing a user does after reading that SURE keeps a history is
    // look at it, and on a machine where nothing has been recorded that must be
    // an answer rather than a blank page. "Nothing was recorded" and "SURE could
    // not tell you" have to be different answers, and the second one is a
    // failure with a status.
    let store = a_store_of_our_own();
    let machine = the_store_on_this_machine();

    let human = run_in_a_store(&store, &["history"]);
    assert_eq!(
        human.status, 0,
        "`sure history` on a machine with nothing recorded exited {}. An empty history is an \
         answer, not a failure:\nstdout: {}\nstderr: {}",
        human.status, human.stdout, human.stderr
    );
    assert!(
        human.stderr.is_empty(),
        "the answer went to standard error, so `sure history > history.txt` would leave the \
         file empty:\n{}",
        human.stderr
    );
    assert!(
        human
            .stdout
            .contains("SURE has recorded nothing on this machine yet."),
        "the empty history does not say it is empty:\n{}",
        human.stdout
    );
    assert!(
        human
            .stdout
            .contains(&store_file(&store).display().to_string()),
        "the empty history does not say which store it looked in, so a user who named one \
         cannot tell whether it was used:\n{}",
        human.stdout
    );
    assert!(
        !human.stdout.contains("kept until"),
        "an empty history printed the fields of a session that is not there:\n{}",
        human.stdout
    );

    let frame = history_frame(&store, &[]);
    assert_eq!(frame["outcome"].as_str(), Some("ok"), "{frame}");
    assert_eq!(frame["details"]["total"].as_u64(), Some(0), "{frame}");
    assert_eq!(
        frame["details"]["sessions"],
        serde_json::json!([]),
        "{frame}"
    );
    assert_eq!(
        frame["details"]["store_present"].as_bool(),
        Some(false),
        "a store that is not there was reported as present, or the other way round: {frame}"
    );

    // And it did not create the store it was reporting on. This is the assertion
    // that makes the empty answer worth anything: a command that reported an
    // empty history by making one would have changed the thing it was reporting,
    // and the file it left would be the evidence of a run that claimed to find
    // nothing.
    assert!(
        !store_file(&store).exists(),
        "`sure history` created {} in a store directory it was asked to report on",
        store_file(&store).display()
    );
    assert!(
        !store.join("sure.db-wal").exists() && !store.join("sure.db-shm").exists(),
        "`sure history` left a journal beside where the store would go"
    );
    assert_untouched(&machine, "by a history that found nothing");
}

#[test]
fn a_recorded_session_is_visible_with_its_project_its_harness_and_how_long_it_is_kept() {
    // The inspect half of the acceptance criterion, at the process. Before this
    // task there was no way for a user to see that anything had been recorded at
    // all: the store is a SQLite file in a per-user directory, and both harness
    // integrations told people to run exactly this command.
    let store = a_store_of_our_own();
    let project = a_project_of_our_own();
    let machine = the_store_on_this_machine();
    record_one_event(&store, &project, "cursor-session-inspect");

    let human = run_in_a_store(&store, &["history"]);
    assert_eq!(human.status, 0, "{}", human.stderr);
    for field in [
        "session",
        "project",
        "harness",
        "started",
        "kept for",
        "kept until",
    ] {
        assert!(
            human.stdout.contains(field),
            "the listing does not say `{field}` for the one session that is there:\n{}",
            human.stdout
        );
    }
    assert!(
        human.stdout.contains(&project.display().to_string()),
        "the listing does not say which project the session was recorded against:\n{}",
        human.stdout
    );
    assert!(
        human.stdout.contains("cursor"),
        "the listing does not say which harness sent the events:\n{}",
        human.stdout
    );
    // The sentence that stops a deadline being read as a deletion. Nothing in
    // this build removes a session because a date passed, and a listing that
    // printed a date without saying so would leave a user believing their
    // history was being cleaned up when it was not.
    assert!(
        human.stdout.contains("not a job it runs"),
        "the listing prints a `kept until` date without saying that nothing acts on it:\n{}",
        human.stdout
    );

    let frame = history_frame(&store, &[]);
    assert_eq!(frame["details"]["total"].as_u64(), Some(1), "{frame}");
    let session = &frame["details"]["sessions"][0];
    assert_eq!(
        session["project_root"].as_str(),
        project.to_str(),
        "{frame}"
    );
    assert_eq!(session["harness"].as_str(), Some("cursor"), "{frame}");
    assert_eq!(
        session["harness_session_id"].as_str(),
        Some("cursor-session-inspect"),
        "{frame}"
    );
    // The retention in force for the session row, which is the session event
    // store's own and is not the setting this task made configurable: a session
    // and its events are kept for `DEFAULT_SESSION_RETENTION_DAYS` whatever
    // `privacy.full_recording_retention_days` says, because that setting is
    // about the *recording*, which is a different row. Read from the frame and
    // compared with the constant rather than with a 90 written here: the number
    // is allowed to change, and a test that pinned it would have to be edited by
    // whoever changed it rather than telling them.
    assert_eq!(
        session["retention_days"].as_i64(),
        Some(sure_core::session_event_store::DEFAULT_SESSION_RETENTION_DAYS),
        "the session was recorded with a retention that is not this build's default: {frame}"
    );
    assert!(
        session["retained_until_ms"]
            .as_i64()
            .is_some_and(|until| until > 0),
        "the session carries no retention deadline: {frame}"
    );

    // One session, and the events recorded in it.
    let id = session["sure_session_id"]
        .as_str()
        .expect("a session carries SURE's own identifier")
        .to_owned();
    let shown = history_frame(&store, &["show", &id]);
    assert_eq!(
        shown["details"]["session"]["sure_session_id"].as_str(),
        Some(id.as_str()),
        "{shown}"
    );
    let events = shown["details"]["events"]
        .as_array()
        .expect("a shown session lists its events");
    assert_eq!(events.len(), 1, "{shown}");
    assert_eq!(
        events[0]["event_type"].as_str(),
        Some("file.edited"),
        "{shown}"
    );
    assert!(
        events[0]["record"]["id"].as_i64().is_some(),
        "the event does not say which record it wrote, so a user cannot look one up: {shown}"
    );

    // An id that is not there is a run that did not finish — not a refusal, and
    // not an empty listing under a name that promised one session.
    let missing = run_in_a_store(&store, &["history", "show", "no-such-session"]);
    assert_eq!(
        missing.status, 5,
        "`sure history show <id that is not there>` returned {}. 3 would say this build cannot \
         show a session, and it can; 0 would be an answer to a question nobody answered:\n\
         stdout: {}\nstderr: {}",
        missing.status, missing.stdout, missing.stderr
    );
    assert!(
        missing.stdout.is_empty(),
        "a run with no answer wrote to standard output:\n{}",
        missing.stdout
    );
    assert!(
        missing.stderr.contains("could not finish"),
        "the complaint does not say the run did not finish:\n{}",
        missing.stderr
    );
    assert_untouched(&machine, "by a history that found one session");
}

#[test]
fn a_delete_removes_the_session_its_events_and_its_records_and_says_how_many() {
    // The delete half of the acceptance criterion, and the half that has to be
    // checked against the file rather than against the sentence: a delete that
    // reached `records` and stopped would leave the session and its events in
    // `sessions` and `session_events`, and the report would still say a number.
    //
    // Two projects, because the scope has to mean something: a delete scoped to
    // one of them may not touch the other, and the only way to check that is for
    // there to be another one.
    let store = a_store_of_our_own();
    let kept = a_project_of_our_own();
    let doomed = a_project_of_our_own();
    let machine = the_store_on_this_machine();
    record_one_event(&store, &kept, "keep-me");
    record_one_event(&store, &doomed, "delete-me");

    assert_eq!(
        history_frame(&store, &[])["details"]["total"].as_u64(),
        Some(2),
        "two ingests did not produce two sessions, so this test would prove nothing"
    );

    // The rows the delete has to reach, read from the store by this process, so
    // that what is asserted afterwards is the absence of *those* rows rather
    // than a number the command printed.
    let (doomed_session, doomed_event) = {
        let opened = open_the_store(&store);
        let sessions = SessionEventStore::new(&opened);
        let all = sessions.sessions(10).expect("the sessions this test wrote");
        let doomed_session = all
            .iter()
            .find(|session| session.project_root == doomed.display().to_string())
            .unwrap_or_else(|| panic!("no session for {}: {all:?}", doomed.display()))
            .clone();
        let events = sessions
            .events_for_session(doomed_session.row_id)
            .expect("the events of a session this test wrote");
        assert_eq!(events.len(), 1, "the ingest did not write one event");
        (doomed_session, events[0].clone())
    };
    let doomed_id = doomed_session.sure_session_id.as_str().to_owned();
    let record_row = doomed_event
        .record_row_id
        .expect("every event in this build owns a record");

    let deleted = history_frame(&store, &["delete", "--session", &doomed_id]);
    assert_eq!(
        deleted["details"]["removed"],
        serde_json::json!(true),
        "{deleted}"
    );
    assert_eq!(
        deleted["details"]["deleted"]["sessions"].as_u64(),
        Some(1),
        "{deleted}"
    );
    assert_eq!(
        deleted["details"]["deleted"]["events"].as_u64(),
        Some(1),
        "{deleted}"
    );
    assert_eq!(
        deleted["details"]["deleted"]["records"].as_u64(),
        Some(1),
        "the delete reported removing a session and left the record it wrote: {deleted}"
    );
    assert_eq!(
        deleted["details"]["deleted"]["recordings"].as_u64(),
        Some(0),
        "there was no full recording to remove: {deleted}"
    );

    // And the rows really went.
    {
        let opened = open_the_store(&store);
        let sessions = SessionEventStore::new(&opened);
        assert!(
            sessions
                .session_by_sure_id(&doomed_id)
                .expect("a lookup")
                .is_none(),
            "the session is still in `sessions` after a delete that reported removing it"
        );
        assert!(
            sessions
                .events_for_session(doomed_session.row_id)
                .expect("a lookup")
                .is_empty(),
            "the session's events are still in `session_events`"
        );
        assert!(
            opened.record(record_row).expect("a lookup").is_none(),
            "the record the event wrote is still in `records`"
        );
        assert_eq!(
            sessions.session_count().expect("a count"),
            1,
            "the delete removed more than the scope it was given"
        );
    }

    // The other project's session was not in the scope, and the second scope
    // proves it is still there by removing it.
    let remaining = history_frame(&store, &[]);
    assert_eq!(
        remaining["details"]["sessions"][0]["project_root"].as_str(),
        kept.to_str(),
        "the survivor is not the session the delete was not asked about: {remaining}"
    );
    let kept_root = kept.display().to_string();
    let second = history_frame(&store, &["delete", "--project", &kept_root]);
    assert_eq!(
        second["details"]["deleted"]["sessions"].as_u64(),
        Some(1),
        "{second}"
    );
    assert_eq!(
        history_frame(&store, &[])["details"]["total"].as_u64(),
        Some(0),
        "a delete scoped to a project left a session behind"
    );

    // A scope that matches nothing says it matched nothing, in those words and
    // in the frame, rather than reporting a deletion that did not happen.
    let nothing = run_in_a_store(&store, &["history", "delete", "--all"]);
    assert_eq!(nothing.status, 0, "{}", nothing.stderr);
    assert!(
        nothing.stdout.contains("Nothing was deleted."),
        "a delete that matched nothing did not say so:\n{}",
        nothing.stdout
    );
    let again = history_frame(&store, &["delete", "--all"]);
    assert_eq!(
        again["details"]["removed"],
        serde_json::json!(false),
        "{again}"
    );
    assert_eq!(
        again["details"]["deleted"]["sessions"].as_u64(),
        Some(0),
        "{again}"
    );
    assert_untouched(&machine, "by a delete that named a store");
}

#[test]
fn a_delete_reaches_a_full_recording_that_its_session_event_wrote() {
    // A full recording is a **second** `records` row, written beside the one the
    // event owns, and nothing in the schema links the two: `session_events`
    // holds the id of the record the event wrote, and the recording carries its
    // event's id inside its JSON document. `PRAGMA foreign_keys` is not set
    // anywhere in this workspace, so the `REFERENCES` clauses in the migrations
    // are documentation rather than enforcement and there is no cascade to
    // inherit. A delete that only walked the columns would therefore leave every
    // full recording behind — the one thing a user deleting their history most
    // wants gone.
    //
    // The rows are written here through the same functions `sure hook ingest`
    // calls, with one `EventId` shared by both writes, because that sharing is
    // the whole of the link and building it by hand is the only way to be sure
    // the test is about it.
    let store_dir = a_store_of_our_own();
    let project = a_project_of_our_own();
    let project_root = project.to_str().expect("this test's paths are utf-8");

    let payload = serde_json::json!({
        "event": "afterFileEdit",
        "harness_session_id": "cursor-session-recording",
        "project_root": project_root,
        "timestamp_utc": "2026-09-19T12:01:00Z",
        "source": "cursor",
        "path": "src/lib.rs",
    })
    .to_string();
    let envelope = sure_core::normalizer::cursor::normalize(&payload).expect("a cursor event");
    let ingested = sure_core::harness_event::ingest_event_str(
        &envelope
            .to_json()
            .expect("an envelope this build can serialise"),
    )
    .expect("a valid event");

    let store = Store::open_at(&store_file(&store_dir)).expect("a store this test made");
    let fingerprint = sure_core::fingerprint::project_fingerprint(
        &project,
        &sure_core::fingerprint::FingerprintOptions::default(),
    )
    .expect("a project this build can fingerprint")
    .id;
    let event_id = sure_core::ids::EventId::generate();
    SessionEventStore::new(&store)
        .persist(&ingested, project_root, &fingerprint, &event_id)
        .expect("an event");
    let recording_row = sure_core::full_recording::persist_full_recording(
        &store,
        &ingested,
        &event_id,
        project_root,
        &fingerprint,
        sure_core::full_recording::FullRecordingConsent::Full,
        1,
    )
    .expect("a full recording");
    let sure_session_id = SessionEventStore::new(&store)
        .sessions(10)
        .expect("the session this test wrote")[0]
        .sure_session_id
        .as_str()
        .to_owned();
    assert!(
        store.record(recording_row).expect("a lookup").is_some(),
        "this test did not manage to write a full recording, so it would prove nothing"
    );

    // The recording's own deadline is in the surface the user inspects, because
    // `records` has no retention column and the document is where a recording
    // says how long it is kept.
    let shown = history_frame(&store_dir, &["show", &sure_session_id]);
    let record = &shown["details"]["events"][0]["record"];
    assert_eq!(record["kind"].as_str(), Some("event"), "{shown}");
    assert!(
        record["retained_until_ms"].is_null(),
        "the record the event owns is not the recording: {shown}"
    );

    let deleted = history_frame(&store_dir, &["delete", "--all"]);
    assert_eq!(
        deleted["details"]["deleted"]["recordings"].as_u64(),
        Some(1),
        "the delete did not reach the full recording: {deleted}"
    );
    assert_eq!(
        deleted["details"]["deleted"]["records"].as_u64(),
        Some(1),
        "the delete did not reach the record the event wrote: {deleted}"
    );
    assert!(
        store.record(recording_row).expect("a lookup").is_none(),
        "the full recording survived a delete that reported removing it"
    );
}

#[test]
fn a_project_that_asks_for_full_recording_does_not_get_one() {
    // Criterion 1 as it reaches the recording. `privacy.full_recording` is a
    // *request* — the setting says "record more", and recording more is not
    // running more — so only the user's own file may grant it
    // (`Authority::full_recording`, `Layer::can_grant`). Before P13-T009 the
    // hook read this setting out of the project's file alone (`Config::load`,
    // beside the `Authority::load` that already arbitrated the retention one
    // line away in the same function), so a repository the user merely opened
    // turned recording on.
    //
    // What the process is asked here is everything a project can ask for, and
    // the difference is the whole test: the event is recorded and the store
    // holds no recording.
    //
    // **The retention number is not observable from here**, and that is said
    // rather than left for a reader to assume. A recording is written only when
    // the user's own file asked for one; that file is
    // `%APPDATA%\SURE\sure.yaml` on this machine and no test may write it. This
    // case names no settings file at all, so what it asserts is the default: a
    // project's `true` is refused and no recording is written. The consented
    // half at the binary layer — a real run pointed at a granting file, and the
    // recording it wrote read back byte by byte — is
    // `crates/sure-cli/tests/privacy_suite.rs`'s
    // `a-full-recording-written-under-consent-is-redacted-on-disk`, whose
    // settings file that suite writes and names with `--settings-file`. The
    // *number* is still not asserted by any process: `hook.rs`'s
    // `a_project_file_cannot_outlast_the_users_retention` covers it in-process,
    // through `Paths::from_roots`, with a user file it writes itself.
    let store = a_store_of_our_own();
    let project = a_project_of_our_own();
    std::fs::write(
        project.join("sure.yaml"),
        "privacy:\n  full_recording: true\n  full_recording_retention_days: 0\n",
    )
    .expect("a project file this test wrote");
    record_one_event(&store, &project, "cursor-session-retention");

    let store = open_the_store(&store);

    // The event itself was recorded, so "no recording" is an absence beside
    // something rather than an empty store: SURE read the request, and what the
    // project asked for is the only thing that is missing.
    let everything = store
        .history(
            &HistoryFilter {
                include_recordings: true,
                ..HistoryFilter::default()
            },
            10,
        )
        .expect("the store this test's hook wrote");
    assert_eq!(
        everything.len(),
        1,
        "the hook recorded no event at all, so this test would pass for the wrong reason"
    );
    assert_ne!(
        everything[0].kind,
        RecordKind::Recording,
        "the one row in this store is the recording this test says was refused"
    );

    let recordings = store
        .history(&HistoryFilter::recordings(), 10)
        .expect("a store this build can read");
    assert!(
        recordings.is_empty(),
        "a project's own file turned the full recording on, which only the user's file may do: \
         {} recording(s) were written",
        recordings.len()
    );
}

#[test]
fn a_named_settings_file_is_the_one_a_real_run_reads_and_no_other() {
    // Acceptance line 1 of P15-T025, as a two-sided pair: one command, one
    // event, one project, one store each, and two settings files that say
    // opposite things about the same setting. The answer has to follow the file
    // that was named, in both directions.
    //
    // Why it takes both directions rather than one. A named file that grants and
    // produces a recording shows the file was read *if* the alternative —
    // the platform's own file, which on this machine is not there — would have
    // answered differently, and on this machine it would. But that is a fact
    // about this machine. The pair is a fact about the code: the same run with
    // the other file named writes nothing, so the flag is not being ignored in
    // favour of a default that happens to agree, and the first file is not
    // sticking for later runs.
    //
    // `privacy.full_recording` is the setting because it is the one whose answer
    // is a file on disk rather than a sentence, and because it is the one only
    // the user's layer can grant — see
    // `a_project_that_asks_for_full_recording_does_not_get_one` next door, which
    // is the same setting with a project's file doing the asking.
    let granting = a_settings_file_of_our_own("privacy:\n  full_recording: true\n");
    let refusing = a_settings_file_of_our_own("privacy:\n  full_recording: false\n");

    let granted_store = a_store_of_our_own();
    let granted_project = a_project_of_our_own();
    let machine = the_store_on_this_machine();
    let granted = ingest_one_event(
        &granted_store,
        &granted_project,
        Some(&granting),
        "p15t025-named-granting",
    );
    assert!(
        granted.succeeded(),
        "the run that named a granting settings file did not finish:\n{}",
        granted.stderr
    );
    assert_eq!(
        recordings_in(&granted_store),
        1,
        "the run named {} and wrote no full recording, so either the file it named was not read or \
         the recording was refused for some other reason:\n{}",
        granting.display(),
        granted.stderr
    );

    let refused_store = a_store_of_our_own();
    let refused_project = a_project_of_our_own();
    let refused = ingest_one_event(
        &refused_store,
        &refused_project,
        Some(&refusing),
        "p15t025-named-refusing",
    );
    assert!(
        refused.succeeded(),
        "the run that named a refusing settings file did not finish:\n{}",
        refused.stderr
    );
    assert_eq!(
        recordings_in(&refused_store),
        0,
        "the run named {} and wrote a full recording anyway, so the file it named is not the file \
         that answered: {} recording(s)",
        refusing.display(),
        recordings_in(&refused_store)
    );

    // The event is in both stores, so the pair is about the recording and not
    // about one run having failed to record anything at all.
    for store in [&granted_store, &refused_store] {
        assert_eq!(
            events_in(store),
            1,
            "a run recorded no event, so the assertions above are about a run that did not happen"
        );
    }

    assert_untouched(&machine, "by a run that named a settings file");
}

#[test]
fn a_project_cannot_set_a_settings_file_through_the_environment() {
    // Acceptance line 2's other half, attempted rather than promised. The flag
    // is a value in the child's own argument vector; the other surface a checked
    // project *can* reach is the environment of the processes it starts, because
    // a harness configuration in the project names the command a hook is run as
    // and can set that command's environment with it.
    //
    // So this test sets the variable the flag would have if it were one, points
    // it at a file the run would *accept* on a command line — outside the
    // project, granting full recording — and requires the run to ignore it.
    // That is the strongest form of the attempt: not a file SURE would refuse,
    // and not a name it would refuse, but a file and a name that would both be
    // honoured if the variable existed. It is the same rule `--store-dir` states
    // about `SURE_STORE_DIR`, and the same reason one step out.
    //
    // The scan in `nothing_a_project_can_write_decides_where_the_store_goes`
    // covers the structural half — a `var` call in a module that decides a
    // location fails there, whatever the variable is called. This is the
    // behavioural half, and it is about the name a reader of the documentation
    // would try.
    let store = a_store_of_our_own();
    let project = a_project_of_our_own();
    let machine = the_store_on_this_machine();
    let granting = a_settings_file_of_our_own("privacy:\n  full_recording: true\n");

    let run = ingest_one_event_through_the_environment(
        &store,
        &project,
        "SURE_SETTINGS_FILE",
        &granting,
        "p15t025-environment",
    );
    assert!(
        run.succeeded(),
        "the run did not finish, and a variable nothing reads should not be able to stop it:\n{}",
        run.stderr
    );
    assert_eq!(
        events_in(&store),
        1,
        "the run recorded no event, so the assertion below is about a run that did not happen"
    );
    assert_eq!(
        recordings_in(&store),
        0,
        "SURE_SETTINGS_FILE named {} and the run obeyed it. A settings file's location that a \
         variable can set is a location the harness configuration of a checked project can set, \
         and the file that decides whether a recording is kept is then a file the judged project \
         can write.",
        granting.display()
    );

    assert_untouched(
        &machine,
        "by a run that named a settings file through the environment",
    );
}

#[test]
fn an_mcp_session_refuses_a_settings_file_named_on_its_command_line() {
    // The one command that refuses the flag outright. `sure mcp serve` answers
    // tool calls for a session a harness is driving, and every command it runs
    // goes through the store that session was started with; there is no consent
    // question in it that a settings file answers, so a name given there is not
    // accepted-and-ignored — it is refused, with a status, before the session
    // starts.
    //
    // The distinction matters for a session in particular. A session lives for
    // as long as a harness keeps talking to it, so a settings file taken at
    // start-up would be in force for every call in it, long after the command
    // line that named it was read — the shape of a grant nobody can see the end
    // of. Refusing keeps the answer to one run of one command.
    let store = a_store_of_our_own();
    let machine = the_store_on_this_machine();
    let granting = a_settings_file_of_our_own("privacy:\n  full_recording: true\n");

    let run = run_in_a_store(
        &store,
        &[
            "--settings-file",
            granting.to_str().expect("this test's paths are utf-8"),
            "mcp",
            "serve",
        ],
    );
    assert_eq!(
        run.status, 5,
        "`sure mcp serve --settings-file X` answered with status {} rather than 5. A session that \
         ignored the name would serve every tool call under a settings file its caller chose, and \
         a session that accepted it would do the same without saying so:\n{}",
        run.status, run.stderr
    );
    assert!(
        run.stdout.is_empty(),
        "the refused session wrote to standard output, which is the stream a protocol session \
         speaks on:\n{}",
        run.stdout
    );
    assert!(
        run.stderr.contains("does not accept a settings file"),
        "the refusal does not say what it refused:\n{}",
        run.stderr
    );

    assert_untouched(&machine, "by a session that refused a settings file");
}

// ---------------------------------------------------------------------------
// P15-T022 — the grants only the person in front of the machine can make
// ---------------------------------------------------------------------------
//
// Full recording and every execution mode other than `inspect_only` are granted
// by the user's own settings file and by nothing else: a checked project's
// `sure.yaml` may ask for both and can never grant either (`Layer::can_grant`).
// Until `sure config set` existed that sentence had no remedy — the file had no
// writer, so a person read "not in force" and had nothing to do about it — and
// these tests are the remedy checked from outside the process: commands this
// build ships, run against a file that is not there, and then what a later run
// says about what is in force.
//
// Every settings file here is a path under `target/tmp` handed to
// `--settings-file`. **Nothing in this file reads or writes the settings file of
// the person running the suite**, and no test asserts anything about its
// contents: the runs below name their own file, which is what the flag is for.

/// The settings file of a person who has never made one: a path, and no file.
///
/// Nothing here creates it. The whole question is what a machine with no
/// settings file at all can reach, so every test below starts from a path that
/// is not there and reads what the commands did with it.
fn a_settings_file_nobody_has_written_yet() -> PathBuf {
    a_directory_of_our_own("settings-nobody-wrote").join("sure.yaml")
}

/// A project whose own `sure.yaml` asks for the two things only the user's file
/// may grant.
///
/// The asking is the point. What a run has to be able to say — before and after —
/// is the difference between *this project asked* and *the user granted*, and
/// these are the two settings that distinction is made of: `privacy.full_recording`
/// and `execution.mode`, the two answers `Authority` gives the user's layer and
/// no other.
///
/// The project's file asks for exactly those two and nothing else, so that the
/// refused list below is a list this fixture controls rather than a list the
/// project happened to make longer.
fn a_project_that_asks_for_what_only_a_users_file_can_grant() -> PathBuf {
    let project = a_project_of_our_own();
    std::fs::write(
        project.join("sure.yaml"),
        "execution:\n  mode: host_confirmed\nprivacy:\n  full_recording: true\n",
    )
    .unwrap_or_else(|error| panic!("cannot write into {}: {error}", project.display()));
    project
}

/// One `sure config set`, run **from inside** the project.
///
/// The working directory is the project because that is where a person is
/// standing when they are trying to make their machine do something about it,
/// and because it is the condition P15-T022's third clause is written in: a
/// write run from inside a project must not reach that project's files.
fn config_set(store: &Path, settings: &Path, project: &Path, setting: &str, value: &str) -> Run {
    let mut command = sure_in_a_store(store);
    command
        .current_dir(project)
        .arg("--settings-file")
        .arg(settings)
        .args(["config", "set", setting, value]);
    Run::of(
        &command
            .output()
            .unwrap_or_else(|error| panic!("could not run {SURE}: {error}")),
    )
}

/// One `sure check --format json`, run from inside the project, with the frame.
///
/// A check rather than a direct call to the reader: what these tests have to
/// show is what a *run* says, from outside the process, and the process is the
/// only place that answer exists. A check of a project this small is not green,
/// which is not what any assertion below is about — they read `details.grants`,
/// which is there whatever the verdict was.
fn check_frame(store: &Path, settings: &Path, project: &Path) -> serde_json::Value {
    let mut command = sure_in_a_store(store);
    command
        .current_dir(project)
        .arg("--settings-file")
        .arg(settings)
        .args(["--format", "json", "check"]);
    let run = Run::of(
        &command
            .output()
            .unwrap_or_else(|error| panic!("could not run {SURE}: {error}")),
    );
    serde_json::from_str(run.stdout.trim()).unwrap_or_else(|error| {
        panic!(
            "`sure --format json check` is not one frame: {error}\nstdout:\n{}\nstderr:\n{}",
            run.stdout, run.stderr
        )
    })
}

/// The grants block of a check's frame: what is in force, and what was refused.
fn grants_of(frame: &serde_json::Value) -> &serde_json::Value {
    &frame["details"]["grants"]
}

/// The requests a check reported as asked for by somebody who could not grant
/// them.
fn refused_requests(grants: &serde_json::Value) -> Vec<&str> {
    grants["refused"]
        .as_array()
        .expect("a grants block carries the requests it refused as a list")
        .iter()
        .filter_map(|row| row["request"].as_str())
        .collect()
}

/// The first line of what a command printed, which is the sentence a person
/// reads before anything else.
fn first_line(text: &str) -> &str {
    text.lines().next().unwrap_or_default()
}

#[test]
fn a_setting_only_a_users_own_file_can_grant_is_written_and_a_later_run_reports_it_in_force() {
    // P15-T022, clauses 0, 1, 2 and 5, as one story a person could live: a
    // machine with no settings file, a project asking in its own `sure.yaml` for
    // an execution mode and a full recording, the commands this build ships, and
    // a run afterwards that reports both as in force because the *user* said so.
    //
    // The "before" half is what makes the "after" half mean something. A run
    // that reported `host_confirmed` on its own would be a run whose answer came
    // from somewhere else — a default that moved, a project's request being
    // honoured, a flag that was already in force — and on this fixture the two
    // answers are opposite by construction: the project asks and the run refuses,
    // and only a file the test writes in between can change that.
    let store = a_store_of_our_own();
    let project = a_project_that_asks_for_what_only_a_users_file_can_grant();
    let settings = a_settings_file_nobody_has_written_yet();
    let machine = the_store_on_this_machine();
    assert!(
        !settings.exists(),
        "this test starts from a machine with no settings file, and {} is already there. Nothing \
         in this suite writes the settings file of the person running it, so a file at a path \
         under this test's own `target/tmp` directory came from somewhere else.",
        settings.display()
    );

    let before = check_frame(&store, &settings, &project);
    let grants = grants_of(&before);
    assert_eq!(
        grants["settings_file_read"],
        serde_json::json!(false),
        "the run says it read a settings file this test never wrote: {grants}"
    );
    assert_eq!(
        grants["execution_mode"],
        serde_json::json!("inspect_only"),
        "a project's own `sure.yaml` asking for `host_confirmed` produced that mode with no \
         settings file anywhere. Only the user's own file may grant an execution mode, and before \
         P15-T022 there was no command that wrote one: {grants}"
    );
    let refused = refused_requests(grants);
    assert!(
        refused.contains(&"run_project_code") && refused.contains(&"full_recording"),
        "the run did not report the project's two requests as asked for and not in force, so the \
         run after the write would not be showing a grant taking effect: {refused:?}"
    );

    // The write, from inside the project, naming a file that is not there yet.
    for (setting, value) in [
        ("execution.mode", "host_confirmed"),
        ("privacy.full_recording", "true"),
    ] {
        let run = config_set(&store, &settings, &project, setting, value);
        assert_eq!(
            run.status, 0,
            "`sure config set {setting} {value}` did not finish, so a person on a machine with no \
             settings file has no way to reach one:\n{}\n{}",
            run.stdout, run.stderr
        );
        // Clause 1: the location in the operating system's own terms. The
        // assertion is against the path the test handed in, spelled by
        // `Path::display` for the machine this is running on, which on Windows
        // is the form Explorer shows. A relative path, a platform path the test
        // did not name, or `%APPDATA%` spelled out would all fail here.
        assert!(
            run.stdout.contains(&settings.display().to_string()),
            "the confirmation does not name {} as this machine spells it:\n{}",
            settings.display(),
            run.stdout
        );
        // Clause 5, the write half: what it says after changing something.
        assert!(
            first_line(&run.stdout).contains("wrote your settings file"),
            "the confirmation does not say a write happened:\n{}",
            run.stdout
        );
    }
    assert!(
        settings.is_file(),
        "the command reported a write and {} is not a file",
        settings.display()
    );
    assert!(
        !settings.starts_with(&project),
        "the settings file this test asked for is inside the project, which makes every assertion \
         below about a different question than the one P15-T022 asks"
    );

    // The read-back, through a process and not through this test: one run later,
    // of a command that was already there.
    let after = check_frame(&store, &settings, &project);
    let grants = grants_of(&after);
    assert_eq!(
        grants["settings_file_read"],
        serde_json::json!(true),
        "the run after the write does not say it read the settings file that was written: {grants}"
    );
    assert_eq!(
        grants["execution_mode"],
        serde_json::json!("host_confirmed"),
        "the setting the command wrote is not the one in force. This is the pair clause 2 is \
         about: the same `Authority::execution_mode` answer, first refused as a project's request \
         and now granted as the user's own: {grants}"
    );
    assert_eq!(
        grants["full_recording"],
        serde_json::json!(true),
        "the second of the two answers only the user's file can give, reported as not in force \
         after the command that wrote it: {grants}"
    );
    assert!(
        grants["granted"]
            .as_array()
            .expect("a grants block carries what was granted as a list")
            .contains(&serde_json::json!("run_project_code")),
        "the run does not report the project's request as granted, so what changed is the file this \
         test wrote and not the request being met: {grants}"
    );
    assert!(
        refused_requests(grants).is_empty(),
        "requests are still reported as not in force after the user's file granted them: {:?}",
        refused_requests(grants)
    );
    assert_eq!(
        after["details"]["mode"],
        serde_json::json!("host_confirmed"),
        "the grants block and the verdict disagree about the mode this run was under: {}",
        after["details"]["mode"]
    );

    assert_untouched(
        &machine,
        "by a command that wrote a settings file of its own",
    );
}

#[test]
fn a_run_reports_a_grant_as_the_users_own_and_the_absence_of_one_as_the_projects_request() {
    // Clause 2's contrast, and clause 1's second half, on one fixture and in one
    // direction each. The same project asks the same question twice; the only
    // difference is whether the user's file says yes.
    //
    // A person reads the answer rather than a JSON field: what the run prints
    // when a setting they asked for is not in force has to name the file that
    // would grant it and the command that writes it there. Without that, the
    // "not in force" is a refusal with no remedy — which is what P15-T022 was
    // opened about, and the reason a passing test here has to check the remedy
    // and not only the refusal.
    let store = a_store_of_our_own();
    let project = a_project_that_asks_for_what_only_a_users_file_can_grant();
    let settings = a_settings_file_nobody_has_written_yet();
    let machine = the_store_on_this_machine();

    let mut command = sure_in_a_store(&store);
    command
        .current_dir(&project)
        .arg("--settings-file")
        .arg(&settings)
        .arg("check");
    let run = Run::of(
        &command
            .output()
            .unwrap_or_else(|error| panic!("could not run {SURE}: {error}")),
    );
    assert!(
        run.stdout.contains("Asked for, and not in force"),
        "a run that could not honour a request did not say so where a person would read it:\n{}",
        run.stdout
    );
    assert!(
        run.stdout.contains(&settings.display().to_string()),
        "the run says a grant is missing and does not name the file where it would go ({}):\n{}",
        settings.display(),
        run.stdout
    );
    // The remedy, named as the command a person can run. `run_project_code` is
    // the request the fixture's own `sure.yaml` makes, and the mode that would
    // grant it is the one this build's own command writes.
    assert!(
        run.stdout.contains("sure config set execution.mode"),
        "the run names what is missing and not what would fix it:\n{}",
        run.stdout
    );
    // Both halves of the same paragraph, so the sentence is about the user's own
    // file rather than about settings in general.
    assert!(
        run.stdout.contains("your own settings file"),
        "the refusal does not say whose file the missing grant belongs in:\n{}",
        run.stdout
    );

    // Both requests, because the fixture makes both: a run that reports one of
    // them still refused is a different statement from the one this test is
    // making, and an assertion that only glanced at the first would not notice.
    for (setting, value) in [
        ("execution.mode", "host_confirmed"),
        ("privacy.full_recording", "true"),
    ] {
        let written = config_set(&store, &settings, &project, setting, value);
        assert_eq!(
            written.status, 0,
            "writing {setting} from the run's own remedy did not finish:\n{}\n{}",
            written.stdout, written.stderr
        );
    }
    let after = check_frame(&store, &settings, &project);
    assert!(
        refused_requests(grants_of(&after)).is_empty(),
        "the grants written by the commands the previous run named did not take the requests off \
         the refused list: {}",
        grants_of(&after)
    );

    assert_untouched(&machine, "by a run that named a settings file of its own");
}

#[test]
fn a_full_recording_granted_by_the_users_own_file_is_one_a_real_run_keeps() {
    // Clause 0's other half and clause 2's strongest form: not a sentence in a
    // report but a file on disk. `privacy.full_recording` is the setting a
    // person reaches for, and what they get for it has to be an actual recording
    // — so the observation is a store this test reads afterwards, written by a
    // hook run in a store of its own, with the same event either side of one
    // command.
    //
    // Both directions are needed. A recording after the write shows the file was
    // read; no recording before it shows the write is what changed the answer,
    // and not a default, a build, or an event that records nothing anyway — the
    // event is in both stores, which is asserted below.
    let granting_store = a_store_of_our_own();
    let project = a_project_of_our_own();
    let settings = a_settings_file_nobody_has_written_yet();
    let machine = the_store_on_this_machine();

    let before = ingest_one_event(&granting_store, &project, Some(&settings), "p15t022-before");
    assert!(
        before.succeeded(),
        "the hook run before the write did not finish:\n{}",
        before.stderr
    );
    assert_eq!(
        recordings_in(&granting_store),
        0,
        "a full recording was kept with no settings file anywhere, so this setting is not the \
         user's to grant and the write below proves nothing"
    );

    let written = config_set(
        &granting_store,
        &settings,
        &project,
        "privacy.full_recording",
        "true",
    );
    assert_eq!(
        written.status, 0,
        "`sure config set privacy.full_recording true` did not finish:\n{}\n{}",
        written.stdout, written.stderr
    );

    let after = ingest_one_event(&granting_store, &project, Some(&settings), "p15t022-after");
    assert!(
        after.succeeded(),
        "the hook run after the write did not finish:\n{}",
        after.stderr
    );
    assert_eq!(
        recordings_in(&granting_store),
        1,
        "the settings file this build wrote is not the file a run reads: the run kept {} \
         recording(s), and the same command wrote one when the same settings were written by hand \
         (`a_named_settings_file_is_the_one_a_real_run_reads_and_no_other`)",
        recordings_in(&granting_store)
    );
    assert_eq!(
        events_in(&granting_store),
        2,
        "the two events did not both land in the store, so the count of recordings above is about \
         runs that did not happen"
    );

    assert_untouched(
        &machine,
        "by a hook run under a settings file this build wrote",
    );
}

#[test]
fn a_settings_file_that_will_not_parse_is_never_more_permissive_than_no_file_at_all() {
    // The failure direction of the reader `sure config set` writes for, and the
    // reason the `--settings-file` section has two answers rather than one:
    // `Authority::load`'s rule is that one bad file stops the read, because a
    // file SURE cannot read is not a file that declared nothing, and carrying on
    // would run under defaults while the person believes their settings are in
    // force.
    //
    // The two files differ by one key, and both ask for the same full recording.
    // That is the shape worth testing: a run that fell back to "whatever I could
    // read out of it" would keep a recording out of a file SURE could not read —
    // a grant made by writing a typo — and this pair is what rules it out in
    // both directions at once.
    let project = a_project_of_our_own();
    let machine = the_store_on_this_machine();
    let readable = a_settings_file_of_our_own("privacy:\n  full_recording: true\n");
    let unreadable = a_settings_file_of_our_own("privacy:\n  full_recording: true\n  nope: 1\n");

    // A hook first, because it is the command that has somebody waiting on it:
    // the event is still recorded, and what it is decided with is the least
    // permissive answer SURE has.
    let machine_checked = a_store_of_our_own();
    let bad = ingest_one_event(
        &machine_checked,
        &project,
        Some(&unreadable),
        "p15t022-unreadable",
    );
    assert!(
        bad.succeeded(),
        "a hook under a settings file that will not parse did not answer:\n{}",
        bad.stderr
    );
    assert_eq!(
        events_in(&machine_checked),
        1,
        "the event was not recorded, so the fallback is not 'carry on without the settings' but \
         'drop the event'"
    );
    assert_eq!(
        recordings_in(&machine_checked),
        0,
        "a full recording was kept out of a settings file SURE could not read. A file with a typo \
         in it would then be a grant, which is the one direction this reader must never fail in"
    );

    let readable_store = a_store_of_our_own();
    let good = ingest_one_event(
        &readable_store,
        &project,
        Some(&readable),
        "p15t022-readable",
    );
    assert!(
        good.succeeded(),
        "the hook under the readable file did not finish:\n{}",
        good.stderr
    );
    assert_eq!(
        recordings_in(&readable_store),
        1,
        "the readable file did not grant the recording either, so the pair above shows nothing \
         about the unreadable one"
    );

    // A check, which has nobody waiting on it and therefore stops: the execution
    // mode every dynamic check is authorised under is a setting that file
    // decides, so a run that could not read it has nothing to check with.
    let check_store = a_store_of_our_own();
    let mut command = sure_in_a_store(&check_store);
    command
        .current_dir(&project)
        .arg("--settings-file")
        .arg(&unreadable)
        .arg("check");
    let checked = Run::of(
        &command
            .output()
            .unwrap_or_else(|error| panic!("could not run {SURE}: {error}")),
    );
    assert_eq!(
        checked.status, 5,
        "a check under a settings file that will not parse exited {} rather than 5. It is not 3 — \
         this build can check a project — and it is not 0 or 1, which would be a verdict about a \
         project the run had no authority to check:\n{}\n{}",
        checked.status, checked.stdout, checked.stderr
    );
    assert!(
        checked.stderr.contains(&unreadable.display().to_string()),
        "the run does not name the file it could not read, which is the one thing a person has to \
         fix:\n{}",
        checked.stderr
    );
    assert!(
        checked.stdout.is_empty(),
        "a run that stopped wrote an answer to standard output:\n{}",
        checked.stdout
    );

    assert_untouched(
        &machine,
        "by runs under a settings file that will not parse",
    );
}

#[test]
fn a_write_a_no_op_and_a_refusal_are_three_different_sentences() {
    // Clause 5. What the command prints when it changed something has to be a
    // different sentence from what it prints when it changed nothing, or a person
    // cannot tell a write from a no-op without opening the file — and the third
    // case, a refusal, must not be mistaken for either.
    //
    // The assertions are on the *first line* of each run and on the three being
    // distinct, not on the words: what the sentence says is SURE's to change, and
    // the clause is about a person being able to tell them apart.
    let store = a_store_of_our_own();
    let project = a_project_of_our_own();
    let settings = a_settings_file_nobody_has_written_yet();
    let machine = the_store_on_this_machine();

    let write = config_set(
        &store,
        &settings,
        &project,
        "execution.mode",
        "host_confirmed",
    );
    assert_eq!(
        write.status, 0,
        "the write did not finish:\n{}",
        write.stderr
    );
    let first_write = first_line(&write.stdout).to_owned();

    let wrote = std::fs::read(&settings).unwrap_or_else(|error| {
        panic!(
            "the write reported success and {} cannot be read: {error}",
            settings.display()
        )
    });

    // The same command again, which has nothing left to change.
    let no_op = config_set(
        &store,
        &settings,
        &project,
        "execution.mode",
        "host_confirmed",
    );
    assert_eq!(
        no_op.status, 0,
        "a no-op is not a failure — what was asked for was already true — and this one exited {}:\n{}",
        no_op.status, no_op.stderr
    );
    let first_no_op = first_line(&no_op.stdout).to_owned();
    assert_ne!(
        first_write, first_no_op,
        "a write and a no-op print the same sentence, so a person cannot tell from the terminal \
         whether the command changed anything:\n{first_write}"
    );
    assert!(
        first_no_op.contains("nothing"),
        "the no-op's sentence does not say that nothing was written:\n{first_no_op}"
    );
    let after_no_op =
        std::fs::read(&settings).unwrap_or_else(|error| panic!("{}: {error}", settings.display()));
    assert!(
        wrote == after_no_op,
        "the command that reported changing nothing rewrote the file anyway: {} bytes became {}",
        wrote.len(),
        after_no_op.len()
    );

    // A setting this command will not write, which is the third answer. A
    // refusal is not an answer, so its human form goes to standard error and
    // standard output stays empty — the rule the rest of this file checks for
    // every command this build refuses, applied to the one command where the
    // refusal is about a file rather than about the command itself.
    let refused = config_set(&store, &settings, &project, "checks.existing_tests", "true");
    assert_eq!(
        refused.status, 5,
        "a refusal exited {} rather than 5. It is not 2 — the command line was understood — and it \
         is not 0, which would be a report of success for a file that was not written:\n{}",
        refused.status, refused.stderr
    );
    assert!(
        refused.stdout.is_empty(),
        "a refusal wrote to standard output, which is the stream a script reads an answer \
         from:\n{}",
        refused.stdout
    );
    let first_refused = first_line(&refused.stderr).to_owned();
    assert_ne!(
        first_refused, first_write,
        "a refusal and a write print the same sentence:\n{first_refused}"
    );
    assert_ne!(
        first_refused, first_no_op,
        "a refusal and a no-op print the same sentence, so a person cannot tell a setting SURE \
         will not write from one it had nothing to do about:\n{first_refused}"
    );
    let after_refusal =
        std::fs::read(&settings).unwrap_or_else(|error| panic!("{}: {error}", settings.display()));
    assert!(
        wrote == after_refusal,
        "a refused command changed the settings file anyway"
    );

    assert_untouched(
        &machine,
        "by a command that wrote a settings file of its own",
    );
}

#[test]
fn no_path_of_a_config_write_reaches_the_projects_own_sure_yaml() {
    // Clause 3, both halves, against one project whose own `sure.yaml` names one
    // of the settings being written.
    //
    // That is the sharpest fixture for this clause: the project has a file, the
    // file is exactly where a naive implementation would write, and the setting
    // is one the file already mentions. If any path of the command reached it,
    // the bytes would differ — and if a write were redirected there, the project
    // would have granted itself what only the user may grant.
    //
    // The second half is the other direction: a request that names a setting a
    // *project* may make is refused rather than written anywhere, because the
    // user's file is not the layer that decides it and writing it there would be
    // a decision with no effect.
    let store = a_store_of_our_own();
    let project = a_project_that_asks_for_what_only_a_users_file_can_grant();
    let settings = a_settings_file_nobody_has_written_yet();
    let machine = the_store_on_this_machine();
    let before = bytes_under(&project);

    let written = config_set(
        &store,
        &settings,
        &project,
        "execution.mode",
        "host_confirmed",
    );
    assert_eq!(
        written.status, 0,
        "the write did not finish:\n{}\n{}",
        written.stdout, written.stderr
    );

    let refused = config_set(&store, &settings, &project, "checks.existing_tests", "true");
    assert_eq!(
        refused.status, 5,
        "a setting a project's own file decides was not refused:\n{}\n{}",
        refused.stdout, refused.stderr
    );
    assert!(
        refused.stderr.contains("checks.existing_tests"),
        "the refusal does not name the setting it refused:\n{}",
        refused.stderr
    );

    let after = bytes_under(&project);
    assert!(
        before == after,
        "the project's files are not byte-for-byte what they were. `sure config set` writes one \
         file — the user's own, outside every project — and every path of it goes through the same \
         `Paths::ensure_settings_outside` a run asks about the file it reads:\nbefore: {:?}\nafter: {:?}",
        before
            .iter()
            .map(|(path, bytes)| (path, bytes.len()))
            .collect::<Vec<_>>(),
        after
            .iter()
            .map(|(path, bytes)| (path, bytes.len()))
            .collect::<Vec<_>>()
    );
    assert!(
        !settings.starts_with(&project) && settings.is_file(),
        "the file that was written is not the file that was named, or is inside the project"
    );
    assert!(
        bytes_under(&store).is_empty(),
        "a command about settings wrote something into the store"
    );

    assert_untouched(&machine, "by a write from inside a project");
}

#[test]
fn a_settings_file_inside_the_project_is_refused_and_nothing_is_written() {
    // Clause 3's edge, and the one a person is most likely to hit: naming the
    // file that is right there in the project they are standing in. It is
    // refused, because a settings file a project could have written is not the
    // user's own word — and the refusal has to leave the project exactly as it
    // was, which on this fixture means no file at all, since the project has
    // none.
    let store = a_store_of_our_own();
    let project = a_project_of_our_own();
    let inside = project.join("sure.yaml");
    let machine = the_store_on_this_machine();
    let before = bytes_under(&project);

    let run = config_set(
        &store,
        &inside,
        &project,
        "execution.mode",
        "host_confirmed",
    );
    assert_eq!(
        run.status, 5,
        "a settings file inside the project was not refused:\n{}\n{}",
        run.stdout, run.stderr
    );
    assert!(
        run.stderr.contains(&inside.display().to_string()),
        "the refusal does not name the file it refused:\n{}",
        run.stderr
    );
    assert!(
        !inside.exists(),
        "the refused command created {} inside the project it was judging",
        inside.display()
    );
    assert!(
        before == bytes_under(&project),
        "the refused command changed the project's files"
    );

    // A relative path never reaches that question at all: it is a wrong command
    // line, refused at the grammar, because whether it was inside the project
    // would depend on which directory SURE happened to be started in.
    let mut command = sure_in_a_store(&store);
    command.current_dir(&project).args([
        "--settings-file",
        "sure.yaml",
        "config",
        "set",
        "execution.mode",
        "host_confirmed",
    ]);
    let relative = Run::of(
        &command
            .output()
            .unwrap_or_else(|error| panic!("could not run {SURE}: {error}")),
    );
    assert_eq!(
        relative.status, 2,
        "a relative settings file is a wrong command line and exited {}:\n{}",
        relative.status, relative.stderr
    );
    assert!(
        !project.join("sure.yaml").exists(),
        "the run that named a relative settings file created one in the project"
    );

    assert_untouched(&machine, "by a refused write inside a project");
}

#[test]
fn a_setting_that_cannot_take_effect_is_refused_with_its_reason() {
    // Clause 4. Two shapes of setting that cannot do anything, and the answer
    // must not be a silent write: `telemetry`, which nothing in this release
    // implements — a file saying `telemetry: false` would look like a decision
    // the person had made and be read by nothing — and a value the release
    // refuses, where the reason is the product's own.
    //
    // The refusal is also the one case where "nothing was written" has to be
    // true of a file that does not exist yet, so the assertion is that the path
    // is still not there: a command that created an empty settings file while
    // refusing to put anything in it would leave a person with a file they did
    // not ask for and could not explain.
    let store = a_store_of_our_own();
    let project = a_project_of_our_own();
    let settings = a_settings_file_nobody_has_written_yet();
    let machine = the_store_on_this_machine();

    for (setting, value) in [
        ("privacy.telemetry", "false"),
        ("privacy.mode", "cloud_enhanced"),
        ("execution.mode", "no_such_mode"),
    ] {
        let run = config_set(&store, &settings, &project, setting, value);
        assert_eq!(
            run.status, 5,
            "`sure config set {setting} {value}` exited {} rather than 5. A setting that cannot \
             take effect is not a wrong command line (2) and is certainly not a success \
             (0):\n{}\n{}",
            run.status, run.stderr, run.stdout
        );
        assert!(
            run.stderr.contains(setting),
            "the refusal does not name the setting it refused, and a person who typed the setting \
             has no way to know which of it SURE is answering about:\n{}",
            run.stderr
        );
        assert!(
            !settings.exists(),
            "`sure config set {setting} {value}` was refused and created {} anyway. A setting that \
             cannot take effect must not be written silently, and a file left behind by a refusal \
             is the same defect with an empty value in it:\n{}",
            settings.display(),
            run.stderr
        );
    }

    assert_untouched(&machine, "by three refused writes");
}

#[test]
fn a_delete_without_a_scope_or_with_two_is_a_wrong_command_line() {
    // The non-interactive decision, checked where a user meets it. Nothing
    // prompts, so the scope on the command line *is* the consent — which means a
    // command line that names no scope, or names two, has to be refused before
    // anything runs. It is a wrong command line (2) and not a run that failed
    // (5): SURE never looked at the store, so there is no run to describe.
    let store = a_store_of_our_own();
    let project = a_project_of_our_own();
    record_one_event(&store, &project, "cursor-session-scope");

    let before = history_frame(&store, &[]);
    assert_eq!(before["details"]["total"].as_u64(), Some(1));

    for args in [
        &["history", "delete"][..],
        &["history", "delete", "--all", "--session", "x"][..],
        &["history", "delete", "--session", "x", "--project", "y"][..],
    ] {
        let run = run_in_a_store(&store, args);
        assert_eq!(
            run.status,
            2,
            "`sure {}` returned {}. A delete that names no scope, or two, is a command line \
             SURE cannot act on:\n{}",
            args.join(" "),
            run.status,
            run.stderr
        );
        assert!(
            run.stdout.is_empty(),
            "a refused command line wrote to standard output:\n{}",
            run.stdout
        );
    }

    // Nothing went. A wrong command line that had deleted anyway would be the
    // worst of both: a user told their command was refused, and a history that
    // had lost a session.
    let after = history_frame(&store, &[]);
    assert_eq!(
        after["details"]["total"].as_u64(),
        Some(1),
        "a refused delete removed a session anyway"
    );
}

#[test]
fn the_two_paths_disagree_about_nothing_that_matters() {
    // The separation has to be a difference in *shape*, not in *content*. If
    // the machine form and the human form could describe different outcomes,
    // a person and their build script would be reading two different products.
    for args in REFUSED {
        let human = run(args);
        let mut machine: Vec<&str> = vec!["--format", "json"];
        machine.extend_from_slice(args);
        let machine = run(&machine);
        let frame: serde_json::Value = serde_json::from_str(machine.stdout.trim()).unwrap();

        assert_eq!(
            human.status,
            i32::try_from(frame["exit_code"].as_i64().expect("an exit code"))
                .expect("a status that fits"),
            "the two paths disagree about the status for `sure {}`",
            args.join(" ")
        );
        let instead = frame["instead"]
            .as_str()
            .expect("a refusal says what happened");
        assert!(
            human.stderr.contains(instead),
            "the human form of `sure {}` does not say what the machine form does:\n\
             machine: {instead}\nhuman: {}",
            args.join(" "),
            human.stderr
        );
    }
}

#[test]
fn a_check_of_a_real_project_answers_with_a_verdict_and_never_with_status_three() {
    // P7-T010's acceptance, at the process. `sure check` used to exit 3 — "this
    // build cannot carry that out" — and the reason was true when it was
    // written: nothing sequenced the stages. It does now, so the status that
    // says "SURE cannot check a project" is a lie about this build, and 1 —
    // "it checked, and the project is not clean" — is what happened.
    //
    // The project is this crate, which is a real one: a `Cargo.toml`, sources,
    // and two declared commands that would run its code.
    let human = run(&["check"]);
    assert_eq!(
        human.status, 1,
        "`sure check` returned {}. 3 would mean this build cannot check a project, which it \
         can; 0 would mean the project is clean, which no run in this build can establish.\n\
         stdout:\n{}\nstderr:\n{}",
        human.status, human.stdout, human.stderr
    );
    assert!(
        human.stdout.contains("SURE checked"),
        "the report does not say what it is about:\n{}",
        human.stdout
    );
    assert!(
        human.stdout.contains("NOT CHECKED"),
        "the run does not mark what it did not check:\n{}",
        human.stdout
    );
    assert!(
        human.stdout.contains("SURE exited with status 1"),
        "the report does not say what the status means, once the exit code is gone into a \
         pipe:\n{}",
        human.stdout
    );
    assert!(
        !human.stderr.contains("is not implemented in this build"),
        "a command that ran is worded as one this build lacks:\n{}",
        human.stderr
    );

    // The same run, read by a script. What must never appear there is `ok`, and
    // it must not appear for the reason the stage log gives.
    let machine = run(&["--format", "json", "check"]);
    assert_eq!(machine.status, human.status);
    let frame: serde_json::Value =
        serde_json::from_str(machine.stdout.trim()).expect("one frame on one line");
    assert_eq!(frame["command"].as_str(), Some("check"));
    assert_ne!(
        frame["outcome"].as_str(),
        Some("ok"),
        "a run that did not finish its stages reported itself clean: {frame}"
    );
    assert_eq!(
        frame["details"]["state"].as_str(),
        Some("finished"),
        "{frame}"
    );
    assert_eq!(
        frame["details"]["green"],
        serde_json::json!(false),
        "{frame}"
    );
    assert_eq!(frame["details"]["stopped_at"], serde_json::Value::Null);
    let stages = frame["details"]["stages"]
        .as_array()
        .expect("the frame carries the stage log");
    assert_eq!(stages.len(), 12, "{frame}");
    assert!(
        stages
            .iter()
            .any(|stage| stage["outcome"] == serde_json::json!("not_run")),
        "a run over a real crate must record a stage that did not run — a run in which every \
         stage claims to have done its work has not told the reader what it left undone: {frame}"
    );
    assert!(
        stages.iter().all(|stage| stage["detail"]
            .as_str()
            .is_some_and(|text| !text.is_empty())),
        "a stage does not say what it did: {frame}"
    );
}

#[test]
fn a_run_says_which_privacy_mode_it_was_under_and_what_it_did_about_models() {
    // P13-T002, at the process: the two things a user could not find out before
    // it. Which privacy mode is running, and whether a model was consulted.
    //
    // Everything asserted here is a *membership* in a closed set rather than a
    // value, and that is deliberate. A real process reads the user's own settings
    // file outside the project, and that directory cannot be moved by a flag or
    // an environment variable, so a test demanding `local_first` here would be a
    // claim about the machine it ran on. The values themselves — including the
    // arbitration between the project's file and the user's — are tested where
    // they can be set: `crates/sure-cli/src/check.rs` and
    // `crates/sure-core/src/privacy.rs`.
    let human = run(&["check"]);
    let machine = run(&["--format", "json", "check"]);
    let frame: serde_json::Value =
        serde_json::from_str(machine.stdout.trim()).expect("one frame on one line");

    let mode = frame["details"]["privacy"]["mode"]
        .as_str()
        .unwrap_or_else(|| panic!("the frame does not say which mode was in effect: {frame}"));
    assert!(
        ["local_first", "fully_local"].contains(&mode),
        "the run reports a mode this release does not implement: {mode}"
    );
    assert_ne!(
        mode, "cloud_enhanced",
        "a mode that is refused at the settings file was reported as in effect"
    );
    assert!(
        frame["details"]["privacy"]["mode_set_by"].is_null()
            || ["user", "project"].contains(
                &frame["details"]["privacy"]["mode_set_by"]
                    .as_str()
                    .unwrap_or("")
            ),
        "the frame names a layer that cannot have set anything: {frame}"
    );
    let provider = frame["details"]["privacy"]["analysis_provider"]
        .as_str()
        .unwrap_or_else(|| panic!("the frame does not name a provider: {frame}"));
    assert!(
        [
            "disabled",
            "local_command",
            "claude_cli",
            "openai_compatible"
        ]
        .contains(&provider),
        "the frame names a provider this release does not have: {provider}"
    );

    // The human form says the same thing, in a sentence: a person who never
    // passes `--format json` is the one who most needs to know.
    assert!(
        human.stdout.contains("Privacy and model use"),
        "the report has no privacy section:\n{}",
        human.stdout
    );
    assert!(
        human.stdout.contains(&format!("Mode in effect: {mode}")),
        "the two renderings disagree about the mode in effect ({mode}):\n{}",
        human.stdout
    );
    assert!(
        human
            .stdout
            .contains(&format!("Analysis provider: {provider}")),
        "the two renderings disagree about the provider ({provider}):\n{}",
        human.stdout
    );

    // And the model question is answered rather than omitted. This build has no
    // check that asks for model-backed analysis, so `consulted` cannot be the
    // answer — the honest one is that no model was consulted, or that this run
    // cannot say. Silence is the state this test exists to rule out.
    let state = frame["details"]["model_use"]["state"]
        .as_str()
        .unwrap_or_else(|| panic!("the frame does not say what happened about models: {frame}"));
    assert!(
        [
            "no_provider",
            "nothing_asked",
            "provider_unusable",
            "consulted",
            "cannot_confirm"
        ]
        .contains(&state),
        "the frame names a model state this build does not have: {state}"
    );
    assert_ne!(
        state, "consulted",
        "no check in this build asks for model-backed analysis, so no run can report one"
    );
    assert!(
        human.stdout.contains("No model was consulted")
            || human
                .stdout
                .contains("cannot say whether a model was consulted"),
        "the report neither states that no model was consulted nor that it cannot say:\n{}",
        human.stdout
    );
}

#[test]
fn the_three_pipeline_commands_are_one_orchestrator_with_three_purposes() {
    // "`sure recheck` and `sure repair` reach the same orchestrator through
    // `Command::report` rather than a second path into the engine." Compared
    // here rather than asserted: the three runs are about the same project, they
    // walk the same twelve stages in the same order, and the only differences
    // are the stages at the end that say what each command is for.
    let mut frames = Vec::new();
    for command in ["check", "recheck", "repair"] {
        let mut args = vec!["--format", "json", command];
        let run = run(&args);
        assert_eq!(run.status, 1, "`sure {command}` returned {}", run.status);
        let frame: serde_json::Value = serde_json::from_str(run.stdout.trim())
            .unwrap_or_else(|error| panic!("`sure {command}` is not one frame: {error}"));
        assert_eq!(frame["command"].as_str(), Some(command), "{frame}");
        args.clear();
        frames.push(frame);
    }

    let project = frames[0]["details"]["project"].clone();
    assert!(project.is_string(), "{}", frames[0]);
    for frame in &frames {
        assert_eq!(
            frame["details"]["project"], project,
            "two commands checked two different projects"
        );
        assert_eq!(frame["details"]["mode"], frames[0]["details"]["mode"]);
        let names: Vec<&str> = frame["details"]["stages"]
            .as_array()
            .expect("a stage log")
            .iter()
            .map(|stage| stage["stage"].as_str().unwrap_or_default())
            .collect();
        assert_eq!(
            names,
            [
                "discover",
                "resolve-intent",
                "fingerprint",
                "plan",
                "static-checks",
                "dynamic-checks",
                "completeness",
                "model-assessment",
                "claim-checking",
                "aggregate",
                "repair-contract",
                "recheck",
            ],
            "`sure {}` did not walk the documented stages in order",
            frame["details"]["purpose"]
        );
    }

    // The last two stages are what separates them, and each says which of the
    // three it is answering.
    let last = |frame: &serde_json::Value| frame["details"]["stages"][11]["outcome"].clone();
    assert_eq!(frames.iter().map(last).collect::<Vec<_>>().len(), 3);
    assert_eq!(
        frames[2]["details"]["stages"][11]["outcome"],
        serde_json::json!("not_part_of_work"),
        "`sure repair` claims to compare against an earlier run: {}",
        frames[2]
    );
    assert_ne!(
        frames[1]["details"]["stages"][11]["outcome"],
        serde_json::json!("not_part_of_work"),
        "`sure recheck` recorded its own stage as not part of the run: {}",
        frames[1]
    );
    assert_ne!(
        frames[2]["details"]["stages"][10]["outcome"],
        serde_json::json!("not_part_of_work"),
        "`sure repair` recorded the stage it exists for as not part of the run: {}",
        frames[2]
    );
    assert_eq!(
        frames[0]["details"]["stages"][10]["outcome"],
        serde_json::json!("not_part_of_work"),
        "`sure check` claims to write repair instructions: {}",
        frames[0]
    );
}

#[test]
fn a_repair_contract_is_carried_to_the_next_run_and_that_run_says_what_it_left_open() {
    // P7-T012's first acceptance, observed by running the two commands rather
    // than by reading a module: `sure repair` answers with a repair contract, and
    // a later `sure recheck` over the same store reports what the first run left
    // open.
    //
    // Four mutations redden this test. All four were run, and each one is a way
    // the loop could look like it works from the outside:
    //
    // - restore `Vec::new()` for the findings in `pipeline.rs`'s `build_verdict`.
    //   Stage 11 goes back to writing no contract and `details.repairs` is `[]`,
    //   so the assertion that a contract exists fails.
    // - set `recheck_lifecycle::HISTORY_SCAN_LIMIT` to `0`. `Store::history`
    //   documents `0` as "return none", so the re-check reads nothing back and
    //   `still_open` is empty while the repair run wrote findings. This is the
    //   mutation that matters most: without it the second run would report
    //   "nothing was left open" and nothing outside would look wrong.
    // - set `HISTORY_SCAN_LIMIT` to a small non-zero number instead, `2`, which is
    //   the tempting repair and is not one: the count assertion fails with "the
    //   repair run recorded 3 finding(s) and the re-check reports 2 as still
    //   open", because `Store::history` answers newest-first and spends its rows
    //   on the newest readings. A limit that is merely large is the same defect
    //   with a longer fuse.
    // - make `repair_impact::select_impacted_checks` return only the contract's
    //   own list, dropping the affected and regression checks it adds. The last
    //   assertion fails, because the run would then hold a finding to one check
    //   after telling the reader it holds it to three.
    let project = a_project_with_a_declared_command_that_never_runs();
    let store = a_store_of_our_own();
    let path = project
        .to_str()
        .expect("this test's own directory is a UTF-8 path");
    let frame = |run: &Run| -> serde_json::Value {
        serde_json::from_str(run.stdout.trim())
            .unwrap_or_else(|error| panic!("`sure` printed no frame: {error}\n{}", run.stdout))
    };
    let strings = |value: &serde_json::Value| -> Vec<String> {
        value
            .as_array()
            .unwrap_or_else(|| panic!("not an array: {value}"))
            .iter()
            .map(|entry| {
                entry
                    .as_str()
                    .unwrap_or_else(|| panic!("not a string: {entry}"))
                    .to_owned()
            })
            .collect()
    };

    // The repair run. Its findings are what the next run has to be able to read.
    let repaired = run_in_a_store(&store, &["--format", "json", "repair", path]);
    assert_eq!(
        repaired.status, 1,
        "`sure repair` returned {}:\n{}",
        repaired.status, repaired.stderr
    );
    let repaired = frame(&repaired);
    assert_eq!(
        repaired["details"]["stages"][10]["outcome"], "ran",
        "stage 11 recorded itself as anything other than a stage that ran, on a project whose \
         checks were all planned and denied: {repaired}"
    );
    let repairs = repaired["details"]["repairs"]
        .as_array()
        .unwrap_or_else(|| panic!("`sure repair` answered with no repairs array: {repaired}"));
    assert!(
        !repairs.is_empty(),
        "`sure repair` answered with no contract at all for a project whose checks were all \
         denied: {repaired}"
    );

    // Each contract names the check that produced its finding, and the run that
    // will hold it to closing names that check too — plus the ones
    // `repair_impact` selects. The second list is the product's answer and the
    // first is the seed it was built from, so the seed is a subset of it, and on
    // this project it is a **strict** subset: both members declare a test script
    // and run project code deterministically, so each one's contract is widened
    // by the other. A `select_impacted_checks` that returned only the contract's
    // own list would leave every pair equal and fail the widening check below.
    let mut widened = 0usize;
    for contract in repairs {
        let named = strings(&contract["recheck"]);
        let held_to = strings(&contract["rechecks_that_must_pass"]);
        assert!(
            !named.is_empty(),
            "a contract names no check to re-run, so nothing could ever close it: {contract}"
        );
        for id in &named {
            assert!(
                held_to.contains(id),
                "the contract names {id} and the run does not hold the finding to it: {contract}"
            );
        }
        if held_to.len() > named.len() {
            widened += 1;
        }
    }
    assert!(
        widened > 0,
        "no contract was held to anything beyond the check it named, so this project cannot tell \
         the selection from the seed and the assertion above is about nothing: {repaired}"
    );

    // Stage 12 belongs to the other command, and the report says which rather
    // than leaving the stage out.
    assert_eq!(
        repaired["details"]["stages"][11]["outcome"], "not_part_of_work",
        "`sure repair` recorded the re-check stage as something other than another command's \
         work: {repaired}"
    );
    assert!(
        repaired["details"]["lifecycle"].is_null(),
        "`sure repair` reported a life-cycle comparison it does not make: {repaired}"
    );

    // The same project and the same store, a later run.
    let rechecked = run_in_a_store(&store, &["--format", "json", "recheck", path]);
    assert_eq!(
        rechecked.status, 1,
        "`sure recheck` returned {}:\n{}",
        rechecked.status, rechecked.stderr
    );
    let rechecked = frame(&rechecked);
    assert_eq!(
        rechecked["details"]["stages"][11]["outcome"], "ran",
        "`sure recheck` did not compare against the earlier run: {rechecked}"
    );
    let still_open = rechecked["details"]["lifecycle"]["still_open"]
        .as_array()
        .unwrap_or_else(|| panic!("`sure recheck` reported no comparison: {rechecked}"));
    assert_eq!(
        still_open.len(),
        repairs.len(),
        "the repair run recorded {} finding(s) and the re-check reports {} as still open, so the \
         two runs do not agree about what the project has open: {rechecked}",
        repairs.len(),
        still_open.len()
    );
    assert!(
        rechecked["details"]["lifecycle"]["closed"]
            .as_array()
            .is_some_and(|rows| rows.is_empty()),
        "a finding closed on a run in which no check passed: {rechecked}"
    );
}

#[test]
fn a_recheck_closes_a_finding_whose_todo_the_repair_removed() {
    // The closing half of the repair loop, observed by running the commands: a
    // repair run records a finding about a TODO candidate, the fix removes the
    // marker, and the re-check closes the finding rather than carrying it open
    // forever. Measured red before this test's fix: stage 12 only ever held the
    // *current* run's contracts, and a fixed project has no current finding to
    // write one from — so `closed` was empty and a genuinely fixed project read
    // as still broken (the MiQi full-repair E2E hit exactly this).
    //
    // No candidate row is planted in the store by hand: the scanner really
    // proposes `chk_candidatetodo<…>` from the file, the repair run's contract
    // really names it, and the fix is a real rewrite of the file. This test's
    // environment carries no analysis key, so the model-assessment stage does
    // not run and the one finding here is the deterministic one — which is why
    // `still_open` can be asserted empty rather than filtered.
    let project = a_directory_of_our_own("todo-project");
    std::fs::write(project.join("README.md"), "# a small project\n")
        .unwrap_or_else(|error| panic!("cannot write into {}: {error}", project.display()));
    let todo = project.join("pay.py");
    std::fs::write(
        &todo,
        "# TODO: implement the payment flow, not finished yet\nraise NotImplementedError(\"payment\")\n",
    )
    .unwrap_or_else(|error| panic!("cannot write {}: {error}", todo.display()));
    let store = a_store_of_our_own();
    let path = project
        .to_str()
        .expect("this test's own directory is a UTF-8 path");
    let frame = |run: &Run| -> serde_json::Value {
        serde_json::from_str(run.stdout.trim())
            .unwrap_or_else(|error| panic!("`sure` printed no frame: {error}\n{}", run.stdout))
    };

    // The repair run writes the finding a later re-check has to find.
    let repaired = run_in_a_store(&store, &["--format", "json", "repair", path]);
    assert_eq!(
        repaired.status, 1,
        "`sure repair` returned {}:\n{}",
        repaired.status, repaired.stderr
    );
    let repaired = frame(&repaired);
    let repairs = repaired["details"]["repairs"]
        .as_array()
        .unwrap_or_else(|| panic!("`sure repair` answered with no repairs array: {repaired}"));
    assert!(
        !repairs.is_empty(),
        "`sure repair` answered with no contract for a project whose TODO check failed: \
         {repaired}"
    );

    // The repair a coding agent would have made: the marker is gone.
    std::fs::write(
        &todo,
        "def pay():\n    \"\"\"Implements the payment flow.\"\"\"\n    return {\"status\": \"paid\"}\n",
    )
    .unwrap_or_else(|error| panic!("cannot rewrite {}: {error}", todo.display()));

    let rechecked = run_in_a_store(&store, &["--format", "json", "recheck", path]);
    let rechecked = frame(&rechecked);
    let closed = rechecked["details"]["lifecycle"]["closed"]
        .as_array()
        .unwrap_or_else(|| panic!("`sure recheck` reported no comparison: {rechecked}"));
    assert_eq!(
        closed.len(),
        1,
        "the fix removed the marker and the re-check closed {} finding(s): {rechecked}",
        closed.len()
    );
    assert!(
        closed[0]["title"]
            .as_str()
            .is_some_and(|title| title.contains("TODO")),
        "the closed finding is not the one the fix was about: {rechecked}"
    );
    assert!(
        rechecked["details"]["lifecycle"]["still_open"]
            .as_array()
            .is_some_and(|rows| rows.is_empty()),
        "a fixed project still reports something open: {rechecked}"
    );
}

#[test]
fn a_recheck_with_nothing_to_compare_does_not_report_a_comparison() {
    // A first re-check has no earlier run behind it, and the report used to say
    // otherwise. The `Some(empty)` stage-12 return made the human form print
    // `Against the earlier run: 0 finding(s) still open, 0 closed.` while stage
    // 12's own detail, fourteen lines below, said `no earlier run left anything
    // open for this project.` — two explanations of one result in one report,
    // which is the thing the comment above `check::lifecycle` forbids. The frame
    // carried the same emptiness as `{"closed": [], "still_open": []}`, the shape
    // of an answer, where the honest value is `null`.
    //
    // The empty case is the only case, and that is what makes one return value
    // enough to say it: `reconcile` walks the earlier findings, and every one it
    // walks lands in `kept_open` or in `resolved`, so `Some` holds a comparison
    // that found something and `None` holds a run with nothing to compare.
    //
    // The last third of the test is the control: a re-check that *does* have an
    // earlier run behind it still says what it found, with the numbers in it. A
    // report that had simply stopped printing the sentence would pass the first
    // half and fail here.
    let project = a_project_with_a_declared_command_that_never_runs();
    let path = project
        .to_str()
        .expect("this test's own directory is a UTF-8 path");
    let frame = |run: &Run| -> serde_json::Value {
        serde_json::from_str(run.stdout.trim())
            .unwrap_or_else(|error| panic!("`sure` printed no frame: {error}\n{}", run.stdout))
    };

    // The first re-check on a store that has never seen this project. The store
    // is this run's own, so "first" is true by construction.
    let first = run_in_a_store(&a_store_of_our_own(), &["recheck", path]);
    assert_eq!(
        first.status, 1,
        "`sure recheck` returned {}:\n{}",
        first.status, first.stderr
    );
    assert!(
        !first.stdout.contains("Against the earlier run"),
        "a re-check with no earlier run to compare against reported a comparison:\n{}",
        first.stdout
    );
    assert!(
        first
            .stdout
            .contains("no earlier run left anything open for this project."),
        "stage 12 does not say what the first re-check found, so the assertion above is about a \
         report that says nothing at all:\n{}",
        first.stdout
    );

    // The same run in the machine frame. A separate store, because this run is
    // the first for whichever store it names.
    let machine = frame(&run_in_a_store(
        &a_store_of_our_own(),
        &["--format", "json", "recheck", path],
    ));
    assert!(
        machine["details"]["lifecycle"].is_null(),
        "a run with nothing to compare answered with a comparison rather than with none: {machine}"
    );
    assert_eq!(
        machine["details"]["stages"][11]["outcome"], "ran",
        "stage 12 did not run on a store it could read, and this test is about a stage that ran \
         with nothing to compare: {machine}"
    );

    // The control. The first run over a store of its own leaves findings open, so
    // the second one has an earlier run to be compared with.
    let store = a_store_of_our_own();
    let opened = frame(&run_in_a_store(
        &store,
        &["--format", "json", "recheck", path],
    ));
    assert!(
        !opened["details"]["report"]["findings"]
            .as_array()
            .unwrap_or_else(|| panic!("no findings array in the frame: {opened}"))
            .is_empty(),
        "this run left nothing open, so the next one has nothing to compare and the control below \
         would be about nothing: {opened}"
    );
    assert!(
        opened["details"]["lifecycle"].is_null(),
        "the first run over this store reported a comparison: {opened}"
    );

    let compared = run_in_a_store(&store, &["recheck", path]);
    assert!(
        compared.stdout.contains("Against the earlier run"),
        "a re-check with an earlier run behind it stopped saying what it found:\n{}",
        compared.stdout
    );
    assert!(
        !compared
            .stdout
            .contains("Against the earlier run: 0 finding(s) still open, 0 closed."),
        "a re-check reported a comparison that found nothing open, on a store where the run before \
         it left findings open:\n{}",
        compared.stdout
    );
}

#[test]
fn a_project_that_cannot_be_read_is_status_five_and_not_status_three() {
    // The other half of the status rule, and the one a user meets by mistyping a
    // path. 5 is "it tried and did not finish": a statement about this run. 3 is
    // "this build cannot carry that out": a statement about the build, whose
    // remedy is a newer SURE — and telling a user that would send them looking
    // for an upgrade instead of at their path.
    let missing = format!("{}/does-not-exist", env!("CARGO_MANIFEST_DIR"));
    let human = run(&["check", &missing]);
    assert_eq!(
        human.status, 5,
        "`sure check <missing>` returned {}:\n{}",
        human.status, human.stderr
    );
    assert!(
        human.stdout.is_empty(),
        "a run with no verdict wrote to standard output:\n{}",
        human.stdout
    );
    assert!(
        human.stderr.contains("could not finish"),
        "the complaint does not say the run did not finish:\n{}",
        human.stderr
    );
    assert!(
        human.stderr.contains("No verdict was produced"),
        "a failed run does not say that it is not a statement about the project:\n{}",
        human.stderr
    );
    assert!(
        !human.stderr.contains("is not implemented in this build"),
        "a run that tried is worded as a command this build lacks:\n{}",
        human.stderr
    );

    let machine = run(&["--format", "json", "check", &missing]);
    assert_eq!(machine.status, 5);
    let frame: serde_json::Value = serde_json::from_str(machine.stdout.trim()).expect("one frame");
    assert_eq!(frame["outcome"].as_str(), Some("failed"), "{frame}");
    assert_eq!(frame["exit_code"].as_i64(), Some(5), "{frame}");
    assert_eq!(
        frame["details"]["state"].as_str(),
        Some("stopped"),
        "a run that produced no verdict says it finished: {frame}"
    );
    assert_eq!(
        frame["details"]["stopped_at"].as_str(),
        Some("discover"),
        "the frame does not say where the run stopped: {frame}"
    );
    assert_eq!(
        frame["details"]["report"],
        serde_json::Value::Null,
        "a run that produced no verdict carries one: {frame}"
    );
}

#[test]
fn the_format_flag_is_taken_in_both_positions_and_refuses_a_third_value() {
    let before = run(&["--format", "json", "version"]);
    let after = run(&["version", "--format", "json"]);
    assert_eq!(before.stdout, after.stdout);
    assert!(before.succeeded() && after.succeeded());

    // An unknown format is a wrong command line, not a silent fall back to the
    // human one. Falling back would put prose where a script expected JSON, and
    // the script would report a parse error rather than the real problem.
    let wrong = run(&["--format", "yaml", "version"]);
    assert_eq!(wrong.status, 2, "{}", wrong.stderr);
    assert!(wrong.stdout.is_empty(), "{}", wrong.stdout);
}

#[test]
fn an_unknown_command_or_flag_is_a_wrong_command_line() {
    // 2, not 3 and not 0. The three mean different things and a user acts on
    // them differently: 2 is "you typed it wrong", 3 is "SURE cannot do that",
    // 0 is "it is done".
    for args in [
        &["chekc"][..],
        &["check", "--deep"][..],
        &["--format"][..],
        &[][..],
        // A version is a number. An adapter that passed a word — a tag, a
        // branch, `latest` — must be told it typed the command line wrong,
        // rather than be answered "SURE cannot talk to that", which reads as a
        // version that exists and is refused.
        &["protocol", "--speaks", "latest"][..],
        &["protocol", "--speaks"][..],
    ] {
        let run = run(args);
        assert_eq!(
            run.status,
            2,
            "`sure {}` returned {}:\n{}",
            args.join(" "),
            run.status,
            run.stderr
        );
    }
}

#[test]
fn the_two_spellings_of_the_version_agree_about_the_number() {
    // `sure version` is SURE's own rendering and `sure --version` is clap's.
    // Two spellings of one fact is where drift starts, so the number is what is
    // compared and the difference in prefix is not.
    let subcommand = run(&["version"]);
    let flag = run(&["--version"]);
    assert!(subcommand.succeeded() && flag.succeeded());
    let number = env!("CARGO_PKG_VERSION");
    assert!(subcommand.stdout.contains(number), "{}", subcommand.stdout);
    assert!(flag.stdout.contains(number), "{}", flag.stdout);
}

#[test]
fn hook_ingest_reads_standard_input_and_evaluates_protection() {
    // P11-T006: `sure hook ingest` reads stdin, normalises the event, and
    // for pre-tool-use events evaluates a protection decision.
    //
    // This is the test the store's location was made choosable for. With no
    // store named, this run opened and wrote the store of whoever ran the suite
    // — measured on 2026-09-18 as 4096 bytes and one `event` row for the session
    // named below. It names a store now, and the machine's own store is
    // compared before and after, so a build where the flag stopped reaching
    // this command fails here instead of adding to somebody's history.
    let store = a_store_of_our_own();
    let machine = the_store_on_this_machine();

    let payload = r#"{
        "event": "preToolUse",
        "harness_session_id": "cursor-session-001",
        "tool": "Shell",
        "args": {"command": "npm test", "workdir": "C:\\Users\\dev\\sample-project"},
        "timestamp_utc": "2026-09-18T12:01:00Z",
        "source": "cursor"
    }"#;

    let mut command = sure_in_a_store(&store);
    command.args([
        "--format",
        "json",
        "hook",
        "ingest",
        "--source",
        "cursor",
        "pre-tool-use",
    ]);
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("a child process");
    let mut stdin = child.stdin.take().expect("the pipe");
    stdin.write_all(payload.as_bytes()).expect("write to stdin");
    drop(stdin);

    let output = child.wait_with_output().expect("the child exits");
    let status = output.status.code().expect("the process exited on its own");
    let stdout = String::from_utf8(output.stdout).expect("stdout is utf-8");

    // Default config is inspect_only, so Shell (ArbitraryCommand) is blocked.
    assert_ne!(status, 0, "a blocked tool should exit non-zero: {stdout}");

    let frame: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|error| panic!("hook ingest is not valid JSON: {error}\n{stdout}"));
    assert_eq!(frame["decision"].as_str(), Some("block"), "{frame}");
    assert!(
        frame["reason"].as_str().is_some_and(|r| !r.is_empty()),
        "a block decision should carry a reason: {frame}"
    );

    // The event really was persisted, and to the store the caller named: this
    // is the half that says the redirect is a redirect rather than a run that
    // silently stored nothing.
    assert!(
        store.join("sure.db").is_file(),
        "`sure hook ingest --store-dir {}` wrote no store, so the event it read was not kept \
         where it was told to keep it",
        store.display()
    );
    assert_untouched(&machine, "by an ingest that named a store");
}

/// One `preToolUse` read, from Cursor, aimed at `path` in `project`, run in
/// `store`.
///
/// The payload is what a harness sends, and it is built with `serde_json` rather
/// than with a `format!` string because the one field that is a Windows path
/// would otherwise have to be escaped by hand — and a path escaped wrongly is a
/// test about a project that does not exist.
fn ingest_a_read(store: &Path, project: &Path, path: &str) -> Run {
    let payload = serde_json::json!({
        "event": "preToolUse",
        "harness_session_id": "p13t004-mode",
        "project_root": project.to_string_lossy(),
        "tool": "Read",
        "path": path,
        "timestamp_utc": "2026-09-19T09:00:00Z",
        "source": "cursor",
    })
    .to_string();

    let mut command = sure_in_a_store(store);
    command.args([
        "--format",
        "json",
        "hook",
        "ingest",
        "--source",
        "cursor",
        "pre-tool-use",
    ]);
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("a child process");
    let mut stdin = child.stdin.take().expect("the pipe");
    stdin.write_all(payload.as_bytes()).expect("write to stdin");
    drop(stdin);
    Run::of(&child.wait_with_output().expect("the child exits"))
}

#[test]
fn the_protection_mode_a_project_names_is_the_one_sure_decides_under() {
    // P13-T004, at the process level and through the command a harness runs:
    // one read, run twice, differing only in the mode the project's own
    // `sure.yaml` names. `docs/security/PROTECTION_MODE.md` makes secret/config
    // areas strict's, so a read of `.env` is allowed under standard and held
    // under strict, and the held one leaves the process with status 1 — which is
    // what a launcher reads, and what this test is really about.
    //
    // Both runs name a store of this test's own, and the machine's store is
    // compared before and after.
    //
    // The mode is resolved from two layers and the other one is the user's own
    // settings file, which no test may write. Rather than assume it holds
    // nothing, the precondition is stated: if this machine has one, the runs
    // below are not the experiment they say they are.
    let user_settings = Paths::discover()
        .expect("this machine reports a per-user location for SURE's files")
        .user_config_file();
    assert!(
        !user_settings.is_file(),
        "this machine has a user settings file at {}, and a protection mode in it would be \
         answering instead of the project's own file. These runs are about the project layer: on a \
         machine with user settings, read what they hold before believing the standard case below.",
        user_settings.display()
    );

    let machine = the_store_on_this_machine();
    let store = a_store_of_our_own();

    // Standard: the read goes through, and the answer says so out loud.
    let standard = a_project_of_our_own();
    std::fs::write(
        standard.join("sure.yaml"),
        "protection:\n  mode: standard\n",
    )
    .expect("write the project's settings");
    let run = ingest_a_read(&store, &standard, ".env");
    assert!(
        run.succeeded(),
        "standard lets this read through, so the process exits 0: status {} and output {}",
        run.status,
        run.stdout
    );
    let frame: serde_json::Value = serde_json::from_str(run.stdout.trim())
        .unwrap_or_else(|error| panic!("hook ingest is not valid JSON: {error}\n{}", run.stdout));
    assert_eq!(frame["decision"].as_str(), Some("allow"), "{frame}");
    assert!(
        frame["reason"]
            .as_str()
            .is_some_and(|reason| !reason.is_empty()),
        "an allow the rule reached carries the reason it reached it with: {frame}"
    );

    // Strict: the same request is held, with status 1 and a sentence about what
    // the file is.
    let strict = a_project_of_our_own();
    std::fs::write(strict.join("sure.yaml"), "protection:\n  mode: strict\n")
        .expect("write the project's settings");
    let run = ingest_a_read(&store, &strict, ".env");
    assert_eq!(
        run.status, 1,
        "a held request is `not_green`, which is 1: output {}",
        run.stdout
    );
    let frame: serde_json::Value = serde_json::from_str(run.stdout.trim())
        .unwrap_or_else(|error| panic!("hook ingest is not valid JSON: {error}\n{}", run.stdout));
    assert_eq!(frame["decision"].as_str(), Some("block"), "{frame}");
    let reason = frame["reason"]
        .as_str()
        .expect("a held request carries a reason");
    assert!(
        reason.contains("credentials"),
        "the reason says what the file is rather than which setting asked: {reason}"
    );
    assert!(
        !reason.contains("protection.mode"),
        "the reason is about the user's work, not policy jargon: {reason}"
    );

    // Strict's other half: it holds what the document names and nothing else, so
    // the same project lets an ordinary read through.
    let run = ingest_a_read(&store, &strict, "src/lib.rs");
    assert!(
        run.succeeded(),
        "strict adds a question about the document's categories, not about every read: status {} \
         and output {}",
        run.status,
        run.stdout
    );

    assert_untouched(&machine, "by ingests that named a store");
}

// --- the audit trail of protection decisions (P13-T006) -----------------

/// One Cursor `preToolUse` shell request, in the shape a harness sends.
///
/// Built with `serde_json` rather than a `format!` string for the reason
/// [`ingest_a_read`] is: one field is a path, and a path escaped by hand on one
/// platform is a test about a project that does not exist on another.
fn shell_request(project: &Path, harness_session: &str, command: &str) -> String {
    serde_json::json!({
        "event": "preToolUse",
        "harness_session_id": harness_session,
        "project_root": project.to_string_lossy(),
        "tool": "Shell",
        "args": {"command": command},
        "timestamp_utc": "2026-09-19T09:30:00Z",
        "source": "cursor",
    })
    .to_string()
}

/// One Cursor `preToolUse` read of one path, in the shape a harness sends.
fn read_request(project: &Path, harness_session: &str, path: &str) -> String {
    serde_json::json!({
        "event": "preToolUse",
        "harness_session_id": harness_session,
        "project_root": project.to_string_lossy(),
        "tool": "Read",
        "path": path,
        "timestamp_utc": "2026-09-19T09:31:00Z",
        "source": "cursor",
    })
    .to_string()
}

/// One `sure hook ingest`, with `payload` on standard input.
///
/// `machine` picks the frame a harness reads. The human form is what a person
/// runs by hand, and one test below checks that a sentence about a record that
/// could not be written reaches both — a harness that reads the frame and a user
/// who reads the sentence are two different readers of the same decision.
fn ingest_payload(store: &Path, payload: &str, machine: bool) -> Run {
    let mut command = sure_in_a_store(store);
    if machine {
        command.args(["--format", "json"]);
    }
    command.args(["hook", "ingest", "--source", "cursor", "pre-tool-use"]);
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("a child process");
    let mut stdin = child.stdin.take().expect("the pipe");
    stdin.write_all(payload.as_bytes()).expect("write to stdin");
    drop(stdin);
    Run::of(&child.wait_with_output().expect("the child exits"))
}

/// The one JSON frame a `--format json` hook run answered with.
///
/// A panic rather than an `Option`: a frame that will not parse is a run that
/// said nothing a launcher could read, and every caller here is about to compare
/// two of them. The stdout is quoted, because the reason it would not parse is
/// usually in it.
fn hook_frame(run: &Run) -> serde_json::Value {
    serde_json::from_str(run.stdout.trim())
        .unwrap_or_else(|error| panic!("hook ingest is not valid JSON: {error}\n{}", run.stdout))
}

/// The `sure_session_id` the session a named harness session produced.
///
/// Read out of the history rather than carried out of the ingest: the id is
/// SURE's, assigned by the run that recorded the session, and a test that made
/// one up would be asking about a session nothing wrote.
fn session_named(store: &Path, harness_session: &str) -> String {
    let listed = history_frame(store, &[]);
    listed["details"]["sessions"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|session| session["harness_session_id"].as_str() == Some(harness_session))
        .and_then(|session| session["sure_session_id"].as_str())
        .unwrap_or_else(|| panic!("no session for {harness_session} in {listed}"))
        .to_owned()
}

/// The `sessions` row id for one `SURE_SESSION_ID`, read from the file.
fn session_row_id(store: &Path, sure_session_id: &str) -> i64 {
    SessionEventStore::new(&open_the_store(store))
        .session_by_sure_id(sure_session_id)
        .expect("a lookup")
        .unwrap_or_else(|| panic!("no session {sure_session_id} in {}", store.display()))
        .row_id
}

/// The decision rows one session wrote, read by this process from the file.
///
/// The store rather than the report: `sure history` says what it shows, and a
/// test that believed it would be checking a sentence against itself.
fn decisions_of_session(store: &Path, session_row_id: i64) -> Vec<StoredRecord> {
    SessionEventStore::new(&open_the_store(store))
        .decisions_for_session(session_row_id)
        .expect("the decisions of a session this test wrote")
}

#[test]
fn a_decision_a_harness_was_given_is_recorded_where_a_user_can_read_it_and_delete_it() {
    // P13-T006, through the command a harness runs: a request SURE held, the
    // answer the harness was given, and the row that answer left behind — read
    // back from the file, shown by `sure history`, and reached by
    // `sure history delete`.
    //
    // What makes this a decision *about* something is a danger on the row, and
    // this file can only produce one the user's own settings do not have to
    // grant: a request that needs consent because the *mode* refused it carries
    // no danger by design (`hook_protection::assess_request`), and the mode that
    // would hold a shell request for consent is `host_confirmed`, which since
    // P13-T009 only the user's own file can name. The user's file is at
    // `%APPDATA%\SURE\sure.yaml` on this machine, which no test may write; a
    // test may point a run at a different one with `--settings-file`
    // (`Paths::discover_with`), and this case does not, because what it asserts
    // is the branch a machine with no settings file of its own takes — and it
    // names the branch it is not taking rather than assuming it. So the danger
    // here is the one a project *can* raise: `protection: mode: strict` holds a
    // read of a secret, and
    // `danger_of` names that a `sensitive_read`.
    let store = a_store_of_our_own();
    let project = a_project_of_our_own();
    let machine = the_store_on_this_machine();
    std::fs::write(project.join("sure.yaml"), "protection:\n  mode: strict\n")
        .expect("write the project's settings");

    let held = ingest_payload(
        &store,
        &read_request(&project, "p13t006-held", ".env"),
        true,
    );
    assert_eq!(
        held.status, 1,
        "a held request is `not_green`, which is 1 — the number a launcher reads:\n{}",
        held.stdout
    );
    let frame: serde_json::Value = serde_json::from_str(held.stdout.trim())
        .unwrap_or_else(|error| panic!("hook ingest is not valid JSON: {error}\n{}", held.stdout));
    assert_eq!(frame["decision"].as_str(), Some("block"), "{frame}");

    let id = session_named(&store, "p13t006-held");

    // What a person reads.
    let shown = run_in_a_store(&store, &["history", "show", &id]);
    assert_eq!(shown.status, 0, "{}", shown.stderr);
    for expected in ["decision", "block", "Read", "credentials"] {
        assert!(
            shown.stdout.contains(expected),
            "`sure history show` does not say {expected:?}:\n{}",
            shown.stdout
        );
    }

    // What a script reads, and the event the decision hangs from.
    let machine_frame = history_frame(&store, &["show", &id]);
    let event = &machine_frame["details"]["events"][0];
    let decision = &event["decision"];
    assert_eq!(
        decision["decision"].as_str(),
        Some("block"),
        "{machine_frame}"
    );
    assert_eq!(
        decision["danger"].as_str(),
        Some("sensitive_read"),
        "the row does not name the danger the hold was about: {machine_frame}"
    );
    assert_eq!(decision["tool"].as_str(), Some("Read"), "{machine_frame}");
    assert!(
        decision["allowance"].is_null(),
        "a request that spent no allowance carries one: {machine_frame}"
    );
    assert_eq!(
        decision["event_id"].as_str(),
        event["event_id"].as_str(),
        "the decision does not name the event it hangs from: {machine_frame}"
    );

    // The row itself, as this process reads it out of the file.
    let rows = decisions_of_session(&store, session_row_id(&store, &id));
    assert_eq!(
        rows.len(),
        1,
        "the ingest wrote {} decision rows",
        rows.len()
    );
    assert_eq!(rows[0].kind, RecordKind::Decision);
    let record = protection_history::read_back(rows[0].clone()).expect("a decision SURE wrote");
    assert_eq!(record.decision, ProtectionDecisionKind::Block);
    assert_eq!(record.danger, Some(Danger::SensitiveRead));
    assert_eq!(record.tool, "Read");
    assert!(record.allowance.is_none());
    assert_eq!(
        record.event_id.as_str(),
        event["event_id"].as_str().expect("the event names itself")
    );
    // The request's own words are not in this row. They are in the event payload
    // it hangs from — redacted, once — and a second copy is the surface the
    // brief's "without secrets" is about. For a read the request's words are the
    // path, which `DecisionRecord`'s own note says it never carries.
    let document = rows[0].document.to_string();
    assert!(
        !document.contains(".env"),
        "the decision row carries the path the request named as well as the event: {document}"
    );

    // And a delete reaches it, counts it, and removes it. The count is read from
    // the frame and the removal from the file, because a report and the thing it
    // reports on are the two halves a test of a delete needs.
    let decision_row = rows[0].id;
    let deleted = history_frame(&store, &["delete", "--session", &id]);
    assert_eq!(
        deleted["details"]["deleted"]["decisions"].as_u64(),
        Some(1),
        "the delete did not report removing the decision row: {deleted}"
    );
    assert!(
        open_the_store(&store)
            .record(decision_row)
            .expect("a lookup")
            .is_none(),
        "the decision row survived a delete that reported removing it"
    );
    assert_untouched(&machine, "by an ingest and a delete that named a store");
}

#[test]
fn an_allowance_that_was_spent_is_what_tells_one_allow_from_another() {
    // The third hard point of the task: an allow that happened because a
    // one-time allowance was spent and an allow that happened because nothing
    // was dangerous are the same kind — `ProtectionDecisionKind` has three
    // variants and this is one of them. The two runs below are that pair, and
    // The two runs below are that pair, and
    // what tells them apart is the allowance the row names, carried from the
    // decision SURE already took rather than re-decided here.
    //
    // The danger this project can raise is the one strict mode holds, because
    // the mode that holds a shell request for consent is `host_confirmed` and
    // since P13-T009 only the user's own settings file can name it — a file at
    // `%APPDATA%\SURE\sure.yaml` on this machine that no test may write. A test
    // can point a run at a file of its own with `--settings-file`, and this case
    // does not: the mode it asserts is the one a project's own file can reach on
    // a machine that has named none. `protection: mode: strict` is a project's
    // own file
    // answering, and `danger_of` names a read of a secret a `sensitive_read`,
    // which is one of the three an allowance may be spent on.
    let store = a_store_of_our_own();
    let project = a_project_of_our_own();
    let machine = the_store_on_this_machine();
    std::fs::write(project.join("sure.yaml"), "protection:\n  mode: strict\n")
        .expect("write the project's settings");

    // The user records an allowance for exactly this request, from the command
    // line, because a hook cannot ask about it.
    let granted = run_in_a_store(
        &store,
        &[
            "--format",
            "json",
            "hook",
            "allow-once",
            "--project",
            &project.to_string_lossy(),
            "--tool",
            "Read",
            "--path",
            ".env",
        ],
    );
    assert_eq!(granted.status, 0, "{}", granted.stderr);
    let frame: serde_json::Value =
        serde_json::from_str(granted.stdout.trim()).unwrap_or_else(|error| {
            panic!("allow-once is not valid JSON: {error}\n{}", granted.stdout)
        });
    let grant = frame["details"]["grant"]
        .as_i64()
        .unwrap_or_else(|| panic!("the allowance has no row id to spend: {frame}"));

    // The request it was recorded for is let through, and the answer says which
    // allowance did it.
    let spent = ingest_payload(
        &store,
        &read_request(&project, "p13t006-spent", ".env"),
        true,
    );
    assert_eq!(
        spent.status, 0,
        "an allowed request exits 0, so the launcher proceeds:\n{}",
        spent.stdout
    );
    let frame: serde_json::Value = serde_json::from_str(spent.stdout.trim())
        .unwrap_or_else(|error| panic!("hook ingest is not valid JSON: {error}\n{}", spent.stdout));
    assert_eq!(frame["decision"].as_str(), Some("allow"), "{frame}");
    assert!(
        frame["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("one-time allowance")),
        "the allow does not say it came from an allowance: {frame}"
    );

    let spent_id = session_named(&store, "p13t006-spent");
    let spent_row = decisions_of_session(&store, session_row_id(&store, &spent_id));
    assert_eq!(spent_row.len(), 1, "the ingest wrote no decision row");
    let spent_record =
        protection_history::read_back(spent_row[0].clone()).expect("a decision SURE wrote");
    assert_eq!(spent_record.decision, ProtectionDecisionKind::Allow);
    assert_eq!(
        spent_record.danger,
        Some(Danger::SensitiveRead),
        "an allowance covers one request SURE itself named as dangerous"
    );
    assert_eq!(
        spent_record.allowance,
        Some(grant),
        "the row does not name the allowance that was spent"
    );

    // The other allow: an ordinary read, which the rule allowed because it found
    // nothing in it. Same kind, no danger, no allowance — and that difference is
    // the whole of what tells the two apart afterwards.
    let ordinary = ingest_payload(
        &store,
        &read_request(&project, "p13t006-ordinary", "src/lib.rs"),
        true,
    );
    assert_eq!(ordinary.status, 0, "{}", ordinary.stdout);
    let ordinary_id = session_named(&store, "p13t006-ordinary");
    let ordinary_rows = decisions_of_session(&store, session_row_id(&store, &ordinary_id));
    assert_eq!(ordinary_rows.len(), 1, "the ingest wrote no decision row");
    let ordinary_record =
        protection_history::read_back(ordinary_rows[0].clone()).expect("a decision SURE wrote");
    assert_eq!(ordinary_record.decision, ProtectionDecisionKind::Allow);
    assert_eq!(
        ordinary_record.danger, None,
        "an ordinary read was recorded as a danger"
    );
    assert_eq!(
        ordinary_record.allowance, None,
        "an ordinary read was recorded as spending an allowance"
    );

    // And the user can see both, told apart in the words they read.
    let shown = run_in_a_store(&store, &["history", "show", &spent_id]);
    assert_eq!(shown.status, 0, "{}", shown.stderr);
    assert!(
        shown.stdout.contains("grant") && shown.stdout.contains("was spent by this request"),
        "the allow-once does not read as one:\n{}",
        shown.stdout
    );
    let shown = run_in_a_store(&store, &["history", "show", &ordinary_id]);
    assert_eq!(shown.status, 0, "{}", shown.stderr);
    assert!(
        !shown.stdout.contains("was spent by this request"),
        "an ordinary allow reads as an allowance that was spent:\n{}",
        shown.stdout
    );

    // The delete reaches both rows, and the frame says how many went.
    let deleted = history_frame(&store, &["delete", "--all"]);
    assert_eq!(
        deleted["details"]["deleted"]["decisions"].as_u64(),
        Some(2),
        "the delete did not report removing both decision rows: {deleted}"
    );
    assert_untouched(&machine, "by runs that named a store");
}

// --- an allowance that cannot be spent, at the command line ---------------
//
// `P13-T010`. The defect was that `sure hook allow-once` reads no configuration
// at all, so it recorded a grant in projects where nothing could ever spend it
// and told the user, in one unconditional sentence, that the next matching
// request would be let through. The evidence the acceptance asks for is the
// command's *own output* — stdout, stderr and the status a shell sees — which
// is why the two tests below run the binary rather than the function.

/// Every allowance row a store holds, as `(grants nothing has spent, uses)`.
///
/// Read through the same serde-tagged document the writer writes, because "the
/// store is consistent" is a claim about a row and not about how many rows there
/// are: the two cases here are a store with *no* allowance row at all and a
/// store with one grant and no use of it, and neither is visible from a count.
/// Spending does not edit the grant — it writes a second row carrying the id of
/// the grant it used — so a grant is outstanding when nothing names it, which is
/// the question [`sure_core::allowance::outstanding`] asks of the same rows.
fn allowance_rows(store: &Path) -> (Vec<i64>, Vec<i64>) {
    let rows = open_the_store(store)
        .history(
            &HistoryFilter {
                project_fingerprint: None,
                kind: Some(RecordKind::Allowance),
                include_recordings: false,
            },
            sure_core::allowance::SCAN_LIMIT,
        )
        .expect("the allowance rows read back");

    let mut grants: Vec<i64> = Vec::new();
    let mut spent: Vec<i64> = Vec::new();
    for row in rows {
        match sure_core::allowance::read_back(row.clone()) {
            Ok(sure_core::allowance::AllowanceRecord::Grant(_)) => grants.push(row.id),
            Ok(sure_core::allowance::AllowanceRecord::Spent(use_of)) => spent.push(use_of.grant),
            Err(error) => panic!("an unreadable allowance row: {error}"),
        }
    }
    grants.retain(|id| !spent.contains(id));
    (grants, spent)
}

#[test]
fn a_change_is_refused_with_the_setting_that_would_let_it_through() {
    // Acceptance line 1 for the change `P13-T011` decided: a tool whose action
    // would change the project's files, and what a user is told about it.
    //
    // **What changed, and why this is not the test it was.** `P13-T010`
    // measured `--tool Write`, `--tool Edit` and `--tool Delete` refused with
    // *"No setting in this build grants it"*, because no `execution.mode` and no
    // request a file could make granted `write_project`. `P13-T011` decided that
    // the **user's own settings file** may grant it — by
    // `execution.allow_project_write`, which a project's `sure.yaml` still
    // cannot — so the build's own limit is no longer the reason those three are
    // refused and the refusal names the setting instead. Nothing is weakened
    // here: the assertion that the build has no such limit is replaced by the
    // assertion that is true of it, and the sentence is now held to *which*
    // setting it names and *which layer* may set it.
    //
    // **Which branch this machine is in is not a choice the test makes.** The
    // flag that names a settings file is `--settings-file`, and this case names
    // none of its own, so the state of the answer is read from the
    // reader SURE reads it with, and every branch is asserted in full. On a
    // machine with no settings file — which is this one, and every machine until
    // a person writes one — that is the third branch below.
    let project = a_project_of_our_own();
    let machine = the_store_on_this_machine();
    let paths =
        Paths::discover().expect("this machine reports a per-user location for SURE's files");
    let (mode, permissions, protection) = match Authority::load(&project, &paths.user_config_file())
    {
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
    };
    // The branch, from the settings themselves and not from the rule the command
    // applies: whether SURE has been given the permission a change needs, and
    // whether the protection in force holds a change that names a whole
    // location. Both halves are needed — a granted change under `standard` is
    // allowed outright and so is held for no act at all, which is why a grant
    // recorded there would be spent by nothing.
    //
    // The mode is resolved here and then read nowhere: writing a file does not
    // run the project's code (`ActionKind::executes_project_code`), so `decide`
    // never consults the mode about a change, and the sentence must not name the
    // mode in force whichever one it is. That is `mode.as_str()`'s place in the
    // absent list below, and it is what makes `execution.mode` the wrong advice
    // for these three tools.
    let writes = permissions.allows(Permission::WriteProject);
    let strict = protection == ProtectionMode::Strict;
    let a_grant_would_be_spendable = writes && strict;
    let project_arg = project.to_string_lossy().into_owned();
    // The three tool names a change to the project's files is spelled with, and
    // the act each of them reaches. `Edit` is the name that was read through
    // Cursor's unrecognised-name fallback until `P13-T010`
    // (`crate::hook`'s own test is the one that measured that), so this loop is
    // over the names and not over one harness's vocabulary.
    let changes = [
        ("Write", "build/out.txt"),
        ("Edit", "src/lib.rs"),
        ("Delete", "build/out.txt"),
    ];

    // The branch every machine until somebody writes a settings file is in, and
    // the one the paragraph above is about: nobody has granted SURE the
    // permission, so no grant can be spent, and the user is told which setting
    // in *their own* file would change that.
    if a_grant_would_be_spendable {
        let store = a_store_of_our_own();
        for (tool, subject) in changes {
            let run = run_in_a_store(
                &store,
                &[
                    "hook",
                    "allow-once",
                    "--project",
                    &project_arg,
                    "--tool",
                    tool,
                    "--path",
                    subject,
                ],
            );
            assert_eq!(
                run.status, 0,
                "a grant the settings in force would let a request spend was not recorded for \
                 {tool}:\nstdout: {}\nstderr: {}",
                run.stdout, run.stderr
            );
            for needed in [
                "SURE recorded a one-time allowance",
                "delete a whole location",
            ] {
                assert!(
                    run.stderr.contains(needed),
                    "the record for {tool} does not say {needed:?}:\n{}",
                    run.stderr
                );
            }
        }
        let (grants, spent) = allowance_rows(&store);
        assert_eq!(
            (grants.len(), spent.len()),
            (3, 0),
            "three grants were recorded and none of them used"
        );
        assert_untouched(&machine, "by runs that named a store");
        let _ = std::fs::remove_dir_all(&project);
        return;
    }

    // The store this test names does **not** exist, which is the point: a store
    // SURE has never written is a directory that is not there, and a refusal
    // that created one would be a refusal that wrote something.
    let store = a_store_of_our_own().join("not-created");
    for (tool, subject) in changes {
        let run = run_in_a_store(
            &store,
            &[
                "hook",
                "allow-once",
                "--project",
                &project_arg,
                "--tool",
                tool,
                "--path",
                subject,
            ],
        );
        assert_eq!(
            run.status, 5,
            "a grant for {tool} that no request could spend was not refused with 5:\n\
             stdout: {}\nstderr: {}",
            run.stdout, run.stderr
        );
        assert!(
            run.stdout.is_empty(),
            "a refusal wrote to the stream a script reads as the answer:\n{}",
            run.stdout
        );
        for needed in [
            "SURE will not record an allowance that no request could spend.",
            &format!("'{tool}'"),
            "Nothing was written",
        ] {
            assert!(
                run.stderr.contains(needed),
                "the refusal for {tool} does not say {needed:?}:\n{}",
                run.stderr
            );
        }
        // The sentence the previous build wrote here, and what this task
        // decided: no setting in this build can grant a change is false of the
        // build now — one can — so it may not be said of any tool.
        for absent in [
            "No setting in this build grants it",
            "`execution.mode`",
            "host_confirmed",
            "inspect_only",
            mode.as_str(),
        ] {
            assert!(
                !run.stderr.contains(absent),
                "the refusal for {tool} names {absent}, which is not the cause and would not \
                 make the grant spendable:\n{}",
                run.stderr
            );
        }
        if writes {
            // The setting is already in force here, so naming it would be advice
            // to change something that is not what stopped the request: what is
            // left is the mode, and only the mode.
            assert!(
                run.stderr.contains("Set `protection.mode: strict`")
                    && !run.stderr.contains("execution.allow_project_write"),
                "the refusal for {tool} offers a setting the settings in force already grant, or \
                 drops the one that would work:\n{}",
                run.stderr
            );
        } else {
            for needed in [
                "would change files inside your project",
                "execution.allow_project_write: true",
                "sure doctor",
                "a project's `sure.yaml` cannot grant this one",
            ] {
                assert!(
                    run.stderr.contains(needed),
                    "the refusal for {tool} does not say {needed}:\n{}",
                    run.stderr
                );
            }
            // The mode is the second half of the remedy exactly while the mode
            // in force is not already the one that holds a whole location.
            assert_eq!(
                run.stderr.contains("and set `protection.mode: strict`"),
                !strict,
                "the refusal for {tool} names the mode beside the permission where the permission \
                 alone would work, or leaves it out where it would not:\n{}",
                run.stderr
            );
        }
        assert!(
            !store.exists(),
            "the refusal for {tool} created the store directory {}",
            store.display()
        );
    }

    assert_untouched(&machine, "by runs that named a store");
    let _ = std::fs::remove_dir_all(&project);
}

#[test]
fn an_allowance_the_settings_cannot_spend_is_refused_and_the_store_stays_empty() {
    // Acceptance line 1 and line 4, in the project the default configuration
    // makes: a `sure.yaml` that declares nothing, and a user who has written no
    // settings file of their own. `execution.mode` is `inspect_only`, so a shell
    // request is refused before SURE asks what it would do, and `protection.mode`
    // is `standard`, which asks no question of its own about a read or a change —
    // so no request from this project can be held for any of the three acts an
    // allowance covers, and a grant recorded here would be spent by nothing.
    //
    // **Which branch this machine is in is not a choice the test makes.** The
    // only file that can name a mode that runs project code is the user's own
    // (`P13-T009`), no test may write that file (`--settings-file` points a run
    // at a file of the test's own; it cannot make the machine's own say
    // anything, and a named file the project could have written is refused
    // outright), and this case names none. So the test asks
    // the same reader SURE asks, and asserts what follows from the answer. On a
    // machine with no settings file — which is this one, and every machine until
    // a person writes one — that is the refusal below. On a machine where
    // somebody has named `host_confirmed`, the same command can be spent and the
    // record branch is asserted instead; the refusal itself is then exercised
    // only by `crate::hook`'s own test, which builds its own paths and is
    // therefore the same on every machine.
    let store = a_store_of_our_own();
    let project = a_project_of_our_own();
    let machine = the_store_on_this_machine();
    let paths =
        Paths::discover().expect("this machine reports a per-user location for SURE's files");
    // The settings in force, resolved the way `crate::hook`'s reader resolves
    // them, including its fallback for a settings file SURE cannot read. The
    // project declares nothing, so the whole of this answer comes from the
    // machine's own file and from the defaults.
    let settings = match Authority::load(&project, &paths.user_config_file()) {
        Ok(authority) => (authority.execution_mode(), authority.protection().value),
        Err(_) => (ExecutionMode::InspectOnly, ProtectionMode::Strict),
    };
    let nothing_can_be_held = settings == (ExecutionMode::InspectOnly, ProtectionMode::Standard);

    let command = [
        "hook",
        "allow-once",
        "--project",
        &project.to_string_lossy(),
        "--tool",
        "Shell",
        "--command",
        "rm -rf build/",
    ];
    let run = run_in_a_store(&store, &command);
    let (grants, spent) = allowance_rows(&store);

    if nothing_can_be_held {
        assert_ne!(
            run.status, 0,
            "an allowance no request in this project could spend was answered with success:\n\
             stdout: {}\nstderr: {}",
            run.stdout, run.stderr
        );
        // It is a complaint, so it goes to stderr, and it says what did not
        // happen rather than only what is wrong with the settings.
        assert!(
            run.stdout.is_empty(),
            "a refusal wrote to the stream a script reads as the answer:\n{}",
            run.stdout
        );
        for needed in [
            "SURE will not record an allowance that no request could spend.",
            "execution.mode",
            "inspect_only",
            "protection.mode",
            "standard",
            "host_confirmed",
            "Nothing was written",
        ] {
            assert!(
                run.stderr.contains(needed),
                "the refusal does not say {needed:?}:\n{}",
                run.stderr
            );
        }
        // The sentence the previous build wrote here, and the reason this task
        // exists: it promised the next matching request would be let through.
        assert!(
            !run.stdout.contains("let that one request through")
                && !run.stderr.contains("let that one request through"),
            "the refusal still promises an outcome the settings make unreachable:\n{}",
            run.stderr
        );
        assert!(
            grants.is_empty() && spent.is_empty(),
            "the writer refused the grant and wrote {grants:?} (spent: {spent:?}) anyway"
        );
    } else {
        // This machine's own settings name a mode that runs project code, so a
        // broad delete is recordable here. The record branch asserts the other
        // half of acceptance line 4 — a grant that *is* written is one a matching
        // request can spend — and the refusal above is not exercised on this
        // machine. `crate::hook`'s test of the same two cases is.
        assert_eq!(run.status, 0, "{}", run.stderr);
        assert_eq!(
            grants.len(),
            1,
            "a recorded grant is not in the store: {grants:?}"
        );
        assert!(
            spent.is_empty(),
            "a grant was spent before any request arrived"
        );
    }

    // And the machine form of the same run, so a script reading the frame is told
    // the same thing the person reading the sentence is.
    let mut machine_command = vec!["--format", "json"];
    machine_command.extend_from_slice(&command);
    let run = run_in_a_store(&store, &machine_command);
    let frame = hook_frame(&run);
    if nothing_can_be_held {
        assert_eq!(frame["outcome"], "failed", "{frame}");
        assert_ne!(frame["exit_code"].as_i64(), Some(0), "{frame}");
        assert_eq!(
            frame["details"]["what"],
            "SURE will not record an allowance that no request could spend.",
            "{frame}"
        );
    } else {
        assert_eq!(frame["outcome"], "ok", "{frame}");
        assert_eq!(frame["exit_code"].as_i64(), Some(0), "{frame}");
    }
    assert_untouched(&machine, "by runs that named a store");
    let _ = std::fs::remove_dir_all(&store);
    let _ = std::fs::remove_dir_all(&project);
}

#[test]
fn a_recorded_allowance_is_one_the_request_it_names_spends() {
    // The other half of acceptance line 4, and acceptance line 3's first half, at
    // the process: a project whose settings leave an act — strict protection
    // holds a read of a file credentials live in, and the permission to read is
    // one every run has — records, says what it recorded in one act rather than
    // three, and the store shows the row being spent by the request it names.
    // This project's settings are the project's own to write, so unlike the test
    // above this one is the same on every machine.
    let store = a_store_of_our_own();
    let project = a_project_of_our_own();
    let machine = the_store_on_this_machine();
    std::fs::write(project.join("sure.yaml"), "protection:\n  mode: strict\n")
        .expect("write the project's settings");

    let recorded = run_in_a_store(
        &store,
        &[
            "hook",
            "allow-once",
            "--project",
            &project.to_string_lossy(),
            "--tool",
            "Read",
            "--path",
            ".env",
        ],
    );
    assert_eq!(
        recorded.status, 0,
        "a project where a grant can be spent refused to record one:\n{}",
        recorded.stderr
    );
    assert!(
        recorded.stdout.contains("read a file of credentials"),
        "the confirmation does not name the act this project leaves:\n{}",
        recorded.stdout
    );
    assert!(
        !recorded.stdout.contains("delete a whole location"),
        "the confirmation names an act these settings cannot hold a request for:\n{}",
        recorded.stdout
    );

    let (grants, spent) = allowance_rows(&store);
    assert_eq!(
        grants.len(),
        1,
        "the recorded grant is not in the store: {grants:?}"
    );
    assert!(
        spent.is_empty(),
        "a grant was spent before any request arrived"
    );

    // The request it names — and only that one — spends it.
    let ordinary = ingest_payload(
        &store,
        &read_request(&project, "p13t010-ordinary", "src/lib.rs"),
        true,
    );
    assert_eq!(ordinary.status, 0, "{}", ordinary.stdout);
    assert_eq!(
        allowance_rows(&store).0,
        grants,
        "a request the allowance was not recorded for spent it"
    );

    let named = ingest_payload(
        &store,
        &read_request(&project, "p13t010-named", ".env"),
        true,
    );
    assert_eq!(named.status, 0, "{}", named.stdout);
    let frame = hook_frame(&named);
    assert_eq!(frame["decision"].as_str(), Some("allow"), "{frame}");
    assert!(
        frame["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("one-time allowance")),
        "the allow does not say it came from the allowance the store shows: {frame}"
    );
    let (grants_after, spent_after) = allowance_rows(&store);
    assert!(
        grants_after.is_empty() && !spent_after.is_empty(),
        "the request the grant was recorded for did not spend it: {grants_after:?} {spent_after:?}"
    );

    assert_untouched(&machine, "by runs that named a store");
    let _ = std::fs::remove_dir_all(&store);
    let _ = std::fs::remove_dir_all(&project);
}

#[test]
fn a_decision_row_holds_the_decision_and_none_of_the_credentials_the_request_carried() {
    // The acceptance's "without secrets", in the shape that can fail: a request
    // whose words carry a credential, the decision SURE took about it, and every
    // byte of the store afterwards.
    //
    // What makes the absence an absence is the redacted form being *there*: the
    // command really did arrive carrying a token, SURE really did look at those
    // words, and what is stored is the request with the credential rewritten.
    // Without that half, a store holding nothing about the request at all would
    // pass the same test.
    //
    // The request is held, and the hold is the execution mode's: a shell request
    // needs a permission the default mode does not grant, and the mode that
    // would grant it is `host_confirmed`, which since P13-T009 only the user's
    // own settings file can name. So the danger field on the row is `null` here,
    // and that is the honest record of what happened — SURE refused the request
    // before any classifier looked at its words. What is *not* affected is the
    // redaction: the event payload is written the same way whatever the decision,
    // and the credential is in the words SURE stored.
    let store = a_store_of_our_own();
    let project = a_project_of_our_own();
    let machine = the_store_on_this_machine();

    let secret = "ghp_0123456789abcdefghij";
    let command = format!("git push --force https://user:{secret}@github.com/acme/app.git");
    let run = ingest_payload(
        &store,
        &shell_request(&project, "p13t006-secret", &command),
        true,
    );
    assert_eq!(
        run.status, 1,
        "a request SURE refuses is held:\n{}",
        run.stdout
    );
    let frame: serde_json::Value = serde_json::from_str(run.stdout.trim())
        .unwrap_or_else(|error| panic!("hook ingest is not valid JSON: {error}\n{}", run.stdout));
    assert_eq!(frame["decision"].as_str(), Some("block"), "{frame}");
    assert!(
        frame["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("does not permit this action")),
        "the hold is not the one this request produced: {frame}"
    );

    let id = session_named(&store, "p13t006-secret");
    let shown = history_frame(&store, &["show", &id]);
    let decision = &shown["details"]["events"][0]["decision"];
    assert!(
        decision["danger"].is_null(),
        "a request refused before its words were classified was recorded as a named danger: {shown}"
    );
    assert!(
        !decision.to_string().contains(secret),
        "the decision row carries the credential: {decision}"
    );

    // Every file under the store directory, as bytes: the credential is in none
    // of them, and the request is in one of them in its redacted form.
    let mut files = Vec::new();
    for entry in std::fs::read_dir(&store).expect("the store directory this test made") {
        let path = entry.expect("an entry").path();
        if path.is_file() {
            files.push(path);
        }
    }
    assert!(
        !files.is_empty(),
        "the ingest wrote no store at all, so this test would prove nothing"
    );
    let mut redacted = false;
    for path in &files {
        let bytes = std::fs::read(path)
            .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
        let text = String::from_utf8_lossy(&bytes).into_owned();
        assert!(
            !text.contains(secret),
            "{} holds the credential the request carried",
            path.display()
        );
        redacted |= text.contains("https://***@github.com/acme/app.git");
    }
    assert!(
        redacted,
        "the credential-bearing command is not in the store in its redacted form either, so \
         nothing here shows that SURE saw the request this test is about"
    );
    assert_untouched(&machine, "by an ingest that named a store");
}

#[test]
fn a_decision_that_could_not_be_recorded_keeps_the_answer_and_says_the_record_is_missing() {
    // The fourth hard point of the task: the row is bookkeeping about an answer
    // a launcher acts on, so a write that failed must not become a status the
    // launcher reads — and must not be silent either.
    //
    // A file where the store goes is the one way to fail this that a test can
    // arrange without a broken disk. It fails the event write too, so the row
    // has nothing to hang from; that is the case the sentence is about, and it
    // is reached here through the command rather than through the function.
    //
    // The hold has to be one the *rule* reached, or the last assertion below
    // would be vacuous: a request the execution mode refused carries the mode's
    // own sentence and never reaches the protection branch, and the mode a
    // project's file could name to change that is inert since P13-T009. Strict
    // mode is a project's own decision, and a read of `.env` under it is held
    // for a danger — so the sentence the rule reached is there to be found
    // underneath the sentence about the missing record.
    let store = a_store_of_our_own();
    let project = a_project_of_our_own();
    let machine = the_store_on_this_machine();
    std::fs::write(project.join("sure.yaml"), "protection:\n  mode: strict\n")
        .expect("write the project's settings");
    std::fs::write(store_file(&store), "this is not a database")
        .expect("a file where the store belongs");

    let held = ingest_payload(
        &store,
        &read_request(&project, "p13t006-unwritable", ".env"),
        true,
    );
    assert_eq!(
        held.status, 1,
        "a store SURE could not write changed the answer a launcher reads:\n{}",
        held.stdout
    );
    let frame: serde_json::Value = serde_json::from_str(held.stdout.trim())
        .unwrap_or_else(|error| panic!("hook ingest is not valid JSON: {error}\n{}", held.stdout));
    assert_eq!(frame["decision"].as_str(), Some("block"), "{frame}");
    assert_eq!(frame["exit_code"].as_i64(), Some(1), "{frame}");
    let reason = frame["reason"]
        .as_str()
        .expect("a held request carries a reason");
    assert!(
        reason.contains("could not record this decision in the local history"),
        "a decision that was not recorded said nothing about it: {reason}"
    );
    assert!(
        reason.contains("The decision above stands."),
        "the sentence does not say the answer is unaffected: {reason}"
    );
    assert!(
        reason.contains("credentials"),
        "the sentence about the record replaced the reason the rule reached: {reason}"
    );

    // The other direction: an allow whose row could not be written exits 0, and
    // says the record is missing rather than losing it in silence. A failed
    // write that turned an allow into a non-zero status would be a hook failing
    // closed on a machine whose store is full.
    let allowed = ingest_payload(
        &store,
        &read_request(&project, "p13t006-unwritable-allow", "src/lib.rs"),
        true,
    );
    assert_eq!(
        allowed.status, 0,
        "a failed write turned an allow into a status a launcher reads as a refusal:\n{}",
        allowed.stdout
    );
    let frame: serde_json::Value =
        serde_json::from_str(allowed.stdout.trim()).unwrap_or_else(|error| {
            panic!("hook ingest is not valid JSON: {error}\n{}", allowed.stdout)
        });
    assert_eq!(frame["decision"].as_str(), Some("allow"), "{frame}");
    // The store could not be opened, so the event is not in it either and the
    // sentence is the one about an event that was not stored. The other arm —
    // the store open and refusing the row — is what `hook.rs`'s own test calls
    // `record_the_decision` to reach.
    assert!(
        frame["reason"].as_str().is_some_and(|reason| {
            reason.contains("could not record this decision in the local history")
                && reason.contains("The decision above stands.")
        }),
        "an allow SURE could not record said nothing about it: {frame}"
    );

    // The human form a person runs says it too, whichever way the decision went.
    let human = ingest_payload(
        &store,
        &read_request(&project, "p13t006-unwritable-human", ".env"),
        false,
    );
    assert_eq!(human.status, 1, "{}", human.stderr);
    assert!(
        human.stdout.contains("SURE blocks this tool request"),
        "the human form is not the decision: {}",
        human.stdout
    );
    assert!(
        human
            .stdout
            .contains("could not record this decision in the local history"),
        "the human form does not say the record is missing:\n{}",
        human.stdout
    );
    assert_untouched(&machine, "by ingests whose store could not be written");
}

#[test]
fn a_named_store_directory_is_the_one_a_real_run_writes_to() {
    // Acceptance 1 and the writing half of acceptance 2, at the process level
    // and in the shape that can fail: a real run that writes, told to keep its
    // evidence somewhere the caller chose. If the mechanism were ignored, the
    // goal would land in the store of the person running the suite and the
    // comparison at the end would fail — which is why this test is the one the
    // `.cargo/config.toml` shape was not needed for: the flag is in the child's
    // own argument vector, so the child cannot get it from anywhere else.
    //
    // What it can see: this test and the process it starts. What it cannot see:
    // a write from a test binary that has not run yet, or from a `sure` process
    // somebody started by hand — a full `cargo test --workspace` covers the
    // first, and the digest of the store taken across that run covers both.
    let store = a_store_of_our_own();
    let project = a_project_of_our_own();
    let machine = the_store_on_this_machine();

    let goal = "make the upload reject a file over 10 MB instead of failing silently";
    let run = run_in_a_store(
        &store,
        &["check", "--goal", goal, project.to_str().expect("a path")],
    );

    // The same verdict a check of a readable project gets in this build: it ran,
    // and it cannot call the project clean. Not 0 (nothing here establishes
    // that) and not 3 (this build can check a project).
    assert_eq!(
        run.status, 1,
        "`sure check --goal …` returned {}:\nstdout:\n{}\nstderr:\n{}",
        run.status, run.stdout, run.stderr
    );
    assert!(
        run.stdout.contains("What SURE recorded"),
        "the report does not say what it wrote:\n{}",
        run.stdout
    );
    assert!(
        run.stdout.contains(goal),
        "the report does not carry the goal that was recorded:\n{}",
        run.stdout
    );

    // The row went into the store the caller named...
    let written = store.join("sure.db");
    assert!(
        written.is_file(),
        "a goal run that named {} wrote no store there",
        store.display()
    );
    // ...and the store this machine really uses is exactly as it was.
    assert_untouched(&machine, "by a check whose goal went to a named store");
}

#[test]
fn a_store_inside_the_project_is_refused_before_anything_is_recorded() {
    // Acceptance 4, at the process: a location inside the project being checked
    // is refused on the road `--store-dir` opened, in the shape the `--goal`
    // path already used. The refusal itself belongs to `Paths::ensure_outside`
    // and has its own tests in `sure-core`; what this checks is that the new
    // mechanism reaches the store through that rule rather than around it, and
    // that the process says what did not happen.
    let project = a_project_of_our_own();
    let inside = project.join(".sure-store");
    let goal = "make the upload reject a file over 10 MB instead of failing silently";

    let run = run_in_a_store(
        &inside,
        &["check", "--goal", goal, project.to_str().expect("a path")],
    );

    assert_eq!(
        run.status, 5,
        "a store inside the project returned {}. 2 would mean the parser refused the command \
         line; 3 would mean this build cannot record a goal, and it can. 5 is a run that tried \
         and did not finish:\nstdout:\n{}\nstderr:\n{}",
        run.status, run.stdout, run.stderr
    );
    assert!(
        run.stdout.is_empty(),
        "a run with no verdict wrote to standard output, where `sure check > report.txt` would \
         file it as a report:\n{}",
        run.stdout
    );
    // The three things the refusal has to say, in the words the rest of the
    // build uses for them: that it did not finish, that nothing was written,
    // and what it did instead of writing.
    assert!(
        run.stderr.contains("could not finish"),
        "the refusal does not say the run did not finish:\n{}",
        run.stderr
    );
    assert!(
        run.stderr.contains("Nothing was recorded"),
        "the refusal does not say whether the history changed:\n{}",
        run.stderr
    );
    assert!(
        run.stderr
            .contains("SURE stopped rather than treat it as authoritative"),
        "the refusal does not say what SURE did instead:\n{}",
        run.stderr
    );
    assert!(
        run.stderr.contains(&inside.display().to_string())
            && run.stderr.contains(&project.display().to_string()),
        "the refusal does not name both the location and the project it is inside:\n{}",
        run.stderr
    );
    // And it is a statement about this run rather than about the build.
    assert!(
        !run.stderr.contains("is not implemented in this build"),
        "a run that tried is worded as a command this build lacks:\n{}",
        run.stderr
    );
    assert!(
        !inside.exists(),
        "SURE left {} inside the project it was recording a goal for",
        inside.display()
    );
}

#[test]
fn a_doctor_report_says_which_store_location_the_run_is_using() {
    // Acceptance 1's other half, and acceptance 3 in the same breath: a caller
    // can name the store, `sure doctor` reports the location it used, and a
    // caller who names nothing still gets the platform's own. The report is
    // where a redirect that was ignored and one that worked are told apart —
    // both print a path, and only one of them is the caller's.
    let store = a_store_of_our_own();

    let named = run_in_a_store(&store, &["--format", "json", "doctor"]);
    assert!(
        matches!(named.status, 0 | 1),
        "`sure doctor` exited {}:\n{}",
        named.status,
        named.stderr
    );
    let frame: serde_json::Value =
        serde_json::from_str(named.stdout.trim()).unwrap_or_else(|error| {
            panic!(
                "`sure --format json doctor` is not JSON: {error}\n{}",
                named.stdout
            )
        });
    assert_eq!(
        frame["details"]["places"]["store_location"], "caller",
        "the report does not say the store's location was the caller's: {frame}"
    );
    assert_eq!(
        frame["details"]["places"]["store_file"]["path"],
        serde_json::json!(store.join("sure.db").display().to_string()),
        "the report names a store other than the one the caller named: {frame}"
    );
    let human = run_in_a_store(&store, &["doctor"]);
    assert!(
        human.stdout.contains("named for this run"),
        "the human form does not say the location is the caller's:\n{}",
        human.stdout
    );
    assert!(
        human
            .stdout
            .contains(&store.join("sure.db").display().to_string()),
        "the human form does not print the store it is using:\n{}",
        human.stdout
    );

    // The default, unchanged: a run that names nothing is about the platform's
    // own per-user location, and it says so.
    let platform = Paths::discover().expect("this machine reports per-user locations");
    let machine = the_store_on_this_machine();
    let default = Run::of(
        &sure_without_a_store()
            .args(["--format", "json", "doctor"])
            .output()
            .unwrap_or_else(|error| panic!("could not run {SURE}: {error}")),
    );
    assert!(
        matches!(default.status, 0 | 1),
        "`sure doctor` with no store named exited {}:\n{}",
        default.status,
        default.stderr
    );
    let frame: serde_json::Value = serde_json::from_str(default.stdout.trim())
        .unwrap_or_else(|error| panic!("`sure doctor` is not JSON: {error}\n{}", default.stdout));
    assert_eq!(
        frame["details"]["places"]["store_location"], "platform",
        "a caller who named nothing was reported as having named a location: {frame}"
    );
    assert_eq!(
        frame["details"]["places"]["store_file"]["path"],
        serde_json::json!(platform.store_file().display().to_string()),
        "a caller who named nothing did not get the platform's own store: {frame}"
    );
    // It read that store and did not change it: `sure doctor`'s own rule is
    // that a diagnostic does not alter what it is diagnosing.
    assert_untouched(&machine, "by a doctor run that named no store");
}

#[test]
fn a_doctor_report_says_which_settings_file_the_run_read() {
    // Acceptance line 5's second half of P15-T025, in both directions for the
    // same reason the store's is: the report is where a named file that was read
    // and one that was ignored are told apart, and a field that always answered
    // "platform" would satisfy a one-sided test while being wrong half the time.
    //
    // The two runs differ in one argument and agree about the store, which is
    // also the proof that the two locations are independent — `--store-dir`
    // names the store and not the settings, and `--settings-file` names the
    // settings and not the store. A report that answered "caller" for both
    // whenever either was named would pass a test that checked them one at a
    // time.
    let store = a_store_of_our_own();
    let settings = a_settings_file_of_our_own("privacy:\n  full_recording: false\n");

    let named = run_in_a_store(
        &store,
        &[
            "--settings-file",
            settings.to_str().expect("this test's paths are utf-8"),
            "--format",
            "json",
            "doctor",
        ],
    );
    assert!(
        matches!(named.status, 0 | 1),
        "`sure doctor` exited {}:\n{}",
        named.status,
        named.stderr
    );
    let frame: serde_json::Value =
        serde_json::from_str(named.stdout.trim()).unwrap_or_else(|error| {
            panic!(
                "`sure --format json doctor` is not JSON: {error}\n{}",
                named.stdout
            )
        });
    assert_eq!(
        frame["details"]["places"]["settings_location"], "caller",
        "the report does not say the settings file's location was the caller's, so a script cannot \
         tell a run that read the file it named from one that read the platform's: {frame}"
    );
    assert_eq!(
        frame["details"]["places"]["settings_file"]["path"],
        serde_json::json!(settings.display().to_string()),
        "the report names a settings file other than the one the caller named: {frame}"
    );
    assert_eq!(
        frame["details"]["places"]["store_location"], "caller",
        "naming a settings file moved the store's location, which is the one thing it must not do: \
         {frame}"
    );
    let human = run_in_a_store(
        &store,
        &[
            "--settings-file",
            settings.to_str().expect("this test's paths are utf-8"),
            "doctor",
        ],
    );
    assert!(
        human.stdout.contains("settings location"),
        "the human form has no line saying which settings file the run read:\n{}",
        human.stdout
    );
    assert!(
        human.stdout.contains(&settings.display().to_string()),
        "the human form does not print the settings file it is using:\n{}",
        human.stdout
    );

    // The half that makes the first half mean something: the same command with
    // no settings file named is about the platform's own file, and says so. Both
    // runs name the same store, so nothing here is explained by the store moving.
    let default = run_in_a_store(&store, &["--format", "json", "doctor"]);
    let frame: serde_json::Value = serde_json::from_str(default.stdout.trim())
        .unwrap_or_else(|error| panic!("`sure doctor` is not JSON: {error}\n{}", default.stdout));
    assert_eq!(
        frame["details"]["places"]["settings_location"], "platform",
        "a run that named no settings file was reported as having named one, so either the default \
         has moved or the report cannot tell the two apart: {frame}"
    );
    let platform = Paths::discover().expect("this machine reports per-user locations");
    assert_eq!(
        frame["details"]["places"]["settings_file"]["path"],
        serde_json::json!(platform.user_config_file().display().to_string()),
        "a run that named no settings file did not report the platform's own: {frame}"
    );
}

#[test]
fn every_harness_the_doctor_report_offers_is_one_sure_will_take_an_event_from() {
    // `P15-T001` put a list of harnesses in the report. A list of names in a
    // document is a claim, and this is the measurement under it: each name the
    // report prints is handed to the command it is a claim about, in this
    // process, and the command has to take it. The other half is the one that
    // makes the first half a measurement rather than a hope — a name that is
    // *not* on the report's list is refused by the same command, so a build that
    // accepted everything would fail here.
    //
    // The list is read out of the report rather than restated, so a harness
    // added to or removed from `crates/sure-core/src/doctor.rs` is exercised by
    // this test without this test being edited.
    //
    // Mutation, run rather than described: in `INTEGRATIONS` of
    // `crates/sure-core/src/doctor.rs`, change the name `"codex"` to `"codexx"`.
    // The first loop hands `codexx` to `sure hook ingest --source` and the
    // refusal is printed. The run is reported in this task's hand-back with what
    // else it reddened.
    let store = a_store_of_our_own();
    let machine = the_store_on_this_machine();

    let doctor = run_in_a_store(&store, &["--format", "json", "doctor"]);
    assert!(
        matches!(doctor.status, 0 | 1),
        "`sure doctor` exited {}:\n{}",
        doctor.status,
        doctor.stderr
    );
    let frame: serde_json::Value = serde_json::from_str(doctor.stdout.trim())
        .unwrap_or_else(|error| panic!("`sure doctor` is not JSON: {error}\n{}", doctor.stdout));
    let offered: Vec<String> = frame["details"]["integrations"]
        .as_array()
        .unwrap_or_else(|| panic!("the report carries no harness list: {frame}"))
        .iter()
        .map(|entry| {
            entry["name"]
                .as_str()
                .unwrap_or_else(|| panic!("a harness in the report has no name: {entry}"))
                .to_owned()
        })
        .collect();
    assert!(
        !offered.is_empty(),
        "the report offers no harness at all, so this test measures nothing: {frame}"
    );

    // A payload rather than an empty pipe, and that matters: an empty standard
    // input is refused before the source is looked at (`hook.rs`'s "No event was
    // read from standard input"), so a test that piped nothing would pass for an
    // unknown source too and would be measuring nothing at all. This payload is
    // not an event any of the three harnesses sends, so what each run answers is
    // the normaliser's refusal — which is the answer that says the *source* was
    // taken and read.
    let payload = serde_json::json!({
        "event": "an event SURE has never seen",
        "harness_session_id": "p15t001-harness-list",
        "tool": "Shell",
        "args": {"command": "echo hello"},
    })
    .to_string();
    for name in &offered {
        let run = ingest_argv(&store, &["hook", "ingest", "--source", name], &payload);
        assert!(
            !run.stderr.contains("not one SURE knows how to ingest"),
            "the report offers `{name}` as a harness SURE can be told about, and \
             `sure hook ingest --source {name}` refuses it:\n{}",
            run.stderr
        );
        assert!(
            matches!(run.status, 0 | 1 | 5),
            "`sure hook ingest --source {name}` exited {}, which is not one of the three \
             answers this command has: 0 or 1 for a decision, 5 for an event it could not \
             read:\nstdout:\n{}\nstderr:\n{}",
            run.status,
            run.stdout,
            run.stderr
        );
    }

    // The other side. `copilot` is not a name this test made up: SURE ships a
    // package for Copilot, and its launcher passes `--source copilot`, which
    // this build refuses. That is why the report does not offer it, and the
    // refusal is asserted here rather than asserted in prose.
    for name in ["copilot", "nope"] {
        assert!(
            !offered.iter().any(|listed| listed == name),
            "the report offers `{name}` and this test is about the names it does not offer: \
             {offered:?}"
        );
        // The same non-empty payload as the loop above, for the same reason:
        // the refusal asserted here is the *source* refusal, and an empty pipe
        // is refused earlier, before the source is looked at.
        let run = ingest_argv(&store, &["hook", "ingest", "--source", name], &payload);
        assert!(
            run.stderr.contains("not one SURE knows how to ingest"),
            "`sure hook ingest --source {name}` did not refuse a source the report does not \
             offer, so the loop above proves nothing:\n{}",
            run.stderr
        );
        assert_eq!(run.status, 5, "{}", run.stderr);
    }

    assert_untouched(&machine, "by a doctor run and the hook sources it offered");
}

// --- hook failure semantics (P13-T007) ----------------------------------

/// One `sure hook ingest` started the way a launcher starts it, or the way a
/// person would.
///
/// `args` is the whole argument vector after the program name, so a test can
/// leave `--source` out or name one SURE does not know without this helper
/// having an opinion about it.
fn ingest_argv(store: &Path, args: &[&str], payload: &str) -> Run {
    let mut command = sure_in_a_store(store);
    command.args(args);
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("a child process");
    let mut stdin = child.stdin.take().expect("the pipe");
    stdin.write_all(payload.as_bytes()).expect("write to stdin");
    drop(stdin);
    Run::of(&child.wait_with_output().expect("the child exits"))
}

#[test]
fn the_inputs_a_harness_produces_by_accident_exit_5_and_record_nothing() {
    // `crates/sure-cli/src/hook.rs` asserts each of these as a `Report` value,
    // which is a statement about a function. A launcher does not talk to a
    // function; it talks to a process, and what it relays is the status. These
    // are the inputs a harness produces by accident — a payload it did not
    // send, a source SURE does not know, an event SURE has no mapping for, a
    // command line with no source on it — and the status they must produce is 5
    // (`report::exit::FAILED`: SURE tried and did not finish), never 0 and
    // never 1.
    //
    // Never 0 is the whole point: 0 is what a launcher passes back to a harness
    // that then proceeds, and a hook that answered nothing while reading as
    // "SURE looked and said yes" is the false green this repository exists to
    // refuse. Never 1 matters just as much for the opposite reason: 1 is SURE's
    // `block`, and an event SURE could not read is not a refusal.
    //
    // **The name carries no count, and that is the repair `P15-T033` made.**
    // It was `the_four_ways_a_hook_event_can_fail_exit_5_and_record_nothing`,
    // which was a claim about a closed set: `docs/integrations/HOOK_FAILURE_SEMANTICS.md`
    // §2.1 headed its block "the four failure inputs" and listed five, and
    // `P15-T025` had since added a sixth that is not an accident at all. `four`
    // was false in two directions at once. A count here goes stale the next time
    // a branch is added and the characterisation does not, so the name is the
    // characterisation; the case the old name had also stopped covering — a
    // command line with no `--source` on it at all, which the block above has
    // always listed — is below.
    //
    // The other kind of input is deliberately **not** here: one a project writes
    // on purpose, by naming a settings file inside itself. It reaches the same
    // status and the same absence of evidence for a different reason, and it is
    // held, with the control that gives "nothing was written" its meaning, by
    // `a_hook_event_that_names_a_settings_file_inside_the_project_is_refused`
    // below. `docs/integrations/HOOK_FAILURE_SEMANTICS.md` §2.4 is the argument
    // for why both are failures rather than verdicts.
    let project = a_project_of_our_own();
    let known = serde_json::json!({
        "event": "preToolUse",
        "harness_session_id": "p13t007-failure",
        "project_root": project.to_string_lossy(),
        "tool": "Shell",
        "args": {"command": "echo hello"},
        "timestamp_utc": "2026-09-19T09:30:00Z",
        "source": "cursor",
    })
    .to_string();
    let unknown_event = serde_json::json!({
        "event": "somethingElseEntirely",
        "harness_session_id": "p13t007-failure",
        "project_root": project.to_string_lossy(),
        "tool": "Shell",
        "args": {"command": "echo hello"},
        "timestamp_utc": "2026-09-19T09:30:00Z",
        "source": "cursor",
    })
    .to_string();

    let cases: [(&str, Vec<&str>, &str); 5] = [
        (
            "empty stdin",
            vec!["hook", "ingest", "--source", "cursor", "pre-tool-use"],
            "",
        ),
        (
            "stdin that is not JSON",
            vec!["hook", "ingest", "--source", "cursor", "pre-tool-use"],
            "this is not an event",
        ),
        (
            "a source SURE does not know",
            vec!["hook", "ingest", "--source", "copilot", "pre-tool-use"],
            &known,
        ),
        (
            "an event type with no mapping",
            vec!["hook", "ingest", "--source", "cursor", "pre-tool-use"],
            &unknown_event,
        ),
        // The last case is a launcher that forgot the flag rather than one that
        // sent something SURE cannot read, and it is here because the block
        // above has listed it since it was written while this test asserted
        // four of its five rows. The claim "this test asserts the block" is
        // only true with it.
        (
            "no --source at all",
            vec!["hook", "ingest", "pre-tool-use"],
            &known,
        ),
    ];

    for (what, args, payload) in cases {
        let store = a_store_of_our_own();
        let machine = the_store_on_this_machine();
        let run = ingest_argv(&store, &args, payload);
        assert_eq!(
            run.status, 5,
            "{what}: a hook event SURE could not read exited {} rather than 5. A launcher relays \
             this status to a harness, so 0 would read as 'SURE looked and allowed it' and 1 as a \
             refusal SURE never made.\nstdout:\n{}\nstderr:\n{}",
            run.status, run.stdout, run.stderr
        );
        assert!(
            !store_file(&store).exists(),
            "{what}: the refused event wrote a store at {}",
            store_file(&store).display()
        );
        let reported = history_frame(&store, &[]);
        assert_eq!(
            reported["details"]["total"].as_i64(),
            Some(0),
            "{what}: a refused event was recorded anyway: {reported}"
        );
        assert_eq!(
            reported["details"]["store_present"].as_bool(),
            Some(false),
            "{what}: a refused event left a store behind: {reported}"
        );
        assert_untouched(&machine, "by a hook event SURE could not read");
    }
}

/// The refusal `P15-T025` added, held at the level a harness meets it: a
/// process, its status, and the frame it wrote.
///
/// The input is the one a **project writes on purpose**: its own `sure.yaml`
/// asks SURE to record everything, and the run is pointed at that file with
/// `--settings-file`. A settings file says what SURE may do and what it may
/// run, and one inside the project could have been written by the thing being
/// judged, so SURE refuses to read it. That refusal is `P15-T025`'s and is not
/// in question here — `a_settings_file_inside_the_project_is_refused_and_nothing_is_written`
/// above holds it for `sure config set`. What `P15-T033` settled is the
/// **shape** of the answer, and this holds the shape rather than any sentence:
/// exit 5, a frame that says `outcome: "failed"` and carries **no `decision`
/// key**, and a store directory with no file in it.
///
/// The control below is the same event about the same project with the flag
/// left off. Without it, "no store and no row" would pass just as well against
/// a hook that records nothing at all; with it, the refusal is the only
/// difference between the two runs. The control is also where the shape's cost
/// is visible: a run that **decides** answers exit 1, a `decision` of `block`,
/// and a store with the event in it — so an answer of `decision: "block"` to
/// this refusal would have had to write the very file its absence leaves out,
/// under settings SURE refused to read. §2.4 of
/// `docs/integrations/HOOK_FAILURE_SEMANTICS.md` is that argument in full.
#[test]
fn a_hook_event_that_names_a_settings_file_inside_the_project_is_refused() {
    let machine = the_store_on_this_machine();
    let project = a_project_of_our_own();
    // The file the project could have written, in the shape the privacy
    // corpus's `a-settings-file-the-project-could-write-grants-nothing` uses.
    // Nothing in this test reads it: it is the file SURE refuses to read.
    let inside = project.join("sure.yaml");
    std::fs::write(&inside, "privacy:\n  full_recording: true\n")
        .unwrap_or_else(|error| panic!("cannot write {}: {error}", inside.display()));
    let inside_named = inside.to_str().expect("the scratch path is utf-8");
    // A pre-action event, so the tool request is one SURE would otherwise judge
    // — and the control below shows it judging it.
    let request = shell_request(&project, "p15t033-inside-project-settings", "rm -rf /");

    let store = a_store_of_our_own();
    let refused = ingest_argv(
        &store,
        &[
            "--format",
            "json",
            "--settings-file",
            inside_named,
            "hook",
            "ingest",
            "--source",
            "cursor",
            "pre-tool-use",
        ],
        &request,
    );
    assert_eq!(
        refused.status, 5,
        "a hook event whose settings file is inside the project it is about exited {} rather than \
         5. 0 is what a launcher passes back to a harness that then proceeds, and 1 is SURE's \
         `block`, which is a verdict about the request — a request SURE never looked at here, \
         because it stopped one question earlier.\nstdout:\n{}\nstderr:\n{}",
        refused.status, refused.stdout, refused.stderr
    );
    let frame: serde_json::Value =
        serde_json::from_str(refused.stdout.trim()).unwrap_or_else(|error| {
            panic!("the refusal is not one frame: {error}\n{}", refused.stdout)
        });
    assert_eq!(
        frame["outcome"].as_str(),
        Some("failed"),
        "the refusal does not say it failed: {frame}"
    );
    assert_eq!(frame["exit_code"].as_i64(), Some(5), "{frame}");
    assert_eq!(
        frame["exit_code"].as_i64(),
        Some(i64::from(refused.status)),
        "the frame and the process disagree about the same run: {frame}"
    );
    assert!(
        frame.get("decision").is_none(),
        "the refusal carries a decision SURE never reached. It stopped before reading the \
         settings, so it read none of the mode, the permissions or the tool the request names, \
         and a harness that reads `decision` would read a verdict: {frame}"
    );
    assert_eq!(
        frame["details"]["what"].as_str(),
        Some("SURE did not read the settings it was pointed at."),
        "{frame}"
    );
    let detail = frame["details"]["detail"]
        .as_str()
        .unwrap_or_else(|| panic!("the refusal carries no detail: {frame}"));
    assert!(
        detail.contains(inside_named)
            && detail.contains("the project it was asked about")
            && detail.contains("SURE stopped rather than"),
        "the refusal does not name the file it would not read, or does not say that it stopped \
         rather than answer: {detail}"
    );

    assert!(
        !store_file(&store).exists(),
        "the refused event wrote a store at {}",
        store_file(&store).display()
    );
    let reported = history_frame(&store, &[]);
    assert_eq!(
        reported["details"]["total"].as_i64(),
        Some(0),
        "a refused event was recorded anyway: {reported}"
    );
    assert_eq!(
        reported["details"]["store_present"].as_bool(),
        Some(false),
        "a refused event left a store behind: {reported}"
    );

    // The control: the same event about the same project, with the flag left
    // off. SURE reads the project, decides about the shell request, and records
    // both — which is what makes the refusal's empty store a statement about
    // the settings file rather than about a hook that writes nothing.
    let store = a_store_of_our_own();
    let decided = ingest_argv(
        &store,
        &[
            "--format",
            "json",
            "hook",
            "ingest",
            "--source",
            "cursor",
            "pre-tool-use",
        ],
        &request,
    );
    assert_eq!(
        decided.status, 1,
        "the control event — the same request, with no settings file named — exited {} rather \
         than 1, so the refusal above is not the only difference between the two runs:\n{}",
        decided.status, decided.stderr
    );
    let frame: serde_json::Value =
        serde_json::from_str(decided.stdout.trim()).unwrap_or_else(|error| {
            panic!(
                "the control's answer is not one frame: {error}\n{}",
                decided.stdout
            )
        });
    assert_eq!(
        frame["decision"].as_str(),
        Some("block"),
        "the control did not reach a verdict about the request: {frame}"
    );
    assert_eq!(frame["outcome"].as_str(), Some("not_green"), "{frame}");
    assert_eq!(
        frame["exit_code"].as_i64(),
        Some(i64::from(decided.status)),
        "the frame and the process disagree about the same run: {frame}"
    );
    assert!(
        store_file(&store).exists(),
        "the control event recorded nothing, so the refusal's empty store would prove nothing"
    );
    let recorded = history_frame(&store, &[]);
    assert_eq!(
        recorded["details"]["total"].as_i64(),
        Some(1),
        "the control event is not in the history it was recorded in: {recorded}"
    );

    assert_untouched(
        &machine,
        "by a hook event whose settings file is inside the project",
    );
}

/// One Cursor `sessionStart`, with the project root the caller names.
///
/// The shape is `integrations/cursor/fixtures/session-start.json`'s. The root is
/// a parameter rather than that fixture's value on purpose: the fixture carries
/// `C:\Users\dev\sample-project`, which is absolute on Windows and relative
/// everywhere else, and an input whose meaning depends on the machine is the
/// defect `P15-T035` repaired.
fn session_start_request(project_root: &str, harness_session: &str) -> String {
    serde_json::json!({
        "event": "sessionStart",
        "harness_session_id": harness_session,
        "project_root": project_root,
        "timestamp_utc": "2026-09-19T09:30:00Z",
        "source": "cursor",
    })
    .to_string()
}

/// The fifth way a hook event stops before it answers: a project root SURE
/// cannot place.
///
/// The four above are events SURE could not *read*. This one it reads
/// completely — the source is known, the event type is mapped, the payload
/// validates — and what stops it is that `project_root` is not an absolute path.
/// Such a value is resolved against whatever directory the hook process was
/// started in, so the settings question ("is the file that decides what SURE may
/// record and run inside this project?") would be answered by the harness's
/// working directory rather than by the event, and so would the key the session
/// is recorded under.
///
/// `P15-T035` decided SURE refuses rather than resolves, and the refusal is
/// argued in `crates/sure-cli/src/hook.rs`'s module doc and recorded harness by
/// harness in `docs/integrations/HOOK_FAILURE_SEMANTICS.md` §2.3. This holds that
/// decision at the level a harness meets it — a process and its status — and
/// holds the *shape* rather than one sentence: exit 5, a frame with no
/// `decision` field, and no store and no row afterwards.
///
/// Every root below is relative on all three of the platforms the suite runs on.
/// None of them is a path that means one thing on Windows and another elsewhere,
/// which is what would make this test the defect it is about — the class the
/// fixtures do not fall into because this test never reads one.
#[test]
fn a_project_root_that_is_not_absolute_is_refused_and_records_nothing() {
    let machine = the_store_on_this_machine();

    // The control. Without it, "no store and no row" below would pass just as
    // well against a hook that records nothing at all; what the refusals have to
    // show is that the *only* thing wrong with those events is where the project
    // is. This event is the same event, with a root SURE can place.
    let store = a_store_of_our_own();
    let project = a_project_of_our_own();
    let allowed = ingest_argv(
        &store,
        &[
            "--format",
            "json",
            "hook",
            "ingest",
            "--source",
            "cursor",
            "session-start",
        ],
        &session_start_request(&project.to_string_lossy(), "p15t035-placeable"),
    );
    assert_eq!(
        allowed.status, 0,
        "a sessionStart about a project SURE can place did not answer:\n{}",
        allowed.stderr
    );
    let frame: serde_json::Value =
        serde_json::from_str(allowed.stdout.trim()).unwrap_or_else(|error| {
            panic!(
                "the answer to a placeable project is not one frame: {error}\n{}",
                allowed.stdout
            )
        });
    assert_eq!(frame["decision"].as_str(), Some("allow"), "{frame}");
    assert!(
        store_file(&store).exists(),
        "the control event recorded nothing, so the refusals below would prove nothing"
    );
    let recorded = history_frame(&store, &[]);
    assert_eq!(
        recorded["details"]["total"].as_i64(),
        Some(1),
        "the control event is not in the history it was recorded in: {recorded}"
    );

    // The empty string is here because it is the value that must *not* fall
    // through to the current-directory default: an event with no `project_root`
    // at all gets that default, deliberately, and an event that names an empty
    // one has named something SURE cannot use. `.` is here because it is what a
    // resolver would turn into the hook's own working directory and then record
    // the session under.
    for root in ["sample-project", "../sample-project", ".", ""] {
        let store = a_store_of_our_own();
        let run = ingest_argv(
            &store,
            &[
                "--format",
                "json",
                "hook",
                "ingest",
                "--source",
                "cursor",
                "session-start",
            ],
            &session_start_request(root, "p15t035-unplaceable"),
        );
        assert_eq!(
            run.status, 5,
            "a sessionStart whose project root is {root:?} exited {} rather than 5. 0 is what a \
             launcher passes back to a harness that then proceeds, and 1 is a block SURE never \
             made.\nstdout:\n{}\nstderr:\n{}",
            run.status, run.stdout, run.stderr
        );
        let frame: serde_json::Value =
            serde_json::from_str(run.stdout.trim()).unwrap_or_else(|error| {
                panic!(
                    "the refusal of {root:?} is not one frame: {error}\n{}",
                    run.stdout
                )
            });
        assert_eq!(frame["outcome"].as_str(), Some("failed"), "{frame}");
        assert_eq!(frame["exit_code"].as_i64(), Some(5), "{frame}");
        assert!(
            frame.get("decision").is_none(),
            "{root:?}: the refusal carries a decision SURE never made, and a harness that read \
             `decision` would read an answer: {frame}"
        );
        assert_eq!(
            frame["details"]["what"].as_str(),
            Some("SURE did not read the settings it was pointed at."),
            "{frame}"
        );
        let detail = frame["details"]["detail"]
            .as_str()
            .unwrap_or_else(|| panic!("the refusal of {root:?} carries no detail: {frame}"));
        assert!(
            detail.contains(&format!("{root:?}")) && detail.contains("is not an absolute path"),
            "the refusal of {root:?} does not name the value it refused and what is wrong with \
             it: {detail}"
        );
        assert!(
            detail.contains("SURE stopped rather than"),
            "the refusal of {root:?} does not say it stopped rather than answer: {detail}"
        );

        assert!(
            !store_file(&store).exists(),
            "{root:?}: the refused event wrote a store at {}",
            store_file(&store).display()
        );
        let reported = history_frame(&store, &[]);
        assert_eq!(
            reported["details"]["total"].as_i64(),
            Some(0),
            "{root:?}: a refused event was recorded anyway: {reported}"
        );
        assert_eq!(
            reported["details"]["store_present"].as_bool(),
            Some(false),
            "{root:?}: a refused event left a store behind: {reported}"
        );
    }

    // The same refusal in the shape the claude-code launcher reads, which passes
    // no `--format` flag: nothing at all on stdout, and the sentence on stderr. A
    // harness reading stdout sees no answer, which is the point of exit 5 — and a
    // person reading stderr sees what to change.
    let store = a_store_of_our_own();
    let human = ingest_argv(
        &store,
        &["hook", "ingest", "--source", "cursor", "session-start"],
        &session_start_request("sample-project", "p15t035-human"),
    );
    assert_eq!(human.status, 5, "{}", human.stderr);
    assert!(
        human.stdout.is_empty(),
        "the human form of the refusal wrote to stdout, where a harness reads an answer: {}",
        human.stdout
    );
    assert!(
        human.stderr.contains("could not finish")
            && human.stderr.contains("is not an absolute path"),
        "the refusal said nothing a person could act on:\n{}",
        human.stderr
    );

    assert_untouched(
        &machine,
        "by a hook event whose project root is not absolute",
    );
}

#[test]
fn a_hook_answer_reaches_stdout_in_the_shape_the_launcher_asked_for() {
    // The launchers differ in one flag, and this is what it buys. Both of the
    // packages that pass `--format json` (cursor and codex) read a frame; the
    // claude-code launcher does not, and reads prose. Both shapes are part of
    // the failure semantics, because a harness reads stdout and decides: the
    // frame carries a `decision` field and the prose does not, and on the
    // failure path the frame carries no `decision` at all, which is the
    // difference between "SURE refused" and "SURE could not say".
    //
    // Asserted at the process level because that is where a harness meets it.
    //
    // The request is a shell command, and the hold it gets is the default
    // execution mode's: since P13-T009 a project's own `execution.*` settings are
    // inert, so this test no longer writes a `sure.yaml` naming a mode — one
    // would change nothing here and would read as though it had.
    let store = a_store_of_our_own();
    let project = a_project_of_our_own();
    let machine = the_store_on_this_machine();
    let held = shell_request(&project, "p13t007-shape", "rm -rf build/");

    // A verdict, human: one sentence on stdout, exit 1. `--format human` is the
    // default the claude-code launcher gets by passing no format flag.
    let human = ingest_argv(
        &store,
        &["hook", "ingest", "--source", "cursor", "pre-tool-use"],
        &held,
    );
    assert_eq!(human.status, 1, "{}", human.stderr);
    assert!(
        human.stdout.contains("SURE blocks this tool request"),
        "the human form of a block is not on stdout: {}",
        human.stdout
    );
    assert!(
        serde_json::from_str::<serde_json::Value>(human.stdout.trim()).is_err(),
        "the human form is JSON after all, so a harness would read a decision it was not sent: {}",
        human.stdout
    );

    // A verdict, machine: one JSON object, and its `decision` is the field a
    // harness looks for.
    let machine_form = ingest_argv(
        &store,
        &[
            "--format",
            "json",
            "hook",
            "ingest",
            "--source",
            "cursor",
            "pre-tool-use",
        ],
        &held,
    );
    assert_eq!(machine_form.status, 1, "{}", machine_form.stderr);
    let frame: serde_json::Value =
        serde_json::from_str(machine_form.stdout.trim()).unwrap_or_else(|error| {
            panic!(
                "the machine form is not JSON: {error}\n{}",
                machine_form.stdout
            )
        });
    assert_eq!(frame["decision"].as_str(), Some("block"), "{frame}");
    assert_eq!(frame["exit_code"].as_i64(), Some(1), "{frame}");

    // A failure, human: nothing on stdout, the sentence on stderr. A harness
    // that reads stdout sees no answer at all.
    let failed_human = ingest_argv(
        &store,
        &["hook", "ingest", "--source", "nope", "pre-tool-use"],
        &held,
    );
    assert_eq!(failed_human.status, 5, "{}", failed_human.stderr);
    assert!(
        failed_human.stdout.is_empty(),
        "the human form of a failure wrote to stdout: {}",
        failed_human.stdout
    );
    assert!(
        failed_human.stderr.contains("could not finish"),
        "the human form of a failure said nothing on stderr: {}",
        failed_human.stderr
    );

    // A failure, machine: a frame that says it failed, and **no `decision`
    // field**. A harness that went looking for one would find nothing rather
    // than something it could read as an answer.
    let failed_machine = ingest_argv(
        &store,
        &["--format", "json", "hook", "ingest", "--source", "nope"],
        &held,
    );
    assert_eq!(failed_machine.status, 5, "{}", failed_machine.stderr);
    let frame: serde_json::Value = serde_json::from_str(failed_machine.stdout.trim())
        .unwrap_or_else(|error| {
            panic!(
                "the machine form of a failure is not JSON: {error}\n{}",
                failed_machine.stdout
            )
        });
    assert_eq!(frame["outcome"].as_str(), Some("failed"), "{frame}");
    assert_eq!(frame["exit_code"].as_i64(), Some(5), "{frame}");
    assert!(
        frame.get("decision").is_none(),
        "the machine form of a failure carries a decision SURE never made: {frame}"
    );
    assert_untouched(&machine, "by the runs whose shapes this test pins");
}

// --- what a project's own files cannot decide (P13-T009) ----------------

/// A project file asking for everything a project's own file can ask for.
///
/// A mode that would run the project's code, the two permissions that only exist
/// under such a mode, the loosest protection mode there is, and a full recording
/// kept for no time at all. Each is a *request*
/// (`docs/adr/0011-project-configuration-is-a-request.md`), and a test claiming
/// a project cannot weaken the user's policy has to have a project that tried.
const A_PROJECT_ASKING_FOR_EVERYTHING: &str = "\
execution:
  mode: host_confirmed
  allow_dependency_install: true
  allow_network: true
protection:
  mode: standard
privacy:
  full_recording: true
  full_recording_retention_days: 0
";

#[test]
fn a_projects_execution_settings_do_not_move_a_hook_decision() {
    // Criterion 1 through the command a harness runs, at the status a launcher
    // reads: two projects — one with no `sure.yaml` at all, one asking for
    // everything — and the same shell request sent to each. The two answers must
    // be the same answer.
    //
    // **This is the test that fails on the old code.** Before the change the
    // second project's `execution.mode: host_confirmed` *was* the mode the hook
    // decided under (`load_execution_config` read `authority.project()` and
    // nothing else), so the request became one that needs consent and the reason
    // became the sentence about the command's own danger. The frames differed.
    //
    // The request is a shell command because that is the one whose permission the
    // `execution.*` settings decide. A read is allowed under every setting either
    // file can name, so a read would produce equal frames whether or not the fix
    // was in place — a test that passes by matching nothing.
    //
    // **What this cannot show on this machine, and does not claim.** The other
    // half of the rule is that the *user's* own file can put the hook in
    // host-confirmed mode. That file is `%APPDATA%\SURE\sure.yaml` here, and no
    // test may write it; this case could point the run at a file of its own with
    // `--settings-file`, and it deliberately does not, because what it is about
    // is the pair of frames a machine that has named no settings file produces —
    // the same limit
    // `the_two_paths_disagree_about_nothing_that_matters` records for the data
    // and config directories. So the sentence below is asserted to be *the same
    // in both frames* and never to be a particular sentence: on a machine whose
    // user file grants host-confirmed execution, both frames carry the rule's own
    // reason instead, and they still have to agree. `hook.rs`'s
    // `a_user_who_allowed_project_code_is_what_puts_the_hook_in_host_confirmed_mode`
    // observes the user's half in-process, through `Paths::from_roots`.
    let store = a_store_of_our_own();
    let machine = the_store_on_this_machine();

    let silent = a_project_of_our_own();
    let demanding = a_project_of_our_own();
    std::fs::write(demanding.join("sure.yaml"), A_PROJECT_ASKING_FOR_EVERYTHING)
        .expect("write the project's settings");

    let silent_run = ingest_payload(
        &store,
        &shell_request(&silent, "p13t009-silent", "rm -rf build/"),
        true,
    );
    let demanding_run = ingest_payload(
        &store,
        &shell_request(&demanding, "p13t009-demanding", "rm -rf build/"),
        true,
    );

    // Both refused, and neither a failure to answer: a `failed` frame carries no
    // `decision`, so equality between two of those would say nothing about the
    // settings.
    assert_eq!(
        silent_run.status, demanding_run.status,
        "{}",
        demanding_run.stdout
    );
    assert_eq!(silent_run.status, 1, "{}", silent_run.stdout);
    let silent_frame = hook_frame(&silent_run);
    let demanding_frame = hook_frame(&demanding_run);

    for field in ["outcome", "command", "decision", "reason", "exit_code"] {
        assert_eq!(
            silent_frame[field], demanding_frame[field],
            "a project's own file moved the {field} of the decision a harness was given:\n\
             silent: {silent_frame}\ndemanding: {demanding_frame}"
        );
    }
    assert_eq!(
        silent_frame["decision"].as_str(),
        Some("block"),
        "the request was not held, so the comparison above is about two allows: {silent_frame}"
    );
    assert!(
        silent_frame["reason"]
            .as_str()
            .is_some_and(|reason| !reason.is_empty()),
        "a block that says nothing about why: {silent_frame}"
    );

    // The recording half of the same claim (D2). The demanding project asked for
    // a full recording; the store holds the two events and no recording. The
    // events are asserted first, so this is an absence beside something rather
    // than an empty store answering for it.
    let store = open_the_store(&store);
    let everything = store
        .history(
            &HistoryFilter {
                include_recordings: true,
                ..HistoryFilter::default()
            },
            10,
        )
        .expect("the store these ingests wrote");
    assert!(
        !everything.is_empty(),
        "neither ingest wrote a row, so the absence below would prove nothing"
    );
    assert!(
        everything
            .iter()
            .all(|row| row.kind != RecordKind::Recording),
        "a project's own file turned the full recording on, which only the user's file may do"
    );
    assert!(
        everything
            .iter()
            .any(|row| row.kind == RecordKind::Decision),
        "no decision was recorded, so this test is not about a decision SURE reached: {everything:?}"
    );
    assert_untouched(&machine, "by ingests that named a store");
}

#[test]
fn a_projects_execution_settings_do_not_move_the_mode_a_check_reports() {
    // The same claim on the other path this task routes (D3), read from the frame
    // a script reads. `sure check` needs no harness: the two runs below are the
    // real binary against two real projects, and `details.mode` is the arbitrated
    // mode the run planned under.
    //
    // What it cannot do is show the mode changing anything: this build has no
    // runner for a planned check (`pipeline.rs`), so the only observable is the
    // plan and the stage text, and the brief says not to write a test whose
    // passing depends on a run that never happens. The plan's own observable —
    // which checks the mode refused — is asserted in `check.rs`, where a user
    // file can be written.
    let silent = a_project_of_our_own();
    let demanding = a_project_of_our_own();
    std::fs::write(demanding.join("sure.yaml"), A_PROJECT_ASKING_FOR_EVERYTHING)
        .expect("write the project's settings");

    let silent_run = run(&[
        "--format",
        "json",
        "check",
        silent.to_str().expect("a path"),
    ]);
    let demanding_run = run(&[
        "--format",
        "json",
        "check",
        demanding.to_str().expect("a path"),
    ]);

    assert_eq!(
        silent_run.status, demanding_run.status,
        "{}",
        demanding_run.stdout
    );
    assert_ne!(
        silent_run.status, 3,
        "this build cannot check a project, which is not what this test is about:\n{}",
        silent_run.stderr
    );
    let silent_frame: serde_json::Value = serde_json::from_str(silent_run.stdout.trim())
        .unwrap_or_else(|error| {
            panic!(
                "`sure check` is not one frame: {error}\n{}",
                silent_run.stdout
            )
        });
    let demanding_frame: serde_json::Value = serde_json::from_str(demanding_run.stdout.trim())
        .unwrap_or_else(|error| {
            panic!(
                "`sure check` is not one frame: {error}\n{}",
                demanding_run.stdout
            )
        });

    let silent_details = &silent_frame["details"];
    let demanding_details = &demanding_frame["details"];
    assert_eq!(
        silent_details["state"], demanding_details["state"],
        "a project's own file changed whether the run finished: {silent_details} vs \
         {demanding_details}"
    );
    assert!(
        silent_details["mode"].is_string(),
        "the run produced no mode to compare:\n{silent_frame}"
    );
    assert_eq!(
        silent_details["mode"], demanding_details["mode"],
        "a project's own file moved the execution mode a check ran under: {} then {}",
        silent_details["mode"], demanding_details["mode"]
    );
    assert_eq!(
        silent_details["privacy"]["mode"], demanding_details["privacy"]["mode"],
        "a project's own file moved the privacy mode a check ran under"
    );
}

// --- what a project's own cache directory cannot do (P13-T009) ---------

/// Every file under `directory`, with its path relative to `directory` and the
/// bytes it holds.
///
/// A panic when a directory cannot be read, and sorted so that two walks of the
/// same tree compare equal: the assertion this is built for is "the bytes are
/// what they were", and a list that came back empty would make that true of a
/// directory nobody had looked at.
fn bytes_under(directory: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    fn walk(root: &Path, directory: &Path, into: &mut Vec<(PathBuf, Vec<u8>)>) {
        let entries = std::fs::read_dir(directory)
            .unwrap_or_else(|error| panic!("{}: {error}", directory.display()));
        for entry in entries {
            let path = entry.expect("a directory entry").path();
            if path.is_dir() {
                walk(root, &path, into);
            } else {
                let relative = path
                    .strip_prefix(root)
                    .expect("a path under the directory being read")
                    .to_path_buf();
                let bytes = std::fs::read(&path)
                    .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
                into.push((relative, bytes));
            }
        }
    }
    let mut found = Vec::new();
    walk(directory, directory, &mut found);
    found.sort();
    found
}

/// A `.sure` directory a project wrote for itself.
///
/// This build has no writer for the directory (`paths/mod.rs`: *"Nothing
/// authoritative may be written here, and the type carries no way to ask for
/// it"*), so the only `.sure` there can be is one the project made. The two
/// files are the two things a project could hope a cache would do for it:
/// settings asking for more than a project may have, and a record saying the
/// project passed.
fn a_hand_written_cache_directory(project: &Path) {
    let cache = project.join(".sure");
    std::fs::create_dir_all(&cache).unwrap_or_else(|error| panic!("{}: {error}", cache.display()));
    std::fs::write(cache.join("sure.yaml"), A_PROJECT_ASKING_FOR_EVERYTHING)
        .expect("a cache file this test wrote");
    std::fs::write(
        cache.join("last-run.json"),
        "{\"state\": \"finished\", \"green\": true, \"stopped_at\": null}\n",
    )
    .expect("a cache file this test wrote");
}

#[test]
fn a_project_cannot_write_its_own_answer_into_the_cache_directory() {
    // Criterion 3, in the terms §3 D4 sets. `.sure` has no writer in this build
    // and nothing reads it, so what can be tested is what poisoning it *cannot*
    // do. The same project is asked the same two questions either side of a
    // hand-written `.sure/` appearing in it:
    //
    //   * the decision a harness is given for one shell request;
    //   * the verdict `sure check --goal` reaches, the state it finished in, and
    //     the digest of the project state the goal was recorded against.
    //
    // The digest and not the fingerprint the report carries: `project_fingerprint`
    // is a `FingerprintId::generate()` per run (`sure-domain/src/vocabulary.rs`),
    // so two runs of one unchanged project differ in it by construction and
    // comparing it would fail whatever `.sure` held. The digest is the field that
    // is the project's state rather than an identifier for this run of it.
    //
    // What this does *not* establish. The other two halves of D4 are rules about
    // what SURE does with a path under `.sure`, and both are already tested where
    // the rule is: `hook_protection.rs`'s
    // `strict_holds_a_change_in_the_documents_areas_and_nothing_else` holds a
    // `Write` to `.sure/cache.json` under strict and allows it under standard,
    // and `scan_project.rs`'s `sure_own_cache_inside_the_project_is_left_out`
    // with `fingerprint_content.rs`'s `churn_in_every_excluded_kind_of_directory_
    // changes_nothing` show the scanner skipping it. They are not repeated here,
    // because at this level they are not reachable: a `Write` to `.sure/…` needs
    // the `WriteProject` permission, which no configuration file can grant
    // (`Authority::permissions`), so under the inspect-only mode every project
    // gets, the request is refused before the configuration-area rule is asked.
    let store = a_store_of_our_own();
    let machine = the_store_on_this_machine();
    let project = a_project_of_our_own();
    let goal = "make the upload reject a file over 10 MB instead of failing silently";

    let clean_hook = ingest_payload(
        &store,
        &shell_request(&project, "p13t009-cache", "rm -rf build/"),
        true,
    );
    let clean_check = run_in_a_store(
        &store,
        &[
            "--format",
            "json",
            "check",
            "--goal",
            goal,
            project.to_str().expect("a path"),
        ],
    );
    assert_eq!(
        clean_check.status, 1,
        "the check before the cache directory existed did not reach a verdict, so there would be \
         nothing for the poisoning to move:\nstdout:\n{}\nstderr:\n{}",
        clean_check.stdout, clean_check.stderr
    );
    let clean_frame: serde_json::Value = serde_json::from_str(clean_check.stdout.trim())
        .unwrap_or_else(|error| {
            panic!(
                "`sure check --format json` is not one frame: {error}\n{}",
                clean_check.stdout
            )
        });
    let clean_digest = clean_frame["details"]["recorded_goal"]["project_state"]["digest"].clone();
    assert!(
        clean_digest.is_string(),
        "the run reported no project state, so the digest comparison below would be between two \
         absences:\n{clean_frame}"
    );

    a_hand_written_cache_directory(&project);
    let written = bytes_under(&project.join(".sure"));
    assert_eq!(
        written.len(),
        2,
        "the poisoning wrote something other than the two files this test names: {written:?}"
    );

    let poisoned_hook = ingest_payload(
        &store,
        &shell_request(&project, "p13t009-cache", "rm -rf build/"),
        true,
    );
    let poisoned_check = run_in_a_store(
        &store,
        &[
            "--format",
            "json",
            "check",
            "--goal",
            goal,
            project.to_str().expect("a path"),
        ],
    );

    // The decision. A `failed` frame carries no `decision` at all, and two of
    // those would compare equal while saying nothing about the poisoning.
    let clean_decision = hook_frame(&clean_hook);
    let poisoned_decision = hook_frame(&poisoned_hook);
    assert_eq!(
        clean_hook.status, 1,
        "a shell request was not held before the poisoning, so the comparison below is about two \
         frames that agree for a reason of their own:\n{}",
        clean_hook.stdout
    );
    assert_eq!(
        clean_decision["decision"].as_str(),
        Some("block"),
        "the decision compared below is not a decision SURE reached: {clean_decision}"
    );
    assert_eq!(
        clean_hook.status, poisoned_hook.status,
        "{}",
        poisoned_hook.stdout
    );
    for field in ["outcome", "command", "decision", "reason", "exit_code"] {
        assert_eq!(
            clean_decision[field], poisoned_decision[field],
            "a `.sure` the project wrote moved the {field} of the decision a harness was given:\n\
             before: {clean_decision}\nafter: {poisoned_decision}"
        );
    }

    // The verdict and the state it was reached against.
    assert_eq!(
        poisoned_check.status, clean_check.status,
        "a `.sure` the project wrote changed the status of a check:\n{}",
        poisoned_check.stderr
    );
    let poisoned_frame: serde_json::Value = serde_json::from_str(poisoned_check.stdout.trim())
        .unwrap_or_else(|error| {
            panic!(
                "`sure check --format json` is not one frame: {error}\n{}",
                poisoned_check.stdout
            )
        });
    let clean_details = &clean_frame["details"];
    let poisoned_details = &poisoned_frame["details"];
    for field in ["state", "green", "stopped_at", "mode"] {
        assert_eq!(
            clean_details[field], poisoned_details[field],
            "a `.sure` the project wrote moved the {field} of a check:\n{clean_details}\n\
             {poisoned_details}"
        );
    }
    assert!(
        clean_details["report"].is_object(),
        "the check produced no verdict to compare, so the equality above is about two runs that \
         stopped:\n{clean_frame}"
    );
    for field in ["aggregate", "totals", "not_checked"] {
        assert_eq!(
            clean_details["report"][field], poisoned_details["report"][field],
            "a `.sure` the project wrote changed the {field} of the verdict:\n{clean_details}\
             \n{poisoned_details}"
        );
    }

    // Findings are compared on everything except their own id.
    //
    // An id is the one part of a finding this design says is different between two
    // runs over the same bytes: `recheck_lifecycle::FindingKey`'s header states it
    // ("Finding IDs are minted per run, so the same issue in two runs would look
    // like two different findings") and that module's key exists because of it, so
    // a comparison that included the id would be asserting something the design
    // denies. Every other field — title, severity, status, `what`, `impact`,
    // `next_action` and the anchors — is still compared, and a run whose *verdict*
    // moved still fails here.
    //
    // The non-emptiness guard is not decoration. Until findings could be produced
    // at all, both sides of this comparison were `[]` and it passed without being
    // able to fail — the defect the guard names. It stays so that a project which
    // stops producing a finding reddens here with the reason, rather than quietly
    // turning the assertion below back into a comparison of two empty lists.
    let stripped = |details: &serde_json::Value| {
        let mut findings = details["report"]["findings"].clone();
        if let Some(rows) = findings.as_array_mut() {
            for row in rows {
                if let Some(object) = row.as_object_mut() {
                    object.remove("id");
                }
            }
        }
        findings
    };
    let clean_findings = stripped(clean_details);
    assert!(
        clean_findings
            .as_array()
            .is_some_and(|rows| !rows.is_empty()),
        "the check produced no finding at all, so the comparison below would be between two \
         empty lists and would pass whatever a project's `.sure` did:\n{clean_details}"
    );
    assert_eq!(
        clean_findings,
        stripped(poisoned_details),
        "a `.sure` the project wrote changed the findings of the verdict:\n{clean_details}\
         \n{poisoned_details}"
    );
    assert_eq!(
        poisoned_details["recorded_goal"]["project_state"]["digest"], clean_digest,
        "a `.sure` the project wrote moved the project state a goal is recorded against, so the \
         next run would be checking a different state than the one the user's goal was about"
    );

    // The control, and it is the whole reason the digest equality above means
    // anything: a digest that never moved would satisfy it. One source file the
    // fingerprint does *not* have a rule for, and the same run reports a
    // different state.
    std::fs::write(
        project.join("src.rs"),
        "pub fn add(a: u32, b: u32) -> u32 { a + b }\n",
    )
    .expect("a source file this test wrote");
    let controlled = run_in_a_store(
        &store,
        &[
            "--format",
            "json",
            "check",
            "--goal",
            goal,
            project.to_str().expect("a path"),
        ],
    );
    let controlled_frame: serde_json::Value = serde_json::from_str(controlled.stdout.trim())
        .unwrap_or_else(|error| {
            panic!(
                "`sure check --format json` is not one frame: {error}\n{}",
                controlled.stdout
            )
        });
    assert_ne!(
        controlled_frame["details"]["recorded_goal"]["project_state"]["digest"], clean_digest,
        "a source file added to the project left the recorded state where it was, so this test's \
         digest comparisons are about a value that does not track the project"
    );

    // Nothing read it and nothing wrote it: the files are the bytes this test
    // left, after two hook runs and three checks.
    assert_eq!(
        bytes_under(&project.join(".sure")),
        written,
        "a run wrote into the project's cache directory, which this build has no writer for"
    );
    assert_untouched(&machine, "by runs over a project with a hand-written .sure");
}

// --- the source scan ----------------------------------------------------

/// Every `.rs` file under a directory, with the text it holds.
///
/// A panic rather than a silent empty list when a directory cannot be read: a
/// scan over no files passes every assertion below, and a scan that proves
/// nothing while reporting success is the failure this repository is about.
fn rust_sources_under(directory: &Path) -> Vec<(PathBuf, String)> {
    fn walk(directory: &Path, into: &mut Vec<(PathBuf, String)>) {
        let entries = std::fs::read_dir(directory)
            .unwrap_or_else(|error| panic!("{}: {error}", directory.display()));
        for entry in entries {
            let path = entry.expect("a directory entry").path();
            if path.is_dir() {
                walk(&path, into);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                let text = std::fs::read_to_string(&path)
                    .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
                into.push((path, text));
            }
        }
    }
    let mut found = Vec::new();
    walk(directory, &mut found);
    assert!(
        !found.is_empty(),
        "{} holds no Rust sources, so a scan over it would prove nothing",
        directory.display()
    );
    found
}

/// This crate's own sources, with the path they came from.
fn sources() -> Vec<(PathBuf, String)> {
    rust_sources_under(&PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src"))
}

/// The same, for the shipped code of every crate in the workspace.
///
/// `src` only, and not the test trees: a test may legitimately ask the platform
/// where SURE keeps its files in order to compare it with a location it made up,
/// while the code that *decides* where a run's store goes may not.
fn every_crates_sources() -> Vec<(PathBuf, String)> {
    let crates = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..");
    let entries =
        std::fs::read_dir(&crates).unwrap_or_else(|error| panic!("{}: {error}", crates.display()));
    let mut found = Vec::new();
    for entry in entries {
        let directory = entry.expect("a directory entry").path().join("src");
        if directory.is_dir() {
            found.extend(rust_sources_under(&directory));
        }
    }
    assert!(found.len() > 1, "the workspace has more than one crate");
    found
}

#[test]
fn only_the_output_module_writes_to_a_stream() {
    // "Human and machine-readable output are separated" is satisfied by there
    // being no third way out. A `println!` anywhere else is the one thing that
    // can break that: it is invisible until somebody pipes the output into a
    // JSON reader, and by then it is in a release.
    //
    // A source scan rather than a test of behaviour, because what is being
    // ruled out is an *absence*, and no run of this binary can demonstrate that
    // a line of code was never written. The tokens are written with the call's
    // syntax so that prose about them does not match.
    const ALLOWED: &str = "output.rs";
    const WRITES: &[&str] = &[
        "println!(",
        "print!(",
        "eprintln!(",
        "eprint!(",
        "io::stdout()",
        "io::stderr()",
    ];

    for (path, text) in sources() {
        if path.file_name().is_some_and(|name| name == ALLOWED) {
            continue;
        }
        for token in WRITES {
            assert!(
                !text.contains(token),
                "{} writes to a stream with `{token}`. Output goes through \
                 src/output.rs, which is what keeps the two paths apart.",
                path.display()
            );
        }
    }
}

#[test]
fn nothing_a_project_can_write_decides_where_the_store_goes() {
    // Acceptance 1's first half, as the absence it is. The store's location is
    // a value in the process's own argument vector (`--store-dir`) and there is
    // no second way in: not a file, and not an environment variable.
    //
    // A source scan, for the reason the test above is one — what is being ruled
    // out is a line of code, and no run can show that a line was never written.
    // The environment is the shape worth naming, because it is the tempting one:
    // a test harness sets the environment of the processes it starts, and so
    // does a checked project's own harness configuration (Claude Code's
    // `.claude/settings.json` has an `env` block, for one), so `SURE_STORE_DIR`
    // would be a store that a checked project can point at any directory it
    // likes. That is the defect acceptance 1 names, and the reason the module
    // documentation says there is deliberately no variable.
    //
    // Only the modules that decide the location are scanned. `SURE_OPENAI_API_KEY`
    // is read by the analysis provider and `PATH` by the tool search; neither is
    // a path SURE keeps anything in, and a scan over the whole workspace would
    // have to allow them and would then allow the thing it exists to catch.
    //
    // P15-T025 added a second nameable location — `--settings-file`, the
    // user-level settings file a run reads — so the list grew by the modules
    // that decide *it*: `check.rs` and `hook.rs` resolve both locations through
    // `Paths::discover_with` and refuse a settings file the project could have
    // written, and `mcp.rs` refuses the flag outright. None of them reads the
    // environment either, and this is what keeps that true: a variable would be
    // a way in for exactly the project the refusal exists to stop, and its name
    // would not have to be the one a behavioural test happens to try.
    const DECIDES_THE_LOCATION: &[&str] = &[
        "crates/sure-core/src/paths/mod.rs",
        "crates/sure-cli/src/cli.rs",
        "crates/sure-cli/src/main.rs",
        "crates/sure-cli/src/commands.rs",
        "crates/sure-cli/src/check.rs",
        "crates/sure-cli/src/hook.rs",
        "crates/sure-cli/src/mcp.rs",
    ];
    const READS_THE_ENVIRONMENT: &[&str] = &["env::var", "env::vars", "var_os", "vars_os"];

    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..");
    for relative in DECIDES_THE_LOCATION {
        let path = workspace.join(relative);
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
        for token in READS_THE_ENVIRONMENT {
            assert!(
                !text.contains(token),
                "{} reads the environment with `{token}`. A location that a variable can set is a \
                 location the harness configuration of a checked project can set, which is a \
                 location the judged thing chooses — and the two locations this module list \
                 decides are the store's (`--store-dir`) and the user-level settings file's \
                 (`--settings-file`). For the store that is a store the project writes the \
                 history from; for the settings file it is a file the project writes SURE's \
                 authority from, which is worse. Neither is named by anything but its flag.",
                path.display()
            );
        }
    }
}

#[test]
fn every_command_is_reached_by_the_location_the_caller_named() {
    // The other half of acceptance 1, and the half that is easy to lose: a
    // command that discovered the platform's location for itself would be a
    // command `--store-dir` cannot reach — `hook ingest` writing to a different
    // store than the verdict reads, which is worse than no mechanism at all.
    //
    // The no-argument `Paths::discover()` is that shape, because it is
    // `discover_at(None)`: it answers "the platform's own location" with nothing
    // able to say otherwise. It is allowed in exactly one file, the one that
    // defines it, and nowhere else in the workspace's shipped code. The scan is
    // over every crate's `src`, so a new crate cannot arrive with a second one.
    const DEFINES_IT: &[&str] = &["sure-core", "src", "paths", "mod.rs"];
    let mut defines_it = PathBuf::new();
    for part in DEFINES_IT {
        defines_it.push(part);
    }

    for (path, text) in every_crates_sources() {
        if path.ends_with(&defines_it) {
            continue;
        }
        assert!(
            !text.contains("Paths::discover()"),
            "{} discovers the platform's own store location for itself. Every command is handed \
             the location the caller named — `Command::report`'s argument, from `--store-dir` — \
             and a command that looked it up instead would keep its evidence somewhere the \
             verdict does not read. Call `Paths::discover_at(store)` with the location you were \
             given.",
            path.display()
        );
    }
}
