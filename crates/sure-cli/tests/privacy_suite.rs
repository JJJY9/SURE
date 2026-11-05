//! The privacy and security integration suite: `fixtures/privacy/manifest.json`.
//!
//! # Why this file exists
//!
//! P13-T008's acceptance is two lines — *full recording off by default* and
//! *mandatory secret/protection fixtures pass* — and neither is a claim about a
//! function. The first is a claim about what is on disk after a real `sure`
//! process has run, and the second is a claim that a *set* of fixtures exists,
//! is enumerable, and passes. So this file is a runner rather than a test of its
//! own: it reads the corpus, and every case in it either drives the real binary
//! or points at the test that already drives the same behaviour somewhere this
//! file cannot reach.
//!
//! # What "mandatory" means here, and what binds it
//!
//! Three documents already said a mandatory fixture set exists and blocks
//! release — `docs/testing/ADVERSARIAL_FIXTURES.md`, `docs/product/DEFINITION_OF_DONE.md`
//! and `docs/product/PRODUCT_EVALS.md` — and until this corpus existed, nothing
//! in `crates/` bound the word to anything. The binding is
//! [`every_case_binds_a_sentence_a_document_still_makes`]: each case names a
//! document and a sentence in it, and the suite fails if the sentence is gone.
//! A promise that is withdrawn takes its fixture with it, rather than leaving a
//! fixture nobody promised and a promise nobody tests.
//!
//! # What this file does not re-prove
//!
//! A behaviour already proved at the layer this file would prove it at is not
//! written again here. It is written as a `covered_by` entry: a pointer at the
//! file and the tests in it, checked to exist by
//! [`every_pointer_names_a_test_that_exists`], so the corpus is a complete
//! inventory of the acceptance rather than a second copy of the test suite.
//!
//! # What it cannot reach, and says so
//!
//! It is recorded in the manifest's `not_confirmed` and printed by
//! [`the_corpus_prints_what_it_could_not_confirm`]. One entry stands there, the
//! seam with P14-T008's three dangerous-action scenarios.
//!
//! # The `--goal` case asserts both halves now
//!
//! It used to be the example here of a thing this file could not reach, and it
//! is worth keeping the shape of that in view. `sure check --goal` printed the
//! words that were typed under a sentence about the record, while the record
//! held the redacted form; the case
//! `a-secret-typed-into-a-goal-reaches-the-store-only-redacted` asserted the
//! store half and the report half was recorded as unsettled. `P15-T024` decided
//! which rule wins — the store's redaction, with the goal not exempt from it —
//! and `check.rs`'s `record_goal` now reads the row back and hands that text to
//! every surface. So the case asserts the report too: no byte under the store
//! directory holds the credential, the redacted text does, the report shows that
//! same text, and the credential is in neither stream. The manifest entry and
//! this paragraph went with the gap.
//!
//! # The settings file a case supplies, and the one it must not
//!
//! A case may carry a `settings` block: a file this suite writes under the
//! case's own scratch directory, named on the run's command line with
//! `--settings-file`. That is the surface the user's own settings file is
//! reached by, and it exists because the alternative is a suite that cannot
//! observe consent at all — see `docs/architecture/CLI.md`, which says what the
//! flag is for and what it may grant.
//!
//! **It is a testing and automation surface and it is not a way to escalate.** A
//! settings file inside the project the run is told about is refused before it
//! is read, whoever named it: the file that says what SURE may do is the user's
//! own word, and the project being judged is the one thing that must not be able
//! to write it. The case `a-settings-file-the-project-could-write-grants-nothing`
//! attempts exactly that and asserts the refusal. The machine's own settings file
//! is never written, named, or read for a decision by anything in this file: what
//! the default would be is observed by
//! [`no_settings_file_at_all_is_the_premise_the_binary_cases_run_under`], which
//! is about the real path, and every case that supplies a settings file says so
//! in its own `settings` block.
//!
//! # Where these runs keep their evidence
//!
//! Every process this file starts names a store with `--store-dir`, in a scratch
//! directory under `target/tmp/privacy suite` that is removed when the test that
//! made it ends. The store of the person running the suite is read before and
//! after each case and compared, because "the run went somewhere else" is the
//! property that keeps this suite from editing somebody's history.

// The workspace forbids `unwrap`, `expect` and `panic` in shipped code, because
// a panic is a message nobody chose. A test is the one place they are the point:
// the panic *is* the report, and it names the value that was wrong.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};

use serde_json::{Map, Value, json};

use sure_core::paths::Paths;
use sure_core::store::{HistoryFilter, RecordKind, Store};

/// The binary this package builds, as cargo hands it to its integration tests.
const SURE: &str = env!("CARGO_BIN_EXE_sure");

/// The kind of a corpus entry that points at a test somewhere else.
const KIND_COVERED_BY: &str = "covered_by";

/// The kinds this file knows how to drive.
const DRIVEN_KINDS: &[&str] = &["hook_ingest", "check"];

/// What one entry in the corpus must carry, by name.
///
/// Checked rather than assumed: the point of the corpus is that a reader can
/// enumerate it, and an entry whose expectation is missing is an entry that
/// passes by having nothing to fail.
const EXPECTED_FIELDS: &[&str] = &["id", "kind", "layer", "title", "why"];

// --- the corpus ---------------------------------------------------------

/// The corpus document, read from `fixtures/privacy/manifest.json`.
fn manifest() -> Value {
    let path = corpus_file();
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
    serde_json::from_str(&text)
        .unwrap_or_else(|error| panic!("{} is not valid JSON: {error}", path.display()))
}

fn corpus_file() -> PathBuf {
    sure_testkit::repository_root()
        .join("fixtures")
        .join("privacy")
        .join("manifest.json")
}

fn cases() -> Vec<Value> {
    manifest()["cases"]
        .as_array()
        .expect("the corpus lists cases")
        .clone()
}

fn case_text(case: &Value, field: &str) -> String {
    case[field]
        .as_str()
        .unwrap_or_else(|| panic!("{} has no {field}", case_id(case)))
        .to_owned()
}

fn case_id(case: &Value) -> &str {
    case["id"].as_str().unwrap_or("<a case with no id>")
}

/// The strings an expectation names, or an empty list.
fn strings(case: &Value, section: &str, field: &str) -> Vec<String> {
    case[section][field]
        .as_array()
        .map(|items| {
            items
                .iter()
                .map(|item| {
                    item.as_str()
                        .unwrap_or_else(|| {
                            panic!(
                                "{}: {section}.{field} must be a list of strings",
                                case_id(case)
                            )
                        })
                        .to_owned()
                })
                .collect()
        })
        .unwrap_or_default()
}

/// A number an expectation names, if it names one.
fn number(case: &Value, section: &str, field: &str) -> Option<i64> {
    case[section][field].as_i64()
}

/// Whether a document still makes a sentence, allowing for how it is wrapped.
///
/// The sentence has to be there word for word, and the whitespace does not: a
/// document is prose that gets reflowed, and a binding that broke every time an
/// editor rewrapped a paragraph would be a binding somebody deletes. Every other
/// difference — a word changed, a clause dropped — is still a failure.
fn still_says(text: &str, sentence: &str) -> bool {
    fn flow(text: &str) -> String {
        text.split_whitespace().collect::<Vec<_>>().join(" ")
    }
    flow(text).contains(&flow(sentence))
}

/// The documents a case binds itself to, and the sentence in each.
fn promised_by(case: &Value) -> Vec<(String, String)> {
    case["promised_by"]
        .as_array()
        .expect("a case names the documents that promise it")
        .iter()
        .map(|promise| {
            (
                promise["doc"].as_str().expect("a doc path").to_owned(),
                promise["says"].as_str().expect("a sentence").to_owned(),
            )
        })
        .collect()
}

// --- scratch directories ------------------------------------------------

/// A directory this test owns, under the workspace's git-ignored `target/tmp`.
///
/// Removed when it goes out of scope, which the process does on unwind as well
/// as on return: this suite runs several cases in one process, and a directory
/// per case that was never removed would fill the workspace's scratch space with
/// the evidence of every run that has ever happened. The root carries the process
/// id so that two test binaries cannot collide on a name, and the leaf carries a
/// counter so that two tests in one process cannot.
struct Scratch {
    root: PathBuf,
    path: PathBuf,
}

impl Scratch {
    fn new(what: &str) -> Self {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let root = sure_testkit::repository_root()
            .join("target")
            .join("tmp")
            .join("privacy suite")
            .join(format!("run-{}", std::process::id()));
        let path = root.join(format!("{}-{what}", NEXT.fetch_add(1, Ordering::Relaxed)));
        std::fs::create_dir_all(&path)
            .unwrap_or_else(|error| panic!("cannot create {}: {error}", path.display()));
        Self { root, path }
    }

    /// The project the run is about. Not the store's directory, and not the
    /// repository: a store inside the project it is about is refused by
    /// `Paths::ensure_outside`, and a project that was this repository would be
    /// one whose own files decide the answer.
    fn project(&self) -> PathBuf {
        let project = self.path.join("project");
        std::fs::create_dir_all(&project)
            .unwrap_or_else(|error| panic!("cannot create {}: {error}", project.display()));
        project
    }

    /// The store the run writes, named on the command line and nowhere else.
    fn store(&self) -> PathBuf {
        let store = self.path.join("store");
        std::fs::create_dir_all(&store)
            .unwrap_or_else(|error| panic!("cannot create {}: {error}", store.display()));
        store
    }

    /// A `--settings-file` path with nothing at it.
    ///
    /// A named file that does not exist is [`ConfigSource::NoFile`] — SURE's
    /// own answer for a user who has no settings file — so the default cases
    /// read no user-level settings while the machine's real file is left alone.
    /// The platform config directory cannot be moved by an environment variable,
    /// and a suite that needed the developer's profile to be empty would be a
    /// suite about the developer. The path is under the case's scratch
    /// directory, outside the project.
    ///
    /// [`ConfigSource::NoFile`]: sure_core::config::ConfigSource::NoFile
    fn absent_settings(&self) -> PathBuf {
        self.path.join("no-user-settings.yaml")
    }

    /// A settings file this case supplies, written where the case says.
    ///
    /// The path is the case's own `settings.file`, resolved inside the case's
    /// scratch directory and never against the repository or the user's
    /// profile. A case that names `project/sure.yaml` is deliberately writing it
    /// *inside* the project — that is the escalation one of them attempts, and
    /// the point of that case is that the run refuses the file rather than
    /// reading it. Every other case writes outside the project, because a
    /// refused settings file would make its expectations about a recording
    /// meaningless.
    fn settings(&self, named: &str) -> PathBuf {
        let file = self.path.join(named);
        if let Some(parent) = file.parent() {
            std::fs::create_dir_all(parent)
                .unwrap_or_else(|error| panic!("cannot create {}: {error}", parent.display()));
        }
        file
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
        // The run's own root, if this was the last test in it. `remove_dir`
        // fails on a directory that still has anything in it, which is exactly
        // the case where another test in this process is still using it, so a
        // failure here is not reported: it means somebody else is not finished.
        let _ = std::fs::remove_dir(&self.root);
    }
}

// --- running the binary -------------------------------------------------

/// What one run of the binary did.
struct Run {
    status: i32,
    stdout: String,
    stderr: String,
}

impl Run {
    fn of(output: &Output) -> Self {
        Self {
            status: output.status.code().expect("the process exited on its own"),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        }
    }

    /// Both streams as one text, for the "this must appear nowhere" checks: a
    /// secret that reached the other stream is a secret that reached a report,
    /// and which one it went to is not the question being asked.
    fn everything_it_said(&self) -> String {
        format!("{}\n{}", self.stdout, self.stderr)
    }
}

/// One run, in a store of the caller's own, with an optional event on stdin.
fn run_sure(store: &Path, args: &[&str], stdin: Option<&str>) -> Run {
    let mut command = Command::new(SURE);
    command.arg("--store-dir").arg(store).args(args);
    match stdin {
        None => {
            command.stdin(Stdio::null());
            Run::of(
                &command
                    .output()
                    .unwrap_or_else(|error| panic!("could not run {SURE}: {error}")),
            )
        }
        Some(text) => {
            let mut child = command
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap_or_else(|error| panic!("could not run {SURE}: {error}"));
            let mut pipe = child.stdin.take().expect("the pipe this test asked for");
            pipe.write_all(text.as_bytes()).expect("write to stdin");
            drop(pipe);
            Run::of(&child.wait_with_output().expect("the child exits"))
        }
    }
}

/// The one JSON frame a `--format json` run answered with.
fn frame(run: &Run, what: &str) -> Value {
    serde_json::from_str(run.stdout.trim()).unwrap_or_else(|error| {
        panic!(
            "{what}: the run did not answer with one JSON frame: {error}\nstdout:\n{}\nstderr:\n{}",
            run.stdout, run.stderr
        )
    })
}

// --- the store, as bytes and as rows ------------------------------------

/// Every file under a directory, with its bytes.
fn files_under(directory: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut found = Vec::new();
    let Ok(entries) = std::fs::read_dir(directory) else {
        return found;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            found.extend(files_under(&path));
        } else if path.is_file() {
            let bytes = std::fs::read(&path)
                .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
            found.push((path, bytes));
        }
    }
    found.sort_by(|a, b| a.0.cmp(&b.0));
    found
}

/// The store directory as one text per file, for a substring search over every
/// byte.
///
/// A lossy decode rather than a database read, because the claim is about the
/// *file*: a value a reader would never be handed back can still be sitting in a
/// page, and a test that asked the store for a row would not see it.
fn store_as_bytes(store_dir: &Path) -> Vec<(PathBuf, String)> {
    files_under(store_dir)
        .into_iter()
        .map(|(path, bytes)| (path, String::from_utf8_lossy(&bytes).into_owned()))
        .collect()
}

fn open_store(store_dir: &Path) -> Store {
    let file = store_dir.join("sure.db");
    Store::open_at(&file).unwrap_or_else(|error| panic!("cannot open {}: {error}", file.display()))
}

/// Every row in the store, recordings included.
fn all_rows(store: &Store) -> Vec<sure_core::store::StoredRecord> {
    store
        .history(
            &HistoryFilter {
                include_recordings: true,
                ..HistoryFilter::default()
            },
            1_000,
        )
        .expect("a store this suite's own process wrote")
}

/// How many rows of one kind a store holds.
///
/// Counted by the kind's stable name rather than by matching on the enum, so
/// that a `Document` is counted as the document it is: `RecordKind::as_str` is
/// the value the `kind` column holds, and it is what a reader of the file would
/// see.
fn rows_named(store: &Store, name: &str) -> usize {
    all_rows(store)
        .iter()
        .filter(|row| row.kind.as_str() == name)
        .count()
}

// --- the store of the person running the suite --------------------------

/// The store a command that named nothing would read and write.
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
/// first, and this is the assertion that catches the inside of one binary —
/// which is what this suite's cases most need, since the case that proves a
/// recording is not written is exactly the case whose bug would be writing
/// somebody's store.
fn assert_untouched(before: &MachineStore, case: &Value) {
    let now = the_store_on_this_machine();
    assert_eq!(
        now.path,
        before.path,
        "{}: the store SURE uses moved, from {} to {}",
        case_id(case),
        before.path.display(),
        now.path.display()
    );
    match (&before.bytes, &now.bytes) {
        (None, None) => {}
        (Some(was), Some(is)) => assert!(
            was == is,
            "{}: {} was {} bytes before this case and is {} bytes now, so a run in this case wrote \
             the store of the person running the suite instead of the store the case named",
            case_id(case),
            before.path.display(),
            was.len(),
            is.len()
        ),
        (None, Some(_)) => panic!(
            "{}: {} did not exist before this case and exists now, so a run in it created the \
             store of the person running the suite",
            case_id(case),
            before.path.display()
        ),
        (Some(was), None) => panic!(
            "{}: {} was {} bytes before this case and is gone now, so something this case ran \
             removed the store of the person running the suite",
            case_id(case),
            before.path.display(),
            was.len()
        ),
    }
}

// --- driving one case ---------------------------------------------------

/// Run one case and return every way it failed, by name.
///
/// Failures are collected rather than asserted, so that one run reports all of
/// what is wrong with a corpus rather than the first thing: a suite whose output
/// is a single panic teaches its reader one fact per run.
fn check_case(case: &Value) -> Vec<String> {
    match case["kind"].as_str().unwrap_or_default() {
        "hook_ingest" => hook_ingest_case(case),
        "check" => check_command_case(case),
        KIND_COVERED_BY => Vec::new(),
        other => vec![format!("{}: unknown kind {other:?}", case_id(case))],
    }
}

/// The project a case asks for, written into the scratch directory.
fn materialize(case: &Value, project: &Path) {
    let files = case["project"]["files"]
        .as_object()
        .unwrap_or_else(|| panic!("{} has no project.files", case_id(case)));
    for (name, contents) in files {
        let text = contents
            .as_str()
            .unwrap_or_else(|| panic!("{}: {name} is not text", case_id(case)));
        std::fs::write(project.join(name), text)
            .unwrap_or_else(|error| panic!("cannot write {name} into the project: {error}"));
    }
}

/// The event a harness would send, built here rather than written out in the
/// manifest as text.
///
/// One field is the project path, and it is this machine's path: a fixture that
/// hard-coded one would be a fixture about a project that exists on the machine
/// that wrote it and nowhere else.
fn event_for(case: &Value, project: &Path) -> String {
    let ingests = &case["ingest"];
    let mut event = Map::new();
    event.insert(
        "source".to_owned(),
        json!(
            ingests["harness"]
                .as_str()
                .unwrap_or_else(|| panic!("{} has no ingest.harness", case_id(case)))
        ),
    );
    event.insert(
        "harness_session_id".to_owned(),
        json!(
            ingests["harness_session_id"]
                .as_str()
                .unwrap_or_else(|| panic!("{} has no harness_session_id", case_id(case)))
        ),
    );
    event.insert("project_root".to_owned(), json!(project.to_string_lossy()));
    for (key, value) in ingests["event"]
        .as_object()
        .unwrap_or_else(|| panic!("{} has no ingest.event", case_id(case)))
    {
        event.insert(key.clone(), value.clone());
    }
    Value::Object(event).to_string()
}

/// A hint is built once and used by both cases, so that a field renamed in one
/// place and not the other is a compile error rather than a quiet difference.
fn strings_from(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

/// The settings file a case supplies, written under its own scratch directory,
/// or the case's absent path when it supplies none.
///
/// A case with no `settings` block is a default case: it is about a machine
/// with no settings file of any kind. Naming a file that does not exist gives
/// the run exactly that answer (`ConfigSource::NoFile`) on every machine,
/// including one whose owner has a real file; without it the cases would be
/// measuring the developer's profile. A case that supplies a file gets *that*
/// file and says so in its own manifest entry, so the two kinds of case cannot
/// be confused for each other by a reader or by this file.
///
/// The path goes into the argument vector beside `--store-dir`, and nothing here
/// sets an environment variable: the flag is the whole of the surface, which is
/// what makes it a value a harness configuration cannot *set* — only put in a
/// command line, where the inside-project refusal then judges it.
fn settings_file_for(case: &Value, scratch: &Scratch) -> PathBuf {
    let Some(settings) = case["settings"].as_object() else {
        return scratch.absent_settings();
    };
    let named = settings["file"]
        .as_str()
        .unwrap_or_else(|| panic!("{}: settings.file is not a path", case_id(case)));
    let yaml = settings["yaml"]
        .as_str()
        .unwrap_or_else(|| panic!("{}: settings.yaml is not text", case_id(case)));
    let file = scratch.settings(named);
    std::fs::write(&file, yaml)
        .unwrap_or_else(|error| panic!("cannot write {}: {error}", file.display()));
    file
}

fn hook_ingest_case(case: &Value) -> Vec<String> {
    let mut failures = Vec::new();
    let scratch = Scratch::new(case_id(case));
    let project = scratch.project();
    materialize(case, &project);
    let store_dir = scratch.store();
    let machine = the_store_on_this_machine();
    let settings = settings_file_for(case, &scratch);

    // The global flags and the verb first, then whatever the manifest names:
    // this is the order a harness launcher uses and the order the contract tests
    // the command line in.
    let mut args = Vec::new();
    args.push("--settings-file".to_owned());
    args.push(settings.to_string_lossy().into_owned());
    args.extend(strings_from(&["--format", "json", "hook", "ingest"]));
    for argument in case["ingest"]["argv"]
        .as_array()
        .unwrap_or_else(|| panic!("{} has no ingest.argv", case_id(case)))
    {
        args.push(argument.as_str().expect("an argument").to_owned());
    }
    let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
    let run = run_sure(&store_dir, &borrowed, Some(&event_for(case, &project)));

    if let Some(expected) = number(case, "expect", "status")
        && i64::from(run.status) != expected
    {
        failures.push(format!(
            "{}: the process exited {} rather than {expected}. stdout:\n{}\nstderr:\n{}",
            case_id(case),
            run.status,
            run.stdout,
            run.stderr
        ));
    }

    for wanted in strings(case, "expect", "stderr_contains") {
        if !run.stderr.contains(&wanted) {
            failures.push(format!(
                "{}: stderr does not contain {wanted:?}:\n{}",
                case_id(case),
                run.stderr
            ));
        }
    }

    let answer = frame(&run, case_id(case));
    if let Some(expected) = case["expect"]["decision"].as_str()
        && answer["decision"].as_str() != Some(expected)
    {
        failures.push(format!(
            "{}: the answer was {} rather than {expected}: {answer}",
            case_id(case),
            answer["decision"]
        ));
    }
    for wanted in strings(case, "expect", "reason_contains") {
        let reason = answer["reason"].as_str().unwrap_or_default();
        if !reason.contains(&wanted) {
            failures.push(format!(
                "{}: the reason does not contain {wanted:?}: {reason}",
                case_id(case)
            ));
        }
    }
    // Sentences the whole frame has to carry. A run that refuses answers with
    // `--format json` on stdout and nothing on stderr — the human form is what
    // goes to the error stream, and this suite never asks for it — so a case
    // that has to read the refusal's own words reads them here, from the same
    // frame a harness would.
    for wanted in strings(case, "expect", "frame_contains") {
        if !answer.to_string().contains(&wanted) {
            failures.push(format!(
                "{}: the frame does not contain {wanted:?}: {answer}",
                case_id(case)
            ));
        }
    }

    let exists = store_dir.join("sure.db").is_file();
    if let Some(expected) = case["expect"]["store_exists"].as_bool()
        && exists != expected
    {
        failures.push(format!(
            "{}: the store {} exist after the run, and this case says it {}",
            case_id(case),
            if exists { "does" } else { "does not" },
            if expected { "should" } else { "should not" }
        ));
    }

    if exists {
        let store = open_store(&store_dir);
        if let Some(least) = number(case, "expect", "event_rows_at_least") {
            let events = rows_named(&store, "event");
            if (events as i64) < least {
                failures.push(format!(
                    "{}: the store holds {events} event rows, fewer than the {least} this case \
                     needs before an assertion about what else is missing means anything",
                    case_id(case)
                ));
            }
        }
        if let Some(exact) = number(case, "expect", "decision_rows") {
            let decisions = rows_named(&store, "decision");
            if decisions as i64 != exact {
                failures.push(format!(
                    "{}: the store holds {decisions} decision rows rather than {exact}",
                    case_id(case)
                ));
            }
        }
        if let Some(exact) = number(case, "expect", "recordings") {
            let recordings = rows_named(&store, RecordKind::Recording.as_str());
            if recordings as i64 != exact {
                failures.push(format!(
                    "{}: the store holds {recordings} full recordings rather than {exact}",
                    case_id(case)
                ));
            }
        }
        // The redaction is asserted about the value the store hands back as well
        // as about the bytes, for a case that names a value the recording must
        // not hold: the two would diverge if a row were ever written twice, or
        // read back through a path that redacted again. Read here rather than in
        // a case of its own, because the row that has to be there is the row the
        // process just wrote.
        let forbidden = strings(case, "expect", "payload_absent");
        if !forbidden.is_empty() {
            match all_rows(&store)
                .into_iter()
                .find(|row| row.kind == RecordKind::Recording)
            {
                Some(row) => {
                    let shown = row.document.to_string();
                    for wanted in &forbidden {
                        if shown.contains(wanted) {
                            failures.push(format!(
                                "{}: the recording the store handed back holds {wanted:?}, and \
                                 this case says no recording holds it",
                                case_id(case)
                            ));
                        }
                    }
                }
                None => failures.push(format!(
                    "{}: the store has no recording row to read back, so the values this case says \
                     a recording must not hold were never at risk",
                    case_id(case)
                )),
            }
        }
        drop(store);
    } else if number(case, "expect", "event_rows_at_least").unwrap_or(0) > 0 {
        failures.push(format!(
            "{}: the run wrote no store at all, so an assertion about what is not in one would \
             pass for the wrong reason",
            case_id(case)
        ));
    }

    failures.extend(bytes_failures(case, &store_dir));
    assert_untouched(&machine, case);
    failures
}

fn check_command_case(case: &Value) -> Vec<String> {
    let mut failures = Vec::new();
    let scratch = Scratch::new(case_id(case));
    let project = scratch.project();
    materialize(case, &project);
    let store_dir = scratch.store();
    let machine = the_store_on_this_machine();

    // An absolute path, always: a relative one is refused as unfinished before
    // any of this is about privacy, and a case that quietly became a test of
    // stage one would still be green.
    let settings = settings_file_for(case, &scratch);
    let mut args = vec![
        "--settings-file".to_owned(),
        settings.to_string_lossy().into_owned(),
        "check".to_owned(),
        project.to_string_lossy().into_owned(),
    ];
    if let Some(goal) = case["check"]["goal"].as_str() {
        args.push("--goal".to_owned());
        args.push(goal.to_owned());
    }
    let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
    let run = run_sure(&store_dir, &borrowed, None);

    if let Some(expected) = number(case, "expect", "status")
        && i64::from(run.status) != expected
    {
        failures.push(format!(
            "{}: the process exited {} rather than {expected}. stdout:\n{}\nstderr:\n{}",
            case_id(case),
            run.status,
            run.stdout,
            run.stderr
        ));
    }
    for forbidden in case["expect"]["status_not"]
        .as_array()
        .into_iter()
        .flatten()
    {
        let forbidden = forbidden.as_i64().expect("a status number");
        if i64::from(run.status) == forbidden {
            failures.push(format!(
                "{}: the process exited {forbidden}, which this case says is not the answer. \
                 stderr:\n{}",
                case_id(case),
                run.stderr
            ));
        }
    }
    for wanted in strings(case, "expect", "stderr_contains") {
        if !run.stderr.contains(&wanted) {
            failures.push(format!(
                "{}: stderr does not contain {wanted:?}:\n{}",
                case_id(case),
                run.stderr
            ));
        }
    }
    for wanted in strings(case, "expect", "stdout_contains") {
        if !run.stdout.contains(&wanted) {
            failures.push(format!(
                "{}: stdout does not contain {wanted:?}:\n{}",
                case_id(case),
                run.stdout
            ));
        }
    }
    for forbidden in strings(case, "expect", "output_absent") {
        let said = run.everything_it_said();
        if said.contains(&forbidden) {
            failures.push(format!(
                "{}: the run printed {forbidden:?}, which is a value from the project's own \
                 settings file:\n{}\n{}",
                case_id(case),
                run.stdout,
                run.stderr
            ));
        }
    }

    let exists = store_dir.join("sure.db").is_file();
    if let Some(expected) = case["expect"]["store_exists"].as_bool()
        && exists != expected
    {
        failures.push(format!(
            "{}: the store {} exist, and this case says it {}",
            case_id(case),
            if exists { "does" } else { "does not" },
            if expected { "should" } else { "should not" }
        ));
    }

    failures.extend(bytes_failures(case, &store_dir));
    assert_untouched(&machine, case);
    failures
}

/// What the bytes of a store directory must and must not hold.
fn bytes_failures(case: &Value, store_dir: &Path) -> Vec<String> {
    let mut failures = Vec::new();
    let files = store_as_bytes(store_dir);
    if files.is_empty() {
        // Not a failure by itself: a case that asserts nothing was written says
        // so with `store_exists: false`, and this helper is only about contents.
        return failures;
    }

    for forbidden in strings(case, "expect", "store_absent") {
        for (path, text) in &files {
            if text.contains(&forbidden) {
                failures.push(format!(
                    "{}: {} holds {forbidden:?}, which is a secret this corpus says never reaches \
                     a stored record",
                    case_id(case),
                    path.display()
                ));
            }
        }
    }

    for wanted in strings(case, "expect", "store_present") {
        let found = files.iter().any(|(_, text)| text.contains(&wanted));
        if !found {
            failures.push(format!(
                "{}: no file under {} holds {wanted:?}, so the absence this case asserts is the \
                 absence of something that was never there",
                case_id(case),
                store_dir.display()
            ));
        }
    }
    failures
}

// --- the tests ----------------------------------------------------------

#[test]
fn every_case_in_the_mandatory_corpus_passes() {
    // The list is printed rather than described, so that a reader running the
    // suite sees the same enumeration the manifest holds. `cargo test ... --
    // --nocapture` shows it on a green run.
    let cases = cases();
    println!(
        "the mandatory privacy corpus: {} entries from fixtures/privacy/manifest.json",
        cases.len()
    );
    for case in &cases {
        println!(
            "  {:<64} {:<24} {}",
            case_id(case),
            case_text(case, "kind"),
            case_text(case, "title")
        );
    }

    let mut failures: Vec<String> = Vec::new();
    for case in &cases {
        failures.extend(check_case(case));
    }
    assert!(
        failures.is_empty(),
        "{} of the {} entries in the mandatory privacy corpus failed:\n\n{}",
        failures.len(),
        cases.len(),
        failures.join("\n\n")
    );
}

#[test]
fn every_case_carries_what_the_corpus_promises_a_reader_can_find() {
    let cases = cases();
    assert!(
        !cases.is_empty(),
        "the corpus is empty, so it promises nothing"
    );

    let mut seen: Vec<String> = Vec::new();
    for case in &cases {
        let id = case_id(case).to_owned();
        for field in EXPECTED_FIELDS {
            assert!(
                case.get(*field).is_some(),
                "{id} has no {field}, so a reader cannot enumerate what it is"
            );
        }
        assert!(
            !seen.contains(&id),
            "{id} is in the corpus twice, and two entries with one id are one entry neither \
             reader can count"
        );
        seen.push(id.clone());

        assert!(
            !case_text(case, "why").trim().is_empty(),
            "{id} says nothing about why it is here"
        );
        assert!(
            case["release_blocking"].is_boolean(),
            "{id} does not say whether it blocks release"
        );
        assert!(
            case["release_blocking"] == Value::Bool(true),
            "{id} is in the mandatory corpus and does not block release: an entry whose failure \
             would not block a release belongs somewhere other than here, and a false understates \
             what a regressed test or a decayed pointer at this entry would do"
        );
        assert!(
            !promised_by(case).is_empty(),
            "{id} is bound to no document, so 'mandatory' has no referent for it"
        );

        let kind = case_text(case, "kind");
        assert!(
            DRIVEN_KINDS.contains(&kind.as_str()) || kind == KIND_COVERED_BY,
            "{id}: this suite does not know how to drive a {kind} entry, and running one as if it \
             had passed would be a false green"
        );

        // The layers, so that "what could not be observed through the binary" is
        // a value a reader can search for rather than a sentence in a comment.
        let layer = case_text(case, "layer");
        assert!(
            ["binary", "store", "test"].contains(&layer.as_str()),
            "{id}: {layer:?} is not a layer this suite knows"
        );
        // A driven entry that is not at the binary layer has to say why, and
        // what would move it there. A `covered_by` entry does not: its note is
        // the pointer, which says which test observes the behaviour and where.
        if kind != KIND_COVERED_BY && layer != "binary" {
            assert!(
                case["layer_note"].is_string(),
                "{id}: an entry this suite drives at layer {layer:?} has to say why it is not at \
                 the binary layer, and what would move it there"
            );
        }

        if kind == KIND_COVERED_BY {
            assert!(
                case["file"].is_string(),
                "{id} points at nothing in particular: a covered_by entry names the file its \
                 tests are in"
            );
            assert!(
                case["tests"]
                    .as_array()
                    .is_some_and(|tests| !tests.is_empty()),
                "{id} points at no test, so it covers nothing"
            );
        } else {
            assert!(
                case["expect"].is_object(),
                "{id} is an entry this suite drives and has no expectations, so it passes by \
                 having nothing to fail"
            );
        }
    }
}

#[test]
fn every_pointer_names_a_test_that_exists() {
    // A corpus entry that points at a test is only as good as the pointer. This
    // is what stops the list decaying into prose: delete or rename the test and
    // the corpus fails, rather than quietly naming nothing.
    let root = sure_testkit::repository_root();
    for case in &cases() {
        if case_text(case, "kind") != KIND_COVERED_BY {
            continue;
        }
        let file = case_text(case, "file");
        let path = root.join(&file);
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("{}: cannot read {file}: {error}", case_id(case)));
        for name in case["tests"].as_array().expect("the tests it points at") {
            let name = name.as_str().expect("a test name");
            assert!(
                text.contains(&format!("fn {name}(")),
                "{}: {file} has no test called {name}, so this corpus entry points at nothing \
                 that runs",
                case_id(case)
            );
        }
    }
}

#[test]
fn every_case_binds_a_sentence_a_document_still_makes() {
    // How "mandatory" acquires a referent. The word is not a property of this
    // file: it is the documents that promise the fixture, and the sentence in
    // each. When one of them stops making its promise, the entry that was
    // justified by it fails here rather than continuing to describe a
    // requirement the product no longer has.
    let root = sure_testkit::repository_root();
    for case in &cases() {
        for (doc, sentence) in promised_by(case) {
            let path = root.join(&doc);
            let text = std::fs::read_to_string(&path)
                .unwrap_or_else(|error| panic!("{}: cannot read {doc}: {error}", case_id(case)));
            assert!(
                still_says(&text, &sentence),
                "{}: {doc} no longer says {sentence:?}, so nothing in this repository promises the \
                 fixture this entry is",
                case_id(case)
            );
        }
    }
}

#[test]
fn no_settings_file_at_all_is_the_premise_the_binary_cases_run_under() {
    // The premise of the recording cases, observed rather than assumed, and
    // observed twice: the case's own settings path has no file at it, and `sure
    // doctor` — the binary's own answer about the same path — reports it absent
    // and that the store the caller named is the one in use.
    //
    // **Every default case names an absent file, and that is the point.** The
    // platform config directory cannot be moved by an environment variable, so
    // a suite that relied on the developer having no `sure.yaml` would be a
    // suite about the developer's profile: it would refuse to run on a machine
    // whose owner has any user setting at all, and say nothing extra on one that
    // does not. A named file that does not exist is `ConfigSource::NoFile`, the
    // same answer SURE gives a user with no file, so the cases measure the
    // default on every machine. The consented case below names a real file
    // instead, and the doctor fields asserted here are what keep the two kinds
    // apart.
    let scratch = Scratch::new("doctor-settings-file");
    let store = scratch.store();
    let settings = scratch.absent_settings();
    assert!(
        !settings.is_file(),
        "{} exists, so a default case would be reading a settings file",
        settings.display()
    );
    let settings_text = settings.to_string_lossy().into_owned();
    let run = run_sure(
        &store,
        &[
            "--settings-file",
            &settings_text,
            "--format",
            "json",
            "doctor",
        ],
        None,
    );
    let answer = frame(&run, "sure doctor");

    assert_eq!(
        answer["details"]["places"]["settings_file"]["presence"].as_str(),
        Some("absent"),
        "`sure doctor` does not report the settings file this process just found to be missing, so \
         the two of them disagree about which file a default case reads: {answer}"
    );
    let reported = PathBuf::from(
        answer["details"]["places"]["settings_file"]["path"]
            .as_str()
            .unwrap_or_else(|| {
                panic!("`sure doctor` did not say where the settings file is: {answer}")
            }),
    );
    assert_eq!(
        reported, settings,
        "the settings file this test checked and the one `sure doctor` reports are different \
         files, so the premise above is not about the file a run would load"
    );
    assert_eq!(
        answer["details"]["places"]["store_location"].as_str(),
        Some("caller"),
        "the run did not use the store this test named, so the cases that name one are not the \
         mechanism they say they are: {answer}"
    );
    // The settings half of the same fact: the case named an absent file, so the
    // binary has to report that path as the caller's rather than as the
    // platform's. An implementation that quietly fell back to the platform file,
    // or to a file this suite had written, would fail here.
    assert_eq!(
        answer["details"]["places"]["settings_location"].as_str(),
        Some("caller"),
        "the run that named no settings file is reported as reading a file a caller named, so \
         either the default has moved or the report cannot tell the two apart: {answer}"
    );
}

#[test]
fn the_corpus_prints_what_it_could_not_confirm() {
    // A skipped check is not a pass, and neither is an omission. Every entry in
    // `not_confirmed` names what cannot be observed, the evidence that it cannot
    // be, what would settle it, and whose acceptance it lands on — and this test
    // prints them, so a reader of the run sees the holes beside the green.
    let entries = manifest()["not_confirmed"]
        .as_array()
        .expect("the corpus says what it could not confirm")
        .clone();
    assert!(
        !entries.is_empty(),
        "a corpus that claims to have confirmed everything is claiming more than this one can"
    );

    println!("--- NOT CHECKED ---");
    for entry in &entries {
        for field in ["id", "kind", "owner", "what", "evidence", "would_settle_it"] {
            let value = entry[field].as_str().unwrap_or_default();
            assert!(
                !value.trim().is_empty(),
                "not_confirmed[{}] has no {field}, and an entry without one is a shrug",
                entry["id"].as_str().unwrap_or("<an entry with no id>")
            );
        }
        let kind = entry["kind"].as_str().expect("a kind");
        assert!(
            ["gap", "seam"].contains(&kind),
            "not_confirmed[{}]: {kind:?} is neither a gap in the corpus nor a seam with another \
             task's acceptance",
            entry["id"]
        );
        println!(
            "  {} [{}] ({}): {}\n      evidence: {}\n      would be settled by: {}",
            entry["id"].as_str().expect("an id"),
            kind,
            entry["owner"].as_str().expect("an owner"),
            entry["what"].as_str().expect("what"),
            entry["evidence"].as_str().expect("evidence"),
            entry["would_settle_it"]
                .as_str()
                .expect("what would settle it")
        );
    }
    println!("--- END NOT CHECKED ---");
}
