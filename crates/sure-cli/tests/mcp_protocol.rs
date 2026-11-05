//! The MCP bridge as a caller meets it: a process, a pipe, and JSON.
//!
//! # Why this file runs the binary
//!
//! `src/mcp.rs` decides what to answer and its tests check those decisions. The
//! claims this file checks are the ones only a process can make:
//!
//! 1. the handshake and the version negotiation happen on the wire;
//! 2. the protocol messages are the *only* thing on stdout, and the session
//!    summary is not one of them;
//! 3. every tool answers with what the command line behind it answers — the
//!    same frame for a program, the same words for a person — which is the
//!    check that has to survive the day those commands start working;
//! 4. no tool reports success for a project that was not checked;
//! 5. a caller cannot reach around the CLI to change the execution mode, the
//!    privacy settings or the protection policy;
//! 6. the process ends when its caller closes the stream, with the status the
//!    session report says it returns.
//!
//! The server is driven the way a harness drives it: the test writes
//! newline-delimited JSON to its standard input and reads lines back from its
//! standard output. Every read has a deadline, so a server that stopped
//! answering fails this test instead of hanging it.
//!
//! # Where the sessions keep their evidence
//!
//! Every session and every command line here names a store with `--store-dir`,
//! in a directory of its own under `target/tmp` — see [`a_store_of_our_own`].
//! `sure_check` routes through `check::run`, so a session that named no store
//! would read the store of whoever ran the suite; a check with no goal does not
//! write one, but a test that read the machine's history would still be a test
//! whose result depends on it, and one test here did exactly that —
//! `sure_status_answers_about_this_build_and_never_about_a_project` compared a
//! record count read from the developer's store, and failed whenever anything
//! else on the machine wrote a row while it ran. Both ends are fixed: the count
//! now comes from a store this file made, and nothing here reaches the other.

// The workspace forbids `unwrap`, `expect` and `panic` in shipped code, because
// a panic is a message nobody chose. A test is the one place they are the point:
// the panic *is* the report, and it names the value that was wrong.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::thread;
use std::time::Duration;

use serde_json::{Value, json};
use sure_cli::mcp::{MAX_MESSAGE_BYTES, PROTOCOL_VERSION};

/// The binary this package builds, as cargo hands it to its integration tests.
const SURE: &str = env!("CARGO_BIN_EXE_sure");

/// A store directory for one session or one command line to use.
///
/// **Everything this file starts names one.** A session that named no store
/// would hand every `sure_check` the store of the person running the suite: a
/// check with no goal does not write to it, but a test whose answer depends on
/// somebody else's history is the same defect as a test that writes it, and this
/// file had one of each.
///
/// Under the workspace's git-ignored `target/tmp` by way of
/// `sure_testkit::scratch`, which holds the reasoning these helpers used to
/// repeat in twenty-five files, and created empty: a store SURE has never
/// written looks like exactly that.
fn a_store_of_our_own() -> PathBuf {
    sure_testkit::scratch::directory("sure mcp protocol", "store")
}

/// The binary, with a store named on its command line.
fn sure_in_a_store(store: &Path) -> Command {
    let mut command = Command::new(SURE);
    command.arg("--store-dir").arg(store);
    command
}

/// How long one answer may take before the test calls it a hang.
///
/// Generous: the point is to fail rather than block forever, not to measure
/// anything. A server that has said nothing within this is not slow, it is
/// stuck.
const DEADLINE: Duration = Duration::from_secs(30);

/// A live `sure mcp serve`, and the pipes the test talks to it on.
struct Session {
    child: Child,
    /// `None` once the caller has closed its side.
    input: Option<ChildStdin>,
    answers: Receiver<String>,
    diagnostics: Receiver<String>,
}

/// What a finished session left behind.
struct Finished {
    status: i32,
    /// Lines on stdout that no test read as an answer.
    unread: Vec<String>,
    stderr: String,
}

/// The one envelope a finished session leaves, read back from stderr.
///
/// The summary of a session is a diagnostic in both formats: the specification's
/// transport page forbids anything but a protocol message on the caller's
/// stream, so `--format json` does not change which stream the envelope takes.
/// A test that wants the summary parses the diagnostic stream — and checks
/// first that stdout held nothing but the messages it already read.
fn envelope_of(finished: &Finished) -> Value {
    let frame = finished.stderr.trim();
    serde_json::from_str(frame)
        .unwrap_or_else(|error| panic!("the session summary was not one frame ({error}): {frame}"))
}

impl Session {
    /// A server in a store of this test's own.
    fn open(args: &[&str]) -> Session {
        Session::open_in(&a_store_of_our_own(), args)
    }

    /// The same, in a store the caller named.
    ///
    /// A caller that wants the session and a command line to be about the same
    /// store — the comparison `sure_status` makes — passes the same directory to
    /// both.
    fn open_in(store: &Path, args: &[&str]) -> Session {
        let mut child = sure_in_a_store(store)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|error| panic!("could not run {SURE}: {error}"));
        let input = child.stdin.take().expect("stdin is piped");
        let answers = lines(child.stdout.take().expect("stdout is piped"));
        let diagnostics = lines(child.stderr.take().expect("stderr is piped"));
        Session {
            child,
            input: Some(input),
            answers,
            diagnostics,
        }
    }

    /// A server with the default format, which is what a harness gets.
    fn serve() -> Session {
        Session::open(&["mcp", "serve"])
    }

    /// A server with the machine format.
    ///
    /// The session's envelope still arrives on stderr rather than on stdout, so
    /// the tests that read it use [`envelope_of`] and check the caller's stream
    /// is protocol messages only.
    fn serve_json() -> Session {
        Session::open(&["--format", "json", "mcp", "serve"])
    }

    fn send(&mut self, line: &str) {
        let mut bytes = line.as_bytes().to_vec();
        bytes.push(b'\n');
        self.send_bytes(&bytes);
    }

    fn send_bytes(&mut self, bytes: &[u8]) {
        let input = self.input.as_mut().expect("the caller has not closed yet");
        input
            .write_all(bytes)
            .and_then(|()| input.flush())
            .unwrap_or_else(|error| panic!("could not write to the server: {error}"));
    }

    /// The next line on stdout, as JSON.
    fn read(&mut self) -> Value {
        let line = self.read_line();
        serde_json::from_str(&line)
            .unwrap_or_else(|error| panic!("a line on stdout was not JSON ({error}): {line}"))
    }

    fn read_line(&mut self) -> String {
        match self.answers.recv_timeout(DEADLINE) {
            Ok(line) => line,
            Err(RecvTimeoutError::Timeout) => {
                panic!("the server did not answer within {DEADLINE:?}")
            }
            Err(RecvTimeoutError::Disconnected) => {
                panic!("the server closed its output without answering")
            }
        }
    }

    /// Send one request and read its answer.
    fn ask(&mut self, request: Value) -> Value {
        self.send(&request.to_string());
        self.read()
    }

    /// The handshake, which every request after it depends on.
    fn start(&mut self) {
        let answer = self.ask(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": PROTOCOL_VERSION, "capabilities": {}, "clientInfo": {}},
        }));
        assert!(answer.get("error").is_none(), "{answer}");
    }

    /// Close the caller's side and collect what the process did.
    fn finish(mut self) -> Finished {
        let _ = self.input.take();
        let status = self
            .child
            .wait()
            .expect("the server exited")
            .code()
            .expect("the server exited on its own");
        Finished {
            status,
            unread: drain(&self.answers),
            stderr: drain(&self.diagnostics).join("\n"),
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        // A test that panicked leaves a server reading a stream nobody writes
        // to any more. Killing it here is what keeps a failure from leaving a
        // process behind; after `finish` the child is already gone and this is
        // a no-op.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Read lines from a pipe on a thread of its own.
///
/// The threads are what stop the two pipes from deadlocking the test: a server
/// that wrote more than a pipe buffer holds would block until somebody read it,
/// and the test is the only somebody there is.
fn lines(pipe: impl Read + Send + 'static) -> Receiver<String> {
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        for line in BufReader::new(pipe).lines() {
            let Ok(line) = line else { return };
            if sender.send(line).is_err() {
                return;
            }
        }
    });
    receiver
}

/// Everything left in a channel once its pipe closed.
fn drain(channel: &Receiver<String>) -> Vec<String> {
    let mut collected = Vec::new();
    loop {
        match channel.recv_timeout(DEADLINE) {
            Ok(line) => collected.push(line),
            Err(RecvTimeoutError::Disconnected) => return collected,
            Err(RecvTimeoutError::Timeout) => {
                panic!("a stream stayed open after the server exited")
            }
        }
    }
}

/// What one run of the binary did.
struct Run {
    status: i32,
    stdout: String,
    stderr: String,
}

fn run(args: &[&str]) -> Run {
    run_in(&a_store_of_our_own(), args)
}

/// The same, in a store the caller named.
fn run_in(store: &Path, args: &[&str]) -> Run {
    let output = sure_in_a_store(store)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .unwrap_or_else(|error| panic!("could not run {SURE}: {error}"));
    Run {
        status: output.status.code().expect("the process exited on its own"),
        stdout: String::from_utf8(output.stdout).expect("stdout is utf-8"),
        stderr: String::from_utf8(output.stderr).expect("stderr is utf-8"),
    }
}

/// The frame the command line prints for one command, as a value.
///
/// The store is always named, and by the caller: a tool result is compared with
/// the command line's answer for the same command, and a frame that names the
/// store it read can only be compared with one that read the same store.
fn frame_of_in(store: &Path, args: &[&str]) -> Value {
    let mut with_format = vec!["--format", "json"];
    with_format.extend_from_slice(args);
    let run = run_in(store, &with_format);
    serde_json::from_str(&run.stdout).unwrap_or_else(|error| {
        panic!(
            "`sure {}` did not print one frame ({error}): {}",
            args.join(" "),
            run.stdout
        )
    })
}

/// The frame a tool answered with, and the frame the command line printed,
/// brought to a common value by replacing every field whose value is **minted
/// for the run that produced it** — and how many were replaced.
///
/// # Why these fields, and not a rule
///
/// The two sides are two runs: one inside the server process and one in a
/// process of its own. Any value a run mints cannot be equal on both, and asking
/// it to be would be asserting that two runs are one run. The fields a run mints
/// in this frame are each named here rather than matched by a pattern:
///
/// - `details.report.project_fingerprint` — a fingerprint id is fresh on every
///   computation so that two results can be told apart by value, while the digest
///   is what two readings of one state share
///   (`docs/architecture/FINGERPRINTING.md`, "The `id` is fresh on every
///   computation"; `ProjectFingerprint::matches` compares the digest and never the
///   id);
/// - `details.report.findings[].id`, `details.lifecycle.still_open[].id` and
///   `details.lifecycle.closed[].id` — `FindingId::generate()` is per run, which
///   is the whole reason `recheck_lifecycle::FindingKey` exists: two runs over one
///   unchanged project raise *the same* finding under two identifiers;
/// - `details.repairs[].id`, `details.repairs[].issue_id`,
///   `details.repairs[].evidence[].id` and
///   `details.repairs[].evidence[].fingerprint` — a `RepairId` is minted where the
///   contract is built, its `issue_id` is that run's `FindingId`, and the evidence
///   it quotes is that run's `Evidence` about that run's project state. The
///   contract's own `recheck` list and its anchors' `subject_id` are **not** here:
///   a check id is a property of the plan, not of the run.
///
/// A rule — "normalise every `id`" — would hide a field the day somebody added
/// one that *is* stable, and the comparison would stop holding the two frames to
/// each other without saying so. The list is exhaustive rather than
/// representative: every replaced value is asserted to carry the prefix its kind
/// is documented to have (`IdKind::prefix`), so a field that stopped carrying an
/// identifier fails here rather than passing by omission.
///
/// # The count
///
/// The caller needs to know that this did something. With no finding, no
/// contract and no life-cycle row in either frame the replacement is a no-op and
/// the comparison is between two frames that agree about nothing, which is the
/// shape of a green that means "nothing was compared".
fn frame_without_the_per_run_ids(frame: &Value) -> (Value, usize) {
    let mut frame = frame.clone();
    let mut replaced_ids = 0usize;
    // A frame with no verdict in it — `sure history` and `sure doctor` are
    // reports that are not about a project state — has no such field, and there
    // is nothing to normalize.
    let Some(details) = frame.get_mut("details") else {
        return (frame, replaced_ids);
    };
    if let Some(report) = details.get_mut("report") {
        if let Some(field) = report.get_mut("project_fingerprint") {
            replaced_ids += replaced_id(field, "<this reading's fingerprint id>", "fp");
        }
        replaced_ids += replace_ids_in_array(
            report.get_mut("findings"),
            "<a finding id, minted for this run>",
            "fnd",
        );
    }
    if let Some(rows) = details
        .get_mut("check_results")
        .and_then(Value::as_array_mut)
    {
        for row in rows {
            if let Some(field) = row.get_mut("project_fingerprint") {
                replaced_ids += replaced_id(field, "<this reading's fingerprint id>", "fp");
            }
        }
    }
    if let Some(lifecycle) = details.get_mut("lifecycle") {
        for rows in ["still_open", "closed"] {
            replaced_ids += replace_ids_in_array(
                lifecycle.get_mut(rows),
                "<a finding id, minted for this run>",
                "fnd",
            );
        }
    }
    if let Some(contracts) = details.get_mut("repairs").and_then(Value::as_array_mut) {
        for contract in contracts {
            if let Some(field) = contract.get_mut("id") {
                replaced_ids += replaced_id(field, "<a repair id, minted for this run>", "rep");
            }
            if let Some(field) = contract.get_mut("issue_id") {
                replaced_ids += replaced_id(field, "<a finding id, minted for this run>", "fnd");
            }
            if let Some(evidence) = contract.get_mut("evidence").and_then(Value::as_array_mut) {
                for item in evidence {
                    if let Some(field) = item.get_mut("id") {
                        replaced_ids +=
                            replaced_id(field, "<an evidence id, minted for this run>", "evd");
                    }
                    if let Some(field) = item.get_mut("fingerprint") {
                        replaced_ids +=
                            replaced_id(field, "<the state this evidence was read against>", "fp");
                    }
                }
            }
        }
    }
    (frame, replaced_ids)
}

/// Replace one per-run identifier, refusing a value that does not carry the
/// prefix its kind is documented to have.
fn replaced_id(field: &mut Value, placeholder: &str, prefix: &str) -> usize {
    let value = field
        .as_str()
        .unwrap_or_else(|| panic!("a per-run identifier is a string: {field}"))
        .to_owned();
    assert!(
        value.starts_with(&format!("{prefix}_")),
        "a field that should carry a `{prefix}_` identifier carries {value:?}"
    );
    *field = json!(placeholder);
    1
}

/// The same, for a list of rows that each carry an `id`.
fn replace_ids_in_array(field: Option<&mut Value>, placeholder: &str, prefix: &str) -> usize {
    let Some(rows) = field.and_then(Value::as_array_mut) else {
        return 0;
    };
    let mut replaced_ids = 0;
    for row in rows {
        if let Some(field) = row.get_mut("id") {
            replaced_ids += replaced_id(field, placeholder, prefix);
        }
    }
    replaced_ids
}

/// A tool call, as a harness sends it.
fn call(id: u32, name: &str, arguments: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments},
    })
}

fn result_of(answer: &Value) -> &Value {
    assert!(answer.get("error").is_none(), "{answer}");
    &answer["result"]
}

fn error_code(answer: &Value) -> i64 {
    answer["error"]["code"]
        .as_i64()
        .unwrap_or_else(|| panic!("this is not an error message: {answer}"))
}

fn text_of(result: &Value) -> &str {
    result["content"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("a tool result carries one text block: {result}"))
}

/// One tool, the command line behind it, and where that command's words go.
struct Route {
    tool: &'static str,
    /// The command line the tool's result says it runs.
    routes_to: &'static str,
    arguments: Value,
    /// The same command, as the test runs it.
    command: &'static [&'static str],
    /// Whether the command's human form is an answer (stdout) or a complaint
    /// (stderr). `Report::is_an_answer` is the same decision inside the binary.
    answers_on_stdout: bool,
}

/// The project both the tools and the command line are pointed at.
///
/// The `packages/checkout` member of `fixtures/adversarial/repair-regression`
/// declares a test script whose result is wrong; checking the package alone
/// gives the three check-shaped routes a real finding to compare: SURE cannot
/// tell which package manager runs that script, so the test is reported as not
/// checked rather than passed. The package has no start script and no TODO,
/// mock, stub, placeholder or no-op pattern in its sources, so the completeness
/// analysis never asks a model to assess it: a developer's own settings may
/// name an analysis provider, and this project keeps that provider out of the
/// comparison instead of asking the test to out-run it.
const COMPARISON_PROJECT: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/adversarial/repair-regression/packages/checkout"
);

/// The four tools whose command is a fixed function of their arguments.
///
/// `sure_status` is checked on its own, because the two sides run `sure doctor`
/// at different moments and a doctor report contains the state of this machine.
///
/// The project is [`COMPARISON_PROJECT`], named absolutely. An absolute path is
/// what SURE requires — a relative root is refused rather than resolved against
/// wherever the process happens to be — and every argument here is a string a
/// harness could really send.
fn routes() -> [Route; 4] {
    const PROJECT: &str = COMPARISON_PROJECT;
    [
        Route {
            tool: "sure_check",
            routes_to: "sure check",
            arguments: json!({"project": PROJECT}),
            command: &["check", PROJECT],
            answers_on_stdout: true,
        },
        Route {
            tool: "sure_recheck",
            routes_to: "sure recheck",
            arguments: json!({"project": PROJECT}),
            command: &["recheck", PROJECT],
            answers_on_stdout: true,
        },
        Route {
            tool: "sure_get_repair",
            routes_to: "sure repair",
            arguments: json!({"project": PROJECT}),
            command: &["repair", PROJECT],
            answers_on_stdout: true,
        },
        Route {
            tool: "sure_get_report",
            routes_to: "sure history list",
            arguments: json!({}),
            command: &["history", "list"],
            // It answers on standard output now, and the flag is the whole of
            // what changed: `sure history list` used to be a command this build
            // could not carry out, so its words went to the complaint stream and
            // `isError` was true. The frame and the words are compared with the
            // command line either way; what this decides is which stream the
            // command line's half is read from, and whether the tool's result is
            // marked as an error.
            answers_on_stdout: true,
        },
    ]
}

/// The command line one tool stands for, by the name of the tool.
///
/// The same table [`routes`] carries, for the tests that ask about the tools
/// without calling them. Kept beside it deliberately: a tool and its command are
/// one decision, and two lists that could disagree are one list too many.
fn command_of(tool: &str) -> &'static str {
    match tool {
        "sure_check" => "check",
        "sure_recheck" => "recheck",
        "sure_get_repair" => "repair",
        "sure_get_report" => "history",
        "sure_status" => "doctor",
        other => panic!("no command is recorded for the tool {other}"),
    }
}

#[test]
fn the_handshake_names_the_revision_this_build_speaks_and_what_it_can_do() {
    let mut session = Session::serve();
    let answer = session.ask(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "mcp_protocol.rs", "version": "0"},
        },
    }));
    let result = result_of(&answer).clone();
    assert_eq!(result["protocolVersion"], PROTOCOL_VERSION);
    assert_eq!(result["serverInfo"]["name"], "sure");
    assert_eq!(result["capabilities"]["tools"]["listChanged"], false);
    // What this build can do, said in the handshake rather than discovered by
    // calling a tool and reading a refusal.
    let instructions = result["instructions"].as_str().expect("instructions");
    for command in sure_cli::commands::IMPLEMENTED {
        assert!(
            instructions.contains(command),
            "the handshake does not mention `sure {command}`: {instructions}"
        );
    }
    let finished = session.finish();
    assert_eq!(finished.status, 0, "{}", finished.stderr);
    assert!(finished.unread.is_empty(), "{:?}", finished.unread);
    assert!(
        finished.stderr.contains(PROTOCOL_VERSION),
        "{}",
        finished.stderr
    );
}

#[test]
fn a_caller_that_asks_for_another_revision_is_still_told_what_sure_speaks() {
    // The negotiation rule: SURE answers with a revision it supports, and the
    // caller decides from the answer whether it can go on.
    let mut session = Session::serve();
    let answer = session.ask(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {"protocolVersion": "1999-01-01"},
    }));
    assert_eq!(result_of(&answer)["protocolVersion"], PROTOCOL_VERSION);
    // And the session remembers both versions, because "which one did it ask
    // for" is the first question a person has when two sides disagree.
    let finished = session.finish();
    assert_eq!(finished.status, 0);
    assert!(
        finished.stderr.contains("1999-01-01"),
        "{}",
        finished.stderr
    );
}

#[test]
fn tools_list_is_the_five_tools_the_bridge_documents_with_closed_schemas() {
    let mut session = Session::serve();
    session.start();
    let answer = session.ask(json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}));
    let tools = result_of(&answer)["tools"]
        .as_array()
        .expect("a list of tools")
        .clone();
    let names: Vec<&str> = tools
        .iter()
        .map(|tool| tool["name"].as_str().expect("a tool has a name"))
        .collect();
    assert_eq!(
        names,
        [
            "sure_check",
            "sure_get_report",
            "sure_get_repair",
            "sure_recheck",
            "sure_status"
        ]
    );
    for tool in &tools {
        assert_eq!(tool["inputSchema"]["type"], "object", "{tool}");
        assert_eq!(tool["inputSchema"]["additionalProperties"], false, "{tool}");
        let properties = tool["inputSchema"]["properties"]
            .as_object()
            .cloned()
            .unwrap_or_default();
        for key in properties.keys() {
            assert_eq!(
                key, "project",
                "a tool exposes an argument that could select a policy: {tool}"
            );
        }
        // A tool says its command is missing exactly when it is, and the list
        // it is read from is the one the command line uses — so the day a
        // command starts working, every sentence that said it did not stops
        // saying it, in the handshake and in the tool list together.
        let name = tool["name"].as_str().expect("a tool has a name");
        let described = tool["description"]
            .as_str()
            .is_some_and(|text| text.contains("does not implement"));
        assert_eq!(
            described,
            !sure_cli::commands::IMPLEMENTED.contains(&command_of(name)),
            "a tool's description disagrees with what its command does: {tool}"
        );
    }
    assert_eq!(session.finish().status, 0);
}

#[test]
fn every_tool_answers_what_the_command_line_behind_it_answers() {
    // The single-path test. Not a hardcoded sentence: the tool result is
    // compared with what this same binary prints for the command the tool
    // stands for. The commands behind the three check tools run now, so the
    // comparison is a comparison of two real verdicts rather than of two
    // refusals — and the fields the two runs cannot share, because a run mints
    // them, are named and set aside in `frame_without_the_per_run_ids` rather
    // than waved at.
    // One store for the session and for the command lines it is compared with,
    // which `sure_status`'s test already had to do and every route needs now:
    // a history frame carries the path of the store it read, so two runs in two
    // stores could not be compared at all.
    let store = a_store_of_our_own();
    // One run is recorded before the comparison starts, because `sure recheck`
    // is a comparison and its answer depends on what the store already holds:
    // on a store with no history it reports that there is nothing to compare
    // against, and on the next run it reports what the earlier one left open.
    // Without this, the tool's re-check would be the first run and the command
    // line's the second, and their frames would differ for a reason that has
    // nothing to do with the two paths. It is also the state a user meets —
    // `sure recheck` after `sure repair` — rather than an artefact of the test.
    let project = COMPARISON_PROJECT;
    let seeded = run_in(&store, &["repair", project]);
    assert_eq!(
        seeded.status, 1,
        "the run that gives the store its history returned {} rather than 1 (checked, not \
         clean):\n{}",
        seeded.status, seeded.stderr
    );
    let mut session = Session::open_in(&store, &["mcp", "serve"]);
    session.start();
    let mut replaced_ids = 0usize;
    for (index, route) in routes().iter().enumerate() {
        let answer = session.ask(call(10 + index as u32, route.tool, route.arguments.clone()));
        let result = result_of(&answer).clone();
        if route.tool == "sure_check" {
            // The comparison is only meaningful while the project asks no
            // model. A developer's settings may name an analysis provider; if
            // this project ever grows a candidate the provider would be
            // consulted, and two model answers are not a comparison.
            let model_state = result["structuredContent"]["sure"]["details"]["model_use"]["state"]
                .as_str()
                .unwrap_or("missing");
            assert!(
                matches!(
                    model_state,
                    "no_provider" | "nothing_asked" | "provider_unusable"
                ),
                "the comparison project must not consult a model, or two runs cannot be \
                 compared: model_use.state is {model_state}"
            );
        }
        let expected = frame_of_in(&store, route.command);
        let (answered, answered_ids) =
            frame_without_the_per_run_ids(&result["structuredContent"]["sure"]);
        let (printed, printed_ids) = frame_without_the_per_run_ids(&expected);
        replaced_ids += answered_ids + printed_ids;
        assert_eq!(
            &answered,
            &printed,
            "{} does not answer with `sure {}`'s frame",
            route.tool,
            route.command.join(" ")
        );
        let human = run_in(&store, route.command);
        let words: &str = if route.answers_on_stdout {
            &human.stdout
        } else {
            &human.stderr
        };
        assert_eq!(
            text_of(&result),
            words,
            "{} does not answer with `sure {}`'s words",
            route.tool,
            route.command.join(" ")
        );
        assert_eq!(
            result["structuredContent"]["routes_to"].as_str(),
            Some(route.routes_to),
            "{}",
            route.tool
        );
        // The two paths agree about the status as well as the words, and the
        // tool's `isError` is the command's own `is_an_answer` turned round: a
        // command that answered is not an error, however bad the news is, and
        // what the caller must read is the frame. A harness that took `isError`
        // for the verdict would be reading the transport as the result.
        assert_eq!(
            human.status,
            i32::try_from(expected["exit_code"].as_i64().expect("an exit code"))
                .expect("a status that fits"),
            "`sure {}` and its own frame disagree about the status",
            route.command.join(" ")
        );
        assert_eq!(
            result["isError"],
            json!(!route.answers_on_stdout),
            "{} disagrees with `sure {}` about whether it answered",
            route.tool,
            route.command.join(" ")
        );
    }
    // The count is the guard against a comparison that holds nothing: with no
    // finding, no contract and no life-cycle row in the frames, the frames agree
    // and the loop above has measured nothing. Measured today, the
    // check-shaped routes carry a finding because the fixture package declares
    // a test that SURE cannot run while it cannot tell which package manager
    // owns it — and a finding id is minted for the run that produced it.
    assert!(
        replaced_ids > 0,
        "not one per-run identifier was replaced across {} routes, so the frames agreed without \
         a finding, a contract or a life-cycle row between them: {replaced_ids}",
        routes().len()
    );
    assert_eq!(session.finish().status, 0);
}

#[test]
fn sure_status_answers_about_this_build_and_never_about_a_project() {
    // One store for the session and for the command line it is compared with.
    // The report this test reads carries the store's path and how many records
    // are in it, so two runs in two stores could not be compared — and reading
    // the number out of the developer's own store is what made this test fail
    // whenever anything else on the machine wrote a row while it ran.
    let store = a_store_of_our_own();
    let mut session = Session::open_in(&store, &["mcp", "serve"]);
    session.start();
    let answer = session.ask(call(20, "sure_status", json!({})));
    let result = result_of(&answer).clone();
    assert_eq!(result["isError"], false, "{answer}");
    assert_eq!(result["structuredContent"]["sure"]["command"], "doctor");
    assert_eq!(
        result["structuredContent"]["mcp"]["protocol_version"],
        PROTOCOL_VERSION
    );
    assert_eq!(
        &result["structuredContent"]["mcp"]["commands_implemented"],
        &json!(sure_cli::commands::IMPLEMENTED)
    );
    // Agreement with the command line, on the fields a doctor report cannot
    // change between two runs of the same build on the same machine.
    let frame = frame_of_in(&store, &["doctor"]);
    for field in ["command", "outcome", "exit_code"] {
        assert_eq!(
            result["structuredContent"]["sure"][field], frame[field],
            "`sure doctor`'s {field} disagrees with the tool's"
        );
    }
    // And the words are doctor's own.
    assert_eq!(text_of(&result), run_in(&store, &["doctor"]).stdout);
    assert_eq!(session.finish().status, 0);
}

#[test]
fn no_tool_reports_success_for_a_project_that_was_never_checked() {
    // The false green, in its MCP shape: an agent reads `isError: false` and
    // tells the user the project is fine.
    //
    // `sure_get_report` is skipped, and it is the only one that is. It does not
    // answer about a project at all — `sure history` says what this *machine*
    // has recorded, and "nothing has been recorded" is a true answer that exits
    // 0. Demanding a non-`ok` outcome here would force it to lie about what it
    // did, which is the failure this test exists to prevent wearing the other
    // face. What it must never do is let that answer be read as a statement
    // about the project, and that is
    // `sure_get_report_answers_about_the_machine_and_never_about_a_project`
    // below. The skip is read from the bridge's own tool schemas rather than
    // from a name written here, so a tool that starts taking a project is back
    // in this loop on the day it does.
    let mut session = Session::serve();
    session.start();
    let answers_about_a_project = tools_that_take_a_project(&mut session);
    for (index, route) in routes().iter().enumerate() {
        if !answers_about_a_project
            .iter()
            .any(|name| name == route.tool)
        {
            continue;
        }
        let result =
            result_of(&session.ask(call(30 + index as u32, route.tool, route.arguments.clone())))
                .clone();
        // `ok` is the word that must never appear. It is the CLI's own word for
        // "the project is clean", so it is the one a harness would act on, and
        // it is a claim about the project rather than about the call.
        assert_ne!(
            result["structuredContent"]["sure"]["outcome"], "ok",
            "{} reported a clean project for work that did not happen: {result}",
            route.tool
        );
        assert_ne!(
            result["structuredContent"]["sure"]["exit_code"], 0,
            "{} exited zero for work that did not happen: {result}",
            route.tool
        );
        // And a tool whose command cannot run at all is still an error, in that
        // command's own words.
        if !sure_cli::commands::IMPLEMENTED.contains(&command_of(route.tool)) {
            assert_eq!(result["isError"], true, "{}: {result}", route.tool);
            assert!(
                text_of(&result).contains("is not implemented in this build."),
                "{}: {}",
                route.tool,
                text_of(&result)
            );
            assert_eq!(
                result["structuredContent"]["sure"]["outcome"],
                "unavailable"
            );
            assert_eq!(result["structuredContent"]["sure"]["exit_code"], 3);
        }
    }
    assert_eq!(session.finish().status, 0);
}

/// The tools that accept a `project` argument, read from the bridge's own
/// `tools/list`.
///
/// From the schema rather than from a list written here, so that a tool which
/// starts or stops taking a project moves the tests that care about the
/// difference with it. The schema is what a caller reads to decide what to send,
/// so it is also the thing that would be wrong if the two disagreed.
fn tools_that_take_a_project(session: &mut Session) -> Vec<String> {
    let listed = result_of(&session.ask(json!({
        "jsonrpc": "2.0", "id": 1, "method": "tools/list"
    })))
    .clone();
    listed["tools"]
        .as_array()
        .expect("the bridge lists tools")
        .iter()
        .filter(|tool| {
            tool["inputSchema"]["properties"]
                .as_object()
                .is_some_and(|properties| properties.contains_key("project"))
        })
        .map(|tool| tool["name"].as_str().expect("a tool has a name").to_owned())
        .collect()
}

#[test]
fn sure_get_report_answers_about_the_machine_and_never_about_a_project() {
    // The other half of the skip above, so that skipping it hides nothing. The
    // tool is asked with no argument, in a store nothing has written, and what
    // comes back has to be an answer about this machine: `ok`, exit 0, and a
    // body that carries a history rather than a verdict — no `green`, no stage
    // log, nothing an agent could quote as "the project is fine".
    let mut session = Session::serve();
    session.start();
    let result = result_of(&session.ask(call(31, "sure_get_report", json!({})))).clone();
    assert_eq!(result["isError"], false, "{result}");
    let sure = &result["structuredContent"]["sure"];
    assert_eq!(sure["command"], "history");
    assert_eq!(sure["outcome"], "ok");
    assert_eq!(sure["exit_code"], 0);
    assert!(
        sure["details"]["green"].is_null(),
        "the history answered with a verdict about a project: {result}"
    );
    assert!(
        sure["details"]["stages"].is_null(),
        "the history answered with a stage log, which is a check's shape: {result}"
    );
    let text = text_of(&result);
    assert!(
        text.contains("this machine"),
        "the answer does not say what it is about, so an agent could quote it as a verdict:\n{text}"
    );
    // And the bridge agrees that this tool takes no project, which is what the
    // skip above rests on. Asked of the schemas, in a session of its own,
    // because the loop above has already consumed the one it built.
    let takes_one = tools_that_take_a_project(&mut session);
    assert!(
        !takes_one.iter().any(|name| name == "sure_get_report"),
        "this test says the history never answers about a project, and the bridge's own schema \
         says the tool takes one: {takes_one:?}"
    );
    assert_eq!(session.finish().status, 0);
}

#[test]
fn no_argument_can_reach_the_execution_privacy_or_protection_policy() {
    let mut session = Session::serve();
    session.start();
    let attempts = [
        (
            "sure_check",
            "execution_mode",
            json!({"execution_mode": "unrestricted"}),
        ),
        ("sure_check", "privacy", json!({"privacy": "off"})),
        ("sure_recheck", "mode", json!({"mode": "unrestricted"})),
        ("sure_status", "trust", json!({"trust": "everything"})),
        // Beside a project, which is the one argument a tool does accept.
        (
            "sure_check",
            "force",
            json!({"project": "somewhere", "force": true}),
        ),
    ];
    for (index, (tool, key, arguments)) in attempts.iter().enumerate() {
        let answer = session.ask(call(40 + index as u32, tool, arguments.clone()));
        assert_eq!(error_code(&answer), -32602, "{answer}");
        let message = answer["error"]["message"].as_str().expect("a message");
        assert!(message.contains(key), "{message}");
        assert!(
            message.contains("the user's own SURE configuration"),
            "the refusal does not say where the policy comes from: {message}"
        );
    }
    // And the list said so before the call did: no tool offers such a key.
    let listed = result_of(&session.ask(json!({
        "jsonrpc": "2.0", "id": 50, "method": "tools/list"
    })))
    .clone();
    for tool in listed["tools"].as_array().expect("tools") {
        let properties = tool["inputSchema"]["properties"]
            .as_object()
            .cloned()
            .unwrap_or_default();
        assert!(properties.len() <= 1, "{tool}");
    }
    assert_eq!(session.finish().status, 0);
}

#[test]
fn a_project_on_a_tool_that_takes_none_is_refused_rather_than_ignored() {
    let mut session = Session::serve();
    session.start();
    let answer = session.ask(call(60, "sure_get_report", json!({"project": "somewhere"})));
    assert_eq!(error_code(&answer), -32602);
    let message = answer["error"]["message"].as_str().expect("a message");
    assert!(message.contains("sure history list"), "{message}");
    assert_eq!(session.finish().status, 0);
}

#[test]
fn a_relative_project_path_is_refused_the_way_the_command_line_refuses_it() {
    let mut session = Session::serve();
    session.start();
    let result =
        result_of(&session.ask(call(70, "sure_check", json!({"project": "relative-dir"})))).clone();
    assert_eq!(result["isError"], true);
    assert_eq!(text_of(&result), run(&["check", "relative-dir"]).stderr);
    assert_eq!(session.finish().status, 0);
}

#[test]
fn a_project_path_with_spaces_and_non_ascii_characters_round_trips() {
    // Windows engineering discipline: a path with a space and a path that is
    // not ASCII are the two that break a bridge written with a shell in mind.
    let project = "C:\\Users\\someone\\ünïcode dir\\проект";
    let mut session = Session::serve();
    session.start();
    let result =
        result_of(&session.ask(call(80, "sure_check", json!({"project": project})))).clone();
    assert_eq!(result["isError"], true);
    assert_eq!(text_of(&result), run(&["check", project]).stderr);
    assert_eq!(session.finish().status, 0);
}

#[test]
fn a_request_before_the_handshake_is_refused_and_the_handshake_still_works() {
    let mut session = Session::serve();
    let answer = session.ask(json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}));
    assert_eq!(error_code(&answer), -32002);
    session.start();
    assert_eq!(session.finish().status, 0);
}

#[test]
fn a_second_handshake_is_refused_and_the_session_goes_on() {
    let mut session = Session::serve();
    session.start();
    let answer = session.ask(json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "initialize",
        "params": {"protocolVersion": PROTOCOL_VERSION},
    }));
    assert_eq!(error_code(&answer), -32600);
    let pong = session.ask(json!({"jsonrpc": "2.0", "id": 3, "method": "ping"}));
    assert!(pong.get("result").is_some(), "{pong}");
    assert_eq!(session.finish().status, 0);
}

#[test]
fn an_unknown_method_is_refused_by_name_and_the_session_goes_on() {
    let mut session = Session::serve();
    session.start();
    let answer = session.ask(json!({"jsonrpc": "2.0", "id": 2, "method": "resources/list"}));
    assert_eq!(error_code(&answer), -32601);
    assert!(
        answer["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("resources/list")),
        "{answer}"
    );
    let pong = session.ask(json!({"jsonrpc": "2.0", "id": 3, "method": "ping"}));
    assert!(pong.get("result").is_some(), "{pong}");
    assert_eq!(session.finish().status, 0);
}

#[test]
fn an_unknown_tool_is_refused_as_a_protocol_error() {
    let mut session = Session::serve();
    session.start();
    let answer = session.ask(call(2, "sure_chekc", json!({})));
    assert_eq!(error_code(&answer), -32602);
    assert_eq!(
        answer["error"]["message"].as_str(),
        Some("Unknown tool: sure_chekc")
    );
    assert_eq!(session.finish().status, 0);
}

#[test]
fn a_line_that_is_not_json_is_refused_with_a_null_identifier_and_the_session_goes_on() {
    let mut session = Session::serve();
    session.start();
    session.send("{ this is not json");
    let answer = session.read();
    assert_eq!(error_code(&answer), -32700);
    assert!(answer["id"].is_null(), "{answer}");
    // A blank line is not a message either.
    session.send("");
    let answer = session.read();
    assert_eq!(error_code(&answer), -32700);
    let pong = session.ask(json!({"jsonrpc": "2.0", "id": 3, "method": "ping"}));
    assert!(pong.get("result").is_some(), "{pong}");
    assert_eq!(session.finish().status, 0);
}

#[test]
fn a_line_longer_than_sure_will_hold_is_refused_and_the_next_line_is_read_as_a_message() {
    // The size bound is SURE's (the specification sets none), and so is the
    // recovery: the rest of the line is discarded rather than read as the
    // beginning of the next message.
    let mut session = Session::serve();
    session.start();
    let mut oversized = vec![b'x'; MAX_MESSAGE_BYTES + 1024];
    oversized.push(b'\n');
    session.send_bytes(&oversized);
    let answer = session.read();
    assert_eq!(error_code(&answer), -32700);
    assert!(answer["id"].is_null(), "{answer}");
    let pong = session.ask(json!({"jsonrpc": "2.0", "id": 3, "method": "ping"}));
    assert!(pong.get("result").is_some(), "{pong}");
    assert_eq!(session.finish().status, 0);
}

#[test]
fn a_notification_is_never_answered_and_never_runs_anything() {
    let mut session = Session::serve_json();
    session.start();
    session.send(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}).to_string());
    session.send(
        &json!({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": "sure_check", "arguments": {"project": "somewhere"}},
        })
        .to_string(),
    );
    // The proof that nothing was answered and nothing ran: the next line on
    // stdout is the answer to the ping, and the session envelope says that no
    // tool call went past.
    let pong = session.ask(json!({"jsonrpc": "2.0", "id": 9, "method": "ping"}));
    assert_eq!(pong["id"], 9, "{pong}");
    let finished = session.finish();
    assert_eq!(finished.status, 0);
    assert!(
        finished.unread.is_empty(),
        "stdout carried something that is not a protocol message: {:?}",
        finished.unread
    );
    let envelope = envelope_of(&finished);
    assert_eq!(envelope["command"], "mcp");
    assert_eq!(envelope["details"]["tool_calls"], 0, "{envelope}");
    assert_eq!(envelope["details"]["notifications"], 2, "{envelope}");
    assert_eq!(envelope["details"]["errors"], 0, "{envelope}");
    assert_eq!(envelope["details"]["initialized"], true, "{envelope}");
    assert_eq!(envelope["details"]["answered"], 2, "{envelope}");
}

#[test]
fn stdout_carries_protocol_messages_and_the_session_summary_goes_to_stderr() {
    // The specification's rule: the server must not write anything to stdout
    // that is not a valid MCP message. The summary of a session is not one, so
    // with the default format it is a diagnostic.
    let mut session = Session::serve();
    session.start();
    let _ = session.ask(call(2, "sure_check", json!({})));
    let finished = session.finish();
    assert_eq!(finished.status, 0);
    assert!(
        finished.unread.is_empty(),
        "stdout carried something that is not a protocol message: {:?}",
        finished.unread
    );
    assert!(
        finished.stderr.contains("handshake") && finished.stderr.contains(PROTOCOL_VERSION),
        "{}",
        finished.stderr
    );
    assert!(
        finished
            .stderr
            .contains("the bridge itself checked nothing"),
        "the summary does not say what it is not: {}",
        finished.stderr
    );
}

#[test]
fn the_machine_format_leaves_stdout_to_the_protocol_and_writes_its_envelope_to_stderr() {
    // This was a wart until P12-T010 and it is not one now: `--format json`
    // means "everything SURE says goes to stdout as one frame", which put a CLI
    // envelope on the protocol channel after the last message. The
    // specification's transport page forbids it — at revision `2025-11-25`,
    // "The server **MUST NOT** write anything to its `stdout` that is not a
    // valid MCP message" — so the summary is a diagnostic in this format too,
    // and a caller may pass the flag without losing the stream.
    let mut session = Session::serve_json();
    session.start();
    let finished = session.finish();
    assert_eq!(finished.status, 0);
    assert!(
        finished.unread.is_empty(),
        "stdout carried something that is not a protocol message: {:?}",
        finished.unread
    );
    let envelope = envelope_of(&finished);
    assert_eq!(envelope["command"], "mcp");
    assert_eq!(envelope["outcome"], "ok");
    assert_eq!(envelope["exit_code"], 0);
    assert_eq!(envelope["details"]["answered"], 1, "{envelope}");
}

#[test]
fn no_line_that_is_not_a_protocol_message_reaches_stdout_in_any_mode() {
    // The claim `docs/architecture/MCP_BRIDGE.md` makes, read back from the
    // process: the caller's stream carries protocol messages and nothing else,
    // whatever format the command line asked for. `--format json` used to be
    // the exception, with the session's CLI envelope arriving after the last
    // message; P12-T010 removed it, and this test is what says so for every
    // mode the grammar accepts rather than for the one that was reported.
    let modes: [&[&str]; 3] = [
        &["mcp", "serve"],
        &["--format", "human", "mcp", "serve"],
        &["--format", "json", "mcp", "serve"],
    ];
    for args in modes {
        let mut session = Session::open(args);
        session.start();
        let _ = session.ask(call(2, "sure_status", json!({})));
        let finished = session.finish();
        assert_eq!(finished.status, 0, "{}", finished.stderr);
        assert!(
            finished.unread.is_empty(),
            "{args:?} left something on stdout that is not a protocol message: {:?}",
            finished.unread
        );
    }
}

/// The PowerShell the packaged manifest names, found the way Windows finds it.
///
/// The manifest says `powershell`, which a harness resolves through `PATH`. A
/// test should not depend on `PATH` any more than the package does, so this asks
/// the system directory for the same binary — Windows PowerShell, not `pwsh`,
/// because that is the name a manifest can count on being there.
#[cfg(windows)]
fn powershell() -> PathBuf {
    let root = std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into());
    PathBuf::from(root).join("System32\\WindowsPowerShell\\v1.0\\powershell.exe")
}

/// The script the packaged Claude Code manifest names as its MCP server.
#[cfg(windows)]
fn packaged_launcher() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("integrations")
        .join("claude-code")
        .join("scripts")
        .join("sure-mcp.ps1")
}

/// Write `input` to a process's standard input, close it, and collect the run.
#[cfg(windows)]
fn run_with_stdin(mut command: Command, input: &str) -> Run {
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|error| panic!("could not start the session: {error}"));
    child
        .stdin
        .take()
        .expect("stdin is piped")
        .write_all(input.as_bytes())
        .expect("the caller can write");
    let output = child.wait_with_output().expect("the process exited");
    Run {
        status: output.status.code().expect("the process exited on its own"),
        stdout: String::from_utf8(output.stdout).expect("stdout is utf-8"),
        stderr: String::from_utf8(output.stderr).expect("stderr is utf-8"),
    }
}

/// The acceptance criterion "plugin MCP manifests invoke local sure binary" is a
/// claim about a package rather than about this crate, so this runs what the
/// package's manifest names a harness to run: `powershell -NoProfile -File
/// <package>/scripts/sure-mcp.ps1`, with `SURE_BIN` naming the binary this build
/// just produced — the resolution a user who set the documented override gets.
///
/// What comes back is compared byte for byte with the same three messages sent
/// straight at `sure --store-dir … mcp serve`, because a launcher between a
/// caller and a server is exactly where a stream gets decorated, re-encoded or
/// ended early. The launcher run carries no `--store-dir`, because the manifest
/// passes none: the three messages are the handshake, the tool list and a ping,
/// none of which runs a command, so the session opens no store and the store of
/// whoever runs the suite is not touched.
#[cfg(windows)]
#[test]
fn the_packaged_mcp_launcher_reaches_sure_and_hands_the_stream_over_untouched() {
    let launcher = packaged_launcher();
    assert!(
        launcher.is_file(),
        "the manifest names {}, and it is not there",
        launcher.display()
    );

    let messages = [
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "mcp_protocol.rs", "version": "0"},
            },
        })
        .to_string(),
        json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}).to_string(),
        json!({"jsonrpc": "2.0", "id": 3, "method": "ping"}).to_string(),
    ];
    let stream = format!("{}\n", messages.join("\n"));

    let mut through_the_launcher = Command::new(powershell());
    through_the_launcher
        .args(["-NoProfile", "-File"])
        .arg(&launcher)
        .env("SURE_BIN", SURE);
    let through = run_with_stdin(through_the_launcher, &stream);

    let mut direct_command = sure_in_a_store(&a_store_of_our_own());
    direct_command.args(["mcp", "serve"]);
    let direct = run_with_stdin(direct_command, &stream);

    assert_eq!(through.status, 0, "{}", through.stderr);
    assert_eq!(direct.status, 0, "{}", direct.stderr);
    assert_eq!(
        through.stdout, direct.stdout,
        "the launcher changed the protocol stream"
    );
    // Every line is a message, and the handshake's own words survived the trip.
    // The instructions carry an em dash (`SURE — Software Understanding`); a
    // launcher that read and re-wrote the stream through a legacy code page
    // would turn it into `?`, and comparing the two runs is what catches that.
    assert_eq!(
        through.stdout.lines().count(),
        3,
        "{:?}",
        through.stdout.lines().collect::<Vec<_>>()
    );
    for line in through.stdout.lines() {
        let message: Value = serde_json::from_str(line)
            .unwrap_or_else(|error| panic!("a line on stdout was not JSON ({error}): {line}"));
        assert_eq!(message["jsonrpc"], "2.0", "{message}");
    }
    assert!(
        through.stdout.contains('\u{2014}'),
        "the handshake's own text did not survive the launcher intact: {}",
        through.stdout
    );
    // The session summary is the server's, and it is a diagnostic here too.
    assert!(
        through.stderr.contains(PROTOCOL_VERSION),
        "{}",
        through.stderr
    );
}

#[test]
fn a_caller_that_never_handshakes_gets_a_summary_that_says_so() {
    let mut session = Session::serve_json();
    session.ask(json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}));
    let finished = session.finish();
    assert_eq!(finished.status, 0);
    let envelope = envelope_of(&finished);
    assert_eq!(envelope["details"]["initialized"], false, "{envelope}");
    assert_eq!(envelope["details"]["answered"], 1, "{envelope}");
    assert_eq!(envelope["details"]["errors"], 1, "{envelope}");
    assert!(
        envelope["details"]["agreed_protocol_version"].is_null(),
        "{envelope}"
    );
}

#[test]
fn the_bridge_writes_nothing_to_stdout_when_the_caller_says_nothing() {
    let session = Session::serve();
    let finished = session.finish();
    assert_eq!(finished.status, 0);
    assert!(finished.unread.is_empty(), "{:?}", finished.unread);
    assert!(
        finished.stderr.contains("never completed one"),
        "{}",
        finished.stderr
    );
}

#[test]
fn the_grammar_refuses_a_bare_sure_mcp() {
    // `serve` is not optional, for `sure hook`'s reason: a harness that read
    // "SURE is listening" out of a process that had already exited would be
    // told about a bridge that was not there.
    let run = run(&["mcp"]);
    assert_eq!(run.status, 2, "{}", run.stderr);
    assert!(run.stdout.is_empty(), "{:?}", run.stdout);
}
