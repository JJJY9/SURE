//! `P14-T003`'s acceptance, checked by running the fixture pair.
//!
//! The task's sentence is one sentence:
//!
//! > *At least one Rust real-fail/real-pass project exercises
//! > discovery/execution/reporting.*
//!
//! # What "real-fail/real-pass" has to mean, and why both halves are assertions
//!
//! `fixtures/adversarial/rust-tests-fail` is a Rust project whose own check
//! genuinely fails, and `fixtures/adversarial/rust-tests-pass` is the same
//! project with one line corrected. They are each other's control, and the pass
//! half is not decoration: a checker that refused every Rust project would
//! satisfy every assertion the failing half can make. So the single line that
//! separates them is asserted as a value in
//! [`the_pair_is_the_same_project_apart_from_one_line`], not described in a
//! README, and the two verdicts are asserted to differ in
//! [`the_failing_half_fails_only_the_test_check_and_is_not_ready`] and
//! [`the_passing_half_passes_every_check_and_is_green`].
//!
//! # What "exercises" has to mean
//!
//! **SURE's own modules run against the fixture and produce the verdict.** Not a
//! README's account of what SURE would say, and not this file's opinion:
//!
//! - [`discover`] reads the fixture from the `Cargo.toml` on disk;
//! - [`RustChecks`] turns that reading into the four proposed checks, in the
//!   plan [`PlanBuilder`] builds for a host-confirmed run;
//! - [`sure_core::process::run`] — the one place in this workspace that starts a
//!   program — runs each of the four, and each check's own exit code is what
//!   becomes its [`CheckResult`];
//! - [`aggregate_run`] turns those results and the plan into the run's verdict;
//! - [`build_verdict`] and [`render_summary`] turn that into the sentence a
//!   person reads.
//!
//! `crates/sure-core/tests/rust_checks.rs` states in as many words that nothing
//! in it runs `cargo` and that its results are "built by this file standing in
//! for the runner", which is the right shape for a test about fingerprint
//! binding. This file is the other half of that sentence: the results here come
//! out of processes that really ran, and that difference is what this task adds.
//!
//! # Three traps this file keeps out of the checkout's own build
//!
//! **A fixture must not become a workspace member.** The root manifest lists its
//! members explicitly, and a deliberately failing project must not be among
//! them: `cargo test --workspace` would build it and run it, and the checkout's
//! own suite would then fail because a fixture is doing its job.
//! [`neither_half_is_a_member_of_this_workspace`] holds both halves of the
//! arrangement — the root members list, and the empty `[workspace]` table that
//! makes each fixture a workspace root of its own, which is the other answer
//! `cargo` offers and the one that leaves the root manifest untouched.
//!
//! **`cargo` writes next to the manifest it reads.** A `Cargo.lock` or a
//! `target/` inside a shipped fixture would appear in `git status`, because the
//! `.gitignore` entry for `target/` is anchored at the repository root. So
//! nothing here runs `cargo` in the fixture: every run happens on a copy under
//! `target/tmp`, and the copy is not taken on trust — [`content_fingerprint`],
//! SURE's own, is computed for the shipped directory and for the copy, and the
//! two digests are asserted equal. The failing half's tests also assert that the
//! shipped directory still has no lock file and no build directory afterwards.
//!
//! **A check's command is one string and the runner takes an argument vector.**
//! [`CheckReason::DeclaredCommand`] carries `cargo test` as a single `String`,
//! and `sure_core::process` splits nothing — its module documentation says so in
//! those words. The split therefore has to happen somewhere between the schedule
//! and the runner, and today that somewhere is [`request`] below, in a test,
//! because the composition layer that will own it does not exist yet. That is
//! recorded rather than hidden: the day a runner is written, this is the shape it
//! has to reproduce.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use sure_core::aggregation::{RunReport, aggregate_run};
use sure_core::checks::rust::RustChecks;
use sure_core::discover::rust::MANIFEST;
use sure_core::discover::{DiscoverOptions, Ecosystem, Findings, discover};
use sure_core::fingerprint::{FingerprintOptions, content_fingerprint, project_fingerprint};
use sure_core::planned_work::PlannedWork;
use sure_core::process::{
    Cancellation, Environment, Limits, Outcome, ProcessRequest, Termination, run,
};
use sure_core::project_verdict::{build_verdict, render_summary};
use sure_core::schedule::{CheckProposal, CheckReason, CheckSchedule, PlanBuilder};
use sure_domain::capability::CapabilityReport;
use sure_domain::execution::{ExecutionMode, ExecutionPermissions};
use sure_domain::ids::FingerprintId;
use sure_domain::intent::ProjectIntent;
use sure_domain::status::{AggregateSeverity, CheckResult, CheckStatus, CriticalState};

/// The half whose own check fails.
const FAILING: &str = "rust-tests-fail";

/// The half whose own check passes, and the pair's control.
const PASSING: &str = "rust-tests-pass";

/// The one line the two halves differ by, on each side.
///
/// Spelled out rather than reduced to "the files differ", because the claim this
/// task makes is not that they differ but that they differ by *this*: one takes
/// the discount off the subtotal and the other adds it.
const ADDING: &str = "subtotal_cents.saturating_add(discount_cents)";
const SUBTRACTING: &str = "subtotal_cents.saturating_sub(discount_cents)";

/// The four commands the acceptance names, in the order the checks layer
/// proposes them.
///
/// Written out because each one is a decision: `--check` on the first is the
/// checks layer's, `--all-targets` on the middle two is the discovery's, and the
/// last is `cargo`'s own.
const THE_FOUR: [&str; 4] = [
    "cargo fmt --check",
    "cargo check --all-targets",
    "cargo clippy --all-targets",
    "cargo test",
];

/// The files that are allowed to differ between the halves for a reason other
/// than the defect: each half has to say which half it is.
const HALF_SPECIFIC_FILES: &[&str] = &["README.md", "scenario.json", "scripts/check.ps1"];

/// The files that make up the project itself — what the pair's claim is about.
const PROJECT_FILES: &[&str] = &["Cargo.toml", "rustfmt.toml", "clippy.toml", "src/main.rs"];

/// How long a check has, and how much of what it says SURE keeps.
///
/// Generous, because these runs compile a crate and this suite may be running on
/// a machine that is compiling other things at the same time. The bound is not
/// about patience: a run that passed its deadline is reported as SURE's own
/// check having failed rather than as a pass, so a runner that deadlocked on a
/// lock file would be a visible failure rather than a hang.
const LIMITS: Limits = Limits::new(Duration::from_secs(300), 256 * 1024, 256 * 1024);

/// The shipped directory of a fixture.
fn shipped(id: &str) -> PathBuf {
    sure_testkit::repository_root()
        .join("fixtures")
        .join("adversarial")
        .join(id)
}

/// The content fingerprint of a directory, as a digest.
///
/// The digest rather than the fingerprint value: a fingerprint carries a freshly
/// generated identity that is unique per computation by design, so two
/// fingerprints of the same project are never equal as values and their digests
/// are. Comparing the values would fail for every pair of directories, which is
/// the shape of assertion that looks like a test and is not one.
fn digest(dir: &Path) -> String {
    content_fingerprint(dir, &FingerprintOptions::default())
        .unwrap_or_else(|error| panic!("cannot fingerprint {}: {error}", dir.display()))
        .digest
}

/// Every file under a directory, as paths relative to it, sorted.
fn files_under(dir: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&current) else {
            continue;
        };
        for entry in entries.filter_map(Result::ok) {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if let Ok(relative) = path.strip_prefix(dir) {
                found.push(relative.to_path_buf());
            }
        }
    }
    found.sort();
    found
}

/// Copy a directory tree.
///
/// No symlinks: the fixtures have none, and a link followed silently would make
/// the copy a different tree from the one that was fingerprinted.
fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to)
        .unwrap_or_else(|error| panic!("cannot create {}: {error}", to.display()));
    for entry in std::fs::read_dir(from)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", from.display()))
        .filter_map(Result::ok)
    {
        let path = entry.path();
        let destination = to.join(entry.file_name());
        if path.is_dir() {
            copy_tree(&path, &destination);
        } else {
            std::fs::copy(&path, &destination).unwrap_or_else(|error| {
                panic!(
                    "cannot copy {} to {}: {error}",
                    path.display(),
                    destination.display()
                )
            });
        }
    }
}

/// A copy of a shipped fixture, outside the fixture, that removes itself.
///
/// Under `target/tmp`, which the repository's `.gitignore` already covers, so a
/// test killed before its cleanup leaves nothing for `git status` to report. The
/// **project** path carries a space and a non-ASCII character, which is the
/// discipline `CLAUDE.md` asks for and `rust_checks.rs` established: a rule that
/// happens to work on ordinary paths should fail here rather than on a user's.
///
/// The build directory is a separate, ASCII path. `rustc` writes its scratch
/// objects there, and the GNU linker this fork is built with on Windows cannot
/// open objects under a non-ASCII path (measured: the same project builds with
/// an ASCII `CARGO_TARGET_DIR` and fails with a Chinese one). The project path
/// — what SURE reads, fingerprints and starts the commands in — is still the
/// Unicode one, so the product behaviour under test is unchanged; only the
/// compiler's own scratch output moved.
struct CopyOfFixture {
    shipped: PathBuf,
    copy: PathBuf,
    build: PathBuf,
}

impl CopyOfFixture {
    fn of(id: &str) -> Self {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let shipped = shipped(id);
        assert!(
            shipped.is_dir(),
            "{} is not a directory, so this fixture is not a shipped artefact",
            shipped.display()
        );

        let unique = format!(
            "{id}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        );
        let copy = sure_testkit::repository_root()
            .join("target")
            .join("tmp")
            .join("sure 指纹 rust-fixture")
            .join(&unique);
        let build = sure_testkit::repository_root()
            .join("target")
            .join("tmp")
            .join("sure-rust-target")
            .join(&unique);
        let _ = std::fs::remove_dir_all(&copy);
        let _ = std::fs::remove_dir_all(&build);
        std::fs::create_dir_all(&copy)
            .unwrap_or_else(|error| panic!("cannot create {}: {error}", copy.display()));
        std::fs::create_dir_all(&build)
            .unwrap_or_else(|error| panic!("cannot create {}: {error}", build.display()));
        copy_tree(&shipped, &copy);
        Self {
            shipped,
            copy,
            build,
        }
    }

    fn path(&self) -> &Path {
        &self.copy
    }

    fn build_path(&self) -> &Path {
        &self.build
    }

    fn shipped_path(&self) -> &Path {
        &self.shipped
    }

    /// SURE's own content fingerprint of the shipped fixture.
    fn shipped_digest(&self) -> String {
        digest(&self.shipped)
    }

    /// The same, of the copy. Taken before anything runs, so the copy is still
    /// the project rather than the project plus a build directory.
    fn copy_digest(&self) -> String {
        digest(&self.copy)
    }
}

impl Drop for CopyOfFixture {
    fn drop(&mut self) {
        // Failing to clean up must not turn a passing test into a failing one.
        drop(std::fs::remove_dir_all(&self.copy));
        drop(std::fs::remove_dir_all(&self.build));
    }
}

/// The command a check declared, as the one `String` the schedule carries.
fn declared_command(proposal: &CheckProposal) -> String {
    match proposal.reason() {
        CheckReason::DeclaredCommand { command, .. } => command.clone(),
        other => panic!("{} has the reason {other:?}", proposal.title()),
    }
}

/// A request to run one declared command on a copy.
///
/// **The split lives here and belongs to the runner that does not exist yet.**
/// See the module documentation. It is safe in this file for one reason, and the
/// reason is asserted rather than assumed: the string is SURE's own, built from
/// a [`CommandRole`](sure_core::discover::rust::CommandRole)'s row, and not text
/// a project wrote.
fn request(working_directory: &Path, build_directory: &Path, command: &str) -> ProcessRequest {
    let mut parts = command.split_whitespace();
    let program = parts
        .next()
        .unwrap_or_else(|| panic!("`{command}` names no program"));
    assert_eq!(
        program, "cargo",
        "`{command}` is not a cargo command, and this fixture's checks are cargo's own"
    );
    ProcessRequest::new(
        program.to_owned(),
        working_directory,
        LIMITS,
        Cancellation::new(),
    )
    .with_arguments(parts.map(str::to_owned))
    .with_environment(Environment::inherited().with("CARGO_TARGET_DIR", build_directory))
}

/// What one check found, from the process that ran it.
///
/// The three non-exit terminations are `errored` rather than failed: a run SURE
/// stopped, or one that never started, is not evidence about the project, and
/// reporting it as a failure of the project's would be this file inventing a
/// fact about code it never observed.
fn result_of(proposal: &CheckProposal, outcome: &Outcome, state: &FingerprintId) -> CheckResult {
    let id = proposal.id().clone();
    let title = proposal.title().to_owned();
    let severity = proposal.severity();
    let critical = proposal.critical();
    let class = proposal.evidence_class();
    match outcome.termination() {
        Termination::Exited { code: Some(0) } => {
            CheckResult::pass(id, title, severity, critical, class, state.clone())
        }
        Termination::Exited { code } => {
            CheckResult::fail(id, title, severity, critical, class, state.clone()).with_reason(
                match code {
                    Some(code) => format!("the command exited with code {code}"),
                    None => {
                        "the command was ended by a signal, so there is no exit code".to_owned()
                    }
                },
            )
        }
        Termination::TimedOut { .. } => CheckResult::errored(
            id,
            title,
            severity,
            critical,
            "the command was stopped because it passed its deadline",
            state.clone(),
        ),
        Termination::Cancelled { .. } | Termination::CancelledBeforeStart => CheckResult::errored(
            id,
            title,
            severity,
            critical,
            "the command was cancelled",
            state.clone(),
        ),
    }
}

/// One check as the run saw it: what it declared, and what came back.
struct Ran {
    command: String,
    output: String,
}

/// Everything one run of one fixture produced.
struct Run {
    schedule: CheckSchedule,
    results: Vec<CheckResult>,
    report: RunReport,
    ran: Vec<Ran>,
    state: FingerprintId,
    summary: String,
}

impl Run {
    /// The result for the check that ran `command`.
    fn result_for(&self, command: &str) -> &CheckResult {
        let index = self.index_of(command);
        &self.results[index]
    }

    /// What a check wrote, for a reader of a failure.
    fn output_of(&self, command: &str) -> &str {
        &self.ran[self.index_of(command)].output
    }

    /// How a critical check contributed, in the domain's own vocabulary.
    fn state_of(&self, command: &str) -> CriticalState {
        let id = &self.result_for(command).id;
        self.report
            .critical()
            .iter()
            .find(|check| check.id() == id)
            .unwrap_or_else(|| panic!("`{command}` is not a critical check of this run"))
            .state()
    }

    fn index_of(&self, command: &str) -> usize {
        self.ran
            .iter()
            .position(|ran| ran.command == command)
            .unwrap_or_else(|| {
                panic!(
                    "no check ran `{command}`; this run ran {:?}",
                    self.ran.iter().map(|ran| &ran.command).collect::<Vec<_>>()
                )
            })
    }
}

/// Discover the copy, propose the four checks, run them with SURE's own runner,
/// aggregate the results, and render the verdict a person would read.
fn run_the_checks(copy: &CopyOfFixture) -> Run {
    // The copy must be the shipped project before anything is measured about it,
    // and the assertion is here rather than in one test so that every claim below
    // that says "this fixture is X" is a claim about the shipped artefact.
    assert_eq!(
        copy.copy_digest(),
        copy.shipped_digest(),
        "the copy is not the shipped fixture, so nothing below is about the fixture"
    );

    let found = discover(copy.path(), &DiscoverOptions::default())
        .unwrap_or_else(|error| panic!("discovery failed on {}: {error}", copy.path().display()));
    let report = found.report(Ecosystem::Rust).unwrap_or_else(|| {
        panic!(
            "{} is a Rust project and discovery did not report one; it looked for {:?}",
            copy.path().display(),
            found
                .looked_for()
                .iter()
                .map(|ecosystem| ecosystem.as_str())
                .collect::<Vec<_>>()
        )
    });
    let Findings::Rust(rust) = &report.findings else {
        panic!("the Rust report carried {:?} findings", report.findings);
    };
    let checks = RustChecks::of(rust, copy.path());

    assert_eq!(
        checks.component(),
        Some(MANIFEST),
        "the fixture's checks are not the root manifest's"
    );
    assert!(
        checks.missing().is_empty(),
        "both halves ship rustfmt.toml and clippy.toml, so no check may be missing: {:?}",
        checks.missing()
    );
    assert_eq!(
        checks.planned().len(),
        4,
        "a project that asks for both tools gets the four checks: {:?}",
        checks
            .planned()
            .iter()
            .map(PlannedWork::proposal)
            .map(|proposal| proposal.title())
            .collect::<Vec<_>>()
    );

    let mut builder = PlanBuilder::new(ExecutionMode::HostConfirmed, host_confirmed());
    checks.add_to(&mut builder);
    assert!(
        builder.refused().is_empty(),
        "the checks layer proposed something the builder refused: {:?}",
        builder.refused()
    );
    let schedule = builder.build();
    assert_eq!(
        schedule.may_run().count(),
        4,
        "a host-confirmed run with the permission granted must be allowed to run all four checks"
    );

    // Taken before anything runs, so the state the results are bound to is the
    // project rather than the project plus its build output.
    let state = project_fingerprint(copy.path(), &FingerprintOptions::default())
        .unwrap_or_else(|error| panic!("cannot fingerprint {}: {error}", copy.path().display()))
        .id;
    let build_directory = copy.build_path().to_path_buf();

    let mut results = Vec::new();
    let mut ran = Vec::new();
    for scheduled in schedule.may_run() {
        let proposal = scheduled.proposal();
        let command = declared_command(proposal);
        let outcome = run(&request(copy.path(), &build_directory, &command))
            .unwrap_or_else(|error| panic!("`{command}` could not be started: {error}"));
        let output = format!(
            "{}{}",
            outcome.stdout().text_lossy(),
            outcome.stderr().text_lossy()
        );
        results.push(result_of(proposal, &outcome, &state));
        ran.push(Ran { command, output });
    }

    let report = aggregate_run(&schedule, &results, &[], &state)
        .unwrap_or_else(|refusal| panic!("the run was refused: {refusal:?}"));

    let verdict = build_verdict(
        state.clone(),
        report.aggregate().clone(),
        ProjectIntent::empty(),
        CapabilityReport::cli(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
    );
    let summary = render_summary(&verdict);

    Run {
        schedule,
        results,
        report,
        ran,
        state,
        summary,
    }
}

/// The commands a run really started, sorted.
///
/// Sorted rather than in the plan's order: the plan lists the checks that matter
/// most first, which is the schedule module's decision, and what this file holds
/// is the *set* of four commands the acceptance names.
fn commands_ran(run: &Run) -> Vec<String> {
    let mut commands: Vec<String> = run.ran.iter().map(|ran| ran.command.clone()).collect();
    commands.sort();
    commands
}

/// [`THE_FOUR`], in the same fixed order as [`commands_ran`].
fn expected_commands() -> Vec<String> {
    let mut expected: Vec<String> = THE_FOUR
        .iter()
        .map(|command| (*command).to_owned())
        .collect();
    expected.sort();
    expected
}

/// Host-confirmed, with the permission actually granted.
fn host_confirmed() -> ExecutionPermissions {
    ExecutionPermissions {
        run_project_code: true,
        ..ExecutionPermissions::inspect_only()
    }
}

#[test]
fn the_pair_is_the_same_project_apart_from_one_line() {
    // The claim the pass half's existence rests on. If the halves differed in
    // the manifest or in the source around the defect, a green control would say
    // nothing about the failing half and a red failing half would say nothing
    // about the control.
    let failing = shipped(FAILING);
    let passing = shipped(PASSING);

    assert_eq!(
        files_under(&failing),
        files_under(&passing),
        "the two halves do not even ship the same files"
    );

    for relative in PROJECT_FILES {
        let left = std::fs::read(failing.join(relative))
            .unwrap_or_else(|error| panic!("cannot read {relative} of the failing half: {error}"));
        let right = std::fs::read(passing.join(relative))
            .unwrap_or_else(|error| panic!("cannot read {relative} of the passing half: {error}"));
        assert_eq!(
            left, right,
            "{relative} differs between the halves, and it is not the line that is meant to"
        );
    }

    let failing_source = std::fs::read_to_string(failing.join("src").join("lib.rs")).unwrap();
    let passing_source = std::fs::read_to_string(passing.join("src").join("lib.rs")).unwrap();
    let failing_lines: Vec<&str> = failing_source.lines().collect();
    let passing_lines: Vec<&str> = passing_source.lines().collect();
    assert_eq!(
        failing_lines.len(),
        passing_lines.len(),
        "the two lib.rs files are not the same length, so they differ by more than one line"
    );

    let differing: Vec<usize> = (0..failing_lines.len())
        .filter(|index| failing_lines[*index] != passing_lines[*index])
        .collect();
    assert_eq!(
        differing.len(),
        1,
        "the halves' lib.rs files differ on {} lines rather than one: {:?}",
        differing.len(),
        differing
            .iter()
            .map(|index| (failing_lines[*index], passing_lines[*index]))
            .collect::<Vec<_>>()
    );
    let line = differing[0];
    assert_eq!(failing_lines[line].trim(), ADDING, "line {line}");
    assert_eq!(passing_lines[line].trim(), SUBTRACTING, "line {line}");

    // And the files that do differ, differ for a reason: each half has to say
    // which half it is, which is why these three are named in both READMEs.
    for relative in HALF_SPECIFIC_FILES {
        let left = std::fs::read_to_string(failing.join(relative)).unwrap();
        let right = std::fs::read_to_string(passing.join(relative)).unwrap();
        assert_ne!(
            left, right,
            "{relative} is byte for byte the same in both halves, so neither says which half it is"
        );
    }
}

#[test]
fn neither_half_is_a_member_of_this_workspace() {
    // A deliberately failing project inside the workspace's member list would be
    // built and run by `cargo test --workspace`, and the checkout's own suite
    // would then fail because a fixture is doing its job.
    let manifest = std::fs::read_to_string(sure_testkit::repository_root().join("Cargo.toml"))
        .expect("the root manifest is readable");

    let members_start = manifest
        .find("members = [")
        .expect("the root manifest declares its members explicitly");
    let members_end = manifest[members_start..]
        .find(']')
        .map(|offset| members_start + offset)
        .expect("the members array is terminated");
    let members = &manifest[members_start..members_end];

    assert!(
        !members.contains("fixtures"),
        "the root manifest's members list reaches into fixtures/, which it must not:\n{members}"
    );

    for id in [FAILING, PASSING] {
        let fixture = std::fs::read_to_string(shipped(id).join("Cargo.toml")).unwrap();
        assert!(
            !members.contains(id) && !members.contains("sure-fixture-rust-order"),
            "{id} is named in the workspace's members, so `cargo test --workspace` would build it"
        );
        // The other answer `cargo` offers, and the one both halves take: a
        // package that is its own workspace root. Without it `cargo` refuses to
        // build a package sitting under another manifest's directory.
        assert!(
            fixture.lines().any(|line| line.trim() == "[workspace]"),
            "{id} does not declare itself a workspace of its own"
        );
        assert!(
            fixture.contains("sure-fixture-rust-order"),
            "{id}'s manifest does not name the package this test expects"
        );
    }
}

#[test]
fn the_failing_half_fails_only_the_test_check_and_is_not_ready() {
    let copy = CopyOfFixture::of(FAILING);
    let run = run_the_checks(&copy);

    // The four commands the acceptance names, and each of them really ran — so
    // nothing below is about a schedule that was built and not used. The order
    // is not asserted: the plan puts the checks that matter most first, which is
    // the schedule module's decision, and a test here that restated the plan's
    // order would be a second place for it to be written down.
    assert_eq!(commands_ran(&run), expected_commands(), "{THE_FOUR:?}");

    // The three commands that pass, asserted as passing — because without this
    // half of the claim a reader could take the failing verdict as a statement
    // about whether the project builds.
    //
    // Only the test check is critical in the checks layer's own four-row table —
    // the other three are a note, a "can fix later" and a "should fix first" —
    // so they do not appear in `RunReport::critical` and their passing is read
    // from the results this run produced.
    for command in &THE_FOUR[..3] {
        let result = run.result_for(command);
        assert_eq!(
            result.status,
            CheckStatus::Pass,
            "{command} did not pass on {}:\n{}",
            copy.shipped_path().display(),
            run.output_of(command)
        );
        assert!(!result.critical, "{command} is not a critical check");
        assert!(!result.blocks_green(), "{command}");
    }

    let test_result = run.result_for("cargo test");
    assert_eq!(
        test_result.status,
        CheckStatus::Fail,
        "the fixture's own tests did not fail:\n{}",
        run.output_of("cargo test")
    );
    assert_eq!(run.state_of("cargo test"), CriticalState::Failed);
    assert!(
        test_result.blocks_green(),
        "the failing test check does not stop a green verdict"
    );

    // The failure is the fixture's own defect and not this machine's: the output
    // names the test the defect breaks, and the result says how it failed.
    let output = run.output_of("cargo test");
    assert!(
        !output.trim().is_empty(),
        "cargo test produced no output at all, so it did not run"
    );
    assert!(
        output.contains("a_discount_comes_off_the_subtotal"),
        "cargo test failed for a reason this fixture does not claim:\n{output}"
    );
    assert!(
        test_result.reason.contains("exited with code"),
        "the failing check does not say how it failed: {:?}",
        test_result.reason
    );

    // The run's own verdict.
    assert!(
        !run.report.is_green(),
        "a failing check aggregated to green"
    );
    assert_eq!(
        run.report.aggregate().severity,
        AggregateSeverity::NotReady,
        "{:?}",
        run.report.plain_description()
    );
    assert_eq!(
        run.report.aggregate().headline,
        "This is not ready to hand off yet."
    );
    assert_eq!(
        run.report.skipped().count(),
        0,
        "a skipped check would leave the run short of green for the wrong reason"
    );
    assert_eq!(run.report.errored().count(), 0);
    assert_eq!(run.report.unknown().count(), 0);
    assert!(
        run.report.unreported().is_empty(),
        "checks were scheduled and reported nothing: {:?}",
        run.report.unreported()
    );
    let blocking: Vec<&str> = run.report.blocking().map(|check| check.title()).collect();
    assert_eq!(
        blocking,
        vec!["run the tests"],
        "the blocking check is not the one that failed: {:?}",
        run.report.plain_description()
    );
    assert_eq!(
        run.report.critical().len(),
        1,
        "the test check is the one critical row of the four, and the run reported {:?}",
        run.report
            .critical()
            .iter()
            .map(|check| check.title())
            .collect::<Vec<_>>()
    );
    assert_eq!(run.results.len(), 4, "the run did not visit four checks");
    assert!(
        run.report
            .plain_description()
            .iter()
            .any(|line| line.contains("run the tests") && line.contains("failed")),
        "{:?}",
        run.report.plain_description()
    );

    // The sentence a person reads.
    assert!(
        run.summary.contains("This is not ready to hand off yet."),
        "summary: {}",
        run.summary
    );
    assert!(
        run.summary
            .contains("This project is not ready to hand off."),
        "summary: {}",
        run.summary
    );
    assert!(
        !run.summary
            .contains("This project looks ready to hand off."),
        "summary: {}",
        run.summary
    );

    // Every result names the state the verdict is about, and the plan is read
    // back rather than built and forgotten.
    for result in &run.results {
        assert_eq!(result.project_fingerprint, run.state);
    }
    assert_eq!(run.schedule.len(), 4);

    // And the run left the shipped fixture alone: cargo wrote into the copy,
    // which is what keeps `git status` clean.
    assert!(
        !copy.shipped_path().join("Cargo.lock").exists(),
        "a Cargo.lock appeared in the shipped fixture"
    );
    assert!(
        !copy.shipped_path().join("target").exists()
            && !copy.shipped_path().join("cargo-target").exists(),
        "a build directory appeared in the shipped fixture"
    );
    assert!(
        copy.build_path().is_dir(),
        "cargo wrote nothing to the build directory, so the run cannot be the one that was measured"
    );
    assert!(
        !copy.path().join("cargo-target").exists() && !copy.path().join("target").exists(),
        "cargo wrote build output into the project copy"
    );
}

#[test]
fn the_passing_half_passes_every_check_and_is_green() {
    let copy = CopyOfFixture::of(PASSING);
    let run = run_the_checks(&copy);

    assert_eq!(commands_ran(&run), expected_commands(), "{THE_FOUR:?}");

    for command in THE_FOUR {
        let result = run.result_for(command);
        assert_eq!(
            result.status,
            CheckStatus::Pass,
            "{command} did not pass on the control half:\n{}",
            run.output_of(command)
        );
        assert!(result.reason.is_empty(), "{command}: {:?}", result.reason);
    }
    assert_eq!(
        run.state_of("cargo test"),
        CriticalState::Passed,
        "the control half's critical check did not come back passed"
    );

    // The fixture's own check really ran: what a project's test run writes is
    // the one thing a stand-in could not have produced.
    assert!(
        run.output_of("cargo test").contains("test result: ok"),
        "the control half's tests did not report a result:\n{}",
        run.output_of("cargo test")
    );

    assert!(
        run.report.is_green(),
        "the control half did not come back green: {:?}",
        run.report.plain_description()
    );
    assert_eq!(run.report.aggregate().severity, AggregateSeverity::Green);
    assert_eq!(
        run.report.aggregate().headline,
        "Everything that could be checked passed."
    );
    assert_eq!(
        run.report.blocking().count(),
        0,
        "{:?}",
        run.report.plain_description()
    );
    assert_eq!(run.report.skipped().count(), 0);
    assert_eq!(run.report.errored().count(), 0);
    assert_eq!(run.report.unknown().count(), 0);
    assert!(run.report.unreported().is_empty());
    assert_eq!(run.report.critical().len(), 1);
    assert_eq!(run.results.len(), 4);

    assert!(
        run.summary
            .contains("This project looks ready to hand off."),
        "summary: {}",
        run.summary
    );
    assert!(
        !run.summary
            .contains("This project is not ready to hand off."),
        "summary: {}",
        run.summary
    );

    for result in &run.results {
        assert_eq!(result.project_fingerprint, run.state);
    }

    assert!(
        !copy.shipped_path().join("Cargo.lock").exists()
            && !copy.shipped_path().join("target").exists()
            && !copy.shipped_path().join("cargo-target").exists(),
        "the run wrote into the shipped fixture"
    );
}

#[test]
fn the_two_halves_are_different_projects_by_content() {
    // The one-line difference has to be visible to SURE's own fingerprint, or a
    // verdict produced for one half would be evidence about the other. These are
    // content fingerprints — both directories sit inside this repository — so
    // the digest is of the files and not of the paths.
    let failing = digest(&shipped(FAILING));
    let passing = digest(&shipped(PASSING));
    assert_ne!(
        failing, passing,
        "the two halves share a content digest, so the pair is one project"
    );

    // And each half's digest is stable across two independent readings, which is
    // what makes a result from one run findable in the next.
    assert_eq!(failing, digest(&shipped(FAILING)));
    assert_eq!(passing, digest(&shipped(PASSING)));
}
