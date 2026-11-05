//! `P14-T009`'s acceptance, checked by repairing the fixture and re-running its
//! own checks.
//!
//! The task's sentence is one sentence, and it has two halves:
//!
//! > *Repair can close only with new passing evidence; regression variant
//! > blocked.*
//!
//! # What makes this file different from `repair_regression_guard.rs`
//!
//! `crates/sure-core/tests/repair_regression_guard.rs` already asserts both
//! halves, with `CheckResult`s built by hand. That is the right shape for a test
//! about the decision rule, and it is not evidence that anything can be
//! repaired: a result someone typed is a claim, not a measurement.
//!
//! Here the evidence is **real**:
//!
//! - [`discover`] reads `fixtures/adversarial/repair-regression` from the
//!   `package.json` on disk;
//! - [`NodeChecks`] turns the two members' declared `test` scripts into the two
//!   checks the plan holds;
//! - [`sure_core::process::run`] — the one place in this workspace that starts a
//!   program — runs each of them against a copy of the project, and each
//!   process's own exit code is what becomes its [`CheckResult`];
//! - a repair is applied **by writing the corrected bytes into the copy**, so
//!   the second run is over a project that is a different project;
//! - [`seed_rechecks`] reads the failing check off the finding's own anchor, so
//!   this file supplies no re-check list of its own;
//! - [`select_impacted_checks`] chooses what has to pass before the finding may
//!   close — and the check that catches the regression is chosen by *it*, not by
//!   this file;
//! - [`reconcile`] makes the decision, and [`aggregate_run`] with
//!   [`build_verdict`] and [`render_summary`] say what the run may claim.
//!
//! # Which re-check list this file supplies, since `P7-T012`
//!
//! None. The list is [`seed_rechecks`]'s answer, read off the finding's own
//! anchor, and it reaches [`RepairContract::from_finding`] the same way it does
//! from the live path — `crates/sure-core/src/pipeline.rs` seeds every contract
//! with that one function, so a rule that stopped reading a finding's anchor
//! would redden here as well as there. The refusal that function's caller has to
//! satisfy is untouched: `from_finding` still rejects an empty list, so a finding
//! nothing can observe is a contract nobody can write rather than one that closes
//! on nothing.
//!
//! So the failing check reaches the contract through the product's own rule
//! rather than through a literal here, and **every other** check that joins it is
//! selected by the product. The second half of this file's claim is exactly that
//! the check which catches the regression gets in that way.
//!
//! # What the binary does with this fixture, measured and not asserted here
//!
//! `sure check <copy of this fixture>` plans three checks and, under the default
//! mode, reports all three as not checked:
//!
//! ```text
//! 3 check(s) could not run or were skipped. 3 of them are critical.
//!   (start the project, run the tests in packages/billing, run the tests in packages/checkout)
//!   - run the tests in packages/checkout  (Checking this would have meant running
//!     your project's code, and you have not allowed that.) [critical]
//! ```
//!
//! Two of those three are this fixture's checks. The third is the probe
//! `crate::runtime_probes` builds from the root `start` script, and it is not in
//! this file's plan for a reason the selection rule states itself:
//! `crates/sure-core/src/repair_impact.rs` asks for a `DeterministicCheck`
//! before a check can be a regression check, and a probe's evidence class is
//! `ObservedFact` — so no plan this fixture can produce will ever add the probe
//! to a re-check list. What the binary does with the fixture is recorded in
//! `fixtures/adversarial/repair-regression/README.md` and in its `scenario.json`
//! rather than asserted here, because a process-level `sure check` is
//! `crates/sure-cli/tests/cli_contract.rs`'s subject and this file's subject is
//! the lifecycle.
//!
//! # What this file does not do
//!
//! It does not run the shipped directory, and it does not write to it: every run
//! happens on a copy under `target/tmp`, taken through SURE's own content
//! fingerprint and asserted equal to the shipped directory before anything
//! happens to it. It opens no store, so `sure.db` on this machine is untouched.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use sure_core::aggregation::{RunReport, aggregate_run};
use sure_core::checks::node::NodeChecks;
use sure_core::discover::node::{MANIFEST, NodeProject, ScriptRole};
use sure_core::discover::{DiscoverOptions, Ecosystem, Findings, discover};
use sure_core::fingerprint::{FingerprintOptions, content_fingerprint, project_fingerprint};
use sure_core::paths::CaseSensitivity;
use sure_core::planned_work::PlannedWork;
use sure_core::process::{
    Cancellation, Environment, Limits, Outcome, ProcessRequest, Termination, run,
};
use sure_core::project_verdict::{build_verdict, render_summary};
use sure_core::recheck_lifecycle::{FindingKey, LifecycleInputs, reconcile};
use sure_core::repair_impact::{seed_rechecks, select_impacted_checks};
use sure_core::schedule::{CheckProposal, CheckReason, CheckSchedule, PlanBuilder};
use sure_domain::capability::CapabilityReport;
use sure_domain::evidence::{AnchorSubject, Evidence, EvidenceAnchor, EvidenceClass};
use sure_domain::execution::{ExecutionMode, ExecutionPermissions};
use sure_domain::finding::{
    AssessmentSource, Finding, FindingBuilder, FindingStatus, SeverityRationale,
};
use sure_domain::ids::{CheckId, FindingId, FingerprintId};
use sure_domain::intent::ProjectIntent;
use sure_domain::severity::Severity;
use sure_domain::status::{AggregateSeverity, CheckResult, CheckStatus};
use sure_domain::vocabulary::RepairContract;

/// The fixture, and the two members whose own checks are this case's evidence.
const FIXTURE: &str = "repair-regression";
const CHECKOUT: &str = "packages/checkout";
const BILLING: &str = "packages/billing";

/// The line `shared/pricing.js` ships, verbatim, and the one line that corrects
/// it.
///
/// Spelled out rather than described, because *the repair is one line in a
/// shared helper and the regression is in the caller it moved under* is the
/// whole arrangement: if the fixture's defect moved, a substitution that still
/// found it would be measuring a different project.
const THE_DEFECT: &str = "  return Math.max(0, total + amount);";
const THE_CORRECTION: &str = "  return Math.max(0, total - amount);";

/// The call in `packages/billing/src/refund.js` that the corrected helper breaks,
/// and the call the complete repair changes it to.
const THE_CALL: &str = "  return less(paidCents, -feeCents);";
const THE_REPAIRED_CALL: &str = "  return less(paidCents, feeCents);";

/// The sentence the failing member's own check prints, which is the defect in
/// the project's own words rather than in this file's.
const CHECKOUT_SAYS: &str = "a discount comes off the basket: expected 750, got 1250";

/// How long a check has, and how much of what it says SURE keeps.
///
/// Generous for what these are: two `node` processes that read three small
/// files each, on a machine that may be compiling the rest of this workspace at
/// the same time. A run that passed its deadline is reported as SURE's own check
/// having failed rather than as a pass, which is why over-provisioning costs
/// nothing here.
const LIMITS: Limits = Limits::new(Duration::from_secs(120), 64 * 1024, 64 * 1024);

/// Which repair is applied to a copy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Repair {
    /// The one line a careless repair stops at: the helper is corrected and the
    /// call that moved under it is left alone.
    Careless,
    /// The helper and the call, which is what the change actually required.
    Complete,
}

impl Repair {
    /// What this repair writes, as the substitutions it makes. Both are asserted
    /// to find the shipped text before they replace it.
    const fn edits(self) -> &'static [(&'static str, &'static str)] {
        match self {
            Self::Careless => &[(THE_DEFECT, THE_CORRECTION)],
            Self::Complete => &[(THE_DEFECT, THE_CORRECTION), (THE_CALL, THE_REPAIRED_CALL)],
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Careless => "the careless repair",
            Self::Complete => "the complete repair",
        }
    }
}

/// The shipped directory of the fixture.
fn shipped() -> PathBuf {
    sure_testkit::repository_root()
        .join("fixtures")
        .join("adversarial")
        .join(FIXTURE)
}

/// The content fingerprint of a directory, as a digest.
///
/// The digest rather than the fingerprint value: a fingerprint carries a freshly
/// generated identity that is unique per computation by design, so two
/// fingerprints of the same bytes are never equal as values and their digests
/// are. Every *new evidence* claim below is a comparison of these, because it is
/// a claim about bytes rather than about two identity values.
fn digest(dir: &Path) -> String {
    content_fingerprint(dir, &FingerprintOptions::default())
        .unwrap_or_else(|error| panic!("cannot fingerprint {}: {error}", dir.display()))
        .digest
}

/// Copy a directory tree. No symlinks: the fixture has none, and a link followed
/// silently would make the copy a different tree from the one fingerprinted.
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

/// A copy of the shipped fixture, outside the fixture, that removes itself.
///
/// Under `target/tmp`, which the repository's `.gitignore` already covers, so a
/// test killed before its cleanup leaves nothing for `git status` to report. The
/// path carries a space and a non-ASCII character, which is the discipline
/// `CLAUDE.md` asks for: a rule that happens to work on ordinary paths should
/// fail here rather than on a user's.
struct CopyOfFixture {
    shipped: PathBuf,
    copy: PathBuf,
}

impl CopyOfFixture {
    fn of() -> Self {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let shipped = shipped();
        assert!(
            shipped.is_dir(),
            "{} is not a directory, so this fixture is not a shipped artefact",
            shipped.display()
        );

        let unique = format!(
            "{FIXTURE}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        );
        let copy = sure_testkit::repository_root()
            .join("target")
            .join("tmp")
            .join("sure 指纹 repair-fixture")
            .join(unique);
        let _ = std::fs::remove_dir_all(&copy);
        std::fs::create_dir_all(&copy)
            .unwrap_or_else(|error| panic!("cannot create {}: {error}", copy.display()));
        copy_tree(&shipped, &copy);

        let taken = Self { shipped, copy };
        assert_eq!(
            digest(taken.path()),
            digest(taken.shipped_path()),
            "the copy is not the shipped fixture, so nothing measured on it is about the fixture"
        );
        taken
    }

    fn path(&self) -> &Path {
        &self.copy
    }

    fn shipped_path(&self) -> &Path {
        &self.shipped
    }

    /// Apply a repair to the copy, one asserted substitution at a time.
    ///
    /// The shipped text has to be found exactly once before it is replaced, so
    /// this is a claim about the fixture rather than a search-and-replace that
    /// would quietly do nothing to a project that had changed.
    fn repair(&self, repair: Repair) {
        for (from, to) in repair.edits() {
            let path = if *from == THE_CALL || *from == THE_REPAIRED_CALL {
                self.path().join(BILLING).join("src").join("refund.js")
            } else {
                self.path().join("shared").join("pricing.js")
            };
            let text = std::fs::read_to_string(&path)
                .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
            assert_eq!(
                text.matches(from).count(),
                1,
                "{} does not hold the line {} is about to replace exactly once, so {} \
                 would be a substitution that measured nothing:\n{text}",
                path.display(),
                from.trim(),
                repair.as_str()
            );
            std::fs::write(&path, text.replace(from, to))
                .unwrap_or_else(|error| panic!("cannot write {}: {error}", path.display()));
        }
    }
}

impl Drop for CopyOfFixture {
    fn drop(&mut self) {
        // Failing to clean up must not turn a passing test into a failing one.
        drop(std::fs::remove_dir_all(&self.copy));
    }
}

/// The command a check declared, as the one `String` the schedule carries.
fn declared_command(proposal: &CheckProposal) -> String {
    match proposal.reason() {
        CheckReason::DeclaredCommand { command, .. } => command.clone(),
        other => panic!("{} has the reason {other:?}", proposal.title()),
    }
}

/// The manifest a check was read from.
fn declared_in(proposal: &CheckProposal) -> String {
    match proposal.reason() {
        CheckReason::DeclaredCommand { declared_in, .. } => declared_in.clone(),
        other => panic!("{} has the reason {other:?}", proposal.title()),
    }
}

/// The fixture member a manifest path belongs to.
///
/// The manifest paths are compared as strings and not as paths on purpose: the
/// discovery writes a member's manifest with `/` on every platform
/// (`sure_core::scan::display_path`), and a test that compared them the way this
/// platform happens to spell a path would be a test that passes on one of the
/// three this workspace runs on.
fn manifest_of(member: &str) -> String {
    format!("{member}/{MANIFEST}")
}

/// A member's own declared test script, read out of SURE's discovery.
///
/// **This is the project's text, and it is used to build a request, so it is
/// asserted before it is used** — see [`request`].
fn member_script<'a>(project: &'a NodeProject, member: &str) -> (&'a Path, &'a str) {
    let found = project
        .workspaces
        .readable_members()
        .find(|candidate| candidate.path.ends_with(member))
        .unwrap_or_else(|| {
            panic!(
                "discovery resolved no member `{member}`; it resolved {:?}",
                project
                    .workspaces
                    .readable_members()
                    .map(|member| member.path.display().to_string())
                    .collect::<Vec<_>>()
            )
        });
    let script = found
        .package
        .as_deref()
        .and_then(|package| package.script(ScriptRole::Test))
        .unwrap_or_else(|| panic!("`{member}` declares no test script"));
    let declared = script.command.as_str();
    assert!(
        declared.starts_with("node "),
        "`{member}` declares the test script `{declared}`, and this file only knows how to run \
         one that starts with `node`"
    );
    (found.path.as_path(), declared)
}

/// A request to run one member's declared check.
///
/// **The composition lives here, and it belongs to the runner that does not
/// exist yet** — the same gap `rust_fixture_apps.rs` records for `cargo`. Two
/// things about this one are measured rather than stylistic:
///
/// - The check's declared command is `npm test`, and `sure_core::process` cannot
///   start a bare `npm` on Windows: `npm` is a `.cmd`, which its own error type
///   says in as many words (`crates/sure-core/src/process/error.rs`). What this
///   function runs is the command `npm test` would run, read out of the member's
///   manifest by SURE's own discovery, and asserted to be a `node` command
///   before it is used. A member that changed its script to something this file
///   cannot run fails here rather than quietly running something else.
/// - The working directory is the member's, because that is what running a
///   script in a workspace member does.
fn request(working_directory: &Path, script: &str) -> (String, ProcessRequest) {
    let mut parts = script.split_whitespace();
    let program = parts
        .next()
        .unwrap_or_else(|| panic!("`{script}` names no program"));
    assert_eq!(program, "node", "`{script}` is not a node command");
    let arguments: Vec<String> = parts.map(str::to_owned).collect();
    let request = ProcessRequest::new(
        program.to_owned(),
        working_directory,
        LIMITS,
        Cancellation::new(),
    )
    .with_arguments(arguments.clone())
    .with_environment(Environment::inherited());
    (
        std::iter::once(program.to_owned())
            .chain(arguments)
            .collect::<Vec<_>>()
            .join(" "),
        request,
    )
}

/// What one check found, from the process that ran it.
///
/// The three non-exit terminations are `errored` rather than failed: a run SURE
/// stopped, or one that never started, is not evidence about the project, and
/// reporting it as a failure of the project's would be this file inventing a
/// fact about code it never observed. `rust_fixture_apps.rs` reads the same
/// three the same way.
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

/// One check as the run saw it: what it declared, the command that really ran,
/// and what that process said.
struct Ran {
    title: String,
    declared: String,
    command: String,
    output: String,
}

/// Everything one run of the fixture produced.
struct Run {
    schedule: CheckSchedule,
    results: Vec<CheckResult>,
    report: RunReport,
    summary: String,
    state: FingerprintId,
    ran: Vec<Ran>,
    checkout: CheckId,
    billing: CheckId,
}

impl Run {
    fn result(&self, id: &CheckId) -> &CheckResult {
        self.results
            .iter()
            .find(|result| result.id == *id)
            .unwrap_or_else(|| panic!("no result for {id}"))
    }

    /// What a check's own process wrote, for a reader of a failure.
    fn output_of(&self, id: &CheckId) -> &str {
        self.ran
            .iter()
            .find(|ran| ran.title == self.result(id).title)
            .map(|ran| ran.output.as_str())
            .unwrap_or_else(|| panic!("no process ran {id}"))
    }

    /// The command that really ran for a check.
    fn command_of(&self, id: &CheckId) -> &str {
        self.ran
            .iter()
            .find(|ran| ran.title == self.result(id).title)
            .map(|ran| ran.command.as_str())
            .unwrap_or_else(|| panic!("no process ran {id}"))
    }
}

/// Discover the copy, propose the members' declared checks, run them with SURE's
/// own runner, aggregate the results, and render the verdict a person would read.
fn run_the_checks(copy: &CopyOfFixture) -> Run {
    // No `copy == shipped` assertion here, and that is deliberate:
    // `CopyOfFixture::of` takes that reading before anything can change the copy,
    // and one of the runs below is over a copy that has *deliberately* stopped
    // being the shipped project. Restating the equality here would make the
    // repair itself a red test.
    let found = discover(copy.path(), &DiscoverOptions::default())
        .unwrap_or_else(|error| panic!("discovery failed on {}: {error}", copy.path().display()));
    let report = found.report(Ecosystem::Node).unwrap_or_else(|| {
        panic!(
            "{} is a Node project and discovery did not report one; it looked for {:?}",
            copy.path().display(),
            found
                .looked_for()
                .iter()
                .map(|ecosystem| ecosystem.as_str())
                .collect::<Vec<_>>()
        )
    });
    let Findings::Node(node) = &report.findings else {
        panic!("the Node report carried {:?} findings", report.findings);
    };

    let checks = NodeChecks::of(node, copy.path());
    let proposed: Vec<&CheckProposal> = checks
        .planned()
        .iter()
        .map(PlannedWork::proposal)
        .filter(|proposal| {
            let manifest = declared_in(proposal);
            manifest == manifest_of(CHECKOUT) || manifest == manifest_of(BILLING)
        })
        .collect();
    assert_eq!(
        proposed.len(),
        2,
        "the fixture's two members each declare one test script, so the checks layer proposes \
         two checks for them: {:?}",
        checks
            .planned()
            .iter()
            .map(|work| (
                declared_in(work.proposal()),
                work.proposal().title().to_owned()
            ))
            .collect::<Vec<_>>()
    );
    for proposal in &proposed {
        assert_eq!(
            declared_command(proposal),
            "npm test",
            "{} is a `test` script and the manager the project names is npm",
            proposal.title()
        );
        assert_eq!(
            proposal.severity(),
            Severity::MustFix,
            "{}",
            proposal.title()
        );
        assert!(proposal.critical(), "{}", proposal.title());
        assert_eq!(
            proposal.evidence_class(),
            EvidenceClass::DeterministicCheck,
            "{}",
            proposal.title()
        );
        assert!(
            proposal.requirements().runs_project_code(),
            "{}",
            proposal.title()
        );
    }

    // The four roles the checks layer knows about, times the three readable
    // manifests, minus the two test scripts the fixture declares. None of these
    // is a plan entry — a role with no command proposes nothing — which is why
    // they are not in this run's results either.
    assert_eq!(
        checks.missing().len(),
        10,
        "{:?}",
        checks
            .missing()
            .iter()
            .map(|missing| (missing.title().to_owned(), missing.kind()))
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
        2,
        "a host-confirmed run with the permission granted must be allowed to run both member \
         checks; the plan holds {} entries",
        schedule.len()
    );

    // Taken before anything runs, so the state the results are bound to is the
    // project rather than the project plus anything a check left behind.
    let state = project_fingerprint(copy.path(), &FingerprintOptions::default())
        .unwrap_or_else(|error| panic!("cannot fingerprint {}: {error}", copy.path().display()))
        .id;

    let mut results = Vec::new();
    let mut ran = Vec::new();
    for scheduled in schedule.may_run() {
        let proposal = scheduled.proposal();
        let member = if declared_in(proposal) == manifest_of(CHECKOUT) {
            CHECKOUT
        } else {
            BILLING
        };
        let (member_path, script) = member_script(node, member);
        let (command, request) = request(&copy.path().join(member_path), script);
        let outcome = run(&request)
            .unwrap_or_else(|error| panic!("`{command}` could not be started: {error}"));
        let output = format!(
            "{}{}",
            outcome.stdout().text_lossy(),
            outcome.stderr().text_lossy()
        );
        results.push(result_of(proposal, &outcome, &state));
        ran.push(Ran {
            title: proposal.title().to_owned(),
            declared: declared_command(proposal),
            command,
            output,
        });
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

    let id_for = |member: &str| {
        proposed
            .iter()
            .find(|proposal| declared_in(proposal) == manifest_of(member))
            .map(|proposal| proposal.id().clone())
            .unwrap_or_else(|| panic!("no check for {member}"))
    };

    Run {
        schedule,
        results,
        report,
        summary,
        state,
        ran,
        checkout: id_for(CHECKOUT),
        billing: id_for(BILLING),
    }
}

/// Host-confirmed, with the permission actually granted.
fn host_confirmed() -> ExecutionPermissions {
    ExecutionPermissions {
        run_project_code: true,
        ..ExecutionPermissions::inspect_only()
    }
}

/// The finding the repair is about, built from the run that found it.
///
/// Every field that the run has an answer for is taken from the run: the
/// severity, the evidence class and the project state come off the failing
/// check's own result, so a fixture whose check stopped being `must_fix` would
/// be a red test here rather than a finding that quietly changed weight.
///
/// The anchor is this file's for *where it points* — the file the defect is in —
/// and the failing check's own identity for *what can observe it*. It is
/// deliberately **not** a manifest path: a check's own anchor is the manifest it
/// was declared in (`CheckReason::DeclaredCommand`), and a finding anchored
/// there would overlap both members' checks and make every selection an
/// *affected* one. The claim this file finishes with is about the *regression*
/// rule, which is the one that reaches a check nothing points at.
///
/// The two halves are separate fields and they do not interfere:
/// `repair_impact`'s overlap test reads the location and the locator, and its
/// seed reads the subject id. Adding the id moves nothing a reader follows and
/// changes no overlap — it is what lets [`seed_rechecks`] answer *which check can
/// observe whether this is fixed* without this file answering it by hand.
fn the_finding(run: &Run) -> Finding {
    let result = run.result(&run.checkout);
    assert_eq!(
        result.status,
        CheckStatus::Fail,
        "the finding is built from a check that failed, and {} did not",
        result.title
    );
    let rationale = SeverityRationale::for_severity(result.severity)
        .unwrap_or_else(|| panic!("{:?} has no rationale", result.severity));
    FindingBuilder::new(AssessmentSource::DeterministicCheck, rationale)
        .id(FindingId::generate())
        .title("the basket total adds the discount instead of taking it off")
        .severity(result.severity)
        .status(FindingStatus::Open)
        .explanation(
            "the shared `less` helper adds the amount it is given instead of taking it off, so a \
             discounted basket is charged more than an undiscounted one",
        )
        .user_impact("a customer with a discount code is charged more than one without")
        .next_step("make `less` subtract the amount it is given")
        .fingerprint(result.project_fingerprint.clone())
        .evidence(vec![Evidence::new(
            result.evidence_class,
            "the project's own check for the basket total fails",
            EvidenceAnchor::new(AnchorSubject::File, CHECKOUT, "totalCents")
                .with_subject_id(run.checkout.clone()),
            Some(result.project_fingerprint.clone()),
            result.severity,
        )])
        .build()
        .expect("the finding has a title, a severity and a fingerprint")
}

/// The contract the repair is made under, and the checks that must pass before
/// the finding may close.
///
/// **The contract names one check and the product adds the rest.** That sentence
/// is the whole of the second half of this file, and it is why this function
/// returns both values rather than just the selection: a test that only saw the
/// selection could not tell a check that was named from one that was found.
///
/// The one check is named by the product too. It comes from [`seed_rechecks`]
/// reading the finding's own anchor rather than from a literal here, so a fixture
/// whose finding stopped pointing at the failing check would fail at this line
/// instead of going on naming the right check by hand.
fn contract_and_selection(run: &Run, finding: &Finding) -> (RepairContract, Vec<CheckId>) {
    let seeded = seed_rechecks(finding, &run.schedule);
    let contract = RepairContract::from_finding(finding, seeded)
        .expect("the finding is grounded and its anchor names a check in this schedule");
    let selected = select_impacted_checks(&contract, &run.schedule);
    (contract, selected)
}

/// Why the billing check can be selected as a regression check at all.
///
/// Read off the proposal rather than restated from the rule's documentation: the
/// three properties below are exactly what
/// `crates/sure-core/src/repair_impact.rs` asks for before a check it was not
/// told about may join a re-check list.
fn assert_is_a_regression_check(run: &Run) {
    let scheduled = run
        .schedule
        .get(&run.billing)
        .expect("the billing check is in the plan");
    let proposal = scheduled.proposal();
    assert!(
        proposal.requirements().runs_project_code(),
        "a check that does not run the project's code cannot catch a side effect of a repair"
    );
    assert_eq!(proposal.evidence_class(), EvidenceClass::DeterministicCheck);
    assert!(
        matches!(
            proposal.severity(),
            Severity::MustFix | Severity::ShouldFixFirst
        ),
        "the regression rule excludes notes, and this check is {:?}",
        proposal.severity()
    );
}

// --- the fixture as shipped ----------------------------------------------

#[test]
fn the_shipped_fixture_fails_its_own_check_and_its_other_member_passes() {
    // The project the case is about, measured before either repair: one member's
    // own check fails, the other's passes. Both halves of the repair claim below
    // start from this, and a fixture whose shipped state stopped being this would
    // make them claims about nothing.
    let run = run_the_checks(&CopyOfFixture::of());

    assert_eq!(
        run.result(&run.checkout).status,
        CheckStatus::Fail,
        "checkout's check passes as shipped:\n{}",
        run.output_of(&run.checkout)
    );
    assert_eq!(
        run.result(&run.billing).status,
        CheckStatus::Pass,
        "billing's check is meant to pass before any repair:\n{}",
        run.output_of(&run.billing)
    );

    // The defect in the project's own words, and the command that produced them.
    assert!(
        run.output_of(&run.checkout).contains(CHECKOUT_SAYS),
        "checkout's check did not say `{CHECKOUT_SAYS}`:\n{}",
        run.output_of(&run.checkout)
    );
    assert_eq!(run.command_of(&run.checkout), "node tests/total.js");
    assert_eq!(run.command_of(&run.billing), "node tests/refund.js");
    // The command the check declared, kept beside the one that ran: `npm test`
    // is what the plan holds, and the runner cannot start it on Windows.
    assert!(
        run.ran.iter().all(|ran| ran.declared == "npm test"),
        "{:?}",
        run.ran
            .iter()
            .map(|ran| (&ran.title, &ran.declared))
            .collect::<Vec<_>>()
    );

    // And what the run may claim: not green, with the failing check named as the
    // thing holding it back.
    assert_eq!(
        run.report.aggregate().severity,
        AggregateSeverity::NotReady,
        "{}\n{}",
        run.report.aggregate().headline,
        run.summary
    );
    assert!(!run.report.is_green());
    assert_eq!(run.report.aggregate().blocking, vec![run.checkout.clone()]);
}

// --- the negative half: a repair that breaks something is not a closure ----

#[test]
fn a_careless_repair_that_breaks_the_other_member_cannot_close_the_finding() {
    let original = CopyOfFixture::of();
    let before = run_the_checks(&original);
    let finding = the_finding(&before);

    // The same project, with the one line a careless repair would stop at.
    let repaired = CopyOfFixture::of();
    let shipped_digest = digest(repaired.path());
    repaired.repair(Repair::Careless);
    let repaired_digest = digest(repaired.path());
    assert_ne!(
        shipped_digest, repaired_digest,
        "the careless repair did not change the project, so nothing below is evidence about a \
         repair"
    );
    let after = run_the_checks(&repaired);

    // The original check is fixed — which is what makes this the adversarial
    // case rather than a repair that simply did not work.
    assert_eq!(
        after.result(&after.checkout).status,
        CheckStatus::Pass,
        "the careless repair is meant to fix the basket total:\n{}",
        after.output_of(&after.checkout)
    );
    // And the check that passed before it now fails, because the shared helper's
    // meaning moved under a call the repair did not touch.
    assert_eq!(
        after.result(&after.billing).status,
        CheckStatus::Fail,
        "billing's check still passes after the careless repair, so there is no regression here:\n{}",
        after.output_of(&after.billing)
    );

    let (contract, selected) = contract_and_selection(&after, &finding);
    assert_eq!(
        contract.recheck,
        vec![after.checkout.clone()],
        "this file supplied one check and the contract is supposed to hold exactly that"
    );
    assert_is_a_regression_check(&after);
    assert!(
        selected.contains(&after.billing),
        "the check that caught the regression was not selected, so its failure could not count: \
         {selected:?}"
    );
    assert_eq!(
        selected,
        vec![after.checkout.clone(), after.billing.clone()],
        "the contract's own re-check comes first, and the only other check in the plan is the one \
         the regression rule has to find"
    );

    // The checks this run planned, as this fixture can state it: the ones whose
    // results it holds. None is candidate-driven, so nothing below turns on the
    // plan-versus-missing distinction `planned` exists for (`c4fd952`), and the
    // failing regression check must keep the finding open by the plain rule.
    let planned: Vec<CheckId> = after
        .results
        .iter()
        .map(|result| result.id.clone())
        .collect();
    let update = reconcile(
        LifecycleInputs {
            previous_open: std::slice::from_ref(&finding),
            current_findings: &[],
            check_results: &after.results,
            rechecks: &[(finding.id.clone(), selected)],
            planned: &planned,
            case: CaseSensitivity::Sensitive,
        },
        after.state.clone(),
    );

    assert!(
        update.resolved.is_empty(),
        "a repair that broke a previously passing check closed the finding: {:#?}",
        update.resolved
    );
    assert_eq!(update.kept_open.len(), 1);
    assert!(
        update
            .findings
            .iter()
            .any(|found| found.status == FindingStatus::Open),
        "{:#?}",
        update.findings
    );

    // And the run itself is not green, in the product's own words.
    assert_eq!(
        after.report.aggregate().severity,
        AggregateSeverity::NotReady,
        "{}\n{}",
        after.report.aggregate().headline,
        after.summary
    );
    assert!(!after.report.is_green());
    assert_eq!(
        after.report.aggregate().blocking,
        vec![after.billing.clone()],
        "the check that broke is the one blocking the run"
    );
}

// --- the positive half: new, passing evidence closes it -------------------

#[test]
fn a_complete_repair_closes_the_finding_on_new_passing_evidence() {
    let original = CopyOfFixture::of();
    let before = run_the_checks(&original);
    let finding = the_finding(&before);

    let repaired = CopyOfFixture::of();
    let shipped_digest = digest(repaired.path());
    repaired.repair(Repair::Complete);
    let repaired_digest = digest(repaired.path());
    assert_ne!(
        shipped_digest, repaired_digest,
        "the complete repair did not change the project, so a pass here would be a pass about the \
         project the finding was already made against"
    );
    let after = run_the_checks(&repaired);

    // **New**: the check that was failing now runs against a project whose bytes
    // are not the ones the finding was made against, and says so in its own
    // words.
    assert_eq!(
        after.result(&after.checkout).status,
        CheckStatus::Pass,
        "the complete repair is meant to fix the basket total:\n{}",
        after.output_of(&after.checkout)
    );
    assert!(
        after.output_of(&after.checkout).contains("ok 3"),
        "checkout's check passed without saying so:\n{}",
        after.output_of(&after.checkout)
    );
    // **Passing, and every selected check of it**: the call the helper's meaning
    // moved under was repaired too, so the member that passed before still does.
    assert_eq!(
        after.result(&after.billing).status,
        CheckStatus::Pass,
        "the complete repair is meant to keep the refund right:\n{}",
        after.output_of(&after.billing)
    );
    assert!(
        after.output_of(&after.billing).contains("ok 3"),
        "billing's check passed without saying so:\n{}",
        after.output_of(&after.billing)
    );

    let (contract, selected) = contract_and_selection(&after, &finding);
    assert_eq!(contract.recheck, vec![after.checkout.clone()]);
    assert_is_a_regression_check(&after);
    assert_eq!(
        selected,
        vec![after.checkout.clone(), after.billing.clone()],
        "the same two checks must be the ones that decide this half, or the two halves are not \
         the same measurement"
    );
    for id in &selected {
        assert_eq!(
            after.result(id).status,
            CheckStatus::Pass,
            "a selected check did not pass, so this is not a closure on passing evidence:\n{}",
            after.output_of(id)
        );
    }

    // Same reading of `planned` as the regression half above: the fixture's own
    // results are what it can name, and no candidate-driven check is among them.
    let planned: Vec<CheckId> = after
        .results
        .iter()
        .map(|result| result.id.clone())
        .collect();
    let update = reconcile(
        LifecycleInputs {
            previous_open: std::slice::from_ref(&finding),
            current_findings: &[],
            check_results: &after.results,
            rechecks: &[(finding.id.clone(), selected)],
            planned: &planned,
            case: CaseSensitivity::Sensitive,
        },
        after.state.clone(),
    );

    assert_eq!(
        update.resolved.len(),
        1,
        "every selected check passed over a repaired project and the finding did not close; kept \
         open: {}",
        update.kept_open.len()
    );
    assert!(update.kept_open.is_empty(), "{:#?}", update.kept_open);
    let closed = &update.resolved[0];
    assert_eq!(closed.status, FindingStatus::Resolved);
    // The same issue, by the identity this module says survives a run: a
    // `FindingId` is minted per run by design, so comparing ids here would be
    // asserting something `recheck_lifecycle` states it does not do.
    assert_eq!(
        FindingKey::from_finding(closed, CaseSensitivity::Sensitive),
        FindingKey::from_finding(&finding, CaseSensitivity::Sensitive),
        "the finding that closed is not the finding that was open"
    );
    assert_eq!(closed.title, finding.title);
    assert_eq!(
        closed.fingerprint, after.state,
        "the resolved finding is bound to the project it was closed against"
    );

    // And the run is green, which is the other thing the negative half must not
    // be: the same plan, the same rule, and the one difference a repair that was
    // finished rather than stopped at.
    assert!(after.report.is_green(), "{}", after.summary);
    assert_eq!(
        after.report.aggregate().severity,
        AggregateSeverity::Green,
        "{}\n{}",
        after.report.aggregate().headline,
        after.summary
    );
}

// --- the arrangement the two halves rest on ------------------------------

#[test]
fn neither_half_is_a_member_of_this_workspace() {
    // `rust_fixture_apps.rs` states the trap for the Rust pair: a deliberately
    // failing project inside the workspace would be built and run by
    // `cargo test --workspace`, and the checkout's own suite would fail because a
    // fixture is doing its job. This fixture is not a Cargo project at all,
    // which is the strongest form of that answer, and it is asserted rather than
    // left to a reader: a `Cargo.toml` appearing here would put it in
    // `RUST_FIXTURES` and into a runnability sweep whose entry point it does not
    // have.
    assert!(
        !shipped().join("Cargo.toml").is_file(),
        "the fixture became a Cargo project, and it is not one"
    );
    let members = std::fs::read_to_string(sure_testkit::repository_root().join("Cargo.toml"))
        .expect("the workspace manifest is readable");
    assert!(
        !members.contains(FIXTURE),
        "the fixture is named in the workspace manifest, so `cargo test --workspace` would build \
         and run it"
    );
}
