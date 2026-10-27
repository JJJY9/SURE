//! The TypeScript adversarial fixtures make the scanners say what they claim.
//!
//! `P14-T001`'s acceptance is one sentence:
//!
//! > *Fake payment/auth/email/dead button/route/demo cases runnable with
//! > expected outcomes.*
//!
//! A fixture directory and a `scenario.json` prove nothing on their own. The
//! files under `fixtures/adversarial/*/` are inputs, and the claim each one
//! makes is that **SURE's own scanners fire on it** — that the defect is
//! discoverable by the product as it is, not by a reader with the README open.
//! This file is that claim, checked against the real scanners reading the real
//! fixture directories.
//!
//! # Why the fixtures are read from the checkout rather than rebuilt in a temp
//! # directory
//!
//! Every other test in this crate writes its project into `target/tmp` so the
//! test owns it. These five scanners are being asked about **the fixtures the
//! product ships**, and a copy would be a different project the day someone
//! edits one and not the other. The directory is the artefact; reading it where
//! it lives is what makes this test able to fail when the artefact stops
//! working.
//!
//! # What is paired with what
//!
//! A scanner that reported everything would satisfy every "this fixture fires"
//! assertion in this file, so each positive assertion is paired with a negative
//! one drawn from the same fixture:
//!
//! - `route-mismatch` declares `/api/health` and *calls* `/api/health`, and the
//!   route checker must stay silent about it while reporting `/api/orders`. A
//!   checker that flagged every frontend path would pass the positive half for
//!   the wrong reason.
//! - `demo-analytics` must produce exactly the four demo-data categories. A
//!   module that flagged every literal would produce them among a crowd.
//! - A project holding none of these patterns must produce nothing at all from
//!   all five scanners, which is the control the whole file rests on.
//!
//! # The Python half, and how it differs
//!
//! `P14-T002` added `missing-migration`, `external-unverified` and
//! `missing-config` under the same directory. They are not driven by the five
//! scanners above; each one fires a different module, and the differences are
//! the point:
//!
//! - `missing-migration` fires [`sure_core::db_migrations`], the only check in
//!   this file whose evidence is `EvidenceClass::ObservedFact` rather than
//!   `Inference`. It reaches `Severity::MustFix` on that observed fact, not
//!   through [`sure_core::finding_gravity`], and it is asserted rather than
//!   assumed.
//! - `external-unverified` fires [`sure_core::external_service`], whose
//!   proposal is `Severity::ShouldFixFirst` with `critical = true` — heavier
//!   than the manifest's `note`, and *not* filed as style noise, because
//!   `is_style_noise` moves only `Note` candidates. What the manifest actually
//!   asks for here is the *outcome*, `cannot_confirm`/`not_checked`, and that is
//!   what `ExternalServiceChecks::not_checked` produces.
//! - `missing-config` fires [`sure_core::env_completeness`] over
//!   [`sure_core::references`]. It has **no case in
//!   `evaluation/acceptance-manifest.json`**, which its `scenario.json` records,
//!   and its severity is asserted against the detector rather than against the
//!   manifest because there is no manifest line to assert it against.
//!
//! # The claim-evidence half, and how it differs
//!
//! `P14-T004` added `tests-not-run`, `stale-test-evidence` and
//! `unknown-evidence` under the same directory. They fire no scanner: each is a
//! **recording** — a claim an AI made and the harness events behind it — and the
//! recording is declared in the fixture's own `scenario.json` as the event
//! documents a harness would send. What is compared here is what SURE says about
//! it, and the three differences from the halves above are the point:
//!
//! - The input is the fixture's own declarations, ingested through
//!   [`sure_core::harness_event::ingest_event_str`] — the entry point a harness's
//!   JSON takes — and stored through the session event store, so a document the
//!   wire refuses is a failing test rather than a document nobody checked.
//! - Every fact asserted comes out of the scenario rather than being restated
//!   here: the assessment, the sentence a reader is shown, the number of
//!   evidence items, the anchor, the class and the freshness are all compared
//!   against the `expect` block, and the rendered `AI claims` section is compared
//!   whole. A fixture edited without this file being edited is a red test.
//! - Each is read twice — once through the store, which is what `sure check`
//!   reads, and once through [`check_claims_against_events`] over the same events
//!   in the order that function documents — and the two answers must be equal.
//!
//! And each has a control: the same recording with exactly one field of one event
//! moved, whose answer must be `confirmed`. That is the one control this half
//! cannot do without. A checker that answered `cannot_confirm` to everything
//! would satisfy all three of these fixtures' required outcomes at once, and the
//! corpus would look green while measuring nothing; the controls are what make
//! the three answers a measurement of the recordings rather than of the checker.
//!
//! # What is not claimed
//!
//! **A severity of its own, for the six TypeScript fixtures.** No scanner in
//! this file holds one. What each emits is [`sure_core::finding_gravity`]'s
//! answer for the gap it found and the reach it found it on: `must_fix` for a
//! substituted action in production code, `should_fix_first` for unreal content,
//! `note` for an unfinished marker and for anything that names nothing, points
//! at a place a reader cannot open, rests on an `Unknown` result, or cannot
//! reach a user. Until `P7-T011` every scanner here emitted `Severity::Note`,
//! `critical = false`, `EvidenceClass::Inference` — the combination
//! [`sure_core::false_completion_aggregator`] filed as style noise — while
//! `evaluation/acceptance-manifest.json` asked for `must_fix` on five of those
//! six ids. The test that recorded that gap was
//! `what_is_detected_is_not_yet_what_the_manifest_requires`;
//! [`what_is_detected_now_carries_the_weight_the_manifest_requires`] is that
//! test inverted, and the sentence is kept in both places because it is the only
//! statement in the tree that the two numbers were ever different.
//!
//! **A raised evidence class.** The severity moved and the class did not:
//! `EvidenceClass::Inference` is what every one of these findings' own
//! `scenario.json` requires, and it is what they still report. A scanner that
//! reached `must_fix` by presenting its inference as a fact would be relabelling
//! rather than grading, and [`sure_core::finding_gravity`]'s own tests refuse
//! that move.
//!
//! **A verdict.** These are candidates. `CheckProposal::severity` is how bad it
//! would be if the check is not satisfied, and no scanner here sets `critical`,
//! so a `must_fix` candidate decides nothing about whether a project passes —
//! what it decides is whether the candidate is shown rather than filed as noise.
//! The weight was not free: `noop_heuristics`' hard-coded-success shape and
//! `ui_action_bridge`'s declared-handler shape both occur in ordinary, working
//! code, and they are now weighted as if a user's money or their primary action
//! is behind them. That cost is deliberate and is recorded at the detectors.
//!
//! **A password check that is always true.** SURE has no detector that reads
//! `verifyPassword` returning `true` as an authentication bypass.
//! `fake-auth` fires on what surrounds the bypass, and
//! `fake_auth_is_detected_by_what_surrounds_the_bypass` says which parts, so a
//! reader does not take the passing test for a capability SURE does not have.
//!
//! **A Python integration that imports its provider.** Two limits of
//! [`sure_core::external_service`] are measured here rather than described:
//! `import stripe` in a `.py` file and `stripe==11.0.0` in `requirements.txt`
//! each produce no proposal at all, because the import and dependency tables are
//! JavaScript-shaped. `external-unverified` fires on its `STRIPE_` environment
//! prefix, and `a_python_provider_import_on_its_own_is_not_detected` holds that
//! difference so nobody reads the passing assertion above as a capability this
//! check does not have.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

use serde_json::{Value, json};
use sure_core::acceptance_report::{AcceptanceReport, CaseRow, acceptance_report};
use sure_core::aggregation::{NOTHING_CAME_BACK, RunReport, aggregate_run};
use sure_core::candidate_scanner::CandidateScanner;
use sure_core::checks::rust::RustChecks;
use sure_core::claim_capture::{ClaimCaptureOutcome, capture_agent_claim};
use sure_core::claim_checker::{
    CheckedClaim, ClaimDocument, check_claims_against_events, check_claims_in_store,
};
use sure_core::claim_report::render_claim_section;
use sure_core::config::{Authority, Config, ExecutionSettings, ProtectionMode};
use sure_core::container::{Availability, OVERCLAIMS, Runtime, isolation_claim, overclaims};
use sure_core::db_migrations::{MigrationsReport, Record};
use sure_core::demo_data_heuristics::DemoDataHeuristics;
use sure_core::discover::{DiscoverOptions, Discovery, Ecosystem, Findings, RustProject, discover};
use sure_core::env_completeness::CompletenessReport;
use sure_core::evidence::{
    AnchorSubject, ClaimAssessment, EvidenceClass, Freshness, StalenessReason,
};
use sure_core::execution::{ActionKind, ExecutionMode, ExecutionPermissions, Permission};
use sure_core::external_service::ExternalServiceChecks;
use sure_core::false_completion_aggregator::aggregate;
use sure_core::harness_event::{IngestedEvent, ingest_event_str};
use sure_core::hook_protection::{
    Assessment, Danger, ToolRequest, acts_a_request_could_be_held_for,
    acts_a_tool_could_be_held_for, assess_claude_code_tool, assess_cursor_tool, danger_reason,
};
use sure_core::ids::{CheckId, ClaimId, EventId, FingerprintId};
use sure_core::intent::{ProjectIntent, may_claim_full_fulfilment};
use sure_core::intent_implementation::{IntentMatchAnchor, compare_intent_to_project};
use sure_core::noop_heuristics::NoOpHeuristics;
use sure_core::paths::Paths;
use sure_core::pipeline::{Pipeline, PipelineOutcome, Purpose, RunOutcome};
use sure_core::planned_check_runner::ProcessRunner;
use sure_core::planned_work::{CheckOperation, PlannedWork, PrecomputedEvidence};
use sure_core::process::Cancellation;
use sure_core::project_intent::explicit_goal;
use sure_core::project_verdict::render_summary;
use sure_core::recording_projection::{BuildTestKind, StandardProjection, project};
use sure_core::references::KeyStatus;
use sure_core::route_consistency::RouteConsistency;
use sure_core::scan::{ScanOptions, scan};
use sure_core::schedule::{CheckProposal, CheckReason, CheckSchedule, PlanBuilder};
use sure_core::session_event_store::SessionEventStore;
use sure_core::severity::Severity;
use sure_core::status::{CheckResult, CheckStatus, NotCheckedReason};
use sure_core::store::Store;
use sure_core::ui_action_bridge::UiActionBridge;
use sure_core::vocabulary::Claim;
use sure_domain::finding::AssessmentSource;

/// Every fixture `P14-T001` is about, and the language half it belongs to.
const TYPESCRIPT_FIXTURES: &[&str] = &[
    "fake-payment",
    "fake-auth",
    "fake-email",
    "dead-button",
    "demo-analytics",
    "route-mismatch",
];

/// Every fixture `P14-T002` is about, named rather than discovered for the same
/// reason the list above is: a test that discovered them would pass on an empty
/// directory.
const PYTHON_FIXTURES: &[&str] = &["missing-migration", "external-unverified", "missing-config"];

/// Every fixture `P14-T004` is about: a recorded AI claim and the events behind
/// it, with no project in either.
///
/// Named rather than discovered, for the reason the lists above are. They are
/// also named in `crates/sure-testkit/tests/fixture_apps.rs`, which checks the
/// scenarios as artefacts; this file is where their outcomes are graded.
const CLAIM_FIXTURES: &[&str] = &["tests-not-run", "stale-test-evidence", "unknown-evidence"];

/// The project root the declared recordings are attributed to.
///
/// A Windows path on purpose: this repository's primary environment is Windows
/// and the root is part of what the recorded session is stored under, so the
/// path worth exercising is one with backslashes in it.
const CLAIM_PROJECT_ROOT: &str = "C:\\work\\shop";

fn fixture(id: &str) -> PathBuf {
    sure_testkit::repository_root()
        .join("fixtures")
        .join("adversarial")
        .join(id)
}

/// A project under the workspace's git-ignored `target/tmp`, for the controls.
///
/// These are the negative half of each Python fixture's claim, and they are
/// built here rather than shipped as fixtures because a control is not a
/// scenario the corpus has a case for. The claiming rules live in
/// `sure_testkit::scratch`, and the history behind them is this repository's:
/// clearing a fixed path and treating it as fresh fails on Windows, and the test
/// then describes a directory that was never emptied. Nothing is adopted — a
/// directory is taken with `create_dir`, which fails when the name is taken,
/// and one that is already there is skipped rather than entered — and the
/// helper clears only directories carrying *its own* process's id, which no live
/// process can own.
struct Scratch {
    project: PathBuf,
}

impl Scratch {
    fn new(test: &str) -> Self {
        Self::under("adversarial python controls", test)
    }

    /// The same, under a base of its own.
    ///
    /// The claim fixtures store recordings rather than writing projects, so
    /// their scratch directories are named for what they hold; the directory
    /// discipline is the one above and is not restated.
    fn under(base_name: &str, test: &str) -> Self {
        Self {
            project: sure_testkit::scratch::directory(base_name, test),
        }
    }

    fn write(&self, relative: &str, contents: &str) -> &Self {
        let full = self.project.join(relative);
        if let Some(parent) = full.parent() {
            std::fs::create_dir_all(parent)
                .unwrap_or_else(|error| panic!("cannot create {}: {error}", parent.display()));
        }
        std::fs::write(&full, contents)
            .unwrap_or_else(|error| panic!("cannot write {}: {error}", full.display()));
        self
    }

    fn discovery(&self) -> Discovery {
        discover(&self.project, &DiscoverOptions::default())
            .unwrap_or_else(|error| panic!("cannot read {}: {error}", self.project.display()))
    }
}

/// What SURE reads out of one shipped fixture.
fn discovery(id: &str) -> sure_core::discover::Discovery {
    let root = fixture(id);
    assert!(
        root.is_dir(),
        "the {id} fixture directory is missing: {}",
        root.display()
    );
    discover(&root, &DiscoverOptions::default())
        .unwrap_or_else(|error| panic!("cannot read the {id} fixture: {error}"))
}

fn candidate_titles(id: &str) -> Vec<String> {
    CandidateScanner::of(&discovery(id))
        .proposed()
        .iter()
        .map(|proposal| proposal.title().to_owned())
        .collect()
}

fn noop_titles(id: &str) -> Vec<String> {
    NoOpHeuristics::of(&discovery(id))
        .proposed()
        .iter()
        .map(|proposal| proposal.title().to_owned())
        .collect()
}

fn demo_titles(id: &str) -> Vec<String> {
    DemoDataHeuristics::of(&discovery(id))
        .proposed()
        .iter()
        .map(|proposal| proposal.title().to_owned())
        .collect()
}

fn route_titles(id: &str) -> Vec<String> {
    RouteConsistency::of(&discovery(id))
        .proposed()
        .iter()
        .map(|proposal| proposal.title().to_owned())
        .collect()
}

fn ui_action_titles(id: &str) -> Vec<String> {
    UiActionBridge::of(&discovery(id))
        .proposals()
        .iter()
        .map(|proposal| proposal.title().to_owned())
        .collect()
}

fn external_titles(id: &str) -> Vec<String> {
    ExternalServiceChecks::of(&discovery(id))
        .proposed()
        .iter()
        .map(|proposal| proposal.title().to_owned())
        .collect()
}

fn migrations_of(id: &str) -> MigrationsReport {
    MigrationsReport::of(&discovery(id), &FingerprintId::generate())
}

fn completeness_of(id: &str) -> CompletenessReport {
    CompletenessReport::of(&discovery(id), &FingerprintId::generate())
}

/// Every key one of the Python fixtures asks the environment for, with the
/// status, verdict and severity SURE reached about it.
fn keys_of(id: &str) -> Vec<(String, KeyStatus, ClaimAssessment, Severity)> {
    completeness_of(id)
        .claims()
        .iter()
        .map(|claim| {
            (
                claim.key().to_owned(),
                claim.status(),
                claim.assessment(),
                claim.severity(),
            )
        })
        .collect()
}

/// Every scanner `P14-T001` put on the TypeScript fixtures, in one list.
///
/// Used here as the *silence* side of the Python fixtures: a fixture that fired
/// six checks at once would satisfy every positive assertion about one of them
/// while telling a reader nothing about which check the fixture measures.
fn every_typescript_scanner_says(id: &str) -> Vec<(&'static str, Vec<String>)> {
    vec![
        ("candidate_scanner", candidate_titles(id)),
        ("noop_heuristics", noop_titles(id)),
        ("demo_data_heuristics", demo_titles(id)),
        ("route_consistency", route_titles(id)),
        ("ui_action_bridge", ui_action_titles(id)),
        ("external_service", external_titles(id)),
    ]
}

/// Assert one scanner said one thing about this fixture.
fn assert_reports(what: &str, said: &[String], expected: &str) {
    assert!(
        said.iter().any(|title| title == expected),
        "{what} did not report it.\n  expected: {expected}\n  it said:  {said:?}"
    );
}

/// Assert one scanner did not say one thing about this fixture.
fn assert_silent(what: &str, said: &[String], unexpected: &str) {
    assert!(
        !said.iter().any(|title| title == unexpected),
        "{what} said something it must not.\n  unexpected: {unexpected}\n  it said:    {said:?}"
    );
}

// --- each fixture fires the scanners its scenario names ------------------

#[test]
fn fake_payment_is_detected_as_a_fake_payment_path() {
    let noop = noop_titles("fake-payment");
    let candidates = candidate_titles("fake-payment");

    assert_reports(
        "noop_heuristics on fake-payment",
        &noop,
        "project contains fake payment or sandbox tokens in production code",
    );
    assert_reports(
        "noop_heuristics on fake-payment",
        &noop,
        "project contains hard-coded success responses in production code",
    );
    assert_reports(
        "noop_heuristics on fake-payment",
        &noop,
        "project contains no-op functions that always succeed in production code",
    );
    assert_reports(
        "candidate_scanner on fake-payment",
        &candidates,
        "project contains mock usage in production code",
    );
}

#[test]
fn fake_auth_is_detected_by_what_surrounds_the_bypass() {
    // The bypass itself — `verifyPassword` returning `true` for any password —
    // is what this fixture is about and what no detector reads. What is
    // asserted here is the evidence around it, and the comment at the top of
    // this file says so rather than letting this test imply a capability SURE
    // does not have.
    let noop = noop_titles("fake-auth");
    let candidates = candidate_titles("fake-auth");

    assert_reports(
        "noop_heuristics on fake-auth",
        &noop,
        "project contains hard-coded success responses in production code",
    );
    assert_reports(
        "noop_heuristics on fake-auth",
        &noop,
        "project contains fake email addresses or domains in production code",
    );
    assert_reports(
        "candidate_scanner on fake-auth",
        &candidates,
        "project contains TODO or FIXME comments in production code",
    );
    assert_reports(
        "candidate_scanner on fake-auth",
        &candidates,
        "project contains mock usage in production code",
    );
}

#[test]
fn fake_email_is_detected_as_console_only() {
    let noop = noop_titles("fake-email");
    let candidates = candidate_titles("fake-email");

    assert_reports(
        "noop_heuristics on fake-email",
        &noop,
        "project contains fake email addresses or domains in production code",
    );
    assert_reports(
        "noop_heuristics on fake-email",
        &noop,
        "project contains hard-coded success responses in production code",
    );
    assert_reports(
        "noop_heuristics on fake-email",
        &noop,
        "project contains no-op functions that always succeed in production code",
    );
    assert_reports(
        "candidate_scanner on fake-email",
        &candidates,
        "project contains TODO or FIXME comments in production code",
    );
}

#[test]
fn dead_button_is_detected_as_a_wired_action_with_no_behaviour() {
    let ui = ui_action_titles("dead-button");
    let candidates = candidate_titles("dead-button");

    assert!(
        ui.iter()
            .any(|title| title.starts_with("UI action: click handler on ")),
        "ui_action_bridge did not find the Buy now click binding: {ui:?}"
    );
    assert_reports(
        "candidate_scanner on dead-button",
        &candidates,
        "project contains placeholder usage in production code",
    );
    assert_reports(
        "candidate_scanner on dead-button",
        &candidates,
        "project contains TODO or FIXME comments in production code",
    );
}

#[test]
fn demo_analytics_is_detected_as_demo_data_and_nothing_else() {
    // Exact, not "contains": a module that flagged every literal in the project
    // would produce these four among a crowd, and the point of `P6-T004` is
    // that a retry count is not a metric.
    let mut demo = demo_titles("demo-analytics");
    demo.sort();

    assert_eq!(
        demo,
        [
            "project contains hard-coded demo analytics values in production code",
            "project contains hard-coded demo or chart values in production code",
            "project contains hard-coded demo or sample datasets in production code",
            "project contains placeholder user or content IDs in production code",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<String>>(),
        "the demo-data reading of demo-analytics changed"
    );
}

#[test]
fn route_mismatch_is_detected_and_the_matching_route_is_left_alone() {
    let routes = route_titles("route-mismatch");

    assert_eq!(
        routes,
        ["frontend expects backend path `/api/orders` which is not declared"]
            .into_iter()
            .map(str::to_owned)
            .collect::<Vec<String>>(),
        "the route-consistency reading of route-mismatch changed"
    );

    // The control. `/api/health` is declared by the backend and called by the
    // frontend, and a checker that reported it would be flagging a working
    // route — which is the failure that makes a real mismatch ignorable.
    assert_silent(
        "route_consistency on route-mismatch",
        &routes,
        "frontend expects backend path `/api/health` which is not declared",
    );
}

#[test]
fn the_route_mismatch_fixture_is_otherwise_clean() {
    // If the mismatch fixture also tripped every other scanner, its
    // `scenario.json` would be naming one of six findings and the eval runner
    // would have no way to tell which one it measured.
    for (what, said) in [
        ("candidate_scanner", candidate_titles("route-mismatch")),
        ("noop_heuristics", noop_titles("route-mismatch")),
        ("demo_data_heuristics", demo_titles("route-mismatch")),
    ] {
        assert!(
            said.is_empty(),
            "{what} reported something about the route-mismatch fixture: {said:?}"
        );
    }
}

// --- the Python fixtures, each firing a different module ----------------

/// Assert the six `P14-T001` scanners say nothing about a Python fixture.
///
/// Each fixture in this half measures one module, and a fixture that tripped
/// the other five would be measuring nothing: a reader could not tell which
/// check the case is about, and an eval runner comparing outcomes would have no
/// way to tell which one it read.
fn assert_the_typescript_scanners_are_silent(id: &str) {
    for (what, said) in every_typescript_scanner_says(id) {
        assert!(
            said.is_empty(),
            "{what} reported something about the {id} fixture: {said:?}"
        );
    }
}

#[test]
fn missing_migration_is_detected_as_a_record_that_is_there_and_empty() {
    let report = migrations_of("missing-migration");

    // The reading first, because the severity below rests on which of the two
    // shapes this is. `Record::Empty` is the project that writes its schema
    // down, uses migrations, and has no revision; `Record::Absent` is the
    // weaker one and carries `ShouldFixFirst` instead.
    let looked: Vec<_> = report.survey().looked().iter().collect();
    assert_eq!(looked.len(), 1, "{:?}", report.survey().looked());
    assert_eq!(looked[0].framework(), "Alembic");
    assert_eq!(looked[0].shape(), Path::new("alembic.ini"));
    assert_eq!(looked[0].record_at(), Path::new("alembic/versions"));
    assert_eq!(looked[0].record(), Record::Empty);

    let claims: Vec<_> = report.claims().iter().collect();
    assert_eq!(claims.len(), 1, "{:?}", report.claims());
    let claim = claims[0];
    assert_eq!(claim.framework(), "Alembic");
    assert_eq!(claim.record(), Record::Empty);
    assert_eq!(claim.assessment(), ClaimAssessment::Confirmed);
    assert_eq!(claim.severity(), Severity::MustFix);
    assert!(
        claim.severity().blocks_hand_off(),
        "this fixture's detector reaches the manifest's `must_fix` on an observed fact \
         rather than through the candidate rule"
    );
    assert!(
        report.is_complete(),
        "a Confirmed verdict rests on SURE having finished reading: {}",
        report.plain_description()
    );

    // A must_fix that nothing stands behind is the false green this product
    // exists to prevent, so the two anchors are pinned: where the framework was
    // read and where its record was looked for. Both carry no excerpt, and that
    // emptiness is asserted rather than tolerated — what is behind them is a
    // path SURE listed, not a line of the project it could quote.
    let mut locations: Vec<String> = claim
        .evidence()
        .iter()
        .map(|evidence| {
            assert_eq!(evidence.class, EvidenceClass::ObservedFact);
            assert_eq!(evidence.severity, Severity::MustFix);
            assert_eq!(
                evidence.anchor.subject,
                AnchorSubject::Database,
                "the variant that exists for a schema and a migration is the one to use"
            );
            assert!(evidence.anchor.is_checkable(), "{:?}", evidence.anchor);
            assert!(evidence.fingerprint.is_some());
            assert!(
                evidence.anchor.excerpt.is_empty(),
                "an anchor here is a path SURE read, and there is no line to quote: {:?}",
                evidence.anchor
            );
            evidence.anchor.location.clone()
        })
        .collect();
    locations.sort();
    assert_eq!(
        locations,
        ["alembic.ini", "alembic/versions"]
            .into_iter()
            .map(str::to_owned)
            .collect::<Vec<String>>(),
        "a reader who disagrees has to be able to go and look at both halves"
    );

    // And the sentence names both halves for the same reason.
    assert!(
        claim.reason().contains("alembic.ini") && claim.reason().contains("alembic/versions"),
        "{}",
        claim.reason()
    );

    // None of the five TypeScript scanners has anything to say about this
    // project, which is what makes the one finding the fixture's own.
    assert_the_typescript_scanners_are_silent("missing-migration");
}

#[test]
fn an_alembic_record_that_holds_a_revision_makes_no_claim() {
    // The control. A check that answered `MustFix` to every project with an
    // `alembic.ini` would satisfy the test above while reporting on projects
    // whose migrations are in order, which is the failure that makes a real
    // finding ignorable.
    let project = Scratch::new("alembic-with-a-revision");
    project
        .write("alembic.ini", "[alembic]\nscript_location = alembic\n")
        .write(
            "alembic/versions/0001_create_orders.py",
            "revision = \"0001\"\ndown_revision = None\n",
        );

    let report = MigrationsReport::of(&project.discovery(), &FingerprintId::generate());
    assert!(
        report.claims().is_empty(),
        "a project with a revision made a claim: {:?}",
        report.claims()
    );
    let records: Vec<Record> = report
        .survey()
        .looked()
        .iter()
        .map(|look| look.record())
        .collect();
    assert_eq!(
        records,
        [Record::Holds(1)],
        "the control has to be read as a project with a migration, or it controls for nothing"
    );
}

#[test]
fn external_unverified_is_reported_as_not_checked_and_never_as_passed() {
    let discovery = discovery("external-unverified");
    let checks = ExternalServiceChecks::of(&discovery);

    // What is proposed, and at what weight. `ShouldFixFirst` with
    // `critical = true` and `Inference` — heavier than the `note` the manifest
    // asks for, and *not* filed as style noise, because
    // `false_completion_aggregator::is_style_noise` moves only `Note`
    // candidates. The mismatch is recorded in the fixture's `scenario.json`
    // and pinned here rather than smoothed over.
    let proposals = checks.proposed();
    assert_eq!(proposals.len(), 1, "{proposals:?}");
    let proposal = &proposals[0];
    assert_eq!(proposal.title(), "project uses an external payment service");
    assert_eq!(proposal.severity(), Severity::ShouldFixFirst);
    assert!(proposal.critical());
    assert_eq!(proposal.evidence_class(), EvidenceClass::Inference);
    assert!(
        !proposal.severity().blocks_hand_off(),
        "the manifest asks for `note` here, so nothing may say this stops a hand-off on its own"
    );

    // The other half of the mismatch the scenario records: because the severity
    // is not `Note`, the aggregator does *not* file this as style noise, so the
    // proposal reaches a reader as material. That is heavier than the manifest
    // asks for, and it is recorded rather than smoothed over.
    let aggregated = aggregate(checks.proposed().to_vec());
    assert_eq!(
        aggregated.material().len(),
        1,
        "the payment proposal is no longer material: {:?} vs {:?}",
        aggregated.material(),
        aggregated.style_noise()
    );
    assert!(aggregated.style_noise().is_empty());
    let anchor = proposal
        .reason()
        .anchor()
        .expect("the reason names the file it was read from");
    assert_eq!(anchor.subject, AnchorSubject::File);
    assert_eq!(anchor.location, "app/payments.py");

    // What the proposal turns into, and the outcome the manifest does ask for:
    // an external service can only be confirmed against the real service, so
    // the check is skipped with its own reason and never reported as a pass.
    let results = checks.not_checked(&FingerprintId::generate());
    assert_eq!(results.len(), 1, "{results:?}");
    let result = &results[0];
    assert_eq!(result.status, CheckStatus::Skipped);
    assert_ne!(result.status, CheckStatus::Pass);
    assert_eq!(
        result.not_checked_reason,
        Some(NotCheckedReason::ExternalServiceUnavailable)
    );
    assert_eq!(result.evidence_class, EvidenceClass::Unknown);
    assert!(result.critical);
    assert!(result.is_not_checked());
    assert!(!result.title.is_empty());

    // The same fixture's second surface. These two keys are what fires the
    // payment proposal at all — the provider is named by nothing else in the
    // project — and they are a finding in their own right.
    assert_eq!(
        keys_of("external-unverified"),
        ["STRIPE_API_BASE", "STRIPE_SECRET_KEY",]
            .into_iter()
            .map(|key| (
                key.to_owned(),
                KeyStatus::ReadButNotDeclared,
                ClaimAssessment::Confirmed,
                Severity::ShouldFixFirst,
            ))
            .collect::<Vec<_>>(),
        "the keys SURE read out of this fixture changed"
    );

    // The five scanners that are not this fixture's, silent, and no migration
    // claim either: the fixture measures one module and says so.
    for (what, said) in every_typescript_scanner_says("external-unverified") {
        if what == "external_service" {
            continue;
        }
        assert!(
            said.is_empty(),
            "{what} reported something about the external-unverified fixture: {said:?}"
        );
    }
    assert!(
        migrations_of("external-unverified").claims().is_empty(),
        "this fixture has no database framework and must make no migration claim"
    );
}

#[test]
fn a_python_provider_import_on_its_own_is_not_detected() {
    // The first of the two limits `external-unverified`'s `scenario.json`
    // records, measured rather than described: the dependency and import
    // tables in `external_service` are JavaScript-shaped, so a Python app that
    // names its provider by importing the provider's own client, and whose
    // requirements file lists that client, produces nothing at all.
    let imports = Scratch::new("python-provider-import");
    imports
        .write(
            "app/paid.py",
            "import stripe\n\nBASE = \"https://api.stripe.com\"\n\n\ndef charge(cents):\n    return {\"amount\": cents, \"currency\": \"usd\"}\n",
        )
        .write("requirements.txt", "stripe==11.0.0\n");
    assert!(
        ExternalServiceChecks::of(&imports.discovery()).is_empty(),
        "a Python provider import now fires external_service, so the fixture's recorded limit changed"
    );

    // The same project with one Stripe-prefixed environment read, which is what
    // the shipped fixture carries and what the limit above is not. Without
    // this half, the assertion above would pass for a check that had stopped
    // working on everything.
    let env = Scratch::new("python-provider-env");
    env.write(
        "app/paid.py",
        "import os\n\nBASE = os.getenv(\"STRIPE_API_BASE\") or \"https://api.stripe.com\"\n",
    );
    let checks = ExternalServiceChecks::of(&env.discovery());
    assert_eq!(
        checks.proposed().len(),
        1,
        "the STRIPE_ environment prefix is what this check reads in a Python project, and it stopped reading it: {:?}",
        checks.proposed()
    );
    assert_eq!(
        checks.proposed()[0].title(),
        "project uses an external payment service"
    );
}

#[test]
fn missing_config_is_detected_as_keys_asked_for_and_named_nowhere() {
    let report = completeness_of("missing-config");

    assert_eq!(
        keys_of("missing-config"),
        ["ORDERS_DB_URL", "ORDERS_QUEUE_URL", "REPORTING_BUCKET"]
            .into_iter()
            .map(|key| (
                key.to_owned(),
                KeyStatus::ReadButNotDeclared,
                ClaimAssessment::Confirmed,
                Severity::ShouldFixFirst,
            ))
            .collect::<Vec<_>>(),
        "the keys SURE read out of this fixture changed"
    );
    assert!(
        report.is_complete(),
        "a Confirmed verdict rests on SURE having finished reading: {}",
        report.plain_description()
    );

    // Where each key was read, and nothing else. Two read sites per key: the
    // settings module the app reads through, and the fixture's own check, which
    // supplies the three names itself — which is exactly what makes the check a
    // trap rather than evidence. No anchor carries an excerpt, because SURE
    // read the name and not the value and there is no line to quote.
    let mut locations: Vec<String> = Vec::new();
    for claim in report.claims() {
        assert!(
            !claim.evidence().is_empty(),
            "{}",
            claim.plain_description()
        );
        assert!(!claim.is_set_aside());
        assert_eq!(claim.severity(), Severity::ShouldFixFirst);
        assert!(
            !claim.severity().blocks_hand_off(),
            "env_completeness documents that no missing line of documentation stops a hand-off"
        );
        for evidence in claim.evidence() {
            assert_eq!(evidence.class, EvidenceClass::ObservedFact);
            assert_eq!(evidence.anchor.subject, AnchorSubject::LineRange);
            assert!(evidence.anchor.is_checkable(), "{:?}", evidence.anchor);
            assert!(
                evidence.anchor.excerpt.is_empty(),
                "SURE reads the key name and never the value: {:?}",
                evidence.anchor
            );
            locations.push(evidence.anchor.location.clone());
        }
    }
    locations.sort();
    locations.dedup();
    assert_eq!(
        locations,
        ["app/settings.py", "scripts/check.py"]
            .into_iter()
            .map(str::to_owned)
            .collect::<Vec<String>>(),
        "the read sites behind this fixture's claims changed"
    );

    // And nothing else in the project has anything to say.
    assert_the_typescript_scanners_are_silent("missing-config");
    assert!(
        migrations_of("missing-config").claims().is_empty(),
        "this fixture has no database framework and must make no migration claim"
    );
}

#[test]
fn a_project_whose_sample_file_assigns_the_keys_makes_no_claim() {
    // The control. A check that answered `ShouldFixFirst` to every key a
    // project reads would satisfy the test above while reporting on projects
    // that document themselves, and the fixture's README would be a defect
    // report about nothing.
    let project = Scratch::new("env-example-names-the-keys");
    project
        .write(
            "app/settings.py",
            "import os\n\n\ndef database_url():\n    return os.environ[\"ORDERS_DB_URL\"]\n",
        )
        .write(".env.example", "ORDERS_DB_URL=postgres://localhost/shop\n");

    let report = CompletenessReport::of(&project.discovery(), &FingerprintId::generate());
    assert!(
        report.claims().is_empty(),
        "a project whose sample file names the key made a claim: {:?}",
        report.claims()
    );
}

#[test]
fn every_python_fixture_these_assertions_name_is_a_fixture_this_repository_ships() {
    // The same guard the list above has, for the same reason: a renamed
    // directory would make `discovery` panic above and every assertion would be
    // about a project nobody ships. The difference is the second half — a
    // Python fixture with a `package.json` would be picked up by the testkit's
    // `npm start` runnability sweep, which is a claim about Node this half
    // cannot honour.
    for id in PYTHON_FIXTURES {
        let dir = fixture(id);
        assert!(dir.is_dir(), "{} is not a directory", dir.display());
        assert!(
            dir.join("scenario.json").is_file(),
            "{id} has no scenario.json"
        );
        assert!(
            !dir.join("package.json").is_file(),
            "{id} is a Python fixture and must not be listed as runnable with `npm start`"
        );
        assert!(
            dir.join("README.md").is_file(),
            "{id} has no README.md, so nothing says in words what it traps"
        );
    }
    for id in TYPESCRIPT_FIXTURES {
        assert!(
            !PYTHON_FIXTURES.contains(id),
            "{id} is in both lists, so one of the two halves is misdescribed"
        );
    }
}

// --- the scanners are not vacuous ---------------------------------------

#[test]
fn a_project_with_none_of_these_patterns_produces_nothing() {
    // The check the rest of this file rests on. Every scanner here is a
    // pattern matcher over source lines, and a matcher that returned a
    // proposal per file would satisfy every positive assertion above.
    let scratch = sure_testkit::repository_root()
        .join("target")
        .join("tmp")
        .join("adversarial-fixture-control");
    let _ = std::fs::remove_dir_all(&scratch);
    std::fs::create_dir_all(scratch.join("src")).unwrap();
    std::fs::write(
        scratch.join("src").join("main.js"),
        "'use strict';\n\nconst MAX_RETRIES = 3;\n\nfunction retryCount() {\n  return MAX_RETRIES;\n}\n\nmodule.exports = { retryCount: retryCount };\n",
    )
    .unwrap();
    std::fs::write(
        scratch.join("package.json"),
        "{\n  \"name\": \"control\",\n  \"private\": true,\n  \"scripts\": { \"start\": \"node src/main.js\" }\n}\n",
    )
    .unwrap();

    let discovery = discover(&scratch, &DiscoverOptions::default()).unwrap();

    assert!(
        CandidateScanner::of(&discovery).is_empty(),
        "candidate_scanner fired on a project with no candidates"
    );
    assert!(
        NoOpHeuristics::of(&discovery).is_empty(),
        "noop_heuristics fired on a project with no fake-success patterns"
    );
    assert!(
        DemoDataHeuristics::of(&discovery).is_empty(),
        "demo_data_heuristics fired on a project with an ordinary constant"
    );
    assert!(
        RouteConsistency::of(&discovery).is_empty(),
        "route_consistency fired on a project with no routes"
    );
    assert!(
        UiActionBridge::of(&discovery).is_empty(),
        "ui_action_bridge fired on a project with no UI actions"
    );

    let _ = std::fs::remove_dir_all(&scratch);
}

#[test]
fn every_fixture_these_assertions_name_is_a_fixture_this_repository_ships() {
    // Guards the file against the way it would most quietly stop testing
    // anything: a renamed fixture directory, where `discovery` would panic
    // above and every assertion would be about a project nobody ships.
    for id in TYPESCRIPT_FIXTURES {
        let dir = fixture(id);
        assert!(dir.is_dir(), "{} is not a directory", dir.display());
        assert!(
            dir.join("scenario.json").is_file(),
            "{id} has no scenario.json"
        );
        assert!(
            dir.join("package.json").is_file(),
            "{id} has no package.json, so it is not runnable with `npm start`"
        );
    }
}

/// What every scanner in this file emitted for these fixtures before `P7-T011`.
///
/// Held as a value rather than only as a sentence, because it is the number the
/// inverted test below replaced and the number its failure message names. A
/// scanner that falls back to it is not failing for an unknown reason: this is
/// where it landed.
const SEVERITY_BEFORE_P7T011: Severity = Severity::Note;

#[test]
fn what_is_detected_now_carries_the_weight_the_manifest_requires() {
    // This is `what_is_detected_is_not_yet_what_the_manifest_requires`, the
    // test that recorded the gap between what SURE saw and what the corpus
    // required, **inverted rather than deleted** by `P7-T011`. It asserted the
    // opposite of everything below: every proposal was `Severity::Note`, not
    // critical, `Inference` — the combination
    // `false_completion_aggregator` files as style noise — while
    // `evaluation/acceptance-manifest.json` asks for `must_fix` on fake-payment
    // and four of its siblings. The old name and the old number are kept here
    // because this is the only statement in the tree that the two were ever
    // different.
    //
    // `noop_heuristics` is the probe. It reads the file that takes the money,
    // its proposals name `src/payments.js` and the line they were read from, and
    // `sure_core::finding_gravity` grades the gap it found — a substituted
    // action, in production code — `must_fix`. The two things that must *not*
    // have moved with it are asserted here beside it.
    let discovery = discovery("fake-payment");
    let proposals = NoOpHeuristics::of(&discovery).proposed().to_vec();
    assert!(
        !proposals.is_empty(),
        "the probe fixture produced nothing, so this test proves nothing"
    );
    for proposal in &proposals {
        assert_eq!(
            proposal.severity(),
            Severity::MustFix,
            "{}: the manifest requires `must_fix` on fake-payment and this is \
             `{:?}`. `{SEVERITY_BEFORE_P7T011:?}` is what every scanner here \
             emitted before P7-T011; if that is where this landed, the severity \
             rule in `sure_core::finding_gravity` was bypassed.",
            proposal.title(),
            proposal.severity(),
        );
        // The weight is about impact, not about how the finding was reached:
        // `Inference` is the class this fixture's `scenario.json` requires and
        // the class the evidence is, and raising the severity by promoting it to
        // a fact is the move this test would have to catch.
        assert_eq!(proposal.evidence_class(), EvidenceClass::Inference);
        // And a heavier candidate is still not a blocker. Nothing in this file
        // sets `critical`, so no candidate decides a verdict however it is
        // weighted.
        assert!(!proposal.critical());
    }

    // The weight reaches the reader. `material` non-empty is the half that says
    // the finding is shown; `style_noise` empty is the half that says it is not
    // filed under a name that tells a reader to skip it. Both used to be the
    // other way round, and that is the whole of what `P7-T011` changed.
    let aggregated = aggregate(proposals);
    assert!(
        !aggregated.material().is_empty(),
        "the probe fixture's findings reached neither list, so this test proves nothing"
    );
    assert!(
        aggregated.style_noise().is_empty(),
        "a payment path that never contacts a provider is filed as style noise: {:?}",
        aggregated.style_noise()
    );
}

// --- the claim-evidence fixtures (P14-T004) ------------------------------
//
// The three fixtures below are not projects and fire no scanner. Each is a
// recording: a claim an AI made, and the harness events behind it, declared in
// the fixture's `scenario.json`. They are read here the way a harness's events
// reach SURE — as JSON documents through `ingest_event_str`, stored through the
// session event store into a scratch store under `target/tmp` — and what is
// asserted is what SURE says about them.
//
// Each fixture is read twice, and each has a control. The control is the thing
// this half cannot do without: a claim checker that answered `cannot_confirm` to
// everything would satisfy all three required outcomes at once, so every one of
// them is paired with the same recording with one field of one event moved,
// which must come back `confirmed`.

/// One event, as a fixture declares it.
#[derive(Debug, Clone)]
struct DeclaredEvent {
    event_type: String,
    timestamp: String,
    payload: Value,
}

/// One evidence item, in the terms a reader of the fixture cares about.
#[derive(Debug, PartialEq)]
struct Attached {
    class: EvidenceClass,
    subject: AnchorSubject,
    location: String,
    locator: String,
    excerpt: String,
    belongs_to_this_state: bool,
    severity: Severity,
    freshness: Freshness,
}

/// What SURE answered about one recording, reduced to the part that is the
/// recording's rather than the store's.
///
/// Row ids and evidence ids are generated per call, so two readings of the same
/// recording differ in those and in nothing else. This is the reduction that
/// makes "the two paths agree" a checkable sentence instead of a comparison
/// between two values that can never be equal.
#[derive(Debug, PartialEq)]
struct Answer {
    assessment: ClaimAssessment,
    reason: String,
    evidence: Vec<Attached>,
}

/// Everything one reading of a recording produced.
struct Recorded {
    checked: CheckedClaim,
    answer: Answer,
    rendered: String,
    ingested: Vec<IngestedEvent>,
}

/// The scenario document of one fixture.
fn scenario_of(id: &str) -> Value {
    let path = fixture(id).join("scenario.json");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
    serde_json::from_str(&text)
        .unwrap_or_else(|error| panic!("{} is not valid JSON: {error}", path.display()))
}

/// The `claim_check` block of one fixture's scenario.
fn claim_block(id: &str) -> Value {
    scenario_of(id)
        .get("claim_check")
        .cloned()
        .unwrap_or_else(|| {
            panic!("fixtures/adversarial/{id}/scenario.json declares no claim_check block")
        })
}

/// The events one block declares.
fn declared_events(id: &str, block: &Value, key: &str) -> Vec<DeclaredEvent> {
    let events = block
        .get(key)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("{id}: the `{key}` list is missing or is not an array"));
    assert!(!events.is_empty(), "{id}: `{key}` declares no events");
    events
        .iter()
        .map(|event| {
            assert!(
                event.is_object(),
                "{id}: an entry in `{key}` is not an event object"
            );
            let string = |name: &str| {
                let value = event
                    .get(name)
                    .and_then(Value::as_str)
                    .unwrap_or_else(|| panic!("{id}: an event in `{key}` declares no `{name}`"));
                assert!(
                    !value.is_empty(),
                    "{id}: an event in `{key}` declares an empty `{name}`"
                );
                value.to_owned()
            };
            let payload = event
                .get("payload")
                .cloned()
                .unwrap_or_else(|| panic!("{id}: an event in `{key}` declares no payload"));
            // The envelope's own rule, and the reason this is asserted rather
            // than assumed: an event with no body has an empty body, and `null`
            // would make "the adapter sent nothing" and "the adapter sent an
            // empty body" the same document.
            assert!(
                payload.is_object(),
                "{id}: the payload of an event in `{key}` is not an object"
            );
            DeclaredEvent {
                event_type: string("event_type"),
                timestamp: string("timestamp"),
                payload,
            }
        })
        .collect()
}

/// The JSON document a harness would send for one declared event.
///
/// Built from the declared fields and nothing else, so the fixture is graded
/// against the wire document a real adapter produces rather than against an
/// `EventEnvelope` assembled in Rust — which would prove nothing about the JSON
/// the fixture ships.
fn event_document(event: &DeclaredEvent) -> String {
    json!({
        "schema_version": sure_core::PROTOCOL_VERSION,
        "source": "claude-code",
        "event_type": event.event_type,
        "timestamp": event.timestamp,
        "capability_tier": sure_core::capability::CapabilityTier::Observed.number(),
        "session_id": "session-1",
        "project_root": CLAIM_PROJECT_ROOT,
        "payload": event.payload,
    })
    .to_string()
}

/// The JSON document a harness would send for one declared claim.
fn agent_claim_document(claim: &Value) -> String {
    let string = |name: &str| {
        claim
            .get(name)
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("the declared claim has no `{name}`"))
            .to_owned()
    };
    json!({
        "schema_version": sure_core::PROTOCOL_VERSION,
        "source": "claude-code",
        "event_type": sure_core::claim_capture::AGENT_CLAIM_EVENT_TYPE,
        "timestamp": string("timestamp"),
        "capability_tier": sure_core::capability::CapabilityTier::Observed.number(),
        "session_id": "session-1",
        "project_root": CLAIM_PROJECT_ROOT,
        "payload": {
            "id": string("id"),
            "claim_text": string("claim_text"),
            "claim_type": string("claim_type"),
        },
    })
    .to_string()
}

/// Reduce a checked claim to the part that is the recording's.
///
/// The two things dropped are the row id and the evidence id, which are minted
/// per call. Everything a fixture declares is kept, including the call the trap
/// in `stale-test-evidence` and `unknown-evidence` is about: the domain's own
/// `freshness` over evidence SURE has just refused to use.
fn answer_of(checked: &CheckedClaim, fingerprint: &FingerprintId) -> Answer {
    Answer {
        assessment: checked.assessment,
        reason: checked.reason.clone(),
        evidence: checked
            .evidence
            .iter()
            .map(|evidence| Attached {
                class: evidence.class,
                subject: evidence.anchor.subject,
                location: evidence.anchor.location.clone(),
                locator: evidence.anchor.locator.clone(),
                excerpt: evidence.anchor.excerpt.clone(),
                belongs_to_this_state: evidence.fingerprint.as_ref() == Some(fingerprint),
                severity: evidence.severity,
                freshness: sure_core::evidence::freshness(evidence, fingerprint),
            })
            .collect(),
    }
}

/// A checked claim in the report's own type, so the rendered section can be read.
///
/// The mapping is the one `pipeline::claim_of` makes and it is made again rather
/// than shared, because a session identifier is not recoverable from a stored
/// claim row and this test has no session to attribute a claim to.
fn claim_of(checked: &CheckedClaim) -> Claim {
    Claim {
        id: ClaimId::parse(checked.id.as_str()).unwrap_or_else(|_| ClaimId::generate()),
        claim_text: checked.claim_text.clone(),
        claim_type: checked.claim_type.clone(),
        assessment: checked.assessment,
        reason: checked.reason.clone(),
        evidence: checked.evidence.clone(),
        session: None,
    }
}

/// Read one declared recording the way a harness's recording reaches SURE.
///
/// The claim and every event are ingested as the documents a harness sends, and
/// stored into a scratch store under `target/tmp` — never the machine's own
/// store. Then SURE is asked twice: once through the store, which is what
/// `sure check` reads, and once through [`check_claims_against_events`] over the
/// same events in the order that function documents. The two answers must be
/// equal, so what the fixture asserts is a property of the recording rather than
/// of either path through it.
fn read_recording(what: &str, scratch: &str, claim: &Value, events: &[DeclaredEvent]) -> Recorded {
    let directory = Scratch::under("claim evidence fixtures", scratch);
    let store = Store::open_at(&directory.project.join("sure.db"))
        .unwrap_or_else(|error| panic!("{what}: the scratch store does not open: {error}"));
    let fingerprint = FingerprintId::generate();

    let claim_event = ingest_event_str(&agent_claim_document(claim)).unwrap_or_else(|error| {
        panic!("{what}: the declared claim is not a document SURE ingests: {error}")
    });
    let captured = capture_agent_claim(&claim_event, &store, CLAIM_PROJECT_ROOT, &fingerprint)
        .unwrap_or_else(|error| panic!("{what}: SURE refused the declared claim: {error}"));
    assert!(
        matches!(captured, ClaimCaptureOutcome::Captured(_)),
        "{what}: the claim event was stored as something other than a claim"
    );

    let mut ingested: Vec<IngestedEvent> = Vec::new();
    for event in events {
        let stored = ingest_event_str(&event_document(event)).unwrap_or_else(|error| {
            panic!(
                "{what}: SURE refused the declared event {} at {}: {error}",
                event.event_type, event.timestamp
            )
        });
        SessionEventStore::new(&store)
            .persist(
                &stored,
                CLAIM_PROJECT_ROOT,
                &fingerprint,
                &EventId::generate(),
            )
            .unwrap_or_else(|error| {
                panic!(
                    "{what}: the declared event {} at {} does not store: {error}",
                    event.event_type, event.timestamp
                )
            });
        ingested.push(stored);
    }

    let through_the_store = check_claims_in_store(&store, CLAIM_PROJECT_ROOT, &fingerprint)
        .unwrap_or_else(|error| panic!("{what}: the claim check failed: {error}"));
    assert_eq!(
        through_the_store.len(),
        1,
        "{what}: the recording holds one claim and SURE checked {} of them",
        through_the_store.len()
    );

    let documents = vec![ClaimDocument {
        record_id: 0,
        id: claim["id"].as_str().unwrap_or_default().to_owned(),
        claim_text: claim["claim_text"].as_str().unwrap_or_default().to_owned(),
        claim_type: claim["claim_type"].as_str().map(str::to_owned),
    }];
    let newest_first: Vec<IngestedEvent> = ingested.iter().rev().cloned().collect();
    let direct = check_claims_against_events(&documents, &newest_first, &fingerprint);

    let answer = answer_of(&through_the_store[0], &fingerprint);
    assert_eq!(
        answer,
        answer_of(&direct[0], &fingerprint),
        "{what}: the store path and the direct path disagree about the same recording"
    );

    let rendered = render_claim_section(&[claim_of(&through_the_store[0])]);
    Recorded {
        checked: through_the_store[0].clone(),
        answer,
        rendered,
        ingested,
    }
}

/// Every fact one `expect` block declares, asserted against what SURE answered.
///
/// The expectations come out of the scenario rather than being restated here, so
/// the two can only drift apart by this test failing. The values that decide
/// whether a fixture is right are asserted by equality — the assessment, the
/// sentence a reader is shown, the count, the anchor, the class and the
/// freshness — and the rendered report section is compared whole, so what a
/// person would read is graded and not only what is behind it.
fn assert_declared_outcome(
    what: &str,
    claim: &Value,
    events: &[DeclaredEvent],
    expect: &Value,
    recorded: &Recorded,
) {
    let declared_assessment: ClaimAssessment = serde_json::from_value(expect["assessment"].clone())
        .unwrap_or_else(|error| {
            panic!(
                "{what}: `{}` is not a claim assessment: {error}",
                expect["assessment"]
            )
        });
    assert_eq!(
        recorded.answer.assessment, declared_assessment,
        "{what}: the assessment changed"
    );
    let declared_reason = expect["reason"]
        .as_str()
        .unwrap_or_else(|| panic!("{what}: the expectation declares no reason"));
    assert_eq!(
        recorded.answer.reason, declared_reason,
        "{what}: the sentence a reader is shown changed"
    );

    match expect["staleness_reason"].as_str() {
        // A reason that comes from a staleness is asserted to be that reason's
        // own sentence rather than a second copy of it, so the sentence a reader
        // sees and the reason the code reached cannot drift apart unnoticed.
        Some(name) => {
            let declared: StalenessReason = serde_json::from_value(
                expect["staleness_reason"].clone(),
            )
            .unwrap_or_else(|error| panic!("{what}: `{name}` is not a staleness reason: {error}"));
            assert_eq!(
                recorded.answer.reason,
                declared.plain_explanation(),
                "{what}: the reason is not `{name}`'s own sentence"
            );
        }
        None => assert!(
            expect["staleness_reason"].is_null(),
            "{what}: staleness_reason is neither a name nor null"
        ),
    }

    let declared_count = expect["evidence_count"]
        .as_u64()
        .unwrap_or_else(|| panic!("{what}: the expectation declares no evidence_count"));
    assert_eq!(
        recorded.answer.evidence.len() as u64,
        declared_count,
        "{what}: SURE attached {} evidence items and the fixture declares {declared_count}",
        recorded.answer.evidence.len()
    );

    let declared_class: EvidenceClass = serde_json::from_value(expect["evidence_class"].clone())
        .unwrap_or_else(|error| {
            panic!(
                "{what}: `{}` is not an evidence class: {error}",
                expect["evidence_class"]
            )
        });

    if declared_count == 0 {
        // Nothing was attached, and the class says exactly that: the
        // vocabulary's weakest class is the one for "not enough evidence to say
        // anything", and a stronger one would be a class attached to nothing.
        assert!(
            recorded.answer.evidence.is_empty(),
            "{what}: the count is zero and there is evidence"
        );
        assert_eq!(
            declared_class,
            EvidenceClass::Unknown,
            "{what}: an outcome with no evidence at all is recorded with the class that means exactly that"
        );
        assert!(
            expect["anchored_to"].is_null(),
            "{what}: the fixture declares an anchor for an outcome that has no evidence to anchor"
        );
        assert!(
            expect["evidence_freshness"].is_null(),
            "{what}: the fixture declares a freshness for evidence that does not exist"
        );
        assert_rendered_section(what, claim, declared_assessment, declared_reason, recorded);
        return;
    }

    for item in &recorded.answer.evidence {
        assert_eq!(
            item.class, declared_class,
            "{what}: the evidence class changed"
        );
        assert!(
            item.belongs_to_this_state,
            "{what}: the evidence is not bound to the project state it was checked against"
        );
        assert_eq!(
            item.severity,
            Severity::Note,
            "{what}: the weight carried by claim evidence changed"
        );
        assert!(
            item.excerpt.is_empty(),
            "{what}: SURE recorded the event's name and time, so there is nothing to quote"
        );
    }

    let anchor = &expect["anchored_to"];
    let index = anchor["event_index"]
        .as_u64()
        .unwrap_or_else(|| panic!("{what}: the declared anchor points at no event"))
        as usize;
    let event = events.get(index).unwrap_or_else(|| {
        panic!(
            "{what}: the declared anchor points at event {index} and the recording declares {}",
            events.len()
        )
    });
    // The anchor must be the event the fixture declares, named in the
    // expectation rather than assumed: the scenario's own two copies of the
    // event's name and time have to agree before SURE's answer is compared with
    // either of them.
    assert_eq!(
        anchor["location"].as_str(),
        Some(event.event_type.as_str()),
        "{what}: the declared anchor names an event the recording does not declare"
    );
    assert_eq!(
        anchor["locator"].as_str(),
        Some(event.timestamp.as_str()),
        "{what}: the declared anchor times an event the recording does not time that way"
    );

    let item = &recorded.answer.evidence[0];
    assert_eq!(
        item.subject,
        AnchorSubject::Event,
        "{what}: the anchor is not the recorded event"
    );
    assert_eq!(
        item.location, event.event_type,
        "{what}: the anchor does not point at the event SURE attached"
    );
    assert_eq!(
        item.locator, event.timestamp,
        "{what}: the anchor does not carry the event's own timestamp"
    );

    let declared_freshness: Freshness =
        serde_json::from_value(expect["evidence_freshness"].clone()).unwrap_or_else(|error| {
            panic!(
                "{what}: `{}` is not a freshness: {error}",
                expect["evidence_freshness"]
            )
        });
    assert_eq!(
        item.freshness, declared_freshness,
        "{what}: the freshness of the attached evidence changed"
    );

    assert_rendered_section(what, claim, declared_assessment, declared_reason, recorded);
}

/// The section a person reads, built from the fixture's own declarations.
///
/// This is what makes the acceptance sentence's word "shown" a graded fact: the
/// header, the label, the claim text, the indent and the reason are assembled
/// from the scenario, and the product's rendered section has to be that string
/// exactly.
fn assert_rendered_section(
    what: &str,
    claim: &Value,
    assessment: ClaimAssessment,
    reason: &str,
    recorded: &Recorded,
) {
    let claim_text = claim["claim_text"]
        .as_str()
        .unwrap_or_else(|| panic!("{what}: the declared claim has no text"));
    let expected = format!(
        "AI claims\n---------\n- {claim_text}\n  {}: {reason}\n",
        assessment.label()
    );
    assert_eq!(
        recorded.rendered, expected,
        "{what}: the claim section a person reads changed"
    );
}

/// The control is the fixture's own recording with one field of one event moved,
/// and no field it could hide a second difference in.
fn assert_the_control_is_one_thing_moved(id: &str, block: &Value, control: &Value) {
    let fixture_events = declared_events(id, block, "events");
    let control_events = declared_events(id, control, "events");
    assert_eq!(
        fixture_events.len(),
        control_events.len(),
        "{id}: the control is not the fixture with one thing moved: it holds {} events against the fixture's {}",
        control_events.len(),
        fixture_events.len()
    );

    let moved = &control["moved"];
    let index = moved["event_index"]
        .as_u64()
        .unwrap_or_else(|| panic!("{id}: the control does not say which event it moved"))
        as usize;
    let field = moved["field"]
        .as_str()
        .unwrap_or_else(|| panic!("{id}: the control does not say which field it moved"));
    assert!(
        fixture_events.get(index).is_some(),
        "{id}: the control says it moved event {index} and the recording declares {}",
        fixture_events.len()
    );

    let mut keys: Vec<String> = control["events"]
        .as_array()
        .expect("the control declares events")
        .iter()
        .flat_map(|event| event.as_object().expect("an event object").keys().cloned())
        .collect();
    keys.sort();
    keys.dedup();
    assert_eq!(
        keys,
        [
            "event_type".to_owned(),
            "payload".to_owned(),
            "timestamp".to_owned()
        ],
        "{id}: a control event carries a field this check does not compare, so a difference could hide in it"
    );

    let read = |event: &DeclaredEvent, field: &str| match field {
        "event_type" => event.event_type.clone(),
        "timestamp" => event.timestamp.clone(),
        other => panic!("{id}: the control moved `{other}`, which this check cannot compare"),
    };
    assert_eq!(
        Some(read(&fixture_events[index], field).as_str()),
        moved["from"].as_str(),
        "{id}: the control says it moved `{field}` from `{}` and the fixture says `{}`",
        moved["from"],
        read(&fixture_events[index], field)
    );
    assert_eq!(
        Some(read(&control_events[index], field).as_str()),
        moved["to"].as_str(),
        "{id}: the control says it moved `{field}` to `{}` and the control says `{}`",
        moved["to"],
        read(&control_events[index], field)
    );

    for (position, (before, after)) in fixture_events.iter().zip(&control_events).enumerate() {
        for name in ["event_type", "timestamp"] {
            if position == index && name == field {
                continue;
            }
            assert_eq!(
                read(before, name),
                read(after, name),
                "{id}: the control moved something other than `{field}` of event {index}: \
                 `{name}` of event {position} differs"
            );
        }
        assert_eq!(
            before.payload, after.payload,
            "{id}: the control moved something other than `{field}` of event {index}: \
             the payload of event {position} differs"
        );
    }

    assert_ne!(
        control["expect"]["assessment"].as_str(),
        Some("cannot_confirm"),
        "{id}: the control reaches cannot_confirm too, so a checker that answered cannot_confirm \
         to everything would pass this fixture and the control would control for nothing"
    );
}

/// What the corpus writes down about this fixture and what its declared stream
/// says must agree, so the entry `evaluation/`-style readers see is not a second
/// copy that has drifted.
fn assert_the_required_outcomes_grade_the_declared_stream(id: &str, block: &Value) {
    let outcomes = scenario_of(id)["required_outcomes"]
        .as_array()
        .cloned()
        .unwrap_or_else(|| panic!("{id}/scenario.json requires no outcomes at all"));

    let claim_outcomes: Vec<&Value> = outcomes
        .iter()
        .filter(|outcome| outcome["kind"] == "claim_check")
        .collect();
    assert_eq!(
        claim_outcomes.len(),
        1,
        "{id}/scenario.json must declare exactly one `claim_check` outcome and declares {}. It is \
         the entry that says in the corpus what this fixture is graded on; with none, the outcome \
         these tests assert is written down nowhere but in this file, and the two could drift apart.",
        claim_outcomes.len()
    );
    let outcome = claim_outcomes[0];
    let expect = &block["expect"];
    assert_eq!(
        outcome["assessment"], expect["assessment"],
        "{id}: the required outcome and the declared stream disagree about the assessment"
    );
    assert_eq!(
        outcome["evidence_count"], expect["evidence_count"],
        "{id}: the required outcome and the declared stream disagree about the evidence count"
    );
    assert_eq!(
        outcome["evidence_class"], expect["evidence_class"],
        "{id}: the required outcome and the declared stream disagree about the evidence class"
    );
    assert_eq!(
        outcome["module"], block["read_by"]["module"],
        "{id}: the required outcome names one module and the declared stream names another"
    );
    assert_eq!(
        outcome["reading_module"], block["read_by"]["plain_report_module"],
        "{id}: the required outcome and the declared stream disagree about where the answer is rendered"
    );

    let controls: Vec<&Value> = outcomes
        .iter()
        .filter(|outcome| outcome["kind"] == "control")
        .collect();
    assert_eq!(
        controls.len(),
        1,
        "{id}: the corpus records {} control entries for a fixture with exactly one control",
        controls.len()
    );
    assert!(
        !controls[0]["why"].as_str().unwrap_or_default().is_empty(),
        "{id}: the control is recorded with no reason given"
    );
    assert!(
        block.get("control").is_some(),
        "{id}: the fixture declares no control, and a fixture whose answer is cannot_confirm is \
         worth nothing without one"
    );
}

#[test]
fn every_claim_fixture_these_assertions_name_is_a_fixture_this_repository_ships() {
    // The same guard the lists above have, for the same reason: a renamed
    // directory would make `scenario_of` panic above and every assertion would
    // be about a recording nobody ships. The second half is what a recording
    // must not grow: these fixtures have no project, so a language manifest in
    // one of them would put it in a runnability sweep that runs nothing.
    for id in CLAIM_FIXTURES {
        let dir = fixture(id);
        assert!(dir.is_dir(), "{} is not a directory", dir.display());
        assert!(
            dir.join("scenario.json").is_file(),
            "{id} has no scenario.json, so there is no recording to read"
        );
        assert!(
            dir.join("README.md").is_file(),
            "{id} has no README.md, so nothing says in words what it traps"
        );
        for manifest in ["package.json", "pyproject.toml", "requirements.txt"] {
            assert!(
                !dir.join(manifest).is_file(),
                "{id} ships a {manifest}: these fixtures are recordings, and a runnability \
                 manifest would claim a project they do not have"
            );
        }
        let block = claim_block(id);
        assert!(
            block.get("events").and_then(Value::as_array).is_some(),
            "{id}/scenario.json declares no events to read"
        );
        assert!(
            block.get("control").is_some(),
            "{id}/scenario.json declares no control"
        );
    }
    for id in PYTHON_FIXTURES.iter().chain(TYPESCRIPT_FIXTURES) {
        assert!(
            !CLAIM_FIXTURES.contains(id),
            "{id} is in both lists, so one of the two halves is misdescribed"
        );
    }
}

#[test]
fn tests_not_run_claim_is_cannot_confirm_with_no_evidence_and_the_control_flips_it() {
    let id = "tests-not-run";
    let block = claim_block(id);
    assert_the_required_outcomes_grade_the_declared_stream(id, &block);
    let claim = &block["claim"];

    let events = declared_events(id, &block, "events");
    let what = format!("{id}: the fixture's own recording");
    let recorded = read_recording(&what, "tests-not-run fixture", claim, &events);
    assert_declared_outcome(&what, claim, &events, &block["expect"], &recorded);

    // The claim the scenario declares is the claim SURE checked, text and type,
    // so nothing about the recording is assumed.
    assert_eq!(
        recorded.checked.claim_text,
        claim["claim_text"].as_str().unwrap(),
        "{id}: the claim text did not survive capture"
    );
    assert_eq!(
        recorded.checked.claim_type, "test_ran",
        "{id}: the claim was checked as a different kind of claim"
    );
    assert_eq!(
        recorded.checked.assessment,
        ClaimAssessment::CannotConfirm,
        "{id}: the claim the AI made about its own tests is not reported as unconfirmed"
    );

    // The trap this fixture is built on, asserted and not described: the event
    // SURE refuses projects to a test run with a passing summary, so what
    // refuses it is the claim checker's family rule and not a failure to
    // understand the event.
    assert_eq!(
        recorded.ingested[1].envelope.event_type, "mytest.finished",
        "{id}: the recording's second event is not the one this check is about"
    );
    match project(&recorded.ingested[1]) {
        Some(StandardProjection::BuildTest {
            kind,
            target,
            success,
            ..
        }) => {
            assert_eq!(
                kind,
                BuildTestKind::Test,
                "{id}: the refused event no longer projects to a test run"
            );
            assert_eq!(target, "unit tests", "{id}: the target changed");
            assert!(success, "{id}: the summary changed");
        }
        other => panic!(
            "{id}: the event this fixture refuses projects to {other:?}, so the fixture no longer \
             measures the family rule it exists for"
        ),
    }

    // The control: the same recording with the event's own name moved.
    let control = &block["control"];
    assert_the_control_is_one_thing_moved(id, &block, control);
    let control_events = declared_events(id, control, "events");
    let control_what = format!("{id}: the control");
    let control_recorded = read_recording(
        &control_what,
        "tests-not-run control",
        claim,
        &control_events,
    );
    assert_declared_outcome(
        &control_what,
        claim,
        &control_events,
        &control["expect"],
        &control_recorded,
    );
}

#[test]
fn stale_test_evidence_claim_is_cannot_confirm_and_points_at_the_run_it_cannot_use() {
    let id = "stale-test-evidence";
    let block = claim_block(id);
    assert_the_required_outcomes_grade_the_declared_stream(id, &block);
    let claim = &block["claim"];

    let events = declared_events(id, &block, "events");
    let what = format!("{id}: the fixture's own recording");
    let recorded = read_recording(&what, "stale-test-evidence fixture", claim, &events);
    assert_declared_outcome(&what, claim, &events, &block["expect"], &recorded);

    // The trap the fixture records as a value, asserted here as a pair: the
    // evidence SURE refuses to use is `Fresh` by the domain's own call, because
    // `check_claim` stamps the current fingerprint on what it attaches. The
    // staleness that decides the assessment is in the reason and nowhere in that
    // call, so a reader who looked for stale evidence that way would find none.
    assert_eq!(
        recorded.answer.assessment,
        ClaimAssessment::CannotConfirm,
        "{id}: the claim is not reported as unconfirmed"
    );
    assert_eq!(
        recorded.answer.evidence[0].freshness,
        Freshness::Fresh,
        "{id}: this is the trap the fixture documents, and it has moved: `freshness` over the \
         attached evidence must answer Fresh while the assessment is cannot_confirm"
    );
    assert_eq!(
        recorded.answer.evidence[0].locator, "2026-09-14T10:22:41.000Z",
        "{id}: the evidence no longer points at the run that came before the write"
    );
    assert!(
        recorded.answer.reason.contains("later changes"),
        "{id}: the reason no longer says what went wrong: {}",
        recorded.answer.reason
    );

    // The control: the same recording with the write's timestamp moved to before
    // the run. Same evidence, same anchor, opposite answer.
    let control = &block["control"];
    assert_the_control_is_one_thing_moved(id, &block, control);
    let control_events = declared_events(id, control, "events");
    let control_what = format!("{id}: the control");
    let control_recorded = read_recording(
        &control_what,
        "stale-test-evidence control",
        claim,
        &control_events,
    );
    assert_declared_outcome(
        &control_what,
        claim,
        &control_events,
        &control["expect"],
        &control_recorded,
    );
    assert_eq!(
        control_recorded.answer.evidence[0].locator, recorded.answer.evidence[0].locator,
        "{id}: the control moved the evidence itself, so what it measures is no longer the verdict"
    );
}

#[test]
fn unknown_evidence_claim_is_cannot_confirm_and_points_at_the_run_it_cannot_date() {
    let id = "unknown-evidence";
    let block = claim_block(id);
    assert_the_required_outcomes_grade_the_declared_stream(id, &block);
    let claim = &block["claim"];

    let events = declared_events(id, &block, "events");
    let what = format!("{id}: the fixture's own recording");
    let recorded = read_recording(&what, "unknown-evidence fixture", claim, &events);
    assert_declared_outcome(&what, claim, &events, &block["expect"], &recorded);

    // The two parsers disagreeing, which is what this fixture is built on and
    // not a claim it describes: the wire accepts the leap second and the
    // timestamp parser refuses it, so the event is stored whole and can never be
    // placed.
    assert_eq!(
        recorded.ingested[1].envelope.event_type, "test.finished",
        "{id}: the recording's second event is not the test run"
    );
    assert_eq!(
        recorded.ingested[1].envelope.timestamp, "2026-06-30T23:59:60Z",
        "{id}: the unreadable timestamp did not survive ingestion"
    );
    assert_eq!(
        sure_core::diagnostics::Timestamp::parse_rfc3339("2026-06-30T23:59:60Z"),
        None,
        "{id}: SURE can read the leap second now, so this fixture no longer has a state to measure"
    );
    assert_eq!(
        recorded.answer.assessment,
        ClaimAssessment::CannotConfirm,
        "{id}: the claim is not reported as unconfirmed"
    );
    assert_eq!(
        recorded.answer.evidence.len(),
        1,
        "{id}: SURE stopped pointing at the event it found, which is the difference between \
         `found nothing` and `found this and cannot date it`"
    );
    assert_eq!(
        recorded.answer.evidence[0].locator, "2026-06-30T23:59:60Z",
        "{id}: the evidence no longer carries the timestamp SURE could not read"
    );
    assert_eq!(
        recorded.answer.evidence[0].freshness,
        Freshness::Fresh,
        "{id}: the evidence SURE refused to date is Fresh by the domain's own call, and that pair \
         is the fixture"
    );

    // The control: the same recording with the leap second moved to the second
    // before it, which SURE can read.
    let control = &block["control"];
    assert_the_control_is_one_thing_moved(id, &block, control);
    let control_events = declared_events(id, control, "events");
    let control_what = format!("{id}: the control");
    let control_recorded = read_recording(
        &control_what,
        "unknown-evidence control",
        claim,
        &control_events,
    );
    assert_declared_outcome(
        &control_what,
        claim,
        &control_events,
        &control["expect"],
        &control_recorded,
    );
}

#[test]
fn a_write_whose_own_timestamp_cannot_be_read_does_not_supersede_the_run() {
    // The other side of `unknown-evidence`, and the reason the two are named
    // together in their notes. There the proof event's own timestamp cannot be
    // read, and the run is refused; here a *later* code change's timestamp
    // cannot be read, and the run stands, because `evidence_freshness` skips an
    // event it cannot place rather than treating it as superseding. An
    // unreadable write cannot invalidate a readable run — which is a boundary of
    // the refusal `stale-test-evidence` is about, and one no fixture declares.
    let id = "unknown-evidence";
    let claim = &claim_block(id)["claim"];
    let events = vec![
        DeclaredEvent {
            event_type: "test.finished".to_owned(),
            timestamp: "2026-06-30T23:59:58Z".to_owned(),
            payload: json!({"target": "unit tests", "success": true}),
        },
        DeclaredEvent {
            event_type: "file.write".to_owned(),
            timestamp: "2026-06-30T23:59:60Z".to_owned(),
            payload: json!({"path": "src/orders.js", "written": true}),
        },
    ];

    let what = "the boundary: a readable run with an unreadable write after it";
    let recorded = read_recording(what, "unreadable write boundary", claim, &events);
    assert_eq!(
        recorded.answer.assessment,
        ClaimAssessment::Confirmed,
        "{what}: a write SURE cannot place is being treated as a later change. The fixture's notes \
         say it is skipped; if that has changed, they are wrong and so is this test."
    );
    assert_eq!(recorded.answer.evidence.len(), 1);
    assert_eq!(recorded.answer.evidence[0].locator, "2026-06-30T23:59:58Z");
    assert_eq!(recorded.answer.evidence[0].freshness, Freshness::Fresh);
}

// --- the intent fixtures -------------------------------------------------
//
// `P14-T005` added `missing-user-intent` and `intent-mismatch`. They fire no
// scanner and ship no recording: each is a **project**, small and honest, plus
// an intent supplied in-process through `sure_core::project_intent::explicit_goal`
// — the door the `--goal` flag goes through. What is compared here is what SURE
// says when it puts the two together, and the two halves are the two acceptance
// sentences:
//
// - with no intent at all, SURE may claim nothing about fulfilment, and the
//   report carries the frozen sentence. That half is **swept**, not
//   spot-checked: a gate written to answer `false` for nothing at all would pass
//   a check at zero and would be measuring nothing.
// - with an explicit goal nothing implements, SURE may say so — once, at the
//   level the gravity rule allows, and no further. The fixture pins both the
//   level and the ceiling above it, because a fixture that recorded only "it is
//   a note today" would leave the next person free to raise it.
//
// Each half carries a control that must reach the opposite answer, because the
// failure this task exists to catch is not a wrong answer: it is a reporter that
// says `cannot_confirm` to everything, or `requirement not met` to everything.
// Either would satisfy the positive half and would measure nothing.
//
// The projects ship no language manifest, for the reason the claim fixtures ship
// none: `every_runnable_fixture_directory_is_named_in_this_file` in
// `crates/sure-testkit/tests/fixture_apps.rs` fires the moment a `package.json`
// appears, and these are graded from a `Discovery` rather than by running
// anything.

/// Every fixture `P14-T005` is about, named rather than discovered for the same
/// reason the lists above are: a test that discovered them would pass on an
/// empty directory.
const INTENT_FIXTURES: &[&str] = &["missing-user-intent", "intent-mismatch"];

/// The keys of a `required_outcomes` entry that are prose about where an answer
/// comes from rather than the answer itself.
///
/// Everything outside this list is a fact the corpus records about what SURE
/// says, and every one of those is compared against the product.
const OUTCOME_PROSE: &[&str] = &[
    "kind",
    "family",
    "surface",
    "module",
    "reading_module",
    "detector",
    "title",
    "status",
    "why",
    "goal_text",
    "moved_file",
];

/// The `intent_comparison` block of one fixture's scenario.
fn intent_block(id: &str) -> Value {
    scenario_of(id)
        .get("intent_comparison")
        .cloned()
        .unwrap_or_else(|| {
            panic!("fixtures/adversarial/{id}/scenario.json declares no intent_comparison block")
        })
}

/// The goal the fixture declares.
///
/// `None` is not a missing declaration: it is the `missing-user-intent` case,
/// where the whole point is that no request was ever provided, and the assertion
/// that the fixture declares no goal is what keeps the two halves apart.
fn declared_goal(id: &str, block: &Value) -> Option<String> {
    match block.get("goal_text") {
        Some(Value::Null) => None,
        Some(Value::String(text)) => Some(text.clone()),
        other => panic!(
            "{id}/scenario.json declares `goal_text` as {other:?}, which is neither a goal nor the \
             absence of one"
        ),
    }
}

/// Every file one directory holds, relative to it, with forward slashes and
/// sorted.
///
/// The two files every fixture here declares itself in are left out: what this
/// answers for is the project, and a fixture whose declaration counted itself as
/// part of the project could not be compared against the control.
fn project_files(root: &Path) -> Vec<String> {
    let mut found = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir)
            .unwrap_or_else(|error| panic!("cannot read {}: {error}", dir.display()))
        {
            let path = entry.expect("a directory entry").path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            let relative = path
                .strip_prefix(root)
                .expect("a file under the directory being walked")
                .to_string_lossy()
                .replace('\\', "/");
            if relative == "scenario.json" || relative == "README.md" {
                continue;
            }
            found.push(relative);
        }
    }
    found.sort();
    found
}

fn shipped_project_files(id: &str) -> Vec<String> {
    project_files(&fixture(id))
}

/// SURE's real pipeline over one project, with one goal and nothing else.
///
/// `store: None` on purpose: grading a fixture must not write to anybody's
/// store, and nothing here needs one. `inspect_only` is the same promise for the
/// project — the run reads it and never executes anything in it.
fn pipelined(root: &Path, goal: Option<&str>) -> PipelineOutcome {
    pipelined_with(root, goal, ExecutionSettings::inspect_only())
}

/// A runner that cannot start anything, for a run over a fixture.
///
/// The directories under `fixtures/adversarial/` are written to make SURE
/// misbehave, and a grading harness must not carry out what they ask for. The
/// stop is asked for **before** the run reaches the runner, and `process::run`
/// reads that stop before it starts anything, so "this harness starts no process
/// from a fixture" is true for a reason a reader can point at rather than
/// because no fixture happens to propose a command this build admits.
fn nothing_starts() -> ProcessRunner {
    let stop = Cancellation::new();
    stop.cancel();
    ProcessRunner::new(stop)
}

/// The same run, with what the user has allowed the one argument that changes.
///
/// `ExecutionSettings` is the pair `sure check` hands the pipeline, and the
/// settings here come from `Authority::execution()` rather than from a literal:
/// a fixture whose control moved the mode by writing a different literal would
/// be measuring this file's idea of the rule rather than the rule.
///
/// The runner is the one above, not a fake: a fixture whose control moved the
/// mode to `host_confirmed` reaches the real runner and gets the real product's
/// answer for a process that did not start, which is an error rather than a
/// pass. What a control grants is a permission, never an execution.
fn pipelined_with(
    root: &Path,
    goal: Option<&str>,
    execution: ExecutionSettings,
) -> PipelineOutcome {
    let config = Config::default();
    let runner = nothing_starts();
    Pipeline {
        project: root,
        purpose: Purpose::Check,
        config: &config,
        execution,
        store: None,
        goal,
        analysis: Default::default(),
        external_commands: &[],
        runner: &runner,
    }
    .run()
}

fn record_of(outcome: &PipelineOutcome) -> &RunOutcome {
    outcome
        .run
        .as_ref()
        .expect("the pipeline finished without a run outcome")
}

/// The summary a person reads, line by line.
fn rendered_summary(outcome: &PipelineOutcome) -> Vec<String> {
    render_summary(&record_of(outcome).verdict)
        .lines()
        .map(str::to_owned)
        .collect()
}

/// A declared list of lines.
fn declared_lines(value: &Value, what: &str) -> Vec<String> {
    value
        .as_array()
        .unwrap_or_else(|| panic!("{what} is not an array of lines"))
        .iter()
        .map(|line| {
            line.as_str()
                .unwrap_or_else(|| panic!("{what} holds a line that is not a string"))
                .to_owned()
        })
        .collect()
}

/// The one `required_outcomes` entry of a given kind.
fn required_outcome<'a>(id: &str, outcomes: &'a [Value], kind: &str) -> &'a Value {
    let matching: Vec<&Value> = outcomes
        .iter()
        .filter(|outcome| outcome["kind"].as_str() == Some(kind))
        .collect();
    assert_eq!(
        matching.len(),
        1,
        "{id}/scenario.json must declare exactly one `{kind}` outcome and declares {}. It is the \
         entry that says in the corpus what this fixture is graded on; with none, the answer these \
         tests assert is written down nowhere but in this file, and the two could drift apart.",
        matching.len()
    );
    matching[0]
}

/// Whether an outcome is one of the kinds that records an answer.
///
/// `control` is deliberately not one: it is collected on its own, against the
/// control's own declaration, because the two blocks are one thing apart and
/// grading them as a single set would let the pair agree on a wrong answer.
fn records_an_answer(kind: &str) -> bool {
    matches!(
        kind,
        "intent_status"
            | "comparison_detail"
            | "intent_implementation"
            | "execution_refusal"
            | "container_absence"
            | "container_limit"
    )
}

/// What the corpus writes down about an intent fixture and what the fixture
/// itself declares must be the same answers, in both directions.
///
/// The forward direction is the drift check: the entry a reader of `evaluation/`
/// sees is not a second copy that has gone stale. The reverse direction is the
/// one that makes deleting an outcome a red test — without it, a corpus entry
/// could be removed and everything left would still pass while grading less.
fn assert_the_outcomes_account_for_the_declared_expectation(id: &str, block: &Value) {
    let outcomes = scenario_of(id)["required_outcomes"]
        .as_array()
        .cloned()
        .unwrap_or_else(|| panic!("{id}/scenario.json requires no outcomes at all"));
    assert!(
        !outcomes.is_empty(),
        "{id}/scenario.json requires no outcomes at all"
    );

    let main: Vec<(String, Value)> = outcomes
        .iter()
        .filter(|outcome| outcome["kind"].as_str().is_some_and(records_an_answer))
        .flat_map(answer_keys)
        .collect();
    assert!(
        !main.is_empty(),
        "{id}/scenario.json records no outcome about what SURE answers"
    );
    assert_answers_account_for(id, &main, &block["expect"], "the fixture's expect block");

    let control: Vec<(String, Value)> = outcomes
        .iter()
        .filter(|outcome| outcome["kind"].as_str() == Some("control"))
        .flat_map(answer_keys)
        .collect();
    let declared_control = block
        .get("control")
        .unwrap_or_else(|| panic!("{id}/scenario.json declares no control"));
    assert!(
        !control.is_empty(),
        "{id}/scenario.json records no outcome for its control, and a fixture whose answer is \
         cannot_confirm is worth nothing without one"
    );
    assert_answers_account_for(
        id,
        &control,
        &declared_control["expect"],
        "the fixture's control",
    );
}

/// The answer keys of one outcome, which is everything but the prose.
fn answer_keys(outcome: &Value) -> Vec<(String, Value)> {
    outcome
        .as_object()
        .unwrap_or_else(|| panic!("a required outcome is not an object: {outcome}"))
        .iter()
        .filter(|(key, _)| !OUTCOME_PROSE.contains(&key.as_str()))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}

fn assert_answers_account_for(id: &str, answers: &[(String, Value)], declared: &Value, what: &str) {
    let declared = declared
        .as_object()
        .unwrap_or_else(|| panic!("{id}: {what} declares no answers"));
    for (key, value) in answers {
        let expected = declared.get(key).unwrap_or_else(|| {
            panic!(
                "{id}: the corpus records `{key}`, and {what} does not declare it, so the entry \
                 asserts something no fixture says"
            )
        });
        assert_eq!(
            expected, value,
            "{id}: the corpus and {what} disagree about `{key}`"
        );
    }
    for key in declared.keys() {
        assert!(
            answers.iter().any(|(recorded, _)| recorded == key),
            "{id}: {what} declares `{key}` and no required_outcomes entry records it, so nothing \
             in the corpus grades it"
        );
    }
}

/// Criterion 1's guarantee, swept rather than spot-checked.
///
/// The counts come from the fixture, and the sweep is wider than the fixture:
/// 0..=4096 by loop and the two points at the top of `usize`. A gate that had
/// been written to answer `false` for nothing at all would pass a check at zero,
/// and one that counted evidence wrongly would very likely pass a check at 1.
fn assert_no_count_lets_an_empty_intent_claim_fulfilment(id: &str, declared: &Value) {
    let points: Vec<usize> = declared["swept_requirement_counts"]
        .as_array()
        .unwrap_or_else(|| panic!("{id}: the fixture declares no counts to sweep"))
        .iter()
        .map(|point| {
            usize::try_from(point.as_u64().unwrap_or_else(|| {
                panic!("{id}: a swept requirement count is not a number: {point}")
            }))
            .expect("a swept requirement count fits in usize")
        })
        .collect();
    assert!(points.contains(&0), "{id}: the sweep does not include zero");
    assert_eq!(
        declared["sweep_includes_the_top_of_the_range"],
        json!(true),
        "{id}: the fixture no longer claims to sweep the top of the range"
    );

    let intent = ProjectIntent::empty();
    for count in points
        .iter()
        .copied()
        .chain(0..=4096)
        .chain([usize::MAX - 1, usize::MAX])
    {
        assert!(
            !may_claim_full_fulfilment(&intent, count),
            "{id}: an intent with no user requirement claimed full fulfilment at {count} pieces of \
             fresh evidence"
        );
    }
    for count in [0, 4096, usize::MAX] {
        assert_eq!(
            json!(may_claim_full_fulfilment(&intent, count)),
            declared["may_claim_full_fulfilment"],
            "{id}: the fixture's declared answer about fulfilment and the gate's answer disagree at \
             {count}"
        );
    }
}

#[test]
fn every_intent_fixture_these_assertions_name_is_a_fixture_this_repository_ships() {
    // The same guard the lists above have, for the same reason: a renamed
    // directory would make every assertion below about a project nobody ships.
    // The second half is what these fixtures must not grow: they are graded from
    // a `Discovery`, so a language manifest in one of them would put it in a
    // runnability sweep that runs nothing.
    for id in INTENT_FIXTURES {
        let dir = fixture(id);
        assert!(dir.is_dir(), "{} is not a directory", dir.display());
        assert!(
            dir.join("scenario.json").is_file(),
            "{id} has no scenario.json, so there is no declaration to read"
        );
        assert!(
            dir.join("README.md").is_file(),
            "{id} has no README.md, so nothing says in words what it traps"
        );
        for manifest in [
            "package.json",
            "pyproject.toml",
            "requirements.txt",
            "Cargo.toml",
        ] {
            assert!(
                !dir.join(manifest).is_file(),
                "{id} ships a {manifest}: these fixtures are projects graded from a `Discovery`, \
                 and a runnability manifest would claim a language half they do not have"
            );
        }
        let block = intent_block(id);
        assert!(
            block.get("control").is_some(),
            "{id}/scenario.json declares no control, and a fixture whose answer is a permission is \
             worth nothing without one"
        );
        assert!(
            block["control"]["moved"]["what"].as_str().is_some(),
            "{id}/scenario.json declares a control that does not say what moved"
        );
        assert!(
            !block["control"]["why"]
                .as_str()
                .unwrap_or_default()
                .is_empty(),
            "{id}/scenario.json declares a control with no reason given"
        );
    }
    for id in PYTHON_FIXTURES
        .iter()
        .chain(TYPESCRIPT_FIXTURES)
        .chain(CLAIM_FIXTURES)
    {
        assert!(
            !INTENT_FIXTURES.contains(id),
            "{id} is in both lists, so one of the two halves is misdescribed"
        );
    }
}

#[test]
fn missing_user_intent_never_claims_fulfilment_and_the_control_supplies_the_request() {
    let id = "missing-user-intent";
    let block = intent_block(id);
    assert_the_outcomes_account_for_the_declared_expectation(id, &block);

    // The fixture is the project it declares, and it is the case where no
    // request was provided — asserted rather than assumed, because a goal added
    // here would turn this into the other fixture.
    assert_eq!(
        shipped_project_files(id),
        declared_lines(&block["project"]["files"], "the declared project"),
        "{id} ships a different project from the one it declares"
    );
    assert_eq!(
        declared_goal(id, &block),
        None,
        "{id}/scenario.json declares a goal, and this is the fixture for the case where none was \
         ever provided"
    );
    let files_before = shipped_project_files(id);

    let outcome = pipelined(&fixture(id), None);
    let record = record_of(&outcome);
    let declared = &block["expect"];

    // The intent the run compared against is the empty one the sweep above
    // sweeps, so the two halves of this test are about the same value.
    assert_eq!(
        record.intent,
        ProjectIntent::empty(),
        "{id}: the run compared against something other than an empty intent"
    );

    // The comparison itself, reached directly: the pipeline keeps only
    // `.findings` and drops the other four fields, so `checked == 0` and the
    // limitation are reachable here and nowhere else. `checked == 0` is what
    // says SURE compared nothing at all; `unmatched == 0` is what says the
    // empty comparison is not the report of one that failed and found nothing;
    // `findings == 0` is what says nothing was invented about a project that
    // was never asked to do anything.
    let project = discovery(id);
    let compared = compare_intent_to_project(&ProjectIntent::empty(), &project);
    let outcomes = scenario_of(id)["required_outcomes"]
        .as_array()
        .cloned()
        .expect("required_outcomes is an array");
    let comparison = required_outcome(id, &outcomes, "comparison_detail");
    assert_eq!(
        json!(compared.user_requirements_checked),
        comparison["user_requirements_checked"],
        "{id}: the number of user requirements SURE checked without a request has changed"
    );
    assert_eq!(
        json!(compared.matched.len()),
        comparison["matched"],
        "{id}: something matched against an intent with no requirements in it"
    );
    assert_eq!(
        json!(compared.unmatched.len()),
        comparison["unmatched"],
        "{id}: the empty comparison reports a requirement that did not match"
    );
    assert_eq!(
        json!(compared.limitation),
        comparison["limitation"],
        "{id}: the comparison's own limitation field is no longer the frozen sentence. It is what \
         the reader-facing half carries by a different route, and `None` would say SURE had a \
         request it could compare against."
    );
    assert_eq!(
        json!(compared.findings.len()),
        comparison["findings"],
        "{id}: the comparison of an empty intent invented a proposal"
    );

    assert_eq!(
        json!(record.intent.requirement_claim()),
        declared["requirement_claim"],
        "{id}: the claim the report is allowed to make has changed"
    );
    assert_eq!(
        json!(record.verdict.must_caveat_requirements()),
        json!(true),
        "{id}: the verdict no longer says the report must carry the caveat"
    );
    assert_eq!(
        json!(record.intent_caveat),
        declared["intent_caveat"],
        "{id}: the caveat is no longer the frozen sentence, or is no longer carried at all"
    );
    assert!(
        !record.verdict.is_ready_for_hand_off(),
        "{id}: the report claims the project is ready to hand off, and it cannot know that"
    );

    // The whole of what a person reads, by equality — not a substring of it. The
    // caveat is one of these lines, and so is the sentence that says the project
    // is not ready, so a report that claimed fulfilment anywhere would have to
    // disagree with the fixture to do it.
    assert_eq!(
        rendered_summary(&outcome),
        declared_lines(&declared["summary_lines"], "the declared summary"),
        "{id}: the summary a person reads has changed"
    );

    assert_no_count_lets_an_empty_intent_claim_fulfilment(id, declared);

    // The control. One thing moves, and it is not in the project: the request
    // that was never provided is provided.
    let control = &block["control"];
    assert_eq!(
        control["moved"]["what"].as_str(),
        Some("the intent"),
        "{id}: the control says it moved something other than the intent, and a control that \
         rebuilt the project would measure a different thing"
    );
    let goal = control["goal_text"]
        .as_str()
        .unwrap_or_else(|| panic!("{id}: the control declares no goal"));
    let supplied = explicit_goal(goal).expect("the declared control goal is a goal");

    // The control's comparison, reached the same way as the fixture's: the
    // supplied request against the same project, read a second time, with the
    // two reads asserted equal so the intent is the only thing that moved.
    let control_project = discovery(id);
    assert_eq!(
        control_project, project,
        "{id}: the control read a different project from the one the fixture was graded against, so \
         it is no longer the intent that flipped the answer"
    );
    let control_compared = compare_intent_to_project(&supplied, &control_project);

    let control_outcome = pipelined(&fixture(id), Some(goal));
    let control_record = record_of(&control_outcome);
    let declared_control = &control["expect"];
    assert_eq!(
        control_record.project_root, record.project_root,
        "{id}: the control read a different project, so what it measures is no longer the intent"
    );
    assert_eq!(
        control_record.intent_caveat, None,
        "{id}: the caveat survives a request being supplied, so it is not about the missing request"
    );
    assert_eq!(
        json!(control_record.intent.requirement_claim()),
        declared_control["requirement_claim"],
        "{id}: supplying the request did not make the project comparable"
    );

    // The control's comparison, by equality on every answer it declares — none
    // of them is left standing on its own. A request supplied against a project
    // that answers it must check one requirement and match it; anything less
    // means the fixture's silence about fulfilment is a reporter's pessimism
    // rather than a fact about the missing request.
    assert_eq!(
        json!(control_compared.user_requirements_checked),
        declared_control["user_requirements_checked"],
        "{id}: the supplied request was not checked as one requirement"
    );
    assert_eq!(
        json!(control_compared.matched.len()),
        declared_control["matched"],
        "{id}: the supplied request did not match the fixture's own route"
    );
    assert_eq!(
        json!(control_compared.unmatched.len()),
        declared_control["unmatched"],
        "{id}: the control still reports an unmatched requirement"
    );
    assert_eq!(
        json!(control_compared.limitation),
        declared_control["limitation"],
        "{id}: the control's limitation changed, and `None` is what says a comparable request has \
         nothing to caveat"
    );
    assert_eq!(
        json!(control_compared.findings.len()),
        declared_control["findings"],
        "{id}: the control produced a proposal, and the whole fixture rests on it producing none"
    );

    // The anchor the control matched on, by its parts rather than by a debug
    // string: this is what makes `matched == 1` a measurement rather than a
    // count somebody could satisfy by matching anything.
    let declared_anchor = &declared_control["matched_anchor"];
    assert_eq!(
        control_compared.matched[0].anchors.len(),
        1,
        "{id}: the control's requirement matched more than one anchor, so the fixture's record of \
         where it matched is incomplete"
    );
    assert_eq!(
        declared_anchor["kind"].as_str(),
        Some("route"),
        "{id}: the control's declared anchor is no longer a route"
    );
    match &control_compared.matched[0].anchors[0] {
        IntentMatchAnchor::Route {
            path,
            declared_in,
            line,
        } => {
            assert_eq!(
                path,
                declared_anchor["path"].as_str().unwrap_or_default(),
                "{id}: the control matched a different route"
            );
            assert_eq!(
                declared_in,
                declared_anchor["declared_in"].as_str().unwrap_or_default(),
                "{id}: the control matched a route declared in a different file"
            );
            assert_eq!(
                json!(line),
                declared_anchor["line"],
                "{id}: the control matched a route declared on a different line"
            );
        }
        other => {
            panic!("{id}: the control matched on {other:?}, and the fixture declares a route")
        }
    }

    assert_eq!(
        rendered_summary(&control_outcome),
        declared_lines(
            &declared_control["summary_lines"],
            "the declared control summary"
        ),
        "{id}: the control's summary is not what the fixture declares"
    );

    // The flip, in both directions and by equality: the summary loses exactly
    // the caveat line and gains nothing. Half a flip — a caveat that vanished
    // along with something else — would still be a reporter changing its answer
    // for a reason nobody recorded.
    let fixture_lines = rendered_summary(&outcome);
    let control_lines = rendered_summary(&control_outcome);
    let caveat = declared["intent_caveat"]
        .as_str()
        .expect("the fixture declares a caveat");
    assert_eq!(
        control_lines.len(),
        fixture_lines.len() - 1,
        "{id}: the control's summary is not the fixture's with one line fewer"
    );
    let without_the_caveat: Vec<String> = fixture_lines
        .iter()
        .filter(|line| line.as_str() != caveat)
        .cloned()
        .collect();
    assert_eq!(
        without_the_caveat.len(),
        fixture_lines.len() - 1,
        "{id}: the summary carries the caveat more than once, so removing it is not one thing"
    );
    assert_eq!(
        without_the_caveat, control_lines,
        "{id}: the control's summary is not the fixture's with the caveat line removed"
    );

    // The gate over the same intent the control was compared against: false at
    // zero, true from one requirement's worth of fresh evidence up. A gate that
    // answered false to everything would satisfy the fixture above and fails
    // here.
    assert_eq!(
        supplied.user_requirements().count(),
        1,
        "{id}: the supplied goal is not one user requirement"
    );
    assert!(
        !may_claim_full_fulfilment(&supplied, 0),
        "{id}: a request with no fresh evidence behind it claimed fulfilment"
    );
    for count in [1, 2, 64, usize::MAX - 1, usize::MAX] {
        assert_eq!(
            json!(may_claim_full_fulfilment(&supplied, count)),
            declared_control["may_claim_full_fulfilment"],
            "{id}: the gate and the fixture's control disagree at {count} pieces of fresh evidence"
        );
    }

    assert_eq!(
        shipped_project_files(id),
        files_before,
        "{id}: a run wrote into the fixture's own project"
    );
}

#[test]
fn an_explicit_intent_mismatch_reaches_one_note_and_no_further_and_the_control_flips_it() {
    let id = "intent-mismatch";
    let block = intent_block(id);
    assert_the_outcomes_account_for_the_declared_expectation(id, &block);

    let goal = declared_goal(id, &block).expect("the fixture declares a goal");
    assert_eq!(
        shipped_project_files(id),
        declared_lines(&block["project"]["files"], "the declared project"),
        "{id} ships a different project from the one it declares"
    );
    let declared = &block["expect"];
    let intent = explicit_goal(&goal).expect("the declared goal is a goal");
    let project = discovery(id);

    // Criterion 2, by equality, from the comparison itself — the pipeline keeps
    // only `.findings` and drops the other four fields, so what says SURE
    // compared anything at all is only reachable here.
    let compared = compare_intent_to_project(&intent, &project);
    assert_eq!(
        json!(compared.user_requirements_checked),
        declared["user_requirements_checked"],
        "{id}: the number of user requirements SURE checked has changed"
    );
    assert_eq!(
        json!(compared.matched.len()),
        declared["matched"],
        "{id}: the number of requirements with an anchor has changed"
    );
    assert_eq!(
        json!(compared.unmatched.len()),
        declared["unmatched"],
        "{id}: the number of requirements with no anchor has changed"
    );
    assert_eq!(
        json!(compared.limitation),
        declared["limitation"],
        "{id}: the comparison's own limitation field is no longer what the fixture declares. It has \
         no production reader — the caveat a person sees travels through the verdict — and it is \
         asserted here because `None` is what says SURE had a request it could compare against."
    );

    assert_eq!(
        json!(compared.findings.len()),
        declared["findings"],
        "{id}: the mismatch produced a different number of proposals"
    );
    let proposal = &compared.findings[0];
    assert_eq!(
        proposal.id().as_str(),
        declared["finding_id"].as_str().unwrap_or_default(),
        "{id}: the proposal's identifier changed, so the corpus is recording a check nothing emits"
    );
    assert_eq!(
        proposal.title(),
        declared["finding_title"].as_str().unwrap_or_default(),
        "{id}: the sentence a person is shown about the mismatch changed"
    );
    assert_eq!(
        json!(proposal.severity()),
        declared["finding_severity"],
        "{id}: the mismatch is no longer reported at the level the gravity rule allows"
    );
    assert_eq!(
        json!(proposal.critical()),
        declared["finding_critical"],
        "{id}: whether the mismatch holds the project out of green changed"
    );
    assert_eq!(
        json!(proposal.evidence_class()),
        declared["finding_evidence_class"],
        "{id}: the class of evidence behind the mismatch changed"
    );

    // And the bucket it lands in, which is the difference between a proposal
    // shown to a reader and one filed as noise. Both buckets are asserted: style
    // noise alone would be satisfied by a candidate that appeared in both.
    let aggregated = aggregate(compared.findings.clone());
    assert_eq!(
        json!(aggregated.material().len()),
        declared["aggregate_material"],
        "{id}: the mismatch is being surfaced as material"
    );
    assert_eq!(
        json!(aggregated.style_noise().len()),
        declared["aggregate_style_noise"],
        "{id}: the mismatch is no longer filed as style noise"
    );
    assert_eq!(
        json!(aggregated.duplicates_dropped()),
        declared["aggregate_duplicates_dropped"],
        "{id}: proposals are being dropped as duplicates that were not before"
    );
    assert!(
        aggregated
            .style_noise()
            .iter()
            .any(|kept| kept.id().as_str() == declared["finding_id"].as_str().unwrap_or_default()),
        "{id}: the proposal the fixture declares is not one of the ones the aggregator kept"
    );

    // The ceiling, as a ceiling, and as a fact of the source rather than of this
    // proposal: an inference cannot support the only severity that blocks a
    // hand-off, so the level above cannot be reached by relabelling.
    let outcomes = scenario_of(id)["required_outcomes"]
        .as_array()
        .cloned()
        .expect("required_outcomes is an array");
    let ceiling = required_outcome(id, &outcomes, "ceiling");
    assert_eq!(
        json!(AssessmentSource::Inference.supports_severity(Severity::MustFix)),
        ceiling["supports_must_fix"],
        "{id}: the fixture records whether an inference can support must_fix and the rule disagrees"
    );
    assert_eq!(
        ceiling["cannot_support"].as_str(),
        Some("must_fix"),
        "{id}: the ceiling no longer names the severity it is about"
    );
    assert_eq!(
        json!(proposal.evidence_class()),
        ceiling["evidence_class"],
        "{id}: the ceiling and the proposal are no longer about the same evidence class"
    );

    // What a person reads, through the real pipeline. The summary is compared
    // whole, including the line about a check that could not run — the count is
    // asserted rather than the sentence, so a reader is not told a number the
    // fixture does not record.
    let outcome = pipelined(&fixture(id), Some(&goal));
    let record = record_of(&outcome);
    assert_eq!(
        record.intent_caveat, None,
        "{id}: a request was supplied, so the after-the-fact caveat does not apply"
    );
    assert_eq!(
        json!(record.intent.requirement_claim()),
        declared["requirement_claim"],
        "{id}: the claim the report may make about the request changed"
    );
    assert_eq!(
        json!(record.candidates.material.len()),
        declared["aggregate_material"],
        "{id}: the run's material list is not what the comparison's bucket says"
    );
    assert_eq!(
        json!(record.candidates.style_noise.len()),
        declared["aggregate_style_noise"],
        "{id}: the run's noise bucket is not what the comparison's bucket says"
    );
    assert_eq!(
        json!(record.candidates.duplicates_dropped),
        declared["aggregate_duplicates_dropped"],
        "{id}: the run dropped a different number of duplicates"
    );
    let surfaced = &record.candidates.style_noise[0];
    assert_eq!(
        surfaced.id,
        declared["finding_id"].as_str().unwrap_or_default(),
        "{id}: the candidate the report shows is not the proposal the comparison built"
    );
    assert_eq!(
        surfaced.title,
        declared["finding_title"].as_str().unwrap_or_default(),
        "{id}: the title a person is shown changed on its way to the report"
    );
    assert_eq!(
        json!(surfaced.severity),
        declared["finding_severity"],
        "{id}: the weight the report shows changed"
    );
    assert_eq!(
        json!(surfaced.critical),
        declared["finding_critical"],
        "{id}: whether the candidate is critical changed on its way to the report"
    );
    assert_eq!(
        surfaced.because,
        declared["finding_because"].as_str().unwrap_or_default(),
        "{id}: the sentence that says why the candidate is shown changed"
    );
    assert_eq!(
        json!(record.verdict.not_checked.len()),
        declared["not_checked"],
        "{id}: the number of checks that could not run changed"
    );
    assert_eq!(
        rendered_summary(&outcome),
        declared_lines(&declared["summary_lines"], "the declared summary"),
        "{id}: the summary a person reads has changed"
    );

    // The control: the same goal against the same project with the implementing
    // file present. The project is built by copying the fixture's own files
    // rather than by restating them, so a second difference cannot hide in the
    // copy.
    let control = &block["control"];
    let declared_control = &control["expect"];
    let added = &control["moved"]["added_file"];
    let added_path = added["path"]
        .as_str()
        .unwrap_or_else(|| panic!("{id}: the control does not say which file it adds"));
    let added_contents = added["contents"]
        .as_str()
        .unwrap_or_else(|| panic!("{id}: the control does not declare the file's contents"));
    assert_eq!(
        added_contents.lines().next(),
        added["first_line"].as_str(),
        "{id}: the control's declared first line is not the first line of its declared contents"
    );

    let scratch = Scratch::under("adversarial intent controls", id);
    for relative in shipped_project_files(id) {
        let full = fixture(id).join(&relative);
        let text = std::fs::read_to_string(&full)
            .unwrap_or_else(|error| panic!("cannot read {}: {error}", full.display()));
        scratch.write(&relative, &text);
    }
    scratch.write(added_path, added_contents);

    // One thing moved, and nothing else: the control's files are the fixture's
    // plus exactly the one path, and every shared file is the fixture's own
    // bytes.
    let mut expected_files = shipped_project_files(id);
    expected_files.push(added_path.to_owned());
    expected_files.sort();
    assert_eq!(
        project_files(&scratch.project),
        expected_files,
        "{id}: the control is not the fixture with one file added"
    );
    for relative in shipped_project_files(id) {
        assert_eq!(
            std::fs::read_to_string(scratch.project.join(&relative)).expect("the copied file"),
            std::fs::read_to_string(fixture(id).join(&relative)).expect("the fixture's file"),
            "{id}: the control's copy of {relative} is not the fixture's own bytes"
        );
    }

    let control_project = scratch.discovery();
    let control_compared = compare_intent_to_project(&intent, &control_project);
    assert_eq!(
        json!(control_compared.matched.len()),
        declared_control["matched"],
        "{id}: the same goal against a project that answers it did not match"
    );
    assert_eq!(
        json!(control_compared.unmatched.len()),
        declared_control["unmatched"],
        "{id}: the control still reports an unmatched requirement"
    );
    assert_eq!(
        json!(control_compared.limitation),
        declared_control["limitation"],
        "{id}: the control's limitation changed"
    );
    assert_eq!(
        json!(control_compared.findings.len()),
        declared_control["findings"],
        "{id}: a project that answers the request still produces a mismatch proposal"
    );
    assert!(
        control_compared.findings.is_empty(),
        "{id}: the control produced a proposal, and the whole fixture rests on it producing none"
    );

    // The anchor the control matched on, by its parts rather than by a debug
    // string: this is what makes `matched == 1` a measurement rather than a
    // count somebody could satisfy by matching anything.
    let declared_anchor = &declared_control["matched_anchor"];
    assert_eq!(
        control_compared.matched[0].anchors.len(),
        1,
        "{id}: the control's requirement matched more than one anchor, so the fixture's record of \
         where it matched is incomplete"
    );
    match &control_compared.matched[0].anchors[0] {
        IntentMatchAnchor::SourceFile {
            path,
            line,
            context,
        } => {
            assert_eq!(
                path,
                declared_anchor["path"].as_str().unwrap_or_default(),
                "{id}: the control matched a different file"
            );
            assert_eq!(
                json!(line),
                declared_anchor["line"],
                "{id}: the control matched a different line"
            );
            assert_eq!(
                context,
                declared_anchor["context"].as_str().unwrap_or_default(),
                "{id}: the control matched on a different text"
            );
        }
        other => {
            panic!("{id}: the control matched on {other:?}, and the fixture declares a source file")
        }
    }

    let control_outcome = pipelined(&scratch.project, Some(&goal));
    let control_record = record_of(&control_outcome);
    assert_eq!(
        json!(control_record.candidates.style_noise.len()),
        declared_control["aggregate_style_noise"],
        "{id}: the control's report still shows a mismatch candidate"
    );
    assert_eq!(
        json!(control_record.verdict.not_checked.len()),
        declared_control["not_checked"],
        "{id}: the control's report still lists a check that could not run"
    );
    assert_eq!(
        rendered_summary(&control_outcome),
        declared_lines(
            &declared_control["summary_lines"],
            "the declared control summary"
        ),
        "{id}: the control's summary is not what the fixture declares"
    );

    // The flip, in both directions and by equality.
    //
    // What this block asserted until `P18-T007` was that the control's summary was
    // the fixture's with exactly one line fewer, the missing line being the count
    // of checks that could not run. That statement described a build in which the
    // one check this fixture is about produced no result at all: it was not
    // checked, it was counted, and the control — where nothing is planned — simply
    // had one sentence less. `P18-T007` wired `crates/sure-core/src/pipeline.rs` to
    // `planned_check_runner`, the candidate's check now produces a result, and the
    // fixture's summary lost that line instead of keeping it, so the old equality
    // became false. It is re-made rather than dropped, and what replaces it is
    // narrower: the two summaries are asserted to be the same length and to differ
    // in exactly two positions, named.
    //
    // The two positions are the lines that carry the state of that one check: the
    // headline — `NeedsAttention` for a run that warned once, `NotEnoughChecked` for
    // the control, which checked nothing at all, a difference that comes from
    // `sure_domain::status::aggregate`'s ordering rather than from the finding
    // producer — and the findings line, `Unresolved findings: 1 Note.` against `No open
    // findings.`. The two lines that are neither are asserted equal, so a control
    // that moved one of them is red here rather than left to a reader.
    let fixture_lines = rendered_summary(&outcome);
    let control_lines = rendered_summary(&control_outcome);
    let differing: Vec<usize> = (0..fixture_lines.len().max(control_lines.len()))
        .filter(|index| fixture_lines.get(*index) != control_lines.get(*index))
        .collect();
    assert_eq!(
        differing,
        vec![0, 3],
        "{id}: the two summaries differ in {differing:?} rather than in the headline and the \
         findings line: {control_lines:?} against {fixture_lines:?}"
    );
    //
    // **This is still the assertion the finding producer is measured by**, in the
    // direction that matters here: a mutation that made
    // `crate::findings_from_checks` raise nothing would take `fixture_lines[3]` back
    // to `No unresolved findings.` — which reddens the declared summary above, and reddens
    // `differing` here as well, because the two summaries would then differ at the
    // headline alone. A mutation that made the *control* raise a finding
    // (for instance one that stopped the added file from matching the requirement)
    // reddens `control_lines[3]` here.
    assert_eq!(
        &fixture_lines[1..3],
        &control_lines[1..3],
        "{id}: the control changed a line of the summary other than the headline and the findings \
         line: {control_lines:?}"
    );
    assert_eq!(
        control_lines[3], "No unresolved findings.",
        "{id}: the control's project answers the request and plans nothing, so it has nothing to \
         leave open"
    );
    // The line this fixture used to end with, and which `P18-T007` took away: the
    // count of checks that could not run. Asserted *absent* rather than merely not
    // asserted, because "this run no longer counts that check as a gap" is the
    // change the wiring made, and an assertion that only stopped looking would not
    // measure it.
    assert!(
        !fixture_lines
            .iter()
            .any(|line| line.starts_with("1 check(s) could not run or were skipped.")),
        "{id}: a run whose one check produced a warning still counts a check that could not run: \
         {fixture_lines:?}"
    );
}

// --- execution trust: the two fixtures P14-T006 implemented ----------------
//
// What SURE may do, and what it can do it in. The first fixture is a check that
// was refused for want of authorisation and has to stay visible as refused; the
// second is a missing container runtime, which is a value with a sentence rather
// than an error, and a limit this build states rather than hides.

/// The `P14-T006` fixtures, named for the reason every list in this file is: a
/// test that discovered them would pass on an empty directory.
///
/// The same two ids are named in `crates/sure-testkit/tests/fixture_apps.rs`,
/// which grades the artefacts — the schema, the false-green rule, the README and
/// the runnability sweep. This file is where the answers are graded, and
/// `every_execution_trust_fixture_these_assertions_name_is_a_fixture_this_repository_ships`
/// is what says the two files are talking about the same directories.
const EXECUTION_TRUST_FIXTURES: &[&str] = &["dynamic-not-authorized", "container-unavailable"];

/// Whichever of the two answer blocks a fixture's scenario carries.
///
/// The guard test reads one block out of every fixture in its list, and which
/// one it is is looked up rather than declared by the list: a list that had to
/// say which block each of its members has would be a second place to keep in
/// step with the fixtures, and the first thing a third execution-trust fixture
/// would fall out of.
fn answer_block(id: &str) -> Value {
    let document = scenario_of(id);
    for key in ["execution_refusal", "container_absence"] {
        if let Some(block) = document.get(key) {
            return block.clone();
        }
    }
    panic!(
        "fixtures/adversarial/{id}/scenario.json declares neither an execution_refusal nor a \
         container_absence block, so there is no declaration of what the case answers"
    )
}

/// The `execution_refusal` block of one fixture's scenario.
fn execution_block(id: &str) -> Value {
    scenario_of(id)
        .get("execution_refusal")
        .cloned()
        .unwrap_or_else(|| {
            panic!(
                "fixtures/adversarial/{id}/scenario.json declares no execution_refusal block, so \
                 there is no declaration of what the unauthorised run answers"
            )
        })
}

/// The `container_absence` block of one fixture's scenario.
fn container_block(id: &str) -> Value {
    scenario_of(id)
        .get("container_absence")
        .cloned()
        .unwrap_or_else(|| {
            panic!(
                "fixtures/adversarial/{id}/scenario.json declares no container_absence block, so \
                 there is no declaration of what the machine question answers"
            )
        })
}

/// One of SURE's answers, compared with the fixture's declaration of it.
///
/// The comparison is an equality on the whole value and it is made in both
/// directions by construction: this asserts that SURE says what the fixture
/// declares, and `assert_the_outcomes_account_for_the_declared_expectation`
/// asserts that the fixture declares everything the corpus records. A key the
/// fixture does not declare is a red test here rather than a silent `null`.
fn assert_declared_answer(id: &str, key: &str, answer: Value, declared: &Value) {
    let expected = declared.get(key).unwrap_or_else(|| {
        panic!(
            "{id}: this test asserts SURE's answer for `{key}`, and the fixture declares no such \
             key, so the assertion has nothing to be checked against"
        )
    });
    assert_eq!(
        &answer, expected,
        "{id}: SURE's answer for `{key}` is not the one the fixture declares"
    );
}

/// How many results a run refused for want of authorisation.
///
/// The predicate the first acceptance sentence is about, and the one the control
/// is measured by. Deliberately not a count of passes and deliberately not the
/// aggregate: a check that was refused and a check that ran are different facts,
/// and this whole fixture exists to keep them apart. The control asserts the
/// *absence* of this reason rather than the presence of a greener anything,
/// because a check that is no longer refused is still not a check that ran.
fn unauthorised_refusals(outcome: &PipelineOutcome) -> usize {
    record_of(outcome)
        .report
        .results()
        .iter()
        .filter(|result| {
            result.not_checked_reason == Some(NotCheckedReason::ExecutionNotAuthorized)
        })
        .count()
}

/// The keys two declared answer blocks disagree about, sorted.
///
/// What moves between a fixture and its control, read off the declarations
/// rather than listed by hand in a second place: a control that stopped moving
/// something, or started moving something else, would otherwise be a change
/// nobody noticed.
fn disagreeing_keys(left: &Value, right: &Value) -> Vec<String> {
    let left = left
        .as_object()
        .unwrap_or_else(|| panic!("a declared answer block is not an object: {left}"));
    let right = right
        .as_object()
        .unwrap_or_else(|| panic!("a declared answer block is not an object: {right}"));
    let mut differing: Vec<String> = left
        .keys()
        .chain(right.keys())
        .filter(|key| left.get(*key) != right.get(*key))
        .cloned()
        .collect();
    differing.sort();
    differing.dedup();
    differing
}

/// The file that defines the container module, which therefore names it.
const THE_CONTAINER_MODULE: &str = "sure-core/src/container.rs";

/// What reaches the container module from *shipped* code, measured over one
/// walk of the tree.
///
/// This is the second half of criterion 2, and since `P15-T001` it answers two
/// questions rather than one. `crates/sure-core/src/container.rs` is read by the
/// diagnostic now — `crate::doctor` looks for a runtime and reports what it
/// found, which is SURE answering a question about *this computer* — so "no
/// shipped line names the module" stopped being true, and a fixture that went on
/// saying it would be recording a limit this build does not have. What is still
/// true, and what the fixture's `container_limit` entry is about, is that
/// nothing *runs* a container: no line of shipped code names the type a
/// container command is built from.
///
/// So one walk answers both. [`module`](ContainerReach::module) is every line of
/// shipped code that names something in the container module — an observation, a
/// report, nothing more. [`execution`](ContainerReach::execution) is every line
/// that names `ContainerPlan` or `PlanError`, which is the type and the error of
/// the one thing that could put a check inside a container. The two are counted
/// over the same files in the same walk rather than by two scans that could
/// drift apart, and neither is a subset rule: each is counted by its own
/// predicate.
///
/// The walk uses the product's own scanner, so "a file in this crate" means here
/// what it means everywhere else in the suite, and it is asserted complete — a
/// source check over an unknown subset of the sources is the false green this
/// file exists to prevent.
///
/// The filter is `src` and not `tests`, because the rule is about what ships and
/// because this file itself names the module; it is tested without a separator,
/// because the separator is the platform's. The file that defines the module is
/// skipped for the same reason: it has to name what it defines. Line comments
/// are stripped before the search, so a doc comment pointing at the module —
/// there is more than one now — is not mistaken for a caller. A `#[cfg(test)]`
/// module inside a shipped file is counted, because the filter is the file's
/// path and not the item's attributes; that is a property of this measurement,
/// and the fixture's numbers are the numbers it produces.
fn container_reach() -> ContainerReach {
    let crates = sure_testkit::repository_root().join("crates");
    let walked = scan(&crates, ScanOptions::default()).expect("crates/ is a directory");
    assert!(
        walked.is_complete(),
        "the source tree could not be read completely, so the limit this test records would be \
         checked against an unknown subset of it"
    );
    let mut module = Vec::new();
    let mut execution = Vec::new();
    let mut scanned = 0;
    for entry in walked.files() {
        if !entry
            .path
            .extension()
            .is_some_and(|extension| extension == "rs")
        {
            continue;
        }
        let path = entry.display_path();
        if !path.contains("src") || path.ends_with(THE_CONTAINER_MODULE) {
            continue;
        }
        scanned += 1;
        let full = crates.join(&entry.path);
        let text = std::fs::read_to_string(&full)
            .unwrap_or_else(|error| panic!("cannot read {}: {error}", full.display()));
        for (number, line) in text.lines().enumerate() {
            let code = line.split("//").next().unwrap_or_default();
            let here = format!("{path}:{}: {}", number + 1, line.trim());
            if code.contains("container::") || code.contains("Availability::") {
                module.push(here.clone());
            }
            if code.contains("ContainerPlan") || code.contains("PlanError") {
                execution.push(here);
            }
        }
    }
    assert!(
        scanned > 100,
        "the source walk found {scanned} shipped files, which is not this repository — the filter \
         is matching the wrong thing"
    );
    ContainerReach { module, execution }
}

/// The two lists [`container_reach`] produces, named so a caller cannot confuse
/// one for the other.
///
/// `module` is the wider question — anything at all that reaches into the
/// container module — and `execution` is the narrow one the fixture's limit is
/// about. They were the same question in `P14` only because both answers were
/// zero; they are kept apart here so that the phase which changed one of them
/// could not silently change the meaning of the other.
struct ContainerReach {
    /// Lines of shipped code naming something in the container module.
    module: Vec<String>,
    /// Lines of shipped code naming the type a container command is built from,
    /// or the error that building it can fail with.
    execution: Vec<String>,
}

/// The suffix a program is stored under on this platform.
///
/// The same rule `crate::doctor` searches with, restated here because the test
/// has to write the file the search is supposed to find.
#[cfg(windows)]
const EXECUTABLE_SUFFIX: &str = ".exe";
/// See above: on a Unix-like platform the name is the file name.
#[cfg(not(windows))]
const EXECUTABLE_SUFFIX: &str = "";

/// A directory holding one executable named after each runtime asked for, as a
/// search path of exactly that directory.
///
/// `OsString` rather than `PathBuf`, because a search path is the value
/// [`Availability::in_path`] takes and a path is not: the conversion is the
/// caller's, which is what makes "this is a search path" not look like "this is
/// a directory".
fn search_path_holding(where_: &Path, runtimes: &[Runtime]) -> OsString {
    std::fs::create_dir_all(where_)
        .unwrap_or_else(|error| panic!("cannot create {}: {error}", where_.display()));
    for runtime in runtimes {
        let path = where_.join(format!("{}{EXECUTABLE_SUFFIX}", runtime.program()));
        std::fs::write(&path, b"not a program")
            .unwrap_or_else(|error| panic!("cannot write {}: {error}", path.display()));
        // On a Unix-like platform a file with no execute bit is not a program
        // the search will accept, so the bit is part of writing it there.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut permissions = std::fs::metadata(&path)
                .expect("metadata for a file just written")
                .permissions();
            permissions.set_mode(0o755);
            std::fs::set_permissions(&path, permissions).unwrap_or_else(|error| {
                panic!("cannot make {} executable: {error}", path.display())
            });
        }
    }
    std::env::join_paths([where_]).expect("a search path with one entry in it")
}

#[test]
fn a_missing_container_runtime_is_a_value_and_the_control_moves_the_search_path() {
    let id = "container-unavailable";
    let block = container_block(id);
    assert_the_outcomes_account_for_the_declared_expectation(id, &block);

    assert_eq!(
        shipped_project_files(id),
        declared_lines(&block["project"]["files"], "the declared project"),
        "{id} ships a different project from the one it declares"
    );
    let files_before = shipped_project_files(id);
    let declared = &block["expect"];

    // The absence, and the reason no assertion here can be a test of the
    // machine: the search path is an argument, and this one holds nothing.
    // `OsStr::new("")` is not a directory, so this is `Absent` on every platform
    // in every terminal — and it is compared with the variant rather than with
    // `is_found()`, because "absent" is a value that has to compare equal to
    // itself, not the lack of one.
    let nothing_to_find = Availability::in_path(OsStr::new(""));
    assert_eq!(
        nothing_to_find,
        Availability::Absent,
        "{id}: an empty search path found something"
    );
    assert_declared_answer(id, "is_found", json!(nothing_to_find.is_found()), declared);
    assert_declared_answer(
        id,
        "runtime",
        json!(nothing_to_find.runtime().map(Runtime::as_str)),
        declared,
    );
    assert_declared_answer(id, "sentence", json!(nothing_to_find.explain()), declared);
    assert_declared_answer(
        id,
        "runtimes_looked_for",
        json!(
            Runtime::ALL
                .iter()
                .map(|runtime| runtime.as_str())
                .collect::<Vec<_>>()
        ),
        declared,
    );

    // The sentence is compared whole, and its third job — naming what was looked
    // for — is a measurement rather than a phrase somebody wrote once: the
    // declared `runtimes_looked_for` above is held to `Runtime::ALL` by equality,
    // so a module that started looking for a third runtime would fail the list
    // comparison and have to come back to this fixture, where the sentence and
    // the list sit next to each other.
    for phrase in OVERCLAIMS {
        assert!(
            !overclaims(&nothing_to_find.explain(), phrase),
            "{id}: the sentence about a missing runtime makes the claim `{phrase}`"
        );
    }

    // The claim the mode is described with, quoted whole and held to the
    // module's own rule about overclaiming rather than to a search for a word.
    // It is the one sentence a person reads *before* agreeing to run a
    // stranger's code, which is why `sandbox` may not appear in it as a promise.
    assert_declared_answer(id, "isolation_claim", json!(isolation_claim()), declared);
    assert_declared_answer(id, "overclaim_phrases", json!(OVERCLAIMS), declared);
    assert_declared_answer(
        id,
        "phrases_found_in_the_claim",
        json!(
            OVERCLAIMS
                .iter()
                .copied()
                .filter(|phrase| overclaims(isolation_claim(), phrase))
                .count()
        ),
        declared,
    );

    // The limit, measured rather than described: the diagnostic reads the
    // container module to report what it found on this computer, and nothing
    // that ships can ask for a check to be run in one. `P15-T001` is where the
    // first half of that became true — and the numbers below are the two halves:
    // `module_call_sites` counts the reporting, which is what changed, and
    // `unwired_call_sites` counts the execution, which did not. A test that
    // fails on the first has found the report changing shape; a test that fails
    // on the second has found the caller this fixture records not existing.
    //
    // Mutation, run rather than described: add one line of code to the `mod
    // tests` at the end of `crates/sure-core/src/doctor.rs` —
    //
    //   #[allow(dead_code)]
    //   fn a_plan_becomes_reachable(_: Option<crate::container::ContainerPlan>) {}
    //
    // — and this test fails on the assertion below, printing that line and its
    // number. Both numbers move, and it was measured rather than assumed: the
    // same scan under the same mutation answers `module_call_sites` = 12 (11 + 1)
    // and `unwired_call_sites` = 1. Reverting the two lines puts both back. The
    // run is reported in this task's hand-back with what else it reddened.
    let reach = container_reach();
    assert!(
        reach.execution.is_empty(),
        "{id}: a container can be planned from shipped code, so the limit this fixture records is \
         no longer true and the declaration has to be re-made deliberately rather than discovered \
         by a reader:\n  {}",
        reach.execution.join("\n  ")
    );
    assert_declared_answer(id, "module_call_sites", json!(reach.module.len()), declared);
    assert_declared_answer(
        id,
        "unwired_call_sites",
        json!(reach.execution.len()),
        declared,
    );

    // And what a run of this fixture produces, which is nothing: the absence is
    // refused by no rule, because nothing in this build asks whether a runtime
    // is there. This is the sentence the fixture's own notes state, measured
    // instead of described — no planned check, no finding, no candidate and no
    // not-checked row either.
    let outcome = pipelined(&fixture(id), None);
    let record = record_of(&outcome);
    assert!(
        record.schedule.checks().is_empty(),
        "{id}: the fixture's project now plans a check, so the container question has been wired in \
         somewhere and this declaration has to be re-made: {:?}",
        record
            .schedule
            .checks()
            .iter()
            .map(|check| check.proposal().id().as_str())
            .collect::<Vec<_>>()
    );
    assert_eq!(
        record.verdict.not_checked.len(),
        0,
        "{id}: a run of this project reports a check that did not run, and nothing here asked for one"
    );
    assert_eq!(
        record.candidates.material.len(),
        0,
        "{id}: a missing runtime was reported as a defect of the project"
    );
    assert_eq!(
        record.candidates.style_noise.len(),
        0,
        "{id}: a missing runtime produced a style-noise candidate"
    );

    // The control. One thing moves, and it is not this computer's `PATH`: a
    // search path this test owns, holding one file named after one runtime.
    let control = &block["control"];
    assert_eq!(
        control["moved"]["what"].as_str(),
        Some("the search path"),
        "{id}: the control says it moved something other than the search path, and a control that \
         changed the machine or the project would measure a different thing"
    );
    let declared_control = &control["expect"];
    let scratch = Scratch::under("adversarial execution trust controls", "container search");
    let docker_only = search_path_holding(&scratch.project.join("docker-only"), &[Runtime::Docker]);
    let found = Availability::in_path(&docker_only);
    let found_program = scratch
        .project
        .join("docker-only")
        .join(format!("docker{EXECUTABLE_SUFFIX}"));
    assert_eq!(
        found,
        Availability::Found {
            runtime: Runtime::Docker,
            program: found_program.clone(),
        },
        "{id}: a directory holding one program named docker did not come back as that program, so \
         the reported runtime and path are not both read out of the search path"
    );
    assert_declared_answer(id, "is_found", json!(found.is_found()), declared_control);
    assert_declared_answer(
        id,
        "runtime",
        json!(found.runtime().map(Runtime::as_str)),
        declared_control,
    );

    // The sentence for a found runtime, by equality. The value is constructed
    // with a program path this file fixes rather than with the scratch one,
    // because a scratch path is unique per run — and then the sentence the
    // search actually produced is compared with that same declaration once the
    // one part that cannot be fixed, the path of the program, is put in its
    // place. Equality on the template and equality on the path are together
    // equality on the whole sentence.
    let constructed = Availability::Found {
        runtime: Runtime::Docker,
        program: PathBuf::from("sure-fixture/bin/docker"),
    };
    assert_declared_answer(
        id,
        "sentence",
        json!(constructed.explain()),
        declared_control,
    );
    let declared_sentence = declared_control["sentence"].as_str().unwrap_or_default();
    assert_eq!(
        found.explain(),
        declared_sentence.replace(
            "sure-fixture/bin/docker",
            &found_program.display().to_string()
        ),
        "{id}: the sentence about a runtime that was found is not the declared one with the path \
         that was actually found in it"
    );

    // The order in `Runtime::ALL` decides when a machine has both, and the name
    // that comes back is the name that was written — which is what makes the
    // reported runtime a measurement rather than the program's preference.
    let both = search_path_holding(
        &scratch.project.join("both"),
        &[Runtime::Docker, Runtime::Podman],
    );
    assert_declared_answer(
        id,
        "both_present",
        json!(Availability::in_path(&both).runtime().map(Runtime::as_str)),
        declared_control,
    );
    let podman_only = search_path_holding(&scratch.project.join("podman-only"), &[Runtime::Podman]);
    assert_declared_answer(
        id,
        "podman_only",
        json!(
            Availability::in_path(&podman_only)
                .runtime()
                .map(Runtime::as_str)
        ),
        declared_control,
    );

    // The flip, declared as well as made: the two halves of this fixture answer
    // opposite questions, and a fixture that asserted one of them unconditionally
    // would be measuring nothing.
    assert_ne!(
        declared["is_found"], declared_control["is_found"],
        "{id}: the fixture and its control declare the same answer, so nothing here is measured"
    );

    // The one call that reads this computer's own `PATH`, asserted in its shape
    // and nothing else: which arm it takes is a fact about the machine running
    // the test. The match has two arms and no wildcard, so a third variant — an
    // error, which is the shape this whole fixture is about the absence of —
    // would not compile here.
    let on_this_machine = Availability::on_this_machine();
    let sentence = on_this_machine.explain();
    assert!(
        !sentence.is_empty(),
        "{id}: a probe of this machine answered with no sentence at all"
    );
    for phrase in OVERCLAIMS {
        assert!(
            !overclaims(&sentence, phrase),
            "{id}: the sentence about this machine makes the claim `{phrase}`"
        );
    }
    match on_this_machine {
        Availability::Found { runtime, .. } => {
            // The one thing about this arm that is a fact about SURE rather than
            // about the machine: the runtimes a search can report are the two
            // the search looks for. The words this arm's sentence is made of are
            // not asserted, because on a machine that has a runtime this test
            // would then be measuring the machine — and on one that has none,
            // this arm does not run at all.
            assert!(
                Runtime::ALL.contains(&runtime),
                "{id}: a probe of this machine reported a runtime no search would have looked for"
            );
        }
        Availability::Absent => {
            // On a machine with nothing on its `PATH`, the probe's answer is the
            // fixture's answer word for word. On one with a runtime, that
            // assertion is not made — and the sentence is still held to the same
            // shape above.
            assert_declared_answer(id, "sentence", json!(sentence), declared);
        }
    }

    assert_eq!(
        shipped_project_files(id),
        files_before,
        "{id}: the fixture's own project changed while it was being read"
    );

    // The search paths this test owned, removed rather than left behind: every
    // file under them was written here, under the repository's own ignored
    // directory, and a test that leaves its own state around is one the next run
    // has to reason about.
    std::fs::remove_dir_all(&scratch.project).unwrap_or_else(|error| {
        panic!(
            "{id}: cannot remove the scratch directory {}: {error}",
            scratch.project.display()
        )
    });
    assert!(
        !scratch.project.exists(),
        "{id}: the scratch directories are still there after the test"
    );
}

#[test]
fn every_execution_trust_fixture_these_assertions_name_is_a_fixture_this_repository_ships() {
    // The guard every list in this file has, for the same reason: a renamed
    // directory would make every assertion below about a project nobody ships.
    for id in EXECUTION_TRUST_FIXTURES {
        let dir = fixture(id);
        assert!(dir.is_dir(), "{} is not a directory", dir.display());
        assert!(
            dir.join("scenario.json").is_file(),
            "{id} has no scenario.json, so there is no declaration to read"
        );
        assert!(
            dir.join("README.md").is_file(),
            "{id} has no README.md, so nothing says in words what it traps"
        );
        // The block this fixture answers with, found by looking for it rather
        // than by the list saying which member has which. The two shapes the one
        // list mixes are asserted below rather than described: a reader who took
        // it for a language list would expect both members to be runnable, and
        // one of them is deliberately not.
        let block = answer_block(id);
        assert!(
            block.get("control").is_some(),
            "{id}/scenario.json declares no control, and a fixture whose answer is a permission or \
             an absence is worth nothing without one"
        );
        assert!(
            block["control"]["moved"]["what"].as_str().is_some(),
            "{id}/scenario.json declares a control that does not say what moved"
        );
        assert!(
            !block["control"]["why"]
                .as_str()
                .unwrap_or_default()
                .is_empty(),
            "{id}/scenario.json declares a control with no reason given"
        );
    }
    // The one that ships a `package.json` is a Node application, so the
    // runnability sweep in `fixture_apps.rs` owns it too and the two lists must
    // agree about that. The other ships no manifest at all — the absence it is
    // about is a fact about the computer — so no language list may claim it.
    assert!(
        fixture("dynamic-not-authorized")
            .join("package.json")
            .is_file(),
        "dynamic-not-authorized declares a dynamic check, and a dynamic check needs a manifest to \
         declare it in"
    );
    for manifest in [
        "package.json",
        "pyproject.toml",
        "requirements.txt",
        "Cargo.toml",
    ] {
        assert!(
            !fixture("container-unavailable").join(manifest).is_file(),
            "container-unavailable ships a {manifest}, and the case is a fact about the machine \
             rather than about the project"
        );
    }
}

#[test]
fn an_unauthorised_dynamic_check_stays_visible_and_the_control_moves_the_users_own_file() {
    let id = "dynamic-not-authorized";
    let block = execution_block(id);
    assert_the_outcomes_account_for_the_declared_expectation(id, &block);

    // The fixture is the project it declares, asserted before either run, so a
    // fixture edited without this file being edited stays a red test.
    assert_eq!(
        shipped_project_files(id),
        declared_lines(&block["project"]["files"], "the declared project"),
        "{id} ships a different project from the one it declares"
    );
    let files_before = shipped_project_files(id);
    let root = fixture(id);
    let declared = &block["expect"];

    // The user's own configuration root, under the repository's ignored
    // `target/tmp`. The machine's real configuration directory is never read and
    // never written: `Paths::from_roots` is the same constructor `sure check`
    // uses when it is pointed somewhere else, and the file the control writes
    // goes into a directory this test owns.
    let scratch = Scratch::under("adversarial execution trust controls", id);
    let paths = Paths::from_roots(scratch.project.join("data"), scratch.project.join("config"))
        .unwrap_or_else(|error| {
            panic!("{id}: cannot put SURE's configuration root under target/tmp: {error}")
        });
    // `Paths::from_roots` validates the two roots and creates neither, so the
    // directory the control's file goes in is made here — by this test, under
    // `target/tmp`, and never in the machine's real configuration directory.
    for root in [scratch.project.join("data"), scratch.project.join("config")] {
        std::fs::create_dir_all(&root)
            .unwrap_or_else(|error| panic!("{id}: cannot create {}: {error}", root.display()));
    }
    assert!(
        !paths.user_config_file().is_file(),
        "{id}: the control's configuration file is there before the fixture has run, so the two \
         halves would not be one file apart"
    );

    // The fixture's own `sure.yaml` asks for execution and cannot grant it. The
    // request is asserted rather than assumed, because a build that read the
    // mode out of the project would show the check below as allowed.
    let authority = Authority::load(&root, &paths.user_config_file())
        .unwrap_or_else(|error| panic!("{id}: cannot read the fixture's configuration: {error}"));
    let asked = authority.privileges();
    assert_declared_answer(id, "project_ask_count", json!(asked.len()), declared);
    assert_declared_answer(id, "project_ask_request", json!(asked[0].request), declared);
    assert_declared_answer(
        id,
        "project_ask_asked_by",
        json!(
            asked[0]
                .asked_by
                .iter()
                .map(|layer| layer.as_str())
                .collect::<Vec<_>>()
        ),
        declared,
    );
    assert_declared_answer(
        id,
        "project_ask_refused_escalation",
        json!(asked[0].is_refused_escalation()),
        declared,
    );
    assert_declared_answer(
        id,
        "project_ask_granted",
        json!(asked[0].is_granted()),
        declared,
    );

    // The run: SURE's real pipeline, over the project where it ships, under the
    // settings the authority resolved to and nothing else.
    let outcome = pipelined_with(&root, None, authority.execution());
    let record = record_of(&outcome);
    assert_eq!(
        record.mode,
        authority.execution().mode,
        "{id}: the run's mode is not the one the configuration resolved to, so what is asserted \
         below is a run nobody asked for"
    );
    assert_declared_answer(id, "mode", json!(record.mode), declared);
    assert_declared_answer(
        id,
        "run_project_code",
        json!(record.permissions.run_project_code),
        declared,
    );
    assert_declared_answer(
        id,
        "plan_checks",
        json!(record.schedule.checks().len()),
        declared,
    );

    // The check the declared script became, found by id rather than by position:
    // a plan that reordered its entries would still be the same plan.
    let check_id = declared["check_id"]
        .as_str()
        .unwrap_or_else(|| panic!("{id}: the fixture declares no check id"))
        .to_owned();
    let check = record
        .schedule
        .checks()
        .iter()
        .find(|check| check.proposal().id().as_str() == check_id)
        .unwrap_or_else(|| {
            panic!(
                "{id}: the plan no longer holds the check the fixture declares. It holds: {:?}",
                record
                    .schedule
                    .checks()
                    .iter()
                    .map(|check| check.proposal().id().as_str())
                    .collect::<Vec<_>>()
            )
        });
    assert_declared_answer(id, "check_title", json!(check.proposal().title()), declared);
    assert_declared_answer(id, "check_may_run", json!(check.may_run()), declared);
    assert_declared_answer(id, "check_decision", json!(check.decision()), declared);
    assert_declared_answer(id, "check_blocked_by", json!(check.blocked_by()), declared);

    // What became of it. The status is `skipped` and never a "not authorized"
    // one: the frozen vocabulary in `crates/sure-domain/src/status.rs` has no
    // such status, and a build that invented one would fail here.
    let result = record
        .report
        .results()
        .iter()
        .find(|result| result.id.as_str() == check_id)
        .unwrap_or_else(|| {
            panic!("{id}: the run produced no result for the check the fixture declares")
        });
    assert_declared_answer(id, "check_status", json!(result.status), declared);
    assert_declared_answer(
        id,
        "check_not_checked_reason",
        json!(result.not_checked_reason),
        declared,
    );
    assert_declared_answer(id, "check_reason", json!(result.reason), declared);
    assert_declared_answer(
        id,
        "check_evidence_class",
        json!(result.evidence_class),
        declared,
    );
    assert_declared_answer(id, "check_critical", json!(result.critical), declared);
    assert_declared_answer(id, "check_severity", json!(result.severity), declared);
    assert_declared_answer(
        id,
        "refusals",
        json!(unauthorised_refusals(&outcome)),
        declared,
    );

    // Visible in five places, because a field on a struct is not a report a
    // person reads: in the verdict's own list of checks that did not run, in the
    // finding the run raises for it, in the coverage summary, in the aggregate's
    // list of critical checks that were not checked and in the two lines
    // `render_summary` prints. The last of those is asserted with the whole
    // summary below.
    assert_declared_answer(
        id,
        "not_checked_count",
        json!(record.verdict.not_checked.len()),
        declared,
    );
    assert!(
        record
            .verdict
            .not_checked
            .iter()
            .any(|listed| listed.id.as_str() == check_id),
        "{id}: the verdict no longer lists the refused check among the ones that did not run: {:?}",
        record
            .verdict
            .not_checked
            .iter()
            .map(|listed| listed.id.as_str())
            .collect::<Vec<_>>()
    );
    // The finding, which `P7-T012` added and which is the place a reader reaches
    // first. Found by the anchor naming this check rather than by position: a
    // verdict that raised a finding about something else and none about the check
    // it refused would satisfy a count. The fixture declares its weight, its
    // status and the check it points at, because those are what separate a
    // material uncertainty from a claim that the code is wrong: `cannot_confirm`
    // and never `open`, and the check's own `must_fix` rather than one chosen for
    // the project.
    //
    // **Reproducible mutations, one per assertion**, each run and its output
    // recorded rather than described: emptying the producer (replacing the call
    // in `pipeline::build_verdict` with `Vec::new()`) makes the `find` below
    // panic with an empty list, and reddens the declared summary and the
    // intent-mismatch fixture with it; making `status_for` answer
    // `FindingStatus::Open` for a check that produced no result reddens
    // `finding_status` with `left: "open"` against `cannot_confirm`, and nothing
    // else; replacing `result.severity` with a fixed severity on the
    // `FindingBuilder` in `finding_for` — both `.severity(..)` and the rationale,
    // or the builder refuses to construct — reddens `finding_severity` with
    // `left: "note"` against `must_fix`; and dropping `with_subject_id` from the
    // anchor `anchor_for` returns leaves the `find` above with nothing to point
    // at, so it panics naming the finding it did raise.
    //
    // The severity mutation is deliberately *not* on `severity_of`: that
    // function is public for a caller and used by this module's own unit test,
    // but `finding_for` does not call it, and mutating it was measured to leave
    // this test green — a mutation that cannot fail is not a measurement, which
    // is why it is written down here rather than left as a plausible-looking
    // sentence.
    let finding = record
        .verdict
        .findings
        .iter()
        .find(|finding| {
            finding.evidence.iter().any(|evidence| {
                evidence
                    .anchor
                    .subject_id
                    .as_ref()
                    .is_some_and(|subject| subject.as_str() == check_id)
            })
        })
        .unwrap_or_else(|| {
            panic!(
                "{id}: the run raised no finding anchored to the check it refused, so the check is \
                 visible in the report's structures and not in its findings. The findings it did \
                 raise: {:?}",
                record
                    .verdict
                    .findings
                    .iter()
                    .map(|finding| finding.title.clone())
                    .collect::<Vec<_>>()
            )
        });
    assert_declared_answer(
        id,
        "findings",
        json!(record.verdict.findings.len()),
        declared,
    );
    assert_declared_answer(id, "finding_title", json!(finding.title), declared);
    assert_declared_answer(id, "finding_severity", json!(finding.severity), declared);
    assert_declared_answer(id, "finding_status", json!(finding.status), declared);
    assert_declared_answer(
        id,
        "finding_subject_id",
        json!(
            finding.evidence[0]
                .anchor
                .subject_id
                .as_ref()
                .map(|subject| subject.as_str())
        ),
        declared,
    );
    assert_declared_answer(
        id,
        "coverage_checked",
        json!(record.coverage.checked_count),
        declared,
    );
    assert_declared_answer(
        id,
        "coverage_skipped",
        json!(record.coverage.skipped_count),
        declared,
    );
    assert_declared_answer(
        id,
        "coverage_could_not_run",
        json!(record.coverage.could_not_run_count),
        declared,
    );
    let entry = record
        .coverage
        .not_checked
        .iter()
        .find(|entry| entry.check_id == check_id)
        .unwrap_or_else(|| {
            panic!("{id}: the coverage summary does not list the refused check as not checked")
        });
    assert_eq!(
        entry.reason,
        declared["check_reason"].as_str().unwrap_or_default(),
        "{id}: the reason in the coverage summary is not the frozen sentence the result carries"
    );
    assert_declared_answer(
        id,
        "aggregate_severity",
        json!(record.verdict.aggregate.severity),
        declared,
    );
    assert_declared_answer(
        id,
        "aggregate_headline",
        json!(record.verdict.aggregate.headline),
        declared,
    );
    assert_declared_answer(
        id,
        "aggregate_skipped",
        json!(record.verdict.aggregate.counts.skipped),
        declared,
    );
    assert_declared_answer(
        id,
        "aggregate_unknown",
        json!(record.verdict.aggregate.counts.unknown),
        declared,
    );
    assert_declared_answer(
        id,
        "critical_not_checked",
        json!(
            record
                .verdict
                .aggregate
                .coverage
                .critical_not_checked
                .iter()
                .map(|id| id.as_str())
                .collect::<Vec<_>>()
        ),
        declared,
    );
    assert_declared_answer(
        id,
        "blocking",
        json!(
            record
                .verdict
                .aggregate
                .blocking
                .iter()
                .map(|id| id.as_str())
                .collect::<Vec<_>>()
        ),
        declared,
    );
    assert_declared_answer(
        id,
        "is_ready_for_hand_off",
        json!(record.verdict.is_ready_for_hand_off()),
        declared,
    );

    // The whole of what a person reads, by equality rather than by substring.
    // The count of checks that could not run is one of these lines, and so is the
    // findings line above it — `Unresolved findings: 1 Must fix.` since `P7-T012`,
    // where it used to read `No unresolved findings.`, and that line is the finding
    // asserted above rather than a second statement about it. Both have to be
    // there, or a reader takes the report for a project with nothing outstanding
    // when the one thing SURE could not do is the one thing it was asked to do.
    assert_declared_answer(
        id,
        "summary_lines",
        json!(rendered_summary(&outcome)),
        declared,
    );

    // And nothing was invented about the project. The finding above lives in the
    // verdict's findings, raised for a check that did not run; what the
    // aggregator's own buckets hold is a different question, and the answer to it
    // has to be nothing. The `must_fix` on the check is the weight of the check,
    // not a verdict about code nobody ran: a build that turned it into a material
    // candidate about the project would fail here while passing everything above.
    assert_eq!(
        record.candidates.material.len(),
        0,
        "{id}: an unauthorised check produced a material finding about the project"
    );
    assert_eq!(
        record.candidates.style_noise.len(),
        0,
        "{id}: an unauthorised check produced a style-noise candidate"
    );

    // The control. One thing moves, and it is not in the project: the user's own
    // configuration file appears, granting what the project's file asked for.
    let control = &block["control"];
    assert_eq!(
        control["moved"]["what"].as_str(),
        Some("the user's own configuration file"),
        "{id}: the control says it moved something other than the user's own file, and a control \
         that changed the project would measure a different thing"
    );
    let grant = control["moved"]["file"]["contents"]
        .as_str()
        .unwrap_or_else(|| panic!("{id}: the control declares no file to write"));
    std::fs::write(paths.user_config_file(), grant).unwrap_or_else(|error| {
        panic!(
            "{id}: cannot write the control's configuration file at {}: {error}",
            paths.user_config_file().display()
        )
    });

    let control_authority = Authority::load(&root, &paths.user_config_file())
        .unwrap_or_else(|error| panic!("{id}: cannot read the control's configuration: {error}"));
    let control_asked = control_authority.privileges();
    let declared_control = &control["expect"];
    assert_declared_answer(
        id,
        "project_ask_count",
        json!(control_asked.len()),
        declared_control,
    );
    assert_declared_answer(
        id,
        "project_ask_asked_by",
        json!(
            control_asked[0]
                .asked_by
                .iter()
                .map(|layer| layer.as_str())
                .collect::<Vec<_>>()
        ),
        declared_control,
    );
    assert_declared_answer(
        id,
        "project_ask_refused_escalation",
        json!(control_asked[0].is_refused_escalation()),
        declared_control,
    );
    assert_declared_answer(
        id,
        "project_ask_granted",
        json!(control_asked[0].is_granted()),
        declared_control,
    );

    let control_outcome = pipelined_with(&root, None, control_authority.execution());
    let control_record = record_of(&control_outcome);
    assert_eq!(
        control_record.project_root, record.project_root,
        "{id}: the control read a different project, so what it measures is no longer the file"
    );
    assert_declared_answer(id, "mode", json!(control_record.mode), declared_control);
    assert_declared_answer(
        id,
        "run_project_code",
        json!(control_record.permissions.run_project_code),
        declared_control,
    );
    assert_declared_answer(
        id,
        "plan_checks",
        json!(control_record.schedule.checks().len()),
        declared_control,
    );
    let control_check = control_record
        .schedule
        .checks()
        .iter()
        .find(|check| check.proposal().id().as_str() == check_id)
        .unwrap_or_else(|| {
            panic!("{id}: the control's plan no longer holds the check the fixture declares")
        });
    assert_declared_answer(
        id,
        "check_may_run",
        json!(control_check.may_run()),
        declared_control,
    );
    assert_declared_answer(
        id,
        "check_decision",
        json!(control_check.decision()),
        declared_control,
    );
    assert_declared_answer(
        id,
        "check_blocked_by",
        json!(control_check.blocked_by()),
        declared_control,
    );
    let control_result = control_record
        .report
        .results()
        .iter()
        .find(|result| result.id.as_str() == check_id)
        .unwrap_or_else(|| {
            panic!("{id}: the control produced no result for the check the fixture declares")
        });
    assert_declared_answer(
        id,
        "check_status",
        json!(control_result.status),
        declared_control,
    );
    assert_declared_answer(
        id,
        "check_not_checked_reason",
        json!(control_result.not_checked_reason),
        declared_control,
    );
    assert_declared_answer(
        id,
        "check_reason",
        json!(control_result.reason),
        declared_control,
    );
    assert_declared_answer(
        id,
        "coverage_checked",
        json!(control_record.coverage.checked_count),
        declared_control,
    );
    assert_declared_answer(
        id,
        "coverage_skipped",
        json!(control_record.coverage.skipped_count),
        declared_control,
    );
    assert_declared_answer(
        id,
        "coverage_could_not_run",
        json!(control_record.coverage.could_not_run_count),
        declared_control,
    );
    assert_declared_answer(
        id,
        "aggregate_skipped",
        json!(control_record.verdict.aggregate.counts.skipped),
        declared_control,
    );
    assert_declared_answer(
        id,
        "aggregate_unknown",
        json!(control_record.verdict.aggregate.counts.unknown),
        declared_control,
    );

    // The negative half, by the predicate rather than by a count: with the
    // user's own file granting execution, no result anywhere in the run carries
    // the not-authorized reason. A reporter hard-wired to deny — the failure
    // this fixture exists to catch — satisfies every positive assertion above
    // and fails here.
    assert!(
        !control_record
            .report
            .results()
            .iter()
            .any(|result| result.not_checked_reason
                == Some(NotCheckedReason::ExecutionNotAuthorized)),
        "{id}: a check the user's own file authorised was still refused as unauthorised: {:?}",
        control_record
            .report
            .results()
            .iter()
            .map(|result| (result.id.as_str(), result.not_checked_reason))
            .collect::<Vec<_>>()
    );
    assert_declared_answer(
        id,
        "refusals",
        json!(unauthorised_refusals(&control_outcome)),
        declared_control,
    );

    // And the difference is asserted as a difference, in both directions: the
    // two halves of one fixture are one file apart and their answers must not be
    // the same, or the fixture measures nothing.
    assert_ne!(
        unauthorised_refusals(&control_outcome),
        unauthorised_refusals(&outcome),
        "{id}: the same run with the user's own file present and absent refused the same number of \
         checks, so nothing here is being measured"
    );
    assert_ne!(
        json!(control_record.mode),
        json!(record.mode),
        "{id}: the mode did not move, so the file the control writes is not what decides it"
    );

    // What moved is declared rather than left to be read off: the two answer
    // blocks must differ in exactly the keys the fixture names, so a change that
    // moved something else — or stopped moving something — is a red test.
    assert_eq!(
        disagreeing_keys(declared, declared_control),
        declared_lines(&control["moved"]["keys"], "the keys the control moves"),
        "{id}: the keys the control moves are not the keys the two declarations disagree about"
    );

    // What did *not* move, asserted beside it: consent changes what SURE is
    // allowed to do and does not make anything checked. The summary a person
    // reads is the same six lines on both sides, word for word — that is the
    // honest half of this fixture, and a later build that learns to carry a
    // planned check out will have to change this declaration deliberately rather
    // than discover it.
    assert_declared_answer(
        id,
        "summary_lines",
        json!(rendered_summary(&control_outcome)),
        declared_control,
    );
    assert_eq!(
        rendered_summary(&control_outcome),
        rendered_summary(&outcome),
        "{id}: granting execution changed the summary a person reads, and a check that is no longer \
         refused is still not a check that ran"
    );
    assert_declared_answer(
        id,
        "aggregate_headline",
        json!(control_record.verdict.aggregate.headline),
        declared_control,
    );
    assert_declared_answer(
        id,
        "aggregate_severity",
        json!(control_record.verdict.aggregate.severity),
        declared_control,
    );
    // The control raises the same finding, and that is the point rather than an
    // oversight: the check is no longer refused, but nothing in this build
    // carries a planned check out, so what SURE knows about the project is
    // unchanged. The two declarations carry the same five finding keys, which is
    // what `disagreeing_keys` below enforces — a control whose finding moved
    // would have to name it in `moved.keys` or be a red test.
    //
    // **Reproducible mutations:** the ones named above redden these five
    // assertions too, because both runs share the function — M1 (nothing
    // raised) panics in the `find`, M2 (`Open`) and M5 (`Resolved`) redden
    // `finding_status` on both sides, M3 reddens `finding_severity` and M4
    // panics in the `find`. M5 additionally reddens the intent-mismatch fixture,
    // which is the direction worth knowing: `Resolved` leaves
    // `FindingStatus::needs_attention`, so the finding drops out of
    // `open_findings()` and the summary goes back to `No unresolved findings.` on a
    // run that refused a check.
    //
    // Nothing here asserts that the two findings are equal, and that is
    // deliberate rather than an omission: both runs share `status_for`, so an
    // equality between them could not fail without one of the five declarations
    // above failing first. What keeps the two sides from drifting apart is
    // `disagreeing_keys` below — these five keys are in neither declaration's
    // `moved.keys`, so a control whose finding moved is a red test unless
    // someone widens that list, and widening it is a change to the corpus rather
    // than to the product.
    let control_finding = control_record
        .verdict
        .findings
        .iter()
        .find(|finding| {
            finding.evidence.iter().any(|evidence| {
                evidence
                    .anchor
                    .subject_id
                    .as_ref()
                    .is_some_and(|subject| subject.as_str() == check_id)
            })
        })
        .unwrap_or_else(|| {
            panic!(
                "{id}: the control raised no finding anchored to the check, so consent changed what \
                 SURE says about the project rather than only what it may do. The findings it did \
                 raise: {:?}",
                control_record
                    .verdict
                    .findings
                    .iter()
                    .map(|finding| finding.title.clone())
                    .collect::<Vec<_>>()
            )
        });
    assert_declared_answer(
        id,
        "findings",
        json!(control_record.verdict.findings.len()),
        declared_control,
    );
    assert_declared_answer(
        id,
        "finding_title",
        json!(control_finding.title),
        declared_control,
    );
    assert_declared_answer(
        id,
        "finding_severity",
        json!(control_finding.severity),
        declared_control,
    );
    assert_declared_answer(
        id,
        "finding_status",
        json!(control_finding.status),
        declared_control,
    );
    assert_declared_answer(
        id,
        "finding_subject_id",
        json!(
            control_finding.evidence[0]
                .anchor
                .subject_id
                .as_ref()
                .map(|subject| subject.as_str())
        ),
        declared_control,
    );
    assert_declared_answer(
        id,
        "not_checked_count",
        json!(control_record.verdict.not_checked.len()),
        declared_control,
    );
    assert!(
        !control_record.verdict.is_ready_for_hand_off(),
        "{id}: the control reports the project ready to hand off, and nothing in it was checked"
    );

    assert_eq!(
        shipped_project_files(id),
        files_before,
        "{id}: a run wrote into the fixture's own project"
    );

    // The configuration root this test owned, removed rather than left behind:
    // the only file under it is the user's grant, and it is under the
    // repository's own ignored directory rather than anybody's real one.
    std::fs::remove_dir_all(&scratch.project).unwrap_or_else(|error| {
        panic!(
            "{id}: cannot remove the scratch directory {}: {error}",
            scratch.project.display()
        )
    });
    assert!(
        !scratch.project.exists(),
        "{id}: the configuration root this test wrote is still there after the test"
    );
}

// --- checker failure: the fixture P14-T007 implemented --------------------
//
// A critical check that produced no result. `aggregate_run` walks the *schedule*
// rather than the results, so a scheduled check nobody reported on becomes a row
// and not an absence, and that function is the only place in the tree that
// decides so — no fixture reached it before this one.
//
// The fixture is a schedule and six runs over it, and the acceptance it grades
// is a **negative** claim. *Critical error/skipped/unknown cannot aggregate
// green* is satisfied by three different broken things, and none of them looks
// like one:
//
// - a product that never produced a result at all, which satisfies it vacuously
//   because there is nothing left to be green;
// - a product that answers `NotEnoughChecked` to everything, including a run in
//   which the one critical check passed;
// - a test asserting only `!severity.is_green()`, which is true of
//   `NotEnoughChecked`, `NotReady`, `NeedsAttention` and of an empty plan.
//
// So nothing here is asserted as "not green". Every run declares the **exact**
// severity it must reach, every row declares its state and its sentence, and
// exactly one run — the control, the same schedule with a pass handed back
// instead of nothing — must reach `Green`.

/// The `P14-T007` fixture, named rather than discovered for the reason every
/// list in this file is: a test that discovered it would pass on an empty
/// directory.
///
/// The same id is named in `crates/sure-testkit/tests/fixture_apps.rs`, which
/// grades the artefacts — the schema, the false-green rule, the README and the
/// manifest row — and
/// `every_checker_failure_fixture_these_assertions_name_is_a_fixture_this_repository_ships`
/// is what says the two files are talking about the same directory.
const CHECKER_FAILURE_FIXTURES: &[&str] = &["check-crash"];

/// The `checker_failure` block of one fixture's scenario.
fn checker_failure_block(id: &str) -> Value {
    scenario_of(id)
        .get("checker_failure")
        .cloned()
        .unwrap_or_else(|| {
            panic!(
                "fixtures/adversarial/{id}/scenario.json declares no checker_failure block, so \
                 there is no declaration of what a check with no result answers"
            )
        })
}

/// A value the fixture declares by its wire name, read as the product's own type.
///
/// The vocabulary is not restated here: `Severity`, `EvidenceClass`,
/// `CheckStatus`, `NotCheckedReason`, `ExecutionMode` and `ActionKind` are all
/// `Deserialize` with their wire names, so a name the fixture gets wrong is a
/// red test rather than a name this file would have had to write down a second
/// time.
///
/// The one name this file *does* spell out is `CheckReason`, and it is spelled
/// out at the call site rather than here: it is not a wire type — it is built by
/// the proposers out of what a discovery read — so there is nothing to
/// deserialise it from.
fn from_wire<T: serde::de::DeserializeOwned>(id: &str, what: &str, value: &Value) -> T {
    serde_json::from_value(value.clone()).unwrap_or_else(|error| {
        panic!("{id}: the fixture declares {what} as {value}, and that is not one: {error}")
    })
}

/// The execution mode and permission set one name in the fixture refers to.
///
/// Every permission is read and none is defaulted: a set that named only the
/// permissions it grants would leave the rest to whatever `inspect_only()`
/// happens to hold, which is a second place for the fixture's answer to live.
fn declared_mode(id: &str, name: &str, declared: &Value) -> (ExecutionMode, ExecutionPermissions) {
    let mode: ExecutionMode = from_wire(
        id,
        &format!("the execution mode `{name}`"),
        declared.get("mode").unwrap_or_else(|| {
            panic!("{id}: the mode `{name}` declares no execution mode of its own")
        }),
    );
    let permissions = declared
        .get("permissions")
        .and_then(Value::as_object)
        .unwrap_or_else(|| panic!("{id}: the mode `{name}` declares no permission set"));
    assert_eq!(
        permissions.len(),
        Permission::ALL.len(),
        "{id}: the mode `{name}` declares a permission set of {} names and there are {} \
         permissions, so one of them is neither granted nor withheld and a test that read it \
         would be guessing",
        permissions.len(),
        Permission::ALL.len()
    );
    let mut granted = ExecutionPermissions::inspect_only();
    for permission in Permission::ALL {
        let name = permission.as_str();
        let allowed = permissions
            .get(name)
            .and_then(Value::as_bool)
            .unwrap_or_else(|| {
                panic!("{id}: the mode `{name}` does not say whether `{name}` is granted")
            });
        granted.set(*permission, allowed);
    }
    (mode, granted)
}

/// One declared check, as the plan entry the plan builder is handed: since
/// `P18-T003` a proposal **and** the operation beside it.
///
/// **A candidate observation, and the most this file can honestly supply.** The
/// fixture declares checks as data and nothing here starts a process, so the only
/// true thing to say about each of them at plan time is *nothing has settled this
/// check* — a warning if a run ever reached it, never a pass. What is graded below
/// is the plan's shape and the mode it ran under, not how a check is carried out;
/// `P18-T004` replaces the placeholders on the product's own paths.
fn declared_proposal(id: &str, check: &Value) -> PlannedWork {
    let declared_id = check["id"]
        .as_str()
        .unwrap_or_else(|| panic!("{id}: a declared check has no id"));
    let check_id = CheckId::parse(declared_id).unwrap_or_else(|error| {
        panic!("{id}: `{declared_id}` is not a well-formed check id: {error}")
    });
    let severity: Severity = from_wire(id, "a check severity", &check["severity"]);
    let evidence: EvidenceClass = from_wire(id, "an evidence class", &check["evidence_class"]);
    let reason = match check["reason"].as_str() {
        Some("project_wide") => CheckReason::ProjectWide,
        other => panic!(
            "{id}: a declared check gives `{other:?}` as its reason, and this file knows only \
             `project_wide`: a check whose reason names a file, a component or a declared command \
             would have to be a fact about a project, and this fixture ships none"
        ),
    };
    let actions: Vec<ActionKind> = check["actions"]
        .as_array()
        .unwrap_or_else(|| {
            panic!(
                "{id}: a declared check takes no actions, and the plan builder refuses such a \
                 check rather than scheduling it"
            )
        })
        .iter()
        .map(|action| from_wire(id, "an action", action))
        .collect();
    PlannedWork::new(
        CheckProposal::new(
            check_id,
            check["title"]
                .as_str()
                .unwrap_or_else(|| panic!("{id}: a declared check has no title")),
            severity,
            check["critical"].as_bool().unwrap_or_else(|| {
                panic!("{id}: a declared check does not say whether it is critical")
            }),
            evidence,
            reason,
            &actions,
        ),
        CheckOperation::Precomputed(PrecomputedEvidence::candidate(
            "this fixture builds a plan and observes nothing",
        )),
    )
}

/// One run's schedule, built by the product's own plan builder.
///
/// The plan is the same code a real run goes through, so what is graded below is
/// the plan a person would actually get rather than one this file assembled. The
/// builder's own `refused()` list is asserted empty before the plan is taken: a
/// proposal it turned down would leave every run below describing a plan that
/// never existed, and the check it named would be missing for a reason nothing
/// else here would notice.
fn declared_schedule(id: &str, block: &Value, run: &Value, what: &str) -> CheckSchedule {
    let mode_name = run["mode"]
        .as_str()
        .unwrap_or_else(|| panic!("{id}: the `{what}` run declares no execution mode"));
    let mode = block["schedule"]["modes"]
        .get(mode_name)
        .unwrap_or_else(|| {
            panic!(
                "{id}: the `{what}` run names the mode `{mode_name}` and the fixture declares no \
                 such mode"
            )
        });
    let (mode, permissions) = declared_mode(id, mode_name, mode);

    let declared = block["schedule"]["checks"]
        .as_array()
        .unwrap_or_else(|| panic!("{id}: the fixture declares no checks at all"));
    let wanted = declared_lines(
        &run["schedule"],
        &format!("the checks the `{what}` run schedules"),
    );

    let mut builder = PlanBuilder::new(mode, permissions);
    for id_of_check in &wanted {
        let check = declared
            .iter()
            .find(|check| check["id"].as_str() == Some(id_of_check.as_str()))
            .unwrap_or_else(|| {
                panic!(
                    "{id}: the `{what}` run schedules `{id_of_check}` and the fixture declares no \
                     such check"
                )
            });
        builder
            .propose(declared_proposal(id, check))
            .unwrap_or_else(|refused| {
                panic!(
                    "{id}: the plan builder refused `{id_of_check}` for the `{what}` run: {refused}"
                )
            });
    }
    assert!(
        builder.refused().is_empty(),
        "{id}: the `{what}` run's plan holds refusals this test did not notice"
    );
    let schedule = builder.build();

    let planned = sorted_ids(
        schedule
            .checks()
            .iter()
            .map(|check| check.proposal().id().as_str()),
    );
    let mut declared_ids = wanted;
    declared_ids.sort();
    assert_eq!(
        planned, declared_ids,
        "{id}: the plan the product built for the `{what}` run holds different checks from the \
         ones the run declares"
    );
    schedule
}

/// The results one run declares it handed back, as the product's own values.
///
/// Three of the product's constructors and nothing else: a check that ran and
/// passed, a checker that failed, and one recorded as not run with a reason.
/// There is no branch here that builds a status by hand, so the fixture cannot
/// declare a result the product has no constructor for.
fn declared_results(
    id: &str,
    run: &Value,
    schedule: &CheckSchedule,
    fingerprint: &FingerprintId,
    what: &str,
) -> Vec<CheckResult> {
    let declared = run["results"]
        .as_array()
        .unwrap_or_else(|| panic!("{id}: the `{what}` run declares no results list at all"));
    let mut results: Vec<CheckResult> = Vec::with_capacity(declared.len());
    let mut seen: Vec<String> = Vec::new();
    for result in declared {
        let of = result["of"]
            .as_str()
            .unwrap_or_else(|| panic!("{id}: a declared result names no check"));
        assert!(
            !seen.iter().any(|already| already == of),
            "{id}: the `{what}` run hands back two results for `{of}`, and `aggregate_run` refuses \
             that rather than choosing between them"
        );
        seen.push(of.to_owned());
        let check_id = CheckId::parse(of)
            .unwrap_or_else(|error| panic!("{id}: a declared result names `{of}`: {error}"));
        let scheduled = schedule.get(&check_id).unwrap_or_else(|| {
            panic!(
                "{id}: the `{what}` run hands back a result for `{of}` and its plan schedules no \
                 such check, so the result would be reported as unscheduled and this run would not \
                 be the one the fixture declares"
            )
        });
        let proposal = scheduled.proposal();
        let status: CheckStatus = from_wire(id, "a check status", &result["status"]);
        let title = proposal.title().to_owned();
        let severity = proposal.severity();
        let critical = proposal.critical();
        let built = match status {
            CheckStatus::Pass => CheckResult::pass(
                check_id,
                title,
                severity,
                critical,
                proposal.evidence_class(),
                fingerprint.clone(),
            ),
            CheckStatus::Error => CheckResult::errored(
                check_id,
                title,
                severity,
                critical,
                result["detail"].as_str().unwrap_or_else(|| {
                    panic!(
                        "{id}: a declared error result carries no detail, and the product has no \
                         sentence of its own for a checker error"
                    )
                }),
                fingerprint.clone(),
            ),
            CheckStatus::Skipped => CheckResult::not_run(
                check_id,
                title,
                severity,
                critical,
                from_wire(id, "a not-checked reason", &result["reason"]),
                fingerprint.clone(),
            ),
            other => panic!(
                "{id}: the `{what}` run declares a result with status `{other:?}`, and this \
                 fixture builds only the three the product has a constructor for"
            ),
        };
        results.push(built);
    }
    results
}

/// The ids of a list of things, as strings and sorted.
///
/// Sorted rather than left in whatever order the product produced, because plan
/// order is a property this fixture does not pin: what it is about is which
/// rows are there and what each one says.
fn sorted_ids<'a>(ids: impl Iterator<Item = &'a str>) -> Vec<String> {
    let mut ids: Vec<String> = ids.map(str::to_owned).collect();
    ids.sort();
    ids
}

/// Every critical row of a report, sorted by id.
///
/// A row is one object holding both halves — the result's own status and
/// evidence class, and the classification, the blocking flag, the reason and the
/// sentence the report shows for it — because all four are what the criterion is
/// read as, and four parallel lists would let one of them be dropped without the
/// others moving.
fn rows_of(report: &RunReport) -> Value {
    let mut rows: Vec<Value> = report
        .critical()
        .iter()
        .map(|check| {
            let result = report
                .results()
                .iter()
                .find(|result| result.id == *check.id())
                .unwrap_or_else(|| {
                    panic!(
                        "the report shows a critical row for `{}` and holds no result behind it",
                        check.id()
                    )
                });
            json!({
                "id": check.id().as_str(),
                "status": result.status.as_str(),
                "evidence_class": result.evidence_class.as_str(),
                "critical_state": check.state(),
                "blocks": check.blocks(),
                "not_checked_reason": check.reason(),
                "detail": check.detail(),
            })
        })
        .collect();
    rows.sort_by(|left, right| left["id"].as_str().cmp(&right["id"].as_str()));
    Value::Array(rows)
}

/// Everything one run's report says, as the fixture declares it.
fn report_answers(report: &RunReport, planned: &[String]) -> Value {
    let aggregate = report.aggregate();
    json!({
        "check_ids": planned,
        "row_count": report.results().len(),
        "rows": rows_of(report),
        "unreported": sorted_ids(report.unreported().iter().map(CheckId::as_str)),
        "overruled": sorted_ids(report.overruled().iter().map(CheckId::as_str)),
        "unscheduled": sorted_ids(report.unscheduled().iter().map(CheckId::as_str)),
        "blocking": sorted_ids(report.blocking().map(|check| check.id().as_str())),
        "critical_not_checked": sorted_ids(aggregate.coverage.critical_not_checked.iter().map(CheckId::as_str)),
        "critical_errored": sorted_ids(aggregate.coverage.critical_errored.iter().map(CheckId::as_str)),
        "critical_failed": sorted_ids(aggregate.coverage.critical_failed.iter().map(CheckId::as_str)),
        "critical_out_of_scope": sorted_ids(aggregate.coverage.critical_out_of_scope.iter().map(CheckId::as_str)),
        "critical_checked": aggregate.coverage.critical_checked,
        "counts": aggregate.counts,
        "checked": aggregate.counts.checked(),
        "not_checked": aggregate.counts.not_checked(),
        "aggregate_severity": aggregate.severity,
        "aggregate_headline": aggregate.headline,
        "report_is_green": report.is_green(),
    })
}

/// What the corpus writes down about this fixture and what the fixture declares
/// must be the same answers, in both directions.
///
/// Unlike the intent fixtures, this one declares a *run* per set of answers
/// rather than one `expect` block, so the comparison is made per run. Both
/// directions matter for the same reason: the forward one is the drift check on
/// what a reader of `evaluation/` sees, and the reverse one is what makes
/// deleting a `required_outcomes` entry a red test rather than a fixture that
/// quietly stopped grading something.
fn assert_the_checker_failure_outcomes_account_for_the_declared_runs(id: &str, block: &Value) {
    let outcomes = scenario_of(id)["required_outcomes"]
        .as_array()
        .cloned()
        .unwrap_or_else(|| panic!("{id}/scenario.json requires no outcomes at all"));
    assert!(
        !outcomes.is_empty(),
        "{id}/scenario.json requires no outcomes at all"
    );
    let runs = block["runs"]
        .as_object()
        .unwrap_or_else(|| panic!("{id}/scenario.json declares no runs"));

    for (kind, run) in runs {
        let outcome = required_outcome(id, &outcomes, kind);
        assert_answers_account_for(
            id,
            &answer_keys(outcome),
            &run["expect"],
            &format!("the fixture's declared `{kind}` run"),
        );
    }
    for outcome in &outcomes {
        let kind = outcome["kind"]
            .as_str()
            .unwrap_or_else(|| panic!("{id}/scenario.json has a required outcome with no kind"));
        assert!(
            runs.contains_key(kind),
            "{id}/scenario.json records a `{kind}` outcome and the fixture declares no such run, \
             so the corpus entry asserts something no fixture says"
        );
    }
}

#[test]
fn every_checker_failure_fixture_these_assertions_name_is_a_fixture_this_repository_ships() {
    // The guard every list in this file has, for the same reason: a renamed
    // directory would make every assertion below about a schedule nobody ships.
    for id in CHECKER_FAILURE_FIXTURES {
        let dir = fixture(id);
        assert!(dir.is_dir(), "{} is not a directory", dir.display());
        let scenario = dir.join("scenario.json");
        assert!(
            scenario.is_file(),
            "{id} has no scenario.json, so there is no declaration to read"
        );
        assert!(
            dir.join("README.md").is_file(),
            "{id} has no README.md, so nothing says in words what it traps"
        );

        let block = checker_failure_block(id);
        assert!(
            block.get("read_by").is_some(),
            "{id}/scenario.json declares no read_by, so nothing says which route answers"
        );
        let checks = block["schedule"]["checks"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        assert!(
            checks.len() >= 2,
            "{id}/scenario.json declares {} checks, and the two kinds of `Skipped` it separates — \
             one refused by the mode, one honestly out of scope — need two",
            checks.len()
        );
        let runs = block["runs"].as_object().cloned().unwrap_or_default();
        assert!(
            runs.len() >= 2,
            "{id}/scenario.json declares {} runs, and a fixture is worth nothing without a control",
            runs.len()
        );
        assert!(
            block["control"]["moved"]["what"].as_str().is_some(),
            "{id}/scenario.json declares a control that does not say what moved"
        );
        assert!(
            !block["control"]["why"]
                .as_str()
                .unwrap_or_default()
                .is_empty(),
            "{id}/scenario.json declares a control with no reason given"
        );

        // Exactly one run may declare itself green and it has to be the control.
        // This is the acceptance stated as a property of the fixture rather than
        // of the product: a directory in which two runs reach `Green`, or in
        // which the control stopped reaching it, is a directory that has stopped
        // measuring the claim it is named after.
        let green: Vec<&str> = runs
            .iter()
            .filter(|(_, run)| run["expect"]["report_is_green"].as_bool() == Some(true))
            .map(|(kind, _)| kind.as_str())
            .collect();
        assert_eq!(
            green,
            ["control"],
            "{id}/scenario.json declares the runs that reach green as {green:?}, and the one run \
             that may is the control: a fixture for *cannot aggregate green* in which nothing can \
             reach green has not measured the refusal"
        );
        assert_eq!(
            runs["control"]["expect"]["aggregate_severity"].as_str(),
            Some("green"),
            "{id}/scenario.json declares a control whose severity is not green"
        );

        // The tripwire, asserted here rather than left to the other file: this
        // case is `release_blocking` and it is not a project, so the key that
        // decides `fixture_has_an_app` in `finding_severity_rule.rs` must not be
        // anywhere in the document.
        let text = std::fs::read_to_string(&scenario)
            .unwrap_or_else(|error| panic!("cannot read {}: {error}", scenario.display()));
        assert!(
            !text.contains("\"entry_points\""),
            "{id}/scenario.json declares entry points, and the case is a schedule rather than a \
             project with runnable code: adding them would pull a release-blocking case into a list \
             in finding_severity_rule.rs that it does not belong on"
        );
    }
}

#[test]
fn a_checker_failure_is_a_row_and_never_a_pass_and_the_control_reaches_green() {
    let id = "check-crash";
    let block = checker_failure_block(id);
    assert_the_checker_failure_outcomes_account_for_the_declared_runs(id, &block);
    let runs = block["runs"].as_object().cloned().unwrap_or_default();

    // One fingerprint for every run: `aggregate_run` refuses a result
    // established against another project state, and a fixture whose runs
    // disagreed about the state would be measuring the refusal rather than the
    // aggregation.
    let fingerprint =
        FingerprintId::parse("fp_g7x2k4m9nq3t8wvb5cy1h").expect("a well-formed fingerprint id");

    let mut answers: BTreeMap<String, Value> = BTreeMap::new();
    let mut reports: BTreeMap<String, RunReport> = BTreeMap::new();
    let mut schedules: BTreeMap<String, CheckSchedule> = BTreeMap::new();
    for (kind, run) in &runs {
        let schedule = declared_schedule(id, &block, run, kind);
        let results = declared_results(id, run, &schedule, &fingerprint, kind);
        let report =
            aggregate_run(&schedule, &results, &[], &fingerprint).unwrap_or_else(|refused| {
                panic!(
                    "{id}: aggregating the `{kind}` run was refused rather than answered: {refused}"
                )
            });
        let planned = sorted_ids(
            schedule
                .checks()
                .iter()
                .map(|check| check.proposal().id().as_str()),
        );
        answers.insert(kind.clone(), report_answers(&report, &planned));
        reports.insert(kind.clone(), report);
        schedules.insert(kind.clone(), schedule);
    }

    // The row must be present, and it is asserted **before** the comparison of
    // the answers, so that the mutation this fixture exists to catch fails on
    // the sentence that says what went wrong rather than on a difference between
    // two JSON objects.
    //
    // A run whose plan lost its check is not a run whose answer nobody needed:
    // with nothing scheduled there is nothing to report, so every answer below
    // would be vacuously non-green and the fixture would still pass a criterion
    // it had stopped measuring. This is the assertion that removing the check
    // from the declared schedule reddens, and the reason the declared ids are
    // read from `expect` rather than from the run's own `schedule` list, which
    // the same edit would empty.
    for (kind, run) in &runs {
        let planned = answers[kind]["check_ids"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        let rows = answers[kind]["rows"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        let declared = declared_lines(
            &run["expect"]["check_ids"],
            &format!("the checks the `{kind}` run must have rows for"),
        );
        assert!(
            !declared.is_empty(),
            "{id}: the `{kind}` run declares no checks, and a run with nothing scheduled is a run \
             this fixture cannot say anything about"
        );
        // The named half first, and this is the order that matters: a plan that
        // lost a declared check must fail on the sentence that names the check,
        // not on two integers that differ, so the count comparison below is the
        // one left to catch the other direction — a plan that grew a check the
        // fixture does not declare, where every declared id is still present.
        for wanted in &declared {
            assert!(
                planned
                    .iter()
                    .any(|planned| planned.as_str() == Some(wanted.as_str())),
                "{id}: the `{kind}` run's plan holds {planned:?} and not `{wanted}`, so the check \
                 the case is about is not a row in the report and nothing below is a measurement \
                 of it"
            );
            assert!(
                rows.iter()
                    .any(|row| row["id"].as_str() == Some(wanted.as_str())),
                "{id}: the `{kind}` run planned `{wanted}` and the report shows no row for it, so \
                 the check the case is about is absent from the verdict rather than reported in it"
            );
        }
        assert_eq!(
            planned.len(),
            declared.len(),
            "{id}: the `{kind}` run planned {} checks and declares {}",
            planned.len(),
            declared.len()
        );
    }

    // The anti-vacuity assertion, and it comes before the per-run severities
    // because it is the one that says whether this fixture is a measurement at
    // all. A fixture whose control declares the same answer as the run it is a
    // control for measures nothing, whether or not the product agrees with it —
    // so the difference is asserted twice, once in the product's own answers and
    // once in the fixture's own declaration, and the second is the one that
    // catches a control edited into a copy of the run beside it.
    assert_ne!(
        reports["control"].aggregate().severity,
        reports["checker_failure_unknown"].aggregate().severity,
        "{id}: the same schedule with nothing reported and with a pass reported reached the same \
         severity, so the two halves of this fixture are the same measurement"
    );
    assert_ne!(
        runs["control"]["expect"]["aggregate_severity"],
        runs["checker_failure_unknown"]["expect"]["aggregate_severity"],
        "{id}: the control declares the same severity as the run it is a control for, so the pair \
         is the same declaration written twice and nothing here is a measurement of the check"
    );
    assert_ne!(
        runs["control"]["expect"]["report_is_green"],
        runs["checker_failure_unknown"]["expect"]["report_is_green"],
        "{id}: the control declares the same greenness as the run it is a control for"
    );

    // The third of the four readings, as its own assertion rather than as a
    // consequence of comparing two JSON objects: **the exact severity, pinned
    // per run**, and the exact answer to *is this a green run*. `!is_green()` is
    // what a test reaches for here and it is not an assertion — it is satisfied
    // by `NotEnoughChecked`, `NotReady`, `NeedsAttention` and by an empty plan
    // alike — so the fixture declares the severity each run must reach and this
    // is where that declaration is held against the product's answer.
    for (kind, run) in &runs {
        let declared = run["expect"]["aggregate_severity"]
            .as_str()
            .unwrap_or_else(|| panic!("{id}: the `{kind}` run declares no aggregate severity"));
        assert_eq!(
            reports[kind].aggregate().severity.as_str(),
            declared,
            "{id}: the `{kind}` run reached `{}` and the fixture declares `{declared}` for it, and \
             this is the assertion a mutation to `green` reddens: a test asserting only that the \
             run is not green would still pass it, because the product's answer does not move when \
             the declaration does",
            reports[kind].aggregate().severity.as_str()
        );
        let declared_green = run["expect"]["report_is_green"]
            .as_bool()
            .unwrap_or_else(|| panic!("{id}: the `{kind}` run declares no greenness"));
        assert_eq!(
            reports[kind].is_green(),
            declared_green,
            "{id}: the `{kind}` run answers `is_green() == {}` and the fixture declares {declared_green}",
            reports[kind].is_green()
        );
    }

    // The exact severity, and the control. `!severity.is_green()` would be
    // satisfied by every one of the runs above and by an empty plan — and the
    // control is the only run that fails a product which answers
    // `not_enough_checked` to everything.
    assert!(
        reports["control"].is_green(),
        "{id}: the control does not reach green, and a fixture for *cannot aggregate green* whose \
         control cannot reach green has not measured the refusal: {}",
        reports["control"].aggregate().headline
    );
    assert_eq!(
        reports["control"].aggregate().severity.as_str(),
        "green",
        "{id}: the control is not green"
    );
    let green: Vec<&String> = reports
        .iter()
        .filter(|(_, report)| report.is_green())
        .map(|(kind, _)| kind)
        .collect();
    assert_eq!(
        green,
        ["control"],
        "{id}: the runs that reach green are {green:?}, and the only one that may is the control"
    );

    // One thing moved. The control's plan is the fixture's own plan — the same
    // checks, the same mode, the same decisions — and the results are the whole
    // of the difference, which is what makes the pair a control rather than two
    // runs that happen to disagree.
    assert_eq!(
        schedules["control"], schedules["checker_failure_unknown"],
        "{id}: the control's plan is not the plan of the run it is a control for, so what moved is \
         not only what came back"
    );

    // The sentences, held against the product's own constant and the
    // vocabulary's own method rather than against the copies in the fixture. A
    // rewrite of either sentence in the product reddens here even if the fixture
    // is rewritten to match, which is the one change this pair exists to notice.
    let unknown_detail = answers["checker_failure_unknown"]["rows"][0]["detail"].clone();
    assert_eq!(
        unknown_detail, NOTHING_CAME_BACK,
        "{id}: the sentence a check that reported nothing carries is not the one \
         `sure_core::aggregation` chose for it"
    );
    assert_eq!(
        unknown_detail, runs["checker_failure_unknown"]["expect"]["rows"][0]["detail"],
        "{id}: the fixture declares a different sentence from the one the product produced"
    );
    let skipped_detail = answers["checker_failure_skipped"]["rows"][0]["detail"].clone();
    assert_eq!(
        skipped_detail,
        NotCheckedReason::ExecutionNotAuthorized.plain_explanation(),
        "{id}: the sentence a refused check carries is not the vocabulary's own sentence for the \
         reason the plan gave"
    );
    assert_eq!(
        answers["checker_failure_skipped"]["rows"][0]["not_checked_reason"],
        json!(NotCheckedReason::ExecutionNotAuthorized),
        "{id}: a check the mode refused is not carrying the reason the plan gave for it"
    );

    // The measured ordering, asserted as the pair it is: the same out-of-scope
    // skip alone is `not_enough_checked`, because nothing ran, and beside a pass
    // it is `needs_attention`. Both differ from each other and from the control,
    // so a build that collapsed either branch reddens here.
    assert_eq!(
        reports["scope_limit_alone"].aggregate().severity.as_str(),
        "not_enough_checked",
        "{id}: a lone out-of-scope critical skip no longer answers the empty-plan severity, so \
         either the branch order moved or the counts did"
    );
    assert_eq!(
        reports["scope_limit_beside_a_pass"]
            .aggregate()
            .severity
            .as_str(),
        "needs_attention",
        "{id}: the same skip beside a pass no longer answers `needs_attention`"
    );
    assert_ne!(
        reports["scope_limit_alone"].aggregate().severity,
        reports["scope_limit_beside_a_pass"].aggregate().severity,
        "{id}: one pass moved and the severity did not, so nothing here is a measurement of the \
         branch this pair exists for"
    );
    assert!(
        reports["scope_limit_beside_a_pass"]
            .aggregate()
            .counts
            .not_checked()
            > 0,
        "{id}: the run with an unchecked critical check reports nothing unchecked, so it has \
         stopped saying the project was not fully checked"
    );

    // An empty plan, which is what removing the check from the schedule leaves.
    // It is asserted here rather than only described: it is not green — which is
    // exactly why `!is_green()` is not the assertion this fixture makes — and it
    // is not the answer any run above reaches, so the row assertion is doing work
    // and not restating a vacuum.
    let empty = PlanBuilder::new(
        ExecutionMode::InspectOnly,
        ExecutionPermissions::inspect_only(),
    )
    .build();
    let nothing = aggregate_run(&empty, &[], &[], &fingerprint).expect("an empty plan aggregates");
    assert!(
        nothing.results().is_empty() && nothing.unreported().is_empty(),
        "{id}: an empty plan produced rows, so the fixture's row assertions would not distinguish \
         it from a run that planned something"
    );
    assert!(
        !nothing.is_green(),
        "{id}: an empty plan is green, and this whole fixture is built on it not being"
    );
    assert_eq!(
        nothing.aggregate().severity.as_str(),
        "not_enough_checked",
        "{id}: an empty plan no longer answers the same severity as the fixture's own run, so \
         non-greenness alone would not tell the two apart even if it were the assertion"
    );
    assert_ne!(
        report_answers(&nothing, &[]),
        answers["checker_failure_unknown"],
        "{id}: an empty plan answers what the fixture's own run answers, so the row assertions \
         above are satisfied by a run that planned nothing"
    );

    // The net, and it is last on purpose. Every asserted claim above is named and
    // says what it is about; this is the exhaustive one, holding **every** key of
    // every run's answer against the fixture's declaration in both directions, so
    // that a key nobody thought to name is still graded rather than ignored. The
    // reverse direction is `answer_keys` / `assert_answers_account_for` above;
    // this is the forward one, and it is the reason a new key in the fixture is a
    // red test rather than a line nothing reads.
    for (kind, run) in &runs {
        let declared = run["expect"]
            .as_object()
            .unwrap_or_else(|| panic!("{id}: the `{kind}` run declares no expected answers"));
        let reported = answers[kind]
            .as_object()
            .unwrap_or_else(|| panic!("{id}: the `{kind}` run produced no answers"));
        let declared_keys: BTreeSet<&str> = declared.keys().map(String::as_str).collect();
        let reported_keys: BTreeSet<&str> = reported.keys().map(String::as_str).collect();
        assert_eq!(
            reported_keys, declared_keys,
            "{id}: the `{kind}` run's answers and the fixture's declaration are about different \
             things, so one of them has stopped being graded"
        );
        for (key, expected) in declared {
            assert_eq!(
                reported[key], *expected,
                "{id}: the `{kind}` run's `{key}` is not the one the fixture declares, so the case \
                 is not being graded as written"
            );
        }
    }
}

// --- P14-T008: the dangerous-action fixtures -------------------------------

/// The `P14-T008` fixtures, named rather than discovered for the reason every
/// list in this file is: a test that discovered them would pass on an empty
/// directory. This is where the in-process grading below registers: each id is
/// driven through `assess_claude_code_tool` / `assess_cursor_tool`, and the runs
/// its `dangerous_action` block declares are held against the product's own
/// answers.
///
/// The same three ids are named in `crates/sure-testkit/tests/fixture_apps.rs`,
/// which grades the artefacts — the schema, the false-green rule, the README,
/// the manifest row and the shape of the control — but they are two lists. This
/// paragraph used to end "the guard below is what says the two files are talking
/// about the same directories", which is more than that guard does: it reads
/// this list against the disk, the other file's guard reads its own copy against
/// the same disk, and the two lists are never compared with each other. Measured
/// at `P14-T008`: removing `"sensitive-read"` from this list leaves this file's
/// tests green at 32 passed and `fixture_apps.rs` green at 26, so an id dropped
/// here stops being graded behaviourally — its runs are still declared, and
/// still artefact-checked through the other file's copy of the list — with
/// nothing in the tree to say so.
const DANGEROUS_ACTION_FIXTURES: &[&str] = &["dangerous-delete", "force-push", "sensitive-read"];

/// The keys of a declared run that are the request and the settings it is
/// answered under — which is to say, the fields a control may move.
///
/// The same list is compared in `fixture_apps.rs`, for the same reason: a
/// control whose difference is not the one the fixture declares is not a control,
/// and the pair would then be two runs that happen to disagree.
const REQUEST_AND_SETTINGS: &[&str] = &["harness", "tool", "path", "command", "mode", "protection"];

/// The `dangerous_action` block of one fixture's scenario.
fn dangerous_action_block(id: &str) -> Value {
    scenario_of(id)
        .get("dangerous_action")
        .cloned()
        .unwrap_or_else(|| {
            panic!(
                "fixtures/adversarial/{id}/scenario.json declares no dangerous_action block, so \
                 there is no declaration of what SURE answers to a request"
            )
        })
}

/// The runs one fixture declares, keyed by the name the corpus uses for them.
fn declared_action_runs(id: &str, block: &Value) -> serde_json::Map<String, Value> {
    block["runs"].as_object().cloned().unwrap_or_else(|| {
        panic!("{id}/scenario.json declares no runs at all, so there is nothing to grade")
    })
}

/// One declared run, driven through the product's own assessment for it.
///
/// The declaration is data and this is the only place it becomes a call: the
/// harness picks the function the integration calls, and the mode name picks a
/// declared settings set through `declared_mode` — every permission is read and
/// none is defaulted — rather than a literal here.
fn assess_declared_run(id: &str, block: &Value, kind: &str, run: &Value) -> Assessment {
    let mode_name = run["mode"]
        .as_str()
        .unwrap_or_else(|| panic!("{id}: the `{kind}` run declares no execution mode"));
    let declared = block["settings"]["modes"]
        .get(mode_name)
        .unwrap_or_else(|| {
            panic!(
                "{id}: the `{kind}` run names the mode `{mode_name}` and the fixture declares no \
                 such mode"
            )
        });
    let (mode, permissions) = declared_mode(id, mode_name, declared);
    let protection: ProtectionMode = from_wire(id, "a protection mode", &run["protection"]);
    let harness = run["harness"]
        .as_str()
        .unwrap_or_else(|| panic!("{id}: the `{kind}` run names no harness"));
    let tool = run["tool"]
        .as_str()
        .unwrap_or_else(|| panic!("{id}: the `{kind}` run names no tool"));
    let request = ToolRequest {
        tool,
        path: run.get("path").and_then(Value::as_str),
        command: run.get("command").and_then(Value::as_str),
    };
    match harness {
        "claude_code" => assess_claude_code_tool(&request, mode, &permissions, protection),
        "cursor" => assess_cursor_tool(&request, mode, &permissions, protection),
        other => panic!(
            "{id}: the `{kind}` run names the harness {other:?}, and this tree has two \
             integrations: `claude_code` and `cursor`"
        ),
    }
}

/// Everything one assessment answers, as the fixture declares it.
///
/// The danger goes in as its **wire name** rather than as the words a user reads
/// (`Danger::as_str`): the wire name is what a stored decision records and what
/// the fixture declares, and the sentence is compared separately, against the
/// product's own function.
fn action_answers(assessment: &Assessment) -> Value {
    json!({
        "decision": assessment.decision.decision.as_str(),
        "danger": assessment.danger.map(Danger::wire_name),
        "reason": assessment.decision.reason.clone(),
    })
}

/// A sentence the fixture declares, read as the list of lines it is.
fn sorted_lines(value: &Value, what: &str) -> Vec<String> {
    let mut lines = declared_lines(value, what);
    lines.sort();
    lines
}

/// The module and the functions a fixture names as the route that answers it.
///
/// The pointer is checked rather than trusted: a fixture naming a function that
/// does not exist would be a declaration about code nobody ships, and the file it
/// points at could then be renamed or split with nothing here noticing.
fn assert_the_pointer_names_the_route(id: &str, what: &str, pointer: &Value) {
    let module = pointer["module"]
        .as_str()
        .unwrap_or_else(|| panic!("{id}: {what} names no module"));
    let path = sure_testkit::repository_root().join(module);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!("{id}: {what} names `{module}`, which is not a file this repository ships: {error}")
    });
    let functions = declared_lines(
        &pointer["functions"],
        &format!("the functions {what} names"),
    );
    assert!(
        !functions.is_empty(),
        "{id}: {what} names no function at all, so it is not a pointer"
    );
    for name in &functions {
        assert!(
            text.contains(&format!("fn {name}(")),
            "{id}: {what} names `{name}` and `{module}` declares no such function, so the route \
             this fixture is about has moved or been renamed and nothing here would notice"
        );
    }
}

/// The sentence a held request carries, held against the product's own answer
/// for it.
///
/// The product writes more than one kind of hold sentence and they are different
/// strings, so the fixture says which one it declares and this is where that
/// claim is graded. Two of the checks are the ones the case exists for:
///
/// - a `danger_reason` sentence is compared **against the function's own return
///   value**, not against a copy of the text in this file, so what the check
///   guarantees is that the two agree: a reworded sentence in the product reddens
///   the fixture unless the declaration is reworded with it, and a reworded
///   declaration reddens unless the product moves with it;
/// - the strict route's sentence is required to begin with the danger's own
///   `consequence()` and to be **none** of the `danger_reason` sentences, because
///   the product writes it as the consequence plus a different tail. A build that
///   collapsed the two routes onto one sentence reddens here.
///
/// Every route is also held against the fixture's own declared text first, which
/// is the direction that makes a rewrite of *any* of these sentences red unless
/// the other copy is reworded with it.
///
/// The first bullet used to end "so a reworded sentence in the product reddens
/// the fixture even if the fixture is reworded to match". That clause was false
/// when it was written rather than something that stopped being true later: the
/// declaration is held against the product's answer by equality before anything
/// else here, and the `danger_reason` check is another equality, so neither can
/// catch the two texts moving together. Measured at `P14-T008`: rewording
/// `FORCE_PUSH_CONSEQUENCE` and the six copies of that sentence in
/// `fixtures/adversarial/force-push/scenario.json` together leaves the grading
/// test below green, while moving either side alone reddens it at that first
/// equality.
fn assert_the_reason_is_the_one_the_fixture_names(
    id: &str,
    kind: &str,
    run: &Value,
    assessment: &Assessment,
) {
    let declared = run["expect"]["reason"]
        .as_str()
        .unwrap_or_else(|| panic!("{id}: the `{kind}` run declares no sentence"));
    let named_by = run["reason_named_by"].as_str().unwrap_or_else(|| {
        panic!("{id}: the `{kind}` run does not say which of the product's sentences it carries")
    });
    let reason = assessment.decision.reason.as_deref().unwrap_or_else(|| {
        panic!(
            "{id}: the `{kind}` run is answered with no sentence at all, and every decision the \
             rule reaches carries one"
        )
    });
    assert_eq!(
        reason, declared,
        "{id}: the `{kind}` run's sentence is not the one its own `expect` block declares, so the \
         fixture and the product disagree about what a user is shown"
    );
    let danger: Option<Danger> =
        from_wire(id, "the danger a run declares", &run["expect"]["danger"]);
    let is_a_danger_sentence = Danger::ALL
        .iter()
        .any(|candidate| reason == danger_reason(*candidate));
    match named_by {
        "danger_reason" => {
            let danger = danger.unwrap_or_else(|| {
                panic!(
                    "{id}: the `{kind}` run says its sentence is `danger_reason`'s and declares no \
                     danger for it"
                )
            });
            assert_eq!(
                reason,
                danger_reason(danger),
                "{id}: the `{kind}` run's sentence is not the one `danger_reason` returns for `{}`, \
                 so either the sentence moved or the danger did — and it is compared against the \
                 function rather than against a copy here on purpose",
                danger.wire_name()
            );
        }
        "the_strict_hold_sentence" => {
            if let Some(danger) = danger {
                assert!(
                    reason.starts_with(danger.consequence()),
                    "{id}: the `{kind}` run is held by strict mode for `{}` and its sentence does \
                     not begin with that danger's own `consequence()`, so the hold and the sentence \
                     have stopped being about the same area",
                    danger.wire_name()
                );
            }
            assert!(
                !is_a_danger_sentence,
                "{id}: the `{kind}` run's sentence is strict mode's own and it equals a \
                 `danger_reason`, so the two routes have collapsed onto one sentence"
            );
        }
        "the_consent_sentence" | "the_permission_sentence" | "the_allow_sentence" => {
            assert!(
                danger.is_none(),
                "{id}: the `{kind}` run carries `{named_by}`'s sentence and declares a danger for \
                 it, and none of those three sentences is a danger's"
            );
            assert!(
                !is_a_danger_sentence,
                "{id}: the `{kind}` run carries `{named_by}`'s sentence, which names no danger, and \
                 it equals a `danger_reason` — so this run is where a build that named a danger it \
                 did not reach would show"
            );
        }
        other => panic!(
            "{id}: the `{kind}` run names its sentence {other:?}, and this file knows \
             `danger_reason`, `the_strict_hold_sentence`, `the_consent_sentence`, \
             `the_permission_sentence` and `the_allow_sentence`"
        ),
    }
}

/// The control, and the one thing it moved.
///
/// Returns the run the control is a control for. The difference is computed from
/// the declaration and compared with the fields the fixture names, because a
/// control that moved two things — or nothing — is a pair that measures something
/// other than what the case is about, and nothing else here would notice.
fn assert_the_control_is_the_one_thing_the_fixture_names(
    id: &str,
    block: &Value,
    runs: &serde_json::Map<String, Value>,
) -> String {
    let of = block["control"]["of"]
        .as_str()
        .unwrap_or_else(|| panic!("{id}: the control names no run"));
    let named = runs.get(of).unwrap_or_else(|| {
        panic!("{id}: the control names `{of}`, which is no run this fixture declares")
    });
    let control = runs.get("control").unwrap_or_else(|| {
        panic!("{id}: the fixture declares no run called `control`, so nothing is held against it")
    });
    let mut differ: Vec<String> = REQUEST_AND_SETTINGS
        .iter()
        .filter(|field| control.get(**field) != named.get(**field))
        .map(|field| (*field).to_owned())
        .collect();
    differ.sort();
    assert!(
        !differ.is_empty(),
        "{id}: the control and the run it is a control for are the same request under the same \
         settings, so the pair measures nothing"
    );
    let declared = sorted_lines(
        &block["control"]["moved"]["fields"],
        &format!("the fields {id}'s control declares it moved"),
    );
    assert_eq!(
        declared, differ,
        "{id}: the control declares it moved {declared:?} and the two runs differ in {differ:?}, \
         so what moved is not what the fixture says moved"
    );
    of.to_owned()
}

/// What the corpus writes down about this fixture and what the fixture declares
/// must be the same answers, in both directions.
///
/// Both directions matter for the same reason the checker-failure fixtures'
/// version of this does: the forward one is the drift check on what a reader of
/// `evaluation/` sees, and the reverse one is what makes deleting a
/// `required_outcomes` entry a red test rather than a fixture that quietly
/// stopped grading something.
fn assert_the_dangerous_action_outcomes_account_for_the_declared_runs(id: &str, block: &Value) {
    let outcomes = scenario_of(id)["required_outcomes"]
        .as_array()
        .cloned()
        .unwrap_or_else(|| panic!("{id}/scenario.json requires no outcomes at all"));
    assert!(
        !outcomes.is_empty(),
        "{id}/scenario.json requires no outcomes at all"
    );
    let runs = declared_action_runs(id, block);

    for (kind, run) in &runs {
        let outcome = required_outcome(id, &outcomes, kind);
        assert_answers_account_for(
            id,
            &answer_keys(outcome),
            &run["expect"],
            &format!("the fixture's declared `{kind}` run"),
        );
    }
    for outcome in &outcomes {
        let kind = outcome["kind"]
            .as_str()
            .unwrap_or_else(|| panic!("{id}/scenario.json has a required outcome with no kind"));
        assert!(
            runs.contains_key(kind),
            "{id}/scenario.json records a `{kind}` outcome and the fixture declares no such run, \
             so the corpus entry asserts something no fixture says"
        );
    }
}

/// What a recorded one-time allowance can be spent on, under the settings each
/// row names.
///
/// Both public functions are read for every row and both answers are graded,
/// because they differ where the tool narrows the acts and the difference is the
/// reason there are two: a grant is spent by a request that matches the tool it
/// names, so what a grant for one tool can cover is not what the settings leave
/// reachable at all.
///
/// The store-backed half — held, allowance, allow, held again — is not driven
/// here. Each fixture names the `sure-cli` test that grades it, and the pointer
/// is checked rather than trusted.
fn assert_the_allowance_is_the_rule_the_fixture_names(id: &str, block: &Value) {
    let allowance = &block["allowance"];
    assert_the_pointer_names_the_route(id, "the allowance's read_by", &allowance["read_by"]);

    let behaviour = &allowance["one_time_behaviour"];
    let file = behaviour["file"]
        .as_str()
        .unwrap_or_else(|| panic!("{id}: the allowance names no file for the store-backed half"));
    let path = sure_testkit::repository_root().join(file);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!(
            "{id}: the allowance names `{file}` for the store-backed half, and that is not a file \
             this repository ships: {error}"
        )
    });
    let tests = declared_lines(
        &behaviour["tests"],
        &format!("the tests {id} names for the store-backed half"),
    );
    assert!(
        !tests.is_empty(),
        "{id}: the allowance names no test for the store-backed half, so nothing says where the \
         grant is actually spent"
    );
    for name in &tests {
        assert!(
            text.contains(&format!("fn {name}(")),
            "{id}: the allowance names `{name}` in `{file}` and no such function is declared there, \
             so the store-backed half of this act is graded nowhere"
        );
    }

    let rows = allowance["rows"]
        .as_array()
        .cloned()
        .unwrap_or_else(|| panic!("{id}: the allowance declares no rows at all"));
    assert!(
        !rows.is_empty(),
        "{id}: the allowance declares no rows, so nothing says what a grant can be spent on"
    );
    for row in &rows {
        let mode_name = row["mode"]
            .as_str()
            .unwrap_or_else(|| panic!("{id}: an allowance row names no execution mode"));
        let declared = block["settings"]["modes"]
            .get(mode_name)
            .unwrap_or_else(|| {
                panic!(
                    "{id}: an allowance row names the mode `{mode_name}` and the fixture declares \
                     no such mode"
                )
            });
        let (mode, permissions) = declared_mode(id, mode_name, declared);
        let protection: ProtectionMode =
            from_wire(id, "an allowance row's protection mode", &row["protection"]);
        let tool = row["tool"]
            .as_str()
            .unwrap_or_else(|| panic!("{id}: an allowance row names no tool"));

        let mut reachable: Vec<String> =
            acts_a_request_could_be_held_for(mode, &permissions, protection)
                .iter()
                .map(|danger| danger.wire_name().to_owned())
                .collect();
        reachable.sort();
        let declared_reachable = sorted_lines(
            &row["acts_the_settings_leave"],
            &format!("the acts an allowance row for `{tool}` under `{mode_name}` leaves in reach"),
        );
        assert_eq!(
            reachable, declared_reachable,
            "{id}: under `{mode_name}` and {protection:?} the settings leave {declared_reachable:?} \
             in reach and the product answers {reachable:?}"
        );

        let mut for_tool: Vec<String> =
            acts_a_tool_could_be_held_for(tool, mode, &permissions, protection)
                .iter()
                .map(|danger| danger.wire_name().to_owned())
                .collect();
        for_tool.sort();
        let declared_for_tool = sorted_lines(
            &row["acts_the_tool_can_be_held_for"],
            &format!("the acts an allowance row for `{tool}` under `{mode_name}` declares"),
        );
        assert_eq!(
            for_tool, declared_for_tool,
            "{id}: a grant for `{tool}` under `{mode_name}` can be spent on {declared_for_tool:?} \
             and the product answers {for_tool:?} — a grant SURE offers for an act this rule \
             cannot reach is a promise it cannot keep"
        );
    }
}

#[test]
fn every_dangerous_action_fixture_these_assertions_name_is_a_fixture_this_repository_ships() {
    // The guard every list in this file has, for the same reason: a renamed
    // directory would make every assertion below about a request nobody ships.
    for id in DANGEROUS_ACTION_FIXTURES {
        let dir = fixture(id);
        assert!(dir.is_dir(), "{} is not a directory", dir.display());
        let scenario = dir.join("scenario.json");
        assert!(
            scenario.is_file(),
            "{id} has no scenario.json, so there is no declaration to read"
        );
        assert!(
            dir.join("README.md").is_file(),
            "{id} has no README.md, so nothing says in words what it traps"
        );

        let block = dangerous_action_block(id);
        assert!(
            block.get("read_by").is_some(),
            "{id}/scenario.json declares no read_by, so nothing says which route answers"
        );
        let runs = declared_action_runs(id, &block);
        assert!(
            runs.len() >= 2,
            "{id}/scenario.json declares {} runs, and a fixture is worth nothing without a control",
            runs.len()
        );
        let control = block["control"]["of"]
            .as_str()
            .unwrap_or_else(|| panic!("{id}/scenario.json declares a control for no run"));
        assert!(
            runs.contains_key(control),
            "{id}/scenario.json's control names `{control}`, which is no run this fixture declares"
        );

        // Exactly one run may declare itself the control, and it has to be the
        // one the fixture points at. This is the acceptance stated as a property
        // of the document rather than of the product: a directory whose control
        // stopped reaching `Allowed` — or whose control run was replaced by the
        // held run beside it — has stopped measuring the claim it is named after.
        let allows: Vec<&str> = runs
            .iter()
            .filter(|(_, run)| run["expect"]["decision"] == "allow")
            .map(|(kind, _)| kind.as_str())
            .collect();
        assert!(
            allows.contains(&"control"),
            "{id}/scenario.json declares no `control` run that reaches `allow`, and a fixture for a \
             held request whose control does not reach `Allowed` measures nothing: {allows:?}"
        );

        // The tripwire, asserted here rather than left to the other file: this
        // case is `release_blocking` and it is a request rather than a project,
        // so the key that decides `fixture_has_an_app` in
        // `finding_severity_rule.rs` must not be anywhere in the document.
        let text = std::fs::read_to_string(&scenario)
            .unwrap_or_else(|error| panic!("cannot read {}: {error}", scenario.display()));
        assert!(
            !text.contains("\"entry_points\""),
            "{id}/scenario.json declares entry points, and the case is a request rather than a \
             project with runnable code: adding them would pull a release-blocking case into a list \
             in finding_severity_rule.rs that it does not belong on"
        );
    }
}

#[test]
fn a_dangerous_action_that_is_held_names_its_danger_before_its_decision_and_the_control_reaches_allowed()
 {
    let mut graded = 0usize;
    for id in DANGEROUS_ACTION_FIXTURES {
        let block = dangerous_action_block(id);
        assert_the_dangerous_action_outcomes_account_for_the_declared_runs(id, &block);
        assert_the_pointer_names_the_route(
            id,
            "the `dangerous_action` block's read_by",
            &block["read_by"],
        );
        let runs = declared_action_runs(id, &block);

        let mut answers: BTreeMap<String, Value> = BTreeMap::new();
        for (kind, run) in &runs {
            let assessment = assess_declared_run(id, &block, kind, run);
            let expected = &run["expect"];

            // 1. The danger, by wire name, **first**. This is the assertion the
            //    fixture exists for. A build with the danger vocabulary deleted
            //    still answers `block` to every one of these runs — the engine
            //    holds every arbitrary command and `base_decision` holds a
            //    request that needs consent with a sentence naming no danger —
            //    so a test that asserted the decision first would pass it, and a
            //    test that asserted only the decision would pass it silently.
            let declared_danger: Option<Danger> =
                from_wire(id, "the danger a run declares", &expected["danger"]);
            let declared_phrase = declared_danger.map_or_else(
                || "no danger".to_owned(),
                |danger| format!("`{}`", danger.wire_name()),
            );
            let reported_phrase = assessment.danger.map_or_else(
                || "no danger".to_owned(),
                |danger| format!("`{}`", danger.wire_name()),
            );
            assert_eq!(
                assessment.danger.map(Danger::wire_name),
                declared_danger.map(Danger::wire_name),
                "{id}: the `{kind}` run is declared as naming {declared_phrase}, and the product \
                 answered {reported_phrase}. The danger is asserted before the decision because the \
                 decision is not the measurement: a build that named no danger at all still blocks \
                 every request here.",
            );

            // 2. The sentence, held against the product's own answer for it.
            assert_the_reason_is_the_one_the_fixture_names(id, kind, run, &assessment);

            // 3. Only now the decision kind: `block` is what this build answers
            //    to a great deal, and it is the last of the three because it is
            //    the only one that is satisfiable with no detector at all.
            let declared_decision = expected["decision"]
                .as_str()
                .unwrap_or_else(|| panic!("{id}: the `{kind}` run declares no decision"));
            assert_eq!(
                assessment.decision.decision.as_str(),
                declared_decision,
                "{id}: the `{kind}` run is declared as `{declared_decision}` and the product \
                 answered `{}`",
                assessment.decision.decision.as_str()
            );

            answers.insert(kind.clone(), action_answers(&assessment));
        }

        // What the fixture has to say about itself before the product's answers
        // mean anything, in the three shapes every one of these directories is
        // built from: a run that names a danger, a run that is held and names
        // none, and the sentence a build with no detector answers all of them
        // with. A directory that lost any of the three would still pass every
        // assertion above while grading less than it says it grades.
        let named: Vec<&str> = runs
            .iter()
            .filter(|(_, run)| run["expect"]["danger"].is_string())
            .map(|(kind, _)| kind.as_str())
            .collect();
        assert!(
            !named.is_empty(),
            "{id}/scenario.json declares no run that names a danger, so nothing here is a \
             measurement of the detector this case is about"
        );
        let unnamed: Vec<&str> = runs
            .iter()
            .filter(|(_, run)| {
                run["expect"]["danger"].is_null() && run["expect"]["decision"] == "block"
            })
            .map(|(kind, _)| kind.as_str())
            .collect();
        assert!(
            !unnamed.is_empty(),
            "{id}/scenario.json declares no run that is held and names nothing, so the near-miss \
             this case needs is missing and a product that named every request dangerous would \
             satisfy every run here"
        );
        let consent: Vec<&str> = runs
            .iter()
            .filter(|(_, run)| run["reason_named_by"].as_str() == Some("the_consent_sentence"))
            .map(|(kind, _)| kind.as_str())
            .collect();
        assert!(
            !consent.is_empty(),
            "{id}/scenario.json declares no run held for the consent sentence, which is the answer \
             a build with no detector produces for every request here — leaving it out is what \
             would let this fixture stop telling the two builds apart"
        );
        for (kind, run) in &runs {
            if run["expect"]["decision"] == "allow" {
                assert_eq!(
                    run["reason_named_by"].as_str(),
                    Some("the_allow_sentence"),
                    "{id}: the `{kind}` run reaches `allow` and does not carry the mode's own \
                     sentence for one, so an allow is declared here with a sentence this file \
                     cannot check"
                );
            }
        }

        // The control: the same run under the settings beside it, one thing
        // moved, and it must reach `Allowed`. `!blocked` would be satisfied by a
        // warning and by a run that was never assessed, so the decision kind is
        // asserted exactly.
        let of = assert_the_control_is_the_one_thing_the_fixture_names(id, &block, &runs);
        let control = answers
            .get("control")
            .unwrap_or_else(|| panic!("{id}: the control run produced no answer"));
        assert_eq!(
            control["decision"].as_str(),
            Some("allow"),
            "{id}: the control does not reach `Allowed`, and a fixture for a held request whose \
             control cannot reach `Allowed` has measured nothing: a product that blocked every \
             request would satisfy every other run in this directory"
        );
        assert_eq!(
            control["danger"],
            Value::Null,
            "{id}: the control is allowed and a danger is recorded for it, and a danger is only \
             ever attached to a request that was held"
        );
        assert_ne!(
            control["decision"], answers[&of]["decision"],
            "{id}: the control and the run it is a control for reach the same decision, so the \
             pair is the same measurement written twice"
        );

        assert_the_allowance_is_the_rule_the_fixture_names(id, &block);

        // The net, and it is last on purpose. Every claim above is named and says
        // what it is about; this is the exhaustive one, holding **every** key of
        // every run's answer against the fixture's declaration in both
        // directions, so that a key nobody thought to name is still graded rather
        // than ignored. The reverse direction is `answer_keys` /
        // `assert_answers_account_for` at the top of this test; this is the
        // forward one, and it is the reason a new key in the fixture is a red
        // test rather than a line nothing reads.
        for (kind, run) in &runs {
            let declared = run["expect"]
                .as_object()
                .unwrap_or_else(|| panic!("{id}: the `{kind}` run declares no expected answers"));
            let reported = answers[kind]
                .as_object()
                .unwrap_or_else(|| panic!("{id}: the `{kind}` run produced no answers"));
            let declared_keys: BTreeSet<&str> = declared.keys().map(String::as_str).collect();
            let reported_keys: BTreeSet<&str> = reported.keys().map(String::as_str).collect();
            assert_eq!(
                reported_keys, declared_keys,
                "{id}: the `{kind}` run's answers and the fixture's declaration are about different \
                 things, so one of them has stopped being graded"
            );
            for (key, expected) in declared {
                assert_eq!(
                    reported[key], *expected,
                    "{id}: the `{kind}` run's `{key}` is not the one the fixture declares, so the \
                     case is not being graded as written"
                );
            }
        }

        graded += 1;
    }
    assert_eq!(
        graded,
        DANGEROUS_ACTION_FIXTURES.len(),
        "every fixture named in DANGEROUS_ACTION_FIXTURES must be graded by this test"
    );
}

// --- P14-T013: the corpus's record of what the detectors produce -------------
//
// Two fields in a `scenario.json` look alike and are not. `required_severity` is
// **the requirement**, it belongs to `evaluation/acceptance-manifest.json`, and
// no task that measures the product may move it — a corpus edited to agree with
// the code is the false green this repository exists to catch, one level up.
// `detector_severity_today` is **the corpus's record of the detectors**, and
// `P7-T011` moved the detectors out from under it: every false-completion
// scanner in this file used to write `Severity::Note` into its own category
// table and now asks [`sure_core::finding_gravity`], so twenty-five of the
// thirty-seven rows that carry the field recorded a severity no detector
// produces any more.
//
// Nothing noticed for two days, and the reason is the one worth keeping in
// mind: `grep -rn detector_severity_today crates/` returned one prose line in
// `sure-core/src/acceptance_report.rs` and nothing else. A field no `.rs` file
// reads cannot be contradicted by one, which is exactly why it could go stale.
// After `P14-T013` it is read by the test below, and the two lists this header
// used to imply — what the corpus says the detectors do, and what they do — are
// compared rather than assumed equal.
//
// # What the test below does, and the two arms it has
//
// It walks `fixtures/adversarial/*/scenario.json` — discovered, not named, so a
// fixture that grows a `detector_severity_today` is checked without this file
// being edited — reads each document's own text, runs the detector that
// document's `surface` and `detector` name over the fixture the document lives
// in, and compares. There is no list of expected severities here: such a list
// would be a *second* place to keep the same fact, and this file is the first
// place that would then have to be kept in step with two others.
//
// A row either carries `detector_severity_today`, which the test checks, or
// `detector_severity_measured_by`, which names the test that measures the value
// instead — the acceptance's own alternative wording, for a value no in-process
// detector call can reach. Exactly one row uses the second arm, and the test
// asserts that it is exactly one, so the weaker arm cannot quietly spread:
// `rust-tests-fail`'s `project_verdict` outcome is about what a *run* of that
// fixture aggregates to, and running it means the four `cargo` invocations
// `crates/sure-core/tests/rust_fixture_apps.rs` already pays for in its own
// test. The second arm is checked rather than trusted: the file the statement
// names must be there and must contain the test it names, so renaming or
// deleting the test that owns the measurement reddens this one.
//
// # The mutation this test is built to catch
//
// The way this test could pass while measuring nothing is not a missing
// assertion but a comparison that agrees by construction. So the mutation is
// written down to be run, in the pattern
// `crates/sure-core/tests/acceptance_report_runner.rs` uses for its own
// anti-vacuity halves. **Reproducible mutation, and the one this test is for:**
// in `fixtures/adversarial/dead-button/scenario.json`, put
//
//     "detector_severity_today": "note",
//
// back on the first `required_outcomes` entry — the `ui_action_bridge` one,
// whose detector reaches `must_fix` — and then run
//
//     cargo test -p sure-core --test adversarial_fixture_detection
//
// This test goes red and its failure message names the fixture, the surface and
// both severities. It was run, not predicted, and run again over the whole
// workspace: `cargo test --workspace --all-features --no-fail-fast` reported 78
// passing targets and this one, so no other test in the tree reads the field —
// which is the same silence that let it go stale, measured rather than assumed.
// The run's own output is at `target/tmp/p14t013-mutation.txt`. The second
// mutation, which measures the comparison rather than the corpus, is to replace
//
//     produced.iter().all(|severity| *severity == recorded)
//
// with `!produced.is_empty()` below; the whole point of the equality is that a
// detector that produced *something* would satisfy the weaker form.

/// The severity every detector call for one fixture is measured through.
///
/// `P14-T013`'s `detector_severity_measured_by` statement names a test that owns
/// a measurement this file cannot make. The statement is `path::test_name` and
/// both halves are checked against the tree, because a statement naming a test
/// nobody ships is a claim about where a value is measured with nothing behind
/// it — the same defect as a stale severity, one level down.
fn assert_the_named_test_exists(id: &str, statement: &str) {
    let (path, test) = statement.split_once("::").unwrap_or_else(|| {
        panic!(
            "{id}: `detector_severity_measured_by` is `{statement}`, which does not name a \
             `path::test` pair"
        )
    });
    let full = sure_testkit::repository_root().join(path);
    let text = std::fs::read_to_string(&full).unwrap_or_else(|error| {
        panic!(
            "{id}: `detector_severity_measured_by` names `{path}`, which cannot be read: {error}"
        )
    });
    assert!(
        text.contains(&format!("fn {test}(")),
        "{id}: `detector_severity_measured_by` names `{test}` in `{path}`, and no such test is \
         there. The value this row records is measured by that test and by nothing this file can \
         call, so a statement pointing at a test that does not exist is a value nobody measures."
    );
}

/// Every fixture whose `scenario.json` records a detector severity, discovered.
///
/// Read out of the directory rather than listed here. A list would be a second
/// place to keep the same fact, and the fixture that grows a
/// `detector_severity_today` tomorrow is the one this test has to reach without
/// being edited.
fn every_fixture_that_records_a_detector_severity() -> Vec<(String, Value)> {
    let root = sure_testkit::repository_root()
        .join("fixtures")
        .join("adversarial");
    let entries = std::fs::read_dir(&root)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", root.display()));

    let mut found: Vec<(String, Value)> = Vec::new();
    for entry in entries {
        let path = entry
            .unwrap_or_else(|error| panic!("cannot read an entry of {}: {error}", root.display()))
            .path();
        let scenario = path.join("scenario.json");
        if !scenario.is_file() {
            continue;
        }
        let text = std::fs::read_to_string(&scenario)
            .unwrap_or_else(|error| panic!("cannot read {}: {error}", scenario.display()));
        let document: Value = serde_json::from_str(&text)
            .unwrap_or_else(|error| panic!("{} is not valid JSON: {error}", scenario.display()));
        let records_one = document["required_outcomes"]
            .as_array()
            .is_some_and(|rows| {
                rows.iter().any(|row| {
                    row.get("detector_severity_today").is_some()
                        || row.get("detector_severity_measured_by").is_some()
                })
            });
        if !records_one {
            continue;
        }
        let id = path
            .file_name()
            .and_then(OsStr::to_str)
            .unwrap_or_else(|| panic!("{} is not a fixture name", path.display()))
            .to_owned();
        found.push((id, document));
    }
    found.sort_by(|left, right| left.0.cmp(&right.0));
    assert!(
        !found.is_empty(),
        "no fixture under {} records a detector severity, so this test measures nothing",
        root.display()
    );
    found
}

/// The severity of the one proposal a row names, found by the fixture's own title.
///
/// **The title is the fixture's, not this file's.** A row says which outcome it
/// is about and the detector says what it produced for it; the two are matched
/// on the only name they share. Zero matches is a red test and so is more than
/// one, because a row that names an outcome the detector no longer produces has
/// stopped being a record of anything.
fn the_one_proposal_the_fixture_names(
    id: &str,
    surface: &str,
    row: &Value,
    proposals: &[CheckProposal],
) -> Vec<Severity> {
    let title = row["title"].as_str().unwrap_or_else(|| {
        panic!(
            "{id}: a `{surface}` outcome records a detector severity and declares no `title`, so \
             the detector's answer cannot be found by the name the fixture gave it"
        )
    });
    let found: Vec<Severity> = proposals
        .iter()
        .filter(|proposal| proposal.title() == title)
        .map(CheckProposal::severity)
        .collect();
    assert_eq!(
        found.len(),
        1,
        "{id}: the fixture records a severity for the `{surface}` outcome `{title}` and the \
         detector produced {} finding(s) under that title. It said: {:?}",
        found.len(),
        proposals
            .iter()
            .map(CheckProposal::title)
            .collect::<Vec<_>>()
    );
    found
}

/// Every severity the detector produced, for a row about the fixture as a whole.
///
/// Some rows name a detector rather than one finding — `ExternalServiceChecks::not_checked`,
/// `AssessedGap::severity`, the weight a claim check attaches — and what they
/// record is what that call answers. Empty is refused here rather than below:
/// a detector that produced nothing has not agreed with the corpus, it has
/// stopped being a detector this row is about.
fn every_severity_the_detector_produced(
    id: &str,
    surface: &str,
    produced: Vec<Severity>,
) -> Vec<Severity> {
    assert!(
        !produced.is_empty(),
        "{id}: `{surface}` produced nothing for this fixture, and the severity the corpus records \
         for it is a record of something. Either the detector stopped firing or this row names a \
         call that is no longer made."
    );
    produced
}

/// The Rust project SURE read, for the one fixture whose detector is a `CHECKS` row.
fn rust_project_of(id: &str) -> RustProject {
    let found = discovery(id);
    let report = found.report(Ecosystem::Rust).unwrap_or_else(|| {
        panic!("{id} is a Rust project and SURE reported no Rust ecosystem for it")
    });
    match &report.findings {
        Findings::Rust(project) => (**project).clone(),
        other => panic!("{id} records a `rust_checks` severity and SURE read it as {other:?}"),
    }
}

/// Every severity the claim checker attached to one fixture's recordings.
///
/// The recording and its control are both read, because the row this answers is
/// about the weight `check_claim` puts on the evidence it attaches and one of
/// the three fixtures — `tests-not-run` — attaches none in the declared
/// recording: the weight is only visible in a state where something was
/// attached, and the control is that state. Both readings go through
/// [`read_recording`], which is where the store path and the direct path are
/// held equal.
fn severities_the_claim_checker_attached(id: &str) -> Vec<Severity> {
    let block = claim_block(id);
    let claim = &block["claim"];
    let mut attached: Vec<Severity> = Vec::new();
    for (what, source) in [
        ("the declared recording", &block),
        ("the control", &block["control"]),
    ] {
        let events = declared_events(id, source, "events");
        let recorded = read_recording(
            &format!("{id}: {what}"),
            &format!("P14-T013 {id} {what}"),
            claim,
            &events,
        );
        attached.extend(
            recorded
                .checked
                .evidence
                .iter()
                .map(|evidence| evidence.severity),
        );
    }
    attached
}

/// What the detector one `required_outcome` names produced for its own fixture.
///
/// The dispatch is on the fixture's own `surface`, and where a surface holds two
/// calls the fixture's own `detector` string picks between them. A surface this
/// table does not know is a red test rather than a skipped row: the alternative
/// is a fixture that records a detector severity and is quietly never asked
/// about it, which is the shape the whole task is about.
fn severities_the_detector_produced(id: &str, row: &Value) -> Vec<Severity> {
    let surface = row["surface"].as_str().unwrap_or_else(|| {
        panic!("{id}: an outcome records a detector severity and names no `surface`: {row}")
    });
    let detector = row["detector"].as_str().unwrap_or_default();
    match surface {
        "candidate_scanner" => the_one_proposal_the_fixture_names(
            id,
            surface,
            row,
            CandidateScanner::of(&discovery(id)).proposed(),
        ),
        "noop_heuristics" => the_one_proposal_the_fixture_names(
            id,
            surface,
            row,
            NoOpHeuristics::of(&discovery(id)).proposed(),
        ),
        "demo_data_heuristics" => the_one_proposal_the_fixture_names(
            id,
            surface,
            row,
            DemoDataHeuristics::of(&discovery(id)).proposed(),
        ),
        "route_consistency" => the_one_proposal_the_fixture_names(
            id,
            surface,
            row,
            RouteConsistency::of(&discovery(id)).proposed(),
        ),
        "ui_action_bridge" => the_one_proposal_the_fixture_names(
            id,
            surface,
            row,
            UiActionBridge::of(&discovery(id)).proposals().as_slice(),
        ),
        "rust_checks" => the_one_proposal_the_fixture_names(
            id,
            surface,
            row,
            &RustChecks::of(&rust_project_of(id), &fixture(id))
                .planned()
                .iter()
                .map(|work| work.proposal().clone())
                .collect::<Vec<_>>(),
        ),
        "external_service" => {
            let checks = ExternalServiceChecks::of(&discovery(id));
            if detector.starts_with("ExternalServiceChecks::not_checked") {
                every_severity_the_detector_produced(
                    id,
                    surface,
                    checks
                        .not_checked(&FingerprintId::generate())
                        .iter()
                        .map(|result| result.severity)
                        .collect(),
                )
            } else {
                the_one_proposal_the_fixture_names(id, surface, row, checks.proposed())
            }
        }
        "env_completeness" => every_severity_the_detector_produced(
            id,
            surface,
            CompletenessReport::of(&discovery(id), &FingerprintId::generate())
                .claims()
                .iter()
                .map(|claim| claim.severity())
                .collect(),
        ),
        "db_migrations" => every_severity_the_detector_produced(
            id,
            surface,
            MigrationsReport::of(&discovery(id), &FingerprintId::generate())
                .claims()
                .iter()
                .map(|gap| gap.severity())
                .collect(),
        ),
        "claim_checker" => every_severity_the_detector_produced(
            id,
            surface,
            severities_the_claim_checker_attached(id),
        ),
        _ => panic!(
            "{id}: an outcome records a detector severity on the surface `{surface}`, which this \
             test cannot run. Either wire the detector into the table above, or replace the field \
             with `detector_severity_measured_by` naming the test that measures it — a row this \
             test cannot check must say so rather than look checked."
        ),
    }
}

#[test]
fn every_recorded_detector_severity_is_what_the_detector_produces_today() {
    let mut checked = 0usize;
    let mut measured_elsewhere: Vec<String> = Vec::new();
    let mut unmet: Vec<String> = Vec::new();

    for (id, document) in every_fixture_that_records_a_detector_severity() {
        let rows = document["required_outcomes"].as_array().unwrap_or_else(|| {
            panic!("fixtures/adversarial/{id}/scenario.json has no `required_outcomes` array")
        });
        for (index, row) in rows.iter().enumerate() {
            let recorded = row.get("detector_severity_today");
            let elsewhere = row.get("detector_severity_measured_by");
            assert!(
                !(recorded.is_some() && elsewhere.is_some()),
                "{id}: required_outcomes[{index}] carries both `detector_severity_today` and \
                 `detector_severity_measured_by`, so a reader cannot tell which one is the record"
            );
            if let Some(statement) = elsewhere {
                let statement = statement.as_str().unwrap_or_else(|| {
                    panic!("{id}: required_outcomes[{index}] has a `detector_severity_measured_by` that is not a string")
                });
                assert_the_named_test_exists(&id, statement);
                measured_elsewhere.push(id.clone());
                continue;
            }
            let Some(recorded) = recorded else {
                continue;
            };
            let recorded: Severity = serde_json::from_value(recorded.clone()).unwrap_or_else(|error| {
                panic!("{id}: required_outcomes[{index}] records a severity SURE has no level for: {error}")
            });

            let produced = severities_the_detector_produced(&id, row);
            assert!(
                produced.iter().all(|severity| *severity == recorded),
                "{id}: the corpus records `{}` for this outcome and the detector produces `{}`.\n  \
                 fixture:   fixtures/adversarial/{id}/scenario.json (required_outcomes[{index}])\n  \
                 surface:   {}\n  detector:  {}\n  \
                 the detector's own answers: {produced:?}\n  \
                 `required_severity` is the requirement and this test does not touch it; \
                 `detector_severity_today` is the corpus's record of what the detector does, and \
                 this is where the two are compared.",
                recorded.as_str(),
                produced
                    .iter()
                    .map(|severity| severity.as_str())
                    .collect::<Vec<_>>()
                    .join("`, `"),
                row["surface"].as_str().unwrap_or("(none)"),
                row["detector"].as_str().unwrap_or("(none)"),
            );

            // Criterion 4's second half, and the half that cannot be left to a
            // reader: where the detector that owns an outcome cannot reach the
            // `required_severity` beside it, the corpus has to say so — the
            // reason the requirement stands unmet and what would have to change
            // for it to be met — rather than leaving a requirement that reads as
            // agreed. `Severity::rank` puts the more serious level higher, so
            // "met" is the weakest severity the detector produced being at or
            // above the requirement.
            let requirement: Severity = serde_json::from_value(row["required_severity"].clone())
                .unwrap_or_else(|error| {
                    panic!(
                        "{id}: required_outcomes[{index}] records a detector severity and its \
                         `required_severity` is missing or is not a level SURE has: {error}"
                    )
                });
            let meets_the_requirement = produced
                .iter()
                .all(|severity| severity.rank() >= requirement.rank());
            match (meets_the_requirement, row.get("required_severity_unmet")) {
                (true, None) => {}
                (true, Some(block)) => panic!(
                    "{id}: required_outcomes[{index}] carries a `required_severity_unmet` block \
                     and the detector meets the requirement it records — it produces {produced:?} \
                     against `required_severity` `{}`. An unmet requirement that has been met is \
                     the same stale claim as a stale severity, one level up.\n  the block: {block}",
                    requirement.as_str()
                ),
                (false, None) => panic!(
                    "{id}: the detector produces {produced:?} for this outcome, which is below the \
                     `{}` its `required_severity` asks for, and required_outcomes[{index}] carries \
                     no `required_severity_unmet` block. P14-T013 requires each such outcome either \
                     to restate its requirement in terms its detector can meet, or to carry the \
                     reason it stands unmet and what would have to change for it to be met; a \
                     silent row here reads as an agreement no detector makes.\n  surface:  {}\n  \
                     detector: {}",
                    requirement.as_str(),
                    row["surface"].as_str().unwrap_or("(none)"),
                    row["detector"].as_str().unwrap_or("(none)"),
                ),
                (false, Some(block)) => {
                    for (field, what) in [
                        ("why", "why the requirement stands unmet"),
                        (
                            "would_require",
                            "what would have to change for it to be met",
                        ),
                    ] {
                        let sentence = block[field].as_str().unwrap_or_else(|| {
                            panic!(
                                "{id}: required_outcomes[{index}].required_severity_unmet has no \
                                 `{field}` string, so it does not say {what}. The block is there \
                                 because the requirement stands unmet, and a block that does not \
                                 say why, or does not say what would have to change, is a \
                                 placeholder.\n  the block: {block}"
                            )
                        });
                        assert!(
                            sentence.trim().len() >= 40,
                            "{id}: required_outcomes[{index}].required_severity_unmet.{field} is \
                             `{sentence}`, too short to be the sentence it claims to be. It is read \
                             as {what}, and the field exists so that a reader is told rather than \
                             left to guess."
                        );
                    }
                    unmet.push(format!("{id}:required_outcomes[{index}]"));
                }
            }
            checked += 1;
        }
    }

    assert_eq!(
        checked, 36,
        "the number of rows this test checked changed. Every row in \
         `fixtures/adversarial/*/scenario.json` that carries a `detector_severity_today` is one of \
         them, so a row that lost the field, or a fixture that left the corpus, moves this number \
         and has to be a decision rather than a detail. An empty corpus proves nothing, which is \
         what this replaced."
    );
    // The weaker arm is checked rather than trusted, and it is pinned here so it
    // cannot spread: a row moved onto it stops being measured by anything in
    // this file, and that has to be a decision rather than a convenience. See
    // the section header for why this one row is the exception.
    assert_eq!(
        measured_elsewhere,
        vec![String::from("rust-tests-fail")],
        "the rows whose detector severity is measured by another test changed. Each of these is a \
         row this test does not check, so the list is asserted rather than summed."
    );
    // The requirements that stand unmet are counted rather than estimated, and
    // the count is asserted rather than left to be re-derived. Eleven of them are
    // the `candidate_scanner` rows the task's own criterion 4 names — one category
    // required at two different weights across the corpus, reachable from neither
    // of the detectors that saw it — and two are the weight a claim check
    // attaches, which no rule in the verdict layer reads. A detector that moved
    // one of these rows changes this number, and a change to this number is a
    // decision about the corpus rather than a detail to be absorbed.
    assert_eq!(
        unmet.len(),
        13,
        "the number of rows whose requirement their detector does not meet changed. Rows: {unmet:?}"
    );
}

// --- P15-T028: what a report run leaves in the tree it drives -----------------
//
// `sure_core::acceptance_report` drives machinery over the shipped fixtures, and
// one of its recipes — `execution_refusal`, the case `dynamic-not-authorized` —
// needs a configuration root, because the file that asks for execution and
// cannot grant it is the fixture's own `sure.yaml`. That root used to be made
// inside the fixture being measured:
//
//   fixtures/adversarial/dynamic-not-authorized/target/tmp/
//     acceptance report configuration/{config,data}
//
// Five directories, every one of them empty, and invisible: git describes a
// directory only through the files inside it, and a directory holding no file
// has none, so `git status --untracked-files=all` reports a tree holding them as
// clean — as does every other setting. They were on disk on every machine that
// had run this report, and the next run over that fixture measured a project the
// previous one had put them in.
//
// This is the check that a run adds nothing to that tree. It has two
// instruments, and they watch for different shapes:
//
// - [`tree_paths`] walks the fixture and reads back EVERY directory and file
//   under it. It is the only instrument here that can see a directory at all,
//   and an empty directory is precisely the shape this case's residue had.
// - `git status --untracked-files=all` is run over the same path. It is the
//   instrument that watches for a FILE, which is the shape git can describe and
//   the shape the residue becomes the moment anything writes into the
//   configuration root this recipe hands to `Paths::from_roots` — the one event
//   that would turn an invisible directory into a change to a tracked tree.
//
// It watches two trees, because on this machine one of them is blind and the
// reason is worth stating rather than leaving a reader to find:
//
// - **The shipped fixture**, with a report run over the real corpus. This is the
//   tree the case is about. It already holds the five directories described
//   above, left there by builds before this change, so a run that re-created
//   them would add nothing to this walk and the walk could not tell such a run
//   from one that leaves nothing. What the shipped tree holds beyond a checkout
//   of it is printed below as a READING and not asserted, because removing it is
//   not this check's to do: a check that deleted inside a shipped fixture tree
//   would be doing to that tree exactly what this change stops the module doing,
//   and nothing in this repository writes there.
// - **A fresh checkout of the corpus** under `target/tmp`, built from the files
//   git tracks — which is every file a checkout of this repository has, and none
//   of the directories the residue is made of, because git tracks neither. A
//   report is run over that tree as well, and this is the instrument that
//   reddens when the scratch moves back under `fixtures_root`: nothing has ever
//   been run over it, so anything a run leaves there is new to it.
//
// The two runs' rows for the case are compared as well. The case has to measure
// the same thing in a tree a report has been run over and in one it has not,
// which is the other half of what the residue would have cost.
//
// Both readings are printed, so `cargo test -- --nocapture` shows what each
// instrument saw on a green run as well as on a red one.

/// Every directory and every file under `root`, as paths relative to it, sorted.
///
/// A directory carries a trailing `/`. That is not decoration: it is what keeps
/// the reading of a directory apart from the reading of a file of the same name,
/// and a directory is the one shape this walk sees that `git status` can see only
/// by accident — as the files inside it, or not at all when it holds none.
fn tree_paths(root: &Path) -> Vec<String> {
    let mut found = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(directory) = stack.pop() {
        for entry in std::fs::read_dir(&directory)
            .unwrap_or_else(|error| panic!("cannot read {}: {error}", directory.display()))
        {
            let path = entry.expect("a directory entry").path();
            let relative = path
                .strip_prefix(root)
                .expect("an entry under the directory being walked")
                .to_string_lossy()
                .replace('\\', "/");
            if path.is_dir() {
                found.push(format!("{relative}/"));
                stack.push(path);
            } else {
                found.push(relative);
            }
        }
    }
    found.sort();
    found
}

/// `git status --untracked-files=all` over one path inside the checkout.
///
/// The machine's own Git, run in the repository, with the path as a pathspec so
/// that what it describes is that path and nothing else in the working tree —
/// which is also why this is read in its `--porcelain` form. The long form
/// prints the branch and how far ahead of its upstream it is, and that is a fact
/// about the repository rather than about the path: another commit landing
/// between the two readings would move it, and this check would report a run
/// that wrote a file when what happened is that somebody else committed. In the
/// porcelain form a path with nothing to report reads as empty, and a file that
/// appeared under it reads as one `??` line naming it.
///
/// A file is the one shape this instrument watches for, and it is paired with
/// [`tree_paths`] for the reason `--untracked-files=all` is on the command line.
/// Git tracks files. A directory it describes only as the file it could not
/// descend into: at the default verbosity a wholly untracked directory reads as
/// `?? full-dir/`, and `--untracked-files=all` replaces that with the files
/// inside it (`?? full-dir/a.txt`). A directory holding no file therefore reads
/// as nothing at either setting — which is precisely the residue this task is
/// about, since the old location was reached by `create_dir_all` and never
/// written to. No invocation of `git status` at any verbosity would have shown
/// it, and that is why the walk, not this, is the instrument the red proof
/// turns on.
fn untracked_text(relative: &str) -> String {
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(sure_testkit::repository_root())
        .args(["status", "--untracked-files=all", "--porcelain", "--"])
        .arg(relative)
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()
        .unwrap_or_else(|error| {
            panic!(
                "this check needs Git on the path (trying to run `git status --untracked-files=all \
                 --porcelain -- {relative}`): {error}"
            )
        });
    assert!(
        output.status.success(),
        "`git status --untracked-files=all --porcelain -- {relative}` failed with {:?}\nstdout: \
         {}\nstderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// The lines `after` has that `before` did not, in the order they appear.
fn appeared(before: &[String], after: &[String]) -> Vec<String> {
    after
        .iter()
        .filter(|line| !before.contains(line))
        .cloned()
        .collect()
}

/// One instrument's reading, before and after, asserted equal.
///
/// `what` names the instrument and the tree, so a failure says which of the two
/// instruments saw something and where — and not merely that two lists differ.
fn assert_nothing_appeared(what: &str, before: &[String], after: &[String]) {
    if before == after {
        return;
    }
    panic!(
        "{what}: the reading changed, so a run left something in a tree it was only supposed to \
         read. It gained {:?} and lost {:?}.\n  before: {before:?}\n  after:  {after:?}",
        appeared(before, after),
        appeared(after, before),
    );
}

/// Every file git tracks under one of `paths`, as repository-relative paths.
///
/// The definition of a checkout used by [`fresh_corpus`], and taken from git
/// rather than by excluding names from a copy: git tracks no directory, so this
/// is exactly the file set a fresh checkout has and exactly nothing of the
/// untracked residue a previous run can leave beside them.
fn tracked_files(repository: &Path, paths: &[&str]) -> Vec<String> {
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(repository)
        .args(["ls-files", "-z", "--"])
        .args(paths)
        .output()
        .unwrap_or_else(|error| panic!("this check needs Git on the path: {error}"));
    assert!(
        output.status.success(),
        "`git ls-files -- {paths:?}` failed with {:?}\nstderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    let mut found: Vec<String> = String::from_utf8_lossy(&output.stdout)
        .split('\0')
        .filter(|path| !path.is_empty())
        .map(str::to_owned)
        .collect();
    found.sort();
    found
}

/// A fresh checkout of the corpus, under `target/tmp`.
///
/// `evaluation/` and `fixtures/adversarial/` are what a report reads, and the
/// tracked files under them are what a checkout of this repository has. The
/// directory is left in place for a reader, as `release_gate_runner.rs`'s
/// control corpora are: it is a build artefact under the repository's ignored
/// `target/tmp`, and `cargo clean` removes it. Nothing here is asserted about
/// the copy after the run except through the fixture the case is about.
///
/// The pool's name carries a space and a non-ASCII character on purpose, the way
/// `sure_testkit`'s other pools do: the report is run over this tree, so the
/// scratch directory the module derives from it is derived under a path that is
/// not plain ASCII — which is the path pressure this repository's own
/// instructions ask for, and the thing a `String` would have been unable to
/// carry.
fn fresh_corpus() -> PathBuf {
    let repository = sure_testkit::repository_root();
    let corpus = sure_testkit::scratch::directory("acceptance report fixture 指纹", "corpus");
    let tracked = tracked_files(&repository, &["evaluation", "fixtures/adversarial"]);
    assert!(
        !tracked.is_empty(),
        "git tracks no file under `evaluation/` or `fixtures/adversarial/` in {}, so the fresh \
         checkout this check builds from them would be empty and every reading below would be \
         about nothing",
        repository.display()
    );
    for relative in &tracked {
        let from = repository.join(relative);
        let to = corpus.join(relative);
        if let Some(parent) = to.parent() {
            std::fs::create_dir_all(parent)
                .unwrap_or_else(|error| panic!("cannot create {}: {error}", parent.display()));
        }
        std::fs::copy(&from, &to).unwrap_or_else(|error| {
            panic!(
                "cannot copy {} to {}: {error}",
                from.display(),
                to.display()
            )
        });
    }
    corpus
}

/// The report's own row for one case.
fn report_row<'a>(report: &'a AcceptanceReport, id: &str) -> &'a CaseRow {
    report
        .cases
        .iter()
        .find(|row| row.id == id)
        .unwrap_or_else(|| {
            panic!(
                "the report has no row for `{id}`; it has {:?}",
                report.cases.iter().map(|row| &row.id).collect::<Vec<_>>()
            )
        })
}

#[test]
fn the_report_leaves_the_fixture_it_measures_holding_nothing_new() {
    let id = "dynamic-not-authorized";
    let repository = sure_testkit::repository_root();
    let shipped = fixture(id);
    assert!(
        shipped.is_dir(),
        "the {id} fixture directory is missing: {}",
        shipped.display()
    );
    let inside = format!("fixtures/adversarial/{id}");

    // The shipped tree's two readings, taken before anything has run.
    let shipped_walk_before = tree_paths(&shipped);
    let shipped_git_before: Vec<String> =
        untracked_text(&inside).lines().map(str::to_owned).collect();

    // The fresh checkout, and its reading. Built before either run, so what the
    // copy holds is what git tracks rather than what a run has just left.
    let fresh = fresh_corpus();
    let fresh_fixture = fresh.join("fixtures").join("adversarial").join(id);
    assert!(
        fresh_fixture.is_dir(),
        "the fresh checkout has no {id} fixture, so nothing below would be a reading of the case \
         this check is about: {}",
        fresh_fixture.display()
    );
    let fresh_walk_before = tree_paths(&fresh_fixture);

    // The reading that is printed and not asserted: what the shipped tree holds
    // beyond a checkout of it. On a machine that has run the builds this task
    // changed, this is the five empty directories, and it is reported here so
    // that the difference between the two trees is a reading rather than
    // something a reader has to know to look for.
    let beyond_a_checkout = appeared(&fresh_walk_before, &shipped_walk_before);

    // The two runs. Both are the module's own entry point: the copy is what a
    // fresh checkout measures, the shipped tree is what the corpus measures.
    let over_fresh = acceptance_report(&fresh).unwrap_or_else(|error| {
        panic!(
            "the report did not run over the fresh checkout at {}: {error}",
            fresh.display()
        )
    });
    let over_shipped = acceptance_report(&repository).unwrap_or_else(|error| {
        panic!(
            "the report did not run over the repository at {}: {error}",
            repository.display()
        )
    });

    // The same two readings, taken again.
    let fresh_walk_after = tree_paths(&fresh_fixture);
    let shipped_walk_after = tree_paths(&shipped);
    let shipped_git_after: Vec<String> =
        untracked_text(&inside).lines().map(str::to_owned).collect();

    println!(
        "{id}: the report ran over a fresh checkout and over the shipped corpus. The walk of the \
         fresh checkout's fixture gained {:?}; the walk of the shipped fixture gained {:?}; `git \
         status --untracked-files=all` over the shipped fixture gained {:?}. The shipped fixture \
         holds {beyond_a_checkout:?} that a checkout of this repository does not, which is reported \
         rather than asserted: those directories were left by the builds before this change, and \
         nothing in this repository removes files from a shipped fixture.",
        appeared(&fresh_walk_before, &fresh_walk_after),
        appeared(&shipped_walk_before, &shipped_walk_after),
        appeared(&shipped_git_before, &shipped_git_after),
    );

    // The instrument that reddens when the scratch goes back under
    // `fixtures_root`, because this tree has never had a report run over it.
    assert_nothing_appeared(
        "the walk of the fixture inside a fresh checkout — the instrument that sees DIRECTORIES, \
         which `git status` sees only through the files inside them and not at all when they hold \
         none, over a tree no run has been over",
        &fresh_walk_before,
        &fresh_walk_after,
    );
    // The shipped tree, the one the case is about. Blind here to a run that
    // re-creates the directories already in it, and sharp on a checkout that
    // does not hold them yet, which is the second sentence of this task's
    // acceptance.
    assert_nothing_appeared(
        "the walk of the shipped fixture — the tree the case measures",
        &shipped_walk_before,
        &shipped_walk_after,
    );
    // The instrument that watches for a FILE, which is the shape git can
    // describe and the shape the residue would take the moment anything wrote
    // into the configuration root this recipe hands to `Paths::from_roots`.
    // It is here as the second reading a reader asked for, and it is the weaker
    // of the two over this particular residue: the directories the old location
    // made were empty, and a directory holding no file reads as nothing to git
    // at every verbosity. The walk above is what reddens.
    assert_nothing_appeared(
        "`git status --untracked-files=all` over the shipped fixture — the instrument that sees \
         FILES",
        &shipped_git_before,
        &shipped_git_after,
    );

    // The other half of what the residue would have cost: the case has to
    // measure the same thing in a tree a report has been run over and in one it
    // has not. A difference here is the fixture being read differently because
    // of what an earlier run left in it, which is the idempotence the residue
    // took away and the reason this is asserted rather than described.
    assert_eq!(
        report_row(&over_fresh, id),
        report_row(&over_shipped, id),
        "{id}: the case measures different things in a fresh checkout and in the shipped tree, so \
         what the run found is being decided by the tree rather than by the fixture"
    );
}
