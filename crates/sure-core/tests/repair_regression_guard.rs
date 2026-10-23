//! Repair-regression guard.
//!
//! A repair that fixes the original issue but breaks something else must not be
//! accepted. SURE enforces this by expanding the repair contract's re-check list
//! with affected and regression checks from the schedule, and by refusing to
//! resolve a previous finding unless every selected re-check passes.
//!
//! This file is the mandatory `repair-regression` adversarial fixture's
//! **decision rule**, read from outside the module that implements it: the
//! project can never turn green while the regression check is failing. Its
//! `CheckResult`s are typed in here, which is the right shape for a test about
//! the rule and not evidence that anything can be repaired — this file used to
//! say of itself that it *is* the fixture, which was all there was to say while
//! `fixtures/adversarial/repair-regression/` held a 186-byte descriptor and
//! nothing else. `P14-T009` gave the directory a real npm workspace to be about
//! and `crates/sure-core/tests/repair_fixture_e2e.rs` to grade it, over checks
//! that really run and a project whose bytes really change. What is left here is
//! the half a synthetic result is good for: the rule stated sharply, including
//! the case where the regression check is selected and fails while every other
//! selected check passes. `the_fixture_status_is_implemented` holds this file
//! and that directory together.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use sure_core::paths::CaseSensitivity;
use sure_core::planned_work::{CheckOperation, PlannedWork, PrecomputedEvidence};
use sure_core::recheck_lifecycle::{LifecycleInputs, reconcile};
use sure_core::repair_impact::select_impacted_checks;
use sure_core::schedule::{CheckProposal, CheckReason, CheckSchedule, PlanBuilder};
use sure_domain::evidence::{AnchorSubject, Evidence, EvidenceAnchor, EvidenceClass};
use sure_domain::execution::{ActionKind, ExecutionMode, ExecutionPermissions};
use sure_domain::finding::{AssessmentSource, FindingBuilder, FindingStatus, SeverityRationale};
use sure_domain::ids::{CheckId, FingerprintId, RepairId};
use sure_domain::severity::Severity;
use sure_domain::status::CheckResult;
use sure_domain::vocabulary::RepairContract;

fn fingerprint() -> FingerprintId {
    FingerprintId::parse("fp_01j2m8q5aaaabbbbccccddddee").unwrap()
}

fn next_fingerprint() -> FingerprintId {
    FingerprintId::parse("fp_01j2m8q5aaaabbbbccccddddef").unwrap()
}

fn email_send_evidence() -> Evidence {
    Evidence::new(
        EvidenceClass::DeterministicCheck,
        "the send path returns before the provider is called",
        EvidenceAnchor::new(AnchorSubject::File, "src/email/send.rs", "line 42"),
        Some(fingerprint()),
        Severity::MustFix,
    )
}

fn previous_email_finding() -> sure_domain::finding::Finding {
    FindingBuilder::new(
        AssessmentSource::DeterministicCheck,
        SeverityRationale::BlocksHandOff,
    )
    .id(sure_domain::ids::FindingId::generate())
    .title("Email not sent")
    .severity(Severity::MustFix)
    .status(FindingStatus::Open)
    .explanation("the send path returns before the provider is called")
    .user_impact("users believe a message was delivered")
    .next_step("call the provider")
    .fingerprint(fingerprint())
    .evidence(vec![email_send_evidence()])
    .build()
    .expect("fixture finding is valid")
}

fn repair_contract(recheck: Vec<CheckId>) -> RepairContract {
    RepairContract {
        id: RepairId::generate(),
        issue_id: sure_domain::ids::FindingId::generate(),
        problem: "Email is reported as sent but nothing is sent".to_owned(),
        why_it_matters: "Users believe a message was delivered when it was not.".to_owned(),
        required_fix: vec!["Call the configured provider on the real send path.".to_owned()],
        preserve: vec!["The current successful UI flow.".to_owned()],
        acceptance: vec!["The provider is called on a successful send.".to_owned()],
        recheck,
        forbidden_shortcuts: Vec::new(),
        evidence: vec![email_send_evidence()],
    }
}

/// The plan entry for a fixture proposal: since `P18-T003` a proposal **and** the
/// operation beside it.
///
/// **A candidate observation, because that is the whole of what this fixture
/// establishes.** Nothing here starts a process — the checks below are typed in by
/// hand so that the rule they are about can be read from outside the module that
/// implements it. The honest value is therefore *nothing has settled this check*,
/// which maps to a warning and never to a pass, and never to a green.
fn work(proposal: CheckProposal) -> PlannedWork {
    PlannedWork::new(
        proposal,
        CheckOperation::Precomputed(PrecomputedEvidence::candidate(
            "this fixture builds a plan and observes nothing",
        )),
    )
}

fn schedule_with(recheck: CheckId, regression: CheckId, affected: CheckId) -> CheckSchedule {
    let mut builder = PlanBuilder::new(
        ExecutionMode::HostConfirmed,
        ExecutionPermissions {
            run_project_code: true,
            ..ExecutionPermissions::inspect_only()
        },
    );

    // The original re-check for the finding: did the provider get called?
    builder
        .propose(work(CheckProposal::new(
            recheck,
            "provider is called on send",
            Severity::MustFix,
            true,
            EvidenceClass::DeterministicCheck,
            CheckReason::FilePresent {
                path: "src/email/send.rs".to_owned(),
            },
            &[ActionKind::RunTests],
        )))
        .unwrap();

    // A check that overlaps the repair location: the send path itself.
    builder
        .propose(work(CheckProposal::new(
            affected,
            "send path behaves correctly",
            Severity::MustFix,
            true,
            EvidenceClass::DeterministicCheck,
            CheckReason::FilePresent {
                path: "src/email/send.rs".to_owned(),
            },
            &[ActionKind::RunTests],
        )))
        .unwrap();

    // A serious regression check: it runs project code but is about a different
    // module. A repair that only fixes the email path could break payment
    // processing if the shared HTTP client is changed carelessly.
    builder
        .propose(work(CheckProposal::new(
            regression,
            "payment provider is called on charge",
            Severity::MustFix,
            true,
            EvidenceClass::DeterministicCheck,
            CheckReason::FilePresent {
                path: "src/payment/charge.rs".to_owned(),
            },
            &[ActionKind::RunTests],
        )))
        .unwrap();

    builder.build()
}

#[test]
fn a_repair_with_failing_regression_check_cannot_turn_green() {
    let previous = previous_email_finding();
    let recheck = CheckId::generate();
    let affected = CheckId::generate();
    let regression = CheckId::generate();

    let contract = repair_contract(vec![recheck.clone()]);
    let schedule = schedule_with(recheck.clone(), regression.clone(), affected.clone());

    // SURE selects the contract's recheck plus affected and regression checks.
    let selected = select_impacted_checks(&contract, &schedule);
    assert!(selected.contains(&recheck));
    assert!(selected.contains(&affected));
    assert!(selected.contains(&regression));

    // Simulate a repair where the original recheck passes, but the regression
    // check fails. This is the adversarial case: the agent "fixed" the email
    // path but broke payment processing.
    let results = vec![
        CheckResult::pass(
            recheck,
            "provider is called on send",
            Severity::MustFix,
            true,
            EvidenceClass::DeterministicCheck,
            next_fingerprint(),
        ),
        CheckResult::pass(
            affected,
            "send path behaves correctly",
            Severity::MustFix,
            true,
            EvidenceClass::DeterministicCheck,
            next_fingerprint(),
        ),
        CheckResult::fail(
            regression,
            "payment provider is called on charge",
            Severity::MustFix,
            true,
            EvidenceClass::DeterministicCheck,
            next_fingerprint(),
        ),
    ];

    // The checks this run planned, as these fixtures can state it: the ones whose
    // results they hold. None is candidate-driven — the generated ids are not
    // `chk_candidate*` — so the plan-versus-missing distinction `planned` serves
    // (`c4fd952`) is out of these cases, and the plain rule decides alone.
    let planned: Vec<CheckId> = results.iter().map(|result| result.id.clone()).collect();
    let update = reconcile(
        LifecycleInputs {
            previous_open: std::slice::from_ref(&previous),
            current_findings: &[],
            check_results: &results,
            rechecks: &[(previous.id.clone(), selected.clone())],
            planned: &planned,
            case: CaseSensitivity::Sensitive,
        },
        next_fingerprint(),
    );

    // The original finding must stay open because not every selected check
    // passed. Resolving it would be a false green.
    assert!(
        update.findings.iter().any(|f| {
            f.status == FindingStatus::Open
                && f.title == "Email not sent"
                && f.severity == Severity::MustFix
        }),
        "a repair with a failing regression check must keep the original finding open"
    );
    assert!(
        update
            .findings
            .iter()
            .all(|f| f.status != FindingStatus::Resolved),
        "the finding must not be resolved while a regression check is failing"
    );
    assert!(update.resolved.is_empty());
    assert_eq!(update.kept_open.len(), 1);
}

#[test]
fn a_repair_with_all_selected_checks_passing_can_resolve() {
    let previous = previous_email_finding();
    let recheck = CheckId::generate();
    let affected = CheckId::generate();
    let regression = CheckId::generate();

    let contract = repair_contract(vec![recheck.clone()]);
    let schedule = schedule_with(recheck.clone(), regression.clone(), affected.clone());
    let selected = select_impacted_checks(&contract, &schedule);

    // Every selected check passes.
    let results = vec![
        CheckResult::pass(
            recheck,
            "provider is called on send",
            Severity::MustFix,
            true,
            EvidenceClass::DeterministicCheck,
            next_fingerprint(),
        ),
        CheckResult::pass(
            affected,
            "send path behaves correctly",
            Severity::MustFix,
            true,
            EvidenceClass::DeterministicCheck,
            next_fingerprint(),
        ),
        CheckResult::pass(
            regression,
            "payment provider is called on charge",
            Severity::MustFix,
            true,
            EvidenceClass::DeterministicCheck,
            next_fingerprint(),
        ),
    ];

    // Same reading of `planned` as the regression case above: the fixture's own
    // results are what it can name.
    let planned: Vec<CheckId> = results.iter().map(|result| result.id.clone()).collect();
    let update = reconcile(
        LifecycleInputs {
            previous_open: std::slice::from_ref(&previous),
            current_findings: &[],
            check_results: &results,
            rechecks: &[(previous.id.clone(), selected)],
            planned: &planned,
            case: CaseSensitivity::Sensitive,
        },
        next_fingerprint(),
    );

    assert!(
        update
            .findings
            .iter()
            .any(|f| f.status == FindingStatus::Resolved),
        "when every selected check passes the finding can be resolved"
    );
    assert_eq!(update.resolved.len(), 1);
    assert!(update.kept_open.is_empty());
}

/// The `scripts.<role>` command a fixture manifest declares.
///
/// Written out rather than inferred, because the point of the test below is that
/// the marker and the directory agree: a script that names a file which is not
/// there is the shape a stub would keep.
fn declared_script(fixture: &std::path::Path, manifest: &str, role: &str) -> String {
    let path = fixture.join(manifest);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
    let document: serde_json::Value = serde_json::from_str(&text)
        .unwrap_or_else(|error| panic!("{} is not valid JSON: {error}", path.display()));
    document["scripts"][role]
        .as_str()
        .unwrap_or_else(|| panic!("{manifest} declares no {role} script"))
        .to_owned()
}

#[test]
fn the_fixture_status_is_implemented() {
    // `P9-T006` wrote this test while the fixture was a 186-byte descriptor, and
    // what it asserted was that the text `implemented` appeared in it. That is a
    // claim about a string rather than about a fixture: the directory could have
    // been emptied and the test would still have passed. `P14-T009` gave the
    // directory a project and a grader, so the same test now holds three things
    // that can each go red on their own — the marker, the project the marker
    // claims, and the grader the scenario names. The old reading is kept here
    // because it is what the marker meant until then.
    let fixture = sure_testkit::repository_root().join("fixtures/adversarial/repair-regression");
    let scenario = include_str!("../../../fixtures/adversarial/repair-regression/scenario.json");
    assert!(
        scenario.contains("\"fixture_status\": \"implemented\""),
        "the repair-regression fixture must be marked as implemented"
    );

    // The project, read off the disk. A directory that went back to being a stub
    // fails here whichever half of it was removed: the root manifest, the two
    // member manifests, or the files their scripts name.
    let start = declared_script(&fixture, "package.json", "start");
    assert_eq!(
        start, "node scripts/demo.js",
        "the root manifest's start script is what a reviewer with nothing but Node runs"
    );
    let mut members = Vec::new();
    for member in ["packages/checkout", "packages/billing"] {
        let manifest = format!("{member}/package.json");
        let test = declared_script(&fixture, &manifest, "test");
        let entry = test
            .strip_prefix("node ")
            .unwrap_or_else(|| panic!("{manifest}'s test script must run node directly: `{test}`"));
        assert!(
            fixture.join(member).join(entry).is_file(),
            "{manifest}'s test script names {entry}, which is not a file in the fixture"
        );
        assert!(
            scenario.contains(&manifest),
            "the scenario does not name {manifest}, so the project it describes is not this one"
        );
        members.push(test);
    }
    assert_ne!(
        members[0], members[1],
        "the two members must run their own checks, or there is nothing for a repair to break"
    );

    // And the grader the two outcomes in `scenario.json` name. `include_str!`
    // rather than a path read at run time, so a deleted grader cannot leave a
    // guard behind that still passes: the file missing stops the build.
    let grader = include_str!("repair_fixture_e2e.rs");
    assert!(
        grader.contains("const FIXTURE: &str = \"repair-regression\";")
            && grader.contains(
                "fn a_careless_repair_that_breaks_the_other_member_cannot_close_the_finding"
            )
            && grader.contains("fn a_complete_repair_closes_the_finding_on_new_passing_evidence"),
        "the file the scenario names as this fixture's grader does not grade both of its \
         outcomes, so `graded_by` points at a claim rather than at a test"
    );
}
