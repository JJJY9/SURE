//! Overall project verdict acceptance tests.
//!
//! These tests verify the plain-language summary contract and the false-green
//! protection that lives in the summary renderer.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use sure_core::project_verdict::{build_verdict, render_summary, render_summary_with_completeness};
use sure_domain::capability::CapabilityReport;
use sure_domain::evidence::{AnchorSubject, Evidence, EvidenceAnchor, EvidenceClass};
use sure_domain::finding::{AssessmentSource, FindingBuilder, FindingStatus, SeverityRationale};
use sure_domain::ids::{CheckId, FingerprintId};
use sure_domain::intent::{ProjectIntent, Requirement};
use sure_domain::severity::Severity;
use sure_domain::status::{
    Aggregate, AggregateSeverity, CheckResult, CheckStatus, CoverageSummary, NotCheckedReason,
    StatusCounts,
};

fn fingerprint() -> FingerprintId {
    FingerprintId::generate()
}

fn green_aggregate() -> Aggregate {
    Aggregate {
        severity: AggregateSeverity::Green,
        headline: AggregateSeverity::Green.headline().to_owned(),
        counts: StatusCounts::tally([CheckStatus::Pass]),
        blocking: Vec::new(),
        coverage: CoverageSummary {
            counts: StatusCounts::tally([CheckStatus::Pass]),
            critical_not_checked: Vec::new(),
            critical_errored: Vec::new(),
            critical_failed: Vec::new(),
            critical_out_of_scope: Vec::new(),
            critical_checked: 1,
        },
    }
}

fn not_enough_checked_aggregate() -> Aggregate {
    Aggregate {
        severity: AggregateSeverity::NotEnoughChecked,
        headline: AggregateSeverity::NotEnoughChecked.headline().to_owned(),
        counts: StatusCounts::default(),
        blocking: Vec::new(),
        coverage: CoverageSummary {
            counts: StatusCounts::default(),
            critical_not_checked: Vec::new(),
            critical_errored: Vec::new(),
            critical_failed: Vec::new(),
            critical_out_of_scope: Vec::new(),
            critical_checked: 0,
        },
    }
}

fn not_ready_aggregate() -> Aggregate {
    let result = CheckResult::fail(
        CheckId::generate(),
        "a check",
        Severity::MustFix,
        true,
        EvidenceClass::DeterministicCheck,
        fingerprint(),
    );
    sure_domain::status::aggregate(&[result])
}

fn a_finding(severity: Severity) -> sure_domain::finding::Finding {
    let fp = fingerprint();
    let source = if severity.blocks_hand_off() {
        AssessmentSource::DeterministicCheck
    } else {
        AssessmentSource::ObservedFact
    };
    let rationale = SeverityRationale::for_severity(severity).unwrap();
    FindingBuilder::new(source, rationale)
        .title("A finding")
        .severity(severity)
        .status(FindingStatus::Open)
        .explanation("Something is wrong.")
        .user_impact("It matters.")
        .next_step("Fix it.")
        .fingerprint(fp.clone())
        .evidence(vec![Evidence::new(
            EvidenceClass::ObservedFact,
            "evidence",
            EvidenceAnchor::new(AnchorSubject::File, "src/x.rs", "line 1"),
            Some(fp.clone()),
            severity,
        )])
        .build()
        .expect("valid finding")
}

#[test]
fn green_aggregate_and_no_findings_means_ready() {
    let verdict = build_verdict(
        fingerprint(),
        green_aggregate(),
        ProjectIntent::empty(),
        CapabilityReport::cli(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
    );
    assert!(verdict.is_ready_for_hand_off());
    let summary = render_summary(&verdict);
    assert!(
        summary.contains("This project looks ready to hand off."),
        "summary: {summary}"
    );
    assert!(
        !summary.contains("This project is not ready to hand off."),
        "summary: {summary}"
    );
}

#[test]
fn green_aggregate_with_unrun_stages_is_not_called_ready() {
    // A green aggregate says every check that ran passed. It does not say every
    // stage ran: a first run with no analysis provider and no claim history has
    // two stages marked not checked, and the CLI exits 1 for that run. The
    // summary must not tell the reader it is ready to hand off at the same time.
    let verdict = build_verdict(
        fingerprint(),
        green_aggregate(),
        ProjectIntent::empty(),
        CapabilityReport::cli(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
    );
    let summary = render_summary_with_completeness(&verdict, false);
    assert!(
        summary.contains("did not check everything"),
        "summary: {summary}"
    );
    assert!(
        !summary.contains("This project looks ready to hand off."),
        "summary: {summary}"
    );
}

#[test]
fn green_aggregate_with_every_stage_run_keeps_the_ready_sentence() {
    let verdict = build_verdict(
        fingerprint(),
        green_aggregate(),
        ProjectIntent::empty(),
        CapabilityReport::cli(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
    );
    let summary = render_summary_with_completeness(&verdict, true);
    assert!(
        summary.contains("This project looks ready to hand off."),
        "summary: {summary}"
    );
}

#[test]
fn green_aggregate_with_open_must_fix_is_not_ready() {
    let verdict = build_verdict(
        fingerprint(),
        green_aggregate(),
        ProjectIntent::empty(),
        CapabilityReport::cli(),
        vec![a_finding(Severity::MustFix)],
        Vec::new(),
        Vec::new(),
    );
    assert!(!verdict.is_ready_for_hand_off());
    let summary = render_summary(&verdict);
    assert!(
        summary.contains("This project is not ready to hand off."),
        "summary: {summary}"
    );
}

#[test]
fn not_enough_checked_aggregate_is_not_ready_and_says_why() {
    let verdict = build_verdict(
        fingerprint(),
        not_enough_checked_aggregate(),
        ProjectIntent::empty(),
        CapabilityReport::cli(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
    );
    assert!(!verdict.is_ready_for_hand_off());
    let summary = render_summary(&verdict);
    assert!(
        summary.contains("This project is not ready to hand off."),
        "summary: {summary}"
    );
    assert!(
        summary.contains("Not enough could be checked"),
        "summary: {summary}"
    );
}

#[test]
fn after_the_fact_intent_caveat_appears_when_appropriate() {
    let verdict = build_verdict(
        fingerprint(),
        green_aggregate(),
        ProjectIntent::empty(),
        CapabilityReport::cli(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
    );
    assert!(verdict.must_caveat_requirements());
    let summary = render_summary(&verdict);
    assert!(
        summary.contains("cannot confirm that it matches your original request"),
        "summary: {summary}"
    );
}

#[test]
fn after_the_fact_caveat_is_absent_when_intent_is_trusted() {
    let intent = ProjectIntent::from_requirements(vec![Requirement::new(
        "r1",
        "build a thing",
        sure_domain::intent::IntentSource::ExplicitUserGoal,
    )]);
    let verdict = build_verdict(
        fingerprint(),
        green_aggregate(),
        intent,
        CapabilityReport::cli(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
    );
    assert!(!verdict.must_caveat_requirements());
    let summary = render_summary(&verdict);
    assert!(
        !summary.contains("cannot confirm that it matches your original request"),
        "summary: {summary}"
    );
}

#[test]
fn skipped_and_could_not_run_checks_are_surfaced() {
    let not_checked = vec![
        CheckResult::not_run(
            CheckId::generate(),
            "run tests",
            Severity::MustFix,
            true,
            NotCheckedReason::ExecutionNotAuthorized,
            fingerprint(),
        ),
        CheckResult::errored(
            CheckId::generate(),
            "check routes",
            Severity::ShouldFixFirst,
            true,
            "parser panicked",
            fingerprint(),
        ),
    ];
    let verdict = build_verdict(
        fingerprint(),
        not_ready_aggregate(),
        ProjectIntent::empty(),
        CapabilityReport::cli(),
        Vec::new(),
        not_checked,
        Vec::new(),
    );
    let summary = render_summary(&verdict);
    assert!(
        summary.contains("could not run or were skipped"),
        "summary: {summary}"
    );
    assert!(summary.contains("run tests"), "summary: {summary}");
    assert!(summary.contains("check routes"), "summary: {summary}");
    assert!(
        summary.contains("2 of them are critical"),
        "summary: {summary}"
    );
}

#[test]
fn control_characters_in_titles_are_escaped() {
    let not_checked = vec![CheckResult::not_run(
        CheckId::generate(),
        "run\ntests",
        Severity::MustFix,
        true,
        NotCheckedReason::ExecutionNotAuthorized,
        fingerprint(),
    )];
    let verdict = build_verdict(
        fingerprint(),
        green_aggregate(),
        ProjectIntent::empty(),
        CapabilityReport::cli(),
        Vec::new(),
        not_checked,
        Vec::new(),
    );
    let summary = render_summary(&verdict);
    assert!(
        !summary.contains("run\ntests"),
        "unescaped title must not appear: {summary:?}"
    );
    assert!(
        summary.contains("run\\ntests"),
        "escaped newline must appear: {summary}"
    );
}
