//! Terminal human report for a [`ProjectVerdict`].
//!
//! Renders a [`ProjectVerdict`] into plain text suitable for a standard terminal,
//! without requiring HTML/Markdown or JSON processing.
//!
//! # Design
//!
//! - No ANSI colour codes unless [`HumanReportSettings::color`] is true.
//! - Line widths are kept reasonable for an 80-column terminal.
//! - Attacker-controlled text is escaped before printing.

use std::io::{self, Write};

use sure_core::claim_report::render_claim_section;
use sure_core::coverage_summary::{CoverageNotCheckedSummary, summarize};
use sure_core::plain_language_finding::{PlainLanguageFinding, render_findings};
use sure_core::project_verdict::render_summary_with_run_facts;
use sure_core::redact::escape_control_characters;
use sure_core::status::CheckResult;
use sure_core::vocabulary::ProjectVerdict;

/// Settings for the human report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HumanReportSettings<'a> {
    /// Whether to emit ANSI colour codes.
    pub color: bool,
    /// The schedule that was run, if available.
    pub schedule: Option<&'a sure_core::schedule::CheckSchedule>,
    /// The report the run produced, if available.
    pub run_report: Option<&'a sure_core::aggregation::RunReport>,
    /// Whether every stage this run asked for did its work.
    ///
    /// A synthetic verdict (a test, a stored report read without its run) has
    /// no stages to consult, and defaults to `true` so its summary keeps the
    /// wording it had before this field existed. The CLI sets it from the run.
    pub every_stage_ran: bool,
    /// Whether discovery found no stack and the run held no check results.
    ///
    /// A wrong path or a directory with no manifest is not a project with
    /// problems; the summary says so instead of "not ready". Synthetic reports
    /// default to `false`.
    pub no_project_found: bool,
}

impl Default for HumanReportSettings<'_> {
    fn default() -> Self {
        Self {
            color: false,
            schedule: None,
            run_report: None,
            every_stage_ran: true,
            no_project_found: false,
        }
    }
}

/// Render a [`ProjectVerdict`] as plain text for a terminal.
#[must_use]
pub fn render_verdict(verdict: &ProjectVerdict, settings: HumanReportSettings<'_>) -> String {
    let mut out = String::new();

    // Overall summary — and the headline, which is its first line.
    //
    // `render_summary` is self-contained: `sure_core::project_verdict` pushes
    // `verdict.aggregate.headline` before anything else. Pushing the headline
    // here as well printed the verdict sentence twice at the top of every human
    // report, with nothing between the copies but a blank line; the summary is
    // the one that stays, because it is also the form that is read on its own.
    out.push_str(&render_summary_with_run_facts(
        verdict,
        settings.every_stage_ran,
        settings.no_project_found,
    ));
    out.push('\n');

    // AI-claim checks
    let claim_section = render_claim_section(&verdict.claim_checks);
    if !claim_section.is_empty() {
        out.push('\n');
        out.push_str(&claim_section);
    }

    // Findings
    let open: Vec<_> = verdict.open_findings().into_iter().cloned().collect();
    if !open.is_empty() {
        out.push('\n');
        out.push_str("Findings\n");
        out.push_str("--------\n");

        let plain = render_findings(&open);
        let (material, non_material): (Vec<&PlainLanguageFinding>, Vec<&PlainLanguageFinding>) =
            plain.iter().partition(|f| f.is_material());

        for finding in &material {
            render_plain_finding(&mut out, finding, settings);
            out.push('\n');
        }

        if !non_material.is_empty() {
            out.push_str("Other findings (some details are missing):\n");
            for finding in &non_material {
                render_plain_finding(&mut out, finding, settings);
                out.push('\n');
            }
        }
    }

    // Not-checked / coverage
    let has_not_checked = !verdict.not_checked.is_empty();
    if has_not_checked {
        out.push('\n');
        out.push_str("Could not check\n");
        out.push_str("---------------\n");

        if let (Some(schedule), Some(report)) = (settings.schedule, settings.run_report) {
            let summary = summarize(schedule, report, &verdict.capability);
            render_coverage_summary(&mut out, &summary);
        } else {
            render_not_checked_fallback(&mut out, &verdict.not_checked);
        }
    }

    out
}

/// Write the human report to a writer.
///
/// # Errors
///
/// Any failure from `out`.
pub fn write_verdict(
    verdict: &ProjectVerdict,
    settings: HumanReportSettings<'_>,
    out: &mut impl Write,
) -> io::Result<()> {
    write!(out, "{}", render_verdict(verdict, settings))
}

fn render_plain_finding(
    out: &mut String,
    finding: &PlainLanguageFinding,
    _settings: HumanReportSettings<'_>,
) {
    out.push_str(&finding.title);
    out.push('\n');

    let severity = if finding.is_model_only {
        format!(
            "{} (model or inference only — this may be wrong)",
            finding.severity_label
        )
    } else {
        finding.severity_label.clone()
    };
    out.push_str(&format!("  Severity: {severity}\n"));
    out.push_str(&format!("  Status:   {}\n", finding.status_label));

    if !finding.what.is_empty() {
        out.push_str(&format!("  What:     {}\n", finding.what));
    }
    if !finding.impact.is_empty() {
        out.push_str(&format!("  Impact:   {}\n", finding.impact));
    }
    if !finding.next_action.is_empty() {
        out.push_str(&format!("  Action:   {}\n", finding.next_action));
    }

    if !finding.evidence_anchors.is_empty() {
        out.push_str("  Where to look:\n");
        for anchor in &finding.evidence_anchors {
            out.push_str(&format!(
                "    - {} at {} ({})",
                anchor.subject, anchor.location, anchor.locator
            ));
            out.push('\n');
        }
    }
}

fn render_coverage_summary(out: &mut String, summary: &CoverageNotCheckedSummary) {
    out.push_str(&summary.plain_summary());
    out.push('\n');

    if summary.not_checked.is_empty() {
        return;
    }

    out.push('\n');
    for entry in &summary.not_checked {
        out.push_str(&format!("  - {} ({})", entry.check_title, entry.reason));
        if entry.is_critical {
            out.push_str(" [critical]");
        }
        out.push('\n');
    }
}

fn render_not_checked_fallback(out: &mut String, not_checked: &[CheckResult]) {
    for result in not_checked {
        let title = escape_control_characters(&result.title);
        let reason = result.not_checked_reason.map_or_else(
            || {
                let r = escape_control_characters(&result.reason);
                if r.is_empty() {
                    "unknown reason".to_owned()
                } else {
                    r
                }
            },
            |r| r.plain_explanation().to_owned(),
        );
        out.push_str(&format!("  - {title} ({reason})"));
        if result.critical {
            out.push_str(" [critical]");
        }
        out.push('\n');
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use sure_core::capability::CapabilityReport;
    use sure_core::evidence::{
        AnchorSubject, ClaimAssessment, Evidence, EvidenceAnchor, EvidenceClass,
    };
    use sure_core::ids::{CheckId, ClaimId, FingerprintId};
    use sure_core::intent::ProjectIntent;
    use sure_core::severity::Severity;
    use sure_core::status::{
        Aggregate, AggregateSeverity, CheckResult, CheckStatus, CoverageSummary, NotCheckedReason,
        StatusCounts,
    };
    use sure_core::vocabulary::{
        AssessmentSource, Claim, FindingBuilder, FindingStatus, ProjectVerdict, SeverityRationale,
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

    fn a_finding(severity: Severity) -> sure_core::vocabulary::Finding {
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

    fn build_verdict(
        aggregate: Aggregate,
        findings: Vec<sure_core::vocabulary::Finding>,
        not_checked: Vec<CheckResult>,
    ) -> ProjectVerdict {
        ProjectVerdict {
            fingerprint: fingerprint(),
            aggregate,
            intent: ProjectIntent::empty(),
            capability: CapabilityReport::cli(),
            findings,
            not_checked,
            claim_checks: Vec::new(),
        }
    }

    fn render(verdict: &ProjectVerdict) -> String {
        render_verdict(verdict, HumanReportSettings::default())
    }

    #[test]
    fn ready_green_project_produces_readable_non_empty_report() {
        let verdict = build_verdict(green_aggregate(), Vec::new(), Vec::new());
        let text = render(&verdict);
        assert!(!text.is_empty(), "report must not be empty");
        assert!(
            text.contains("ready to hand off"),
            "green report should say ready: {text}"
        );
        assert!(
            text.contains(AggregateSeverity::Green.headline()),
            "report should contain headline: {text}"
        );
    }

    #[test]
    fn incomplete_run_does_not_call_a_green_aggregate_ready() {
        let verdict = build_verdict(green_aggregate(), Vec::new(), Vec::new());
        let text = render_verdict(
            &verdict,
            HumanReportSettings {
                every_stage_ran: false,
                ..HumanReportSettings::default()
            },
        );
        assert!(
            text.contains("did not check everything"),
            "an incomplete run should say what it could not check: {text}"
        );
        assert!(
            !text.contains("ready to hand off"),
            "an incomplete run must not read as ready: {text}"
        );
    }

    #[test]
    fn project_with_open_must_fix_says_not_ready() {
        let verdict = build_verdict(
            green_aggregate(),
            vec![a_finding(Severity::MustFix)],
            Vec::new(),
        );
        let text = render(&verdict);
        assert!(
            text.contains("not ready to hand off"),
            "must-fix finding should make report say not ready: {text}"
        );
        assert!(
            text.contains("A finding"),
            "report should list the finding: {text}"
        );
        assert!(
            text.contains("Must fix"),
            "report should show severity: {text}"
        );
    }

    #[test]
    fn skipped_checks_are_visible() {
        let not_checked = vec![CheckResult::not_run(
            CheckId::generate(),
            "run tests",
            Severity::MustFix,
            true,
            NotCheckedReason::ExecutionNotAuthorized,
            fingerprint(),
        )];
        let verdict = build_verdict(green_aggregate(), Vec::new(), not_checked);
        let text = render(&verdict);
        assert!(
            text.contains("Could not check"),
            "skipped checks should have a section: {text}"
        );
        assert!(
            text.contains("run tests"),
            "skipped check title should appear: {text}"
        );
        assert!(
            text.contains("[critical]"),
            "critical skipped check should be marked: {text}"
        );
    }

    #[test]
    fn could_not_run_checks_are_visible() {
        let not_checked = vec![CheckResult::errored(
            CheckId::generate(),
            "lint check",
            Severity::ShouldFixFirst,
            false,
            "the linter crashed",
            fingerprint(),
        )];
        let verdict = build_verdict(green_aggregate(), Vec::new(), not_checked);
        let text = render(&verdict);
        assert!(
            text.contains("Could not check"),
            "errored checks should have a section: {text}"
        );
        assert!(
            text.contains("lint check"),
            "errored check title should appear: {text}"
        );
    }

    #[test]
    fn after_the_fact_caveat_appears_when_appropriate() {
        let verdict = build_verdict(green_aggregate(), Vec::new(), Vec::new());
        let text = render(&verdict);
        assert!(
            text.contains("cannot confirm that it matches your original request"),
            "after-the-fact caveat should appear: {text}"
        );
    }

    #[test]
    fn caveat_does_not_appear_when_intent_is_trusted() {
        let intent = ProjectIntent::from_requirements(vec![sure_core::intent::Requirement::new(
            "r1",
            "build a thing",
            sure_core::intent::IntentSource::ExplicitUserGoal,
        )]);
        let verdict = ProjectVerdict {
            fingerprint: fingerprint(),
            aggregate: green_aggregate(),
            intent,
            capability: CapabilityReport::cli(),
            findings: Vec::new(),
            not_checked: Vec::new(),
            claim_checks: Vec::new(),
        };
        let text = render(&verdict);
        assert!(
            !text.contains("cannot confirm that it matches your original request"),
            "caveat should not appear with trusted intent: {text}"
        );
    }

    #[test]
    fn control_characters_in_titles_and_descriptions_are_escaped() {
        let not_checked = vec![CheckResult::not_run(
            CheckId::generate(),
            "run\ntests",
            Severity::MustFix,
            true,
            NotCheckedReason::ExecutionNotAuthorized,
            fingerprint(),
        )];
        let verdict = build_verdict(green_aggregate(), Vec::new(), not_checked);
        let text = render(&verdict);
        assert!(
            !text.contains("run\ntests"),
            "unescaped newline must not appear: {text:?}"
        );
        assert!(
            text.contains("run\\ntests"),
            "escaped newline should appear: {text}"
        );
    }

    #[test]
    fn report_is_plain_text_no_ansi_by_default() {
        let not_checked = vec![CheckResult::not_run(
            CheckId::generate(),
            "run tests",
            Severity::MustFix,
            true,
            NotCheckedReason::ExecutionNotAuthorized,
            fingerprint(),
        )];
        let verdict = build_verdict(green_aggregate(), Vec::new(), not_checked);
        let text = render(&verdict);
        assert!(
            !text.contains('\x1b'),
            "default report must not contain ANSI escape codes: {text:?}"
        );
    }

    #[test]
    fn reduced_coverage_caveat_appears_when_analysis_provider_is_disabled() {
        let not_checked = vec![CheckResult::not_run(
            CheckId::generate(),
            "semantic intent match",
            Severity::ShouldFixFirst,
            true,
            NotCheckedReason::AnalysisProviderDisabled,
            fingerprint(),
        )];
        let verdict = build_verdict(green_aggregate(), Vec::new(), not_checked);
        let text = render(&verdict);
        assert!(
            text.contains("Model-backed analysis is disabled"),
            "human report should note reduced coverage: {text}"
        );
        assert!(
            text.contains("deterministic checks only"),
            "human report should say coverage is limited to deterministic checks: {text}"
        );
        assert!(
            text.contains("semantic intent match"),
            "human report should list the disabled check: {text}"
        );
    }

    #[test]
    fn material_findings_are_shown_before_non_material() {
        let fp = fingerprint();
        let material = FindingBuilder::new(
            AssessmentSource::ObservedFact,
            SeverityRationale::BlocksHandOff,
        )
        .title("Material finding")
        .severity(Severity::MustFix)
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
            Severity::MustFix,
        )])
        .build()
        .expect("valid finding");

        let non_material = FindingBuilder::new(
            AssessmentSource::ObservedFact,
            SeverityRationale::Informational,
        )
        .title("Non-material finding")
        .severity(Severity::Note)
        .status(FindingStatus::Open)
        .fingerprint(fp.clone())
        .build()
        .expect("valid finding");

        let verdict = build_verdict(green_aggregate(), vec![non_material, material], Vec::new());
        let text = render(&verdict);

        let material_pos = text
            .find("Material finding")
            .expect("material finding present");
        let other_pos = text
            .find("Other findings (some details are missing)")
            .expect("non-material header present");
        let non_material_pos = text
            .find("Non-material finding")
            .expect("non-material finding present");

        assert!(
            material_pos < other_pos,
            "material finding should appear before the non-material header"
        );
        assert!(
            other_pos < non_material_pos,
            "non-material header should appear before the non-material finding"
        );
    }

    #[test]
    fn model_only_finding_is_flagged() {
        let fp = fingerprint();
        let finding = FindingBuilder::new(
            AssessmentSource::ModelAssessment,
            SeverityRationale::Informational,
        )
        .title("Model-only uncertainty")
        .severity(Severity::Note)
        .status(FindingStatus::Open)
        .explanation("The model inferred something but cannot point to a project location.")
        .user_impact("This may be nothing.")
        .next_step("Look for a concrete symptom.")
        .fingerprint(fp.clone())
        .evidence(vec![Evidence::new(
            EvidenceClass::ModelAssessment,
            "inferred from prompt",
            EvidenceAnchor::model_only("model-only conclusion"),
            Some(fp.clone()),
            Severity::Note,
        )])
        .build()
        .expect("valid note finding");

        let verdict = build_verdict(green_aggregate(), vec![finding], Vec::new());
        let text = render(&verdict);
        assert!(
            text.contains("model or inference only — this may be wrong"),
            "model-only finding should be flagged: {text}"
        );
    }

    #[test]
    fn write_verdict_produces_same_output_as_render() {
        let verdict = build_verdict(green_aggregate(), Vec::new(), Vec::new());
        let rendered = render_verdict(&verdict, HumanReportSettings::default());
        let mut buf = Vec::new();
        write_verdict(&verdict, HumanReportSettings::default(), &mut buf).unwrap();
        let written = String::from_utf8(buf).unwrap();
        assert_eq!(rendered, written);
    }

    fn a_claim(assessment: ClaimAssessment, text: &str) -> Claim {
        Claim {
            id: ClaimId::generate(),
            claim_text: text.to_owned(),
            claim_type: "test_ran".to_owned(),
            assessment,
            reason: String::from("A recorded harness event supports this claim."),
            evidence: Vec::new(),
            session: None,
        }
    }

    #[test]
    fn claim_section_appears_when_claim_checks_exist() {
        let verdict = ProjectVerdict {
            fingerprint: fingerprint(),
            aggregate: green_aggregate(),
            intent: ProjectIntent::empty(),
            capability: CapabilityReport::cli(),
            findings: Vec::new(),
            not_checked: Vec::new(),
            claim_checks: vec![a_claim(ClaimAssessment::Confirmed, "I ran the tests")],
        };
        let text = render(&verdict);
        assert!(text.contains("AI claims"), "{text}");
        assert!(text.contains("I ran the tests"), "{text}");
        assert!(text.contains("Confirmed"), "{text}");
    }

    #[test]
    fn claim_section_is_absent_when_no_claim_checks_exist() {
        let verdict = build_verdict(green_aggregate(), Vec::new(), Vec::new());
        let text = render(&verdict);
        assert!(!text.contains("AI claims"), "{text}");
    }

    #[test]
    fn claim_text_is_escaped_in_human_report() {
        let verdict = ProjectVerdict {
            fingerprint: fingerprint(),
            aggregate: green_aggregate(),
            intent: ProjectIntent::empty(),
            capability: CapabilityReport::cli(),
            findings: Vec::new(),
            not_checked: Vec::new(),
            claim_checks: vec![a_claim(
                ClaimAssessment::Confirmed,
                "I ran the tests\nsecret",
            )],
        };
        let text = render(&verdict);
        assert!(!text.contains("I ran the tests\nsecret"), "{text:?}");
        assert!(text.contains("I ran the tests\\nsecret"), "{text}");
    }
}
