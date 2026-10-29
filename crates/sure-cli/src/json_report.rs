//! Stable, machine-readable JSON report for a [`ProjectVerdict`].
//!
//! Produces a deterministic, versioned JSON object suitable for downstream
//! tools (CI parsers, IDEs, review dashboards). No ANSI escape codes or
//! terminal formatting are included.

use serde::{Deserialize, Serialize};
use sure_core::finding::{Finding, FindingStatus};
use sure_core::plain_language_finding::render_finding;
use sure_core::vocabulary::ProjectVerdict;

/// The schema version of the JSON report.
///
/// Bumped when the shape changes in a way an older reader would get wrong.
pub const REPORT_SCHEMA_VERSION: u32 = 3;

/// A stable JSON report for a project verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsonReport {
    /// Schema version of this report.
    pub schema_version: u32,
    /// The project state this verdict is about.
    pub project_fingerprint: String,
    /// How the checks aggregated.
    pub aggregate: JsonAggregate,
    /// Whether this verdict permits hand-off.
    pub ready_for_hand_off: bool,
    /// Whether the report must carry the "I did not see your request" caveat.
    pub must_caveat_requirements: bool,
    /// The caveat text, when it applies.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub caveat: Option<String>,
    /// A reduced-coverage note when model-backed analysis is disabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub coverage_caveat: Option<String>,
    /// What the harness integration could and could not see.
    pub capability: JsonCapability,
    /// Findings that still need attention, most serious first.
    pub findings: Vec<JsonFinding>,
    /// Checks that did not run, kept visible so they are never mistaken for passes.
    pub not_checked: Vec<JsonNotChecked>,
    /// Agent completion claims checked against recorded evidence.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub claim_checks: Vec<JsonClaimCheck>,
    /// Per-category counts.
    pub totals: JsonTotals,
}

/// The aggregated result of a run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsonAggregate {
    /// The honest overall recommendation.
    pub severity: String,
    /// Plain-language headline.
    #[serde(rename = "headline")]
    pub headline_text: String,
    /// Whether the run ended without any blocking problem.
    pub is_green: bool,
}

/// Capability and support level summary.
///
/// # Why the tier is never alone here
///
/// A number is the one form of this answer that cannot carry a limitation, and
/// `tier: 1` on its own reads as "SURE saw the session" — with nothing beside it
/// saying which parts of the session it did not see, or whether it counted any
/// events at all. So the blind spots travel with it as data (the wire names of
/// [`sure_core::capability::BlindSpotKind`], which
/// `crates/sure-domain/tests/wire_contract.rs` freezes), and the account of what
/// was counted travels with it in
/// [`summary`](Self::summary), in the same sentence the human report prints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsonCapability {
    /// Numeric capability tier: 0 snapshot, 1 observed, 2 protected.
    pub tier: u8,
    /// Plain-language description of what the user actually gets, including
    /// what was counted and what this tier still does not cover.
    pub summary: String,
    /// What SURE could not see, as the wire names of `BlindSpotKind`.
    ///
    /// A list rather than prose: a script deciding whether a verdict is usable
    /// for its purpose is asking whether a *named* gap is present, and parsing
    /// sentences to find out is how a script breaks when a sentence is improved.
    pub blind_spots: Vec<String>,
    /// What the tier was counted from, when it came from recorded events.
    ///
    /// `None` when SURE counted nothing — the report is the command line's own,
    /// which has no session to count. The distinction is the field: a project
    /// with no recorded events and a project whose events belong to a different
    /// directory both report tier 0, and only this says which is which.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<JsonCapabilityEvidence>,
}

/// What a capability tier was counted from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsonCapabilityEvidence {
    /// The harnesses the counted events came from, sorted and deduplicated.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub harnesses: Vec<String>,
    /// How many session events were counted for this project.
    pub events: usize,
    /// The earliest and latest counted event, as the envelopes carried them.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub window: Option<JsonCapabilityWindow>,
    /// Session events the read found that are about other projects.
    pub elsewhere: usize,
    /// Whether the read stopped at its own limit before reading everything.
    pub truncated: bool,
    /// Whether SURE could not read the events its store holds at all.
    pub unreadable: bool,
}

/// The span the counted events cover, as the envelopes wrote it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsonCapabilityWindow {
    /// The earliest counted event, RFC 3339.
    pub oldest: String,
    /// The latest counted event, RFC 3339.
    pub newest: String,
}

/// One finding rendered for a machine-readable report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsonFinding {
    /// Stable identity of the finding.
    pub id: String,
    /// Short title.
    pub title: String,
    /// What is wrong, in plain language.
    pub what: String,
    /// What it means for the person reading the report.
    pub impact: String,
    /// User-facing severity label.
    pub severity: String,
    /// User-facing finding status.
    pub status: String,
    /// What SURE thinks should happen next.
    pub next_action: String,
    /// Whether the finding rests only on model output, inference, or no source.
    pub is_model_only: bool,
    /// Whether a person may accept this finding as a risk (ADR 0019).
    ///
    /// True only when no piece of the finding's evidence could alone carry a
    /// `must_fix` — a candidate a scanner inferred. A failing check, a checker
    /// error and a check that did not run are never acknowledgeable, and a
    /// caller offering the choice is offering a decision SURE would refuse.
    pub acknowledgeable: bool,
    /// Simplified list of checkable evidence anchors.
    pub evidence_anchors: Vec<JsonEvidenceAnchor>,
}

/// A simplified, checkable pointer back to one piece of evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsonEvidenceAnchor {
    /// Where a human finds this.
    pub location: String,
    /// The specific thing at that location.
    pub locator: String,
    /// The stable wire name for what kind of thing the anchor points at.
    pub subject: String,
}

/// One check that did not run, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsonNotChecked {
    /// The check's stable identity.
    pub id: String,
    /// The short human title shown in the report.
    pub title: String,
    /// Why the check did not run, in plain language.
    pub reason: String,
    /// Whether this check is critical to hand-off.
    pub is_critical: bool,
}

/// One agent claim that was checked against recorded evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsonClaimCheck {
    /// Stable identity of the claim.
    pub id: String,
    /// The claim text.
    pub claim_text: String,
    /// The claim type that was checked.
    pub claim_type: String,
    /// User-facing assessment label.
    pub assessment: String,
    /// Plain-language explanation of the assessment.
    pub reason: String,
}

/// Per-category counts for the report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsonTotals {
    /// Checks that produced a real result about the project.
    pub checked: u32,
    /// Checks deliberately not run.
    pub skipped: u32,
    /// Checks that could not run because of an error or unavailable tool.
    pub could_not_run: u32,
    /// Findings that still need attention.
    pub open_findings: u32,
}

/// Render a [`ProjectVerdict`] as a stable JSON string.
///
/// The output is compact (no unnecessary whitespace) and deterministic:
/// the same inputs always produce the same JSON bytes.
#[must_use]
#[allow(
    clippy::expect_used,
    reason = "JsonReport contains only basic serializable types; serde_json::to_string is infallible here"
)]
pub fn render_json_report(verdict: &ProjectVerdict) -> String {
    let report = build_json_report(verdict);
    // Compact, deterministic output: fields in declaration order.
    serde_json::to_string(&report).expect("JsonReport serializes to JSON")
}

/// Render a [`ProjectVerdict`] as a stable, pretty-printed JSON string.
///
/// The output is deterministic but includes whitespace for human readability.
#[must_use]
#[allow(
    clippy::expect_used,
    reason = "JsonReport contains only basic serializable types; serde_json::to_string_pretty is infallible here"
)]
pub fn render_json_report_pretty(verdict: &ProjectVerdict) -> String {
    let report = build_json_report(verdict);
    serde_json::to_string_pretty(&report).expect("JsonReport serializes to JSON")
}

/// The report as a value, before it is a string.
///
/// Public so that `sure check`'s own machine form can carry the verdict in the
/// shape this module defines and versions, rather than growing a second
/// description of a finding that would have to be kept in step with this one.
/// `#[must_use]` because a caller that built it and dropped it wanted
/// [`render_json_report`].
#[must_use]
pub fn build_json_report(verdict: &ProjectVerdict) -> JsonReport {
    let open = verdict.open_findings();

    // The list carries what needs attention and what the person has already
    // accepted (ADR 0019). An accepted finding is not unresolved — it is out of
    // `open_findings()` and out of `totals.open_findings` — and it is not
    // hidden either: a decision a reader cannot see is indistinguishable from a
    // fix, and the whole point of recording it is that somebody may need to
    // read it later.
    let mut accepted: Vec<&Finding> = verdict
        .findings
        .iter()
        .filter(|finding| finding.status == FindingStatus::AcceptedRisk)
        .collect();
    accepted.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.title.cmp(&b.title))
    });
    let shown: Vec<&Finding> = open.iter().copied().chain(accepted).collect();

    let findings: Vec<JsonFinding> = shown
        .iter()
        .map(|finding| {
            let plain = render_finding(finding);
            JsonFinding {
                id: finding.id.as_str().to_owned(),
                title: plain.title,
                what: plain.what,
                impact: plain.impact,
                severity: plain.severity_label,
                status: plain.status_label,
                next_action: plain.next_action,
                is_model_only: plain.is_model_only,
                acknowledgeable: finding.can_be_acknowledged(),
                evidence_anchors: plain
                    .evidence_anchors
                    .iter()
                    .map(|a| JsonEvidenceAnchor {
                        location: a.location.clone(),
                        locator: a.locator.clone(),
                        subject: a.subject.clone(),
                    })
                    .collect(),
            }
        })
        .collect();

    let not_checked: Vec<JsonNotChecked> = verdict
        .not_checked
        .iter()
        .map(|result| JsonNotChecked {
            id: result.id.as_str().to_owned(),
            title: result.title.clone(),
            reason: result.reason.clone(),
            is_critical: result.critical,
        })
        .collect();

    let claim_checks: Vec<JsonClaimCheck> = verdict
        .claim_checks
        .iter()
        .map(|claim| JsonClaimCheck {
            id: claim.id.as_str().to_owned(),
            claim_text: claim.claim_text.clone(),
            claim_type: claim.claim_type.clone(),
            assessment: claim.assessment.label().to_owned(),
            reason: claim.reason.clone(),
        })
        .collect();

    let counts = verdict.aggregate.counts;

    JsonReport {
        schema_version: REPORT_SCHEMA_VERSION,
        project_fingerprint: verdict.fingerprint.as_str().to_owned(),
        aggregate: JsonAggregate {
            severity: verdict.aggregate.severity.as_str().to_owned(),
            headline_text: verdict.aggregate.headline.clone(),
            is_green: verdict.aggregate.is_green(),
        },
        ready_for_hand_off: verdict.is_ready_for_hand_off(),
        must_caveat_requirements: verdict.must_caveat_requirements(),
        caveat: if verdict.must_caveat_requirements() {
            Some(sure_core::status::NO_TRUSTED_INTENT_LIMITATION.to_owned())
        } else {
            None
        },
        coverage_caveat: if verdict.not_checked.iter().any(|r| {
            r.not_checked_reason
                == Some(sure_core::status::NotCheckedReason::AnalysisProviderDisabled)
        }) {
            Some(sure_core::project_verdict::REDUCED_COVERAGE_ANALYSIS_DISABLED.to_owned())
        } else {
            None
        },
        capability: JsonCapability {
            tier: verdict.capability.tier_number(),
            summary: verdict.capability.summary(),
            blind_spots: verdict
                .capability
                .blind_spots
                .iter()
                .map(|spot| spot.kind.as_str().to_owned())
                .collect(),
            evidence: verdict
                .capability
                .evidence
                .as_ref()
                .map(|evidence| JsonCapabilityEvidence {
                    harnesses: evidence.harnesses.clone(),
                    events: evidence.events,
                    window: evidence.window.as_ref().map(|window| JsonCapabilityWindow {
                        oldest: window.oldest.clone(),
                        newest: window.newest.clone(),
                    }),
                    elsewhere: evidence.elsewhere,
                    truncated: evidence.truncated,
                    unreadable: evidence.unreadable,
                }),
        },
        findings,
        not_checked,
        claim_checks,
        totals: JsonTotals {
            checked: counts.checked(),
            skipped: counts.skipped,
            could_not_run: counts.error + counts.unknown,
            open_findings: open.len() as u32,
        },
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use sure_core::capability::{
        BlindSpot, BlindSpotKind, CapabilityEvidence, CapabilityReport, CapabilityTier, EventWindow,
    };
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

    fn parse_report(json: &str) -> JsonReport {
        serde_json::from_str(json).expect("valid JSON report")
    }

    #[test]
    fn green_verdict_serialises_and_round_trips() {
        let verdict = build_verdict(green_aggregate(), Vec::new(), Vec::new());
        let json = render_json_report(&verdict);
        let report = parse_report(&json);
        assert_eq!(report.schema_version, REPORT_SCHEMA_VERSION);
        assert_eq!(report.aggregate.severity, "green");
        assert!(report.aggregate.is_green);
        assert!(report.ready_for_hand_off);
        assert!(report.findings.is_empty());
        assert!(report.not_checked.is_empty());
        assert_eq!(report.totals.checked, 1);
        assert_eq!(report.totals.open_findings, 0);
    }

    #[test]
    fn open_must_fix_finding_appears_in_findings_array() {
        let verdict = build_verdict(
            green_aggregate(),
            vec![a_finding(Severity::MustFix)],
            Vec::new(),
        );
        let json = render_json_report(&verdict);
        let report = parse_report(&json);
        assert_eq!(report.findings.len(), 1);
        let finding = &report.findings[0];
        assert_eq!(finding.severity, "Must fix");
        assert_eq!(finding.status, "Open");
        assert!(!finding.is_model_only);
        assert_eq!(finding.evidence_anchors.len(), 1);
        assert_eq!(finding.evidence_anchors[0].subject, "file");
        assert!(!report.ready_for_hand_off);
        assert_eq!(report.totals.open_findings, 1);
    }

    #[test]
    fn skipped_and_errored_checks_appear_in_not_checked_array() {
        let pass = CheckResult::pass(
            CheckId::generate(),
            "static analysis",
            Severity::ShouldFixFirst,
            false,
            EvidenceClass::DeterministicCheck,
            fingerprint(),
        );
        let skipped = CheckResult::not_run(
            CheckId::generate(),
            "run tests",
            Severity::MustFix,
            true,
            NotCheckedReason::ExecutionNotAuthorized,
            fingerprint(),
        );
        let errored = CheckResult::errored(
            CheckId::generate(),
            "lint check",
            Severity::ShouldFixFirst,
            false,
            "the linter crashed",
            fingerprint(),
        );
        let aggregate = sure_core::status::aggregate(&[pass, skipped.clone(), errored.clone()]);
        let verdict = build_verdict(aggregate, Vec::new(), vec![skipped, errored]);
        let json = render_json_report(&verdict);
        let report = parse_report(&json);
        assert_eq!(report.not_checked.len(), 2);

        let skipped_entry = report
            .not_checked
            .iter()
            .find(|e| e.title == "run tests")
            .expect("skipped check present");
        assert!(skipped_entry.is_critical);

        let errored_entry = report
            .not_checked
            .iter()
            .find(|e| e.title == "lint check")
            .expect("errored check present");
        assert!(!errored_entry.is_critical);
        assert_eq!(report.totals.skipped, 1);
        assert_eq!(report.totals.could_not_run, 1);
    }

    #[test]
    fn caveat_flag_and_text_are_present_when_intent_is_after_the_fact() {
        let verdict = build_verdict(green_aggregate(), Vec::new(), Vec::new());
        let json = render_json_report(&verdict);
        let report = parse_report(&json);
        assert!(report.must_caveat_requirements);
        assert!(report.caveat.is_some());
        let caveat = report.caveat.unwrap();
        assert!(caveat.contains("cannot confirm"));
    }

    #[test]
    fn caveat_is_absent_when_intent_is_trusted() {
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
        let json = render_json_report(&verdict);
        let report = parse_report(&json);
        assert!(!report.must_caveat_requirements);
        assert!(report.caveat.is_none());
    }

    #[test]
    fn output_is_deterministic() {
        let verdict = build_verdict(
            green_aggregate(),
            vec![a_finding(Severity::ShouldFixFirst)],
            Vec::new(),
        );
        let a = render_json_report(&verdict);
        let b = render_json_report(&verdict);
        assert_eq!(a, b, "same inputs must produce identical JSON bytes");
    }

    #[test]
    fn no_ansi_codes_in_json_output() {
        let verdict = build_verdict(green_aggregate(), Vec::new(), Vec::new());
        let json = render_json_report(&verdict);
        assert!(
            !json.contains('\x1b'),
            "JSON report must not contain ANSI escape codes"
        );
    }

    #[test]
    fn pretty_output_is_readable_and_still_valid() {
        let verdict = build_verdict(green_aggregate(), Vec::new(), Vec::new());
        let pretty = render_json_report_pretty(&verdict);
        assert!(
            pretty.contains('\n'),
            "pretty output should contain newlines"
        );
        let report: JsonReport = serde_json::from_str(&pretty).expect("pretty JSON is valid");
        assert_eq!(report.schema_version, REPORT_SCHEMA_VERSION);
    }

    #[test]
    fn model_only_finding_is_flagged_and_omits_checkable_anchors() {
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
        let json = render_json_report(&verdict);
        let report = parse_report(&json);
        assert_eq!(report.findings.len(), 1);
        assert!(report.findings[0].is_model_only);
        assert!(report.findings[0].evidence_anchors.is_empty());
    }

    #[test]
    fn the_machine_form_names_the_gaps_and_what_the_tier_was_counted_from() {
        // Criterion 3 for a machine reader: `tier: 1` on its own is the one form
        // of this answer that cannot carry a limitation. The blind spots travel
        // as their wire names — so a script asks whether a *named* gap is
        // present rather than parsing the sentence — and the count says which
        // harnesses the events came from and over what window, which is what
        // separates "nothing was recorded" from "events exist and were not
        // counted".
        let mut verdict = build_verdict(green_aggregate(), Vec::new(), Vec::new());
        verdict.capability = CapabilityReport {
            adapter: "codex".to_owned(),
            tier: CapabilityTier::Observed,
            blind_spots: vec![BlindSpot {
                kind: BlindSpotKind::NoPreActionControl,
                explanation: BlindSpotKind::NoPreActionControl
                    .plain_explanation()
                    .to_owned(),
            }],
            pre_action_control: false,
            hook_failure: sure_core::capability::HookFailureBehaviour::NotApplicable,
            evidence: Some(CapabilityEvidence {
                harnesses: vec!["codex".to_owned()],
                events: 3,
                window: Some(EventWindow {
                    oldest: "2026-09-14T09:10:56.827Z".to_owned(),
                    newest: "2026-09-14T09:11:30.000Z".to_owned(),
                }),
                elsewhere: 1,
                truncated: false,
                unreadable: false,
            }),
        };

        let json = render_json_report(&verdict);
        let report = parse_report(&json);
        assert_eq!(report.capability.tier, 1);
        assert_eq!(report.capability.blind_spots, vec!["no_pre_action_control"]);
        let evidence = report
            .capability
            .evidence
            .expect("a counted tier carries its count");
        assert_eq!(evidence.events, 3);
        assert_eq!(evidence.harnesses, vec!["codex".to_owned()]);
        assert_eq!(evidence.elsewhere, 1);
        assert_eq!(
            evidence.window.map(|window| (window.oldest, window.newest)),
            Some((
                "2026-09-14T09:10:56.827Z".to_owned(),
                "2026-09-14T09:11:30.000Z".to_owned()
            ))
        );
        assert!(!evidence.truncated);
        assert!(!evidence.unreadable);
        // The sentence beside it is the same one the human report prints, so a
        // reader of either form has the same account of the same run.
        assert_eq!(report.capability.summary, verdict.capability.summary());

        let schema_text = include_str!("../../../schemas/report.schema.json");
        let schema = sure_protocol::schema::Schema::parse("report.schema.json", schema_text)
            .expect("schema is enforceable");
        let value: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
        let violations = schema.validate(&value);
        assert!(
            violations.is_empty(),
            "a report with a counted tier violates the schema it ships with: {violations:?}"
        );
    }

    #[test]
    fn a_report_that_counted_nothing_carries_no_evidence_field() {
        // The distinction is carried by the absence, so the absence has to be
        // real: a project with no store must not read as a project whose events
        // were counted and came to zero.
        let verdict = build_verdict(green_aggregate(), Vec::new(), Vec::new());
        let value: serde_json::Value =
            serde_json::from_str(&render_json_report(&verdict)).expect("valid JSON");
        assert!(
            value["capability"].get("evidence").is_none(),
            "a report that counted nothing claims a count: {}",
            value["capability"]
        );
        // And the blind spots are there all the same: the field is unconditional
        // because an empty list is an answer ("nothing was hidden from SURE at
        // this tier"), while a missing key would be a question.
        assert_eq!(
            value["capability"]["blind_spots"],
            serde_json::json!(["no_session_visibility", "no_pre_action_control"])
        );
    }

    #[test]
    fn report_validates_against_schema() {
        let schema_text = include_str!("../../../schemas/report.schema.json");
        let schema = sure_protocol::schema::Schema::parse("report.schema.json", schema_text)
            .expect("schema is enforceable");

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
                "lint check",
                Severity::ShouldFixFirst,
                false,
                "the linter crashed",
                fingerprint(),
            ),
        ];
        let verdict = build_verdict(
            green_aggregate(),
            vec![a_finding(Severity::MustFix)],
            not_checked,
        );
        let json = render_json_report(&verdict);
        let value: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
        let violations = schema.validate(&value);
        assert!(
            violations.is_empty(),
            "report violates schema: {violations:?}"
        );
    }

    #[test]
    fn control_characters_do_not_break_json_output() {
        let fp = fingerprint();
        let finding = FindingBuilder::new(
            AssessmentSource::DeterministicCheck,
            SeverityRationale::NonBlockingImprovement,
        )
        .title("Line\nbreak")
        .severity(Severity::CanFixLater)
        .explanation("Tab\there")
        .user_impact("Carriage\rreturn")
        .next_step("Bell\u{0007}character")
        .fingerprint(fp.clone())
        .build()
        .expect("valid finding");

        let verdict = build_verdict(green_aggregate(), vec![finding], Vec::new());
        let json = render_json_report(&verdict);

        // Compact JSON must not contain raw control bytes.
        assert!(
            !json.as_bytes().contains(&b'\n'),
            "compact JSON must not contain raw newline bytes: {json}"
        );
        assert!(
            !json.as_bytes().contains(&b'\t'),
            "compact JSON must not contain raw tab bytes: {json}"
        );
        assert!(
            !json.as_bytes().contains(&b'\r'),
            "compact JSON must not contain raw carriage-return bytes: {json}"
        );

        // The parsed report must not contain raw control characters.
        let report: JsonReport = serde_json::from_str(&json).expect("valid JSON");
        assert!(!report.findings[0].title.contains('\n'));
        assert!(!report.findings[0].what.contains('\t'));
        assert!(!report.findings[0].impact.contains('\r'));
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
    fn coverage_caveat_is_present_when_analysis_provider_is_disabled() {
        let not_checked = vec![CheckResult::not_run(
            CheckId::generate(),
            "semantic intent match",
            Severity::ShouldFixFirst,
            true,
            NotCheckedReason::AnalysisProviderDisabled,
            fingerprint(),
        )];
        let verdict = build_verdict(green_aggregate(), Vec::new(), not_checked);
        let json = render_json_report(&verdict);
        let report = parse_report(&json);
        assert!(
            report.coverage_caveat.is_some(),
            "coverage caveat should be present: {json}"
        );
        let caveat = report.coverage_caveat.unwrap();
        assert!(
            caveat.contains("Model-backed analysis is disabled"),
            "{caveat}"
        );
        assert!(caveat.contains("deterministic checks only"), "{caveat}");
    }

    #[test]
    fn coverage_caveat_is_absent_when_provider_is_not_disabled() {
        let not_checked = vec![CheckResult::not_run(
            CheckId::generate(),
            "run tests",
            Severity::MustFix,
            true,
            NotCheckedReason::ExecutionNotAuthorized,
            fingerprint(),
        )];
        let verdict = build_verdict(green_aggregate(), Vec::new(), not_checked);
        let json = render_json_report(&verdict);
        let report = parse_report(&json);
        assert!(
            report.coverage_caveat.is_none(),
            "coverage caveat should not appear: {json}"
        );
    }

    #[test]
    fn claim_checks_are_absent_from_json_when_empty() {
        let verdict = build_verdict(green_aggregate(), Vec::new(), Vec::new());
        let json = render_json_report(&verdict);
        let report = parse_report(&json);
        assert!(report.claim_checks.is_empty());
    }

    #[test]
    fn claim_checks_are_present_in_json_when_non_empty() {
        let verdict = ProjectVerdict {
            fingerprint: fingerprint(),
            aggregate: green_aggregate(),
            intent: ProjectIntent::empty(),
            capability: CapabilityReport::cli(),
            findings: Vec::new(),
            not_checked: Vec::new(),
            claim_checks: vec![a_claim(ClaimAssessment::Confirmed, "I ran the tests")],
        };
        let json = render_json_report(&verdict);
        let report = parse_report(&json);
        assert_eq!(report.claim_checks.len(), 1);
        assert_eq!(report.claim_checks[0].assessment, "Confirmed");
        assert_eq!(report.claim_checks[0].claim_text, "I ran the tests");
    }
}
