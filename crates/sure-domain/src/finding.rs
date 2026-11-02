//! Finding model: a material user-facing problem or uncertainty, anchored in
//! evidence and labelled with where the conclusion came from and why it was
//! assigned that severity.
//!
//! The rule this module enforces: a finding cannot silently claim to be the
//! product of a deterministic check when it is only a model assessment, and a
//! `must_fix` severity cannot be chosen without a rationale that matches it.

use serde::{Deserialize, Serialize};

use crate::evidence::{ClaimAssessment, Evidence, EvidenceClass};
use crate::ids::{FindingId, FingerprintId};
use crate::severity::Severity;
use crate::variants::variants;

/// Whether a finding is still standing.
///
/// The wire names are frozen by `schemas/finding.schema.json`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingStatus {
    /// Still a problem.
    Open,
    /// Later evidence showed the problem is gone.
    Resolved,
    /// The user decided to live with it.
    AcceptedRisk,
    /// SURE cannot tell whether the problem is still there.
    CannotConfirm,
}

variants!(FindingStatus {
    Open,
    Resolved,
    AcceptedRisk,
    CannotConfirm
});

impl FindingStatus {
    /// The stable wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Resolved => "resolved",
            Self::AcceptedRisk => "accepted_risk",
            Self::CannotConfirm => "cannot_confirm",
        }
    }

    /// Whether this finding still needs attention.
    ///
    /// `CannotConfirm` counts as needing attention: SURE does not close a
    /// finding merely because it can no longer see the problem.
    #[must_use]
    pub const fn needs_attention(self) -> bool {
        matches!(self, Self::Open | Self::CannotConfirm)
    }
}

/// Where the conclusion in a finding came from.
///
/// This is not the same as the class of each piece of evidence: a finding can
/// be raised because a claim was assessed, or because evidence was aggregated,
/// and the source keeps that provenance explicit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssessmentSource {
    /// Captured directly from the OS, a harness or the current project state.
    ObservedFact,
    /// A known command or tool produced a result bound to a project fingerprint.
    DeterministicCheck,
    /// Model interpretation grounded in specific anchors. May be wrong.
    ModelAssessment,
    /// Pattern-derived conclusion with uncertainty.
    Inference,
    /// The finding arose from checking an agent claim.
    ClaimAssessment(ClaimAssessment),
    /// Not enough evidence to say anything.
    Unknown,
}

impl AssessmentSource {
    /// The stable wire name for the source itself.
    ///
    /// For `ClaimAssessment`, the inner [`ClaimAssessment::as_str`] names the
    /// specific assessment outcome.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ObservedFact => "observed_fact",
            Self::DeterministicCheck => "deterministic_check",
            Self::ModelAssessment => "model_assessment",
            Self::Inference => "inference",
            Self::ClaimAssessment(_) => "claim_assessment",
            Self::Unknown => "unknown",
        }
    }

    /// Plain-language description of what this source means for the reader.
    #[must_use]
    pub const fn plain_description(self) -> &'static str {
        match self {
            Self::ObservedFact => "Captured directly from the project or its environment.",
            Self::DeterministicCheck => {
                "Produced by a deterministic check against the project state."
            }
            Self::ModelAssessment => "A model interpretation grounded in anchors; it may be wrong.",
            Self::Inference => "A pattern-derived conclusion with uncertainty.",
            Self::ClaimAssessment(_) => "Raised from checking a claim made by a coding agent.",
            Self::Unknown => "The source of the conclusion is not known.",
        }
    }

    /// Whether this source is strong enough to justify `severity` on its own.
    ///
    /// `MustFix` is only supported by observed facts and deterministic checks,
    /// and by a claim assessment that found the claim was contradicted. A
    /// `must_fix` finding backed only by a model opinion, an inference, an
    /// unchecked claim or no source at all would be an overclaim.
    #[must_use]
    pub const fn supports_severity(self, severity: Severity) -> bool {
        if !severity.blocks_hand_off() {
            return true;
        }
        match self {
            Self::ObservedFact | Self::DeterministicCheck => true,
            Self::ClaimAssessment(ClaimAssessment::Contradicted) => true,
            Self::ModelAssessment
            | Self::Inference
            | Self::ClaimAssessment(
                ClaimAssessment::Confirmed
                | ClaimAssessment::CannotConfirm
                | ClaimAssessment::NotCheckable,
            )
            | Self::Unknown => false,
        }
    }
}

/// Why a finding was assigned its severity.
///
/// The rationale and the severity cannot silently disagree: each severity has
/// exactly one rationale, and [`Self::for_severity`] is the only way to derive
/// it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SeverityRationale {
    /// The finding blocks hand-off or publication.
    BlocksHandOff,
    /// A material reliability or quality risk.
    ReliabilityOrQualityRisk,
    /// A non-blocking improvement.
    NonBlockingImprovement,
    /// Informational only.
    Informational,
}

variants!(
    /// Every rationale.
    SeverityRationale {
        BlocksHandOff,
        ReliabilityOrQualityRisk,
        NonBlockingImprovement,
        Informational
    }
);

impl SeverityRationale {
    /// The stable wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BlocksHandOff => "blocks_hand_off",
            Self::ReliabilityOrQualityRisk => "reliability_or_quality_risk",
            Self::NonBlockingImprovement => "non_blocking_improvement",
            Self::Informational => "informational",
        }
    }

    /// Plain-language description of what the rationale means.
    #[must_use]
    pub const fn plain_description(self) -> &'static str {
        match self {
            Self::BlocksHandOff => "This finding blocks hand-off or publication.",
            Self::ReliabilityOrQualityRisk => {
                "This is a material reliability or quality risk that should be fixed first."
            }
            Self::NonBlockingImprovement => "This is a non-blocking improvement.",
            Self::Informational => "This finding is informational only.",
        }
    }

    /// The rationale that matches `severity`, if the two are consistent.
    ///
    /// Returns `None` only for an input that has no matching rationale; in
    /// practice every [`Severity`] maps to exactly one.
    #[must_use]
    pub const fn for_severity(severity: Severity) -> Option<Self> {
        match severity {
            Severity::MustFix => Some(Self::BlocksHandOff),
            Severity::ShouldFixFirst => Some(Self::ReliabilityOrQualityRisk),
            Severity::CanFixLater => Some(Self::NonBlockingImprovement),
            Severity::Note => Some(Self::Informational),
        }
    }
}

/// A material user-facing problem or uncertainty, anchored in evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    /// Identity of the finding.
    pub id: FindingId,
    /// Short title, written for someone who is not a programmer.
    pub title: String,
    /// How serious it is.
    pub severity: Severity,
    /// Whether it is still standing.
    pub status: FindingStatus,
    /// What is wrong, in plain language.
    pub explanation: String,
    /// What it means for the person reading the report.
    pub user_impact: String,
    /// What SURE thinks should happen next.
    pub next_step: String,
    /// The evidence that grounds this finding.
    pub evidence: Vec<Evidence>,
    /// Which project state the finding was raised against.
    pub fingerprint: FingerprintId,
    /// Detail the user can expand, already redacted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub technical_details: Option<serde_json::Value>,
    /// Where the conclusion came from.
    pub assessment_source: AssessmentSource,
    /// Why this severity was chosen.
    pub severity_rationale: SeverityRationale,
}

impl Finding {
    /// Whether this finding is honest about its own basis.
    ///
    /// A `must_fix` finding needs an assessment source that can support that
    /// severity, and at least one anchor that is not a model opinion or a guess.
    #[must_use]
    pub fn is_grounded(&self) -> bool {
        if self.evidence.is_empty() {
            return false;
        }
        if !self.assessment_source.supports_severity(self.severity) {
            return false;
        }
        if !self.severity.blocks_hand_off() {
            return true;
        }
        self.evidence
            .iter()
            .any(|e| e.class.can_alone_support_must_fix() && e.anchor.is_checkable())
    }

    /// The strongest evidence class behind this finding.
    #[must_use]
    pub fn strongest_evidence_class(&self) -> EvidenceClass {
        self.evidence
            .iter()
            .map(|e| e.class)
            .min_by_key(|c| c.truth_rank())
            .unwrap_or(EvidenceClass::Unknown)
    }

    /// Whether a person may accept this finding as a risk (ADR 0019).
    ///
    /// **A finding SURE settled with evidence a check could carry is a defect to
    /// fix, not a risk to accept.** Accepting is an answer to SURE's honest
    /// uncertainty — the candidate a scanner inferred, the model opinion — and
    /// never to a failing test, a checker error or a check that did not run. So
    /// this is false as soon as one piece of evidence could alone carry a
    /// `must_fix` ([`EvidenceClass::can_alone_support_must_fix`]): that is the
    /// same line [`Self::is_grounded`] draws for blocking severities, used here
    /// for the opposite direction — what may not be waved away.
    ///
    /// A finding with no evidence at all cannot be keyed to anything and is not
    /// acknowledgeable either.
    #[must_use]
    pub fn can_be_acknowledged(&self) -> bool {
        !self.evidence.is_empty()
            && !self
                .evidence
                .iter()
                .any(|e| e.class.can_alone_support_must_fix())
    }
}

/// What went wrong when a [`FindingBuilder`] could not produce a finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FindingBuildError {
    /// A required field was not supplied.
    MissingField(&'static str),
    /// The chosen severity and rationale do not match.
    SeverityRationaleMismatch {
        /// The severity that was supplied.
        severity: Severity,
        /// The rationale that was supplied.
        rationale: SeverityRationale,
    },
    /// The assessment source cannot support this severity on its own.
    UnsupportedSeverityForSource {
        /// The severity that was supplied.
        severity: Severity,
        /// The source that was supplied.
        source: AssessmentSource,
    },
}

impl std::fmt::Display for FindingBuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingField(field) => write!(f, "missing required field: {field}"),
            Self::SeverityRationaleMismatch {
                severity,
                rationale,
            } => write!(
                f,
                "severity {:?} does not match rationale {:?}",
                severity.as_str(),
                rationale.as_str()
            ),
            Self::UnsupportedSeverityForSource { severity, source } => write!(
                f,
                "source {:?} cannot support severity {:?}",
                source.as_str(),
                severity.as_str()
            ),
        }
    }
}

impl std::error::Error for FindingBuildError {}

/// Builds a [`Finding`] while enforcing required provenance fields.
///
/// The assessment source and severity rationale are required at construction
/// time; other fields have sensible defaults or are checked at build time.
#[derive(Debug, Clone)]
pub struct FindingBuilder {
    assessment_source: AssessmentSource,
    severity_rationale: SeverityRationale,
    id: Option<FindingId>,
    title: Option<String>,
    severity: Option<Severity>,
    status: Option<FindingStatus>,
    explanation: Option<String>,
    user_impact: Option<String>,
    next_step: Option<String>,
    evidence: Vec<Evidence>,
    fingerprint: Option<FingerprintId>,
    technical_details: Option<serde_json::Value>,
}

impl FindingBuilder {
    /// Start a finding with the two provenance fields the acceptance criterion
    /// requires.
    #[must_use]
    pub fn new(assessment_source: AssessmentSource, severity_rationale: SeverityRationale) -> Self {
        Self {
            assessment_source,
            severity_rationale,
            id: None,
            title: None,
            severity: None,
            status: None,
            explanation: None,
            user_impact: None,
            next_step: None,
            evidence: Vec::new(),
            fingerprint: None,
            technical_details: None,
        }
    }

    /// Set the finding identifier.
    #[must_use]
    pub fn id(mut self, id: FindingId) -> Self {
        self.id = Some(id);
        self
    }

    /// Set the title.
    #[must_use]
    pub fn title(mut self, title: impl Into<String>) -> Self {
        self.title = Some(title.into());
        self
    }

    /// Set the severity.
    #[must_use]
    pub fn severity(mut self, severity: Severity) -> Self {
        self.severity = Some(severity);
        self
    }

    /// Set the status.
    #[must_use]
    pub fn status(mut self, status: FindingStatus) -> Self {
        self.status = Some(status);
        self
    }

    /// Set the explanation.
    #[must_use]
    pub fn explanation(mut self, explanation: impl Into<String>) -> Self {
        self.explanation = Some(explanation.into());
        self
    }

    /// Set the user impact.
    #[must_use]
    pub fn user_impact(mut self, user_impact: impl Into<String>) -> Self {
        self.user_impact = Some(user_impact.into());
        self
    }

    /// Set the next step.
    #[must_use]
    pub fn next_step(mut self, next_step: impl Into<String>) -> Self {
        self.next_step = Some(next_step.into());
        self
    }

    /// Set the evidence.
    #[must_use]
    pub fn evidence(mut self, evidence: impl IntoIterator<Item = Evidence>) -> Self {
        self.evidence = evidence.into_iter().collect();
        self
    }

    /// Set the project fingerprint.
    #[must_use]
    pub fn fingerprint(mut self, fingerprint: FingerprintId) -> Self {
        self.fingerprint = Some(fingerprint);
        self
    }

    /// Set the technical details.
    #[must_use]
    pub fn technical_details(mut self, technical_details: serde_json::Value) -> Self {
        self.technical_details = Some(technical_details);
        self
    }

    /// Build the finding, checking that severity, rationale and source agree.
    ///
    /// # Errors
    ///
    /// Returns [`FindingBuildError::MissingField`] when `severity`, `title` or
    /// `fingerprint` were not supplied; [`FindingBuildError::SeverityRationaleMismatch`]
    /// when the severity and rationale disagree; or
    /// [`FindingBuildError::UnsupportedSeverityForSource`] when the assessment
    /// source cannot support the chosen severity on its own.
    pub fn build(self) -> Result<Finding, FindingBuildError> {
        let severity = self
            .severity
            .ok_or(FindingBuildError::MissingField("severity"))?;
        let title = self.title.ok_or(FindingBuildError::MissingField("title"))?;
        let fingerprint = self
            .fingerprint
            .ok_or(FindingBuildError::MissingField("fingerprint"))?;

        if SeverityRationale::for_severity(severity) != Some(self.severity_rationale) {
            return Err(FindingBuildError::SeverityRationaleMismatch {
                severity,
                rationale: self.severity_rationale,
            });
        }

        if !self.assessment_source.supports_severity(severity) {
            return Err(FindingBuildError::UnsupportedSeverityForSource {
                severity,
                source: self.assessment_source,
            });
        }

        Ok(Finding {
            id: self.id.unwrap_or_else(FindingId::generate),
            title,
            severity,
            status: self.status.unwrap_or(FindingStatus::Open),
            explanation: self.explanation.unwrap_or_default(),
            user_impact: self.user_impact.unwrap_or_default(),
            next_step: self.next_step.unwrap_or_default(),
            evidence: self.evidence,
            fingerprint,
            technical_details: self.technical_details,
            assessment_source: self.assessment_source,
            severity_rationale: self.severity_rationale,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::evidence::{AnchorSubject, EvidenceAnchor};

    fn anchor() -> EvidenceAnchor {
        EvidenceAnchor::new(AnchorSubject::File, "src/x.rs", "line 1")
    }

    fn fingerprint() -> FingerprintId {
        FingerprintId::generate()
    }

    fn evidence(class: EvidenceClass) -> Evidence {
        Evidence::new(
            class,
            "summary",
            anchor(),
            Some(fingerprint()),
            Severity::MustFix,
        )
    }

    fn builder() -> FindingBuilder {
        FindingBuilder::new(
            AssessmentSource::ObservedFact,
            SeverityRationale::BlocksHandOff,
        )
        .title("Payment looks successful but nothing is charged")
        .severity(Severity::MustFix)
        .fingerprint(fingerprint())
    }

    #[test]
    fn finding_status_wire_names_match_the_schema() {
        for status in [
            FindingStatus::Open,
            FindingStatus::Resolved,
            FindingStatus::AcceptedRisk,
            FindingStatus::CannotConfirm,
        ] {
            let json = serde_json::to_string(&status).expect("serialize");
            assert_eq!(json, format!("\"{}\"", status.as_str()));
        }
    }

    #[test]
    fn an_inferred_candidate_may_be_acknowledged() {
        let finding = builder()
            .evidence(vec![evidence(EvidenceClass::Inference)])
            .build()
            .expect("valid finding");
        assert!(finding.can_be_acknowledged());
    }

    #[test]
    fn a_model_opinion_may_be_acknowledged() {
        let finding = FindingBuilder::new(
            AssessmentSource::ModelAssessment,
            SeverityRationale::for_severity(Severity::ShouldFixFirst)
                .expect("a rationale for should_fix_first"),
        )
        .title("Model assessment: something looks incomplete")
        .severity(Severity::ShouldFixFirst)
        .evidence(vec![Evidence::new(
            EvidenceClass::ModelAssessment,
            "summary",
            EvidenceAnchor::model_only("a candidate"),
            Some(fingerprint()),
            Severity::ShouldFixFirst,
        )])
        .fingerprint(fingerprint())
        .build()
        .expect("valid finding");
        assert!(finding.can_be_acknowledged());
    }

    #[test]
    fn a_deterministic_failure_may_not_be_acknowledged() {
        let finding = builder()
            .evidence(vec![evidence(EvidenceClass::DeterministicCheck)])
            .build()
            .expect("valid finding");
        assert!(!finding.can_be_acknowledged());
    }

    #[test]
    fn an_observed_fact_may_not_be_acknowledged() {
        // A check that did not run is evidence about what the run did, and
        // accepting it would accept an untested project.
        let finding = builder()
            .evidence(vec![evidence(EvidenceClass::ObservedFact)])
            .build()
            .expect("valid finding");
        assert!(!finding.can_be_acknowledged());
    }

    #[test]
    fn a_finding_with_no_evidence_may_not_be_acknowledged() {
        let mut finding = builder()
            .evidence(vec![evidence(EvidenceClass::Inference)])
            .build()
            .expect("valid finding");
        finding.evidence.clear();
        assert!(!finding.can_be_acknowledged());
    }

    #[test]
    fn observed_fact_with_blocks_hand_off_is_grounded() {
        let finding = builder()
            .evidence(vec![evidence(EvidenceClass::ObservedFact)])
            .build()
            .expect("valid finding");
        assert!(finding.is_grounded());
        assert_eq!(finding.assessment_source, AssessmentSource::ObservedFact);
        assert_eq!(finding.severity_rationale, SeverityRationale::BlocksHandOff);
    }

    #[test]
    fn must_fix_backed_only_by_model_assessment_is_rejected() {
        let result = FindingBuilder::new(
            AssessmentSource::ModelAssessment,
            SeverityRationale::BlocksHandOff,
        )
        .title("t")
        .severity(Severity::MustFix)
        .fingerprint(fingerprint())
        .evidence(vec![evidence(EvidenceClass::ModelAssessment)])
        .build();
        assert!(
            matches!(
                result,
                Err(FindingBuildError::UnsupportedSeverityForSource { .. })
            ),
            "expected unsupported severity error, got {result:?}"
        );
    }

    #[test]
    fn must_fix_backed_only_by_inference_is_rejected() {
        let result = FindingBuilder::new(
            AssessmentSource::Inference,
            SeverityRationale::BlocksHandOff,
        )
        .title("t")
        .severity(Severity::MustFix)
        .fingerprint(fingerprint())
        .build();
        assert!(
            matches!(
                result,
                Err(FindingBuildError::UnsupportedSeverityForSource { .. })
            ),
            "expected unsupported severity error, got {result:?}"
        );
    }

    #[test]
    fn must_fix_backed_only_by_unknown_is_rejected() {
        let result =
            FindingBuilder::new(AssessmentSource::Unknown, SeverityRationale::BlocksHandOff)
                .title("t")
                .severity(Severity::MustFix)
                .fingerprint(fingerprint())
                .build();
        assert!(
            matches!(
                result,
                Err(FindingBuildError::UnsupportedSeverityForSource { .. })
            ),
            "expected unsupported severity error, got {result:?}"
        );
    }

    #[test]
    fn contradicted_claim_can_support_must_fix() {
        let finding = FindingBuilder::new(
            AssessmentSource::ClaimAssessment(ClaimAssessment::Contradicted),
            SeverityRationale::BlocksHandOff,
        )
        .title("t")
        .severity(Severity::MustFix)
        .fingerprint(fingerprint())
        .evidence(vec![evidence(EvidenceClass::ObservedFact)])
        .build()
        .expect("valid finding");
        assert!(finding.is_grounded());
    }

    #[test]
    fn confirmed_claim_cannot_support_must_fix() {
        let result = FindingBuilder::new(
            AssessmentSource::ClaimAssessment(ClaimAssessment::Confirmed),
            SeverityRationale::BlocksHandOff,
        )
        .title("t")
        .severity(Severity::MustFix)
        .fingerprint(fingerprint())
        .build();
        assert!(
            matches!(
                result,
                Err(FindingBuildError::UnsupportedSeverityForSource { .. })
            ),
            "expected unsupported severity error, got {result:?}"
        );
    }

    #[test]
    fn cannot_confirm_claim_cannot_support_must_fix() {
        let result = FindingBuilder::new(
            AssessmentSource::ClaimAssessment(ClaimAssessment::CannotConfirm),
            SeverityRationale::BlocksHandOff,
        )
        .title("t")
        .severity(Severity::MustFix)
        .fingerprint(fingerprint())
        .build();
        assert!(
            matches!(
                result,
                Err(FindingBuildError::UnsupportedSeverityForSource { .. })
            ),
            "expected unsupported severity error, got {result:?}"
        );
    }

    #[test]
    fn not_checkable_claim_cannot_support_must_fix() {
        let result = FindingBuilder::new(
            AssessmentSource::ClaimAssessment(ClaimAssessment::NotCheckable),
            SeverityRationale::BlocksHandOff,
        )
        .title("t")
        .severity(Severity::MustFix)
        .fingerprint(fingerprint())
        .build();
        assert!(
            matches!(
                result,
                Err(FindingBuildError::UnsupportedSeverityForSource { .. })
            ),
            "expected unsupported severity error, got {result:?}"
        );
    }

    #[test]
    fn mismatched_severity_and_rationale_are_rejected() {
        let result = FindingBuilder::new(
            AssessmentSource::DeterministicCheck,
            SeverityRationale::Informational,
        )
        .title("t")
        .severity(Severity::MustFix)
        .fingerprint(fingerprint())
        .build();
        assert!(
            matches!(
                result,
                Err(FindingBuildError::SeverityRationaleMismatch { .. })
            ),
            "expected rationale mismatch error, got {result:?}"
        );
    }

    #[test]
    fn assessment_source_wire_names_are_frozen() {
        assert_eq!(AssessmentSource::ObservedFact.as_str(), "observed_fact");
        assert_eq!(
            AssessmentSource::DeterministicCheck.as_str(),
            "deterministic_check"
        );
        assert_eq!(
            AssessmentSource::ModelAssessment.as_str(),
            "model_assessment"
        );
        assert_eq!(AssessmentSource::Inference.as_str(), "inference");
        assert_eq!(
            AssessmentSource::ClaimAssessment(ClaimAssessment::Confirmed).as_str(),
            "claim_assessment"
        );
        assert_eq!(AssessmentSource::Unknown.as_str(), "unknown");
    }

    #[test]
    fn severity_rationale_wire_names_are_frozen() {
        assert_eq!(SeverityRationale::BlocksHandOff.as_str(), "blocks_hand_off");
        assert_eq!(
            SeverityRationale::ReliabilityOrQualityRisk.as_str(),
            "reliability_or_quality_risk"
        );
        assert_eq!(
            SeverityRationale::NonBlockingImprovement.as_str(),
            "non_blocking_improvement"
        );
        assert_eq!(SeverityRationale::Informational.as_str(), "informational");
    }

    #[test]
    fn severity_rationale_for_severity_is_one_to_one() {
        assert_eq!(
            SeverityRationale::for_severity(Severity::MustFix),
            Some(SeverityRationale::BlocksHandOff)
        );
        assert_eq!(
            SeverityRationale::for_severity(Severity::ShouldFixFirst),
            Some(SeverityRationale::ReliabilityOrQualityRisk)
        );
        assert_eq!(
            SeverityRationale::for_severity(Severity::CanFixLater),
            Some(SeverityRationale::NonBlockingImprovement)
        );
        assert_eq!(
            SeverityRationale::for_severity(Severity::Note),
            Some(SeverityRationale::Informational)
        );
    }

    #[test]
    fn serialization_round_trip_preserves_fields() {
        let original = builder()
            .status(FindingStatus::Open)
            .explanation("the code only prints a line")
            .user_impact("people believe a message was delivered")
            .next_step("call the provider")
            .evidence(vec![evidence(EvidenceClass::DeterministicCheck)])
            .technical_details(serde_json::json!({"file": "src/x.rs"}))
            .build()
            .expect("valid finding");

        let text = serde_json::to_string(&original).expect("serialize");
        let back: Finding = serde_json::from_str(&text).expect("deserialize");
        assert_eq!(back, original);

        let again = serde_json::to_string(&back).expect("re-serialize");
        assert_eq!(again, text);
    }

    #[test]
    fn model_only_finding_is_grounded_at_note_but_not_must_fix() {
        let note_finding = FindingBuilder::new(
            AssessmentSource::ModelAssessment,
            SeverityRationale::Informational,
        )
        .title("Model-only uncertainty")
        .severity(Severity::Note)
        .status(FindingStatus::Open)
        .explanation("The model inferred something but cannot point to a project location.")
        .fingerprint(fingerprint())
        .evidence(vec![Evidence::new(
            EvidenceClass::ModelAssessment,
            "inferred from prompt",
            EvidenceAnchor::model_only("model-only conclusion"),
            Some(fingerprint()),
            Severity::Note,
        )])
        .build()
        .expect("valid note finding with model anchor");
        assert!(note_finding.is_grounded());
        assert!(
            note_finding
                .evidence
                .iter()
                .any(|e| e.anchor.subject == AnchorSubject::Model),
            "model-only finding must carry a Model anchor"
        );

        let must_fix_result = FindingBuilder::new(
            AssessmentSource::ModelAssessment,
            SeverityRationale::BlocksHandOff,
        )
        .title("t")
        .severity(Severity::MustFix)
        .fingerprint(fingerprint())
        .evidence(vec![Evidence::new(
            EvidenceClass::ModelAssessment,
            "inferred from prompt",
            EvidenceAnchor::model_only("model-only conclusion"),
            Some(fingerprint()),
            Severity::MustFix,
        )])
        .build();
        assert!(
            matches!(
                must_fix_result,
                Err(FindingBuildError::UnsupportedSeverityForSource { .. })
            ),
            "expected unsupported severity for model-only must_fix, got {must_fix_result:?}"
        );
    }

    #[test]
    fn builder_requires_title_severity_and_fingerprint() {
        let missing_title = FindingBuilder::new(
            AssessmentSource::ObservedFact,
            SeverityRationale::BlocksHandOff,
        )
        .severity(Severity::MustFix)
        .fingerprint(fingerprint())
        .build();
        assert!(
            matches!(missing_title, Err(FindingBuildError::MissingField("title"))),
            "got {missing_title:?}"
        );

        let missing_severity = FindingBuilder::new(
            AssessmentSource::ObservedFact,
            SeverityRationale::BlocksHandOff,
        )
        .title("t")
        .fingerprint(fingerprint())
        .build();
        assert!(
            matches!(
                missing_severity,
                Err(FindingBuildError::MissingField("severity"))
            ),
            "got {missing_severity:?}"
        );

        let missing_fingerprint = FindingBuilder::new(
            AssessmentSource::ObservedFact,
            SeverityRationale::BlocksHandOff,
        )
        .title("t")
        .severity(Severity::MustFix)
        .build();
        assert!(
            matches!(
                missing_fingerprint,
                Err(FindingBuildError::MissingField("fingerprint"))
            ),
            "got {missing_fingerprint:?}"
        );
    }
}
