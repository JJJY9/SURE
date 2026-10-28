//! Repair-contract generation from grounded findings.
//!
//! A repair contract is only as honest as the finding it comes from. This module
//! refuses to turn an ungrounded finding into a contract, and every acceptance
//! condition it produces is tied to an observable check or anchor rather than to
//! an invented fact.

use serde::{Deserialize, Serialize};

use crate::evidence::EvidenceClass;
use crate::finding::Finding;
use crate::ids::{CheckId, RepairId};
use crate::vocabulary::RepairContract;

/// The version of the harness-neutral repair envelope format.
///
/// Bumping this means the wrapper around a [`RepairContract`] changed in a way
/// that readers need to know about. The contract inside keeps its own identity.
pub const REPAIR_ENVELOPE_VERSION: u32 = 1;

/// A harness-neutral wrapper around a [`RepairContract`].
///
/// Adapters for Claude, Cursor, Codex and any future harness receive the same
/// contract; the envelope only adds delivery metadata. The `target_harness`
/// field is optional: when present it names the adapter this envelope was
/// addressed to, but the contract itself is unchanged.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepairEnvelope {
    /// Envelope format version.
    pub version: u32,
    /// The bounded repair contract any adapter can consume.
    pub contract: RepairContract,
    /// Optional adapter this envelope is addressed to. `None` means the envelope
    /// is harness-neutral.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_harness: Option<String>,
}

impl RepairEnvelope {
    /// Wrap a contract in a neutral envelope.
    #[must_use]
    pub fn new(contract: RepairContract) -> Self {
        Self {
            version: REPAIR_ENVELOPE_VERSION,
            contract,
            target_harness: None,
        }
    }

    /// Address the envelope to a specific harness adapter without changing the
    /// contract.
    #[must_use]
    pub fn for_harness(mut self, harness: impl Into<String>) -> Self {
        self.target_harness = Some(harness.into());
        self
    }

    /// The contract every adapter ultimately works from.
    #[must_use]
    pub fn into_contract(self) -> RepairContract {
        self.contract
    }
}

/// Why a repair contract could not be generated from a finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RepairFromFindingError {
    /// The finding is not grounded in checkable evidence, so a contract would
    /// have to invent facts.
    NotGrounded,
    /// No checks were supplied to re-run after the repair, so SURE could not
    /// observe whether the fix worked.
    NoRechecks,
}

impl std::fmt::Display for RepairFromFindingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotGrounded => write!(
                f,
                "the finding is not grounded in checkable evidence, so a repair contract cannot be generated"
            ),
            Self::NoRechecks => write!(
                f,
                "at least one check must be re-run after the repair so SURE can observe the result"
            ),
        }
    }
}

impl std::error::Error for RepairFromFindingError {}

impl RepairContract {
    /// Build a repair contract from a grounded finding and the checks to re-run.
    ///
    /// Returns an error if the finding is not grounded or if no re-checks are
    /// supplied. The contract copies the finding's own evidence rather than
    /// inventing new facts, and the acceptance criteria are phrased as
    /// observable re-check outcomes.
    ///
    /// The `recheck` list should contain the checks that can observe whether the
    /// fix worked. P9-T004 is responsible for selecting the right checks.
    pub fn from_finding(
        finding: &Finding,
        recheck: Vec<CheckId>,
    ) -> Result<Self, RepairFromFindingError> {
        if !finding.is_grounded() {
            return Err(RepairFromFindingError::NotGrounded);
        }
        if recheck.is_empty() {
            return Err(RepairFromFindingError::NoRechecks);
        }

        let required_fix = if finding.next_step.trim().is_empty() {
            vec![format!("Address the finding: {}", finding.title)]
        } else {
            vec![finding.next_step.clone()]
        };

        let acceptance = observable_acceptance(finding, &recheck);
        let forbidden_shortcuts = forbidden_shortcuts_for(finding);

        Ok(Self {
            id: RepairId::generate(),
            issue_id: finding.id.clone(),
            problem: finding.title.clone(),
            why_it_matters: finding.user_impact.clone(),
            required_fix,
            preserve: Vec::new(),
            acceptance,
            recheck,
            forbidden_shortcuts,
            evidence: finding.evidence.clone(),
        })
    }

    /// Convenience constructor when the finding's own id is the only issue id
    /// needed and a single check is enough to verify the repair.
    pub fn from_finding_with_one_check(
        finding: &Finding,
        recheck: CheckId,
    ) -> Result<Self, RepairFromFindingError> {
        Self::from_finding(finding, vec![recheck])
    }
}

fn observable_acceptance(finding: &Finding, recheck: &[CheckId]) -> Vec<String> {
    let mut conditions = Vec::new();

    if recheck.len() == 1 {
        conditions.push(format!(
            "Re-run check {} and confirm it passes for {}.",
            recheck[0].as_str(),
            finding.title
        ));
    } else {
        let list = recheck
            .iter()
            .map(|id| id.as_str().to_owned())
            .collect::<Vec<_>>()
            .join(", ");
        conditions.push(format!(
            "Re-run checks {} and confirm they all pass for {}.",
            list, finding.title
        ));
    }

    // If the strongest evidence is an observed fact with a concrete anchor,
    // add an acceptance condition that points at the same anchor so the fix
    // cannot be declared done without touching the actual location.
    if let Some(strongest) = finding.evidence.iter().min_by_key(|e| e.class.truth_rank())
        && strongest.class == EvidenceClass::ObservedFact
        && strongest.anchor.is_checkable()
    {
        conditions.push(format!(
            "The fix is visible at {} ({}).",
            strongest.anchor.location, strongest.anchor.locator
        ));
    }

    conditions
}

/// Whether a repair for this finding has to change the project's product code.
///
/// A finding whose strongest evidence is a [`EvidenceClass::DeterministicCheck`]
/// is one SURE observed by running a check: the check ran, and the project did
/// not satisfy it. What makes a check pass again is a change to the behaviour
/// the check observed, and the shortcut that passes it without changing that
/// behaviour is editing the check's own test until it agrees with the code.
///
/// This is the one predicate behind that judgement, and it has two readers:
/// [`forbidden_shortcuts_for`], which writes the rule into the repair contract,
/// and `sure_core::recheck_lifecycle`, which refuses to close such a finding
/// when every file recorded as written since the earlier run is a test file.
/// Two readers, one rule, so the contract cannot forbid something the re-check
/// would accept.
#[must_use]
pub fn requires_production_change(finding: &Finding) -> bool {
    finding.strongest_evidence_class() == EvidenceClass::DeterministicCheck
}

fn forbidden_shortcuts_for(finding: &Finding) -> Vec<String> {
    let mut shortcuts = Vec::new();

    if requires_production_change(finding) {
        shortcuts.push(String::from(
            "Changing only the test or assertion so it passes without fixing the underlying behavior.",
        ));
    }

    if finding.strongest_evidence_class() == EvidenceClass::ObservedFact {
        shortcuts.push(String::from(
            "Hiding the symptom in the observed output without fixing the code path that produces it.",
        ));
    }

    // A model-only or inferred finding should not be used to demand a specific
    // code change, but by the time we generate a contract the finding has
    // already been required to be grounded, so this is a defense-in-depth note.
    if !finding.is_grounded() {
        shortcuts.push(String::from(
            "Treating an ungrounded suggestion as a confirmed defect and changing code based only on that suggestion.",
        ));
    }

    shortcuts
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::evidence::{
        AnchorSubject, ClaimAssessment, Evidence, EvidenceAnchor, EvidenceClass,
    };
    use crate::finding::{AssessmentSource, FindingBuilder, FindingStatus, SeverityRationale};
    use crate::ids::{CheckId, FingerprintId};
    use crate::severity::Severity;

    fn fingerprint() -> FingerprintId {
        FingerprintId::parse("fp_01j2m8q5aaaabbbbccccddddee").unwrap()
    }

    fn grounded_finding() -> Finding {
        FindingBuilder::new(
            AssessmentSource::DeterministicCheck,
            SeverityRationale::BlocksHandOff,
        )
        .id(crate::ids::FindingId::generate())
        .title("Email is reported as sent but nothing is sent")
        .severity(Severity::MustFix)
        .status(FindingStatus::Open)
        .explanation("The app says the email went out, and the code only prints a line.")
        .user_impact("People believe a message was delivered when it was not.")
        .next_step("Call the configured email provider on the real send path.")
        .evidence(vec![Evidence::new(
            EvidenceClass::DeterministicCheck,
            "the send path returns before the provider is called",
            EvidenceAnchor::new(AnchorSubject::File, "src/email/send.rs", "line 42"),
            Some(fingerprint()),
            Severity::MustFix,
        )])
        .fingerprint(fingerprint())
        .build()
        .expect("fixture finding is valid")
    }

    #[test]
    fn a_grounded_finding_becomes_an_actionable_contract() {
        let finding = grounded_finding();
        let recheck = CheckId::generate();
        let contract = RepairContract::from_finding_with_one_check(&finding, recheck.clone())
            .expect("contract is generated");

        assert_eq!(contract.issue_id, finding.id);
        assert_eq!(contract.problem, finding.title);
        assert_eq!(contract.why_it_matters, finding.user_impact);
        assert_eq!(contract.required_fix, vec![finding.next_step]);
        assert_eq!(contract.recheck, vec![recheck]);
        assert!(!contract.acceptance.is_empty());
        assert!(contract.is_actionable());
    }

    #[test]
    fn an_ungrounded_finding_is_rejected() {
        let mut finding = grounded_finding();
        finding.evidence.clear();
        assert!(!finding.is_grounded());

        let result = RepairContract::from_finding_with_one_check(&finding, CheckId::generate());
        assert_eq!(result.unwrap_err(), RepairFromFindingError::NotGrounded);
    }

    #[test]
    fn a_contract_without_rechecks_is_rejected() {
        let finding = grounded_finding();
        let result = RepairContract::from_finding(&finding, Vec::new());
        assert_eq!(result.unwrap_err(), RepairFromFindingError::NoRechecks);
    }

    #[test]
    fn acceptance_conditions_are_observable() {
        let finding = grounded_finding();
        let recheck = vec![CheckId::generate(), CheckId::generate()];
        let contract =
            RepairContract::from_finding(&finding, recheck.clone()).expect("contract is generated");

        for condition in &contract.acceptance {
            assert!(
                condition.contains("Re-run") || condition.contains("visible at"),
                "acceptance must be observable: {condition}"
            );
        }
        let joined = contract.acceptance.join(" ");
        assert!(
            joined.contains(recheck[0].as_str()) && joined.contains(recheck[1].as_str()),
            "acceptance must name the checks to re-run"
        );
    }

    #[test]
    fn no_invented_evidence_is_added() {
        let finding = grounded_finding();
        let contract = RepairContract::from_finding_with_one_check(&finding, CheckId::generate())
            .expect("contract is generated");
        assert_eq!(contract.evidence.len(), finding.evidence.len());
        assert_eq!(contract.evidence, finding.evidence);
    }

    #[test]
    fn forbidden_shortcuts_warn_against_fake_fixes() {
        let finding = grounded_finding();
        let contract = RepairContract::from_finding_with_one_check(&finding, CheckId::generate())
            .expect("contract is generated");
        assert!(
            contract
                .forbidden_shortcuts
                .iter()
                .any(|s| s.contains("test")),
            "deterministic-check findings should warn against test-only fixes"
        );
    }

    /// One predicate decides both the contract clause and what the re-check
    /// accepts, so a contract cannot forbid a shortcut the re-check would accept.
    #[test]
    fn only_a_check_failure_needs_a_production_change() {
        let check = grounded_finding();
        assert!(requires_production_change(&check));

        let mut observed = grounded_finding();
        observed.evidence[0].class = EvidenceClass::ObservedFact;
        assert!(
            !requires_production_change(&observed),
            "an observed fact is not a failed check and carries no test-change clause"
        );

        let clause = |finding: &Finding| {
            let contract =
                RepairContract::from_finding_with_one_check(finding, CheckId::generate())
                    .expect("contract is generated");
            contract
                .forbidden_shortcuts
                .iter()
                .any(|s| s.contains("test or assertion"))
        };
        assert_eq!(clause(&check), requires_production_change(&check));
        assert_eq!(clause(&observed), requires_production_change(&observed));
    }

    #[test]
    fn claim_assessment_contradicted_can_generate_contract() {
        let finding = FindingBuilder::new(
            AssessmentSource::ClaimAssessment(ClaimAssessment::Contradicted),
            SeverityRationale::BlocksHandOff,
        )
        .id(crate::ids::FindingId::generate())
        .title("Agent claimed tests pass but a test failure was recorded")
        .severity(Severity::MustFix)
        .status(FindingStatus::Open)
        .explanation("The agent said all tests pass, but a recorded test event shows a failure.")
        .user_impact("A claimed completion may not be complete.")
        .next_step("Fix the failing test or the code it exercises.")
        .evidence(vec![Evidence::new(
            EvidenceClass::ObservedFact,
            "recorded test event shows exit code 1",
            EvidenceAnchor::new(AnchorSubject::Event, "test.run", "harness-42"),
            Some(fingerprint()),
            Severity::MustFix,
        )])
        .fingerprint(fingerprint())
        .build()
        .expect("fixture finding is valid");

        let contract = RepairContract::from_finding_with_one_check(&finding, CheckId::generate())
            .expect("contract is generated");
        assert!(contract.is_actionable());
        assert!(
            contract
                .forbidden_shortcuts
                .iter()
                .any(|s| s.contains("hiding") || s.contains("symptom"))
        );
    }

    #[test]
    fn repair_envelope_wraps_a_contract_without_changing_it() {
        let finding = grounded_finding();
        let contract = RepairContract::from_finding_with_one_check(&finding, CheckId::generate())
            .expect("contract is generated");
        let envelope = RepairEnvelope::new(contract.clone());

        assert_eq!(envelope.version, REPAIR_ENVELOPE_VERSION);
        assert!(envelope.target_harness.is_none());
        assert_eq!(envelope.into_contract(), contract);
    }

    #[test]
    fn repair_envelope_can_be_addressed_to_a_harness() {
        let finding = grounded_finding();
        let contract = RepairContract::from_finding_with_one_check(&finding, CheckId::generate())
            .expect("contract is generated");
        let envelope = RepairEnvelope::new(contract).for_harness("claude-code");

        assert_eq!(envelope.target_harness.as_deref(), Some("claude-code"));
        assert_eq!(envelope.version, REPAIR_ENVELOPE_VERSION);
    }

    #[test]
    fn repair_envelope_round_trips_through_json() {
        let finding = grounded_finding();
        let contract = RepairContract::from_finding_with_one_check(&finding, CheckId::generate())
            .expect("contract is generated");
        let envelope = RepairEnvelope::new(contract).for_harness("cursor");

        let text = serde_json::to_string(&envelope).expect("envelope serializes");
        let back: RepairEnvelope = serde_json::from_str(&text).expect("envelope deserializes");
        assert_eq!(back, envelope);
    }

    #[test]
    fn repair_envelope_omits_target_harness_when_none() {
        let finding = grounded_finding();
        let contract = RepairContract::from_finding_with_one_check(&finding, CheckId::generate())
            .expect("contract is generated");
        let envelope = RepairEnvelope::new(contract);

        let document = serde_json::to_value(&envelope).expect("envelope serializes");
        assert!(document.get("target_harness").is_none());
        assert_eq!(
            document["version"],
            serde_json::json!(REPAIR_ENVELOPE_VERSION)
        );
        assert!(document.get("contract").is_some());
    }
}
