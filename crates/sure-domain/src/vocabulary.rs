//! The frozen core domain vocabulary.
//!
//! Every name here is fixed by `docs/architecture/DOMAIN_MODEL.md`. These types
//! are deliberately thin: they carry identity, provenance and outcome, and hold
//! no checking logic, so that the check engine can be replaced without changing
//! what a finding means.

use serde::{Deserialize, Serialize};

use crate::capability::CapabilityReport;
use crate::evidence::{ClaimAssessment, Evidence};
use crate::execution::ExecutionMode;
use crate::ids::{CheckId, ClaimId, EventId, FingerprintId, ProjectId, RepairId, SessionId};
use crate::intent::ProjectIntent;
use crate::status::{Aggregate, CheckResult, NotCheckedReason};
use crate::variants::variants;

pub use crate::finding::{
    AssessmentSource, Finding, FindingBuildError, FindingBuilder, FindingStatus, SeverityRationale,
};

/// A local software project or workspace under inspection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Project {
    /// Stable identity for this project within SURE's local storage.
    pub id: ProjectId,
    /// Human-readable name, usually the directory name.
    pub name: String,
    /// Absolute path to the project root.
    pub root: String,
    /// What kind of project SURE believes this is, with its support level.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stacks: Vec<StackClassification>,
    /// The one level for the project as a whole, and why.
    ///
    /// Not a restatement of [`Self::stacks`]: those answer *per ecosystem*, and
    /// a project is the thing a person points SURE at. Which one a reader wants
    /// depends on the question, so both are here and neither is derived from the
    /// other at read time.
    ///
    /// **The rule that fills this is `sure_core::support`'s, not this crate's**,
    /// and the crate that applies it is the one that can see a [`Discovery`].
    /// A project record built by [`Self::new`] has not been classified, and says
    /// so rather than guessing.
    ///
    /// [`Discovery`]: https://docs.rs/sure-core
    #[serde(default)]
    pub support: ProjectSupport,
}

impl Project {
    /// Build a project record.
    ///
    /// The support level is left [`unrecorded`](ProjectSupport::unrecorded).
    /// There is no honest level to invent here: a project nobody has classified
    /// is not a project at the weakest level, it is a project with no answer,
    /// and the two would be the same value if this defaulted to a real one.
    #[must_use]
    pub fn new(id: ProjectId, name: impl Into<String>, root: impl Into<String>) -> Self {
        Self {
            id,
            name: name.into(),
            root: root.into(),
            stacks: Vec::new(),
            support: ProjectSupport::unrecorded(),
        }
    }
}

/// How well SURE supports a discovered stack, and why.
///
/// # The order, which is load-bearing
///
/// The variants are declared **best first**, so the derived [`Ord`] sorts by
/// strength: `FirstClass < Generic < InspectOnly`. `sure_core::support` takes
/// the [`Ord::max`] of a project's levels, which is therefore the *weakest* one,
/// and that is the whole of the aggregation rule.
///
/// It is written down because the derive makes it invisible: reordering the
/// variants to read worst-first, which is an easy tidy-up, would silently
/// invert every project's support level and no test that compared a level
/// against its own name would notice. The variant order is part of this type's
/// meaning, and `support::tests::the_order_of_the_levels_is_by_strength` is what
/// holds it.
///
/// [`Ord`]: std::cmp::Ord
/// [`Ord::max`]: std::cmp::Ord::max
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SupportLevel {
    /// Framework-aware discovery and meaningful deterministic checks.
    FirstClass,
    /// Common manifests and commands are discoverable, with no claim of
    /// framework-specific completeness.
    Generic,
    /// Files and configuration can be inspected, but there is no safe or
    /// reliable way to run it.
    InspectOnly,
}

variants!(SupportLevel {
    FirstClass,
    Generic,
    InspectOnly
});

impl SupportLevel {
    /// The letter used in the product documentation.
    #[must_use]
    pub const fn letter(self) -> char {
        match self {
            Self::FirstClass => 'A',
            Self::Generic => 'B',
            Self::InspectOnly => 'C',
        }
    }

    /// The stable wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FirstClass => "first_class",
            Self::Generic => "generic",
            Self::InspectOnly => "inspect_only",
        }
    }

    /// Plain-language description of what the user gets.
    #[must_use]
    pub const fn plain_description(self) -> &'static str {
        match self {
            Self::FirstClass => {
                "SURE understands this kind of project well and can check it properly."
            }
            Self::Generic => {
                "SURE can find how this project is built and run when you allow it, and can run \
                 approved generic checks, but does not understand everything about it. A check \
                 whose command cannot be started is reported as not checked, not passed."
            }
            Self::InspectOnly => "SURE can look at this project's files, but cannot safely run it.",
        }
    }
}

/// The one support level for a project as a whole, and the sentence saying why.
///
/// [`Project::stacks`] carries a level per ecosystem; this carries the level for
/// the thing a person pointed SURE at. Both exist because they answer different
/// questions and, for a project with two ecosystems at different levels, they
/// have different answers — collapsing them would mean one of the two questions
/// getting a wrong one.
///
/// **The two fields are recorded together and are filled by one rule**, in
/// `sure_core::support`. A record whose level and reason came from different
/// places is what this type exists to make visible: the reason is not optional
/// and not a formatting of the level, so a level with nothing to say for itself
/// cannot be constructed by accident.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectSupport {
    /// How well SURE supports the project as a whole.
    pub level: SupportLevel,
    /// Why, naming what set the level, so the claim can be audited.
    pub reason: String,
}

impl ProjectSupport {
    /// The state of a project SURE has not classified.
    ///
    /// [`SupportLevel::InspectOnly`] rather than [`SupportLevel::FirstClass`],
    /// because a missing answer must never read as the best one. It is still not
    /// an answer, which is what [`Self::is_recorded`] is for — a caller that
    /// wants to know whether anybody looked asks that, rather than comparing the
    /// level against the default and hoping the comparison is right.
    #[must_use]
    pub fn unrecorded() -> Self {
        Self {
            level: SupportLevel::InspectOnly,
            reason: "SURE has not worked out how well it supports this project.".to_owned(),
        }
    }

    /// Build a classified project support record.
    ///
    /// The reason is taken as given rather than derived here: the rule that
    /// decides a level also knows the findings it decided it from, and this
    /// crate has neither.
    #[must_use]
    pub fn new(level: SupportLevel, reason: impl Into<String>) -> Self {
        Self {
            level,
            reason: reason.into(),
        }
    }

    /// Whether a rule filled this in, as opposed to [`Self::unrecorded`].
    ///
    /// `false` means SURE has no answer for this project, which is not the same
    /// as an answer of [`SupportLevel::InspectOnly`] — and, because
    /// [`Self::unrecorded`] returns that level, the difference is invisible to a
    /// caller that only reads [`Self::level`].
    #[must_use]
    pub fn is_recorded(&self) -> bool {
        *self != Self::unrecorded()
    }
}

impl Default for ProjectSupport {
    /// [`Self::unrecorded`], so that a stored project record written before this
    /// field existed deserializes to *no answer* rather than to a claim.
    fn default() -> Self {
        Self::unrecorded()
    }
}

/// One technology SURE found in the project, at a stated support level.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StackClassification {
    /// A stable stack identifier, for example `node`, `python`, `rust`.
    pub stack: String,
    /// How well SURE supports it.
    pub level: SupportLevel,
    /// Why SURE assigned that level, so the claim can be audited.
    pub reason: String,
}

/// How a project's identity was computed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FingerprintKind {
    /// Derived from Git state.
    Git,
    /// Derived from a deterministic content manifest, for projects without Git.
    Content,
}

variants!(FingerprintKind { Git, Content });

impl FingerprintKind {
    /// The stable wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Git => "git",
            Self::Content => "content",
        }
    }
}

/// The Git state a fingerprint was taken from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitState {
    /// The commit that was checked out.
    pub head: String,
    /// Whether tracked files differed from `head` at capture time.
    pub dirty: bool,
    /// Digest over the tracked diff, when the tree was dirty.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dirty_digest: Option<String>,
    /// Digest over the untracked files that matter, when any were present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub untracked_digest: Option<String>,
    /// The current branch name, when the repository is not detached.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
}

/// The identity of exactly the project state that evidence applies to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectFingerprint {
    /// Identity of this fingerprint.
    pub id: FingerprintId,
    /// How the fingerprint was computed.
    pub kind: FingerprintKind,
    /// The digest itself. Two states share a digest only if they are the same state
    /// as far as the relevant checks are concerned.
    pub digest: String,
    /// Git detail, when the project is a Git repository.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub git: Option<GitState>,
}

impl ProjectFingerprint {
    /// A content fingerprint.
    #[must_use]
    pub fn content(digest: impl Into<String>) -> Self {
        Self {
            id: FingerprintId::generate(),
            kind: FingerprintKind::Content,
            digest: digest.into(),
            git: None,
        }
    }

    /// A fingerprint derived from Git state.
    #[must_use]
    pub fn git(digest: impl Into<String>, state: GitState) -> Self {
        Self {
            id: FingerprintId::generate(),
            kind: FingerprintKind::Git,
            digest: digest.into(),
            git: Some(state),
        }
    }

    /// Whether this fingerprint describes the same project state as another.
    #[must_use]
    pub fn matches(&self, other: &Self) -> bool {
        self.kind == other.kind && self.digest == other.digest
    }
}

/// Observed coding-harness activity related to a project.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Session {
    /// Identity of this session.
    pub id: SessionId,
    /// The project the session worked on.
    pub project: ProjectId,
    /// The harness that produced the session, for example `claude-code`.
    pub source: String,
    /// What SURE could actually see, reported by the adapter.
    pub capability: CapabilityReport,
    /// When the session started, as an RFC 3339 timestamp.
    pub started_at: String,
}

/// A normalized observed harness event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    /// Identity of this event.
    pub id: EventId,
    /// The session the event belongs to.
    pub session: SessionId,
    /// The semantic event name, for example `action.completed`.
    pub event_type: String,
    /// When it happened, as an RFC 3339 timestamp.
    pub timestamp: String,
    /// The event body, already normalized and redacted.
    #[serde(default)]
    pub payload: serde_json::Value,
}

/// The approved set of checks for a project state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckPlan {
    /// Identity of the plan.
    pub id: String,
    /// The project state this plan was built for.
    pub fingerprint: FingerprintId,
    /// The execution mode the plan was built under.
    pub mode: ExecutionMode,
    /// Checks that do not execute any project code.
    #[serde(default)]
    pub static_checks: Vec<CheckId>,
    /// Checks that would execute project code.
    #[serde(default)]
    pub dynamic_checks: Vec<CheckId>,
    /// Checks deliberately excluded, and why. These stay visible in the report.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub excluded: Vec<NotCheckedReason>,
}

impl CheckPlan {
    /// Build an empty plan for a project state.
    #[must_use]
    pub fn new(id: impl Into<String>, fingerprint: FingerprintId, mode: ExecutionMode) -> Self {
        Self {
            id: id.into(),
            fingerprint,
            mode,
            static_checks: Vec::new(),
            dynamic_checks: Vec::new(),
            excluded: Vec::new(),
        }
    }

    /// Take a check out of the plan and record why it will not run.
    ///
    /// **Removing the id as well as recording the reason is the whole point.**
    /// A plan that held a check in `dynamic_checks` *and* in `excluded` would
    /// read as "this will run" to a caller iterating one field and as "this will
    /// not run" to a reader looking at the other, and which of the two a report
    /// showed would depend on which field it read. The three lists are disjoint
    /// here by construction rather than by a rule every caller has to remember.
    ///
    /// Returns whether the check was in the plan, and **a check that was not is
    /// not recorded at all**: `excluded` means exactly "checks this plan
    /// contained and then took out", and a reason appended for a check the plan
    /// never held would be a line in the report that names no check. A caller
    /// excluding something it never planned has a bug, and the `false` is where
    /// that shows — the caller's to report, which is what `sure_core`'s
    /// `PermissionPlan::exclude_refused_from` does with it.
    pub fn exclude(&mut self, check: &CheckId, reason: NotCheckedReason) -> bool {
        let before = self.static_checks.len() + self.dynamic_checks.len();
        self.static_checks.retain(|id| id != check);
        self.dynamic_checks.retain(|id| id != check);
        let was_planned = self.static_checks.len() + self.dynamic_checks.len() != before;
        if was_planned {
            self.excluded.push(reason);
        }
        was_planned
    }

    /// Every check in the plan.
    #[must_use]
    pub fn all_checks(&self) -> Vec<&CheckId> {
        self.static_checks
            .iter()
            .chain(self.dynamic_checks.iter())
            .collect()
    }
}

/// A statement a coding agent made that can sometimes be checked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Claim {
    /// Identity of the claim.
    pub id: ClaimId,
    /// The claim, quoted or transcribed from the agent.
    pub claim_text: String,
    /// What kind of claim it is, for example `tests_pass` or `feature_complete`.
    pub claim_type: String,
    /// What checking it produced.
    pub assessment: ClaimAssessment,
    /// Plain-language explanation of the assessment.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub reason: String,
    /// The evidence behind the assessment.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<Evidence>,
    /// The session the claim came from, when it came from one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionId>,
}

impl Claim {
    /// Whether SURE actually reached a verdict, as opposed to running out of evidence.
    #[must_use]
    pub const fn has_verdict(&self) -> bool {
        matches!(
            self.assessment,
            ClaimAssessment::Confirmed | ClaimAssessment::Contradicted
        )
    }
}

/// Bounded instructions and acceptance conditions handed to a coding harness.
///
/// The wire form is `schemas/repair.schema.json`, and
/// `docs/architecture/REPAIR_PROTOCOL.md` lists "issue ID" as its first required
/// field. The field is named `issue_id` here so that the Rust name and the wire
/// name are the same word, rather than being related by a `serde` attribute that
/// a reader has to go looking for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepairContract {
    /// Identity of the contract.
    pub id: RepairId,
    /// The finding this contract addresses.
    pub issue_id: crate::ids::FindingId,
    /// What is wrong.
    pub problem: String,
    /// Why it matters to the person using the software.
    pub why_it_matters: String,
    /// The concrete fix required.
    pub required_fix: Vec<String>,
    /// Behaviour that must keep working after the fix.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub preserve: Vec<String>,
    /// How SURE will know the fix worked.
    pub acceptance: Vec<String>,
    /// Checks to re-run after the repair.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub recheck: Vec<CheckId>,
    /// Cheats that would satisfy the letter of the acceptance criteria without
    /// fixing the problem.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub forbidden_shortcuts: Vec<String>,
    /// The evidence behind the problem statement.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<Evidence>,
}

impl RepairContract {
    /// Whether the contract gives a coding agent everything it needs.
    ///
    /// A contract without acceptance criteria cannot be verified, and one
    /// without a re-check list cannot be closed honestly.
    #[must_use]
    pub fn is_actionable(&self) -> bool {
        !self.problem.trim().is_empty()
            && !self.why_it_matters.trim().is_empty()
            && !self.required_fix.is_empty()
            && !self.acceptance.is_empty()
            && !self.recheck.is_empty()
    }
}

/// The overall recommendation for a project.
///
/// A verdict is derived from results and findings. It is never a free-form
/// opinion, and it never claims more than the coverage supports.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectVerdict {
    /// The project state this verdict is about.
    pub fingerprint: FingerprintId,
    /// How the checks aggregated.
    pub aggregate: Aggregate,
    /// Whether SURE may compare the project against what the user asked for.
    pub intent: ProjectIntent,
    /// What the harness integration could and could not see.
    pub capability: CapabilityReport,
    /// Findings, ordered most serious first.
    #[serde(default)]
    pub findings: Vec<Finding>,
    /// Checks that did not run, kept visible so they are never mistaken for passes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub not_checked: Vec<CheckResult>,
    /// Agent completion claims that were checked against recorded evidence.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub claim_checks: Vec<Claim>,
}

impl ProjectVerdict {
    /// Whether this verdict permits hand-off.
    ///
    /// True only when the aggregate is green **and** no open finding blocks
    /// hand-off. A green aggregate with an open `must_fix` finding is a
    /// contradiction that must never be presented as ready.
    #[must_use]
    pub fn is_ready_for_hand_off(&self) -> bool {
        self.aggregate.is_green()
            && !self
                .findings
                .iter()
                .any(|f| f.status.needs_attention() && f.severity.blocks_hand_off())
    }

    /// Whether the report must carry the "I did not see your request" caveat.
    #[must_use]
    pub fn must_caveat_requirements(&self) -> bool {
        self.intent.is_after_the_fact()
    }

    /// Findings that still need attention, most serious first.
    #[must_use]
    pub fn open_findings(&self) -> Vec<&Finding> {
        let mut open: Vec<&Finding> = self
            .findings
            .iter()
            .filter(|f| f.status.needs_attention())
            .collect();
        open.sort_by_key(|f| std::cmp::Reverse(f.severity));
        open
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::evidence::{AnchorSubject, EvidenceAnchor, EvidenceClass};
    use crate::severity::Severity;

    fn anchor() -> EvidenceAnchor {
        EvidenceAnchor::new(AnchorSubject::File, "src/x.rs", "line 1")
    }

    fn fingerprint() -> FingerprintId {
        FingerprintId::generate()
    }

    fn finding(severity: Severity, class: EvidenceClass) -> Finding {
        let assessment_source = match class {
            EvidenceClass::ObservedFact => AssessmentSource::ObservedFact,
            EvidenceClass::DeterministicCheck => AssessmentSource::DeterministicCheck,
            EvidenceClass::ModelAssessment => AssessmentSource::ModelAssessment,
            EvidenceClass::Inference => AssessmentSource::Inference,
            EvidenceClass::Unknown => AssessmentSource::Unknown,
        };
        let severity_rationale =
            SeverityRationale::for_severity(severity).expect("test severity maps to a rationale");
        Finding {
            id: crate::ids::FindingId::generate(),
            title: "Payment looks successful but nothing is charged".to_owned(),
            severity,
            status: FindingStatus::Open,
            explanation: String::new(),
            user_impact: String::new(),
            next_step: String::new(),
            evidence: vec![Evidence::new(
                class,
                "s",
                anchor(),
                Some(fingerprint()),
                severity,
            )],
            fingerprint: fingerprint(),
            technical_details: None,
            assessment_source,
            severity_rationale,
        }
    }

    #[test]
    fn a_must_fix_finding_backed_only_by_model_opinion_is_not_grounded() {
        assert!(!finding(Severity::MustFix, EvidenceClass::ModelAssessment).is_grounded());
        assert!(!finding(Severity::MustFix, EvidenceClass::Inference).is_grounded());
        assert!(finding(Severity::MustFix, EvidenceClass::DeterministicCheck).is_grounded());
        assert!(finding(Severity::MustFix, EvidenceClass::ObservedFact).is_grounded());
    }

    #[test]
    fn strongest_evidence_class_picks_the_highest_truth_rank() {
        let mut f = finding(Severity::ShouldFixFirst, EvidenceClass::Inference);
        f.evidence.push(Evidence::new(
            EvidenceClass::ObservedFact,
            "s",
            anchor(),
            Some(fingerprint()),
            Severity::Note,
        ));
        assert_eq!(f.strongest_evidence_class(), EvidenceClass::ObservedFact);
    }

    #[test]
    fn support_levels_map_to_the_documented_letters() {
        assert_eq!(SupportLevel::FirstClass.letter(), 'A');
        assert_eq!(SupportLevel::Generic.letter(), 'B');
        assert_eq!(SupportLevel::InspectOnly.letter(), 'C');
        assert_eq!(SupportLevel::FirstClass.as_str(), "first_class");
        assert_eq!(SupportLevel::Generic.as_str(), "generic");
        assert_eq!(SupportLevel::InspectOnly.as_str(), "inspect_only");
    }

    #[test]
    fn an_unclassified_project_defaults_to_the_weakest_level_and_says_it_has_no_answer() {
        // Both halves matter, and the second is the one a caller is likely to
        // forget: `unrecorded()` returns a *real* level, so a reader that looks
        // only at `level` cannot tell "nobody classified this" from "SURE
        // classified this and it is level C". `is_recorded` is the only door to
        // that difference, and defaulting to the strongest level instead would
        // make a project nobody had looked at the best-supported one.
        let unrecorded = ProjectSupport::unrecorded();
        assert_eq!(unrecorded.level, SupportLevel::InspectOnly);
        assert!(!unrecorded.is_recorded());
        assert_eq!(ProjectSupport::default(), unrecorded);

        let classified = ProjectSupport::new(SupportLevel::InspectOnly, "because");
        assert_eq!(
            classified.level, unrecorded.level,
            "the two must share a level or this test proves nothing"
        );
        assert!(
            classified.is_recorded(),
            "a rule that filled the reason in must count as an answer even when it \
             lands on the same level as the default"
        );
        assert!(
            ProjectSupport::new(SupportLevel::InspectOnly, "").is_recorded(),
            "an answer with nothing to say for itself is still an answer; the level \
             and the reason together are what `unrecorded` is, not the reason alone"
        );
        assert_eq!(
            ProjectSupport::new(SupportLevel::FirstClass, "because").level,
            SupportLevel::FirstClass,
            "`new` records the level it is handed; a classifier's answer is the whole \
             point of the type and it must not be replaced by a default here"
        );

        let built = Project::new(ProjectId::generate(), "shop", "C:\\shop");
        assert!(
            !built.support.is_recorded(),
            "a project record built by `Project::new` carries no classification until a \
             rule fills one in: {}",
            built.support.reason
        );
    }

    #[test]
    fn fingerprints_only_match_when_kind_and_digest_agree() {
        let a = ProjectFingerprint::content("abc");
        let b = ProjectFingerprint::content("abc");
        let c = ProjectFingerprint::content("def");
        assert!(a.matches(&b));
        assert!(!a.matches(&c));
        assert!(!a.matches(&ProjectFingerprint::git(
            "abc",
            GitState {
                head: "deadbeef".to_owned(),
                dirty: false,
                dirty_digest: None,
                untracked_digest: None,
                branch: Some("main".to_owned()),
            }
        )));
    }

    #[test]
    fn an_empty_or_incomplete_plan_still_lists_its_checks() {
        let plan = CheckPlan::new("plan-1", fingerprint(), ExecutionMode::InspectOnly);
        assert!(plan.all_checks().is_empty());
        assert!(plan.excluded.is_empty());
    }

    #[test]
    fn excluding_a_check_takes_it_out_and_says_why() {
        // The three lists are disjoint by construction, which is the property a
        // report depends on: a check that is in `dynamic_checks` *and* in
        // `excluded` would read as "will run" to one reader and "will not" to
        // another, and which one a report showed would depend on which field it
        // read.
        let mut plan = CheckPlan::new("plan-1", fingerprint(), ExecutionMode::InspectOnly);
        let stays = CheckId::generate();
        let goes = CheckId::generate();
        plan.static_checks.push(stays.clone());
        plan.dynamic_checks.push(goes.clone());

        assert!(
            plan.exclude(&goes, NotCheckedReason::ExecutionNotAuthorized),
            "the check was in the plan, so this removed it"
        );
        assert!(plan.dynamic_checks.is_empty());
        assert_eq!(plan.static_checks, vec![stays.clone()]);
        assert_eq!(
            plan.excluded,
            vec![NotCheckedReason::ExecutionNotAuthorized]
        );
        assert_eq!(plan.all_checks(), vec![&stays]);
    }

    #[test]
    fn a_check_the_plan_never_held_is_left_out_of_the_reasons_too() {
        // `excluded` means exactly "checks this plan contained and then took
        // out". A reason appended for a check that was never in the plan would
        // be a line in the report naming no check, and the caller that excluded
        // it has a bug of its own to report — the `false` is the whole of what
        // this method can say about one.
        let mut plan = CheckPlan::new("plan-1", fingerprint(), ExecutionMode::InspectOnly);
        let never_planned = CheckId::generate();
        assert!(!plan.exclude(&never_planned, NotCheckedReason::UserDeclined));
        assert!(plan.excluded.is_empty(), "{:?}", plan.excluded);
        assert!(plan.all_checks().is_empty());
    }

    #[test]
    fn a_repair_contract_without_acceptance_or_recheck_is_not_actionable() {
        let base = RepairContract {
            id: RepairId::generate(),
            issue_id: crate::ids::FindingId::generate(),
            problem: "p".to_owned(),
            why_it_matters: "w".to_owned(),
            required_fix: vec!["f".to_owned()],
            preserve: Vec::new(),
            acceptance: vec!["a".to_owned()],
            recheck: vec![CheckId::generate()],
            forbidden_shortcuts: Vec::new(),
            evidence: Vec::new(),
        };
        assert!(base.is_actionable());

        let no_acceptance = RepairContract {
            acceptance: Vec::new(),
            ..base.clone()
        };
        assert!(!no_acceptance.is_actionable());

        let no_recheck = RepairContract {
            recheck: Vec::new(),
            ..base.clone()
        };
        assert!(!no_recheck.is_actionable());

        let no_fix = RepairContract {
            required_fix: Vec::new(),
            ..base
        };
        assert!(!no_fix.is_actionable());
    }

    #[test]
    fn a_green_aggregate_with_an_open_must_fix_finding_is_not_ready() {
        use crate::status::{AggregateSeverity, CheckResult, CoverageSummary, StatusCounts};
        let aggregate = Aggregate {
            severity: AggregateSeverity::Green,
            headline: AggregateSeverity::Green.headline().to_owned(),
            counts: StatusCounts::tally([crate::status::CheckStatus::Pass]),
            blocking: Vec::new(),
            coverage: CoverageSummary {
                counts: StatusCounts::tally([crate::status::CheckStatus::Pass]),
                critical_not_checked: Vec::new(),
                critical_errored: Vec::new(),
                critical_failed: Vec::new(),
                critical_out_of_scope: Vec::new(),
                critical_checked: 1,
            },
        };
        let verdict = ProjectVerdict {
            fingerprint: fingerprint(),
            aggregate,
            intent: ProjectIntent::empty(),
            capability: CapabilityReport::cli(),
            findings: vec![finding(
                Severity::MustFix,
                EvidenceClass::DeterministicCheck,
            )],
            not_checked: vec![CheckResult::not_run(
                CheckId::generate(),
                "start the app",
                Severity::MustFix,
                true,
                NotCheckedReason::ExecutionNotAuthorized,
                fingerprint(),
            )],
            claim_checks: Vec::new(),
        };
        assert!(!verdict.is_ready_for_hand_off());
        assert!(verdict.must_caveat_requirements());
        assert_eq!(verdict.open_findings().len(), 1);
        assert_eq!(verdict.not_checked.len(), 1);
    }

    #[test]
    fn open_findings_are_returned_most_serious_first_and_resolved_ones_are_dropped() {
        let mut resolved = finding(Severity::CanFixLater, EvidenceClass::ObservedFact);
        resolved.status = FindingStatus::Resolved;
        let verdict = ProjectVerdict {
            fingerprint: fingerprint(),
            aggregate: crate::status::aggregate(&[]),
            intent: ProjectIntent::empty(),
            capability: CapabilityReport::cli(),
            findings: vec![
                finding(Severity::Note, EvidenceClass::ObservedFact),
                finding(Severity::MustFix, EvidenceClass::ObservedFact),
                resolved,
            ],
            not_checked: Vec::new(),
            claim_checks: Vec::new(),
        };
        let open = verdict.open_findings();
        assert_eq!(open.len(), 2);
        assert_eq!(open[0].severity, Severity::MustFix);
        assert_eq!(open[1].severity, Severity::Note);
    }

    #[test]
    fn a_claim_only_has_a_verdict_when_evidence_produced_one() {
        let make = |assessment| Claim {
            id: ClaimId::generate(),
            claim_text: "all tests pass".to_owned(),
            claim_type: "tests_pass".to_owned(),
            assessment,
            reason: String::new(),
            evidence: Vec::new(),
            session: None,
        };
        assert!(make(ClaimAssessment::Confirmed).has_verdict());
        assert!(make(ClaimAssessment::Contradicted).has_verdict());
        assert!(!make(ClaimAssessment::CannotConfirm).has_verdict());
        assert!(!make(ClaimAssessment::NotCheckable).has_verdict());
    }
}
