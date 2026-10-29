//! Check status, aggregation and the false-green rule.
//!
//! This module owns the single most important safety property in SURE: a
//! critical check that did not actually pass must never silently aggregate into
//! "all good". Everything here is deliberately explicit — there is no status
//! that means "probably fine".

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::evidence::EvidenceClass;
use crate::ids::{CheckId, FingerprintId};
use crate::severity::Severity;
use crate::variants::variants;

/// The outcome of a single check.
///
/// The wire form is exactly the `pass`/`fail`/`warning`/`skipped`/`error`/
/// `unknown` enumeration frozen in `schemas/check-result.schema.json`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    /// The check ran and the project satisfied it.
    Pass,
    /// The check ran and the project did not satisfy it.
    Fail,
    /// The check ran and the project satisfied it only partially.
    ///
    /// A warning never blocks by itself, but it always appears in the report.
    Warning,
    /// The check was deliberately not run.
    ///
    /// This covers a denied execution consent, an unsupported stack, an
    /// unavailable tool and a deliberate `check = "off"` configuration.
    Skipped,
    /// The check was attempted and the checker itself failed.
    ///
    /// An error means "SURE does not know", never "the project is fine".
    Error,
    /// SURE has no basis for a verdict on this check.
    Unknown,
}

variants!(
    /// Every status, in report order.
    CheckStatus { Pass, Fail, Warning, Skipped, Error, Unknown }
);

impl CheckStatus {
    /// The stable wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
            Self::Warning => "warning",
            Self::Skipped => "skipped",
            Self::Error => "error",
            Self::Unknown => "unknown",
        }
    }

    /// Whether the check produced a usable result about the project.
    ///
    /// `false` means the project was **not** actually checked, regardless of how
    /// reassuring the status sounds.
    #[must_use]
    pub const fn produced_a_result(self) -> bool {
        matches!(self, Self::Pass | Self::Fail | Self::Warning)
    }

    /// Whether the check ran and found the project acceptable.
    #[must_use]
    pub const fn is_green(self) -> bool {
        matches!(self, Self::Pass)
    }

    /// Whether this is the check's own failure rather than the project's.
    #[must_use]
    pub const fn is_checker_failure(self) -> bool {
        matches!(self, Self::Error)
    }
}

/// How one check contributes to the overall decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CriticalState {
    /// It ran and the project passed.
    Passed,
    /// It ran and the project did not pass.
    Failed,
    /// It never ran: denied, unsupported, unavailable or deliberately skipped.
    NotRun,
    /// It ran, but the checker itself failed.
    CheckerError,
    /// It did not run and SURE does not know whether it needed to.
    Uncertain,
}

variants!(CriticalState {
    Passed,
    Failed,
    NotRun,
    CheckerError,
    Uncertain
});

impl CriticalState {
    /// Classify a check status for a check that was required for this project state.
    #[must_use]
    pub const fn from_status(status: CheckStatus) -> Self {
        match status {
            CheckStatus::Pass => Self::Passed,
            CheckStatus::Fail => Self::Failed,
            CheckStatus::Error => Self::CheckerError,
            CheckStatus::Skipped => Self::NotRun,
            CheckStatus::Unknown => Self::Uncertain,
            // A warning cannot block, but it also cannot be reported as a clean
            // critical pass; `not_checked_reason` decides whether it still counts
            // as blocking. It is classified as Passed here so that a warning on a
            // critical check degrades to `needs_attention` rather than `blocked`.
            CheckStatus::Warning => Self::Passed,
        }
    }

    /// Whether this state forbids a green verdict.
    #[must_use]
    pub const fn blocks_green(self) -> bool {
        matches!(
            self,
            Self::Failed | Self::NotRun | Self::CheckerError | Self::Uncertain
        )
    }
}

/// Why a check did not run.
///
/// The distinction matters for the report: "we were not allowed to look" and
/// "this check does not apply to your project" are different promises to the
/// user, and only one of them should worry them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotCheckedReason {
    /// The user's execution mode did not allow running project code.
    ExecutionNotAuthorized,
    /// Container mode was requested, but this build cannot execute in one.
    ContainerExecutionUnavailable,
    /// The user declined a specific approval prompt.
    UserDeclined,
    /// Dependency installation was not permitted, so the check could not run.
    DependencyInstallNotPermitted,
    /// Network access was not permitted.
    NetworkNotPermitted,
    /// A required tool is not installed.
    ToolUnavailable,
    /// The project is not on a stack SURE can check.
    UnsupportedStack,
    /// The check does not apply to this project shape (for example no database).
    NotApplicable,
    /// The user configured the check off.
    DisabledByConfiguration,
    /// It needed a real external service that is not reachable.
    ExternalServiceUnavailable,
    /// No analysis provider is configured, so model-backed checks could not run.
    AnalysisProviderDisabled,
    /// SURE has no rule for deciding.
    UnknownReason,
}

variants!(NotCheckedReason {
    ExecutionNotAuthorized,
    ContainerExecutionUnavailable,
    UserDeclined,
    DependencyInstallNotPermitted,
    NetworkNotPermitted,
    ToolUnavailable,
    UnsupportedStack,
    NotApplicable,
    DisabledByConfiguration,
    ExternalServiceUnavailable,
    AnalysisProviderDisabled,
    UnknownReason
});

impl NotCheckedReason {
    /// Whether this reason reflects a genuine gap in what SURE was able to check.
    ///
    /// `NotApplicable`, `UnsupportedStack` and `DisabledByConfiguration` are
    /// honest scope limits that the user chose or that the project shape
    /// implies. The rest are gaps that must stay visible as blocking when the
    /// check was critical.
    #[must_use]
    pub const fn is_scope_limit(self) -> bool {
        matches!(
            self,
            Self::NotApplicable | Self::UnsupportedStack | Self::DisabledByConfiguration
        )
    }

    /// Whether this reason means model-backed analysis was disabled for this run.
    #[must_use]
    pub const fn is_analysis_provider_disabled(self) -> bool {
        matches!(self, Self::AnalysisProviderDisabled)
    }

    /// Plain-language explanation written for someone who is not a programmer.
    #[must_use]
    pub const fn plain_explanation(self) -> &'static str {
        match self {
            Self::ExecutionNotAuthorized => {
                "Checking this would have meant running your project's code, and you have not allowed that."
            }
            Self::ContainerExecutionUnavailable => {
                "You allowed a container check, but this version of SURE cannot run checks in a container. Your project's code was not run on this computer."
            }
            Self::UserDeclined => "You said no when SURE asked to run this check.",
            Self::DependencyInstallNotPermitted => {
                "The project needs extra packages installed first, and you have not allowed installing them."
            }
            Self::NetworkNotPermitted => {
                "Checking this needs internet access, and you have not allowed it."
            }
            Self::ToolUnavailable => "The tool this check needs is not installed on this computer.",
            Self::UnsupportedStack => "SURE does not know how to check this kind of project yet.",
            Self::NotApplicable => "This check does not apply to your project.",
            Self::DisabledByConfiguration => "You switched this check off in the SURE settings.",
            Self::ExternalServiceUnavailable => {
                "This can only be confirmed against the real outside service, which is not available here."
            }
            Self::AnalysisProviderDisabled => {
                "No analysis provider is configured, so SURE cannot perform model-backed checks."
            }
            Self::UnknownReason => "SURE does not know why this was not checked.",
        }
    }
}

/// One checked (or not checked) item, as it reaches the aggregator.
///
/// A result is a **statement about a project**, so it carries the same two
/// things every other statement in SURE carries: how it was established, and
/// which project state it is about. `docs/architecture/EVIDENCE_MODEL.md` asks
/// for the first and `docs/architecture/DOMAIN_MODEL.md` for the second.
///
/// Both are required rather than optional. A result that does not say how it
/// was established invites a file read and a live run to be summarised into the
/// same green, and a result that does not name its state can be read against a
/// later state — which is how a stale pass becomes a false green. The wire form
/// is `schemas/check-result.schema.json`, which requires both.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckResult {
    /// Stable identity, usable in the report and in evidence anchors.
    pub id: CheckId,
    /// Short human title.
    pub title: String,
    /// The outcome.
    pub status: CheckStatus,
    /// How bad it is if this check is not satisfied.
    pub severity: Severity,
    /// How this result was established.
    ///
    /// Not decoration: a `pass` from reading a file is `DeterministicCheck`, and
    /// a `pass` from running the project and watching what it did is
    /// `ObservedFact`. They are different promises, and the truth hierarchy in
    /// `docs/architecture/EVIDENCE_MODEL.md` ranks them differently.
    pub evidence_class: EvidenceClass,
    /// The project state this result applies to.
    pub project_fingerprint: FingerprintId,
    /// Root cause when `status` is not a result, and why.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_checked_reason: Option<NotCheckedReason>,
    /// One line of plain-language detail.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub reason: String,
    /// Whether the project cannot be trusted for hand-off when this fails.
    pub critical: bool,
}

impl CheckResult {
    /// A check that ran and passed.
    ///
    /// `class` says how it passed, and `fingerprint` says which state it passed
    /// against. Neither has a default: a caller that does not know one of them
    /// does not have a result.
    #[must_use]
    pub fn pass(
        id: CheckId,
        title: impl Into<String>,
        severity: Severity,
        critical: bool,
        class: EvidenceClass,
        fingerprint: FingerprintId,
    ) -> Self {
        Self {
            id,
            title: title.into(),
            status: CheckStatus::Pass,
            severity,
            evidence_class: class,
            project_fingerprint: fingerprint,
            not_checked_reason: None,
            reason: String::new(),
            critical,
        }
    }

    /// A check that ran and failed.
    #[must_use]
    pub fn fail(
        id: CheckId,
        title: impl Into<String>,
        severity: Severity,
        critical: bool,
        class: EvidenceClass,
        fingerprint: FingerprintId,
    ) -> Self {
        Self {
            status: CheckStatus::Fail,
            ..Self::pass(id, title, severity, critical, class, fingerprint)
        }
    }

    /// A check that ran and only partly satisfied the project.
    #[must_use]
    pub fn warning(
        id: CheckId,
        title: impl Into<String>,
        severity: Severity,
        critical: bool,
        class: EvidenceClass,
        fingerprint: FingerprintId,
    ) -> Self {
        Self {
            status: CheckStatus::Warning,
            ..Self::pass(id, title, severity, critical, class, fingerprint)
        }
    }

    /// A check that ran and established nothing either way.
    ///
    /// The evidence class **is** a parameter here, unlike [`CheckResult::not_run`]
    /// and [`CheckResult::errored`], and the difference is the point: those two
    /// mean SURE has no evidence, while this one means SURE has evidence that
    /// supports no verdict. The first caller is a probe that found a port open
    /// and nothing said — an observed fact, and not a basis for saying the
    /// project is fine or that it is broken.
    ///
    /// `unknown` is not a soft failure and it is not a pass: for a critical
    /// check, [`aggregate`] treats it as not checked (rule 1).
    #[must_use]
    pub fn unknown(
        id: CheckId,
        title: impl Into<String>,
        severity: Severity,
        critical: bool,
        class: EvidenceClass,
        fingerprint: FingerprintId,
    ) -> Self {
        Self {
            status: CheckStatus::Unknown,
            ..Self::pass(id, title, severity, critical, class, fingerprint)
        }
    }

    /// A check that could not be run, with the reason.
    ///
    /// The evidence class is [`EvidenceClass::Unknown`] and is not a parameter.
    /// A check that did not run established nothing, and offering a choice here
    /// would only offer a way to write that down wrongly.
    #[must_use]
    pub fn not_run(
        id: CheckId,
        title: impl Into<String>,
        severity: Severity,
        critical: bool,
        reason: NotCheckedReason,
        fingerprint: FingerprintId,
    ) -> Self {
        Self {
            status: CheckStatus::Skipped,
            not_checked_reason: Some(reason),
            reason: reason.plain_explanation().to_owned(),
            ..Self::pass(
                id,
                title,
                severity,
                critical,
                EvidenceClass::Unknown,
                fingerprint,
            )
        }
    }

    /// A check whose checker itself failed.
    ///
    /// [`EvidenceClass::Unknown`], for the same reason as [`CheckResult::not_run`]:
    /// an error means SURE does not know, never that the project is fine.
    #[must_use]
    pub fn errored(
        id: CheckId,
        title: impl Into<String>,
        severity: Severity,
        critical: bool,
        reason: impl Into<String>,
        fingerprint: FingerprintId,
    ) -> Self {
        Self {
            status: CheckStatus::Error,
            reason: reason.into(),
            ..Self::pass(
                id,
                title,
                severity,
                critical,
                EvidenceClass::Unknown,
                fingerprint,
            )
        }
    }

    /// Attach or replace the plain-language detail line.
    #[must_use]
    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = reason.into();
        self
    }

    /// How this check contributes to the overall decision.
    #[must_use]
    pub fn critical_state(&self) -> CriticalState {
        CriticalState::from_status(self.status)
    }

    /// Whether this check blocks a green verdict.
    ///
    /// A critical check blocks unless it passed the project or was honestly out
    /// of scope. A non-critical check never blocks by itself.
    #[must_use]
    pub fn blocks_green(&self) -> bool {
        if !self.critical {
            return false;
        }
        if self.status == CheckStatus::Skipped
            && self
                .not_checked_reason
                .is_some_and(NotCheckedReason::is_scope_limit)
        {
            return false;
        }
        self.critical_state().blocks_green()
    }

    /// Whether this check could not be evaluated at all.
    #[must_use]
    pub fn is_not_checked(&self) -> bool {
        !self.status.produced_a_result()
    }
}

/// What the run as a whole can honestly claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AggregateSeverity {
    /// Everything that had to run, ran, and the project passed.
    Green,
    /// Nothing blocking, but something needs a look before hand-off.
    NeedsAttention,
    /// Something is wrong that should be fixed before hand-off.
    NotReady,
    /// SURE could not check enough to make any recommendation.
    NotEnoughChecked,
}

variants!(AggregateSeverity {
    Green,
    NeedsAttention,
    NotReady,
    NotEnoughChecked
});

impl AggregateSeverity {
    /// The stable wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Green => "green",
            Self::NeedsAttention => "needs_attention",
            Self::NotReady => "not_ready",
            Self::NotEnoughChecked => "not_enough_checked",
        }
    }

    /// Plain-language headline for the report.
    #[must_use]
    pub const fn headline(self) -> &'static str {
        match self {
            Self::Green => "Everything that could be checked passed.",
            Self::NeedsAttention => "Nothing blocking, but a few things need your attention.",
            Self::NotReady => "This is not ready to hand off yet.",
            Self::NotEnoughChecked => "Not enough could be checked to say whether this is ready.",
        }
    }

    /// Whether this lets the user proceed without further work.
    #[must_use]
    pub const fn is_green(self) -> bool {
        matches!(self, Self::Green)
    }
}

/// Per-status totals for a run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct StatusCounts {
    /// Checks that passed.
    pub pass: u32,
    /// Checks that failed.
    pub fail: u32,
    /// Checks that warned.
    pub warning: u32,
    /// Checks that were deliberately not run.
    pub skipped: u32,
    /// Checks whose checker failed.
    pub error: u32,
    /// Checks with no basis for a verdict.
    pub unknown: u32,
}

impl StatusCounts {
    /// Tally a set of statuses.
    #[must_use]
    pub fn tally(statuses: impl IntoIterator<Item = CheckStatus>) -> Self {
        let mut counts = Self::default();
        for status in statuses {
            match status {
                CheckStatus::Pass => counts.pass += 1,
                CheckStatus::Fail => counts.fail += 1,
                CheckStatus::Warning => counts.warning += 1,
                CheckStatus::Skipped => counts.skipped += 1,
                CheckStatus::Error => counts.error += 1,
                CheckStatus::Unknown => counts.unknown += 1,
            }
        }
        counts
    }

    /// Total checks recorded.
    #[must_use]
    pub const fn total(self) -> u32 {
        self.pass + self.fail + self.warning + self.skipped + self.error + self.unknown
    }

    /// Checks that produced a result about the project.
    #[must_use]
    pub const fn checked(self) -> u32 {
        self.pass + self.fail + self.warning
    }

    /// Checks that did not produce a result about the project.
    #[must_use]
    pub const fn not_checked(self) -> u32 {
        self.skipped + self.error + self.unknown
    }
}

/// What was and was not covered by a run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverageSummary {
    /// Per-status totals.
    pub counts: StatusCounts,
    /// Critical checks that did not run.
    pub critical_not_checked: Vec<CheckId>,
    /// Critical checks whose checker failed.
    pub critical_errored: Vec<CheckId>,
    /// Critical checks that failed the project.
    pub critical_failed: Vec<CheckId>,
    /// Critical checks that were honestly out of scope for this project.
    pub critical_out_of_scope: Vec<CheckId>,
    /// Time saved by not running critical checks, in the run's own terms: how
    /// many critical checks produced a real result.
    pub critical_checked: u32,
}

impl CoverageSummary {
    /// Whether SURE managed to evaluate at least one critical check.
    #[must_use]
    pub const fn has_any_critical_result(&self) -> bool {
        self.critical_checked > 0
    }
}

/// The aggregated result of a run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Aggregate {
    /// The honest overall recommendation.
    pub severity: AggregateSeverity,
    /// Plain-language headline.
    pub headline: String,
    /// Per-status totals.
    pub counts: StatusCounts,
    /// Every check that blocks a green verdict, in input order.
    pub blocking: Vec<CheckId>,
    /// Coverage detail.
    pub coverage: CoverageSummary,
}

impl Aggregate {
    /// Whether the run ended without any blocking problem.
    #[must_use]
    pub fn is_green(&self) -> bool {
        self.severity.is_green()
    }
}

/// Aggregate check results into a verdict that cannot be falsely green.
///
/// Rules, in order:
///
/// 1. If any check blocks green (see [`CheckResult::blocks_green`]) the result is
///    never green. A critical `fail` is `not_ready`; a critical check that did
///    not run, or whose checker failed, is `not_enough_checked`.
/// 2. If nothing blocks but any check failed, warned, or was not checked for a
///    reason other than a scope limit, the result is `needs_attention`.
/// 3. Only when every recorded check passed — and at least one check ran — is the
///    result green.
#[must_use]
pub fn aggregate(results: &[CheckResult]) -> Aggregate {
    aggregate_inner(results, &BTreeSet::new())
}

/// The same aggregation, with findings a person reviewed and accepted
/// (ADR 0019).
///
/// **Exactly one rule is relaxed: `warning` results whose finding the user
/// acknowledged no longer contribute `needs_attention`.** Nothing else moves —
/// a `fail`, an `error`, an `unknown`, a skipped check, a critical out-of-scope
/// check and the "nothing ran" rule are untouched, and an id in `accepted` that
/// names a non-warning result has no effect at all. When the run is green only
/// because of such acknowledgements, the headline gains a clause that says how
/// many findings were accepted to get there, so a green run cannot read as
/// "everything passed" when something was reviewed and accepted instead.
///
/// The counts keep the warnings: the check results are facts and are reported
/// as they were, whatever the person decided about the findings built from
/// them.
#[must_use]
pub fn aggregate_with_accepted(results: &[CheckResult], accepted: &BTreeSet<CheckId>) -> Aggregate {
    aggregate_inner(results, accepted)
}

fn aggregate_inner(results: &[CheckResult], accepted: &BTreeSet<CheckId>) -> Aggregate {
    let counts = StatusCounts::tally(results.iter().map(|r| r.status));

    let mut critical_failed = Vec::new();
    let mut critical_errored = Vec::new();
    let mut critical_not_checked = Vec::new();
    let mut critical_out_of_scope = Vec::new();
    let mut critical_checked = 0_u32;
    let mut blocking = Vec::new();

    for result in results {
        if !result.critical {
            continue;
        }
        match result.status {
            CheckStatus::Pass | CheckStatus::Warning => critical_checked += 1,
            CheckStatus::Fail => {
                critical_checked += 1;
                critical_failed.push(result.id.clone());
            }
            CheckStatus::Error => critical_errored.push(result.id.clone()),
            CheckStatus::Skipped if result.blocks_green() => {
                critical_not_checked.push(result.id.clone());
            }
            CheckStatus::Skipped => critical_out_of_scope.push(result.id.clone()),
            CheckStatus::Unknown => critical_not_checked.push(result.id.clone()),
        }
        if result.blocks_green() {
            blocking.push(result.id.clone());
        }
    }

    let accepted_warnings = results
        .iter()
        .filter(|r| r.status == CheckStatus::Warning && accepted.contains(&r.id))
        .count();
    let unaccepted_warning = results
        .iter()
        .any(|r| r.status == CheckStatus::Warning && !accepted.contains(&r.id));

    let severity = if !critical_failed.is_empty() {
        AggregateSeverity::NotReady
    } else if !critical_errored.is_empty() || !critical_not_checked.is_empty() {
        AggregateSeverity::NotEnoughChecked
    } else if counts.checked() == 0 {
        // Nothing actually ran. That is never green, even when nothing is
        // technically "blocking" because the plan was empty.
        AggregateSeverity::NotEnoughChecked
    } else if counts.fail > 0
        || unaccepted_warning
        || counts.not_checked() > 0
        // A critical check that was honestly out of scope still means the
        // project was not fully checked, so the run is not a clean green.
        || !critical_out_of_scope.is_empty()
    {
        AggregateSeverity::NeedsAttention
    } else {
        AggregateSeverity::Green
    };

    let coverage = CoverageSummary {
        counts,
        critical_not_checked,
        critical_errored,
        critical_failed,
        critical_out_of_scope,
        critical_checked,
    };

    // Green because warnings were accepted is not the same statement as green
    // because everything passed, and the headline is where a reader finds out
    // which one this is.
    let headline = if severity.is_green() && accepted_warnings > 0 {
        format!(
            "{} {accepted_warnings} finding{} you reviewed and accepted {} not counted against \
             this result.",
            severity.headline(),
            if accepted_warnings == 1 { "" } else { "s" },
            if accepted_warnings == 1 { "is" } else { "are" },
        )
    } else {
        severity.headline().to_owned()
    };

    Aggregate {
        severity,
        headline,
        counts,
        blocking,
        coverage,
    }
}

/// The exact sentence SURE must use when it did not receive the user's original request.
///
/// Frozen wording from `docs/product/UX_AND_LANGUAGE.md`. Reports that omit this
/// caveat when no trusted intent source exists are false claims.
pub const NO_TRUSTED_INTENT_LIMITATION: &str = "I can check whether the current project runs and whether anything obviously looks incomplete. I cannot confirm that it matches your original request because that request was not provided to SURE.";

/// Whether a report may claim the project meets what the user asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequirementClaim {
    /// A trusted intent source exists, so SURE may compare against it.
    Comparable,
    /// No trusted intent source exists. SURE may judge current behaviour,
    /// obvious incompleteness and documented claims, and nothing more.
    AfterTheFact,
}

variants!(RequirementClaim {
    Comparable,
    AfterTheFact
});

impl RequirementClaim {
    /// The caveat the report must include, if any.
    #[must_use]
    pub const fn caveat(self) -> Option<&'static str> {
        match self {
            Self::Comparable => None,
            Self::AfterTheFact => Some(NO_TRUSTED_INTENT_LIMITATION),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// One project state for every result the aggregation tests build.
    ///
    /// Fixed rather than generated, so two results are comparable and a failure
    /// message names a value that does not change between runs. The tests here
    /// are about statuses; a different state per result would only add noise.
    fn fingerprint() -> FingerprintId {
        FingerprintId::parse("fp_00000000000000000000").expect("a well-formed fingerprint id")
    }

    fn check(status: CheckStatus, critical: bool) -> CheckResult {
        CheckResult {
            id: CheckId::generate(),
            title: "t".to_owned(),
            status,
            severity: Severity::MustFix,
            evidence_class: EvidenceClass::DeterministicCheck,
            project_fingerprint: fingerprint(),
            not_checked_reason: None,
            reason: String::new(),
            critical,
        }
    }

    #[test]
    fn every_status_has_a_distinct_wire_name() {
        let names: std::collections::BTreeSet<_> =
            CheckStatus::ALL.iter().map(|s| s.as_str()).collect();
        assert_eq!(names.len(), CheckStatus::ALL.len());
        assert_eq!(
            names.into_iter().collect::<Vec<_>>(),
            ["error", "fail", "pass", "skipped", "unknown", "warning"]
        );
    }

    #[test]
    fn only_three_statuses_mean_the_project_was_actually_checked() {
        for &status in CheckStatus::ALL {
            let expected = matches!(
                status,
                CheckStatus::Pass | CheckStatus::Fail | CheckStatus::Warning
            );
            assert_eq!(status.produced_a_result(), expected, "{status:?}");
        }
    }

    #[test]
    fn all_passing_is_green() {
        let results = [
            check(CheckStatus::Pass, true),
            check(CheckStatus::Pass, false),
        ];
        let summary = aggregate(&results);
        assert_eq!(summary.severity, AggregateSeverity::Green);
        assert!(summary.blocking.is_empty());
        assert!(summary.is_green());
    }

    #[test]
    fn a_critical_skipped_check_is_never_green() {
        // The false-green rule. A denied execution consent must not read as "fine".
        let mut skipped = check(CheckStatus::Skipped, true);
        skipped.not_checked_reason = Some(NotCheckedReason::ExecutionNotAuthorized);
        let results = [check(CheckStatus::Pass, true), skipped];
        let summary = aggregate(&results);
        assert_ne!(summary.severity, AggregateSeverity::Green);
        assert_eq!(summary.severity, AggregateSeverity::NotEnoughChecked);
        assert_eq!(summary.blocking.len(), 1);
        assert_eq!(summary.coverage.critical_not_checked.len(), 1);
    }

    #[test]
    fn a_critical_checker_error_is_never_green() {
        let results = [
            check(CheckStatus::Pass, true),
            check(CheckStatus::Error, true),
        ];
        let summary = aggregate(&results);
        assert_eq!(summary.severity, AggregateSeverity::NotEnoughChecked);
        assert_eq!(summary.coverage.critical_errored.len(), 1);
    }

    #[test]
    fn a_critical_unknown_is_never_green() {
        let results = [check(CheckStatus::Unknown, true)];
        let summary = aggregate(&results);
        assert_eq!(summary.severity, AggregateSeverity::NotEnoughChecked);
    }

    #[test]
    fn an_unknown_check_carries_the_evidence_it_was_given_and_no_skip_reason() {
        // `unknown` is the only status whose evidence class is a parameter, and
        // that is the whole of what distinguishes it from `not_run`: here SURE
        // has evidence, and the evidence supports no verdict; there SURE has
        // none. Two results that differ only in their `CheckStatus` would be a
        // distinction a report could not explain.
        let unknown = CheckResult::unknown(
            CheckId::generate(),
            "local probe: GET /health HTTP/1.1 answered",
            Severity::MustFix,
            true,
            EvidenceClass::ObservedFact,
            fingerprint(),
        );
        assert_eq!(unknown.status, CheckStatus::Unknown);
        assert_eq!(unknown.evidence_class, EvidenceClass::ObservedFact);
        assert!(
            unknown.not_checked_reason.is_none(),
            "unknown means the check ran and established nothing, not that it was skipped"
        );

        let skipped = CheckResult::not_run(
            CheckId::generate(),
            "local probe: GET /health HTTP/1.1 answered",
            Severity::MustFix,
            true,
            NotCheckedReason::ToolUnavailable,
            fingerprint(),
        );
        assert_eq!(skipped.status, CheckStatus::Skipped);
        assert!(skipped.not_checked_reason.is_some());

        // Both block green, and for different reasons — the distinction the
        // report has to be able to make.
        for result in [unknown, skipped] {
            let summary = aggregate(&[result]);
            assert_ne!(summary.severity, AggregateSeverity::Green);
        }
    }

    #[test]
    fn a_critical_failure_outranks_a_missing_check() {
        let mut skipped = check(CheckStatus::Skipped, true);
        skipped.not_checked_reason = Some(NotCheckedReason::NetworkNotPermitted);
        let results = [check(CheckStatus::Fail, true), skipped];
        let summary = aggregate(&results);
        assert_eq!(summary.severity, AggregateSeverity::NotReady);
        assert_eq!(summary.blocking.len(), 2);
    }

    #[test]
    fn an_empty_plan_is_not_green() {
        let summary = aggregate(&[]);
        assert_eq!(summary.severity, AggregateSeverity::NotEnoughChecked);
        assert!(!summary.is_green());
    }

    #[test]
    fn a_run_that_only_skipped_everything_is_not_green() {
        let results = [
            check(CheckStatus::Skipped, false),
            check(CheckStatus::Unknown, false),
        ];
        let summary = aggregate(&results);
        assert_eq!(summary.severity, AggregateSeverity::NotEnoughChecked);
    }

    #[test]
    fn out_of_scope_critical_checks_do_not_block_but_are_not_a_clean_green() {
        for reason in [
            NotCheckedReason::NotApplicable,
            NotCheckedReason::UnsupportedStack,
            NotCheckedReason::DisabledByConfiguration,
        ] {
            assert!(reason.is_scope_limit());
            let mut skipped = check(CheckStatus::Skipped, true);
            skipped.not_checked_reason = Some(reason);
            let results = [check(CheckStatus::Pass, true), skipped];
            let summary = aggregate(&results);
            assert_eq!(
                summary.severity,
                AggregateSeverity::NeedsAttention,
                "{reason:?}"
            );
            assert_eq!(summary.coverage.critical_out_of_scope.len(), 1);
            assert!(summary.blocking.is_empty(), "{reason:?} must not block");
        }
    }

    #[test]
    fn a_clean_green_needs_every_recorded_critical_check_to_have_run_and_passed() {
        let results = [
            check(CheckStatus::Pass, true),
            check(CheckStatus::Pass, false),
            check(CheckStatus::Pass, true),
        ];
        let summary = aggregate(&results);
        assert_eq!(summary.severity, AggregateSeverity::Green);
        assert_eq!(summary.coverage.critical_checked, 2);
        assert!(summary.coverage.has_any_critical_result());
    }

    #[test]
    fn gaps_that_are_not_scope_limits_do_block() {
        for reason in [
            NotCheckedReason::ExecutionNotAuthorized,
            NotCheckedReason::UserDeclined,
            NotCheckedReason::DependencyInstallNotPermitted,
            NotCheckedReason::NetworkNotPermitted,
            NotCheckedReason::ToolUnavailable,
            NotCheckedReason::ExternalServiceUnavailable,
            NotCheckedReason::AnalysisProviderDisabled,
            NotCheckedReason::UnknownReason,
        ] {
            assert!(!reason.is_scope_limit());
            let mut skipped = check(CheckStatus::Skipped, true);
            skipped.not_checked_reason = Some(reason);
            let summary = aggregate(&[skipped]);
            assert_ne!(summary.severity, AggregateSeverity::Green, "{reason:?}");
        }
    }

    #[test]
    fn analysis_provider_disabled_is_recognized_and_reported() {
        let reason = NotCheckedReason::AnalysisProviderDisabled;
        assert!(!reason.is_scope_limit());
        assert!(reason.is_analysis_provider_disabled());
        let explanation = reason.plain_explanation();
        assert!(
            explanation.contains("analysis provider"),
            "explanation should mention the analysis provider: {explanation}"
        );
        assert!(
            explanation.contains("model-backed"),
            "explanation should mention model-backed checks: {explanation}"
        );
    }

    #[test]
    fn a_non_critical_failure_degrades_but_does_not_block() {
        let results = [
            check(CheckStatus::Pass, true),
            check(CheckStatus::Fail, false),
        ];
        let summary = aggregate(&results);
        assert_eq!(summary.severity, AggregateSeverity::NeedsAttention);
        assert!(summary.blocking.is_empty());
        assert!(!summary.is_green());
    }

    #[test]
    fn a_critical_warning_is_not_green_but_does_not_block() {
        let results = [check(CheckStatus::Warning, true)];
        let summary = aggregate(&results);
        assert_eq!(summary.severity, AggregateSeverity::NeedsAttention);
        assert!(summary.blocking.is_empty());
        assert_eq!(summary.coverage.critical_checked, 1);
    }

    #[test]
    fn counts_add_up() {
        let results = [
            check(CheckStatus::Pass, true),
            check(CheckStatus::Fail, false),
            check(CheckStatus::Warning, false),
            check(CheckStatus::Skipped, false),
            check(CheckStatus::Error, false),
            check(CheckStatus::Unknown, false),
        ];
        let counts = StatusCounts::tally(results.iter().map(|r| r.status));
        assert_eq!(counts.total(), 6);
        assert_eq!(counts.checked(), 3);
        assert_eq!(counts.not_checked(), 3);
    }

    #[test]
    fn a_wire_round_trip_preserves_every_status() {
        for &status in CheckStatus::ALL {
            let json = serde_json::to_string(&status).expect("serialize");
            assert_eq!(json, format!("\"{}\"", status.as_str()));
        }
    }

    #[test]
    fn after_the_fact_reports_carry_the_frozen_caveat() {
        assert!(RequirementClaim::AfterTheFact.caveat().is_some());
        assert!(RequirementClaim::Comparable.caveat().is_none());
        assert!(NO_TRUSTED_INTENT_LIMITATION.contains("cannot confirm"));
    }

    #[test]
    fn agg_severities_have_plain_language_headlines_free_of_jargon() {
        for severity in [
            AggregateSeverity::Green,
            AggregateSeverity::NeedsAttention,
            AggregateSeverity::NotReady,
            AggregateSeverity::NotEnoughChecked,
        ] {
            let headline = severity.headline().to_lowercase();
            for banned in [
                "sha",
                "provenance",
                "gate",
                "attestation",
                "policy violation",
                "schema drift",
            ] {
                assert!(!headline.contains(banned), "{severity:?} leads with jargon");
            }
        }
    }

    #[test]
    fn an_accepted_warning_does_not_hold_the_run_back() {
        let pass = check(CheckStatus::Pass, true);
        let warning = check(CheckStatus::Warning, false);
        let accepted: BTreeSet<CheckId> = [warning.id.clone()].into();
        let summary = aggregate_with_accepted(&[pass, warning], &accepted);
        assert_eq!(summary.severity, AggregateSeverity::Green);
        assert!(summary.is_green());
        assert!(
            summary
                .headline
                .contains("1 finding you reviewed and accepted"),
            "a green run because of an acceptance must say so: {}",
            summary.headline
        );
        // The result itself is a fact and is still counted as the warning it is.
        assert_eq!(summary.counts.warning, 1);
    }

    #[test]
    fn the_plural_headline_says_findings() {
        let pass = check(CheckStatus::Pass, true);
        let first = check(CheckStatus::Warning, false);
        let second = check(CheckStatus::Warning, false);
        let accepted: BTreeSet<CheckId> = [first.id.clone(), second.id.clone()].into();
        let summary = aggregate_with_accepted(&[pass, first, second], &accepted);
        assert_eq!(summary.severity, AggregateSeverity::Green);
        assert!(
            summary
                .headline
                .contains("2 findings you reviewed and accepted are"),
            "{}",
            summary.headline
        );
    }

    #[test]
    fn a_warning_nobody_accepted_still_needs_attention() {
        let pass = check(CheckStatus::Pass, true);
        let warning = check(CheckStatus::Warning, false);
        let summary = aggregate_with_accepted(&[pass, warning], &BTreeSet::new());
        assert_eq!(summary.severity, AggregateSeverity::NeedsAttention);
        assert_eq!(
            summary.headline,
            AggregateSeverity::NeedsAttention.headline()
        );
    }

    #[test]
    fn acceptance_never_discounts_a_failure() {
        let pass = check(CheckStatus::Pass, true);
        let fail = check(CheckStatus::Fail, true);
        let accepted: BTreeSet<CheckId> = [fail.id.clone()].into();
        let summary = aggregate_with_accepted(&[pass, fail], &accepted);
        assert_eq!(summary.severity, AggregateSeverity::NotReady);
    }

    #[test]
    fn acceptance_never_discounts_a_check_that_did_not_run() {
        for status in [
            CheckStatus::Unknown,
            CheckStatus::Error,
            CheckStatus::Skipped,
        ] {
            let pass = check(CheckStatus::Pass, true);
            let other = check(status, true);
            let accepted: BTreeSet<CheckId> = [other.id.clone()].into();
            let summary = aggregate_with_accepted(&[pass, other], &accepted);
            assert_ne!(
                summary.severity,
                AggregateSeverity::Green,
                "{status:?} must never be accepted into a green run"
            );
            assert!(!summary.is_green());
        }
    }

    #[test]
    fn an_accepted_id_that_names_nothing_changes_nothing() {
        let pass = check(CheckStatus::Pass, true);
        let accepted: BTreeSet<CheckId> = [CheckId::generate()].into();
        let summary = aggregate_with_accepted(&[pass], &accepted);
        assert_eq!(summary.severity, AggregateSeverity::Green);
        assert_eq!(summary.headline, AggregateSeverity::Green.headline());
    }

    #[test]
    fn an_empty_accepted_set_aggregates_exactly_like_aggregate() {
        let results = [
            check(CheckStatus::Pass, true),
            check(CheckStatus::Warning, false),
            check(CheckStatus::Skipped, false),
        ];
        let plain = aggregate(&results);
        let with_empty = aggregate_with_accepted(&results, &BTreeSet::new());
        assert_eq!(plain.severity, with_empty.severity);
        assert_eq!(plain.headline, with_empty.headline);
        assert_eq!(plain.counts, with_empty.counts);
    }
}
