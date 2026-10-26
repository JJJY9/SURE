//! The check pipeline: from a project directory to a verdict.
//!
//! `docs/architecture/CHECK_PIPELINE.md` names twelve stages, and this module is
//! the thing that runs them, in that order, for one project. **It implements no
//! stage.** Every stage is a call into a module an earlier phase built and
//! tested — [`crate::discover`], [`crate::project_intent`] and
//! [`crate::intent_model`], [`crate::fingerprint`], [`crate::schedule`],
//! [`crate::checks`] and [`crate::runtime_probes`], the five completeness
//! scanners, [`crate::analysis_provider`], [`crate::claim_checker`],
//! [`crate::aggregation`], [`crate::coverage_summary`],
//! [`crate::project_verdict`] and [`crate::recheck_lifecycle`] — and composed
//! through [`crate::false_completion_aggregator`]. What is written here is the
//! sequencing, the per-stage record, and the rule that decides what all of it
//! means together.
//!
//! # The rule this module exists to keep
//!
//! **A stage that did not run is never a stage that passed.** Every one of the
//! twelve stages gets a [`StageRecord`], and a stage that had work and did not do
//! it takes one of three forms, none of which is silence:
//!
//! - [`StageOutcome::NotPartOfWork`] — this run does not ask for the stage. A
//!   `sure check` produces no repair contract, and a stage SURE was never asked
//!   to perform is not a stage that failed to run.
//! - [`StageOutcome::NotRun`] — the stage had work to do and did not do it, with
//!   the reason the domain's own vocabulary gives where the vocabulary has a word
//!   for it. Every such stage also contributes a [`CheckResult`] to the
//!   aggregate, so the verdict is degraded by the gap rather than merely
//!   accompanied by a note about it.
//! - [`StageOutcome::Unfinished`] — the stage tried and could not finish. The run
//!   has no verdict at all, and [`PipelineOutcome::run`] is `None`.
//!
//! [`PipelineOutcome::is_green`] asks two questions and requires both: the
//! verdict permits hand-off by [`ProjectVerdict`]'s own rule, **and** no stage in
//! this run's range is anything other than [`StageOutcome::Ran`]. The second is
//! not a restatement of the first — a stage whose gap produced no `CheckResult`,
//! because it had nothing checkable to record a gap against, would be invisible
//! to the aggregate and visible here. A reviewer can see both.
//!
//! # What runs
//!
//! Stage 4 builds three things and not one: the schedule, the [`PermissionPlan`]
//! holding every command the schedule names, and the [`Enforcement`] that applies
//! the execution mode to both. It then hands the schedule and the enforcement to
//! [`run_scheduled_checks`](crate::planned_check_runner::run_scheduled_checks),
//! which is the plan carried out — and that one call is the whole of what stages 5
//! and 6 describe.
//!
//! Its contract is one result per scheduled check, in the plan's order, so that
//! **no check that produced nothing can become green**. A check the plan stopped
//! keeps the plan's own
//! [`not_run`](crate::schedule::ScheduledCheck::not_run); a check the mode
//! admitted whose runner reported nothing is an `Error`; two results for one check
//! is a refusal that stops the run rather than a rule for choosing. Static detector
//! checks carry their own observation and reach no process at all — they are
//! [`CheckOperation::Precomputed`](crate::planned_work::CheckOperation::Precomputed),
//! and the runner reads their result out of the evidence.
//!
//! # The project is read twice, and the second read is the one that matters
//!
//! Stage 3 takes **one** fingerprint, and every result in the run names it. That
//! is a binding on the *value* — [`CheckResult::project_fingerprint`]'s own
//! documentation says a result that names its state exists so that it cannot be
//! read against a later one — and it is not a statement about the world. Every
//! result in a run carries the same fingerprint, so nothing inside the run can
//! ever notice that the project moved; `aggregate_run`'s refusal is a
//! within-run consistency check and would refuse a *correct* answer as readily as
//! a wrong one. **The world is what the second read compares against**, and stage
//! 10 takes it, immediately before the results are added up. A result from a
//! check that ran the project's own code, taken before the project moved, is
//! replaced by one that is not a pass and that says why.
//!
//! **A build's own caches are not a change, and this is measured rather than
//! argued.** The fingerprint covers exactly what a check can read
//! ([`crate::fingerprint`]), so `target/` ([`crate::scan`] ignores it as build
//! output), `node_modules/` (vendored) and SURE's own `.sure/` are outside it: a
//! run whose only writes land in those does not move the fingerprint, so it does
//! not invalidate anything and cannot invalidate itself. The honest limit of that
//! statement is the other half of it, and it is not papered over: a build that
//! writes a file the walk **does** cover — a generated source file, a
//! regenerated lockfile — has genuinely changed the project, and the run that
//! caused it has genuinely invalidated its own evidence. That is not a false
//! stale; it is the first failure in [`crate::fingerprint`]'s two-way list being
//! paid for the sake of the second, which is the worse one.
//!
//! # What a run a user did not grant does
//!
//! **Nothing, and that is a reading rather than a promise.**
//! [`crate::consent::decide_for`] refuses any command that runs the project's code
//! in a mode that does not, so under [`ExecutionSettings::inspect_only`] the
//! enforcement admits no such command and the runner is never reached. The
//! measurement is `tests::a_run_a_user_did_not_grant_starts_nothing` below, which
//! hands this pipeline a runner that records being called and cannot start
//! anything: what it observes is that the recording is empty. The same seam, under
//! a granted authority, observes a run *reaching* the runner — which is why the
//! seam is a field rather than a default nobody can substitute.

//!
//! # The store
//!
//! The pipeline reads a store when it is given one and never opens one itself.
//! That is deliberate: opening a store creates its directory and its file, and a
//! check that created a history in order to report that it had nothing to compare
//! against would be a command changing the thing it is describing. `sure doctor`
//! states the same rule for the same reason.

use std::path::Path;

use sure_domain::evidence::{
    ClaimAssessment, Evidence, EvidenceAnchor, EvidenceClass, StalenessReason,
};
use sure_domain::execution::{ExecutionMode, ExecutionPermissions};
use sure_domain::finding::{
    AssessmentSource, Finding, FindingBuilder, FindingStatus, SeverityRationale,
};
use sure_domain::ids::{CheckId, ClaimId, FingerprintId};
use sure_domain::intent::{IntentSource, ProjectIntent};
use sure_domain::severity::Severity;
use sure_domain::status::{CheckResult, CheckStatus, NotCheckedReason};
use sure_domain::vocabulary::{Claim, ProjectFingerprint, ProjectSupport, ProjectVerdict};

use crate::aggregation::{RunReport, aggregate_run};
use crate::analysis_provider;
use crate::candidate_scanner::CandidateScanner;
use crate::capability_report;
use crate::checks::{self, check_id};
use crate::claim_checker::{self, CheckedClaim};
use crate::components::ComponentGraph;
use crate::config::AnalysisConfig;
use crate::config::AnalysisProvider;
use crate::config::Config;
use crate::config::ExecutionSettings;
use crate::consent::{PermissionPlan, PlannedCheck};
use crate::coverage_summary::{CoverageNotCheckedSummary, summarize};
use crate::demo_data_heuristics::DemoDataHeuristics;
use crate::discover::{self, DiscoverOptions, Discovery, Ecosystem, Findings};
use crate::enforce::Enforcement;
use crate::false_completion_aggregator;
use crate::findings_from_checks::findings_from_checks;
use crate::fingerprint::{self, project_fingerprint};
use crate::intent_implementation::compare_intent_to_project;
use crate::intent_model;
use crate::noop_heuristics::NoOpHeuristics;
use crate::planned_check_runner::{CheckRunner, run_scheduled_checks};
use crate::planned_work::{CheckOperation, PlannedWork, PrecomputedEvidence};
use crate::project_intent;
use crate::project_verdict::build_verdict;
use crate::recheck_lifecycle::{self, LifecycleInputs, LifecycleUpdate};
use crate::repair_impact::{seed_rechecks, select_impacted_checks};
use crate::route_consistency::RouteConsistency;
use crate::runtime_probes::{PlanRefused, ProbePlan};
use crate::schedule::{CheckProposal, CheckSchedule, PlanBuilder, ProposalRefused, ScheduledCheck};
use crate::service_plan::ServicePlan;
use crate::store::Store;
use crate::support;
use crate::ui_action_bridge::UiActionBridge;

/// What SURE was asked to do with the pipeline.
///
/// The three commands on this surface that reach the engine, and the reason they
/// are a value rather than three entry points: they differ in **how far down the
/// twelve stages they go** and in nothing else. They share the discovery, the
/// intent, the fingerprint, the plan, the checks, the aggregation and the
/// verdict, so a second entry point would be a second copy of all of that.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Purpose {
    /// `sure check`: stages 1 to 10.
    Check,
    /// `sure repair`: stages 1 to 11. The same check, plus the repair contract.
    Repair,
    /// `sure recheck`: all twelve. The same check, plus the comparison with what
    /// the last run left open.
    Recheck,
}

impl Purpose {
    /// The stable name, matching the command a user typed.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Check => "check",
            Self::Repair => "repair",
            Self::Recheck => "recheck",
        }
    }

    /// The last stage this purpose performs.
    ///
    /// Stated as an endpoint rather than as a list, because the range is
    /// contiguous: a run performs stages `1..=this` and no others, and a table of
    /// two ranges is a table somebody has to keep in step with the enum. The
    /// stages after it are [`StageOutcome::NotPartOfWork`] and are recorded rather
    /// than omitted, so a reader of the log sees the whole documented pipeline
    /// whatever the command was.
    #[must_use]
    pub const fn last_stage(self) -> Stage {
        match self {
            Self::Check => Stage::Aggregate,
            Self::Repair => Stage::RepairContract,
            Self::Recheck => Stage::Recheck,
        }
    }

    /// Whether this purpose performs the repair-contract stage.
    #[must_use]
    pub const fn wants_repair_contracts(self) -> bool {
        matches!(self, Self::Repair | Self::Recheck)
    }

    /// Whether this purpose performs the re-check stage.
    #[must_use]
    pub const fn wants_recheck(self) -> bool {
        matches!(self, Self::Recheck)
    }
}

/// One stage of `docs/architecture/CHECK_PIPELINE.md`.
///
/// The variants are in the order that document lists them, and [`Self::ALL`] is
/// that order. A stage's number is its position, so a report can print "3/12"
/// without a second table to keep in step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Stage {
    /// 1. Discover the project, its stacks, components and declared commands.
    Discover,
    /// 2. Resolve intent from explicit and documented sources.
    ResolveIntent,
    /// 3. Fingerprint the current relevant project state.
    Fingerprint,
    /// 4. Plan static and dynamic checks and their execution trust.
    Plan,
    /// 5. Static deterministic checks that do not execute project code.
    StaticChecks,
    /// 6. Approved dynamic checks, under the selected execution mode.
    DynamicChecks,
    /// 7. Completeness analysis: mocks, stubs, fake success, dead glue.
    Completeness,
    /// 8. Grounded model assessment, if a provider is configured.
    ModelAssessment,
    /// 9. Claim checking against observed evidence and the current state.
    ClaimChecking,
    /// 10. Aggregate into findings, scope and a verdict.
    Aggregate,
    /// 11. Repair contract for the selected findings.
    RepairContract,
    /// 12. Re-check affected and regression checks after a repair.
    Recheck,
}

impl Stage {
    /// Every stage, in the documented order.
    pub const ALL: &'static [Self] = &[
        Self::Discover,
        Self::ResolveIntent,
        Self::Fingerprint,
        Self::Plan,
        Self::StaticChecks,
        Self::DynamicChecks,
        Self::Completeness,
        Self::ModelAssessment,
        Self::ClaimChecking,
        Self::Aggregate,
        Self::RepairContract,
        Self::Recheck,
    ];

    /// The stage's number in the documented order, counting from one.
    #[must_use]
    pub const fn number(self) -> u8 {
        match self {
            Self::Discover => 1,
            Self::ResolveIntent => 2,
            Self::Fingerprint => 3,
            Self::Plan => 4,
            Self::StaticChecks => 5,
            Self::DynamicChecks => 6,
            Self::Completeness => 7,
            Self::ModelAssessment => 8,
            Self::ClaimChecking => 9,
            Self::Aggregate => 10,
            Self::RepairContract => 11,
            Self::Recheck => 12,
        }
    }

    /// The stage's name, spelled as the architecture document spells it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Discover => "discover",
            Self::ResolveIntent => "resolve-intent",
            Self::Fingerprint => "fingerprint",
            Self::Plan => "plan",
            Self::StaticChecks => "static-checks",
            Self::DynamicChecks => "dynamic-checks",
            Self::Completeness => "completeness",
            Self::ModelAssessment => "model-assessment",
            Self::ClaimChecking => "claim-checking",
            Self::Aggregate => "aggregate",
            Self::RepairContract => "repair-contract",
            Self::Recheck => "recheck",
        }
    }

    /// The title a report shows for this stage.
    #[must_use]
    pub const fn title(self) -> &'static str {
        match self {
            Self::Discover => "Find the project's parts",
            Self::ResolveIntent => "Work out what was asked for",
            Self::Fingerprint => "Take the project's fingerprint",
            Self::Plan => "Decide what to check",
            Self::StaticChecks => "Read the project and check it",
            Self::DynamicChecks => "Run the project's own checks",
            Self::Completeness => "Look for unfinished work",
            Self::ModelAssessment => "Ask a model to assess the project",
            Self::ClaimChecking => "Check what was claimed against the evidence",
            Self::Aggregate => "Work out the verdict",
            Self::RepairContract => "Write instructions for a repair",
            Self::Recheck => "Compare with what the last run found",
        }
    }

    /// The identifier SURE uses for a result this stage contributes.
    ///
    /// Deterministic, through [`crate::checks::check_id`], so that the same stage
    /// in the same project is the same check on every run. A generated identifier
    /// would make two runs' results for one stage look like two stages.
    #[must_use]
    pub fn id(self) -> CheckId {
        check_id("sure.pipeline", self.as_str())
    }
}

/// What happened to one stage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StageOutcome {
    /// The stage did its work for this run.
    Ran {
        /// What it did, in one line a person reads.
        detail: String,
    },
    /// This run does not ask for the stage.
    ///
    /// Not a gap: nothing was asked of the stage, so there is nothing that failed
    /// to happen. Recorded rather than omitted so that the log shows the whole
    /// documented pipeline, and deliberately not turned into a [`CheckResult`]: a
    /// result saying "not checked" about a stage nobody asked for would be a gap
    /// SURE invented.
    NotPartOfWork {
        /// Why this run does not ask for it.
        detail: String,
    },
    /// The stage had work to do and did not run it.
    ///
    /// `reason` is the domain's own vocabulary where the vocabulary has a word for
    /// it, so the sentence a user reads is not invented here; `None` when the
    /// honest answer is in `detail` and no variant of [`NotCheckedReason`] says
    /// it.
    NotRun {
        /// Why, in the vocabulary's terms when it has them.
        reason: Option<NotCheckedReason>,
        /// What did not happen, in plain language.
        detail: String,
    },
    /// The stage tried and could not finish.
    ///
    /// The run has no verdict. This is the only outcome that stops the pipeline: a
    /// stage that cannot finish leaves the stages after it without an input, and
    /// carrying on would produce a report about a project SURE never got to look
    /// at.
    Unfinished {
        /// What stopped it.
        detail: String,
    },
}

impl StageOutcome {
    /// Whether the stage did its work.
    #[must_use]
    pub const fn ran(&self) -> bool {
        matches!(self, Self::Ran { .. })
    }

    /// Whether SURE has to say that this stage did not happen.
    ///
    /// `NotPartOfWork` is not a gap — see [`StageOutcome`] — and `Ran` is not one
    /// either. Everything else is.
    #[must_use]
    pub const fn is_a_gap(&self) -> bool {
        matches!(self, Self::NotRun { .. } | Self::Unfinished { .. })
    }

    /// The sentence a report prints for this outcome.
    #[must_use]
    pub fn detail(&self) -> &str {
        match self {
            Self::Ran { detail }
            | Self::NotPartOfWork { detail }
            | Self::NotRun { detail, .. }
            | Self::Unfinished { detail } => detail,
        }
    }
}

/// One stage and what happened to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StageRecord {
    /// Which stage.
    pub stage: Stage,
    /// What happened.
    pub outcome: StageOutcome,
}

impl StageRecord {
    /// The stage, its number and what happened, as a line a person reads.
    #[must_use]
    pub fn plain_description(&self) -> String {
        let marker = match &self.outcome {
            StageOutcome::Ran { .. } => "",
            StageOutcome::NotPartOfWork { .. } => " (not part of this run)",
            StageOutcome::NotRun { .. } => " (NOT CHECKED)",
            StageOutcome::Unfinished { .. } => " (STOPPED HERE)",
        };
        format!(
            "{}/{}. {}: {}{marker}",
            self.stage.number(),
            Stage::ALL.len(),
            self.stage.title(),
            self.outcome.detail(),
        )
    }
}

/// One completeness candidate, as a report reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateSummary {
    /// The candidate's stable identity.
    pub id: String,
    /// The short human title.
    pub title: String,
    /// How bad it would be if the check this describes did not pass.
    pub severity: Severity,
    /// Whether the project cannot be trusted for hand-off if it does not.
    pub critical: bool,
    /// Why this candidate is proposed, in plain language.
    pub because: String,
}

/// The completeness candidates stage 7 found.
///
/// Carried rather than folded into the findings, because a candidate is not a
/// defect: [`crate::candidate_scanner`]'s own acceptance is that candidates "are
/// not automatically product defects", and turning a `TODO` comment into a finding
/// with a severity would be this module inventing a judgement no phase made. What
/// the run reports is what was seen — which is what a reader needs in order to
/// decide.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Candidates {
    /// Candidates worth acting on, ordered by their identifiers.
    pub material: Vec<CandidateSummary>,
    /// Candidates that are style noise by [`crate::false_completion_aggregator`]'s
    /// own rule.
    pub style_noise: Vec<CandidateSummary>,
    /// Candidates dropped because another proposal at the same anchor was more
    /// serious.
    pub duplicates_dropped: usize,
}

impl Candidates {
    /// Whether stage 7 saw anything at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.material.is_empty() && self.style_noise.is_empty()
    }

    /// Every candidate, material first.
    #[must_use]
    pub fn total(&self) -> usize {
        self.material.len() + self.style_noise.len()
    }
}

/// Everything a run that finished produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunOutcome {
    /// The project, as text, for a record or a report.
    pub project_root: String,
    /// The execution mode every dynamic check was decided under.
    pub mode: ExecutionMode,
    /// The permissions that mode was granted for this run.
    pub permissions: ExecutionPermissions,
    /// The project state everything in this outcome is about.
    pub project_state: ProjectFingerprint,
    /// What SURE could and could not see, from discovery.
    pub support: ProjectSupport,
    /// The intent the run compared the project against.
    pub intent: ProjectIntent,
    /// What the run planned to check, and what became of each entry.
    pub schedule: CheckSchedule,
    /// Every planned check's result, and every way a critical check contributed.
    pub report: RunReport,
    /// The checked and not-checked scope, in plain language.
    pub coverage: CoverageNotCheckedSummary,
    /// The intent, evidence and scope assembled into one value.
    pub verdict: ProjectVerdict,
    /// What the completeness scanners found.
    pub candidates: Candidates,
    /// What the project's agent claimed, and whether it could be confirmed.
    pub claims: Vec<Claim>,
    /// The caveat the report must carry when SURE may not compare the project
    /// against what the user asked for.
    pub intent_caveat: Option<&'static str>,
    /// One repair contract per finding, when the purpose asks for them.
    pub repairs: Vec<sure_domain::vocabulary::RepairContract>,
    /// What the comparison with the previous run found, for a re-check.
    ///
    /// `Some` exactly when there was something to compare: an earlier run left
    /// findings open for this project and stage 12 matched them against this one.
    /// `None` when there was no store, when the store could not be read, and when
    /// it held nothing open for the project — a first run has no earlier run to
    /// be compared with, and a reader of the report is told that rather than told
    /// that the comparison found nothing.
    pub lifecycle: Option<LifecycleUpdate>,
}

impl RunOutcome {
    /// Every check that did not run, in plan order.
    #[must_use]
    pub fn not_checked(&self) -> Vec<&CheckResult> {
        self.report
            .results()
            .iter()
            .filter(|result| result.is_not_checked())
            .collect()
    }
}

/// The result of running the pipeline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PipelineOutcome {
    /// What SURE was asked to do.
    pub purpose: Purpose,
    /// Every stage, in order, and what happened to each.
    pub stages: Vec<StageRecord>,
    /// What the run found, or `None` when it did not finish.
    pub run: Option<RunOutcome>,
    /// The stage that stopped the run, when one did.
    pub stopped_at: Option<Stage>,
}

impl PipelineOutcome {
    /// What happened to one stage.
    ///
    /// Every stage has exactly one record by construction, so this is total. The
    /// fallback to the first record is unreachable and is there rather than an
    /// index expression because this workspace forbids `panic` in shipped code: a
    /// wrong answer under a test is a better failure than a crash in a terminal.
    #[must_use]
    pub fn stage(&self, stage: Stage) -> &StageRecord {
        let position = stage.number() as usize - 1;
        self.stages.get(position).unwrap_or(&self.stages[0])
    }

    /// Whether every stage this run asked for did its work.
    ///
    /// The second half of [`Self::is_green`], exposed on its own so that a test —
    /// and a reader — can see which of the two questions failed.
    #[must_use]
    pub fn every_stage_ran(&self) -> bool {
        self.stages.iter().all(|record| !record.outcome.is_a_gap())
    }

    /// Every stage SURE has to say did not happen.
    pub fn gaps(&self) -> impl Iterator<Item = &StageRecord> {
        self.stages
            .iter()
            .filter(|record| record.outcome.is_a_gap())
    }

    /// Whether the run finished.
    #[must_use]
    pub const fn finished(&self) -> bool {
        self.run.is_some()
    }

    /// Whether this run may be reported as a clean one.
    ///
    /// Two independent questions, and both have to be yes:
    ///
    /// 1. the verdict permits hand-off, by [`ProjectVerdict`]'s own rule — a green
    ///    aggregate with no open finding that blocks hand-off;
    /// 2. no stage in this run's range failed to do its work.
    ///
    /// The second is not a restatement of the first. A stage whose gap produced no
    /// `CheckResult` — because it had nothing checkable to record a gap against —
    /// would be invisible to the aggregate and visible here.
    #[must_use]
    pub fn is_green(&self) -> bool {
        self.run
            .as_ref()
            .is_some_and(|run| run.verdict.is_ready_for_hand_off() && self.every_stage_ran())
    }
}

/// One run of the pipeline for one project.
///
/// Built rather than called as a function with six arguments, because the inputs
/// are named at the call site and a caller that got the order wrong would
/// otherwise compile. Every field is public and every one is an input: the type
/// holds no state between [`Self::run`] calls, and running it twice is running it
/// twice rather than continuing it.
#[derive(Debug)]
pub struct Pipeline<'a> {
    /// The project directory SURE was pointed at.
    pub project: &'a Path,
    /// What SURE was asked to do.
    pub purpose: Purpose,
    /// The settings in effect, already read from the project.
    pub config: &'a Config,
    /// What SURE may do, and how, already arbitrated between the two files.
    ///
    /// Not read from [`Self::config`] here, and that is the point: this run
    /// plans checks under the mode and the permissions a *hook* would decide
    /// under, and the authority layer is the one place either is worked out
    /// (`Authority::execution`). A stage 4 that read `config.execution` would
    /// plan under whatever the project's own file asked for, including on a
    /// machine whose user never allowed any of it — the defect P13-T009 exists
    /// to close, in the one place `check` can observe it.
    pub execution: ExecutionSettings,
    /// The history to compare against, when there is one.
    ///
    /// Never opened here: see the module comment.
    pub store: Option<&'a Store>,
    /// The goal the user stated on the command line, if they stated one.
    ///
    /// It is here rather than only in the store because stage 2 resolves intent
    /// from it in the same run that records it — a run that wrote a goal and then
    /// checked against a different intent would be recording something it did not
    /// use.
    pub goal: Option<&'a str>,
    /// What carries out the commands the enforcement admits.
    ///
    /// **A field rather than a default**, and that is the whole of why it is
    /// here: *what may this run start?* is a question about this run, so the
    /// answer is given where the run is described — at the call site — rather
    /// than buried in the stage that happens to need it. A caller that hands a
    /// runner which records being called and starts nothing is then measuring
    /// this pipeline rather than a copy of it, which is how the acceptance
    /// *a run a user did not grant starts nothing* is read rather than argued.
    ///
    /// [`ProcessRunner`](crate::planned_check_runner::ProcessRunner) is the only
    /// runner in the product that starts a process. Nothing else in the product
    /// implements [`CheckRunner`], and a caller's own is exactly that: a
    /// caller's own.
    ///
    /// It is consulted only through
    /// [`run_scheduled_checks`](crate::planned_check_runner::run_scheduled_checks),
    /// which hands it an
    /// [`AdmittedRun`](crate::planned_check_runner::AdmittedRun) or an
    /// [`AdmittedService`](crate::planned_check_runner::AdmittedService) and
    /// nothing else — values only an [`Enforcement`] can produce — so this field
    /// cannot be used to start something the mode did not admit.
    pub runner: &'a dyn CheckRunner,
    /// The analysis settings in force, **already arbitrated between the two
    /// files**.
    ///
    /// Not read from [`Self::config`] here, for the same reason
    /// [`Self::execution`] is not: the project's own file holds a *request*,
    /// and a stage that read it directly would consult a provider the
    /// arbitration had not put in force. When the project names no provider,
    /// the user's own file decides (`Authority::analysis`).
    pub analysis: AnalysisConfig,
}

/// A stage that stopped the run.
struct Stopped {
    stage: Stage,
    detail: String,
}

/// What SURE says about a stage it never reached.
const STOPPED_BEFORE: &str = "the run stopped before reaching this stage.";

/// The stage records, kept in order as they are produced.
struct Stages {
    records: Vec<StageRecord>,
}

impl Stages {
    fn new() -> Self {
        Self {
            records: Vec::with_capacity(Stage::ALL.len()),
        }
    }

    fn push(&mut self, stage: Stage, outcome: StageOutcome) {
        debug_assert_eq!(
            self.records.len() + 1,
            stage.number() as usize,
            "stages are recorded once each and in order"
        );
        self.records.push(StageRecord { stage, outcome });
    }
}

/// The proposals stage 4 gathered, and the ones that could not be planned.
#[derive(Default)]
struct Planned {
    /// Declared commands the project does not have, which are checks SURE could
    /// not plan and must record as not-checked rather than drop.
    missing: Vec<checks::MissingCommand>,
    /// How many runtime probes the project's shape ruled out.
    ///
    /// Read by nothing yet, and kept for the same reason
    /// `ProbePlan::not_planned` is a list rather than a count: the number is the
    /// half a report can print without a new sentence per reason, and a stage
    /// that wanted the reasons has them one call away rather than nowhere.
    not_planned: usize,
    /// Why the probe planner refused, when it did.
    probe_refusal: Option<PlanRefused>,
    /// How many of the project's `checks.services` declarations became checks.
    ///
    /// Zero for every project that declares none, which is every project until
    /// somebody writes one — and **not** the same statement as an empty plan: a
    /// declaration that was refused is counted by [`Self::service_refusals`]
    /// instead, and a set that is empty because nothing was declared and a set
    /// that is empty because everything was refused are two different projects.
    services: usize,
    /// The declarations that could not become checks, one value each.
    ///
    /// **Held as the refusals and not as their count**, unlike
    /// [`Self::not_planned`]: a count says how many and nothing about what to
    /// fix, while the sentence a refusal carries is the whole of what a user can
    /// act on. `PlanRefused` beside it is reported the same way, and the two
    /// readings are meant to be alike.
    service_refusals: Vec<crate::service_plan::ServiceRefusal>,
    /// The checks a declaration could have had and did not, one value each.
    ///
    /// **A different answer from [`Self::service_refusals`]**, and reported
    /// beside it because a reader comparing the two is asking one question:
    /// *the file asked for a check and the plan does not hold it — whose
    /// decision was that?* A refusal is SURE's; a gap is the project's own
    /// setting, or a field its declaration left empty. Held as the values rather
    /// than as a count for the reason the refusals are — each sentence names the
    /// setting that decided, and a count says how many and nothing about which.
    service_gaps: Vec<crate::service_plan::ServiceGap>,
}

impl Pipeline<'_> {
    /// Run the twelve stages, in order, as far as `purpose` asks.
    #[must_use]
    pub fn run(&self) -> PipelineOutcome {
        let mut stages = Stages::new();

        // ---- 1. Discover -----------------------------------------------------
        let discovery = match discover::discover(self.project, &DiscoverOptions::default()) {
            Ok(discovery) => discovery,
            Err(error) => {
                return self.stopped_at(
                    stages,
                    Stopped {
                        stage: Stage::Discover,
                        detail: error.to_string(),
                    },
                );
            }
        };
        let support = support::classify(&discovery);
        stages.push(
            Stage::Discover,
            StageOutcome::Ran {
                detail: describe_discovery(&discovery, &support),
            },
        );

        // ---- 2. Resolve intent -----------------------------------------------
        let intent = self.resolve_intent();
        stages.push(
            Stage::ResolveIntent,
            StageOutcome::Ran {
                detail: describe_intent(&intent),
            },
        );

        // ---- 3. Fingerprint --------------------------------------------------
        let state =
            match project_fingerprint(self.project, &fingerprint::FingerprintOptions::default()) {
                Ok(state) => state,
                Err(error) => {
                    return self.stopped_at(
                        stages,
                        Stopped {
                            stage: Stage::Fingerprint,
                            detail: error.to_string(),
                        },
                    );
                }
            };
        let fingerprint = state.id.clone();
        stages.push(
            Stage::Fingerprint,
            StageOutcome::Ran {
                detail: format!("the project is at fingerprint {}.", state.digest),
            },
        );

        // ---- 4. Plan ---------------------------------------------------------
        let graph = ComponentGraph::of(&discovery);
        let mode = self.execution.mode;
        let permissions = self.execution.permissions.clone();
        let mut builder = PlanBuilder::new(mode, permissions.clone());
        let planned = propose_everything(
            &discovery,
            &graph,
            &intent,
            &self.config.checks,
            &mut builder,
        );
        let refused: Vec<ProposalRefused> = builder.refused().to_vec();
        let schedule = builder.build();
        stages.push(
            Stage::Plan,
            StageOutcome::Ran {
                detail: describe_plan(&schedule, &refused, &planned),
            },
        );

        // The plan of commands, and the decision about every one of them.
        //
        // Built here because this is the first point at which the fingerprint and
        // the schedule exist together, and built from **the mode and the
        // permissions this run was handed** — `self.execution`, which comes from
        // `Authority::execution` — rather than from the project's own
        // configuration. A plan built from `self.config.execution` would be a
        // project granting itself the right to run its own code, which is the
        // defect the authority layer exists to close and the one thing this
        // wiring must not reintroduce.
        //
        // A check that holds one command has a command to plan, and a service's
        // own command is one: a service is started by a program with an argument
        // vector, and the mode's decision about *that* program is what lets the
        // service door pair an admission with a `ServiceCheckSpec`. A service whose
        // command was never planned is a service the enforcement can only stop,
        // which is the honest answer for a program this run was not granted.
        //
        // A browser check holds a service too, and `P18-T010` applied the rule
        // above to it: the program that starts its service is planned here, so the
        // browser door can pair an admission with a `BrowserCheckSpec` exactly as
        // the service door pairs one with a `ServiceCheckSpec`. **The page itself
        // is not planned and has nothing to plan**: opening it starts no process
        // and reaches no address SURE did not already reach — see
        // `planned_check_runner.rs`, where a browser check's admission is the
        // program that starts its service and nothing else.
        //
        // A detector's own observation is the one that is not a command, and it is
        // not: it happened while the plan was being made and there is nothing left
        // to admit.
        //
        // `Enforcement` has an answer for a check with no command: it is a check
        // that launches nothing, and nothing is admitted for it.
        let scheduled: Vec<PlannedCheck> = schedule.planned_checks();
        debug_assert_eq!(
            scheduled.len(),
            schedule.checks().len(),
            "`planned_checks` is one entry per scheduled check, in this schedule's order"
        );
        let mut permission_plan =
            PermissionPlan::new(mode, fingerprint.clone(), permissions.clone());
        for (scheduled_check, check) in schedule.checks().iter().zip(&scheduled) {
            let command = match scheduled_check.operation() {
                CheckOperation::Command(spec) => Some(spec),
                CheckOperation::Service(service) => Some(service.command()),
                CheckOperation::Browser(browser) => Some(browser.service().command()),
                CheckOperation::Precomputed(_) => None,
            };
            if let Some(spec) = command {
                permission_plan.add(check.clone(), spec.program(), spec.arguments().to_vec());
            }
        }
        // The plan a report is built from, named the way a person reads it: the
        // command they ran, `sure check` or `sure repair` or `sure recheck`
        // (`Purpose::as_str`). The name reaches `CheckPlan::id` and nowhere else
        // today — `Enforcement::check_plan()` is the only door onto it, the plan is
        // not part of `RunOutcome`, and no render surface prints it — so this is
        // the plan's identity for a caller, not a line in front of a reader.
        let enforcement = Enforcement::of(
            format!("sure {}", self.purpose.as_str()),
            permission_plan,
            &scheduled,
        );

        // The plan carried out, and the whole of what stages 5 and 6 describe.
        //
        // The runner's contract is one result per scheduled check, in the plan's
        // order, and it is asked for every check — including the ones the mode
        // stopped, whose result is the plan's own. So the results below are
        // exactly as many as the schedule is long, and a check that produced
        // nothing is an `Error` rather than a missing row: **there is no path
        // from here to a check that quietly became green.**
        //
        // A refusal is not a shorter list of results — it is a plan this runner
        // cannot read — so it stops the run at the stage that would have consumed
        // the results, which is what `aggregate_run`'s own refusal does one stage
        // later. Nothing is invented for a refusal and no repair is attempted.
        let run_results =
            match run_scheduled_checks(&schedule, &enforcement, &fingerprint, self.runner) {
                Ok(results) => results,
                Err(refusal) => {
                    return self.stopped_at(
                        stages,
                        Stopped {
                            stage: Stage::StaticChecks,
                            detail: refusal.to_string(),
                        },
                    );
                }
            };

        // The runner's results — and only those. The one kind of check it has
        // never heard of is not pushed in here: a declared command the project
        // does not have was never scheduled, so the runner was never handed it
        // and nothing came back for it. Its own declaration stands in for an
        // observation, and it is handed to `aggregate_run` beside these results
        // at stage 10 rather than mixed into them, so that what this list holds
        // stays *what the run reported*.
        let mut results: Vec<CheckResult> = run_results.results().to_vec();

        // ---- 5. Static deterministic checks ----------------------------------
        let static_checks = schedule
            .checks()
            .iter()
            .filter(|scheduled| !scheduled.proposal().requirements().runs_project_code())
            .count();
        let dynamic_checks = schedule.checks().len() - static_checks;
        let stopped_static = schedule
            .checks()
            .iter()
            .filter(|scheduled| !scheduled.proposal().requirements().runs_project_code())
            .filter(|scheduled| {
                enforcement
                    .stopped()
                    .iter()
                    .any(|result| &result.id == scheduled.proposal().id())
            })
            .count();
        stages.push(
            Stage::StaticChecks,
            if static_checks == 0 {
                StageOutcome::NotPartOfWork {
                    detail: "the plan holds no check that reads your project without running it."
                        .to_owned(),
                }
            } else {
                StageOutcome::Ran {
                    detail: format!(
                        "{static_checks} of the planned checks read your project's files and run \
                         nothing. Each of them has a result: {stopped_static} were stopped by the \
                         execution mode and are recorded as not checked rather than passed, and the \
                         rest are the runner's answer — a detector's own observation where the check \
                         carries one, and its command's outcome where the plan holds a command."
                    ),
                }
            },
        );

        // ---- 6. Approved dynamic checks --------------------------------------
        stages.push(
            Stage::DynamicChecks,
            describe_dynamic(&schedule, &enforcement, dynamic_checks),
        );

        // ---- 7. Completeness analysis ----------------------------------------
        let candidates = completeness(&discovery, &intent);
        stages.push(
            Stage::Completeness,
            StageOutcome::Ran {
                detail: describe_candidates(&candidates),
            },
        );

        // ---- 8. Grounded model assessment ------------------------------------
        let (model_outcome, model_results, model_findings) =
            self.model_assessment(&fingerprint, &candidates);
        results.extend(model_results);
        stages.push(Stage::ModelAssessment, model_outcome);

        // ---- 9. Claim checking -----------------------------------------------
        let (claims, claim_outcome, claim_results) = self.check_claims(&fingerprint);
        results.extend(claim_results);
        stages.push(Stage::ClaimChecking, claim_outcome);

        // ---- 10. Aggregate ---------------------------------------------------
        //
        // **The project is read a second time, here, before anything is added
        // up.** Stage 3's fingerprint is the state every result in this run
        // names, and a run cannot notice from the inside that it has stopped
        // being true: every result names the same state, so `aggregate_run`'s
        // own refusal is a check on the set's consistency and never on the
        // world. What the run has done since stage 3 is work that takes real
        // time — a build, a test suite — and a project edited while it ran
        // leaves exactly the stale pass `CheckResult::project_fingerprint`
        // exists to prevent.
        //
        // **This is the last read that can still change anything**, which is why
        // the pipeline takes it here: a fingerprint computed one line above
        // `aggregate_run` covers the whole of the run's window, and one taken
        // beside the runtime work covers a prefix of it. It is also why there is
        // no thirteenth stage. The second read is not a phase of checking anybody
        // asked for — nothing is discovered, planned, run or reported by it — it
        // is a fact about whether this run's evidence is still current, so it
        // belongs inside the stage that has to act on the answer.
        // `Stage::Aggregate` is that stage: the results it is about to add up are
        // the ones this changes, and a reader who wants to know what the verdict
        // is about reads this stage's line.
        //
        // The page taken from the environment is the domain's own:
        // [`StalenessReason::SupersededByLaterChange`] is the vocabulary's word
        // for "this was checked before later changes were made", and it is quoted
        // rather than paraphrased. The status is `Unknown`, which is the one
        // `CheckResult::unknown` gives *SURE has evidence that supports no
        // verdict* — never `Warning`, which `CriticalState::from_status` maps to
        // `Passed` and which therefore blocks nothing on the checks where it
        // matters most.
        let current_state =
            project_fingerprint(self.project, &fingerprint::FingerprintOptions::default());
        let moved = stale_evidence_reason(&state, &current_state);
        let stale = moved.as_deref().map_or_else(Vec::new, |reason| {
            invalidate_runtime_passes(reason, &schedule, &mut results)
        });
        let report = match aggregate_run(&schedule, &results, &planned.missing, &fingerprint) {
            Ok(report) => report,
            Err(refusal) => {
                return self.stopped_at(
                    stages,
                    Stopped {
                        stage: Stage::Aggregate,
                        detail: refusal.to_string(),
                    },
                );
            }
        };
        // The tier comes from the project's own recorded events, not from the
        // command line, and the store is the one this run was handed — never one
        // opened here (see the module comment). What SURE may say about a session
        // it recorded is a fact about the project being checked, and a report
        // that answered "no session visibility" for a project with a week of
        // events in the store would be SURE understating what it knows about the
        // one thing this whole layer exists to know.
        //
        // The rule for what those events earn, and the account of what was
        // counted, are `capability_report`'s: this stage passes the store and the
        // project root and adds no rule of its own.
        let project_root = discovery.root.to_string_lossy().into_owned();
        let capability_of_project = capability_report::for_project(self.store, &project_root);
        let capability = capability_of_project.report;
        let coverage = summarize(&schedule, &report, &capability);
        let not_checked: Vec<CheckResult> = report
            .results()
            .iter()
            .filter(|result| result.is_not_checked())
            .cloned()
            .collect();
        // What this run found, as opposed to what it looked at. The rule and the
        // argument for it are in `crate::findings_from_checks`: a check result
        // that did not pass and did not stand aside for a scope limit is the one
        // thing in a run that is already about the project, already carries a
        // severity and already carries an evidence class. Candidates are not
        // folded in here and the comment above the field that carries them says
        // why; claims cannot be either, because `claim_checker` never contradicts
        // one.
        //
        // Read from `report.results()` and not from `not_checked` below, although
        // the two overlap: `not_checked` is the subset with no result, and a check
        // that ran and failed is a finding with no entry in it.
        let mut findings = findings_from_checks(report.results(), &schedule);
        findings.extend(model_findings);
        let verdict = build_verdict(
            fingerprint,
            report.aggregate().clone(),
            intent.clone(),
            capability,
            findings,
            not_checked,
            claims.clone(),
        );
        // A store whose events could not be read is not a project with no
        // session, and the two must not read alike: the run reports the tier it
        // can prove without those events and says here what stopped it. The
        // error's own text is in this detail rather than in the capability line,
        // which is a sentence SURE writes about itself.
        let capability_failure = match capability_of_project.read_failure {
            Some(detail) => format!(
                " SURE could not read the events its store holds, so it reports the tier it can \
                 prove without them: {detail}"
            ),
            None => String::new(),
        };
        // What the second read did, said on the stage a reader looks at for what
        // the verdict is about. One sentence and not a paragraph: each replaced
        // result carries the movement in its own reason, and the coverage summary
        // lists every one of them under "could not run" — so this line says the
        // thing only it can say, which is that there are such results at all.
        //
        // **The movement is said even when nothing was replaced**, which is the
        // second arm and not an omission. `moved` and `stale` are two different
        // facts — the project is not where stage 3 found it, and this run withdrew
        // these passes — and a line that reported only the second would answer the
        // first by saying nothing at all. That case is reachable on the ordinary
        // path rather than a corner: it is every run with nothing to withdraw,
        // which is every run whose checks read the project without running it.
        // [`stale_evidence_reason`] answers `Some` when it could not read the
        // project a second time *precisely so that the movement is not silently
        // dropped*, and dropping it here would undo that decision one line later.
        let stale_clause = match moved.as_deref() {
            None => String::new(),
            Some(reason) if stale.is_empty() => format!(
                " {reason} Nothing above is replaced, because no check that ran your project's \
                 own code was left standing as a pass — and these results describe the state \
                 SURE read rather than the state the project is in now."
            ),
            Some(_) => {
                let titles: Vec<&str> = results
                    .iter()
                    .filter(|result| stale.contains(&result.id))
                    .map(|result| result.title.as_str())
                    .collect();
                format!(
                    " {} of those checks ran your project's own code and the project changed \
                     while the run was working, so their earlier results are not current: they \
                     are not counted above as checks that produced a result, and each one says \
                     what moved: {}.",
                    stale.len(),
                    titles.join(", "),
                )
            }
        };
        stages.push(
            Stage::Aggregate,
            StageOutcome::Ran {
                detail: format!(
                    "{} {} check(s) produced a result, {} did not run.{stale_clause}{capability_failure}",
                    verdict.aggregate.headline,
                    coverage.checked_count,
                    coverage.not_checked.len(),
                ),
            },
        );

        // ---- 11 and 12, as far as this purpose asks --------------------------
        let mut run = RunOutcome {
            project_root,
            mode,
            permissions,
            project_state: state,
            support,
            intent,
            schedule,
            report,
            coverage,
            verdict,
            candidates,
            claims,
            intent_caveat: self.resolve_intent().caveat(),
            repairs: Vec::new(),
            lifecycle: None,
        };

        if self.purpose.wants_repair_contracts() {
            let (repairs, outcome) = repair_contracts(&run);
            run.repairs = repairs;
            stages.push(Stage::RepairContract, outcome);
        } else {
            stages.push(
                Stage::RepairContract,
                StageOutcome::NotPartOfWork {
                    detail: format!(
                        "`sure {}` reports what was found; `sure repair` turns it into \
                         instructions an agent can act on.",
                        self.purpose.as_str()
                    ),
                },
            );
        }

        if self.purpose.wants_recheck() {
            let (lifecycle, outcome) = self.recheck(&run);
            run.lifecycle = lifecycle;
            stages.push(Stage::Recheck, outcome);
        } else {
            stages.push(
                Stage::Recheck,
                StageOutcome::NotPartOfWork {
                    detail: "this run is not comparing against an earlier one.".to_owned(),
                },
            );
        }

        PipelineOutcome {
            purpose: self.purpose,
            stages: stages.records,
            run: Some(run),
            stopped_at: None,
        }
    }

    /// The outcome for a run that could not finish.
    fn stopped_at(&self, mut stages: Stages, stopped: Stopped) -> PipelineOutcome {
        let stopped_at = stopped.stage;
        let number = stopped_at.number();
        stages.push(
            stopped_at,
            StageOutcome::Unfinished {
                detail: stopped.detail,
            },
        );
        for stage in Stage::ALL.iter().copied() {
            if stage.number() > number {
                stages.push(
                    stage,
                    StageOutcome::NotPartOfWork {
                        detail: STOPPED_BEFORE.to_owned(),
                    },
                );
            }
        }
        PipelineOutcome {
            purpose: self.purpose,
            stages: stages.records,
            run: None,
            stopped_at: Some(stopped_at),
        }
    }

    /// Stage 2: every trusted source of intent, kept apart by where it came from.
    ///
    /// Two channels can stand in for what the user asked for: the words they typed
    /// on this command line, and — where a permission allows it — what a saved
    /// session showed. The project's own `sure.yaml` is documentation, and
    /// [`intent_model::documented_goal`] labels it as such, so it is carried and
    /// never graded against. Nothing here invents a requirement from a guess:
    /// [`intent_model::inferred`] exists for a guess and is the caller's to add,
    /// not this function's.
    fn resolve_intent(&self) -> ProjectIntent {
        let mut requirements = Vec::new();
        if let Some(goal) = self.goal
            && let Ok(recorded) = project_intent::explicit_goal(goal)
        {
            requirements.extend(recorded.requirements);
        }
        if let Some(documented) = intent_model::documented_goal(self.config) {
            requirements.push(documented);
        }
        ProjectIntent::from_requirements(requirements)
    }

    /// Stage 8: the grounded model assessment, or the state a run is in without
    /// one.
    ///
    /// **This is a scope question and not a failure.** With no provider configured
    /// the stage contributes a non-critical not-checked result carrying
    /// [`NotCheckedReason::AnalysisProviderDisabled`], which is the vocabulary's
    /// own word for it, and [`crate::project_verdict`] already has a sentence for
    /// what that costs. The run is then `needs_attention` rather than green, and it
    /// is never reported as having passed something it did not do.
    fn model_assessment(
        &self,
        fingerprint: &FingerprintId,
        candidates: &Candidates,
    ) -> (StageOutcome, Vec<CheckResult>, Vec<Finding>) {
        let analysis = &self.analysis;
        let not_checked = |reason: NotCheckedReason, detail: &str| {
            CheckResult::not_run(
                Stage::ModelAssessment.id(),
                Stage::ModelAssessment.title(),
                Severity::Note,
                false,
                reason,
                fingerprint.clone(),
            )
            .with_reason(detail.to_owned())
        };

        if analysis.provider == AnalysisProvider::Disabled {
            let detail = "No analysis provider is configured, so SURE assessed nothing with a \
                          model. This is a scope limit and not a failure: the deterministic \
                          checks are unaffected.";
            return (
                StageOutcome::NotRun {
                    reason: Some(NotCheckedReason::AnalysisProviderDisabled),
                    detail: detail.to_owned(),
                },
                vec![not_checked(
                    NotCheckedReason::AnalysisProviderDisabled,
                    detail,
                )],
                Vec::new(),
            );
        }

        match analysis_provider::build(analysis, self.project) {
            // 模型评估接入(最小版):把阶段 7 找到的候选(material)交给配置好
            // 的分析器做 grounded 评估——每条候选要么被确认(成为一条
            // model_assessment 证据类的 finding),要么被判为噪音(不加 finding,
            // 但原样保留在阶段明细里)。没有候选时如实记录"没有可评估的东西"。
            Ok(analyzer) => self.assess_candidates(analyzer.as_ref(), fingerprint, candidates),
            // The project asked for a provider SURE cannot build — a local-command
            // provider with no command, say. That is a configuration fault rather
            // than a scope limit, it is visible as one, and it is not a crash.
            Err(error) => {
                let detail = format!("SURE could not build the configured model provider: {error}");
                (
                    StageOutcome::NotRun {
                        reason: Some(NotCheckedReason::AnalysisProviderDisabled),
                        detail: detail.clone(),
                    },
                    vec![not_checked(
                        NotCheckedReason::AnalysisProviderDisabled,
                        &detail,
                    )],
                    Vec::new(),
                )
            }
        }
    }

    /// 阶段 8 的接入面(最小版):把阶段 7 的候选交给分析器逐条评估。
    ///
    /// 每条被确认的候选产出一 LinkFinding:证据类如实标
    /// [`EvidenceClass::ModelAssessment`],锚为 `model_only`(模型意见没有
    /// 具体项目位置可指,不可核——`is_model_only` 判据据此命中),严重度按
    /// `docs/adr/0005-evidence-hierarchy.md` 以 ShouldFixFirst 为上限
    /// (模型独证不能支撑 must_fix),rationale 与之自动配对(builder 校验)。
    /// 上游预留的 planned-check 管道(`disabled_result`/模型检查提案)接线
    /// 后,这里迁回检查结果通道。
    fn assess_candidates(
        &self,
        analyzer: &dyn analysis_provider::Analyzer,
        fingerprint: &FingerprintId,
        candidates: &Candidates,
    ) -> (StageOutcome, Vec<CheckResult>, Vec<Finding>) {
        if candidates.material.is_empty() {
            return (
                StageOutcome::NotPartOfWork {
                    detail: "the analysis provider is configured, and the completeness \
                             analysis found no candidate for a model to assess."
                        .to_owned(),
                },
                Vec::new(),
                Vec::new(),
            );
        }
        let prompt = assessment_prompt(self.project, candidates);
        let response = match analyzer
            .analyze(analysis_provider::AnalysisRequest { prompt: &prompt })
        {
            Ok(response) => response,
            Err(error) => {
                let detail =
                    format!("the configured model provider could not assess the project: {error}");
                return (
                    StageOutcome::NotRun {
                        reason: Some(NotCheckedReason::AnalysisProviderDisabled),
                        detail: detail.clone(),
                    },
                    vec![
                        CheckResult::not_run(
                            Stage::ModelAssessment.id(),
                            Stage::ModelAssessment.title(),
                            Severity::Note,
                            false,
                            NotCheckedReason::AnalysisProviderDisabled,
                            fingerprint.clone(),
                        )
                        .with_reason(detail),
                    ],
                    Vec::new(),
                );
            }
        };
        let verdicts = parse_assessment(&response.text, candidates);
        let flagged = verdicts.iter().filter(|verdict| verdict.is_problem).count();
        let mut findings = Vec::new();
        for verdict in verdicts.iter().filter(|verdict| verdict.is_problem) {
            let Some(candidate) = candidates
                .material
                .iter()
                .find(|candidate| candidate.id == verdict.candidate_id)
            else {
                continue;
            };
            // 第一版直接以 Finding 进入报告(见函数 doc 的迁移说明)。
            let severity = model_supported_severity(candidate.severity);
            if let Ok(finding) = FindingBuilder::new(
                AssessmentSource::ModelAssessment,
                SeverityRationale::for_severity(severity)
                    .unwrap_or(SeverityRationale::Informational),
            )
            .title(format!("Model assessment: {}", candidate.title))
            .severity(severity)
            .status(FindingStatus::Open)
            .explanation(verdict.reason.clone())
            .user_impact(
                "A model's assessment of what SURE observed. Model opinion is evidence and \
                 not proof: it may be wrong, and what to do about it stays your call."
                    .to_owned(),
            )
            .next_step("Review the flagged candidate, decide what to do, and re-check.".to_owned())
            .evidence([Evidence::new(
                EvidenceClass::ModelAssessment,
                candidate.because.clone(),
                EvidenceAnchor::model_only(format!("{} ({})", candidate.title, candidate.id)),
                Some(fingerprint.clone()),
                severity,
            )])
            .fingerprint(fingerprint.clone())
            .build()
            {
                findings.push(finding);
            }
        }
        (
            StageOutcome::Ran {
                detail: format!(
                    "the configured model provider assessed {} completeness candidate(s): \
                     {flagged} flagged as problems, {} judged style noise.",
                    candidates.material.len(),
                    verdicts.len() - flagged,
                ),
            },
            Vec::new(),
            findings,
        )
    }

    /// Stage 9: what the project's agent claimed, against what was recorded.
    ///
    /// Without a store there are no claims and nothing to check them against — a
    /// scope limit rather than a gap in the project, and recorded as one. With a
    /// store, [`crate::claim_checker`] decides; a claim SURE cannot confirm is
    /// reported as `Cannot confirm` and never as `Contradicted`, which is that
    /// module's own distinction and not this one's.
    fn check_claims(
        &self,
        fingerprint: &FingerprintId,
    ) -> (Vec<Claim>, StageOutcome, Vec<CheckResult>) {
        let Some(store) = self.store else {
            let detail = "SURE has no recorded history for this machine, so there are no agent \
                          claims to check against evidence.";
            return (
                Vec::new(),
                StageOutcome::NotRun {
                    // A scope limit rather than a gap in the project: nothing was
                    // ever recorded, so there is nothing a claim could be checked
                    // against. `NotApplicable` is the vocabulary's own word for
                    // exactly that, and it is a scope limit, which is why this is
                    // not a critical result.
                    reason: Some(NotCheckedReason::NotApplicable),
                    detail: detail.to_owned(),
                },
                vec![
                    CheckResult::not_run(
                        Stage::ClaimChecking.id(),
                        Stage::ClaimChecking.title(),
                        Severity::Note,
                        false,
                        NotCheckedReason::NotApplicable,
                        fingerprint.clone(),
                    )
                    .with_reason(detail.to_owned()),
                ],
            );
        };

        // 2026-10-20: claims are matched to the project by root, not by this
        // run's minted fingerprint id — see the function's own doc comment.
        let project_root = self.project.to_string_lossy();
        match claim_checker::check_claims_in_store(store, &project_root, fingerprint) {
            Ok(checked) => {
                let detail = if checked.is_empty() {
                    "the history holds no claims about this project.".to_owned()
                } else {
                    format!(
                        "{} claim(s) checked against the recorded evidence.",
                        checked.len()
                    )
                };
                let claims = checked.iter().map(claim_of).collect();
                (claims, StageOutcome::Ran { detail }, Vec::new())
            }
            // SURE tried and could not tell, which is `errored` and not
            // `not_run`: a check that could not be read is a different promise
            // from one that was never going to run, and the vocabulary keeps the
            // two apart for a reader deciding whether to try again.
            Err(error) => {
                let detail = format!("SURE could not read the claims it had recorded: {error}");
                (
                    Vec::new(),
                    StageOutcome::NotRun {
                        reason: Some(NotCheckedReason::UnknownReason),
                        detail: detail.clone(),
                    },
                    vec![CheckResult::errored(
                        Stage::ClaimChecking.id(),
                        Stage::ClaimChecking.title(),
                        Severity::Note,
                        false,
                        detail,
                        fingerprint.clone(),
                    )],
                )
            }
        }
    }

    /// Stage 12: what the last run left open, compared with this one.
    ///
    /// The comparison needs a history. Without one the stage has nothing to
    /// compare against, which is a scope limit: a first run on a machine with no
    /// history is not a run that failed to re-check.
    fn recheck(&self, run: &RunOutcome) -> (Option<LifecycleUpdate>, StageOutcome) {
        let Some(store) = self.store else {
            return (
                None,
                StageOutcome::NotRun {
                    reason: Some(NotCheckedReason::NotApplicable),
                    detail:
                        "SURE has no recorded history for this machine, so there is no earlier \
                             run to compare this one with."
                            .to_owned(),
                },
            );
        };

        // The volume is asked once, here, and the one answer decides every key
        // this stage builds — the keys the earlier findings are looked up by and
        // the keys this run's findings are matched by. Asking twice would be two
        // answers to one question, and the two places a finding could then
        // differ are the two this stage exists to keep apart: a finding dropped
        // from history as a duplicate of its own other spelling, and a finding
        // carried open beside this run's copy of it.
        let case = recheck_lifecycle::case_rule_for(&run.project_root);

        let previous =
            match recheck_lifecycle::previous_open_findings(store, &run.project_root, case) {
                Ok(previous) => previous,
                // **A scan that stopped at its bound arrives here, on purpose.**
                // `previous_open_findings` refuses rather than answering with a
                // list that stopped early — the direction `Store::spend_allowance`
                // fails in — and this arm is the plain-language path that refusal
                // was written for: the stage did not run, the detail says so in the
                // error's own words, and no comparison is built from a list that
                // was cut short. The alternative, reading what there was and
                // warning about it, would put a number in front of a reader that
                // says "this many findings are still open" when the truth is that
                // SURE did not read far enough to know.
                Err(error) => {
                    return (
                        None,
                        StageOutcome::NotRun {
                            reason: Some(NotCheckedReason::UnknownReason),
                            detail: format!(
                                "SURE could not read what an earlier run left open: {error}"
                            ),
                        },
                    );
                }
            };

        // **Nothing to compare is not a comparison, and it is answered as such.**
        // `reconcile` walks `previous_open`, and every entry it walks lands in
        // `kept_open` or in `resolved` — there is no path through its loop that
        // drops one — so an empty `previous` is the *only* way for both lists to
        // come back empty. That is what lets `Some` and `None` carry exactly the
        // fact the callers need: whether SURE compared this run with an earlier
        // one. Returning `Some(empty)` said a comparison happened and found
        // nothing open, which is how the human report came to print "Against the
        // earlier run: 0 finding(s) still open, 0 closed." beside this stage's own
        // "no earlier run left anything open for this project.", and how the
        // machine frame came to carry `{"closed": [], "still_open": []}` — the
        // shape of an answer — where the honest answer is that there was nothing
        // to compare. One result, one explanation: the sentence is absent and
        // `details.lifecycle` is `null`.
        //
        // The stage itself **ran**: the store was read, and what it held is what
        // this says. A stage that did not run would be a gap, and a first
        // re-check is not a gap in the repair loop — there is simply no earlier
        // run yet.
        if previous.is_empty() {
            return (
                None,
                StageOutcome::Ran {
                    detail: "no earlier run left anything open for this project.".to_owned(),
                },
            );
        }

        // Which checks have to pass before an earlier finding may close. The list
        // is `repair_impact::select_impacted_checks`'s answer — the module that
        // owns the rule, not a second rule written here — asked of the contract
        // that governs each finding. It is asked rather than stored because a
        // copy of it on the run would be a second list that could disagree with
        // the contract it was copied from, and the function is pure.
        //
        // **Two sources of contracts, and the second is what makes closing
        // reachable at all.** A finding the current run still produces has the
        // contract stage 11 just wrote for it. A finding the current run no
        // longer produces — the fix removed what it was about, the very case
        // this stage exists to resolve — has no contract here, and its contract
        // is the earlier repair run's; that one is reconstructed the way the
        // repository answers every *which checks can observe a fix* question:
        // from the finding itself ([`repair_impact::named_checks`]), through the
        // same `RepairContract::from_finding` + `select_impacted_checks` pair the
        // writing path uses, widened against this run's plan. Without the
        // reconstruction, stage 12 could not tell "the marker the candidate
        // check was built from is gone" — the one absence `recheck_lifecycle`
        // resolves — from "nothing observed the fix", which stays open; a fix
        // that worked would carry its finding open forever (measured 2026-10-14,
        // the MiQi full-repair E2E: subagent fixed the TODO, re-check reported
        // both findings still open).
        //
        // A finding with no contract from either source — one whose anchors name
        // no check, so nothing could ever observe a fix — gets no entry, and
        // `recheck_lifecycle` keeps it open. That is the right reading.
        let mut rechecks: Vec<(sure_domain::ids::FindingId, Vec<CheckId>)> = run
            .repairs
            .iter()
            .map(|contract| {
                (
                    contract.issue_id.clone(),
                    select_impacted_checks(contract, &run.schedule),
                )
            })
            .collect();
        for earlier in &previous {
            let named = crate::repair_impact::named_checks(earlier);
            let Ok(reconstructed) =
                sure_domain::vocabulary::RepairContract::from_finding(earlier, named)
            else {
                continue;
            };
            rechecks.push((
                earlier.id.clone(),
                select_impacted_checks(&reconstructed, &run.schedule),
            ));
        }
        // Which checks this run planned, whatever their results — the
        // comparison needs the distinction between "planned and unobserved"
        // and "a candidate check the scanner no longer proposes" (its subject
        // is gone), which is the one absence that resolves a finding.
        let planned: Vec<CheckId> = run
            .schedule
            .checks()
            .iter()
            .map(|scheduled| scheduled.proposal().id().clone())
            .collect();
        let update = recheck_lifecycle::reconcile(
            LifecycleInputs {
                previous_open: &previous,
                current_findings: &run.verdict.findings,
                check_results: run.report.results(),
                rechecks: &rechecks,
                planned: &planned,
                case,
            },
            run.project_state.id.clone(),
        );
        let detail = format!(
            "{} earlier finding(s) stayed open, {} resolved. A finding closes when every check \
             its repair contract named has passed in this run — or, for a candidate-driven check, \
             when this run no longer plans it because the marker it was built from is gone.",
            update.kept_open.len(),
            update.resolved.len(),
        );
        (Some(update), StageOutcome::Ran { detail })
    }
}

/// Stage 11: a repair contract per finding, when the purpose asks for one.
///
/// # Where the re-check list comes from
///
/// [`RepairContract::from_finding`] refuses an empty list, and
/// [`crate::repair_impact::select_impacted_checks`] takes the contract it would
/// be helping to build — so the two cannot be called in the order they read in.
/// The way through is the one this repository already models in
/// `crates/sure-core/tests/repair_fixture_e2e.rs`: a **seed** derived from the
/// finding alone, handed to the constructor, and then the selection, which the
/// product widens.
///
/// The seed is [`seed_rechecks`], in the module that owns the selection rule, and
/// it reads the check whose result produced the finding — the check that can
/// observe whether the fix worked. It is a subset of the selection by
/// construction, because the selection copies the contract's own list in first.
///
/// **The contract keeps the seed in its `recheck` field and the selection is what
/// governs closing.** That is not an oversight: `from_finding` phrases the
/// acceptance criteria from the list it was handed, so a contract whose `recheck`
/// was widened afterwards would carry acceptance text about one check and a
/// re-check list naming three. The widened list is what stage 12 hands to
/// `reconcile`, which is where closing actually happens.
///
/// # When it cannot write one
///
/// A finding whose evidence cannot carry its severity — a `must_fix` candidate
/// the scanner inferred from source text, or a model-only finding — gets no
/// contract: there is no check that can settle it, and asking an agent to
/// "fix" evidence SURE never established is the false task this rule exists to
/// prevent. It stays in the report as `cannot_confirm` with a manual next step.
///
/// A finding whose evidence names no check this run planned gets an empty seed,
/// and `from_finding` refuses it — correctly, because a contract naming a check
/// nobody can run is worse than no contract. The refusal is not swallowed: the
/// stage records what could not be written, and a run whose findings *all*
/// refused is a stage that did not run rather than one that ran and found nothing
/// to do.
///
/// [`RepairContract::from_finding`]: sure_domain::vocabulary::RepairContract::from_finding
/// [`seed_rechecks`]: crate::repair_impact::seed_rechecks
/// The contracts the findings justify, and the ones they do not.
///
/// Split out from [`repair_contracts`] so the rule can be tested without a whole
/// run: a finding whose evidence cannot carry its severity is a candidate (or a
/// model opinion), not a settled defect, and no check can settle it. It stays in
/// the report with a manual next step; it does not become a repair task.
fn contracts_for(
    findings: &[sure_domain::finding::Finding],
    schedule: &crate::schedule::CheckSchedule,
) -> (Vec<sure_domain::vocabulary::RepairContract>, Vec<String>) {
    let mut contracts = Vec::new();
    let mut refused: Vec<String> = Vec::new();
    for finding in findings {
        // A contract is an instruction to change the project and a check that
        // can observe the change. A finding whose own evidence cannot carry its
        // severity — a `must_fix` candidate the scanner inferred from source
        // text, or a model-only finding — has no such check: the candidate
        // scanner's question is not settled by a command, and writing a repair
        // contract for it asks an agent to "fix" evidence SURE never
        // established. The finding stays in the report as `cannot_confirm` with
        // a manual next step (see `findings_from_checks`); it does not become a
        // repair task.
        if !finding.is_grounded() {
            refused.push(format!(
                "{} (candidate evidence: no check can settle it)",
                finding.title
            ));
            continue;
        }
        // The seed comes from the finding and is filtered to checks this run
        // planned, so it can never name a check nobody can re-run.
        let seed = seed_rechecks(finding, schedule);
        match sure_domain::vocabulary::RepairContract::from_finding(finding, seed) {
            Ok(contract) => contracts.push(contract),
            Err(error) => refused.push(format!("{} ({error})", finding.title)),
        }
    }
    (contracts, refused)
}

fn repair_contracts(
    run: &RunOutcome,
) -> (Vec<sure_domain::vocabulary::RepairContract>, StageOutcome) {
    if run.verdict.findings.is_empty() {
        return (
            Vec::new(),
            StageOutcome::Ran {
                detail: "no check produced a finding, so there is nothing to write instructions \
                         for."
                    .to_owned(),
            },
        );
    }

    let (contracts, refused) = contracts_for(&run.verdict.findings, &run.schedule);

    let findings = run.verdict.findings.len();
    if contracts.is_empty() {
        return (
            Vec::new(),
            StageOutcome::NotRun {
                reason: None,
                detail: format!(
                    "{findings} finding(s) need instructions and none of them is grounded in \
                     evidence a check can settle, so SURE has no acceptance test it is willing to \
                     write: {}",
                    refused.join("; ")
                ),
            },
        );
    }
    let written = contracts.len();
    if !refused.is_empty() {
        return (
            contracts,
            StageOutcome::NotRun {
                reason: None,
                detail: format!(
                    "{written} of {findings} finding(s) have instructions; the rest are not \
                     grounded in evidence a check can settle, and SURE will not invent an \
                     acceptance test for them: {}",
                    refused.join("; ")
                ),
            },
        );
    }
    (
        contracts,
        StageOutcome::Ran {
            detail: format!(
                "{written} repair contract(s), one per finding. Each names the check that produced \
                 the finding, and re-running that check is what closes it."
            ),
        },
    )
}

/// Stage 4's proposals, from every module that produces one.
fn propose_everything(
    discovery: &Discovery,
    graph: &ComponentGraph,
    intent: &ProjectIntent,
    preferences: &crate::config::ChecksConfig,
    builder: &mut PlanBuilder,
) -> Planned {
    let mut planned = Planned::default();

    if let Some(node) = node_of(discovery) {
        let checks = checks::node::NodeChecks::of(&node, &discovery.root);
        planned.missing.extend(checks.missing().iter().cloned());
        checks.add_to(builder);

        // The runtime probes need the Node project, because a probe is a command
        // the manifest declares. A project that is not Node-shaped plans none,
        // which is a statement about the project rather than a failure.
        match ProbePlan::of(graph, &node, preferences) {
            Ok(probes) => {
                planned.not_planned = probes.not_planned().len();
                probes.add_to(builder);
            }
            Err(refusal) => planned.probe_refusal = Some(refusal),
        }
    }
    if let Some(python) = python_of(discovery) {
        let checks = checks::python::PythonChecks::of(&python, &discovery.root);
        planned.missing.extend(checks.missing().iter().cloned());
        checks.add_to(builder);
    }
    if let Some(rust) = rust_of(discovery) {
        let checks = checks::rust::RustChecks::of(&rust, &discovery.root);
        planned.missing.extend(checks.missing().iter().cloned());
        checks.add_to(builder);
    }

    // The project's own declared services, planned **outside** the three blocks
    // above and not inside any of them. A declaration names its launcher, its
    // port, its readiness path and its page, and none of that is a fact about an
    // ecosystem: the `node` block's probes need a discovered Node project, while
    // a service only needs the project to have said, in its own file, what to
    // start. A declaration that is refused, a check no preference plans and a
    // declaration that became nothing are each recorded rather than dropped —
    // which is what makes this stage's report able to say so.
    let services = ServicePlan::of(&discovery.root, preferences);
    planned.services = services.services().len();
    planned.service_refusals = services.refusals().to_vec();
    planned.service_gaps = services.gaps().to_vec();
    services.add_to(builder);

    // Stage 7's own proposals are planned too: a candidate SURE can see is a check
    // SURE would run, and leaving them out of the plan would make the plan a
    // shorter and greener thing than the run.
    //
    // **The observation beside each is the one every one of these scanners made:
    // a reading, and nothing settled by it.** Stage 7 reads source files and
    // never runs the project, so a candidate it found is a
    // `StaticObservation::Candidate` with the place it was read from in the
    // sentence — the one answer that claims neither a pass nor a defect. It is
    // not `CouldNotRun`: a scanner that could not read a file produced no
    // proposal for it, and the reading that did happen is what this carries.
    //
    // Nothing here changes how the plan is assembled: the proposal, the missing
    // commands and the refusals are exactly what they were before.
    for proposal in completeness_proposals(discovery, intent) {
        // A refusal is remembered by the builder rather than lost, and the plan
        // stage reports it. Nothing here second-guesses the decision.
        let observation = reading_observation(&proposal);
        drop(builder.propose(PlannedWork::new(proposal, observation)));
    }

    planned
}

/// The work beside one stage-7 candidate: the reading that produced it.
///
/// The sentence is [`CheckReason::plain_description`] — the same rendering the
/// report prints — with this stage's own clause after it, so the check's
/// evidence and its reason name one place rather than two that agree today.
/// [`crate::false_completion_aggregator`] files these as candidates, and a
/// candidate is what the placeholder used to say on their behalf: since
/// `P18-T004` each scanner says it in its own words, and stage 7 says it here
/// because this loop is where five scanners and the intent comparison meet.
fn reading_observation(proposal: &CheckProposal) -> CheckOperation {
    CheckOperation::Precomputed(PrecomputedEvidence::candidate(format!(
        "{} Nothing has settled it: it was read from the source, and no command has \
         been run for it.",
        proposal.reason().plain_description()
    )))
}

/// Stage 7: the completeness scanners, and the aggregator that orders them.
/// 阶段 8 发给模型的评估请求(纯函数,可测)。
///
/// grounded:只给阶段 7 已经观察到的候选(各自的 id、标题、严重度与判据理由),
/// 要求模型逐条回答"problem/noise + 一句理由",并明确禁止发明候选之外的
/// 内容。行格式供 [`parse_assessment`] 解析;无法解析的整段文本不进 finding。
fn assessment_prompt(project: &Path, candidates: &Candidates) -> String {
    let mut prompt =
        String::from("You are assessing completeness candidates SURE observed in the project at ");
    prompt.push_str(&project.display().to_string());
    prompt.push_str(
        ".\nFor EACH candidate below answer with exactly one line:\n\
         <candidate id>: problem — <one short sentence: why the evidence supports this is a \
         real problem for hand-off>\n\
         or\n\
         <candidate id>: noise — <one short sentence: why this is style noise>\n\
         Assess only the candidates listed. Do not invent candidates.\n\nCandidates:\n",
    );
    for candidate in &candidates.material {
        prompt.push_str(&format!(
            "- {}: {} (severity: {}; because: {})\n",
            candidate.id,
            candidate.title,
            candidate.severity.as_str(),
            candidate.because
        ));
    }
    prompt
}

/// 一条候选的模型判定。
#[derive(Debug)]
struct ModelVerdict {
    candidate_id: String,
    is_problem: bool,
    reason: String,
}

/// 解析模型回复里的 `id: problem|noise — reason` 行(纯函数,可测)。
///
/// 宽容但绝不猜测:大小写不敏感;只认 [`Candidates::material`] 里出现过的
/// id;分隔符接受 em dash 或 " - ";无法识别的行一律忽略——finding 只从
/// 被理解的行里来。
fn parse_assessment(text: &str, candidates: &Candidates) -> Vec<ModelVerdict> {
    let mut verdicts: Vec<ModelVerdict> = Vec::new();
    for line in text.lines() {
        let line = line.trim().trim_start_matches(['-', '*']).trim_start();
        let Some((id_part, rest)) = line.split_once(':') else {
            continue;
        };
        let id = id_part.trim();
        if !candidates
            .material
            .iter()
            .any(|candidate| candidate.id == id)
        {
            continue;
        }
        let rest = rest.trim();
        let (word, reason) = rest
            .split_once('—')
            .or_else(|| rest.split_once(" - "))
            .unwrap_or((rest, ""));
        let word = word.trim().to_ascii_lowercase();
        if word != "problem" && word != "noise" {
            continue;
        }
        if verdicts.iter().any(|verdict| verdict.candidate_id == id) {
            continue; // 同一候选出现多行:只认第一行,后面的不覆盖也不叠加
        }
        verdicts.push(ModelVerdict {
            candidate_id: id.to_owned(),
            is_problem: word == "problem",
            reason: reason.trim().to_owned(),
        });
    }
    verdicts
}

/// ADR 0005 的执行点:模型评估证据不能单独支撑 must_fix,确认项的严重度
/// 因此以 ShouldFixFirst 为上限,其余原样(只执行既有规则,不发明新档)。
fn model_supported_severity(severity: Severity) -> Severity {
    match severity {
        Severity::MustFix => Severity::ShouldFixFirst,
        other => other,
    }
}

fn completeness(discovery: &Discovery, intent: &ProjectIntent) -> Candidates {
    let aggregated =
        false_completion_aggregator::aggregate(completeness_proposals(discovery, intent));
    let mut candidates = Candidates {
        material: aggregated
            .material()
            .iter()
            .map(summarize_proposal)
            .collect(),
        style_noise: aggregated
            .style_noise()
            .iter()
            .map(summarize_proposal)
            .collect(),
        duplicates_dropped: aggregated.duplicates_dropped(),
    };
    candidates
        .material
        .sort_by(|left, right| left.id.cmp(&right.id));
    candidates
        .style_noise
        .sort_by(|left, right| left.id.cmp(&right.id));
    candidates
}

/// Every proposal the completeness scanners produce, in one list.
///
/// The five scanners and the intent comparison are separate modules and this is
/// the only place they are gathered. Nothing is filtered here:
/// [`crate::false_completion_aggregator`] decides what is material and what is
/// style noise, and a second opinion about that in this function would be the
/// drift that module exists to prevent.
fn completeness_proposals(discovery: &Discovery, intent: &ProjectIntent) -> Vec<CheckProposal> {
    let mut proposals = Vec::new();
    proposals.extend(CandidateScanner::of(discovery).proposed().iter().cloned());
    proposals.extend(NoOpHeuristics::of(discovery).proposed().iter().cloned());
    proposals.extend(DemoDataHeuristics::of(discovery).proposed().iter().cloned());
    proposals.extend(RouteConsistency::of(discovery).proposed().iter().cloned());
    proposals.extend(UiActionBridge::of(discovery).proposals());
    proposals.extend(compare_intent_to_project(intent, discovery).findings);
    proposals
}

fn summarize_proposal(proposal: &CheckProposal) -> CandidateSummary {
    CandidateSummary {
        id: proposal.id().as_str().to_owned(),
        title: proposal.title().to_owned(),
        severity: proposal.severity(),
        critical: proposal.critical(),
        because: proposal.reason().plain_description(),
    }
}

fn node_of(discovery: &Discovery) -> Option<crate::discover::NodeProject> {
    match &discovery.report(Ecosystem::Node)?.findings {
        Findings::Node(node) => Some((**node).clone()),
        _ => None,
    }
}

fn python_of(discovery: &Discovery) -> Option<crate::discover::PythonProject> {
    match &discovery.report(Ecosystem::Python)?.findings {
        Findings::Python(python) => Some((**python).clone()),
        _ => None,
    }
}

fn rust_of(discovery: &Discovery) -> Option<crate::discover::RustProject> {
    match &discovery.report(Ecosystem::Rust)?.findings {
        Findings::Rust(rust) => Some((**rust).clone()),
        _ => None,
    }
}

/// A checked claim in the verdict's own type.
///
/// [`crate::claim_checker`] reports what it established; [`ProjectVerdict`] holds
/// the domain's [`Claim`]. The mapping is here rather than in either module
/// because it is a conversion between two vocabularies — and a session identifier
/// is not recoverable from a stored claim row, so it is `None`, which says "this
/// claim is not attributed to a session" rather than inventing one.
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

/// Whether a claim assessment falls on the positive side, for a report grouping
/// claims. The vocabulary owns the answer; this names it for a renderer.
#[must_use]
pub const fn is_confirmed(assessment: ClaimAssessment) -> bool {
    matches!(assessment, ClaimAssessment::Confirmed)
}

fn describe_discovery(discovery: &Discovery, support: &ProjectSupport) -> String {
    let stacks: Vec<String> = discovery
        .stacks()
        .iter()
        .map(|stack| format!("{} (level {})", stack.stack, stack.level.letter()))
        .collect();
    let named = if stacks.is_empty() {
        "no stack SURE recognises".to_owned()
    } else {
        stacks.join(", ")
    };
    let complete = if discovery.is_complete() {
        "all of it was read"
    } else {
        "part of it was not read"
    };
    format!(
        "{named}; {complete}. Support reaches level {}.",
        support.level.letter()
    )
}

fn describe_intent(intent: &ProjectIntent) -> String {
    let user = intent.user_requirements().count();
    let documented = intent_model::from_source(intent, IntentSource::ProjectSpec).count();
    if user == 0 {
        format!(
            "nothing you said was available to check against ({documented} statement(s) the \
             project documents about itself)."
        )
    } else {
        format!("{user} statement(s) from you, {documented} the project documented for itself.")
    }
}

fn describe_plan(
    schedule: &CheckSchedule,
    refused: &[ProposalRefused],
    planned: &Planned,
) -> String {
    let mut parts = vec![format!(
        // "stopped by the mode" rather than "was stopped": the count is
        // parenthesised out of the grammar, and `crate::enforce` prints the
        // same phrase for the same fact.
        "{} check(s) planned under {}: {} may run, {} stopped by the mode.",
        schedule.len(),
        schedule.mode().as_str(),
        schedule.may_run().count(),
        schedule.blocked().count(),
    )];
    if !planned.missing.is_empty() {
        parts.push(format!(
            "{} declared check(s) have no command because the project does not declare one; \
             they are listed as not checked below.",
            planned.missing.len()
        ));
    }
    if !refused.is_empty() {
        parts.push(format!(
            "{} candidate(s) could not become a check: {}.",
            refused.len(),
            refused
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("; ")
        ));
    }
    if let Some(refusal) = planned.probe_refusal.as_ref() {
        parts.push(format!("the runtime probes were not planned: {refusal}."));
    }
    // What part of the plan came from the project's own file rather than from
    // what discovery found. It is stated beside the refusals rather than folded
    // into the count above, because a reader has to be able to tell *this project
    // declared nothing* from *it declared a service and that service is one of
    // the checks counted*. The second is what a project that took the trouble to
    // write a declaration is owed, and a count alone would read as the first.
    if planned.services > 0 {
        parts.push(format!(
            "{} of them are services the project declared in {}.",
            planned.services,
            crate::config::Config::FILE_NAME,
        ));
    }
    // A declaration SURE would not act on is stated the same way a proposal the
    // builder refused is, and for the same reason: the project asked for a check
    // and the answer is *no, and here is why*. A silent drop would leave a report
    // whose plan is short by one service and says nothing about the one.
    if !planned.service_refusals.is_empty() {
        parts.push(format!(
            "{} declared service(s) could not become a check: {}.",
            planned.service_refusals.len(),
            planned
                .service_refusals
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("; ")
        ));
    }
    // The other answer to the same question, and the one a report has to state
    // rather than leave to the reader: a service row can be missing because SURE
    // refused the declaration and because the project's own setting declined it,
    // and those two send a person to different places. `docs/architecture/
    // EXECUTION_SAFETY.md` makes the distinction the reason the sentences exist —
    // *this project switched it off* against *SURE does not open a page on a
    // guess* — so every sentence below names which setting decided, and the
    // lead-in claims only what is true of all of them.
    if !planned.service_gaps.is_empty() {
        parts.push(format!(
            "{} declared service(s) were planned with a check left out, and each says why: {}.",
            planned.service_gaps.len(),
            planned
                .service_gaps
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("; ")
        ));
    }
    parts.join(" ")
}

/// Stage 6, in the terms of what the run did with each dynamic check.
///
/// **The enforcement's answer and not the schedule's**, because the two are two
/// views of one decision and it is the enforcement's that stops a command: a
/// check the plan allowed whose command the mode did not admit is stopped here,
/// and a stage that read `schedule.blocked()` would report it as one that ran.
/// `run_scheduled_checks` asks the same two questions in the same order, so this
/// description and that result set cannot disagree about which checks ran.
fn describe_dynamic(
    schedule: &CheckSchedule,
    enforcement: &Enforcement,
    dynamic: usize,
) -> StageOutcome {
    if dynamic == 0 {
        return StageOutcome::NotPartOfWork {
            detail: "no check in the plan would run your project's code.".to_owned(),
        };
    }
    let dynamic_checks = || {
        schedule
            .checks()
            .iter()
            .filter(|scheduled: &&ScheduledCheck| {
                scheduled.proposal().requirements().runs_project_code()
            })
    };
    let stopped: Vec<(&str, Option<NotCheckedReason>)> = dynamic_checks()
        .filter_map(|scheduled| {
            enforcement
                .stopped()
                .iter()
                .find(|result| &result.id == scheduled.proposal().id())
                .map(|result| (scheduled.proposal().title(), result.not_checked_reason))
        })
        .collect();
    let stopped_titles: Vec<&str> = stopped.iter().map(|(title, _)| *title).collect();
    let reason = common_not_checked_reason(stopped.iter().map(|(_, reason)| *reason));
    let why = stopped_reason_phrase(reason);
    if stopped.len() == dynamic {
        return StageOutcome::NotRun {
            reason,
            detail: format!(
                "{dynamic} check(s) would run your project's code, but {why}, so none was \
                 carried out and each is recorded as not checked rather than passed: {}.",
                stopped_titles.join(", ")
            ),
        };
    }
    if stopped.is_empty() {
        return StageOutcome::Ran {
            detail: format!(
                "{dynamic} check(s) would run your project's code and the execution mode allowed \
                 them. Each one has a result: the runner reports one for every scheduled check, \
                 and a check it produced nothing for is an error rather than a pass."
            ),
        };
    }
    StageOutcome::NotRun {
        reason,
        detail: format!(
            "{dynamic} check(s) would run your project's code. {} of them did not run because \
             {why}, and those are recorded as not checked: {}. The rest were carried out and each \
             has a result.",
            stopped.len(),
            stopped_titles.join(", ")
        ),
    }
}

/// The reason every stopped check shares, if they share one.
///
/// A mixed set answers `None` rather than picking one check's reason and
/// speaking for the others: [`StageOutcome::NotRun`] allows that, and a stage
/// sentence that named one permission while another stopped a check would be
/// the same misattribution this helper exists to stop.
fn common_not_checked_reason(
    mut reasons: impl Iterator<Item = Option<NotCheckedReason>>,
) -> Option<NotCheckedReason> {
    let first = reasons.next()??;
    reasons.all(|reason| reason == Some(first)).then_some(first)
}

/// Why stopped checks did not run, in the terms of the permission that stopped
/// them rather than the execution mode alone.
fn stopped_reason_phrase(reason: Option<NotCheckedReason>) -> &'static str {
    match reason {
        Some(NotCheckedReason::DependencyInstallNotPermitted) => {
            "installing their dependencies is not allowed"
        }
        Some(NotCheckedReason::NetworkNotPermitted) => "network access is not allowed",
        Some(NotCheckedReason::ExecutionNotAuthorized) => "the execution mode stopped them",
        Some(NotCheckedReason::UserDeclined) => "you declined them",
        Some(NotCheckedReason::ContainerExecutionUnavailable) => {
            "this build cannot run checks in a container"
        }
        _ => "the run's permissions stopped them",
    }
}

/// Why a run's results may no longer describe the project, if they may not.
///
/// **The whole of clause one, read against the world rather than against the
/// value.** [`CheckResult::project_fingerprint`] binds every result to the state
/// that produced it and `aggregate_run` refuses a set whose members name
/// different states — and neither of those can see the project. Every result in
/// one run names the one state stage 3 took, so the refusal is a check on the
/// set and never on the world, and a run whose project moved has no member of
/// the set that disagrees. `before` is that state, `after` is the project read
/// again, and the comparison is [`ProjectFingerprint::matches`] — `kind` and
/// `digest`, never the `id`, which is freshly generated per computation and would
/// differ for two reads of one unchanged project.
///
/// `None` is the ordinary answer: the project is where stage 3 found it, nothing
/// is replaced, and a run that only built its own caches lands here. `Some` is
/// the reason, written once and quoted by every result the answer replaces.
///
/// **A project SURE could not read again is not a project that stayed still.**
/// The error arm answers `Some`, because the honest statement is that SURE could
/// not tell — and of the two ways to be wrong about that, invalidating evidence
/// SURE could not confirm is the one that costs a repeated check rather than a
/// green about a project nobody looked at twice.
fn stale_evidence_reason(
    before: &ProjectFingerprint,
    after: &Result<ProjectFingerprint, fingerprint::FingerprintError>,
) -> Option<String> {
    match after {
        Ok(after) if before.matches(after) => None,
        Ok(after) => Some(format!(
            "{} SURE took this project's fingerprint as {} before the run's checks were carried \
             out, and the project is now at {}.",
            StalenessReason::SupersededByLaterChange.plain_explanation(),
            before.digest,
            after.digest,
        )),
        Err(error) => Some(format!(
            "SURE could not take the project's fingerprint again after the run's checks were \
             carried out, so it cannot confirm that this still describes the project: {error}"
        )),
    }
}

/// Replace every pass whose evidence came from running the project's own code
/// now that the project is not the one that evidence is about.
///
/// Returns the checks it replaced, in plan order, so that the stage which has to
/// say what happened and the results themselves are answering from one rule
/// rather than from two that agree today.
///
/// # What is replaced, and what is deliberately not
///
/// **Only a `Pass`.** [`CheckResult::blocks_green`] is what the verdict turns on,
/// and a result that already failed, warned, could not run or established nothing
/// is not a pass that could stand as current — replacing one would cost a finding
/// the run actually made (a failing test is the most useful thing a runtime
/// check produces) and would buy no safety at all, because none of those statuses
/// is green. `Pass` is the only status this rule can be about, which is why the
/// clause it implements is phrased about an *earlier pass* and not about an
/// earlier result.
///
/// **Only a check whose evidence came from a process**, which is
/// [`CheckOperation::starts_a_process`]: a check whose operation is
/// [`CheckOperation::Precomputed`] has evidence SURE can read again, and every
/// other operation started something whose execution is over by the time this
/// runs.
///
/// **That predicate used to be the consent one, and a browser check is where the
/// two part.** `requirements().runs_project_code()` answers *would this need the
/// user's permission to run project code*, and a browser probe does not: it
/// connects to a service SURE started, under `connect_service`, which is why
/// `ActionKind::BrowserProbe` is deliberately not one of the actions
/// `ActionKind::executes_project_code` lists. That is the right answer to the
/// consent question and the wrong one to this one — a page row's evidence is a
/// page served by the project's own service, so it is about an execution that has
/// ended in exactly the way the service row's is. Reading the consent predicate
/// here **kept a `Pass`** that said a page answered, about a project that had
/// since moved, while withdrawing the `Pass` beside it about the service that
/// served that page: a false green, and the failure this repository treats as
/// worse than a visible error. So this rule asks the question it is about, and
/// stages 5 and 6 go on asking theirs.
///
/// The status is [`CheckStatus::Unknown`] with a reason — not `Warning`, which
/// maps to `CriticalState::Passed` and so blocks nothing on a critical check, and
/// not `Skipped`, which would read as a decision somebody made when nobody did.
///
/// The result keeps **its own** `project_fingerprint`. That is not an oversight
/// and the alternative is worse in both directions: binding it to the newer state
/// would make `aggregate_run` refuse the whole set and leave the run with no
/// verdict at all, and binding it to the older state is simply true — the run is
/// about the state stage 3 read, every other result in it is about that state,
/// and this result is SURE saying it may not be carried forward to the one that
/// is there now. Which state that is, is in the reason.
fn invalidate_runtime_passes(
    reason: &str,
    schedule: &CheckSchedule,
    results: &mut [CheckResult],
) -> Vec<CheckId> {
    let mut replaced: Vec<CheckId> = Vec::new();
    for scheduled in schedule.checks() {
        if !scheduled.operation().starts_a_process() {
            continue;
        }
        let id = scheduled.proposal().id();
        let Some(result) = results.iter_mut().find(|result| &result.id == id) else {
            continue;
        };
        if result.status != CheckStatus::Pass {
            continue;
        }
        *result = CheckResult::unknown(
            id.clone(),
            result.title.clone(),
            result.severity,
            result.critical,
            // The class a result SURE cannot stand behind carries: `unknown`'s own
            // documentation keeps this a parameter rather than a default *because*
            // this is the case that needs one — the check did observe something,
            // and what it observed is not about the project in front of a reader.
            EvidenceClass::Unknown,
            result.project_fingerprint.clone(),
        )
        .with_reason(reason.to_owned());
        replaced.push(id.clone());
    }
    replaced
}

fn describe_candidates(candidates: &Candidates) -> String {
    if candidates.is_empty() {
        return "no completeness candidate was found.".to_owned();
    }
    format!(
        "{} candidate(s) worth acting on, {} that are style noise, {} dropped as duplicates. A \
         candidate is something to look at, not a defect SURE has established.",
        candidates.material.len(),
        candidates.style_noise.len(),
        candidates.duplicates_dropped,
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    use crate::planned_check_runner::ProcessRunner;
    use crate::planned_work::CommandRun;
    use crate::process::{Cancellation, CapturedOutput, Outcome, Termination};

    #[test]
    fn every_purpose_performs_a_contiguous_run_of_the_documented_stages() {
        for purpose in [Purpose::Check, Purpose::Repair, Purpose::Recheck] {
            let last = purpose.last_stage();
            assert!(
                last.number() >= Stage::Aggregate.number(),
                "{} stops before it has a verdict",
                purpose.as_str()
            );
            assert!(Stage::ALL.contains(&last));
        }
        assert_eq!(Purpose::Check.last_stage(), Stage::Aggregate);
        assert_eq!(Purpose::Repair.last_stage(), Stage::RepairContract);
        assert_eq!(Purpose::Recheck.last_stage(), Stage::Recheck);
        assert!(!Purpose::Check.wants_recheck());
        assert!(Purpose::Recheck.wants_recheck());
        assert!(!Purpose::Check.wants_repair_contracts());
        assert!(Purpose::Repair.wants_repair_contracts());
    }

    #[test]
    fn the_stages_are_numbered_by_their_position_in_the_documented_order() {
        for (position, stage) in Stage::ALL.iter().enumerate() {
            assert_eq!(
                stage.number() as usize,
                position + 1,
                "{} is out of order",
                stage.as_str()
            );
        }
    }

    #[test]
    fn a_stage_identifier_is_the_same_on_every_run_and_differs_between_stages() {
        for stage in Stage::ALL {
            assert_eq!(stage.id(), stage.id());
        }
        for pair in Stage::ALL.windows(2) {
            assert_ne!(pair[0].id(), pair[1].id());
        }
    }

    #[test]
    fn only_an_outcome_that_did_not_run_is_a_gap() {
        assert!(
            !StageOutcome::Ran {
                detail: String::new()
            }
            .is_a_gap()
        );
        assert!(
            !StageOutcome::NotPartOfWork {
                detail: String::new()
            }
            .is_a_gap()
        );
        assert!(
            StageOutcome::NotRun {
                reason: None,
                detail: String::new()
            }
            .is_a_gap()
        );
        assert!(
            StageOutcome::Unfinished {
                detail: String::new()
            }
            .is_a_gap()
        );
    }

    #[test]
    fn a_confirmed_claim_is_the_only_positive_assessment() {
        assert!(is_confirmed(ClaimAssessment::Confirmed));
        assert!(!is_confirmed(ClaimAssessment::CannotConfirm));
        assert!(!is_confirmed(ClaimAssessment::Contradicted));
        assert!(!is_confirmed(ClaimAssessment::NotCheckable));
    }

    // --- stage 12's failure to read --------------------------------------

    /// A store that holds one finding for `project`, and nothing else.
    ///
    /// The finding is the same shape `recheck_lifecycle`'s own tests store: what
    /// this test needs from it is that it is a valid stored `Finding` for this
    /// project, because that is what makes stage 12's *successful* reading
    /// non-empty and the saturated reading a lost answer rather than an empty
    /// project.
    fn a_stored_finding(title: &str, location: &str) -> sure_domain::finding::Finding {
        use sure_domain::evidence::{AnchorSubject, Evidence, EvidenceAnchor, EvidenceClass};
        use sure_domain::finding::{
            AssessmentSource, FindingBuilder, FindingStatus, SeverityRationale,
        };
        use sure_domain::ids::FindingId;

        let fingerprint =
            FingerprintId::parse("fp_01j2m8q5aaaabbbbccccddddee").expect("a fixture id");
        FindingBuilder::new(
            AssessmentSource::DeterministicCheck,
            SeverityRationale::BlocksHandOff,
        )
        .id(FindingId::generate())
        .title(title)
        .severity(Severity::MustFix)
        .status(FindingStatus::Open)
        .explanation("the send path returns before the provider is called")
        .user_impact("users believe a message was delivered")
        .next_step("call the provider")
        .fingerprint(fingerprint.clone())
        .evidence(vec![Evidence::new(
            EvidenceClass::DeterministicCheck,
            "the send path returns before the provider is called",
            EvidenceAnchor::new(AnchorSubject::File, location, "line 42"),
            Some(fingerprint),
            Severity::MustFix,
        )])
        .build()
        .expect("the fixture finding is valid")
    }

    /// What a reader is told when the read of what an earlier run left open stops
    /// at its bound.
    ///
    /// **This is the clause `P15-T029` is about, observed rather than argued.**
    /// The read's failure has a plain-language path that already existed —
    /// [`Pipeline::recheck`] turns an `Err` from it into stage 12
    /// [`StageOutcome::NotRun`] with the error as the detail — and this is the only
    /// place that translation can be watched: the saturation is real (the store
    /// ends up holding more `Finding` records than
    /// [`recheck_lifecycle::HISTORY_SCAN_LIMIT`]), the run reaches stage 12, and
    /// what the run says about that stage is asserted rather than read off the
    /// source.
    ///
    /// Three things a false green would need, and none of them may hold:
    /// a comparison built from a scan that stopped early (`run.lifecycle` must be
    /// `None` — which is also what stops a report printing `Against the earlier
    /// run: 0 finding(s) still open`), a `Ran` stage whose detail is the reassuring
    /// *"no earlier run left anything open"*, and a run that counts as green.
    ///
    /// **The middle reading is the control.** The same project and the same store
    /// are read twice: once with one finding in it, where stage 12 runs and finds
    /// it, and once after enough rows for other projects have been added to push
    /// this project's own finding past the bound. Without that, a stage that never
    /// ran for some other reason would satisfy every assertion about the last one.
    #[test]
    fn a_history_that_stops_the_scan_makes_stage_12_not_run_rather_than_compare() {
        let root = crate::store::scratch_root().join(format!(
            "pipeline-recheck-saturation-{}",
            std::process::id()
        ));
        match std::fs::remove_dir_all(&root) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => panic!("cannot clear {}: {error}", root.display()),
        }
        let project = root.join("project");
        let store_dir = root.join("store");
        std::fs::create_dir_all(&project).expect("a scratch project");
        std::fs::create_dir_all(&store_dir).expect("a scratch store directory");
        std::fs::write(
            project.join("README.md"),
            "# A project SURE was pointed at\n\nIt is small on purpose: what this test is about is \
             the history SURE reads, not the project it reads it for.\n",
        )
        .expect("a project file");

        let store = Store::open_at(&store_dir.join("sure.db")).expect("the store opens");
        let config = Config::default();
        let runner = nothing_starts();
        let run_recheck = |store: &Store| {
            Pipeline {
                project: &project,
                purpose: Purpose::Recheck,
                config: &config,
                execution: ExecutionSettings::inspect_only(),
                store: Some(store),
                goal: None,
                analysis: Default::default(),
                runner: &runner,
            }
            .run()
        };

        // The first run is the one that answers the question this test cannot
        // answer for itself: what text the pipeline uses as the project's root.
        // A stored finding has to carry that exact text for stage 12 to recognise
        // it as this project's, and guessing it would make the control below
        // prove nothing.
        let first = run_recheck(&store);
        let first_run = first
            .run
            .as_ref()
            .expect("a run over a readable scratch project reaches its verdict");
        let project_root = first_run.project_root.clone();
        assert!(
            matches!(
                first.stage(Stage::Recheck).outcome,
                StageOutcome::Ran { .. }
            ),
            "an empty history is not a failure to read one: {:?}",
            first.stage(Stage::Recheck).outcome
        );

        crate::recheck_lifecycle::store_run(
            &store,
            &project_root,
            &first_run.project_state.id,
            &[a_stored_finding("Email not sent", "src/email/send.rs")],
            &[],
        )
        .expect("the earlier run's finding is stored");

        // The control: the same project, the same store, one finding in it.
        let control = run_recheck(&store);
        let control_run = control.run.as_ref().expect("the run finishes");
        let control_lifecycle = control_run
            .lifecycle
            .as_ref()
            .expect("a readable history is compared against");
        assert_eq!(
            control_lifecycle.kept_open.len(),
            1,
            "the stored finding was not carried open, so this store is not the \
             control the saturated reading is measured against: {:?}",
            control.stage(Stage::Recheck).outcome
        );
        match &control.stage(Stage::Recheck).outcome {
            StageOutcome::Ran { detail } => assert!(
                detail.starts_with("1 earlier finding(s) stayed open"),
                "stage 12 ran but did not say what it compared: {detail}"
            ),
            other => panic!("stage 12 with a readable history is {other:?}"),
        }

        // Now the bound: this project's finding is the oldest row in the store, and
        // `HISTORY_SCAN_LIMIT` rows for another project are newer than it — which
        // is exactly what the newest-first scan spends its bound on.
        let filler: Vec<sure_domain::finding::Finding> = (0..recheck_lifecycle::HISTORY_SCAN_LIMIT)
            .map(|i| {
                a_stored_finding(
                    &format!("Someone else's problem {i}"),
                    &format!("src/other/{i}.rs"),
                )
            })
            .collect();
        crate::recheck_lifecycle::store_run(
            &store,
            "C:/projects/other",
            &control_run.project_state.id,
            &filler,
            &[],
        )
        .expect("the filler is stored");

        let saturated = run_recheck(&store);
        assert!(
            saturated.run.is_some(),
            "the run itself stopped instead of reporting the stage: {:?}",
            saturated.stopped_at
        );
        let run = saturated.run.as_ref().expect("checked above");

        assert!(
            run.lifecycle.is_none(),
            "a scan that stopped at its bound produced a comparison, and `Against the \
             earlier run: {} finding(s) still open` is read off it",
            run.lifecycle
                .as_ref()
                .map_or(0, |update| update.kept_open.len())
        );

        match &saturated.stage(Stage::Recheck).outcome {
            StageOutcome::NotRun { reason, detail } => {
                assert_eq!(
                    *reason,
                    Some(NotCheckedReason::UnknownReason),
                    "the bound is not a scope limit: this project was in range and the \
                     history could not be read far enough"
                );
                assert!(
                    detail.contains(&recheck_lifecycle::HISTORY_SCAN_LIMIT.to_string()),
                    "the detail does not say which bound was reached: {detail}"
                );
                assert!(
                    !detail.contains("no earlier run left anything open"),
                    "a scan that stopped early is saying what a scan that found nothing \
                     says: {detail}"
                );
            }
            other => panic!(
                "a history read that stopped at its bound is reported as {other:?}, which is \
                 a comparison the read did not make"
            ),
        }

        // And the run does not pass as a clean one: a stage that did not do its
        // work is a gap, so a saturated re-check is not green either.
        assert!(
            !saturated.is_green(),
            "a run whose stage 12 could not read what the last run left open reported itself \
             as clean"
        );
    }

    // --- the repair loop's closing half ----------------------------------

    /// A stored finding whose anchor names the check that produced it.
    ///
    /// The shape the store really holds for a finding a check produced, measured
    /// off the TODO candidate's stored row: `subject_id` is the check id
    /// (`chk_candidatetodo<…>`), which is what a re-check reads to answer *which
    /// checks can observe a fix for this finding*. [`a_stored_finding`] anchors at
    /// a file and names no check — right for a test about the history read and
    /// nothing for a test about closing.
    fn a_stored_finding_about_a_check(
        title: &str,
        location: &str,
        check: &str,
    ) -> sure_domain::finding::Finding {
        use sure_domain::evidence::{AnchorSubject, Evidence, EvidenceAnchor, EvidenceClass};
        use sure_domain::finding::{
            AssessmentSource, FindingBuilder, FindingStatus, SeverityRationale,
        };
        use sure_domain::ids::{CheckId, FindingId};

        let fingerprint =
            FingerprintId::parse("fp_01j2m8q5aaaabbbbccccddddee").expect("a fixture id");
        let check = CheckId::parse(check).expect("a fixture check id");
        FindingBuilder::new(
            AssessmentSource::DeterministicCheck,
            SeverityRationale::BlocksHandOff,
        )
        .id(FindingId::generate())
        .title(title)
        .severity(Severity::MustFix)
        .status(FindingStatus::Open)
        .explanation("the marker the check was built from")
        .user_impact("the work is unfinished")
        .next_step("remove the marker")
        .fingerprint(fingerprint.clone())
        .evidence(vec![Evidence::new(
            EvidenceClass::DeterministicCheck,
            "the check did not pass",
            EvidenceAnchor::new(
                AnchorSubject::LineRange,
                location,
                "the candidate on line 1",
            )
            .with_subject_id(check),
            Some(fingerprint),
            Severity::MustFix,
        )])
        .build()
        .expect("the fixture finding is valid")
    }

    /// A fix that removed its marker closes the stored finding on the next
    /// re-check — while a check the run never observed keeps its finding open.
    ///
    /// **This is the wiring the full-repair loop needed, observed through the
    /// stage rather than through `recheck_lifecycle`.** `c4fd952` taught
    /// `recheck_passed` that *a candidate check this run did not plan* is the
    /// scanner saying the marker it was built from is gone — a resolution — but
    /// stage 12 only ever handed it the contracts of the *current* run's findings,
    /// and a fix that worked leaves the current run with no finding to write one
    /// from. An earlier finding's contract is answered here the way
    /// `repair_impact`'s own doctrine answers it: **asked**, of the finding (the
    /// checks its anchors name, [`crate::repair_impact::named_checks`]), widened
    /// against this run's plan — never stored a second time, so the store stays
    /// the only copy and this stage stays a reading rather than a cache.
    ///
    /// The control is the second stored finding, anchored at a check that is also
    /// not planned and is *not* candidate-driven: its absence is an absence of
    /// observation and it must stay open. Without it, a stage that closed every
    /// earlier finding would satisfy the first assertion.
    #[test]
    fn a_recheck_closes_a_stored_finding_whose_candidate_check_is_no_longer_planned() {
        let root = crate::store::scratch_root().join(format!(
            "pipeline-recheck-candidate-gone-{}",
            std::process::id()
        ));
        match std::fs::remove_dir_all(&root) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => panic!("cannot clear {}: {error}", root.display()),
        }
        let project = root.join("project");
        let store_dir = root.join("store");
        std::fs::create_dir_all(&project).expect("a scratch project");
        std::fs::create_dir_all(&store_dir).expect("a scratch store directory");
        std::fs::write(
            project.join("README.md"),
            "# A project SURE was pointed at\n\nThe marker the stored finding was about is \
             gone, and this run's own plan is where that shows.\n",
        )
        .expect("a project file");

        let store = Store::open_at(&store_dir.join("sure.db")).expect("the store opens");
        let config = Config::default();
        let runner = nothing_starts();
        let run_recheck = |store: &Store| {
            Pipeline {
                project: &project,
                purpose: Purpose::Recheck,
                config: &config,
                execution: ExecutionSettings::inspect_only(),
                store: Some(store),
                goal: None,
                analysis: Default::default(),
                runner: &runner,
            }
            .run()
        };

        // The first run answers what text the pipeline uses as this project's
        // root; the stored rows must carry exactly it to be read back.
        let first = run_recheck(&store);
        let first_run = first
            .run
            .as_ref()
            .expect("a run over a readable scratch project reaches its verdict");
        let project_root = first_run.project_root.clone();

        let removed_marker = a_stored_finding_about_a_check(
            "project contains TODO or FIXME comments in production code",
            "pay.py",
            "chk_candidatetodo9a707a1f764658ab",
        );
        let never_observed = a_stored_finding_about_a_check(
            "a declared command did not run",
            "package.json",
            "chk_nodetest",
        );
        crate::recheck_lifecycle::store_run(
            &store,
            &project_root,
            &first_run.project_state.id,
            &[removed_marker.clone(), never_observed.clone()],
            &[],
        )
        .expect("the earlier run's findings are stored");

        let second = run_recheck(&store);
        let run = second.run.as_ref().expect("the run finishes");
        let lifecycle = run
            .lifecycle
            .as_ref()
            .expect("a readable history is compared against");
        assert_eq!(
            lifecycle.resolved.len(),
            1,
            "the finding whose marker the fix removed did not close; kept open: {:?}",
            lifecycle
                .kept_open
                .iter()
                .map(|finding| finding.title.as_str())
                .collect::<Vec<_>>()
        );
        assert_eq!(lifecycle.resolved[0].title, removed_marker.title);
        assert_eq!(
            lifecycle.resolved[0].status,
            sure_domain::finding::FindingStatus::Resolved
        );
        assert_eq!(
            lifecycle.kept_open.len(),
            1,
            "a check the run did not plan and never observed lost its finding, or the fixed \
             finding was not the only one that closed"
        );
        assert_eq!(lifecycle.kept_open[0].title, never_observed.title);
    }

    // --- what a run may start, read rather than argued --------------------

    /// A runner that starts nothing, because a stop has already been asked for.
    ///
    /// **This is the product's own runner with one thing already decided**, and
    /// that is the point of using it here rather than a fake: `process::run`
    /// checks whether a stop has been asked for *before* it spawns anything, so
    /// the answer this runner gives — [`Termination::CancelledBeforeStart`] — is
    /// a real answer the product really produces, and no process can have been
    /// started to produce it. A fake returning a canned pass would be able to
    /// agree with this one on everything except the thing being measured.
    ///
    /// [`Termination::CancelledBeforeStart`]: crate::process::Termination::CancelledBeforeStart
    /// 阶段 8 接入(最小版)的测试用分析器:回放一段固定文本。
    struct ScriptedAnalyzer(String);

    impl crate::analysis_provider::Analyzer for ScriptedAnalyzer {
        fn analyze(
            &self,
            _request: crate::analysis_provider::AnalysisRequest<'_>,
        ) -> Result<
            crate::analysis_provider::AnalysisResponse,
            crate::analysis_provider::AnalysisError,
        > {
            Ok(crate::analysis_provider::AnalysisResponse::new(
                self.0.clone(),
            ))
        }
    }

    fn one_candidate() -> Candidates {
        Candidates {
            material: vec![CandidateSummary {
                id: "cand_todo".to_owned(),
                title: "TODO comment in production code".to_owned(),
                severity: Severity::MustFix,
                critical: true,
                because: "a TODO comment was found in a source file".to_owned(),
            }],
            style_noise: Vec::new(),
            duplicates_dropped: 0,
        }
    }

    fn assessment_probe<'a>(
        project: &'a Path,
        config: &'a Config,
        runner: &'a dyn CheckRunner,
    ) -> Pipeline<'a> {
        Pipeline {
            project,
            purpose: Purpose::Recheck,
            config,
            execution: ExecutionSettings::inspect_only(),
            store: None,
            goal: None,
            analysis: Default::default(),
            runner,
        }
    }

    #[test]
    fn a_model_flagged_candidate_becomes_a_model_only_result() {
        // 接线:模型确认的候选成为一条 fail 结果,证据类 ModelAssessment,
        // 且按 ADR 0005 钳制严重度与 critical——模型独证不判"不可交付"。
        let directory = std::env::temp_dir();
        let config = Config::default();
        let runner = nothing_starts();
        let pipeline = assessment_probe(&directory, &config, &runner);
        let fingerprint = FingerprintId::parse("fp_01j2m8q5aaaabbbbccccddddee").expect("fixture");
        let analyzer = ScriptedAnalyzer("cand_todo: problem — unfinished work\n".to_owned());

        let (outcome, results, findings) =
            pipeline.assess_candidates(&analyzer, &fingerprint, &one_candidate());
        assert!(results.is_empty(), "{results:?}");

        assert!(matches!(outcome, StageOutcome::Ran { .. }), "{outcome:?}");
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].status, FindingStatus::Open);
        assert_eq!(
            findings[0].assessment_source,
            AssessmentSource::ModelAssessment
        );
        assert_eq!(findings[0].severity, Severity::ShouldFixFirst);
        assert!(findings[0].explanation.contains("unfinished work"));
        assert!(findings[0].title.starts_with("Model assessment:"));
        assert_eq!(findings[0].evidence.len(), 1);
        assert_eq!(
            findings[0].evidence[0].class,
            EvidenceClass::ModelAssessment
        );
        assert_eq!(
            findings[0].evidence[0].anchor.subject,
            sure_domain::evidence::AnchorSubject::Model
        );
    }

    #[test]
    fn a_noise_verdict_produces_no_result() {
        let directory = std::env::temp_dir();
        let config = Config::default();
        let runner = nothing_starts();
        let pipeline = assessment_probe(&directory, &config, &runner);
        let fingerprint = FingerprintId::parse("fp_01j2m8q5aaaabbbbccccddddee").expect("fixture");
        let analyzer = ScriptedAnalyzer("cand_todo: noise — style only\n".to_owned());

        let (outcome, results, findings) =
            pipeline.assess_candidates(&analyzer, &fingerprint, &one_candidate());
        assert!(results.is_empty(), "{results:?}");

        assert!(matches!(outcome, StageOutcome::Ran { .. }), "{outcome:?}");
        assert!(findings.is_empty(), "{findings:?}");
    }

    #[test]
    fn no_candidates_keeps_stage_8_out_of_the_work() {
        let directory = std::env::temp_dir();
        let config = Config::default();
        let runner = nothing_starts();
        let pipeline = assessment_probe(&directory, &config, &runner);
        let fingerprint = FingerprintId::parse("fp_01j2m8q5aaaabbbbccccddddee").expect("fixture");
        let analyzer = ScriptedAnalyzer(String::new());

        let (outcome, results, findings) =
            pipeline.assess_candidates(&analyzer, &fingerprint, &Candidates::default());

        assert!(
            matches!(outcome, StageOutcome::NotPartOfWork { .. }),
            "{outcome:?}"
        );
        assert!(results.is_empty());
        assert!(findings.is_empty());
    }

    #[test]
    fn the_assessment_prompt_lists_candidates_and_the_line_format() {
        let prompt = assessment_prompt(Path::new("/tmp/project"), &one_candidate());
        assert!(prompt.contains("cand_todo"), "{prompt}");
        assert!(prompt.contains("problem — "), "{prompt}");
        assert!(prompt.contains("Do not invent candidates."), "{prompt}");
    }

    #[test]
    fn parse_assessment_reads_verdict_lines_and_ignores_the_rest() {
        let candidates = one_candidate();
        let verdicts = parse_assessment(
            "Sure!\ncand_todo: PROBLEM — real issue\ncand_unknown: problem — not listed\n\
             cand_todo: noise — duplicate line\nunparseable line\n",
            &candidates,
        );
        assert_eq!(verdicts.len(), 1, "{verdicts:?}");
        assert!(verdicts[0].is_problem);
        assert_eq!(verdicts[0].reason, "real issue");
        // " - " 分隔也认;noise 判定如实
        let alt = parse_assessment("cand_todo: noise - just style\n", &candidates);
        assert_eq!(alt.len(), 1);
        assert!(!alt[0].is_problem);
        assert_eq!(alt[0].reason, "just style");
    }

    fn nothing_starts() -> ProcessRunner {
        let stop = Cancellation::new();
        stop.cancel();
        ProcessRunner::new(stop)
    }

    /// A runner that records every command it is handed, and starts nothing.
    ///
    /// The recording is the measurement: it answers *was the runner reached at
    /// all?*, which is the question the acceptance's second clause is about and
    /// a question a silenced runner could not answer. The answer it returns is
    /// [`nothing_starts`]'s.
    ///
    /// `run_service` is unreachable through the runs this file makes — a
    /// [`CheckOperation::Service`] is planned by [`crate::service_plan`], and every
    /// run here is configured by `Config::default()`, which declares none — so it
    /// records the check's identity and delegates to the same cancelled runner
    /// rather than pretending to answer. It is here rather than defaulted on the
    /// trait because a runner that *cannot* be asked to start a service is a
    /// different claim from one that answers nothing to every question.
    ///
    /// [`CheckOperation::Service`]: crate::planned_work::CheckOperation::Service
    #[derive(Debug)]
    struct Recording {
        asked: RefCell<Vec<String>>,
        services: RefCell<Vec<String>>,
        browsers: RefCell<Vec<String>>,
        runner: ProcessRunner,
    }

    impl Recording {
        fn new() -> Self {
            Self {
                asked: RefCell::new(Vec::new()),
                services: RefCell::new(Vec::new()),
                browsers: RefCell::new(Vec::new()),
                runner: nothing_starts(),
            }
        }

        /// What the runner was asked to run, in the order it was asked.
        fn asked(&self) -> Vec<String> {
            self.asked.borrow().clone()
        }

        /// Which checks were handed to it as services, in order.
        fn services(&self) -> Vec<String> {
            self.services.borrow().clone()
        }

        /// Which checks were handed to it as browser pages, in order.
        ///
        /// The third half of the same seam, kept apart from the other two for the
        /// reason the two above are kept apart: *this check went to the browser
        /// door* and *this check went to the service door* are different
        /// measurements, and one list could not tell them apart.
        fn browsers(&self) -> Vec<String> {
            self.browsers.borrow().clone()
        }
    }

    impl CheckRunner for Recording {
        fn run(
            &self,
            work: &crate::planned_check_runner::AdmittedRun<'_>,
        ) -> crate::planned_work::CommandRun {
            let spec = work.command();
            self.asked.borrow_mut().push(format!(
                "{} {}",
                spec.program().to_string_lossy(),
                spec.arguments()
                    .iter()
                    .map(|argument| argument.to_string_lossy().into_owned())
                    .collect::<Vec<_>>()
                    .join(" ")
            ));
            self.runner.run(work)
        }

        fn run_service(
            &self,
            work: &crate::planned_check_runner::AdmittedService<'_>,
        ) -> CheckResult {
            let spec = work.service().command();
            self.services.borrow_mut().push(format!(
                "{} {}",
                spec.program().to_string_lossy(),
                spec.arguments()
                    .iter()
                    .map(|argument| argument.to_string_lossy().into_owned())
                    .collect::<Vec<_>>()
                    .join(" ")
            ));
            self.runner.run_service(work)
        }

        /// Records the page and hands it to the real runner, which has no browser
        /// driver and therefore answers with an `Error`.
        ///
        /// **The delegation is the point**: this fake decides nothing about a
        /// browser, so if a planner emits one, the answer is
        /// [`ProcessRunner`]'s own — *SURE was not given a browser driver* — and
        /// not a status invented in a test. It is also why this arm is recorded
        /// separately rather than folded into `asked`: the page is not a command,
        /// and a test that could not tell the two apart could not tell a browser
        /// check reaching the browser door from one reaching the wrong one.
        fn run_browser(
            &self,
            work: &crate::planned_check_runner::AdmittedBrowser<'_>,
        ) -> CheckResult {
            let spec = work.browser();
            self.browsers
                .borrow_mut()
                .push(format!("{} {}", spec.loopback_url(), spec.path()));
            self.runner.run_browser(work)
        }
    }

    /// A small Rust project on disk, under a directory of this test's own.
    ///
    /// Rust because its declared checks are the ones this build turns into
    /// commands it would have to run: `cargo check --all-targets`, `cargo
    /// clippy --all-targets` and `cargo test` all run the project's code, so a
    /// run that carries one of them out is a run that starts a process.
    fn a_rust_project(name: &str) -> std::path::PathBuf {
        let root = crate::store::scratch_root().join(format!("{name}-{}", std::process::id()));
        match std::fs::remove_dir_all(&root) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => panic!("cannot clear {}: {error}", root.display()),
        }
        std::fs::create_dir_all(root.join("src")).expect("a scratch project directory");
        std::fs::write(
            root.join("Cargo.toml"),
            "[package]\nname = \"thing\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .expect("a manifest");
        std::fs::write(
            root.join("src/lib.rs"),
            "pub fn add(a: u32, b: u32) -> u32 {\n    a + b\n}\n",
        )
        .expect("a source file");
        std::fs::write(
            root.join("README.md"),
            "# A project SURE was pointed at\n\nIt is small on purpose: what this test is about is \
             what SURE would run for it.\n",
        )
        .expect("a project file");
        root
    }

    /// The checks in a run's plan that would run the project's own code.
    fn would_run_the_project_code(run: &RunOutcome) -> Vec<String> {
        run.schedule
            .checks()
            .iter()
            .filter(|scheduled| scheduled.proposal().requirements().runs_project_code())
            .map(|scheduled| scheduled.proposal().title().to_owned())
            .collect()
    }

    /// The second acceptance clause, read rather than promised.
    ///
    /// **What is measured is the number of commands the runner was handed**, and
    /// the instrument is a runner that records every one and starts nothing —
    /// see [`Recording`]. Under [`ExecutionSettings::inspect_only`] the plan
    /// holds checks that would run this project's code and the mode admits none
    /// of them, so the recording must be empty: not "a process was reported as
    /// stopped", but *the runner was never reached*. The guard below is what
    /// makes that a measurement rather than a walk over an empty plan — a
    /// fixture that planned nothing dynamic would satisfy the empty recording
    /// while measuring nothing, which is the shape of a test that cannot fail.
    #[test]
    fn a_run_a_user_did_not_grant_starts_nothing() {
        let project = a_rust_project("pipeline-inspect-only");
        let config = Config::default();
        let runner = Recording::new();

        let outcome = Pipeline {
            project: &project,
            purpose: Purpose::Check,
            config: &config,
            execution: ExecutionSettings::inspect_only(),
            store: None,
            goal: None,
            analysis: Default::default(),
            runner: &runner,
        }
        .run();

        let run = outcome
            .run
            .as_ref()
            .unwrap_or_else(|| panic!("the run stopped: {:?}", outcome.stopped_at));
        assert_eq!(run.mode, ExecutionMode::InspectOnly);
        assert!(
            !run.permissions.run_project_code,
            "the default settings grant execution, so this test is not measuring the default"
        );
        let dynamic = would_run_the_project_code(run);
        assert!(
            !dynamic.is_empty(),
            "this project planned no check that would run its code, so an empty recording would \
             measure nothing: {:?}",
            run.schedule.plain_description()
        );

        let asked = runner.asked();
        assert!(
            asked.is_empty(),
            "a run the user granted nothing started {} command(s): {asked:?}",
            asked.len()
        );
        let services = runner.services();
        assert!(
            services.is_empty(),
            "a run the user granted nothing started {} service(s): {services:?}",
            services.len()
        );
    }

    #[test]
    fn a_user_requesting_a_container_never_reaches_the_host_runner() {
        let project = a_rust_project("pipeline-container-refused");
        let config_root = project.join("configuration");
        std::fs::create_dir_all(&config_root).expect("a scratch configuration directory");
        let user_config = config_root.join("config.yaml");
        std::fs::write(
            &user_config,
            "execution:\n  mode: container\n  allow_network: true\n",
        )
        .expect("the user's own configuration file");
        let authority = crate::config::Authority::load(&project, &user_config)
            .expect("the two configuration files are readable");
        let runner = Recording::new();
        let config = Config::default();
        let outcome = Pipeline {
            project: &project,
            purpose: Purpose::Check,
            config: &config,
            execution: authority.execution(),
            store: None,
            goal: None,
            analysis: Default::default(),
            runner: &runner,
        }
        .run();
        let run = outcome
            .run
            .as_ref()
            .unwrap_or_else(|| panic!("the run stopped: {:?}", outcome.stopped_at));
        assert_eq!(run.mode, ExecutionMode::Container);
        assert!(
            run.permissions.run_project_code,
            "the user's grant must be real"
        );
        let dynamic = would_run_the_project_code(run);
        assert!(!dynamic.is_empty(), "the fixture must plan project code");
        assert!(runner.asked().is_empty(), "the host runner was reached");
        assert!(runner.services().is_empty(), "a host service was reached");
        assert!(
            runner.browsers().is_empty(),
            "a host browser check was reached"
        );
        for result in run.report.results() {
            if dynamic.contains(&result.title) {
                assert_eq!(result.status, sure_domain::status::CheckStatus::Skipped);
                assert_eq!(
                    result.not_checked_reason,
                    Some(NotCheckedReason::ContainerExecutionUnavailable),
                    "{}: {}",
                    result.title,
                    result.reason
                );
                if result.critical {
                    assert!(result.blocks_green());
                }
            }
        }
    }

    /// The control for the measurement above, and the proof the seam is live.
    ///
    /// The same project and the same runner, with the user's own configuration
    /// file granting execution. One thing moves, and it is the user's file — read
    /// through [`Authority::load`], which is the route `sure check` reads it by
    /// rather than a literal handed to the pipeline.
    ///
    /// Two readings, and the second is why this test is here at all. The runner
    /// **is** reached now, which is what stops the first test from being
    /// satisfied by a stage that never consults a runner at all. And what comes
    /// back for those checks is *nothing ran* — this runner has been asked to
    /// stop before it started — reported as an `Error` and never as a pass, which
    /// is the same false-green rule read from the other side.
    #[test]
    fn a_run_a_user_granted_reaches_the_runner_and_is_never_reported_as_passed() {
        let project = a_rust_project("pipeline-granted");
        let config_root = project.join("configuration");
        std::fs::create_dir_all(&config_root).expect("a scratch configuration directory");
        let user_config = config_root.join("config.yaml");
        std::fs::write(
            &user_config,
            "execution:\n  mode: host_confirmed\n  allow_network: true\n",
        )
        .expect("the user's own configuration file");

        let authority = crate::config::Authority::load(&project, &user_config)
            .expect("the two configuration files are readable");
        let config = Config::default();
        let runner = Recording::new();

        let outcome = Pipeline {
            project: &project,
            purpose: Purpose::Check,
            config: &config,
            execution: authority.execution(),
            store: None,
            goal: None,
            analysis: Default::default(),
            runner: &runner,
        }
        .run();

        let run = outcome
            .run
            .as_ref()
            .unwrap_or_else(|| panic!("the run stopped: {:?}", outcome.stopped_at));
        assert_eq!(run.mode, ExecutionMode::HostConfirmed);
        assert!(
            run.permissions.run_project_code,
            "the user's own file did not move the mode, so this test is not the control it claims \
             to be"
        );
        let dynamic = would_run_the_project_code(run);
        assert!(
            !dynamic.is_empty(),
            "this project planned no check that would run its code: {:?}",
            run.schedule.plain_description()
        );

        let asked = runner.asked();
        assert!(
            !asked.is_empty(),
            "the user granted execution and the runner was never reached, so the run above is \
             satisfied by a runner nothing consults: {dynamic:?}"
        );
        // The other two doors of the same seam are **not** reached here, and since
        // `P18-T012`'s follow-up that is a fact about this run rather than about the
        // build: a project that declares a service in `checks.services` gets a
        // `CheckOperation::Service` from `crate::service_plan`, and a declaration
        // that names a page gets a `CheckOperation::Browser` beside it. This run is
        // configured by `Config::default()`, which declares neither. The wiring
        // that would carry one out is measured in `planned_check_runner.rs` with a
        // runner that starts nothing, because a test that made this path live would
        // have to start a real service.
        //
        // Asserted for both doors and not just the one: `pipeline.rs` now plans a
        // browser check's *service* command into the permission plan, so a planner
        // that emitted one would be admitted rather than stopped, and a run that
        // carried a page out would reach the runner as a browser check and not as
        // a service. An assertion about `services()` alone would not see it.
        assert!(
            runner.services().is_empty(),
            "this run declares no service, so nothing should have been handed to the runner as \
             one: {:?}",
            runner.services()
        );
        assert!(
            runner.browsers().is_empty(),
            "this run declares no page, so nothing should have been handed to the runner as a \
             browser check: {:?}",
            runner.browsers()
        );
        for result in run.report.results() {
            if dynamic.contains(&result.title) {
                // `Error`, and not merely "not `Pass`". The weaker assertion is
                // the one a reader writes first, and it is not enough here:
                // `CriticalState::from_status` maps `Warning` to `Passed`, so a
                // regression that made this arm a warning would satisfy
                // `!= Pass` and put a green on the check that matters most. The
                // doc comment above says `Error`; this is it as a measurement.
                assert_eq!(
                    result.status,
                    sure_domain::status::CheckStatus::Error,
                    "{} was admitted, the runner started nothing, and the run reports it as \
                     something other than an error: {}",
                    result.title,
                    result.reason
                );
                assert!(
                    result
                        .reason
                        .contains("cancelled before the command was started"),
                    "{} is reported with a reason that does not say what happened: {}",
                    result.title,
                    result.reason
                );
            }
        }
    }

    // --- the project, read a second time ----------------------------------

    /// The identities of the checks in a run's plan whose evidence came from a
    /// process, in plan order.
    ///
    /// The predicate [`invalidate_runtime_passes`] itself uses —
    /// [`CheckOperation::starts_a_process`] and not the consent predicate stages
    /// 5 and 6 split the plan by — rather than a list of titles, so this test and
    /// the pipeline agree on what "runtime evidence" is by construction. The two
    /// predicates part on a browser row, for the reason the production function
    /// records: a page row's evidence is about an execution and its permission is
    /// not `run_project_code`, so a helper that asked the consent question here
    /// would quietly stop covering the row this rule was repaired for.
    fn runtime_check_ids(run: &RunOutcome) -> Vec<CheckId> {
        run.schedule
            .checks()
            .iter()
            .filter(|scheduled| scheduled.operation().starts_a_process())
            .map(|scheduled| scheduled.proposal().id().clone())
            .collect()
    }

    /// A run's results as `(title, status)` pairs, for a failing assertion's
    /// message.
    fn statuses(results: &[&CheckResult]) -> Vec<(String, CheckStatus)> {
        results
            .iter()
            .map(|result| (result.title.clone(), result.status))
            .collect()
    }

    /// The stage line a reader of this run sees for one stage.
    fn stage_detail(outcome: &PipelineOutcome, stage: Stage) -> String {
        outcome
            .stages
            .iter()
            .find(|record| record.stage == stage)
            .unwrap_or_else(|| panic!("a finished run has a record for every stage"))
            .outcome
            .detail()
            .to_owned()
    }

    /// The third acceptance clause, **measured rather than argued**.
    ///
    /// The second reading in the run below would fire on every honest run if a
    /// build moved the fingerprint, so the rule is stated for the trees a build
    /// legitimately writes rather than pretending those trees do not exist. The
    /// tree already carries the answer — the scan's ignore tables *are* the
    /// fingerprint's coverage, so `target/`, `node_modules/` and SURE's own
    /// `.sure/` are outside the walk — and this is that answer as a reading
    /// rather than a second statement of it.
    ///
    /// **The last third is the control, and without it this test could not
    /// fail.** A fingerprint that answered `matches` for every pair would
    /// satisfy both readings above while measuring nothing, so the same fixture
    /// then gets a file the walk *does* cover — a generated module under `src/`.
    /// That is the honest limit of the rule and it is not papered over: a build
    /// that writes a generated source file, or regenerates a lockfile, has
    /// genuinely changed the project, and a run that caused that has genuinely
    /// invalidated its own evidence.
    #[test]
    fn a_builds_own_caches_do_not_move_the_fingerprint() {
        let project = a_rust_project("pipeline-caches");
        let now = || {
            project_fingerprint(&project, &fingerprint::FingerprintOptions::default())
                .expect("this fixture is readable")
        };

        let before = now();
        for (tree, file) in [
            ("target", "debug/thing.exe"),
            ("node_modules", "left-pad/index.js"),
            (crate::paths::PROJECT_CACHE_DIR, "evidence/current.json"),
        ] {
            let path = project.join(tree).join(file);
            std::fs::create_dir_all(path.parent().expect("a parent directory"))
                .expect("a cache directory a build would write");
            std::fs::write(&path, b"a build wrote this").expect("a cache file a build would write");
        }
        let after = now();
        assert!(
            before.matches(&after),
            "a build writing its own caches moved the fingerprint, so every honest run would \
             invalidate its own evidence: {} became {}",
            before.digest,
            after.digest
        );

        std::fs::write(
            project.join("src").join("generated.rs"),
            "pub fn generated() -> u32 {\n    7\n}\n",
        )
        .expect("a generated source file");
        let moved = now();
        assert!(
            !after.matches(&moved),
            "a file the walk covers did not move the fingerprint, so the reading above measures \
             nothing: both are {}",
            after.digest
        );
    }

    /// A runner that answers *the command passed*, and writes a file first.
    ///
    /// **It starts nothing.** The seam `P18-T007` added exists so that the wired
    /// path is measurable with a runner that records being called and starts no
    /// process, and this test would be worth nothing without it: a real `cargo
    /// test` would measure the machine rather than the pipeline, and the one
    /// thing this test needs — a project that moves *while the run is working* —
    /// can only be arranged from inside the window the project's own checks
    /// occupy.
    ///
    /// The answer it returns is a real shape rather than a convenience: an
    /// [`Outcome`] whose process exited with code 0 and whose streams SURE holds
    /// whole is exactly what [`CommandRun::to_result`] reports as a `Pass`, and a
    /// pass is the only thing this test is about — it is the status a stale
    /// result must not be left standing as.
    #[derive(Debug)]
    struct Moves {
        /// Written, in order, every time the runner is asked to run anything.
        writes: Vec<std::path::PathBuf>,
        /// Every command it was handed, so a test can show it was reached.
        asked: RefCell<Vec<String>>,
        /// The exit code it answers with. `Some(0)` is the pass a stale result
        /// must not be left standing as; anything else is a finding the run made,
        /// which the stale rule is deliberately not about.
        exit: Option<i32>,
    }

    impl CheckRunner for Moves {
        fn run(
            &self,
            work: &crate::planned_check_runner::AdmittedRun<'_>,
        ) -> crate::planned_work::CommandRun {
            let spec = work.command();
            self.asked.borrow_mut().push(format!(
                "{} {}",
                spec.program().to_string_lossy(),
                spec.arguments()
                    .iter()
                    .map(|argument| argument.to_string_lossy().into_owned())
                    .collect::<Vec<_>>()
                    .join(" ")
            ));
            for path in &self.writes {
                std::fs::create_dir_all(path.parent().expect("a parent directory"))
                    .expect("a directory for the write");
                std::fs::write(path, b"written while the run was working")
                    .expect("a write inside the run's window");
            }
            CommandRun::Ran(Outcome::new(
                spec.program().to_owned(),
                Termination::Exited { code: self.exit },
                CapturedOutput::empty(),
                CapturedOutput::empty(),
                std::time::SystemTime::now(),
                std::time::Duration::ZERO,
            ))
        }

        /// Unreachable through the runs this file makes, and answered the way
        /// everything unreachable in this file is: with an `Error`.
        ///
        /// A `CheckOperation::Service` is planned by `crate::service_plan`, and
        /// every run here is configured by `Config::default()`, which declares no
        /// service — so a test that needed this arm would have to plan one by hand,
        /// and a test that made it live would have to start a real service. An
        /// `Error` rather than a pass, so that a future path reaching it without
        /// measuring anything cannot look like a success — the same rule the rest
        /// of this file is written under.
        fn run_service(
            &self,
            work: &crate::planned_check_runner::AdmittedService<'_>,
        ) -> CheckResult {
            let check = work.admitted().command().check();
            self.asked
                .borrow_mut()
                .push(format!("service {}", check.id()));
            CheckResult::errored(
                check.id().clone(),
                check.title().to_owned(),
                check.severity(),
                check.critical(),
                "this run declares no service and this runner starts nothing, so a service check \
                 reaching it is not a result",
                work.fingerprint().clone(),
            )
        }

        /// Unreachable through the runs this file makes for the same reason and
        /// for one more: a `CheckOperation::Browser` needs a declaration that
        /// names a page, and this runner was given no browser driver even if one
        /// arrived.
        fn run_browser(
            &self,
            work: &crate::planned_check_runner::AdmittedBrowser<'_>,
        ) -> CheckResult {
            let check = work.admitted().command().check();
            self.asked
                .borrow_mut()
                .push(format!("browser {}", check.id()));
            CheckResult::errored(
                check.id().clone(),
                check.title().to_owned(),
                check.severity(),
                check.critical(),
                "this run declares no page and this runner holds no browser driver, so a browser \
                 check reaching it is not a result",
                work.fingerprint().clone(),
            )
        }
    }

    /// The second acceptance clause, in both directions, over the real pipeline.
    ///
    /// **Two runs of the same project with the same runner, differing in one
    /// thing: which file the runner writes while the run's checks are being
    /// carried out.** The runner is [`Moves`], and it answers every admitted
    /// command with a clean exit — so every runtime check comes back `Pass`,
    /// which is what makes the second run a measurement rather than a run that
    /// never had a pass to lose.
    ///
    /// - **The control** writes only where a build legitimately writes, into
    ///   `target/` and `node_modules/`. Those same checks are still `Pass`, which
    ///   is the other half of the clause: a rule that invalidated on any write to
    ///   the tree would fail here, and a fingerprint that moves when the project
    ///   did not teaches a reader to stop reading the word "stale".
    /// - **The run whose project moved** writes a file the walk covers, and the
    ///   checks that had passed come back `Unknown`, carrying the domain
    ///   vocabulary's own sentence and the digest of the state the project is
    ///   *actually* in.
    ///
    /// Two guard assertions keep this from being a test that cannot fail: the
    /// runner must have been reached, and at least one runtime check must have
    /// come back `Pass` in the control. The project's movement is measured too —
    /// the fingerprint is taken again after the run and the run's own state is
    /// asserted not to match it.
    #[test]
    fn a_project_that_moved_under_a_run_leaves_no_pass_from_running_it_standing() {
        let project = a_rust_project("pipeline-moved");
        let config_root = project.join("configuration");
        std::fs::create_dir_all(&config_root).expect("a scratch configuration directory");
        let user_config = config_root.join("config.yaml");
        std::fs::write(
            &user_config,
            "execution:\n  mode: host_confirmed\n  allow_network: true\n",
        )
        .expect("the user's own configuration file");
        let authority = crate::config::Authority::load(&project, &user_config)
            .expect("the two configuration files are readable");
        let config = Config::default();

        let run_writing = |writes: Vec<std::path::PathBuf>| {
            let runner = Moves {
                writes,
                asked: RefCell::new(Vec::new()),
                exit: Some(0),
            };
            let outcome = Pipeline {
                project: &project,
                purpose: Purpose::Check,
                config: &config,
                execution: authority.execution(),
                store: None,
                goal: None,
                analysis: Default::default(),
                runner: &runner,
            }
            .run();
            let asked = runner.asked.borrow().clone();
            (outcome, asked)
        };

        // The control: the same runner, writing only where a build writes.
        let (control_outcome, control_asked) = run_writing(vec![
            project.join("target").join("debug").join("thing.exe"),
            project
                .join("node_modules")
                .join("left-pad")
                .join("index.js"),
        ]);
        let control = control_outcome
            .run
            .as_ref()
            .unwrap_or_else(|| panic!("the control run stopped: {:?}", control_outcome.stopped_at));
        assert_eq!(control.mode, ExecutionMode::HostConfirmed);
        assert!(
            control.permissions.run_project_code,
            "the user's own file did not move the mode, so the runs below are not the granted runs \
             they claim to be"
        );
        assert!(
            !control_asked.is_empty(),
            "the user granted execution and the runner was never reached, so there is no pass to \
             lose and the second run measures nothing: {:?}",
            control.schedule.plain_description()
        );
        let runtime_ids = runtime_check_ids(control);
        assert!(
            !runtime_ids.is_empty(),
            "this project planned no check that would run its code: {:?}",
            control.schedule.plain_description()
        );
        let runtime_in_control: Vec<&CheckResult> = control
            .report
            .results()
            .iter()
            .filter(|result| runtime_ids.contains(&result.id))
            .collect();
        let passed_in_control: Vec<CheckId> = runtime_in_control
            .iter()
            .filter(|result| result.status == CheckStatus::Pass)
            .map(|result| result.id.clone())
            .collect();
        assert!(
            !passed_in_control.is_empty(),
            "the runner answered every admitted command with a clean exit and no check that ran \
             this project's code came back as a pass, so the run below has nothing to invalidate: \
             {:?}",
            statuses(&runtime_in_control)
        );

        // The same run, with the runner writing a file the walk covers.
        let (moved_outcome, moved_asked) =
            run_writing(vec![project.join("src").join("generated.rs")]);
        let moved = moved_outcome
            .run
            .as_ref()
            .unwrap_or_else(|| panic!("the run stopped: {:?}", moved_outcome.stopped_at));
        assert!(
            !moved_asked.is_empty(),
            "the runner was never reached in the run whose project moved, so nothing was \
             invalidated because nothing was ever observed"
        );
        let now = project_fingerprint(&project, &fingerprint::FingerprintOptions::default())
            .expect("this fixture is readable");
        assert!(
            !moved.project_state.matches(&now),
            "the fixture did not move, so this run is not the run it claims to be: {} and {}",
            moved.project_state.digest,
            now.digest
        );

        let runtime_in_moved: Vec<&CheckResult> = moved
            .report
            .results()
            .iter()
            .filter(|result| runtime_ids.contains(&result.id))
            .collect();
        assert_eq!(
            runtime_in_moved.len(),
            runtime_ids.len(),
            "the run reports {} of the {} checks in its plan that would run the project's code",
            runtime_in_moved.len(),
            runtime_ids.len()
        );
        assert!(
            runtime_in_moved
                .iter()
                .all(|result| result.status != CheckStatus::Pass),
            "the project moved while these ran and the run still stands one of them up as current: \
             {:?}",
            statuses(&runtime_in_moved)
        );
        for result in runtime_in_moved
            .iter()
            .filter(|result| passed_in_control.contains(&result.id))
        {
            assert_eq!(
                result.status,
                CheckStatus::Unknown,
                "{} passed, the project moved while it was working, and the run reports it as \
                 `{:?}` rather than as evidence that supports no verdict: {}",
                result.title,
                result.status,
                result.reason
            );
            assert!(
                result
                    .reason
                    .contains(StalenessReason::SupersededByLaterChange.plain_explanation()),
                "{} does not say why in the vocabulary's own words: {}",
                result.title,
                result.reason
            );
            assert!(
                result.reason.contains(&now.digest),
                "{} does not name the state the project is actually in, so a reader cannot tell \
                 what its result is stale against: {}",
                result.title,
                result.reason
            );
            assert!(
                result.blocks_green() || !result.critical,
                "{} is critical and its pass is no longer current, but the run still counts it as \
                 passing: {:?}",
                result.title,
                result.status
            );
        }

        // The line a reader of the report looks at for what the verdict is
        // about, and the coverage entry that carries the same fact.
        let aggregate_line = stage_detail(&moved_outcome, Stage::Aggregate);
        assert!(
            aggregate_line.contains("the project changed while the run was working"),
            "the aggregate stage does not say the project moved: {aggregate_line}"
        );
        for id in &passed_in_control {
            let title = moved
                .report
                .results()
                .iter()
                .find(|result| &result.id == id)
                .map(|result| result.title.as_str())
                .expect("a result that was in the control run is in this one");
            assert!(
                aggregate_line.contains(title),
                "the aggregate stage does not name {title} among the results it is not counting: \
                 {aggregate_line}"
            );
            let entry = moved
                .coverage
                .not_checked
                .iter()
                .find(|entry| entry.check_id == id.to_string())
                .unwrap_or_else(|| {
                    panic!(
                        "{title} is not in the coverage summary's not-checked list: {:?}",
                        moved.coverage.not_checked
                    )
                });
            assert!(
                entry
                    .reason
                    .contains(StalenessReason::SupersededByLaterChange.plain_explanation()),
                "{title} is listed as not checked with a reason that does not say why: {}",
                entry.reason
            );
        }

        // The control's own report says nothing of the sort, which is the
        // direction that would otherwise be this rule's false positive.
        assert!(
            !stage_detail(&control_outcome, Stage::Aggregate)
                .contains("the project changed while the run was working"),
            "a run that only wrote its own build caches was reported as one whose project moved: \
             {}",
            stage_detail(&control_outcome, Stage::Aggregate)
        );
        let control_passed: Vec<&CheckResult> = control
            .report
            .results()
            .iter()
            .filter(|result| passed_in_control.contains(&result.id))
            .collect();
        assert_eq!(
            control_passed.len(),
            passed_in_control.len(),
            "a check that passed in the control run is missing from its report: {:?}",
            statuses(&control_passed)
        );
        assert!(
            control_passed
                .iter()
                .all(|result| result.status == CheckStatus::Pass),
            "a run that wrote only its own build caches invalidated a check that ran the project's \
             code: {:?}",
            statuses(&control_passed)
        );
    }

    /// The movement named even when there was nothing to withdraw, over the real
    /// pipeline.
    ///
    /// [`invalidate_runtime_passes`] replaces a `Pass` and nothing else — rightly,
    /// because a failing check is a finding the run actually made rather than a
    /// stale one — so a run whose project moved and whose runtime checks all
    /// *failed* has an empty withdrawal list while the second read has still
    /// answered. **A stage line that spoke only for the non-empty list is silent
    /// in exactly that run**, and silent too in every run that plans no check
    /// which runs the project's code at all, which is every run a user has not
    /// granted execution. This is the reading that keeps the second read from
    /// being taken and then dropped — the shape
    /// [`stale_evidence_reason`]'s error arm exists to avoid one line earlier.
    ///
    /// The runner answers with a failing exit code and writes a file the walk
    /// covers, so both halves of the fixture are arranged by the one call the run
    /// makes. Three guard assertions keep this from being a test that cannot
    /// fail: the runner must have been reached, no runtime check may have passed,
    /// and the project must actually have moved.
    #[test]
    fn a_project_that_moved_is_named_even_when_no_pass_was_withdrawn() {
        let project = a_rust_project("pipeline-moved-unreplaced");
        let config_root = project.join("configuration");
        std::fs::create_dir_all(&config_root).expect("a scratch configuration directory");
        let user_config = config_root.join("config.yaml");
        std::fs::write(
            &user_config,
            "execution:\n  mode: host_confirmed\n  allow_network: true\n",
        )
        .expect("the user's own configuration file");
        let authority = crate::config::Authority::load(&project, &user_config)
            .expect("the two configuration files are readable");
        let config = Config::default();

        let runner = Moves {
            writes: vec![project.join("src").join("generated.rs")],
            asked: RefCell::new(Vec::new()),
            // A command that ran, ended on its own, and reported failure: the
            // `fail` row of `CommandRun::to_result`'s table rather than the pass
            // the other test needs.
            exit: Some(1),
        };
        let outcome = Pipeline {
            project: &project,
            purpose: Purpose::Check,
            config: &config,
            execution: authority.execution(),
            store: None,
            goal: None,
            analysis: Default::default(),
            runner: &runner,
        }
        .run();
        let run = outcome
            .run
            .as_ref()
            .unwrap_or_else(|| panic!("the run stopped: {:?}", outcome.stopped_at));
        assert!(
            !runner.asked.borrow().is_empty(),
            "the user granted execution and the runner was never reached, so this run has no \
             runtime result at all and measures nothing: {:?}",
            run.schedule.plain_description()
        );
        let now = project_fingerprint(&project, &fingerprint::FingerprintOptions::default())
            .expect("this fixture is readable");
        assert!(
            !run.project_state.matches(&now),
            "the fixture did not move, so this run is not the run it claims to be: {} and {}",
            run.project_state.digest,
            now.digest
        );

        let runtime_ids = runtime_check_ids(run);
        assert!(
            !runtime_ids.is_empty(),
            "this project planned no check that would run its code: {:?}",
            run.schedule.plain_description()
        );
        let runtime: Vec<&CheckResult> = run
            .report
            .results()
            .iter()
            .filter(|result| runtime_ids.contains(&result.id))
            .collect();
        assert!(
            runtime
                .iter()
                .all(|result| result.status == CheckStatus::Fail),
            "the runner answered every admitted command with a failing exit code, so no runtime \
             check has a pass to withdraw and the run below is about the empty list; one came \
             back as something else: {:?}",
            statuses(&runtime)
        );

        // The line a reader of the verdict looks at. **Both assertions are about
        // the second read's answer reaching the page**, not about how it is
        // phrased: a run whose project did not move carries neither of these, and
        // that is the difference this test exists to measure.
        let line = stage_detail(&outcome, Stage::Aggregate);
        assert!(
            line.contains(StalenessReason::SupersededByLaterChange.plain_explanation()),
            "the project moved while the run was working and the run's own line does not say so, \
             because it had no pass to withdraw: {line}"
        );
        assert!(
            line.contains(&now.digest),
            "the line does not name the state the project is actually in, so a reader cannot tell \
             what this run's results are stale against: {line}"
        );
    }

    #[test]
    fn a_candidate_must_fix_is_not_offered_as_a_repair_contract() {
        use sure_domain::evidence::EvidenceClass;
        use sure_domain::finding::FindingStatus;
        use sure_domain::ids::{CheckId, FingerprintId};
        use sure_domain::severity::Severity;
        use sure_domain::status::CheckResult;

        let fingerprint =
            FingerprintId::parse("fp_01j2m8q5aaaabbbbccccddddee").expect("a fixture id");
        let result = CheckResult::warning(
            CheckId::generate(),
            "UI action: click handler on element",
            Severity::MustFix,
            true,
            EvidenceClass::Inference,
            fingerprint,
        );
        let schedule = crate::schedule::PlanBuilder::new(
            ExecutionMode::InspectOnly,
            ExecutionPermissions::inspect_only(),
        )
        .build();
        let findings = crate::findings_from_checks::findings_from_checks(&[result], &schedule);

        assert_eq!(findings[0].status, FindingStatus::CannotConfirm);
        let (contracts, refused) = contracts_for(&findings, &schedule);
        assert!(
            contracts.is_empty(),
            "a candidate was offered as a repair contract: {contracts:?}"
        );
        assert!(
            refused
                .iter()
                .any(|reason| reason.contains("candidate evidence")),
            "the refusal does not say the finding is candidate evidence: {refused:?}"
        );
    }

    #[test]
    fn a_stage_sentence_only_names_a_reason_every_stopped_check_shares() {
        let install = Some(NotCheckedReason::DependencyInstallNotPermitted);
        let network = Some(NotCheckedReason::NetworkNotPermitted);

        assert_eq!(
            common_not_checked_reason([install, install].into_iter()),
            install
        );
        assert_eq!(
            common_not_checked_reason([install, network].into_iter()),
            None,
            "a mixed set named one check's permission for the others"
        );
        assert_eq!(
            common_not_checked_reason([install, None].into_iter()),
            None,
            "a check with no recorded reason was folded into a permission it never named"
        );
        assert_eq!(
            stopped_reason_phrase(install),
            "installing their dependencies is not allowed"
        );
        assert_eq!(
            stopped_reason_phrase(Some(NotCheckedReason::ExecutionNotAuthorized)),
            "the execution mode stopped them"
        );
    }

    #[test]
    fn a_todo_candidate_is_not_excluded_by_the_candidate_rule() {
        use sure_domain::evidence::EvidenceClass;
        use sure_domain::ids::{CheckId, FingerprintId};
        use sure_domain::severity::Severity;
        use sure_domain::status::CheckResult;

        let fingerprint =
            FingerprintId::parse("fp_01j2m8q5aaaabbbbccccddddee").expect("a fixture id");
        let result = CheckResult::warning(
            CheckId::generate(),
            "project contains TODO comments",
            Severity::CanFixLater,
            false,
            EvidenceClass::Inference,
            fingerprint,
        );
        let schedule = crate::schedule::PlanBuilder::new(
            ExecutionMode::InspectOnly,
            ExecutionPermissions::inspect_only(),
        )
        .build();
        let findings = crate::findings_from_checks::findings_from_checks(&[result], &schedule);

        let (_contracts, refused) = contracts_for(&findings, &schedule);
        assert!(
            refused
                .iter()
                .all(|reason| !reason.contains("candidate evidence")),
            "a non-blocking TODO candidate was excluded by the candidate rule: {refused:?}"
        );
    }
}
