//! The acceptance report: `evaluation/acceptance-manifest.json`, measured.
//!
//! # The sentence this module exists for
//!
//! `evaluation/README.md` states the release contract's requirement in one line:
//!
//! > *The release report must include actual observed outcome for every case.*
//!
//! **Actual observed outcome.** Every row below is produced by driving the
//! machinery that grades its case — the five candidate scanners, `db_migrations`,
//! `external_service`, `claim_checker`, the pipeline, `hook_protection` — and
//! never by reading `expected_severity` out of the manifest or the fixture's own
//! `scenario.json` and printing it back. That distinction is the whole of the
//! module: a report that restated the requirement as the outcome would read
//! green over exactly the cases where the two are known to differ, which is the
//! false green this repository exists to catch one level up.
//!
//! # Why this is a module and not a `sure` subcommand
//!
//! The corpus is a repository artefact. `evaluation/` and `fixtures/adversarial/`
//! are tracked files that exist in a checkout and not in a user's installation,
//! so a `sure eval` would either bake the build machine's path into a shipped
//! binary or fail on every user's machine. The runner is
//! `crates/sure-core/tests/acceptance_report_runner.rs`, which is where every
//! other grader of this manifest already lives and where the corpus path is
//! resolved the way this repository resolves it.
//!
//! # What this module does not do
//!
//! It opens no store, starts no process, and writes nothing: [`acceptance_report`]
//! takes a repository root and returns a value. One case — `repair-regression` —
//! cannot be observed here at all, and the reason is a rule rather than an
//! oversight: `crates/sure-core/tests/spawn_sites.rs`'s rule two forbids any file
//! under `crates/**/src/**` outside its own allowed list from naming the type the
//! process runner is handed, and observing that case means running the fixture's
//! two node checks. The module answers `cannot_confirm` for it with that reason
//! written into the row, and [`acceptance_report_with`] is the seam the runner
//! supplies the real measurement through — so a reader can always see which of
//! the two observed a row from the row itself.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::aggregation::{NOTHING_CAME_BACK, aggregate_run};
use crate::candidate_scanner::CandidateScanner;
use crate::capability::CapabilityTier;
use crate::claim_capture::AGENT_CLAIM_EVENT_TYPE;
use crate::claim_checker::{ClaimDocument, check_claims_against_events};
use crate::config::{Authority, Config, ExecutionSettings};
use crate::db_migrations::MigrationsReport;
use crate::demo_data_heuristics::DemoDataHeuristics;
use crate::discover::{DiscoverOptions, discover};
use crate::evidence::{AnchorSubject, ClaimAssessment, EvidenceClass};
use crate::execution::{ActionKind, ExecutionMode, ExecutionPermissions, Permission};
use crate::external_service::ExternalServiceChecks;
use crate::false_completion_aggregator::aggregate;
use crate::fingerprint::digest::Digest as CorpusDigest;
use crate::harness_event::{IngestedEvent, ingest_event_str};
use crate::hook_protection::{
    Danger, ProtectionDecisionKind, ToolRequest, assess_claude_code_tool, assess_cursor_tool,
    danger_reason,
};
use crate::ids::{CheckId, FingerprintId};
use crate::intent::{ProjectIntent, may_claim_full_fulfilment};
use crate::intent_implementation::compare_intent_to_project;
use crate::noop_heuristics::NoOpHeuristics;
use crate::paths::Paths;
use crate::pipeline::Pipeline;
use crate::planned_check_runner::ProcessRunner;
use crate::planned_work::{CheckOperation, PlannedWork, PrecomputedEvidence};
use crate::process::Cancellation;
use crate::project_verdict::render_summary;
use crate::route_consistency::RouteConsistency;
use crate::schedule::{CheckProposal, CheckReason, CheckSchedule, PlanBuilder};
use crate::severity::Severity;
use crate::status::{CheckResult, CheckStatus, NotCheckedReason};
use crate::ui_action_bridge::UiActionBridge;

/// The version of this report's shape.
///
/// Bumped when the shape changes in a way an older reader would get wrong.
pub const ACCEPTANCE_REPORT_SCHEMA_VERSION: u32 = 1;

/// The release contract, relative to the repository root.
pub const MANIFEST_PATH: &str = "evaluation/acceptance-manifest.json";

/// The only manifest schema version this build knows.
pub const MANIFEST_SCHEMA_VERSION: u32 = 1;

/// Where the adversarial corpus lives, relative to the repository root.
pub const FIXTURES_PATH: &str = "fixtures/adversarial";

/// The domain tag of the digest over the manifest bytes.
///
/// A domain tag is what makes two different kinds of digest unable to collide
/// even by coincidence, and the version number in it is what makes an old
/// digest and a new one over the same bytes different values. The digest is the
/// one `sure_core::fingerprint::digest` builds for this domain with the
/// manifest's bytes as its single length-prefixed field.
const MANIFEST_DIGEST_DOMAIN: &str = "sure.acceptance-corpus.v1";

/// The case the module cannot observe, and the one the runner supplies.
pub const REPAIR_REGRESSION: &str = "repair-regression";

/// The rule every severity-axis row is graded by.
///
/// Stated in the row so that no reader has to guess what "met" meant, and stated
/// as an equality rather than a floor. A floor was the first version of this
/// rule and it was wrong in the direction that matters most here: it cannot see
/// an escalation, so a build that turned a `note` into a `must_fix` would have
/// scored `met` over exactly the case `benign-test-mocks` exists to detect — a
/// false green, inside the artefact whose purpose is to catch them. The
/// manifest's field is `expected_severity`: what the product should say, not the
/// least it may say. Both directions of disagreement are therefore `unmet`, and
/// the row's comparison says which direction it went.
pub const SEVERITY_RULE: &str = "the manifest states the severity this case should produce, and the case is met when \
     the severity the machinery that grades it reaches equals that value exactly: a heavier observation is an \
     escalation and a lighter one is a miss, and both are `unmet`, because a false positive and a false negative are \
     the same defect seen from two sides. A row whose observed severity is `null` means nothing fired at all, which \
     is a measurement and not a requirement met";

// --- the shape of the report ----------------------------------------------

/// How one case is graded: by the severity the machinery reaches, or by the
/// outcome it produces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Axis {
    /// The manifest states a severity; the machinery that grades the case
    /// reaches one.
    Severity,
    /// The manifest names an outcome — a block, a refusal that stays visible, a
    /// claim that is not confirmed — and the case is graded on whether it
    /// happened.
    Outcome,
}

/// Whether a case meets what the manifest requires of it.
///
/// `CannotConfirm` is a first-class value and not a failure: it is what a row
/// says when nothing callable observes the case. It is never filled in with the
/// required value to make the report look complete.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Agreement {
    /// The requirement held, as measured.
    Met,
    /// The requirement did not hold, as measured. The observed value is in the
    /// row.
    Unmet,
    /// Nothing callable observed this case.
    CannotConfirm,
}

/// Where a reader who disagrees can go and look.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct RowAnchor {
    /// What kind of thing the location is, by `AnchorSubject`'s wire name.
    pub subject: String,
    /// The file, directory or command, relative to the repository root.
    pub location: String,
    /// The specific thing at that location.
    pub locator: String,
}

/// What was measured about one case, or why nothing could be.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Observation {
    /// The machinery that grades this case was driven, and this is what it
    /// produced.
    Observed {
        /// Which rule the case is graded on.
        axis: Axis,
        /// The severity the machinery that graded the case reached, in the
        /// manifest's own vocabulary — carried on both axes, so that an
        /// escalation is never invisible merely because a case is graded on its
        /// outcome. `None` means there is no such severity to carry: on
        /// [`Axis::Severity`] nothing fired at all, and on [`Axis::Outcome`] the
        /// machinery answers with a decision, an assessment or a run aggregate
        /// and computes no severity in this vocabulary. Serialised on every
        /// observed row, `null` included, so that a reader can tell "there is no
        /// severity here" from "this document has no such field".
        #[serde(default)]
        severity: Option<String>,
        /// The rule the row is graded by, in words.
        rule: String,
        /// The measured facts the row rests on.
        statements: Vec<String>,
        /// The modules and functions that produced them.
        surfaces: Vec<String>,
        /// The places they rest on.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        anchors: Vec<RowAnchor>,
    },
    /// Nothing callable observed this case, and the row says so rather than
    /// guessing.
    CannotConfirm {
        /// Which rule the case *would* have been graded by.
        axis: Axis,
        /// What was read instead of an observation.
        statements: Vec<String>,
        /// Always empty: nothing observed it.
        surfaces: Vec<String>,
        /// What is missing.
        missing: String,
        /// What would have to change for the row to carry an observation.
        would_require: String,
    },
}

/// What the manifest requires of one case.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Required {
    /// The least severity the manifest accepts, in its own vocabulary.
    pub severity: Severity,
    /// The manifest's own sentence about what this case is.
    pub expectation: String,
}

/// One case of the manifest, with what was observed about it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaseRow {
    /// The manifest's id for the case.
    pub id: String,
    /// Whether the contract blocks a release on this case.
    pub release_blocking: bool,
    /// What the manifest asks for.
    pub required: Required,
    /// What was measured.
    pub observed: Observation,
    /// Whether the requirement held.
    pub agreement: Agreement,
    /// The requirement and the observation side by side, with the measured
    /// value in it.
    pub comparison: String,
}

/// A corpus directory that corresponds to no case in the manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UncontractedFixture {
    /// The directory's name under [`FIXTURES_PATH`].
    pub id: String,
    /// Why it has no case.
    pub reason: String,
}

/// Which contract, and which corpus, a report is against.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Corpus {
    /// The manifest, relative to the repository root.
    pub manifest: String,
    /// The manifest's own `schema_version`.
    pub manifest_schema_version: u32,
    /// The digest that ties this report to the exact contract it was produced
    /// against: the manifest file's bytes, hashed under
    /// [`MANIFEST_DIGEST_DOMAIN`].
    pub manifest_digest: String,
    /// The corpus directory, relative to the repository root.
    pub fixtures: String,
    /// How many cases the manifest declares.
    pub cases: usize,
    /// How many of them are release-blocking.
    pub release_blocking: usize,
}

/// Counts over the rows, so a reader does not have to recount by hand.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Totals {
    /// Every case in the manifest.
    pub cases: usize,
    /// The release-blocking subset.
    pub release_blocking: usize,
    /// Rows that carry an observation.
    pub observed: usize,
    /// Rows that could not be observed.
    pub cannot_confirm: usize,
    /// Rows whose requirement held.
    pub met: usize,
    /// Rows whose requirement did not hold.
    pub unmet: usize,
    /// Release-blocking rows that carry an observation.
    pub release_blocking_observed: usize,
    /// Release-blocking rows whose requirement held.
    pub release_blocking_met: usize,
    /// Release-blocking rows whose requirement did not hold. **A release that
    /// is not zero here is a release this report does not permit.**
    pub release_blocking_unmet: usize,
    /// Release-blocking rows nothing observed.
    pub release_blocking_cannot_confirm: usize,
}

/// Every case in `evaluation/acceptance-manifest.json`, with the outcome
/// observed for each one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcceptanceReport {
    /// This report's shape version.
    pub schema_version: u32,
    /// The contract and corpus it is against.
    pub corpus: Corpus,
    /// One row per case, sorted by id.
    pub cases: Vec<CaseRow>,
    /// Corpus directories that answer to no case.
    pub fixtures_without_a_case: Vec<UncontractedFixture>,
    /// What this report does not know.
    pub limitations: Vec<String>,
    /// Counts over the rows.
    pub totals: Totals,
}

/// Why a report could not be produced.
///
/// Every variant is about the corpus or the manifest rather than about a case:
/// a case that cannot be observed is a row, not an error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CorpusError {
    /// A file the report depends on could not be read.
    Unreadable {
        /// The file, as it was looked for.
        path: String,
        /// What the operating system said.
        message: String,
    },
    /// A file the report depends on is not the shape it has to be.
    Malformed {
        /// The file, as it was looked for.
        path: String,
        /// What is wrong with it.
        message: String,
    },
    /// The manifest declares a schema version this build does not know.
    UnsupportedSchemaVersion {
        /// The file, as it was looked for.
        path: String,
        /// The version it declares.
        found: u64,
    },
    /// Two manifest cases share an id.
    DuplicateCase {
        /// The id.
        id: String,
    },
}

impl fmt::Display for CorpusError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unreadable { path, message } => {
                write!(formatter, "cannot read {path}: {message}")
            }
            Self::Malformed { path, message } => {
                write!(
                    formatter,
                    "{path} is not the shape this report needs: {message}"
                )
            }
            Self::UnsupportedSchemaVersion { path, found } => write!(
                formatter,
                "{path} declares schema_version {found} and this build knows {MANIFEST_SCHEMA_VERSION}"
            ),
            Self::DuplicateCase { id } => {
                write!(
                    formatter,
                    "the manifest declares more than one case with the id `{id}`"
                )
            }
        }
    }
}

impl std::error::Error for CorpusError {}

// --- measurements, as the recipes produce them ----------------------------

/// Everything one observation rests on, minus the value that decides it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Reading {
    /// The measured facts.
    pub statements: Vec<String>,
    /// The modules and functions that produced them.
    pub surfaces: Vec<String>,
    /// The places they rest on.
    pub anchors: Vec<RowAnchor>,
    /// The rule the row is graded by.
    pub rule: String,
}

/// How one case was observed, in the terms its own grading rule is stated in.
///
/// The three arms are the three honest answers: a severity was reached, an
/// outcome did or did not happen, or nothing callable could tell. There is no
/// arm that carries a severity nobody produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Measurement {
    /// The machinery that grades the case reaches a severity. `None` means
    /// nothing fired at all, which is a measurement and cannot meet a
    /// requirement.
    Severity {
        /// What it reached.
        severity: Option<Severity>,
        /// Everything behind it.
        reading: Reading,
    },
    /// The machinery that grades the case either did or did not produce the
    /// outcome the manifest's expectation names.
    Outcome {
        /// Whether it happened.
        held: bool,
        /// The severity, in the manifest's vocabulary, that the machinery which
        /// grades this case attached to what it produced — `None` where that
        /// machinery answers with a decision, an assessment or a run aggregate
        /// and no such severity exists.
        ///
        /// Carried so that an escalation cannot hide behind an outcome: a case
        /// graded on whether something happened still says how heavily the
        /// product weighed it, and a row that stayed `met` while weighing the
        /// case more heavily than the manifest asks says so in its comparison.
        severity: Option<Severity>,
        /// Everything behind it.
        reading: Reading,
    },
    /// Nothing callable observes this case.
    CannotConfirm {
        /// Which rule the case would have been graded by.
        axis: Axis,
        /// What was read instead of an observation.
        statements: Vec<String>,
        /// What is missing.
        missing: String,
        /// What would have to change.
        would_require: String,
    },
}

/// The recipe each manifest id is observed with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Recipe {
    /// The five false-completion scanners over the fixture project.
    Scanners,
    /// `db_migrations` over the fixture project.
    Migrations,
    /// `external_service` over the fixture project.
    ExternalService,
    /// The fixture's declared recording, through `claim_checker`.
    Claim,
    /// The fixture project, through the pipeline with no goal.
    Intent,
    /// The fixture project, through the pipeline under the authority its own
    /// configuration resolves to.
    ExecutionRefusal,
    /// The fixture's declared schedule and runs, through `aggregate_run`.
    CheckerFailure,
    /// The fixture's declared tool-call runs, through `hook_protection`.
    Action(Danger),
    /// The manifest has a case and the corpus ships a declaration with no
    /// project to observe.
    DeclarationOnly,
    /// The observation is made by the runner, one crate closer, and supplied
    /// through [`acceptance_report_with`].
    NeedsAProcessRunner,
}

/// The recipe table.
///
/// Every id in today's manifest is here, and a case whose id is not gets a
/// `cannot_confirm` row that says so — a new manifest case must never become an
/// invisible absence. `crates/sure-core/tests/acceptance_report_runner.rs`
/// asserts the set of ids that read `cannot_confirm` over the real corpus, so a
/// case falling out of this table is a red test rather than a quiet hole.
const RECIPES: &[(&str, Recipe)] = &[
    ("fake-payment", Recipe::Scanners),
    ("fake-auth", Recipe::Scanners),
    ("fake-email", Recipe::Scanners),
    ("dead-button", Recipe::Scanners),
    ("demo-analytics", Recipe::Scanners),
    ("route-mismatch", Recipe::Scanners),
    ("missing-migration", Recipe::Migrations),
    ("lying-readme", Recipe::DeclarationOnly),
    ("tests-not-run", Recipe::Claim),
    ("stale-test-evidence", Recipe::Claim),
    ("external-unverified", Recipe::ExternalService),
    (REPAIR_REGRESSION, Recipe::NeedsAProcessRunner),
    ("check-crash", Recipe::CheckerFailure),
    ("unknown-evidence", Recipe::Claim),
    ("benign-test-mocks", Recipe::Scanners),
    ("dangerous-delete", Recipe::Action(Danger::BroadDelete)),
    ("force-push", Recipe::Action(Danger::ForcePush)),
    ("sensitive-read", Recipe::Action(Danger::SensitiveRead)),
    ("missing-user-intent", Recipe::Intent),
    ("dynamic-not-authorized", Recipe::ExecutionRefusal),
];

/// The reason each corpus directory that answers to no case has none.
///
/// The same five are named, with the same reasons, in
/// `crates/sure-testkit/tests/fixture_apps.rs`'s
/// `FIXTURES_WITHOUT_A_MANIFEST_CASE`. The report carries them because the
/// requirement is *against the manifest*: a directory with no row must be named
/// rather than skipped into invisibility, and the two files are compared in both
/// directions by `acceptance_report_runner.rs` so neither can list an id the
/// other does not.
const OUT_OF_CONTRACT: &[(&str, &str)] = &[
    (
        "missing-config",
        "the manifest's case list is the release contract and P14-T002 was not asked to add a row to it; \
         the nearest case, `external-unverified`, is a different defect and is not claimed to cover this one",
    ),
    (
        "rust-tests-fail",
        "the manifest has no Rust case and no language-generic one, so no row's trap is this fixture's: \
         a Rust project whose own tests ran and failed. `tests-not-run`, the nearest by name, is the \
         opposite defect — a project whose tests were never run — and renaming this fixture after that \
         case would make its row grade something it was not written for",
    ),
    (
        "rust-tests-pass",
        "the same as `rust-tests-fail`, whose control this half is: it exists so that the failing half's \
         verdict is a measurement rather than a checker that refuses every Rust project, and the manifest \
         has no case for a project that is meant to come back green",
    ),
    (
        "intent-mismatch",
        "the manifest has one case about a request and the project it is compared against, and it is the \
         opposite situation: `missing-user-intent` is a project with no request at all, and its row asks \
         that nothing be claimed about fulfilment. This fixture has the request and SURE may report one \
         candidate about it, so the row's trap — a claim made without trusted intent — is not this \
         fixture's defect and renaming this directory after that case would make its row grade a fixture \
         that has exactly the trusted intent the row is about the absence of",
    ),
    (
        "container-unavailable",
        "every case in the manifest is about a defect in a project — a payment path that contacts nobody, \
         a route that was never built, a claim with no recording behind it — and none of them is about a \
         machine. The nearest by name, `dynamic-not-authorized`, is a different defect: there a check was \
         *refused* by a rule about consent, and its refusal is the thing that has to stay visible; here \
         nothing is refused by the absence at all, because nothing in this build asks whether a container \
         runtime is there. Renaming this fixture after that case would make its row grade a fixture whose \
         check is planned and denied when this one's is never planned",
    ),
];

// --- the entry points -----------------------------------------------------

/// Produce the acceptance report for the corpus under `repository_root`.
///
/// Pure in the sense that matters: no store is opened, no process is started and
/// nothing is written. The corpus is read, the machinery that grades each case is
/// driven, and a value is returned.
///
/// The one case no `src` module can observe — [`REPAIR_REGRESSION`] — reads
/// `cannot_confirm` here, with the rule that makes it so written into the row.
/// [`acceptance_report_with`] is the seam that lets the runner supply the real
/// measurement, and the row's `surfaces` say which of the two produced it.
///
/// # Errors
///
/// Returns [`CorpusError`] when the manifest cannot be read, is not the shape
/// this build needs, or names a schema version this build does not know, and
/// when a fixture the recipe table drives cannot be read. A case that cannot be
/// *observed* is a row and never an error.
pub fn acceptance_report(repository_root: &Path) -> Result<AcceptanceReport, CorpusError> {
    acceptance_report_with(repository_root, &BTreeMap::new())
}

/// The same, with observations supplied by the caller.
///
/// A supplied measurement replaces the recipe for that id, and the recipe table
/// is not consulted for it. This exists for exactly one reason: an observation
/// that requires starting a process cannot be made from a `src` module (see
/// [`REPAIR_REGRESSION`]'s row), so the caller that *can* make it supplies it
/// and the row records the surface that did.
///
/// # Errors
///
/// As [`acceptance_report`].
pub fn acceptance_report_with(
    repository_root: &Path,
    supplied: &BTreeMap<String, Measurement>,
) -> Result<AcceptanceReport, CorpusError> {
    let manifest_file = repository_root.join(MANIFEST_PATH);
    let manifest_text = read_to_string(&manifest_file)?;
    let document: Value =
        serde_json::from_str(&manifest_text).map_err(|error| CorpusError::Malformed {
            path: MANIFEST_PATH.to_owned(),
            message: error.to_string(),
        })?;

    let schema_version = document
        .get("schema_version")
        .and_then(Value::as_u64)
        .ok_or_else(|| CorpusError::Malformed {
            path: MANIFEST_PATH.to_owned(),
            message: "the manifest declares no numeric `schema_version`".to_owned(),
        })?;
    if schema_version != u64::from(MANIFEST_SCHEMA_VERSION) {
        return Err(CorpusError::UnsupportedSchemaVersion {
            path: MANIFEST_PATH.to_owned(),
            found: schema_version,
        });
    }

    let declared = manifest_cases(&document)?;
    let mut manifest_digest = CorpusDigest::new(MANIFEST_DIGEST_DOMAIN);
    manifest_digest.field(manifest_text.as_bytes());
    let manifest_digest = manifest_digest.finish();

    let fixtures_root = repository_root.join(FIXTURES_PATH);
    let mut rows: Vec<CaseRow> = Vec::with_capacity(declared.len());
    for case in &declared {
        rows.push(row_for(repository_root, &fixtures_root, case, supplied)?);
    }
    rows.sort_by(|left, right| left.id.cmp(&right.id));

    let totals = totals_of(&rows);
    Ok(AcceptanceReport {
        schema_version: ACCEPTANCE_REPORT_SCHEMA_VERSION,
        corpus: Corpus {
            manifest: MANIFEST_PATH.to_owned(),
            manifest_schema_version: MANIFEST_SCHEMA_VERSION,
            manifest_digest,
            fixtures: FIXTURES_PATH.to_owned(),
            cases: rows.len(),
            release_blocking: rows.iter().filter(|row| row.release_blocking).count(),
        },
        fixtures_without_a_case: fixtures_without_a_case(repository_root, &rows)?,
        limitations: limitations(),
        totals,
        cases: rows,
    })
}

/// The report, as the JSON document the schema describes.
///
/// Separated from [`acceptance_report`] so the runner can write bytes and
/// compare bytes without a second serialisation of its own.
///
/// # Errors
///
/// Returns [`CorpusError::Malformed`] when the report cannot be serialised,
/// which is a defect in this module rather than in a corpus.
pub fn acceptance_report_json(report: &AcceptanceReport) -> Result<String, CorpusError> {
    let mut text =
        serde_json::to_string_pretty(report).map_err(|error| CorpusError::Malformed {
            path: MANIFEST_PATH.to_owned(),
            message: format!("the report does not serialise: {error}"),
        })?;
    text.push('\n');
    Ok(text)
}

/// What this report does not know, said in the report.
///
/// The three the brief names, plus the two a reader of the corpus needs to know
/// before reading any row. They are constants rather than measurements because
/// they are properties of this build, and each one is checked where it lives:
/// the first by `crates/sure-core/src/pipeline.rs`, `crates/sure-cli/src/check.rs`
/// and `crates/sure-core/tests/acceptance_report_runner.rs`, the second by the
/// fact that every pipeline drive here is `inspect_only`, the third by this
/// module's own signature, and the fourth by
/// `crates/sure-core/tests/acceptance_report_runner.rs`.
fn limitations() -> Vec<String> {
    vec![
        String::from(
            "The closing half of the repair loop is unreached here, and that is the limit to read \
             every `met` row against. This report's drives run with `store: None`, so there is no \
             earlier run to compare against and `recheck_lifecycle::reconcile` has nothing it could \
             close. The product path now carries the rest of the loop: \
             `crates/sure-core/src/pipeline.rs` derives each contract's re-check list from \
             `sure_core::repair_impact`, `sure repair` and `sure recheck` record every finding a run \
             leaves open, and a second run over one store reports what the first left open. But a \
             finding closes only when every check its contract named has passed, and no drive here \
             produces a passing check at all — every one runs `inspect_only` and its own verdict \
             says `0 check(s) produced a result`. A row whose agreement is `met` is a row about what \
             SURE reports, not about a repair SURE completed.",
        ),
        String::from(
            "No project's code is run from a product path by this report. Every pipeline drive here \
             runs under `ExecutionSettings::inspect_only()`, and under that mode \
             `sure_core::enforce` admits no command that runs project code, so the checks that would \
             run one are planned and left unrun rather than executed. That is a fact about these \
             drives, and since `P18-T007` it is no longer a fact about the build: the pipeline reaches \
             the runner, and `crates/sure-core/src/support.rs`'s ceiling of level C rests on level B \
             being a claim about every platform SURE runs on rather than on a route nobody takes. The \
             one case whose checks really run — `repair-regression` — has them run from \
             `crates/sure-core/tests/acceptance_report_runner.rs` through `sure_core::process`, and its \
             row names that file as the surface.",
        ),
        String::from(
            "Nothing here read or wrote a SURE store. Every observation ran with `store: None`, and no \
             machine's user-data or configuration directory was touched; the one drive that needs a \
             configuration root places it under `target/tmp`.",
        ),
        String::from(
            "The corpus's own records of what the detectors produce are not a source for any value \
             here. When this report was written they were stale: fixtures carried a \
             `detector_severity_today` saying every detector emits `Severity::Note`, which `P7-T011` \
             had already made false, and no `.rs` file read the field, so nothing contradicted it. \
             `P14-T013` re-measured every value by running the detector named beside it, and \
             `crates/sure-core/tests/adversarial_fixture_detection.rs`'s \
             `every_recorded_detector_severity_is_what_the_detector_produces_today` reads each \
             fixture's own text and re-runs that detector, so the field cannot go stale again \
             unnoticed. This report read neither that field nor the manifest's `expected_severity` \
             for any observed value: every measure in a row came from the module named in its \
             `surfaces`.",
        ),
        String::from(
            "Deterministic. Two runs produce byte-identical output: no wall-clock timestamp, no \
             generated identifier and no path of the machine that produced it appears anywhere in \
             this document, and every collection is ordered before it is written.",
        ),
    ]
}

// --- reading the manifest -------------------------------------------------

/// One case as the manifest declares it.
#[derive(Debug, Clone)]
struct DeclaredCase {
    id: String,
    release_blocking: bool,
    expected_severity: Severity,
    expectation: String,
}

/// Every case the manifest declares, in the order it declares them.
fn manifest_cases(document: &Value) -> Result<Vec<DeclaredCase>, CorpusError> {
    let declared = document
        .get("cases")
        .and_then(Value::as_array)
        .ok_or_else(|| CorpusError::Malformed {
            path: MANIFEST_PATH.to_owned(),
            message: "the manifest declares no `cases` array".to_owned(),
        })?;

    let mut cases: Vec<DeclaredCase> = Vec::with_capacity(declared.len());
    for entry in declared {
        let id = entry
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| CorpusError::Malformed {
                path: MANIFEST_PATH.to_owned(),
                message: "a case declares no string `id`".to_owned(),
            })?
            .to_owned();
        let release_blocking = entry
            .get("release_blocking")
            .and_then(Value::as_bool)
            .ok_or_else(|| CorpusError::Malformed {
                path: MANIFEST_PATH.to_owned(),
                message: format!("the case `{id}` declares no boolean `release_blocking`"),
            })?;
        let severity =
            entry
                .get("expected_severity")
                .cloned()
                .ok_or_else(|| CorpusError::Malformed {
                    path: MANIFEST_PATH.to_owned(),
                    message: format!("the case `{id}` declares no `expected_severity`"),
                })?;
        let expected_severity: Severity =
            serde_json::from_value(severity).map_err(|error| CorpusError::Malformed {
                path: MANIFEST_PATH.to_owned(),
                message: format!("the case `{id}` declares `expected_severity` as {error}"),
            })?;
        let expectation = entry
            .get("expectation")
            .and_then(Value::as_str)
            .ok_or_else(|| CorpusError::Malformed {
                path: MANIFEST_PATH.to_owned(),
                message: format!("the case `{id}` declares no string `expectation`"),
            })?
            .to_owned();
        cases.push(DeclaredCase {
            id,
            release_blocking,
            expected_severity,
            expectation,
        });
    }

    let mut ids: Vec<&str> = cases.iter().map(|case| case.id.as_str()).collect();
    ids.sort_unstable();
    for pair in ids.windows(2) {
        if pair.first() == pair.get(1) {
            return Err(CorpusError::DuplicateCase {
                id: pair.first().copied().unwrap_or_default().to_owned(),
            });
        }
    }
    Ok(cases)
}

/// One row: the requirement from the manifest, the observation from the
/// machinery, and the comparison between them.
fn row_for(
    repository_root: &Path,
    fixtures_root: &Path,
    case: &DeclaredCase,
    supplied: &BTreeMap<String, Measurement>,
) -> Result<CaseRow, CorpusError> {
    let measurement = match supplied.get(&case.id) {
        Some(measurement) => measurement.clone(),
        None => observe(repository_root, fixtures_root, &case.id)?,
    };

    let (observed, agreement, comparison) = match measurement {
        Measurement::Severity { severity, reading } => {
            // The equality, not a floor. See `SEVERITY_RULE` for why the first
            // version of this line was a false green waiting to happen.
            let held = severity == Some(case.expected_severity);
            let rule = reading.rule;
            let observed = Observation::Observed {
                axis: Axis::Severity,
                severity: severity.map(|reached| reached.as_str().to_owned()),
                rule,
                statements: reading.statements,
                surfaces: reading.surfaces,
                anchors: reading.anchors,
            };
            let agreement = if held {
                Agreement::Met
            } else {
                Agreement::Unmet
            };
            // Which direction the disagreement went, in the sentence itself, so
            // that an escalation and a miss are two different readings to a
            // reader who has not read the rule.
            let comparison = match severity {
                Some(reached) if held => format!(
                    "`{}` requires `{}`; the machinery that grades it reaches `{}`, exactly what the \
                     contract asks, so the requirement is met.",
                    case.id,
                    case.expected_severity.as_str(),
                    reached.as_str()
                ),
                Some(reached) => format!(
                    "`{}` requires `{}`; the machinery that grades it reaches `{}` — {} than the \
                     contract asks, so the requirement is not met. {}",
                    case.id,
                    case.expected_severity.as_str(),
                    reached.as_str(),
                    if reached.rank() > case.expected_severity.rank() {
                        "heavier"
                    } else {
                        "lighter"
                    },
                    if reached.rank() > case.expected_severity.rank() {
                        "An escalation is a false positive, and a report that scored it `met` would be \
                         the false green this case exists to catch."
                    } else {
                        "A miss, which is the direction the requirement is usually read in and not the \
                         only one this rule sees."
                    }
                ),
                None => format!(
                    "`{}` requires `{}`; nothing fired at all, which is a measurement and not a \
                     requirement met, so the requirement is not met.",
                    case.id,
                    case.expected_severity.as_str()
                ),
            };
            (observed, agreement, comparison)
        }
        Measurement::Outcome {
            held,
            severity,
            reading,
        } => {
            let observed = Observation::Observed {
                axis: Axis::Outcome,
                severity: severity.map(|reached| reached.as_str().to_owned()),
                rule: reading.rule.clone(),
                statements: reading.statements,
                surfaces: reading.surfaces,
                anchors: reading.anchors,
            };
            let agreement = if held {
                Agreement::Met
            } else {
                Agreement::Unmet
            };
            // The axis grades the outcome. The severity is still recorded, and
            // where the machinery weighed the case more heavily than the
            // manifest asks, the disagreement is in this sentence and not only
            // among the statements: P14-T012 computes a rate over these rows and
            // must not have to parse prose to find it.
            let weight = match severity {
                Some(reached) if reached.rank() > case.expected_severity.rank() => format!(
                    " The machinery that grades it weighs the case `{}` where the manifest's \
                     `expected_severity` is `{}` — heavier than the contract asks. This row records \
                     that disagreement and does not hide it, and the expectation it states is about \
                     the outcome, which the machinery {}.",
                    reached.as_str(),
                    case.expected_severity.as_str(),
                    if held { "produces" } else { "does not produce" }
                ),
                Some(reached) if reached.rank() < case.expected_severity.rank() => format!(
                    " The machinery that grades it weighs the case `{}` where the manifest's \
                     `expected_severity` is `{}` — lighter than the contract asks, which this row \
                     records; the expectation it states is about the outcome, which the machinery \
                     {}.",
                    reached.as_str(),
                    case.expected_severity.as_str(),
                    if held { "produces" } else { "does not produce" }
                ),
                Some(reached) => format!(
                    " The machinery that grades it weighs the case `{}`, which is the manifest's \
                     `expected_severity` exactly.",
                    reached.as_str()
                ),
                None => String::from(
                    " The machinery that grades this case answers with a decision, an assessment or a \
                     run aggregate rather than a severity in the manifest's vocabulary, so the row's \
                     observed severity is empty: there is nothing here for a build to escalate.",
                ),
            };
            let comparison = format!(
                "`{}` states the expectation \"{}\", and the rule this report grades it by is: {}.{} \
                 The requirement is {}.",
                case.id,
                case.expectation,
                reading.rule,
                weight,
                if held { "met" } else { "not met" }
            );
            (observed, agreement, comparison)
        }
        Measurement::CannotConfirm {
            axis,
            statements,
            missing,
            would_require,
        } => {
            let observed = Observation::CannotConfirm {
                axis,
                statements,
                surfaces: Vec::new(),
                missing: missing.clone(),
                would_require,
            };
            let comparison = format!(
                "`{}` states the expectation \"{}\" and nothing callable observed it: {}",
                case.id, case.expectation, missing
            );
            (observed, Agreement::CannotConfirm, comparison)
        }
    };

    Ok(CaseRow {
        id: case.id.clone(),
        release_blocking: case.release_blocking,
        required: Required {
            severity: case.expected_severity,
            expectation: case.expectation.clone(),
        },
        observed,
        agreement,
        comparison,
    })
}

// --- the recipes ----------------------------------------------------------

/// Drive the machinery that grades one case.
fn observe(
    repository_root: &Path,
    fixtures_root: &Path,
    id: &str,
) -> Result<Measurement, CorpusError> {
    let recipe = RECIPES
        .iter()
        .find(|(named, _)| *named == id)
        .map(|(_, recipe)| *recipe);
    match recipe {
        Some(Recipe::Scanners) => scanners(repository_root, fixtures_root, id),
        Some(Recipe::Migrations) => migrations(repository_root, fixtures_root, id),
        Some(Recipe::ExternalService) => external_service(repository_root, fixtures_root, id),
        Some(Recipe::Claim) => claim_recording(repository_root, fixtures_root, id),
        Some(Recipe::Intent) => intent(fixtures_root, id),
        Some(Recipe::ExecutionRefusal) => execution_refusal(repository_root, fixtures_root, id),
        Some(Recipe::CheckerFailure) => checker_failure(fixtures_root, id),
        Some(Recipe::Action(danger)) => action(fixtures_root, id, danger),
        Some(Recipe::DeclarationOnly) => Ok(declaration_only(fixtures_root, id)),
        Some(Recipe::NeedsAProcessRunner) => Ok(needs_a_process_runner()),
        None => Ok(Measurement::CannotConfirm {
            axis: Axis::Severity,
            statements: vec![format!(
                "the manifest declares the case `{id}` and this report's recipe table has no entry for \
                 it, so nothing was driven and nothing was read"
            )],
            missing: format!(
                "this report has no recipe for the case `{id}`: it is in the manifest and no module in \
                 this build observes it"
            ),
            would_require: format!(
                "an entry in `sure_core::acceptance_report`'s recipe table for `{id}`, naming the module \
                 that grades it — a case the report has never heard of must not become an invisible \
                 absence"
            ),
        }),
    }
}

/// The five false-completion scanners, and what the aggregator makes of them.
fn scanners(
    repository_root: &Path,
    fixtures_root: &Path,
    id: &str,
) -> Result<Measurement, CorpusError> {
    let directory = fixtures_root.join(id);
    let discovery = discover(&directory, &DiscoverOptions::default())
        .map_err(|error| unreadable(&directory, error.to_string()))?;

    let groups: [(&str, Vec<CheckProposal>); 5] = [
        (
            "sure_core::candidate_scanner::CandidateScanner::of(..).proposed()",
            CandidateScanner::of(&discovery).proposed().to_vec(),
        ),
        (
            "sure_core::noop_heuristics::NoOpHeuristics::of(..).proposed()",
            NoOpHeuristics::of(&discovery).proposed().to_vec(),
        ),
        (
            "sure_core::demo_data_heuristics::DemoDataHeuristics::of(..).proposed()",
            DemoDataHeuristics::of(&discovery).proposed().to_vec(),
        ),
        (
            "sure_core::route_consistency::RouteConsistency::of(..).proposed()",
            RouteConsistency::of(&discovery).proposed().to_vec(),
        ),
        (
            "sure_core::ui_action_bridge::UiActionBridge::of(..).proposals()",
            UiActionBridge::of(&discovery).proposals(),
        ),
    ];

    let mut statements: Vec<String> = Vec::new();
    let mut surfaces: Vec<String> = Vec::new();
    let mut all: Vec<CheckProposal> = Vec::new();
    for (surface, proposals) in &groups {
        let heaviest = proposals
            .iter()
            .map(CheckProposal::severity)
            .max_by_key(|severity| severity.rank());
        statements.push(format!(
            "`{surface}` proposes {} check(s); the heaviest severity it reaches is `{}`",
            proposals.len(),
            heaviest.map_or("nothing", Severity::as_str)
        ));
        surfaces.push((*surface).to_owned());
        all.extend(proposals.iter().cloned());
    }

    let heaviest = all
        .iter()
        .map(CheckProposal::severity)
        .max_by_key(|severity| severity.rank());
    let classes: BTreeSet<&str> = all
        .iter()
        .map(|proposal| proposal.evidence_class().as_str())
        .collect();
    let aggregated = aggregate(all.clone());
    statements.push(format!(
        "the five scanners propose {} check(s) between them, every one of them with an evidence class in \
         {{{}}}; the heaviest severity over all of them is `{}`",
        all.len(),
        classes.iter().copied().collect::<Vec<_>>().join(", "),
        heaviest.map_or("nothing", Severity::as_str)
    ));
    statements.push(format!(
        "`false_completion_aggregator::aggregate` keeps {} of them as material, files {} as style noise, \
         and drops {} as duplicates of a candidate that shares their anchor",
        aggregated.material().len(),
        aggregated.style_noise().len(),
        aggregated.duplicates_dropped()
    ));
    surfaces.push("sure_core::false_completion_aggregator::aggregate".to_owned());

    let mut anchors: Vec<RowAnchor> = all
        .iter()
        .filter_map(|proposal| proposal.reason().anchor())
        .map(|anchor| {
            fixture_anchor(
                repository_root,
                fixtures_root,
                id,
                &anchor.location,
                &anchor.locator,
            )
        })
        .collect();
    anchors.sort();
    anchors.dedup();

    Ok(Measurement::Severity {
        severity: heaviest,
        reading: Reading {
            statements,
            surfaces,
            anchors,
            rule: SEVERITY_RULE.to_owned(),
        },
    })
}

/// `db_migrations`'s own reading of the fixture project.
fn migrations(
    repository_root: &Path,
    fixtures_root: &Path,
    id: &str,
) -> Result<Measurement, CorpusError> {
    let directory = fixtures_root.join(id);
    let discovery = discover(&directory, &DiscoverOptions::default())
        .map_err(|error| unreadable(&directory, error.to_string()))?;
    let report = MigrationsReport::of(&discovery, &FingerprintId::generate());

    let claims: Vec<_> = report.claims().iter().collect();
    let mut statements = vec![format!(
        "`sure_core::db_migrations::MigrationsReport::of(..)` reports {} gap(s) about this project, and \
         `is_complete()` is {}",
        claims.len(),
        report.is_complete()
    )];
    let mut anchors: Vec<RowAnchor> = Vec::new();
    for claim in &claims {
        statements.push(format!(
            "`{}`: the record at `{}` is {}, the verdict is `{}` and the severity is `{}`. {}",
            claim.framework(),
            claim.claim().record_at().display(),
            record_name(claim.record()),
            claim.assessment().as_str(),
            claim.severity().as_str(),
            claim.reason()
        ));
        for evidence in claim.evidence() {
            anchors.push(fixture_anchor(
                repository_root,
                fixtures_root,
                id,
                &evidence.anchor.location,
                &evidence.anchor.locator,
            ));
        }
    }
    anchors.sort();
    anchors.dedup();

    Ok(Measurement::Severity {
        severity: claims
            .iter()
            .map(|claim| claim.severity())
            .max_by_key(|severity| severity.rank()),
        reading: Reading {
            statements,
            surfaces: vec![
                "sure_core::db_migrations::MigrationsReport::of(..).claims()".to_owned(),
            ],
            anchors,
            rule: SEVERITY_RULE.to_owned(),
        },
    })
}

/// `external_service`'s proposal, and what it becomes.
fn external_service(
    repository_root: &Path,
    fixtures_root: &Path,
    id: &str,
) -> Result<Measurement, CorpusError> {
    let directory = fixtures_root.join(id);
    let discovery = discover(&directory, &DiscoverOptions::default())
        .map_err(|error| unreadable(&directory, error.to_string()))?;
    let checks = ExternalServiceChecks::of(&discovery);
    let proposals = checks.proposed();
    let results = checks.not_checked(&FingerprintId::generate());

    let heaviest = proposals
        .iter()
        .map(CheckProposal::severity)
        .max_by_key(|severity| severity.rank());
    let mut statements = vec![format!(
        "`sure_core::external_service::ExternalServiceChecks::of(..).proposed()` proposes {} check(s); \
         the heaviest severity is `{}` and {} of them are critical",
        proposals.len(),
        heaviest.map_or("nothing", Severity::as_str),
        proposals
            .iter()
            .filter(|proposal| proposal.critical())
            .count()
    )];
    let mut anchors: Vec<RowAnchor> = Vec::new();
    for proposal in proposals {
        statements.push(format!(
            "the proposal `{}` carries evidence class `{}` and rests on `{}`",
            proposal.title(),
            proposal.evidence_class().as_str(),
            proposal
                .reason()
                .anchor()
                .map_or_else(|| String::from("nothing"), |anchor| anchor.location.clone())
        ));
        if let Some(anchor) = proposal.reason().anchor() {
            anchors.push(fixture_anchor(
                repository_root,
                fixtures_root,
                id,
                &anchor.location,
                &anchor.locator,
            ));
        }
    }
    let every_one_is_a_refusal = !results.is_empty()
        && results.iter().all(|result| {
            result.status == CheckStatus::Skipped
                && result.not_checked_reason == Some(NotCheckedReason::ExternalServiceUnavailable)
        });
    statements.push(format!(
        "`ExternalServiceChecks::not_checked(..)` turns all {} of them into results with status `{}` and \
         the reason sentence \"{}\"; `{}` of them are reported as `{}`",
        results.len(),
        results
            .first()
            .map_or("nothing", |result| result.status.as_str()),
        NotCheckedReason::ExternalServiceUnavailable.plain_explanation(),
        results
            .iter()
            .filter(|result| result.status == CheckStatus::Pass)
            .count(),
        CheckStatus::Pass.as_str()
    ));
    anchors.sort();
    anchors.dedup();

    Ok(Measurement::Outcome {
        held: !proposals.is_empty() && every_one_is_a_refusal,
        // The weight the product itself puts on an unconfirmable external
        // service, read off its own proposals rather than out of the manifest —
        // and it is heavier than this case's `expected_severity`, which the
        // row's comparison says in words.
        severity: heaviest,
        reading: Reading {
            statements,
            surfaces: vec![
                "sure_core::external_service::ExternalServiceChecks::of(..).proposed()".to_owned(),
                "sure_core::external_service::ExternalServiceChecks::not_checked(..)".to_owned(),
            ],
            anchors,
            rule: String::from(
                "an external service can only be confirmed against the real service, so the check has \
                 to be turned into a result that is not checked — with `external_service_unavailable` \
                 as its reason and never as a pass",
            ),
        },
    })
}

/// One of the three declared recordings, through `claim_checker`.
fn claim_recording(
    _repository_root: &Path,
    fixtures_root: &Path,
    id: &str,
) -> Result<Measurement, CorpusError> {
    let document = scenario_of(fixtures_root, id)?;
    let block = document
        .get("claim_check")
        .ok_or_else(|| CorpusError::Malformed {
            path: format!("{FIXTURES_PATH}/{id}/scenario.json"),
            message: "it declares no `claim_check` block".to_owned(),
        })?;
    let claim = block.get("claim").ok_or_else(|| CorpusError::Malformed {
        path: format!("{FIXTURES_PATH}/{id}/scenario.json"),
        message: "the `claim_check` block declares no `claim`".to_owned(),
    })?;
    let claim_text = required_string(claim, "claim_text", id)?;
    let claim_type = required_string(claim, "claim_type", id)?;
    let claim_id = required_string(claim, "id", id)?;
    let claim_timestamp = required_string(claim, "timestamp", id)?;

    let events = block
        .get("events")
        .and_then(Value::as_array)
        .ok_or_else(|| CorpusError::Malformed {
            path: format!("{FIXTURES_PATH}/{id}/scenario.json"),
            message: "the `claim_check` block declares no `events` array".to_owned(),
        })?;

    // The claim itself goes in first and the declared events after it, and the
    // list is then read newest-first — the same order
    // `crates/sure-core/tests/adversarial_fixture_detection.rs` hands the
    // checker, so the two readings of one recording are the same reading.
    let mut ingested: Vec<IngestedEvent> = Vec::with_capacity(events.len() + 1);
    let claim_document = claim_document(id, &claim_id, &claim_text, &claim_type, &claim_timestamp);
    ingested.push(ingest(id, &claim_document)?);
    for event in events {
        let event_type = required_string(event, "event_type", id)?;
        let timestamp = required_string(event, "timestamp", id)?;
        let payload = event.get("payload").ok_or_else(|| CorpusError::Malformed {
            path: format!("{FIXTURES_PATH}/{id}/scenario.json"),
            message: format!("an event at {timestamp} declares no payload"),
        })?;
        let wire = serde_json::json!({
            "schema_version": crate::PROTOCOL_VERSION,
            "source": "claude-code",
            "event_type": event_type,
            "timestamp": timestamp,
            "capability_tier": CapabilityTier::Observed.number(),
            "session_id": "session-1",
            "project_root": CLAIM_PROJECT_ROOT,
            "payload": payload,
        })
        .to_string();
        ingested.push(ingest(id, &wire)?);
    }

    let documents = vec![ClaimDocument {
        record_id: 0,
        id: claim_id,
        claim_text: claim_text.clone(),
        claim_type: Some(claim_type.clone()),
    }];
    let newest_first: Vec<IngestedEvent> = ingested.iter().rev().cloned().collect();
    let checked =
        check_claims_against_events(&documents, &newest_first, &FingerprintId::generate());
    let answer = checked.first().ok_or_else(|| CorpusError::Malformed {
        path: format!("{FIXTURES_PATH}/{id}/scenario.json"),
        message: "the recording holds no claim, so there was nothing to check".to_owned(),
    })?;

    let mut statements = vec![
        format!(
            "the recording is one claim of type `{claim_type}` at {claim_timestamp} — \"{claim_text}\" \
             — against {} declared event(s)",
            events.len()
        ),
        format!(
            "`sure_core::claim_checker::check_claims_against_events(..)` answers `{}` for it, and the \
             sentence the report shows is: {}",
            answer.assessment.as_str(),
            answer.reason
        ),
    ];
    if answer.evidence.is_empty() {
        statements.push(String::from(
            "the answer rests on no evidence at all, which is why it is a refusal to confirm rather \
             than a verdict",
        ));
    } else {
        statements.push(format!(
            "the answer rests on {} evidence item(s), the strongest class among them being `{}`",
            answer.evidence.len(),
            answer
                .evidence
                .iter()
                .map(|evidence| evidence.class)
                .min_by_key(|class| class_rank(*class))
                .map_or("nothing", EvidenceClass::as_str)
        ));
    }

    let mut anchors: Vec<RowAnchor> = Vec::new();
    for evidence in &answer.evidence {
        anchors.push(RowAnchor {
            subject: AnchorSubject::Claim.as_str().to_owned(),
            location: format!("{FIXTURES_PATH}/{id}/scenario.json"),
            locator: format!("{} {}", evidence.anchor.location, evidence.anchor.locator),
        });
    }
    anchors.push(RowAnchor {
        subject: AnchorSubject::File.as_str().to_owned(),
        location: format!("{FIXTURES_PATH}/{id}/scenario.json"),
        locator: format!("claim_check.claim {claim_text} ({claim_type})"),
    });
    anchors.sort();
    anchors.dedup();
    statements.push(format!(
        "the machinery that grades this case answers with a `ClaimAssessment` (`{}`) and carries no \
         severity in the manifest's vocabulary, so the row carries no observed severity — there is \
         nothing here for a build to escalate",
        answer.assessment.as_str()
    ));

    Ok(Measurement::Outcome {
        held: answer.assessment == ClaimAssessment::CannotConfirm,
        severity: None,
        reading: Reading {
            statements,
            surfaces: vec!["sure_core::claim_checker::check_claims_against_events".to_owned()],
            anchors,
            rule: String::from(
                "a claim about something SURE cannot see has to come back `cannot_confirm` rather than \
                 confirmed: the case is met when the checker refuses to confirm it, and it is not met \
                 when the checker confirms a claim its own evidence does not support",
            ),
        },
    })
}

/// A runner that cannot start anything, for a corpus that must not be executed.
///
/// **The corpus is a set of projects SURE does not trust** — `fixtures/` and
/// `fixtures/adversarial/` are deliberately broken or hostile applications, and a
/// report that produced its rows by running them would be the exact thing this
/// product exists to prevent. The stop is asked for *before* the run, and
/// `process::run` checks for it *before* it spawns anything, so what this returns
/// is a value saying "nothing starts" rather than the absence of a runner saying
/// it: the sentence in this module's documentation — *it starts no process* — is
/// true of this file for a reason a reader can point at.
///
/// It is [`ProcessRunner`] rather than a fake, so every result these rows carry
/// about a check that could have run is the product's own answer
/// (`CancelledBeforeStart`, which is an `Error`) rather than a value invented
/// here.
fn nothing_starts() -> ProcessRunner {
    let stop = Cancellation::new();
    stop.cancel();
    ProcessRunner::new(stop)
}

/// The fixture project, through the pipeline, with no goal at all.
fn intent(fixtures_root: &Path, id: &str) -> Result<Measurement, CorpusError> {
    let root = fixtures_root.join(id);
    let config = Config::default();
    let runner = nothing_starts();
    let outcome = Pipeline {
        project: &root,
        purpose: crate::pipeline::Purpose::Check,
        config: &config,
        execution: ExecutionSettings::inspect_only(),
        store: None,
        goal: None,
        analysis: Default::default(),
        runner: &runner,
    }
    .run();
    let Some(record) = outcome.run.as_ref() else {
        return Ok(Measurement::CannotConfirm {
            axis: Axis::Outcome,
            statements: vec![format!(
                "the pipeline ran over `{FIXTURES_PATH}/{id}` and stopped at {} rather than reaching a \
                 report, so there is no record to read",
                outcome.stopped_at.map_or_else(
                    || String::from("no stage it named"),
                    |stage| format!("{stage:?}")
                )
            )],
            missing: format!(
                "the pipeline did not finish over this fixture: it stopped at {}",
                outcome.stopped_at.map_or_else(
                    || String::from("no stage it named"),
                    |stage| format!("{stage:?}")
                )
            ),
            would_require: String::from(
                "a fixture the pipeline can read to the end, which is what every other case in this \
                 manifest drives",
            ),
        });
    };

    let discovery = discover(&root, &DiscoverOptions::default())
        .map_err(|error| unreadable(&root, error.to_string()))?;
    let compared = compare_intent_to_project(&ProjectIntent::empty(), &discovery);

    let mut statements = vec![
        format!(
            "`sure_core::pipeline::Pipeline{{ .., goal: None, store: None }}` compared the project \
             against `ProjectIntent::empty()`: {} requirement(s) checked, {} matched, {} unmatched, {} \
             finding(s) — the comparison's own limitation sentence is: \"{}\"",
            compared.user_requirements_checked,
            compared.matched.len(),
            compared.unmatched.len(),
            compared.findings.len(),
            compared.limitation.unwrap_or("none")
        ),
        format!(
            "the run's verdict says the report must carry the caveat: {}; the caveat it carries is: {}",
            record.verdict.must_caveat_requirements(),
            record
                .intent_caveat
                .map_or_else(|| String::from("none"), |caveat| format!("\"{caveat}\""))
        ),
        format!(
            "`ProjectVerdict::is_ready_for_hand_off()` is {}, and the summary a person reads is {} line(s)",
            record.verdict.is_ready_for_hand_off(),
            render_summary(&record.verdict).lines().count()
        ),
        fulfilment_sweep_statement(),
    ];

    let held = record.intent == ProjectIntent::empty()
        && record.verdict.must_caveat_requirements()
        && record.intent_caveat.is_some()
        && !record.verdict.is_ready_for_hand_off()
        && !may_claim_full_fulfilment(&ProjectIntent::empty(), 0)
        && !may_claim_full_fulfilment(&ProjectIntent::empty(), 4096)
        && !may_claim_full_fulfilment(&ProjectIntent::empty(), usize::MAX);

    // The weight the comparison puts on what it found, read off its own
    // proposals rather than out of the manifest.
    let heaviest = compared
        .findings
        .iter()
        .map(CheckProposal::severity)
        .max_by_key(|severity| severity.rank());
    statements.push(format!(
        "the comparison's own proposals carry the heaviest severity `{}`, which is the weight this \
         report records for the case rather than the manifest's `expected_severity`",
        heaviest.map_or("nothing", Severity::as_str)
    ));

    Ok(Measurement::Outcome {
        held,
        severity: heaviest,
        reading: Reading {
            statements,
            surfaces: vec![
                "sure_core::pipeline::Pipeline::run".to_owned(),
                "sure_core::intent::may_claim_full_fulfilment".to_owned(),
                "sure_core::project_verdict::render_summary".to_owned(),
            ],
            anchors: vec![RowAnchor {
                subject: AnchorSubject::Directory.as_str().to_owned(),
                location: format!("{FIXTURES_PATH}/{id}"),
                locator: String::from("the fixture project the run read"),
            }],
            rule: String::from(
                "with no request there is nothing to compare against, so SURE may claim nothing about \
                 fulfilment — the case is met when the intent is empty, the verdict demands the caveat, \
                 the caveat is present, the verdict does not permit hand-off, and the fulfilment gate \
                 answers false at every evidence count it is asked about",
            ),
        },
    })
}

/// The scratch configuration root one drive is given, under the repository's
/// own `target/tmp`.
///
/// # Where it is
///
/// `<repository_root>/target/tmp/acceptance report configuration/<id>`, holding
/// the `data` and `config` roots the case hands to [`Paths::from_roots`].
/// `target/tmp` is the repository's scratch directory: git-ignored, and on the
/// same volume as the checkout. It is built with [`PathBuf::join`] and never by
/// assembling a string, and one of its components has spaces in it on purpose,
/// which is the same path pressure `target/tmp` already carries. The machine's
/// own configuration directory — `Paths::discover`'s answer, the file a person's
/// own `sure.yaml` lives in — is never read and never written by this module.
///
/// # Why it is not inside the fixture, which is where it was
///
/// This directory used to be `fixtures_root/<id>/target/tmp/…`, inside the
/// fixture the case measures, and that was a defect rather than a preference:
///
/// - **The fixture is shipped bytes.** The discipline this repository states for
///   its fixtures is `crates/sure-core/tests/repair_fixture_e2e.rs`'s — *"It does
///   not run the shipped directory, and it does not write to it: every run
///   happens on a copy under `target/tmp`."* This module wrote to it.
/// - **The residue was invisible and is not ignored.** Nothing under
///   `fixtures/` carries a `.gitignore`, and the repository root's `/target/`
///   entry is anchored, so it does not reach a `target/` inside a fixture. What
///   kept the directories out of `git status` was that they were *empty*: git
///   tracks files and describes a directory through them, so a directory holding
///   no file reads as nothing at every verbosity, while one holding a file reads
///   as `?? dir/` or, under `--untracked-files=all`, as the files inside it.
///   Nothing was ever written into these, so no reading of `git status` had
///   anything to report and no `.gitignore` entry was doing any work.
/// - **The case stopped measuring the same thing twice.** The directory the
///   drive made was inside the project the drive then read, so the second run
///   over that fixture measured a project the first run had changed.
///
/// # Why the root comes from the argument rather than from `env!`
///
/// `crates/sure-core/src/store/mod.rs`'s `scratch_root` reaches this same
/// `target/tmp` from `env!("CARGO_MANIFEST_DIR")` "rather than the working
/// directory, so a test gives the same answer wherever it was started from".
/// That answer is about *one* checkout — the one the crate was compiled in — and
/// it is test-only (`#[cfg(test)] pub(crate)`), which this module is not: it is
/// shipped code, and the shipped library may not name test infrastructure or
/// bake the path of the machine it was built on into a binary that ships to
/// someone else. This module is handed the tree it is measuring, so it takes the
/// scratch directory of *that* tree. Nothing is duplicated from the test helper;
/// the derivation is not the helper, the argument is.
///
/// # Why the name carries no process id, though two precedents' do
///
/// `store/mod.rs`'s `scratch_root` and the test-module `scratch` helpers beside
/// it put the process id in the name, and their reason is written out where they
/// are: a name another process cannot compute is a name another process cannot
/// delete, so freshness does not depend on a deletion succeeding on Windows.
/// That reason is about a directory that is **written to and cleared**. Nothing
/// here writes and nothing here clears — the two roots are made and then read,
/// and the one file read out of them is one that does not exist — so a process
/// id would buy protection against a writer there is none of, at the price of a
/// directory per run under `target/tmp`, which is residue of the family this
/// change exists to stop producing. Two processes driving this recipe at the
/// same time therefore converge on these two directories rather than racing over
/// them: `create_dir_all` is idempotent, and no step here removes what another
/// step is reading.
///
/// # Why nothing is cleared before use, and what is measured instead
///
/// `crates/sure-core/tests/doctor.rs` clears its scratch path before using it,
/// and its own header records that the concurrency mechanism that clear rests on
/// *"was not confirmed"* — so a clear here would be an unconfirmed mechanism
/// guarding against a writer that does not exist. What would matter if these
/// roots were not empty is not staleness but the measurement, and the caller
/// measures it: see the emptiness check in [`execution_refusal`].
fn scratch_for(repository_root: &Path, id: &str) -> PathBuf {
    repository_root
        .join("target")
        .join("tmp")
        .join("acceptance report configuration")
        .join(id)
}

/// The fixture project, through the pipeline under the authority its own
/// configuration resolves to.
fn execution_refusal(
    repository_root: &Path,
    fixtures_root: &Path,
    id: &str,
) -> Result<Measurement, CorpusError> {
    let root = fixtures_root.join(id);
    // A configuration root under the repository's own scratch directory, which
    // is created here and never in the machine's own configuration directory.
    // `Paths::from_roots` validates both roots and creates neither, so this
    // module has to make them — and it makes them empty: the file that asks for
    // more is the fixture's own `sure.yaml`, which is what the case is about.
    // `scratch_for` says where the directory is and why it is there rather than
    // inside the fixture.
    let scratch = scratch_for(repository_root, id);
    let data = scratch.join("data");
    let configuration = scratch.join("config");
    for directory in [&data, &configuration] {
        std::fs::create_dir_all(directory)
            .map_err(|error| unreadable(directory, error.to_string()))?;
        // Made, and then read rather than assumed empty. Nothing in this module
        // writes here, so a file in either root is not this report's doing and
        // is not a condition to carry on through: a settings file in the
        // configuration root is a second asker beside the fixture's own, and
        // `Authority::load` below would resolve an authority this case is not
        // about. A case that cannot say which authority it measured is a case
        // that has stopped measuring the fixture's own `sure.yaml`.
        if let Some(entry) = std::fs::read_dir(directory)
            .map_err(|error| unreadable(directory, error.to_string()))?
            .next()
        {
            let entry = entry
                .map_err(|error| unreadable(directory, error.to_string()))?
                .file_name();
            return Err(CorpusError::Malformed {
                path: directory.display().to_string(),
                message: format!(
                    "this case's configuration root holds `{}` before the drive begins, and every \
                     file in it changes the authority the case resolves to. Nothing in this report \
                     writes here, so the directory is not this run's, and the drive is refused \
                     rather than run under an authority nobody chose",
                    entry.to_string_lossy()
                ),
            });
        }
    }
    let paths = Paths::from_roots(data, configuration)
        .map_err(|error| unreadable(&scratch, error.to_string()))?;
    let authority = Authority::load(&root, &paths.user_config_file())
        .map_err(|error| unreadable(&root, error.to_string()))?;

    let config = Config::default();
    // The same runner as `intent`'s, and for the same reason: the authority here
    // is the fixture's own, and a fixture that asked for its code to be run must
    // still not be run by a report about it.
    let runner = nothing_starts();
    let outcome = Pipeline {
        project: &root,
        purpose: crate::pipeline::Purpose::Check,
        config: &config,
        execution: authority.execution(),
        store: None,
        goal: None,
        analysis: Default::default(),
        runner: &runner,
    }
    .run();
    let Some(record) = outcome.run.as_ref() else {
        return Ok(Measurement::CannotConfirm {
            axis: Axis::Outcome,
            statements: vec![format!(
                "the pipeline ran over `{FIXTURES_PATH}/{id}` and stopped at {} rather than reaching a \
                 report, so there is no record to read and nothing to say about the refusal",
                outcome.stopped_at.map_or_else(
                    || String::from("no stage it named"),
                    |stage| format!("{stage:?}")
                )
            )],
            missing: format!(
                "the pipeline did not finish over this fixture: it stopped at {}",
                outcome.stopped_at.map_or_else(
                    || String::from("no stage it named"),
                    |stage| format!("{stage:?}")
                )
            ),
            would_require: String::from(
                "a fixture the pipeline can read to the end, which is what every other case in this \
                 manifest drives",
            ),
        });
    };

    let refusals: Vec<&CheckResult> = record
        .report
        .results()
        .iter()
        .filter(|result| {
            result.not_checked_reason == Some(NotCheckedReason::ExecutionNotAuthorized)
        })
        .collect();
    let planned = record.schedule.checks().len();
    let allowed = record.schedule.may_run().count();
    let mut statements = vec![
        format!(
            "the fixture's own `sure.yaml` asks for execution and cannot grant it, so the authority \
             resolves to mode `{}` with `run_project_code` {}",
            execution_mode_name(record.mode),
            record.permissions.run_project_code
        ),
        format!(
            "the plan holds {planned} check(s) and {allowed} of them may run under those settings; the \
             one this case is about is blocked by `{}`",
            record
                .schedule
                .checks()
                .iter()
                .find_map(|check| check.blocked_by())
                .map_or("nothing", Permission::as_str)
        ),
        format!(
            "`{}` of the {} result(s) carry `execution_not_authorized`; the sentence a person reads for \
             one is: {}",
            refusals.len(),
            record.report.results().len(),
            NotCheckedReason::ExecutionNotAuthorized.plain_explanation()
        ),
        format!(
            "`RunReport::aggregate().severity` is `{}` and the report's headline is: {}",
            record.report.aggregate().severity.as_str(),
            record.report.aggregate().headline
        ),
    ];
    let blocked_ids: Vec<String> = refusals
        .iter()
        .map(|result| result.id.as_str().to_owned())
        .collect();
    statements.push(format!(
        "the refused check(s) stay in the report as rows rather than disappearing: {blocked_ids:?}"
    ));

    let mut anchors = vec![RowAnchor {
        subject: AnchorSubject::Directory.as_str().to_owned(),
        location: format!("{FIXTURES_PATH}/{id}"),
        locator: String::from("the fixture project, whose sure.yaml asks for execution"),
    }];
    anchors.sort();

    Ok(Measurement::Outcome {
        held: !refusals.is_empty()
            && allowed < planned
            && refusals
                .iter()
                .all(|result| result.status == CheckStatus::Skipped && result.critical),
        // The run's weight is an `AggregateSeverity` — `green`, `needs_attention`,
        // `not_ready`, `not_enough_checked` — which is a different vocabulary from
        // the manifest's, and mapping one onto the other here would be this
        // report inventing a value rather than measuring one. The row's rule and
        // its comparison both say so.
        severity: None,
        reading: Reading {
            statements,
            surfaces: vec![
                "sure_core::config::Authority::load".to_owned(),
                "sure_core::pipeline::Pipeline::run".to_owned(),
            ],
            anchors,
            rule: String::from(
                "a check refused for want of authorisation has to stay visible as refused — the case is \
                 met when at least one critical check is planned, denied and reported as `skipped` with \
                 `execution_not_authorized` behind it, and not when the refusal is dropped or reported \
                 as a pass",
            ),
        },
    })
}

/// The fixture's declared schedule and runs, through `aggregate_run`.
fn checker_failure(fixtures_root: &Path, id: &str) -> Result<Measurement, CorpusError> {
    let document = scenario_of(fixtures_root, id)?;
    let block = document
        .get("checker_failure")
        .ok_or_else(|| CorpusError::Malformed {
            path: format!("{FIXTURES_PATH}/{id}/scenario.json"),
            message: "it declares no `checker_failure` block".to_owned(),
        })?;
    let declared_checks = block
        .get("schedule")
        .and_then(|schedule| schedule.get("checks"))
        .and_then(Value::as_array)
        .ok_or_else(|| CorpusError::Malformed {
            path: format!("{FIXTURES_PATH}/{id}/scenario.json"),
            message: "the `schedule` block declares no `checks` array".to_owned(),
        })?;
    let runs = block
        .get("runs")
        .and_then(Value::as_object)
        .ok_or_else(|| CorpusError::Malformed {
            path: format!("{FIXTURES_PATH}/{id}/scenario.json"),
            message: "it declares no `runs` object".to_owned(),
        })?;

    let fingerprint = FingerprintId::generate();
    let mut statements: Vec<String> = Vec::new();
    let mut green_runs = 0_usize;
    let mut blocking_runs = 0_usize;
    let mut everything_that_did_not_pass_is_not_green = true;
    let mut a_missing_critical_is_a_row_with_the_product_sentence = false;

    let mut names: Vec<&String> = runs.keys().collect();
    names.sort();
    for kind in names {
        let Some(run) = runs.get(kind) else {
            continue;
        };
        let schedule = declared_schedule(id, block, declared_checks, run, kind)?;
        let results = declared_results(id, run, &schedule, &fingerprint, kind)?;
        let report = aggregate_run(&schedule, &results, &[], &fingerprint).map_err(|refused| {
            CorpusError::Malformed {
                path: format!("{FIXTURES_PATH}/{id}/scenario.json"),
                message: format!("the `{kind}` run cannot be aggregated honestly: {refused}"),
            }
        })?;

        let mut not_passing: Vec<String> = Vec::new();
        for scheduled in schedule.checks() {
            let check = scheduled.proposal();
            let result = results.iter().find(|result| result.id == *check.id());
            let passed = result.is_some_and(|result| result.status == CheckStatus::Pass);
            if !passed {
                not_passing.push(check.id().as_str().to_owned());
                if check.critical() && result.is_none() {
                    // A critical check nobody reported on. The product's whole
                    // claim is that this becomes a row and not an absence.
                    let row = report.critical().iter().find(|row| row.id() == check.id());
                    if row.is_some_and(|row| row.detail() == NOTHING_CAME_BACK) {
                        a_missing_critical_is_a_row_with_the_product_sentence = true;
                    }
                }
            }
        }
        if !not_passing.is_empty() {
            blocking_runs += 1;
            if report.is_green() {
                everything_that_did_not_pass_is_not_green = false;
            }
        } else if report.is_green() {
            green_runs += 1;
        }

        statements.push(format!(
            "run `{kind}`: the plan holds {} check(s) and the run hands back {} result(s); \
             `aggregate_run` answers severity `{}`, `is_green()` is {}, and the check(s) not passing are \
             {not_passing:?}",
            schedule.checks().len(),
            results.len(),
            report.aggregate().severity.as_str(),
            report.is_green()
        ));
    }

    let held = everything_that_did_not_pass_is_not_green
        && blocking_runs > 0
        && green_runs > 0
        && a_missing_critical_is_a_row_with_the_product_sentence;
    statements.push(format!(
        "{blocking_runs} declared run(s) have a check that did not pass and none of them is green; \
         {green_runs} declared run(s) reach `{}`, so \"a critical checker failure cannot aggregate \
         green\" is a measurement rather than a predicate nothing could satisfy; a critical check with \
         no result is a row whose detail is the product's own sentence \"{NOTHING_CAME_BACK}\": {}",
        CheckStatus::Pass.as_str(),
        a_missing_critical_is_a_row_with_the_product_sentence
    ));

    Ok(Measurement::Outcome {
        held,
        // The runs' weights are `AggregateSeverity` values, a different
        // vocabulary from the manifest's, and each declared check's own severity
        // comes out of the fixture's declaration rather than out of a product
        // computation. Neither is an observed severity for this case.
        severity: None,
        reading: Reading {
            statements,
            surfaces: vec![
                "sure_core::schedule::PlanBuilder::build".to_owned(),
                "sure_core::aggregation::aggregate_run".to_owned(),
            ],
            anchors: vec![RowAnchor {
                subject: AnchorSubject::File.as_str().to_owned(),
                location: format!("{FIXTURES_PATH}/{id}/scenario.json"),
                locator: String::from("checker_failure.schedule and checker_failure.runs"),
            }],
            rule: String::from(
                "a scheduled critical check that produced no result has to become a row rather than an \
                 absence, and no run in which a check did not pass may aggregate green — measured \
                 against a control run that does reach green, so the claim is not vacuous",
            ),
        },
    })
}

/// The fixture's declared tool-call runs, through `hook_protection`.
fn action(fixtures_root: &Path, id: &str, danger: Danger) -> Result<Measurement, CorpusError> {
    let document = scenario_of(fixtures_root, id)?;
    let block = document
        .get("dangerous_action")
        .ok_or_else(|| CorpusError::Malformed {
            path: format!("{FIXTURES_PATH}/{id}/scenario.json"),
            message: "it declares no `dangerous_action` block".to_owned(),
        })?;
    let modes = block
        .get("settings")
        .and_then(|settings| settings.get("modes"))
        .ok_or_else(|| CorpusError::Malformed {
            path: format!("{FIXTURES_PATH}/{id}/scenario.json"),
            message: "it declares no `settings.modes`".to_owned(),
        })?;
    let runs = block
        .get("runs")
        .and_then(Value::as_object)
        .ok_or_else(|| CorpusError::Malformed {
            path: format!("{FIXTURES_PATH}/{id}/scenario.json"),
            message: "it declares no `runs` object".to_owned(),
        })?;

    let mut statements: Vec<String> = Vec::new();
    let mut named_and_blocked = false;
    let mut names: Vec<&String> = runs.keys().collect();
    names.sort();
    for kind in names {
        let Some(run) = runs.get(kind) else {
            continue;
        };
        let mode_name = required_string(run, "mode", id)?;
        let declared = modes
            .get(&mode_name)
            .ok_or_else(|| CorpusError::Malformed {
                path: format!("{FIXTURES_PATH}/{id}/scenario.json"),
                message: format!(
                    "the `{kind}` run names the mode `{mode_name}` and no such mode is declared"
                ),
            })?;
        let (mode, permissions) = declared_mode(id, &mode_name, declared)?;
        let protection = required_string(run, "protection", id)?;
        let protection: crate::config::ProtectionMode = serde_json::from_value(Value::String(
            protection,
        ))
        .map_err(|error| CorpusError::Malformed {
            path: format!("{FIXTURES_PATH}/{id}/scenario.json"),
            message: format!(
                "the `{kind}` run declares a protection mode this build does not know: {error}"
            ),
        })?;
        let harness = required_string(run, "harness", id)?;
        let tool = required_string(run, "tool", id)?;
        let path = run.get("path").and_then(Value::as_str);
        let command = run.get("command").and_then(Value::as_str);
        let request = ToolRequest {
            tool: &tool,
            path,
            command,
        };
        let assessment = match harness.as_str() {
            "claude_code" => assess_claude_code_tool(&request, mode, &permissions, protection),
            "cursor" => assess_cursor_tool(&request, mode, &permissions, protection),
            other => {
                return Err(CorpusError::Malformed {
                    path: format!("{FIXTURES_PATH}/{id}/scenario.json"),
                    message: format!(
                        "the `{kind}` run names the harness `{other}`, and this tree has two \
                         integrations: `claude_code` and `cursor`"
                    ),
                });
            }
        };
        let decision = assessment.decision.decision;
        statements.push(format!(
            "run `{kind}`: the harness is `{harness}`, the mode is `{mode_name}`, the protection mode is \
             `{}`, and the request is {}. `{}` answers decision `{}`{}",
            protection_name(protection),
            describe_request(&request),
            if harness == "claude_code" {
                "assess_claude_code_tool"
            } else {
                "assess_cursor_tool"
            },
            decision.as_str(),
            match assessment.danger {
                Some(found) => format!(" naming the danger `{}`", found.wire_name()),
                None => String::from(" naming no danger"),
            }
        ));
        if assessment.danger == Some(danger) && decision == ProtectionDecisionKind::Block {
            named_and_blocked = true;
        }
    }

    statements.push(format!(
        "the danger this case is about is `{}`, and the sentence the product holds it with is: \"{}\"",
        danger.wire_name(),
        danger_reason(danger)
    ));

    Ok(Measurement::Outcome {
        held: named_and_blocked,
        // A protection decision is `allow`, `warn` or `block` with a danger
        // named beside it; `hook_protection` carries no severity at all, so
        // there is none to record and the row says so in its comparison.
        severity: None,
        reading: Reading {
            statements,
            surfaces: vec![
                "sure_core::hook_protection::assess_claude_code_tool".to_owned(),
                "sure_core::hook_protection::assess_cursor_tool".to_owned(),
            ],
            anchors: vec![RowAnchor {
                subject: AnchorSubject::File.as_str().to_owned(),
                location: format!("{FIXTURES_PATH}/{id}/scenario.json"),
                locator: String::from("dangerous_action.runs"),
            }],
            rule: format!(
                "the request this case is about has to be named as `{}` and held rather than allowed — a \
                 build that blocked it for some other reason, or that named no danger while blocking it, \
                 would not be the protection this case is about",
                danger.wire_name()
            ),
        },
    })
}

/// A case the manifest has and the corpus ships a declaration for, with nothing
/// to observe.
fn declaration_only(fixtures_root: &Path, id: &str) -> Measurement {
    let directory = fixtures_root.join(id);
    let files = directory_files(&directory);
    let mut statements = vec![
        format!(
            "`{FIXTURES_PATH}/{id}` holds {} file(s): {}",
            files.len(),
            if files.is_empty() {
                String::from("none")
            } else {
                files.join(", ")
            }
        ),
        String::from(
            "the declaration names no project — there is nothing in the directory to read, run or \
             compare — so the recipe table has no observation for this case and the row says so rather \
             than restating the manifest",
        ),
    ];
    statements.sort();
    Measurement::CannotConfirm {
        axis: Axis::Severity,
        statements,
        missing: format!(
            "nothing callable observes `{id}`: the corpus ships `{FIXTURES_PATH}/{id}/scenario.json` and \
             no project beside it, and this build has no module that reads the case"
        ),
        would_require: "a fixture that ships the project the case is about, and a module that observes \
             it — the shape `missing-migration` and `dynamic-not-authorized` already have. Until then \
             this case is `cannot_confirm` in the release report, and P14-T012's false-green rate \
             cannot cover it"
            .to_owned(),
    }
}

/// The case no `src` module can observe, with the rule that makes it so.
fn needs_a_process_runner() -> Measurement {
    Measurement::CannotConfirm {
        axis: Axis::Outcome,
        statements: vec![String::from(
            "the row's `surfaces` are empty here and non-empty when the runner supplies the measurement: \
             `crates/sure-core/tests/acceptance_report_runner.rs` is the surface that observes this case, \
             and a row that names it is a row that ran the fixture's two node checks",
        )],
        missing: String::from(
            "observing this case means starting the fixture's two node checks through \
             `sure_core::process`, and this report is produced by `crates/sure-core/src/acceptance_report.rs`. \
             That file is not on the route the product runs checks on — `sure_core::pipeline` into \
             `sure_core::planned_check_runner`, which runs the work a check's schedule holds — and \
             `crates/sure-core/tests/spawn_sites.rs`'s rule two forbids any file under `crates/**/src/**` \
             outside the list that file holds from naming the type the runner is handed. Putting that \
             observation here would mean editing that list — and editing it to make a report green is the \
             change it exists to make visible.",
        ),
        would_require: String::from(
            "the caller supplies the measurement through `sure_core::acceptance_report::acceptance_report_with`. \
             `crates/sure-core/tests/acceptance_report_runner.rs` is the caller that does: it copies the \
             fixture under `target/tmp`, runs both members' checks with `sure_core::process`, drives the \
             repair lifecycle, and supplies the result — and this row's `surfaces` name that file, so a \
             reader can see which of the two produced the row",
        ),
    }
}

// --- helpers --------------------------------------------------------------

/// Every file under a directory, relative to it, with forward slashes, sorted.
fn directory_files(directory: &Path) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    let mut stack: Vec<PathBuf> = vec![directory.to_path_buf()];
    while let Some(current) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&current) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            let relative = path
                .strip_prefix(directory)
                .unwrap_or(&path)
                .to_string_lossy()
                .replace('\\', "/");
            found.push(relative);
        }
    }
    found.sort();
    found
}

/// A fixture file's contents, as JSON.
fn scenario_of(fixtures_root: &Path, id: &str) -> Result<Value, CorpusError> {
    let relative = format!("{FIXTURES_PATH}/{id}/scenario.json");
    let path = fixtures_root.join(id).join("scenario.json");
    let text = read_to_string(&path)?;
    serde_json::from_str(&text).map_err(|error| CorpusError::Malformed {
        path: relative,
        message: error.to_string(),
    })
}

/// A string a fixture declares, with the fixture named when it does not.
fn required_string(value: &Value, key: &str, id: &str) -> Result<String, CorpusError> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| CorpusError::Malformed {
            path: format!("{FIXTURES_PATH}/{id}/scenario.json"),
            message: format!("a declaration has no string `{key}`"),
        })
}

/// The JSON document a harness would send for one declared claim.
fn claim_document(
    id: &str,
    claim_id: &str,
    claim_text: &str,
    claim_type: &str,
    timestamp: &str,
) -> String {
    let _ = id;
    serde_json::json!({
        "schema_version": crate::PROTOCOL_VERSION,
        "source": "claude-code",
        "event_type": AGENT_CLAIM_EVENT_TYPE,
        "timestamp": timestamp,
        "capability_tier": CapabilityTier::Observed.number(),
        "session_id": "session-1",
        "project_root": CLAIM_PROJECT_ROOT,
        "payload": {
            "id": claim_id,
            "claim_text": claim_text,
            "claim_type": claim_type,
        },
    })
    .to_string()
}

/// Ingest one wire document, with the fixture named when SURE refuses it.
fn ingest(id: &str, document: &str) -> Result<IngestedEvent, CorpusError> {
    ingest_event_str(document).map_err(|error| CorpusError::Malformed {
        path: format!("{FIXTURES_PATH}/{id}/scenario.json"),
        message: format!("SURE refuses a declared document: {error}"),
    })
}

/// An anchor on a file of this corpus, as a path relative to the repository
/// root and with forward slashes.
fn fixture_anchor(
    repository_root: &Path,
    _fixtures_root: &Path,
    id: &str,
    location: &str,
    locator: &str,
) -> RowAnchor {
    let normalized = location.replace('\\', "/");
    let root = repository_root.display().to_string().replace('\\', "/");
    let without_root = if root.is_empty() {
        normalized.as_str()
    } else {
        normalized.strip_prefix(&root).unwrap_or(&normalized)
    }
    .trim_start_matches('/');
    let path = if without_root.starts_with("fixtures/") {
        without_root.to_owned()
    } else {
        format!(
            "{FIXTURES_PATH}/{id}/{}",
            without_root.trim_start_matches("./")
        )
    };
    RowAnchor {
        subject: AnchorSubject::File.as_str().to_owned(),
        location: path,
        locator: locator.to_owned(),
    }
}

/// How many migrations a `Record` holds, in words.
fn record_name(record: crate::db_migrations::Record) -> String {
    match record {
        crate::db_migrations::Record::Empty => String::from("a location with no migration in it"),
        crate::db_migrations::Record::Absent => {
            String::from("a location the project does not have")
        }
        crate::db_migrations::Record::Holds(count) => {
            format!("a location holding {count} migration(s)")
        }
    }
}

/// The strongest evidence class first, so "the strongest among them" means
/// something.
fn class_rank(class: EvidenceClass) -> u8 {
    match class {
        EvidenceClass::ObservedFact => 0,
        EvidenceClass::DeterministicCheck => 1,
        EvidenceClass::ModelAssessment => 2,
        EvidenceClass::Inference => 3,
        EvidenceClass::Unknown => 4,
    }
}

/// An execution mode's wire name.
fn execution_mode_name(mode: ExecutionMode) -> &'static str {
    match mode {
        ExecutionMode::InspectOnly => "inspect_only",
        ExecutionMode::HostConfirmed => "host_confirmed",
        _ => "another mode this report does not name",
    }
}

/// A protection mode's wire name.
fn protection_name(mode: crate::config::ProtectionMode) -> &'static str {
    match mode {
        crate::config::ProtectionMode::Standard => "standard",
        crate::config::ProtectionMode::Strict => "strict",
        _ => "another mode this report does not name",
    }
}

/// One tool request, as a sentence.
fn describe_request(request: &ToolRequest<'_>) -> String {
    match (request.path, request.command) {
        (Some(path), None) => format!("`{}` on `{path}`", request.tool),
        (None, Some(command)) => format!("`{}` running `{command}`", request.tool),
        (Some(path), Some(command)) => {
            format!("`{}` running `{command}` against `{path}`", request.tool)
        }
        (None, None) => format!("`{}` with no path and no command", request.tool),
    }
}

/// The statement about the fulfilment gate, swept rather than spot-checked.
fn fulfilment_sweep_statement() -> String {
    let intent = ProjectIntent::empty();
    let refused = [0_usize, 1, 4096, usize::MAX]
        .into_iter()
        .filter(|count| !may_claim_full_fulfilment(&intent, *count))
        .count();
    format!(
        "`sure_core::intent::may_claim_full_fulfilment` answers false for an empty intent at {refused} of \
         the 4 counts it was swept over, including `usize::MAX`, so no amount of evidence can make this \
         project claimable"
    )
}

/// A mode and the permission set a fixture declares for it, with every
/// permission read and none defaulted.
fn declared_mode(
    id: &str,
    mode_name: &str,
    declared: &Value,
) -> Result<(ExecutionMode, ExecutionPermissions), CorpusError> {
    let mode: ExecutionMode = serde_json::from_value(declared.get("mode").cloned().ok_or_else(
        || CorpusError::Malformed {
            path: format!("{FIXTURES_PATH}/{id}/scenario.json"),
            message: format!("the mode `{mode_name}` declares no execution mode"),
        },
    )?)
    .map_err(|error| CorpusError::Malformed {
        path: format!("{FIXTURES_PATH}/{id}/scenario.json"),
        message: format!(
            "the mode `{mode_name}` declares an execution mode this build does not know: {error}"
        ),
    })?;
    let permissions = declared
        .get("permissions")
        .and_then(Value::as_object)
        .ok_or_else(|| CorpusError::Malformed {
            path: format!("{FIXTURES_PATH}/{id}/scenario.json"),
            message: format!("the mode `{mode_name}` declares no permission set"),
        })?;
    if permissions.len() != Permission::ALL.len() {
        return Err(CorpusError::Malformed {
            path: format!("{FIXTURES_PATH}/{id}/scenario.json"),
            message: format!(
                "the mode `{mode_name}` declares {} permission(s) and there are {}, so one of them is \
                 neither granted nor withheld and a reader of it would be guessing",
                permissions.len(),
                Permission::ALL.len()
            ),
        });
    }
    let mut granted = ExecutionPermissions::inspect_only();
    for permission in Permission::ALL {
        let name = permission.as_str();
        let allowed = permissions
            .get(name)
            .and_then(Value::as_bool)
            .ok_or_else(|| CorpusError::Malformed {
                path: format!("{FIXTURES_PATH}/{id}/scenario.json"),
                message: format!("the mode `{mode_name}` does not say whether `{name}` is granted"),
            })?;
        granted.set(*permission, allowed);
    }
    Ok((mode, granted))
}

/// One run's schedule, built by the product's own plan builder.
fn declared_schedule(
    id: &str,
    block: &Value,
    declared_checks: &[Value],
    run: &Value,
    what: &str,
) -> Result<CheckSchedule, CorpusError> {
    let mode_name = required_string(run, "mode", id)?;
    let modes = block
        .get("schedule")
        .and_then(|schedule| schedule.get("modes"))
        .ok_or_else(|| CorpusError::Malformed {
            path: format!("{FIXTURES_PATH}/{id}/scenario.json"),
            message: String::from("the `schedule` block declares no `modes`"),
        })?;
    let declared = modes
        .get(&mode_name)
        .ok_or_else(|| CorpusError::Malformed {
            path: format!("{FIXTURES_PATH}/{id}/scenario.json"),
            message: format!(
                "the `{what}` run names the mode `{mode_name}` and no such mode is declared"
            ),
        })?;
    let (mode, permissions) = declared_mode(id, &mode_name, declared)?;

    let wanted = run
        .get("schedule")
        .and_then(Value::as_array)
        .ok_or_else(|| CorpusError::Malformed {
            path: format!("{FIXTURES_PATH}/{id}/scenario.json"),
            message: format!("the `{what}` run declares no `schedule` list"),
        })?;

    let mut builder = PlanBuilder::new(mode, permissions);
    for id_of_check in wanted {
        let name = id_of_check.as_str().ok_or_else(|| CorpusError::Malformed {
            path: format!("{FIXTURES_PATH}/{id}/scenario.json"),
            message: format!("the `{what}` run schedules a check that is not a string"),
        })?;
        let check = declared_checks
            .iter()
            .find(|check| check.get("id").and_then(Value::as_str) == Some(name))
            .ok_or_else(|| CorpusError::Malformed {
                path: format!("{FIXTURES_PATH}/{id}/scenario.json"),
                message: format!(
                    "the `{what}` run schedules `{name}` and no such check is declared"
                ),
            })?;
        // **The observation is the one a corpus check can honestly make, which is
        // that nothing here observed anything.** A fixture's `scenario.json`
        // declares the check and declares the result it must produce, and the
        // reader of this file establishes only that the two agree — so the value
        // is a candidate that claims neither a pass nor a defect and starts no
        // process, and the sentence says which declaration it came from. It is
        // not a `CouldNotRun`: the file that was needed is the one being read.
        let observation = PrecomputedEvidence::candidate(format!(
            "Nothing has settled it: the `{what}` run's schedule in {id}'s \
             scenario.json declares this check, and no part of the project was \
             read for it."
        ));
        let work = PlannedWork::new(
            declared_proposal(id, check)?,
            CheckOperation::Precomputed(observation),
        );
        builder
            .propose(work)
            .map_err(|refused| CorpusError::Malformed {
                path: format!("{FIXTURES_PATH}/{id}/scenario.json"),
                message: format!(
                    "the plan builder refused `{name}` for the `{what}` run: {refused}"
                ),
            })?;
    }
    if !builder.refused().is_empty() {
        return Err(CorpusError::Malformed {
            path: format!("{FIXTURES_PATH}/{id}/scenario.json"),
            message: format!("the `{what}` run's plan holds refusals nobody noticed"),
        });
    }
    Ok(builder.build())
}

/// One declared check, as the proposal the plan builder is handed.
fn declared_proposal(id: &str, check: &Value) -> Result<CheckProposal, CorpusError> {
    let declared_id = required_string(check, "id", id)?;
    let check_id = CheckId::parse(&declared_id).map_err(|error| CorpusError::Malformed {
        path: format!("{FIXTURES_PATH}/{id}/scenario.json"),
        message: format!("`{declared_id}` is not a well-formed check id: {error}"),
    })?;
    let severity = from_wire(id, "a check severity", check.get("severity"))?;
    let evidence = from_wire(id, "an evidence class", check.get("evidence_class"))?;
    let reason = match check.get("reason").and_then(Value::as_str) {
        Some("project_wide") => CheckReason::ProjectWide,
        other => {
            return Err(CorpusError::Malformed {
                path: format!("{FIXTURES_PATH}/{id}/scenario.json"),
                message: format!(
                    "a declared check gives `{other:?}` as its reason, and this report knows only \
                     `project_wide`: a check whose reason names a file, a component or a declared \
                     command would be a fact about a project, and this fixture ships none"
                ),
            });
        }
    };
    let actions = check
        .get("actions")
        .and_then(Value::as_array)
        .ok_or_else(|| CorpusError::Malformed {
            path: format!("{FIXTURES_PATH}/{id}/scenario.json"),
            message: String::from(
                "a declared check takes no actions, and the plan builder refuses such a check",
            ),
        })?;
    let mut kinds: Vec<ActionKind> = Vec::with_capacity(actions.len());
    for action in actions {
        kinds.push(from_wire(id, "an action", Some(action))?);
    }
    Ok(CheckProposal::new(
        check_id,
        required_string(check, "title", id)?,
        severity,
        check
            .get("critical")
            .and_then(Value::as_bool)
            .ok_or_else(|| CorpusError::Malformed {
                path: format!("{FIXTURES_PATH}/{id}/scenario.json"),
                message: String::from("a declared check does not say whether it is critical"),
            })?,
        evidence,
        reason,
        &kinds,
    ))
}

/// A value a fixture declares by its wire name, read as the product's own type.
fn from_wire<T: serde::de::DeserializeOwned>(
    id: &str,
    what: &str,
    value: Option<&Value>,
) -> Result<T, CorpusError> {
    let value = value.ok_or_else(|| CorpusError::Malformed {
        path: format!("{FIXTURES_PATH}/{id}/scenario.json"),
        message: format!("a declared check has no {what}"),
    })?;
    serde_json::from_value(value.clone()).map_err(|error| CorpusError::Malformed {
        path: format!("{FIXTURES_PATH}/{id}/scenario.json"),
        message: format!("a declared check gives {what} as {value}, and that is not one: {error}"),
    })
}

/// The results one run declares it handed back, as the product's own values.
fn declared_results(
    id: &str,
    run: &Value,
    schedule: &CheckSchedule,
    fingerprint: &FingerprintId,
    what: &str,
) -> Result<Vec<CheckResult>, CorpusError> {
    let declared = run
        .get("results")
        .and_then(Value::as_array)
        .ok_or_else(|| CorpusError::Malformed {
            path: format!("{FIXTURES_PATH}/{id}/scenario.json"),
            message: format!("the `{what}` run declares no `results` list"),
        })?;

    let mut results: Vec<CheckResult> = Vec::with_capacity(declared.len());
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for result in declared {
        let of = required_string(result, "of", id)?;
        if !seen.insert(of.clone()) {
            return Err(CorpusError::Malformed {
                path: format!("{FIXTURES_PATH}/{id}/scenario.json"),
                message: format!(
                    "the `{what}` run hands back two results for `{of}`, and `aggregate_run` refuses \
                     that rather than choosing between them"
                ),
            });
        }
        let check_id = CheckId::parse(&of).map_err(|error| CorpusError::Malformed {
            path: format!("{FIXTURES_PATH}/{id}/scenario.json"),
            message: format!("a declared result names `{of}`: {error}"),
        })?;
        let scheduled = schedule.get(&check_id).ok_or_else(|| CorpusError::Malformed {
            path: format!("{FIXTURES_PATH}/{id}/scenario.json"),
            message: format!(
                "the `{what}` run hands back a result for `{of}` and its plan schedules no such check"
            ),
        })?;
        let proposal = scheduled.proposal();
        let status: CheckStatus = from_wire(id, "a check status", result.get("status"))?;
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
                required_string(result, "detail", id)?,
                fingerprint.clone(),
            ),
            CheckStatus::Skipped => CheckResult::not_run(
                check_id,
                title,
                severity,
                critical,
                from_wire(id, "a not-checked reason", result.get("reason"))?,
                fingerprint.clone(),
            ),
            other => {
                return Err(CorpusError::Malformed {
                    path: format!("{FIXTURES_PATH}/{id}/scenario.json"),
                    message: format!(
                        "the `{what}` run declares a result with status `{}`, and this report builds \
                         only the three the product has a constructor for",
                        other.as_str()
                    ),
                });
            }
        };
        results.push(built);
    }
    Ok(results)
}

/// Every corpus directory that answers to no case.
///
/// The reasons are the ones in `fixture_apps.rs`; the *set* is measured against
/// the disk and against the manifest rather than trusted, so a directory added
/// to the corpus without a case or a reason is an error here rather than a
/// silence.
fn fixtures_without_a_case(
    repository_root: &Path,
    rows: &[CaseRow],
) -> Result<Vec<UncontractedFixture>, CorpusError> {
    let fixtures_root = repository_root.join(FIXTURES_PATH);
    let entries = std::fs::read_dir(&fixtures_root)
        .map_err(|error| unreadable(&fixtures_root, error.to_string()))?;
    let mut directories: Vec<String> = Vec::new();
    for entry in entries.flatten() {
        if entry.path().is_dir() {
            directories.push(entry.file_name().to_string_lossy().to_string());
        }
    }
    directories.sort();

    let contracted: BTreeSet<&str> = rows.iter().map(|row| row.id.as_str()).collect();
    let mut found: Vec<UncontractedFixture> = Vec::new();
    for directory in &directories {
        if contracted.contains(directory.as_str()) {
            continue;
        }
        let reason = OUT_OF_CONTRACT
            .iter()
            .find(|(id, _)| id == directory)
            .map(|(_, reason)| (*reason).to_owned())
            .ok_or_else(|| CorpusError::Malformed {
                path: format!("{FIXTURES_PATH}/{directory}"),
                message: String::from(
                    "this directory answers to no case in the manifest and no reason is written for it \
                     anywhere this report can read — which is the silence this report exists to prevent",
                ),
            })?;
        found.push(UncontractedFixture {
            id: directory.clone(),
            reason,
        });
    }

    // The other direction: a reason written for a directory the corpus does not
    // ship is a name that has drifted.
    for (id, _) in OUT_OF_CONTRACT {
        if !directories.iter().any(|directory| directory == id) {
            return Err(CorpusError::Malformed {
                path: format!("{FIXTURES_PATH}/{id}"),
                message: String::from(
                    "a reason is written for this directory and the corpus ships no such directory",
                ),
            });
        }
    }
    Ok(found)
}

/// Counts over the rows.
fn totals_of(rows: &[CaseRow]) -> Totals {
    let count = |wanted: Agreement| rows.iter().filter(|row| row.agreement == wanted).count();
    let blocking: Vec<&CaseRow> = rows.iter().filter(|row| row.release_blocking).collect();
    Totals {
        cases: rows.len(),
        release_blocking: blocking.len(),
        observed: rows
            .iter()
            .filter(|row| matches!(row.observed, Observation::Observed { .. }))
            .count(),
        cannot_confirm: count(Agreement::CannotConfirm),
        met: count(Agreement::Met),
        unmet: count(Agreement::Unmet),
        release_blocking_observed: blocking
            .iter()
            .filter(|row| matches!(row.observed, Observation::Observed { .. }))
            .count(),
        release_blocking_met: blocking
            .iter()
            .filter(|row| row.agreement == Agreement::Met)
            .count(),
        release_blocking_unmet: blocking
            .iter()
            .filter(|row| row.agreement == Agreement::Unmet)
            .count(),
        release_blocking_cannot_confirm: blocking
            .iter()
            .filter(|row| row.agreement == Agreement::CannotConfirm)
            .count(),
    }
}

/// Read a file, with the failure named rather than panicked.
fn read_to_string(path: &Path) -> Result<String, CorpusError> {
    std::fs::read_to_string(path).map_err(|error| unreadable(path, error.to_string()))
}

/// The error for a file that could not be read, with a repository-relative path
/// where one is known.
fn unreadable(path: &Path, message: String) -> CorpusError {
    CorpusError::Unreadable {
        path: path.display().to_string(),
        message,
    }
}

/// The project root the declared recordings are attributed to.
///
/// A Windows path on purpose, and the same one
/// `crates/sure-core/tests/adversarial_fixture_detection.rs` uses: the root is
/// part of what a recorded session is stored under, and the path worth
/// exercising is one with backslashes in it.
const CLAIM_PROJECT_ROOT: &str = "C:\\work\\shop";
