//! P14-T011's acceptance, measured over the real corpus.
//!
//! > *Produces machine-readable acceptance report against
//! > `evaluation/acceptance-manifest.json`.*
//!
//! and the sentence `evaluation/README.md:5` states the quality bar in:
//!
//! > *The release report must include actual observed outcome for every case.*
//!
//! # What this file is
//!
//! It is the runner §3 of the brief asks for. `sure_core::acceptance_report`
//! holds the report's shape and one recipe per case; this file drives it over
//! `evaluation/acceptance-manifest.json` and `fixtures/adversarial/`, writes the
//! document to `target/tmp/acceptance-report.json`, and asserts the properties a
//! reader has to be able to rely on without re-reading any of it.
//!
//! # The one observation this file makes and the module cannot
//!
//! `repair-regression` is measured by running the fixture's two node checks
//! against a copy of the project and driving the repair lifecycle over the
//! results — the drive `repair_fixture_e2e.rs` makes in full. A `src` module
//! cannot do it: `crates/sure-core/tests/spawn_sites.rs`'s rule two forbids any
//! file under `crates/**/src/**` outside `MAY_NAME_A_PROCESS_REQUEST` from naming
//! a `ProcessRequest`, and **that rule is the whole of the reason**. It is a rule
//! about which files may *name* a request, not about whether this build is able
//! to run one: since `P18-T007` a product path does run project code, which is
//! what `sure_core::support`'s module comment records, and the ceiling of level B
//! rests on the tracked three-platform reading, not on that path having been
//! absent (ADR 0017). A sentence here used to say the opposite — that the ceiling
//! *rests on no product path running project code* — and it was a true conclusion
//! resting on a premise that had gone; `P18-T012` corrected it. So the module reports the case
//! `cannot_confirm` with that rule written into the row, and this file measures
//! it and supplies the measurement through
//! `acceptance_report_with` — which is why the row's `surfaces` name this file
//! and not a module of the product.
//!
//! # What this file does not do
//!
//! It opens no store (`store: None` everywhere), it never writes into
//! `fixtures/` or `evaluation/`, and every copy it runs is taken under
//! `target/tmp` and removed again. `fixtures/adversarial/repair-regression` is
//! read and copied; nothing in it is modified.
//!
//! # Where the report goes
//!
//! `target/tmp/acceptance-report.json`. `.gitignore` covers `/target/`, so the
//! document is a build artefact rather than a tracked file: it is a reading of
//! this checkout on this day, and a committed one would be a document that goes
//! stale in a way nothing reddens. `cargo clean` removes it, which is the right
//! lifetime for a measurement — re-running this test regenerates it.
//!
//! # The gate written beside it
//!
//! `the_release_gate_over_this_report_permits_the_release_and_is_written_beside_it`
//! writes `target/tmp/release-gate.json` — P14-T012's document, which the P15
//! packaging tasks read — from this same report, because the gate must be taken
//! from the report the release is judged on and this is the report that carries
//! the one measurement no `src` module can make.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use sure_core::acceptance_report::{
    AcceptanceReport, Agreement, Axis, Measurement, Observation, Reading, RowAnchor,
    acceptance_report, acceptance_report_json, acceptance_report_with,
};
use sure_core::aggregation::{RunReport, aggregate_run};
use sure_core::checks::node::NodeChecks;
use sure_core::discover::node::{MANIFEST, NodeProject, ScriptRole};
use sure_core::discover::{DiscoverOptions, Ecosystem, Findings, discover};
use sure_core::fingerprint::{FingerprintOptions, content_fingerprint, project_fingerprint};
use sure_core::paths::CaseSensitivity;
use sure_core::planned_work::PlannedWork;
use sure_core::process::{
    Cancellation, Environment, Limits, Outcome, ProcessRequest, Termination, run,
};
use sure_core::project_verdict::{build_verdict, render_summary};
use sure_core::recheck_lifecycle::{LifecycleInputs, reconcile};
use sure_core::release_gate::{Decision, MetricValue, release_gate, release_gate_json};
use sure_core::repair_impact::select_impacted_checks;
use sure_core::schedule::{CheckProposal, CheckReason, CheckSchedule, PlanBuilder};
use sure_core::severity::Severity;
use sure_core::status::{AggregateSeverity, CheckResult, CheckStatus};
use sure_domain::capability::CapabilityReport;
use sure_domain::evidence::{AnchorSubject, Evidence, EvidenceAnchor, EvidenceClass};
use sure_domain::execution::{ExecutionMode, ExecutionPermissions};
use sure_domain::finding::{
    AssessmentSource, Finding, FindingBuilder, FindingStatus, SeverityRationale,
};
use sure_domain::ids::{CheckId, FindingId, FingerprintId};
use sure_domain::intent::ProjectIntent;
use sure_domain::vocabulary::RepairContract;

/// The contract this report is against, and the corpus it is produced from.
const MANIFEST_FILE: &str = "evaluation/acceptance-manifest.json";
const FIXTURES: &str = "fixtures/adversarial";

/// Where the report is written, and what its bytes are.
const REPORT: &str = "target/tmp/acceptance-report.json";

/// Where the release gate is written, and the schema it is checked against.
///
/// The gate is `sure_core::release_gate`'s document: the seven metrics
/// `docs/product/PRODUCT_EVALS.md` states, measured over this report, and the
/// decision P15's packaging tasks read. It is written here, in the same binary
/// that writes the report it is computed from, so the two cannot disagree about
/// which reading of the corpus they describe.
const GATE: &str = "target/tmp/release-gate.json";
const GATE_SCHEMA: &str = include_str!("../../../schemas/release-gate.schema.json");

/// The five corpus directories that answer to no case in the manifest.
///
/// Named here as the *measurement* `sure-testkit`'s
/// `FIXTURES_WITHOUT_A_MANIFEST_CASE` is compared against: a directory added to
/// the corpus without a case has to appear in one of these two lists or the
/// comparison below reddens, which is what stops it from being skipped into
/// invisibility.
const OUT_OF_CONTRACT: &[&str] = &[
    "container-unavailable",
    "intent-mismatch",
    "missing-config",
    "rust-tests-fail",
    "rust-tests-pass",
];

/// The one case the module cannot observe and this file can.
const REPAIR_REGRESSION: &str = "repair-regression";

/// The one case neither the module nor this file can observe.
///
/// `lying-readme`'s corpus directory holds a `scenario.json` and nothing else:
/// there is no project to read, no declaration of a recording to check and no
/// schedule to aggregate, so no call in this build observes it. It is
/// `cannot_confirm` in the report on purpose — filling it in with the manifest's
/// own `should_fix_first` would be the false green the task is built around.
const UNOBSERVABLE: &str = "lying-readme";

/// The schema the report is validated against, embedded at compile time the way
/// `crates/sure-cli/src/json_report.rs` embeds its own.
const SCHEMA: &str = include_str!("../../../schemas/acceptance-report.schema.json");

// --- the corpus, driven ---------------------------------------------------

/// The repository root, as `sure_testkit` resolves it.
fn repository_root() -> PathBuf {
    sure_testkit::repository_root()
}

/// The report over the real corpus, with `repair-regression` measured here.
///
/// Built once and shared: the drive runs the fixture's checks through `node`,
/// and a report rebuilt per test would start four processes for each of the ten
/// tests in this file. The value is the same either way — that is what
/// `two_runs_are_byte_identical` measures — so it is built once and cloned.
fn the_report() -> AcceptanceReport {
    static REPORT: std::sync::OnceLock<AcceptanceReport> = std::sync::OnceLock::new();
    REPORT
        .get_or_init(|| {
            let mut supplied: BTreeMap<String, Measurement> = BTreeMap::new();
            supplied.insert(REPAIR_REGRESSION.to_owned(), repair_regression());
            acceptance_report_with(&repository_root(), &supplied)
                .unwrap_or_else(|error| panic!("the corpus did not produce a report: {error}"))
        })
        .clone()
}

/// The report over the real corpus, with nothing supplied.
///
/// The reading the module produces on its own, which is what a caller with no
/// process runner gets — used below to show that supplying the measurement is
/// what moves the row and not something else.
fn the_module_report() -> AcceptanceReport {
    static REPORT: std::sync::OnceLock<AcceptanceReport> = std::sync::OnceLock::new();
    REPORT
        .get_or_init(|| {
            acceptance_report(&repository_root())
                .unwrap_or_else(|error| panic!("the corpus did not produce a report: {error}"))
        })
        .clone()
}

/// A row by id, with a message naming the ids when it is missing.
fn row<'a>(report: &'a AcceptanceReport, id: &str) -> &'a sure_core::acceptance_report::CaseRow {
    report
        .cases
        .iter()
        .find(|row| row.id == id)
        .unwrap_or_else(|| {
            panic!(
                "the report has no row for `{id}`; it has {:?}",
                report.cases.iter().map(|row| &row.id).collect::<Vec<_>>()
            )
        })
}

/// The observed severity of a severity-axis row, or `None` when the row carries
/// no observation at all.
fn observed_severity(row: &sure_core::acceptance_report::CaseRow) -> Option<&str> {
    match &row.observed {
        Observation::Observed { severity, .. } => severity.as_deref(),
        Observation::CannotConfirm { .. } => None,
    }
}

/// Which rule a row was graded by, whatever it carries.
trait AxisOf {
    fn observed_axis(&self) -> Axis;
}

impl AxisOf for sure_core::acceptance_report::CaseRow {
    fn observed_axis(&self) -> Axis {
        match &self.observed {
            Observation::Observed { axis, .. } | Observation::CannotConfirm { axis, .. } => *axis,
        }
    }
}

// --- the properties the report must have ----------------------------------

#[test]
fn every_manifest_case_appears_exactly_once() {
    let report = the_report();
    let manifest = read_json(&repository_root().join(MANIFEST_FILE));
    let declared: Vec<&str> = manifest["cases"]
        .as_array()
        .expect("the manifest declares a cases array")
        .iter()
        .map(|case| case["id"].as_str().expect("a case declares an id"))
        .collect();

    let reported: Vec<&str> = report.cases.iter().map(|row| row.id.as_str()).collect();
    let mut sorted = reported.clone();
    sorted.sort_unstable();
    let mut wanted = declared.clone();
    wanted.sort_unstable();
    assert_eq!(
        sorted, wanted,
        "the report's rows are the manifest's cases, exactly once each"
    );
    assert_eq!(
        report.corpus.cases,
        declared.len(),
        "the report counts its own rows"
    );
    assert_eq!(report.schema_version, 1);

    // And the release-blocking flags are the manifest's, read out of the
    // manifest rather than recomputed from a constant here.
    for row in &report.cases {
        let case = manifest["cases"]
            .as_array()
            .expect("cases")
            .iter()
            .find(|case| case["id"].as_str() == Some(row.id.as_str()))
            .expect("the row's case");
        assert_eq!(
            row.release_blocking,
            case["release_blocking"].as_bool().expect("a boolean"),
            "`{}`",
            row.id
        );
        assert_eq!(
            row.required.severity.as_str(),
            case["expected_severity"].as_str().expect("a severity"),
            "`{}`",
            row.id
        );
        assert_eq!(
            row.required.expectation,
            case["expectation"].as_str().expect("an expectation"),
            "`{}`",
            row.id
        );
    }
    assert_eq!(report.corpus.release_blocking, 13);
}

#[test]
fn the_report_is_against_the_contract_it_names() {
    let report = the_report();
    let manifest_text = std::fs::read_to_string(repository_root().join(MANIFEST_FILE))
        .expect("the manifest is readable");
    assert_eq!(report.corpus.manifest, MANIFEST_FILE);
    assert_eq!(report.corpus.fixtures, FIXTURES);
    assert_eq!(
        report.corpus.manifest_schema_version as u64,
        read_json(&repository_root().join(MANIFEST_FILE))["schema_version"]
            .as_u64()
            .expect("the manifest declares a schema version")
    );
    assert_ne!(
        report.corpus.manifest_digest, "",
        "a report with no digest is not tied to the contract it was produced against"
    );
    // The digest is over the manifest's bytes, so an edited contract makes every
    // existing report a report about a different contract. Checked by taking the
    // same bytes twice rather than by re-deriving the algorithm here.
    let again = the_report();
    assert_eq!(report.corpus.manifest_digest, again.corpus.manifest_digest);
    assert!(
        manifest_text.contains("\"schema_version\"") && !manifest_text.is_empty(),
        "the manifest read for the digest is the manifest"
    );
}

#[test]
fn every_row_carries_what_it_claims_to_carry() {
    let report = the_report();
    for row in &report.cases {
        assert!(
            !row.comparison.is_empty(),
            "`{}` states its requirement and its observation side by side",
            row.id
        );
        match &row.observed {
            Observation::Observed {
                rule,
                statements,
                surfaces,
                ..
            } => {
                // Every observed row names the severity the grading machinery
                // reached, in the manifest's own vocabulary, or `null` where the
                // machinery reached none — and that is true of both rules, not
                // only the severity one. An outcome-graded row carries the
                // severity as well, because an escalation must not be invisible
                // merely because a case is graded on whether something happened.
                // A weight from any other vocabulary is a row a reader cannot
                // compare with a requirement, and this is where that is caught.
                let reached = observed_severity(row);
                assert!(
                    reached.is_none()
                        || matches!(
                            reached,
                            Some("must_fix" | "should_fix_first" | "can_fix_later" | "note")
                        ),
                    "`{}` is graded on the {:?} axis and reaches `{:?}`, which is not a severity the \
                     manifest's vocabulary has",
                    row.id,
                    row.observed_axis(),
                    reached
                );
                assert!(
                    !rule.is_empty(),
                    "`{}` is graded by a rule it states",
                    row.id
                );
                assert!(
                    !surfaces.is_empty(),
                    "`{}` names the surface that observed it — a row with an observed outcome \
                     and no surface is a row restating a requirement",
                    row.id
                );
                assert!(
                    !statements.is_empty(),
                    "`{}` carries the measured facts it rests on",
                    row.id
                );
                assert!(
                    row.agreement != Agreement::CannotConfirm,
                    "`{}` is observed and its agreement is met or unmet",
                    row.id
                );
            }
            Observation::CannotConfirm {
                missing,
                would_require,
                surfaces,
                statements,
                ..
            } => {
                assert_eq!(
                    row.agreement,
                    Agreement::CannotConfirm,
                    "`{}` could not be observed and says so",
                    row.id
                );
                assert!(!missing.is_empty(), "`{}` names what is missing", row.id);
                assert!(
                    !would_require.is_empty(),
                    "`{}` names what would have to change",
                    row.id
                );
                assert!(
                    surfaces.is_empty(),
                    "`{}` was not observed and names no surface",
                    row.id
                );
                assert!(
                    !statements.is_empty(),
                    "`{}` was not observed and says what was read instead",
                    row.id
                );
            }
        }
    }

    // And the field is in the document, not only in the Rust type: a reader of
    // the JSON — P14-T012 computes a rate over these rows — must be able to tell
    // "the machinery produced no severity in the manifest's vocabulary" from
    // "this document has no such field", and an absent key reads as the second.
    let document: serde_json::Value =
        serde_json::from_str(&acceptance_report_json(&report).expect("the report serialises"))
            .expect("the report is JSON");
    let mut carried = 0_usize;
    for row in document["cases"].as_array().expect("`cases` is an array") {
        if row["observed"]["status"] != "observed" {
            continue;
        }
        assert!(
            row["observed"]
                .as_object()
                .expect("`observed` is an object")
                .contains_key("severity"),
            "`{}` is an observed row and the document does not carry a `severity` for it, so a \
             reader cannot tell a case with no severity in the manifest's vocabulary from a \
             document that never had the field: {}",
            row["id"],
            row["observed"]
        );
        carried += 1;
    }
    assert!(
        carried == report.totals.observed,
        "every observed row in the document carries the field: {carried} of {}",
        report.totals.observed
    );
}

#[test]
fn no_observed_row_copies_the_requirement_it_is_graded_against() {
    // The trap the task is built around, as an assertion that can fail alone: a
    // row whose observed severity is exactly the manifest's required severity,
    // for every row of the corpus at once, is the shape a report that read
    // `expected_severity` and printed it back would have. Some rows legitimately
    // *agree* — that is the point of a measurement — so this does not assert
    // they differ; it asserts each one was produced by the machinery, which is
    // what `surfaces` names, and that the agreement follows the rule the row
    // states.
    //
    // The rule is an **equality**: an escalation is as much a failure as a miss,
    // which is why the `>=` this file used to assert is gone. The one row in the
    // corpus where the machinery and the manifest disagree in weight —
    // `external-unverified`, whose own proposals are heavier than the manifest
    // asks — is the positive evidence that the number in a row is measured and
    // not copied: a copied value could never differ from the requirement it was
    // copied from.
    let report = the_report();
    let mut on_the_severity_axis = 0_usize;
    let mut on_the_outcome_axis = 0_usize;
    let mut heavier_than_asked: Vec<&str> = Vec::new();
    for row in &report.cases {
        let Observation::Observed { axis, .. } = &row.observed else {
            continue;
        };
        let required = row.required.severity;
        let carried = observed_severity(row).map(severity_of);
        if carried.is_some_and(|reached| reached.rank() > required.rank()) {
            heavier_than_asked.push(row.id.as_str());
            assert!(
                row.comparison.contains("heavier") && row.comparison.contains(required.as_str()),
                "`{}` carries `{}` where the manifest asks for `{}`, and a reader has to be able to \
                 see that from the row's own comparison rather than from the rule:\n{}",
                row.id,
                observed_severity(row).unwrap_or("nothing"),
                required.as_str(),
                row.comparison
            );
        }
        match axis {
            Axis::Severity => {
                on_the_severity_axis += 1;
                // `None` is "nothing fired at all" and cannot meet a requirement
                // of any weight, so the equality is over `Option<Severity>`.
                let wanted = if carried == Some(required) {
                    Agreement::Met
                } else {
                    Agreement::Unmet
                };
                assert_eq!(
                    row.agreement,
                    wanted,
                    "`{}` requires `{}` and reached `{}`, so its agreement is `{wanted:?}` and not \
                     `{:?}`",
                    row.id,
                    required.as_str(),
                    observed_severity(row).unwrap_or("nothing at all"),
                    row.agreement
                );
            }
            Axis::Outcome => {
                on_the_outcome_axis += 1;
                // An outcome-graded row carries the weight the machinery put on
                // what it produced, where there is one to carry: an escalation
                // must not be invisible merely because the case is graded on
                // whether something happened.
                assert!(
                    observed_severity(row).is_none()
                        || matches!(
                            observed_severity(row),
                            Some("must_fix" | "should_fix_first" | "can_fix_later" | "note")
                        ),
                    "`{}` carries `{:?}`, which is not a severity the manifest's vocabulary has",
                    row.id,
                    observed_severity(row)
                );
                assert!(
                    row.agreement != Agreement::CannotConfirm,
                    "`{}` carries an observation and its agreement is met or unmet",
                    row.id
                );
            }
        }
    }
    assert!(
        on_the_severity_axis > 0 && on_the_outcome_axis > 0,
        "both rules are used: {on_the_severity_axis} row(s) on the severity axis and \
         {on_the_outcome_axis} on the outcome axis"
    );
    assert!(
        !heavier_than_asked.is_empty(),
        "no row in the corpus observes a severity heavier than its requirement, so nothing here \
         shows that an observed severity is measured rather than copied out of the manifest"
    );
    assert_eq!(
        heavier_than_asked,
        ["external-unverified"],
        "the set of rows whose observed severity is heavier than the manifest asks moved, and the \
         escalation control below is written about the one that exists"
    );
}

#[test]
fn the_cannot_confirm_rows_are_the_named_ones_with_their_reasons() {
    let report = the_report();
    let unobserved: BTreeSet<&str> = report
        .cases
        .iter()
        .filter(|row| row.agreement == Agreement::CannotConfirm)
        .map(|row| row.id.as_str())
        .collect();
    assert_eq!(
        unobserved,
        BTreeSet::from([UNOBSERVABLE]),
        "exactly the case nothing in this workspace can observe reads cannot_confirm, and it is \
         not filled in with the manifest's expectation"
    );
    assert_eq!(
        report.totals.cannot_confirm,
        report
            .cases
            .iter()
            .filter(|row| row.agreement == Agreement::CannotConfirm)
            .count()
    );
    assert_eq!(
        report.totals.observed + report.totals.cannot_confirm,
        report.totals.cases
    );
    assert!(
        !row(&report, UNOBSERVABLE).release_blocking,
        "the unobservable case is not release-blocking, which is worth knowing and not worth \
         hiding"
    );

    // Supplying the one measurement this file can make is what moves
    // `repair-regression` out of that set — the row is a reading of the module's
    // own reach rather than a fact about the corpus.
    let module_only = the_module_report();
    let module_unobserved: BTreeSet<&str> = module_only
        .cases
        .iter()
        .filter(|row| row.agreement == Agreement::CannotConfirm)
        .map(|row| row.id.as_str())
        .collect();
    assert_eq!(
        module_unobserved,
        BTreeSet::from([UNOBSERVABLE, REPAIR_REGRESSION]),
        "the module on its own cannot observe `repair-regression`, and says so"
    );
    let supplied = row(&report, REPAIR_REGRESSION);
    assert_ne!(
        supplied.agreement,
        Agreement::CannotConfirm,
        "this file measured it, so the row it supplies is an observation"
    );
    let Observation::Observed { surfaces, .. } = &supplied.observed else {
        panic!("`repair-regression` was supplied and is not observed");
    };
    assert!(
        surfaces
            .iter()
            .any(|surface| surface.contains("acceptance_report_runner.rs")),
        "the row says which file observed it, so a reader can tell the module's reach from the \
         runner's: {surfaces:?}"
    );
}

#[test]
fn the_five_directories_with_no_case_are_named_in_both_directions() {
    let report = the_report();
    let named: BTreeSet<&str> = report
        .fixtures_without_a_case
        .iter()
        .map(|fixture| fixture.id.as_str())
        .collect();
    assert_eq!(
        named,
        OUT_OF_CONTRACT.iter().copied().collect::<BTreeSet<&str>>(),
        "the report names the directories that answer to no case"
    );
    for fixture in &report.fixtures_without_a_case {
        assert!(
            fixture.reason.len() > 40,
            "`{}` has a written reason rather than a placeholder",
            fixture.id
        );
    }

    // Measured against the disk rather than against the constant above: the
    // directories the corpus ships minus the cases the manifest declares.
    let contracted: BTreeSet<&str> = report.cases.iter().map(|row| row.id.as_str()).collect();
    let mut on_disk: BTreeSet<String> = BTreeSet::new();
    for entry in std::fs::read_dir(repository_root().join(FIXTURES))
        .expect("the corpus directory is readable")
        .filter_map(Result::ok)
    {
        if entry.path().is_dir() {
            on_disk.insert(entry.file_name().to_string_lossy().to_string());
        }
    }
    let expected: BTreeSet<String> = on_disk
        .iter()
        .filter(|id| !contracted.contains(id.as_str()))
        .cloned()
        .collect();
    assert_eq!(
        named.iter().copied().collect::<BTreeSet<&str>>(),
        expected.iter().map(String::as_str).collect(),
        "every directory the corpus ships is either a case or a named exception, and the two sets \
         are computed from the disk rather than from a list"
    );
    // The other direction: nothing the manifest declares is missing from the
    // disk, which is what makes \"the report's rows are the corpus\" true.
    for id in &contracted {
        assert!(
            on_disk.contains(*id),
            "the manifest declares `{id}` and the corpus ships no such directory"
        );
    }
}

#[test]
fn two_runs_are_byte_identical() {
    let first = acceptance_report_json(&the_report()).expect("the report serialises");
    let second = acceptance_report_json(&the_report()).expect("the report serialises");
    assert_eq!(
        first, second,
        "the same corpus twice is the same document; a difference here is a wall-clock value, a \
         generated identifier or a hash-map iteration order"
    );
}

#[test]
fn no_machine_path_appears_in_the_document() {
    let text = acceptance_report_json(&the_report()).expect("the report serialises");
    let root = repository_root().display().to_string();
    assert!(
        !text.contains(&root),
        "the report names the checkout it was produced in, so it is not portable: {root}"
    );
    let windows_root = root.replace('\\', "/");
    assert!(
        !text.contains(&windows_root),
        "the same path with forward slashes"
    );
    for absolute in ["C:/", "C:\\\\"] {
        assert!(
            !text.contains(absolute),
            "the document carries an absolute Windows path: {absolute}"
        );
    }
    assert!(
        !text.contains("\\\\?\\"),
        "the document carries a long-path prefix"
    );
    // The report's own file is written where a build artefact belongs.
    let out = repository_root().join(REPORT);
    std::fs::create_dir_all(out.parent().expect("the report has a parent"))
        .expect("target/tmp is creatable");
    std::fs::write(&out, &text).expect("the report is writable");
    assert!(out.is_file(), "the report was written to {}", out.display());
}

#[test]
fn the_report_matches_the_schema_it_ships_with() {
    let report = the_report();
    let text = acceptance_report_json(&report).expect("the report serialises");
    let value: serde_json::Value = serde_json::from_str(&text).expect("the report is JSON");
    let schema = sure_protocol::schema::Schema::parse("acceptance-report", SCHEMA)
        .unwrap_or_else(|error| panic!("schemas/acceptance-report.schema.json: {error}"));
    let violations = schema.validate(&value);
    assert!(
        violations.is_empty(),
        "the report does not match schemas/acceptance-report.schema.json: {violations:#?}"
    );
}

#[test]
fn a_row_that_should_be_unmet_does_not_read_met() {
    // The anti-vacuity control. A report that read `expected_severity` out of
    // the manifest and printed it back as the observed outcome would read green
    // over exactly the cases where the two are known to differ — the trap §5.1
    // of the brief is about — and every assertion in this file would still pass,
    // because a copied requirement agrees with itself.
    //
    // So the corpus is made to disagree with itself on purpose: the same
    // fixture, under a contract that requires `must_fix` for a case the
    // machinery reaches `note` on. The row must read `unmet`, and its observed
    // severity must be the measured one rather than the required one.
    //
    // Reproducible mutation, and the one this test is for: in
    // `sure_core::acceptance_report::row_for`, replace
    //
    //     let held = severity.is_some_and(|reached| reached.rank() >= case.expected_severity.rank());
    //
    // with `let held = true;` — or replace the observed `severity` with
    // `Some(case.expected_severity.as_str().to_owned())`. Either one turns the
    // row `met` and turns the first assertion below red.
    let control = control_corpus(
        "miss",
        "benign-test-mocks",
        "must_fix",
        "the control: a contract that requires more than the machinery reaches",
    );
    let report = acceptance_report(&control)
        .unwrap_or_else(|error| panic!("the control corpus produced no report: {error}"));
    let controlled = row(&report, "benign-test-mocks");

    assert_eq!(
        controlled.agreement,
        Agreement::Unmet,
        "the control corpus requires `must_fix` and the machinery reaches `{}`, so this row is not \
         met — a row that reads `met` here is a row that restated its requirement: {}",
        observed_severity(controlled).unwrap_or("nothing"),
        controlled.comparison
    );
    assert_eq!(
        observed_severity(controlled),
        Some("note"),
        "the observed severity is what the five scanners reached over the fixture, and not the \
         `must_fix` the control's manifest asks for"
    );
    assert_ne!(
        observed_severity(controlled),
        Some(controlled.required.severity.as_str()),
        "the observed outcome and the requirement are two different readings"
    );
    assert_eq!(report.totals.unmet, 1);
    assert_eq!(report.totals.release_blocking_unmet, 1);

    // The same fixture under the real contract reads `met`, because the real
    // contract asks for `note`. The control's redness is therefore about the
    // requirement it changed and not about a recipe that stopped working.
    let real = the_report();
    let same = row(&real, "benign-test-mocks");
    assert_eq!(same.agreement, Agreement::Met);
    assert_eq!(observed_severity(same), observed_severity(controlled));
}

/// A one-case corpus under `target/tmp` whose contract disagrees with what the
/// fixture's machinery produces, in one direction.
///
/// Written rather than checked in: `evaluation/` and `fixtures/` are the real
/// corpus and this task does not edit them, so the control builds its own copy
/// of the fixture beside a manifest written for it. The directory is left in
/// place for a reader — it is a build artefact under `target/tmp`, and
/// `cargo clean` removes it.
///
/// Both directions are built from this one function, because they are the same
/// experiment with one value moved: `control miss` requires more than the
/// machinery reaches and `control escalation` requires less.
fn control_corpus(what: &str, fixture: &str, required: &str, expectation: &str) -> PathBuf {
    let root = repository_root()
        .join("target")
        .join("tmp")
        .join(format!("sure 指纹 acceptance-report control {what}"));
    let shipped = root.join(FIXTURES).join(fixture);
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("evaluation")).expect("the control corpus is creatable");
    copy_tree(&repository_root().join(FIXTURES).join(fixture), &shipped);
    // The five directories the module has a written reason for, created empty.
    // `fixtures_without_a_case` is computed from the disk in both directions and
    // a corpus that shipped only one directory would be a corpus with a reason
    // written for four it does not have — which the module refuses, correctly,
    // and which is not what this control is about.
    for id in OUT_OF_CONTRACT {
        std::fs::create_dir_all(root.join(FIXTURES).join(id))
            .expect("the control corpus is creatable");
    }
    let manifest = serde_json::json!({
        "schema_version": 1,
        "cases": [{
            "id": fixture,
            "release_blocking": true,
            "expected_severity": required,
            "expectation": expectation,
        }],
    });
    std::fs::write(root.join(MANIFEST_FILE), format!("{manifest:#}\n"))
        .expect("the control manifest is writable");
    root
}

#[test]
fn an_escalation_does_not_read_met() {
    // The control in the other direction, and the reason this file no longer
    // grades a severity by a floor. `benign-test-mocks`'s manifest expectation
    // is that benign test mocks do not become must-fix production findings, and
    // its `forbidden_outcomes` record that outcome as a false positive. A rule
    // of `reached >= required` cannot see that: a build that escalated the case
    // would score `met` over the exact false positive the case exists to detect,
    // which is a false green inside the artefact whose purpose is to catch them.
    //
    // So the control corpus here requires *less* than the machinery produces:
    // `demo-analytics`, whose five scanners reach `should_fix_first`, under a
    // contract that asks for `note`. The row must read `unmet`, and its own
    // comparison must say which way the disagreement went.
    //
    // Reproducible mutation, and the one this test is for: in
    // `sure_core::acceptance_report::row_for`, replace
    //
    //     let held = severity == Some(case.expected_severity);
    //
    // with the floor it used to be —
    //
    //     let held = severity.is_some_and(|reached| reached.rank() >= case.expected_severity.rank());
    //
    // The row reads `met` and the first assertion below goes red alone.
    let control = control_corpus(
        "escalation",
        "demo-analytics",
        "note",
        "the control: a contract that requires less than the machinery reaches",
    );
    let report = acceptance_report(&control)
        .unwrap_or_else(|error| panic!("the control corpus produced no report: {error}"));
    let escalated = row(&report, "demo-analytics");

    assert_eq!(
        escalated.agreement,
        Agreement::Unmet,
        "the control corpus requires `note` and the machinery reaches `{}`, so this row is not met — \
         a rule that treats a heavier observation as a pass scores `met` here, which is the false \
         green `benign-test-mocks` exists to catch: {}",
        observed_severity(escalated).unwrap_or("nothing"),
        escalated.comparison
    );
    assert_eq!(
        observed_severity(escalated),
        Some("should_fix_first"),
        "the observed severity is what the five scanners reached over the fixture, and not the `note` \
         the control's manifest asks for"
    );
    assert_ne!(
        observed_severity(escalated),
        Some(escalated.required.severity.as_str()),
        "the observed outcome and the requirement are two different readings"
    );
    // The direction is in the row's own sentence, not only in the rule: a reader
    // who has the requirement and the observation side by side has to be able to
    // tell an escalation from a miss without reading the paragraph above it.
    assert!(
        escalated.comparison.contains("heavier")
            && escalated.comparison.contains("should_fix_first")
            && escalated.comparison.contains("note"),
        "the comparison does not say which way the disagreement went:\n{}",
        escalated.comparison
    );
    assert_eq!(report.totals.unmet, 1);
    assert_eq!(report.totals.release_blocking_unmet, 1);

    // The same fixture under the real contract reads `met`, because the real
    // contract asks for `should_fix_first`. The control's redness is therefore
    // about the requirement it changed and not about a recipe that stopped
    // working — and this is the pair that makes the rule an equality rather than
    // a floor: the same measurement is `met` against one contract and `unmet`
    // against the other.
    let real = the_report();
    let same = row(&real, "demo-analytics");
    assert_eq!(same.agreement, Agreement::Met);
    assert_eq!(observed_severity(same), observed_severity(escalated));
}

#[test]
fn the_limitations_are_in_the_document_rather_than_in_a_commit_message() {
    let report = the_report();
    let all = report.limitations.join("\n");
    for (what, wanted) in [
        (
            "the closing half of the repair loop is unreached, and why",
            "The closing half of the repair loop is unreached here",
        ),
        (
            "this report's own drives run nothing that runs project code",
            "inspect_only",
        ),
        ("nothing touched the store", "store: None"),
        ("what is deterministic about it", "byte-identical"),
    ] {
        assert!(
            all.contains(wanted),
            "the limitations do not state {what} (`{wanted}`):\n{all}"
        );
    }
}

#[test]
fn the_release_gate_over_this_report_permits_the_release_and_is_written_beside_it() {
    // P14-T012's document, taken from the report this file produces rather than
    // from a second reading of the corpus. That is not a convenience: this
    // report carries the one measurement no `src` module can make
    // (`repair-regression`), and a gate computed from the module's own report
    // would block the release over a case this file measured — a false red,
    // which is the other half of the same failure as a false green.
    //
    // The gate's own properties are measured in
    // `crates/sure-core/tests/release_gate_runner.rs`: the seven metrics as
    // values, the control corpora that make it block and permit, and the
    // module-only reading in which the unobserved case is what blocks. This test
    // is the shipped document, and what it asserts is what a packaging task
    // reading that document is entitled to take from it.
    let report = the_report();
    let gate = release_gate(&report);
    assert_eq!(
        gate.decision,
        Decision::Permitted,
        "the corpus's release-blocking cases are all met, as measured: {:#?}",
        gate.blocked_by
    );
    assert!(
        gate.blocked_by.is_empty(),
        "a permitted release names no blocking case: {:#?}",
        gate.blocked_by
    );
    assert_eq!(gate.corpus.manifest_digest, report.corpus.manifest_digest);
    assert_eq!(gate.corpus.release_blocking, report.totals.release_blocking);
    assert_eq!(
        gate.corpus.release_blocking_cannot_confirm,
        report.totals.release_blocking_cannot_confirm
    );

    // Clause 1 of the acceptance as a value rather than as a sentence: the
    // release-blocking corpus has zero false green, and the rate is taken over
    // the rows that carry an observation rather than over the corpus's own
    // declarations.
    let false_green = gate
        .metrics
        .iter()
        .find(|metric| metric.claim.contains("false green rate"))
        .expect("the gate carries the document's first metric");
    assert_eq!(
        false_green.value,
        MetricValue::Rate {
            numerator: 0,
            denominator: report.totals.release_blocking_observed,
        },
        "the false-green rate over the release-blocking corpus, from the observed rows"
    );

    let text = release_gate_json(&gate).expect("the gate serialises");
    let root = repository_root().display().to_string();
    assert!(
        !text.contains(&root) && !text.contains(&root.replace('\\', "/")),
        "the gate names the checkout it was produced in, so it is not portable: {root}"
    );
    let value: serde_json::Value = serde_json::from_str(&text).expect("the gate is JSON");
    let schema = sure_protocol::schema::Schema::parse("release-gate", GATE_SCHEMA)
        .unwrap_or_else(|error| panic!("schemas/release-gate.schema.json: {error}"));
    let violations = schema.validate(&value);
    assert!(
        violations.is_empty(),
        "the gate does not match schemas/release-gate.schema.json: {violations:#?}"
    );

    let out = repository_root().join(GATE);
    std::fs::create_dir_all(out.parent().expect("the gate has a parent"))
        .expect("target/tmp is creatable");
    std::fs::write(&out, &text).expect("the gate is writable");
    assert!(out.is_file(), "the gate was written to {}", out.display());
}

/// The two artefacts over this corpus, measured against each other.
///
/// Two documents describe one corpus and read two decisions. The gate
/// `crates/sure-core/tests/release_gate_runner.rs` computes over the module's
/// own report reads `Blocked`, with one blocker, `repair-regression`, at
/// `Agreement::CannotConfirm`; the gate this file writes to
/// `target/tmp/release-gate.json` reads `permitted`. The false-green rate splits
/// the same way, `0 of 12` against `0 of 13`, because the module's report cannot
/// observe the thirteenth case. Read one document at a time, the shipped one is
/// the more permissive of the two — which is the shape of a false green, and is
/// why what has to be established is that both are over *one* corpus and differ
/// only in what each could observe.
///
/// That is not a property either document can be read for. It is a relation
/// between two values, so both readings are built here, in this binary, and the
/// comparison is between two reports rather than between two files: nothing
/// here reads `target/tmp/release-gate.json`, and nothing here depends on
/// whether the other binary has run.
#[test]
fn the_two_readings_are_of_one_corpus_and_differ_only_in_what_each_could_observe() {
    let shipped = the_report();
    let module = the_module_report();

    // What is the same. The whole corpus block — the contract's path, its
    // digest, the fixtures directory, the case count and the release-blocking
    // count — is one value rather than two that happen to agree today, because
    // the supplied measurement is the only input that differs between the two
    // calls: `acceptance_report` is `acceptance_report_with` with nothing
    // supplied. If this ever fails, the two denominators and the two decisions
    // are two facts about two contracts, and the shipped document is a reading
    // of a corpus the other gate never saw.
    assert_eq!(
        module.corpus, shipped.corpus,
        "the two readings name different corpora: {:#?}\nagainst\n{:#?}",
        module.corpus, shipped.corpus
    );
    assert_eq!(module.corpus.manifest, MANIFEST_FILE);
    assert_eq!(module.corpus.fixtures, FIXTURES);
    assert_eq!(module.corpus.cases, 20);
    assert_eq!(module.corpus.release_blocking, 13);

    // The rows are the corpus's, in the same order, and exactly one of them
    // reads differently.
    let ids = |report: &AcceptanceReport| {
        report
            .cases
            .iter()
            .map(|row| row.id.clone())
            .collect::<Vec<String>>()
    };
    assert_eq!(
        ids(&module),
        ids(&shipped),
        "the two readings do not hold the same rows"
    );
    let differing: Vec<&str> = module
        .cases
        .iter()
        .zip(&shipped.cases)
        .filter(|(left, right)| left != right)
        .map(|(left, _)| left.id.as_str())
        .collect();
    assert_eq!(
        differing,
        [REPAIR_REGRESSION],
        "the two readings differ on a row other than the one measurement this file supplies, so the \
         difference between the two decisions is not the difference this test is about"
    );

    // And the difference is reach rather than corpus: the same thirteen
    // release-blocking cases, counted the same way on both sides.
    assert_eq!(
        shipped.totals.release_blocking,
        module.totals.release_blocking
    );
    assert_eq!(shipped.totals.release_blocking_observed, 13);
    assert_eq!(shipped.totals.release_blocking_cannot_confirm, 0);
    assert_eq!(module.totals.release_blocking_observed, 12);
    assert_eq!(module.totals.release_blocking_cannot_confirm, 1);

    // The thirteenth case, on both sides, as the two rows a reader would see.
    let unobserved = row(&module, REPAIR_REGRESSION);
    assert_eq!(unobserved.agreement, Agreement::CannotConfirm);
    assert!(unobserved.release_blocking);
    let Observation::CannotConfirm { missing, .. } = &unobserved.observed else {
        panic!("the module observed `{REPAIR_REGRESSION}`, so this test's premise has moved");
    };
    assert!(
        missing.contains("sure_core::process"),
        "the module's row does not say what observing this case would take: {missing}"
    );
    let observed = row(&shipped, REPAIR_REGRESSION);
    assert_eq!(observed.agreement, Agreement::Met);
    assert!(observed.release_blocking);

    // The two decisions, over one corpus, parting on that one row.
    let module_gate = release_gate(&module);
    let shipped_gate = release_gate(&shipped);
    assert_eq!(module_gate.decision, Decision::Blocked);
    assert_eq!(
        module_gate
            .blocked_by
            .iter()
            .map(|case| (case.id.as_str(), case.agreement))
            .collect::<Vec<_>>(),
        vec![(REPAIR_REGRESSION, Agreement::CannotConfirm)],
        "the module's gate does not block on exactly the case this file measured"
    );
    assert_eq!(shipped_gate.decision, Decision::Permitted);
    assert!(shipped_gate.blocked_by.is_empty());
    assert_eq!(
        module_gate.corpus.manifest_digest, shipped_gate.corpus.manifest_digest,
        "the two decisions were taken against different contracts, which is the one thing that would \
         make the shipped document a reading of a corpus the other gate never saw"
    );

    // The rate, which is where the two denominators are visible. The numerator
    // is `0` in both readings, so the document's line — which states the
    // numerator — cannot be where the split shows; the split is in the
    // denominator, and the denominator is the release-blocking rows the reading
    // could observe. Thirteen are in the corpus and twelve of them carry an
    // observation here, so the narrower reading is the more demanding
    // denominator rather than the more permissive one.
    let false_green = |gate: &sure_core::release_gate::ReleaseGate| {
        gate.metrics
            .iter()
            .find(|metric| metric.claim.contains("false green rate"))
            .map(|metric| match &metric.value {
                MetricValue::Rate {
                    numerator,
                    denominator,
                } => (*numerator, *denominator),
                MetricValue::Unmeasured { .. } => {
                    panic!("the false-green rate read unmeasured on a corpus of thirteen")
                }
            })
            .expect("the gate carries the document's first metric")
    };
    assert_eq!(false_green(&shipped_gate), (0, 13));
    assert_eq!(false_green(&module_gate), (0, 12));
}

/// A severity by its wire name, for the rows the report carries.
fn severity_of(name: &str) -> Severity {
    match name {
        "must_fix" => Severity::MustFix,
        "should_fix_first" => Severity::ShouldFixFirst,
        "can_fix_later" => Severity::CanFixLater,
        "note" => Severity::Note,
        other => panic!("`{other}` is not a severity the manifest vocabulary has"),
    }
}

/// A JSON document read from the checkout.
fn read_json(path: &Path) -> serde_json::Value {
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
    serde_json::from_str(&text)
        .unwrap_or_else(|error| panic!("{} is not JSON: {error}", path.display()))
}

// --- the repair-regression observation, measured here ---------------------

/// The fixture, and the two members whose own checks are this case's evidence.
const FIXTURE: &str = "repair-regression";
const CHECKOUT: &str = "packages/checkout";
const BILLING: &str = "packages/billing";

/// The line `shared/pricing.js` ships, and the one line that corrects it.
const THE_DEFECT: &str = "  return Math.max(0, total + amount);";
const THE_CORRECTION: &str = "  return Math.max(0, total - amount);";

/// The call in `packages/billing/src/refund.js` that the corrected helper breaks,
/// and the call the complete repair changes it to.
const THE_CALL: &str = "  return less(paidCents, -feeCents);";
const THE_REPAIRED_CALL: &str = "  return less(paidCents, feeCents);";

/// How long a check has, and how much of what it says SURE keeps.
const LIMITS: Limits = Limits::new(Duration::from_secs(120), 64 * 1024, 64 * 1024);

/// Which repair is applied to a copy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Repair {
    /// The helper corrected and the call that moved under it left alone.
    Careless,
    /// The helper and the call.
    Complete,
}

impl Repair {
    const fn edits(self) -> &'static [(&'static str, &'static str)] {
        match self {
            Self::Careless => &[(THE_DEFECT, THE_CORRECTION)],
            Self::Complete => &[(THE_DEFECT, THE_CORRECTION), (THE_CALL, THE_REPAIRED_CALL)],
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Careless => "the careless repair",
            Self::Complete => "the complete repair",
        }
    }
}

/// The shipped directory of the fixture.
fn shipped() -> PathBuf {
    repository_root().join(FIXTURES).join(FIXTURE)
}

/// The content fingerprint of a directory, as a digest.
fn digest(dir: &Path) -> String {
    content_fingerprint(dir, &FingerprintOptions::default())
        .unwrap_or_else(|error| panic!("cannot fingerprint {}: {error}", dir.display()))
        .digest
}

/// Copy a directory tree, links included as links.
fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to)
        .unwrap_or_else(|error| panic!("cannot create {}: {error}", to.display()));
    for entry in std::fs::read_dir(from)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", from.display()))
        .filter_map(Result::ok)
    {
        let path = entry.path();
        let destination = to.join(entry.file_name());
        if path.is_dir() {
            copy_tree(&path, &destination);
        } else {
            std::fs::copy(&path, &destination).unwrap_or_else(|error| {
                panic!(
                    "cannot copy {} to {}: {error}",
                    path.display(),
                    destination.display()
                )
            });
        }
    }
}

/// A copy of the shipped fixture, outside the fixture, that removes itself.
///
/// Under `target/tmp`, which `.gitignore` covers, and with a space and a
/// non-ASCII character in the path because that is the discipline `CLAUDE.md`
/// asks for: a rule that happens to work on ordinary paths should fail here
/// rather than on a user's machine.
struct CopyOfFixture {
    copy: PathBuf,
}

impl CopyOfFixture {
    fn of() -> Self {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let from = shipped();
        assert!(
            from.is_dir(),
            "{} is not a directory, so this fixture is not a shipped artefact",
            from.display()
        );
        let unique = format!(
            "{FIXTURE}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        );
        let copy = repository_root()
            .join("target")
            .join("tmp")
            .join("sure 指纹 acceptance-report")
            .join(unique);
        let _ = std::fs::remove_dir_all(&copy);
        std::fs::create_dir_all(&copy)
            .unwrap_or_else(|error| panic!("cannot create {}: {error}", copy.display()));
        copy_tree(&from, &copy);
        let taken = Self { copy };
        assert_eq!(
            digest(taken.path()),
            digest(&from),
            "the copy is not the shipped fixture, so nothing measured on it is about the fixture"
        );
        taken
    }

    fn path(&self) -> &Path {
        &self.copy
    }

    /// Apply a repair, one asserted substitution at a time.
    fn repair(&self, repair: Repair) {
        for (from, to) in repair.edits() {
            let path = if *from == THE_CALL || *from == THE_REPAIRED_CALL {
                self.path().join(BILLING).join("src").join("refund.js")
            } else {
                self.path().join("shared").join("pricing.js")
            };
            let text = std::fs::read_to_string(&path)
                .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
            assert_eq!(
                text.matches(from).count(),
                1,
                "{} does not hold the line {} is about to replace exactly once, so {} would be a \
                 substitution that measured nothing",
                path.display(),
                from.trim(),
                repair.as_str()
            );
            std::fs::write(&path, text.replace(from, to))
                .unwrap_or_else(|error| panic!("cannot write {}: {error}", path.display()));
        }
    }
}

impl Drop for CopyOfFixture {
    fn drop(&mut self) {
        drop(std::fs::remove_dir_all(&self.copy));
    }
}

/// The command a check declared.
fn declared_command(proposal: &CheckProposal) -> String {
    match proposal.reason() {
        CheckReason::DeclaredCommand { command, .. } => command.clone(),
        other => panic!("{} has the reason {other:?}", proposal.title()),
    }
}

/// The manifest a check was read from.
fn declared_in(proposal: &CheckProposal) -> String {
    match proposal.reason() {
        CheckReason::DeclaredCommand { declared_in, .. } => declared_in.clone(),
        other => panic!("{} has the reason {other:?}", proposal.title()),
    }
}

fn manifest_of(member: &str) -> String {
    format!("{member}/{MANIFEST}")
}

/// A member's own declared test script.
fn member_script<'a>(project: &'a NodeProject, member: &str) -> (&'a Path, &'a str) {
    let found = project
        .workspaces
        .readable_members()
        .find(|candidate| candidate.path.ends_with(member))
        .unwrap_or_else(|| panic!("discovery resolved no member `{member}`"));
    let script = found
        .package
        .as_deref()
        .and_then(|package| package.script(ScriptRole::Test))
        .unwrap_or_else(|| panic!("`{member}` declares no test script"));
    let declared = script.command.as_str();
    assert!(
        declared.starts_with("node "),
        "`{member}` declares the test script `{declared}`, and this file only knows how to run one \
         that starts with `node`"
    );
    (found.path.as_path(), declared)
}

/// A request to run one member's declared check.
fn request(working_directory: &Path, script: &str) -> (String, ProcessRequest) {
    let mut parts = script.split_whitespace();
    let program = parts
        .next()
        .unwrap_or_else(|| panic!("`{script}` names no program"));
    assert_eq!(program, "node", "`{script}` is not a node command");
    let arguments: Vec<String> = parts.map(str::to_owned).collect();
    let request = ProcessRequest::new(
        program.to_owned(),
        working_directory,
        LIMITS,
        Cancellation::new(),
    )
    .with_arguments(arguments.clone())
    .with_environment(Environment::inherited());
    (
        std::iter::once(program.to_owned())
            .chain(arguments)
            .collect::<Vec<_>>()
            .join(" "),
        request,
    )
}

/// What one check found, from the process that ran it.
fn result_of(proposal: &CheckProposal, outcome: &Outcome, state: &FingerprintId) -> CheckResult {
    let id = proposal.id().clone();
    let title = proposal.title().to_owned();
    let severity = proposal.severity();
    let critical = proposal.critical();
    let class = proposal.evidence_class();
    match outcome.termination() {
        Termination::Exited { code: Some(0) } => {
            CheckResult::pass(id, title, severity, critical, class, state.clone())
        }
        Termination::Exited { code } => {
            CheckResult::fail(id, title, severity, critical, class, state.clone()).with_reason(
                match code {
                    Some(code) => format!("the command exited with code {code}"),
                    None => {
                        "the command was ended by a signal, so there is no exit code".to_owned()
                    }
                },
            )
        }
        Termination::TimedOut { .. } => CheckResult::errored(
            id,
            title,
            severity,
            critical,
            "the command was stopped because it passed its deadline",
            state.clone(),
        ),
        Termination::Cancelled { .. } | Termination::CancelledBeforeStart => CheckResult::errored(
            id,
            title,
            severity,
            critical,
            "the command was cancelled",
            state.clone(),
        ),
    }
}

/// One check as the run saw it.
struct Ran {
    title: String,
    command: String,
    output: String,
}

/// Everything one run of the fixture produced.
struct Run {
    schedule: CheckSchedule,
    results: Vec<CheckResult>,
    report: RunReport,
    summary: String,
    state: FingerprintId,
    ran: Vec<Ran>,
    checkout: CheckId,
    billing: CheckId,
}

impl Run {
    fn result(&self, id: &CheckId) -> &CheckResult {
        self.results
            .iter()
            .find(|result| result.id == *id)
            .unwrap_or_else(|| panic!("no result for {id}"))
    }

    fn output_of(&self, id: &CheckId) -> &str {
        self.ran
            .iter()
            .find(|ran| ran.title == self.result(id).title)
            .map(|ran| ran.output.as_str())
            .unwrap_or_else(|| panic!("no process ran {id}"))
    }
}

/// Discover the copy, propose the members' declared checks, run them with SURE's
/// own runner, aggregate the results, and render the verdict a person would read.
fn run_the_checks(copy: &CopyOfFixture) -> Run {
    let found = discover(copy.path(), &DiscoverOptions::default())
        .unwrap_or_else(|error| panic!("discovery failed on {}: {error}", copy.path().display()));
    let report = found.report(Ecosystem::Node).unwrap_or_else(|| {
        panic!(
            "{} is a Node project and discovery did not report one",
            copy.path().display()
        )
    });
    let Findings::Node(node) = &report.findings else {
        panic!("the Node report carried {:?} findings", report.findings);
    };

    let checks = NodeChecks::of(node, copy.path());
    let proposed: Vec<&CheckProposal> = checks
        .planned()
        .iter()
        .map(PlannedWork::proposal)
        .filter(|proposal| {
            let manifest = declared_in(proposal);
            manifest == manifest_of(CHECKOUT) || manifest == manifest_of(BILLING)
        })
        .collect();
    assert_eq!(
        proposed.len(),
        2,
        "the fixture's two members each declare one test script, so the checks layer proposes two \
         checks for them: {:?}",
        checks
            .planned()
            .iter()
            .map(PlannedWork::proposal)
            .map(|proposal| (declared_in(proposal), proposal.title().to_owned()))
            .collect::<Vec<_>>()
    );
    for proposal in &proposed {
        assert_eq!(
            declared_command(proposal),
            "npm test",
            "{}",
            proposal.title()
        );
        assert_eq!(
            proposal.severity(),
            Severity::MustFix,
            "{}",
            proposal.title()
        );
        assert!(proposal.critical(), "{}", proposal.title());
        assert_eq!(
            proposal.evidence_class(),
            EvidenceClass::DeterministicCheck,
            "{}",
            proposal.title()
        );
        assert!(
            proposal.requirements().runs_project_code(),
            "{}",
            proposal.title()
        );
    }

    let mut builder = PlanBuilder::new(ExecutionMode::HostConfirmed, host_confirmed());
    checks.add_to(&mut builder);
    assert!(
        builder.refused().is_empty(),
        "the checks layer proposed something the builder refused: {:?}",
        builder.refused()
    );
    let schedule = builder.build();
    assert_eq!(
        schedule.may_run().count(),
        2,
        "the plan holds {} entries",
        schedule.len()
    );

    let state = project_fingerprint(copy.path(), &FingerprintOptions::default())
        .unwrap_or_else(|error| panic!("cannot fingerprint {}: {error}", copy.path().display()))
        .id;

    let mut results = Vec::new();
    let mut ran = Vec::new();
    for scheduled in schedule.may_run() {
        let proposal = scheduled.proposal();
        let member = if declared_in(proposal) == manifest_of(CHECKOUT) {
            CHECKOUT
        } else {
            BILLING
        };
        let (member_path, script) = member_script(node, member);
        let (command, request) = request(&copy.path().join(member_path), script);
        let outcome = run(&request)
            .unwrap_or_else(|error| panic!("`{command}` could not be started: {error}"));
        let output = format!(
            "{}{}",
            outcome.stdout().text_lossy(),
            outcome.stderr().text_lossy()
        );
        results.push(result_of(proposal, &outcome, &state));
        ran.push(Ran {
            title: proposal.title().to_owned(),
            command,
            output,
        });
    }

    let report = aggregate_run(&schedule, &results, &[], &state)
        .unwrap_or_else(|refusal| panic!("the run was refused: {refusal:?}"));
    let verdict = build_verdict(
        state.clone(),
        report.aggregate().clone(),
        ProjectIntent::empty(),
        CapabilityReport::cli(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
    );
    let summary = render_summary(&verdict);

    let id_for = |member: &str| {
        proposed
            .iter()
            .find(|proposal| declared_in(proposal) == manifest_of(member))
            .map(|proposal| proposal.id().clone())
            .unwrap_or_else(|| panic!("no check for {member}"))
    };

    Run {
        schedule,
        results,
        report,
        summary,
        state,
        ran,
        checkout: id_for(CHECKOUT),
        billing: id_for(BILLING),
    }
}

/// Host-confirmed, with the permission actually granted.
fn host_confirmed() -> ExecutionPermissions {
    ExecutionPermissions {
        run_project_code: true,
        ..ExecutionPermissions::inspect_only()
    }
}

/// The finding the repair is about, built from the run that found it.
fn the_finding(run: &Run) -> Finding {
    let result = run.result(&run.checkout);
    assert_eq!(
        result.status,
        CheckStatus::Fail,
        "the finding is built from a check that failed, and {} did not",
        result.title
    );
    let rationale = SeverityRationale::for_severity(result.severity)
        .unwrap_or_else(|| panic!("{:?} has no rationale", result.severity));
    FindingBuilder::new(AssessmentSource::DeterministicCheck, rationale)
        .id(FindingId::generate())
        .title("the basket total adds the discount instead of taking it off")
        .severity(result.severity)
        .status(FindingStatus::Open)
        .explanation(
            "the shared `less` helper adds the amount it is given instead of taking it off, so a \
             discounted basket is charged more than an undiscounted one",
        )
        .user_impact("a customer with a discount code is charged more than one without")
        .next_step("make `less` subtract the amount it is given")
        .fingerprint(result.project_fingerprint.clone())
        .evidence(vec![Evidence::new(
            result.evidence_class,
            "the project's own check for the basket total fails",
            EvidenceAnchor::new(AnchorSubject::File, CHECKOUT, "totalCents"),
            Some(result.project_fingerprint.clone()),
            result.severity,
        )])
        .build()
        .expect("the finding has a title, a severity and a fingerprint")
}

/// The contract the repair is made under, and the checks that must pass before
/// the finding may close. The contract names one check; the product adds the rest.
fn contract_and_selection(run: &Run, finding: &Finding) -> (RepairContract, Vec<CheckId>) {
    let contract = RepairContract::from_finding(finding, vec![run.checkout.clone()])
        .expect("the finding is grounded and one check was supplied");
    let selected = select_impacted_checks(&contract, &run.schedule);
    (contract, selected)
}

/// Why the billing check can be selected as a regression check at all.
fn assert_is_a_regression_check(run: &Run) {
    let scheduled = run
        .schedule
        .get(&run.billing)
        .expect("the billing check is in the plan");
    let proposal = scheduled.proposal();
    assert!(
        proposal.requirements().runs_project_code(),
        "a check that does not run the project's code cannot catch a side effect of a repair"
    );
    assert_eq!(proposal.evidence_class(), EvidenceClass::DeterministicCheck);
    assert!(
        matches!(
            proposal.severity(),
            Severity::MustFix | Severity::ShouldFixFirst
        ),
        "the regression rule excludes notes, and this check is {:?}",
        proposal.severity()
    );
}

/// What one half of the repair measured.
struct Half {
    /// Whether the finding stayed open.
    stayed_open: bool,
    /// How many findings the lifecycle resolved.
    resolved: usize,
    /// The severity the run aggregated to.
    severity: AggregateSeverity,
    /// Whether the run was green.
    green: bool,
    /// The checks blocking the run.
    blocking: Vec<CheckId>,
    /// The checks the product selected as having to pass.
    selected: Vec<CheckId>,
    /// What each member's own check said.
    checkout: CheckStatus,
    billing: CheckStatus,
    /// What the members' checks printed.
    checkout_output: String,
    billing_output: String,
    /// The summary a person would read.
    summary: String,
}

/// One half of the repair: apply it, run the checks, and let the product decide.
fn half(finding: &Finding, repair: Repair) -> Half {
    let repaired = CopyOfFixture::of();
    let shipped_digest = digest(repaired.path());
    repaired.repair(repair);
    assert_ne!(
        shipped_digest,
        digest(repaired.path()),
        "{} did not change the project, so nothing below is evidence about a repair",
        repair.as_str()
    );
    let after = run_the_checks(&repaired);

    let (_, selected) = contract_and_selection(&after, finding);
    let planned: Vec<CheckId> = after
        .schedule
        .checks()
        .iter()
        .map(|scheduled| scheduled.proposal().id().clone())
        .collect();
    let update = reconcile(
        LifecycleInputs {
            previous_open: std::slice::from_ref(finding),
            current_findings: &[],
            check_results: &after.results,
            rechecks: &[(finding.id.clone(), selected.clone())],
            planned: &planned,
            case: CaseSensitivity::Sensitive,
        },
        after.state.clone(),
    );
    assert!(
        !update.findings.is_empty(),
        "the lifecycle said nothing about the finding"
    );
    let stayed_open = update
        .findings
        .iter()
        .any(|found| found.status == FindingStatus::Open);

    // The contract holds the one check this file supplied and no other; every
    // check that joined it was selected by the product's own rule.
    let (contract, _) = contract_and_selection(&after, finding);
    assert_eq!(contract.recheck, vec![after.checkout.clone()]);
    assert_is_a_regression_check(&after);

    Half {
        stayed_open,
        resolved: update.resolved.len(),
        severity: after.report.aggregate().severity,
        green: after.report.is_green(),
        blocking: after.report.aggregate().blocking.clone(),
        selected,
        checkout: after.result(&after.checkout).status,
        billing: after.result(&after.billing).status,
        checkout_output: after.output_of(&after.checkout).to_owned(),
        billing_output: after.output_of(&after.billing).to_owned(),
        summary: after.summary,
    }
}

/// The `repair-regression` row's observation, measured with the real runner.
///
/// The manifest's expectation is *repair regression remains blocked*. The
/// yardstick is the repair lifecycle over two runs of the fixture's own checks:
/// the careless repair fixes the check that was failing and breaks the other
/// member, and the finding may not close; the complete repair fixes both and the
/// finding closes. Both halves are measured, so the block is a measurement
/// rather than a predicate nothing can satisfy.
fn repair_regression() -> Measurement {
    let before = run_the_checks(&CopyOfFixture::of());
    assert_eq!(
        before.result(&before.checkout).status,
        CheckStatus::Fail,
        "the fixture's failing member passes as shipped:\n{}",
        before.output_of(&before.checkout)
    );
    assert_eq!(
        before.result(&before.billing).status,
        CheckStatus::Pass,
        "the fixture's other member is meant to pass before any repair:\n{}",
        before.output_of(&before.billing)
    );
    let finding = the_finding(&before);

    let careless = half(&finding, Repair::Careless);
    assert_eq!(
        careless.checkout,
        CheckStatus::Pass,
        "the careless repair is meant to fix the basket total:\n{}",
        careless.checkout_output
    );
    assert_eq!(
        careless.billing,
        CheckStatus::Fail,
        "the other member still passes after the careless repair, so there is no regression here: \
         \n{}",
        careless.billing_output
    );
    assert!(
        careless.selected.contains(&before.billing),
        "the check that caught the regression was not selected by the product, so its failure \
         could not count: {:?}",
        careless.selected
    );

    let complete = half(&finding, Repair::Complete);
    assert_eq!(
        complete.checkout,
        CheckStatus::Pass,
        "{}",
        complete.checkout_output
    );
    assert_eq!(
        complete.billing,
        CheckStatus::Pass,
        "{}",
        complete.billing_output
    );

    let blocked = careless.stayed_open
        && !careless.green
        && careless.severity == AggregateSeverity::NotReady
        && careless.blocking.contains(&before.billing);
    let closes =
        !complete.stayed_open && complete.green && complete.severity == AggregateSeverity::Green;

    // The weight SURE's own node proposer put on the checks that produced this
    // row — `ScriptRole::Test` is `must_fix` in its table — read off the results
    // rather than out of the manifest, so the case is graded on an outcome and
    // still says how heavily the product weighed it.
    let weight = before
        .results
        .iter()
        .map(|result| result.severity)
        .max_by_key(|severity| severity.rank());

    Measurement::Outcome {
        held: blocked && closes,
        severity: weight,
        reading: Reading {
            statements: vec![
                format!(
                    "`{}` is shipped with one member whose own check fails and one whose check \
                     passes; the failing check says, in the project's own words: {:?}",
                    "packages/checkout",
                    before
                        .output_of(&before.checkout)
                        .lines()
                        .find(|line| line.contains("expected"))
                        .unwrap_or("(no line naming an expectation)")
                ),
                format!(
                    "with {} applied, `packages/checkout`'s check is `{}` and `packages/billing`'s is \
                     `{}`; the product selected {:?} as the checks that must pass, the run aggregated \
                     to `{}`, `is_green()` is {}, the lifecycle resolved {} finding(s), and the finding \
                     is still open: {}",
                    Repair::Careless.as_str(),
                    careless.checkout.as_str(),
                    careless.billing.as_str(),
                    careless
                        .selected
                        .iter()
                        .map(CheckId::as_str)
                        .collect::<Vec<_>>(),
                    careless.severity.as_str(),
                    careless.green,
                    careless.resolved,
                    careless.stayed_open
                ),
                format!(
                    "with {} applied, both members' checks are `{}` and `{}`, the run aggregated to \
                     `{}`, `is_green()` is {}, the lifecycle resolved {} finding(s), and the finding \
                     is still open: {} — the summary a person reads is {} line(s)",
                    Repair::Complete.as_str(),
                    complete.checkout.as_str(),
                    complete.billing.as_str(),
                    complete.severity.as_str(),
                    complete.green,
                    complete.resolved,
                    complete.stayed_open,
                    complete.summary.lines().count()
                ),
                format!(
                    "the command the runner really started for each member is read out of the member's \
                     own manifest by SURE's discovery and asserted to be a `node` command; the runs \
                     that produced the results above are {}",
                    before
                        .ran
                        .iter()
                        .map(|ran| ran.command.as_str())
                        .collect::<Vec<_>>()
                        .join(" and ")
                ),
                String::from(
                    "the check that catches the regression was not named by anything here: it was \
                     selected by `sure_core::repair_impact::select_impacted_checks`, which is the \
                     rule this half of the case is about",
                ),
                format!(
                    "the weight on the checks that produced this row is `{}`, which is what SURE's own \
                     node proposer gives a declared test script; it is read off the results and not out \
                     of the manifest, so this outcome-graded case still records how heavily the product \
                     weighed it",
                    weight.map_or("nothing", Severity::as_str)
                ),
            ],
            surfaces: vec![
                String::from("crates/sure-core/tests/acceptance_report_runner.rs"),
                String::from("sure_core::process::run"),
                String::from("sure_core::checks::node::NodeChecks::of"),
                String::from("sure_core::aggregation::aggregate_run"),
                String::from("sure_core::recheck_lifecycle::reconcile"),
                String::from("sure_core::repair_impact::select_impacted_checks"),
            ],
            anchors: vec![RowAnchor {
                subject: AnchorSubject::Directory.as_str().to_owned(),
                location: format!("{FIXTURES}/{FIXTURE}"),
                locator: String::from(
                    "the fixture project, copied under target/tmp before any check ran",
                ),
            }],
            rule: String::from(
                "a repair may close a finding only on new passing evidence, and a repair that breaks \
                 something else may not close it: the case is met when the careless repair leaves the \
                 finding open with the regressed member blocking a run that is not green, and the \
                 complete repair closes it with every selected check passing. Both halves are \
                 measured, so the block is not a predicate nothing can satisfy",
            ),
        },
    }
}
