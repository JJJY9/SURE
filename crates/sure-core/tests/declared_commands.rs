//! A declared check SURE cannot run is a check with an answer, and the answer
//! reaches the verdict.
//!
//! `P18-T011`'s clause two is two sentences: *"A critical result that is not a
//! pass blocks green, and an unreported critical check does too."* The second
//! half has a shape that is easy to miss, because the check *was* reported —
//! `MissingCommand::not_checked` builds the row, and its unit test asserts the
//! scope-limit split that decides whether the row blocks. What was wrong was one
//! layer out: `aggregate_run` walked the schedule, a declared check was never
//! proposed so its id was never in the schedule, and the row was left over in
//! `RunReport::unscheduled` — a field documented as *"reported and not
//! aggregated"* that **no renderer and no product path reads**.
//!
//! So the value's own test passed while the product dropped the value, which is
//! the purest form of the false green this repository is built against: a
//! property proved about a value nothing gives a chance to matter.
//!
//! # What this file holds, and what it does not
//!
//! Every assertion below is made **through the pipeline** rather than against
//! `MissingCommand` directly, because the defect was never in the type. The
//! fixture is a manifest with one script a runner can carry out, one declaration
//! no runner accepts, and one name with no value at all, and the run is
//! `sure check`'s own — discovered, planned, enforced, aggregated, summarised.
//!
//! **The mode is inspecting, so nothing in this fixture is executed.** The
//! runner is the product's own with its cancellation already asked for, so a
//! check that somehow reached it would come back as an error rather than as a
//! process. Nothing here needs a runner to work; it needs a pipeline to finish.
//!
//! # What is not claimed
//!
//! **Not that the manifest is read the way a package manager reads it.** SURE's
//! own reader decides what `"test": ["jest"]` is, and that decision is
//! `crates/sure-core/src/discover/node.rs`'s and is tested there. What is
//! measured here is what happens to the answer afterwards.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};

use sure_core::config::{Config, ExecutionSettings};
use sure_core::discover::node::{MANIFEST, ScriptRole};
use sure_core::pipeline::{Pipeline, Purpose, RunOutcome};
use sure_core::planned_check_runner::ProcessRunner;
use sure_core::process::Cancellation;
use sure_domain::status::{CheckResult, CheckStatus, NotCheckedReason};

/// A manifest with one command, one declaration no runner accepts, and one name
/// with no value.
///
/// The three roles are the point of the fixture rather than decoration: `build`
/// is proposed and is the run's one scheduled check — so the plan is not empty
/// and the declaration rows are not the whole of the report — `test` is the
/// critical declaration whose kind is a defect rather than a scope, and `lint`
/// and `typecheck` are the two controls below.
const A_BROKEN_MANIFEST: &str =
    r#"{"name":"declared","scripts":{"build":"tsc -b","test":["jest"],"lint":null}}"#;

/// The sentence the vocabulary cannot write and SURE can, quoted from
/// `MissingKind::NotACommand`'s own arm rather than paraphrased: the line a
/// person reads about this row is the reason `MissingCommand::not_checked`
/// replaced the generic one.
const NOT_A_COMMAND_SENTENCE: &str =
    "What your project declares for this is not a command SURE can run.";

#[test]
fn a_critical_declaration_that_cannot_run_blocks_green_and_is_counted() {
    let root = fixture();
    let run = check(&root);

    // The run is a real run: the one script with a command was proposed, and it
    // has a row of its own. Without this the test would pass on an empty plan,
    // where every row is a declaration and nothing was ever scheduled.
    assert!(
        run.schedule
            .checks()
            .iter()
            .any(|scheduled| scheduled.proposal().title() == ScriptRole::Build.plain_description()),
        "the fixture's one runnable script was not proposed, so this is not the run it is \
         measuring: {:?}",
        rows(&run)
    );

    // One: the declaration's answer is a row of the report. Before this task the
    // row was built and then dropped into `unscheduled`, so everything below
    // asserted nothing about the product.
    let test = row(&run, ScriptRole::Test);
    assert_eq!(
        test.status,
        CheckStatus::Skipped,
        "the test role's row is not a not-run row: {test:?}"
    );
    assert_eq!(
        test.not_checked_reason,
        Some(NotCheckedReason::UnknownReason),
        "the test role's row carries a different reason, so the scope-limit split this test is \
         about is not the one being measured: {test:?}"
    );
    assert!(test.critical, "the test role is not critical: {test:?}");
    assert_eq!(
        test.reason, NOT_A_COMMAND_SENTENCE,
        "the line a person reads about this row is not SURE's own sentence for a declaration no \
         runner accepts"
    );

    // Two: and the verdict was computed over it. `blocks_green` is the domain's
    // rule applied to this row, and the aggregate carries its answer.
    assert!(
        test.blocks_green(),
        "a critical check that cannot run because the manifest declares something no runner \
         accepts does not block green: {test:?}"
    );
    assert!(
        run.report.blocking().any(|check| check.id() == &test.id),
        "the run's own blocking list does not name the test declaration, so the verdict a \
         renderer reads is greener than this row: {:?}",
        run.report
            .blocking()
            .map(|c| c.id().clone())
            .collect::<Vec<_>>()
    );
    assert!(
        run.report
            .aggregate()
            .coverage
            .critical_not_checked
            .contains(&test.id),
        "the aggregate's own coverage does not name the test declaration: {:?}",
        run.report.aggregate().coverage.critical_not_checked
    );

    // Three: and the summary a person reads first counts it, because a total
    // that skipped this row would answer "SURE checked all N checks" about a
    // report that holds it as not checked.
    assert!(
        run.coverage
            .not_checked
            .iter()
            .any(|entry| entry.check_id == test.id.as_str()),
        "the coverage summary does not list the test declaration: {:?}",
        run.coverage.not_checked
    );
    assert!(
        !run.coverage.is_complete(),
        "the coverage summary calls the run complete while a critical check is not checked"
    );
    assert!(
        !run.coverage.plain_summary().contains("checked all"),
        "the summary claims everything was checked: {}",
        run.coverage.plain_summary()
    );
    assert!(
        !run.report.is_green(),
        "a run with a critical declaration it could not carry out reports itself green"
    );

    // And the controls, which are the other half of the rule: the split is the
    // *kind*'s and not a blanket rule about declarations. A role the project
    // never wrote is a scope limit and does not block, and a declaration that is
    // not critical is reported without holding the run out of green.
    let typecheck = row(&run, ScriptRole::TypeCheck);
    assert_eq!(
        typecheck.not_checked_reason,
        Some(NotCheckedReason::NotApplicable),
        "the typecheck role's row is not the scope-limit kind: {typecheck:?}"
    );
    assert!(
        !typecheck.blocks_green(),
        "a check the project never declared, on a role that is not critical, blocks green: \
         {typecheck:?}"
    );
    let lint = row(&run, ScriptRole::Lint);
    assert_eq!(
        lint.not_checked_reason,
        Some(NotCheckedReason::UnknownReason),
        "the lint role's row is not the kind this fixture declares it as: {lint:?}"
    );
    assert!(
        !lint.critical,
        "the fixture's lint role is critical, which moves the control out from under this test"
    );
    assert!(
        !lint.blocks_green(),
        "a declaration that is not critical holds the run out of green: {lint:?}"
    );
    assert!(
        !run.report
            .blocking()
            .any(|check| check.id() == &lint.id || check.id() == &typecheck.id),
        "the run's blocking list names a row that does not block green: {:?}",
        run.report
            .blocking()
            .map(|c| c.id().clone())
            .collect::<Vec<_>>()
    );

    // The rows are the report's and the split is the vocabulary's: what a row
    // carries is what the type decided, read here off the shipped row rather
    // than restated beside it.
    assert!(
        !test
            .not_checked_reason
            .expect("the test row said why it did not run")
            .is_scope_limit(),
        "a declaration no runner accepts has to be a gap rather than a scope limit, and the \
         vocabulary says otherwise: {test:?}"
    );
}

/// A project directory with the manifest above and a lockfile naming its runner.
///
/// The lockfile is what makes the manifest's `"build"` script a command SURE can
/// carry out: without one there is no runner to carry it out *with*, and every
/// role in the fixture would be a gap of a different kind.
fn fixture() -> PathBuf {
    let root = sure_testkit::scratch::directory("declared-commands", "broken-manifest");
    std::fs::write(root.join(MANIFEST), A_BROKEN_MANIFEST).expect("the manifest is written");
    std::fs::write(root.join("pnpm-lock.yaml"), "").expect("the lockfile is written");
    root
}

/// `sure check` over that project, with nothing allowed to run.
fn check(root: &Path) -> RunOutcome {
    let config = Config::default();
    let stop = Cancellation::new();
    stop.cancel();
    let runner = ProcessRunner::new(stop);
    Pipeline {
        project: root,
        purpose: Purpose::Check,
        config: &config,
        execution: ExecutionSettings::inspect_only(),
        store: None,
        goal: None,
        analysis: Default::default(),
        external_commands: &[],
        runner: &runner,
    }
    .run()
    .run
    .expect("the pipeline finished without a run outcome")
}

/// The row the run holds for one role.
fn row(run: &RunOutcome, role: ScriptRole) -> &CheckResult {
    let title = role.plain_description();
    run.report
        .results()
        .iter()
        .find(|result| result.title == title)
        .unwrap_or_else(|| {
            panic!(
                "the run holds no row for {role:?}, so it says nothing about that role: {:?}",
                rows(run)
            )
        })
}

/// Every row's title and status, for a failure message.
fn rows(run: &RunOutcome) -> Vec<(String, CheckStatus)> {
    run.report
        .results()
        .iter()
        .map(|result| (result.title.clone(), result.status))
        .collect()
}
