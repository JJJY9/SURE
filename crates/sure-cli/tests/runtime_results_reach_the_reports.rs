//! `P18-T011`'s clause 1, pinned at both renderers a reader actually opens.
//!
//! > *Runtime results reach the human and machine reports through the existing
//! > renderers.*
//!
//! The route was already there — `crate::check::finished` hands
//! [`human_report::render_verdict`] the run's own schedule and report, and
//! `crate::check::verdict_machine` serializes [`json_report::build_json_report`]
//! into the frame — so the two tests here call those two renderers with what a
//! real run of the pipeline produced and assert that **the answer the run
//! produced for a scheduled check is the sentence a person reads and the
//! sentence a script reads**.
//!
//! # What is a runtime result here
//!
//! The project declares `scripts.test` and a package manager, so the check is
//! planned rather than left as a declaration; the user's own configuration file
//! (outside the project, where only the user's own file may grant) allows
//! execution, so the plan admits it. The runner is
//! `ProcessRunner::new` over a [`Cancellation`] this file cancels **before the
//! run begins** — the product's own runner and a real cancellation, which
//! `sure_core::process` reads before it starts anything — so the check is
//! carried all the way to the runner and the row that comes back is the
//! runner's own answer for a process that did not start. Nothing is started on
//! the machine that grades this, which is what makes the fixture usable here at
//! all.
//!
//! # The half that is the false green
//!
//! The second test runs the same project with no grant at all, through the
//! product's own entry point ([`check::run_with`](sure_cli::check::run_with)).
//! The check is then refused by the plan and the report has to say so: listed as
//! not checked with the frozen sentence, not ready for hand-off in the machine
//! report, and never a pass. A build that dropped the row would satisfy the
//! first test and fail here.
//!
//! # What these two tests do not measure
//!
//! The CLI's runner is not injected: `check::run_with` takes no runner, so the
//! first test builds the run the way `crate::check` builds it (`Config`,
//! `Authority::execution()`, `store: None`) and hands it a runner that starts
//! nothing. What that pins is the renderers and the settings route between the
//! run and them — not that `crate::check` passes those settings, which the
//! second test pins from the other side, with the product's own entry point.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use sure_cli::check::run_with;
use sure_cli::human_report::{HumanReportSettings, render_verdict};
use sure_cli::json_report::build_json_report;
use sure_cli::report::Report;
use sure_core::config::{Authority, Config};
use sure_core::coverage_summary::summarize;
use sure_core::paths::Paths;
use sure_core::pipeline::{Pipeline, PipelineOutcome, Purpose};
use sure_core::planned_check_runner::ProcessRunner;
use sure_core::process::Cancellation;
use sure_core::status::{CheckResult, CheckStatus, NotCheckedReason};

/// A scratch machine: a project, and SURE's own locations beside it.
struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn new(test: &str) -> Self {
        let root = sure_testkit::scratch::directory("runtime results", test);
        std::fs::create_dir_all(root.join("project"))
            .unwrap_or_else(|error| panic!("cannot create the project: {error}"));
        Self { root }
    }

    fn project(&self) -> PathBuf {
        self.root.join("project")
    }

    fn paths(&self) -> Paths {
        Paths::from_roots(self.root.join("data"), self.root.join("config"))
            .expect("the scratch locations are absolute")
    }

    fn write(&self, relative: &str, contents: &str) {
        let full = self.project().join(relative);
        if let Some(parent) = full.parent() {
            std::fs::create_dir_all(parent)
                .unwrap_or_else(|error| panic!("cannot create {}: {error}", parent.display()));
        }
        std::fs::write(&full, contents)
            .unwrap_or_else(|error| panic!("cannot write {}: {error}", full.display()));
    }

    /// The user's own configuration file, outside the project.
    fn write_user_config(&self, contents: &str) {
        let path = self.paths().user_config_file();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .unwrap_or_else(|error| panic!("cannot create {}: {error}", parent.display()));
        }
        std::fs::write(&path, contents)
            .unwrap_or_else(|error| panic!("cannot write {}: {error}", path.display()));
    }
}

/// A Node project whose one declared check SURE plans: a `test` script and the
/// package manager that runs it.
///
/// Nothing about this project is broken. The check is a command, which is what
/// separates it from the declaration rows a manifest with no script produces;
/// what stops it running here is the cancellation below, not the project.
fn a_project_whose_check_is_planned(fixture: &Fixture) {
    fixture.write(
        "package.json",
        r#"{"name":"runtime-results","version":"1.0.0","private":true,"packageManager":"npm@10.9.0","scripts":{"test":"node src/totals.test.js"}}"#,
    );
    fixture.write("src/totals.js", "module.exports = 1;\n");
    fixture.write("src/totals.test.js", "process.exit(0);\n");
}

/// The runner the product's own runner is, with the stop already asked for.
///
/// `sure_core::process` reads this before it starts anything, so a run over this
/// fixture reaches the runner and starts no process on the machine grading it.
/// The stop is asked for here rather than inside a fake so that what the report
/// carries is the product's answer for a real cancelled run.
fn a_runner_that_starts_nothing() -> ProcessRunner {
    let stop = Cancellation::new();
    stop.cancel();
    ProcessRunner::new(stop)
}

/// The run `crate::check` would make, with a runner that starts nothing.
fn the_run(fixture: &Fixture) -> (Config, PipelineOutcome) {
    let config = Config::default();
    let runner = a_runner_that_starts_nothing();
    let authority = Authority::load(&fixture.project(), &fixture.paths().user_config_file())
        .unwrap_or_else(|error| panic!("cannot read the fixture's configuration: {error}"));
    let outcome = Pipeline {
        project: &fixture.project(),
        purpose: Purpose::Check,
        config: &config,
        execution: authority.execution(),
        store: None,
        goal: None,
        analysis: Default::default(),
        external_commands: &[],
        runner: &runner,
    }
    .run();
    (config, outcome)
}

fn run_of(outcome: &PipelineOutcome) -> &sure_core::pipeline::RunOutcome {
    outcome
        .run
        .as_ref()
        .expect("the pipeline finished without a run outcome")
}

/// The row the run holds for the project's declared check.
fn row_for_the_declared_check(outcome: &PipelineOutcome) -> CheckResult {
    let run = run_of(outcome);
    let title = sure_core::discover::node::ScriptRole::Test.plain_description();
    run.report
        .results()
        .iter()
        .find(|result| result.title == title)
        .cloned()
        .unwrap_or_else(|| {
            panic!(
                "the run holds no row for {title:?}, so it says nothing about the one check this \
                 project declares. It holds: {:?}",
                run.report
                    .results()
                    .iter()
                    .map(|result| (result.title.as_str(), result.status))
                    .collect::<Vec<_>>()
            )
        })
}

/// The one entry of the machine report's `not_checked` array that is this check.
fn machine_entry<'a>(report: &'a serde_json::Value, id: &str) -> &'a serde_json::Value {
    report["not_checked"]
        .as_array()
        .unwrap_or_else(|| panic!("the machine report carries no not_checked array: {report}"))
        .iter()
        .find(|entry| entry["id"] == id)
        .unwrap_or_else(|| {
            panic!("the machine report does not list the check {id} as not checked: {report}")
        })
}

#[test]
fn a_runtime_result_reaches_the_human_and_the_machine_report() {
    let fixture = Fixture::new("granted");
    a_project_whose_check_is_planned(&fixture);
    fixture.write_user_config("execution:\n  mode: host_confirmed\n");
    let (_config, outcome) = the_run(&fixture);
    let run = run_of(&outcome);

    // The check was planned and admitted: this is a check the runner was handed,
    // not a declaration and not a refusal.
    assert_eq!(
        run.schedule.len(),
        1,
        "the plan holds {:?}",
        run.schedule
            .checks()
            .iter()
            .map(|check| check.proposal().title())
            .collect::<Vec<_>>()
    );
    let row = row_for_the_declared_check(&outcome);
    assert_eq!(
        row.status,
        CheckStatus::Error,
        "the runner's answer for a process that did not start is not an error: {row:?}"
    );
    assert!(
        row.blocks_green(),
        "a critical check the runner answered is not blocking: {row:?}"
    );
    assert!(
        !row.reason.trim().is_empty(),
        "the runner's answer carries no sentence: {row:?}"
    );

    // The human report, rendered the way `crate::check::finished` renders it.
    let human = render_verdict(
        &run.verdict,
        HumanReportSettings {
            color: false,
            schedule: Some(&run.schedule),
            run_report: Some(&run.report),
            every_stage_ran: true,
            no_project_found: false,
        },
    );
    assert!(
        human.contains(&row.title),
        "the human report does not name the check the run held a row for:\n{human}"
    );
    assert!(
        human.contains(&row.reason),
        "the human report does not carry the run's own sentence for the check ({:?}):\n{human}",
        row.reason
    );
    // And the coverage line, which only the settings route prints: the fallback
    // in `human_report` lists the rows but never counts them against the plan.
    let summary = summarize(&run.schedule, &run.report, &run.verdict.capability);
    assert!(
        human.contains(&summary.plain_summary()),
        "the human report does not carry the coverage sentence ({:?}), so it was rendered without \
         the run's own schedule and report:\n{human}",
        summary.plain_summary()
    );

    // The machine report, rendered the way `crate::check::verdict_machine` does.
    let machine = serde_json::to_value(build_json_report(&run.verdict))
        .expect("a JsonReport is made of JSON values");
    let entry = machine_entry(&machine, row.id.as_str());
    assert_eq!(entry["title"], row.title);
    assert_eq!(
        entry["reason"], row.reason,
        "the machine report does not carry the run's own sentence for the check"
    );
    assert_eq!(entry["is_critical"], true);
    assert_eq!(
        machine["aggregate"]["severity"], "not_enough_checked",
        "a run whose check did not produce a result is not `not_enough_checked`"
    );
    assert_eq!(machine["aggregate"]["is_green"], false);
    assert_eq!(machine["ready_for_hand_off"], false);
}

#[test]
fn a_check_the_plan_refused_reaches_both_reports_as_not_checked() {
    let fixture = Fixture::new("refused");
    a_project_whose_check_is_planned(&fixture);
    // No grant anywhere: the project's own file cannot give one, and there is no
    // user file yet. So the check is planned and refused, and the runner is
    // never reached — which is why this half can go through the product's own
    // entry point rather than through a run built here.
    let report = run_with(Purpose::Check, &fixture.paths(), &fixture.project(), None);
    let check = match &report {
        Report::Check(check) => check,
        other => panic!("the run did not produce a check report: {other:?}"),
    };
    let run = check.run.run.as_ref().expect("the run produced no outcome");
    let row = run
        .report
        .results()
        .iter()
        .find(|result| {
            result.title == sure_core::discover::node::ScriptRole::Test.plain_description()
        })
        .cloned()
        .unwrap_or_else(|| {
            panic!(
                "the report holds no row for the check the plan refused. It holds: {:?}",
                run.report
                    .results()
                    .iter()
                    .map(|result| (result.title.as_str(), result.status))
                    .collect::<Vec<_>>()
            )
        });
    assert_eq!(
        row.status,
        CheckStatus::Skipped,
        "a refused check is a skipped one: {row:?}"
    );
    assert_eq!(
        row.not_checked_reason,
        Some(NotCheckedReason::ExecutionNotAuthorized),
        "the row does not carry the reason the plan refused the check: {row:?}"
    );
    assert!(row.blocks_green(), "{row:?}");

    let human = report.human_text();
    assert!(
        human.contains(&row.title),
        "the human report dropped the check the plan refused:\n{human}"
    );
    assert!(
        human.contains(&row.reason),
        "the human report does not say why the check did not run ({:?}):\n{human}",
        row.reason
    );

    let frame = report.frame();
    let machine = &frame["details"]["report"];
    let entry = machine_entry(machine, row.id.as_str());
    assert_eq!(entry["reason"], row.reason);
    assert_eq!(entry["is_critical"], true);
    assert_eq!(machine["aggregate"]["severity"], "not_enough_checked");
    assert_eq!(machine["ready_for_hand_off"], false);
    assert_eq!(frame["details"]["green"], false);
    assert_ne!(report.exit_code(), 0, "a not-checked project is not a pass");
}
