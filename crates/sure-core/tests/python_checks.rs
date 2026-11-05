//! `P4-T003`'s acceptance, checked from outside the crate.
//!
//! The task's sentence is one sentence:
//!
//! > *Declared import/test/lint/type checks use available tools without silent
//! > package installation.*
//!
//! Like `node_checks.rs`, this file works over **real directories**: manifests
//! written to disk, the product's own discovery reading them, and the checks
//! layer standing on what the discovery found. The unit tests in
//! `checks/python.rs` hold the rules against hand-built discovery results; this
//! file holds that the rules are reachable — that a `pyproject.toml` a person
//! would actually write reaches them, that the identifiers are stable across two
//! independent readings, and that the TOML-to-tools path the unit tests skip is
//! the one the product runs.
//!
//! # What the acceptance's four words turn into, and why there are four
//!
//! `import`, `test`, `lint` and `type` are not four roles: three of them are
//! [`CommandRole`]s and `import` is not a role at all. `checks/python.rs` argues
//! that at length; the part this file has to hold is the consequence, which is
//! that **every role the acceptance names produces either a plan entry or a
//! skipped result** — a cover, not a count. A report that says nothing about
//! tests in a project that has no test tool is the failure this guards, and it is
//! invisible in a count.
//!
//! # The half of the sentence that is about installing
//!
//! *Without silent package installation* is the clause with teeth, and it is
//! checked here in the only two places it can be: **no check may need the
//! install permission**, and **the thing that does install must not be a check**.
//! The first is asked of the domain's own permission mapping rather than of this
//! module's table — a proposal's requirements are a set of [`ActionKind`]s, and
//! `ExecutionRequirements::blocked_by` says which permission those need. The
//! second is asked by looking for the install command anywhere in the schedule.
//!
//! What is *not* claimed here, and cannot be: that a check's command does no
//! environment work of its own inside the runner. SURE does not compose an
//! install and does not claim the runner never does.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use sure_core::checks::MissingKind;
use sure_core::checks::python::PythonChecks;
use sure_core::discover::python::{CommandRole, MANIFEST};
use sure_core::discover::{DiscoverOptions, Discovery, Ecosystem, Findings, discover};
use sure_core::planned_work::PlannedWork;
use sure_core::schedule::{CheckReason, CheckSchedule, ExecutionRequirements, PlanBuilder};
use sure_domain::execution::{
    ActionKind, ExecutionDecision, ExecutionMode, ExecutionPermissions, Permission,
};
use sure_domain::ids::FingerprintId;
use sure_domain::status::CheckStatus;

/// A scratch project that removes itself.
///
/// Under the workspace's own `target/` so the fixture is on the same volume as
/// the checkout, with a space and a non-ASCII character in the path — the
/// cheapest way to make every path below one two platforms disagree about, which
/// is the discipline `CLAUDE.md` asks for and which `discover_python.rs`
/// established.
struct Fixture {
    project: PathBuf,
}

impl Fixture {
    fn new(test: &str) -> Self {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let unique = format!(
            "{test}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        );
        let project = sure_testkit::repository_root()
            .join("target")
            .join("tmp")
            .join("sure 指纹 python")
            .join(unique);
        std::fs::create_dir_all(&project)
            .unwrap_or_else(|error| panic!("cannot create {}: {error}", project.display()));
        Self { project }
    }

    fn path(&self) -> &Path {
        &self.project
    }

    /// Write a file inside the project, creating the directories above it.
    fn write(&self, relative: &str, contents: &str) -> &Self {
        let full = self.project.join(relative);
        if let Some(parent) = full.parent() {
            std::fs::create_dir_all(parent)
                .unwrap_or_else(|error| panic!("cannot create {}: {error}", parent.display()));
        }
        std::fs::write(&full, contents)
            .unwrap_or_else(|error| panic!("cannot write {}: {error}", full.display()));
        self
    }

    fn discover(&self) -> Discovery {
        discover(&self.project, &DiscoverOptions::default())
            .unwrap_or_else(|error| panic!("{error}"))
    }

    /// The Python findings, or `None` when discovery reported no Python project.
    fn python_or_none(&self) -> Option<sure_core::discover::PythonProject> {
        let found = self.discover();
        let report = found.report(Ecosystem::Python)?;
        match &report.findings {
            Findings::Python(python) => Some((**python).clone()),
            other => panic!("the Python report carried {other:?}"),
        }
    }

    fn python(&self) -> sure_core::discover::PythonProject {
        self.python_or_none().unwrap_or_else(|| {
            panic!(
                "this fixture is a Python project and discovery did not report one; \
                 it looked for {:?}",
                self.discover()
                    .looked_for()
                    .iter()
                    .map(|ecosystem| ecosystem.as_str())
                    .collect::<Vec<_>>()
            )
        })
    }

    fn checks(&self) -> PythonChecks {
        PythonChecks::of(&self.python(), &self.project)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        // Failing to clean up must not turn a passing test into a failing one.
        drop(std::fs::remove_dir_all(&self.project));
    }
}

/// A plan built from these checks under a mode and a permission set.
///
/// Refuses to return a plan when anything was refused: `PlanBuilder::propose`
/// remembers a refusal, and a test that read the schedule without reading the
/// refusals would be checking a plan that is quietly missing a check — the exact
/// shape of defect this repository ranks above a visible error.
fn plan(
    checks: &PythonChecks,
    mode: ExecutionMode,
    permissions: ExecutionPermissions,
) -> CheckSchedule {
    let mut builder = PlanBuilder::new(mode, permissions);
    checks.add_to(&mut builder);
    assert!(
        builder.refused().is_empty(),
        "the checks layer proposed something the builder refused: {:?}",
        builder.refused()
    );
    builder.build()
}

/// Inspect-only permissions, with project code allowed by the *permission*.
///
/// The combination a permission-only reading of the acceptance would call
/// runnable, and which the mode still refuses.
fn inspect_only_but_permitted() -> ExecutionPermissions {
    ExecutionPermissions {
        run_project_code: true,
        ..ExecutionPermissions::inspect_only()
    }
}

/// Host-confirmed, with the permission actually granted.
fn host_confirmed() -> ExecutionPermissions {
    ExecutionPermissions {
        run_project_code: true,
        ..ExecutionPermissions::inspect_only()
    }
}

/// Every title either list accounts for, sorted.
///
/// The cover, as a value: a role missing from both lists is a role SURE says
/// nothing about, and nothing else in these tests would notice.
fn covered(checks: &PythonChecks, fingerprint: &FingerprintId) -> Vec<String> {
    let mut titles: Vec<String> = checks
        .planned()
        .iter()
        .map(|work| work.proposal().title().to_owned())
        .chain(
            checks
                .not_checked(fingerprint)
                .iter()
                .map(|result| result.title.clone()),
        )
        .collect();
    titles.sort();
    titles
}

#[test]
fn every_fixture_sits_at_a_path_two_platforms_disagree_about() {
    // The discipline `CLAUDE.md` asks for, held rather than asserted in a
    // comment: a space and a non-ASCII character in every path below, so that a
    // rule which happens to work on this machine's ordinary paths fails here
    // instead of on a user's. If the fixture stopped carrying them, every other
    // test in this file would keep passing and this one would not.
    let fixture = Fixture::new("hostile-path");
    let path = fixture.path().to_string_lossy().into_owned();
    assert!(path.contains(' '), "no space in {path}");
    assert!(
        !path.is_ascii(),
        "no non-ASCII character in {path}, so nothing here tests one"
    );
    assert!(
        path.replace('\\', "/").contains("sure 指纹 python/"),
        "the fixture is not where this file says it is: {path}"
    );
}

/// A project a person would write: PEP 621 metadata, tools, a build backend,
/// and a uv lockfile.
const COMPLETE: &str = r#"
[project]
name = "demo"
version = "0.1.0"
requires-python = ">=3.11"
dependencies = ["pytest>=8", "ruff>=0.4", "mypy>=1.8", "setuptools>=68"]

[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"
"#;

/// A project with no tools and no installer.
const BARE: &str = r#"
[project]
name = "demo"
version = "0.1.0"
"#;

#[test]
fn a_real_manifest_reaches_the_checks_layer_with_the_tools_it_declares() {
    // The TOML path the unit tests in `checks/python.rs` deliberately skip: a
    // manifest as a file on disk, read by the product's own discovery, with the
    // tool rows that discovery built out of `dependencies`.
    let fixture = Fixture::new("real-manifest");
    fixture
        .write("pyproject.toml", COMPLETE)
        .write("uv.lock", "");
    let checks = fixture.checks();

    assert_eq!(checks.component(), Some(MANIFEST));
    assert_eq!(
        commands(&checks),
        vec![
            (CommandRole::Test, "uv run pytest".to_owned()),
            (CommandRole::Lint, "uv run ruff check .".to_owned()),
            (CommandRole::TypeCheck, "uv run mypy .".to_owned()),
            (CommandRole::Build, "uv build".to_owned()),
        ],
        "a project that declares all four tools does not get the four checks \
         its declarations name"
    );
    assert!(
        checks.missing().is_empty(),
        "nothing is missing in this project: {:?}",
        checks.missing()
    );

    // And the install, which this project does have a plan for.
    let step = checks.install().expect("uv.lock names an installer");
    assert_eq!(step.command(), "uv sync");
    assert_eq!(step.declared_in(), "uv.lock");
}

#[test]
fn nothing_the_plan_holds_needs_the_permission_to_install_anything() {
    // **The acceptance clause, asked of the domain's own mapping.** For every
    // check over every project shape below, the permissions its actions require
    // must not include `InstallDependencies`. Asked through
    // `ExecutionRequirements::blocked_by`, so it is the same function the consent
    // path uses rather than a second reading of the same table.
    let shapes: Vec<(&str, Fixture)> = vec![
        ("a complete project", Fixture::new("no-install-complete")),
        (
            "a project with no installer",
            Fixture::new("no-install-bare"),
        ),
        ("a poetry project", Fixture::new("no-install-poetry")),
    ];
    shapes[0]
        .1
        .write("pyproject.toml", COMPLETE)
        .write("uv.lock", "");
    shapes[1].1.write("pyproject.toml", BARE);
    shapes[2].1.write(
        "pyproject.toml",
        "[tool.poetry]\nname = \"demo\"\nversion = \"0.1.0\"\n",
    );

    let mut seen = 0;
    for (what, fixture) in &shapes {
        let checks = fixture.checks();
        for work in checks.planned() {
            let proposal = work.proposal();
            seen += 1;
            let blocked = proposal
                .requirements()
                .blocked_by(&ExecutionPermissions::inspect_only());
            assert_ne!(
                blocked,
                Some(Permission::InstallDependencies),
                "{what}: {:?} needs the install permission",
                proposal.title()
            );
            assert!(
                !proposal
                    .requirements()
                    .actions()
                    .contains(&ActionKind::InstallDependencies),
                "{what}: {:?} would install packages, which is the one thing a \
                 check must never do",
                proposal.title()
            );
        }
    }
    // Four, and not five: two of the three shapes declare nothing SURE can run.
    // The count is here so that a shape that quietly stopped producing checks
    // fails rather than sweeping an empty set and passing.
    assert_eq!(seen, 4, "the sweep did not visit the checks it claims");

    // The other half, as a positive: the thing that *does* install needs that
    // permission, so its absence from every check above is a difference rather
    // than a permission nothing in this module ever asks for.
    let install = ExecutionRequirements::of(&[ActionKind::InstallDependencies]);
    assert_eq!(
        install.blocked_by(&ExecutionPermissions::inspect_only()),
        Some(Permission::InstallDependencies),
        "an install must not be something inspect-only permissions already allow"
    );
}

#[test]
fn the_install_is_a_step_beside_the_plan_and_never_a_row_inside_it() {
    // **The other half of the clause.** A check can come back as a result, and an
    // install has nothing to say about whether the project is any good — so the
    // install is a value of a type that cannot enter a schedule, and this asks
    // the schedule whether it got in anyway.
    let fixture = Fixture::new("install-beside");
    fixture
        .write("pyproject.toml", COMPLETE)
        .write("uv.lock", "");
    let checks = fixture.checks();
    let step = checks.install().expect("uv.lock names an installer");

    let schedule = plan(&checks, ExecutionMode::HostConfirmed, host_confirmed());
    assert_eq!(schedule.len(), checks.planned().len());
    assert_eq!(schedule.may_run().count(), schedule.len());
    assert!(
        schedule.duplicates().is_empty(),
        "{:?}",
        schedule.duplicates()
    );
    assert!(
        !schedule.checks().iter().any(|entry| {
            entry.proposal().title() == step.plain_description()
                || matches!(
                    entry.proposal().reason(),
                    CheckReason::DeclaredCommand { command, .. } if command == step.command()
                )
        }),
        "the install reached the schedule: {:?}",
        schedule.checks()
    );

    // And a caller that never asks for it gets no install at all: nothing in
    // `add_to` produced one.
    assert_eq!(step.action(), ActionKind::InstallDependencies);
    assert!(
        step.plain_description().contains("not a check"),
        "the line a person reads has to say what this is: {}",
        step.plain_description()
    );
    assert!(
        !schedule
            .checks()
            .iter()
            .any(|entry| entry.proposal().requirements().actions()
                == [ActionKind::InstallDependencies]),
        "a check could still reach an install through its action list"
    );
}

#[test]
fn every_role_the_acceptance_names_is_either_checked_or_reported_as_missing() {
    // **The cover, and the failure it guards is a silence.** A project that
    // declares pytest and nothing else must not produce a report that is quiet
    // about linting: a reader takes the absence of a row for the absence of a
    // problem.
    let fixture = Fixture::new("cover");
    fixture.write(
        "pyproject.toml",
        "[project]\nname = \"demo\"\nversion = \"0.1.0\"\n\
         dependencies = [\"pytest>=8\"]\n",
    );
    let checks = fixture.checks();
    let fingerprint = FingerprintId::generate();

    assert_eq!(
        covered(&checks, &fingerprint),
        vec![
            CommandRole::Build.plain_description().to_owned(),
            CommandRole::Lint.plain_description().to_owned(),
            CommandRole::Test.plain_description().to_owned(),
            CommandRole::TypeCheck.plain_description().to_owned(),
        ]
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>(),
        "the four roles the acceptance and this module argue for are not the \
         four the report accounts for"
    );

    // The declared one is a check; the three undeclared ones are the skipped
    // results, and none of them is green, produced a result, or blocks.
    let results = checks.not_checked(&fingerprint);
    assert_eq!(results.len(), 3, "{:?}", checks.missing());
    for result in &results {
        assert_eq!(result.status, CheckStatus::Skipped, "{}", result.title);
        assert!(!result.status.is_green(), "{}", result.title);
        assert!(!result.status.produced_a_result(), "{}", result.title);
        assert!(result.is_not_checked(), "{}", result.title);
        assert!(
            !result.blocks_green(),
            "a project that declares no {} is not a project SURE should hold \
             out of green: {}",
            result.title,
            result.reason
        );
    }
}

#[test]
fn a_project_that_declares_nothing_still_gets_four_rows_and_no_checks() {
    // The degenerate case, which is also the one a mutation is most likely to
    // turn green: four roles, no commands, and `is_empty` false because the
    // *gaps* are what there is to say.
    let fixture = Fixture::new("bare");
    fixture.write("pyproject.toml", BARE);
    let checks = fixture.checks();

    assert!(checks.planned().is_empty());
    assert_eq!(checks.missing().len(), 4);
    assert!(!checks.is_empty());
    assert!(checks.install().is_none(), "nothing names an installer");
    assert_eq!(checks.not_checked(&FingerprintId::generate()).len(), 4);
}

#[test]
fn a_declaration_written_in_a_table_sure_cannot_read_is_a_gap_about_the_project() {
    // Poetry's `mypy = { version = "^1.8" }` is valid, ordinary, and unreadable
    // to a reader that will not guess. The manifest says `mypy`; SURE's tool list
    // does not; and reporting that as "you declare no type checker" would be a
    // false statement about a file SURE has just read.
    let fixture = Fixture::new("poetry-table");
    fixture
        .write(
            "pyproject.toml",
            "[tool.poetry]\nname = \"demo\"\nversion = \"0.1.0\"\n\n\
         [tool.poetry.dependencies]\npython = \"^3.11\"\n\
         mypy = { version = \"^1.8\", extras = [\"types-requests\"] }\n",
        )
        .write("poetry.lock", "");
    let checks = fixture.checks();

    let gap = checks
        .missing()
        .iter()
        .find(|missing| missing.title() == CommandRole::TypeCheck.plain_description())
        .expect("a table form is not a declaration SURE can run");
    assert_eq!(gap.kind(), &MissingKind::NotReadable);
    assert_ne!(
        gap.kind(),
        &MissingKind::NotDeclared,
        "an unreadable declaration and an absent one are different facts"
    );

    // The other roles are untouched: this manifest says nothing about a linter,
    // and the two gaps must not be rendered as the same finding.
    for role in [CommandRole::Test, CommandRole::Lint, CommandRole::Build] {
        assert_eq!(
            gap_kind(&checks, role),
            MissingKind::NotDeclared,
            "{role:?} is about the project's silence, not about a line SURE \
             could not read"
        );
    }
}

#[test]
fn an_unreadable_declaration_holds_the_run_out_of_green_and_an_absent_one_does_not() {
    // **The pair, and the two fixtures differ only in how one package is
    // written.** Both leave SURE without a test command; the first because the
    // project declares no test tool, the second because it declares one inside a
    // table SURE will not guess at. Both gaps are the same role, so `critical` is
    // the same on both sides and the difference in `blocks_green` is the
    // scope-limit rule and nothing else.
    //
    // It is worth being precise about what is being told apart, because the rule
    // reads the other way round from how it sounds: the *absent* one is out of
    // scope and does **not** hold a run out of green — SURE cannot fault a
    // project for not having a test runner — while the *unreadable* one is a
    // defect in a file SURE has read and does. A report that collapsed the two
    // would either nag every project without tests or quietly accept a broken
    // manifest, and the two failures look nothing alike.
    let silent = Fixture::new("scope-limit-absent");
    silent.write("pyproject.toml", BARE);

    let unreadable = Fixture::new("scope-limit-unreadable");
    unreadable
        .write(
            "pyproject.toml",
            "[tool.poetry]\nname = \"demo\"\nversion = \"0.1.0\"\n\n\
         [tool.poetry.dependencies]\npython = \"^3.11\"\n\
         pytest = { version = \"^8\", extras = [\"dev\"] }\n",
        )
        .write("poetry.lock", "");

    let fingerprint = FingerprintId::generate();
    let blocking = |checks: &PythonChecks| -> Vec<String> {
        checks
            .not_checked(&fingerprint)
            .iter()
            .filter(|result| result.blocks_green())
            .map(|result| result.title.clone())
            .collect()
    };

    let silent = silent.checks();
    assert_eq!(
        gap_kind(&silent, CommandRole::Test),
        MissingKind::NotDeclared
    );
    assert!(
        blocking(&silent).is_empty(),
        "a project that declares no test runner is not a project SURE should \
         hold out of green"
    );

    let unreadable = unreadable.checks();
    assert_eq!(
        gap_kind(&unreadable, CommandRole::Test),
        MissingKind::NotReadable
    );
    assert_eq!(
        blocking(&unreadable),
        vec![CommandRole::Test.plain_description().to_owned()],
        "a manifest SURE cannot read is a defect the user can fix"
    );

    // Which roles this can be true of at all: only the critical ones, because
    // `blocks_green` reads `critical` first and returns false for everything
    // else. Written down so that a later change giving a non-critical role a
    // blocking skipped result is a failing test rather than a surprise.
    let results = unreadable.not_checked(&fingerprint);
    for result in &results {
        if result.critical {
            continue;
        }
        assert!(
            !result.blocks_green(),
            "{} is not critical and must never block: {}",
            result.title,
            result.reason
        );
    }
}

#[test]
fn a_project_that_names_two_environments_is_refused_rather_than_run_through_a_third() {
    // **The case `command_for` gets wrong on its own.** `[tool.poetry]` in the
    // manifest and a `uv.lock` beside it is mid-migration: the discovery answers
    // `None`, its own planner falls through to `python -m pytest`, and that is a
    // third interpreter neither declaration named. Running it produces
    // `No module named pytest` — false about a project that declares pytest.
    let fixture = Fixture::new("two-environments");
    fixture
        .write(
            "pyproject.toml",
            "[tool.poetry]\nname = \"demo\"\nversion = \"0.1.0\"\n\n\
             [tool.poetry.dependencies]\npython = \"^3.11\"\n\
             pytest = \"^8\"\n",
        )
        .write("uv.lock", "");
    let python = fixture.python();

    // Stated as a value rather than as a sentence, so that a later change to the
    // discovery cannot quietly make the refusal unnecessary and leave this test
    // passing for the wrong reason.
    assert_eq!(
        python.managers.agreed(),
        None,
        "the fixture is supposed to be a disagreement"
    );
    assert!(
        python.managers.disagreement().is_some(),
        "and it is a disagreement rather than an empty result"
    );

    let checks = PythonChecks::of(&python, fixture.path());
    assert!(
        checks.planned().is_empty(),
        "a command for an interpreter nobody named is not a check: {:?}",
        checks.planned()
    );
    assert!(checks.install().is_none());

    // The refusal is about the one role the project *does* declare. The other
    // three are gaps about the declaration rather than about the environment,
    // and the order of the two questions is what keeps them apart: a project with
    // no linter and two installers has one problem a person acts on, and the
    // sentence should be about the declaration.
    match checks
        .missing()
        .iter()
        .find(|missing| missing.title() == CommandRole::Test.plain_description())
        .expect("pytest is declared and cannot be run")
        .kind()
    {
        MissingKind::NoRunner { why } => assert!(
            why.contains("installer"),
            "the refusal does not say what is wrong: {why}"
        ),
        other => panic!("the test check is {other:?}"),
    }
    for role in [
        CommandRole::Lint,
        CommandRole::TypeCheck,
        CommandRole::Build,
    ] {
        let missing = checks
            .missing()
            .iter()
            .find(|missing| missing.title() == role.plain_description())
            .unwrap_or_else(|| panic!("{role:?} has a command"));
        assert_eq!(
            missing.kind(),
            &MissingKind::NotDeclared,
            "{role:?} is about the project's silence, not its environment"
        );
    }

    // And no check in the plan may need an install permission, which is the
    // clause that would otherwise be easiest to break on this shape: the tempting
    // "fix" for a project with two environments is to install into one of them.
    let schedule = plan(&checks, ExecutionMode::HostConfirmed, host_confirmed());
    assert!(schedule.is_empty());
}

#[test]
fn a_requirements_file_is_the_manifest_of_last_resort_and_names_itself() {
    // A project with no `pyproject.toml` at all. The tools come from the flat
    // file, and the component names the file SURE read the project from — which
    // is a question about what to open, not a claim about which file wrote the
    // name, and `checks/python.rs` says so.
    let fixture = Fixture::new("requirements-only");
    fixture.write("requirements.txt", "pytest==8.0.0\nruff==0.4.0\n");
    let checks = fixture.checks();

    assert_eq!(checks.component(), Some("requirements.txt"));
    assert_eq!(commands(&checks).len(), 2, "{:?}", checks.missing());
    assert_eq!(
        commands(&checks)
            .into_iter()
            .map(|(role, _)| role)
            .collect::<Vec<_>>(),
        vec![CommandRole::Test, CommandRole::Lint]
    );

    // **A requirements file is installer evidence, and it is the weakest kind.**
    // It is the third tier of `Managers` and the only one that is never a
    // disagreement, so this project does get an install plan — pip's, because pip
    // is what reads the file SURE just read.
    let step = checks.install().expect("a requirements file names pip");
    assert_eq!(step.command(), "python -m pip install -r requirements.txt");
    assert_eq!(step.declared_in(), "requirements.txt");

    // And pip has no `run`, so the tools are run as modules of the interpreter
    // SURE can name rather than through a manager that cannot run them: `pytest`
    // alone would depend on which interpreter is first on the path.
    assert_eq!(commands(&checks)[0].1, "python -m pytest");
}

#[test]
fn two_independent_readings_of_one_project_give_the_same_identifiers() {
    // The identifiers are derived from the component and the role and from
    // nothing else, so they survive a second discovery — which is what makes a
    // result comparable against the run before it. A report whose check ids moved
    // between runs would make every comparison a difference.
    let fixture = Fixture::new("stable-ids");
    fixture
        .write("pyproject.toml", COMPLETE)
        .write("uv.lock", "");
    let first = fixture.checks();
    let second = fixture.checks();

    let ids = |checks: &PythonChecks| -> Vec<String> {
        checks
            .planned()
            .iter()
            .map(|work| work.proposal().id().as_str().to_owned())
            .collect()
    };
    assert_eq!(ids(&first), ids(&second));
    assert_eq!(ids(&first).len(), 4);
    assert_eq!(
        ids(&first)
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        4,
        "two roles share an identifier: {:?}",
        ids(&first)
    );
}

#[test]
fn the_mode_and_not_the_permission_is_what_stops_a_check_from_running() {
    // The three answers, told apart. A permission-only reading of the acceptance
    // would call the middle case runnable; the mode is what refuses, and a user
    // who has already granted the permission is told something true about what is
    // stopping them.
    let fixture = Fixture::new("mode");
    fixture
        .write("pyproject.toml", COMPLETE)
        .write("uv.lock", "");
    let checks = fixture.checks();

    let denied = plan(
        &checks,
        ExecutionMode::InspectOnly,
        ExecutionPermissions::inspect_only(),
    );
    assert_eq!(denied.may_run().count(), 0);
    for entry in denied.checks() {
        assert_eq!(entry.decision(), ExecutionDecision::Denied);
        assert_eq!(
            entry.blocked_by(),
            Some(Permission::RunProjectCode),
            "{} is denied and nothing says what would change that",
            entry.proposal().title()
        );
    }

    // The middle case, and the one a permission-only reading of the acceptance
    // gets wrong: the permission *is* granted, so nothing is missing, and the
    // check still does not run. `blocked_by` answering `None` here is the point —
    // it is the sentence that would otherwise ask a user to grant something they
    // have already granted.
    let consented = plan(
        &checks,
        ExecutionMode::InspectOnly,
        inspect_only_but_permitted(),
    );
    assert_eq!(consented.may_run().count(), 0);
    for entry in consented.checks() {
        assert_eq!(entry.decision(), ExecutionDecision::NeedsConsent);
        assert_eq!(
            entry.blocked_by(),
            None,
            "the permission is granted; the mode is what refuses"
        );
    }

    let allowed = plan(&checks, ExecutionMode::HostConfirmed, host_confirmed());
    assert_eq!(allowed.may_run().count(), allowed.len());
    assert_eq!(allowed.len(), 4);
}

#[test]
fn a_manifest_that_is_not_there_is_not_a_project_that_declares_nothing() {
    // The distinction the whole layer rests on, from the outside: a directory
    // with a `pyproject.toml` that is not a manifest at all. Four "you declare
    // nothing" rows here would be four false statements about a file SURE could
    // not read.
    let fixture = Fixture::new("unreadable");
    fixture.write("pyproject.toml", "this is not TOML = = =\n");
    let checks = fixture.checks();

    assert!(checks.is_empty(), "{checks:?}");
    assert!(checks.component().is_none());
    assert!(checks.not_checked(&FingerprintId::generate()).is_empty());

    // And the discovery still reported a project, so the emptiness above is a
    // statement about the manifest rather than about discovery finding nothing.
    assert!(
        fixture.python_or_none().is_some(),
        "the fixture must still be a Python project for this test to mean \
         anything"
    );
}

#[test]
fn the_command_a_check_names_is_the_line_sure_would_run() {
    // The sentence a person reads, over a real file. `uv run pytest` is SURE's
    // construction out of the installer and a name from its own table; it is not
    // a line the project wrote, and the reason carries the constructed one.
    let fixture = Fixture::new("reason");
    fixture
        .write("pyproject.toml", COMPLETE)
        .write("uv.lock", "");
    let checks = fixture.checks();

    let test = checks
        .planned()
        .iter()
        .map(PlannedWork::proposal)
        .find(|proposal| proposal.title() == CommandRole::Test.plain_description())
        .expect("pytest is declared");
    match test.reason() {
        CheckReason::DeclaredCommand {
            declared_in,
            command,
        } => {
            assert_eq!(declared_in, MANIFEST);
            assert_eq!(command, "uv run pytest");
        }
        other => panic!("the test check's reason is {other:?}"),
    }
    assert!(
        test.reason().names_something(),
        "a proposal whose reason names nothing is refused by the builder"
    );
}

/// Why there is no command for a role, or a panic when there is one.
fn gap_kind(checks: &PythonChecks, role: CommandRole) -> MissingKind {
    checks
        .missing()
        .iter()
        .find(|missing| missing.title() == role.plain_description())
        .unwrap_or_else(|| panic!("{role:?} has a command, so there is no gap"))
        .kind()
        .clone()
}

/// The role and command of every proposed check, in the module's own order.
fn commands(checks: &PythonChecks) -> Vec<(CommandRole, String)> {
    checks
        .planned()
        .iter()
        .map(|work| {
            let proposal = work.proposal();
            let role = CommandRole::ALL
                .iter()
                .copied()
                .find(|role| role.plain_description() == proposal.title())
                .unwrap_or_else(|| panic!("{} is not a role's title", proposal.title()));
            let command = match proposal.reason() {
                CheckReason::DeclaredCommand { command, .. } => command.clone(),
                other => panic!("{} has the reason {other:?}", proposal.title()),
            };
            (role, command)
        })
        .collect()
}
