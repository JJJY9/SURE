//! The cross-layer invariant, checked from outside the crate.
//!
//! **Every command SURE plans is a command SURE can classify, and therefore
//! start.** The discovery layer builds command lines from what a project
//! declares; the execution layer decides whether a command may run, starting
//! with [`sure_core::safety::classify`]. A command the classifier does not know
//! is refused under every mode, so a plan that carries one produces a check
//! that cannot run — and the failure is reported as the project's when it is
//! SURE's. The 2026-10-29 Python repair-loop run found exactly that shape:
//! `python -m ruff` and `python -m mypy` were planned, and the classifier had no
//! rows for them.
//!
//! This file builds real projects on disk for every ecosystem SURE reads,
//! plans the checks the discovery layer proposes, and asserts the invariant over
//! every command. A future tool that is added to a plan without an invocation
//! and a classifier row fails here rather than in a user's report.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use sure_core::checks::MissingKind;
use sure_core::checks::dotnet::DotnetChecks;
use sure_core::checks::go::GoChecks;
use sure_core::checks::java::JavaChecks;
use sure_core::checks::node::NodeChecks;
use sure_core::checks::python::PythonChecks;
use sure_core::checks::rust::RustChecks;
use sure_core::discover::{DiscoverOptions, Discovery, discover};
use sure_core::planned_work::CheckOperation;
use sure_core::safety::{Source, classify};
use sure_core::schedule::{CheckSchedule, PlanBuilder};
use sure_domain::execution::{CommandClass, ExecutionMode, ExecutionPermissions, Permission};

/// A scratch project that removes itself, on the same volume as the checkout.
struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn new(test: &str) -> Self {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let unique = format!(
            "{test}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        );
        let root = sure_testkit::repository_root()
            .join("target")
            .join("tmp")
            .join("sure plan conformance")
            .join(unique);
        std::fs::create_dir_all(&root)
            .unwrap_or_else(|error| panic!("cannot create {}: {error}", root.display()));
        Self { root }
    }

    fn write(&self, relative: &str, contents: &str) -> &Self {
        let full = self.root.join(relative);
        if let Some(parent) = full.parent() {
            std::fs::create_dir_all(parent)
                .unwrap_or_else(|error| panic!("cannot create {}: {error}", parent.display()));
        }
        std::fs::write(&full, contents)
            .unwrap_or_else(|error| panic!("cannot write {}: {error}", full.display()));
        self
    }

    fn discover(&self) -> Discovery {
        discover(&self.root, &DiscoverOptions::default()).unwrap_or_else(|error| panic!("{error}"))
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        match std::fs::remove_dir_all(&self.root) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => {}
        }
    }
}

/// Every permission granted: this test is about classification, not gating.
fn all_granted() -> ExecutionPermissions {
    let mut permissions = ExecutionPermissions::inspect_only();
    for permission in Permission::ALL {
        permissions.set(*permission, true);
    }
    permissions
}

/// Plan everything the discovery found, across every ecosystem, through the
/// same builder the pipeline uses.
fn schedule_of(found: &Discovery) -> CheckSchedule {
    let mut builder = PlanBuilder::new(ExecutionMode::HostConfirmed, all_granted());
    let root: &Path = &found.root;
    for report in &found.ecosystems {
        match &report.findings {
            sure_core::discover::Findings::Python(project) => {
                PythonChecks::of(project, root).add_to(&mut builder);
            }
            sure_core::discover::Findings::Node(project) => {
                NodeChecks::of(project, root).add_to(&mut builder);
            }
            sure_core::discover::Findings::Rust(project) => {
                RustChecks::of(project, root).add_to(&mut builder);
            }
            sure_core::discover::Findings::Go(project) => {
                GoChecks::of(project).add_to(project, root, &mut builder);
            }
            sure_core::discover::Findings::Dotnet(project) => {
                DotnetChecks::of(project).add_to(project, root, &mut builder);
            }
            sure_core::discover::Findings::Java(project) => {
                JavaChecks::of(project).add_to(project, root, &mut builder);
            }
        }
    }
    assert!(
        builder.refused().is_empty(),
        "the checks layer proposed something the builder refused: {:?}",
        builder.refused()
    );
    builder.build()
}

/// The invariant, over one fixture: every planned command is a command SURE's
/// classifier can read and that runs the project's code.
fn assert_every_planned_command_is_runnable(what: &str, fixture: &Fixture) -> Vec<String> {
    let found = fixture.discover();
    assert!(
        !found.ecosystems.is_empty(),
        "{what}: discovery reported no ecosystem at all"
    );
    let schedule = schedule_of(&found);
    let mut commands = Vec::new();
    for check in schedule.checks() {
        let CheckOperation::Command(spec) = check.operation() else {
            continue;
        };
        let rendered = format!(
            "{} {}",
            spec.program().to_string_lossy(),
            spec.arguments()
                .iter()
                .map(|argument| argument.to_string_lossy())
                .collect::<Vec<_>>()
                .join(" ")
        )
        .trim()
        .to_owned();
        let classification = classify(spec.program(), spec.arguments().iter().cloned());
        assert!(
            matches!(classification.source(), Source::Rule { .. }),
            "{what}: SURE planned `{rendered}`, and its own command classifier does not know \
             it ({:?}). A planned command the classifier refuses can never run.",
            classification.source()
        );
        assert!(
            classification.effects().contains(CommandClass::DynamicHost),
            "{what}: SURE planned `{rendered}` for a check that runs the project's code, and \
             the classifier did not read it as running code"
        );
        commands.push(rendered);
    }
    assert!(
        !commands.is_empty(),
        "{what}: the fixture planned no command at all; the invariant was not exercised"
    );
    commands
}

fn python_project(installer: &str) -> Fixture {
    let fixture = Fixture::new(installer);
    fixture
        .write(
            "pyproject.toml",
            "[build-system]\nrequires = [\"setuptools>=68\"]\nbuild-backend = \"setuptools.build_meta\"\n\n\
             [project]\nname = \"demo\"\nversion = \"1.0.0\"\n\
             dependencies = [\"pytest\", \"ruff\", \"mypy\"]\n",
        )
        .write("pytest.ini", "[pytest]\ntestpaths = tests\n")
        .write("src/demo/__init__.py", "");
    match installer {
        "uv" => {
            fixture.write("uv.lock", "version = 1\n");
        }
        "poetry" => {
            fixture.write("poetry.lock", "");
        }
        "pdm" => {
            fixture.write("pdm.lock", "");
        }
        "pipenv" => {
            fixture.write(
                "Pipfile",
                "[[source]]\nurl = \"https://pypi.org/simple\"\nverify_ssl = true\nname = \"pypi\"\n\n\
                 [packages]\npytest = \"*\"\nruff = \"*\"\nmypy = \"*\"\n",
            );
            fixture.write("Pipfile.lock", "{}");
        }
        _ => {}
    };
    fixture
}

#[test]
fn every_python_installer_plans_commands_sure_can_classify() {
    for installer in ["pip", "uv", "poetry", "pdm", "pipenv"] {
        let fixture = python_project(installer);
        let commands = assert_every_planned_command_is_runnable(installer, &fixture);
        // The four roles the acceptance names, each as a real command line. This
        // is the assertion that would have caught the bare `python -m ruff`.
        for expected in ["pytest", "ruff", "mypy"] {
            assert!(
                commands.iter().any(|command| command.contains(expected)),
                "{installer}: no planned command runs {expected}: {commands:?}"
            );
        }
        assert!(
            commands.iter().any(|command| command.contains("build")),
            "{installer}: no planned command builds the distribution: {commands:?}"
        );
    }
}

#[test]
fn a_declared_tool_sure_cannot_run_is_a_missing_command_not_a_doomed_one() {
    // `pyflakes` is in the tool table (a package SURE recognises as a linter)
    // and not in the invocation table (its CLI takes files, not a directory).
    // The check must be recorded as not runnable with the tool named — never
    // planned as `python -m pyflakes .`, which could only fail.
    let fixture = Fixture::new("pyflakes");
    fixture.write(
        "pyproject.toml",
        "[project]\nname = \"demo\"\nversion = \"1.0.0\"\ndependencies = [\"pytest\", \"pyflakes\"]\n",
    );
    let found = fixture.discover();
    let Some(report) = found.report(sure_core::discover::Ecosystem::Python) else {
        panic!("the fixture is a Python project and discovery did not report one");
    };
    let sure_core::discover::Findings::Python(project) = &report.findings else {
        panic!("the Python report carried other findings");
    };
    let checks = PythonChecks::of(project, &found.root);
    assert!(
        !checks
            .planned()
            .iter()
            .any(|work| work.proposal().title().contains("style")),
        "pyflakes was planned although SURE has no invocation for it"
    );
    assert!(
        checks.missing().iter().any(|missing| matches!(
            missing.kind(),
            MissingKind::NotRunnable { tool: "pyflakes" }
        )),
        "the pyflakes declaration is not reported as not runnable: {:?}",
        checks.missing()
    );
}

#[test]
fn node_rust_go_dotnet_and_java_plan_commands_sure_can_classify() {
    let node = Fixture::new("node-npm");
    node.write(
        "package.json",
        "{\n  \"name\": \"demo\",\n  \"version\": \"1.0.0\",\n  \"private\": true,\n  \
         \"packageManager\": \"npm@10.9.0\",\n  \
         \"scripts\": { \"test\": \"node tests/demo.js\", \"build\": \"node scripts/build.js\" }\n}\n",
    );
    assert_every_planned_command_is_runnable("node/npm", &node);

    let rust = Fixture::new("rust");
    rust.write(
        "Cargo.toml",
        "[package]\nname = \"demo\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )
    .write(
        "src/lib.rs",
        "pub fn add(a: i32, b: i32) -> i32 { a + b }\n",
    );
    assert_every_planned_command_is_runnable("rust/cargo", &rust);

    let go = Fixture::new("go");
    go.write("go.mod", "module example.com/demo\n\ngo 1.22\n")
        .write("main.go", "package main\n\nfunc main() {}\n");
    assert_every_planned_command_is_runnable("go", &go);

    let dotnet = Fixture::new("dotnet");
    dotnet.write(
        "demo.csproj",
        "<Project Sdk=\"Microsoft.NET.Sdk\">\n  <PropertyGroup>\n    \
         <TargetFramework>net8.0</TargetFramework>\n  </PropertyGroup>\n</Project>\n",
    );
    assert_every_planned_command_is_runnable("dotnet", &dotnet);

    let java = Fixture::new("java-maven");
    java.write(
        "pom.xml",
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <project xmlns=\"http://maven.apache.org/POM/4.0.0\">\n  \
         <modelVersion>4.0.0</modelVersion>\n  <groupId>com.example</groupId>\n  \
         <artifactId>demo</artifactId>\n  <version>1.0.0</version>\n</project>\n",
    );
    assert_every_planned_command_is_runnable("java/maven", &java);
}
