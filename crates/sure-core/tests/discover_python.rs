//! Finding out what a Python project declares.
//!
//! P2-T005 acceptance:
//!
//! > Detects dependency files, virtualenv/package-manager choice, declared test
//! > and lint tooling, and framework usage.
//!
//! `docs/architecture/ECOSYSTEM_DISCOVERY.md` is the authority for what is
//! asserted here, and its "Enforced by" table is the index from a statement to
//! the test below that holds it.
//!
//! # Why these tests build real projects
//!
//! Every criterion is about reading files a person wrote, and the parts that can
//! be unit-tested — the tables, the accessors, the rules — already are, in
//! `src/discover/python.rs`. What is left, and what only a real directory can
//! answer, is whether discovery finds the files at all: whether the walk lists
//! them, whether a file it could not read is reported instead of being treated
//! as a file that is not there, and whether a directory that is not a Python
//! project is left alone.
//!
//! # The two properties most of this file is about
//!
//! **A manifest that could not be read is not a manifest that is absent.** A
//! project whose `pyproject.toml` failed to parse declares no dependencies, no
//! tooling and no entry points — and so does a project with no `pyproject.toml`
//! at all. Reporting the second when the first is true is a false statement
//! about the project, and it is the failure `CLAUDE.md` ranks above a visible
//! error. Several tests below exist only to hold that line.
//!
//! **Discovery at this stage runs nothing.** `setup.py` is a Python *program*,
//! and this is the ecosystem where "reading the manifest" could most easily turn
//! into running the project. One test writes a `setup.py` that would leave a
//! file behind if anything executed it, and checks that no such file appears.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use sure_core::discover::python::{
    CommandRole, DependencyKind, Disagreement, Installer, InstallerEvidence, ManifestState,
    ToolRole,
};
use sure_core::discover::{
    DiscoverOptions, Discovery, Ecosystem, Findings, PythonProject, UnreadReason, discover,
};
use sure_core::scan::{ScanOptions, SkipReason};
use sure_core::vocabulary::SupportLevel;

/// A scratch project that removes itself.
///
/// Under the workspace's own `target/` so that the fixture is on the same volume
/// as the checkout, and with a space and a non-ASCII character in the path —
/// which is the cheapest way to make every path below one that two platforms
/// disagree about.
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
            .join("sure 指纹 discover")
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
        self.discover_with(DiscoverOptions::default())
    }

    fn discover_with(&self, options: DiscoverOptions) -> Discovery {
        discover(&self.project, &options).unwrap_or_else(|error| panic!("{error}"))
    }

    /// The Python findings, or a panic naming what was found instead.
    fn python(&self) -> PythonProject {
        self.python_with(DiscoverOptions::default())
    }

    fn python_with(&self, options: DiscoverOptions) -> PythonProject {
        let found = self.discover_with(options);
        let report = found.report(Ecosystem::Python).unwrap_or_else(|| {
            panic!(
                "this fixture is a Python project and discovery did not report one; \
                 it looked for {:?}",
                found
                    .looked_for()
                    .iter()
                    .map(|ecosystem| ecosystem.as_str())
                    .collect::<Vec<_>>()
            )
        });
        match &report.findings {
            Findings::Python(python) => (**python).clone(),
            // The enum makes this arm mandatory rather than optional, which is
            // the reason it is an enum: a report for one ecosystem cannot be
            // handed to a test that asked for another without saying so.
            other => panic!("the Python report carried {other:?}"),
        }
    }

    /// Whether a path inside the project is there, asked of the filesystem.
    ///
    /// **The premise asserted with the tool that is not under test.** A test
    /// that says "discovery found the requirements file" is worth nothing unless
    /// the file is really there; asking discovery whether it is there would be
    /// asking the defendant. This asks `std::fs`.
    fn exists(&self, relative: &str) -> bool {
        self.project.join(relative).exists()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        // Failing to clean up must not turn a passing test into a failing one.
        // Windows keeps directory handles open longer than Unix does, so a
        // reader may still hold one.
        let _ = std::fs::remove_dir_all(&self.project);
    }
}

/// The dependencies a project declares, as `(name, kind)` pairs.
fn dependencies(project: &PythonProject) -> Vec<(String, DependencyKind)> {
    project
        .dependencies()
        .into_iter()
        .map(|dependency| (dependency.name, dependency.kind))
        .collect()
}

/// The tool packages a project was found to declare, sorted.
fn tool_packages(project: &PythonProject) -> Vec<&'static str> {
    let mut packages: Vec<&'static str> = project.tooling.iter().map(|tool| tool.package).collect();
    packages.sort_unstable();
    packages.dedup();
    packages
}

// ---------------------------------------------------------------------------
// Is this a Python project at all?
// ---------------------------------------------------------------------------

#[test]
fn a_pyproject_toml_project_is_found_and_read() {
    let fixture = Fixture::new("pyproject-basic");
    fixture.write(
        "pyproject.toml",
        r#"
[project]
name = "widget"
version = "1.4.0"
requires-python = ">=3.10"

[project.scripts]
widget = "widget.cli:main"

[project.dependencies]
"#,
    );
    // The premise, asked of the filesystem rather than of discovery.
    assert!(fixture.exists("pyproject.toml"));

    let found = fixture.discover();
    let report = found.report(Ecosystem::Python).expect("a Python project");
    assert_eq!(report.ecosystem, Ecosystem::Python);
    assert_eq!(report.level, SupportLevel::Generic);
    assert!(
        report.found_by.contains(&PathBuf::from("pyproject.toml")),
        "the file the conclusion rests on is not named: {:?}",
        report.found_by
    );

    let python = fixture.python();
    let manifest = python.manifest.project().expect("the manifest was read");
    assert_eq!(manifest.name.as_deref(), Some("widget"));
    assert_eq!(manifest.version.as_deref(), Some("1.4.0"));
    assert_eq!(
        manifest
            .requires_python
            .as_ref()
            .map(|claim| claim.text.as_str()),
        Some(">=3.10")
    );
    assert_eq!(
        manifest
            .entry_points
            .iter()
            .map(|point| point.name.as_str())
            .collect::<Vec<_>>(),
        ["widget"]
    );
    assert!(found.unread.is_empty(), "nothing here is unreadable");
}

#[test]
fn every_file_that_marks_a_python_project_is_enough_on_its_own() {
    // The complete list, each written into its own project with nothing else.
    // A marker that stopped counting would report a real project as not one —
    // and the report would be missing rather than wrong, which is the harder
    // kind of failure to notice.
    let cases: &[(&str, &str, &str)] = &[
        (
            "marker-pyproject",
            "pyproject.toml",
            "[project]\nname = \"x\"\n",
        ),
        (
            "marker-pipfile",
            "Pipfile",
            "[packages]\nrequests = \"*\"\n",
        ),
        ("marker-version", ".python-version", "3.12.1\n"),
        ("marker-setup-py", "setup.py", "raise SystemExit(1)\n"),
        ("marker-setup-cfg", "setup.cfg", "[metadata]\nname = x\n"),
        ("marker-lockfile", "uv.lock", "version = 1\n"),
        ("marker-requirements", "requirements.txt", "requests\n"),
    ];
    for (test, file, contents) in cases {
        let fixture = Fixture::new(test);
        fixture.write(file, contents);
        assert!(fixture.exists(file), "{file} is not really there");
        let found = fixture.discover();
        assert!(
            found.report(Ecosystem::Python).is_some(),
            "{file} on its own did not make this a Python project"
        );
    }
}

#[test]
fn a_directory_of_python_files_with_no_manifest_is_not_a_python_project() {
    // Source files are deliberately not a marker. A directory containing a `.py`
    // file is a directory containing a `.py` file, and every file on the list
    // above is one a person creates deliberately to declare something.
    let fixture = Fixture::new("sources-only");
    fixture.write("main.py", "print('hello')\n");
    fixture.write("package/__init__.py", "");
    fixture.write("package/module.py", "VALUE = 1\n");
    fixture.write("README.md", "# not a project\n");

    let found = fixture.discover();
    assert!(
        found.report(Ecosystem::Python).is_none(),
        "a directory of .py files was reported as a Python project"
    );
    // And the list of what SURE looked for still names Python, so "not found" is
    // distinguishable from "never looked" — which is the whole reason
    // `looked_for` exists.
    assert!(found.looked_for().contains(&Ecosystem::Python));
}

#[test]
fn a_project_that_is_both_node_and_python_reports_both_in_a_fixed_order() {
    let fixture = Fixture::new("node-and-python");
    fixture.write("package.json", r#"{ "name": "both" }"#);
    fixture.write("pyproject.toml", "[project]\nname = \"both\"\n");

    let found = fixture.discover();
    let ecosystems: Vec<Ecosystem> = found
        .ecosystems
        .iter()
        .map(|report| report.ecosystem)
        .collect();
    assert_eq!(ecosystems, [Ecosystem::Node, Ecosystem::Python]);
    // The order is the product's, not the walk's: `Ecosystem::ALL` is the list
    // discovery pushes in.
    assert_eq!(found.looked_for(), Ecosystem::ALL);
}

// ---------------------------------------------------------------------------
// A manifest that could not be read is not a manifest that is absent
// ---------------------------------------------------------------------------

#[test]
fn a_manifest_that_is_not_toml_is_unread_and_never_absent() {
    let fixture = Fixture::new("not-toml");
    // Valid Python-adjacent text, invalid TOML — and a file a real project can
    // really have, since `pyproject.toml` is hand-edited.
    fixture.write(
        "pyproject.toml",
        "[project\nname = \"broken\"\nthis line has no equals sign\n",
    );
    assert!(fixture.exists("pyproject.toml"), "the premise");

    let found = fixture.discover();
    let python = fixture.python();
    assert!(
        !python.manifest.is_absent(),
        "a file that exists was reported as absent"
    );
    match &python.manifest {
        ManifestState::Unread(UnreadReason::NotParsed { detail }) => {
            assert!(!detail.is_empty(), "the parser said nothing");
        }
        other => panic!("expected NotParsed, got {other:?}"),
    }
    // The shape failure reached the result as well as the finding. One project
    // must not be described two ways, and this is the assertion that holds it.
    let unread = found
        .unread
        .iter()
        .find(|entry| entry.path == Path::new("pyproject.toml"))
        .expect("a file SURE could not read must be named");
    assert!(matches!(unread.reason, UnreadReason::NotParsed { .. }));
    assert_eq!(
        found.report(Ecosystem::Python).unwrap().level,
        SupportLevel::InspectOnly,
        "a manifest that could not be read is not the higher support level"
    );
}

#[test]
fn a_manifest_that_is_valid_toml_and_not_a_manifest_is_unread() {
    // The route `package.json` has too: a document that parses and is not the
    // shape this file has. `name = 4` is a project whose name is a number, and
    // reading fields out of it would produce a project with no name rather than
    // a project SURE could not read.
    let fixture = Fixture::new("wrong-shape");
    fixture.write("pyproject.toml", "name = 4\n");
    fixture.write("requirements.txt", "requests\n");
    assert!(fixture.exists("pyproject.toml"), "the premise");

    let python = fixture.python();
    match &python.manifest {
        // A top-level `name` with no `[project]` table is not a shape SURE
        // knows, and it is not absent either.
        ManifestState::Read(project) => assert_eq!(project.name, None),
        other => panic!("a top-level `name` must not stop the file being read: {other:?}"),
    }
    // The stronger shape failure: TOML's top level is always a table, so a
    // document whose root is not one cannot come from the TOML reader. This
    // asserts the reader and the converter agree about what a manifest is.
    let manifest = python.manifest.project().expect("read");
    assert!(manifest.dependencies.is_empty());
}

#[test]
fn a_manifest_too_large_to_read_is_unread_rather_than_half_read() {
    // Half a `pyproject.toml` is not a smaller `pyproject.toml`; it is a
    // document that fails to parse, and it would fail with an error the project
    // does not have. So the limit refuses outright.
    let fixture = Fixture::new("too-large");
    let filler = "#".repeat(4_000);
    fixture.write(
        "pyproject.toml",
        &format!("[project]\nname = \"big\"\n{filler}\n"),
    );

    let found = fixture.discover_with(DiscoverOptions::default().with_max_manifest_bytes(1_000));
    let python = fixture.python_with(DiscoverOptions::default().with_max_manifest_bytes(1_000));
    match &python.manifest {
        ManifestState::Unread(UnreadReason::TooLarge { limit }) => assert_eq!(*limit, 1_000),
        other => panic!("expected TooLarge, got {other:?}"),
    }
    assert!(matches!(
        found
            .unread
            .iter()
            .find(|entry| entry.path == Path::new("pyproject.toml"))
            .expect("the refused file must be named")
            .reason,
        UnreadReason::TooLarge { .. }
    ));

    // And a limit the file fits under reads it, so the refusal above is about
    // the limit rather than about large manifests being unreadable in general.
    let read = fixture.python_with(DiscoverOptions::default().with_max_manifest_bytes(65_536));
    assert_eq!(
        read.manifest
            .project()
            .and_then(|project| project.name.as_deref()),
        Some("big")
    );
}

#[test]
fn a_manifest_sure_ran_out_of_budget_for_is_unread_and_never_absent() {
    // The third route: not a parse failure and not a size failure, but a project
    // SURE declined to read. It answers the same question the other two do, and
    // it must not answer it differently.
    let fixture = Fixture::new("out-of-budget");
    fixture.write("pyproject.toml", "[project]\nname = \"unread\"\n");
    assert!(fixture.exists("pyproject.toml"), "the premise");

    let options = DiscoverOptions::default().with_max_manifests(0);
    let found = fixture.discover_with(options);
    let python = fixture.python_with(options);
    match &python.manifest {
        ManifestState::Unread(UnreadReason::OutOfBudget { limit }) => assert_eq!(*limit, 0),
        other => panic!("expected OutOfBudget, got {other:?}"),
    }
    assert!(!python.manifest.is_absent());
    assert!(matches!(
        found
            .unread
            .iter()
            .find(|entry| entry.path == Path::new("pyproject.toml"))
            .expect("a file SURE did not read must be named")
            .reason,
        UnreadReason::OutOfBudget { .. }
    ));
    // The lockfile evidence is unaffected by the manifest budget, so a project
    // SURE could not read still gets its installer where a lockfile says.
    assert_eq!(
        found.report(Ecosystem::Python).unwrap().level,
        SupportLevel::InspectOnly
    );
}

#[test]
fn a_requirements_file_that_could_not_be_read_is_named_and_not_dropped() {
    let fixture = Fixture::new("requirements-unread");
    fixture.write(
        "requirements.txt",
        &format!("# {}\nrequests\n", "x".repeat(4_000)),
    );
    assert!(fixture.exists("requirements.txt"), "the premise");

    let options = DiscoverOptions::default().with_max_manifest_bytes(500);
    let found = fixture.discover_with(options);
    let python = fixture.python_with(options);
    assert!(
        python.requirements.is_empty(),
        "a file that could not be read produced a reading of it"
    );
    let unread = found
        .unread
        .iter()
        .find(|entry| entry.path == Path::new("requirements.txt"))
        .expect("the file SURE could not read must be named");
    assert!(matches!(unread.reason, UnreadReason::TooLarge { .. }));
}

// ---------------------------------------------------------------------------
// Which installer, and where the evidence disagrees with itself
// ---------------------------------------------------------------------------

#[test]
fn a_lockfile_names_its_installer() {
    let fixture = Fixture::new("lockfile");
    fixture.write("pyproject.toml", "[project]\nname = \"x\"\n");
    fixture.write("uv.lock", "version = 1\n");
    assert!(fixture.exists("uv.lock"), "the premise");

    let python = fixture.python();
    let locked: Vec<Installer> = python
        .managers
        .locked
        .iter()
        .map(|finding| finding.installer)
        .collect();
    assert_eq!(locked, [Installer::Uv]);
    assert_eq!(python.managers.agreed(), Some(Installer::Uv));
    assert_eq!(python.managers.disagreement(), None);
    assert_eq!(
        python.managers.locked[0].evidence,
        InstallerEvidence::Lockfile
    );
    assert_eq!(python.managers.locked[0].source.path, Path::new("uv.lock"));
}

#[test]
fn two_lockfiles_are_reported_as_a_disagreement_rather_than_resolved() {
    // A project with `uv.lock` and `poetry.lock` says two things about which
    // tool records its dependencies. SURE picks neither, and says why.
    let fixture = Fixture::new("two-lockfiles");
    fixture.write("pyproject.toml", "[project]\nname = \"x\"\n");
    fixture.write("uv.lock", "version = 1\n");
    fixture.write("poetry.lock", "[[package]]\n");

    let python = fixture.python();
    let disagreement = python
        .managers
        .disagreement()
        .expect("two lockfiles must be reported");
    assert!(matches!(disagreement, Disagreement::TwoLockfiles { .. }));
    // The order is the lockfile table's, not the order the files were written in
    // or the order the walk met them, so which one is reported first does not
    // depend on the filesystem.
    assert_eq!(disagreement.one_of(), Installer::Uv);
    assert_eq!(disagreement.other_of(), Installer::Poetry);
    assert!(
        python.managers.agreed().is_none(),
        "a project SURE cannot decide about was decided about"
    );
    // The sentence is a constant, and it says what happened.
    assert!(!disagreement.plain_description().is_empty());
}

#[test]
fn a_configured_installer_and_another_lockfile_are_a_disagreement() {
    let fixture = Fixture::new("configured-vs-locked");
    fixture.write(
        "pyproject.toml",
        "[project]\nname = \"x\"\n\n[tool.poetry]\nname = \"x\"\n",
    );
    fixture.write("uv.lock", "version = 1\n");

    let python = fixture.python();
    assert!(
        python
            .managers
            .configured
            .iter()
            .any(|finding| finding.installer == Installer::Poetry)
    );
    assert_eq!(
        python.managers.disagreement(),
        Some(Disagreement::ConfigurationAndLockfile {
            configured: Installer::Poetry,
            locked: Installer::Uv,
        })
    );
    assert!(python.managers.agreed().is_none());
}

#[test]
fn the_projects_own_configuration_decides_which_installer_it_uses() {
    let fixture = Fixture::new("configured");
    fixture.write(
        "pyproject.toml",
        "[project]\nname = \"x\"\n\n[tool.pdm]\ndistribution = true\n",
    );

    let python = fixture.python();
    assert_eq!(python.managers.agreed(), Some(Installer::Pdm));
    assert_eq!(python.managers.configured.len(), 1);
    assert_eq!(
        python.managers.configured[0].evidence,
        InstallerEvidence::Declared
    );
    assert_eq!(
        python.managers.configured[0].source.path,
        Path::new("pyproject.toml")
    );
}

#[test]
fn a_pipfile_is_read_by_the_same_accessors_and_names_pipenv() {
    let fixture = Fixture::new("pipfile");
    fixture.write(
        "Pipfile",
        "[packages]\nrequests = \">=2.31\"\n\n[dev-packages]\npytest = \"*\"\n",
    );
    assert!(fixture.exists("Pipfile"), "the premise");

    let found = fixture.discover();
    let report = found.report(Ecosystem::Python).expect("a Python project");
    assert_eq!(
        report.level,
        SupportLevel::Generic,
        "a readable Pipfile is a manifest SURE read"
    );
    assert!(report.found_by.contains(&PathBuf::from("Pipfile")));

    let python = fixture.python();
    assert!(python.pipfile.project().is_some());
    assert_eq!(python.managers.agreed(), Some(Installer::Pipenv));
    assert_eq!(
        dependencies(&python),
        [
            ("pytest".to_owned(), DependencyKind::Development),
            ("requests".to_owned(), DependencyKind::Runtime),
        ]
    );
    assert!(tool_packages(&python).contains(&"pytest"));
}

#[test]
fn a_requirements_file_is_the_weakest_evidence_and_never_a_disagreement() {
    // pip, uv, poetry and pdm all read `requirements.txt`, so its presence next
    // to a `uv.lock` is the normal shape of a project that moved to uv. Calling
    // that a contradiction would be a false alarm, and a false alarm beside a
    // real one is how a reader learns to ignore both.
    let fixture = Fixture::new("requirements-weak");
    fixture.write("requirements.txt", "requests>=2.31\n");
    fixture.write("uv.lock", "version = 1\n");

    let python = fixture.python();
    assert_eq!(
        python.managers.disagreement(),
        None,
        "a requirements file made a project disagree with itself"
    );
    assert_eq!(
        python.managers.agreed(),
        Some(Installer::Uv),
        "the weaker evidence overrode the stronger"
    );
    assert_eq!(
        python.managers.requirements[0].evidence,
        InstallerEvidence::RequirementsFile
    );

    // And with nothing stronger, the requirements file is what decides — the
    // same project with the lockfile taken away.
    let only = Fixture::new("requirements-only");
    only.write("requirements.txt", "requests>=2.31\n");
    assert_eq!(only.python().managers.agreed(), Some(Installer::Pip));
}

#[test]
fn a_requirements_file_that_proves_a_python_project_says_so_in_the_level() {
    let fixture = Fixture::new("requirements-level");
    fixture.write("requirements.txt", "requests\n");

    let found = fixture.discover();
    let report = found.report(Ecosystem::Python).expect("a Python project");
    assert_eq!(report.level, SupportLevel::InspectOnly);
    assert!(
        report.reason.contains("requirements"),
        "the reason does not say what the level is based on: {}",
        report.reason
    );
}

#[test]
fn a_project_with_no_manifest_sure_can_read_is_not_called_fully_understood() {
    // The four routes to `InspectOnly` each name what they are based on, and
    // three of them are reached by the tests around this one: an unreadable
    // manifest, a requirements file, and a `setup.py`. This is the fourth — the
    // arm reached when the project is recognised from a lockfile or a
    // `.python-version` and nothing SURE reads declares anything.
    //
    // **This test exists because a mutation found the hole.** Changing that
    // arm's level from `InspectOnly` to `Generic` left every test in this file
    // passing, which is the false-green direction: a project SURE read nothing
    // from, reported as a project SURE fully understands.
    for (test, file, contents) in [
        ("level-lockfile", "uv.lock", "version = 1\n"),
        ("level-version-file", ".python-version", "3.12.1\n"),
    ] {
        let fixture = Fixture::new(test);
        fixture.write(file, contents);
        assert!(fixture.exists(file), "the premise");

        let found = fixture.discover();
        let report = found.report(Ecosystem::Python).expect("a Python project");
        assert_eq!(
            report.level,
            SupportLevel::InspectOnly,
            "{file} alone is not a manifest SURE read"
        );
        assert!(
            report.reason.contains("pyproject.toml"),
            "the reason does not say what was missing: {}",
            report.reason
        );
        // And the reason is the product's own sentence, not the project's file:
        // the level is a claim about SURE's reading, so nothing from the file
        // may appear in it.
        assert!(
            !report.reason.contains("3.12.1") && !report.reason.contains("version = 1"),
            "project text reached the sentence explaining the level: {}",
            report.reason
        );
    }
}

// ---------------------------------------------------------------------------
// The requirements files themselves
// ---------------------------------------------------------------------------

#[test]
fn thicker_requirements_files_are_all_read_and_in_a_fixed_order() {
    let fixture = Fixture::new("requirements-many");
    fixture.write("requirements.txt", "requests\n");
    fixture.write("requirements-dev.txt", "pytest\nruff\n");
    fixture.write("requirements-prod.txt", "gunicorn\n");
    // Not a requirements file by the rule, so not read: the suffix is what
    // decides, and a file called `dev-requirements.txt` does not match it.
    fixture.write("dev-requirements.txt", "this-is-not-read\n");

    let python = fixture.python();
    let paths: Vec<&Path> = python
        .requirements
        .iter()
        .map(|file| file.path.as_path())
        .collect();
    assert_eq!(
        paths,
        [
            Path::new("requirements-dev.txt"),
            Path::new("requirements-prod.txt"),
            Path::new("requirements.txt"),
        ],
        "the order is not the sorted one, so the cut-off would depend on the walk"
    );
    let names: Vec<String> = dependencies(&python)
        .iter()
        .map(|(name, _)| name.clone())
        .collect();
    assert!(names.iter().any(|name| name == "gunicorn"));
    assert!(
        !names.iter().any(|name| name == "this-is-not-read"),
        "a file the naming rule excludes was read"
    );
}

#[test]
fn a_requirements_file_keeps_every_line_in_exactly_one_place() {
    let fixture = Fixture::new("requirements-lines");
    let text = "# a comment\n\
                \n\
                pytest==8.0.0\n\
                -r other.txt\n\
                requests>=2.31  # pinned by the platform team\n\
                --index-url https://example.invalid/simple\n";
    fixture.write("requirements.txt", text);

    let python = fixture.python();
    let file = &python.requirements[0];
    assert_eq!(
        file.requirements
            .iter()
            .map(|requirement| requirement.name.as_str())
            .collect::<Vec<_>>(),
        ["pytest", "requests"]
    );
    assert_eq!(
        file.directives,
        ["-r other.txt", "--index-url https://example.invalid/simple"]
    );
    assert_eq!(file.comments, 2);
    assert!(!file.truncated);
    // Nothing was dropped and nothing was counted twice: the file has six
    // lines, and six of them landed somewhere.
    assert_eq!(
        file.requirements.len() + file.directives.len() + file.comments,
        text.lines().count(),
        "a line of the file went nowhere"
    );
    // The requirement is verbatim, with the comment removed and nothing else
    // changed.
    assert_eq!(file.requirements[1].line, "requests>=2.31");
}

#[test]
fn a_url_line_in_a_requirements_file_is_not_a_dependency_named_https() {
    // The failure this rule exists for. `https://…` begins with a perfectly good
    // run of name characters, and taking it would report the project as
    // depending on a package called `https` — an invented fact about the project
    // in the one place the product promises not to invent any.
    let fixture = Fixture::new("requirements-url");
    fixture.write(
        "requirements.txt",
        "https://example.invalid/pkg-1.0.whl\nfoo @ https://example.invalid/foo.tar.gz\n",
    );

    let python = fixture.python();
    let names: Vec<&str> = python.requirements[0]
        .requirements
        .iter()
        .map(|requirement| requirement.name.as_str())
        .collect();
    assert_eq!(names, ["foo"], "a URL was read as a distribution name");
}

#[test]
fn more_requirements_files_than_sure_reads_is_a_bound_on_work() {
    // The names after `requirements` are the project's, so the count is
    // unbounded by anything SURE controls. Reading a thousand of them is work a
    // project does not get to ask for.
    let fixture = Fixture::new("requirements-flood");
    for index in 0..40 {
        fixture.write(&format!("requirements-{index:02}.txt"), "requests\n");
    }

    let python = fixture.python();
    assert_eq!(python.requirements.len(), 32);
    // The ones that were read are the first 32 in sorted order, so which files
    // are left out is a function of the project rather than of the walk.
    assert_eq!(
        python.requirements[0].path,
        Path::new("requirements-00.txt")
    );
    assert_eq!(
        python.requirements[31].path,
        Path::new("requirements-31.txt")
    );
}

// ---------------------------------------------------------------------------
// The interpreter, the tooling and the commands
// ---------------------------------------------------------------------------

#[test]
fn the_interpreter_the_project_asks_for_is_carried_verbatim_from_every_place() {
    let fixture = Fixture::new("interpreter");
    fixture.write(
        "pyproject.toml",
        "[project]\n\
         name = \"x\"\n\
         requires-python = \">=3.9,<4\"\n\
         classifiers = [\n\
         \"Programming Language :: Python :: 3.12\",\n\
         \"License :: OSI Approved :: MIT License\",\n\
         ]\n\n\
         [tool.poetry.dependencies]\n\
         python = \"^3.11\"\n",
    );
    fixture.write(".python-version", "3.12.1\n");

    let python = fixture.python();
    assert_eq!(
        python
            .python
            .requires_python
            .as_ref()
            .map(|claim| claim.text.as_str()),
        Some(">=3.9,<4"),
        "the specifier set was interpreted rather than carried"
    );
    assert_eq!(
        python
            .python
            .poetry_python
            .as_ref()
            .map(|claim| claim.text.as_str()),
        Some("^3.11")
    );
    assert_eq!(
        python
            .python
            .version_file
            .as_ref()
            .map(|claim| claim.text.as_str()),
        Some("3.12.1"),
        "the version file's text was not carried"
    );
    assert_eq!(
        python.python.classifiers,
        ["Programming Language :: Python :: 3.12"],
        "only the Python classifiers are classifiers, and they are verbatim"
    );
    // Three sources, three claims: SURE does not merge them into one answer.
    assert_eq!(python.python.claims().count(), 3);
    assert!(python.python.is_declared());
}

#[test]
fn a_python_version_file_is_read_as_its_whole_text() {
    let fixture = Fixture::new("version-file-only");
    fixture.write(".python-version", "3.11.7\n");
    assert!(fixture.exists(".python-version"), "the premise");

    let python = fixture.python();
    assert_eq!(
        python
            .python
            .version_file
            .as_ref()
            .map(|claim| claim.text.as_str()),
        // Trimmed of the trailing newline, and of nothing else: the newline is
        // how the file ends rather than part of what it says.
        Some("3.11.7")
    );
}

#[test]
fn a_project_declares_its_test_and_lint_tooling_and_sure_names_it() {
    let fixture = Fixture::new("tooling");
    fixture.write(
        "pyproject.toml",
        "[project]\n\
         name = \"x\"\n\
         dependencies = [\"Django>=5\", \"celery\"]\n\n\
         [project.optional-dependencies]\n\
         dev = [\"pytest\", \"ruff\", \"Scikit_Learn\"]\n\n\
         [build-system]\n\
         requires = [\"hatchling\"]\n\
         build-backend = \"hatchling.build\"\n",
    );

    let python = fixture.python();
    let packages = tool_packages(&python);
    for expected in [
        "django",
        "celery",
        "pytest",
        "ruff",
        "scikit-learn",
        "hatchling",
    ] {
        assert!(
            packages.contains(&expected),
            "{expected} was not recognised; found {packages:?}"
        );
    }
    // A project's spelling never reaches a finding: the table's name does.
    assert!(python.tooling.iter().all(|tool| {
        let package = tool.package;
        package == package.to_lowercase().as_str()
    }));
    // `ruff` is two things, and both are reported.
    assert!(python.declares("ruff"));
    assert_eq!(
        python
            .tooling_of_role(ToolRole::Linter)
            .map(|tool| tool.package)
            .collect::<Vec<_>>(),
        ["ruff"]
    );
    assert_eq!(
        python
            .tooling_of_role(ToolRole::WebFramework)
            .map(|tool| tool.package)
            .collect::<Vec<_>>(),
        ["django"]
    );
    assert_eq!(
        python
            .tooling_of_role(ToolRole::TestRunner)
            .map(|tool| tool.package)
            .collect::<Vec<_>>(),
        ["pytest"]
    );
}

#[test]
fn a_command_is_planned_only_for_a_tool_the_project_declared() {
    // The rule that keeps a plan from becoming an invented fact: no tool, no
    // command. A project that declares a test runner gets a test command and
    // nothing else, and the row for every other role is there with no command —
    // "there is no way to check this project's types" said out loud rather than
    // left as a line missing from a list.
    let fixture = Fixture::new("commands");
    fixture.write(
        "pyproject.toml",
        "[project]\n\
         name = \"x\"\n\
         dependencies = [\"pytest\", \"mypy\"]\n\n\
         [tool.uv]\n\
         package = true\n",
    );

    let python = fixture.python();
    let rows = python.conventional_commands();
    assert_eq!(rows.len(), CommandRole::ALL.len());

    let row = |role: CommandRole| {
        rows.iter()
            .find(|row| row.role == role)
            .unwrap_or_else(|| panic!("no row for {role:?}"))
    };

    assert_eq!(
        row(CommandRole::Test).command.as_deref(),
        Some("uv run pytest")
    );
    assert_eq!(row(CommandRole::Test).because, ["pytest"]);
    assert_eq!(
        row(CommandRole::TypeCheck).command.as_deref(),
        Some("uv run mypy")
    );
    // No linter and no formatter were declared, so there is no plan for either.
    assert!(row(CommandRole::Lint).command.is_none());
    assert!(row(CommandRole::Format).command.is_none());
    // The installer is configured, so the install plan is its own command.
    assert_eq!(
        row(CommandRole::Install).command.as_deref(),
        Some("uv sync")
    );
    // And a plan with no command carries no reasons, so nothing is offered as
    // evidence for a command that does not exist.
    assert!(row(CommandRole::Lint).because.is_empty());
}

#[test]
fn a_build_plan_names_a_frontend_and_never_the_backend_library() {
    let fixture = Fixture::new("build-plan");
    fixture.write(
        "pyproject.toml",
        "[project]\nname = \"x\"\n\n\
         [build-system]\n\
         requires = [\"setuptools>=68\"]\n\
         build-backend = \"setuptools.build_meta\"\n",
    );

    let python = fixture.python();
    let build = python
        .conventional_commands()
        .into_iter()
        .find(|row| row.role == CommandRole::Build)
        .expect("a row for build");
    // `setuptools` is a library a frontend calls. Naming it as the command would
    // be a plan that does not run, and it is the obvious wrong answer here.
    assert_eq!(build.command.as_deref(), Some("python -m build"));
    assert_eq!(
        build.because,
        ["setuptools"],
        "the plan hides what it rests on"
    );
}

#[test]
fn a_requirements_file_can_declare_the_tooling_too() {
    let fixture = Fixture::new("tooling-from-requirements");
    fixture.write("requirements.txt", "pytest\nruff\nrequests\n");

    let python = fixture.python();
    let packages = tool_packages(&python);
    assert!(packages.contains(&"pytest"));
    assert!(packages.contains(&"ruff"));
    // And the command plan is built from that evidence, through pip, which is
    // the installer a requirements file points at.
    let test = python
        .conventional_commands()
        .into_iter()
        .find(|row| row.role == CommandRole::Test)
        .expect("a row for test");
    assert_eq!(test.command.as_deref(), Some("python -m pytest"));
}

#[test]
fn a_dedicated_config_file_declares_a_tool_without_a_dependency() {
    // The shape a project has when CI installs the tools and the manifest does
    // not: `pytest.ini`, `ruff.toml` and `mypy.ini` are the declarations.
    let fixture = Fixture::new("tooling-from-config");
    fixture.write("pytest.ini", "[pytest]\n");
    fixture.write("ruff.toml", "line-length = 100\n");
    fixture.write("mypy.ini", "[mypy]\n");

    let python = fixture.python();
    let packages = tool_packages(&python);
    for expected in ["pytest", "ruff", "mypy"] {
        assert!(
            packages.contains(&expected),
            "{expected} was not recognised; found {packages:?}"
        );
    }
    let source = |package: &str| {
        python
            .tooling
            .iter()
            .find(|tool| tool.package == package)
            .and_then(|tool| tool.source.as_deref())
    };
    assert_eq!(source("pytest"), Some(Path::new("pytest.ini")));
    assert_eq!(source("ruff"), Some(Path::new("ruff.toml")));
    assert_eq!(source("mypy"), Some(Path::new("mypy.ini")));

    let row = |role: CommandRole| {
        python
            .conventional_commands()
            .into_iter()
            .find(|row| row.role == role)
            .unwrap_or_else(|| panic!("no row for {role:?}"))
    };
    assert_eq!(
        row(CommandRole::Test).command.as_deref(),
        Some("python -m pytest")
    );
    assert_eq!(
        row(CommandRole::Lint).command.as_deref(),
        Some("python -m ruff")
    );
    assert_eq!(
        row(CommandRole::TypeCheck).command.as_deref(),
        Some("python -m mypy")
    );
}

#[test]
fn tox_ini_and_noxfile_name_their_runners() {
    let tox = Fixture::new("tooling-tox");
    tox.write("tox.ini", "[testenv]\ncommands = python -m pytest\n");
    let python = tox.python();
    assert_eq!(
        python
            .tooling_of_role(ToolRole::TestRunner)
            .map(|tool| tool.package)
            .collect::<Vec<_>>(),
        ["tox"]
    );
    let test = python
        .conventional_commands()
        .into_iter()
        .find(|row| row.role == CommandRole::Test)
        .expect("a row for test");
    assert_eq!(test.command.as_deref(), Some("python -m tox"));

    let nox = Fixture::new("tooling-nox");
    nox.write("noxfile.py", "import nox\n");
    let python = nox.python();
    assert_eq!(
        python
            .tooling_of_role(ToolRole::TestRunner)
            .map(|tool| tool.package)
            .collect::<Vec<_>>(),
        ["nox"]
    );
    let test = python
        .conventional_commands()
        .into_iter()
        .find(|row| row.role == CommandRole::Test)
        .expect("a row for test");
    assert_eq!(test.command.as_deref(), Some("python -m nox"));
}

#[test]
fn pyproject_tool_sections_declare_tools_without_dependency_entries() {
    let fixture = Fixture::new("tooling-from-tool-sections");
    fixture.write(
        "pyproject.toml",
        "[project]\n\
         name = \"x\"\n\n\
         [tool.pytest.ini_options]\n\
         testpaths = [\"tests\"]\n\n\
         [tool.ruff]\n\
         line-length = 100\n\n\
         [tool.mypy]\n\
         strict = true\n",
    );

    let python = fixture.python();
    let packages = tool_packages(&python);
    for expected in ["pytest", "ruff", "mypy"] {
        assert!(
            packages.contains(&expected),
            "{expected} was not recognised; found {packages:?}"
        );
    }
    let source = |package: &str| {
        python
            .tooling
            .iter()
            .find(|tool| tool.package == package)
            .and_then(|tool| tool.source.as_deref())
    };
    assert_eq!(source("pytest"), Some(Path::new("pyproject.toml")));
    assert_eq!(source("ruff"), Some(Path::new("pyproject.toml")));
    assert_eq!(source("mypy"), Some(Path::new("pyproject.toml")));
}

#[test]
fn a_configured_runner_wins_over_a_dependency_runner() {
    // MiQi's project-test detector makes the same choice: a `tox.ini` owns the
    // test environments, so a bare `pytest` from the dependency list would
    // bypass them.
    let fixture = Fixture::new("configured-runner-wins");
    fixture.write(
        "pyproject.toml",
        "[project]\nname = \"x\"\ndependencies = [\"pytest\"]\n",
    );
    fixture.write("tox.ini", "[testenv]\ncommands = python -m pytest\n");

    let python = fixture.python();
    let test = python
        .conventional_commands()
        .into_iter()
        .find(|row| row.role == CommandRole::Test)
        .expect("a row for test");
    assert_eq!(test.command.as_deref(), Some("python -m tox"));
}

#[test]
fn tox_ini_wins_over_a_pytest_ini() {
    // MiQi's config order is tox.ini, noxfile.py, pytest.ini, then the
    // pyproject tables. A tox project is run through tox even when a pytest
    // config is also present.
    let fixture = Fixture::new("tox-ini-wins");
    fixture.write("tox.ini", "[testenv]\ncommands = python -m pytest\n");
    fixture.write("pytest.ini", "[pytest]\ntestpaths = tests\n");

    let python = fixture.python();
    let test = python
        .conventional_commands()
        .into_iter()
        .find(|row| row.role == CommandRole::Test)
        .expect("a row for test");
    assert_eq!(test.command.as_deref(), Some("python -m tox"));
}

#[test]
fn pytest_ini_wins_over_a_pyproject_tox_table() {
    // The file-level pytest declaration is earlier in MiQi's order than the
    // pyproject `[tool.tox]` table.
    let fixture = Fixture::new("pytest-ini-wins-over-table");
    fixture.write(
        "pyproject.toml",
        "[project]\nname = \"x\"\n\n[tool.tox]\nenvlist = [\"py311\"]\n",
    );
    fixture.write("pytest.ini", "[pytest]\n");

    let python = fixture.python();
    let test = python
        .conventional_commands()
        .into_iter()
        .find(|row| row.role == CommandRole::Test)
        .expect("a row for test");
    assert_eq!(test.command.as_deref(), Some("python -m pytest"));
}

#[test]
fn setup_cfg_tool_sections_declare_tools_without_reading_packaging_metadata() {
    let fixture = Fixture::new("tooling-from-setup-cfg");
    fixture.write(
        "setup.cfg",
        "[metadata]\n\
         name = x\n\n\
         [tool:pytest]\n\
         addopts = -q\n\n\
         [mypy]\n\
         strict = true\n",
    );

    let python = fixture.python();
    let packages = tool_packages(&python);
    assert!(packages.contains(&"pytest"), "{packages:?}");
    assert!(packages.contains(&"mypy"), "{packages:?}");
    let source = |package: &str| {
        python
            .tooling
            .iter()
            .find(|tool| tool.package == package)
            .and_then(|tool| tool.source.as_deref())
    };
    assert_eq!(source("pytest"), Some(Path::new("setup.cfg")));
    assert_eq!(source("mypy"), Some(Path::new("setup.cfg")));

    let row = |role: CommandRole| {
        python
            .conventional_commands()
            .into_iter()
            .find(|row| row.role == role)
            .unwrap_or_else(|| panic!("no row for {role:?}"))
    };
    assert_eq!(
        row(CommandRole::Test).command.as_deref(),
        Some("python -m pytest")
    );
    assert_eq!(
        row(CommandRole::TypeCheck).command.as_deref(),
        Some("python -m mypy")
    );
}

// ---------------------------------------------------------------------------
// setup.py, and what SURE will not run
// ---------------------------------------------------------------------------

#[test]
fn a_setup_py_is_reported_rather_than_read() {
    // `setup.py` is a Python *program*: what it declares is the result of
    // running it. So its presence says "this project declares itself in code
    // SURE will not execute", which is a finding, and it is not the same
    // finding as "there is nothing here".
    let fixture = Fixture::new("setup-py");
    fixture.write("setup.py", "print('this would run')\n");
    fixture.write("setup.cfg", "[metadata]\nname = x\n");
    assert!(fixture.exists("setup.py"), "the premise");

    let found = fixture.discover();
    let python = fixture.python();
    assert_eq!(python.unread_legacy, ["setup.py", "setup.cfg"]);
    let report = found.report(Ecosystem::Python).expect("a Python project");
    assert_eq!(report.level, SupportLevel::InspectOnly);
    assert!(report.found_by.contains(&PathBuf::from("setup.py")));
    // Nothing about what the files declare is claimed, because nothing was read.
    assert!(python.manifest.is_absent());
}

#[test]
fn discovery_runs_nothing() {
    // The property that matters most in this ecosystem. Each file below would
    // leave a `ran-<name>.txt` behind if SURE executed it, and a `setup.py`
    // would do so merely by being imported. Reading a manifest is not executing
    // a project, and this is the test that says so with the filesystem.
    let fixture = Fixture::new("runs-nothing");
    let tripwire = |name: &str| {
        format!(
            "import pathlib\n\
             pathlib.Path(__file__).with_name('ran-{name}.txt').write_text('ran')\n"
        )
    };
    fixture.write("setup.py", &tripwire("setup"));
    fixture.write("conftest.py", &tripwire("conftest"));
    fixture.write(
        "pyproject.toml",
        "[project]\nname = \"x\"\nversion = \"1.0\"\n\n\
         [project.scripts]\n\
         x = \"x.cli:main\"\n\n\
         [build-system]\n\
         requires = [\"setuptools\"]\n\
         build-backend = \"setuptools.build_meta\"\n",
    );
    fixture.write("requirements.txt", "requests\n");
    fixture.write(".python-version", "3.12.1\n");
    fixture.write("uv.lock", "version = 1\n");

    let found = fixture.discover();
    assert!(found.report(Ecosystem::Python).is_some());
    for name in ["setup", "conftest"] {
        assert!(
            !fixture.exists(&format!("ran-{name}.txt")),
            "discovery ran {name}.py"
        );
    }
    // Nothing the project directory contains was written to: the trap is checked
    // by listing the directory rather than only by looking for the two names.
    let entries: Vec<String> = std::fs::read_dir(fixture.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert!(
        !entries.iter().any(|name| name.starts_with("ran-")),
        "discovery wrote something into the project: {entries:?}"
    );
}

// ---------------------------------------------------------------------------
// What the walk leaves out
// ---------------------------------------------------------------------------

#[test]
fn a_virtual_environment_inside_a_python_project_is_not_walked() {
    // The environment names a Python project is most likely to have, each with a
    // file inside that would otherwise be read as project content. `.tox`,
    // `.nox` and `.eggs` are the three this task added to the table.
    let fixture = Fixture::new("environments");
    fixture.write("pyproject.toml", "[project]\nname = \"x\"\n");
    for directory in [".venv", "venv", ".tox", ".nox", ".eggs", "__pycache__"] {
        fixture.write(&format!("{directory}/inside.txt"), "not project content\n");
    }
    assert!(fixture.exists(".tox/inside.txt"), "the premise");

    let found = fixture.discover();
    // `scope()`, not `losses()`: an environment SURE declined to walk into on
    // purpose is reported so a person can disagree, and it is not a loss —
    // nothing that was project content went unseen. The distinction is the
    // scan's, and asserting the wrong one here would have said `.venv` was
    // something SURE failed to do.
    let skipped: Vec<(String, SkipReason)> = found
        .scan
        .scope()
        .map(|skipped| (skipped.path.to_string_lossy().into_owned(), skipped.reason))
        .collect();
    let names: Vec<String> = skipped
        .iter()
        .map(|(path, _)| path.replace('\\', "/"))
        .collect();
    for directory in [".venv", "venv", ".tox", ".nox", ".eggs", "__pycache__"] {
        assert!(
            names.iter().any(|path| path == directory),
            "{directory} was not reported as left out; the walk reported {names:?}"
        );
    }
    assert!(
        skipped
            .iter()
            .filter(|(path, _)| [".tox", ".nox", ".eggs"].contains(&path.as_str()))
            .all(|(_, reason)| *reason == SkipReason::Vendored),
        "a tool's environment was reported as something other than vendored"
    );
}

#[test]
fn a_scan_that_looked_at_everything_says_so_and_one_that_did_not_says_what_it_missed() {
    // The property `Discovery::is_complete` rests on, asserted from this
    // ecosystem's side. A report that cannot tell "there is nothing else" from
    // "I stopped early" is the false-comfort case this product ranks worst, and
    // the two are told apart by the *reason* a thing was left out rather than by
    // whether it was.
    let fixture = Fixture::new("completeness");
    fixture.write("pyproject.toml", "[project]\nname = \"x\"\n");
    fixture.write(".git/HEAD", "ref: refs/heads/main\n");
    fixture.write(".git/objects/ab/cdef", "binary-ish\n");
    assert!(fixture.exists(".git/HEAD"), "the premise");

    let found = fixture.discover();
    assert!(
        found.is_complete(),
        "leaving out a version-control directory on purpose is not an incomplete scan"
    );
    assert_eq!(found.losses().count(), 0);
    // And it is still reported, so the person reading the result can say "no, I
    // keep something in there that matters".
    let scope: Vec<String> = found
        .scan
        .scope()
        .map(|skipped| skipped.path.to_string_lossy().replace('\\', "/"))
        .collect();
    assert!(
        scope.iter().any(|path| path == ".git"),
        "a version-control directory was walked: {scope:?}"
    );

    // Now a real loss: a directory deeper than SURE was allowed to go. What is
    // below it was not looked at and could have been anything, which is why this
    // one does make the scan incomplete.
    fixture.write("deep/deeper/deepest/note.txt", "unseen\n");
    let bounded = fixture.discover_with(
        DiscoverOptions::default().with_scan(ScanOptions::default().with_max_depth(2)),
    );
    assert!(
        !bounded.is_complete(),
        "a walk that stopped early reported itself as complete"
    );
    let losses: Vec<String> = bounded
        .losses()
        .map(|skipped| {
            assert_eq!(skipped.reason, SkipReason::TooDeep);
            skipped.path.to_string_lossy().replace('\\', "/")
        })
        .collect();
    assert!(
        losses.iter().any(|path| path.starts_with("deep/")),
        "the depth limit was reached and nothing under it was named: {losses:?}"
    );
}
