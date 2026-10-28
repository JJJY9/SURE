//! Finding out what a Rust project declares.
//!
//! P2-T006 acceptance:
//!
//! > Detects Cargo workspaces/packages and conventional commands.
//!
//! `docs/architecture/ECOSYSTEM_DISCOVERY.md` is the authority for what is
//! asserted here, and its "Enforced by" table is the index from a statement to
//! the test below that holds it.
//!
//! # Why these tests build real projects
//!
//! Every criterion is about reading files a person wrote, and the parts that can
//! be unit-tested — the tables, the accessors, the rules — already are, in
//! `src/discover/rust.rs`. What is left, and what only a real directory can
//! answer, is whether discovery finds the files at all: whether the walk lists
//! them, whether a file it could not read is reported instead of being treated
//! as a file that is not there, and whether a directory that is not a Rust
//! project is left alone.
//!
//! # The three properties most of this file is about
//!
//! **A manifest that could not be read is not a manifest that is absent.** A
//! project whose `Cargo.toml` failed to parse declares no dependencies, no
//! members and no targets — and so does an empty directory. Reporting the second
//! when the first is true is a false statement about the project, and it is the
//! failure `CLAUDE.md` ranks above a visible error. Several tests below exist
//! only to hold that line.
//!
//! **A `.rs` file is not a Rust project.** The marker list is short on purpose,
//! and this is the ecosystem where a lazy marker would be most tempting: a
//! directory holding one `.rs` file is a directory holding one `.rs` file, and
//! saying it is a Rust project would put a stack in a report that has none.
//!
//! **Discovery at this stage runs nothing.** `build.rs` is a Rust *program* that
//! Cargo compiles and runs before the crate, and this is the ecosystem where
//! "reading the manifest" could most easily turn into running the project. One
//! test writes a `build.rs` that would leave a file behind if anything executed
//! it, and checks that no such file appears.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use sure_core::discover::rust::{
    BuildScript, CommandRole, DependencyKind, ManifestState, Requirement, TargetKind, ToolRole,
};
use sure_core::discover::{
    DiscoverOptions, Discovery, Ecosystem, Findings, RustProject, UnreadReason, UnresolvedReason,
    discover,
};
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
            .join("sure crates discover")
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

    /// The Rust findings, or a panic naming what was found instead.
    fn rust(&self) -> RustProject {
        self.rust_with(DiscoverOptions::default())
    }

    fn rust_with(&self, options: DiscoverOptions) -> RustProject {
        let found = self.discover_with(options);
        let report = found
            .report(Ecosystem::Rust)
            .unwrap_or_else(|| panic!("no Rust findings; found {:?}", found.stacks()));
        assert_eq!(report.ecosystem, Ecosystem::Rust);
        assert!(
            !report.reason.is_empty(),
            "a level has to come with a reason a person can read"
        );
        match &report.findings {
            Findings::Rust(project) => (**project).clone(),
            other => panic!("Rust was reported with {other:?}"),
        }
    }

    /// The command planned for one role, or a panic.
    fn command(&self, role: CommandRole) -> Option<String> {
        self.rust()
            .conventional_commands()
            .into_iter()
            .find(|row| row.role == role)
            .unwrap_or_else(|| panic!("no row for {role:?}"))
            .command
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        // Best effort: a fixture that cannot be removed must not turn a passing
        // test into a failing one, and `target/tmp` is scratch.
        let _ = std::fs::remove_dir_all(&self.project);
    }
}

/// A minimal crate that declares itself.
const MINIMAL: &str = r#"
[package]
name = "sure-fixture"
version = "0.1.0"
edition = "2024"
"#;

#[test]
fn a_cargo_package_is_found_and_what_it_declares_is_read() {
    let fixture = Fixture::new("package");
    fixture.write(
        "Cargo.toml",
        r#"
[package]
name = "sure-fixture"
version = "0.3.1"
edition = "2024"
rust-version = "1.83"
publish = false

[dependencies]
serde = { version = "1", features = ["derive"] }

[dev-dependencies]
pretty_assertions = "1"

[features]
default = ["std"]
std = []
extra = ["dep:serde"]
"#,
    );
    fixture.write("Cargo.lock", "version = 4\n");
    fixture.write(
        "src/lib.rs",
        "pub fn add(a: u32, b: u32) -> u32 { a + b }\n",
    );

    let found = fixture.discover();
    let report = found.report(Ecosystem::Rust).expect("a Rust report");
    assert_eq!(report.level, SupportLevel::Generic);
    // Everything the conclusion rests on is named, so a reader can go and look.
    assert_eq!(
        report.found_by,
        vec![PathBuf::from("Cargo.lock"), PathBuf::from("Cargo.toml")]
    );

    let project = fixture.rust();
    assert!(project.lockfile);
    let package = project.package().expect("a package table");
    assert_eq!(package.name.as_deref(), Some("sure-fixture"));
    assert_eq!(package.version.as_deref(), Some("0.3.1"));
    assert_eq!(package.edition.as_deref(), Some("2024"));
    assert_eq!(package.rust_version.as_deref(), Some("1.83"));
    assert_eq!(package.publishes, Some(false));
    assert_eq!(package.dependencies.len(), 2);
    assert_eq!(
        package.dependencies_of(DependencyKind::Development).count(),
        1
    );

    // A feature list is a list, and `default` is reported by name rather than by
    // being first.
    let features: Vec<(&str, bool)> = package
        .features
        .iter()
        .map(|feature| (feature.name.as_str(), feature.default))
        .collect();
    assert_eq!(
        features,
        vec![("default", true), ("extra", false), ("std", false)]
    );
    assert_eq!(package.features[1].enables, vec!["dep:serde"]);

    // `src/lib.rs` is reported as what is at the path, and nothing was read from
    // it: discovery does not look inside source files.
    assert_eq!(
        project.conventional_targets,
        vec![sure_core::discover::rust::ConventionalTarget {
            path: PathBuf::from("src/lib.rs"),
            kind: TargetKind::Library,
        }]
    );
}

#[test]
fn a_virtual_manifest_is_a_manifest_and_its_members_are_read() {
    let fixture = Fixture::new("workspace");
    fixture.write(
        "Cargo.toml",
        r#"
[workspace]
resolver = "2"
members = ["crates/parser", "crates/serializer"]

[workspace.dependencies]
serde = "1"

[workspace.lints.clippy]
unwrap_used = "warn"
"#,
    );
    for (name, extra) in [
        ("parser", "\n[dependencies]\nserde = { workspace = true }\n"),
        ("serializer", "\n[dependencies]\ntokio = \"1\"\n"),
    ] {
        fixture.write(
            &format!("crates/{name}/Cargo.toml"),
            &format!("[package]\nname = \"{name}\"\nversion = \"0.1.0\"\n{extra}"),
        );
        fixture.write(&format!("crates/{name}/src/lib.rs"), "");
    }

    let project = fixture.rust();

    // A virtual manifest has no package, and it is still a manifest SURE read.
    assert!(project.package().is_none());
    assert_eq!(
        fixture
            .discover()
            .report(Ecosystem::Rust)
            .expect("a report")
            .level,
        SupportLevel::Generic
    );

    let workspaces = &project.workspaces;
    assert!(workspaces.is_declared());
    assert!(workspaces.names_any_member());
    assert_eq!(workspaces.declared_by.len(), 1);
    assert_eq!(workspaces.declared_by[0].path, PathBuf::from("Cargo.toml"));
    assert_eq!(
        workspaces.tables.patterns,
        vec!["crates/parser", "crates/serializer"]
    );
    assert_eq!(workspaces.tables.inherited, vec!["serde"]);
    assert!(workspaces.unresolved.is_empty());

    // Compared as paths and not as strings: a member path is built by joining
    // components, so it carries the platform's separator, and `Path` equality is
    // component-based. A string comparison here would pass on the Unix jobs and
    // fail on Windows for a path that is the same path.
    let members: Vec<(&Path, Option<&str>)> = workspaces
        .members
        .iter()
        .map(|member| {
            (
                member.path.as_path(),
                member
                    .package
                    .as_deref()
                    .and_then(|package| package.name.as_deref()),
            )
        })
        .collect();
    assert_eq!(
        members,
        vec![
            (Path::new("crates/parser"), Some("parser")),
            (Path::new("crates/serializer"), Some("serializer")),
        ]
    );

    // Tooling comes from every manifest that was read, and names the file it
    // came from — a crate in `crates/serializer` is not a crate the root
    // declared.
    let tokio = project
        .tooling
        .iter()
        .find(|tool| tool.package == "tokio")
        .expect("tokio was declared in a member");
    assert_eq!(tokio.role, ToolRole::AsyncRuntime);
    assert_eq!(tokio.from, PathBuf::from("crates/serializer/Cargo.toml"));
    assert_eq!(project.dependencies(), vec![], "the root has no package");

    // `[workspace.lints.clippy]` is the workspace saying it runs the linter, and
    // a virtual manifest has no other place to say it.
    assert_eq!(
        fixture.command(CommandRole::Lint).as_deref(),
        Some("cargo clippy --all-targets")
    );
    assert_eq!(
        fixture.command(CommandRole::Build).as_deref(),
        Some("cargo build")
    );
    // ...and a workspace has no program of its own to run.
    assert_eq!(fixture.command(CommandRole::Run), None);
}

#[test]
fn a_member_pattern_sure_will_not_expand_is_reported_rather_than_dropped() {
    let fixture = Fixture::new("glob");
    fixture.write(
        "Cargo.toml",
        r#"
[workspace]
members = ["crates/**", "crates/*"]
"#,
    );
    fixture.write("crates/one/Cargo.toml", "[package]\nname = \"one\"\n");
    fixture.write("crates/one/src/lib.rs", "");

    let project = fixture.rust();
    let unresolved: Vec<(&str, UnresolvedReason)> = project
        .workspaces
        .unresolved
        .iter()
        .map(|entry| (entry.pattern.as_str(), entry.reason))
        .collect();
    // `crates/**` is refused and said so. The `*` beside it is expanded, which
    // is why the refusal has to be a value rather than an empty list: the
    // workspace below is smaller than the patterns name, and the reason says so.
    assert_eq!(
        unresolved,
        vec![("crates/**", UnresolvedReason::UnsupportedPattern)]
    );
    assert_eq!(project.workspaces.members.len(), 1);
    assert_eq!(
        project.workspaces.members[0].path,
        PathBuf::from("crates/one")
    );
    assert!(!project.workspaces.truncated);
    assert!(
        project.workspaces.unresolved[0]
            .reason
            .plain_description()
            .len()
            > 20,
        "a refusal has to come with a sentence"
    );
}

#[test]
fn a_member_pattern_that_would_leave_the_project_is_refused() {
    let fixture = Fixture::new("escape");
    fixture.write(
        "Cargo.toml",
        r#"
[workspace]
members = ["../outside", "/etc", "crates/../../escape"]
"#,
    );

    let project = fixture.rust();
    assert!(project.workspaces.members.is_empty());
    assert_eq!(project.workspaces.unresolved.len(), 3);
    for entry in &project.workspaces.unresolved {
        assert_eq!(entry.reason, UnresolvedReason::NotInsideProject);
        assert_eq!(entry.reason.as_str(), "not_inside_project");
    }
}

#[test]
fn a_member_the_exclude_list_also_names_is_reported_as_both() {
    let fixture = Fixture::new("exclude");
    fixture.write(
        "Cargo.toml",
        r#"
[workspace]
members = ["crates/*"]
exclude = ["crates/experiments"]
"#,
    );
    for name in ["kept", "experiments"] {
        fixture.write(
            &format!("crates/{name}/Cargo.toml"),
            &format!("[package]\nname = \"{name}\"\n"),
        );
    }

    let project = fixture.rust();
    // Both facts are here, and neither has been applied: whether `exclude`
    // removes a directory `members` named is Cargo's rule, and SURE reports the
    // overlap rather than asserting an answer it cannot cite.
    assert_eq!(project.workspaces.members.len(), 2);
    assert_eq!(
        project.workspaces.excluded_members,
        vec![PathBuf::from("crates/experiments")]
    );
    assert_eq!(
        project.workspaces.tables.excluded,
        vec!["crates/experiments"]
    );
}

#[test]
fn members_beyond_the_limit_are_cut_and_the_workspace_says_so() {
    let fixture = Fixture::new("truncated");
    let members: Vec<String> = (0..5).map(|n| format!("\"crates/m{n}\"")).collect();
    fixture.write(
        "Cargo.toml",
        &format!("[workspace]\nmembers = [{}]\n", members.join(", ")),
    );
    for n in 0..5 {
        fixture.write(
            &format!("crates/m{n}/Cargo.toml"),
            &format!("[package]\nname = \"m{n}\"\n"),
        );
    }

    let project = fixture.rust_with(DiscoverOptions::default().with_max_workspace_members(2));
    assert_eq!(project.workspaces.members.len(), 2);
    assert!(
        project.workspaces.truncated,
        "a member list that was cut short has to say so, or the workspace looks \
         like it is the whole one"
    );
}

#[test]
fn a_manifest_that_could_not_be_read_is_not_a_manifest_that_is_absent() {
    let unreadable = Fixture::new("unreadable");
    unreadable.write("Cargo.toml", "[package\nname = \"broken\"\n");

    let empty = Fixture::new("empty");
    empty.write("Cargo.lock", "version = 4\n");

    let broken = unreadable.rust();
    let absent = empty.rust();

    // The two projects are both reported, and they are not reported the same
    // way. This is the whole of the distinction: an unreadable manifest is a
    // finding about the project, and a missing one is a fact about it.
    assert!(
        matches!(broken.manifest, ManifestState::Unread(_)),
        "a manifest that failed to parse was reported as read"
    );
    assert!(!broken.manifest.is_absent());
    assert!(broken.manifest.package().is_none());
    assert!(absent.manifest.is_absent());
    assert!(absent.lockfile, "the lockfile is what made this a project");

    assert_eq!(
        unreadable
            .discover()
            .report(Ecosystem::Rust)
            .expect("a report")
            .level,
        SupportLevel::InspectOnly
    );
    assert_eq!(
        empty
            .discover()
            .report(Ecosystem::Rust)
            .expect("a report")
            .level,
        SupportLevel::InspectOnly
    );
    // The reason says which of the two happened, so a reader does not have to
    // infer it from the level.
    assert!(
        unreadable
            .discover()
            .report(Ecosystem::Rust)
            .expect("a report")
            .reason
            .contains("could not read")
    );
    assert!(
        empty
            .discover()
            .report(Ecosystem::Rust)
            .expect("a report")
            .reason
            .contains("Cargo.lock")
    );

    // And the file that could not be read is named, with a reason.
    let unread = unreadable.discover().unread;
    assert_eq!(unread.len(), 1);
    assert_eq!(unread[0].path, PathBuf::from("Cargo.toml"));
    assert!(matches!(unread[0].reason, UnreadReason::NotParsed { .. }));
    assert!(empty.discover().unread.is_empty());
}

#[test]
fn a_rust_source_file_alone_is_not_a_rust_project() {
    // The marker list, which is the thing this test exists for. A directory with
    // a `.rs` file in it is a directory with a `.rs` file in it: nothing here
    // says the project is built with cargo, and reporting a stack on this
    // evidence would put a Rust entry in a report about some other project.
    let fixture = Fixture::new("stray-source");
    fixture.write("src/main.rs", "fn main() {}\n");
    fixture.write("notes.rs", "// a snippet somebody pasted\n");

    let found = fixture.discover();
    assert!(
        found.report(Ecosystem::Rust).is_none(),
        "one .rs file made this a Rust project"
    );
    assert!(found.ecosystems.is_empty());
    // Not looking is reported as not looking: the list of what was looked for is
    // what says the absence is an answer rather than a gap.
    assert!(found.looked_for().contains(&Ecosystem::Rust));
    assert!(found.is_complete(), "the walk found the whole of this");
}

#[test]
fn a_directory_that_is_not_a_rust_project_is_left_entirely_alone() {
    let fixture = Fixture::new("not-rust");
    fixture.write("README.md", "# notes\n");
    fixture.write("src/index.js", "export const x = 1;\n");
    fixture.write("package.json", "{\"name\":\"js-only\"}\n");

    let found = fixture.discover();
    assert!(found.report(Ecosystem::Rust).is_none());
    assert!(
        found.unread.is_empty(),
        "a directory with no Rust project in it produced a Rust finding: {:?}",
        found.unread
    );
    // The Node project beside it is still found, so the absence above is about
    // Rust and not about discovery having failed.
    assert!(found.report(Ecosystem::Node).is_some());
}

#[test]
fn a_toolchain_pin_is_a_marker_on_its_own_and_its_components_are_read() {
    let fixture = Fixture::new("toolchain-only");
    fixture.write(
        "rust-toolchain.toml",
        r#"
[toolchain]
channel = "1.83.0"
components = ["clippy", "rustfmt"]
targets = ["wasm32-unknown-unknown"]
"#,
    );

    // No Cargo.toml and no lockfile: the pin is the only marker, and it is
    // enough for SURE to say this is a Rust project it could not read a build
    // for.
    let found = fixture.discover();
    let report = found.report(Ecosystem::Rust).expect("a Rust report");
    assert_eq!(report.level, SupportLevel::InspectOnly);
    assert_eq!(report.found_by, vec![PathBuf::from("rust-toolchain.toml")]);

    let project = fixture.rust();
    let toolchain = project.toolchain.toolchain().expect("the pin");
    assert_eq!(toolchain.file, "rust-toolchain.toml");
    assert_eq!(toolchain.channel.as_deref(), Some("1.83.0"));
    assert_eq!(toolchain.targets, vec!["wasm32-unknown-unknown"]);
    assert!(project.toolchain.asks_for("clippy"));
    assert!(!project.toolchain.asks_for("miri"));

    // A component is a claim about what the project asked to have installed, and
    // it is what makes clippy a command the project asked for. With no manifest
    // read, though, no command is planned at all.
    assert_eq!(fixture.command(CommandRole::Lint), None);
    assert_eq!(fixture.command(CommandRole::Build), None);
}

#[test]
fn a_toolchain_file_that_could_not_be_read_is_not_a_project_that_pins_nothing() {
    let fixture = Fixture::new("unreadable-toolchain");
    fixture.write("Cargo.toml", MINIMAL);
    // A `[toolchain]` table that is not valid TOML. Read as "no pin" it would
    // report a project that pins nothing, which is a fact about a different
    // project.
    fixture.write("rust-toolchain.toml", "[toolchain\nchannel = \n");

    let project = fixture.rust();
    assert!(
        matches!(
            project.toolchain,
            sure_core::discover::rust::ToolchainState::Unread(_)
        ),
        "an unreadable pin was reported as no pin"
    );
    assert!(!project.toolchain.is_absent());
    let unread = fixture.discover().unread;
    assert_eq!(unread.len(), 1);
    assert_eq!(unread[0].path, PathBuf::from("rust-toolchain.toml"));
    // Its commands are unaffected: clippy is simply not something the project
    // was shown to have asked for.
    assert_eq!(fixture.command(CommandRole::Lint), None);
    assert_eq!(
        fixture.command(CommandRole::Build).as_deref(),
        Some("cargo build")
    );
}

#[test]
fn a_build_script_is_reported_as_a_target_and_never_run() {
    let fixture = Fixture::new("build-script");
    fixture.write("Cargo.toml", MINIMAL);
    fixture.write("src/lib.rs", "");
    // A program Cargo compiles and runs before the crate. If anything in
    // discovery executed it, `ran.txt` would appear beside it.
    fixture.write(
        "build.rs",
        "fn main() {\n    std::fs::write(\"ran.txt\", \"the build script ran\").unwrap();\n}\n",
    );

    let project = fixture.rust();
    let kinds: Vec<TargetKind> = project
        .conventional_targets
        .iter()
        .map(|target| target.kind)
        .collect();
    assert!(kinds.contains(&TargetKind::BuildScript));
    assert_eq!(
        project.package().expect("a package").build,
        BuildScript::Unstated,
        "the key is absent, which is a different fact from `build = false`"
    );
    assert!(
        !fixture.path().join("ran.txt").exists(),
        "discovery ran the project's build script"
    );
    // Nothing about the build script's *contents* is reported: only that
    // something is at the path.
    let found = fixture.discover();
    let report = found.report(Ecosystem::Rust).expect("a report");
    assert_eq!(
        report.found_by,
        vec![PathBuf::from("Cargo.toml")],
        "the build script is a target, not evidence the level rests on"
    );
}

#[test]
fn the_conventional_commands_are_planned_from_what_the_project_declared() {
    let fixture = Fixture::new("commands");
    fixture.write(
        "Cargo.toml",
        r#"
[package]
name = "sure-fixture"
version = "0.1.0"
edition = "2024"

[dependencies]
axum = "0.7"

[dev-dependencies]
criterion = "0.5"
"#,
    );
    fixture.write("src/main.rs", "fn main() {}\n");
    fixture.write("benches", ".keep");
    fixture.write("clippy.toml", "msrv = \"1.83\"\n");
    fixture.write("rustfmt.toml", "edition = \"2024\"\n");

    let project = fixture.rust();
    assert!(project.declares("axum"));
    assert!(!project.declares("serde"));
    assert_eq!(
        project
            .tooling_of_role(ToolRole::BenchmarkRunner)
            .map(|tool| tool.package)
            .collect::<Vec<_>>(),
        vec!["criterion"]
    );

    let rows: Vec<(CommandRole, Option<String>)> = project
        .conventional_commands()
        .into_iter()
        .map(|row| (row.role, row.command))
        .collect();
    assert_eq!(
        rows,
        vec![
            (CommandRole::Build, Some("cargo build".to_owned())),
            (CommandRole::Test, Some("cargo test".to_owned())),
            (
                CommandRole::Check,
                Some("cargo check --all-targets".to_owned())
            ),
            (
                CommandRole::Lint,
                Some("cargo clippy --all-targets".to_owned())
            ),
            (CommandRole::Format, Some("cargo fmt".to_owned())),
            (CommandRole::Document, Some("cargo doc".to_owned())),
            (CommandRole::Run, Some("cargo run".to_owned())),
            (CommandRole::Bench, Some("cargo bench".to_owned())),
            (CommandRole::Clean, Some("cargo clean".to_owned())),
        ]
    );

    // Every command is one of a fixed set of strings, and no crate name, file
    // name or package name that a project wrote is anywhere in them.
    let constants: BTreeSet<&str> = [
        "cargo build",
        "cargo test",
        "cargo check --all-targets",
        "cargo clippy --all-targets",
        "cargo fmt",
        "cargo doc",
        "cargo run",
        "cargo bench",
        "cargo clean",
    ]
    .into_iter()
    .collect();
    for (_, command) in &rows {
        if let Some(command) = command {
            assert!(
                constants.contains(command.as_str()),
                "{command} is not one of the commands SURE knows how to plan"
            );
        }
    }
}

#[test]
fn a_project_with_nothing_configured_is_told_what_it_has_no_way_to_do() {
    let fixture = Fixture::new("bare");
    fixture.write("Cargo.toml", MINIMAL);
    fixture.write("src/lib.rs", "");

    let project = fixture.rust();
    let rows = project.conventional_commands();
    let planned: Vec<CommandRole> = rows
        .iter()
        .filter(|row| row.is_planned())
        .map(|row| row.role)
        .collect();
    // A row for every role, and the three that need something the project does
    // not have are present with no command — which is how "there is no way to
    // check this project's types" is reported at all.
    assert_eq!(rows.len(), CommandRole::ALL.len());
    assert_eq!(
        planned,
        vec![
            CommandRole::Build,
            CommandRole::Test,
            CommandRole::Check,
            CommandRole::Document,
            CommandRole::Clean,
        ]
    );
    for row in rows.iter().filter(|row| row.command.is_none()) {
        assert!(
            row.because.is_empty(),
            "{:?} has no command and still carries a reason for one",
            row.role
        );
    }
}

#[test]
fn the_files_sure_read_are_named_and_sure_writes_nothing() {
    let fixture = Fixture::new("no-writes");
    fixture.write("Cargo.toml", MINIMAL);
    fixture.write("Cargo.lock", "version = 4\n");
    fixture.write("rust-toolchain.toml", "[toolchain]\nchannel = \"stable\"\n");
    fixture.write("clippy.toml", "");
    fixture.write("rustfmt.toml", "");
    fixture.write("src/lib.rs", "");

    let before = listing(fixture.path());
    let discovery = fixture.discover();
    let after = listing(fixture.path());
    assert_eq!(before, after, "discovery wrote into the project");

    let report = discovery.report(Ecosystem::Rust).expect("a report");
    assert_eq!(
        report.found_by,
        vec![
            PathBuf::from("Cargo.lock"),
            PathBuf::from("Cargo.toml"),
            PathBuf::from("rust-toolchain.toml"),
            PathBuf::from("rustfmt.toml"),
            PathBuf::from("clippy.toml"),
        ]
    );
    // Neither configuration file is parsed, and both are still evidence that the
    // project asked for the tool.
    let project = fixture.rust();
    assert_eq!(project.linter_config, Some("clippy.toml"));
    assert_eq!(project.formatter_config, Some("rustfmt.toml"));
    assert!(discovery.unread.is_empty());
}

#[test]
fn one_budget_is_shared_by_every_ecosystem_and_reaching_it_says_so() {
    let fixture = Fixture::new("shared-budget");
    fixture.write("package.json", "{\"name\":\"js\"}\n");
    fixture.write("pyproject.toml", "[project]\nname = \"py\"\n");
    fixture.write("Cargo.toml", MINIMAL);

    // One manifest's worth of budget, and three ecosystems that each want one.
    // The order is `Ecosystem::ALL`, so Node reads the manifest and the other
    // two do not.
    let found = fixture.discover_with(DiscoverOptions::default().with_max_manifests(1));
    assert!(found.report(Ecosystem::Node).is_some());
    assert_eq!(
        found.report(Ecosystem::Node).expect("a report").level,
        SupportLevel::Generic
    );

    // The two that were not reached say they were not reached. This is the whole
    // point of a shared budget being reported: "SURE did not read this" and
    // "this declares nothing" are different facts, and a level of `InspectOnly`
    // with a reason that names what happened is the first.
    let rust = found.report(Ecosystem::Rust).expect("a Rust report");
    assert_eq!(rust.level, SupportLevel::InspectOnly);

    // Read again through the fixture helper, which is where the findings
    // themselves are unwrapped.
    let project = fixture.rust_with(DiscoverOptions::default().with_max_manifests(1));
    assert!(
        matches!(project.manifest, ManifestState::Unread(_)),
        "the manifest SURE could not afford to read was reported as read"
    );
    assert_eq!(
        project
            .conventional_commands()
            .iter()
            .filter(|row| row.is_planned())
            .count(),
        0,
        "a command was planned for a project whose manifest SURE never read"
    );

    // Every later ecosystem reports the file it did not read, and the count is
    // two and not one: one `Budget` is built per discovery and threaded through
    // all of `Ecosystem::ALL`, so the first ecosystem to spend it starves every
    // ecosystem after it rather than just the next one. That is the fact worth
    // pinning — a caller that raised `max_manifests` to fix Python would find
    // Rust still starved if this were per-pair rather than shared.
    let out_of_budget: Vec<(&Path, usize)> = found
        .unread
        .iter()
        .filter_map(|unread| match unread.reason {
            UnreadReason::OutOfBudget { limit } => Some((unread.path.as_path(), limit)),
            _ => None,
        })
        .collect();
    assert_eq!(
        out_of_budget,
        vec![
            (Path::new("pyproject.toml"), 1),
            (Path::new("Cargo.toml"), 1),
        ],
        "a file SURE ran out of budget before is a finding and not a silence"
    );
}

#[test]
fn a_directory_that_is_every_ecosystem_at_once_is_reported_as_all_of_them() {
    let fixture = Fixture::new("everything");
    fixture.write("package.json", "{\"name\":\"js\"}\n");
    fixture.write("pyproject.toml", "[project]\nname = \"py\"\n");
    fixture.write("Cargo.toml", MINIMAL);
    fixture.write("go.mod", "module example.com/everything\n\ngo 1.21\n");
    fixture.write(
        "Everything.csproj",
        "<Project Sdk=\"Microsoft.NET.Sdk\"></Project>\n",
    );
    fixture.write(
        "pom.xml",
        "<project><artifactId>everything</artifactId></project>\n",
    );

    let found = fixture.discover();
    let ecosystems: Vec<Ecosystem> = found
        .ecosystems
        .iter()
        .map(|report| report.ecosystem)
        .collect();
    assert_eq!(
        ecosystems,
        vec![
            Ecosystem::Node,
            Ecosystem::Python,
            Ecosystem::Rust,
            Ecosystem::Go,
            Ecosystem::Dotnet,
            Ecosystem::Java,
        ],
        "the reports are in the order of the list that says what was looked for"
    );
    assert_eq!(ecosystems, found.looked_for());
    let stacks = found.stacks();
    assert_eq!(
        stacks
            .iter()
            .map(|stack| stack.stack.as_str())
            .collect::<Vec<_>>(),
        vec!["node", "python", "rust", "go", "dotnet", "java"]
    );
    for stack in &stacks {
        assert!(!stack.reason.is_empty());
    }
}

#[test]
fn a_member_with_no_manifest_is_described_rather_than_skipped() {
    let fixture = Fixture::new("member-without-manifest");
    fixture.write("Cargo.toml", "[workspace]\nmembers = [\"crates/*\"]\n");
    fixture.write("crates/real/Cargo.toml", "[package]\nname = \"real\"\n");
    fixture.write("crates/empty/README.md", "nothing here yet\n");

    let project = fixture.rust();
    assert_eq!(project.workspaces.members.len(), 2);
    let descriptions: Vec<(&Path, bool)> = project
        .workspaces
        .members
        .iter()
        .map(|member| (member.path.as_path(), member.package.is_some()))
        .collect();
    assert_eq!(
        descriptions,
        vec![
            (Path::new("crates/empty"), false),
            (Path::new("crates/real"), true),
        ]
    );
    assert_eq!(
        project.workspaces.readable_members().count(),
        1,
        "only the member with a manifest declares anything"
    );
    // A member with no manifest is `Absent`, which is a different fact from a
    // member whose manifest could not be read — and neither is skipped.
    assert_eq!(
        project.workspaces.members[0].manifest,
        sure_core::discover::MemberManifest::Absent
    );
    assert_eq!(
        project.workspaces.members[1].manifest,
        sure_core::discover::MemberManifest::Present
    );
}

#[test]
fn a_manifest_that_is_oversized_is_reported_rather_than_half_read() {
    let fixture = Fixture::new("oversized");
    fixture.write("Cargo.toml", MINIMAL);
    fixture.write("Cargo.lock", "version = 4\n");

    // A limit below the manifest's size. Half a `Cargo.toml` is not a smaller
    // `Cargo.toml`, and reading the first however-many bytes would produce a
    // parse failure that has nothing to do with the project.
    let project = fixture.rust_with(DiscoverOptions::default().with_max_manifest_bytes(8));
    assert!(matches!(
        project.manifest,
        ManifestState::Unread(UnreadReason::TooLarge { .. })
    ));
    assert!(project.package().is_none());

    let unread = fixture
        .discover_with(DiscoverOptions::default().with_max_manifest_bytes(8))
        .unread;
    assert_eq!(unread.len(), 1);
    assert_eq!(unread[0].path, PathBuf::from("Cargo.toml"));
    assert!(matches!(
        unread[0].reason,
        UnreadReason::TooLarge { limit: 8 }
    ));
}

#[test]
fn a_requirement_is_recorded_as_written_and_never_resolved() {
    let fixture = Fixture::new("requirements");
    fixture.write(
        "Cargo.toml",
        r#"
[package]
name = "sure-fixture"
version = "0.1.0"

[dependencies]
serde = ">=1.0, <2.0"
local = { path = "../local" }
inherited = { workspace = true }

[target.'cfg(windows)'.dependencies]
winapi = "0.3"
"#,
    );

    let project = fixture.rust();
    let package = project.package().expect("a package");
    let find = |name: &str| {
        package
            .dependencies
            .iter()
            .find(|entry| entry.name == name)
            .unwrap_or_else(|| panic!("no dependency named {name}"))
    };
    // Verbatim, including the range SURE has not resolved and cannot say the
    // meaning of.
    assert_eq!(
        find("serde").requirement,
        Requirement::Stated(">=1.0, <2.0".to_owned())
    );
    assert_eq!(find("local").requirement, Requirement::Unstated);
    assert_eq!(find("inherited").requirement, Requirement::FromWorkspace);
    assert_eq!(find("winapi").target.as_deref(), Some("cfg(windows)"));
    assert_eq!(
        find("serde").requirement.as_str(),
        "stated",
        "the stable name is what a caller matches on"
    );
}

/// Every path under a directory, relative and sorted.
///
/// Used to assert that discovery wrote nothing. Relative so the project's own
/// awkward path — a space, a non-ASCII character — is not part of the
/// comparison.
fn listing(root: &Path) -> Vec<String> {
    let mut found = Vec::new();
    let mut queue = vec![root.to_path_buf()];
    while let Some(directory) = queue.pop() {
        let entries = std::fs::read_dir(&directory)
            .unwrap_or_else(|error| panic!("cannot list {}: {error}", directory.display()));
        for entry in entries {
            let entry = entry.expect("a directory entry");
            let path = entry.path();
            if path.is_dir() {
                queue.push(path.clone());
            }
            found.push(
                path.strip_prefix(root)
                    .expect("a path under the root")
                    .to_string_lossy()
                    .replace('\\', "/"),
            );
        }
    }
    found.sort();
    found
}

#[test]
fn a_cargo_toml_that_is_not_a_manifest_is_still_not_a_project_that_declares_nothing() {
    // The shape check in `Manifest::from_json` — "is this a table?" — cannot be
    // reached from a file, because TOML documents *are* tables: a document that
    // is not one is a parse error, which is a `NotParsed` and not a `WrongShape`.
    // What this asserts is therefore the reachable half, and it is the half that
    // matters: text under the name `Cargo.toml` that is not a manifest leaves the
    // project unread rather than empty.
    //
    // Asserted concretely, because the difference is not academic. `5` is the
    // smallest thing that could be mistaken for a document; reported as a
    // manifest it would be a project with no dependencies, no members and no
    // targets, which is a claim about a project SURE never read.
    let fixture = Fixture::new("non-manifest");
    fixture.write("Cargo.toml", "5\n");

    let project = fixture.rust();
    assert!(
        matches!(project.manifest, ManifestState::Unread(_)),
        "text that is not a manifest was reported as one"
    );
    assert!(!project.manifest.is_absent());
    assert!(project.manifest.package().is_none());
    assert!(
        !project.workspaces.is_declared(),
        "nothing declared a workspace"
    );

    let found = fixture.discover();
    let report = found.report(Ecosystem::Rust).expect("a report");
    assert_eq!(report.level, SupportLevel::InspectOnly);
    assert!(
        report.reason.contains("could not read"),
        "the reason does not say the manifest was unreadable: {}",
        report.reason
    );

    // The file is named with the reason SURE has, which is that the text did not
    // parse — not that the shape was wrong, which is what a value that parsed
    // would have produced.
    assert_eq!(found.unread.len(), 1);
    assert_eq!(found.unread[0].path, PathBuf::from("Cargo.toml"));
    assert!(
        matches!(found.unread[0].reason, UnreadReason::NotParsed { .. }),
        "the reason is not a parse failure: {:?}",
        found.unread[0].reason
    );

    // And no command rests on it.
    for role in CommandRole::ALL {
        assert_eq!(
            fixture.command(*role),
            None,
            "{role:?} was planned from a manifest SURE did not read"
        );
    }
}

#[test]
fn a_toolchain_file_sure_could_not_read_is_not_a_project_that_pins_nothing() {
    // The other route to the same state, and the reason it needs its own test:
    // `a_toolchain_file_that_could_not_be_read_is_not_a_project_that_pins_nothing`
    // uses a toolchain file SURE *read* and could not make sense of, which is
    // one arm of `read_toolchain`. This one is a file SURE could not read at
    // all, which is a different arm, and a mutation that collapses only the
    // second one into "no pin" is invisible to the first.
    let fixture = Fixture::new("oversized-toolchain");
    fixture.write("Cargo.toml", "[package]\n");
    let mut toolchain =
        String::from("[toolchain]\nchannel = \"stable\"\ncomponents = [\"clippy\"]\n");
    while toolchain.len() < 512 {
        toolchain.push_str("# padding so the file is larger than the limit\n");
    }
    fixture.write("rust-toolchain.toml", &toolchain);

    let options = DiscoverOptions::default().with_max_manifest_bytes(64);
    let project = fixture.rust_with(options);
    assert!(
        matches!(
            project.toolchain,
            sure_core::discover::rust::ToolchainState::Unread(_)
        ),
        "a pin SURE could not read was reported as no pin"
    );
    assert!(
        !project.toolchain.is_absent(),
        "there is a toolchain file here, and it is not an absent one"
    );
    // Nothing is claimed from a file that was not read, in either direction.
    assert!(!project.toolchain.asks_for("clippy"));
    assert!(project.toolchain.toolchain().is_none());

    // The manifest was read in full and the toolchain was not, so the level is
    // the manifest's — the two are graded separately and this test is about the
    // second.
    assert!(
        fixture
            .discover_with(options)
            .report(Ecosystem::Rust)
            .expect("a report")
            .level
            == SupportLevel::Generic
    );

    let found = fixture.discover_with(options);
    assert_eq!(found.unread.len(), 1, "{:?}", found.unread);
    assert_eq!(found.unread[0].path, PathBuf::from("rust-toolchain.toml"));
    assert!(
        matches!(found.unread[0].reason, UnreadReason::TooLarge { .. }),
        "the reason is not that the file was too large: {:?}",
        found.unread[0].reason
    );
}

#[test]
fn a_member_whose_cargo_toml_is_not_a_file_is_not_a_member_with_no_manifest() {
    // A directory called `Cargo.toml`. Nothing declares anything here either
    // way, which is why the two are easy to conflate — but one is a member with
    // no manifest and the other is a member whose manifest SURE does not read,
    // and only the first is a fact the project's own tree states.
    let fixture = Fixture::new("member-manifest-is-a-directory");
    fixture.write("Cargo.toml", "[workspace]\nmembers = [\"crates/*\"]\n");
    fixture.write("crates/odd/Cargo.toml/README.md", "not a manifest\n");
    fixture.write("crates/real/Cargo.toml", "[package]\nname = \"real\"\n");

    let project = fixture.rust();
    assert_eq!(project.workspaces.members.len(), 2);
    assert_eq!(
        project.workspaces.members[0].manifest,
        sure_core::discover::MemberManifest::NotReadable("a directory")
    );
    assert_eq!(
        project.workspaces.members[1].manifest,
        sure_core::discover::MemberManifest::Present
    );
    assert!(
        project.workspaces.members[0].package.is_none(),
        "nothing was declared from a manifest that is not a file"
    );
    assert_eq!(
        project.workspaces.readable_members().count(),
        1,
        "only the member whose manifest is a file declares anything"
    );
}

#[test]
fn the_targets_cargo_finds_without_a_table_are_found_in_both_of_their_shapes() {
    // Cargo's conventional target paths are six, and four of them are
    // directories. A check that looked for a file at all six would find the two
    // files and silently report no tests, examples or benchmarks — a shorter
    // program than the one the project has, which is the answer this product
    // exists not to give.
    let fixture = Fixture::new("conventional-targets");
    fixture.write("Cargo.toml", MINIMAL);
    fixture.write("src/lib.rs", "");
    fixture.write("src/main.rs", "");
    fixture.write("src/bin/tool.rs", "");
    fixture.write("examples/demo.rs", "");
    fixture.write("tests/smoke.rs", "");
    fixture.write("benches/throughput.rs", "");
    fixture.write("build.rs", "fn main() {}\n");

    let project = fixture.rust();
    let found: Vec<(&Path, TargetKind)> = project
        .conventional_targets
        .iter()
        .map(|target| (target.path.as_path(), target.kind))
        .collect();
    // In the order the table names them, which is the order they are reported
    // in: the two files Cargo looks for first, then the four directories.
    assert_eq!(
        found,
        vec![
            (Path::new("src/lib.rs"), TargetKind::Library),
            (Path::new("src/main.rs"), TargetKind::Binary),
            (Path::new("src/bin"), TargetKind::Binary),
            (Path::new("examples"), TargetKind::Example),
            (Path::new("tests"), TargetKind::Test),
            (Path::new("benches"), TargetKind::Benchmark),
            (Path::new("build.rs"), TargetKind::BuildScript),
        ]
    );

    // And a directory target is what makes the roles available, which is the
    // consequence: `cargo test` acts on `tests/`, and `cargo bench` on
    // `benches/`.
    assert_eq!(
        fixture.command(CommandRole::Bench).as_deref(),
        Some("cargo bench")
    );
    assert_eq!(
        fixture.command(CommandRole::Test).as_deref(),
        Some("cargo test")
    );
}
