#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! .NET discovery and planning: a solution/project file is a project SURE can plan for.

use sure_core::checks::dotnet::DotnetChecks;
use sure_core::discover::{DiscoverOptions, Ecosystem, Findings, discover};
use sure_core::planned_work::CheckOperation;
use sure_core::schedule::PlanBuilder;
use sure_domain::execution::{ExecutionMode, ExecutionPermissions};
use sure_domain::vocabulary::SupportLevel;

fn scratch(name: &str) -> std::path::PathBuf {
    let root = std::env::temp_dir().join(format!("sure-dotnet-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&root).expect("scratch project");
    root
}

#[test]
fn a_solution_is_discovered_as_generic() {
    let root = scratch("discovery");
    std::fs::write(
        root.join("App.sln"),
        "Microsoft Visual Studio Solution File\n",
    )
    .expect("App.sln");
    std::fs::write(
        root.join("App.csproj"),
        "<Project Sdk=\"Microsoft.NET.Sdk\"></Project>\n",
    )
    .expect("App.csproj");

    let discovery = discover(&root, &DiscoverOptions::default()).expect("discover");
    let report = discovery
        .report(Ecosystem::Dotnet)
        .expect("a .NET project was found");
    assert_eq!(report.level, SupportLevel::Generic);
    let Findings::Dotnet(project) = &report.findings else {
        panic!("the .NET report carries a non-.NET finding");
    };
    let manifest = project.manifest.as_ref().expect("the solution was read");
    assert_eq!(manifest.kind.as_str(), "solution");
    assert_eq!(
        project.target.as_deref(),
        Some(std::path::Path::new("App.sln"))
    );
}

#[test]
fn a_solution_plans_test_build_and_format_when_configured() {
    let root = scratch("checks");
    std::fs::write(
        root.join("App.sln"),
        "Microsoft Visual Studio Solution File\n",
    )
    .expect("App.sln");
    std::fs::write(root.join(".editorconfig"), "root = true\n").expect(".editorconfig");
    let discovery = discover(&root, &DiscoverOptions::default()).expect("discover");
    let report = discovery.report(Ecosystem::Dotnet).expect("a .NET project");
    let Findings::Dotnet(project) = &report.findings else {
        panic!("not .NET");
    };
    let checks = DotnetChecks::of(project);
    assert!(checks.missing().is_empty());
    let mut builder = PlanBuilder::new(
        ExecutionMode::HostConfirmed,
        ExecutionPermissions::inspect_only(),
    );
    checks.add_to(project, &root, &mut builder);
    let schedule = builder.build();
    assert_eq!(schedule.checks().len(), 3);
    let commands: Vec<&str> = schedule
        .checks()
        .iter()
        .filter_map(|scheduled| match scheduled.operation() {
            CheckOperation::Command(spec) => Some(spec.program().to_str().unwrap_or("")),
            _ => None,
        })
        .collect();
    assert_eq!(commands, vec!["dotnet", "dotnet", "dotnet"]);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_project_file_with_spaces_stays_one_argument() {
    let root = scratch("spaces");
    std::fs::write(root.join("My App.csproj"), "<Project></Project>\n").expect("My App.csproj");
    let discovery = discover(&root, &DiscoverOptions::default()).expect("discover");
    let report = discovery.report(Ecosystem::Dotnet).expect("a .NET project");
    let Findings::Dotnet(project) = &report.findings else {
        panic!("not .NET");
    };
    let checks = DotnetChecks::of(project);
    let mut builder = PlanBuilder::new(
        ExecutionMode::HostConfirmed,
        ExecutionPermissions::inspect_only(),
    );
    checks.add_to(project, &root, &mut builder);
    let schedule = builder.build();
    let test = schedule
        .checks()
        .iter()
        .find(|check| (*check).proposal().id().as_str().contains("dotnettest"))
        .expect("a test check");
    let CheckOperation::Command(spec) = test.operation() else {
        panic!("not a command");
    };
    let arguments: Vec<&std::ffi::OsStr> =
        spec.arguments().iter().map(|arg| arg.as_os_str()).collect();
    assert!(
        arguments.contains(&std::ffi::OsStr::new("My App.csproj")),
        "{arguments:?}"
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn several_projects_without_a_solution_have_missing_commands() {
    let root = scratch("ambiguous");
    std::fs::write(root.join("A.csproj"), "<Project></Project>\n").expect("A.csproj");
    std::fs::write(root.join("B.csproj"), "<Project></Project>\n").expect("B.csproj");
    let discovery = discover(&root, &DiscoverOptions::default()).expect("discover");
    let report = discovery
        .report(Ecosystem::Dotnet)
        .expect("a .NET project marker");
    assert_eq!(report.level, SupportLevel::InspectOnly);
    let Findings::Dotnet(project) = &report.findings else {
        panic!("not .NET");
    };
    assert!(project.target.is_none());
    let checks = DotnetChecks::of(project);
    assert_eq!(checks.missing().len(), 3);
    let _ = std::fs::remove_dir_all(&root);
}

/// **A solution under `Src/` is still this project's solution.** Measured on
/// `JamesNK/Newtonsoft.Json` (2026-11-02): the root holds no .NET file, and
/// treating that as "not a .NET project" hid a real stack behind a directory
/// layout. `global.json` and `.editorconfig` beside the manifest count too.
#[test]
fn a_solution_under_a_subdirectory_is_still_the_project() {
    let root = scratch("nested-solution");
    let src = root.join("Src");
    std::fs::create_dir_all(&src).expect("Src");
    std::fs::write(src.join("App.slnx"), "<Solution></Solution>\n").expect("App.slnx");
    std::fs::write(
        src.join("global.json"),
        "{\"sdk\": {\"version\": \"9.0.0\"}}\n",
    )
    .expect("global.json");
    std::fs::write(src.join(".editorconfig"), "root = true\n").expect(".editorconfig");

    let discovery = discover(&root, &DiscoverOptions::default()).expect("discover");
    let report = discovery
        .report(Ecosystem::Dotnet)
        .expect("the nested solution was found");
    assert_eq!(report.level, SupportLevel::Generic);
    let Findings::Dotnet(project) = &report.findings else {
        panic!("not .NET");
    };
    let manifest = project.manifest.as_ref().expect("the solution was read");
    assert_eq!(manifest.kind.as_str(), "solution");
    assert_eq!(
        project.target.as_deref(),
        Some(std::path::Path::new("Src/App.slnx"))
    );
    assert!(
        project.global_json,
        "global.json beside the manifest counts"
    );
    assert!(
        project.editorconfig,
        ".editorconfig beside the manifest counts"
    );

    let checks = DotnetChecks::of(project);
    assert!(checks.missing().is_empty());
    let mut builder = PlanBuilder::new(
        ExecutionMode::HostConfirmed,
        ExecutionPermissions::inspect_only(),
    );
    checks.add_to(project, &root, &mut builder);
    let schedule = builder.build();
    assert_eq!(
        schedule.checks().len(),
        3,
        "test, build and the configured format"
    );
    let test = schedule
        .checks()
        .iter()
        .find(|check| (*check).proposal().id().as_str().contains("dotnettest"))
        .expect("a test check");
    let CheckOperation::Command(spec) = test.operation() else {
        panic!("not a command");
    };
    let arguments: Vec<&std::ffi::OsStr> =
        spec.arguments().iter().map(|arg| arg.as_os_str()).collect();
    assert!(
        arguments.contains(&std::ffi::OsStr::new("Src/App.slnx")),
        "the command names the nested solution: {arguments:?}"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// **The shallowest solution wins.** A root file is the project's own before a
/// deeper one is, and the choice does not depend on the order the scan walked
/// the directories in.
#[test]
fn the_shallowest_solution_wins() {
    let root = scratch("nested-shallowest");
    std::fs::write(root.join("App.slnx"), "<Solution></Solution>\n").expect("App.slnx");
    let deep = root.join("tools").join("fixtures");
    std::fs::create_dir_all(&deep).expect("tools/fixtures");
    std::fs::write(deep.join("Example.slnx"), "<Solution></Solution>\n").expect("Example.slnx");

    let discovery = discover(&root, &DiscoverOptions::default()).expect("discover");
    let report = discovery.report(Ecosystem::Dotnet).expect("a .NET project");
    let Findings::Dotnet(project) = &report.findings else {
        panic!("not .NET");
    };
    assert_eq!(
        project.target.as_deref(),
        Some(std::path::Path::new("App.slnx"))
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// **Several project files under a subdirectory are still ambiguous.** The
/// depth-agnostic rule must not quietly turn "which project did you mean" into
/// a guess about the first one the scan met.
#[test]
fn several_nested_project_files_with_no_solution_are_not_guessed() {
    let root = scratch("nested-ambiguous");
    let src = root.join("Src");
    std::fs::create_dir_all(&src).expect("Src");
    std::fs::write(src.join("A.csproj"), "<Project></Project>\n").expect("A.csproj");
    std::fs::write(src.join("B.csproj"), "<Project></Project>\n").expect("B.csproj");

    let discovery = discover(&root, &DiscoverOptions::default()).expect("discover");
    let report = discovery
        .report(Ecosystem::Dotnet)
        .expect("a .NET project marker");
    assert_eq!(report.level, SupportLevel::InspectOnly);
    let Findings::Dotnet(project) = &report.findings else {
        panic!("not .NET");
    };
    assert!(project.target.is_none());
    assert_eq!(project.projects.len(), 2);
    let checks = DotnetChecks::of(project);
    assert_eq!(checks.missing().len(), 3);
    let _ = std::fs::remove_dir_all(&root);
}
