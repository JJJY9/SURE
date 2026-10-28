#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Go discovery and planning: a Go module is a project SURE can plan for.

use sure_core::checks::go::GoChecks;
use sure_core::discover::{DiscoverOptions, Ecosystem, Findings, discover};
use sure_core::planned_work::CheckOperation;
use sure_core::schedule::PlanBuilder;
use sure_domain::execution::{ExecutionMode, ExecutionPermissions};
use sure_domain::vocabulary::SupportLevel;

fn scratch(name: &str) -> std::path::PathBuf {
    let root = std::env::temp_dir().join(format!("sure-go-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&root).expect("scratch project");
    root
}

#[test]
fn a_go_module_is_discovered_as_generic() {
    let root = scratch("discovery");
    std::fs::write(
        root.join("go.mod"),
        "module example.com/app\n\ngo 1.27\n\ntoolchain go1.27.0\n",
    )
    .expect("go.mod");
    std::fs::write(root.join("go.sum"), "").expect("go.sum");

    let discovery = discover(&root, &DiscoverOptions::default()).expect("discover");
    let report = discovery
        .report(Ecosystem::Go)
        .expect("a Go project was found");
    assert_eq!(report.level, SupportLevel::Generic);
    let Findings::Go(project) = &report.findings else {
        panic!("the Go report carries a non-Go finding");
    };
    let manifest = project.manifest.as_ref().expect("go.mod was read");
    assert_eq!(manifest.module.as_deref(), Some("example.com/app"));
    assert!(project.lockfile);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_go_module_plans_its_three_commands() {
    let root = scratch("checks");
    std::fs::write(root.join("go.mod"), "module example.com/app\n\ngo 1.27\n").expect("go.mod");
    let discovery = discover(&root, &DiscoverOptions::default()).expect("discover");
    let report = discovery.report(Ecosystem::Go).expect("a Go project");
    let Findings::Go(project) = &report.findings else {
        panic!("not Go");
    };
    let checks = GoChecks::of(project);
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
    assert_eq!(commands, vec!["go", "go", "go"]);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_go_project_without_a_readable_manifest_has_missing_commands() {
    let root = scratch("missing");
    std::fs::write(root.join("go.sum"), "").expect("go.sum");
    let discovery = discover(&root, &DiscoverOptions::default()).expect("discover");
    let report = discovery
        .report(Ecosystem::Go)
        .expect("a Go project marker");
    let Findings::Go(project) = &report.findings else {
        panic!("not Go");
    };
    let checks = GoChecks::of(project);
    assert_eq!(checks.missing().len(), 3);
    let _ = std::fs::remove_dir_all(&root);
}
