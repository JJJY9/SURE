#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! A Go workspace (`go.work`) is checked module by module.

use sure_core::checks::go::GoChecks;
use sure_core::components::{ComponentGraph, Members};
use sure_core::discover::{DiscoverOptions, Ecosystem, Findings, discover};
use sure_core::planned_work::CheckOperation;
use sure_core::schedule::PlanBuilder;
use sure_domain::execution::{ExecutionMode, ExecutionPermissions};
use sure_domain::vocabulary::SupportLevel;

fn scratch(name: &str) -> std::path::PathBuf {
    let root = std::env::temp_dir().join(format!("sure-go-work-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&root).expect("scratch project");
    root
}

fn write_module(root: &std::path::Path, name: &str) {
    let dir = root.join(name);
    std::fs::create_dir_all(&dir).expect("module dir");
    std::fs::write(
        dir.join("go.mod"),
        format!("module example.com/{name}\n\ngo 1.21\n"),
    )
    .expect("go.mod");
    std::fs::write(dir.join("lib.go"), "package lib\n").expect("lib.go");
}

#[test]
fn a_workspace_names_its_modules() {
    let root = scratch("discovery");
    std::fs::write(
        root.join("go.work"),
        "go 1.21\n\nuse (\n    ./app\n    ./lib\n)\n",
    )
    .expect("go.work");
    write_module(&root, "app");
    write_module(&root, "lib");

    let discovery = discover(&root, &DiscoverOptions::default()).expect("discover");
    let report = discovery
        .report(Ecosystem::Go)
        .expect("a Go workspace was found");
    assert_eq!(report.level, SupportLevel::Generic);
    let Findings::Go(project) = &report.findings else {
        panic!("the Go report carries a non-Go finding");
    };
    let workspace = project.workspace.as_ref().expect("go.work was read");
    assert_eq!(workspace.uses.len(), 2);
    assert_eq!(project.modules.len(), 2);
    assert!(project.modules.iter().all(|module| module.manifest_read()));

    let graph = ComponentGraph::of(&discovery);
    assert_eq!(graph.components.len(), 3, "root plus two modules");
    assert!(matches!(
        graph
            .resolution_of(Ecosystem::Go)
            .expect("Go resolution")
            .members,
        Members::Resolved { truncated: false }
    ));
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_workspace_plans_three_checks_per_module() {
    let root = scratch("checks");
    std::fs::write(root.join("go.work"), "go 1.21\n\nuse app\nuse lib\n").expect("go.work");
    write_module(&root, "app");
    write_module(&root, "lib");
    let discovery = discover(&root, &DiscoverOptions::default()).expect("discover");
    let report = discovery.report(Ecosystem::Go).expect("a Go workspace");
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
    assert_eq!(schedule.checks().len(), 6);
    let directories: Vec<std::path::PathBuf> = schedule
        .checks()
        .iter()
        .filter_map(|scheduled| match scheduled.operation() {
            CheckOperation::Command(spec) => Some(spec.working_directory().to_path_buf()),
            _ => None,
        })
        .collect();
    assert_eq!(
        directories
            .iter()
            .filter(|dir| **dir == root.join("app"))
            .count(),
        3
    );
    assert_eq!(
        directories
            .iter()
            .filter(|dir| **dir == root.join("lib"))
            .count(),
        3
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_workspace_module_without_a_manifest_has_missing_commands() {
    let root = scratch("missing");
    std::fs::write(root.join("go.work"), "go 1.21\n\nuse app\nuse missing\n").expect("go.work");
    write_module(&root, "app");
    std::fs::create_dir_all(root.join("missing")).expect("empty module dir");
    let discovery = discover(&root, &DiscoverOptions::default()).expect("discover");
    let report = discovery.report(Ecosystem::Go).expect("a Go workspace");
    let Findings::Go(project) = &report.findings else {
        panic!("not Go");
    };
    let checks = GoChecks::of(project);
    assert_eq!(checks.missing().len(), 3);
    let _ = std::fs::remove_dir_all(&root);
}
