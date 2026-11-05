#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Java discovery and planning: a Maven POM is a project SURE can plan for, and
//! a Gradle build script is one it reports without guessing.

use sure_core::checks::java::JavaChecks;
use sure_core::components::{ComponentGraph, Members};
use sure_core::discover::{DiscoverOptions, Ecosystem, Findings, discover, java};
use sure_core::planned_work::CheckOperation;
use sure_core::schedule::PlanBuilder;
use sure_domain::execution::{ExecutionMode, ExecutionPermissions};
use sure_domain::vocabulary::SupportLevel;

fn scratch(name: &str) -> std::path::PathBuf {
    let root = std::env::temp_dir().join(format!("sure-java-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&root).expect("scratch project");
    root
}

fn write_module(root: &std::path::Path, name: &str) {
    let dir = root.join(name);
    std::fs::create_dir_all(&dir).expect("module dir");
    std::fs::write(
        dir.join("pom.xml"),
        format!(
            "<project><groupId>com.example</groupId><artifactId>{name}</artifactId><version>1.0.0</version></project>\n"
        ),
    )
    .expect("module pom");
}

#[test]
fn a_maven_reactor_names_its_modules() {
    let root = scratch("discovery");
    std::fs::write(
        root.join("pom.xml"),
        "<project><groupId>com.example</groupId><artifactId>app</artifactId><version>1.0.0</version><packaging>pom</packaging><modules><module>core</module><module>web</module></modules></project>\n",
    )
    .expect("pom.xml");
    write_module(&root, "core");
    write_module(&root, "web");

    let discovery = discover(&root, &DiscoverOptions::default()).expect("discover");
    let report = discovery
        .report(Ecosystem::Java)
        .expect("a Java project was found");
    assert_eq!(report.level, SupportLevel::Generic);
    let Findings::Java(project) = &report.findings else {
        panic!("the Java report carries a non-Java finding");
    };
    assert_eq!(project.build, java::JavaBuild::Maven);
    let manifest = project.manifest.as_ref().expect("the POM was read");
    assert_eq!(manifest.artifact_id.as_deref(), Some("app"));
    assert_eq!(manifest.packaging.as_deref(), Some("pom"));
    assert_eq!(manifest.modules.len(), 2);
    assert!(project.modules.iter().all(|module| module.manifest_read()));

    let graph = ComponentGraph::of(&discovery);
    assert_eq!(graph.components.len(), 3, "root plus two modules");
    assert!(matches!(
        graph
            .resolution_of(Ecosystem::Java)
            .expect("Java resolution")
            .members,
        Members::Resolved { truncated: false }
    ));
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_maven_project_plans_test_and_build_at_the_root() {
    let root = scratch("checks");
    std::fs::write(
        root.join("pom.xml"),
        "<project><groupId>com.example</groupId><artifactId>app</artifactId><version>1.0.0</version></project>\n",
    )
    .expect("pom.xml");
    let discovery = discover(&root, &DiscoverOptions::default()).expect("discover");
    let report = discovery.report(Ecosystem::Java).expect("a Java project");
    let Findings::Java(project) = &report.findings else {
        panic!("not Java");
    };
    let checks = JavaChecks::of(project);
    assert!(checks.missing().is_empty());
    let mut builder = PlanBuilder::new(
        ExecutionMode::HostConfirmed,
        ExecutionPermissions::inspect_only(),
    );
    checks.add_to(project, &root, &mut builder);
    let schedule = builder.build();
    assert_eq!(schedule.checks().len(), 2);
    for scheduled in schedule.checks() {
        let CheckOperation::Command(spec) = scheduled.operation() else {
            panic!("not a command");
        };
        assert_eq!(spec.program().to_str(), Some("mvn"));
        assert_eq!(spec.working_directory(), root);
        let arguments: Vec<&str> = spec
            .arguments()
            .iter()
            .map(|argument| argument.to_str().unwrap_or(""))
            .collect();
        assert_eq!(arguments[0], "-B");
        assert!(arguments.contains(&"test") || arguments.contains(&"package"));
    }
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_module_without_a_pom_is_reported_but_the_reactor_still_plans() {
    let root = scratch("missing-module");
    std::fs::write(
        root.join("pom.xml"),
        "<project><modules><module>core</module><module>empty</module></modules></project>\n",
    )
    .expect("pom.xml");
    write_module(&root, "core");
    std::fs::create_dir_all(root.join("empty")).expect("empty module dir");
    let discovery = discover(&root, &DiscoverOptions::default()).expect("discover");
    let report = discovery.report(Ecosystem::Java).expect("a Java project");
    let Findings::Java(project) = &report.findings else {
        panic!("not Java");
    };
    assert_eq!(project.modules.len(), 2);
    assert!(!project.modules[1].manifest_read());
    let checks = JavaChecks::of(project);
    assert!(
        checks.missing().is_empty(),
        "Maven's reactor fails on a module without a POM by itself"
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_broken_pom_has_missing_commands() {
    let root = scratch("broken");
    std::fs::write(root.join("pom.xml"), "<project><groupId></project>\n").expect("pom.xml");
    let discovery = discover(&root, &DiscoverOptions::default()).expect("discover");
    let report = discovery.report(Ecosystem::Java).expect("a Java marker");
    assert_eq!(report.level, SupportLevel::InspectOnly);
    let Findings::Java(project) = &report.findings else {
        panic!("not Java");
    };
    assert!(project.unread.is_some());
    let checks = JavaChecks::of(project);
    assert_eq!(checks.missing().len(), 2);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_gradle_project_is_inspect_only_and_has_missing_commands() {
    let root = scratch("gradle");
    std::fs::write(root.join("build.gradle"), "plugins { id 'java' }\n").expect("build.gradle");
    std::fs::write(root.join("settings.gradle"), "rootProject.name = 'app'\n")
        .expect("settings.gradle");
    let discovery = discover(&root, &DiscoverOptions::default()).expect("discover");
    let report = discovery.report(Ecosystem::Java).expect("a Java marker");
    assert_eq!(report.level, SupportLevel::InspectOnly);
    let Findings::Java(project) = &report.findings else {
        panic!("not Java");
    };
    assert_eq!(project.build, java::JavaBuild::Gradle);
    assert!(project.manifest.is_none());
    let checks = JavaChecks::of(project);
    assert_eq!(checks.missing().len(), 2);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_module_path_outside_the_root_is_ignored() {
    let root = scratch("outside");
    std::fs::write(
        root.join("pom.xml"),
        "<project><modules><module>../outside</module><module>inside</module></modules></project>\n",
    )
    .expect("pom.xml");
    write_module(&root, "inside");
    let discovery = discover(&root, &DiscoverOptions::default()).expect("discover");
    let report = discovery.report(Ecosystem::Java).expect("a Java project");
    let Findings::Java(project) = &report.findings else {
        panic!("not Java");
    };
    assert_eq!(project.modules.len(), 1);
    assert_eq!(project.modules[0].path, std::path::Path::new("inside"));
    let _ = std::fs::remove_dir_all(&root);
}
