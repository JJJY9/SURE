//! A real Maven project runs the checks SURE plans for a project with a `pom.xml`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;
use std::process::Command;

use sure_cli::check::run_with;
use sure_cli::report::Report;
use sure_core::paths::Paths;
use sure_core::pipeline::Purpose;

struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn new(test: &str) -> Self {
        let root = sure_testkit::scratch::directory("java-project", test);
        std::fs::create_dir_all(root.join("project")).unwrap();
        Self { root }
    }

    fn project(&self) -> PathBuf {
        self.root.join("project")
    }

    fn paths(&self) -> Paths {
        Paths::from_roots(self.root.join("data"), self.root.join("config")).unwrap()
    }

    fn write(&self, relative: &str, contents: &str) {
        let path = self.project().join(relative);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&path, contents).unwrap();
    }

    fn write_user_config(&self, contents: &str) {
        let path = self.paths().user_config_file();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, contents).unwrap();
    }
}

/// Maven on `PATH`.
///
/// On Windows the installed name is `mvn.cmd`, and a bare `mvn` is not
/// startable through `Command::new` there — which is the same fact the product
/// handles in `sure_core::package_launcher`.
fn maven_is_available() -> bool {
    let program = if cfg!(windows) { "mvn.cmd" } else { "mvn" };
    Command::new(program)
        .arg("-v")
        .output()
        .is_ok_and(|output| output.status.success())
}

fn java_is_available() -> bool {
    Command::new("java")
        .arg("-version")
        .output()
        .is_ok_and(|output| output.status.success())
}

fn write_project(fixture: &Fixture) {
    fixture.write(
        "pom.xml",
        r#"<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>app</artifactId>
  <version>1.0.0</version>
  <properties>
    <maven.compiler.release>17</maven.compiler.release>
    <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
  </properties>
  <dependencies>
    <dependency>
      <groupId>org.junit.jupiter</groupId>
      <artifactId>junit-jupiter</artifactId>
      <version>5.10.2</version>
      <scope>test</scope>
    </dependency>
  </dependencies>
  <build>
    <plugins>
      <plugin>
        <groupId>org.apache.maven.plugins</groupId>
        <artifactId>maven-compiler-plugin</artifactId>
        <version>3.13.0</version>
      </plugin>
      <plugin>
        <groupId>org.apache.maven.plugins</groupId>
        <artifactId>maven-surefire-plugin</artifactId>
        <version>3.2.5</version>
      </plugin>
    </plugins>
  </build>
</project>
"#,
    );
    fixture.write(
        "src/main/java/com/example/App.java",
        "package com.example;\n\npublic final class App {\n    private App() {}\n\n    public static int value() {\n        return 1;\n    }\n}\n",
    );
    fixture.write(
        "src/test/java/com/example/AppTest.java",
        "package com.example;\n\nimport org.junit.jupiter.api.Test;\n\nimport static org.junit.jupiter.api.Assertions.assertEquals;\n\nclass AppTest {\n    @Test\n    void valueIsOne() {\n        assertEquals(1, App.value());\n    }\n}\n",
    );
}

#[test]
fn a_real_maven_project_runs_test_and_build() {
    if !maven_is_available() {
        eprintln!("skipping: maven is not installed on this machine");
        return;
    }
    if !java_is_available() {
        eprintln!("skipping: java is not installed on this machine");
        return;
    }
    let fixture = Fixture::new("real");
    write_project(&fixture);
    fixture.write_user_config("execution:\n  mode: host_confirmed\n");

    let report = run_with(Purpose::Check, &fixture.paths(), &fixture.project(), None);

    let Report::Check(report) = report else {
        panic!("check did not produce a check report: {report:?}");
    };
    let run = report.run.run.as_ref().expect("the Maven checks ran");
    let results = run.report.results();
    let by_title: Vec<(&str, &str, &str)> = results
        .iter()
        .map(|result| {
            (
                result.title.as_str(),
                result.status.as_str(),
                result.reason.as_str(),
            )
        })
        .collect();
    let status_of = |title: &str| {
        by_title
            .iter()
            .find(|(found, _, _)| *found == title)
            .map(|(_, status, reason)| (*status, *reason))
    };
    assert_eq!(run.support.level.as_str(), "generic", "{:?}", run.support);
    assert_eq!(results.len(), 2, "{by_title:?}");
    assert_eq!(
        status_of("run the Java tests").map(|(status, _)| status),
        Some("pass"),
        "{by_title:?}"
    );
    assert_eq!(
        status_of("build the Java project").map(|(status, _)| status),
        Some("pass"),
        "{by_title:?}"
    );
    let _ = std::fs::remove_dir_all(&fixture.root);
}

#[test]
fn a_gradle_project_plans_nothing_and_says_so() {
    let fixture = Fixture::new("gradle");
    fixture.write("build.gradle", "plugins { id 'java' }\n");
    fixture.write_user_config("execution:\n  mode: host_confirmed\n");

    let report = run_with(Purpose::Check, &fixture.paths(), &fixture.project(), None);
    let Report::Check(report) = report else {
        panic!("check did not produce a check report: {report:?}");
    };
    let run = report.run.run.as_ref().expect("a Java run");
    assert_eq!(
        run.support.level.as_str(),
        "inspect_only",
        "{:?}",
        run.support
    );
    let results = run.report.results();
    assert_eq!(results.len(), 2, "{results:?}");
    assert!(
        results
            .iter()
            .all(|result| result.status.as_str() == "skipped"),
        "{results:?}"
    );
    let _ = std::fs::remove_dir_all(&fixture.root);
}

#[test]
fn the_status_of_a_maven_check_is_not_a_pass_without_a_manifest() {
    let fixture = Fixture::new("broken");
    fixture.write("pom.xml", "<project><modules></project>\n");
    fixture.write_user_config("execution:\n  mode: host_confirmed\n");
    let report = run_with(Purpose::Check, &fixture.paths(), &fixture.project(), None);
    let Report::Check(report) = report else {
        panic!("check did not produce a check report: {report:?}");
    };
    let run = report.run.run.as_ref().expect("a Java run");
    assert_eq!(
        run.support.level.as_str(),
        "inspect_only",
        "{:?}",
        run.support
    );
    let results = run.report.results();
    assert!(
        results
            .iter()
            .all(|result| result.status.as_str() == "skipped"),
        "{results:?}"
    );
    let _ = std::fs::remove_dir_all(&fixture.root);
}
