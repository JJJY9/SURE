//! A real .NET project runs the checks SURE plans for a solution/project.

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
        let root = sure_testkit::scratch::directory("dotnet project", test);
        std::fs::create_dir_all(root.join("project")).unwrap();
        Self { root }
    }

    fn project(&self) -> PathBuf {
        self.root.join("project")
    }

    fn paths(&self) -> Paths {
        Paths::from_roots(self.root.join("data"), self.root.join("config")).unwrap()
    }

    fn write_user_config(&self, contents: &str) {
        let path = self.paths().user_config_file();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, contents).unwrap();
    }
}

fn dotnet_is_available() -> bool {
    Command::new("dotnet")
        .arg("--version")
        .output()
        .is_ok_and(|output| output.status.success())
}

#[test]
fn a_real_dotnet_test_project_runs_build_and_test() {
    if !dotnet_is_available() {
        eprintln!("skipping: dotnet is not installed on this machine");
        return;
    }
    let fixture = Fixture::new("real");
    let created = Command::new("dotnet")
        .args(["new", "xunit", "-o", "project", "--force"])
        .current_dir(&fixture.root)
        .output();
    let Ok(created) = created else {
        eprintln!("skipping: could not start dotnet new");
        return;
    };
    if !created.status.success() {
        eprintln!(
            "skipping: dotnet new xunit failed: {}",
            String::from_utf8_lossy(&created.stderr)
        );
        return;
    }
    fixture.write_user_config("execution:\n  mode: host_confirmed\n");

    let report = run_with(Purpose::Check, &fixture.paths(), &fixture.project(), None);
    let Report::Check(report) = report else {
        panic!("check did not produce a check report: {report:?}");
    };
    let run = report.run.run.as_ref().expect("the .NET checks ran");
    assert_eq!(run.support.level.as_str(), "generic", "{:?}", run.support);
    let results = run.report.results();
    assert_eq!(results.len(), 3, "{results:?}");
    let by_title: Vec<(&str, &str)> = results
        .iter()
        .map(|result| (result.title.as_str(), result.status.as_str()))
        .collect();
    assert!(
        by_title.contains(&("build the .NET project", "pass")),
        "{by_title:?}"
    );
    assert!(
        by_title.contains(&("run the .NET tests", "pass")),
        "{by_title:?}"
    );
    assert!(
        by_title.contains(&("check the .NET formatting", "skipped")),
        "{by_title:?}"
    );
    let _ = std::fs::remove_dir_all(&fixture.root);
}
