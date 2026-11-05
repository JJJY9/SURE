//! `sure check --commands-file` on a project with no discoverable stack.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use sure_cli::check::run_with_commands;
use sure_cli::report::Report;
use sure_core::paths::Paths;
use sure_core::pipeline::Purpose;

struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn new(test: &str) -> Self {
        let root = sure_testkit::scratch::directory("external commands", test);
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

    fn write_commands(&self, contents: &str) -> PathBuf {
        let path = self.root.join("commands.yaml");
        std::fs::write(&path, contents).unwrap();
        path
    }
}

#[test]
fn commands_file_plans_and_runs_all_four_roles() {
    let fixture = Fixture::new("all roles");
    fixture.write_user_config("execution:\n  mode: host_confirmed\n");
    let commands = fixture.write_commands(
        "commands:\n  test: [\"cargo\", \"--version\"]\n  build: [\"cargo\", \"--version\"]\n  lint: [\"cargo\", \"--version\"]\n  typecheck: [\"cargo\", \"--version\"]\n",
    );

    let report = run_with_commands(
        Purpose::Check,
        &fixture.paths(),
        &fixture.project(),
        None,
        Some(&commands),
    );

    let Report::Check(report) = report else {
        panic!("check did not produce a check report: {report:?}");
    };
    let run = report.run.run.as_ref().expect("the declared commands ran");
    let results = run.report.results();
    assert_eq!(results.len(), 4, "{results:?}");
    assert!(
        results
            .iter()
            .all(|result| result.status.as_str() == "pass"),
        "{results:?}"
    );
    assert!(
        results.iter().any(|result| result.title == "run the tests"),
        "{results:?}"
    );
    let _ = std::fs::remove_dir_all(&fixture.root);
}

#[test]
fn a_commands_file_inside_the_project_is_refused() {
    let fixture = Fixture::new("inside");
    fixture.write_user_config("execution:\n  mode: host_confirmed\n");
    let commands = fixture.project().join("commands.yaml");
    std::fs::write(&commands, "commands:\n  test: [\"cargo\", \"--version\"]\n").unwrap();

    let report = run_with_commands(
        Purpose::Check,
        &fixture.paths(),
        &fixture.project(),
        None,
        Some(&commands),
    );

    let Report::Failed(failed) = report else {
        panic!("an inside commands file was not refused: {report:?}");
    };
    assert!(failed.detail.contains("inside the project"), "{failed:?}");
    let _ = std::fs::remove_dir_all(&fixture.root);
}
