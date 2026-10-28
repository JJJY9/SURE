//! A real Go workspace runs three checks for each module `go.work` names.

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
        let root = sure_testkit::scratch::directory("go workspace", test);
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

fn go_is_available() -> bool {
    Command::new("go")
        .arg("version")
        .output()
        .is_ok_and(|output| output.status.success())
}

fn write_module(fixture: &Fixture, name: &str) {
    fixture.write(
        &format!("{name}/go.mod"),
        &format!("module example.com/{name}\n\ngo 1.21\n"),
    );
    fixture.write(
        &format!("{name}/lib.go"),
        &format!("package {name}\n\nfunc Value() int {{ return 1 }}\n"),
    );
    fixture.write(
        &format!("{name}/lib_test.go"),
        &format!(
            "package {name}\n\nimport \"testing\"\n\nfunc TestValue(t *testing.T) {{\n\tif Value() != 1 {{\n\t\tt.Fatal(\"bad value\")\n\t}}\n}}\n"
        ),
    );
}

#[test]
fn a_real_go_workspace_runs_each_module() {
    if !go_is_available() {
        eprintln!("skipping: go is not installed on this machine");
        return;
    }
    let fixture = Fixture::new("real");
    fixture.write("go.work", "go 1.21\n\nuse (\n    ./app\n    ./lib\n)\n");
    write_module(&fixture, "app");
    write_module(&fixture, "lib");
    fixture.write_user_config("execution:\n  mode: host_confirmed\n");

    let report = run_with(Purpose::Check, &fixture.paths(), &fixture.project(), None);

    let Report::Check(report) = report else {
        panic!("check did not produce a check report: {report:?}");
    };
    let run = report
        .run
        .run
        .as_ref()
        .expect("the Go workspace checks ran");
    assert_eq!(run.support.level.as_str(), "generic", "{:?}", run.support);
    let results = run.report.results();
    assert_eq!(results.len(), 6, "{results:?}");
    assert!(
        results
            .iter()
            .all(|result| result.status.as_str() == "pass"),
        "{results:?}"
    );
    let _ = std::fs::remove_dir_all(&fixture.root);
}
