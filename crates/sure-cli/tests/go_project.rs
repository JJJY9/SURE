//! A real Go project runs the three commands SURE plans for a Go module.

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
        let root = sure_testkit::scratch::directory("go project", test);
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

#[test]
fn a_real_go_module_runs_test_build_and_vet() {
    if !go_is_available() {
        eprintln!("skipping: go is not installed on this machine");
        return;
    }
    let fixture = Fixture::new("real");
    fixture.write("go.mod", "module example.com/app\n\ngo 1.27\n");
    fixture.write(
        "lib.go",
        "package app\n\nfunc Add(a, b int) int { return a + b }\n",
    );
    fixture.write(
        "lib_test.go",
        "package app\n\nimport \"testing\"\n\nfunc TestAdd(t *testing.T) {\n\tif Add(1, 2) != 3 {\n\t\tt.Fatal(\"bad sum\")\n\t}\n}\n",
    );
    fixture.write_user_config("execution:\n  mode: host_confirmed\n");

    let report = run_with(Purpose::Check, &fixture.paths(), &fixture.project(), None);

    let Report::Check(report) = report else {
        panic!("check did not produce a check report: {report:?}");
    };
    let run = report.run.run.as_ref().expect("the Go checks ran");
    assert_eq!(run.support.level.as_str(), "generic", "{:?}", run.support);
    let results = run.report.results();
    assert_eq!(results.len(), 3, "{results:?}");
    assert!(
        results
            .iter()
            .all(|result| result.status.as_str() == "pass"),
        "{results:?}"
    );
    let _ = std::fs::remove_dir_all(&fixture.root);
}
