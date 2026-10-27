#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! User-declared commands let SURE check a project with no discovered stack.
//!
//! The project here has no manifest SURE knows. Its four checks come only from
//! the commands the user named, and the production runner carries them out.

use sure_core::config::{Config, ExecutionSettings};
use sure_core::external_commands::{ExternalCommand, ExternalRole};
use sure_core::pipeline::{Pipeline, Purpose};
use sure_core::planned_check_runner::ProcessRunner;
use sure_core::process::Cancellation;
use sure_domain::execution::{ExecutionMode, ExecutionPermissions, Permission};
use sure_domain::status::CheckStatus;
use sure_domain::vocabulary::SupportLevel;

fn host_confirmed() -> ExecutionPermissions {
    let mut permissions = ExecutionPermissions::inspect_only();
    permissions.set(Permission::RunProjectCode, true);
    permissions
}

#[test]
fn a_project_with_no_discovered_stack_runs_the_users_commands() {
    let root = std::env::temp_dir().join(format!("sure-external-commands-{}", std::process::id()));
    std::fs::create_dir_all(&root).expect("scratch project");
    // `cargo --version` is present on every machine this workspace builds on,
    // and it returns a real exit status without changing the scratch project.
    let commands: Vec<ExternalCommand> = ExternalRole::ALL
        .iter()
        .map(|role| ExternalCommand {
            role: *role,
            argv: vec!["cargo".to_owned(), "--version".to_owned()],
        })
        .collect();
    let config = Config::default();
    let runner = ProcessRunner::new(Cancellation::new());
    let outcome = Pipeline {
        project: &root,
        purpose: Purpose::Check,
        config: &config,
        execution: ExecutionSettings {
            mode: ExecutionMode::HostConfirmed,
            permissions: host_confirmed(),
        },
        external_commands: &commands,
        store: None,
        goal: None,
        analysis: Default::default(),
        runner: &runner,
    }
    .run();

    let run = outcome.run.expect("the declared commands ran");
    assert_eq!(run.support.level, SupportLevel::Generic);
    let results = run.report.results();
    assert_eq!(results.len(), 4, "{results:?}");
    assert!(
        results
            .iter()
            .all(|result| result.status == CheckStatus::Pass),
        "{results:?}"
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn a_test_only_override_is_not_a_green_verdict() {
    let root = std::env::temp_dir().join(format!(
        "sure-external-commands-partial-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root).expect("scratch project");
    let commands = vec![ExternalCommand {
        role: ExternalRole::Test,
        argv: vec!["cargo".to_owned(), "--version".to_owned()],
    }];
    let config = Config::default();
    let runner = ProcessRunner::new(Cancellation::new());
    let outcome = Pipeline {
        project: &root,
        purpose: Purpose::Check,
        config: &config,
        execution: ExecutionSettings {
            mode: ExecutionMode::HostConfirmed,
            permissions: host_confirmed(),
        },
        external_commands: &commands,
        store: None,
        goal: None,
        analysis: Default::default(),
        runner: &runner,
    }
    .run();

    let run = outcome.run.expect("the declared command ran");
    assert!(
        !run.verdict.is_ready_for_hand_off(),
        "a test-only override must not be green: {:?}",
        run.verdict.aggregate
    );
    let _ = std::fs::remove_dir_all(&root);
}
