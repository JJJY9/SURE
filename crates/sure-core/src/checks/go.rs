//! The checks a Go project's module declaration turns into.
//!
//! Three commands, each `go`'s own: `go test ./...`, `go build ./...` and
//! `go vet ./...`. The module path is not used to name a package; the commands
//! are the toolchain's conventions for the project root, and every one is a
//! [`CommandRole`] SURE already has an [`ActionKind`] for.
//!
//! **A project whose `go.mod` SURE did not read gets no command.** The three
//! checks are missing commands rather than an empty plan, for the reason
//! [`super::python`] gives: a report that said nothing about tests in a project
//! whose manifest could not be read would be a silence a reader takes for
//! absence.

use std::path::Path;
use std::time::Duration;

use sure_domain::evidence::EvidenceClass;
use sure_domain::execution::ActionKind;
use sure_domain::severity::Severity;

use crate::checks::{MissingCommand, MissingKind, check_id};
use crate::discover::GoProject;
use crate::planned_work::{CheckOperation, CommandSpec, PlannedWork};
use crate::process::{Environment, Limits};
use crate::schedule::{CheckProposal, CheckReason, PlanBuilder};

/// The three roles SURE proposes for a Go project.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GoRole {
    Test,
    Build,
    Lint,
}

impl GoRole {
    pub const ALL: &'static [Self] = &[Self::Test, Self::Build, Self::Lint];

    #[must_use]
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Test => "gotest",
            Self::Build => "gobuild",
            Self::Lint => "golint",
        }
    }

    #[must_use]
    pub const fn title(self) -> &'static str {
        match self {
            Self::Test => "run the tests",
            Self::Build => "build the project",
            Self::Lint => "check the code for style and likely mistakes",
        }
    }

    #[must_use]
    pub const fn command(self) -> &'static str {
        match self {
            Self::Test => "go test ./...",
            Self::Build => "go build ./...",
            Self::Lint => "go vet ./...",
        }
    }

    #[must_use]
    pub const fn severity(self) -> Severity {
        match self {
            Self::Test | Self::Build => Severity::MustFix,
            Self::Lint => Severity::CanFixLater,
        }
    }

    #[must_use]
    pub const fn critical(self) -> bool {
        matches!(self, Self::Test | Self::Build)
    }

    #[must_use]
    pub const fn action(self) -> ActionKind {
        match self {
            Self::Test => ActionKind::RunTests,
            Self::Build => ActionKind::Build,
            Self::Lint => ActionKind::Lint,
        }
    }
}

/// The proposals a Go project produces, and the ones it cannot.
#[derive(Debug, Clone, Default)]
pub struct GoChecks {
    component: String,
    missing: Vec<MissingCommand>,
}

impl GoChecks {
    /// The checks for one Go project.
    #[must_use]
    pub fn of(project: &GoProject) -> Self {
        let component = "go.mod".to_owned();
        let mut missing = Vec::new();
        if !project.manifest_read() {
            let kind = if project.unread.is_some() {
                MissingKind::NotReadable
            } else {
                MissingKind::NotDeclared
            };
            for role in GoRole::ALL {
                missing.push(MissingCommand::new(
                    check_id(&component, role.tag()),
                    role.title(),
                    component.clone(),
                    role.severity(),
                    role.critical(),
                    kind.clone(),
                ));
            }
        }
        Self { component, missing }
    }

    /// The missing commands, for a report that has to say what did not run.
    #[must_use]
    pub fn missing(&self) -> &[MissingCommand] {
        &self.missing
    }

    /// Add the checks this project declares.
    pub fn add_to(&self, project: &GoProject, root: &Path, builder: &mut PlanBuilder) {
        if !project.manifest_read() {
            return;
        }
        for role in GoRole::ALL {
            let command = role.command();
            let spec = CommandSpec::new(
                "go",
                root,
                Environment::inherited(),
                Limits::new(Duration::from_secs(600), 64 * 1024, 64 * 1024),
            )
            .with_arguments(command.split_whitespace().skip(1).collect::<Vec<_>>());
            let proposal = CheckProposal::new(
                check_id(&self.component, role.tag()),
                role.title(),
                role.severity(),
                role.critical(),
                EvidenceClass::DeterministicCheck,
                CheckReason::DeclaredCommand {
                    declared_in: self.component.clone(),
                    command: command.to_owned(),
                },
                &[role.action()],
            );
            drop(builder.propose(PlannedWork::new(proposal, CheckOperation::Command(spec))));
        }
    }
}
