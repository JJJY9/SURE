//! The checks a Go project's module declaration turns into.
//!
//! Three commands per module, each `go`'s own: `go test ./...`, `go build
//! ./...` and `go vet ./...`, run in the module's directory. The module path is
//! not used to name a package; the commands are the toolchain's conventions for
//! a module root, and every one is a [`CommandRole`] SURE already has an
//! [`ActionKind`] for.
//!
//! A `go.work` root is checked module by module. `go test ./...` at the
//! workspace root does not describe the modules a `go.work` names — the root is
//! not itself a module unless it has a `go.mod` — so each `use` directory with a
//! readable `go.mod` gets its own three checks, running in that directory.
//!
//! **A module whose `go.mod` SURE did not read gets no command.** The three
//! checks are missing commands rather than an empty plan, for the reason
//! [`super::python`] gives: a report that said nothing about tests in a module
//! whose manifest could not be read would be a silence a reader takes for
//! absence.

use std::path::{Path, PathBuf};
use std::time::Duration;

use sure_domain::evidence::EvidenceClass;
use sure_domain::execution::ActionKind;
use sure_domain::severity::Severity;

use crate::checks::{MissingCommand, MissingKind, check_id};
use crate::discover::GoProject;
use crate::planned_work::{CheckOperation, CommandSpec, PlannedWork};
use crate::process::{Environment, Limits};
use crate::scan::display_path;
use crate::schedule::{CheckProposal, CheckReason, PlanBuilder};

/// The three roles SURE proposes for a Go module.
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

/// One module SURE will plan commands for.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Module {
    /// The directory the commands run in, relative to the project root.
    directory: PathBuf,
    /// The manifest the commands are declared in, as a report spells it.
    declared_in: String,
}

/// The proposals a Go project produces, and the ones it cannot.
#[derive(Debug, Clone, Default)]
pub struct GoChecks {
    modules: Vec<Module>,
    missing: Vec<MissingCommand>,
}

impl GoChecks {
    /// The checks for one Go project (its root module and any workspace modules).
    #[must_use]
    pub fn of(project: &GoProject) -> Self {
        let mut modules = Vec::new();
        let mut missing = Vec::new();

        if project.manifest_read() {
            modules.push(Module {
                directory: PathBuf::new(),
                declared_in: "go.mod".to_owned(),
            });
        } else if project.workspace.is_none() {
            // A lockfile-only project, or a go.mod SURE could not read: there is
            // no workspace to fall back to, so all three checks are missing.
            let component = "go.mod";
            let kind = if project.unread.is_some() {
                MissingKind::NotReadable
            } else {
                MissingKind::NotDeclared
            };
            push_missing(&mut missing, component, kind);
        }

        if let Some(workspace) = &project.workspace {
            if project.workspace_unread.is_some() {
                push_missing(&mut missing, "go.work", MissingKind::NotReadable);
            } else if workspace.uses.is_empty() {
                push_missing(&mut missing, "go.work", MissingKind::NotDeclared);
            }
            for module in &project.modules {
                if module.path == Path::new(".") && project.manifest_read() {
                    continue;
                }
                let declared_in = display_path(&module.path.join("go.mod"));
                if module.manifest_read() {
                    modules.push(Module {
                        directory: module.path.clone(),
                        declared_in,
                    });
                } else {
                    let kind = if module.unread.is_some() {
                        MissingKind::NotReadable
                    } else {
                        MissingKind::NotDeclared
                    };
                    push_missing(&mut missing, &declared_in, kind);
                }
            }
        } else if project.workspace_unread.is_some() {
            push_missing(&mut missing, "go.work", MissingKind::NotReadable);
        }

        Self { modules, missing }
    }

    /// The missing commands, for a report that has to say what did not run.
    #[must_use]
    pub fn missing(&self) -> &[MissingCommand] {
        &self.missing
    }

    /// Add the checks this project declares.
    pub fn add_to(&self, project: &GoProject, root: &Path, builder: &mut PlanBuilder) {
        let _ = project;
        for module in &self.modules {
            let directory = if module.directory.as_os_str().is_empty() {
                root.to_path_buf()
            } else {
                root.join(&module.directory)
            };
            for role in GoRole::ALL {
                let command = role.command();
                let spec = CommandSpec::new(
                    "go",
                    &directory,
                    Environment::inherited(),
                    Limits::new(Duration::from_secs(600), 64 * 1024, 64 * 1024),
                )
                .with_arguments(command.split_whitespace().skip(1).collect::<Vec<_>>());
                let title = if module.directory.as_os_str().is_empty() {
                    role.title().to_owned()
                } else {
                    format!("{} ({})", role.title(), display_path(&module.directory))
                };
                let proposal = CheckProposal::new(
                    check_id(&module.declared_in, role.tag()),
                    title,
                    role.severity(),
                    role.critical(),
                    EvidenceClass::DeterministicCheck,
                    CheckReason::DeclaredCommand {
                        declared_in: module.declared_in.clone(),
                        command: command.to_owned(),
                    },
                    &[role.action()],
                );
                drop(builder.propose(PlannedWork::new(proposal, CheckOperation::Command(spec))));
            }
        }
    }
}

fn push_missing(missing: &mut Vec<MissingCommand>, component: &str, kind: MissingKind) {
    for role in GoRole::ALL {
        missing.push(MissingCommand::new(
            check_id(component, role.tag()),
            role.title(),
            component.to_owned(),
            role.severity(),
            role.critical(),
            kind.clone(),
        ));
    }
}
