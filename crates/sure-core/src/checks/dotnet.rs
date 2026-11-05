//! The checks a .NET solution or project file turns into.
//!
//! `dotnet test`, `dotnet build`, and — only when the project configures
//! formatting (`.editorconfig`) — `dotnet format --verify-no-changes`. The
//! command target is the solution when there is one, otherwise the single
//! project file; several projects without a solution produce missing commands
//! rather than a guess about which one was meant.
//!
//! A project whose manifest SURE did not read gets missing commands for the
//! same reason [`super::go`] gives: a report that stayed silent about tests in a
//! project whose manifest could not be read is a silence a reader takes for
//! absence.

use std::path::Path;
use std::time::Duration;

use sure_domain::evidence::EvidenceClass;
use sure_domain::execution::ActionKind;
use sure_domain::severity::Severity;

use crate::checks::{MissingCommand, MissingKind, check_id};
use crate::discover::DotnetProject;
use crate::planned_work::{CheckOperation, CommandSpec, PlannedWork};
use crate::process::{Environment, Limits};
use crate::schedule::{CheckProposal, CheckReason, PlanBuilder};

/// The roles SURE proposes for a .NET project.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DotnetRole {
    Test,
    Build,
    Lint,
}

impl DotnetRole {
    pub const ALL: &'static [Self] = &[Self::Test, Self::Build, Self::Lint];

    #[must_use]
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Test => "dotnettest",
            Self::Build => "dotnetbuild",
            Self::Lint => "dotnetformat",
        }
    }

    #[must_use]
    pub const fn title(self) -> &'static str {
        match self {
            Self::Test => "run the .NET tests",
            Self::Build => "build the .NET project",
            Self::Lint => "check the .NET formatting",
        }
    }

    #[must_use]
    pub fn command(self, target: &str) -> String {
        match self {
            Self::Test => format!("dotnet test {target}"),
            Self::Build => format!("dotnet build {target}"),
            Self::Lint => format!("dotnet format {target} --verify-no-changes --no-restore"),
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

/// The proposals a .NET project produces, and the ones it cannot.
#[derive(Debug, Clone, Default)]
pub struct DotnetChecks {
    component: String,
    missing: Vec<MissingCommand>,
}

impl DotnetChecks {
    /// The checks for one .NET project.
    #[must_use]
    pub fn of(project: &DotnetProject) -> Self {
        let component = project
            .manifest
            .as_ref()
            .map(|manifest| crate::scan::display_path(&manifest.file))
            .unwrap_or_else(|| "the .NET project file".to_owned());
        let mut missing = Vec::new();
        let target = project.target.as_ref();
        let readable = project.manifest_read() && target.is_some();
        if !readable {
            let kind = if project.unread.is_some() {
                MissingKind::NotReadable
            } else {
                MissingKind::NotDeclared
            };
            for role in DotnetRole::ALL {
                missing.push(MissingCommand::new(
                    check_id(&component, role.tag()),
                    role.title(),
                    component.clone(),
                    role.severity(),
                    role.critical(),
                    kind.clone(),
                ));
            }
        } else if !project.editorconfig {
            // Formatting is only checked when the project configures it.
            missing.push(MissingCommand::new(
                check_id(&component, DotnetRole::Lint.tag()),
                DotnetRole::Lint.title(),
                component.clone(),
                DotnetRole::Lint.severity(),
                DotnetRole::Lint.critical(),
                MissingKind::NotDeclared,
            ));
        }
        Self { component, missing }
    }

    /// The missing commands, for a report that has to say what did not run.
    #[must_use]
    pub fn missing(&self) -> &[MissingCommand] {
        &self.missing
    }

    /// Add the checks this project declares.
    pub fn add_to(&self, project: &DotnetProject, root: &Path, builder: &mut PlanBuilder) {
        let Some(target) = project.target.as_ref() else {
            return;
        };
        if !project.manifest_read() {
            return;
        }
        let target = crate::scan::display_path(target);
        for role in [DotnetRole::Test, DotnetRole::Build] {
            self.propose(role, &target, root, builder);
        }
        if project.editorconfig {
            self.propose(DotnetRole::Lint, &target, root, builder);
        }
    }

    fn propose(&self, role: DotnetRole, target: &str, root: &Path, builder: &mut PlanBuilder) {
        let command = role.command(target);
        // Build argv as typed values, not by splitting the display string: a
        // solution or project file name may contain spaces.
        let mut arguments: Vec<&str> = match role {
            DotnetRole::Test => vec!["test", target],
            DotnetRole::Build => vec!["build", target],
            DotnetRole::Lint => {
                vec!["format", target, "--verify-no-changes", "--no-restore"]
            }
        };
        if role == DotnetRole::Test || role == DotnetRole::Build {
            arguments.push("--nologo");
        }
        // `dotnet` writes bin/ and obj/ inside the project by default. That would
        // (a) modify the project SURE is only supposed to observe and (b) move
        // the fingerprint, making every result stale. Keep both outside the
        // project, in SURE's ignored cache directory; MSBuild honours these
        // variables for build, test and format (measured 2026-10-27).
        let output = crate::paths::project_cache_dir(root)
            .join("dotnet")
            .join(role.tag());
        let slash = std::path::MAIN_SEPARATOR;
        let obj = format!("{}{slash}obj{slash}", output.display());
        let bin = format!("{}{slash}bin{slash}", output.display());
        let environment = Environment::inherited()
            .with("MSBuildProjectExtensionsPath", obj.clone())
            .with("BaseIntermediateOutputPath", obj)
            .with("OutputPath", bin);
        let spec = CommandSpec::new(
            "dotnet",
            root,
            environment,
            Limits::new(Duration::from_secs(600), 64 * 1024, 64 * 1024),
        )
        .with_arguments(arguments);
        let proposal = CheckProposal::new(
            check_id(&self.component, role.tag()),
            role.title(),
            role.severity(),
            role.critical(),
            EvidenceClass::DeterministicCheck,
            CheckReason::DeclaredCommand {
                declared_in: self.component.clone(),
                command: command.clone(),
            },
            &[role.action()],
        );
        drop(builder.propose(PlannedWork::new(proposal, CheckOperation::Command(spec))));
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_and_build_are_required_and_format_is_optional() {
        let project = DotnetProject {
            manifest: Some(crate::discover::dotnet::DotnetManifest {
                kind: crate::discover::dotnet::DotnetManifestKind::Solution,
                file: PathBuf::from("App.sln"),
            }),
            unread: None,
            target: Some(PathBuf::from("App.sln")),
            projects: Vec::new(),
            global_json: false,
            editorconfig: false,
        };
        let checks = DotnetChecks::of(&project);
        assert_eq!(checks.missing().len(), 1);
        assert_eq!(checks.missing()[0].title(), DotnetRole::Lint.title());

        let with_format = DotnetProject {
            editorconfig: true,
            ..project
        };
        assert!(DotnetChecks::of(&with_format).missing().is_empty());
    }
}
