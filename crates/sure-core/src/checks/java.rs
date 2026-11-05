//! The checks a Java project's Maven POM turns into.
//!
//! Two commands, both Maven's own: `mvn -B -ntp test` and `mvn -B -ntp package
//! -DskipTests`, run at the project root. The root is the directory Maven runs a
//! reactor from: a POM whose `<modules>` names subdirectories is built by the
//! aggregator, so one pair of commands covers every module the reactor includes
//! — planning one pair per module would run the same reactor once per module and
//! report Maven's own aggregation as several separate checks.
//!
//! `-B` is batch mode: no colour, no interactive progress, which is what a
//! captured log wants. `-ntp` (no transfer progress) stops the download progress
//! lines a first run prints for every artifact: they are megabytes of noise for
//! a log SURE keeps a bounded prefix of, and a bounded log full of progress bars
//! is one that may be truncated before the part that says whether the build
//! passed. `-DskipTests` on the build check compiles the test sources and skips
//! running them, so the test role owns *running* tests and the build role owns
//! *building* the project without paying for the suite twice.
//!
//! **A Gradle project gets no command.** A Gradle build script is code, and two
//! commands picked from it would be SURE's guess at another tool's language; the
//! checks are missing commands whose reason says the declaration is written in a
//! shape SURE does not read. A POM SURE could not read is missing commands for
//! the same reason [`super::go`] gives: silence about tests in a project whose
//! manifest could not be read is a silence a reader takes for absence.

use std::path::Path;

use sure_domain::evidence::EvidenceClass;
use sure_domain::execution::ActionKind;
use sure_domain::severity::Severity;

use crate::checks::{CHECK_LIMITS, MissingCommand, MissingKind, check_id};
use crate::discover::JavaProject;
use crate::discover::java::JavaBuild;
use crate::planned_work::{CheckOperation, CommandSpec, PlannedWork};
use crate::process::Environment;
use crate::schedule::{CheckProposal, CheckReason, PlanBuilder};

/// The roles SURE proposes for a Maven project.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JavaRole {
    Test,
    Build,
}

impl JavaRole {
    pub const ALL: &'static [Self] = &[Self::Test, Self::Build];

    #[must_use]
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Test => "maventest",
            Self::Build => "mavenbuild",
        }
    }

    #[must_use]
    pub const fn title(self) -> &'static str {
        match self {
            Self::Test => "run the Java tests",
            Self::Build => "build the Java project",
        }
    }

    #[must_use]
    pub const fn command(self) -> &'static str {
        match self {
            Self::Test => "mvn -B -ntp test",
            Self::Build => "mvn -B -ntp package -DskipTests",
        }
    }

    /// The argument vector, one element per argument.
    #[must_use]
    pub const fn arguments(self) -> &'static [&'static str] {
        match self {
            Self::Test => &["-B", "-ntp", "test"],
            Self::Build => &["-B", "-ntp", "package", "-DskipTests"],
        }
    }

    #[must_use]
    pub const fn severity(self) -> Severity {
        match self {
            Self::Test | Self::Build => Severity::MustFix,
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
        }
    }
}

/// The proposals a Java project produces, and the ones it cannot.
#[derive(Debug, Clone, Default)]
pub struct JavaChecks {
    component: String,
    missing: Vec<MissingCommand>,
}

impl JavaChecks {
    /// The checks for one Java project.
    #[must_use]
    pub fn of(project: &JavaProject) -> Self {
        let component = match project.build {
            JavaBuild::Maven => "pom.xml".to_owned(),
            JavaBuild::Gradle => project
                .gradle_files
                .first()
                .map(|name| (*name).to_owned())
                .or_else(|| project.wrapper.map(str::to_owned))
                .unwrap_or_else(|| "the Gradle build script".to_owned()),
        };
        let mut missing = Vec::new();
        if !project.manifest_read() {
            // A Gradle build script declares its tasks in code SURE does not
            // read; a POM SURE could not read is a recorded unread reason; and a
            // wrapper without a POM declares no command at all.
            let kind = if project.build == JavaBuild::Gradle || project.unread.is_some() {
                MissingKind::NotReadable
            } else {
                MissingKind::NotDeclared
            };
            for role in JavaRole::ALL {
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
    pub fn add_to(&self, project: &JavaProject, root: &Path, builder: &mut PlanBuilder) {
        if !project.manifest_read() || project.build != JavaBuild::Maven {
            return;
        }
        for role in JavaRole::ALL {
            let command = role.command();
            let spec = CommandSpec::new("mvn", root, Environment::inherited(), CHECK_LIMITS)
                .with_arguments(role.arguments());
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn gradle_project() -> JavaProject {
        JavaProject {
            build: JavaBuild::Gradle,
            manifest: None,
            unread: None,
            modules: Vec::new(),
            wrapper: None,
            gradle_files: vec!["build.gradle"],
        }
    }

    #[test]
    fn a_gradle_project_has_missing_commands() {
        let checks = JavaChecks::of(&gradle_project());
        assert_eq!(checks.missing().len(), 2);
        assert!(
            checks
                .missing()
                .iter()
                .all(|missing| *missing.kind() == MissingKind::NotReadable)
        );
    }

    #[test]
    fn a_maven_wrapper_without_a_pom_declares_no_command() {
        let project = JavaProject {
            build: JavaBuild::Maven,
            manifest: None,
            unread: None,
            modules: Vec::new(),
            wrapper: Some("mvnw"),
            gradle_files: Vec::new(),
        };
        let checks = JavaChecks::of(&project);
        assert_eq!(checks.missing().len(), 2);
        assert!(
            checks
                .missing()
                .iter()
                .all(|missing| *missing.kind() == MissingKind::NotDeclared)
        );
    }
}
