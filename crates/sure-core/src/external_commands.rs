//! User-declared commands for a project SURE cannot discover.
//!
//! Some projects are not Node, Python or Rust: a Makefile, a shell script, a
//! build system with no manifest SURE knows. Their checks still matter, and the
//! person running SURE is the only one who can say what command answers them.
//!
//! **This is a user-level declaration and never project text.** The file is
//! named on the command line (`--commands-file`), lives outside the project, and
//! carries an argument vector rather than a command line — SURE never splits a
//! shell string. A project cannot write it, and a command here is still planned
//! under the same execution mode and permissions as every other check.
//!
//! # The file
//!
//! ```yaml
//! commands:
//!   test: ["make", "test"]
//!   build: ["make", "build"]
//!   lint: ["make", "lint"]
//!   typecheck: ["make", "typecheck"]
//! ```
//!
//! The first element is the program, the rest are its arguments, one element
//! per argument. Roles SURE knows are `test`, `build`, `lint` and `typecheck`;
//! an unknown role, an empty vector or an empty program is refused before any
//! check is planned.

use std::collections::BTreeMap;
use std::path::Path;

use serde::Deserialize;
use sure_domain::execution::ActionKind;
use sure_domain::severity::Severity;

/// One role a user may declare a command for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ExternalRole {
    Test,
    Build,
    Lint,
    TypeCheck,
}

impl ExternalRole {
    pub const ALL: &'static [Self] = &[Self::Test, Self::Build, Self::Lint, Self::TypeCheck];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Test => "test",
            Self::Build => "build",
            Self::Lint => "lint",
            Self::TypeCheck => "typecheck",
        }
    }

    /// The sentence a report prints as the check's title.
    #[must_use]
    pub const fn title(self) -> &'static str {
        match self {
            Self::Test => "run the tests",
            Self::Build => "build the project",
            Self::Lint => "check the code for style and likely mistakes",
            Self::TypeCheck => "check the types without running the code",
        }
    }

    #[must_use]
    pub const fn severity(self) -> Severity {
        match self {
            Self::Test | Self::Build => Severity::MustFix,
            Self::Lint => Severity::CanFixLater,
            Self::TypeCheck => Severity::ShouldFixFirst,
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
            Self::TypeCheck => ActionKind::TypeCheck,
        }
    }

    fn from_name(name: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|role| role.as_str() == name)
    }
}

/// One user-declared command, with the role it answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalCommand {
    pub role: ExternalRole,
    /// Program followed by its arguments, one element per argument.
    pub argv: Vec<String>,
}

impl ExternalCommand {
    /// The line a report shows. Display only; the argv is what runs.
    #[must_use]
    pub fn command_line(&self) -> String {
        self.argv.join(" ")
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CommandsFile {
    commands: BTreeMap<String, Vec<String>>,
}

/// Parse the YAML commands file.
///
/// # Errors
///
/// Returns a user-readable sentence for invalid YAML, an unknown role, an empty
/// command list, or an empty program name.
pub fn parse(text: &str) -> Result<Vec<ExternalCommand>, String> {
    let file: CommandsFile = serde_yaml_ng::from_str(text)
        .map_err(|error| format!("the commands file is not valid YAML: {error}"))?;
    if file.commands.is_empty() {
        return Err("the commands file declares no commands".to_owned());
    }
    let mut commands = Vec::with_capacity(file.commands.len());
    for (name, argv) in file.commands {
        let role = ExternalRole::from_name(&name).ok_or_else(|| {
            format!(
                "the commands file names `{name}`, which is not one of: {}",
                ExternalRole::ALL
                    .iter()
                    .map(|role| role.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        })?;
        if argv.is_empty() || argv[0].trim().is_empty() {
            return Err(format!(
                "the commands file declares `{name}` with no program to run"
            ));
        }
        commands.push(ExternalCommand { role, argv });
    }
    commands.sort_by_key(|command| command.role);
    Ok(commands)
}

/// Read and parse a commands file.
///
/// # Errors
///
/// Returns a user-readable sentence when the file cannot be read or parsed.
pub fn load(path: &Path) -> Result<Vec<ExternalCommand>, String> {
    let text = std::fs::read_to_string(path).map_err(|error| {
        format!(
            "could not read the commands file {}: {error}",
            path.display()
        )
    })?;
    parse(&text)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn a_complete_file_parses_in_role_order() {
        let commands =
            parse("commands:\n  typecheck: [\"make\", \"types\"]\n  test: [\"make\", \"test\"]\n")
                .expect("a valid file");
        assert_eq!(
            commands.iter().map(|c| c.role).collect::<Vec<_>>(),
            vec![ExternalRole::Test, ExternalRole::TypeCheck]
        );
        assert_eq!(commands[0].command_line(), "make test");
    }

    #[test]
    fn an_unknown_role_is_refused_with_the_known_ones_named() {
        let error = parse("commands:\n  deploy: [\"make\", \"deploy\"]\n").unwrap_err();
        assert!(error.contains("deploy"), "{error}");
        assert!(error.contains("typecheck"), "{error}");
    }

    #[test]
    fn an_empty_program_is_refused() {
        let error = parse("commands:\n  test: [\"\"]\n").unwrap_err();
        assert!(error.contains("no program"), "{error}");
        let error = parse("commands:\n  test: []\n").unwrap_err();
        assert!(error.contains("no program"), "{error}");
    }
}
