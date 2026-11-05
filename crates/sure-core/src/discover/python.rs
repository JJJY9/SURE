//! What a Python project declares about itself.
//!
//! See [`super`] for the rule this is all arranged around: **a manifest states a
//! request, not a fact.** Nothing here runs `pip`, `uv` or `python`, resolves a
//! version, imports anything, or opens a virtual environment.
//!
//! # The files it reads, and why those
//!
//! | File | What it answers |
//! |---|---|
//! | `pyproject.toml` | the whole of what a modern project declares — PEP 621, Poetry, PDM and uv all put it here |
//! | `Pipfile` | what pipenv projects declare, in TOML, under the same accessors |
//! | `requirements*.txt` | dependencies declared as a flat list, the older way |
//! | `setup.py`, `setup.cfg` | that this is a Python project, and that SURE cannot read what it declares |
//! | `poetry.lock`, `uv.lock`, `Pipfile.lock`, `pdm.lock` | which installer has run here |
//! | `.python-version` | the interpreter the project asks for |
//!
//! A lockfile is **not parsed**, for the reason [`super::node`] gives and one of
//! its own: a Python lockfile is not a single format. `poetry.lock` is TOML,
//! `uv.lock` is TOML with a different schema, `Pipfile.lock` is JSON, and
//! `pdm.lock` is TOML again. What is wanted from all four is one bit — *this
//! project has a `uv.lock`* — and that bit is the file's existence, which is
//! also why the manifest byte budget is never spent on one.
//!
//! # Why `setup.py` is never read
//!
//! **`setup.py` is a Python program.** Everything it declares is the result of
//! running it: `install_requires=[x for x in ...]`, a version read from a file,
//! a dependency list fetched from the network. There is no reading it that is
//! not running it, and SURE does not run a project to find out what it is. So
//! its presence says *this project declares itself in code SURE will not
//! execute*, which is a finding, and `setup.cfg` is left unread for a smaller
//! reason with the same shape: it is INI, no INI parser is in this workspace's
//! dependency set, and a hand-rolled one could silently mis-parse — the reason
//! `docs/architecture/RUST_DESIGN.md` gives for using real parsers everywhere
//! else. Both are recorded as what they are rather than reported as absence.
//!
//! # Why the installer is not simply "the one with a lockfile"
//!
//! The same argument [`super::node`] makes, and it lands differently here
//! because Python's evidence is different in kind:
//!
//! - **declared** — a `[tool.<installer>]` table, or a `Pipfile` for pipenv.
//!   The project's own statement about itself.
//! - **locked** — that installer's lockfile exists.
//! - **requirements** — a `requirements*.txt` exists.
//!
//! The third is the interesting one, and it is **the weakest evidence in the
//! whole module**, weaker than Node's `engines` hint: `uv pip install -r
//! requirements.txt`, `poetry export`, `pdm export` and pip all consume that same
//! file, so its existence says *something installs from a requirements file* and
//! does not say which. It therefore never creates a disagreement, and it decides
//! [`Managers::agreed`] only when nothing stronger was found. A project with both
//! `requirements.txt` and `uv.lock` is not contradicting itself — that is the
//! normal shape of a project that moved to uv and kept the file its deployment
//! reads — and reporting it as a contradiction would be a false alarm of exactly
//! the kind that trains a reader to ignore the real one.
//!
//! # Why the tool table is fixed
//!
//! Same reason as [`super::node`]: package names live in the project's manifest,
//! so every tool this module reports comes from [`TOOLS`] and the value stored is
//! the table's own `&'static str`. A dependency that is not in the table is not
//! reported at all.
//!
//! # The one thing here that is SURE's construction rather than the project's
//!
//! [`command_for`] returns a command SURE built — `uv run pytest` — and Node's
//! [`super::node::Package::command_for`] returns one built from a script the
//! *project* wrote. The difference matters and is why this module names its
//! type [`ConventionalCommand`] rather than reusing Node's
//! [`super::node::ConventionalScript`]: **the command is a plan, and it is never
//! evidence about the project.** A plan is only offered for a role the project
//! declared the tool for, and the tools behind it are named in
//! [`ConventionalCommand::because`] so a reader can see what the plan rests on.
//!
//! **The plan and the line are one value seen twice.** Since `P18-T003`
//! [`invocation_for`] answers the plan as an [`Invocation`] — a program and its
//! argument vector — and [`command_for`] renders that plan for a person to read.
//! Nothing is spelled twice and nothing is parsed: a caller that means to *start*
//! a check takes the vector, and a report takes the rendering, so the two cannot
//! describe different things.

use std::path::{Path, PathBuf};

use sure_domain::vocabulary::SupportLevel;

use super::read::{self, Budget, Probe, ReadFile, UnreadReason};
use super::{DiscoverOptions, Ecosystem, EcosystemReport, Findings, Invocation, Source, Unread};
use crate::scan::Scan;

/// The manifest modern Python projects declare themselves in.
///
/// Public for the same reason [`super::node::MANIFEST`] is: a check about this
/// project has to name the file it was read from, and a copy of the string one
/// layer up is a copy that stops agreeing the day this one changes.
pub const MANIFEST: &str = "pyproject.toml";

/// pipenv's manifest, which is TOML too and is read by the same accessors.
pub const PIPFILE: &str = "Pipfile";

/// The file that says what interpreter the project asks for.
const VERSION_FILE: &str = ".python-version";

/// `setup.cfg`, whose packaging metadata SURE does not read but whose tool
/// sections name tools a project uses.
const SETUP_CFG: &str = "setup.cfg";

/// The two legacy files that say "this is a Python project" without SURE being
/// able to read what it declares.
const LEGACY_FILES: &[&str] = &["setup.py", SETUP_CFG];

/// Tool configuration files that name a tool without a dependency entry.
///
/// A project can install its tools from CI or a developer shell rather than
/// list them in `pyproject.toml`; the file the tool reads is itself evidence
/// that the project uses it. Existence is enough — these files are dedicated to
/// one tool, so no content is guessed at and no file is executed.
///
/// `setup.cfg` is not here because its sections need reading rather than its
/// existence; [`SETUP_CFG_TOOL_SECTIONS`] is the smaller list read from it.
const CONFIG_TOOLS: &[(&str, &str, ToolingEvidence)] = &[
    ("pytest.ini", "pytest", ToolingEvidence::PytestIni),
    ("tox.ini", "tox", ToolingEvidence::ToxIni),
    ("noxfile.py", "nox", ToolingEvidence::Noxfile),
    ("ruff.toml", "ruff", ToolingEvidence::Config),
    (".ruff.toml", "ruff", ToolingEvidence::Config),
    ("mypy.ini", "mypy", ToolingEvidence::Config),
    (".mypy.ini", "mypy", ToolingEvidence::Config),
    ("pyrightconfig.json", "pyright", ToolingEvidence::Config),
    ("pylintrc", "pylint", ToolingEvidence::Config),
    (".pylintrc", "pylint", ToolingEvidence::Config),
    (".flake8", "flake8", ToolingEvidence::Config),
];

/// Tool sections in `setup.cfg`.
///
/// The packaging metadata in that file is still not read; these section names
/// are, because they name a tool without putting it in a dependency table.
const SETUP_CFG_TOOL_SECTIONS: &[(&str, &str, ToolingEvidence)] = &[
    ("tool:pytest", "pytest", ToolingEvidence::SetupCfgPytest),
    ("flake8", "flake8", ToolingEvidence::Config),
    ("mypy", "mypy", ToolingEvidence::Config),
    ("pylint", "pylint", ToolingEvidence::Config),
];

/// `[tool.*]` tables in `pyproject.toml` that name a tool SURE checks.
///
/// The table's existence is the declaration; its contents are the tool's
/// business and are never interpreted here.
const TOOL_SECTIONS: &[(&str, &str, ToolingEvidence)] = &[
    ("pytest", "pytest", ToolingEvidence::PytestTable),
    ("tox", "tox", ToolingEvidence::ToxTable),
    ("ruff", "ruff", ToolingEvidence::Config),
    ("mypy", "mypy", ToolingEvidence::Config),
    ("pyright", "pyright", ToolingEvidence::Config),
    ("pylint", "pylint", ToolingEvidence::Config),
    ("flake8", "flake8", ToolingEvidence::Config),
];

/// The prefix and suffix a requirements file is recognised by.
///
/// A rule rather than a list, because the names after `requirements` are the
/// project's: `requirements-dev.txt`, `requirements-prod.txt`,
/// `requirements-test.txt` and a dozen other spellings are all in use, and a
/// fixed list of guesses would silently miss whichever one a project chose.
const REQUIREMENTS_PREFIX: &str = "requirements";
const REQUIREMENTS_SUFFIX: &str = ".txt";

/// How many requirements files one discovery will read.
///
/// Separate from the manifest budget because the names are unbounded: a rule
/// that matches every `requirements*.txt` will match a directory of a thousand
/// of them if a project has one, and reading all of them is work a project does
/// not get to ask for. Reaching this is reported, not applied quietly.
const MAX_REQUIREMENTS_FILES: usize = 32;

/// The lockfiles recognised, each naming the installer that writes it.
///
/// A table rather than a chain of `if`s so that "every lockfile SURE knows" is a
/// list a test can hold against [`Installer::ALL`] — a manager that could never
/// be detected from a lockfile is worth failing a test over.
const LOCKFILES: &[(&str, Installer)] = &[
    ("uv.lock", Installer::Uv),
    ("poetry.lock", Installer::Poetry),
    ("Pipfile.lock", Installer::Pipenv),
    ("pdm.lock", Installer::Pdm),
];

/// An installer or project manager SURE can recognise.
///
/// Five, and each one owns both a way to install and a way to record what was
/// installed. `hatch` and `flit` are deliberately **not** here: they build
/// distributions, and a build backend is a different claim from an installer —
/// see [`ToolRole::BuildBackend`], where both appear as tools.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Installer {
    /// `pip`, with `requirements.txt`.
    Pip,
    /// `uv`.
    Uv,
    /// `poetry`.
    Poetry,
    /// `pipenv`.
    Pipenv,
    /// `pdm`.
    Pdm,
}

impl Installer {
    /// Every installer SURE recognises, in a fixed order.
    pub const ALL: &'static [Self] = &[Self::Pip, Self::Uv, Self::Poetry, Self::Pipenv, Self::Pdm];

    /// The stable name, and the command a person would type.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pip => "pip",
            Self::Uv => "uv",
            Self::Poetry => "poetry",
            Self::Pipenv => "pipenv",
            Self::Pdm => "pdm",
        }
    }

    /// The `[tool.<name>]` table that declares this installer, if it has one.
    ///
    /// `pip` answers `None` and that is correct rather than missing: pip has no
    /// pyproject table, no lockfile and no manifest of its own. What it has is
    /// `requirements.txt`, which four other tools also read.
    #[must_use]
    pub const fn tool_table(self) -> Option<&'static str> {
        match self {
            Self::Pip => None,
            Self::Uv => Some("uv"),
            Self::Poetry => Some("poetry"),
            Self::Pipenv => None,
            Self::Pdm => Some("pdm"),
        }
    }

    /// The installer a `[build-system]` backend belongs to, if any.
    ///
    /// Only the two backends that share a name with their installer. A backend
    /// naming anything else — `setuptools`, `hatchling`, `flit_core`,
    /// `scikit-build-core` — says nothing about which installer is used, and
    /// mapping one onto the other would be SURE inventing a convention.
    #[must_use]
    pub fn from_build_backend(backend: &str) -> Option<Self> {
        // `poetry.core.masonry.api` and `pdm.backend` are the dotted forms a
        // `[build-system]` table really writes, so the first component is what
        // is compared rather than the whole string.
        let head = backend.split('.').next().unwrap_or(backend);
        match head {
            "poetry" => Some(Self::Poetry),
            "pdm" => Some(Self::Pdm),
            "uv" => Some(Self::Uv),
            _ => None,
        }
    }
}

/// Ordered strongest first, which is the order [`Managers::agreed`] uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum InstallerEvidence {
    /// A `[tool.<installer>]` table, or a `Pipfile` for pipenv.
    Declared,
    /// A lockfile for it is present.
    Lockfile,
    /// A `requirements*.txt` is present.
    ///
    /// The weakest thing in this module. See the module comment: pip, uv, poetry
    /// and pdm all install from one.
    RequirementsFile,
}

impl InstallerEvidence {
    /// The stable wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Declared => "declared",
            Self::Lockfile => "lockfile",
            Self::RequirementsFile => "requirements_file",
        }
    }

    /// The sentence a person reads.
    #[must_use]
    pub const fn plain_description(self) -> &'static str {
        match self {
            Self::Declared => {
                "the project has this installer's own configuration in its pyproject.toml"
            }
            Self::Lockfile => "this project has a lockfile for it",
            Self::RequirementsFile => {
                "this project has a requirements file, which several installers read, so \
                 this is the weakest evidence here"
            }
        }
    }
}

/// One installer, and why SURE named it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallerFinding {
    /// Which installer.
    pub installer: Installer,
    /// How SURE knows.
    pub evidence: InstallerEvidence,
    /// The file it came from.
    pub source: Source,
}

/// Two pieces of evidence naming two different installers.
///
/// Reported rather than resolved, for the reason [`super::node::Disagreement`]
/// gives: where the project says two things, SURE's answer is that it says two
/// things.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disagreement {
    /// The project's own configuration names two installers.
    ///
    /// Python can do this and Node cannot: `[tool.pdm]` and `[tool.uv]` are two
    /// tables in one file, and a project can genuinely carry both — which is a
    /// different thing from carrying a lockfile left behind by an installer it
    /// no longer uses, and is reported as the different thing it is.
    TwoDeclarations {
        /// The first, in [`Installer::ALL`] order.
        first: Installer,
        /// The second.
        second: Installer,
    },
    /// Two lockfiles, for two installers.
    TwoLockfiles {
        /// The first, in [`Installer::ALL`] order.
        first: Installer,
        /// The second.
        second: Installer,
    },
    /// The project's own configuration names one installer and a lockfile names
    /// another.
    ConfigurationAndLockfile {
        /// What the project's configuration says it uses.
        configured: Installer,
        /// What a lockfile says was used.
        locked: Installer,
    },
}

impl Disagreement {
    /// The sentence a person reads.
    #[must_use]
    pub const fn plain_description(self) -> &'static str {
        match self {
            Self::TwoDeclarations { .. } => {
                "This project configures two different installers, so SURE cannot tell \
                 which one it uses."
            }
            Self::TwoLockfiles { .. } => {
                "This project has lockfiles for two different installers, so SURE cannot \
                 tell which one it uses."
            }
            Self::ConfigurationAndLockfile { .. } => {
                "This project configures one installer and has a lockfile from another, \
                 so SURE cannot tell which one it uses."
            }
        }
    }

    /// One of the two installers involved.
    #[must_use]
    pub const fn one_of(self) -> Installer {
        match self {
            Self::TwoDeclarations { first, .. } | Self::TwoLockfiles { first, .. } => first,
            Self::ConfigurationAndLockfile { configured, .. } => configured,
        }
    }

    /// The other one.
    #[must_use]
    pub const fn other_of(self) -> Installer {
        match self {
            Self::TwoDeclarations { second, .. } | Self::TwoLockfiles { second, .. } => second,
            Self::ConfigurationAndLockfile { locked, .. } => locked,
        }
    }
}

/// Every installer SURE found evidence for, kept by how strong the evidence is.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Managers {
    /// Installers the project's own configuration names. More than one is a
    /// disagreement.
    pub configured: Vec<InstallerFinding>,
    /// Installers a lockfile names. More than one is a disagreement.
    pub locked: Vec<InstallerFinding>,
    /// Installers a requirements file points at. Never a disagreement; see the
    /// module comment.
    pub requirements: Vec<InstallerFinding>,
}

impl Managers {
    /// Where the evidence contradicts itself, if it does.
    ///
    /// The configuration is checked first, on the same reasoning
    /// [`super::node::Managers::disagreement`] uses: a project that configures
    /// poetry and carries a `uv.lock` is mid-migration, and that is a more
    /// useful thing to say than "there are two lockfiles" even when both are
    /// true.
    #[must_use]
    pub fn disagreement(&self) -> Option<Disagreement> {
        let configured: Vec<Installer> = self
            .configured
            .iter()
            .map(|found| found.installer)
            .collect();
        let locked: Vec<Installer> = self.locked.iter().map(|found| found.installer).collect();

        // Two declarations first: a project configuring two installers is saying
        // two things about itself right now, which is a stronger statement than
        // a lockfile left behind by one it no longer uses — and the two are
        // different findings, so they are different variants.
        if let Some(first) = configured.first().copied()
            && let Some(second) = second_distinct(configured.iter().copied())
        {
            return Some(Disagreement::TwoDeclarations { first, second });
        }
        if let Some(&configured) = configured.first()
            && let Some(&locked) = locked.iter().find(|&&found| found != configured)
        {
            return Some(Disagreement::ConfigurationAndLockfile { configured, locked });
        }
        if let Some(first) = locked.first().copied()
            && let Some(second) = second_distinct(locked.iter().copied())
        {
            return Some(Disagreement::TwoLockfiles { first, second });
        }
        None
    }

    /// The evidence that decided which installer, or `None` when it cannot pick
    /// one.
    ///
    /// **The tier order lives here and nowhere else**, and [`Self::agreed`] is a
    /// view of this function rather than a second copy of the walk. A caller
    /// that needs to name *the file that decided* — a report line saying where an
    /// install step comes from — cannot get that from an [`Installer`], and a
    /// second walk written to fetch it would be a second answer to the same
    /// question, free to drift from the first.
    ///
    /// `None` for two different reasons that are not the same finding: no
    /// evidence at all, and evidence pointing two ways. A caller that has to tell
    /// them apart asks [`Self::disagreement`], as [`super`](crate::checks) does.
    #[must_use]
    pub fn agreed_finding(&self) -> Option<&InstallerFinding> {
        if self.disagreement().is_some() {
            return None;
        }
        self.configured
            .first()
            .or_else(|| self.locked.first())
            .or_else(|| self.requirements.first())
    }

    /// The one installer SURE would use, or `None` when it cannot pick one.
    ///
    /// `None` for two different reasons that are not the same finding: no
    /// evidence at all, and evidence pointing two ways.
    #[must_use]
    pub fn agreed(&self) -> Option<Installer> {
        self.agreed_finding().map(|found| found.installer)
    }
}

/// The first value an iterator yields that differs from its first, if any.
///
/// The lists it is used on are one-per-installer and sorted by [`Installer::ALL`]
/// by the time they get here, so "a value differing from the first" is "a second
/// one". Written as a scan rather than as `list[1]` so it does not depend on the
/// caller having deduplicated first.
fn second_distinct(mut values: impl Iterator<Item = Installer>) -> Option<Installer> {
    let first = values.next()?;
    values.find(|&found| found != first)
}

/// Which part of a manifest declared a dependency.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DependencyKind {
    /// Needed to run it — PEP 621 `dependencies`, Poetry's `dependencies`,
    /// pipenv's `packages`.
    Runtime,
    /// Needed to develop it — PEP 735 `dependency-groups`, Poetry's groups and
    /// its older `dev-dependencies`, pipenv's `dev-packages`.
    Development,
    /// Needed for one optional feature — PEP 621 `optional-dependencies`.
    ///
    /// Kept apart from [`Self::Development`] because they answer different
    /// questions: an extra is something a *consumer* can ask for, and a
    /// development group is something a contributor installs.
    Optional,
}

impl DependencyKind {
    /// Every kind, in a fixed order.
    pub const ALL: &'static [Self] = &[Self::Runtime, Self::Development, Self::Optional];

    /// The stable wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Runtime => "runtime",
            Self::Development => "development",
            Self::Optional => "optional",
        }
    }

    /// The sentence a person reads.
    #[must_use]
    pub const fn plain_description(self) -> &'static str {
        match self {
            Self::Runtime => "the project needs it to run",
            Self::Development => "the project needs it to be worked on",
            Self::Optional => "the project needs it for one optional feature",
        }
    }
}

/// One dependency, as the manifest wrote it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dependency {
    /// The distribution name.
    pub name: String,
    /// The requirement, **verbatim**.
    ///
    /// `">=1.2,<2"`, `"^1.2"`, `"*"`, `"==1.0.0"`, `"foo @ https://..."` — a
    /// PEP 508 string, a Poetry caret range, or a URL. SURE has run no resolver
    /// and does not know what any of them resolves to, so it does not say.
    pub requirement: String,
    /// Which part of the manifest declared it.
    pub kind: DependencyKind,
    /// The extra or group it was declared under, **verbatim**, when it was
    /// declared under one.
    ///
    /// Data, never a sentence: a group name is the project's text, and the
    /// sentences around it are constants.
    pub group: Option<String>,
}

/// What kind of thing a recognised package is.
///
/// SURE's list, not the project's, for the reason [`super::node::ToolRole`]
/// gives: a project that declares no linter is a finding, and it can only be
/// reported by looking for tools the project did not choose.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ToolRole {
    /// A framework for building a web application.
    WebFramework,
    /// A program that serves one — WSGI or ASGI.
    Server,
    /// Something that runs tests.
    TestRunner,
    /// Something tests use rather than something that runs them.
    TestSupport,
    /// Something that reports style and probable mistakes.
    Linter,
    /// Something that rewrites files to a style.
    Formatter,
    /// Something that checks types without running the code.
    TypeChecker,
    /// Something that measures which lines the tests ran.
    Coverage,
    /// Something that looks for security problems.
    Security,
    /// Something that builds the documentation.
    Docs,
    /// Something that builds a distribution.
    BuildBackend,
    /// Something that runs work outside the request.
    TaskQueue,
    /// Something that maps objects to a database.
    Orm,
    /// Something a data or machine-learning project is built on.
    DataStack,
}

impl ToolRole {
    /// Every role, in a fixed order.
    pub const ALL: &'static [Self] = &[
        Self::WebFramework,
        Self::Server,
        Self::TestRunner,
        Self::TestSupport,
        Self::Linter,
        Self::Formatter,
        Self::TypeChecker,
        Self::Coverage,
        Self::Security,
        Self::Docs,
        Self::BuildBackend,
        Self::TaskQueue,
        Self::Orm,
        Self::DataStack,
    ];

    /// The stable wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WebFramework => "web_framework",
            Self::Server => "server",
            Self::TestRunner => "test_runner",
            Self::TestSupport => "test_support",
            Self::Linter => "linter",
            Self::Formatter => "formatter",
            Self::TypeChecker => "type_checker",
            Self::Coverage => "coverage",
            Self::Security => "security",
            Self::Docs => "docs",
            Self::BuildBackend => "build_backend",
            Self::TaskQueue => "task_queue",
            Self::Orm => "orm",
            Self::DataStack => "data_stack",
        }
    }

    /// The sentence a person reads.
    #[must_use]
    pub const fn plain_description(self) -> &'static str {
        match self {
            Self::WebFramework => "build a web application",
            Self::Server => "serve a web application",
            Self::TestRunner => "run the tests",
            Self::TestSupport => "write tests with",
            Self::Linter => "report style and probable mistakes",
            Self::Formatter => "rewrite files to a style",
            Self::TypeChecker => "check types without running the code",
            Self::Coverage => "measure which lines the tests ran",
            Self::Security => "look for security problems",
            Self::Docs => "build the documentation",
            Self::BuildBackend => "build a distribution",
            Self::TaskQueue => "run work outside the request",
            Self::Orm => "map objects to a database",
            Self::DataStack => "work with data or train a model",
        }
    }
}

/// Where a recognised tool's declaration came from.
///
/// The order is the precedence MiQi's project-test detector uses: a `tox.ini`
/// names the test entry point, then a `noxfile.py`, then a `pytest.ini`, then
/// the corresponding `pyproject.toml` tables, then `setup.cfg`. A dependency
/// list comes last. The derived `Ord` puts the earliest declaration first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ToolingEvidence {
    /// `tox.ini`.
    ToxIni,
    /// `noxfile.py`.
    Noxfile,
    /// `pytest.ini`.
    PytestIni,
    /// `[tool.tox]` in `pyproject.toml`.
    ToxTable,
    /// `[tool.pytest]` in `pyproject.toml`.
    PytestTable,
    /// `[tool:pytest]` in `setup.cfg`.
    SetupCfgPytest,
    /// Any other dedicated config file or `[tool.*]` table.
    Config,
    /// A dependency or requirements table names the package.
    Dependency,
}

/// One recognised package, and where it was declared.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tooling {
    /// The package name, from [`TOOLS`] — never the project's spelling.
    pub package: &'static str,
    /// What it is.
    pub role: ToolRole,
    /// The directory it was declared in, relative to the project root.
    ///
    /// Empty for the root project. Carried so that a monorepo's tools can be
    /// told apart by where they were declared once member manifests are read.
    pub from: PathBuf,
    /// The file that declared it, when discovery can name one.
    ///
    /// `None` for a hand-built value that has no file behind it; `Some` for a
    /// dependency table, a requirements file, or a tool's own config file. The
    /// check's `declared_in` reads this so a `pytest.ini` declaration points at
    /// `pytest.ini` rather than at the manifest SURE happened to read first.
    pub source: Option<PathBuf>,
    /// Whether the declaration is a config file/table or a dependency list.
    pub evidence: ToolingEvidence,
}

/// The packages SURE recognises, and what each one is.
///
/// A fixed table, and the value stored in a [`Tooling`] is the table's own
/// `&'static str`. A package not in this table is not reported at all.
///
/// Two packages appear twice, which is why everything that reads this table
/// takes an iterator rather than one value: `ruff` lints *and* formats, and
/// `pytest-cov` is both a test support package and the way coverage is usually
/// measured. Picking one role for either would be SURE choosing which half of a
/// tool to mention.
///
/// Names are **normalised the way the packaging metadata normalises them** — see
/// [`normalise`] — so `Pillow`, `pillow` and `PIL` are one row, and
/// `scikit-learn` is found whether the manifest wrote it with a dash or an
/// underscore. That is the one place a project's spelling decides whether a
/// finding exists, and it is safe because the *matched* spelling is discarded:
/// what is reported is this table's name.
const TOOLS: &[(&str, ToolRole)] = &[
    // Web frameworks.
    ("django", ToolRole::WebFramework),
    ("flask", ToolRole::WebFramework),
    ("fastapi", ToolRole::WebFramework),
    ("starlette", ToolRole::WebFramework),
    ("aiohttp", ToolRole::WebFramework),
    ("tornado", ToolRole::WebFramework),
    ("pyramid", ToolRole::WebFramework),
    ("bottle", ToolRole::WebFramework),
    ("sanic", ToolRole::WebFramework),
    ("litestar", ToolRole::WebFramework),
    ("quart", ToolRole::WebFramework),
    ("streamlit", ToolRole::WebFramework),
    ("gradio", ToolRole::WebFramework),
    ("dash", ToolRole::WebFramework),
    // Servers.
    ("uvicorn", ToolRole::Server),
    ("gunicorn", ToolRole::Server),
    ("hypercorn", ToolRole::Server),
    ("waitress", ToolRole::Server),
    ("daphne", ToolRole::Server),
    // Test runners.
    ("pytest", ToolRole::TestRunner),
    ("nose2", ToolRole::TestRunner),
    ("nose", ToolRole::TestRunner),
    ("robotframework", ToolRole::TestRunner),
    ("tox", ToolRole::TestRunner),
    ("nox", ToolRole::TestRunner),
    ("green", ToolRole::TestRunner),
    // Test support.
    ("pytest-asyncio", ToolRole::TestSupport),
    ("pytest-django", ToolRole::TestSupport),
    ("pytest-mock", ToolRole::TestSupport),
    ("pytest-xdist", ToolRole::TestSupport),
    ("pytest-cov", ToolRole::TestSupport),
    ("pytest-cov", ToolRole::Coverage),
    ("hypothesis", ToolRole::TestSupport),
    ("factory-boy", ToolRole::TestSupport),
    ("faker", ToolRole::TestSupport),
    ("freezegun", ToolRole::TestSupport),
    ("responses", ToolRole::TestSupport),
    ("requests-mock", ToolRole::TestSupport),
    ("mutmut", ToolRole::TestSupport),
    // Linters.
    ("ruff", ToolRole::Linter),
    ("flake8", ToolRole::Linter),
    ("pylint", ToolRole::Linter),
    ("pyflakes", ToolRole::Linter),
    ("pycodestyle", ToolRole::Linter),
    ("pydocstyle", ToolRole::Linter),
    ("vulture", ToolRole::Linter),
    ("mccabe", ToolRole::Linter),
    // Formatters.
    ("ruff", ToolRole::Formatter),
    ("black", ToolRole::Formatter),
    ("isort", ToolRole::Formatter),
    ("yapf", ToolRole::Formatter),
    ("autopep8", ToolRole::Formatter),
    // Type checkers.
    ("mypy", ToolRole::TypeChecker),
    ("pyright", ToolRole::TypeChecker),
    ("pyre-check", ToolRole::TypeChecker),
    ("pytype", ToolRole::TypeChecker),
    ("typeguard", ToolRole::TypeChecker),
    ("beartype", ToolRole::TypeChecker),
    // Coverage.
    ("coverage", ToolRole::Coverage),
    ("diff-cover", ToolRole::Coverage),
    // Security.
    ("bandit", ToolRole::Security),
    ("pip-audit", ToolRole::Security),
    ("safety", ToolRole::Security),
    // Documentation.
    ("sphinx", ToolRole::Docs),
    ("mkdocs", ToolRole::Docs),
    ("mkdocstrings", ToolRole::Docs),
    ("pdoc", ToolRole::Docs),
    // Build backends.
    ("setuptools", ToolRole::BuildBackend),
    ("poetry-core", ToolRole::BuildBackend),
    ("hatchling", ToolRole::BuildBackend),
    ("flit-core", ToolRole::BuildBackend),
    ("pdm-backend", ToolRole::BuildBackend),
    ("maturin", ToolRole::BuildBackend),
    ("scikit-build-core", ToolRole::BuildBackend),
    ("meson-python", ToolRole::BuildBackend),
    // Task queues.
    ("celery", ToolRole::TaskQueue),
    ("dramatiq", ToolRole::TaskQueue),
    ("rq", ToolRole::TaskQueue),
    ("arq", ToolRole::TaskQueue),
    ("huey", ToolRole::TaskQueue),
    // ORMs and database layers.
    ("sqlalchemy", ToolRole::Orm),
    ("peewee", ToolRole::Orm),
    ("tortoise-orm", ToolRole::Orm),
    ("sqlmodel", ToolRole::Orm),
    ("alembic", ToolRole::Orm),
    // Data and machine learning.
    ("numpy", ToolRole::DataStack),
    ("pandas", ToolRole::DataStack),
    ("polars", ToolRole::DataStack),
    ("scipy", ToolRole::DataStack),
    ("scikit-learn", ToolRole::DataStack),
    ("torch", ToolRole::DataStack),
    ("tensorflow", ToolRole::DataStack),
    ("jax", ToolRole::DataStack),
    ("matplotlib", ToolRole::DataStack),
    ("seaborn", ToolRole::DataStack),
    ("plotly", ToolRole::DataStack),
    ("transformers", ToolRole::DataStack),
    ("datasets", ToolRole::DataStack),
];

/// A package name in the form the packaging metadata compares them in.
///
/// The Python packaging specification says a distribution name is
/// case-insensitive and that runs of `-`, `_` and `.` are equivalent:
/// `scikit-learn`, `scikit_learn` and `Scikit.Learn` are one distribution. So a
/// table that matched literally would miss `Pillow` for `pillow` and
/// `scikit_learn` for `scikit-learn`, and a project would be reported as
/// declaring no image library because of how it spelled one.
///
/// This is a *lookup* rule and nothing else. What a finding reports is the
/// table's own name, so a project cannot put text into a sentence by choosing a
/// spelling.
#[must_use]
fn normalise(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut last_was_separator = false;
    for character in name.chars() {
        if matches!(character, '-' | '_' | '.') {
            // Collapsed rather than kept: `a--b` and `a-b` are the same name,
            // and a rule that kept the run would be a rule that says otherwise.
            if !last_was_separator {
                out.push('-');
                last_was_separator = true;
            }
        } else {
            out.extend(character.to_lowercase());
            last_was_separator = false;
        }
    }
    out
}

/// Every role a package in [`TOOLS`] has, in table order.
///
/// Yields the table's own name beside each role, not the spelling it was asked
/// about. That is what keeps a project's spelling out of a finding: the caller
/// stores what it is given here, and what it is given here comes from the table.
fn tool_roles_of(name: &str) -> impl Iterator<Item = (&'static str, ToolRole)> + '_ {
    let wanted = normalise(name);
    TOOLS
        .iter()
        .filter(move |(package, _)| *package == wanted)
        .copied()
}

/// The declared name of a PEP 508 requirement string.
///
/// A conservative parse, and deliberately not a PEP 508 parser: a name is the
/// leading run of characters the specification allows in one. Everything after
/// that — an extra, a version specifier, an environment marker, a URL, a hash —
/// is left in the verbatim string and never interpreted.
///
/// `None` when the line does not begin with a name at all, which is what an
/// option line and a bare URL line look like: `--index-url ...`, `-r other.txt`,
/// `https://example.invalid/pkg.whl`.
///
/// The two rejections past "the run is empty" are what keeps a name from being
/// *invented*, and both are there because of a line that really occurs in a
/// requirements file:
///
/// - **A URL.** `https://example.invalid/pkg.whl` begins with a perfectly good
///   run of name characters, and taking it would report a project as depending
///   on a package called `https` — a dependency that does not exist, in a
///   context where the whole point is that SURE's claims are anchored. A name is
///   followed by nothing, whitespace, or one of the characters a requirement
///   continues with — never by `:` or `/`.
/// - **A trailing separator.** The specification's name ends in an alphanumeric,
///   so `foo-` is not a name and `foo.bar-` is not one either. Accepting one
///   would put a name in a finding that no installer would resolve.
fn requirement_name(line: &str) -> Option<String> {
    let trimmed = line.trim();
    let name: String = trimmed
        .chars()
        .take_while(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.')
        })
        .collect();
    if name.is_empty() || name.starts_with('-') || name.starts_with('.') {
        return None;
    }
    let last = name.chars().next_back().unwrap_or(' ');
    if !last.is_ascii_alphanumeric() {
        return None;
    }
    match trimmed[name.len()..].chars().next() {
        // `:` is a URL scheme and `/` a path — `https://…`, `/etc/…`. Neither
        // can follow a distribution name.
        Some(':' | '/') => None,
        _ => Some(name),
    }
}

/// One requirement line from a requirements file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Requirement {
    /// The distribution name, parsed from the line. Empty when the line names
    /// no distribution — see [`Self::line`].
    pub name: String,
    /// The whole line, **verbatim**, including any extras, specifier, marker,
    /// URL or hash it carried.
    pub line: String,
}

/// A requirements file, read.
///
/// Requirements files are the one Python declaration that is not a structured
/// document, so they are read line by line and every line lands in exactly one
/// of three places: a requirement, a directive, or a comment. Nothing is
/// dropped, because a reader who is told there are three requirements when the
/// file holds four has been told something false.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequirementsFile {
    /// The file, relative to the project root.
    pub path: PathBuf,
    /// The lines that name a distribution, in file order.
    pub requirements: Vec<Requirement>,
    /// The lines that are neither a requirement nor a comment, **verbatim**.
    ///
    /// `-r other.txt`, `--index-url ...`, `--hash=...` on its own line. Not
    /// followed: an `-r` include is a path from project text, and following one
    /// means reading a file the count of which is bounded by nothing SURE
    /// controls. Recorded so the reader knows the file points somewhere SURE did
    /// not go.
    pub directives: Vec<String>,
    /// How many lines were blank or started with `#`.
    pub comments: usize,
    /// Whether the file was longer than the number of lines SURE read.
    ///
    /// `true` means this is a prefix. A requirements file with a hundred
    /// thousand lines is a file SURE did not finish reading, and saying so is
    /// the useful answer.
    pub truncated: bool,
}

/// How many lines of one requirements file SURE will read.
const MAX_REQUIREMENTS_LINES: usize = 4096;

/// What is at the manifest's name.
///
/// Three arms, not an `Option`, for the reason [`super::read`] gives in full: a
/// project whose `pyproject.toml` could not be read must not be described as a
/// project with no `pyproject.toml`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestState {
    /// There is a manifest and this is what it says.
    Read(Box<PyProject>),
    /// There is nothing at that name.
    Absent,
    /// There is a manifest and SURE did not get a value out of it.
    Unread(UnreadReason),
}

impl ManifestState {
    /// The manifest, if it was read.
    #[must_use]
    pub fn project(&self) -> Option<&PyProject> {
        match self {
            Self::Read(project) => Some(project),
            Self::Absent | Self::Unread(_) => None,
        }
    }

    /// Whether anything at all was at that name.
    #[must_use]
    pub fn is_absent(&self) -> bool {
        matches!(self, Self::Absent)
    }
}

/// One declared console command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryPoint {
    /// The command's name, **verbatim** — the word a person types.
    pub name: String,
    /// What it points at, **verbatim**: `"pkg.cli:main"`.
    ///
    /// Never resolved. SURE has imported nothing and does not know whether that
    /// module exists.
    pub target: String,
    /// Which table declared it.
    pub kind: EntryPointKind,
}

/// Which of a manifest's tables declared an entry point.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum EntryPointKind {
    /// `[project.scripts]` — a command-line program.
    Console,
    /// `[project.gui-scripts]` — a program with a window.
    Gui,
    /// `[tool.poetry.scripts]` — Poetry's own spelling, which does not
    /// distinguish the two.
    PoetryScript,
}

impl EntryPointKind {
    /// The stable wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Console => "console",
            Self::Gui => "gui",
            Self::PoetryScript => "poetry_script",
        }
    }

    /// The sentence a person reads.
    #[must_use]
    pub const fn plain_description(self) -> &'static str {
        match self {
            Self::Console => "a command this project installs",
            Self::Gui => "a program with a window that this project installs",
            Self::PoetryScript => "a command this project installs, declared for Poetry",
        }
    }
}

/// A version constraint the project declared for its interpreter.
///
/// **Verbatim, and never interpreted.** `">=3.9,<4"` is a specifier set that
/// some resolver evaluates against a list of available interpreters; SURE has
/// run no resolver and has not looked for an interpreter, so it records the text
/// and says nothing about what satisfies it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionClaim {
    /// The text, exactly as written.
    pub text: String,
    /// Where it was declared.
    pub source: Source,
}

/// What the project says about the interpreter it wants.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PythonVersion {
    /// `[project].requires-python`, verbatim.
    pub requires_python: Option<VersionClaim>,
    /// `.python-version`, verbatim — usually one line, sometimes a constraint.
    pub version_file: Option<VersionClaim>,
    /// Poetry's `[tool.poetry.dependencies].python`, verbatim.
    ///
    /// Its own field rather than a [`Dependency`], because that is what it is:
    /// the interpreter constraint, which happens to live in a dependency table.
    pub poetry_python: Option<VersionClaim>,
    /// The `Programming Language :: Python ::` classifiers, **verbatim**.
    ///
    /// A classifier is a claim about what the project is tested against, and it
    /// is the project's claim. SURE reports it as one and does not read a
    /// version out of it.
    pub classifiers: Vec<String>,
}

impl PythonVersion {
    /// Every claim the project made, in a fixed order.
    pub fn claims(&self) -> impl Iterator<Item = &VersionClaim> {
        [
            self.requires_python.as_ref(),
            self.version_file.as_ref(),
            self.poetry_python.as_ref(),
        ]
        .into_iter()
        .flatten()
    }

    /// Whether anything at all said what interpreter this project wants.
    #[must_use]
    pub fn is_declared(&self) -> bool {
        self.claims().next().is_some() || !self.classifiers.is_empty()
    }
}

/// A `pyproject.toml`, read.
///
/// Every field is what the file said. Nothing here has been checked against the
/// filesystem, resolved, or run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PyProject {
    /// `[project].name`, or Poetry's.
    pub name: Option<String>,
    /// `[project].version`, verbatim, or Poetry's.
    pub version: Option<String>,
    /// `[project].requires-python`.
    pub requires_python: Option<VersionClaim>,
    /// Poetry's `[tool.poetry.dependencies].python`, verbatim.
    ///
    /// Its own field rather than a [`Dependency`], because that is what it is:
    /// the interpreter constraint, which happens to live in a dependency table.
    /// Kept apart from [`Self::requires_python`] because those are two different
    /// keys that can both be present, and merging them would be SURE deciding
    /// which one the project meant.
    pub poetry_python: Option<VersionClaim>,
    /// `[build-system].build-backend`, verbatim.
    pub build_backend: Option<String>,
    /// `[build-system].requires`, verbatim.
    pub build_requires: Vec<String>,
    /// Which `[tool.*]` tables are present, by [`Installer`].
    pub tool_tables: Vec<Installer>,
    /// The `[tool.*]` tables that name a tool SURE checks, sorted.
    ///
    /// Names from [`TOOL_SECTIONS`]; the table's contents are not read.
    pub tool_sections: Vec<String>,
    /// Every dependency, sorted by name then kind then group.
    pub dependencies: Vec<Dependency>,
    /// Names whose declared value was not something SURE can read as a
    /// requirement.
    ///
    /// Poetry allows `foo = { version = "^1", extras = ["x"] }`. A project can
    /// write that, SURE will not guess at what it means, and the name is
    /// recorded rather than dropped — a dependency that is there and unreadable
    /// is not a dependency that is not there.
    pub dependencies_not_text: Vec<String>,
    /// The entry points the manifest declares, sorted.
    pub entry_points: Vec<EntryPoint>,
    /// The `Programming Language :: Python ::` classifiers, verbatim.
    pub classifiers: Vec<String>,
}

impl PyProject {
    /// Read a `pyproject.toml` out of parsed JSON.
    ///
    /// # Errors
    ///
    /// [`UnreadReason::WrongShape`] when the document is not a table. TOML's
    /// top level is always a table, so reaching this needs a document that is
    /// valid TOML and not a manifest — which cannot happen through the
    /// converter, and is refused rather than assumed away because the accessors
    /// below would otherwise read a project with no dependencies out of it.
    pub fn from_json(value: &serde_json::Value) -> Result<Self, UnreadReason> {
        let Some(root) = value.as_object() else {
            return Err(UnreadReason::WrongShape {
                found: json_shape(value),
            });
        };

        let project = table(root.get("project"));
        let poetry = table(root.get("tool").and_then(|tool| tool.get("poetry")));

        // --- dependencies -----------------------------------------------------
        let mut dependencies = Vec::new();
        let mut dependencies_not_text = Vec::new();

        // PEP 621: `dependencies` is an array of PEP 508 strings.
        collect_requirement_strings(
            project.and_then(|project| project.get("dependencies")),
            DependencyKind::Runtime,
            None,
            &mut dependencies,
            &mut dependencies_not_text,
        );
        collect_requirement_table(
            project
                .and_then(|project| project.get("optional-dependencies"))
                .and_then(serde_json::Value::as_object),
            DependencyKind::Optional,
            &mut dependencies,
            &mut dependencies_not_text,
        );
        // Poetry's, whose `python` key is the interpreter and not a dependency.
        let poetry_python = poetry
            .and_then(|poetry| poetry.get("dependencies"))
            .and_then(serde_json::Value::as_object)
            .and_then(|declared| {
                let claim = declared.get("python").and_then(version_claim_value);
                let mut rest = declared.clone();
                rest.remove("python");
                collect_dependency_object(
                    &rest,
                    DependencyKind::Runtime,
                    None,
                    &mut dependencies,
                    &mut dependencies_not_text,
                );
                claim
            });
        // Poetry's legacy dev table, which is `name = "range"` — a dependency
        // object, **not** a table of arrays. Reading it with
        // `collect_requirement_table` would take every entry for a shape SURE
        // does not know and record each name as unreadable, which is wrong
        // twice: the dependency would be missing and a false "could not read
        // this" would be beside it.
        if let Some(dev) = poetry
            .and_then(|poetry| poetry.get("dev-dependencies"))
            .and_then(serde_json::Value::as_object)
        {
            collect_dependency_object(
                dev,
                DependencyKind::Development,
                None,
                &mut dependencies,
                &mut dependencies_not_text,
            );
        }
        // Poetry groups: `[tool.poetry.group.<name>.dependencies]`.
        if let Some(groups) = poetry
            .and_then(|poetry| poetry.get("group"))
            .and_then(serde_json::Value::as_object)
        {
            for (group, body) in groups {
                collect_dependency_object(
                    body.get("dependencies")
                        .and_then(serde_json::Value::as_object)
                        .unwrap_or(&serde_json::Map::new()),
                    DependencyKind::Development,
                    Some(group.clone()),
                    &mut dependencies,
                    &mut dependencies_not_text,
                );
            }
        }
        // pipenv's, whose whole manifest is these two tables. `Pipfile` is the
        // one other manifest Python has, it is TOML, and the questions asked of
        // it are the same ones — which is why it is read into this type rather
        // than into a second type carrying the same fields under other names.
        //
        // Read whenever the two tables are present rather than only when the
        // file is called `Pipfile`, because no other manifest format puts
        // `[packages]` at its top level: `uv`, `poetry` and `pdm` put theirs
        // under `[tool.*]`, and PEP 621 puts its under `[project]`.
        for (key, kind) in [
            ("packages", DependencyKind::Runtime),
            ("dev-packages", DependencyKind::Development),
        ] {
            if let Some(declared) = root.get(key).and_then(serde_json::Value::as_object) {
                collect_dependency_object(
                    declared,
                    kind,
                    None,
                    &mut dependencies,
                    &mut dependencies_not_text,
                );
            }
        }

        // PEP 735: `[dependency-groups]`, an array of strings per group.
        if let Some(groups) = root
            .get("dependency-groups")
            .and_then(serde_json::Value::as_object)
        {
            for (group, entries) in groups {
                collect_requirement_strings(
                    Some(entries),
                    DependencyKind::Development,
                    Some(group.clone()),
                    &mut dependencies,
                    &mut dependencies_not_text,
                );
            }
        }
        dependencies.sort_by(|a, b| {
            a.name
                .cmp(&b.name)
                .then(a.kind.cmp(&b.kind))
                .then(a.group.cmp(&b.group))
        });
        dependencies_not_text.sort();
        dependencies_not_text.dedup();

        // --- entry points -----------------------------------------------------
        let mut entry_points = Vec::new();
        for (key, kind) in [
            ("scripts", EntryPointKind::Console),
            ("gui-scripts", EntryPointKind::Gui),
        ] {
            collect_entry_points(
                project.and_then(|project| project.get(key)),
                kind,
                &mut entry_points,
            );
        }
        collect_entry_points(
            poetry.and_then(|poetry| poetry.get("scripts")),
            EntryPointKind::PoetryScript,
            &mut entry_points,
        );
        entry_points.sort_by(|a, b| a.name.cmp(&b.name).then(a.kind.cmp(&b.kind)));

        // --- the build system --------------------------------------------------
        let build_system = table(root.get("build-system"));
        let mut build_requires = Vec::new();
        if let Some(entries) = build_system
            .and_then(|system| system.get("requires"))
            .and_then(serde_json::Value::as_array)
        {
            for entry in entries {
                if let Some(text) = entry.as_str() {
                    build_requires.push(text.to_owned());
                }
            }
        }
        let build_backend = build_system
            .and_then(|system| system.get("build-backend"))
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned);

        // --- which tool tables are present ------------------------------------
        let mut tool_tables = Vec::new();
        if let Some(tool) = root.get("tool").and_then(serde_json::Value::as_object) {
            for &installer in Installer::ALL {
                if let Some(name) = installer.tool_table()
                    && tool.contains_key(name)
                {
                    tool_tables.push(installer);
                }
            }
        }
        tool_tables.sort_unstable();

        // --- which tool sections are present ----------------------------------
        let mut tool_sections = Vec::new();
        if let Some(tool) = root.get("tool").and_then(serde_json::Value::as_object) {
            for &(section, _, _) in TOOL_SECTIONS {
                if tool.get(section).is_some_and(serde_json::Value::is_object) {
                    tool_sections.push(section.to_owned());
                }
            }
        }
        tool_sections.sort();

        Ok(Self {
            name: text(project.and_then(|project| project.get("name")))
                .or_else(|| text(poetry.and_then(|poetry| poetry.get("name")))),
            version: text(project.and_then(|project| project.get("version")))
                .or_else(|| text(poetry.and_then(|poetry| poetry.get("version")))),
            requires_python: project
                .and_then(|project| project.get("requires-python"))
                .and_then(version_claim_value)
                .map(|text| VersionClaim {
                    text,
                    source: Source::new(MANIFEST, "declares the interpreters it supports"),
                }),
            poetry_python: poetry_python.map(|text| VersionClaim {
                text,
                source: Source::new(MANIFEST, "declares the interpreter it is built for"),
            }),
            build_backend,
            build_requires,
            tool_tables,
            tool_sections,
            dependencies,
            dependencies_not_text,
            entry_points,
            classifiers: classifiers(project),
        })
    }
}

/// A sub-table of a JSON object, if it is one.
fn table(value: Option<&serde_json::Value>) -> Option<&serde_json::Map<String, serde_json::Value>> {
    value.and_then(serde_json::Value::as_object)
}

/// A string field, or `None` if it is absent or not a string.
fn text(value: Option<&serde_json::Value>) -> Option<String> {
    value.and_then(serde_json::Value::as_str).map(str::to_owned)
}

/// A version claim whose value is a string.
fn version_claim_value(value: &serde_json::Value) -> Option<String> {
    value.as_str().map(str::to_owned)
}

/// The `Programming Language :: Python ::` classifiers, verbatim.
fn classifiers(project: Option<&serde_json::Map<String, serde_json::Value>>) -> Vec<String> {
    let mut found = Vec::new();
    if let Some(entries) = project
        .and_then(|project| project.get("classifiers"))
        .and_then(serde_json::Value::as_array)
    {
        for entry in entries {
            if let Some(text) = entry.as_str()
                && text.starts_with("Programming Language :: Python")
            {
                found.push(text.to_owned());
            }
        }
    }
    found
}

/// Collect an array of PEP 508 requirement strings.
fn collect_requirement_strings(
    value: Option<&serde_json::Value>,
    kind: DependencyKind,
    group: Option<String>,
    dependencies: &mut Vec<Dependency>,
    not_text: &mut Vec<String>,
) {
    let Some(entries) = value.and_then(serde_json::Value::as_array) else {
        return;
    };
    for entry in entries {
        match entry.as_str() {
            Some(line) => {
                if let Some(name) = requirement_name(line) {
                    dependencies.push(Dependency {
                        name,
                        requirement: line.to_owned(),
                        kind,
                        group: group.clone(),
                    });
                } else {
                    // A line in a dependency list that names no distribution:
                    // recorded as an entry SURE could not read rather than
                    // dropped, so the count of dependencies is not quietly
                    // short.
                    not_text.push(line.to_owned());
                }
            }
            None => not_text.push(json_shape(entry).to_owned()),
        }
    }
}

/// Collect a table of `name = ...` declarations, one table per group.
fn collect_requirement_table(
    declared: Option<&serde_json::Map<String, serde_json::Value>>,
    kind: DependencyKind,
    dependencies: &mut Vec<Dependency>,
    not_text: &mut Vec<String>,
) {
    let Some(declared) = declared else {
        return;
    };
    for (group, entries) in declared {
        match entries {
            serde_json::Value::Array(_) => collect_requirement_strings(
                Some(entries),
                kind,
                Some(group.clone()),
                dependencies,
                not_text,
            ),
            // `[tool.poetry.dev-dependencies]` is one table with no group names
            // in it, and `optional-dependencies` is always a table of arrays.
            // Anything else here is a shape SURE does not know.
            _ => not_text.push(group.clone()),
        }
    }
}

/// Collect a `name = requirement` object.
fn collect_dependency_object(
    declared: &serde_json::Map<String, serde_json::Value>,
    kind: DependencyKind,
    group: Option<String>,
    dependencies: &mut Vec<Dependency>,
    not_text: &mut Vec<String>,
) {
    for (name, requirement) in declared {
        match requirement {
            serde_json::Value::String(requirement) => dependencies.push(Dependency {
                name: name.clone(),
                requirement: requirement.clone(),
                kind,
                group: group.clone(),
            }),
            // Poetry's table form, and anything else that is not a requirement
            // string. The name is kept, because a dependency that is there and
            // unreadable is not a dependency that is not there.
            _ => not_text.push(name.clone()),
        }
    }
}

/// Collect entry points from a `name = target` table.
fn collect_entry_points(
    value: Option<&serde_json::Value>,
    kind: EntryPointKind,
    into: &mut Vec<EntryPoint>,
) {
    let Some(entries) = value.and_then(serde_json::Value::as_object) else {
        return;
    };
    for (name, target) in entries {
        if let Some(target) = target.as_str() {
            into.push(EntryPoint {
                name: name.clone(),
                target: target.to_owned(),
                kind,
            });
        }
    }
}

/// What shape a JSON value has, as one of this module's own phrases.
fn json_shape(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::Null => "nothing",
        serde_json::Value::Bool(_) => "a boolean",
        serde_json::Value::Number(_) => "a number",
        serde_json::Value::String(_) => "a string",
        serde_json::Value::Array(_) => "an array",
        serde_json::Value::Object(_) => "an object",
    }
}

/// One command SURE would run for a conventional role.
///
/// **The command is SURE's construction, not the project's text.** That is the
/// difference between this and [`super::node::ConventionalScript`], and it is
/// the reason for a separate type rather than a shared one: Node's scripts are
/// lines the project wrote and SURE repeats, and these are plans SURE builds out
/// of the installer and the tools the project declared. The two must not be
/// rendered by one code path that treats them as the same kind of claim.
///
/// `command` is `None` when the project declared nothing to run for that role,
/// which is a finding rather than an omission — see [`conventional_commands`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConventionalCommand {
    /// The role.
    pub role: CommandRole,
    /// The command SURE would run, or `None` when the project declared nothing
    /// for this role.
    pub command: Option<String>,
    /// The tools the plan rests on, from [`TOOLS`].
    ///
    /// Empty when there is no command. A caller that shows the command without
    /// this is showing a plan with its reasons removed.
    pub because: Vec<&'static str>,
}

/// The work a Python project is conventionally expected to be able to do.
///
/// SURE's list, not the project's, for the reason [`super::node::ScriptRole`]
/// gives: a project with no way to run its tests is a finding, and it can only
/// be reported by looking for a tool the project did not declare.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CommandRole {
    /// Get the dependencies into place.
    Install,
    /// Run the tests.
    Test,
    /// Report style and probable mistakes.
    Lint,
    /// Check types without running the code.
    TypeCheck,
    /// Rewrite files to a style.
    Format,
    /// Produce a distribution.
    Build,
}

impl CommandRole {
    /// Every role, in a fixed order.
    pub const ALL: &'static [Self] = &[
        Self::Install,
        Self::Test,
        Self::Lint,
        Self::TypeCheck,
        Self::Format,
        Self::Build,
    ];

    /// The stable wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Install => "install",
            Self::Test => "test",
            Self::Lint => "lint",
            Self::TypeCheck => "typecheck",
            Self::Format => "format",
            Self::Build => "build",
        }
    }

    /// The sentence a person reads.
    #[must_use]
    pub const fn plain_description(self) -> &'static str {
        match self {
            Self::Install => "put the dependencies in place",
            Self::Test => "run the tests",
            Self::Lint => "check the code for style and likely mistakes",
            Self::TypeCheck => "check the types without running the code",
            Self::Format => "rewrite the files to a style",
            Self::Build => "build the distribution",
        }
    }

    /// The tool roles that answer this one.
    ///
    /// **A list per role, checked in order, and the first tool the project
    /// declared wins.** The order is SURE's preference among tools that do the
    /// same job — `ruff` before `flake8`, `uv` before `pip` — and it is written
    /// here rather than derived so that it is one list a reader can disagree
    /// with.
    #[must_use]
    pub const fn tool_roles(self) -> &'static [ToolRole] {
        match self {
            // `Install` is answered by the installer rather than by a tool.
            Self::Install => &[],
            Self::Test => &[ToolRole::TestRunner],
            Self::Lint => &[ToolRole::Linter],
            Self::TypeCheck => &[ToolRole::TypeChecker],
            Self::Format => &[ToolRole::Formatter],
            Self::Build => &[ToolRole::BuildBackend],
        }
    }
}

/// The command a person would run for one role, and what it rests on.
///
/// `manager` is the installer [`Managers::agreed`] named, if it named one.
///
/// **Returned and never executed.** Choosing a command is a plan, and running it
/// is a later step with its own authorisation — the same rule
/// [`super::node::Package::command_for`] holds to.
///
/// **The plan behind the line is [`invocation_for`]**, which since `P18-T003` is
/// also what a caller that means to start something asks for: this function is
/// that plan rendered, plus the tools it rests on. See [`Invocation`].
///
/// The plan differs by role in where it comes from, and the difference is worth
/// stating: `Test`, `Lint`, `TypeCheck`, `Format` and `Build` are only offered
/// when the project declared a tool for the job, and `Install` is offered when
/// there is an installer at all. Neither is offered on a guess.
#[must_use]
pub fn command_for(
    manager: Option<Installer>,
    role: CommandRole,
    tools: &[Tooling],
) -> ConventionalCommand {
    let because: Vec<&'static str> = role
        .tool_roles()
        .iter()
        .flat_map(|&wanted| {
            tools
                .iter()
                .filter(move |tool| tool.role == wanted)
                .map(|tool| tool.package)
        })
        .collect();

    // **The line is a rendering of [`invocation_for`], and this is the only way
    // it is produced.** Since `P18-T003` the same plan also has to reach a
    // runner as a program and an argument vector, and two spellings of one plan
    // would be two things free to disagree — a report showing a person
    // `uv run pytest` while a check ran something else is exactly the failure
    // the pairing with a typed operation exists to end.
    let command = invocation_for(manager, role, tools).map(|invocation| invocation.rendered());

    // Computed before the literal, because a row with no command has no reasons
    // either: naming the tools a plan rests on when there is no plan would be a
    // reader's evidence for a command that does not exist.
    let because = if command.is_some() {
        because
    } else {
        Vec::new()
    };

    ConventionalCommand {
        role,
        command,
        because,
    }
}

/// The program and its argument vector for one role, and the plan
/// [`command_for`] prints.
///
/// **The plan itself, where [`command_for`] is one way of showing it.** See
/// [`Invocation`] for what the value is and why the program is a name.
///
/// `None` means the project declared nothing for this role, which is the finding
/// [`conventional_commands`] exists to report, and it is the same condition as
/// `command_for` returning `None` — including for
/// [`Install`](CommandRole::Install), which is answered by the installer rather
/// than by a tool.
#[must_use]
pub fn invocation_for(
    manager: Option<Installer>,
    role: CommandRole,
    tools: &[Tooling],
) -> Option<Invocation> {
    match role {
        // The installer answers this one, and there is nothing in `TOOLS` to
        // look for: a project that named no installer has no install plan.
        CommandRole::Install => manager.map(install_invocation),
        // A build backend is not a command: `setuptools` and `poetry-core` are
        // libraries a frontend calls, so the command is the *frontend's* —
        // `python -m build`, or the installer's own `build` subcommand. Naming
        // the backend as if it were the command would be a plan that does not
        // run. Offered only when the project declared a backend, because a
        // project that declared nothing that builds it has no build plan.
        CommandRole::Build => {
            declared_tool(role, tools)?;
            Some(match manager {
                Some(Installer::Uv) => Invocation::of("uv", &["build"]),
                Some(Installer::Poetry) => Invocation::of("poetry", &["build"]),
                Some(Installer::Pdm) => Invocation::of("pdm", &["build"]),
                // `python -m build` is the frontend the packaging specification
                // defines, and it is what is left for pip and Pipenv: neither
                // has a `build` subcommand of its own. Naming `<manager> build`
                // for them would be a plan that does not run.
                _ => Invocation::of("python", &["-m", "build"]),
            })
        }
        // Everything else is the tool's own command, run through the installer,
        // and only for a tool the project declared. Every one of these is built
        // from a constant and a name from [`TOOLS`], so no project text reaches
        // a command.
        _ => {
            let tool = declared_tool(role, tools)?;
            let (module, arguments) = plan_for(role, tool)?;
            Some(run_invocation(manager, module, arguments))
        }
    }
}

/// The tool the project declared for this role, if it declared one.
///
/// **The first in the discovery's order**, which is what [`command_for`] has
/// always used: a tool list is sorted as the manifests were read, so the first
/// match is the stable and reproposable choice, and picking any other would make
/// the plan depend on nothing.
///
/// The one deliberate exception is `Test`: a runner named by a dedicated config
/// file (`tox.ini`, `noxfile.py`, `pytest.ini`, a `[tool.tox]`/`[tool.pytest]`
/// table, or a `setup.cfg` section) wins over a package that merely appears in
/// a dependency list. A project with a `tox.ini` runs its tests through tox;
/// running a bare `pytest` would bypass the environments tox defines. MiQi's
/// project-test detector follows the same rule.
fn declared_tool(role: CommandRole, tools: &[Tooling]) -> Option<&str> {
    let matching = || {
        role.tool_roles()
            .iter()
            .flat_map(|&wanted| tools.iter().filter(move |tool| tool.role == wanted))
    };
    if role == CommandRole::Test
        && let Some(tool) = matching().min_by_key(|tool| tool.evidence)
    {
        return Some(tool.package);
    }
    matching().next().map(|tool| tool.package)
}

/// A tool SURE knows how to run for one role.
///
/// **The counterpart to [`TOOLS`], and the reason the two are separate.** `TOOLS`
/// says which package fills a role; this says how that package is started. A
/// package can be the first and not the second, and when it is not, SURE must
/// say so rather than invent a command line — otherwise the plan carries a
/// check that could never pass, and the re-check reports a failure that is
/// SURE's rather than the project's.
///
/// [`TOOLS`]: static@TOOLS
struct ToolPlan {
    /// The package name, from [`TOOLS`].
    package: &'static str,
    /// The role this invocation is for. A package can fill one and not
    /// another: `ruff` is a linter here, never a test runner.
    role: CommandRole,
    /// The name `python -m` receives, or the program `<manager> run` starts.
    /// The same as `package` unless the distribution and the importable module
    /// differ (`robotframework` ships `robot`).
    module: &'static str,
    /// The arguments appended after the module name. Empty when the tool's bare
    /// form is the check.
    arguments: &'static [&'static str],
}

/// How SURE runs each Python tool it plans a check for.
///
/// **A test runner defaults to the project; a linter and a type checker do
/// not.** Bare `pytest` collects the project, which is why its arguments are
/// empty. Bare `ruff` prints its help screen and exits 2, and bare `mypy`
/// refuses with "Missing target module" — measured on a real project on
/// 2026-10-29, where SURE planned `python -m ruff` and `python -m mypy` and
/// could never have passed either. So the linters and type checkers name the
/// project root, `.`, and `ruff` additionally names its `check` subcommand.
///
/// **The table is deliberately shorter than [`TOOLS`].** A linter whose CLI
/// takes files rather than a directory (`pyflakes`, `mccabe`) and a type
/// checker that is a library rather than a command (`typeguard`, `beartype`)
/// are not listed. A project that declares one of those gets a
/// [`MissingKind::NotRunnable`](crate::checks::MissingKind::NotRunnable)
/// instead of a command that could only fail — the difference between a check
/// SURE could not run and one that fails for a reason that is not the project's.
///
/// [`TOOLS`]: static@TOOLS
const PYTHON_TOOL_PLANS: &[ToolPlan] = &[
    // Test runners.
    ToolPlan {
        package: "pytest",
        role: CommandRole::Test,
        module: "pytest",
        arguments: &[],
    },
    ToolPlan {
        package: "nose2",
        role: CommandRole::Test,
        module: "nose2",
        arguments: &[],
    },
    ToolPlan {
        package: "nose",
        role: CommandRole::Test,
        module: "nose",
        arguments: &[],
    },
    ToolPlan {
        package: "tox",
        role: CommandRole::Test,
        module: "tox",
        arguments: &[],
    },
    ToolPlan {
        package: "nox",
        role: CommandRole::Test,
        module: "nox",
        arguments: &[],
    },
    ToolPlan {
        package: "green",
        role: CommandRole::Test,
        module: "green",
        arguments: &[],
    },
    ToolPlan {
        package: "robotframework",
        role: CommandRole::Test,
        module: "robot",
        arguments: &["."],
    },
    // Linters.
    ToolPlan {
        package: "ruff",
        role: CommandRole::Lint,
        module: "ruff",
        arguments: &["check", "."],
    },
    ToolPlan {
        package: "flake8",
        role: CommandRole::Lint,
        module: "flake8",
        arguments: &["."],
    },
    ToolPlan {
        package: "pylint",
        role: CommandRole::Lint,
        module: "pylint",
        arguments: &["."],
    },
    ToolPlan {
        package: "pycodestyle",
        role: CommandRole::Lint,
        module: "pycodestyle",
        arguments: &["."],
    },
    ToolPlan {
        package: "pydocstyle",
        role: CommandRole::Lint,
        module: "pydocstyle",
        arguments: &["."],
    },
    ToolPlan {
        package: "vulture",
        role: CommandRole::Lint,
        module: "vulture",
        arguments: &["."],
    },
    // Type checkers.
    ToolPlan {
        package: "mypy",
        role: CommandRole::TypeCheck,
        module: "mypy",
        arguments: &["."],
    },
    ToolPlan {
        package: "pyright",
        role: CommandRole::TypeCheck,
        module: "pyright",
        arguments: &["."],
    },
];

/// The module and arguments for one tool in one role, if SURE knows them.
fn plan_for(role: CommandRole, tool: &str) -> Option<(&'static str, &'static [&'static str])> {
    PYTHON_TOOL_PLANS
        .iter()
        .find(|plan| plan.package == tool && plan.role == role)
        .map(|plan| (plan.module, plan.arguments))
}

/// A tool a project runs, through the installer if there is one.
fn run_invocation(manager: Option<Installer>, module: &str, arguments: &[&str]) -> Invocation {
    let mut invocation = match manager {
        // `uv run`, `poetry run` and `pdm run` all execute a command inside the
        // project's environment. `pipenv run` does the same for pipenv.
        Some(manager) if manager != Installer::Pip => {
            Invocation::of(manager.as_str(), &["run", module])
        }
        // pip has no `run`: it installs, and `python -m` is how the standard
        // library names a module. `pytest` alone would be a command that
        // depends on which interpreter is first on the path.
        _ => Invocation::of("python", &["-m", module]),
    };
    for argument in arguments {
        invocation = invocation.with_argument(argument);
    }
    invocation
}

/// The plan that installs a project's dependencies.
///
/// One arm per installer, and they are **not all the same verb**: uv's is
/// `uv sync`, and poetry's and pdm's are `install`. Composing one of them from
/// `as_str()` and a shared `" sync"` would produce `poetry sync`, which is not
/// the command that installs a project's dependencies. Writing all five out is
/// the only form in which a reader can check them, and the tests hold each one.
fn install_invocation(manager: Installer) -> Invocation {
    match manager {
        // Not `pip install .`: a project with a `requirements.txt` has not
        // necessarily made itself installable, and the requirements file is what
        // the weakest piece of evidence in this module is about.
        Installer::Pip => Invocation::of(
            "python",
            &["-m", "pip", "install", "-r", "requirements.txt"],
        ),
        Installer::Uv => Invocation::of("uv", &["sync"]),
        Installer::Poetry => Invocation::of("poetry", &["install"]),
        Installer::Pipenv => Invocation::of("pipenv", &["install"]),
        Installer::Pdm => Invocation::of("pdm", &["install"]),
    }
}

/// A row for every conventional role, **whether or not the project supports it**.
///
/// The rows with no command are the point, for the reason
/// [`super::node::Package::conventional_scripts`] gives: a report built from
/// this says "there is no way to run this project's tests" out loud, instead of
/// leaving a reader to notice that a line is missing from a list whose length
/// they cannot see.
#[must_use]
pub fn conventional_commands(project: &PythonProject) -> Vec<ConventionalCommand> {
    let manager = project.managers.agreed();
    CommandRole::ALL
        .iter()
        .map(|&role| command_for(manager, role, &project.tooling))
        .collect()
}

/// Everything SURE found out about a Python project.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PythonProject {
    /// What is at the project root's `pyproject.toml`.
    pub manifest: ManifestState,
    /// What is at the project root's `Pipfile`, read by the same accessors.
    ///
    /// A separate field rather than folded into [`Self::manifest`], because the
    /// two are two files: a project can have both, they can disagree, and a
    /// reader told "the manifest says X" has to be able to see which one said
    /// it. [`Self::dependencies`] is where the two are brought together, and
    /// that is the only place they are.
    pub pipfile: ManifestState,
    /// The installers SURE found evidence for.
    pub managers: Managers,
    /// The requirements files at the project root, sorted by path.
    pub requirements: Vec<RequirementsFile>,
    /// Recognised packages.
    pub tooling: Vec<Tooling>,
    /// What the project says about the interpreter it wants.
    pub python: PythonVersion,
    /// The legacy files that are there, whose packaging metadata SURE does not
    /// read.
    ///
    /// Names from [`LEGACY_FILES`], so this is a fixed vocabulary and not
    /// project text. `setup.py` is a program and is not read at all;
    /// `setup.cfg` contributes its tool sections to [`Self::tooling`] while its
    /// packaging metadata remains outside what SURE reads.
    pub unread_legacy: Vec<&'static str>,
}

impl PythonProject {
    /// Every recognised package with one role.
    pub fn tooling_of_role(&self, role: ToolRole) -> impl Iterator<Item = &Tooling> {
        self.tooling.iter().filter(move |tool| tool.role == role)
    }

    /// Whether the project declared this package anywhere.
    ///
    /// `package` is matched against the table's own names, so a caller asks
    /// about a package SURE knows rather than about one a project wrote.
    #[must_use]
    pub fn declares(&self, package: &str) -> bool {
        self.tooling.iter().any(|tool| tool.package == package)
    }

    /// Every dependency name the project declared in a shape SURE could not read.
    ///
    /// Project text, carried as data for the reason
    /// [`PyProject::dependencies_not_text`] gives: a dependency that is there and
    /// unreadable is not a dependency that is not there, and a report that
    /// dropped the name would leave a person with nothing to go and look at.
    #[must_use]
    pub fn unreadable_dependencies(&self) -> Vec<&str> {
        self.project()
            .into_iter()
            .chain(self.pipfile.project())
            .flat_map(|manifest| manifest.dependencies_not_text.iter().map(String::as_str))
            .collect()
    }

    /// Whether a declaration SURE could not read names a tool for this role.
    ///
    /// **The question a caller cannot answer for itself.** [`TOOLS`] is matched
    /// through the packaging metadata's normalisation — `Scikit_Learn` and
    /// `scikit-learn` are one row — and that rule is this module's, so a caller
    /// holding a raw project spelling would have to rewrite it and would get a
    /// different answer for every project that spelled a name with an
    /// underscore.
    ///
    /// Poetry's table form is the case this is for:
    /// `mypy = { version = "^1.8", extras = ["types-requests"] }` is a real and
    /// ordinary declaration, it lands in [`PyProject::dependencies_not_text`]
    /// rather than in [`PyProject::dependencies`], and so it never reaches
    /// [`TOOLS`]. [`Self::tooling_of_role`] then answers that the project
    /// declares no type checker, which is false — and this is the other half of
    /// the question, asked separately so that "declares none" and "declared one
    /// SURE could not read" cannot be confused.
    #[must_use]
    pub fn declares_unreadable(&self, role: ToolRole) -> bool {
        self.unreadable_dependencies()
            .into_iter()
            .any(|name| tool_roles_of(name).any(|(_, found)| found == role))
    }

    /// The root manifest, if there is a readable one.
    #[must_use]
    pub fn project(&self) -> Option<&PyProject> {
        self.manifest.project()
    }

    /// Every dependency declared in the manifest or in a requirements file.
    ///
    /// Requirements-file entries carry their whole line as the requirement, so
    /// the two sources answer the same question in the same shape.
    #[must_use]
    pub fn dependencies(&self) -> Vec<Dependency> {
        let mut found = self
            .project()
            .map(|project| project.dependencies.clone())
            .unwrap_or_default();
        if let Some(pipfile) = self.pipfile.project() {
            found.extend(pipfile.dependencies.iter().cloned());
        }
        for file in &self.requirements {
            found.extend(file.requirements.iter().map(|requirement| Dependency {
                name: requirement.name.clone(),
                requirement: requirement.line.clone(),
                kind: DependencyKind::Runtime,
                group: None,
            }));
        }
        found.sort_by(|a, b| {
            a.name
                .cmp(&b.name)
                .then(a.kind.cmp(&b.kind))
                .then(a.group.cmp(&b.group))
        });
        found
    }

    /// The commands SURE would run for the conventional roles.
    #[must_use]
    pub fn conventional_commands(&self) -> Vec<ConventionalCommand> {
        conventional_commands(self)
    }
}

/// What a Python project's support level is, and the sentence that says why.
///
/// Returned together, and as a constant, so that a level and its reason cannot
/// be assigned in two places and disagree.
fn grade(
    manifest: &ManifestState,
    found_requirements: bool,
    found_legacy: bool,
    found_config: bool,
    pipfile_read: bool,
) -> (SupportLevel, &'static str) {
    match manifest {
        ManifestState::Read(_) => (
            SupportLevel::Generic,
            "SURE read this project's pyproject.toml, so it can find how the project is \
             built and run.",
        ),
        ManifestState::Unread(_) => (
            SupportLevel::InspectOnly,
            "There is a pyproject.toml here and SURE could not read it, so it can only \
             look at the project's files.",
        ),
        // A readable `Pipfile` is the same standing as a readable
        // `pyproject.toml`: it is a manifest SURE read, and what it declares is
        // what the project declares.
        ManifestState::Absent if pipfile_read => (
            SupportLevel::Generic,
            "SURE read this project's Pipfile, so it can find how the project is built \
             and run.",
        ),
        ManifestState::Absent if found_requirements => (
            SupportLevel::InspectOnly,
            "This project has a requirements file and no pyproject.toml, so SURE can see \
             what it installs and cannot read how it is built.",
        ),
        ManifestState::Absent if found_config => (
            SupportLevel::InspectOnly,
            "This project configures Python tools but has no pyproject.toml, so SURE can \
             run the configured checks and cannot read how the project is built.",
        ),
        ManifestState::Absent if found_legacy => (
            SupportLevel::InspectOnly,
            "This project declares itself in setup.py or setup.cfg; SURE cannot read their \
             packaging metadata, so it can only look at the project's files.",
        ),
        ManifestState::Absent => (
            SupportLevel::InspectOnly,
            "There is no pyproject.toml here, so SURE can see this project's files and \
             cannot read how it is built or run.",
        ),
    }
}

/// Find out what a Python project declares, if this is one.
///
/// Returns `None` when nothing says this is a Python project. See
/// [`looks_like_one`] for the complete list of what counts, which is short on
/// purpose.
pub(super) fn look(
    root: &Path,
    scan: &Scan,
    options: &DiscoverOptions,
    budget: &mut Budget,
    unread: &mut Vec<Unread>,
) -> Option<EcosystemReport> {
    let tree = read::Tree::of(scan, options.scan.case);
    let mut found_by = Vec::new();

    // --- presence, before anything is read ----------------------------------
    //
    // Six names, none of them opened, so that "is this a Python project at all?"
    // is decided before any file is read and before any of the manifest budget
    // is spent. Deciding afterwards would mean a directory that turned out not to
    // be a Python project had still spent SURE's budget and could still have put
    // a file into `unread` — a finding about a project SURE then says nothing
    // about, which is the one shape of result this module exists to avoid.
    let manifest_path = Path::new(MANIFEST);
    let pipfile_path = Path::new(PIPFILE);
    let version_path = Path::new(VERSION_FILE);
    let manifest_there = !matches!(tree.probe(manifest_path), Probe::Nothing);
    let pipfile_there = !matches!(tree.probe(pipfile_path), Probe::Nothing);
    let version_there = !matches!(tree.probe(version_path), Probe::Nothing);
    // `Probe::File` for the three below, and `Probe::Nothing` as the only
    // "nothing here" for the three above. The difference is deliberate: a *link*
    // named `uv.lock` is not a lockfile, because SURE does not read through links
    // and a lockfile's whole contribution is that the installer wrote it — but a
    // `pyproject.toml` SURE cannot open is a finding rather than a silence, so
    // anything at that name counts.
    let unread_legacy: Vec<&'static str> = LEGACY_FILES
        .iter()
        .copied()
        .filter(|name| matches!(tree.probe(Path::new(name)), Probe::File(_)))
        .collect();
    let lockfiles_present: Vec<(&'static str, Installer)> = LOCKFILES
        .iter()
        .copied()
        .filter(|(name, _)| matches!(tree.probe(Path::new(name)), Probe::File(_)))
        .collect();
    let requirement_paths = requirement_candidates(&tree);
    let config_tools: Vec<(&'static str, &'static str, ToolingEvidence)> = CONFIG_TOOLS
        .iter()
        .copied()
        .filter(|(name, _, _)| matches!(tree.probe(Path::new(*name)), Probe::File(_)))
        .collect();
    let setup_cfg_sections = read_setup_cfg_tool_sections(root, &tree, options, budget, unread);
    let found_tool_config = !config_tools.is_empty() || !setup_cfg_sections.is_empty();

    if !looks_like_one(
        manifest_there,
        pipfile_there,
        version_there,
        &unread_legacy,
        &lockfiles_present,
        &requirement_paths,
        found_tool_config,
    ) {
        return None;
    }

    // --- the manifest -------------------------------------------------------
    let manifest = read_manifest(root, manifest_path, &tree, options, budget, unread);
    if !manifest.is_absent() {
        found_by.push(manifest_path.to_path_buf());
    }

    // --- the legacy files, by existence and never by contents ---------------
    for &name in &unread_legacy {
        found_by.push(PathBuf::from(name));
    }

    // --- the tool configuration files, by existence -------------------------
    for &(name, _, _) in &config_tools {
        found_by.push(PathBuf::from(name));
    }

    // --- the lockfiles ------------------------------------------------------
    let mut configured = Vec::new();
    let mut locked = Vec::new();
    for &(name, installer) in &lockfiles_present {
        found_by.push(PathBuf::from(name));
        locked.push(InstallerFinding {
            installer,
            evidence: InstallerEvidence::Lockfile,
            source: Source::new(name, "is a lockfile for this installer"),
        });
    }

    // --- pipenv's manifest --------------------------------------------------
    //
    // Read by the same function as `pyproject.toml`, because it is the same
    // format and nearly the same questions. What differs is that a `Pipfile`
    // declares itself in `[packages]` and `[dev-packages]` rather than under
    // `[project]`, which [`PyProject::from_json`] reads as well.
    let pipfile = read_manifest(root, pipfile_path, &tree, options, budget, unread);
    if !pipfile.is_absent() {
        found_by.push(pipfile_path.to_path_buf());
    }

    // --- the requirements files --------------------------------------------
    let requirements = read_requirements(
        root,
        &requirement_paths,
        &tree,
        options,
        budget,
        unread,
        &mut found_by,
    );

    // --- what each manifest declares about its installer --------------------
    if pipfile.project().is_some() {
        configured.push(InstallerFinding {
            installer: Installer::Pipenv,
            evidence: InstallerEvidence::Declared,
            source: Source::new(PIPFILE, "is this installer's own manifest"),
        });
    }

    if let Some(project) = manifest.project() {
        for &installer in &project.tool_tables {
            configured.push(InstallerFinding {
                installer,
                evidence: InstallerEvidence::Declared,
                source: Source::new(
                    MANIFEST,
                    "has this installer's own table in its tool section",
                ),
            });
        }
        if let Some(backend) = project.build_backend.as_deref()
            && let Some(installer) = Installer::from_build_backend(backend)
            && !project.tool_tables.contains(&installer)
        {
            configured.push(InstallerFinding {
                installer,
                evidence: InstallerEvidence::Declared,
                source: Source::new(
                    MANIFEST,
                    "names this installer's build backend for the project",
                ),
            });
        }
    }
    configured.sort_by_key(|finding| finding.installer);

    // --- the requirements file as evidence, weakest of the three -----------
    let mut from_requirements = Vec::new();
    if !requirements.is_empty() {
        from_requirements.push(InstallerFinding {
            installer: Installer::Pip,
            evidence: InstallerEvidence::RequirementsFile,
            source: Source::new(
                requirements
                    .first()
                    .map(|file| file.path.clone())
                    .unwrap_or_else(|| PathBuf::from("requirements.txt")),
                "is a requirements file, which several installers read",
            ),
        });
    }

    let found_a_pipfile = !pipfile.is_absent();

    // --- the interpreter the project asks for -------------------------------
    let mut python = PythonVersion {
        version_file: read_version_file(root, &tree, options, budget, unread, &mut found_by),
        ..PythonVersion::default()
    };
    if let Some(project) = manifest.project() {
        python.requires_python.clone_from(&project.requires_python);
        python.poetry_python.clone_from(&project.poetry_python);
        python.classifiers.clone_from(&project.classifiers);
        python.classifiers.sort();
    }

    // --- the tools, from every list of dependencies ------------------------
    let mut tooling = Vec::new();
    if let Some(project) = manifest.project() {
        collect_tooling(
            &project.dependencies,
            Path::new(""),
            Some(Path::new(MANIFEST)),
            ToolingEvidence::Dependency,
            &mut tooling,
        );
        // A build backend is a tool the project declared even though it is not
        // in a dependency table, and `[tool.poetry]` names one by existing.
        for backend in project
            .build_requires
            .iter()
            .filter_map(|requirement| requirement_name(requirement))
        {
            collect_tooling_named(
                &backend,
                Path::new(""),
                Some(Path::new(MANIFEST)),
                ToolingEvidence::Dependency,
                &mut tooling,
            );
        }
    }
    if let Some(pipfile) = pipfile.project() {
        collect_tooling(
            &pipfile.dependencies,
            Path::new(""),
            Some(Path::new(PIPFILE)),
            ToolingEvidence::Dependency,
            &mut tooling,
        );
    }
    for file in &requirements {
        for requirement in &file.requirements {
            collect_tooling_named(
                &requirement.name,
                Path::new(""),
                Some(file.path.as_path()),
                ToolingEvidence::Dependency,
                &mut tooling,
            );
        }
    }
    // A `[tool.*]` table is a declaration the dependency tables do not carry:
    // a project can install ruff or pytest from CI and still configure it in
    // `pyproject.toml`. The table's existence names the tool; its contents are
    // the tool's business and are not read.
    if let Some(project) = manifest.project() {
        for section in &project.tool_sections {
            if let Some(&(_, package, evidence)) =
                TOOL_SECTIONS.iter().find(|(name, _, _)| *name == section)
            {
                collect_tooling_named(
                    package,
                    Path::new(""),
                    Some(Path::new(MANIFEST)),
                    evidence,
                    &mut tooling,
                );
            }
        }
    }
    // A dedicated config file is the same declaration for a tool that has no
    // pyproject table. Existence is enough; nothing is parsed or executed.
    for &(name, package, evidence) in &config_tools {
        collect_tooling_named(
            package,
            Path::new(""),
            Some(Path::new(name)),
            evidence,
            &mut tooling,
        );
    }
    // `setup.cfg`'s tool sections are the same evidence; its packaging
    // metadata remains unread.
    for &(package, evidence) in &setup_cfg_sections {
        collect_tooling_named(
            package,
            Path::new(""),
            Some(Path::new(SETUP_CFG)),
            evidence,
            &mut tooling,
        );
    }
    // Sorted by the table's name, role, directory, evidence, then source — every
    // one of the five a fixed order, so two runs over one project cannot produce
    // two lists. `Config` sorts before `Dependency`, so `dedup_by` collapses a
    // package declared in both and keeps the config file as the source a report
    // names.
    tooling.sort_by(|a, b| {
        a.package
            .cmp(b.package)
            .then(a.role.cmp(&b.role))
            .then(a.from.cmp(&b.from))
            .then(a.evidence.cmp(&b.evidence))
            .then(a.source.cmp(&b.source))
    });
    tooling.dedup_by(|a, b| a.package == b.package && a.role == b.role && a.from == b.from);

    let managers = Managers {
        configured,
        locked,
        requirements: from_requirements,
    };
    let (level, reason) = grade(
        &manifest,
        !requirements.is_empty(),
        !unread_legacy.is_empty(),
        found_tool_config,
        found_a_pipfile,
    );

    Some(EcosystemReport {
        ecosystem: Ecosystem::Python,
        level,
        reason: reason.to_owned(),
        found_by,
        findings: Findings::Python(Box::new(PythonProject {
            manifest,
            pipfile,
            managers,
            requirements,
            tooling,
            python,
            unread_legacy,
        })),
    })
}

/// Read `setup.cfg`'s tool sections, and never its packaging metadata.
///
/// The file is read as text inside the same budget and byte limits as every
/// other manifest; only section names from [`SETUP_CFG_TOOL_SECTIONS`] are
/// looked at. A `setup.cfg` that cannot be read is recorded in `unread`, the
/// same way `.python-version` is, rather than silently treated as one with no
/// tools.
fn read_setup_cfg_tool_sections(
    root: &Path,
    tree: &read::Tree<'_>,
    options: &DiscoverOptions,
    budget: &mut Budget,
    unread: &mut Vec<Unread>,
) -> Vec<(&'static str, ToolingEvidence)> {
    let relative = Path::new(SETUP_CFG);
    match read::read_text_file(root, tree.probe(relative), options, budget) {
        ReadFile::Absent => Vec::new(),
        ReadFile::Unread(reason) => {
            unread.push(Unread {
                path: relative.to_path_buf(),
                reason,
            });
            Vec::new()
        }
        ReadFile::Parsed(value) => value
            .as_str()
            .map(setup_cfg_tool_sections)
            .unwrap_or_default(),
    }
}

/// Which tool sections a `setup.cfg` names.
///
/// A section header is `[name]` on a line of its own; comments and values are
/// not interpreted. The names are compared case-insensitively because config
/// parsers do, and only names from [`SETUP_CFG_TOOL_SECTIONS`] are returned.
fn setup_cfg_tool_sections(text: &str) -> Vec<(&'static str, ToolingEvidence)> {
    let mut found = Vec::new();
    for raw in text.lines() {
        let line = raw.trim();
        let Some(open) = line.find('[') else {
            continue;
        };
        let rest = &line[open + 1..];
        let Some(close) = rest.find(']') else {
            continue;
        };
        let section = rest[..close].trim().to_ascii_lowercase();
        if let Some(&(_, package, evidence)) = SETUP_CFG_TOOL_SECTIONS
            .iter()
            .find(|(name, _, _)| *name == section)
            && !found.iter().any(|(seen, _)| *seen == package)
        {
            found.push((package, evidence));
        }
    }
    found
}

/// Whether anything here says this is a Python project.
///
/// Seven things count, and every one is a **project-level** file: a
/// `pyproject.toml`, a `Pipfile`, a `.python-version`, a `setup.py` or
/// `setup.cfg`, a lockfile, a requirements file, or a dedicated tool config
/// file (`pytest.ini`, `tox.ini`, `noxfile.py`, and the linter/type-checker
/// files in [`CONFIG_TOOLS`]). Source files are **not** on the list, for the
/// reason [`super::node::looks_like_one`] gives: a directory containing a `.py`
/// file is a directory containing a `.py` file, and every one of the seven above
/// is a file a person creates deliberately to declare something.
///
/// Seven arguments rather than the tree, because the decision is made from
/// *presence alone* and this signature is what says so: nothing here can read a
/// file, spend the budget, or record an [`Unread`].
fn looks_like_one(
    manifest_there: bool,
    pipfile_there: bool,
    version_there: bool,
    legacy: &[&'static str],
    lockfiles: &[(&'static str, Installer)],
    requirements: &[PathBuf],
    tool_config: bool,
) -> bool {
    manifest_there
        || pipfile_there
        || version_there
        || !legacy.is_empty()
        || !lockfiles.is_empty()
        || !requirements.is_empty()
        || tool_config
}

/// The requirements files at the project root the naming rule selects.
///
/// Sorted, so which files are read — and therefore which are cut off by
/// [`MAX_REQUIREMENTS_FILES`] — is a function of the project rather than of the
/// order the walk happened to list its files in.
fn requirement_candidates(tree: &read::Tree<'_>) -> Vec<PathBuf> {
    let mut candidates: Vec<PathBuf> = tree
        .child_files(Path::new(""))
        .into_iter()
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| {
                    let lowered = name.to_lowercase();
                    lowered.starts_with(REQUIREMENTS_PREFIX)
                        && lowered.ends_with(REQUIREMENTS_SUFFIX)
                })
        })
        .map(Path::to_path_buf)
        .collect();
    candidates.sort();
    candidates
}

/// Read a manifest, and make it impossible for an unread one to go unrecorded.
///
/// One function rather than a reader and a converter, for the reason
/// [`super::node::read_manifest`] gives at length: a shape failure that reached
/// `ManifestState::Unread` without reaching `Discovery::unread` would describe
/// one project two ways.
fn read_manifest(
    root: &Path,
    relative: &Path,
    tree: &read::Tree<'_>,
    options: &DiscoverOptions,
    budget: &mut Budget,
    unread: &mut Vec<Unread>,
) -> ManifestState {
    let unreadable = |reason: UnreadReason, unread: &mut Vec<Unread>| {
        unread.push(Unread {
            path: relative.to_path_buf(),
            reason: reason.clone(),
        });
        ManifestState::Unread(reason)
    };

    match read::read_toml(root, tree.probe(relative), options, budget) {
        ReadFile::Absent => ManifestState::Absent,
        ReadFile::Unread(reason) => unreadable(reason, unread),
        ReadFile::Parsed(value) => match PyProject::from_json(&value) {
            Ok(project) => ManifestState::Read(Box::new(project)),
            Err(reason) => unreadable(reason, unread),
        },
    }
}

/// Read `.python-version`, and record it if it could not be read.
///
/// Read as text rather than as anything structured, because that is what it is:
/// the file's whole content is the claim, and it is carried verbatim.
fn read_version_file(
    root: &Path,
    tree: &read::Tree<'_>,
    options: &DiscoverOptions,
    budget: &mut Budget,
    unread: &mut Vec<Unread>,
    found_by: &mut Vec<PathBuf>,
) -> Option<VersionClaim> {
    let relative = Path::new(VERSION_FILE);
    let read = read::read_text_file(root, tree.probe(relative), options, budget);
    match read {
        ReadFile::Absent => None,
        ReadFile::Unread(reason) => {
            unread.push(Unread {
                path: relative.to_path_buf(),
                reason,
            });
            None
        }
        ReadFile::Parsed(value) => {
            found_by.push(relative.to_path_buf());
            let text = value
                .as_str()
                .map(str::trim)
                .filter(|text| !text.is_empty())
                .map(str::to_owned)?;
            Some(VersionClaim {
                text,
                source: Source::new(VERSION_FILE, "names the interpreter this project uses"),
            })
        }
    }
}

/// The requirements files at the project root, read.
///
/// The rule for what counts is [`REQUIREMENTS_PREFIX`] and
/// [`REQUIREMENTS_SUFFIX`] rather than a list of names, because the names after
/// `requirements` are the project's to choose. The count is bounded by
/// [`MAX_REQUIREMENTS_FILES`], and each file's lines by
/// [`MAX_REQUIREMENTS_LINES`]; both are reported when reached rather than
/// applied quietly.
fn read_requirements(
    root: &Path,
    candidates: &[PathBuf],
    tree: &read::Tree<'_>,
    options: &DiscoverOptions,
    budget: &mut Budget,
    unread: &mut Vec<Unread>,
    found_by: &mut Vec<PathBuf>,
) -> Vec<RequirementsFile> {
    let mut found = Vec::new();
    for path in candidates.iter().take(MAX_REQUIREMENTS_FILES) {
        let read = read::read_text_file(root, tree.probe(path), options, budget);
        match read {
            // A name the walk listed and the reader found nothing at is a file
            // that went away between the two. That is not a finding about the
            // project, so nothing is recorded and nothing is invented.
            ReadFile::Absent => continue,
            ReadFile::Unread(reason) => {
                unread.push(Unread {
                    path: path.clone(),
                    reason,
                });
            }
            ReadFile::Parsed(value) => {
                let Some(text) = value.as_str() else {
                    continue;
                };
                found_by.push(path.clone());
                found.push(read_requirement_lines(path, text));
            }
        }
    }
    found
}

/// A requirements line with any trailing comment removed.
///
/// A `#` begins a comment at the start of a line or after whitespace — pip's own
/// rule for the case that matters — which is what keeps a URL fragment intact:
/// `pkg.whl#sha256=...` has no space before its `#`, so it survives. Where the
/// rule is wrong, the worst it can do is put a slightly wrong string into
/// [`Requirement::line`], which is carried verbatim and never interpreted.
fn strip_comment(raw: &str) -> &str {
    let mut preceded_by_whitespace = true;
    for (at, character) in raw.char_indices() {
        if character == '#' && preceded_by_whitespace {
            return &raw[..at];
        }
        preceded_by_whitespace = character.is_whitespace();
    }
    raw
}

/// One requirements file's text, as a [`RequirementsFile`].
fn read_requirement_lines(path: &Path, text: &str) -> RequirementsFile {
    let mut requirements = Vec::new();
    let mut directives = Vec::new();
    let mut comments = 0;
    let mut truncated = false;

    for (index, raw) in text.lines().enumerate() {
        if index >= MAX_REQUIREMENTS_LINES {
            truncated = true;
            break;
        }
        let line = strip_comment(raw).trim();
        if line.is_empty() {
            // A blank line and a line that is wholly a comment are counted
            // together: to a reader asking how much of this file was a
            // declaration, the answer is that neither was one.
            comments += 1;
            continue;
        }
        match requirement_name(line) {
            Some(name) => requirements.push(Requirement {
                name,
                line: line.to_owned(),
            }),
            None => directives.push(line.to_owned()),
        }
    }

    RequirementsFile {
        path: path.to_path_buf(),
        requirements,
        directives,
        comments,
        truncated,
    }
}

/// Every recognised package among a list of dependencies.
fn collect_tooling(
    dependencies: &[Dependency],
    from: &Path,
    source: Option<&Path>,
    evidence: ToolingEvidence,
    into: &mut Vec<Tooling>,
) {
    for dependency in dependencies {
        collect_tooling_named(&dependency.name, from, source, evidence, into);
    }
}

/// Every recognised role of one package name.
fn collect_tooling_named(
    name: &str,
    from: &Path,
    source: Option<&Path>,
    evidence: ToolingEvidence,
    into: &mut Vec<Tooling>,
) {
    for (package, role) in tool_roles_of(name) {
        into.push(Tooling {
            package,
            role,
            from: from.to_path_buf(),
            source: source.map(Path::to_path_buf),
            evidence,
        });
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    /// A manifest built by parsing TOML through the same conversion the reader
    /// uses, so these tests cannot pass against a conversion nothing runs. A
    /// private copy beside them would test a conversion with no caller.
    fn manifest(text: &str) -> PyProject {
        let value = toml::from_str::<toml::Value>(text).expect("the test document must parse");
        let value = read::to_json(&value);
        PyProject::from_json(&value).expect("the document must be a manifest")
    }

    /// The table's own name and role for one package, in table order.
    fn roles(name: &str) -> Vec<ToolRole> {
        tool_roles_of(name).map(|(_, role)| role).collect()
    }

    #[test]
    fn a_package_name_is_matched_the_way_the_packaging_metadata_matches_it() {
        // The specification: names are case-insensitive and runs of `-`, `_`
        // and `.` are equivalent. A table that matched literally would miss
        // `scikit_learn` for `scikit-learn`, and the project would be reported
        // as declaring nothing it depends on because of how it spelled one.
        for spelling in [
            "scikit-learn",
            "scikit_learn",
            "Scikit.Learn",
            "SCIKIT--LEARN",
            "Scikit.-_Learn",
        ] {
            assert_eq!(normalise(spelling), "scikit-learn", "{spelling}");
        }
        assert_eq!(roles("Scikit_Learn"), [ToolRole::DataStack]);
        assert_eq!(roles("PyTest"), [ToolRole::TestRunner]);
        // The premise of the whole normalisation, asserted rather than
        // described: the spelling a project writes really is different from the
        // table's.
        assert_ne!("Scikit_Learn", "scikit-learn");
        // And a name the table does not have stays absent, so the matching above
        // is matching rather than accepting everything.
        assert_eq!(roles("pillow"), []);
    }

    #[test]
    fn what_a_finding_reports_is_the_tables_own_name_and_never_the_projects() {
        let project = manifest(
            "[project]\n\
             name = \"x\"\n\
             dependencies = [\"Scikit_Learn>=1\", \"RUFF\", \"PyTest\"]\n",
        );
        let mut tooling = Vec::new();
        collect_tooling(
            &project.dependencies,
            Path::new(""),
            None,
            ToolingEvidence::Dependency,
            &mut tooling,
        );
        let names: BTreeSet<&str> = tooling.iter().map(|tool| tool.package).collect();
        assert_eq!(
            names,
            ["pytest", "ruff", "scikit-learn"].into_iter().collect(),
            "a project's spelling reached a finding"
        );
        // And the requirement it came from is still verbatim, so nothing was
        // lost by matching case-insensitively.
        assert!(
            project
                .dependencies
                .iter()
                .any(|dependency| dependency.requirement == "Scikit_Learn>=1")
        );
    }

    #[test]
    fn a_package_that_is_two_things_is_reported_as_both() {
        // `ruff` lints and formats; `pytest-cov` is a test-support package and
        // the way coverage is usually measured. Picking one role would be SURE
        // choosing which half of a tool to mention.
        assert_eq!(roles("ruff"), [ToolRole::Linter, ToolRole::Formatter]);
        assert_eq!(
            roles("pytest-cov"),
            [ToolRole::TestSupport, ToolRole::Coverage]
        );
        // The premise: a package with one role really does get one row, so the
        // two assertions above are about the table rather than about `roles`.
        assert_eq!(roles("black"), [ToolRole::Formatter]);
    }

    #[test]
    fn every_row_of_the_table_is_written_in_the_form_the_lookup_produces() {
        // A row written `scikit_learn` would be unreachable: the lookup
        // normalises the project's spelling and then compares literally, so a
        // table entry that is not already normalised can never match. That is
        // the failure that makes a package silently invisible, and it is
        // invisible in exactly the same way.
        for (package, _) in TOOLS {
            assert_eq!(
                normalise(package),
                *package,
                "the table row {package:?} can never be matched"
            );
        }
    }

    #[test]
    fn every_role_has_at_least_one_package_and_every_package_names_a_known_role() {
        // A role with no package is a role that can never be reported, and a
        // role nothing names is a sentence a person can never read.
        for &role in ToolRole::ALL {
            assert!(
                TOOLS.iter().any(|(_, found)| *found == role),
                "no package has the role {role:?}"
            );
            assert!(!role.as_str().is_empty());
            assert!(!role.plain_description().is_empty());
        }
    }

    #[test]
    fn no_two_rows_of_the_table_are_the_same_pair() {
        // Two identical rows would produce two identical findings, which is a
        // duplicate a reader cannot explain.
        let mut seen: Vec<(&str, ToolRole)> = TOOLS.to_vec();
        seen.sort_unstable_by(|a, b| a.0.cmp(b.0).then(a.1.cmp(&b.1)));
        let count = seen.len();
        seen.dedup();
        assert_eq!(seen.len(), count, "the tool table has a duplicate row");
    }

    #[test]
    fn a_requirement_line_yields_a_name_and_nothing_else_is_guessed_at() {
        for (line, expected) in [
            ("pytest", Some("pytest")),
            ("pytest>=7", Some("pytest")),
            ("pytest == 7", Some("pytest")),
            ("scikit_learn[alldeps]==1.4.0", Some("scikit_learn")),
            ("requests; python_version < \"3.9\"", Some("requests")),
            ("black==24.1.0 --hash=sha256:abc", Some("black")),
            // A direct reference, which is the one form where the name really is
            // followed by something that looks like a URL.
            ("foo @ https://example.invalid/foo-1.0.tar.gz", Some("foo")),
            // The lines that name no distribution. The URL is the one that was
            // really reported as a dependency named `https` before the rule in
            // `requirement_name` rejected a name followed by a scheme.
            ("--index-url https://example.invalid/simple", None),
            ("-r other.txt", None),
            ("https://example.invalid/pkg.whl", None),
            ("/absolute/path/pkg.whl", None),
            ("foo-", None),
            ("foo.", None),
            ("", None),
        ] {
            assert_eq!(requirement_name(line).as_deref(), expected, "{line:?}");
        }
    }

    #[test]
    fn the_poetry_interpreter_constraint_is_not_read_as_a_dependency() {
        // `[tool.poetry.dependencies].python` sits in a dependency table and is
        // not one. Reading it as a dependency would report a project as
        // depending on a package called `python`, and would put a project's
        // interpreter constraint into a list where a check would look for a
        // pinned library.
        let project = manifest(
            "[tool.poetry]\n\
             name = \"x\"\n\
             \n\
             [tool.poetry.dependencies]\n\
             python = \"^3.11\"\n\
             requests = \"^2.31\"\n",
        );
        assert!(
            !project
                .dependencies
                .iter()
                .any(|found| found.name == "python"),
            "the interpreter constraint was read as a dependency"
        );
        assert!(
            project
                .dependencies
                .iter()
                .any(|found| found.name == "requests")
        );
    }

    #[test]
    fn a_sibling_of_the_interpreter_constraint_is_unaffected_by_removing_it() {
        // The removal above edits a copy of the table. This asserts the edit
        // did not take a neighbour with it, which is the way that code could be
        // wrong without the test above noticing.
        let project = manifest(
            "[tool.poetry.dependencies]\n\
             python = \"^3.11\"\n\
             python-dotenv = \"^1.0\"\n\
             python_dateutil = \"^2.8\"\n",
        );
        let names: BTreeSet<&str> = project
            .dependencies
            .iter()
            .map(|found| found.name.as_str())
            .collect();
        // Verbatim, as the project spelled them: a dependency's name is data and
        // is recorded as written. The normalisation in this module is a *lookup*
        // rule for [`TOOLS`] and never rewrites what a project declared.
        assert_eq!(
            names,
            ["python-dotenv", "python_dateutil"]
                .into_iter()
                .collect::<BTreeSet<&str>>(),
            "a neighbour of the interpreter constraint was lost"
        );
    }

    #[test]
    fn a_dependency_sure_cannot_read_is_not_a_dependency_that_is_not_there() {
        // Poetry's table form is a real declaration SURE will not guess at.
        let project = manifest(
            "[tool.poetry.dependencies]\n\
             requests = { version = \"^2.31\", extras = [\"socks\"] }\n\
             flask = \"^3\"\n",
        );
        assert_eq!(project.dependencies.len(), 1);
        assert_eq!(project.dependencies[0].name, "flask");
        assert_eq!(project.dependencies_not_text, ["requests"]);
    }

    #[test]
    fn a_requirements_file_keeps_every_line_in_exactly_one_place() {
        let file = read_requirement_lines(
            Path::new("requirements.txt"),
            "# a comment\n\
             \n\
             pytest==8.0.0\n\
             -r other.txt\n\
             requests>=2.31  # pinned by the platform team\n\
             --index-url https://example.invalid/simple\n",
        );
        assert_eq!(
            file.requirements
                .iter()
                .map(|requirement| requirement.name.as_str())
                .collect::<Vec<_>>(),
            ["pytest", "requests"]
        );
        assert_eq!(
            file.directives,
            ["-r other.txt", "--index-url https://example.invalid/simple"]
        );
        assert_eq!(file.comments, 2);
        assert!(!file.truncated);
        // Every line accounted for, which is the property the count of a
        // requirements file has to have: six lines in, six lines placed.
        assert_eq!(
            file.requirements.len() + file.directives.len() + file.comments,
            6
        );
    }

    #[test]
    fn a_requirements_file_that_is_longer_than_sure_reads_says_so() {
        let text: String = (0..MAX_REQUIREMENTS_LINES + 10)
            .map(|index| format!("package{index}\n"))
            .collect();
        let file = read_requirement_lines(Path::new("requirements.txt"), &text);
        assert!(file.truncated, "the cut-off was applied quietly");
        assert_eq!(file.requirements.len(), MAX_REQUIREMENTS_LINES);
    }

    #[test]
    fn a_command_is_only_offered_for_a_role_the_project_declared_a_tool_for() {
        // The rule that keeps a plan from becoming an invented fact: no tool,
        // no command — except `Install`, which the installer answers.
        let none = command_for(None, CommandRole::Test, &[]);
        assert!(none.command.is_none());
        assert!(none.because.is_empty());
        assert!(
            command_for(Some(Installer::Uv), CommandRole::Test, &[])
                .command
                .is_none()
        );

        let tooling = vec![Tooling {
            package: "pytest",
            role: ToolRole::TestRunner,
            from: PathBuf::new(),
            source: None,
            evidence: ToolingEvidence::Dependency,
        }];
        let test = command_for(Some(Installer::Uv), CommandRole::Test, &tooling);
        assert_eq!(test.command.as_deref(), Some("uv run pytest"));
        assert_eq!(test.because, ["pytest"]);
    }

    #[test]
    fn a_command_names_the_interpreter_when_the_installer_is_pip() {
        // `pip install` puts a console script somewhere; which `pytest` runs
        // then depends on what is first on the path. `python -m pytest` is the
        // same interpreter that pip installed into.
        let tooling = vec![Tooling {
            package: "pytest",
            role: ToolRole::TestRunner,
            from: PathBuf::new(),
            source: None,
            evidence: ToolingEvidence::Dependency,
        }];
        assert_eq!(
            command_for(Some(Installer::Pip), CommandRole::Test, &tooling)
                .command
                .as_deref(),
            Some("python -m pytest")
        );
        assert_eq!(
            command_for(Some(Installer::Poetry), CommandRole::Test, &tooling)
                .command
                .as_deref(),
            Some("poetry run pytest")
        );
        assert_eq!(
            command_for(Some(Installer::Pip), CommandRole::Install, &[])
                .command
                .as_deref(),
            Some("python -m pip install -r requirements.txt")
        );
        assert_eq!(
            command_for(Some(Installer::Uv), CommandRole::Install, &[])
                .command
                .as_deref(),
            Some("uv sync")
        );
    }

    #[test]
    fn every_installer_has_the_install_line_the_product_plans() {
        // `install_invocation`'s doc says the tests hold each one, and until
        // this test that was true of three of the five: pip and uv were held
        // here and pipenv in `checks::python`, and poetry's and pdm's lines were
        // asserted nowhere in the crate. The sentence was made true rather than
        // deleted, because the two that were unheld are the two that differ in
        // verb.
        //
        // An exact list and not a lower bound. `uv sync` against everyone else's
        // `install` is the whole reason the arms are written out, and a shared
        // `" sync"` or a shared `"install"` gets one side or the other wrong —
        // `poetry sync` is not the command that installs a project's
        // dependencies, and neither is `uv install`. A sixth installer added
        // without a line here fails the comparison below rather than being
        // planned with a command nobody has read.
        let expected = [
            (Installer::Pip, "python -m pip install -r requirements.txt"),
            (Installer::Uv, "uv sync"),
            (Installer::Poetry, "poetry install"),
            (Installer::Pipenv, "pipenv install"),
            (Installer::Pdm, "pdm install"),
        ];
        assert_eq!(
            expected.map(|(manager, _)| manager).as_slice(),
            Installer::ALL,
            "this test no longer visits every installer SURE recognises"
        );
        for (manager, line) in expected {
            assert_eq!(
                command_for(Some(manager), CommandRole::Install, &[])
                    .command
                    .as_deref(),
                Some(line),
                "{manager:?} would be planned with a line that does not install"
            );
        }
    }

    #[test]
    fn a_build_backend_is_not_offered_as_the_command_that_builds() {
        // `setuptools` and `poetry-core` are libraries a frontend calls. Naming
        // one as if it were the command would be a plan that does not run.
        let tooling = vec![Tooling {
            package: "setuptools",
            role: ToolRole::BuildBackend,
            from: PathBuf::new(),
            source: None,
            evidence: ToolingEvidence::Dependency,
        }];
        let built = command_for(None, CommandRole::Build, &tooling);
        assert_eq!(built.command.as_deref(), Some("python -m build"));
        assert_eq!(
            built.because,
            ["setuptools"],
            "the plan hides what it rests on"
        );
        assert_eq!(
            command_for(Some(Installer::Poetry), CommandRole::Build, &tooling)
                .command
                .as_deref(),
            Some("poetry build"),
            "the frontend the project declared is preferred to the generic one"
        );
    }

    #[test]
    fn a_row_exists_for_every_conventional_role_whether_or_not_it_can_run() {
        let project = PythonProject {
            manifest: ManifestState::Absent,
            pipfile: ManifestState::Absent,
            managers: Managers::default(),
            requirements: Vec::new(),
            tooling: Vec::new(),
            python: PythonVersion::default(),
            unread_legacy: Vec::new(),
        };
        let rows = project.conventional_commands();
        assert_eq!(rows.len(), CommandRole::ALL.len());
        assert_eq!(
            rows.iter().map(|row| row.role).collect::<Vec<_>>(),
            CommandRole::ALL.to_vec()
        );
        assert!(
            rows.iter().all(|row| row.command.is_none()),
            "a command was invented for a project that declared nothing"
        );
    }

    #[test]
    fn a_configured_installer_and_a_lockfile_for_another_are_a_disagreement() {
        let managers = Managers {
            configured: vec![InstallerFinding {
                installer: Installer::Poetry,
                evidence: InstallerEvidence::Declared,
                source: Source::new(MANIFEST, "test"),
            }],
            locked: vec![InstallerFinding {
                installer: Installer::Uv,
                evidence: InstallerEvidence::Lockfile,
                source: Source::new("uv.lock", "test"),
            }],
            requirements: Vec::new(),
        };
        assert_eq!(
            managers.disagreement(),
            Some(Disagreement::ConfigurationAndLockfile {
                configured: Installer::Poetry,
                locked: Installer::Uv,
            })
        );
        assert!(managers.agreed().is_none());
        // Both, and not merely the one this test is about: `agreed` is a view of
        // `agreed_finding`, so a disagreement that stopped one of them would be
        // two answers to one question.
        assert!(managers.agreed_finding().is_none());
    }

    #[test]
    fn a_requirements_file_never_makes_a_project_disagree_with_itself() {
        // The claim in the module comment, asserted: pip, uv, poetry and pdm
        // all install from a requirements file, so its presence next to a
        // `uv.lock` is the normal shape of a project that moved to uv — not a
        // contradiction, and reporting one would train a reader to ignore the
        // real ones.
        let managers = Managers {
            configured: Vec::new(),
            locked: vec![InstallerFinding {
                installer: Installer::Uv,
                evidence: InstallerEvidence::Lockfile,
                source: Source::new("uv.lock", "test"),
            }],
            requirements: vec![InstallerFinding {
                installer: Installer::Pip,
                evidence: InstallerEvidence::RequirementsFile,
                source: Source::new("requirements.txt", "test"),
            }],
        };
        assert_eq!(managers.disagreement(), None);
        assert_eq!(managers.agreed(), Some(Installer::Uv));
        // And the finding behind it, which is what a caller names a file from.
        // The lockfile decides while the requirements file is sitting right
        // there, so a caller that picked the *pip* finding would name
        // `requirements.txt` for a project whose installer is uv — an anchor
        // pointing at a file that did not decide, which is the defect this
        // accessor exists to make unspellable.
        assert_eq!(
            managers
                .agreed_finding()
                .map(|found| found.source.path.as_path()),
            Some(Path::new("uv.lock"))
        );

        // And with nothing stronger, the requirements file is what decides.
        let only_requirements = Managers {
            requirements: managers.requirements.clone(),
            ..Managers::default()
        };
        assert_eq!(only_requirements.agreed(), Some(Installer::Pip));
        assert_eq!(
            only_requirements
                .agreed_finding()
                .map(|found| found.source.path.as_path()),
            Some(Path::new("requirements.txt"))
        );
    }

    #[test]
    fn two_tool_tables_naming_two_installers_are_a_disagreement() {
        let managers = Managers {
            configured: vec![
                InstallerFinding {
                    installer: Installer::Pdm,
                    evidence: InstallerEvidence::Declared,
                    source: Source::new(MANIFEST, "test"),
                },
                InstallerFinding {
                    installer: Installer::Uv,
                    evidence: InstallerEvidence::Declared,
                    source: Source::new(MANIFEST, "test"),
                },
            ],
            ..Managers::default()
        };
        // `TwoDeclarations`, not `TwoLockfiles`: two `[tool.*]` tables are two
        // statements the project is making right now, and reporting them as
        // "two lockfiles" would name evidence the project does not have. This
        // test held the wrong variant until the variant existed — which is the
        // shape of a wrong answer a test can hold in place for a long time.
        assert_eq!(
            managers.disagreement(),
            Some(Disagreement::TwoDeclarations {
                first: Installer::Pdm,
                second: Installer::Uv,
            })
        );
        assert!(managers.agreed().is_none());
        // Both, and not merely the one this test is about: `agreed` is a view of
        // `agreed_finding`, so a disagreement that stopped one of them would be
        // two answers to one question.
        assert!(managers.agreed_finding().is_none());
    }

    #[test]
    fn a_build_backend_names_an_installer_only_when_it_shares_the_name() {
        // `poetry.core.masonry.api` is what a `[build-system]` table really
        // writes; `hatchling` says nothing about which installer is used.
        assert_eq!(
            Installer::from_build_backend("poetry.core.masonry.api"),
            Some(Installer::Poetry)
        );
        assert_eq!(
            Installer::from_build_backend("pdm.backend"),
            Some(Installer::Pdm)
        );
        assert_eq!(Installer::from_build_backend("hatchling.build"), None);
        assert_eq!(Installer::from_build_backend("setuptools.build_meta"), None);
        assert_eq!(Installer::from_build_backend("flit_core.buildapi"), None);
    }

    #[test]
    fn the_lockfile_table_names_every_installer_that_has_one_and_no_other() {
        // A manager that could never be detected from a lockfile is a row that
        // can never be produced; an installer with no lockfile (pip) must not
        // be invented one.
        for &(name, installer) in LOCKFILES {
            assert!(!name.is_empty(), "{installer:?} has an unnamed lockfile");
            assert_ne!(installer, Installer::Pip, "pip has no lockfile");
        }
        for &installer in Installer::ALL {
            if installer == Installer::Pip {
                continue;
            }
            assert!(
                LOCKFILES.iter().any(|(_, found)| *found == installer),
                "{installer:?} has no lockfile, so it can only be found by \
                 configuration"
            );
        }
        // Every table name is a real table name, and they are distinct.
        let mut names: Vec<&str> = Installer::ALL
            .iter()
            .filter_map(|installer| installer.tool_table())
            .collect();
        names.sort_unstable();
        let count = names.len();
        names.dedup();
        assert_eq!(names.len(), count, "two installers share a tool table");
    }

    #[test]
    fn every_installer_can_be_named_and_described() {
        for &installer in Installer::ALL {
            assert!(!installer.as_str().is_empty());
        }
        for evidence in [
            InstallerEvidence::Declared,
            InstallerEvidence::Lockfile,
            InstallerEvidence::RequirementsFile,
        ] {
            assert!(!evidence.as_str().is_empty());
            assert!(!evidence.plain_description().is_empty());
        }
        for role in CommandRole::ALL {
            assert!(!role.as_str().is_empty());
            assert!(!role.plain_description().is_empty());
        }
        for kind in DependencyKind::ALL {
            assert!(!kind.as_str().is_empty());
            assert!(!kind.plain_description().is_empty());
        }
    }

    #[test]
    fn a_comment_is_removed_only_where_a_comment_can_begin() {
        // The rule that keeps a URL fragment intact. Stripping at any `#` would
        // turn a pinned artifact into a different requirement.
        assert_eq!(
            strip_comment("requests>=2.31  # pinned"),
            "requests>=2.31  "
        );
        assert_eq!(strip_comment("# entirely a comment"), "");
        assert_eq!(strip_comment("  # indented comment"), "  ");
        assert_eq!(
            strip_comment("https://example.invalid/pkg.whl#sha256=abc"),
            "https://example.invalid/pkg.whl#sha256=abc",
            "a URL fragment was read as a comment"
        );
    }

    #[test]
    fn a_file_that_does_not_match_the_requirements_rule_is_not_one() {
        // The rule is a prefix and a suffix, and it is the one place a project's
        // choice of file name decides whether SURE reads it. The names below are
        // the ones a looser rule would wrongly take.
        let matches = |name: &str| {
            let lowered = name.to_lowercase();
            lowered.starts_with(REQUIREMENTS_PREFIX) && lowered.ends_with(REQUIREMENTS_SUFFIX)
        };
        for name in [
            "requirements.txt",
            "requirements-dev.txt",
            "REQUIREMENTS-PROD.TXT",
            "requirements_test.txt",
        ] {
            assert!(matches(name), "{name} was not recognised");
        }
        for name in [
            "requirements",
            "requirements.in",
            "dev-requirements.txt",
            "requirements.txt.bak",
            "notes.txt",
        ] {
            assert!(!matches(name), "{name} was wrongly recognised");
        }
    }

    #[test]
    fn every_file_that_marks_a_python_project_is_on_the_list_that_decides() {
        // The complete list, asserted by varying exactly one fact at a time: a
        // `looks_like_one` that had lost a marker would report a real project as
        // not Python rather than report nothing at all.
        let none: &[&str] = &[];
        let no_locks: &[(&str, Installer)] = &[];
        let no_requirements: &[PathBuf] = &[];
        assert!(!looks_like_one(
            false,
            false,
            false,
            none,
            no_locks,
            no_requirements,
            false,
        ));
        assert!(looks_like_one(
            true,
            false,
            false,
            none,
            no_locks,
            no_requirements,
            false,
        ));
        assert!(looks_like_one(
            false,
            true,
            false,
            none,
            no_locks,
            no_requirements,
            false,
        ));
        assert!(looks_like_one(
            false,
            false,
            true,
            none,
            no_locks,
            no_requirements,
            false,
        ));
        assert!(looks_like_one(
            false,
            false,
            false,
            &["setup.py"],
            no_locks,
            no_requirements,
            false,
        ));
        assert!(looks_like_one(
            false,
            false,
            false,
            none,
            &[("uv.lock", Installer::Uv)],
            no_requirements,
            false,
        ));
        assert!(looks_like_one(
            false,
            false,
            false,
            none,
            no_locks,
            &[PathBuf::from("requirements.txt")],
            false,
        ));
        assert!(looks_like_one(
            false,
            false,
            false,
            none,
            no_locks,
            no_requirements,
            true
        ));
    }
}
