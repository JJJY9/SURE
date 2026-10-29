//! The checks a Python project's declared tools turn into.
//!
//! `P4-T003`'s acceptance, and it is one sentence:
//!
//! > *Declared import/test/lint/type checks use available tools without silent
//! > package installation.*
//!
//! # The four words, and the role that is not a role
//!
//! Three of the four are [`CommandRole`]s and are checks:
//! [`Test`](CommandRole::Test), [`Lint`](CommandRole::Lint) and
//! [`TypeCheck`](CommandRole::TypeCheck). The fourth is read as
//! [`Install`](CommandRole::Install), and the evidence for that reading is in
//! the sentence itself: the half that gives this task its teeth is about package
//! installation, and `CommandRole::ALL` opens with exactly these four in exactly
//! this order. Whatever the word was meant to be, **installing is what the
//! sentence is about**, and [`InstallStep`] is where this module answers for it.
//!
//! **`import` is not a [`CommandRole`], and SURE proposes no import check.** The
//! conventional smoke check in a Python CI job is `python -c "import pkg"`, and
//! SURE cannot build it from anything a manifest declares: the import name is
//! not the distribution name — `PyYAML` imports as `yaml` and `scikit-learn` as
//! `sklearn` — so an import check derived from `[project] name` would be a
//! command that fails for a large fraction of the projects it was built for, and
//! deriving the mapping would be SURE inventing a convention and then running a
//! command on the strength of it. That is the same line
//! [`discover::node`](crate::discover::node)'s script matching holds to when it
//! refuses to read `test:unit` as `test`, and it is stated here rather than left
//! as a missing row.
//!
//! # What the module adds that `super::node` did not have to
//!
//! **Installing is planned and is never a check.** [`InstallStep`] is a separate
//! type, and the separation is the whole of *without silent package
//! installation*: no [`CheckProposal`] this module builds names
//! [`ActionKind::InstallDependencies`], and
//! `nothing_this_module_proposes_installs_anything` holds that over every role
//! rather than over the ones somebody thought of. Where node's acceptance was
//! about which mode may run a check, this one is about a step that is not a
//! check at all — and the failure it is arranged against is not a wrong verdict
//! but an **unrequested change to the machine**. A caller that schedules the
//! proposals and never asks for [`PythonChecks::install`] has a plan that runs
//! tools which may not be installed, and the outcome of that is a check that
//! *fails* — visibly, with the tool's own error — rather than a package SURE
//! put on the user's disk without being asked.
//!
//! **The interpreter is a question no other ecosystem asks.** Node's runner is a
//! package manager and `Managers::agreed` answering `None` means SURE cannot
//! spell a command. For Python it is worse than that: `command_for` has an
//! answer for `None` — `python -m <tool>` — and that answer is *the wrong
//! interpreter* when the project has already named two. See [`Runner`].
//!
//! **A declaration SURE could not read is not a declaration that is not there.**
//! Poetry's table form puts a real dependency in
//! [`PyProject::dependencies_not_text`](crate::discover::python::PyProject::dependencies_not_text)
//! instead of in the dependency list, so it never reaches `TOOLS` and the
//! project looks like one that declares no linter. [`MissingKind::NotReadable`]
//! is the fourth way a project can leave SURE without a command, and it exists
//! because of this ecosystem.
//!
//! # What it does not do
//!
//! **It does not look at the installed environment.** Nothing here can tell
//! whether a declared tool is *installed*, so a `[tool.poetry]` table naming
//! pytest proposes `poetry run pytest` whether or not `poetry install` has ever
//! been run in this checkout. That is not an oversight: whether the tool is
//! importable is a fact about this machine and the interpreter, it is discovered
//! by running the command, and the run is the check. It is the same limit
//! [`super::node`] states about `node_modules`.
//!
//! **It cannot promise that a runner does not install.** A check command is
//! built by [`command_for`] out of the installer and a name from SURE's own
//! table, and what that command does *inside* the runner is the runner's
//! business — several of them do environment work before running, and which ones
//! and in which version is not something a manifest says. SURE cannot confirm it
//! and does not claim it; what it does instead is carry the exact line in
//! [`CheckReason::DeclaredCommand`] so that the consent prompt shows what would
//! run, and never compose an install of its own.
//!
//! **It does not read a workspace.** `discover::python` reads one project's
//! manifest set and does not walk members, so unlike [`super::node`] there is
//! one component here and not one per member.
//!
//! **It is not the plan.** No check here has been ordered, deduplicated or
//! gated by a mode; that is [`crate::schedule`]'s work and
//! `tests/python_checks.rs` is where the two are put together.
//!
//! # A check is planned as work, and not only as a line
//!
//! Since `P18-T003` every check here is a proposal **and the operation that
//! would carry it out** ([`PlannedWork`](crate::planned_work::PlannedWork)): the
//! program is the installer's own name or `python`, the arguments are `run` and
//! the tool from [`TOOLS`](crate::discover::python::TOOLS), and the directory is
//! the project root.
//!
//! **The rendered line stays a rendering.**
//! [`CheckReason::DeclaredCommand`] still carries `uv run pytest`, because that
//! is what a report prints and what a person is being asked to allow — and
//! nothing reads it back into a program. The line and the vector are one value
//! seen twice: they both come from the discovery's
//! [`invocation_for`](crate::discover::python::invocation_for), which is also
//! what [`command_for`](crate::discover::python::command_for) renders, so a check
//! cannot be shown one command and started with another.
//!
//! **The installer's name is not rewritten for the platform**, and neither is
//! `python`. On Windows a bare `uv` is a name Windows completes with `.exe` and
//! nothing else, so a project whose only installer is installed as `uv.exe` is
//! planned as a command this build will not start; whether a name is startable is
//! [`ProgramPath`](crate::planned_work::ProgramPath)'s answer and the runner's to
//! act on. Appending `.exe` — or wrapping the name in `cmd.exe /c` — would be
//! constructing the interpreter ADR 0014 says SURE must not build.
//!
//! **`python` is the one program SURE names that the project did not.** It is
//! already how [`command_for`] has always spelled the no-installer case, and the
//! reasons [`Runner`] gives for that are the reasons it is spelled here too: a
//! bare tool name would depend on which interpreter is first on the path, which
//! is the fact SURE cannot see and does not claim.

use std::path::Path;

use sure_domain::evidence::EvidenceClass;
use sure_domain::execution::ActionKind;
use sure_domain::ids::FingerprintId;
use sure_domain::severity::Severity;
use sure_domain::status::CheckResult;

use crate::discover::Source;
use crate::discover::python::{
    CommandRole, Installer, Managers, PIPFILE, PythonProject, ToolRole, command_for, invocation_for,
};
use crate::planned_work::PlannedWork;
use crate::scan::display_path;
use crate::schedule::{CheckProposal, CheckReason, PlanBuilder};

use super::{MissingCommand, MissingKind, check_id, command_operation};

/// What SURE proposes for one role.
///
/// A table rather than a `match` per question, for the reason
/// [`super::node`]'s is one: four roles have to agree about four things, and
/// four matches that agree by hand are four places for a role to be added to
/// only one of.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RoleCheck {
    /// What the check would do.
    ///
    /// The field that decides the first acceptance clause: all four of these
    /// execute project code, so `decide` refuses each of them under
    /// [`InspectOnly`](sure_domain::execution::ExecutionMode::InspectOnly).
    /// **None of them is `InstallDependencies`**, which is what
    /// [`InstallStep`] exists to keep true.
    action: ActionKind,
    /// How bad it is if the check does not pass.
    severity: Severity,
    /// Whether the project cannot be trusted for hand-off when it does not pass.
    ///
    /// Failing tests and a distribution that will not build are both reasons not
    /// to hand a project over. A lint or a type check that fails is a finding
    /// about quality. **Nothing in a `pyproject.toml` says how much any of this
    /// matters**, so the four weights are SURE's judgement, written where they
    /// can be argued with — and, because `P4-T002`'s first mutation run found
    /// that prose alone holds nothing, pinned by
    /// `the_table_carries_the_three_weighted_roles_and_the_one_that_is_not`.
    critical: bool,
}

/// The roles SURE checks, and what each one's check is.
///
/// **The order is the acceptance's**, test then lint then type, with
/// [`Build`](CommandRole::Build) after them because the acceptance does not name
/// it and the reason to check it is [`super::node`]'s rather than this
/// sentence's: a distribution that does not build is a reason not to hand the
/// project over, and that argument is about packaging rather than about
/// JavaScript.
///
/// [`Install`](CommandRole::Install) and [`Format`](CommandRole::Format) are
/// absent on purpose. `Install` is absent because it is not a check — see
/// [`InstallStep`], which is where it went. `Format` is absent for the reason
/// node's is: `ruff format` and `black` rewrite files, and a check is a question
/// rather than an edit. `ActionKind` has no variant for formatting either, which
/// is the domain saying the same thing.
const CHECKS: &[(CommandRole, RoleCheck)] = &[
    (
        CommandRole::Test,
        RoleCheck {
            action: ActionKind::RunTests,
            severity: Severity::MustFix,
            critical: true,
        },
    ),
    (
        CommandRole::Lint,
        RoleCheck {
            action: ActionKind::Lint,
            severity: Severity::CanFixLater,
            critical: false,
        },
    ),
    (
        CommandRole::TypeCheck,
        RoleCheck {
            action: ActionKind::TypeCheck,
            severity: Severity::ShouldFixFirst,
            critical: false,
        },
    ),
    (
        CommandRole::Build,
        RoleCheck {
            action: ActionKind::Build,
            severity: Severity::MustFix,
            critical: true,
        },
    ),
];

/// The tool role each checked role looks for, so a gap can be told apart from a
/// declaration SURE could not read.
///
/// Written as a function of the discovery's own answer rather than as a second
/// table, because the two have to agree: a role added to [`CHECKS`] whose tool
/// role was not added here would report every project as declaring nothing.
/// `CommandRole` already answers this for all six of its roles and
/// `the_tool_role_this_asks_about_is_the_one_the_command_is_built_from` holds
/// that this is that answer and not a copy of it.
///
/// [`Build`](CommandRole::Build) is the row worth reading, because it is the one
/// whose answer is not obvious: a build is answered by
/// [`ToolRole::BuildBackend`], the *library* a frontend calls rather than a
/// command — `setuptools` and `poetry-core` are not programs. So "this project
/// declares no build backend" is a true gap, and a backend written in a shape
/// SURE could not read is [`MissingKind::NotReadable`] like any other tool.
fn tool_role(role: CommandRole) -> Option<ToolRole> {
    role.tool_roles().first().copied()
}

/// Which environment a project's tools are installed in, or why SURE cannot say.
///
/// Three values rather than node's two, and the third is the reason this type
/// exists. `/`[`Managers::agreed`] answering `None` is one answer in Node — SURE
/// cannot spell a command — and two here, because
/// [`command_for`] spells a command anyway: with no installer it builds
/// `python -m pytest`, and whether that is right depends entirely on *why* there
/// is no installer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Runner<'a> {
    /// The project names one installer, and SURE will run tools through it.
    ///
    /// **The finding and not merely the installer**, because a caller has to be
    /// able to say which file decided. [`Managers::agreed`] carries only the
    /// [`Installer`], and looking the file back up by installer would be a
    /// second walk of the tiers — an answer free to disagree with the one this
    /// was built from, and one whose only possible repair in the disagreeing
    /// case is to name a file that did not decide.
    Agreed {
        /// Which installer.
        installer: Installer,
        /// The file that named it, so a step's anchor is the evidence itself.
        found: &'a Source,
    },
    /// The project names no installer at all.
    ///
    /// **Not a failure.** `python -m pytest` is a complete command and the only
    /// interpreter SURE can name; a project that declares no installer has not
    /// contradicted itself, it has merely said nothing. Whether pytest is
    /// importable by that interpreter is the fact the run discovers.
    Interpreter,
    /// The project names two, and SURE cannot tell which environment holds the
    /// tools.
    ///
    /// This is the case `command_for` gets wrong on its own. A project with a
    /// `[tool.poetry]` table and a `uv.lock` beside it is mid-migration:
    /// [`Managers::agreed`] answers `None`, `command_for` falls through to
    /// `python -m <tool>`, and that is a *third* interpreter which neither
    /// declaration named. Running it produces `No module named pytest` — a
    /// sentence that is false about the project, since the project does declare
    /// pytest, and true only about the interpreter SURE picked. **A visible gap
    /// is better than a misleading error**, so the roles refuse and say which
    /// way the project failed to answer.
    Unknown {
        /// A constant from the discovery. Never project text.
        why: &'static str,
    },
}

impl<'a> Runner<'a> {
    /// Which environment this project's tools are in.
    fn of(managers: &'a Managers) -> Self {
        match managers.agreed_finding() {
            Some(found) => Self::Agreed {
                installer: found.installer,
                found: &found.source,
            },
            None if managers.disagreement().is_some() => Self::Unknown {
                // Irreversible: `agreed` answers `None` here exactly because
                // `disagreement` answered `Some`, so the second read cannot
                // disagree with the first. Folded into the third value rather
                // than panicking on a shipped path.
                why: managers
                    .disagreement()
                    .map_or(NO_EVIDENCE_IS_NOT_A_CONTRADICTION, |disagreement| {
                        disagreement.plain_description()
                    }),
            },
            None => Self::Interpreter,
        }
    }

    /// The installer, if the project named one.
    const fn installer(&self) -> Option<Installer> {
        match self {
            Self::Agreed { installer, .. } => Some(*installer),
            Self::Interpreter | Self::Unknown { .. } => None,
        }
    }
}

/// The sentence for the one refusal that is about the project's own silence.
///
/// A constant rather than a built string, for the reason every sentence in this
/// repository is: a project must not be able to write a line SURE says. It is
/// distinct from [`super::NOTHING_NAMES_A_RUNNER`], which is about a package
/// manager and a script: nothing here is a script, and the thing that is missing
/// is an environment.
const NO_EVIDENCE_IS_NOT_A_CONTRADICTION: &str =
    "Nothing in this project says which environment its tools are installed in.";

/// The step that puts a project's dependencies in place, which is not a check.
///
/// **A type of its own, and that is the acceptance.** *Without silent package
/// installation* is not a rule about which commands SURE composes — [`command_for`]
/// already builds every check command out of constants and SURE's own tool table,
/// so no project text reaches one — it is a rule about a change to the user's
/// machine that must be asked for rather than assumed. A value that is not a
/// [`CheckProposal`] cannot enter a [`CheckSchedule`](crate::schedule::CheckSchedule),
/// cannot be handed to [`PlanBuilder`], and cannot acquire a
/// [`CheckResult`](sure_domain::status::CheckResult) that reads as a verdict
/// about the project.
///
/// It is a *step* rather than a *finding* for the same reason. An install that
/// fails, or that the user refuses, says nothing about whether the project is
/// any good; it says the tools are not there yet. What a caller does with that
/// is [`crate::approval`]'s and [`crate::consent`]'s business, and
/// [`Self::action`] is the requirement they need from it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallStep {
    command: String,
    because: Vec<&'static str>,
    declared_in: String,
    says: &'static str,
}

impl InstallStep {
    /// The line SURE would run, from [`command_for`] and never from project
    /// text.
    #[must_use]
    pub fn command(&self) -> &str {
        &self.command
    }

    /// The tools the plan rests on, from `TOOLS`.
    ///
    /// For an install this is the installer's own name, which is also the
    /// manager in [`Self::command`] — carried anyway so that a reader of a step
    /// and a reader of a check read the same field.
    #[must_use]
    pub fn because(&self) -> &[&'static str] {
        &self.because
    }

    /// The file SURE found the evidence in.
    ///
    /// **A true anchor, unlike a check's.** Where a check's file is the manifest
    /// SURE read the project from — see [`PythonChecks::component`] — an install
    /// rests on one piece of evidence, and the discovery carried it as a
    /// [`Source`] with its own path. This names that one.
    #[must_use]
    pub fn declared_in(&self) -> &str {
        &self.declared_in
    }

    /// What that file said, as the discovery's own constant phrase.
    #[must_use]
    pub const fn says(&self) -> &'static str {
        self.says
    }

    /// What an install needs allowed before it may run.
    ///
    /// Always [`ActionKind::InstallDependencies`], and it is a function rather
    /// than a field because there is exactly one answer and a field would be a
    /// second place for it to be written down wrong. It is the requirement
    /// [`crate::consent`] turns into the question a user is asked.
    #[must_use]
    pub const fn action(&self) -> ActionKind {
        ActionKind::InstallDependencies
    }

    /// One line for a report, in the shape a check's is.
    #[must_use]
    pub fn plain_description(&self) -> String {
        format!(
            "install the dependencies - not a check. SURE would run `{}`, because {}.",
            self.command, self.says
        )
    }
}

/// What SURE would check in a Python project, what it could not, and the one
/// step that is neither.
///
/// Built from a discovery result and nothing else — see the module
/// documentation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PythonChecks {
    component: Option<String>,
    proposed: Vec<PlannedWork>,
    missing: Vec<MissingCommand>,
    install: Option<InstallStep>,
}

impl PythonChecks {
    /// Everything SURE would check in this project, and everything it could not.
    ///
    /// **One component, because a Python project is one project.** Node walks
    /// workspace members and gives each one its own component; Python's
    /// discovery reads a root `pyproject.toml`, a root `Pipfile` and the
    /// `requirements*.txt` files beside them, and those describe one project
    /// rather than several. Four tool declarations spread over two of them are
    /// one test check, not two.
    ///
    /// **A project with nothing readable is not a project that declares
    /// nothing.** [`Self::component`] is `None` exactly when SURE read no
    /// manifest at all — a `pyproject.toml` that failed to parse and no
    /// `Pipfile` and no requirements file — and the result is a `PythonChecks`
    /// with no proposals and no gaps, for the reason `super::node` gives about a
    /// manifest that could not be read: four "you declare nothing" rows for a
    /// file SURE never opened would be four false statements about the project,
    /// and the unread manifest is already a value in the discovery result.
    ///
    /// **`root` is the project root, and it is a parameter rather than a field of
    /// the discovery result** because every check here is planned as typed work
    /// and [`CommandSpec`](crate::planned_work::CommandSpec) requires an absolute
    /// working directory, while a discovery result carries paths relative to
    /// whatever it was read from. The scan refuses a root that is not absolute
    /// (`scan::open_root`), so the directory handed to a
    /// [`CommandSpec`](crate::planned_work::CommandSpec) is absolute whenever the
    /// discovery is a value at all — which is what makes it a value a runner
    /// could be given rather than a path that happens to look right.
    #[must_use]
    pub fn of(project: &PythonProject, root: &Path) -> Self {
        let mut checks = Self {
            component: component(project),
            proposed: Vec::new(),
            missing: Vec::new(),
            install: None,
        };

        let Some(component) = checks.component.clone() else {
            return checks;
        };

        let runner = Runner::of(&project.managers);
        let installer = runner.installer();
        checks.install = install_step(project, &runner);

        for &(role, check) in CHECKS {
            let id = check_id(&component, &format!("python{}", role.as_str()));
            let title = titled(role);
            // The file this role's check points at. A tool named by its own
            // config file names that file; a tool from a dependency table
            // falls back to the manifest SURE read.
            let declared_in = declared_in_for(project, role, &component);
            // **The plan, asked for once**, and both the line the reason carries
            // and the operation beside it are derived from it: `invocation_for`
            // is what `command_for` renders, so the row a report prints and the
            // program a runner would start cannot come from two decisions.
            let invocation = invocation_for(installer, role, &project.tooling);

            // The order is Node's and the reason is the same: *is the tool
            // declared* is asked before *can SURE tell where it lives*, because
            // a project with neither a linter nor a coherent installer has one
            // problem a person acts on and one they do not, and the sentence
            // should be about the first.
            match (invocation, runner) {
                (None, _) => checks.missing.push(MissingCommand::new(
                    id,
                    title,
                    declared_in.clone(),
                    check.severity,
                    check.critical,
                    gap_kind(project, role),
                )),
                (Some(_), Runner::Unknown { why }) => checks.missing.push(MissingCommand::new(
                    id,
                    title,
                    declared_in.clone(),
                    check.severity,
                    check.critical,
                    MissingKind::NoRunner { why },
                )),
                (Some(invocation), _) => checks.proposed.push(PlannedWork::new(
                    CheckProposal::new(
                        id,
                        title,
                        check.severity,
                        check.critical,
                        // The same answer node's proposer gives, and for the same
                        // reason: a declared command watched for what it does is
                        // deterministic, and the same project state gives the same
                        // answer.
                        EvidenceClass::DeterministicCheck,
                        CheckReason::DeclaredCommand {
                            declared_in,
                            // The rendered line, and only the rendered line: it is
                            // what a report prints, and the program that would run
                            // is the `CommandSpec` beside it. Nothing reads this
                            // string back into a program -- ADR 0014 rejected
                            // exactly that, and the pairing is what makes it
                            // unnecessary.
                            command: invocation.rendered(),
                        },
                        &[check.action],
                    ),
                    command_operation(
                        invocation.program(),
                        root,
                        &invocation
                            .arguments()
                            .iter()
                            .map(String::as_str)
                            .collect::<Vec<_>>(),
                    ),
                )),
            }
        }

        checks
    }

    /// The file SURE read this project from, or `None` when it read no manifest.
    ///
    /// **The file SURE read the project from, and not necessarily the file that
    /// writes the tool's name.** Python spreads declarations over a
    /// `pyproject.toml`, a `Pipfile` and any number of `requirements*.txt`, and
    /// the discovery collects the tools as one list without recording which of
    /// them a package came from — [`Tooling::from`](crate::discover::python::Tooling::from)
    /// is a *directory* and is empty for all of them, because for a root project
    /// that is what it is meant to be. So this answers the question a reader
    /// actually has, *which file do I open*, with the manifest SURE read first,
    /// and `PyProject::dependencies_not_text` and the requirements list are
    /// where a reader who does not find the name goes next. **SURE cannot
    /// confirm which file declared a tool and does not claim to**; naming one of
    /// three on a guess would be the anchorless claim
    /// `docs/architecture/EVIDENCE_MODEL.md` refuses.
    ///
    /// The order is: [`MANIFEST`](crate::discover::python::MANIFEST) when SURE
    /// read one, then [`PIPFILE`] when SURE read one, then the first
    /// `requirements*.txt` in the sorted order the discovery already put them
    /// in.
    #[must_use]
    pub fn component(&self) -> Option<&str> {
        self.component.as_deref()
    }

    /// The checks SURE would run, in no particular order.
    ///
    /// **No particular order is the honest description**: [`PlanBuilder`] sorts
    /// them, and a caller that read an order out of this list would be depending
    /// on the order of [`CHECKS`], which is not a fact about the project.
    ///
    /// Each value is a proposal **with the work that would carry it out** — the
    /// program, its arguments and the directory, as typed fields. A caller that
    /// wants a proposal alone asks a value in this list for one; there is no
    /// second list, because a pair kept in two places can be put together wrong.
    #[must_use]
    pub fn planned(&self) -> &[PlannedWork] {
        &self.proposed
    }

    /// The checks SURE could not propose, one per checked role.
    #[must_use]
    pub fn missing(&self) -> &[MissingCommand] {
        &self.missing
    }

    /// The step that puts the dependencies in place, if the project named one
    /// installer to use.
    ///
    /// `None` in three situations and they are three different facts: the
    /// project names no installer, it names two, or SURE read no manifest. The
    /// **absence of this is not a permission to install** — nothing else in this
    /// module composes an install — it is the absence of a plan to.
    #[must_use]
    pub const fn install(&self) -> Option<&InstallStep> {
        self.install.as_ref()
    }

    /// Whether there is nothing to check and nothing missing.
    ///
    /// **A conjunction, and the second half is the one a mutation can drop.**
    /// True for a project discovery found no readable manifest for, which is a
    /// project SURE has nothing to say about here. False for a project that
    /// declares nothing, which proposes no checks and finds four gaps — and a
    /// caller reading "empty" as "nothing was proposed" would print a report
    /// saying nothing about any of the four roles the acceptance names, which is
    /// the silence [`MissingCommand`] exists to prevent, arriving through the
    /// accessor instead of through the type.
    ///
    /// **The install step is deliberately not in the conjunction.** A project
    /// with an installer and no tools has four gaps and is not empty; a project
    /// with an installer *and* tools has proposals. There is no project with an
    /// install step and neither, because an install step needs a readable
    /// manifest to be attached to and a manifest that declares an installer
    /// almost always declares something else — and where it does not, the four
    /// gaps make it non-empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.proposed.is_empty() && self.missing.is_empty()
    }

    /// Hands every proposal to a plan builder.
    ///
    /// **The install step is not handed over, and this is where that is
    /// decided.** A builder carrying it would put a change to the user's machine
    /// into a schedule of checks, where it would eventually be a
    /// [`CheckResult`](sure_domain::status::CheckResult) — a *verdict about the
    /// project* standing where an unrequested package installation used to be.
    /// The caller that wants to install asks [`Self::install`] for it and takes
    /// it through the consent path, which is the only path in this product that
    /// asks a person a question.
    ///
    /// **The builder's refusals are the record, which is why nothing is
    /// returned here.** [`PlanBuilder::propose`] remembers a refusal even when
    /// its `Err` is dropped, and [`PlanBuilder::refused`] is where a caller
    /// finds them — so a proposal this module got wrong cannot disappear by
    /// being ignored. Nothing this module builds can be refused in the first
    /// place: every proposal has a title, a reason naming a file, and exactly
    /// one action, and `nothing_this_module_builds_is_refused` holds that rather
    /// than this sentence.
    /// **The work is handed over with the proposal, not beside it.** A check
    /// enters the plan as one value carrying both, so a schedule cannot hold a
    /// proposal whose operation stayed behind in this module — see
    /// [`PlanBuilder::propose`].
    pub fn add_to(&self, builder: &mut PlanBuilder) {
        for work in &self.proposed {
            // The `Err` is the refusal, and it is not dropped: `propose` has
            // already pushed it onto the builder's own list by the time this
            // returns it, which is the contract that function documents.
            if let Err(refusal) = builder.propose(work.clone()) {
                debug_assert!(
                    builder.refused().contains(&refusal),
                    "the builder returned a refusal it did not record"
                );
            }
        }
    }

    /// One skipped result per missing command.
    ///
    /// **This is the half of the acceptance that is about absences**, and it is
    /// the only thing this module produces that is a result. A caller that
    /// renders the checks SURE ran and forgets this list has a report that is
    /// silent about every tool the project does not declare; a caller that
    /// renders both cannot show a missing command as anything but something that
    /// was not checked, because [`MissingCommand::not_checked`] has one
    /// constructor to reach for and it is `CheckResult::not_run`.
    #[must_use]
    pub fn not_checked(&self, project_fingerprint: &FingerprintId) -> Vec<CheckResult> {
        self.missing
            .iter()
            .map(|missing| missing.not_checked(project_fingerprint))
            .collect()
    }
}

/// The file a role's check points at.
///
/// A tool named by its own config file names that file; a tool from a
/// dependency table falls back to the manifest SURE read. The check identifier
/// still comes from [`component`], so adding `pytest.ini` to a project does not
/// rename the check a previous run recorded.
fn declared_in_for(project: &PythonProject, role: CommandRole, fallback: &str) -> String {
    tool_role(role)
        .and_then(|wanted| {
            project
                .tooling_of_role(wanted)
                .find_map(|tool| tool.source.as_deref())
        })
        .map_or_else(|| fallback.to_owned(), display_path)
}

/// The file SURE read this project from, or `None` when nothing marks one.
///
/// See [`PythonChecks::component`] for what this does and does not claim. A
/// project with no manifest and no requirements but a dedicated tool config
/// (`pytest.ini`, `ruff.toml`, ...) falls back to that config, so its checks
/// have a component instead of disappearing.
fn component(project: &PythonProject) -> Option<String> {
    if project.manifest.project().is_some() {
        return Some(crate::discover::python::MANIFEST.to_owned());
    }
    if project.pipfile.project().is_some() {
        return Some(PIPFILE.to_owned());
    }
    project
        .requirements
        .first()
        .map(|file| display_path(&file.path))
        .or_else(|| {
            project
                .tooling
                .iter()
                .find_map(|tool| tool.source.as_deref().map(display_path))
        })
}

/// Why there is no command for a role, told apart from a project that declares
/// nothing.
///
/// **The distinction the discovery made and this is where it survives.** A name
/// in [`PyProject::dependencies_not_text`](crate::discover::python::PyProject::dependencies_not_text)
/// is a declaration that is there and unreadable; a project with neither is one
/// that does not declare the tool. A report that showed both as "you declare no
/// type checker" would be describing a manifest with `mypy` in it as a manifest
/// without one, which is the false statement this whole layer exists to refuse.
///
/// Every role [`CHECKS`] holds has a tool role, so the `None` arm below is
/// unreachable from this module — and it is written out rather than unwrapped
/// because `CommandRole::tool_roles` answering [`None`] for
/// [`Install`](CommandRole::Install) is a fact about another module, and a
/// `match` that said so by panicking would turn a change there into a crash in
/// a report. An absent answer is not a declaration SURE failed to read, so
/// [`MissingKind::NotDeclared`] is the honest default.
fn gap_kind(project: &PythonProject, role: CommandRole) -> MissingKind {
    match tool_role(role) {
        Some(role) if project.declares_unreadable(role) => MissingKind::NotReadable,
        _ => MissingKind::NotDeclared,
    }
}

/// The step that puts the dependencies in place, if there is one.
///
/// **Asked of the same [`ConventionalCommand`](crate::discover::python::ConventionalCommand)
/// the checks are built from**, so that a project whose install row has no
/// command cannot have an install step: the two would have to disagree about
/// `CommandRole::Install`, and neither of them decides it.
///
/// **And answered only for a runner that is [`Agreed`](Runner::Agreed)**, which
/// is the one case where there is a file to name. The two branches that are not
/// are not failures: a project that names two installers has no one install
/// command to offer, and a project that names none has nothing to install from.
/// The anchor is the finding the runner was built from rather than a second
/// lookup of it, so this cannot say *declared in `Pipfile`* about an installer
/// the `Pipfile` did not declare — there is no branch in which it could.
fn install_step(project: &PythonProject, runner: &Runner<'_>) -> Option<InstallStep> {
    let Runner::Agreed { installer, found } = runner else {
        return None;
    };
    let conventional = command_for(Some(*installer), CommandRole::Install, &project.tooling);
    let command = conventional.command?;

    Some(InstallStep {
        command,
        because: conventional.because,
        declared_in: display_path(&found.path),
        says: found.says,
    })
}

/// The title a check would have, which is also what a missing command is titled.
///
/// The role's own sentence and nothing else. Node appends a directory because a
/// workspace has several of one role; a Python project has one component, so
/// `run the tests in .` would be noise and `run the tests in pyproject.toml`
/// would be a worse title than the sentence alone.
fn titled(role: CommandRole) -> String {
    role.plain_description().to_owned()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::discover::python::{
        InstallerEvidence, InstallerFinding, ManifestState, PyProject, Requirement,
        RequirementsFile, Tooling, ToolingEvidence,
    };
    use crate::planned_work::CheckOperation;
    use serde_json::json;
    use std::ffi::{OsStr, OsString};
    use std::path::PathBuf;
    use sure_domain::ids::CheckId;
    use sure_domain::status::CheckStatus;

    /// The root these fixtures are read from.
    ///
    /// **A directory and not a manifest path**, because that is what a check's
    /// working directory is: the project root, for a project whose manifest is at
    /// the top of it. Written with a space so that a path assembled by pasting
    /// strings together has somewhere to go wrong — the Windows discipline this
    /// repository holds to — and absolute, because
    /// [`CommandSpec`](crate::planned_work::CommandSpec) refuses anything else.
    ///
    /// **Absolute on the platform this is compiled for, which is why the spelling
    /// forks.** The sentence above was true on Windows and false on the other two
    /// platforms this crate is built for: `C:\projects\my fixture` has no root that
    /// Unix recognises, so off Windows the fixture root was a relative path while
    /// the comment said otherwise. Nothing here asserts absoluteness yet, which is
    /// why only `checks::node`'s copy of this fixture was red — the assertion there
    /// is the one that noticed, and all three are the same decision made once.
    fn root() -> PathBuf {
        if cfg!(windows) {
            PathBuf::from(r"C:\projects\my fixture")
        } else {
            PathBuf::from("/projects/my fixture")
        }
    }

    /// The checks SURE would plan for this project, read from [`root`].
    fn checks_of(project: &PythonProject) -> PythonChecks {
        PythonChecks::of(project, &root())
    }

    /// The proposals alone, for the assertions that are about a proposal.
    fn proposals(checks: &PythonChecks) -> Vec<&CheckProposal> {
        checks.planned().iter().map(PlannedWork::proposal).collect()
    }

    /// The work behind one role's check, by the title a person reads.
    fn work_for(checks: &PythonChecks, role: CommandRole) -> &PlannedWork {
        checks
            .planned()
            .iter()
            .find(|work| work.proposal().title() == role.plain_description())
            .unwrap_or_else(|| panic!("{role:?} was not proposed: {:?}", checks.missing()))
    }

    /// A project whose `pyproject.toml` is this document and whose recognised
    /// tools are these.
    ///
    /// **`tooling` is given rather than derived from the manifest's
    /// `dependencies`, and that is the honest fixture rather than the easy
    /// one.** The mapping from a declared package name to a [`Tooling`] row is
    /// `discover::python`'s `TOOLS` table, reached through a private
    /// `collect_tooling`; deriving it here would be a second copy of that table
    /// in the module that exists to consume its answer. `PythonProject` is a
    /// *discovery result*, this layer receives one, and a fixture standing in
    /// for one has to carry the field a discovery would have filled. The real
    /// mapping is exercised end to end, over `pyproject.toml` files on disk, by
    /// `tests/python_checks.rs`.
    ///
    /// **JSON rather than TOML.** `discover::python`'s own tests parse TOML and
    /// go through `read::to_json`, because the conversion is *its* code and a
    /// private copy beside them would test a conversion nothing runs. This
    /// module is one layer up, `PyProject::from_json` is the boundary it
    /// receives a manifest across, and a fixture that went round it through TOML
    /// would be testing the layer below.
    fn project(manifest: serde_json::Value, tools: &[(&'static str, ToolRole)]) -> PythonProject {
        PythonProject {
            manifest: ManifestState::Read(Box::new(
                PyProject::from_json(&manifest).expect("this fixture is a manifest"),
            )),
            pipfile: ManifestState::Absent,
            managers: Managers::default(),
            requirements: Vec::new(),
            tooling: tooling(tools),
            python: Default::default(),
            unread_legacy: Vec::new(),
        }
    }

    /// The tool rows a discovery would have found, in the table's own names.
    fn tooling(tools: &[(&'static str, ToolRole)]) -> Vec<Tooling> {
        tools
            .iter()
            .map(|&(package, role)| Tooling {
                package,
                role,
                // Empty is what a root project's own tools carry; see
                // `Tooling::from`.
                from: "".into(),
                source: None,
                evidence: ToolingEvidence::Dependency,
            })
            .collect()
    }

    /// A manifest naming the project and nothing else.
    fn empty_manifest() -> serde_json::Value {
        json!({ "project": { "name": "demo" } })
    }

    /// A project that declares nothing at all.
    fn empty_project() -> PythonProject {
        project(empty_manifest(), &[])
    }

    /// A project with no `pyproject.toml` at all, for the shapes built out of
    /// the other files.
    fn no_manifest() -> PythonProject {
        PythonProject {
            manifest: ManifestState::Absent,
            ..empty_project()
        }
    }

    /// The same project, with a lockfile naming one installer.
    fn with_lockfile(
        mut project: PythonProject,
        name: &str,
        installer: Installer,
    ) -> PythonProject {
        project.managers.locked.push(InstallerFinding {
            installer,
            evidence: InstallerEvidence::Lockfile,
            source: Source::new(name, "is a lockfile for this installer"),
        });
        project
    }

    /// Every role, declared.
    const ALL_TOOLS: &[(&str, ToolRole)] = &[
        ("pytest", ToolRole::TestRunner),
        ("ruff", ToolRole::Linter),
        ("mypy", ToolRole::TypeChecker),
        ("setuptools", ToolRole::BuildBackend),
    ];

    /// A project that declares all four roles and one installer.
    fn a_complete_project() -> PythonProject {
        with_lockfile(
            project(
                json!({
                    "project": {
                        "name": "demo",
                        "dependencies": ["pytest", "ruff", "mypy", "setuptools"],
                    },
                }),
                ALL_TOOLS,
            ),
            "uv.lock",
            Installer::Uv,
        )
    }

    /// A project that declares one tool and two installers.
    ///
    /// Mid-migration, which Python can be in a way Node cannot: `[tool.poetry]`
    /// in the manifest and a `uv.lock` beside it are two real pieces of evidence
    /// pointing two ways.
    fn split_project() -> PythonProject {
        let mut found = with_lockfile(
            project(
                json!({ "project": { "name": "demo", "dependencies": ["pytest"] } }),
                &[("pytest", ToolRole::TestRunner)],
            ),
            "uv.lock",
            Installer::Uv,
        );
        found.managers.configured.push(InstallerFinding {
            installer: Installer::Poetry,
            evidence: InstallerEvidence::Declared,
            source: Source::new("pyproject.toml", "declares this installer"),
        });
        found
    }

    /// A project whose manifest declares pytest the only way SURE can see it.
    fn pytest_project() -> PythonProject {
        project(
            json!({ "project": { "name": "demo", "dependencies": ["pytest"] } }),
            &[("pytest", ToolRole::TestRunner)],
        )
    }

    /// A Poetry project whose dependency table is these entries.
    ///
    /// **The tools are empty on purpose, and that is the whole shape.** Poetry's
    /// table form is a declaration SURE can see and cannot read, so the names in
    /// it never reach `TOOLS` and a discovery running over this manifest would
    /// report no tooling at all. A fixture that pushed a [`Tooling`] row anyway
    /// would be testing a project this module can never be handed.
    fn poetry_project(dependencies: serde_json::Value) -> PythonProject {
        with_lockfile(
            project(
                json!({
                    "tool": { "poetry": { "dependencies": dependencies } },
                }),
                &[],
            ),
            "poetry.lock",
            Installer::Poetry,
        )
    }

    /// A `Pipfile` and nothing else, which is a whole Python project to SURE.
    ///
    /// No `pyproject.toml` at all, so the component is the `Pipfile` and the
    /// installer is the one that file names. The anchor a step gets here is the
    /// **configured** tier's, which the lockfile fixture does not reach: a
    /// module that only ever saw a lockfile could hard-code the lockfile's
    /// sentence and pass.
    fn pipenv_project() -> PythonProject {
        let mut found = no_manifest();
        found.pipfile = ManifestState::Read(Box::new(
            PyProject::from_json(&json!({ "packages": { "pytest": "*" } }))
                .expect("this fixture is a Pipfile"),
        ));
        found.managers.configured.push(InstallerFinding {
            installer: Installer::Pipenv,
            evidence: InstallerEvidence::Declared,
            source: Source::new(PIPFILE, "is this installer's own manifest"),
        });
        found
    }

    /// The gap for one role, by the title a person reads.
    fn gap_for(checks: &PythonChecks, role: CommandRole) -> &MissingKind {
        checks
            .missing()
            .iter()
            .find(|missing| missing.title() == role.plain_description())
            .unwrap_or_else(|| panic!("{role:?} has a command, so there is no gap to read"))
            .kind()
    }

    #[test]
    fn the_table_covers_the_three_roles_the_acceptance_names_and_the_fourth_it_implies() {
        // The claim this module's headline makes, held against the table rather
        // than against a paragraph: the three words the acceptance spells, then
        // `Build`. A role added here, or one of these dropped, fails.
        let roles: Vec<CommandRole> = CHECKS.iter().map(|(role, _)| *role).collect();
        assert_eq!(
            roles,
            vec![
                CommandRole::Test,
                CommandRole::Lint,
                CommandRole::TypeCheck,
                CommandRole::Build,
            ],
            "the checked roles are not the ones this module argues for"
        );

        // And the two that are absent are absent for the reason the module
        // documentation gives: one is not a check at all and one writes files.
        for role in CommandRole::ALL {
            let checked = roles.contains(role);
            let expected = !matches!(role, CommandRole::Install | CommandRole::Format);
            assert_eq!(checked, expected, "{role:?} is on the wrong side");
        }
    }

    #[test]
    fn the_table_carries_the_three_weighted_roles_and_the_one_that_is_not() {
        // The policy, pinned rather than left to four fields a reader compares
        // by eye. `RoleCheck::critical` argues that failing tests and a
        // distribution that will not build are reasons not to hand a project
        // over while a lint and a type check that fail are findings about
        // quality — and `P4-T002`'s mutation set found that prose alone holds
        // nothing: moving the lint's weight and the type check's criticality
        // passed its whole suite, which is why the same table is pinned here
        // before the same defect can arrive.
        let table: Vec<(CommandRole, ActionKind, Severity, bool)> = CHECKS
            .iter()
            .map(|(role, check)| (*role, check.action, check.severity, check.critical))
            .collect();
        assert_eq!(
            table,
            vec![
                (
                    CommandRole::Test,
                    ActionKind::RunTests,
                    Severity::MustFix,
                    true
                ),
                (
                    CommandRole::Lint,
                    ActionKind::Lint,
                    Severity::CanFixLater,
                    false
                ),
                (
                    CommandRole::TypeCheck,
                    ActionKind::TypeCheck,
                    Severity::ShouldFixFirst,
                    false
                ),
                (
                    CommandRole::Build,
                    ActionKind::Build,
                    Severity::MustFix,
                    true
                ),
            ],
            "a role's check, its action, its weight or its criticality moved, and \
             the prose above the table is the only thing that still says why"
        );
    }

    #[test]
    fn every_checked_role_executes_project_code() {
        // Read out of the domain rather than trusted to this module's table: if
        // any of the four actions did not execute project code, the check would
        // be one `InspectOnly` allows and the gating the acceptance leans on
        // would be absent.
        for (role, check) in CHECKS {
            assert!(
                check.action.executes_project_code(),
                "{role:?} is gated by the mode only because its action executes \
                 project code, and {:?} does not",
                check.action
            );
        }
    }

    #[test]
    fn nothing_this_module_proposes_installs_anything() {
        // **The acceptance, as a property of every proposal this module can
        // build.** *Without silent package installation* is not a rule about one
        // role; it is a rule about the whole set, and the way to hold it is over
        // every project shape rather than over the one someone thought of. Each
        // of these declares a different combination, and between them they
        // produce every branch `of` can take: proposals, all four gaps, a
        // refusal for a disagreement, and no component at all.
        let fixtures: Vec<(&str, PythonProject)> = vec![
            ("a complete project", a_complete_project()),
            (
                "a project that declares nothing",
                with_lockfile(empty_project(), "uv.lock", Installer::Uv),
            ),
            (
                "a project that declares one tool and no installer",
                pytest_project(),
            ),
            ("a project that names two installers", split_project()),
            ("a project SURE read no manifest of", unreadable_project()),
        ];

        let mut proposed = 0;
        for (what, project) in &fixtures {
            let checks = checks_of(project);
            for proposal in proposals(&checks) {
                proposed += 1;
                assert!(
                    !proposal
                        .requirements()
                        .actions()
                        .contains(&ActionKind::InstallDependencies),
                    "{what}: {} would install packages, which is the one thing a \
                     check must never do",
                    proposal.title()
                );
                assert!(
                    !proposal.requirements().runs_nothing(),
                    "{what}: {} runs nothing",
                    proposal.title()
                );
            }
            // And the install, where there is one, is not in that list: it is a
            // value of a type that cannot reach a schedule.
            if let Some(step) = checks.install() {
                assert_eq!(step.action(), ActionKind::InstallDependencies);
                assert!(
                    step.action().executes_project_code(),
                    "an install runs the installer, which is project code by the \
                     domain's own definition"
                );
                assert!(
                    !proposals(&checks)
                        .iter()
                        .any(|proposal| proposal.reason().names_something()
                            && matches!(
                                proposal.reason(),
                                CheckReason::DeclaredCommand { command, .. }
                                    if command == step.command()
                            )),
                    "{what}: the install command is also a check's command"
                );
            }
        }
        assert_eq!(proposed, 5, "the sweep did not visit the shapes it claims");
    }

    #[test]
    fn a_project_with_an_installer_and_no_tools_has_a_step_and_four_gaps() {
        // The two halves are not substitutes. A project that declares only an
        // installer gets no checks at all and one install step — and a caller
        // that rendered the step as the plan would be showing a report with
        // nothing in it about tests.
        let checks = checks_of(&with_lockfile(empty_project(), "uv.lock", Installer::Uv));
        assert!(checks.planned().is_empty());
        assert_eq!(checks.missing().len(), 4);
        assert!(!checks.is_empty());

        let step = checks.install().expect("the lockfile names an installer");
        assert_eq!(step.command(), "uv sync");
        assert_eq!(step.declared_in(), "uv.lock");
        assert_eq!(step.says(), "is a lockfile for this installer");
        assert_eq!(step.action(), ActionKind::InstallDependencies);
        assert!(step.plain_description().contains("uv sync"), "{step:?}");
        assert!(
            step.plain_description().contains("not a check"),
            "the line a person reads has to say what this is: {}",
            step.plain_description()
        );
    }

    #[test]
    fn the_install_step_names_the_file_that_decided_and_says_what_that_file_is() {
        // Two tiers and two sentences, from two different files, so neither can
        // be a constant this module writes. The step carries the finding's own
        // `says` rather than composing one about it: a module that described
        // every anchor as a lockfile would be telling a person their `Pipfile`
        // is a lockfile, and the sentence is the only part of the step a reader
        // sees.
        let locked = checks_of(&with_lockfile(empty_project(), "uv.lock", Installer::Uv));
        let step = locked.install().expect("the lockfile names an installer");
        assert_eq!(step.declared_in(), "uv.lock");
        assert_eq!(step.says(), "is a lockfile for this installer");
        assert_eq!(step.command(), "uv sync");

        let configured = checks_of(&pipenv_project());
        assert_eq!(configured.component(), Some(PIPFILE));
        let step = configured
            .install()
            .expect("the Pipfile names an installer");
        assert_eq!(step.declared_in(), PIPFILE);
        assert_eq!(step.says(), "is this installer's own manifest");
        assert_eq!(step.command(), "pipenv install");
    }

    #[test]
    fn a_project_that_declares_no_installer_has_no_install_step_and_still_gets_checks() {
        // Not a failure, and the difference from node is the point. Node without
        // a package manager has no command at all; Python without an installer
        // has `python -m pytest`, which is a complete command and the only
        // interpreter SURE can name.
        let checks = checks_of(&pytest_project());
        assert!(checks.install().is_none(), "{:?}", checks.install());
        assert_eq!(checks.planned().len(), 1);
        assert_eq!(
            command_of(&checks, CommandRole::Test),
            "python -m pytest",
            "with no installer the tool is run as a module of the interpreter, \
             and not through a manager nobody named"
        );

        // And the three it does not declare are gaps about the project rather
        // than about a runner, so the sentence a person reads is the one they
        // act on.
        for role in [
            CommandRole::Lint,
            CommandRole::TypeCheck,
            CommandRole::Build,
        ] {
            assert_eq!(
                gap_for(&checks, role),
                &MissingKind::NotDeclared,
                "{role:?}"
            );
        }
    }

    #[test]
    fn two_installers_are_a_refusal_and_not_a_command_for_a_third_interpreter() {
        // **The case `command_for` gets wrong on its own.** It answers
        // `python -m pytest` for a project that named two environments, and that
        // is neither of them: running it produces `No module named pytest`,
        // which is false about a project that declares pytest and true only
        // about the interpreter SURE picked. A visible gap is better than a
        // misleading error.
        let split = split_project();
        assert_eq!(
            split.managers.agreed(),
            None,
            "the fixture is supposed to be a disagreement"
        );

        // The discovery plans a command for this project, and this module
        // refuses it anyway. Stated as a value rather than as a sentence, so
        // that a later change to `command_for` cannot quietly make the refusal
        // unnecessary and leave the test passing for the wrong reason.
        let planned = command_for(None, CommandRole::Test, &split.tooling).command;
        assert_eq!(planned.as_deref(), Some("python -m pytest"));

        let checks = checks_of(&split);
        assert!(
            checks.planned().is_empty(),
            "a command for the wrong interpreter is not a check: {:?}",
            checks.planned()
        );
        match gap_for(&checks, CommandRole::Test) {
            MissingKind::NoRunner { why } => {
                // The discovery's own sentence for this disagreement, not a
                // sentence this module wrote: which way the project failed to
                // answer is a fact the discovery established and knows the shape
                // of, and a second wording here would be a second thing to keep
                // in step.
                assert_eq!(
                    *why,
                    crate::discover::python::Disagreement::ConfigurationAndLockfile {
                        configured: Installer::Poetry,
                        locked: Installer::Uv,
                    }
                    .plain_description(),
                    "the refusal does not say what is wrong with the project"
                );
            }
            other => panic!("the test gap is {other:?}"),
        }

        // And no install either: the project that cannot say which installer it
        // uses has no install plan, which is the same answer `command_for` gives
        // for `Install` and the one this module agrees with.
        assert!(checks.install().is_none());
    }

    #[test]
    fn a_declaration_sure_could_not_read_is_not_a_project_that_declares_nothing() {
        // Poetry's table form is ordinary, valid and unreadable to a reader that
        // will not guess. `mypy` is declared; it is not in the tooling list; and
        // a report built from that list alone would say "you declare no type
        // checker" about a manifest with `mypy` written in it.
        let checks = checks_of(&poetry_project(json!({
            "mypy": { "version": "^1.8", "extras": ["types-requests"] },
        })));

        assert_eq!(
            gap_for(&checks, CommandRole::TypeCheck),
            &MissingKind::NotReadable,
            "an unreadable declaration is not a missing one"
        );
        assert_eq!(
            gap_for(&checks, CommandRole::Test),
            &MissingKind::NotDeclared,
            "and a role the project says nothing about is still reported as \
             nothing said"
        );
        assert_ne!(
            MissingKind::NotReadable.plain_explanation(),
            MissingKind::NotDeclared.plain_explanation(),
            "the two are different facts and a report that renders them the same \
             way has turned one into the other"
        );
    }

    #[test]
    fn the_tool_role_this_asks_about_is_the_one_the_command_is_built_from() {
        // `gap_kind` asks `TOOLS` about a role, and `command_for` builds the
        // command from the same answer. A second table here would be a copy that
        // stops agreeing the day `CommandRole::tool_roles` changes, and the
        // symptom would be a project reported as declaring nothing while its
        // command sits in the proposal next to the gap.
        for (role, _) in CHECKS {
            let wanted = tool_role(*role);
            assert_eq!(
                wanted,
                role.tool_roles().first().copied(),
                "{role:?} asks about a different tool role than the one its \
                 command is built from"
            );
        }
        // Written out per role rather than swept, because the interesting
        // answers are the two that are not a tool being run directly: `Install`
        // has no tool role at all — the installer answers it — and `Build`'s is
        // a library the frontend calls rather than a command.
        assert_eq!(tool_role(CommandRole::Test), Some(ToolRole::TestRunner));
        assert_eq!(tool_role(CommandRole::Lint), Some(ToolRole::Linter));
        assert_eq!(
            tool_role(CommandRole::TypeCheck),
            Some(ToolRole::TypeChecker)
        );
        assert_eq!(tool_role(CommandRole::Build), Some(ToolRole::BuildBackend));
        assert_eq!(tool_role(CommandRole::Format), Some(ToolRole::Formatter));
        assert_eq!(tool_role(CommandRole::Install), None);
    }

    #[test]
    fn a_project_sure_read_no_manifest_of_is_neither_a_check_nor_a_gap() {
        // The false green this module is arranged against: a `pyproject.toml`
        // that failed to parse declares no tools — and so does a project with no
        // manifest, and so does a project with three of them unreadable. Four
        // gaps here would say "your project declares nothing" about a file SURE
        // never read.
        let checks = checks_of(&unreadable_project());
        assert!(checks.is_empty(), "{checks:?}");
        assert!(checks.component().is_none());
        assert!(checks.install().is_none());
        assert!(checks.not_checked(&FingerprintId::generate()).is_empty());
    }

    #[test]
    fn the_component_is_the_manifest_sure_read_and_not_a_guess_at_the_file() {
        // Three shapes, three answers, and the order between them is the
        // documented one: the modern manifest, then pipenv's, then the first
        // requirements file. A project with a `pyproject.toml` and a `Pipfile`
        // gets one set of checks rather than two, because the two files describe
        // one project.
        let both = {
            let mut found = pytest_project();
            found.pipfile = ManifestState::Read(Box::new(pipfile()));
            found
        };
        let checks = checks_of(&both);
        assert_eq!(checks.component(), Some("pyproject.toml"));
        assert_eq!(
            checks.planned().len() + checks.missing().len(),
            4,
            "two manifests describing one project are four roles, not eight"
        );

        let pipfile_only = {
            let mut found = no_manifest();
            found.pipfile = ManifestState::Read(Box::new(pipfile()));
            found
        };
        assert_eq!(
            checks_of(&pipfile_only).component(),
            Some("Pipfile"),
            "a project with no pyproject.toml must not be given one's name"
        );

        let requirements_only = {
            let mut found = no_manifest();
            found
                .requirements
                .push(requirements_file("requirements-dev.txt"));
            found
        };
        assert_eq!(
            checks_of(&requirements_only).component(),
            Some("requirements-dev.txt")
        );
    }

    /// A `Pipfile` read by the same accessors.
    fn pipfile() -> PyProject {
        PyProject::from_json(&json!({ "packages": { "ruff": "*" } }))
            .expect("this fixture is a Pipfile")
    }

    /// One `requirements*.txt` naming pytest.
    fn requirements_file(path: &str) -> RequirementsFile {
        RequirementsFile {
            path: path.into(),
            requirements: vec![Requirement {
                name: "pytest".to_owned(),
                line: "pytest==8.0.0".to_owned(),
            }],
            directives: Vec::new(),
            comments: 0,
            truncated: false,
        }
    }

    #[test]
    fn a_tool_from_a_config_file_names_that_file_in_the_reason() {
        let mut project = project(
            json!({ "project": { "name": "demo" } }),
            &[("pytest", ToolRole::TestRunner)],
        );
        project.tooling[0].source = Some(PathBuf::from("pytest.ini"));

        let checks = checks_of(&project);
        match work_for(&checks, CommandRole::Test).proposal().reason() {
            CheckReason::DeclaredCommand {
                declared_in,
                command,
            } => {
                assert_eq!(declared_in, "pytest.ini");
                assert_eq!(command, "python -m pytest");
            }
            other => panic!("a declared test check carries {other:?}"),
        }
    }

    #[test]
    fn a_config_only_project_has_a_component_and_is_not_silent() {
        let mut project = project(
            json!({ "project": { "name": "demo" } }),
            &[("pytest", ToolRole::TestRunner)],
        );
        project.manifest = ManifestState::Absent;
        project.tooling[0].source = Some(PathBuf::from("pytest.ini"));

        assert_eq!(component(&project).as_deref(), Some("pytest.ini"));
    }

    #[test]
    fn a_declared_tool_becomes_a_check_carrying_its_own_line_and_its_own_identity() {
        // What a proposal has to be for the rest of the product to work: a
        // command a person can read before it runs, a reason naming the file
        // SURE read, the deterministic weight, and an identity that is the same
        // on the next run — the last because a result is compared against the
        // run before it, and an identity that moved with the *plan* rather than
        // the project would make every comparison a difference.
        let found = with_lockfile(
            project(
                json!({
                    "project": { "name": "demo", "dependencies": ["pytest", "ruff"] },
                }),
                &[("pytest", ToolRole::TestRunner), ("ruff", ToolRole::Linter)],
            ),
            "uv.lock",
            Installer::Uv,
        );

        let checks = checks_of(&found);
        assert_eq!(checks.planned().len(), 2, "{:?}", checks.missing());
        assert_eq!(command_of(&checks, CommandRole::Test), "uv run pytest");
        assert_eq!(
            command_of(&checks, CommandRole::Lint),
            "uv run ruff check ."
        );

        for proposal in proposals(&checks) {
            assert_eq!(
                proposal.evidence_class(),
                EvidenceClass::DeterministicCheck,
                "{} was proposed with the wrong weight",
                proposal.title()
            );
            match proposal.reason() {
                CheckReason::DeclaredCommand {
                    declared_in,
                    command,
                } => {
                    assert_eq!(declared_in, "pyproject.toml");
                    assert!(command.starts_with("uv run "), "{command}");
                }
                other => panic!("{} has the reason {other:?}", proposal.title()),
            }
            assert_eq!(proposal.requirements().actions().len(), 1);
        }

        // Same project, same identities, and the two are not the same identity
        // as each other — the tag is what tells the two checks apart, and a tag
        // built from the role's *title* rather than its wire name would still
        // pass that and would fail the day two roles shared a first word.
        let again = checks_of(&found);
        let ids: Vec<&CheckId> = proposals(&checks)
            .into_iter()
            .map(CheckProposal::id)
            .collect();
        assert_eq!(
            ids,
            proposals(&again)
                .into_iter()
                .map(CheckProposal::id)
                .collect::<Vec<_>>()
        );
        assert_ne!(ids[0], ids[1]);
        assert_eq!(
            ids[0].as_str(),
            check_id("pyproject.toml", "pythontest").as_str()
        );
        assert_eq!(
            ids[1].as_str(),
            check_id("pyproject.toml", "pythonlint").as_str()
        );
    }

    #[test]
    fn the_work_behind_a_check_is_the_typed_form_of_the_line_a_report_prints() {
        // **The pairing, held rather than asserted about.** A report prints
        // `uv run pytest` and a runner is handed a program and an argument
        // vector; the two are one value seen twice, so rendering the vector has
        // to give back the line a person was shown — over every role, including
        // the one whose command is not the tool at all (`Build`'s frontend).
        let checks = checks_of(&a_complete_project());
        let expected: &[(CommandRole, &str, &[&str])] = &[
            (CommandRole::Test, "uv", &["run", "pytest"]),
            (CommandRole::Lint, "uv", &["run", "ruff", "check", "."]),
            (CommandRole::TypeCheck, "uv", &["run", "mypy", "."]),
            // `setuptools` is a library rather than a command, so the plan is
            // the frontend's own subcommand.
            (CommandRole::Build, "uv", &["build"]),
        ];
        assert_eq!(
            checks.planned().len(),
            expected.len(),
            "{:?}",
            checks.missing()
        );

        for (role, program, arguments) in expected {
            let work = work_for(&checks, *role);
            let CheckReason::DeclaredCommand { command, .. } = work.proposal().reason() else {
                panic!("{role:?} is not a declared command");
            };
            let CheckOperation::Command(spec) = work.operation() else {
                panic!(
                    "{role:?} is not a command operation: {:?}",
                    work.operation()
                );
            };

            assert_eq!(spec.program(), OsStr::new(*program), "{role:?}");
            // **A name, and not one this module completed.** On Windows a name
            // Windows cannot complete is not a program, and appending `.cmd` or
            // `.exe` to make it one would be SURE inventing a program — see the
            // module documentation.
            assert!(
                !spec.program().to_string_lossy().contains('.'),
                "{role:?} names a program with an extension: {:?}",
                spec.program()
            );
            let planned: Vec<OsString> = arguments.iter().map(OsString::from).collect();
            assert_eq!(spec.arguments(), planned.as_slice(), "{role:?}");
            assert_eq!(spec.working_directory(), root(), "{role:?}");

            // The line and the vector cannot describe different commands: the
            // line *is* this vector rendered, character for character.
            let rendered = std::iter::once(spec.program().to_owned())
                .chain(spec.arguments().iter().cloned())
                .map(|word| word.to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join(" ");
            assert_eq!(&rendered, command, "{role:?}");
        }

        // And the other spelling of a plan: no installer at all is
        // `python -m <tool>`, which is the only interpreter SURE can name and is
        // not a guess at which one is first on the path.
        let without = checks_of(&pytest_project());
        let work = work_for(&without, CommandRole::Test);
        let CheckOperation::Command(spec) = work.operation() else {
            panic!("the test check is not a command operation");
        };
        assert_eq!(spec.program(), OsStr::new("python"));
        assert_eq!(
            spec.arguments(),
            [OsString::from("-m"), OsString::from("pytest")].as_slice()
        );
    }

    #[test]
    fn nothing_this_module_builds_is_refused_and_the_plan_holds_everything() {
        // `add_to` ignores a refusal because the builder records it, which is
        // only an acceptable design while nothing is ever refused. This is the
        // test that would fail first if a proposal here lost its title, its
        // reason or its action.
        let checks = checks_of(&a_complete_project());
        let mut builder = PlanBuilder::new(
            sure_domain::execution::ExecutionMode::HostConfirmed,
            sure_domain::execution::ExecutionPermissions {
                run_project_code: true,
                ..sure_domain::execution::ExecutionPermissions::inspect_only()
            },
        );
        checks.add_to(&mut builder);

        assert!(builder.refused().is_empty(), "{:?}", builder.refused());
        let schedule = builder.build();
        assert_eq!(schedule.len(), checks.planned().len());
        assert!(
            schedule.duplicates().is_empty(),
            "{:?}",
            schedule.duplicates()
        );
        assert_eq!(schedule.may_run().count(), schedule.len());
        assert!(schedule.get(proposals(&checks)[0].id()).is_some());

        // And the install is not in the schedule, which is the whole reason it is
        // a separate type: a schedule entry can come back as a result, and an
        // install has nothing to say about whether the project is any good.
        let step = checks.install().expect("the fixture names an installer");
        assert!(
            !schedule.checks().iter().any(|entry| {
                entry.proposal().title() == step.plain_description()
                    || matches!(
                        entry.proposal().reason(),
                        CheckReason::DeclaredCommand { command, .. }
                            if command == step.command()
                    )
            }),
            "the install reached the schedule: {:?}",
            schedule.checks()
        );
        // The four checks are the four the table names, and the install would
        // have had to displace one of them to get in.
        assert_eq!(
            schedule
                .checks()
                .iter()
                .map(|entry| entry.proposal().title())
                .collect::<Vec<_>>()
                .len(),
            CHECKS.len()
        );
    }

    #[test]
    fn a_missing_command_is_a_skipped_result_and_never_a_pass() {
        // From the module that has to satisfy the clause, over the projects that
        // produce each kind. `not_checked` is the only result-producing function
        // here and this is what it may produce.
        let fingerprint = FingerprintId::generate();
        for (what, project) in [
            (
                "declares nothing",
                with_lockfile(empty_project(), "uv.lock", Installer::Uv),
            ),
            (
                "declares something unreadable",
                poetry_project(json!({ "mypy": { "version": "^1.8" } })),
            ),
        ] {
            let checks = checks_of(&project);
            let results = checks.not_checked(&fingerprint);
            assert_eq!(results.len(), checks.missing().len(), "{what}");
            assert_eq!(results.len(), 4, "{what}");
            for result in &results {
                assert_eq!(
                    result.status,
                    CheckStatus::Skipped,
                    "{what}: {}",
                    result.title
                );
                assert!(!result.status.is_green(), "{what}: {}", result.title);
                assert!(
                    !result.status.produced_a_result(),
                    "{what}: {}",
                    result.title
                );
                assert!(result.is_not_checked(), "{what}: {}", result.title);
                assert!(!result.reason.trim().is_empty(), "{what}: {}", result.title);
                assert_eq!(result.project_fingerprint, fingerprint, "{what}");
            }
        }

        // The scope-limit split, which is the part that decides whether a
        // critical check holds the run out of green. A project that declares
        // nothing is out of scope for all four; a project whose manifest SURE
        // could not read a declaration out of is a project with something to fix,
        // and the one critical role among its gaps must block.
        let declares_nothing = checks_of(&with_lockfile(empty_project(), "uv.lock", Installer::Uv));
        let results = declares_nothing.not_checked(&fingerprint);
        assert!(
            results.iter().all(|result| !result.blocks_green()),
            "a project that declares no test runner is not a project SURE should \
             refuse to call green: {:?}",
            results
                .iter()
                .filter(|result| result.blocks_green())
                .map(|result| result.title.as_str())
                .collect::<Vec<_>>()
        );

        let unreadable = checks_of(&poetry_project(json!({
            "pytest": { "version": "^8", "extras": ["dev"] },
        })));
        let results = unreadable.not_checked(&fingerprint);
        let blocking: Vec<&str> = results
            .iter()
            .filter(|result| result.blocks_green())
            .map(|result| result.title.as_str())
            .collect();
        assert_eq!(
            blocking,
            vec![CommandRole::Test.plain_description()],
            "a manifest SURE cannot read is a defect the user can fix, so the one \
             critical gap among these must keep the run out of green"
        );
    }

    /// A project whose only manifest SURE could not read.
    fn unreadable_project() -> PythonProject {
        PythonProject {
            manifest: ManifestState::Unread(crate::discover::UnreadReason::WrongShape {
                found: "an array",
            }),
            pipfile: ManifestState::Absent,
            managers: Managers::default(),
            requirements: Vec::new(),
            tooling: Vec::new(),
            python: Default::default(),
            unread_legacy: Vec::new(),
        }
    }

    /// The command a role's proposal carries, or a panic naming the gap.
    fn command_of(checks: &PythonChecks, role: CommandRole) -> String {
        proposals(checks)
            .into_iter()
            .find(|proposal| proposal.title() == role.plain_description())
            .map_or_else(
                || panic!("{role:?} has no command: {:?}", checks.missing()),
                |proposal| match proposal.reason() {
                    CheckReason::DeclaredCommand { command, .. } => command.clone(),
                    other => panic!("the {role:?} check's reason is {other:?}"),
                },
            )
    }
}
