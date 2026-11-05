//! The checks a JavaScript or TypeScript project's own scripts turn into.
//!
//! `P4-T002`'s acceptance, and it is two sentences:
//!
//! > *Declared build/lint/type/test checks run only under allowed execution
//! > mode. Missing commands are not passes.*
//!
//! # The four roles, and the four this module ignores
//!
//! [`ScriptRole`] has eight variants and SURE proposes checks for four of them.
//! The four it ignores are [`Format`](ScriptRole::Format),
//! [`Dev`](ScriptRole::Dev), [`Start`](ScriptRole::Start) and
//! [`Clean`](ScriptRole::Clean), and the reason is what each one does to a
//! project rather than how useful it is:
//!
//! - `format` and `clean` **write**. Reformatting every file and deleting build
//!   output are the two most destructive things in a `package.json`, and neither
//!   is a check — there is no question they answer. `ActionKind` has no variant
//!   for them either, which is the domain saying the same thing.
//! - `dev` and `start` **do not finish**. They are servers, and a check is
//!   something that ends. Starting one is what [`crate::service`] and
//!   `checks.browser_probe` are for, with their own permissions and their own
//!   timeouts.
//!
//! The four that remain are exactly the four the acceptance names, and
//! `the_table_covers_the_four_roles_the_acceptance_names` is what says so
//! rather than this paragraph.
//!
//! **`P5-T001` kept the half of that second bullet this module could only
//! promise.** [`crate::runtime_probes`] reads `start` and `dev` — through
//! [`command_for`] below, which is why that function and [`Runner`] stopped
//! being private to this file — and turns the command into a check that starts
//! the project and looks at it. **Neither role becomes a check here**, and the
//! distinction that keeps that true is the acceptance's rather than a style
//! choice: what a check *is* has not changed, and what changed is that the thing
//! which starts a server is now a plan entry rather than an absence.
//!
//! # Why every check here is gated without this module deciding anything
//!
//! The four [`ActionKind`]s the table below names — `Build`, `RunTests`, `Lint`
//! and `TypeCheck` — are four of the seven for which
//! [`executes_project_code`](ActionKind::executes_project_code) answers `true`.
//! That is the whole of the first acceptance sentence: a plan entry's decision
//! is its requirements' decision, the requirements' decision is the worst of its
//! actions' decisions, and
//! [`decide`](sure_domain::execution::decide) refuses an action that executes
//! project code under
//! [`InspectOnly`](sure_domain::execution::ExecutionMode::InspectOnly). Nothing
//! here compares a mode to anything, and `tests/node_checks.rs` checks the
//! consequences rather than the mechanism: under the inspect-only mode every
//! declared check comes back as one that would not run, and it is
//! [`ScheduledCheck::not_run`](crate::schedule::ScheduledCheck::not_run) that
//! turns it into a skipped result.
//!
//! # Why a missing command is a value and not a silence
//!
//! See [`MissingCommand`]. The short version: a check that cannot be proposed
//! produces no plan entry, so a report built from the plan would say nothing at
//! all about a project with no test script — and a reader takes the absence of a
//! row for the absence of a problem. Every one of the four roles produces
//! *something* for every readable manifest: a proposal where there is a command,
//! and a recorded gap where there is not.
//!
//! # The three ways a project leaves SURE without a command
//!
//! They are [`MissingKind`]'s variants and they are not the same fact:
//!
//! 1. **The script is not declared.**
//!    [`Package::script`](crate::discover::node::Package::script) answers `None`
//!    under the role's conventional name, and
//!    [`ScriptRole::conventional_name`] documents why the matching is exact: a
//!    project that spelled its test script `test:unit` has not declared a `test`
//!    script, and mapping one to the other would be SURE inventing a convention
//!    and then running a command on the strength of it.
//! 2. **The script is declared and its value is not a command.** The name is in
//!    [`Package::scripts_not_commands`](crate::discover::node::Package::scripts_not_commands),
//!    where the discovery put it precisely so that "there and unusable" would
//!    not read as "not there".
//! 3. **The script is declared and nothing says what runs it.**
//!    [`Managers::agreed`](crate::discover::node::Managers::agreed) answers
//!    `None`, and it answers `None` for two different reasons which
//!    [`Runner`] keeps apart in the sentence.
//!
//! # A check is planned as work, and not only as a line
//!
//! Since `P18-T003` every check here is a proposal **and the operation that would
//! carry it out** ([`PlannedWork`](crate::planned_work::PlannedWork)): the program
//! is the package manager's own name, the arguments are the script's own name
//! after `run` where the manager needs one, and the directory is the component's —
//! the project root for the project's own manifest and the member's own directory
//! for a workspace member's.
//!
//! **The rendered command stays a rendering.**
//! [`CheckReason::DeclaredCommand`] still carries `npm run build`, because that is
//! what a report prints and what a person is being asked to allow, and nothing
//! reads it back into a program: ADR 0014 rejected exactly that, and the pairing is
//! what makes it unnecessary. The two are one decision shown twice —
//! `discover::node`'s `invocation_for` holds the program and the vector and
//! `command_for` renders it — so the line and the program cannot come apart, and
//! `the_work_behind_a_check_is_the_typed_form_of_the_line_a_report_prints` holds
//! that over every manager and all four roles.
//!
//! **The manager's name is not rewritten for the platform.** On Windows a bare
//! `npm` is a name Windows completes with `.exe` and nothing else, so a project
//! whose only manager is `npm.cmd` plans the name as written; appending `.cmd`
//! — or wrapping the name in `cmd.exe /c`, which is what the operating system
//! would do — would be constructing the interpreter ADR 0014 says SURE must not
//! build. What the runner does with that name is
//! [`crate::package_launcher`]'s question: on the product path a known manager
//! shim, with `node` and the manager's own shipped JavaScript entry present, is
//! started as `node <entry> <the plan's arguments>`, so the check runs without
//! ever naming the batch file. Every other shape keeps the honest
//! not-startable result.
//!
//! # What it does not do
//!
//! **It does not look at `node_modules`.** Nothing here can tell whether a
//! declared command is *installed*, so a `"test": "jest"` in a project that has
//! never run `npm install` is proposed exactly like one in a project that has.
//! That is not an oversight: whether the tool is installed is a fact about this
//! machine, it is discovered by running the command, and the run is the check.
//! The support level in the discovery report is where "SURE has read this but
//! run nothing" is said.
//!
//! **It does not resolve a workspace pattern.** The members are the ones the
//! discovery resolved, including the ones it could not read — those are in
//! [`Workspaces::unresolved`](crate::discover::node::Workspaces::unresolved)
//! and are not components here, because a directory SURE could not resolve is
//! not a directory it can say anything true about.
//!
//! **It does not deduplicate a root script that fans out.** A workspace root
//! with `"build": "turbo run build"` and three members each declaring their own
//! `build` gets four build checks, and running the root's runs the members' work
//! again. That is honest — all four are declared, and none of them is SURE's to
//! drop — and it is wasteful, which is stated here rather than discovered later.

use std::path::Path;

use sure_domain::evidence::EvidenceClass;
use sure_domain::execution::ActionKind;
use sure_domain::ids::FingerprintId;
use sure_domain::severity::Severity;
use sure_domain::status::CheckResult;

use crate::discover::node::{MANIFEST, Managers, NodeProject, Package, PackageManager, ScriptRole};
use crate::planned_work::PlannedWork;
use crate::scan::display_path;
use crate::schedule::{CheckProposal, CheckReason, PlanBuilder};

use super::{
    MissingCommand, MissingKind, NOTHING_NAMES_A_RUNNER, check_id, command_operation,
    component_directory,
};

/// What SURE proposes for one role.
///
/// A table rather than a `match` per question, because the four roles have to
/// agree about four things and four matches that agree by hand are four places
/// for a role to be added to only one of. `ActionKind::ALL` and the enum's own
/// order were made to assert against each other for the same reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RoleCheck {
    /// What the check would do.
    ///
    /// This is the field that decides the whole of the first acceptance
    /// sentence: all four of these execute project code, which is what
    /// `every_checked_role_executes_project_code` reads out of the domain rather
    /// than trusting a table written here.
    action: ActionKind,
    /// How bad it is if the check does not pass.
    severity: Severity,
    /// Whether the project cannot be trusted for hand-off when it does not pass.
    ///
    /// A build that fails and tests that fail are both reasons not to hand a
    /// project over. A lint or a type check that fails is a finding about
    /// quality, and the four weights below are a policy rather than a discovery:
    /// nothing in a `package.json` says how much a lint failure matters, so this
    /// is SURE's judgement and it is written where it can be argued with.
    critical: bool,
}

/// The roles SURE checks, and what each one's check is.
///
/// **The order is the acceptance's**: build, test, lint, type. It is not the
/// order a report shows — [`crate::schedule`] decides that, and deliberately not
/// from how the proposals arrived — so this order is only how the table reads.
///
/// [`Format`](ScriptRole::Format), [`Dev`](ScriptRole::Dev),
/// [`Start`](ScriptRole::Start) and [`Clean`](ScriptRole::Clean) are absent on
/// purpose and the module documentation says why for each. Their absence is what
/// makes [`RoleCheck`]'s weight a required field rather than a defaulted one.
const CHECKS: &[(ScriptRole, RoleCheck)] = &[
    (
        ScriptRole::Build,
        RoleCheck {
            action: ActionKind::Build,
            severity: Severity::MustFix,
            critical: true,
        },
    ),
    (
        ScriptRole::Test,
        RoleCheck {
            action: ActionKind::RunTests,
            severity: Severity::MustFix,
            critical: true,
        },
    ),
    (
        ScriptRole::Lint,
        RoleCheck {
            action: ActionKind::Lint,
            severity: Severity::CanFixLater,
            critical: false,
        },
    ),
    (
        ScriptRole::TypeCheck,
        RoleCheck {
            action: ActionKind::TypeCheck,
            severity: Severity::ShouldFixFirst,
            critical: false,
        },
    ),
];

/// What runs a project's scripts, or why SURE cannot say.
///
/// One value asked once and used for every component, rather than a
/// `Option<PackageManager>` and a sentence rebuilt per check. The two halves
/// belong together because they are two answers to one question, and because
/// [`Managers::agreed`] answers `None` for two different reasons that its own
/// documentation says a caller must not render the same way.
///
/// **`pub(crate)` since `P5-T001`**, which is the second caller: a runtime probe
/// runs the project's own start command, so it asks the same question of the
/// same value. Widening this rather than copying it is the point — *which
/// package manager runs this project's scripts* has one answer per project, and
/// two modules that each computed it could give two.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Runner {
    /// The project names a package manager, and SURE will use it.
    Agreed(PackageManager),
    /// The project names none, and this is the sentence saying which way it
    /// failed to.
    Unknown {
        /// A constant from the discovery, or one of SURE's own. Never project
        /// text.
        why: &'static str,
    },
}

impl Runner {
    /// What runs this project's scripts.
    pub(crate) fn of(managers: &Managers) -> Self {
        match managers.agreed() {
            Some(manager) => Self::Agreed(manager),
            None => Self::Unknown {
                why: match managers.disagreement() {
                    Some(disagreement) => disagreement.plain_description(),
                    None => NOTHING_NAMES_A_RUNNER,
                },
            },
        }
    }

    /// The manager, if there is one.
    const fn manager(self) -> Option<PackageManager> {
        match self {
            Self::Agreed(manager) => Some(manager),
            Self::Unknown { .. } => None,
        }
    }

    /// Why there is not one, if there is not.
    const fn why(self) -> Option<&'static str> {
        match self {
            Self::Agreed(_) => None,
            Self::Unknown { why } => Some(why),
        }
    }
}

/// What SURE would check in a Node project, and what it could not.
///
/// Built from a discovery result and nothing else — see the module
/// documentation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeChecks {
    proposed: Vec<PlannedWork>,
    missing: Vec<MissingCommand>,
}

impl NodeChecks {
    /// Everything SURE would check in this project, and everything it could not.
    ///
    /// **One component per *readable* manifest**: the root's and every workspace
    /// member's. A manifest SURE could not read is not a component here, and
    /// that is the same line `docs/architecture/ECOSYSTEM_DISCOVERY.md` draws one
    /// level down — *a manifest that could not be read is not a manifest that is
    /// absent*. Four "nothing is declared" gaps for a `package.json` that failed
    /// to parse would be four false statements about the project, and the unread
    /// manifest is already a value in the discovery result where it belongs.
    ///
    /// **`root` is the project root, and it is a parameter rather than a field of
    /// the discovery result** because a check's command is planned as typed work
    /// and a command that runs must have an absolute working directory — the rule
    /// is [`process`](crate::process)'s, and
    /// [`CommandSpec::new`](crate::planned_work::CommandSpec::new) documents
    /// itself as *not* restating it, so nothing here should be read as a
    /// constructor having checked. The discovery carries the root and the members carry
    /// their own paths; what a member's check needs is the two joined, which is
    /// the fact a member's *rendered* command does not hold — ADR 0014 rejected
    /// parsing that string partly because it cannot say where the command runs.
    /// The scan refuses a root that is not absolute (`scan::open_root`), so the
    /// directory built here is absolute whenever the discovery is a value at all.
    #[must_use]
    pub fn of(project: &NodeProject, root: &Path) -> Self {
        let mut checks = Self {
            proposed: Vec::new(),
            missing: Vec::new(),
        };

        // One runner for the whole project, because a package manager is a
        // property of the installation and not of a member: a pnpm workspace's
        // members are all run by pnpm. Asked once rather than per component, so
        // that two members cannot be told two different things.
        let runner = Runner::of(&project.managers);

        for (manifest, package) in components(project) {
            // The directory this component's check runs in, which is the root for
            // the project's own manifest and the member's own directory for a
            // member's. Derived from the component path rather than from anything
            // the manifest says, which is what makes it true for a workspace.
            let directory = component_directory(root, &manifest);

            for &(role, check) in CHECKS {
                let id = check_id(&manifest, &format!("node{}", role.conventional_name()));
                let title = titled(role, &manifest);

                match invocation_for(package, role, runner) {
                    Ok(invocation) => checks.proposed.push(PlannedWork::new(
                        CheckProposal::new(
                            id,
                            title,
                            check.severity,
                            check.critical,
                            // A check that runs a command the project declared and
                            // watches what it does is a deterministic check rather
                            // than an observation: the same project state gives the
                            // same answer, which is the whole of what makes it worth
                            // running.
                            EvidenceClass::DeterministicCheck,
                            CheckReason::DeclaredCommand {
                                declared_in: manifest.clone(),
                                // The rendered line, and only the rendered line: it
                                // is what a report prints, and the program that would
                                // run is the `CommandSpec` beside it. Nothing reads
                                // this string back into a program -- ADR 0014
                                // rejected exactly that, and the pairing is what
                                // makes it unnecessary.
                                command: invocation.rendered,
                            },
                            &[check.action],
                        ),
                        command_operation(
                            invocation.manager.as_str(),
                            &directory,
                            &invocation
                                .arguments
                                .iter()
                                .map(String::as_str)
                                .collect::<Vec<_>>(),
                        ),
                    )),
                    Err(kind) => checks.missing.push(MissingCommand::new(
                        id,
                        title,
                        manifest.clone(),
                        check.severity,
                        check.critical,
                        kind,
                    )),
                }
            }
        }

        checks
    }

    /// The checks SURE would run, in no particular order.
    ///
    /// **No particular order is the honest description**: [`PlanBuilder`] sorts
    /// them, and a caller that read an order out of this list would be depending
    /// on the order the components were walked, which is not a fact about the
    /// project.
    ///
    /// Each value is a proposal **with the work that would carry it out** — the
    /// program, its arguments and the directory, as typed fields. A caller that
    /// wants only what a report shows asks each one for its proposal; a caller
    /// that means to run the check reads the operation, and neither can reach one
    /// half without the other existing.
    #[must_use]
    pub fn planned(&self) -> &[PlannedWork] {
        &self.proposed
    }

    /// The checks SURE could not propose, one per role per readable manifest.
    #[must_use]
    pub fn missing(&self) -> &[MissingCommand] {
        &self.missing
    }

    /// Whether there is nothing to check and nothing missing.
    ///
    /// True for a project discovery found a `package.json` for and could not
    /// read, which is a project SURE has nothing to say about here — and
    /// `a_manifest_sure_could_not_read_is_not_a_manifest_that_declares_nothing`
    /// in `tests/node_checks.rs` is what says so rather than leaving it to be
    /// discovered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.proposed.is_empty() && self.missing.is_empty()
    }

    /// Hands every check to a plan builder, each with its own work.
    ///
    /// **The builder's refusals are the record, which is why nothing is
    /// returned here.** [`PlanBuilder::propose`] remembers a refusal even when
    /// its `Err` is dropped, and [`PlanBuilder::refused`] is where a caller
    /// finds them — so a check this module got wrong cannot disappear by
    /// being ignored. Nothing this module builds can be refused in the first
    /// place: every check has a title, a reason naming a file, exactly one
    /// action, and the operation it was planned with, and
    /// `nothing_this_module_builds_is_refused` is what holds that rather than
    /// this sentence.
    pub fn add_to(&self, builder: &mut PlanBuilder) {
        for work in &self.proposed {
            // The `Err` is the refusal, and it is not dropped: `propose` has
            // already pushed it onto the builder's own list by the time this
            // returns it, which is the contract that function documents. Binding
            // it here rather than with `let _` is what makes that deliberate.
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
    /// **This is the second acceptance sentence, and it is the only thing this
    /// module produces that is a result.** A caller that renders the checks SURE
    /// ran and forgets this list has a report that is silent about every command
    /// the project does not have; a caller that renders both cannot show a
    /// missing command as anything but something that was not checked, because
    /// [`MissingCommand::not_checked`] has one constructor to reach for and it is
    /// `CheckResult::not_run`.
    #[must_use]
    pub fn not_checked(&self, project_fingerprint: &FingerprintId) -> Vec<CheckResult> {
        self.missing
            .iter()
            .map(|missing| missing.not_checked(project_fingerprint))
            .collect()
    }
}

/// Every manifest SURE read, with the path it was read from.
///
/// The root first, then the members in the order the discovery resolved them —
/// an order nothing downstream depends on, which is stated here because the
/// temptation to read a meaning into it is real.
///
/// **`pub(crate)` since `P5-T001`**, so that a runtime probe walks the same list
/// for the same reason: *which manifests SURE read* is one answer, and a second
/// walk over `readable_members` would be a second place to get the root, the
/// spelling of a member's path, or the unread-manifest rule wrong.
pub(crate) fn components(project: &NodeProject) -> Vec<(String, &Package)> {
    let mut found: Vec<(String, &Package)> = Vec::new();

    if let Some(package) = project.package() {
        found.push((MANIFEST.to_owned(), package));
    }

    for member in project.workspaces.readable_members() {
        if let Some(package) = member.package.as_deref() {
            found.push((display_path(&member.path.join(MANIFEST)), package));
        }
    }

    found
}

/// One declared command, in the three forms its two callers need.
///
/// **The three fields are one decision rather than three computations.** `manager`
/// and `arguments` are what a check would start; `rendered` is the same pair as the
/// line a report prints. It comes from the discovery's own
/// [`Package::command_for`](crate::discover::node::Package::command_for), which is
/// that pair rendered, so a change to how a command is spelled reaches the report
/// and the program together — and there is no second `format!` here that could
/// disagree with the first.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Invocation {
    /// The program's name, as a command line spells it.
    manager: PackageManager,
    /// The arguments, one per argument.
    arguments: Vec<String>,
    /// The line a report prints for this command.
    rendered: String,
}

/// The command SURE would run for a role, or why it has none.
///
/// The three failures are ordered deliberately. *Is the script declared* is
/// asked before *is there a runner*, because a project with neither a `test`
/// script nor a lockfile has one problem a person acts on and one they do not:
/// the sentence should be about the missing script.
///
/// **`pub(crate)` since `P5-T001`**, which asks it about roles this module does
/// not check — `start` and `dev`, for the reason the module documentation gives
/// for their absence here. The ordering above is the reason it is reused rather
/// than re-derived: a probe's gap has to be the same value, about the same
/// manifest, in the same order of questions, or one project would be described
/// two ways by one report.
pub(crate) fn command_for(
    package: &Package,
    role: ScriptRole,
    runner: Runner,
) -> Result<String, MissingKind> {
    invocation_for(package, role, runner).map(|invocation| invocation.rendered)
}

/// The same command as typed work: the program, its arguments and the rendering.
///
/// **This is where a declared check stops being text.** The program is
/// [`PackageManager::as_str`](crate::discover::node::PackageManager::as_str) — a
/// name, and on Windows a name with no extension, which is the platform's business
/// and not this module's: whether `npm` is startable is [`Resolution`]'s answer, and
/// a builder that appended `.cmd` to make it "work" would be inventing a program.
/// The arguments are the discovery's own vector, so a script named `my tests` is one
/// argument and not two.
///
/// [`Resolution`]: crate::planned_work::Resolution
fn invocation_for(
    package: &Package,
    role: ScriptRole,
    runner: Runner,
) -> Result<Invocation, MissingKind> {
    if package.script(role).is_none() {
        return Err(if is_not_a_command(package, role) {
            MissingKind::NotACommand
        } else {
            MissingKind::NotDeclared
        });
    }

    let Some(manager) = runner.manager() else {
        return Err(MissingKind::NoRunner {
            // `Runner::Unknown` carries a sentence and `Agreed` does not, so the
            // `None` here is only reachable when the `None` above was not — the
            // two reads of one value rather than two decisions that have to
            // agree.
            why: runner.why().unwrap_or(NOTHING_NAMES_A_RUNNER),
        });
    };

    match (
        package.invocation_for(manager, role),
        package.command_for(manager, role),
    ) {
        (Some((manager, arguments)), Some(rendered)) => Ok(Invocation {
            manager,
            arguments,
            rendered,
        }),
        // Unreachable: both answer `None` exactly when `script(role)` does, and
        // that was excluded above. Folded into the shape it would mean — a script
        // SURE could not turn into a command is one it has no command for —
        // rather than panicking on a shipped path.
        _ => Err(MissingKind::NotDeclared),
    }
}

/// Whether the project declared this role's name with a value that is not a
/// command.
///
/// **This is the distinction the discovery made and this is where it survives.**
/// A name in `scripts_not_commands` is a script that is there and unusable; a
/// name in neither list is a script that is not there; and a report that showed
/// both as "no test script" would be describing a broken manifest as a project
/// that never wrote one.
fn is_not_a_command(package: &Package, role: ScriptRole) -> bool {
    package
        .scripts_not_commands
        .iter()
        .any(|name| name == role.conventional_name())
}

/// The title a check would have, which is also what a missing command is titled.
///
/// The component is in the title because a workspace has several: two rows
/// saying `run the tests` with nothing to tell them apart is what a monorepo
/// report is made of. The root manifest is the project itself, so its title is
/// the bare one — `run the tests in .` would be noise.
fn titled(role: ScriptRole, manifest: &str) -> String {
    match manifest.strip_suffix(MANIFEST) {
        Some("") => role.plain_description().to_owned(),
        Some(directory) => format!(
            "{} in {}",
            role.plain_description(),
            directory.trim_end_matches('/')
        ),
        // Unreachable: every component is built by joining `MANIFEST`. A whole
        // path is a worse title than a directory and a better one than nothing,
        // which is the trade this arm makes rather than panicking.
        None => format!("{} in {manifest}", role.plain_description()),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::ffi::{OsStr, OsString};
    use std::path::PathBuf;

    use crate::discover::Source;
    use crate::discover::node::{ManagerEvidence, ManagerFinding, ManifestState};
    use crate::planned_work::CheckOperation;
    use serde_json::json;
    use sure_domain::status::{CheckStatus, NotCheckedReason};

    fn package(value: serde_json::Value) -> Package {
        Package::from_json(&value).expect("this fixture is a manifest")
    }

    /// A lockfile a fixture wrote: the file, and the manager that writes it.
    ///
    /// **Both are named at every call site rather than derived from the file
    /// name here.** A `lockfile -> manager` table in this module would be a copy
    /// of `LOCKFILES` in `discover/node.rs`, and a copy is the thing that stops
    /// agreeing the day the original changes. The real mapping is exercised over
    /// real files on disk by `tests/node_checks.rs`, which is where it belongs.
    type Lockfile = (&'static str, PackageManager);

    /// A project whose root manifest is these scripts.
    fn project(scripts: serde_json::Value, locked: &[Lockfile]) -> NodeProject {
        let mut managers = Managers::default();
        for &(name, manager) in locked {
            managers.locked.push(ManagerFinding {
                manager,
                evidence: ManagerEvidence::Lockfile,
                source: Source::new(name, "is a lockfile for this package manager"),
            });
        }
        NodeProject {
            manifest: ManifestState::Read(Box::new(package(json!({ "scripts": scripts })))),
            managers,
            workspaces: Default::default(),
            tooling: Vec::new(),
            typescript: Default::default(),
        }
    }

    /// A project that is fully declared: all four roles, one lockfile.
    fn a_complete_project() -> NodeProject {
        project(
            json!({
                "build": "tsc -b",
                "test": "vitest run",
                "lint": "eslint .",
                "typecheck": "tsc --noEmit",
            }),
            &[("package-lock.json", PackageManager::Npm)],
        )
    }

    /// The root every fixture in this module is a project in.
    ///
    /// One spelling, so that a test asserting a working directory compares against
    /// a value rather than against a second `PathBuf::from` that could differ by a
    /// separator and pass for the wrong reason. It is a Windows-looking path on
    /// purpose: a working directory is a path, and the module is portable because
    /// it never parses one.
    ///
    /// **Absolute on every platform, and that is why it is written twice.** A
    /// Windows absolute path is not one anywhere else: `Path::is_absolute` asks the
    /// platform what a root is, and `C:\projects\fixture` has none off Windows. One
    /// literal would therefore make
    /// `a_members_check_runs_in_the_members_directory_and_the_roots_in_the_root`'s
    /// `is_absolute` assertion a statement about where this file was compiled
    /// rather than about the directory a check was given — which is what it was
    /// until the two non-Windows legs of CI ran the test for the first time and it
    /// failed on both.
    fn root() -> PathBuf {
        if cfg!(windows) {
            PathBuf::from(r"C:\projects\fixture")
        } else {
            PathBuf::from("/projects/fixture")
        }
    }

    /// The checks for a project, in the root above.
    fn checks_of(project: &NodeProject) -> NodeChecks {
        NodeChecks::of(project, &root())
    }

    /// The proposals of a check list.
    ///
    /// For the assertions that are about what a report shows rather than about what
    /// would run. **The two are reached through different accessors on purpose**:
    /// `planned` is what a runner reads and this is what a person reads, and a test
    /// that is really about one of them says so.
    fn proposals(checks: &NodeChecks) -> Vec<&CheckProposal> {
        checks.planned().iter().map(PlannedWork::proposal).collect()
    }

    /// The work behind the check with this title.
    fn work_for<'a>(checks: &'a NodeChecks, title: &str) -> &'a PlannedWork {
        checks
            .planned()
            .iter()
            .find(|work| work.proposal().title() == title)
            .unwrap_or_else(|| panic!("there is no check titled {title:?}"))
    }

    /// The gap for one role, by the title a person reads.
    ///
    /// By title rather than by position: a project can be missing four commands
    /// at once, they arrive in the role table's order, and an index into that
    /// list would be a fact about the table rather than about the role.
    fn gap_for(checks: &NodeChecks, role: ScriptRole) -> &MissingKind {
        checks
            .missing()
            .iter()
            .find(|missing| missing.title() == role.plain_description())
            .unwrap_or_else(|| panic!("{role:?} has a command, so there is no gap to read"))
            .kind()
    }

    #[test]
    fn the_table_covers_the_four_roles_the_acceptance_names() {
        // The claim the module's own headline makes, held against the table
        // rather than against a paragraph. A fifth role added here, or one of
        // the four dropped, fails.
        let roles: Vec<ScriptRole> = CHECKS.iter().map(|(role, _)| *role).collect();
        assert_eq!(
            roles,
            vec![
                ScriptRole::Build,
                ScriptRole::Test,
                ScriptRole::Lint,
                ScriptRole::TypeCheck,
            ],
            "the checked roles are not the four the acceptance names"
        );

        // And the four that are absent are absent for the reason the module
        // documentation gives: two of them write and two of them do not finish.
        for role in ScriptRole::ALL {
            let checked = roles.contains(role);
            let expected = !matches!(
                role,
                ScriptRole::Format | ScriptRole::Dev | ScriptRole::Start | ScriptRole::Clean
            );
            assert_eq!(checked, expected, "{role:?} is on the wrong side");
        }
    }

    #[test]
    fn the_table_carries_the_four_checks_and_the_weight_this_module_argues_for_each() {
        // The policy, pinned as a table rather than left to four fields a reader
        // has to compare by eye. `RoleCheck::critical` argues that a failing
        // build and failing tests are reasons not to hand a project over while a
        // lint and a type check that fail are findings about quality, and
        // `CHECKS` says the four weights are SURE's judgement written where it
        // can be argued with. **The first run of `P4-T002`'s mutation set moved
        // the lint's weight and the type check's criticality and every test
        // passed** — the documentation argued for a policy that nothing held,
        // which is the cheapest way this repository can be wrong about something
        // a report then states as fact.
        let table: Vec<(ScriptRole, ActionKind, Severity, bool)> = CHECKS
            .iter()
            .map(|(role, check)| (*role, check.action, check.severity, check.critical))
            .collect();
        assert_eq!(
            table,
            vec![
                (
                    ScriptRole::Build,
                    ActionKind::Build,
                    Severity::MustFix,
                    true
                ),
                (
                    ScriptRole::Test,
                    ActionKind::RunTests,
                    Severity::MustFix,
                    true
                ),
                (
                    ScriptRole::Lint,
                    ActionKind::Lint,
                    Severity::CanFixLater,
                    false
                ),
                (
                    ScriptRole::TypeCheck,
                    ActionKind::TypeCheck,
                    Severity::ShouldFixFirst,
                    false
                ),
            ],
            "a role's check, its action, its weight or its criticality moved, and \
             the prose above the table is the only thing that still says why"
        );
    }

    #[test]
    fn every_checked_role_executes_project_code() {
        // The first acceptance sentence, read out of the domain rather than
        // trusted to this module's table: if any of the four actions did not
        // execute project code, the check would be one `InspectOnly` allows and
        // the sentence would be false.
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
    fn a_declared_script_becomes_a_check_running_the_command_sure_would_run() {
        let checks = checks_of(&a_complete_project());
        assert!(checks.missing().is_empty(), "{:?}", checks.missing());
        assert_eq!(proposals(&checks).len(), 4);

        let build = proposals(&checks)
            .into_iter()
            .find(|proposal| {
                proposal.reason().names_something() && proposal.title() == "build the project"
            })
            .expect("the build check");
        assert_eq!(build.severity(), Severity::MustFix);
        assert!(build.critical());
        assert_eq!(build.evidence_class(), EvidenceClass::DeterministicCheck);
        assert_eq!(build.requirements().actions(), [ActionKind::Build]);
        assert!(build.requirements().runs_project_code());
        assert!(!build.requirements().runs_nothing());
        match build.reason() {
            CheckReason::DeclaredCommand {
                declared_in,
                command,
            } => {
                assert_eq!(declared_in, MANIFEST);
                // `npm run build` and not `build`: the reason names the command
                // a person is being asked to allow, which is what `npm` needs
                // for a script whose name is not `test` or `start`.
                assert_eq!(command, "npm run build");
            }
            other => panic!("the build check's reason is {other:?}"),
        }

        // And the two roles npm spells differently, because a table that got
        // this wrong would propose `npm test` as `npm run test`, which happens
        // to work and is not what the manager documents.
        let test = proposals(&checks)
            .into_iter()
            .find(|proposal| proposal.title() == "run the tests")
            .expect("the test check");
        match test.reason() {
            CheckReason::DeclaredCommand { command, .. } => assert_eq!(command, "npm test"),
            other => panic!("the test check's reason is {other:?}"),
        }
    }

    #[test]
    fn the_runner_the_project_locked_is_the_one_the_command_names() {
        // Three managers, three spellings, and none of them npm — so a module
        // that defaulted to npm when it could not tell would fail here rather
        // than in a project.
        for (locked, expected) in [
            (("package-lock.json", PackageManager::Npm), "npm run build"),
            (("yarn.lock", PackageManager::Yarn), "yarn run build"),
            (("pnpm-lock.yaml", PackageManager::Pnpm), "pnpm run build"),
            (("bun.lockb", PackageManager::Bun), "bun run build"),
        ] {
            let checks = checks_of(&project(json!({ "build": "tsc -b" }), &[locked]));
            let build = proposals(&checks)
                .into_iter()
                .find(|proposal| proposal.title() == "build the project")
                .unwrap_or_else(|| panic!("no build check for {}", locked.0));
            match build.reason() {
                CheckReason::DeclaredCommand { command, .. } => {
                    assert_eq!(command, expected, "for {}", locked.0)
                }
                other => panic!("the build check's reason is {other:?}"),
            }
        }
    }

    #[test]
    fn the_work_behind_a_check_is_the_typed_form_of_the_line_a_report_prints() {
        // **The pairing `P18-T003` exists for, held over the whole matrix rather
        // than over one example.** Every manager and all four roles, so both
        // spellings npm has and the `run` the other three need are covered. The
        // claim is that the program and the argument vector are the *same decision*
        // as the rendered line: the discovery renders the line from that vector
        // (`Package::command_for` is `invocation_for` joined with spaces), so a
        // change to one that did not reach the other fails here rather than in a
        // report nobody can execute.
        for &manager in PackageManager::ALL {
            let checks = checks_of(&project(
                json!({
                    "build": "tsc -b",
                    "test": "vitest run",
                    "lint": "eslint .",
                    "typecheck": "tsc --noEmit",
                }),
                &[match manager {
                    PackageManager::Npm => ("package-lock.json", PackageManager::Npm),
                    PackageManager::Yarn => ("yarn.lock", PackageManager::Yarn),
                    PackageManager::Pnpm => ("pnpm-lock.yaml", PackageManager::Pnpm),
                    PackageManager::Bun => ("bun.lockb", PackageManager::Bun),
                }],
            ));

            for role in [
                ScriptRole::Build,
                ScriptRole::Test,
                ScriptRole::Lint,
                ScriptRole::TypeCheck,
            ] {
                let work = work_for(&checks, &titled(role, MANIFEST));
                let CheckOperation::Command(spec) = work.operation() else {
                    panic!("{role:?} for {manager:?} is not work that runs a command");
                };
                let CheckReason::DeclaredCommand { command, .. } = work.proposal().reason() else {
                    panic!("a declared script has a reason that is not a command");
                };

                // The program is the manager's own name -- `npm`, and on Windows a
                // name with no extension. **Nothing appends `.cmd` here**: whether
                // a name is startable is `ProgramPath`'s answer, and a builder that
                // rewrote the name to make it so would be inventing the program it
                // then starts.
                assert_eq!(spec.program(), OsStr::new(manager.as_str()));
                assert!(
                    !spec.program().to_string_lossy().contains('.'),
                    "{} was given an extension a check must not add",
                    spec.program().to_string_lossy()
                );

                // The line a report prints is the vector, and this is the direction
                // that matters: rendering the operation and comparing it with the
                // reason is what would fail if either moved alone.
                let rendered = std::iter::once(spec.program().to_string_lossy().into_owned())
                    .chain(
                        spec.arguments()
                            .iter()
                            .map(|argument| argument.to_string_lossy().into_owned()),
                    )
                    .collect::<Vec<String>>()
                    .join(" ");
                assert_eq!(&rendered, command, "for {manager:?} and {role:?}");

                // And the vector says what the manager expects, which for npm is
                // two different things: `npm test` is not `npm run test`.
                let expected: Vec<&str> = match (manager, role) {
                    (PackageManager::Npm, ScriptRole::Test) => {
                        vec![ScriptRole::Test.conventional_name()]
                    }
                    _ => vec!["run", role.conventional_name()],
                };
                assert_eq!(
                    spec.arguments().to_vec(),
                    expected
                        .iter()
                        .copied()
                        .map(OsString::from)
                        .collect::<Vec<_>>(),
                    "the arguments for {manager:?} and {role:?}"
                );
            }
        }
    }

    #[test]
    fn a_members_check_runs_in_the_members_directory_and_the_roots_in_the_root() {
        // **The fact ADR 0014 says a parsed display string cannot carry.** A
        // member's check runs in the member's own directory, which appears nowhere
        // in the command a report prints: `npm run build` and
        // `npm run build in packages/web` are the same program in different places.
        // The directory is derived from the component path the discovery holds as a
        // value, and this is the test that says so.
        let mut found = a_complete_project();
        found.workspaces.patterns.push("packages/*".to_owned());
        found
            .workspaces
            .members
            .push(crate::discover::node::Member {
                path: "packages/web".into(),
                manifest: crate::discover::MemberManifest::Present,
                package: Some(Box::new(package(
                    json!({ "scripts": { "build": "vite build" } }),
                ))),
            });

        let checks = checks_of(&found);
        let mut seen: Vec<PathBuf> = Vec::new();
        for (work, expected) in [
            (work_for(&checks, "build the project"), root()),
            (
                work_for(&checks, "build the project in packages/web"),
                root().join("packages").join("web"),
            ),
        ] {
            let CheckOperation::Command(spec) = work.operation() else {
                panic!("{} does not run a command", work.proposal().title());
            };
            assert!(
                spec.working_directory().is_absolute(),
                "{} would run somewhere relative to wherever SURE was started",
                work.proposal().title()
            );
            assert_eq!(
                spec.working_directory(),
                expected,
                "{}",
                work.proposal().title()
            );
            seen.push(spec.working_directory().to_path_buf());
        }
        assert_ne!(
            seen[0], seen[1],
            "the root's check and the member's run in the same directory, so a \
             member's command would be run against the root's manifest"
        );
    }

    #[test]
    fn a_role_with_no_script_is_not_checked_rather_than_passed() {
        let checks = checks_of(&project(
            json!({ "build": "tsc -b" }),
            &[("yarn.lock", PackageManager::Yarn)],
        ));
        assert_eq!(proposals(&checks).len(), 1);

        let kinds: Vec<&MissingKind> = checks.missing().iter().map(MissingCommand::kind).collect();
        assert_eq!(
            kinds,
            vec![
                &MissingKind::NotDeclared,
                &MissingKind::NotDeclared,
                &MissingKind::NotDeclared,
            ],
            "the three roles the project does not declare"
        );
        assert_eq!(
            checks
                .missing()
                .iter()
                .map(MissingCommand::title)
                .collect::<Vec<_>>(),
            vec![
                "run the tests",
                "check the code for style and likely mistakes",
                "check the types without building"
            ]
        );
    }

    #[test]
    fn a_project_whose_only_findings_are_gaps_is_not_a_project_with_nothing_to_say() {
        // `is_empty` is a conjunction and this is the half a mutation can drop.
        // A project that declares no script proposes nothing and finds four
        // gaps, and a caller reading "empty" as "nothing was proposed" would
        // print a report saying nothing about four of the roles the acceptance
        // names — the silence `MissingCommand` exists to prevent, arriving
        // through the accessor instead of through the type.
        //
        // **The fixture has to be one where the two halves disagree, and the
        // first version of this test was not.** It used a project with one
        // script, so `proposed.is_empty()` was `false` under the original and
        // under the mutation alike, and the mutation survived a test written
        // against it. A test for a conjunction is worth exactly as much as the
        // case where the two conjuncts differ, and a project that declares
        // nothing is that case: no proposals, four gaps.
        let checks = checks_of(&project(
            json!({}),
            &[("package-lock.json", PackageManager::Npm)],
        ));
        assert!(
            proposals(&checks).is_empty(),
            "the fixture declares a script"
        );
        assert_eq!(checks.missing().len(), 4);
        assert!(
            !checks.is_empty(),
            "a project with four gaps answers that it has nothing to say"
        );
    }

    #[test]
    fn a_script_that_is_there_and_is_not_a_command_is_not_a_script_that_is_not_there() {
        // The distinction `docs/architecture/ECOSYSTEM_DISCOVERY.md` calls the
        // one that matters, arriving in a plan. `"test": ["jest"]` is a name
        // that is present with a value that is not a command, and a report that
        // showed it as a project with no test script would be describing a
        // broken manifest as a project that never wrote one.
        let checks = checks_of(&project(
            json!({ "build": "tsc -b", "test": ["jest"], "lint": null }),
            &[("package-lock.json", PackageManager::Npm)],
        ));

        let missing: Vec<(&str, &MissingKind)> = checks
            .missing()
            .iter()
            .map(|missing| (missing.title(), missing.kind()))
            .collect();
        assert_eq!(
            missing,
            vec![
                ("run the tests", &MissingKind::NotACommand),
                (
                    "check the code for style and likely mistakes",
                    &MissingKind::NotACommand
                ),
                (
                    "check the types without building",
                    &MissingKind::NotDeclared
                ),
            ],
            "an unusable script is reported as an unusable script and a missing \
             one as missing, and the two are not the same row"
        );
    }

    #[test]
    fn the_two_ways_a_project_can_fail_to_name_a_runner_are_told_apart() {
        // `Managers::agreed` answers `None` for two different reasons and says in
        // its own documentation that a caller rendering them the same way throws
        // away `disagreement`. This is the caller that must not.
        let scripts = json!({ "test": "jest" });

        let nothing = checks_of(&project(scripts.clone(), &[]));
        let two = checks_of(&project(
            scripts,
            &[
                ("package-lock.json", PackageManager::Npm),
                ("pnpm-lock.yaml", PackageManager::Pnpm),
            ],
        ));

        let why = |checks: &NodeChecks| match gap_for(checks, ScriptRole::Test) {
            MissingKind::NoRunner { why } => *why,
            other => panic!("the test gap is {other:?}"),
        };
        assert_eq!(why(&nothing), NOTHING_NAMES_A_RUNNER);
        assert_ne!(
            why(&two),
            NOTHING_NAMES_A_RUNNER,
            "a project with two lockfiles is not a project with no evidence"
        );
        assert!(
            why(&two).contains("two different package managers"),
            "the sentence does not say what is wrong: {}",
            why(&two)
        );

        // And a script that is not declared is reported as that, whatever the
        // runner evidence says: the sentence a person reads should be about the
        // problem they act on.
        let undeclared = checks_of(&project(json!({ "build": "tsc" }), &[]));
        assert_eq!(
            gap_for(&undeclared, ScriptRole::Test),
            &MissingKind::NotDeclared,
            "a project with no test script and no lockfile has two problems and \
             the missing script is the one to report"
        );
    }

    #[test]
    fn the_root_manifest_and_every_readable_member_is_its_own_component() {
        // A workspace: two members with the same script and one without, so the
        // identifiers have to differ by component and a member with no readable
        // manifest has to be absent rather than empty.
        let mut found = a_complete_project();
        found.workspaces.patterns.push("packages/*".to_owned());
        for (path, has_manifest) in [("packages/web", true), ("packages/api", false)] {
            let package = has_manifest.then(|| {
                Box::new(package(
                    json!({ "scripts": { "build": "vite build", "test": "vitest run" } }),
                ))
            });
            found
                .workspaces
                .members
                .push(crate::discover::node::Member {
                    path: path.into(),
                    manifest: if has_manifest {
                        crate::discover::MemberManifest::Present
                    } else {
                        crate::discover::MemberManifest::Absent
                    },
                    package,
                });
        }

        let checks = checks_of(&found);
        // Four for the root, four for `packages/web`, none for `packages/api`.
        assert_eq!(proposals(&checks).len() + checks.missing().len(), 8);

        let titles: Vec<&str> = proposals(&checks)
            .into_iter()
            .map(CheckProposal::title)
            .chain(checks.missing().iter().map(MissingCommand::title))
            .collect();
        assert!(titles.contains(&"build the project"), "{titles:?}");
        assert!(
            titles.contains(&"build the project in packages/web"),
            "{titles:?}"
        );
        assert!(
            !titles.iter().any(|title| title.contains("packages/api")),
            "a member whose manifest SURE did not read became a component: {titles:?}"
        );

        // And the identities are distinct, because two of them describe the same
        // role in two directories.
        let mut ids: Vec<&str> = proposals(&checks)
            .into_iter()
            .map(|proposal| proposal.id().as_str())
            .chain(checks.missing().iter().map(|missing| missing.id().as_str()))
            .collect();
        let total = ids.len();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), total, "two components share an identifier");
    }

    #[test]
    fn a_manifest_sure_did_not_read_is_neither_a_check_nor_a_gap() {
        // The false green this module is arranged against, one level up from the
        // one `discover_node.rs` holds: a `package.json` that failed to parse
        // declares no scripts — and so does a project with no `package.json`,
        // and so does a project with eight of them missing. Four gaps here would
        // say "your project declares nothing" about a file SURE never read.
        for state in [
            ManifestState::Absent,
            ManifestState::Unread(crate::discover::UnreadReason::WrongShape { found: "an array" }),
        ] {
            let project = NodeProject {
                manifest: state.clone(),
                managers: Default::default(),
                workspaces: Default::default(),
                tooling: Vec::new(),
                typescript: Default::default(),
            };
            let checks = checks_of(&project);
            assert!(checks.is_empty(), "{state:?} produced {checks:?}");
            assert!(checks.not_checked(&FingerprintId::generate()).is_empty());
        }
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
        assert_eq!(schedule.len(), proposals(&checks).len());
        assert!(
            schedule.duplicates().is_empty(),
            "{:?}",
            schedule.duplicates()
        );
        assert_eq!(schedule.may_run().count(), schedule.len());
        assert!(schedule.get(proposals(&checks)[0].id()).is_some());
    }

    #[test]
    fn a_missing_command_is_a_skipped_result_and_never_a_pass() {
        // The second acceptance sentence, from the module that has to satisfy
        // it. `not_checked` is the only result-producing function here and this
        // is what it may produce. A project that declares nothing gets three
        // gaps where a lesser design would have got three absent rows.
        let fingerprint = FingerprintId::generate();
        let results = |scripts: serde_json::Value| {
            let checks = checks_of(&project(scripts, &[("yarn.lock", PackageManager::Yarn)]));
            assert_eq!(
                checks.missing().len(),
                checks.not_checked(&fingerprint).len()
            );
            checks.not_checked(&fingerprint)
        };

        let nothing_declared = results(json!({ "build": "tsc -b" }));
        assert_eq!(nothing_declared.len(), 3);
        for result in &nothing_declared {
            assert_eq!(result.status, CheckStatus::Skipped, "{}", result.title);
            assert!(!result.status.is_green(), "{}", result.title);
            assert!(!result.status.produced_a_result(), "{}", result.title);
            assert!(result.is_not_checked(), "{}", result.title);
            assert!(!result.reason.trim().is_empty(), "{}", result.title);
            assert_eq!(result.project_fingerprint, fingerprint);
        }
        assert!(
            nothing_declared.iter().all(|result| !result.blocks_green()),
            "a project that declares no test script is a project this check is out \
             of scope for, so it must not hold the run out of green"
        );

        // **The sentence this whole module is arranged around.** The same
        // project, the same role, the same severity and the same criticality —
        // and the one difference is that the manifest has a `test` name whose
        // value is not a command. That alone is the difference between a gap
        // that is out of scope and a defect that keeps the run out of green.
        let declared_unusable = results(json!({ "build": "tsc -b", "test": ["jest"] }));
        let tests = declared_unusable
            .iter()
            .find(|result| result.title == ScriptRole::Test.plain_description())
            .expect("the test role is missing a command");
        assert!(
            tests.blocks_green(),
            "a manifest SURE cannot run is a defect the user can fix, and it must \
             not be filed as a scope limit: {}",
            tests.reason
        );
        assert_ne!(
            tests.reason,
            NotCheckedReason::UnknownReason.plain_explanation(),
            "the generic sentence for the frozen word is false here and a person \
             would read it as SURE not knowing something it does know"
        );

        // And the non-critical gaps never block, whatever kind they are — the
        // other half of `blocks_green`'s rule, applied to values this module
        // built rather than restated here.
        let blocking: Vec<&str> = declared_unusable
            .iter()
            .filter(|result| result.blocks_green())
            .map(|result| result.title.as_str())
            .collect();
        assert_eq!(blocking, vec![ScriptRole::Test.plain_description()]);
    }
}
