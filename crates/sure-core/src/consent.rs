//! Which permissions a planned command needs, why, and what a refused command becomes.
//!
//! `P3-T005` acceptance: *"Check plan can explain which commands need permission
//! and why."* and *"Denied command becomes skipped/not checked, never pass."*
//!
//! # What was missing, and what this fills
//!
//! Three pieces existed and did not meet. [`crate::safety`] reads a command line
//! and answers with the categories it may fall into. The domain's
//! [`decide`](sure_domain::execution::decide) answers whether an
//! [`ActionKind`](sure_domain::execution::ActionKind) may proceed under a mode
//! and a permission set — but it takes an `ActionKind`, which is a *named
//! activity* rather than a command, so a caller holding a command line had
//! nothing to hand it. And [`CheckPlan`] records which checks will run, with
//! `excluded` for the ones that will not, but nothing moved a check between
//! those two lists.
//!
//! This module is the join. [`PlannedCommand::new`] takes the same
//! program-and-argument-vector pair the classifier takes, works out **which
//! permissions the command needs and which category required each one**,
//! decides, and — when the answer is not "allowed" — carries the
//! [`NotCheckedReason`] the check will be reported under.
//!
//! # The three rules, and where each comes from
//!
//! 1. **Every permission a command needs must be granted.** A command that
//!    installs *and* reaches the network needs both, and granting one of them
//!    does not carry the other. This is `ExecutionPermissions`' own rule — six
//!    independent permissions — applied to a command that needs more than one.
//! 2. **A category no permission covers is never covered by a grant.**
//!    [`CommandClass::Destructive`] answers `None` to `required_permission`, so
//!    no set of permissions can satisfy it: it needs its own approval, naming
//!    the exact command. `ADR 0009` already states this rule for arbitrary
//!    commands — *"an arbitrary command always requires its own approval in
//!    every mode"* — and this is the same rule for the other thing SURE cannot
//!    bound. It is `P3-T006`'s to *grant*, not this module's; here it is
//!    reported, and [`PlannedCommand::ungrantable`] is where a caller reads which
//!    category it was.
//! 3. **The mode is consulted last, and only for a command that runs code.** The
//!    order is [`decide`](sure_domain::execution::decide)'s own order, and it
//!    decides which of two answers a user gets: a missing permission is
//!    [`ExecutionDecision::Denied`] — SURE is not going to ask — while a mode
//!    that is too cautious is [`ExecutionDecision::NeedsConsent`], because there
//!    is a question to ask and the user can answer it.
//!
//! Rule 3's predicate is [`runs_project_code`], which is true of a set holding
//! [`CommandClass::DynamicHost`] **or** [`CommandClass::Install`] — and the
//! second half of that is the finding this task produced. Installing runs code:
//! npm runs a package's `preinstall`, `install`, `postinstall` and `prepare`
//! around an install, and a source distribution is built by a backend the
//! package brought with it. A rule that consulted the mode only for
//! `DynamicHost` would answer **allowed** for `cargo add serde` in a mode that
//! runs nothing, whenever the install and network permissions happened to be
//! granted — which is exactly what `decide` answers `NeedsConsent` for, and
//! exactly the wrong direction. The test that compares this module against
//! `decide` is what found it.
//!
//! # A refused command is never a pass, and that is structural rather than careful
//!
//! There is no constructor here that turns a command into a [`CheckResult`] with
//! [`CheckStatus::Pass`](sure_domain::status::CheckStatus::Pass).
//! [`PlannedCommand::refusal`] returns `Some` **only** when the decision leaves
//! the check unperformed, and what it returns is [`CheckResult::not_run`] — a
//! `Skipped` result carrying its reason and its weight. A caller that runs an
//! allowed command builds its own result afterwards, from what happened; a caller
//! holding a refused command has nothing to build one from, because no command
//! has run. The plan cannot report a pass for something it did not run, which is
//! the acceptance sentence in the form a reader can check.
//!
//! # Which reason a refusal is reported under
//!
//! **The first permission the command needs that the user has not granted, in
//! [`Permission::ALL`] order** — the vocabulary's own "order shown to a user". A
//! command that needs to install *and* to reach the network reports the install,
//! because the vocabulary lists it first; the full set is on
//! [`PlannedCommand::needs`], and the reason is the headline rather than the
//! list.
//!
//! **The frozen vocabulary has no reason for "this command needs its own approval
//! and has not had it yet", and that case is reported as
//! [`NotCheckedReason::ExecutionNotAuthorized`].** The command is not authorized
//! to execute, which is true whether the obstacle is the mode or the absence of an
//! approval. `UserDeclined` is deliberately not used: nothing has been declined,
//! and a report that said so would be inventing an event — the prompt that can be
//! declined is `P3-T006`'s. `UnknownReason` is not used either: SURE does have a
//! rule here, and it is the vocabulary that is missing a word.
//!
//! # What this does not establish
//!
//! **Nothing about what the command will do when it runs.** [`crate::safety`] says
//! the same thing from its side, and it stays true here: approving `cargo test`
//! approves a command line, not the code behind it.
//!
//! **Nothing about a consent that was actually granted.** This computes what a
//! command needs from the permission set it is handed. Whether the user was asked,
//! what they were shown, and what they answered are
//! [`HostConsent`](sure_domain::execution::HostConsent)'s and `P3-T006`'s, and a
//! test that asserted "the user agreed" from this module's output would be
//! asserting something this module cannot see.
//!
//! **Nothing about ordering, and nothing about how many times a command runs.** A
//! plan is a set of decisions about commands, not a schedule.
//!
//! **Nothing about which checks SURE should have planned.** A plan here is the
//! commands a caller handed over; a command that was never planned cannot be
//! refused by this module, and
//! [`exclude_refused_from`](PermissionPlan::exclude_refused_from) reports that
//! rather than absorbing it.

use std::ffi::{OsStr, OsString};

use sure_domain::execution::{
    CommandClass, CommandEffects, ExecutionDecision, ExecutionMode, ExecutionPermissions,
    Permission,
};
use sure_domain::ids::{CheckId, FingerprintId};
use sure_domain::severity::Severity;
use sure_domain::status::{CheckResult, NotCheckedReason};
use sure_domain::vocabulary::CheckPlan;

use crate::safety::{self, Classification};

/// One permission a command needs, and the category that required it.
///
/// The pair is the whole of "why": a permission on its own says what SURE is
/// asking for, and the category says what the command did to make SURE ask.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Requirement {
    permission: Permission,
    because: CommandClass,
}

impl Requirement {
    /// The permission the command needs.
    #[must_use]
    pub const fn permission(self) -> Permission {
        self.permission
    }

    /// The category that required it.
    #[must_use]
    pub const fn because(self) -> CommandClass {
        self.because
    }

    /// The reason, in the words a consent prompt shows.
    ///
    /// The permission's own prompt is reused rather than restated, so the line a
    /// plan explains itself with is the same line the user is asked with. The two
    /// drifting apart is how a plan comes to describe a question nobody was asked.
    #[must_use]
    pub fn explain(self) -> String {
        format!(
            "{} — because the command {}",
            self.permission.consent_prompt(),
            self.because.plain_description()
        )
    }
}

/// The identity and weight of the check a command belongs to.
///
/// Carried rather than looked up, because a refusal has to be reported as a result
/// and a result needs to know how bad it would be if the check had run and failed.
/// A plan that could not answer that would produce a `Skipped` result that silently
/// forgot it was `MustFix`, which is the shape of a green report built out of
/// things that never happened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedCheck {
    id: CheckId,
    title: String,
    severity: Severity,
    critical: bool,
}

impl PlannedCheck {
    /// Describe the check a command belongs to.
    #[must_use]
    pub fn new(id: CheckId, title: impl Into<String>, severity: Severity, critical: bool) -> Self {
        Self {
            id,
            title: title.into(),
            severity,
            critical,
        }
    }

    /// The check's identity, usable in the report and in evidence anchors.
    #[must_use]
    pub const fn id(&self) -> &CheckId {
        &self.id
    }

    /// The check's short human title.
    #[must_use]
    pub fn title(&self) -> &str {
        &self.title
    }

    /// How bad it is if this check is not satisfied.
    #[must_use]
    pub const fn severity(&self) -> Severity {
        self.severity
    }

    /// Whether the project cannot be trusted for hand-off when this fails.
    #[must_use]
    pub const fn critical(&self) -> bool {
        self.critical
    }
}

/// A command, what it needs, and what happens to it.
///
/// Built by [`PlannedCommand::new`], which classifies and decides in one step so
/// that the two cannot be done separately and then disagree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedCommand {
    check: PlannedCheck,
    program: OsString,
    arguments: Vec<OsString>,
    classification: Classification,
    needs: Vec<Requirement>,
    decision: ExecutionDecision,
    reason: Option<NotCheckedReason>,
}

impl PlannedCommand {
    /// Classify a command and decide whether it may run.
    ///
    /// Takes the program and argument vector, exactly as [`safety::classify`] does
    /// and for the same reason: a caller has these before there is anything to
    /// run, and handing this a
    /// [`ProcessRequest`](crate::process::ProcessRequest) would make planning a
    /// caller of the runner.
    ///
    /// A program name or argument that is not text SURE can read is refused by the
    /// classifier and arrives here as a command that needs everything, which is the
    /// correct outcome and not a special case: SURE cannot say what it would be
    /// approving.
    #[must_use]
    pub fn new<I, S>(
        check: PlannedCheck,
        program: impl Into<OsString>,
        arguments: I,
        mode: ExecutionMode,
        permissions: &ExecutionPermissions,
    ) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        // Kept as the caller gave them, and the classifier is given a copy: what
        // is displayed and what would run have to be the same command line, and a
        // display built from a second reading is a display that can drift.
        let program: OsString = program.into();
        let arguments: Vec<OsString> = arguments.into_iter().map(Into::into).collect();
        let classification = safety::classify(program.clone(), arguments.clone());
        Self::with_classification(check, program, arguments, classification, mode, permissions)
    }

    /// A command the user named in a `--commands-file`.
    ///
    /// Same constructor and the same decision path, with one difference: the
    /// classification is [`Classification::declared_by_user`] rather than the
    /// program table's. The user wrote the argv themselves in a file SURE refuses
    /// to read from inside the project; the command still needs
    /// `run_project_code`, so it runs only under a mode and permission that allow
    /// project code.
    #[must_use]
    pub fn new_declared<I, S>(
        check: PlannedCheck,
        program: impl Into<OsString>,
        arguments: I,
        mode: ExecutionMode,
        permissions: &ExecutionPermissions,
    ) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        Self::with_classification(
            check,
            program.into(),
            arguments.into_iter().map(Into::into).collect(),
            safety::Classification::declared_by_user(),
            mode,
            permissions,
        )
    }

    fn with_classification(
        check: PlannedCheck,
        program: OsString,
        arguments: Vec<OsString>,
        classification: safety::Classification,
        mode: ExecutionMode,
        permissions: &ExecutionPermissions,
    ) -> Self {
        let needs = needs_of(classification.effects());
        let decision = decide_for(classification.effects(), mode, permissions);
        let reason = refusal_reason(
            decision,
            &needs,
            permissions,
            mode,
            classification.effects(),
        );
        Self {
            check,
            program,
            arguments,
            classification,
            needs,
            decision,
            reason,
        }
    }

    /// The check this command belongs to.
    #[must_use]
    pub const fn check(&self) -> &PlannedCheck {
        &self.check
    }

    /// The program, exactly as the caller gave it.
    #[must_use]
    pub fn program(&self) -> &OsStr {
        &self.program
    }

    /// The arguments, one element each and exactly as the caller gave them.
    ///
    /// A vector rather than a string, which is what a caller needs to run the
    /// command without a shell in between — and what a consent record stores so
    /// that nothing is re-parsed later.
    #[must_use]
    pub fn arguments(&self) -> &[OsString] {
        &self.arguments
    }

    /// The categories the command may fall into.
    #[must_use]
    pub fn effects(&self) -> &CommandEffects {
        self.classification.effects()
    }

    /// Why the classifier answered the way it did.
    #[must_use]
    pub fn source(&self) -> safety::Source {
        self.classification.source()
    }

    /// The permissions the command needs, each with the category that required it.
    #[must_use]
    pub fn needs(&self) -> &[Requirement] {
        &self.needs
    }

    /// The decision.
    #[must_use]
    pub const fn decision(&self) -> ExecutionDecision {
        self.decision
    }

    /// Whether the command may run.
    #[must_use]
    pub const fn is_allowed(&self) -> bool {
        self.decision.is_allowed()
    }

    /// Whether the command is waiting on an answer.
    ///
    /// True for a command that needs its own approval — a destructive one, or one
    /// SURE could not read — and for one the mode does not permit but a question
    /// could. The difference from [`Self::is_allowed`] is that a `NeedsConsent`
    /// command may yet run and a `Denied` one may not.
    #[must_use]
    pub const fn needs_consent(&self) -> bool {
        matches!(self.decision, ExecutionDecision::NeedsConsent)
    }

    /// The category that no permission covers, when the command has one.
    ///
    /// This is what makes a command need its own approval rather than a grant:
    /// [`CommandClass::Destructive`] has no permission, so there is nothing to
    /// grant. Exposed because a consent prompt has to say *why* the answer is
    /// "approve this exact command" instead of "grant this permission".
    #[must_use]
    pub fn ungrantable(&self) -> Option<CommandClass> {
        self.classification.ungrantable()
    }

    /// The command line as a person should read it.
    ///
    /// For display only. What would run is [`Self::program`] and
    /// [`Self::arguments`], and nothing anywhere re-parses this: splitting a
    /// command line back into arguments is the act of starting a shell.
    ///
    /// An element that is not text SURE can read is shown with the replacement
    /// character, because there is nothing better to show — and a command with one
    /// cannot run, so this line only ever explains a refusal.
    #[must_use]
    pub fn display(&self) -> String {
        let mut out = self.program.to_string_lossy().into_owned();
        for argument in &self.arguments {
            out.push(' ');
            let text = argument.to_string_lossy();
            if text.contains(' ') || text.contains('"') {
                out.push('"');
                out.push_str(&text.replace('"', "\\\""));
                out.push('"');
            } else {
                out.push_str(&text);
            }
        }
        out
    }

    /// One clause describing what happens to this command.
    #[must_use]
    pub const fn standing(&self) -> &'static str {
        match self.decision {
            ExecutionDecision::Allowed => "This command may run.",
            ExecutionDecision::NeedsConsent => {
                "This command needs approval for this exact command before it runs."
            }
            ExecutionDecision::Denied => "This command will not run.",
        }
    }

    /// Why this command needs what it needs, one line per permission.
    ///
    /// The first acceptance sentence, in the form a report can carry: the command,
    /// what SURE read it as, what happens to it, and — per permission — the
    /// question the user is asked with the reason it is being asked. A command that
    /// needs nothing still gets its first two lines, because "needs nothing" and
    /// "the explanation was not collected" are different facts and a blank space
    /// reads as the second.
    #[must_use]
    pub fn explain(&self) -> Vec<String> {
        let mut lines = vec![
            format!("{} — read as {}.", self.display(), self.effects()),
            self.standing().to_owned(),
        ];
        if let Some(class) = self.ungrantable() {
            lines.push(format!(
                "No permission SURE can ask for covers this: the command {}. It needs your \
                 approval for this exact command, and nothing wider.",
                class.plain_description()
            ));
        }
        for need in &self.needs {
            lines.push(need.explain());
        }
        lines
    }

    /// Why the check will not run, when it will not.
    #[must_use]
    pub const fn reason(&self) -> Option<NotCheckedReason> {
        self.reason
    }

    /// The result for a command that will not run, and `None` for one that will.
    ///
    /// **This is the second acceptance sentence, and it is the only way this
    /// module produces a result.** It cannot produce a passing one: a command that
    /// may run returns `None`, because what to report about it depends on what
    /// happens when it does — and nothing has happened yet. A refused command
    /// returns [`CheckResult::not_run`], which is `Skipped` with its reason and its
    /// weight kept.
    #[must_use]
    pub fn refusal(&self, fingerprint: &FingerprintId) -> Option<CheckResult> {
        let reason = self.reason?;
        Some(CheckResult::not_run(
            self.check.id.clone(),
            self.check.title.clone(),
            self.check.severity,
            self.check.critical,
            reason,
            fingerprint.clone(),
        ))
    }
}

/// The permissions a set of categories needs, each with the category that asked.
///
/// In the set's own canonical order, which is [`CommandClass::ALL`]'s — and that
/// is the order [`Permission::ALL`] lists the four permissions in, so a list of
/// requirements reads in the same order as the prompt built from it. The two
/// orders are held together by a test rather than by a sort, because a sort here
/// would be a second copy of a rule this vocabulary already has, and the copy
/// would be invisible when it drifted.
///
/// One requirement per category, with no de-duplication: the domain's own test
/// requires two categories to need two different permissions, so a command cannot
/// ask for the same permission twice and a branch that merged them would be
/// unreachable.
fn needs_of(effects: &CommandEffects) -> Vec<Requirement> {
    effects
        .classes()
        .iter()
        .filter_map(|class| {
            class.required_permission().map(|permission| Requirement {
                permission,
                because: *class,
            })
        })
        .collect()
}

/// Whether a command may run, by [`decide`](sure_domain::execution::decide)'s rules.
///
/// Written out rather than delegating, because `decide` takes an `ActionKind` and a
/// command is not one — [`CommandEffects`] can hold categories no single
/// `ActionKind` describes. The two are held together by a test that runs both over
/// every category that does have an `ActionKind`, in every mode and under both a
/// read-only and a fully granted permission set, and requires them to agree. That
/// test is not decoration: it is what found `Install` missing from the mode rule.
fn decide_for(
    effects: &CommandEffects,
    mode: ExecutionMode,
    permissions: &ExecutionPermissions,
) -> ExecutionDecision {
    // 1. Every permission the command needs. One missing permission is enough.
    for class in effects.classes() {
        if let Some(permission) = class.required_permission()
            && !permissions.allows(permission)
        {
            return ExecutionDecision::Denied;
        }
    }
    // 2. A category with no permission is never covered by a grant. This is
    //    `ADR 0009`'s rule for arbitrary commands, applied to the other thing SURE
    //    cannot bound, and it is checked before the mode for the same reason
    //    `decide` checks it there.
    if effects
        .classes()
        .iter()
        .any(|class| class.required_permission().is_none())
    {
        return if mode.runs_project_code() {
            ExecutionDecision::NeedsConsent
        } else {
            ExecutionDecision::Denied
        };
    }
    // 3. The mode, last. A mode that is too cautious is a question to ask; a
    //    missing permission is not.
    if runs_project_code(effects) && !mode.has_project_executor() {
        return if mode == ExecutionMode::Container {
            ExecutionDecision::Denied
        } else {
            ExecutionDecision::NeedsConsent
        };
    }
    ExecutionDecision::Allowed
}

/// Whether any category in a set runs code the project controls.
///
/// [`CommandClass::DynamicHost`] obviously, and [`CommandClass::Install`] with it:
/// installing runs a package's own install steps and builds source distributions
/// with the backend they shipped. This is the class-set counterpart of
/// [`ActionKind::executes_project_code`](sure_domain::execution::ActionKind::executes_project_code),
/// and the agreement test is where the two are required to say the same thing.
///
/// [`CommandClass::Network`] and [`CommandClass::Destructive`] are not in it. A
/// fetch runs no project code, which is why `decide` answers `Allowed` for
/// `NetworkAccess` in a mode that runs nothing; and `Destructive` never reaches
/// this rule, because rule 2 answers for it first.
///
/// **Not private, and the one caller outside this module is deliberate.**
/// [`crate::enforce`] asks the same question to decide whether a check is a
/// dynamic one, and the two answers have to be about the same set of categories:
/// a check is dynamic exactly when this function says one of its commands runs
/// project code, so a copy of the rule over there is where the two would drift.
/// A third caller would be one too many.
pub(crate) fn runs_project_code(effects: &CommandEffects) -> bool {
    effects.contains(CommandClass::DynamicHost) || effects.contains(CommandClass::Install)
}

/// The reason a refused check is reported under.
///
/// See the module documentation for the rule, and for why the vocabulary's gap
/// lands on [`NotCheckedReason::ExecutionNotAuthorized`].
fn refusal_reason(
    decision: ExecutionDecision,
    needs: &[Requirement],
    permissions: &ExecutionPermissions,
    mode: ExecutionMode,
    effects: &CommandEffects,
) -> Option<NotCheckedReason> {
    if decision.is_allowed() {
        return None;
    }
    if let Some(need) = needs
        .iter()
        .find(|need| !permissions.allows(need.permission))
    {
        return Some(reason_for(need.permission));
    }
    if mode == ExecutionMode::Container
        && runs_project_code(effects)
        && effects
            .classes()
            .iter()
            .all(|class| class.required_permission().is_some())
    {
        return Some(NotCheckedReason::ContainerExecutionUnavailable);
    }
    Some(NotCheckedReason::ExecutionNotAuthorized)
}

/// The reason a permission the user has not granted is reported under.
const fn reason_for(permission: Permission) -> NotCheckedReason {
    match permission {
        Permission::InstallDependencies => NotCheckedReason::DependencyInstallNotPermitted,
        Permission::Network => NotCheckedReason::NetworkNotPermitted,
        Permission::Inspect
        | Permission::RunProjectCode
        | Permission::WriteProject
        | Permission::ConnectService => NotCheckedReason::ExecutionNotAuthorized,
    }
}

/// Every command a run intends to use, with what each one needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionPlan {
    mode: ExecutionMode,
    fingerprint: FingerprintId,
    permissions: ExecutionPermissions,
    commands: Vec<PlannedCommand>,
}

impl PermissionPlan {
    /// An empty plan, under one mode and one permission set.
    ///
    /// Both are held rather than passed to each [`Self::add`], because a plan is
    /// built under one mode and one set of grants — a per-command pair would
    /// describe a plan whose commands were decided under different rules, which is
    /// not a thing a report could explain.
    #[must_use]
    pub fn new(
        mode: ExecutionMode,
        fingerprint: FingerprintId,
        permissions: ExecutionPermissions,
    ) -> Self {
        Self {
            mode,
            fingerprint,
            permissions,
            commands: Vec::new(),
        }
    }

    /// Plan one command.
    pub fn add<I, S>(&mut self, check: PlannedCheck, program: impl Into<OsString>, arguments: I)
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        self.commands.push(PlannedCommand::new(
            check,
            program,
            arguments,
            self.mode,
            &self.permissions,
        ));
    }

    /// Plan one user-declared command.
    ///
    /// Same plan, same mode and permissions, and the same refusal path; the only
    /// difference is the classification the command carries.
    pub fn add_declared<I, S>(
        &mut self,
        check: PlannedCheck,
        program: impl Into<OsString>,
        arguments: I,
    ) where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        self.commands.push(PlannedCommand::new_declared(
            check,
            program,
            arguments,
            self.mode,
            &self.permissions,
        ));
    }

    /// The execution mode the plan was built under.
    #[must_use]
    pub const fn mode(&self) -> ExecutionMode {
        self.mode
    }

    /// The project state the plan was built for.
    #[must_use]
    pub const fn fingerprint(&self) -> &FingerprintId {
        &self.fingerprint
    }

    /// The permissions the plan was built with.
    #[must_use]
    pub const fn permissions(&self) -> &ExecutionPermissions {
        &self.permissions
    }

    /// Every planned command, in the order they were added.
    #[must_use]
    pub fn commands(&self) -> &[PlannedCommand] {
        &self.commands
    }

    /// Commands that may run.
    pub fn allowed(&self) -> impl Iterator<Item = &PlannedCommand> {
        self.commands.iter().filter(|command| command.is_allowed())
    }

    /// Commands that will not run, for any reason.
    pub fn refused(&self) -> impl Iterator<Item = &PlannedCommand> {
        self.commands.iter().filter(|command| !command.is_allowed())
    }

    /// Every permission the planned commands need, in the order shown to a user.
    ///
    /// The union over all commands, **refused ones included**: a permission a
    /// refused command needed is still one the user would have to grant for that
    /// check to be possible, and dropping it would make the plan's summary disagree
    /// with its own explanations.
    #[must_use]
    pub fn permissions_needed(&self) -> Vec<Permission> {
        Permission::ALL
            .iter()
            .copied()
            .filter(|permission| {
                self.commands.iter().any(|command| {
                    command
                        .needs
                        .iter()
                        .any(|need| need.permission == *permission)
                })
            })
            .collect()
    }

    /// The permissions the plan needs that have not been granted.
    #[must_use]
    pub fn permissions_missing(&self) -> Vec<Permission> {
        self.permissions_needed()
            .into_iter()
            .filter(|permission| !self.permissions.allows(*permission))
            .collect()
    }

    /// Commands waiting on their own approval rather than on a permission.
    pub fn awaiting_own_approval(&self) -> impl Iterator<Item = &PlannedCommand> {
        self.commands
            .iter()
            .filter(|command| command.ungrantable().is_some())
    }

    /// What a report should say about every command: the command, and why.
    #[must_use]
    pub fn explain(&self) -> Vec<String> {
        let mut lines = vec![format!(
            "Execution mode: {}. {}",
            self.mode.as_str(),
            self.mode.plain_description()
        )];
        if self.commands.is_empty() {
            lines.push("No commands are planned.".to_owned());
            return lines;
        }
        for command in &self.commands {
            lines.extend(command.explain());
        }
        lines
    }

    /// A result for every command that will not run.
    ///
    /// Every one of them is `Skipped` with a reason, in the order the commands were
    /// planned. A plan whose commands all run returns an empty list — which is not
    /// a green result and is not treated as one: this says nothing about whether
    /// any check passed.
    #[must_use]
    pub fn refusals(&self) -> Vec<CheckResult> {
        self.refused()
            .filter_map(|command| command.refusal(&self.fingerprint))
            .collect()
    }

    /// Move every refused command's check out of a check plan and record why.
    ///
    /// The bridge to [`CheckPlan`], and the acceptance's second sentence at the
    /// plan's own level: a refused check leaves `static_checks` and
    /// `dynamic_checks` and appears in `excluded` with its reason, so a report
    /// built from the plan sees it as *not checked* rather than as one that ran.
    ///
    /// **Returns the refused checks that were not in the plan**, which is a
    /// caller-visible anomaly rather than something to absorb: a command planned
    /// against a check the plan does not contain is a plan assembled from two
    /// different check sets, and the alternative — discarding
    /// [`CheckPlan::exclude`]'s `false` — is exactly the silent failure this
    /// repository treats as worse than a visible error. Commands that may run are
    /// left alone; this plans, it does not decide what belongs in a plan a caller
    /// built.
    pub fn exclude_refused_from(&self, plan: &mut CheckPlan) -> Vec<CheckId> {
        let mut not_in_the_plan = Vec::new();
        for command in self.refused() {
            let Some(reason) = command.reason() else {
                continue;
            };
            if !plan.exclude(command.check.id(), reason) {
                not_in_the_plan.push(command.check.id().clone());
            }
        }
        not_in_the_plan
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use sure_domain::execution::ActionKind;
    use sure_domain::status::{CheckStatus, aggregate};

    fn fingerprint() -> FingerprintId {
        FingerprintId::generate()
    }

    fn check(title: &str) -> PlannedCheck {
        PlannedCheck::new(CheckId::generate(), title, Severity::MustFix, true)
    }

    fn everything() -> ExecutionPermissions {
        let mut permissions = ExecutionPermissions::inspect_only();
        for permission in Permission::ALL {
            permissions.set(*permission, true);
        }
        permissions
    }

    fn ordered(
        program: &str,
        arguments: &[&str],
        mode: ExecutionMode,
        permissions: &ExecutionPermissions,
    ) -> PlannedCommand {
        PlannedCommand::new(
            check("a check"),
            program,
            arguments.to_vec(),
            mode,
            permissions,
        )
    }

    fn plan_with(mode: ExecutionMode, permissions: ExecutionPermissions) -> PermissionPlan {
        PermissionPlan::new(mode, fingerprint(), permissions)
    }

    #[test]
    fn a_read_only_command_is_allowed_with_only_the_read_permission() {
        let command = ordered(
            "git",
            &["status"],
            ExecutionMode::InspectOnly,
            &ExecutionPermissions::inspect_only(),
        );
        assert_eq!(command.decision(), ExecutionDecision::Allowed);
        assert_eq!(
            command
                .needs()
                .iter()
                .map(|need| need.permission())
                .collect::<Vec<_>>(),
            vec![Permission::Inspect]
        );
        assert_eq!(command.reason(), None);
        assert!(command.refusal(&fingerprint()).is_none());
    }

    #[test]
    fn container_mode_does_not_turn_a_user_grant_into_host_execution() {
        let command = ordered("cargo", &["test"], ExecutionMode::Container, &everything());
        assert_eq!(command.decision(), ExecutionDecision::Denied);
        assert_eq!(
            command.reason(),
            Some(NotCheckedReason::ContainerExecutionUnavailable)
        );
        let result = command.refusal(&fingerprint()).expect("a stopped result");
        assert_eq!(result.status, CheckStatus::Skipped);
        assert!(result.blocks_green());
        assert!(result.reason.contains("cannot run checks in a container"));

        let on_host = ordered(
            "cargo",
            &["test"],
            ExecutionMode::HostConfirmed,
            &everything(),
        );
        assert!(
            on_host.is_allowed(),
            "the host mode remains available by consent"
        );
    }

    #[test]
    fn one_missing_permission_of_several_is_enough_to_deny() {
        // `cargo add serde` installs a package and reaches the registry, so it
        // needs two permissions and the second one is the one that is missing.
        let mut permissions = everything();
        permissions.set(Permission::Network, false);
        let command = ordered(
            "cargo",
            &["add", "serde"],
            ExecutionMode::HostConfirmed,
            &permissions,
        );
        assert_eq!(command.decision(), ExecutionDecision::Denied);
        assert!(!command.is_allowed());
        assert_eq!(
            command.reason(),
            Some(NotCheckedReason::NetworkNotPermitted),
            "the reason names the permission that is actually missing"
        );
    }

    #[test]
    fn a_user_declared_command_is_dynamic_only_even_when_the_table_does_not_know_it() {
        // `frobnicate` is not in the program table, so the normal path would
        // classify it as install/network/destructive and refuse it. A command
        // the user named in a commands file is the user's own argv; it needs
        // only `run_project_code`, exactly as a package script does.
        let mut permissions = ExecutionPermissions::inspect_only();
        permissions.set(Permission::RunProjectCode, true);
        let mut plan =
            PermissionPlan::new(ExecutionMode::HostConfirmed, fingerprint(), permissions);
        plan.add_declared(check("a declared test"), "frobnicate", ["--everything"]);

        let command = &plan.commands()[0];
        assert_eq!(
            command.source(),
            safety::Source::Rule {
                program: "a command you declared",
                decided_by: None,
            }
        );
        assert!(command.reason().is_none(), "{:?}", command.reason());
        assert_eq!(command.effects().classes(), &[CommandClass::DynamicHost]);
    }

    #[test]
    fn an_allowed_command_says_what_it_is_and_what_it_needs() {
        let command = ordered(
            "git",
            &["status"],
            ExecutionMode::InspectOnly,
            &ExecutionPermissions::inspect_only(),
        );
        let lines = command.explain();
        assert!(lines[0].contains("git status"), "{lines:?}");
        assert!(lines[0].contains("read as static"), "{lines:?}");
        assert!(
            lines.iter().any(|line| line.contains("may run")),
            "{lines:?}"
        );
        assert!(
            lines
                .iter()
                .any(|line| line.contains("because the command only reads things")),
            "the permission and the reason are on one line: {lines:?}"
        );
    }

    #[test]
    fn every_category_with_a_permission_gets_exactly_one_requirement() {
        let command = ordered(
            "cargo",
            &["add", "serde"],
            ExecutionMode::HostConfirmed,
            &everything(),
        );
        assert_eq!(
            command
                .needs()
                .iter()
                .map(|need| need.permission())
                .collect::<Vec<_>>(),
            vec![Permission::InstallDependencies, Permission::Network]
        );
        for need in command.needs() {
            assert_eq!(
                need.because().required_permission(),
                Some(need.permission()),
                "a requirement names the category that really required it"
            );
        }
    }

    #[test]
    fn requirements_are_listed_in_the_order_the_vocabulary_shows_permissions() {
        // The list of requirements is built in `CommandClass::ALL` order, and the
        // prompt is built in `Permission::ALL` order. This is the test that stops
        // the two drifting: reorder either enum and a command that needs two
        // permissions starts explaining itself in the other order.
        for (program, arguments) in [
            ("cargo", vec!["add", "serde"]),
            ("npm", vec!["install"]),
            ("python", vec!["-m", "pip", "install", "requests"]),
            ("frobnicate", vec!["--everything"]),
        ] {
            let command = ordered(
                program,
                &arguments,
                ExecutionMode::HostConfirmed,
                &everything(),
            );
            let positions: Vec<usize> = command
                .needs()
                .iter()
                .map(|need| {
                    Permission::ALL
                        .iter()
                        .position(|permission| *permission == need.permission())
                        .unwrap()
                })
                .collect();
            let mut sorted = positions.clone();
            sorted.sort_unstable();
            assert_eq!(
                positions, sorted,
                "{program} listed its needs out of the order a prompt reads in"
            );
        }
    }

    #[test]
    fn a_command_no_permission_covers_is_never_covered_by_a_grant() {
        // `git clean` is destruction and nothing else, so it needs no permission
        // at all — and the point is that granting every permission SURE has changes
        // nothing. That is what "no permission covers it" means.
        let command = ordered(
            "git",
            &["clean"],
            ExecutionMode::HostConfirmed,
            &everything(),
        );
        assert_eq!(command.decision(), ExecutionDecision::NeedsConsent);
        assert_eq!(command.ungrantable(), Some(CommandClass::Destructive));
        assert!(
            command.needs().is_empty(),
            "a command no permission covers needs no permission: {:?}",
            command.needs()
        );

        let nothing_granted = ordered(
            "git",
            &["clean"],
            ExecutionMode::HostConfirmed,
            &ExecutionPermissions::inspect_only(),
        );
        assert_eq!(
            nothing_granted.decision(),
            command.decision(),
            "every permission granted had to be the same answer as none"
        );
    }

    #[test]
    fn a_command_no_permission_covers_is_denied_in_a_mode_that_runs_nothing() {
        for (program, arguments) in [("git", vec!["clean"]), ("git", vec!["push", "--force"])] {
            let command = ordered(
                program,
                &arguments,
                ExecutionMode::InspectOnly,
                &everything(),
            );
            assert_eq!(
                command.decision(),
                ExecutionDecision::Denied,
                "{program} {arguments:?} was left waiting for an answer in a mode that runs nothing"
            );
            assert!(!command.needs_consent());
            assert_eq!(
                command.reason(),
                Some(NotCheckedReason::ExecutionNotAuthorized)
            );
        }
    }

    #[test]
    fn a_command_sure_could_not_read_is_never_allowed_by_a_grant() {
        for (program, arguments) in [
            ("frobnicate", vec!["--everything"]),
            ("git", vec!["frobnicate"]),
            ("npm.cmd", vec!["install"]),
            ("cmd", vec!["/c", "del", "everything"]),
        ] {
            let command = ordered(
                program,
                &arguments,
                ExecutionMode::HostConfirmed,
                &everything(),
            );
            assert!(
                !command.is_allowed(),
                "{program} {arguments:?} was allowed with every permission granted"
            );
            assert_eq!(
                command.decision(),
                ExecutionDecision::NeedsConsent,
                "a command SURE could not read needs its own approval rather than a grant"
            );
            assert_eq!(command.ungrantable(), Some(CommandClass::Destructive));
        }
    }

    #[test]
    fn a_refused_command_never_produces_a_passing_result() {
        let cases: &[(&str, &[&str], ExecutionMode, bool)] = &[
            ("git", &["status"], ExecutionMode::InspectOnly, false),
            ("npm", &["test"], ExecutionMode::InspectOnly, false),
            ("npm", &["test"], ExecutionMode::HostConfirmed, false),
            (
                "cargo",
                &["add", "serde"],
                ExecutionMode::HostConfirmed,
                false,
            ),
            ("git", &["clean"], ExecutionMode::HostConfirmed, true),
            (
                "git",
                &["push", "--force"],
                ExecutionMode::HostConfirmed,
                true,
            ),
            ("frobnicate", &["--all"], ExecutionMode::HostConfirmed, true),
            ("frobnicate", &["--all"], ExecutionMode::InspectOnly, true),
        ];
        let mut refused = 0;
        for (program, arguments, mode, all_granted) in cases {
            let permissions = if *all_granted {
                everything()
            } else {
                ExecutionPermissions::inspect_only()
            };
            let command = ordered(program, arguments, *mode, &permissions);
            let Some(result) = command.refusal(&fingerprint()) else {
                continue;
            };
            refused += 1;
            assert_eq!(
                result.status,
                CheckStatus::Skipped,
                "{program} {arguments:?} did not become skipped"
            );
            assert_ne!(result.status, CheckStatus::Pass);
            assert_eq!(
                result.not_checked_reason,
                command.reason(),
                "the result carries the reason the command was refused for"
            );
            assert_eq!(result.severity, Severity::MustFix, "the weight is kept");
            assert!(result.critical, "criticality is kept");
            assert!(!result.reason.is_empty(), "a skipped check explains itself");
            assert!(
                !aggregate(&[result]).is_green(),
                "a refused critical check must not aggregate to green"
            );
        }
        assert!(
            refused >= 6,
            "the walk refused only {refused} of its cases, so it is not testing what it says"
        );
    }

    #[test]
    fn an_allowed_command_produces_no_result_at_all() {
        let command = ordered(
            "git",
            &["status"],
            ExecutionMode::InspectOnly,
            &ExecutionPermissions::inspect_only(),
        );
        assert!(command.is_allowed());
        assert_eq!(command.reason(), None);
        assert!(
            command.refusal(&fingerprint()).is_none(),
            "nothing has run, so there is nothing to report"
        );
    }

    #[test]
    fn the_reason_names_the_first_missing_permission_in_the_vocabularys_order() {
        // Both the install and the network are missing. The vocabulary lists the
        // install first, and the headline follows it.
        let command = ordered(
            "cargo",
            &["add", "serde"],
            ExecutionMode::HostConfirmed,
            &ExecutionPermissions::inspect_only(),
        );
        assert_eq!(
            command.reason(),
            Some(NotCheckedReason::DependencyInstallNotPermitted)
        );

        // With the install granted, the same command reports the network.
        let mut permissions = ExecutionPermissions::inspect_only();
        permissions.set(Permission::InstallDependencies, true);
        let command = ordered(
            "cargo",
            &["add", "serde"],
            ExecutionMode::HostConfirmed,
            &permissions,
        );
        assert_eq!(
            command.reason(),
            Some(NotCheckedReason::NetworkNotPermitted)
        );
    }

    #[test]
    fn a_mode_that_is_too_cautious_asks_and_a_missing_permission_does_not() {
        // The permission is granted and the mode does not run project code: there
        // is a question to ask.
        let command = ordered("npm", &["test"], ExecutionMode::InspectOnly, &everything());
        assert_eq!(command.decision(), ExecutionDecision::NeedsConsent);
        // The permission is missing: SURE is not going to ask.
        let command = ordered(
            "npm",
            &["test"],
            ExecutionMode::HostConfirmed,
            &ExecutionPermissions::inspect_only(),
        );
        assert_eq!(command.decision(), ExecutionDecision::Denied);
    }

    #[test]
    fn an_install_is_askable_in_a_mode_that_runs_nothing_because_installing_runs_code() {
        // The finding this task produced. With every permission granted and a mode
        // that runs nothing, an install is still a question rather than an answer
        // — because installing runs a package's own install steps. A rule that
        // consulted the mode only for `DynamicHost` said `Allowed` here, and the
        // domain's own decider says otherwise.
        let command = ordered(
            "cargo",
            &["add", "serde"],
            ExecutionMode::InspectOnly,
            &everything(),
        );
        assert_eq!(command.decision(), ExecutionDecision::NeedsConsent);
        assert_eq!(
            sure_domain::execution::decide(
                ActionKind::InstallDependencies,
                ExecutionMode::InspectOnly,
                &everything()
            ),
            ExecutionDecision::NeedsConsent,
            "the domain agrees, which is why the rule was written this way"
        );
    }

    #[test]
    fn a_command_plan_cannot_disagree_with_the_domains_own_decider() {
        // The one place the two rules could drift, checked rather than asserted.
        let pairs = [
            (CommandClass::Static, ActionKind::StaticAnalysis),
            (CommandClass::DynamicHost, ActionKind::RunTests),
            (CommandClass::Install, ActionKind::InstallDependencies),
            (CommandClass::Network, ActionKind::NetworkAccess),
        ];
        for mode in [
            ExecutionMode::InspectOnly,
            ExecutionMode::HostConfirmed,
            ExecutionMode::Container,
        ] {
            for permissions in [ExecutionPermissions::inspect_only(), everything()] {
                for (class, action) in pairs {
                    let effects = CommandEffects::single(class);
                    assert_eq!(
                        decide_for(&effects, mode, &permissions),
                        sure_domain::execution::decide(action, mode, &permissions),
                        "{class:?} under {mode:?} disagreed with `decide` for {action:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn a_mode_that_runs_nothing_never_leaves_a_command_waiting_for_an_answer() {
        // The one place this module is deliberately stricter than `decide`, and the
        // direction is the point. `decide` answers `NeedsConsent` for an arbitrary
        // command whenever `RunProjectCode` is granted, without looking at the mode
        // — which is only reachable with a permission set that contradicts the
        // mode, since inspect-only's own baseline grants nothing else. SURE's answer
        // is `Denied`: a mode whose promise is that nothing runs cannot be the mode
        // that offers to run this.
        let cases: &[(&str, &[&str])] = &[
            ("frobnicate", &["--all"]),
            ("git", &["clean"]),
            ("git", &["push", "--force"]),
            ("rm", &["-rf", ".."]),
        ];
        for (program, arguments) in cases {
            let command = ordered(
                program,
                arguments,
                ExecutionMode::InspectOnly,
                &everything(),
            );
            assert_eq!(
                command.decision(),
                ExecutionDecision::Denied,
                "{program} {arguments:?} was left waiting in a mode that runs nothing"
            );
            assert!(!command.is_allowed());
        }
        assert_eq!(
            sure_domain::execution::decide(
                ActionKind::ArbitraryCommand,
                ExecutionMode::InspectOnly,
                &everything()
            ),
            ExecutionDecision::NeedsConsent,
            "this is the disagreement, stated: `decide` asks, and SURE here says no"
        );
    }

    #[test]
    fn a_plan_collects_the_permissions_it_would_need_and_only_those() {
        let mut plan = plan_with(ExecutionMode::HostConfirmed, everything());
        plan.add(check("tests"), "npm", ["test"]);
        plan.add(check("status"), "git", ["status"]);
        assert_eq!(
            plan.permissions_needed(),
            vec![Permission::Inspect, Permission::RunProjectCode]
        );
        assert!(plan.permissions_missing().is_empty());

        let mut plan = plan_with(
            ExecutionMode::HostConfirmed,
            ExecutionPermissions::inspect_only(),
        );
        plan.add(check("tests"), "npm", ["test"]);
        plan.add(check("install"), "cargo", ["add", "serde"]);
        assert_eq!(
            plan.permissions_missing(),
            vec![
                Permission::RunProjectCode,
                Permission::InstallDependencies,
                Permission::Network
            ],
            "a refused command's permissions are still permissions the plan needs"
        );
    }

    #[test]
    fn a_plan_with_nothing_planned_says_so_rather_than_printing_nothing() {
        let plan = plan_with(
            ExecutionMode::InspectOnly,
            ExecutionPermissions::inspect_only(),
        );
        let lines = plan.explain();
        assert!(lines[0].contains("inspect_only"), "{lines:?}");
        assert!(
            lines
                .iter()
                .any(|line| line.contains("No commands are planned")),
            "{lines:?}"
        );
        assert!(plan.refusals().is_empty());
        assert!(plan.permissions_needed().is_empty());
        assert_eq!(plan.allowed().count(), 0);
    }

    /// The plan's own explanation, which is the first acceptance sentence at the
    /// level a report prints it.
    ///
    /// **This test is here because `mutate21.py` reported that the plan's
    /// `explain` had no test at all.** Deleting the loop that appends each
    /// command's lines left the whole suite green: `PlannedCommand::explain` is
    /// covered from several directions, and the plan's — which is the one a
    /// report actually calls — was covered from none. A report that names the
    /// execution mode and then stops is not a plan that explains itself, and it
    /// is the shape this whole task is against: a set of commands that looks
    /// described and is not.
    ///
    /// The count is taken from the commands rather than written down, so this
    /// pins *every command, exactly once* without becoming a second copy of the
    /// layout that has to be edited whenever a line is added to it.
    #[test]
    fn a_plan_explains_every_command_it_holds() {
        let mut plan = plan_with(
            ExecutionMode::InspectOnly,
            ExecutionPermissions::inspect_only(),
        );
        plan.add(check("status"), "git", ["status"]);
        plan.add(check("tests"), "npm", ["test"]);

        let lines = plan.explain();
        assert!(
            lines[0].contains(ExecutionMode::InspectOnly.plain_description()),
            "the plan opens by saying what it will do, in the mode's own words: {lines:?}"
        );
        for command in plan.commands() {
            for line in command.explain() {
                assert!(
                    lines.contains(&line),
                    "the plan does not explain {}: {line:?} is missing from {lines:?}",
                    command.display()
                );
            }
        }
        assert_eq!(
            lines.len(),
            1 + plan
                .commands()
                .iter()
                .map(|command| command.explain().len())
                .sum::<usize>(),
            "the plan's explanation is the mode line plus every command's own lines, \
             with nothing dropped and nothing invented: {lines:?}"
        );
    }

    #[test]
    fn refusing_a_command_takes_its_check_out_of_the_check_plan() {
        let fingerprint = fingerprint();
        let mut plan = PermissionPlan::new(
            ExecutionMode::InspectOnly,
            fingerprint.clone(),
            ExecutionPermissions::inspect_only(),
        );
        let allowed = check("status");
        let refused = check("tests");
        plan.add(allowed.clone(), "git", ["status"]);
        plan.add(refused.clone(), "npm", ["test"]);

        let mut check_plan = CheckPlan::new("plan-1", fingerprint, ExecutionMode::InspectOnly);
        check_plan.static_checks.push(allowed.id().clone());
        check_plan.dynamic_checks.push(refused.id().clone());
        let not_in_the_plan = plan.exclude_refused_from(&mut check_plan);

        assert_eq!(not_in_the_plan, Vec::<CheckId>::new());
        assert_eq!(check_plan.dynamic_checks, Vec::<CheckId>::new());
        assert_eq!(check_plan.static_checks, vec![allowed.id().clone()]);
        assert_eq!(
            check_plan.excluded,
            vec![NotCheckedReason::ExecutionNotAuthorized]
        );
        assert!(
            !check_plan.all_checks().contains(&&refused.id().clone()),
            "an excluded check is not among the plan's runnable checks"
        );
        assert!(
            check_plan.all_checks().contains(&&allowed.id().clone()),
            "a command that may run is left where it was"
        );
    }

    #[test]
    fn a_refused_check_the_plan_never_held_is_reported_rather_than_absorbed() {
        // `CheckPlan::exclude` says `false` when the check was not planned, and a
        // caller that dropped that answer would see a command silently vanish into
        // a reason list. It comes back instead — and the plan it was asked to
        // exclude from is left alone, all the way down to the reasons.
        let plan = {
            let mut plan = plan_with(
                ExecutionMode::InspectOnly,
                ExecutionPermissions::inspect_only(),
            );
            plan.add(check("tests"), "npm", ["test"]);
            plan
        };
        let mut check_plan = CheckPlan::new("plan-2", fingerprint(), ExecutionMode::InspectOnly);
        let missing = plan.exclude_refused_from(&mut check_plan);
        assert_eq!(
            missing,
            vec![plan.commands()[0].check().id().clone()],
            "the check nobody planned is named"
        );
        assert!(
            check_plan.excluded.is_empty(),
            "a plan that never held the check has nothing to have excluded, so it \
             must not gain a reason for a check it does not mention: {:?}",
            check_plan.excluded
        );
        assert!(check_plan.all_checks().is_empty());
    }

    #[test]
    fn the_command_line_a_plan_shows_is_the_one_it_would_run() {
        let command = ordered(
            "cargo",
            &["test", "--package", "a b"],
            ExecutionMode::HostConfirmed,
            &everything(),
        );
        assert_eq!(command.program(), OsStr::new("cargo"));
        assert_eq!(command.arguments().len(), 3);
        assert_eq!(command.display(), "cargo test --package \"a b\"");
    }

    #[test]
    fn an_ungrantable_command_says_why_a_permission_will_not_do() {
        let command = ordered(
            "git",
            &["clean"],
            ExecutionMode::HostConfirmed,
            &everything(),
        );
        let lines = command.explain();
        assert!(
            lines.iter().any(|line| line.contains(
                "No permission SURE can ask for covers this: the command can destroy data"
            )),
            "{lines:?}"
        );
        assert!(
            lines
                .iter()
                .any(|line| line.contains("needs approval for this exact command")),
            "{lines:?}"
        );

        let plan = {
            let mut plan = plan_with(ExecutionMode::HostConfirmed, everything());
            plan.add(check("clean"), "git", ["clean"]);
            plan
        };
        assert_eq!(plan.awaiting_own_approval().count(), 1);
        assert_eq!(plan.allowed().count(), 0);
        assert_eq!(plan.refusals().len(), 1);
        assert_eq!(plan.refusals()[0].status, CheckStatus::Skipped);
    }
}
