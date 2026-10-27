//! The checks a discovered project's own declarations turn into.
//!
//! This is step 4 of `docs/architecture/CHECK_PIPELINE.md` — *"Plan
//! static/dynamic checks and execution trust requirements."* — and it is the
//! first place in the product where a check is proposed.
//! [`crate::schedule`] is the machinery that orders and gates proposals, and
//! until this module existed nothing handed it one; `tests/check_schedule.rs`
//! says in its own documentation that it is written to fail on the day that
//! changed, and that day is `P4-T002`.
//!
//! # It adds no file access of its own
//!
//! Every fact a check here rests on is a field of a discovery result. Nothing in
//! this module opens a manifest, resolves a dependency, looks at
//! `node_modules`, or runs anything: the reading is [`crate::discover`]'s job
//! and this layer only decides what the reading means for a plan. That is not a
//! style preference — a proposer that read a file the scan had not walked would
//! be able to propose a check on evidence the report cannot point at, and
//! `docs/architecture/EVIDENCE_MODEL.md` calls an anchorless claim unsupported.
//!
//! # The two sentences this layer is arranged around
//!
//! **A check SURE would run is gated by the execution mode, and the gating
//! happens elsewhere.** Every check proposed here declares an
//! [`ActionKind`](sure_domain::execution::ActionKind) that
//! [`executes_project_code`](sure_domain::execution::ActionKind::executes_project_code)
//! answers `true` for, so under
//! [`InspectOnly`](sure_domain::execution::ExecutionMode::InspectOnly) every one
//! of them is refused by [`decide`](sure_domain::execution::decide) and comes
//! back from [`CheckSchedule`](crate::schedule::CheckSchedule) as an entry that
//! would not run. Nothing in this module makes that decision — it cannot, since
//! a decision is not a property of a check — and
//! `a_declared_check_runs_only_under_a_mode_that_allows_it` is where that is
//! held rather than asserted.
//!
//! **A command the project does not have never becomes a pass.** This is the
//! half that has no plan entry to hide in. Where a project gives SURE no command
//! for a check, there is nothing to schedule, and the honest answer is a
//! [`MissingCommand`]: an identity, the title the check would have had, and why
//! there is no command for it. [`MissingCommand::not_checked`] turns one into a
//! [`CheckResult`] by way of the domain's own `not_run` constructor, so the only
//! status it can produce is a *skipped* one — and the test
//! `every_missing_command_is_skipped_and_none_of_them_is_a_pass` says so over
//! the whole vocabulary of reasons rather than over the ones somebody thought
//! of.
//!
//! # The vocabulary gap this layer exists to name
//!
//! [`NotCheckedReason`] is frozen and has ten variants, and **none of them means
//! "the project declares this and what it declares is not something SURE can
//! run"**. The nearest is [`NotApplicable`](NotCheckedReason::NotApplicable) —
//! *"This check does not apply to your project."* — which is close for a check
//! the project declares no command for and false for one where the project
//! declared a command and wrote it in a shape that is not a command.
//!
//! [`MissingKind`] is SURE's own answer, and it is the shape
//! [`crate::browser`]'s `AbsenceReason` already has: **the frozen reason is what
//! a report groups by, and SURE's own sentence is what it prints.** The two are
//! separate because they answer separate questions, and because the frozen
//! enum's `is_scope_limit` is load-bearing —
//! [`blocks_green`](sure_domain::status::CheckResult::blocks_green) reads it to
//! decide whether a critical check that did not run holds the run out of green —
//! so the choice is not free and each variant below argues for its own.
//!
//! # What it does not do
//!
//! **It does not decide whether a check passes.** There is no result here except
//! the skipped one a missing command produces, and no path from this module to
//! [`CheckStatus`](sure_domain::status::CheckStatus) other than through
//! `CheckResult::not_run`.
//!
//! **It does not run anything.** Nothing here builds a
//! [`Command`](std::process::Command); the execution trust requirements the
//! acceptance names are the [`ActionKind`](sure_domain::execution::ActionKind)
//! each proposal declares, which is the same thing
//! `tests/spawn_sites.rs` counts the callers of.
//!
//! **It is not the only proposer.** `P4-T003` added [`python`] beside [`node`],
//! `P4-T004` added [`rust`] beside them, and the reason the identifier scheme
//! lives here rather than in any one of them is that the identifiers share a
//! namespace: two ecosystems describing one directory must not name one check
//! twice. [`MissingKind`] is the vocabulary they have in common without any of
//! them producing all of it, and [`evidence_of`] is the second thing they share
//! without sharing a rule — it is the one door from a finished check to the
//! evidence it is worth, and it takes the state off the result rather than from
//! its caller. [`python`]'s documentation said `P4-T004` would add a third
//! proposer and that the module would be a diff to this paragraph; it was.
//!
//! # What the three proposers share now that they propose work
//!
//! Since `P18-T003` a proposer hands over typed work rather than a rendered
//! command, and the parts all three of them need are here: [`command_operation`]
//! turns a program, an argument vector and a directory into the operation a check
//! carries, [`component_directory`] derives a member's directory from the manifest
//! path the scan spells it by, and [`CHECK_LIMITS`] is the one deadline and output
//! bound every declared check runs under. **They are here rather than repeated in
//! each proposer because they are policy**, and three copies of a deadline are
//! three deadlines.
//!
//! What is deliberately *not* here is any way to get a program name or an argument
//! vector out of text. Each proposer builds those from its own typed discovery
//! values — [`node`] from a script's own name and the package manager, [`python`]
//! from an installer and a tool, [`rust`] from `cargo` and a subcommand — and a
//! shared function taking a rendered line would be the parse
//! `docs/adr/0014-planned-check-execution-contract.md` rejected, moved one module
//! up rather than avoided.
//!
//! **It witnesses nothing about whether these checks are the right ones.** A
//! `package.json` that declares `"test": "true"` gets a test check that passes,
//! and nothing here can tell. Choosing good checks is not a thing a table of
//! conventions can do, and the module says so rather than implying otherwise —
//! the same limit [`crate::browser`] states about its drivers.
//!
//! **A detector's proposal needs an operation too, and it has no program to
//! name.** Since `P18-T003` every proposed check carries one, so the places that
//! propose from a *reading* rather than from a declared command — the candidate
//! scanners, the runtime probes, the flow steps and the corpus fixtures — carry
//! a [`PrecomputedEvidence`](crate::planned_work::PrecomputedEvidence) built from
//! the reading they made. `P18-T003` gave every one of them one shared
//! placeholder for that and named `P18-T004` as its owner; `P18-T004` removed it,
//! and each site now writes its own detector's observation. Every one of them is
//! a *candidate*, because a reading settles nothing about a project that was
//! never run — and a candidate is never a pass. The three ecosystem proposers
//! above are untouched by that: they hold a program and an argument vector and
//! plan a command.

pub mod dotnet;
pub mod go;
pub mod node;
pub mod python;
pub mod rust;

use std::path::{Path, PathBuf};
use std::time::Duration;

use sure_domain::evidence::{Evidence, EvidenceAnchor, EvidenceClass};
use sure_domain::ids::{CheckId, FingerprintId};
use sure_domain::severity::Severity;
use sure_domain::status::{CheckResult, CheckStatus, NotCheckedReason};

use crate::fingerprint::digest::Digest;
use crate::planned_work::{CheckOperation, CommandSpec};
use crate::process::{Environment, Limits};

/// The domain tag for a check identifier.
///
/// A version is in the name because the recipe below is what makes an old
/// result's identifier findable in a new run, and a recipe that changed without
/// saying so would silently orphan every stored result. Changing this string is
/// the honest way to change the recipe, and it is a decision rather than an
/// edit.
const ID_DOMAIN: &str = "sure.check-id.v1";

/// How many hexadecimal characters of the digest an identifier carries.
///
/// Sixty-four bits, which is not a security boundary and is not treated as one.
/// What actually protects against two components sharing an identifier is not
/// this number but the fact that a collision is *reported*: two checks with one
/// identifier end up in [`CheckSchedule::duplicates`](crate::schedule::CheckSchedule::duplicates)
/// rather than being silently merged, so the failure mode of a truncated digest
/// is a visible one. Finding a collision takes on the order of 2^64 hashes for
/// a component path somebody else chose, which is the reason the truncation is
/// affordable at all.
const ID_HEX: usize = 16;

/// The identifier a check for a component and a tag always has.
///
/// **Deterministic on purpose, and that is the whole of its job.** A check's
/// identity is what joins a result from one run to the plan that proposed it in
/// another — `docs/architecture/CHECK_PIPELINE.md` steps 11 and 12 are the
/// repair contract and the re-check, and neither can look a check up if the
/// second run named it something else. `CheckId::generate` is therefore not
/// usable here and its absence from this file is deliberate.
///
/// `component` is the file the check is about — a manifest path, as the scan
/// spells it — and `tag` is the readable half: `nodetest`, and one day
/// `pythonlint`. **The tag is not trusted**: everything outside `[a-z0-9]` is
/// dropped, and the digest is taken over the raw text, so two tags that read
/// alike after dropping (`node-test` and `nodetest`) still get different
/// identifiers.
///
/// # Panics
///
/// Does not, and the reason it can be written as though it cannot is checked
/// rather than asserted:
/// `an_identifier_is_well_formed_for_every_tag_and_component_this_can_be_given`
/// sweeps components and tags with spaces, punctuation, Unicode, path
/// separators, the empty string and lengths past the Windows path limit.
#[allow(
    clippy::expect_used,
    reason = "the body is the tag with every character outside [a-z0-9] dropped, \
              then ID_HEX lowercase hexadecimal characters, under the literal \
              prefix `chk_` — a string CheckId::parse cannot reject. The sweep in \
              `an_identifier_is_well_formed_for_every_tag_and_component_this_can_be_given` \
              holds that over the hostile inputs rather than this sentence \
              asserting it, and a panic here would be a bug this crate's \
              `unwrap_used` rule is right to forbid"
)]
#[must_use]
pub fn check_id(component: &str, tag: &str) -> CheckId {
    let mut digest = Digest::new(ID_DOMAIN);
    digest.field(component).field(tag);
    let digest = digest.finish();

    let mut body: String = tag
        .chars()
        .filter(|character| character.is_ascii_lowercase() || character.is_ascii_digit())
        .collect();
    body.extend(digest.chars().take(ID_HEX));

    CheckId::parse(format!("{}_{body}", CheckId::KIND.prefix()))
        .expect("the body is built from [a-z0-9] and lowercase hexadecimal")
}

/// How long a declared check has, and how much of what it says SURE keeps.
///
/// **One policy for every declared check, written down where it can be argued
/// with.** A check with no deadline is a check that hangs, and a check that hangs
/// is indistinguishable from one that is still working — so there is no
/// `Limits::default` for this to fall back on and no proposer decides for itself.
/// Fifteen minutes is long enough for a cold build or a full test suite on the
/// projects this build is aimed at, and short enough that a stuck check is a
/// reported failure rather than a run nobody can end; the output bounds are wide
/// enough that an ordinary log fits and small enough that a program printing in a
/// loop cannot exhaust memory.
///
/// **Truncation is not silent.** `docs/adr/0014-planned-check-execution-contract.md`
/// decision 7 makes materially truncated output an error rather than a pass, so
/// these two numbers are the point at which a check's result stops being `Pass`
/// — which is why they are here, in one place, rather than four.
///
/// `pub(crate)` since `P18-T012`'s follow-up, for [`crate::service_plan`]: a
/// declared service's command is a declared check's command, run on the same
/// machine under the same mode, so it is planned under this policy rather than
/// under a second one written beside it. Two numbers that mean *how long a check
/// may take* and disagree are a check that reports differently depending on
/// which proposer built it.
pub(crate) const CHECK_LIMITS: Limits =
    Limits::new(Duration::from_secs(15 * 60), 256 * 1024, 256 * 1024);

/// A check's command, as typed work.
///
/// `program` is a program's *name* — `npm`, `python`, `cargo` — and never a
/// command line: an argument with a space in it is one argument and stays one,
/// because the operating system is handed the vector rather than a string somebody
/// split. The three ecosystem proposers call this with values they already hold
/// typed, which is the whole of `P18-T003`: the `npm run build` a report prints is
/// a rendering of the same decision and not its source.
///
/// **`directory` must be absolute**, and that is [`process`](crate::process)'s
/// rule — `ProcessRequest` refuses a relative directory, and
/// [`CommandSpec::new`](crate::planned_work::CommandSpec::new) deliberately does
/// not repeat the refusal, so that there is one place it is enforced rather than
/// two that can disagree. What holds the rule here is the callers and their
/// source: every one passes the scan's root joined with a component path, and
/// `scan::open_root` refuses a root that is not absolute, so there is no path from
/// here to a command whose directory is relative to whatever SURE happened to be
/// started in. **This function does not enforce it**, and a reader who takes the
/// guarantee from the constructor rather than from the refusal downstream would
/// be reading it from the wrong place.
///
/// **The environment is SURE's own**, because of what a check is: `npm` finds
/// `node`, and `cargo` finds the linker, by name and through `PATH`. ADR 0014's
/// decision 11 — a *service* is not given SURE's environment, and gets the
/// machine's own minimum instead — is about programs SURE starts for a project,
/// where the environment is part of what is being observed; a declared check is
/// the project's own command run in the user's own
/// shell's environment, and a check that could not find `node` would report a
/// missing toolchain that is installed.
#[must_use]
pub(crate) fn command_operation(
    program: &str,
    directory: &Path,
    arguments: &[&str],
) -> CheckOperation {
    CheckOperation::Command(
        CommandSpec::new(program, directory, Environment::inherited(), CHECK_LIMITS)
            .with_arguments(arguments.iter().copied()),
    )
}

/// The absolute directory a component's manifest sits in.
///
/// `manifest` is a path the scan spells a component by — `package.json` for the
/// project's own manifest, `packages/web/package.json` for a workspace member —
/// and the answer is the project root for the first and the root joined with the
/// member's own directory for the second. **This is the case ADR 0014 says a parsed
/// display string could not represent**: the directory a member's check runs in is
/// not in the rendered command at all, and it is here because the discovery has the
/// member's path as a value.
///
/// The empty parent — what `Path::parent` answers for a bare file name — is folded
/// into the root rather than joined onto it: `root.join("")` is the root *with a
/// trailing separator*, which is a different string and, on Windows, can be a
/// different path to a program that cares. `runtime_probes.rs` has the same
/// derivation one layer up and keeps the empty path, because there it is a
/// component identity rather than a directory to run something in.
#[must_use]
pub(crate) fn component_directory(root: &Path, manifest: &str) -> PathBuf {
    match Path::new(manifest).parent() {
        Some(directory) if !directory.as_os_str().is_empty() => root.join(directory),
        _ => root.to_path_buf(),
    }
}

/// Why SURE has no command for a check it would otherwise propose.
///
/// See the module documentation for why this type exists at all rather than a
/// [`NotCheckedReason`] alone: the frozen vocabulary is what a report groups by,
/// this is what it prints, and the two answer different questions.
///
/// **The variants are the four ways a project can leave SURE without a
/// command**, and they are not interchangeable. A project that declares nothing
/// is a project whose shape puts the check out of scope; a project that declares
/// something unusable, or declares it in a shape SURE could not read, or cannot
/// say what runs it, has a defect in it — the difference decides whether a
/// critical check holds the run out of green, and that is what each variant's
/// reason is argued for.
///
/// **No single ecosystem produces all four, and that is expected rather than a
/// gap.** [`NotACommand`](Self::NotACommand) is reachable only where a project
/// declares *commands*, which is `package.json` and nothing else SURE reads yet:
/// a Python manifest declares packages, and its equivalent failure — a
/// declaration in a shape the reader refused — is
/// [`NotReadable`](Self::NotReadable). [`NoRunner`](Self::NoRunner) means
/// something different in each: which of several package managers starts a
/// script, and which of several interpreters has the project's packages in it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MissingKind {
    /// Nothing in the project declares a way to do this.
    ///
    /// [`NotApplicable`](NotCheckedReason::NotApplicable), and it is the one
    /// variant where the frozen enum's own sentence is true: a check SURE knows
    /// how to perform against a project of this shape does not apply to a
    /// project that declares no command for it. It is a scope limit, so a
    /// critical check that hits it does **not** hold the run out of green —
    /// which is the right answer, because a project without a `lint` script is
    /// not a project SURE should refuse to call green.
    NotDeclared,
    /// The project declares one, and what it declares is not a command.
    ///
    /// A `"test": ["jest"]` in `package.json`. npm refuses to run it, SURE
    /// refuses to guess at it, and the name is recorded rather than dropped —
    /// [`Package::scripts_not_commands`](crate::discover::node::Package::scripts_not_commands)
    /// says in its own documentation that a script which is there and unusable
    /// is not a script that is not there, and this variant is where that
    /// distinction survives into the report.
    ///
    /// **Not a scope limit.** The vocabulary has no word for this and the
    /// nearest one is used; see [`Self::not_checked_reason`] for why that word
    /// is [`UnknownReason`](NotCheckedReason::UnknownReason) rather than
    /// [`NotApplicable`](NotCheckedReason::NotApplicable).
    NotACommand,
    /// The project declares one, and SURE could not read the declaration.
    ///
    /// Poetry's dependency table is the case this is for:
    /// `mypy = { version = "^1.8", extras = ["types-requests"] }` is an
    /// ordinary, valid declaration with a value that is not a requirement
    /// string, and the discovery records the *name* in
    /// [`PyProject::dependencies_not_text`](crate::discover::python::PyProject::dependencies_not_text)
    /// rather than guessing at it. The package is therefore absent from the
    /// tooling list, and a report built from that list alone says *your project
    /// declares no type checker* about a manifest that has `mypy` written in it.
    ///
    /// **Not a scope limit**, for [`Self::NotACommand`]'s reason: what is wrong
    /// is a line in the project, and the person reading the report is the only
    /// one who can fix it. The two differ in what they are about — a command,
    /// and a declaration — which is why they are two variants rather than one.
    NotReadable,
    /// The project declares one and does not say what runs it.
    ///
    /// `why` is a constant sentence from the discovery — the one that says
    /// *which* of the two ways the project failed to name a runner, because
    /// [`Managers::agreed`](crate::discover::node::Managers::agreed) answers
    /// `None` for two different reasons and says in its own documentation that a
    /// caller which renders the two the same way throws away
    /// [`disagreement`](crate::discover::node::Managers::disagreement).
    NoRunner {
        /// The discovery's own sentence, never project text.
        why: &'static str,
    },
}

/// The sentence for the case where nothing at all names a runner.
///
/// A constant rather than a built string, for the reason every sentence in this
/// repository is: a project must not be able to write a line SURE says.
const NOTHING_NAMES_A_RUNNER: &str =
    "Nothing in this project says which package manager runs its scripts, and SURE does not guess.";

impl MissingKind {
    /// Every kind, so a rule can be checked over the whole set.
    ///
    /// The same technique as
    /// [`AbsenceReason::ALL`](crate::browser::AbsenceReason::ALL), and for the
    /// same reason: a fourth kind added later that landed on the wrong side of
    /// the scope-limit split fails a test rather than being noticed in review.
    pub const ALL: &'static [Self] = &[
        Self::NotDeclared,
        Self::NotACommand,
        Self::NotReadable,
        Self::NoRunner {
            why: NOTHING_NAMES_A_RUNNER,
        },
    ];

    /// The frozen reason this maps onto.
    ///
    /// **`NotACommand`, `NotReadable` and `NoRunner` all answer
    /// [`UnknownReason`](NotCheckedReason::UnknownReason), and that word is
    /// wrong.** SURE knows exactly why none of them ran. The vocabulary has no
    /// word for *the project declared this and what it declared is not something
    /// SURE can run*, and the three candidates that come close are each false in
    /// a way that costs something:
    ///
    /// - [`NotApplicable`](NotCheckedReason::NotApplicable) says the check does
    ///   not apply to your project, which is a lie a person would act on — they
    ///   would not go and look at their manifest.
    /// - [`ToolUnavailable`](NotCheckedReason::ToolUnavailable) says the tool is
    ///   not installed on this computer, which is a claim about the machine and
    ///   is false whenever `npm` is sitting right there.
    /// - [`UnsupportedStack`](NotCheckedReason::UnsupportedStack) says the
    ///   project is not on a stack SURE can check, which is false: this is the
    ///   stack it checks best.
    ///
    /// What is left is a reason that is false about SURE's own state instead of
    /// false about the project or the machine — and it is the only one of the
    /// four that does not class a defect the user can fix as a scope limit. A
    /// `"test": ["jest"]` is a broken manifest, and a critical test check that
    /// cannot run because of one should keep the run out of green. The sentence
    /// a person reads is [`Self::plain_explanation`]'s and is true; this is the
    /// word a report groups by, and it is recorded in `progress/DECISIONS.md`.
    #[must_use]
    pub const fn not_checked_reason(&self) -> NotCheckedReason {
        match self {
            Self::NotDeclared => NotCheckedReason::NotApplicable,
            Self::NotACommand | Self::NotReadable | Self::NoRunner { .. } => {
                NotCheckedReason::UnknownReason
            }
        }
    }

    /// SURE's own sentence, which is the one a report prints.
    #[must_use]
    pub fn plain_explanation(&self) -> String {
        match self {
            Self::NotDeclared => "Your project does not declare a way to do this.".to_owned(),
            Self::NotACommand => {
                "What your project declares for this is not a command SURE can run.".to_owned()
            }
            Self::NotReadable => {
                "What your project declares for this is written in a shape SURE could not \
                 read, so it will not guess at it."
                    .to_owned()
            }
            Self::NoRunner { why } => (*why).to_owned(),
        }
    }
}

/// A check SURE would have proposed and could not, because the project gives it
/// no command to run.
///
/// **The acceptance sentence this type exists for is "Missing commands are not
/// passes."** A check with no command produces no plan entry, so the failure
/// this guards against is not a wrong verdict but a *silence*: a report built
/// from the checks that exist would say nothing at all about tests in a project
/// that has none, and a reader would take the absence of a row for the absence
/// of a problem.
///
/// So a missing command is a value with the identity the check would have had,
/// and [`Self::not_checked`] turns it into the only kind of
/// [`CheckResult`] this crate can produce for a check that did not run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MissingCommand {
    id: CheckId,
    title: String,
    component: String,
    severity: Severity,
    critical: bool,
    kind: MissingKind,
}

impl MissingCommand {
    /// A missing command, for a check that would have been about `component`.
    #[must_use]
    pub fn new(
        id: CheckId,
        title: impl Into<String>,
        component: impl Into<String>,
        severity: Severity,
        critical: bool,
        kind: MissingKind,
    ) -> Self {
        Self {
            id,
            title: title.into(),
            component: component.into(),
            severity,
            critical,
            kind,
        }
    }

    /// The identity the check would have had.
    ///
    /// The same identity the proposal would have carried, because it is derived
    /// from the component and the role and not from whether a command exists.
    /// Anything else would make the answer to "was this check run?" depend on
    /// the project having been changed between the two runs being compared.
    #[must_use]
    pub const fn id(&self) -> &CheckId {
        &self.id
    }

    /// The title the check would have had.
    #[must_use]
    pub fn title(&self) -> &str {
        &self.title
    }

    /// The file SURE read to find out.
    #[must_use]
    pub fn component(&self) -> &str {
        &self.component
    }

    /// How bad it would have been if this check had not been satisfied.
    #[must_use]
    pub const fn severity(&self) -> Severity {
        self.severity
    }

    /// Whether the check would have held the run out of green.
    #[must_use]
    pub const fn critical(&self) -> bool {
        self.critical
    }

    /// Why there is no command.
    #[must_use]
    pub const fn kind(&self) -> &MissingKind {
        &self.kind
    }

    /// This check as the result of not running it.
    ///
    /// **`CheckResult::not_run` is the only constructor this reaches**, which is
    /// what makes the acceptance sentence structural rather than a convention:
    /// the status is `Skipped`, the evidence class is `Unknown` because the
    /// domain's constructor says a check that did not run established nothing,
    /// and there is no way to spell a pass here even by mistake.
    ///
    /// **The printed sentence is replaced.** `not_run` fills `reason` with
    /// `not_checked_reason.plain_explanation()`, which is the frozen
    /// vocabulary's generic sentence for the word it was given; for
    /// [`MissingKind::NotDeclared`] that sentence is true and for the other
    /// three it is not, so the line a person reads is SURE's own and the vocabulary's
    /// word stays in `not_checked_reason` for anything that groups by it.
    /// `browser.rs` does the same thing for the same reason.
    #[must_use]
    pub fn not_checked(&self, project_fingerprint: &FingerprintId) -> CheckResult {
        let mut result = CheckResult::not_run(
            self.id.clone(),
            self.title.clone(),
            self.severity,
            self.critical,
            self.kind.not_checked_reason(),
            project_fingerprint.clone(),
        );
        result.reason = self.kind.plain_explanation();
        result
    }

    /// One line for a report, in the shape a scheduled check's is.
    #[must_use]
    pub fn plain_description(&self) -> String {
        format!(
            "{} - not checked. {}",
            self.title,
            self.kind.plain_explanation()
        )
    }
}

/// Evidence a finished check is worth, bound to the state it ran against.
///
/// # The binding is taken from the result and not from the caller
///
/// [`Evidence::fingerprint`] is an `Option<FingerprintId>`, and `None` is not a
/// default that costs nothing: [`freshness`](sure_domain::evidence::freshness)
/// reads it as `Stale(UnknownProvenance)`, so evidence without a state **can
/// never support anything**. A check that produced a result and handed back
/// evidence with no state attached would be a green nothing could confirm —
/// and the type would not have noticed, because
/// [`Evidence::new`](sure_domain::evidence::Evidence::new) takes the fingerprint
/// as an `Option` and leaving it out is one keystroke away from filling it in.
///
/// So the fingerprint comes off the result. [`CheckResult::project_fingerprint`]
/// is a required field with no `Default`, every constructor in `sure-domain` sets
/// it, and a `CheckResult` that exists therefore has a state — which makes
/// *a result's evidence is bound to the state that result is about* a property
/// of the signature rather than a rule for a caller to remember.
/// `the_evidence_a_result_produces_is_fresh_for_the_result_and_only_for_that_state`
/// holds it over every status and both directions.
///
/// # `None` is one case, and it is the check that established nothing
///
/// The class decides, and it is the domain's own field rather than a status
/// list written again here. [`EvidenceClass::Unknown`] means *not enough
/// evidence to say anything*, and the domain's own constructors set it exactly
/// where that is true: [`CheckResult::not_run`](sure_domain::status::CheckResult::not_run)
/// and [`CheckResult::errored`](sure_domain::status::CheckResult::errored) do
/// not offer a caller a choice, because an error means SURE does not know and a
/// check that never ran established nothing.
///
/// **This is what keeps a gap from ever becoming a green**, and it is the same
/// rule as [`MissingCommand`]'s seen from the other side: a missing command
/// becomes a skipped result, and a skipped result has no evidence to give. The
/// two are tested together in
/// `a_missing_command_produces_a_result_that_produces_no_evidence`.
///
/// [`CheckResult::unknown`](sure_domain::status::CheckResult::unknown) **does**
/// produce evidence, and that is the distinction it exists for: it is the one
/// status whose class is a parameter, because it means *SURE has evidence that
/// supports no verdict* rather than *SURE has none*.
///
/// # It does not decide that the evidence is any good
///
/// Everything but the class comes straight off the result — the summary is the
/// result's own title and status, the severity is the result's own — and nothing
/// here can tell a real pass from a `"test": "true"` that exits zero. That is
/// the limit this whole layer states about itself, arriving one type further on.
#[must_use]
pub fn evidence_of(result: &CheckResult, anchor: EvidenceAnchor) -> Option<Evidence> {
    if result.evidence_class == EvidenceClass::Unknown {
        return None;
    }
    Some(Evidence::new(
        result.evidence_class,
        format!("{}: {}.", result.title, outcome_phrase(result.status)),
        anchor,
        Some(result.project_fingerprint.clone()),
        result.severity,
    ))
}

/// How a check's outcome reads in the middle of a sentence.
///
/// A function of the status rather than of the result, so the six sentences are
/// six values in one place and `a_report_can_tell_all_six_outcomes_apart` can
/// ask whether any two of them read the same. Deliberately not
/// [`CheckStatus::as_str`](sure_domain::status::CheckStatus::as_str): that is the
/// wire name, and a person reading a report should not be shown `skipped`.
///
/// **A sentence rather than a verdict.** Nothing here says the project is fine —
/// `passed` is a statement about what the check found and about nothing else —
/// and nothing here is project text, for the reason every sentence in this
/// repository is a constant: a project must not be able to write a line SURE says.
fn outcome_phrase(status: CheckStatus) -> &'static str {
    match status {
        CheckStatus::Pass => "passed",
        CheckStatus::Fail => "failed",
        CheckStatus::Warning => "only partly passed",
        CheckStatus::Skipped => "was not checked",
        CheckStatus::Error => "could not be completed",
        CheckStatus::Unknown => "reached no conclusion",
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use sure_domain::evidence::{
        AnchorSubject, EvidenceClass, Freshness, StalenessReason, freshness,
    };
    use sure_domain::status::CheckStatus;

    /// Component paths and tags chosen to be hostile rather than representative.
    ///
    /// Every one of these is a string a scan can hand over: a member directory
    /// with a space in it, one with Unicode, one that is a Windows path with
    /// backslashes, one with `..` in it, one with a `.` or a `-` where the tag
    /// would have had a letter, an empty one, and one longer than the Windows
    /// path limit. The tags are the ones this layer builds plus the shapes that
    /// would break a `<prefix><tag><hex>` recipe if the tag were trusted.
    const HOSTILE: &[&str] = &[
        "",
        ".",
        "..",
        "package.json",
        "apps/web/package.json",
        "apps/my app/package.json",
        "apps/包/package.json",
        "apps\\win\\package.json",
        "apps/web/../../etc/package.json",
        "NODE_TEST",
        "node-test",
        "nodetest",
        "node test",
        "node.test",
        "chk_nodetest",
        "chk_",
        "_",
        "0",
        "9999999999",
    ];

    fn long_path() -> String {
        let mut path = String::from("apps");
        for index in 0..40 {
            path.push_str(&format!("/member-{index}"));
        }
        path.push_str("/package.json");
        path
    }

    #[test]
    fn an_identifier_is_well_formed_for_every_tag_and_component_this_can_be_given() {
        // The claim `check_id`'s `expect` rests on, held over the inputs rather
        // than asserted in a sentence. A panic here is the failure this test
        // exists to catch before it can reach a project.
        let long = long_path();
        let components = HOSTILE
            .iter()
            .copied()
            .chain(std::iter::once(long.as_str()));

        let mut built = 0;
        for component in components {
            for tag in HOSTILE {
                let id = check_id(component, tag);
                // Parsed back, so this is a claim about the identifier's *text*
                // and not about the constructor having accepted it once.
                let parsed = CheckId::parse(id.as_str().to_owned())
                    .unwrap_or_else(|error| panic!("{id} is not a CheckId: {error}"));
                assert_eq!(parsed, id);
                assert!(id.as_str().starts_with("chk_"), "{id}");
                assert!(
                    id.as_str().len() > "chk_".len(),
                    "the body is empty, which is the one shape a CheckId refuses: {id}"
                );
                built += 1;
            }
        }
        assert_eq!(
            built,
            (HOSTILE.len() + 1) * HOSTILE.len(),
            "the sweep did not visit every pair, so it is not the claim it says it is"
        );
    }

    #[test]
    fn an_identifier_is_the_same_every_time_and_different_for_every_check() {
        // Two claims, and the second is the one with teeth: a tag that reads the
        // same after everything outside `[a-z0-9]` is dropped must still get its
        // own identifier, because the digest is taken over the raw text. Without
        // that, `node-test` and `nodetest` would be one check.
        let ids: Vec<CheckId> = HOSTILE
            .iter()
            .map(|tag| check_id("apps/web/package.json", tag))
            .collect();
        for (index, id) in ids.iter().enumerate() {
            assert_eq!(
                *id,
                check_id("apps/web/package.json", HOSTILE[index]),
                "the same component and tag gave two identifiers"
            );
        }

        let mut sorted = ids.clone();
        sorted.sort_by(|left, right| left.as_str().cmp(right.as_str()));
        sorted.dedup();
        assert_eq!(
            sorted.len(),
            ids.len(),
            "two tags share an identifier, so one check would be dropped as a \
             duplicate of the other: {ids:?}"
        );

        // And the component is in the digest as well as the tag, which is the
        // half a tag-only recipe would lose: the same role in two members is two
        // checks.
        assert_ne!(
            check_id("apps/web/package.json", "nodetest"),
            check_id("apps/api/package.json", "nodetest")
        );
    }

    #[test]
    fn a_component_that_is_not_there_is_not_a_component_with_no_command() {
        // The false green this type is arranged against, stated as a value: a
        // missing command is a *reason*, and a caller cannot build one without
        // saying which reason. An empty component is refused by the discovery
        // rather than here — what is held here is that the three kinds are three
        // values, so a caller that has one cannot be read as having another.
        assert_eq!(MissingKind::ALL.len(), 4);
        assert_ne!(MissingKind::NotDeclared, MissingKind::NotACommand);
        assert_ne!(MissingKind::NotACommand, MissingKind::NotReadable);
        assert_ne!(MissingKind::NotDeclared, MissingKind::NotReadable);
        assert_ne!(
            MissingKind::NotDeclared,
            MissingKind::NoRunner {
                why: NOTHING_NAMES_A_RUNNER
            }
        );
    }

    #[test]
    fn every_missing_command_is_skipped_and_none_of_them_is_a_pass() {
        // The acceptance sentence, over the whole vocabulary rather than over
        // the kinds somebody thought of. A fourth kind added later that landed
        // on anything but `Skipped` fails here.
        let fingerprint = FingerprintId::generate();
        for kind in MissingKind::ALL {
            let missing = MissingCommand::new(
                check_id("package.json", "nodetest"),
                "run the tests",
                "package.json",
                Severity::MustFix,
                true,
                kind.clone(),
            );
            let result = missing.not_checked(&fingerprint);

            assert_eq!(result.status, CheckStatus::Skipped, "{kind:?}");
            assert!(!result.status.is_green(), "{kind:?} was green");
            assert!(
                !result.status.produced_a_result(),
                "{kind:?} claimed to have checked the project"
            );
            assert_eq!(result.evidence_class, EvidenceClass::Unknown);
            assert_eq!(result.not_checked_reason, Some(kind.not_checked_reason()));
            assert_eq!(result.project_fingerprint, fingerprint);

            // The sentence a person reads is SURE's, and it is never empty. This
            // is the half the frozen vocabulary cannot carry: for two of the
            // three kinds the generic sentence is false, so the two must differ.
            assert_eq!(result.reason, kind.plain_explanation());
            assert!(!result.reason.trim().is_empty(), "{kind:?} says nothing");

            // And the scope-limit split, which is the part that decides whether
            // a critical check holds the run out of green.
            assert_eq!(
                result.blocks_green(),
                !kind.not_checked_reason().is_scope_limit(),
                "{kind:?} blocks green if and only if its domain reason is a gap"
            );

            // And the one-line description, which is the other place the
            // sentence has to survive. **The first run of `P4-T002`'s mutation
            // set dropped the explanation from this line and every test
            // passed**, because nothing read it: a report showing
            // `run the tests - not checked.` and stopping is the exact silence
            // this type exists against, printed one layer further out than the
            // type can see.
            let line = missing.plain_description();
            assert!(line.contains(missing.title()), "{line}");
            assert!(line.contains(&kind.plain_explanation()), "{line}");
            assert_ne!(line, missing.title(), "{line}");
        }

        // The specific split, written out so that moving one kind across it is a
        // failing test rather than a plausible-looking diff: a project that
        // declares nothing is out of scope, and a project that declares
        // something SURE cannot run is a defect in the project.
        let scope_limits: Vec<&MissingKind> = MissingKind::ALL
            .iter()
            .filter(|kind| kind.not_checked_reason().is_scope_limit())
            .collect();
        assert_eq!(scope_limits, vec![&MissingKind::NotDeclared]);
    }

    #[test]
    fn the_sentence_a_person_reads_is_not_the_vocabularys_sentence_where_that_one_is_false() {
        // Named directly because it is the reason `not_checked` overwrites the
        // field at all, and a reader who found the assignment odd deserves the
        // failing test that says what it is for. Both of these answer
        // `UnknownReason`, whose sentence is that SURE does not know why a check
        // did not run — which would be a false statement about SURE's own state
        // in place of a true one about the project's.
        for kind in [
            MissingKind::NotACommand,
            MissingKind::NotReadable,
            MissingKind::NoRunner {
                why: NOTHING_NAMES_A_RUNNER,
            },
        ] {
            assert_eq!(kind.not_checked_reason(), NotCheckedReason::UnknownReason);
            assert_ne!(
                kind.plain_explanation(),
                kind.not_checked_reason().plain_explanation(),
                "{kind:?} would print the generic sentence, which is false for it"
            );
        }

        // And each of the three says something the other two do not, so a report
        // showing one where another belongs is a visible difference rather than
        // three ways of saying "not checked".
        let sentences: Vec<String> = MissingKind::ALL
            .iter()
            .map(MissingKind::plain_explanation)
            .collect();
        assert_eq!(sentences.len(), 4);
        for (index, sentence) in sentences.iter().enumerate() {
            assert!(
                !sentences[index + 1..].contains(sentence),
                "two missing kinds render identically: {sentence}"
            );
        }
    }

    /// An anchor pointing at a file and a line that could be checked.
    fn anchor() -> EvidenceAnchor {
        EvidenceAnchor::new(
            AnchorSubject::File,
            "package.json",
            "the scripts it declares",
        )
    }

    /// A finished check, with every field the type has set by hand.
    ///
    /// **A struct literal rather than a constructor, and the status is why.** The
    /// six constructors each pin a class — `not_run` and `errored` force
    /// [`EvidenceClass::Unknown`], `pass`, `fail` and `warning` force a fixed one,
    /// and only `unknown` offers a choice — so a sweep written with them would be
    /// testing six constructors rather than the matrix they produce. What the tests
    /// below ask is what `evidence_of` does with a *result*, and a result is a
    /// value with nine public fields.
    fn finished(
        status: CheckStatus,
        class: EvidenceClass,
        fingerprint: &FingerprintId,
    ) -> CheckResult {
        CheckResult {
            id: check_id("package.json", "nodetest"),
            title: "run the tests".to_owned(),
            status,
            severity: Severity::MustFix,
            evidence_class: class,
            project_fingerprint: fingerprint.clone(),
            not_checked_reason: None,
            reason: String::new(),
            critical: true,
        }
    }

    #[test]
    fn a_report_can_tell_all_six_outcomes_apart() {
        // **The question `outcome_phrase`'s documentation says can be asked, asked
        // here.** Six statuses, six sentences in the middle of a sentence, and the
        // failure this guards is the one that reads as writing rather than as a bug:
        // two arms of a `match` collapsing into one phrase, so a report says a check
        // "failed" when it was never run.
        let phrases: Vec<&'static str> = CheckStatus::ALL
            .iter()
            .copied()
            .map(outcome_phrase)
            .collect();
        assert_eq!(
            phrases.len(),
            CheckStatus::ALL.len(),
            "the sweep did not visit every status"
        );

        for (index, phrase) in phrases.iter().enumerate() {
            assert!(
                !phrase.trim().is_empty(),
                "{:?} says nothing",
                CheckStatus::ALL[index]
            );
            assert!(
                !phrase.ends_with('.'),
                "{phrase:?} ends a sentence in the middle of one"
            );
            assert!(
                !phrases[index + 1..].contains(phrase),
                "two statuses render identically: {phrase:?}"
            );
            // The sentence is never the wire name, which is the thing
            // `outcome_phrase` explicitly is not: a person reading a report should
            // not be shown `not_checked`.
            assert_ne!(
                *phrase,
                CheckStatus::ALL[index].as_str(),
                "{:?} prints its own wire name",
                CheckStatus::ALL[index]
            );
        }

        // Written out as a value, because the six are a decision rather than a
        // derivation and a seventh status would have to be argued for here.
        assert_eq!(
            phrases,
            vec![
                "passed",
                "failed",
                "only partly passed",
                "was not checked",
                "could not be completed",
                "reached no conclusion",
            ]
        );
    }

    #[test]
    fn the_evidence_a_result_produces_is_fresh_for_the_result_and_only_for_that_state() {
        // **The claim `evidence_of`'s documentation makes about the signature,
        // asked over the whole matrix.** The fingerprint comes off the result rather
        // than from a caller, so "a result's evidence is bound to the state that
        // result is about" is a property of the shape of the function — and a
        // property of a shape is checked by sweeping the values the shape admits,
        // not by reading it.
        let ran_at = FingerprintId::generate();
        let moved_on = FingerprintId::generate();

        let mut checked = 0;
        for status in CheckStatus::ALL {
            for class in EvidenceClass::ALL {
                let result = finished(*status, *class, &ran_at);
                let evidence = evidence_of(&result, anchor());

                if *class == EvidenceClass::Unknown {
                    assert_eq!(
                        evidence, None,
                        "{status:?} with {class:?} produced evidence, and {class:?} is \
                         the class that means nothing was established"
                    );
                    continue;
                }

                let evidence =
                    evidence.unwrap_or_else(|| panic!("{status:?} with {class:?} is None"));
                checked += 1;

                // The first direction: fresh for the state the result names.
                assert_eq!(
                    freshness(&evidence, &ran_at),
                    Freshness::Fresh,
                    "{status:?} is not bound to the state it ran against"
                );
                // The second: and for no other. This is the half that matters —
                // evidence that stayed fresh after the project moved on is the green
                // that outlived what earned it.
                assert_eq!(
                    freshness(&evidence, &moved_on),
                    Freshness::Stale(StalenessReason::FingerprintChanged),
                    "{status:?} stayed usable against a state it was not earned in"
                );
                // And not the third way to be bound wrongly, which reads as caution
                // rather than as a defect: no provenance at all is stale against
                // *everything*.
                assert!(
                    evidence.fingerprint.is_some(),
                    "{status:?} produced evidence that applies to nothing"
                );

                // Everything but the class comes straight off the result, which is
                // what makes the summary a sentence about this check rather than a
                // sentence about checks in general.
                assert_eq!(evidence.class, *class);
                assert_eq!(evidence.severity, result.severity);
                assert!(
                    evidence.summary.contains(&result.title),
                    "{}",
                    evidence.summary
                );
                assert!(
                    evidence.summary.contains(outcome_phrase(*status)),
                    "{} does not say what happened",
                    evidence.summary
                );
            }
        }
        // The vacuity guard: a matrix that visited nothing would satisfy every
        // assertion above. Six statuses times five non-`Unknown` classes.
        assert_eq!(
            checked,
            CheckStatus::ALL.len() * (EvidenceClass::ALL.len() - 1)
        );
        assert_eq!(
            CheckStatus::ALL.len() * EvidenceClass::ALL.len(),
            30,
            "the matrix is not the six times five this test claims to sweep"
        );
    }
}
