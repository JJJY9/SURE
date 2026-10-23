//! Executable work, typed at the moment a check is proposed.
//!
//! # Why this module exists
//!
//! The plan has always said *what* a run intends to check and never *what
//! running one is*. `checks::node::NodeChecks::of` asks its discovery for a
//! rendered line — `npm run build` — and files it in
//! [`CheckReason::DeclaredCommand`](crate::schedule::CheckReason), which is
//! display text: it is what a report prints. From that point the only
//! description of the work is the sentence a person reads, and the shortest
//! way to execute it — split the string, start the pieces — is the act
//! `docs/architecture/EXECUTION_SAFETY.md` and the repository's invariants
//! forbid. A string that a report prints must never become the reason a
//! program runs.
//!
//! So the work is a value here, and it is a value **before** anything decides
//! whether it may run: [`PlannedWork`] holds a check's proposal and the
//! operation that would carry it out, and it is built where the check is
//! proposed. A caller that has one of them cannot have the other missing, and
//! that is a fact about a type rather than a rule for a reader to remember.
//!
//! # A command is named, never spelled
//!
//! [`CommandSpec`] carries a program, an argument vector, a working directory,
//! an environment policy, a deadline and an output bound as **named fields**.
//! There is no variant that takes a string to be split and no function in this
//! module that splits one. `process::ProcessRequest` has the same rule one
//! layer down; this is that rule carried back to where the work is first known,
//! so that the layer which knows a `package.json` declared `build` is also the
//! layer that decides the program is `npm` and the argument is `run build`.
//!
//! # A name with no extension is not a program on Windows
//!
//! [`crate::process`] records the measurement and this module inherits the
//! consequence. `CreateProcess` completes a name that has **no** extension with
//! `.exe` and nothing else, so a bare `npm` is not found on a machine where
//! `npm.cmd` is on `PATH`; and a `.cmd` named *with* its extension does start,
//! by starting a command interpreter to run the text inside it. A plan that
//! wrote `npm` holds a name this layer cannot start; the product runner may
//! still start the work through the program the shim itself runs
//! ([`crate::package_launcher`]), and every other shape reaches the same honest
//! not-startable result. A plan that wrote `npm run build` would be the thing
//! this module exists to prevent.
//!
//! [`ProgramPath`] is therefore a value with a question — *what is this name,
//! on this machine?* — and [`Resolution`] is its answer, in four parts that are
//! four different sentences in a report: an executable this build starts, a file
//! whose start would be an interpreter's, a file that is not a program, and
//! nothing at all. Which of the four came back is decided by the files on disk
//! and by no string formatting anywhere in this crate.
//!
//! # What this module does not decide
//!
//! **It does not decide whether the work may run.** Nothing here consults an
//! [`ExecutionMode`](sure_domain::execution::ExecutionMode), a permission or a
//! consent, and nothing here can: `crate::enforce` is the only thing that
//! answers that question and [`crate::enforce::AdmittedCommand`] is the only
//! value that carries a *yes*. A `CommandSpec` is not a launch and cannot be
//! made into one — `crate::process` and `crate::service` take what they start
//! from the enforcement, and this type is what the enforcement was asked about.
//!
//! **It does not run anything.** There is no spawn, no thread and no I/O in
//! this file. `tests/spawn_sites.rs` counts the places that build a `Command`
//! and this module is not one of them, which is what makes it safe for the
//! discovery layer to hold.
//!
//! **It does not make a resolved path trustworthy.** A name found on `PATH` is
//! a file on this machine that something else could replace between the plan and
//! the run. Resolving early is about saying the *honest* thing — "there is an
//! `npm.cmd` here and this build will not start that file" rather than "there
//! is no `npm`" — and not about pinning a program down. The runner may still
//! start what the shim itself runs; see [`crate::package_launcher`].
//!
//! **It does not search the current directory, and Windows would.** An empty
//! element of `PATH` means *the current directory* to `CreateProcess`, so a
//! project that writes `npm.exe` into its own folder is a project whose build
//! check resolves to its own file. [`ProgramPath::directories`] drops empty
//! entries for exactly that reason. The cost is real and is stated rather than
//! hidden: on a machine whose `PATH` ends in a separator, SURE would not find a
//! program that a shell in the same directory would — and a plan that names the
//! wrong program is a worse failure than a plan that finds none, because the
//! first one is a permission question asked about something the project chose.

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use sure_domain::evidence::EvidenceClass;
use sure_domain::ids::FingerprintId;
use sure_domain::status::{CheckResult, CheckStatus};

use crate::probe::{Endpoint, EndpointError};
use crate::process::{Environment, Limits, Outcome, ProcessError, Stop, Termination};
use crate::schedule::CheckProposal;

/// One check, and the work that would carry it out if it runs.
///
/// The two halves are one value because they are one decision. A check whose
/// operation could not be produced is not a check with a missing field — it is a
/// check SURE cannot carry out, and it belongs in the plan as a declaration it
/// could not plan rather than as a proposal whose work something else is
/// expected to remember. [`crate::schedule::PlanBuilder::propose`] takes this
/// type and not a [`CheckProposal`], so that gap cannot be opened by forgetting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedWork {
    proposal: CheckProposal,
    operation: CheckOperation,
}

impl PlannedWork {
    /// Bind a check to the work that would carry it out.
    #[must_use]
    pub const fn new(proposal: CheckProposal, operation: CheckOperation) -> Self {
        Self {
            proposal,
            operation,
        }
    }

    /// The check, as a report reads it.
    #[must_use]
    pub const fn proposal(&self) -> &CheckProposal {
        &self.proposal
    }

    /// What running the check means.
    #[must_use]
    pub const fn operation(&self) -> &CheckOperation {
        &self.operation
    }
}

/// What running a check is.
///
/// Four kinds, and the list is closed on purpose: a fifth kind of work is a
/// fifth kind of question about the host, and this build answers four. Every
/// variant is data — nothing in this enum starts anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckOperation {
    /// The answer is already known. A detector read the project while the plan
    /// was being made, and there is no process to start because there is
    /// nothing left to ask.
    Precomputed(PrecomputedEvidence),
    /// Run one command, once, under a deadline, and read what it said.
    Command(CommandSpec),
    /// Start a program that is meant to stay up, ask it one question on
    /// loopback, and stop it.
    Service(ServiceCheckSpec),
    /// Start a service and look at a page it serves, in a browser this machine
    /// already has.
    Browser(BrowserCheckSpec),
}

impl CheckOperation {
    /// Whether carrying this out starts a process at all.
    ///
    /// [`CheckOperation::Precomputed`] is the only `false`, and it is the one
    /// that matters for the invariant the census in `tests/spawn_sites.rs`
    /// protects: a plan made entirely of precomputed work reaches no runner and
    /// no process, whatever the mode says.
    #[must_use]
    pub const fn starts_a_process(&self) -> bool {
        !matches!(self, Self::Precomputed(_))
    }

    /// The sentence a report shows for this kind of work.
    #[must_use]
    pub const fn plain_description(&self) -> &'static str {
        match self {
            Self::Precomputed(_) => "already observed while the plan was made",
            Self::Command(_) => "one command, once, under a deadline",
            Self::Service(_) => "started, asked one question, and stopped",
            Self::Browser(_) => "a page served on loopback, read by a browser",
        }
    }
}

/// What a detector already found, before any process was considered.
///
/// **This is evidence and not a verdict**, which is why the four answers are the
/// four things a detector can honestly know and not the six statuses a check can
/// have. The mapping to a status belongs to [`Self::to_result`], where it can be
/// read in one place, and the arrow always points the same way: a detector that
/// could not read what it needed says so, and never that the property holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StaticObservation {
    /// The detector read the project and the property it looks for is there.
    Holds,
    /// The detector read the project and found the property contradicted.
    ///
    /// A contradiction is the only shape in which a detector is allowed to say
    /// the project is wrong, because it is the only one where the detector has
    /// both the rule and the thing that breaks it.
    Contradicted,
    /// The detector read the project and found something it cannot settle — a
    /// candidate, a partial reading, a file too large to finish.
    Candidate,
    /// The detector could not read what it needed: a file that was not there, a
    /// parse that failed, a query the project did not answer.
    CouldNotRun,
}

/// An observation a detector made, and the sentence a person reads about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrecomputedEvidence {
    observation: StaticObservation,
    detail: String,
}

impl PrecomputedEvidence {
    /// An observation, with the detail line that says what was read.
    #[must_use]
    pub fn new(observation: StaticObservation, detail: impl Into<String>) -> Self {
        Self {
            observation,
            detail: detail.into(),
        }
    }

    /// The detector read the project and found what it was looking for.
    #[must_use]
    pub fn holds(detail: impl Into<String>) -> Self {
        Self::new(StaticObservation::Holds, detail)
    }

    /// The detector read the project and found the property contradicted.
    #[must_use]
    pub fn contradicted(detail: impl Into<String>) -> Self {
        Self::new(StaticObservation::Contradicted, detail)
    }

    /// The detector found a candidate and cannot settle it.
    #[must_use]
    pub fn candidate(detail: impl Into<String>) -> Self {
        Self::new(StaticObservation::Candidate, detail)
    }

    /// The detector could not read what it needed.
    #[must_use]
    pub fn could_not_run(detail: impl Into<String>) -> Self {
        Self::new(StaticObservation::CouldNotRun, detail)
    }

    /// What the detector observed.
    #[must_use]
    pub const fn observation(&self) -> StaticObservation {
        self.observation
    }

    /// The detail line.
    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }

    /// This observation as the result of the check it belongs to.
    ///
    /// The check's severity, evidence class and identity come from its
    /// proposal, so an observation cannot carry a weight its check did not
    /// claim. The fingerprint is a parameter for the same reason it is a
    /// parameter everywhere else in this repository: a result is evidence
    /// **about a project state**, and a result that did not name one would be
    /// evidence about a state nobody can point at.
    ///
    /// # Only the two classes that can stand alone can carry a pass
    ///
    /// **A [`StaticObservation::Holds`] whose check claims a class that cannot
    /// support a pass is reported as `Unknown`, never as a `Pass`.** The set of
    /// classes is not a decision taken here. `CheckResult::evidence_class`,
    /// whose field documentation is in `crates/sure-domain/src/status.rs`, says
    /// what a pass is made of — *"a `pass` from reading a file is
    /// `DeterministicCheck`, and a `pass` from running the project and watching
    /// what it did is `ObservedFact`. They are different promises, and the
    /// truth hierarchy in `docs/architecture/EVIDENCE_MODEL.md` ranks them
    /// differently."* — and those are the same two classes
    /// [`EvidenceClass::can_alone_support_must_fix`] names in the other
    /// direction, which the evidence table of
    /// `docs/architecture/FROZEN_SEMANTICS.md` marks **no** for the other
    /// three and `docs/adr/0010-frozen-domain-semantics-in-code.md` item 6
    /// freezes in code.
    ///
    /// **The class is what makes this a rule rather than a formality.** A
    /// detector that pattern-matched a source file reports
    /// [`EvidenceClass::Inference`], and
    /// `tests/finding_severity_rule.rs::severity_was_not_bought_by_promoting_an_inference_to_a_fact`
    /// requires it to keep reporting that class — *"a pattern guess presented
    /// as an observation is the false green this product exists to catch"*. So
    /// a detector that read text and found no counterexample in it reports
    /// exactly that, and `Unknown` is the honest status for it: SURE has
    /// evidence, and the evidence supports no verdict. It is not a soft
    /// failure: `aggregate` treats `Unknown` on a critical check as not checked
    /// (rule 1 of `FROZEN_SEMANTICS.md`), so nothing here can make a run green.
    ///
    /// **The other three observations are not filtered this way, and the
    /// asymmetry is the repository's own.** A `fail`, a `warning` and an
    /// `error` are visible states a reader weighs with the evidence class
    /// printed beside them, and `CLAUDE.md`'s rule is one-directional: a false
    /// green is more serious than a visible error. A `Contradicted` under
    /// `Inference` also has an owner of its own — the corpus requires exactly
    /// that pair for the candidate detectors (`fixtures/adversarial/fake-payment`),
    /// and it is a [`Finding`](sure_domain::finding::Finding) rather than a
    /// check result that has to earn its severity from an anchor.
    ///
    /// A candidate is a [`CheckStatus::Warning`](sure_domain::status::CheckStatus)
    /// and not an `Unknown`, because the detector did observe something and the
    /// difference between "here is a thing worth looking at" and "SURE has no
    /// evidence" is a difference a reader acts on. A detector that could not run
    /// is an `Error` — [`CheckResult::errored`] fixes its class at
    /// [`EvidenceClass::Unknown`], so no caller can offer it a stronger weight
    /// than a check that established nothing has — which for a critical check is
    /// not a pass.
    #[must_use]
    pub fn to_result(&self, proposal: &CheckProposal, fingerprint: &FingerprintId) -> CheckResult {
        let (id, title) = (proposal.id().clone(), proposal.title().to_owned());
        let (severity, critical) = (proposal.severity(), proposal.critical());
        let class = proposal.evidence_class();
        match self.observation {
            StaticObservation::Holds if !carries_a_pass(class) => {
                CheckResult::unknown(id, title, severity, critical, class, fingerprint.clone())
                    .with_reason(format!(
                        "{} Nothing contradicted this, and a check established by `{}` \
                         evidence cannot be reported as passed.",
                        self.detail,
                        class.as_str()
                    ))
            }
            StaticObservation::Holds => {
                CheckResult::pass(id, title, severity, critical, class, fingerprint.clone())
                    .with_reason(self.detail.clone())
            }
            StaticObservation::Contradicted => {
                CheckResult::fail(id, title, severity, critical, class, fingerprint.clone())
                    .with_reason(self.detail.clone())
            }
            StaticObservation::Candidate => {
                CheckResult::warning(id, title, severity, critical, class, fingerprint.clone())
                    .with_reason(self.detail.clone())
            }
            StaticObservation::CouldNotRun => CheckResult::errored(
                id,
                title,
                severity,
                critical,
                self.detail.clone(),
                fingerprint.clone(),
            ),
        }
    }
}

/// Whether a `Pass` may be built from an observation of this class.
///
/// **The one list, asked rather than copied.** A check result claims either that
/// the project is wrong or that it is right, and the repository's answer to
/// *which evidence may carry that claim alone* is
/// [`EvidenceClass::can_alone_support_must_fix`] — the two classes
/// `CheckResult::evidence_class` names for a pass, and the two
/// `docs/architecture/FROZEN_SEMANTICS.md` marks **yes** for a finding that
/// blocks hand-off. A second list here would be a second place for that rule to
/// change, and a reader of either one would have to guess which was current.
fn carries_a_pass(class: EvidenceClass) -> bool {
    class.can_alone_support_must_fix()
}

/// What came of one run of a planned command.
///
/// **Two answers in one type, because they are one question** — *what did
/// running this command establish?* A caller holds either what the operating
/// system let SURE start or the error that stands in its place, and a caller
/// that had to hold the two separately would be carrying the distinction this
/// type exists to make in two places. `crate::process::error` states the second
/// half in its own words — *"every one of these means the process did not run"*
/// — and that is what makes an error a status here rather than a gap in a
/// report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandRun {
    /// The process ran. What came of it, both streams included.
    Ran(Outcome),
    /// The process did not run, and this is why.
    NeverStarted(ProcessError),
}

impl From<Result<Outcome, ProcessError>> for CommandRun {
    /// What the runner handed back, as this type.
    ///
    /// `process::run` returns exactly this `Result`, so the conversion is the
    /// step from the machinery to [`CommandRun::to_result`] rather than a
    /// reshape every caller writes and keeps right of its own.
    fn from(result: Result<Outcome, ProcessError>) -> Self {
        match result {
            Ok(outcome) => Self::Ran(outcome),
            Err(error) => Self::NeverStarted(error),
        }
    }
}

impl CommandRun {
    /// The run, when there was one.
    #[must_use]
    pub const fn outcome(&self) -> Option<&Outcome> {
        match self {
            Self::Ran(outcome) => Some(outcome),
            Self::NeverStarted(_) => None,
        }
    }

    /// Why nothing ran, when nothing did.
    #[must_use]
    pub const fn error(&self) -> Option<&ProcessError> {
        match self {
            Self::Ran(_) => None,
            Self::NeverStarted(error) => Some(error),
        }
    }

    /// What this run supports, before any check is named.
    ///
    /// Separate from [`Self::to_result`] for the reason
    /// [`ProbeOutcome::status`](crate::probe::ProbeOutcome::status) is separate
    /// from `ProbeOutcome::verdict`: a caller — or a test — can ask what a run
    /// is worth without building a proposal and a fingerprint first. The two
    /// cannot disagree, because `to_result` is written against this.
    ///
    /// **One status here can come back weaker from `to_result`**, and the
    /// difference is a rule rather than a disagreement: a `Pass` is only
    /// reported as a pass when the check's own evidence class can carry one, so
    /// a run that maps to `Pass` becomes `Unknown` under a proposal that claims
    /// a class `carries_a_pass` says no to.
    #[must_use]
    pub fn status(&self) -> CheckStatus {
        match self {
            // The error module's first sentence is the whole of this arm: every
            // `ProcessError` means the process did not run. `Error` and not
            // `Unknown`, because `unknown` means SURE has evidence that
            // supports no verdict, and a run that never began produced none.
            Self::NeverStarted(_) => CheckStatus::Error,
            Self::Ran(outcome) => match outcome.termination() {
                // The only pass in this mapping, and it takes both halves:
                // the command's own account of itself, and SURE's copy of
                // what it said being a whole rather than a beginning.
                Termination::Exited { code: Some(0) } if output_is_complete(outcome) => {
                    CheckStatus::Pass
                }
                // A zero exit whose output SURE holds only part of. See
                // `incompleteness`: the exit code is one fact about the run
                // and the streams are the rest of what a check reads.
                Termination::Exited { code: Some(0) } => CheckStatus::Unknown,
                Termination::Exited { code: Some(_) } => CheckStatus::Fail,
                // `None` is not a clean exit, and it is not an absence either:
                // the operating system ended the process with a signal, which is
                // a Unix fact this tree models as `None` rather than as a
                // fabricated code.
                Termination::Exited { code: None } => CheckStatus::Fail,
                Termination::TimedOut { .. } | Termination::Cancelled { .. } => {
                    CheckStatus::Unknown
                }
                // A start that was cancelled before it began. `process::run`
                // really returns this — `Outcome::never_started` — so it is a
                // reachable answer rather than a defensive arm, and nothing ran
                // when it comes back.
                Termination::CancelledBeforeStart => CheckStatus::Error,
            },
        }
    }

    /// One line of plain language: what happened, in the terms a report can
    /// quote.
    ///
    /// The status says what the run is worth and this says why, and the two
    /// carry different facts on purpose: a stop that reached only the process
    /// is a fact about SURE's own operation and about what may still be running
    /// on this machine, and it changes no status — see [`Self::to_result`].
    #[must_use]
    pub fn reason(&self) -> String {
        match self {
            // The error's own text, whole. `crate::process::error` writes it for
            // a person, and it is the only place that says which of "not
            // installed", "not a program this build starts" and "the directory
            // moved" happened — paraphrasing it here would be a second copy of
            // a careful text, and the copy is the one a report would quote.
            Self::NeverStarted(error) => format!(
                "SURE could not run the command this check is about, so nothing about it was \
                 observed: {error}"
            ),
            Self::Ran(outcome) => {
                let mut clauses: Vec<String> = Vec::new();
                match outcome.termination() {
                    Termination::Exited { code } => clauses.push(match code {
                        Some(code) => format!("the command ran and ended with exit code {code}"),
                        None => "the command was ended by the operating system and never \
                                 reported an exit code of its own"
                            .to_owned(),
                    }),
                    Termination::TimedOut { stopped } => {
                        clauses.push(
                            "the command was still running when the time it was given ran out, \
                             so SURE stopped it"
                                .to_owned(),
                        );
                        clauses.push(stop_clause(stopped).to_owned());
                    }
                    Termination::Cancelled { stopped } => {
                        clauses.push(
                            "the run was cancelled before the command finished, so SURE stopped \
                             it"
                            .to_owned(),
                        );
                        clauses.push(stop_clause(stopped).to_owned());
                    }
                    Termination::CancelledBeforeStart => clauses.push(
                        "the run was cancelled before the command was started, so nothing \
                               ran"
                        .to_owned(),
                    ),
                }
                if let Some(incomplete) = incompleteness(outcome) {
                    clauses.push(incomplete);
                }
                clauses.join("; ")
            }
        }
    }

    /// This run as the result of the check it belongs to.
    ///
    /// The check's severity, criticality, evidence class and identity come from
    /// its proposal, so a run cannot report a weight its check did not claim.
    /// That is [`PrecomputedEvidence::to_result`]'s rule, and it is the same
    /// rule because it is the same question: what may this evidence be turned
    /// into?
    ///
    /// # The mapping, in full
    ///
    /// | what the runner reported | status | why |
    /// | --- | --- | --- |
    /// | `Exited { code: Some(0) }`, both streams read to the end | `pass` | the command ran to its own end, reported success, and SURE kept the whole of what it said |
    /// | `Exited { code: Some(0) }`, a stream truncated or unfinished | `unknown` | the exit code is the command's own account of itself, and SURE's copy of what it said is a beginning rather than a whole |
    /// | `Exited { code: Some(n) }`, `n` not zero | `fail` | the command ran, ended on its own, and reported failure |
    /// | `Exited { code: None }` | `fail` | the operating system ended it, which is not a clean exit |
    /// | `TimedOut { .. }` | `unknown` | SURE cut the run short at its own deadline: the command neither succeeded nor was shown to fail |
    /// | `Cancelled { .. }` | `unknown` | the run was cut short from outside, so nothing about the command's outcome was observed |
    /// | `CancelledBeforeStart` | `error` | nothing ran, so there is no observation to weigh |
    /// | any `ProcessError` | `error` | nothing ran, and `process::error` says exactly that of every variant |
    ///
    /// **No row of that table is a `Warning`, and that is not a detail of
    /// taste.** `CriticalState::from_status` maps `CheckStatus::Warning` to
    /// `CriticalState::Passed` — deliberately, so that a warning degrades a run
    /// to `needs_attention` rather than blocking it — and
    /// [`CheckResult::blocks_green`] is that mapping read back. So a warning on
    /// a **critical** check is a false green on exactly the checks where it
    /// matters most. Everything in this mapping that means *SURE did not observe
    /// a completed, trustworthy success* is therefore `Unknown`, `Error` or
    /// `Fail`, because those are the three statuses whose `CriticalState`
    /// blocks.
    ///
    /// # Why the cut-short rows are `Unknown` rather than `Fail`
    ///
    /// The rejected alternative is the one a reader reaches for first, so it is
    /// named here rather than left to be rediscovered: a timeout looks like the
    /// project's failure, and `Fail` would be a status that blocks. It is not
    /// what SURE observed. A command still running when its deadline passed is a
    /// command whose outcome SURE never saw — a slow build is not a broken one,
    /// and `Fail` would be SURE accusing the project of something it did not
    /// measure. `Unknown` is the honest report of the same run: SURE has
    /// evidence and the evidence supports no verdict. The `Warning` reading of
    /// the same rows is rejected one paragraph above, and for a stronger reason.
    ///
    /// # `Exited { code: None }` is a failure, and it is the opposite answer to
    /// the same shape elsewhere
    ///
    /// `runtime_start.rs`'s `observe` maps every `Termination::Exited` to
    /// `CheckStatus::Fail` **regardless of the code**, because its check is
    /// about a service that was meant to stay up: there, a service that ended by
    /// itself is the failure, and the code is printed as detail rather than read
    /// as a verdict. Here the check is whether a command completes successfully,
    /// so exit zero is the pass and a code is read. The two mappings read the
    /// same enum in opposite directions, and neither can call the other.
    ///
    /// Within this table, `Exited { code: None }` is `fail` and not `unknown`
    /// because something *was* observed: the process ended, and not on its own
    /// terms. SURE's own stops are `TimedOut` and `Cancelled` and are never this
    /// variant, so a signal reaching a process SURE started came from outside
    /// the run — a crash, or something on this machine ending it.
    ///
    /// # A stop that could not be confirmed changes the sentence, not the status
    ///
    /// [`Stop::ProcessOnly`] means SURE stopped the process it held and reached
    /// nothing else, so anything the command started may still be running, with
    /// the project's files open or a port bound. It is carried in
    /// [`Self::reason`] rather than in a status, and the reason it can be is
    /// where it occurs: `Stop` is a field of `TimedOut` and `Cancelled` and of
    /// nothing else, so a run whose stop was unconfirmed is already a run that
    /// was cut short and already `Unknown`. What the sentence adds is the one
    /// fact the status cannot carry — the process SURE holds was stopped, and
    /// the rest of the tree was not.
    ///
    /// # A pass is only built from a class that can carry one
    ///
    /// A zero exit with both streams read to the end is reported as `Unknown`
    /// rather than `Pass` when the proposal claims an evidence class that the
    /// private `carries_a_pass` refuses — the same gate
    /// [`PrecomputedEvidence::to_result`] applies through the same predicate,
    /// and for the same reason: the class is what makes a pass a promise, and a
    /// run cannot be promoted past the weight its own check claimed. It is not a
    /// formality on this path either. A proposal that claims `Inference` while
    /// its operation runs a command is a proposal whose two halves disagree, and
    /// the honest report of that is *SURE has evidence that supports no
    /// verdict*, never a green.
    #[must_use]
    pub fn to_result(&self, proposal: &CheckProposal, fingerprint: &FingerprintId) -> CheckResult {
        let (id, title) = (proposal.id().clone(), proposal.title().to_owned());
        let (severity, critical) = (proposal.severity(), proposal.critical());
        let class = proposal.evidence_class();
        let reason = self.reason();
        let status = self.status();
        match status {
            CheckStatus::Pass if !carries_a_pass(class) => {
                CheckResult::unknown(id, title, severity, critical, class, fingerprint.clone())
                    .with_reason(format!(
                        "{reason} A check established by `{}` evidence cannot be reported as \
                         passed.",
                        class.as_str()
                    ))
            }
            CheckStatus::Pass => {
                CheckResult::pass(id, title, severity, critical, class, fingerprint.clone())
                    .with_reason(reason)
            }
            CheckStatus::Fail => {
                CheckResult::fail(id, title, severity, critical, class, fingerprint.clone())
                    .with_reason(reason)
            }
            CheckStatus::Unknown => {
                CheckResult::unknown(id, title, severity, critical, class, fingerprint.clone())
                    .with_reason(reason)
            }
            CheckStatus::Error => {
                CheckResult::errored(id, title, severity, critical, reason, fingerprint.clone())
            }
            // The two statuses this mapping never returns, named rather than
            // swallowed by `_` so that adding a status to `CheckStatus` is a
            // compile error here instead of a silent mis-mapping. Both are sent
            // to `errored` because that is the one constructor that cannot carry
            // a pass: a status arriving here by a future bug would be reported
            // as a failure of SURE's own check, which is what it would be.
            CheckStatus::Warning | CheckStatus::Skipped => CheckResult::errored(
                id,
                title,
                severity,
                critical,
                format!(
                    "SURE cannot say what this run established: it is worth `{}`, which this \
                     mapping never produces.",
                    status.as_str()
                ),
                fingerprint.clone(),
            ),
        }
    }
}

/// What a stop reached, in the words a report uses.
///
/// `WholeTree` is the operating system's own account of the tree — what
/// `taskkill /T /F` reporting success means on Windows — and it is stated rather
/// than left out because "the thing you started is gone, and so is what it
/// started" is a fact a person waiting on a run wants and cannot otherwise
/// check.
fn stop_clause(stop: Stop) -> &'static str {
    match stop {
        Stop::WholeTree => "the stop reached the command and the programs it started",
        Stop::ProcessOnly => {
            "the stop reached only the command itself, so anything it started may still be \
             running"
        }
    }
}

/// What SURE is missing from a run's streams, when it is missing anything.
///
/// `None` means both streams were read to the end and neither was cut short by
/// the output bound: SURE holds the whole of what the process said.
///
/// **Two different facts make a stream less than the whole, and they are one
/// answer here.** [`CapturedOutput::was_truncated`] is bytes SURE *chose* not to
/// keep, and [`CapturedOutput::unfinished`] is a stream SURE *could not* read to
/// the end; the module documentation of `process::outcome` keeps them apart
/// because they mean opposite things about why. A reader's question is a third
/// thing — *am I holding a beginning or a whole?* — and the answer is the same
/// either way, which is why this returns one sentence per stream rather than a
/// two-field verdict.
fn incompleteness(outcome: &Outcome) -> Option<String> {
    let mut clauses: Vec<String> = Vec::new();
    for (name, stream) in [
        ("standard output", outcome.stdout()),
        ("standard error", outcome.stderr()),
    ] {
        if stream.was_truncated() {
            clauses.push(format!(
                "SURE kept the first {} bytes of {name} and {} more were written and not kept, \
                 so what SURE has is a beginning rather than the whole of it",
                stream.bytes().len(),
                stream.discarded_bytes()
            ));
        }
        if let Some(reason) = stream.unfinished() {
            clauses.push(format!("{name} was not read to its end ({reason})"));
        }
    }
    if clauses.is_empty() {
        None
    } else {
        Some(clauses.join("; "))
    }
}

/// Whether SURE holds the whole of what the process said on both streams.
///
/// Written as *nothing to report from [`incompleteness`]* rather than as its own
/// pair of checks, so that the status and the sentence cannot come from two
/// rules that disagree — a stream the reason calls partial is a stream this
/// calls incomplete, by construction rather than by review.
fn output_is_complete(outcome: &Outcome) -> bool {
    incompleteness(outcome).is_none()
}

/// One command: a program, its arguments, and the rules it runs under.
///
/// Every field is named and none of them is a string to be interpreted. An
/// argument holding a space is one argument and stays one argument; on Windows
/// the operating system is handed the vector it is given, and there is no
/// quoting step for SURE to get wrong or right.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandSpec {
    program: OsString,
    arguments: Vec<OsString>,
    working_directory: PathBuf,
    environment: Environment,
    limits: Limits,
}

impl CommandSpec {
    /// A command, with the rules it will run under.
    ///
    /// `working_directory` must be absolute: `process::ProcessRequest` refuses
    /// anything else, and it refuses it there rather than here so that there is
    /// one place where that rule is enforced rather than two that can disagree.
    #[must_use]
    pub fn new(
        program: impl Into<OsString>,
        working_directory: impl Into<PathBuf>,
        environment: Environment,
        limits: Limits,
    ) -> Self {
        Self {
            program: program.into(),
            arguments: Vec::new(),
            working_directory: working_directory.into(),
            environment,
            limits,
        }
    }

    /// The arguments, in the order the program will receive them.
    #[must_use]
    pub fn with_arguments<I, S>(mut self, arguments: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        self.arguments = arguments.into_iter().map(Into::into).collect();
        self
    }

    /// The program, as the plan decided to name it.
    #[must_use]
    pub fn program(&self) -> &OsStr {
        &self.program
    }

    /// The arguments, as the plan decided them.
    #[must_use]
    pub fn arguments(&self) -> &[OsString] {
        &self.arguments
    }

    /// The directory the command runs in, absolute.
    #[must_use]
    pub fn working_directory(&self) -> &Path {
        &self.working_directory
    }

    /// What the command is given to start with.
    #[must_use]
    pub const fn environment(&self) -> &Environment {
        &self.environment
    }

    /// The deadline and the output bound.
    #[must_use]
    pub const fn limits(&self) -> Limits {
        self.limits
    }

    // There is deliberately no method here that turns a spec into the runner's
    // request type. Doing that is the moment this module names
    // `process::ProcessRequest` in code rather than in prose, and
    // `tests/spawn_sites.rs` reads that name as the statement "this file can
    // call the runner". No file has a caller for it yet — the runner is
    // `planned_check_runner`, and it adds that door where the census can see
    // who wanted it and whether the support ceiling has to move with it.
}

/// A service: a program that is meant to stay up, and the one question to ask it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceCheckSpec {
    command: CommandSpec,
    readiness: Readiness,
    window: Duration,
}

impl ServiceCheckSpec {
    /// A service, what will be asked of it, and how long it is given.
    #[must_use]
    pub const fn new(command: CommandSpec, readiness: Readiness, window: Duration) -> Self {
        Self {
            command,
            readiness,
            window,
        }
    }

    /// The command that starts it.
    #[must_use]
    pub const fn command(&self) -> &CommandSpec {
        &self.command
    }

    /// What counts as ready.
    #[must_use]
    pub const fn readiness(&self) -> &Readiness {
        &self.readiness
    }

    /// How long the service is given to become ready, and how long it is kept.
    #[must_use]
    pub const fn window(&self) -> Duration {
        self.window
    }
}

/// The address a service check can ask about.
///
/// **There is no host field, and that is the invariant.** A service check asks a
/// question of a project's own process on the machine it was started on, so the
/// host is loopback and is not a decision anyone gets to make; a variant that
/// carried one would be a variant that could carry `example.com`, and the
/// repository's "no silent external network validation" rule would then rest on
/// every caller rather than on this type.
///
/// **The path is not a `String` either, and that is the same invariant one layer
/// along.** A URL is authority-then-path, and the authority ends at the first
/// `/`. So a path that does *not* begin with one does not extend the path — it
/// extends the **host**: `Answers { port: 8080, path: "@evil.example/" }` reads,
/// to every URL parser there is, as the host `evil.example`, and a check whose
/// whole reason for existing is that it never leaves this machine would have
/// left it. Holding a [`probe::Endpoint`] instead makes that unrepresentable
/// rather than unreviewed: the field is private, both of its constructors
/// validate, and neither will produce one whose path omits the `/`. **This is
/// deliberately the same type the local probe uses and not a second copy of its
/// rule**, because two copies of a refusal rule are two rules the day one of
/// them is changed — the reason [`crate::browser::Target`] gives for wrapping
/// it, which is now this module's reason too.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Readiness {
    /// Nothing is asked of it beyond staying up for the window.
    ///
    /// The weakest of the four and named so that it cannot be mistaken for a
    /// readiness: a service that stayed up and answered nothing is not a service
    /// SURE has confirmed anything about, and the result says exactly that.
    StaysUp,
    /// It answers at this endpoint, which is on loopback by construction.
    Answers {
        /// Where the question is sent.
        endpoint: Endpoint,
    },
}

impl Readiness {
    /// The address a probe of this readiness would be sent to, if any.
    ///
    /// The string is [`Endpoint`]'s own `Display` and not an assembly here, so
    /// the URL a report prints and the URL a request is written for are the same
    /// value rendered once. `127.0.0.1` by number rather than `localhost`,
    /// because `localhost` is a name this machine resolves and a name can be
    /// pointed elsewhere.
    #[must_use]
    pub fn loopback_url(&self) -> Option<String> {
        match self {
            Self::StaysUp => None,
            Self::Answers { endpoint } => Some(endpoint.to_string()),
        }
    }

    /// The endpoint a question would be sent to, or `None` for [`Self::StaysUp`].
    #[must_use]
    pub const fn endpoint(&self) -> Option<&Endpoint> {
        match self {
            Self::StaysUp => None,
            Self::Answers { endpoint } => Some(endpoint),
        }
    }
}

/// A browser check: a service, and the page it is expected to serve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserCheckSpec {
    service: ServiceCheckSpec,
    endpoint: Endpoint,
    expectation: String,
}

impl BrowserCheckSpec {
    /// A page to read, on the service this check starts.
    ///
    /// The host is not a parameter for the same reason it is not one in
    /// [`Readiness`]: the page is the supervised service's own, on loopback. It
    /// is passed to the browser as a URL because a browser takes one, and the
    /// URL is [`Self::loopback_url`] — built by the same [`Endpoint`] that
    /// refused the path, rather than assembled here.
    ///
    /// # Errors
    ///
    /// [`WorkRefusal::ServiceNamesNoPort`] when the service's readiness is
    /// [`Readiness::StaysUp`], because a service that names no port has no page
    /// for a browser to open and the honest answer is to refuse the check rather
    /// than to hand back a `None` a caller would have to remember to handle.
    /// [`WorkRefusal::Endpoint`] when `path` is not a path
    /// [`Endpoint::loopback`] will write into a request line.
    pub fn new(
        service: ServiceCheckSpec,
        path: impl Into<String>,
        expectation: impl Into<String>,
    ) -> Result<Self, WorkRefusal> {
        let port = match service.readiness().endpoint() {
            Some(endpoint) => endpoint.address().port(),
            None => return Err(WorkRefusal::ServiceNamesNoPort),
        };
        let endpoint = Endpoint::loopback(port, path).map_err(WorkRefusal::Endpoint)?;
        Ok(Self {
            service,
            endpoint,
            expectation: expectation.into(),
        })
    }

    /// The service this check starts and stops.
    #[must_use]
    pub const fn service(&self) -> &ServiceCheckSpec {
        &self.service
    }

    /// The path on it the browser opens.
    #[must_use]
    pub fn path(&self) -> &str {
        self.endpoint.path()
    }

    /// What the observation is for.
    #[must_use]
    pub fn expectation(&self) -> &str {
        &self.expectation
    }

    /// The loopback URL the browser is sent to.
    ///
    /// **Not an `Option`.** A browser check that has no URL was refused when it
    /// was built, so a value of this type always has one, and no caller needs a
    /// branch for a case that cannot arise.
    #[must_use]
    pub fn loopback_url(&self) -> String {
        self.endpoint.to_string()
    }
}

/// Why a planned check could not be built.
///
/// A refusal is not a check that failed: it is a check that was never made,
/// and it says which. It is a value so that the reason survives to whatever
/// reports it, instead of becoming a sentence written where it happened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkRefusal {
    /// A browser check was built on a service that never says which port to ask
    /// on, so there is no page to open and nothing to observe.
    ServiceNamesNoPort,
    /// The endpoint a check would have used was refused.
    Endpoint(EndpointError),
}

impl fmt::Display for WorkRefusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ServiceNamesNoPort => write!(
                formatter,
                "the service says it stays up and never says which port to ask on, so there is no page to open"
            ),
            Self::Endpoint(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for WorkRefusal {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ServiceNamesNoPort => None,
            Self::Endpoint(error) => Some(error),
        }
    }
}

/// What a name on `PATH` turns out to be, on the machine that asked.
///
/// Four answers rather than two, because "not found" and "found, and this build
/// will not start it" are different sentences in a report and a user acts on
/// them differently: the first is a tool that is not installed, the second is a
/// tool that is installed and is a script.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolution {
    /// A file this build starts directly.
    Executable(PathBuf),
    /// A file of that name is there, and starting it starts an interpreter:
    /// a `.cmd`, `.bat` or `.ps1` on Windows. This build does not start one, and
    /// `crate::safety` records why a batch file's name is not evidence of what
    /// running it does.
    InterpreterRequired(PathBuf),
    /// A file of that name is there and is not something an operating system
    /// starts as a program.
    NotAProgram(PathBuf),
    /// Nothing of that name is on this path.
    Absent,
}

impl Resolution {
    /// The file that was found, if one was.
    #[must_use]
    pub fn path(&self) -> Option<&Path> {
        match self {
            Self::Executable(path) | Self::InterpreterRequired(path) | Self::NotAProgram(path) => {
                Some(path)
            }
            Self::Absent => None,
        }
    }

    /// Whether this build would start what was found.
    #[must_use]
    pub const fn is_startable(&self) -> bool {
        matches!(self, Self::Executable(_))
    }

    /// What the plan should name as the program, if it names one.
    ///
    /// The **found** name and not the name that was asked for. That is the whole
    /// point of resolving at all: a plan that wrote `npm` names a program this
    /// layer cannot start, and the failure would arrive at run time as a spawn
    /// error rather than at plan time as the truth — there is an `npm.cmd`
    /// here, and this build will not run that file. (The product runner may
    /// still start the program the shim itself runs; see
    /// [`crate::package_launcher`].)
    #[must_use]
    pub fn program_name(&self) -> Option<&Path> {
        self.path()
    }

    /// One line for a report.
    #[must_use]
    pub fn plain_description(&self) -> String {
        match self {
            Self::Executable(path) => {
                format!("{} is a program this build can start", path.display())
            }
            Self::InterpreterRequired(path) => format!(
                "{} is there and starting it starts an interpreter, so this build does not start it",
                path.display()
            ),
            Self::NotAProgram(path) => format!(
                "{} is there and is not a program this build starts",
                path.display()
            ),
            Self::Absent => "nothing of that name is on PATH".to_owned(),
        }
    }
}

/// The directories a program name is looked for in.
///
/// A value rather than a call to [`std::env::var_os`] buried in a builder,
/// because a plan that depends on the machine's `PATH` is a plan whose result
/// depends on the machine — and a test that wants to ask *what would this plan
/// say on a machine where only `npm.cmd` is installed* cannot ask it if the
/// only `PATH` available is the one the test is running under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgramPath {
    search: OsString,
}

impl ProgramPath {
    /// A search path, as the platform spells one.
    #[must_use]
    pub fn from_search_path(search: impl Into<OsString>) -> Self {
        Self {
            search: search.into(),
        }
    }

    /// This machine's `PATH`.
    ///
    /// An empty string when the variable is not set, which makes every name
    /// [`Resolution::Absent`] rather than an error: a machine with no `PATH` is
    /// a machine where nothing is found by name, and saying so is the honest
    /// answer rather than a panic.
    #[must_use]
    pub fn of_this_machine() -> Self {
        Self::from_search_path(std::env::var_os("PATH").unwrap_or_default())
    }

    /// The directories, in the order the platform lists them.
    ///
    /// **Empty entries are dropped, and that is a decision rather than
    /// tidiness.** On Windows an empty element of `PATH` means *the current
    /// directory*, and a current directory that is searched for a program name
    /// is a program name that can be answered by a file the project just wrote:
    /// drop `npm.exe` into a project, run SURE in it, and the plan resolves to
    /// the project's own file. SURE resolves a name to decide what it is about
    /// to ask permission for, so an answer the project could place on disk is
    /// the one answer that must not be given. `Command::new` on Windows would
    /// search it, and this module deliberately does not do what the operating
    /// system would do here — the difference is stated in the module comment so
    /// that it does not read as an oversight.
    pub fn directories(&self) -> impl Iterator<Item = PathBuf> + '_ {
        std::env::split_paths(&self.search).filter(|directory| !directory.as_os_str().is_empty())
    }

    /// What `name` is, on this path, completed the way this platform completes
    /// a bare name.
    #[must_use]
    pub fn resolve(&self, name: &OsStr) -> Resolution {
        self.resolve_with(name, completions())
    }

    /// [`Self::resolve`] against a table of completions handed in.
    ///
    /// **The table is a parameter so that the platform this build is not running
    /// on can be tested on it.** The defect this split was made for is the one
    /// `completions` records: a table that was wrong on macOS and Linux and
    /// right on Windows, where every test that would have read the wrong half
    /// was `#[cfg(windows)]` — so the bug sat in precisely the place no test on
    /// this machine could reach, and the fix for it would have been just as
    /// unreachable as the bug. An argument turns "wrong on the other platform"
    /// from a fact about the build machine into a case, and a case can fail
    /// here.
    fn resolve_with(&self, name: &OsStr, completions: &[(&str, Completion)]) -> Resolution {
        let named = Path::new(name);
        let spelled_out = named.extension().is_some();
        for directory in self.directories() {
            if spelled_out {
                // A caller that named an extension gets that name and no other.
                // Completing `thing.exe` with a second extension would be SURE
                // answering a question nobody asked.
                let candidate = directory.join(named);
                if candidate.is_file() {
                    return classify(&candidate);
                }
                continue;
            }
            for (extension, kind) in completions {
                let candidate = if extension.is_empty() {
                    // The platform completes a bare name with nothing, so the
                    // candidate is the name itself. This is a branch rather
                    // than a `format!` so that the joined spelling is never
                    // produced at all: `{name}.` is a different file name from
                    // `{name}`, and looking for it would report a program that
                    // is installed as one that is not.
                    directory.join(named)
                } else {
                    directory.join(format!(
                        "{}.{extension}",
                        named.as_os_str().to_string_lossy()
                    ))
                };
                if candidate.is_file() {
                    return match kind {
                        Completion::Executable => Resolution::Executable(candidate),
                        // Gated with the variant it reads. On a platform whose
                        // completion table cannot hold one of these the arm
                        // could never be reached, and `Completion` has a single
                        // variant there.
                        #[cfg(windows)]
                        Completion::Interpreter => Resolution::InterpreterRequired(candidate),
                    };
                }
            }
        }
        Resolution::Absent
    }
}

/// One extension a name with none of its own is completed with.
enum Completion {
    /// An image this build starts directly.
    Executable,
    /// A file whose start is an interpreter's.
    ///
    /// **Windows-only, and gated rather than allowed to be dead.** Only the
    /// `PATHEXT` list can hold one of these — `.bat`, `.cmd` and `.ps1` are
    /// where an interpreter's start comes from — while a platform without
    /// `PATHEXT` completes a bare name with the name and with nothing else, so
    /// it has no such completion to describe. On those platforms this variant is
    /// not unused but unconstructible, and the gate is what makes an
    /// `Interpreter` entry in the table below a **compile error** rather than a
    /// silently dead enum arm; `#[allow(dead_code)]` would have silenced the
    /// same warning and left the entry writable.
    #[cfg(windows)]
    Interpreter,
}

/// The completions, in the order the operating system would try them.
///
/// Windows' own `PATHEXT` order is `.COM;.EXE;.BAT;.CMD`, and the two script
/// extensions are kept in that order here so that a machine with both would be
/// reported as it would behave. `.PS1` is **not** in `PATHEXT` — Windows would
/// never start `foo.ps1` by that name — and it is listed last so that a machine
/// with both an `.exe` and a `.ps1` reports the `.exe`, and one with only the
/// `.ps1` says there is a script there rather than saying there is nothing.
#[cfg(windows)]
const fn completions() -> &'static [(&'static str, Completion)] {
    &[
        ("com", Completion::Executable),
        ("exe", Completion::Executable),
        ("bat", Completion::Interpreter),
        ("cmd", Completion::Interpreter),
        ("ps1", Completion::Interpreter),
    ]
}

/// On a platform without `PATHEXT` there is one completion and it is the name.
///
/// The empty suffix is the completion, not a wildcard: `execvp` starts the file
/// whose name is the one it was handed, so `cargo` on `PATH` is a file called
/// `cargo`. **An empty list here was wrong, and wrong in the direction this
/// repository treats as serious.** It meant a bare name could only ever answer
/// [`Resolution::Absent`] on macOS and Linux — every installed program reported
/// as one that is not there, on the two platforms this build is required to stay
/// portable to, and only on those, because the Windows list below is not empty.
/// Nothing caught it while P18-T002 stood: the table of completions had no test
/// of its own off Windows, and the tests that would have read it were
/// `#[cfg(windows)]` because the *interesting* cases are Windows cases. The
/// predicate was right on the machine it was written on and false on the two it
/// was written for, which is the shape this repository keeps finding.
#[cfg(any(not(windows), test))]
const WITHOUT_PATHEXT: &[(&str, Completion)] = &[("", Completion::Executable)];

#[cfg(not(windows))]
const fn completions() -> &'static [(&'static str, Completion)] {
    WITHOUT_PATHEXT
}

/// What a file that was found is.
#[cfg(windows)]
fn classify(path: &Path) -> Resolution {
    let extension = path
        .extension()
        .map(|extension| extension.to_string_lossy().to_ascii_lowercase());
    match extension.as_deref() {
        Some("com" | "exe") => Resolution::Executable(path.to_path_buf()),
        Some("bat" | "cmd" | "ps1") => Resolution::InterpreterRequired(path.to_path_buf()),
        _ => Resolution::NotAProgram(path.to_path_buf()),
    }
}

/// On a platform that starts a file by its own rules, a file that is there is a
/// program this build will start: whether it runs is the operating system's
/// question, and this build does not pretend to answer it.
#[cfg(not(windows))]
fn classify(path: &Path) -> Resolution {
    if path.is_file() {
        Resolution::Executable(path.to_path_buf())
    } else {
        Resolution::NotAProgram(path.to_path_buf())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::process::{CapturedOutput, Limits};
    use crate::schedule::CheckReason;
    use std::time::SystemTime;
    use sure_domain::evidence::EvidenceClass;
    use sure_domain::ids::CheckId;
    use sure_domain::severity::Severity;
    use sure_domain::status::{AggregateSeverity, CheckStatus, aggregate};

    fn a_proposal() -> CheckProposal {
        CheckProposal::new(
            CheckId::generate(),
            "the project declares a test script",
            Severity::ShouldFixFirst,
            true,
            EvidenceClass::ObservedFact,
            CheckReason::ProjectWide,
            &[sure_domain::execution::ActionKind::ReadFile],
        )
    }

    fn a_fingerprint() -> FingerprintId {
        FingerprintId::generate()
    }

    fn a_spec() -> CommandSpec {
        CommandSpec::new(
            "cargo",
            PathBuf::from(r"C:\project"),
            Environment::inherited(),
            Limits::new(Duration::from_secs(5), 4096, 4096),
        )
        .with_arguments(["test", "--workspace", "a path with spaces"])
    }

    /// A directory of this test's own, holding the named files.
    fn a_directory_holding(name: &str, files: &[&str]) -> PathBuf {
        let directory = sure_testkit::scratch::directory("sure planned work", name);
        for file in files {
            std::fs::write(directory.join(file), b"fixture\n").expect("the fixture file");
        }
        directory
    }

    #[test]
    fn work_carries_its_operation_and_its_identity_together() {
        let proposal = a_proposal();
        let id = proposal.id().clone();
        let work = PlannedWork::new(proposal, CheckOperation::Command(a_spec()));
        assert_eq!(work.proposal().id(), &id);
        assert!(matches!(work.operation(), CheckOperation::Command(_)));
        assert!(work.operation().starts_a_process());
    }

    #[test]
    fn precomputed_work_is_the_only_kind_that_starts_nothing() {
        let work = PlannedWork::new(
            a_proposal(),
            CheckOperation::Precomputed(PrecomputedEvidence::holds("the script is there")),
        );
        assert!(!work.operation().starts_a_process());
    }

    #[test]
    fn an_argument_with_a_space_in_it_is_one_argument() {
        let spec = a_spec();
        assert_eq!(
            spec.arguments(),
            ["test", "--workspace", "a path with spaces"]
        );
        assert_eq!(spec.program(), OsStr::new("cargo"));
    }

    #[test]
    fn a_detector_that_holds_produces_a_pass_and_one_that_could_not_run_does_not() {
        let proposal = a_proposal();
        let fingerprint = a_fingerprint();
        let held = PrecomputedEvidence::holds("package.json declares scripts.test")
            .to_result(&proposal, &fingerprint);
        assert_eq!(held.status, sure_domain::status::CheckStatus::Pass);
        assert!(!held.blocks_green());

        let unread = PrecomputedEvidence::could_not_run("package.json could not be parsed")
            .to_result(&proposal, &fingerprint);
        assert_eq!(unread.status, sure_domain::status::CheckStatus::Error);
        assert!(
            unread.blocks_green(),
            "a detector that could not read what it needed must not leave a critical check green"
        );

        let candidate = PrecomputedEvidence::candidate("a route that looks like a stub")
            .to_result(&proposal, &fingerprint);
        assert_eq!(candidate.status, sure_domain::status::CheckStatus::Warning);

        let contradicted =
            PrecomputedEvidence::contradicted("the lockfile and the manifest disagree")
                .to_result(&proposal, &fingerprint);
        assert_eq!(contradicted.status, sure_domain::status::CheckStatus::Fail);
    }

    /// A critical proposal claiming this evidence class, for the sweep below.
    fn a_critical_proposal_weighted(class: EvidenceClass) -> CheckProposal {
        CheckProposal::new(
            CheckId::generate(),
            "a pattern SURE found in a source file",
            Severity::MustFix,
            true,
            class,
            CheckReason::ProjectWide,
            &[sure_domain::execution::ActionKind::ReadFile],
        )
    }

    #[test]
    fn a_pass_is_only_built_from_a_class_that_can_carry_one() {
        // The split is the domain's own predicate and not a list restated here,
        // which is the point: a copy of it in this test would pass while the
        // product's half changed.
        let fingerprint = a_fingerprint();
        for &class in EvidenceClass::ALL {
            let result = PrecomputedEvidence::holds("the pattern this check is about is not there")
                .to_result(&a_critical_proposal_weighted(class), &fingerprint);
            assert_eq!(
                result.evidence_class, class,
                "{class:?}: the result relabelled the evidence the check claimed"
            );
            if class.can_alone_support_must_fix() {
                assert_eq!(result.status, CheckStatus::Pass, "{class:?}");
                assert!(
                    !result.blocks_green(),
                    "{class:?}: a pass that can carry a verdict must not block green"
                );
            } else {
                assert_eq!(
                    result.status,
                    CheckStatus::Unknown,
                    "{class:?}: a reading that cannot stand behind a finding came \
                     back as a pass, which is the false green this product exists \
                     to catch"
                );
                assert!(
                    result.blocks_green(),
                    "{class:?}: a critical check that supports no verdict must not \
                     leave a run green"
                );
                assert!(
                    result.reason.contains("cannot be reported as passed"),
                    "{class:?}: the reason does not say why this is not a pass: {}",
                    result.reason
                );
            }
        }
    }

    #[test]
    fn a_result_carries_the_proposals_own_weight_and_the_fingerprint_it_was_given() {
        let proposal = a_proposal();
        let fingerprint = a_fingerprint();
        let result = PrecomputedEvidence::holds("it is there").to_result(&proposal, &fingerprint);
        assert_eq!(result.evidence_class, EvidenceClass::ObservedFact);
        assert_eq!(result.severity, Severity::ShouldFixFirst);
        assert!(result.critical);
        assert_eq!(result.project_fingerprint, fingerprint);
    }

    /// An outcome, as the runner would have produced it, with both streams read
    /// to the end.
    fn an_outcome(termination: Termination) -> Outcome {
        an_outcome_saying(termination, said(""), said(""))
    }

    /// The same, with the two streams handed in.
    fn an_outcome_saying(
        termination: Termination,
        stdout: CapturedOutput,
        stderr: CapturedOutput,
    ) -> Outcome {
        Outcome::new(
            OsString::from("npm"),
            termination,
            stdout,
            stderr,
            SystemTime::now(),
            Duration::from_millis(1_500),
        )
    }

    /// A stream SURE read to its end.
    fn said(text: &str) -> CapturedOutput {
        CapturedOutput::new(text.as_bytes().to_vec(), 0, None)
    }

    /// A stream with more bytes in it than SURE keeps.
    fn said_more_than_it_kept(text: &str, discarded: u64) -> CapturedOutput {
        CapturedOutput::new(text.as_bytes().to_vec(), discarded, None)
    }

    /// A stream SURE could not read to the end.
    fn never_finished(text: &str, why: &str) -> CapturedOutput {
        CapturedOutput::new(text.as_bytes().to_vec(), 0, Some(why.to_owned()))
    }

    /// A run of a command that ended in this way.
    fn a_run_that_ended(termination: Termination) -> CommandRun {
        CommandRun::Ran(an_outcome(termination))
    }

    /// A short name for a termination, for a failure message — **and the tie
    /// between [`every_termination`] and the enum**.
    ///
    /// This function matches every variant with no `_` arm, so a termination
    /// added to `crate::process` stops this module compiling, and it stops it
    /// here: next to the list a case has to be added to, rather than at some
    /// assertion far away. `Termination` has no `ALL` — it belongs to
    /// `crate::process`, and this task adds a mapping rather than a variant list
    /// to it — so a sweep has to name its cases itself, and a hand-written list
    /// is exactly the thing that goes stale. This is what keeps it honest.
    fn termination_name(termination: Termination) -> &'static str {
        match termination {
            Termination::Exited { code: Some(0) } => "Exited { code: Some(0) }",
            Termination::Exited { code: Some(_) } => "Exited { code: Some(non-zero) }",
            Termination::Exited { code: None } => "Exited { code: None }",
            Termination::TimedOut {
                stopped: Stop::WholeTree,
            } => "TimedOut { stopped: WholeTree }",
            Termination::TimedOut {
                stopped: Stop::ProcessOnly,
            } => "TimedOut { stopped: ProcessOnly }",
            Termination::Cancelled {
                stopped: Stop::WholeTree,
            } => "Cancelled { stopped: WholeTree }",
            Termination::Cancelled {
                stopped: Stop::ProcessOnly,
            } => "Cancelled { stopped: ProcessOnly }",
            Termination::CancelledBeforeStart => "CancelledBeforeStart",
        }
    }

    /// Every termination the runner can report.
    ///
    /// The four variants, and every combination of the fields they carry: both
    /// stops for each of the two that have one, and three exit codes rather than
    /// one, because *which* non-zero code came back is a thing SURE prints and
    /// never a thing it decides a status by.
    fn every_termination() -> Vec<Termination> {
        vec![
            Termination::Exited { code: Some(0) },
            Termination::Exited { code: Some(1) },
            Termination::Exited { code: Some(9_009) },
            Termination::Exited { code: None },
            Termination::TimedOut {
                stopped: Stop::WholeTree,
            },
            Termination::TimedOut {
                stopped: Stop::ProcessOnly,
            },
            Termination::Cancelled {
                stopped: Stop::WholeTree,
            },
            Termination::Cancelled {
                stopped: Stop::ProcessOnly,
            },
            Termination::CancelledBeforeStart,
        ]
    }

    /// A short name for a `ProcessError`, on the same terms as
    /// [`termination_name`]: exhaustive, no `_` arm, so a variant added to the
    /// error type stops this module compiling.
    fn error_name(error: &ProcessError) -> &'static str {
        match error {
            ProcessError::WorkingDirectoryNotAbsolute { .. } => "WorkingDirectoryNotAbsolute",
            ProcessError::WorkingDirectoryUnusable { .. } => "WorkingDirectoryUnusable",
            ProcessError::NotStarted { .. } => "NotStarted",
            ProcessError::CouldNotBeWatched { .. } => "CouldNotBeWatched",
        }
    }

    /// One of every `ProcessError` the runner can report — the four shapes
    /// `process::run` returns in place of an outcome.
    fn every_process_error() -> Vec<ProcessError> {
        vec![
            ProcessError::WorkingDirectoryNotAbsolute {
                working_directory: PathBuf::from("relative/dir"),
            },
            ProcessError::WorkingDirectoryUnusable {
                working_directory: PathBuf::from(r"C:\moved away"),
                message: "the system cannot find the path specified".to_owned(),
            },
            ProcessError::NotStarted {
                program: OsString::from("npm"),
                working_directory: PathBuf::from(r"C:\project"),
                message: "the system cannot find the file specified".to_owned(),
            },
            ProcessError::CouldNotBeWatched {
                program: OsString::from("npm"),
                message: "the handle is invalid".to_owned(),
            },
        ]
    }

    #[test]
    fn every_termination_the_runner_can_report_gets_an_answer_and_never_a_warning() {
        // The acceptance's third clause, and the sweep it asks for is driven by
        // `every_termination` rather than by a list written into this test —
        // with `termination_name` as the tie that refuses to compile when a
        // variant is added. What it asserts is not the table (every row has its
        // own test below) but the two things that must hold for *every* case: an
        // answer comes back, and it is never one of the two statuses this
        // mapping does not have a case for.
        let proposal = a_proposal();
        let fingerprint = a_fingerprint();
        for case in every_termination() {
            let run = a_run_that_ended(case);
            // Asked of the mapping's own answer first, and of the result
            // second, because the two can differ: `to_result` sends a status it
            // never produces to `errored` rather than believing it, so a
            // `Warning` introduced into `status` alone would be caught there and
            // hidden here. Both halves are asserted so that a single-line
            // mutation shows up whichever line it was made on.
            assert!(
                matches!(
                    run.status(),
                    CheckStatus::Pass
                        | CheckStatus::Fail
                        | CheckStatus::Unknown
                        | CheckStatus::Error
                ),
                "{} came back as `{}`, which this mapping must never produce: a warning on a \
                 critical check is read as `CriticalState::Passed` and does not block green",
                termination_name(case),
                run.status().as_str()
            );
            let result = run.to_result(&proposal, &fingerprint);
            assert!(
                matches!(
                    result.status,
                    CheckStatus::Pass
                        | CheckStatus::Fail
                        | CheckStatus::Unknown
                        | CheckStatus::Error
                ),
                "{} came back as `{}`, which this mapping must never produce",
                termination_name(case),
                result.status.as_str()
            );
            assert!(
                !result.reason.trim().is_empty(),
                "{} produced a result with nothing said about it",
                termination_name(case)
            );
        }
        for error in every_process_error() {
            let result = CommandRun::NeverStarted(error.clone()).to_result(&proposal, &fingerprint);
            assert_eq!(result.status, CheckStatus::Error, "{}", error_name(&error));
            assert!(
                !result.reason.trim().is_empty(),
                "{} produced a result with nothing said about it",
                error_name(&error)
            );
        }
    }

    #[test]
    fn only_a_command_that_exited_zero_with_both_streams_read_to_the_end_is_a_pass() {
        // The acceptance's first clause, both halves, over the whole sweep
        // rather than over the two cases that name it: "exit 0 is a pass" is a
        // claim about one row and "everything else is not" is a claim about all
        // of them. `blocks_green` is asserted as well as the status, because a
        // critical check that came back `warning` would satisfy a status-only
        // reading and still be a green.
        let proposal = a_proposal();
        let fingerprint = a_fingerprint();
        for case in every_termination() {
            let result = a_run_that_ended(case).to_result(&proposal, &fingerprint);
            let is_the_pass_case = case == (Termination::Exited { code: Some(0) });
            assert_eq!(
                result.status == CheckStatus::Pass,
                is_the_pass_case,
                "{} came back as `{}`: a pass is exactly the zero exit with both streams read to \
                 the end",
                termination_name(case),
                result.status.as_str()
            );
            assert_eq!(
                result.blocks_green(),
                !is_the_pass_case,
                "{} came back as `{}`, and a run that is not the passing one must block a green \
                 verdict on a critical check",
                termination_name(case),
                result.status.as_str()
            );
        }
    }

    /// The acceptance's second clause, as one test: *a spawn failure, a timeout,
    /// a cancellation, a stop that could not be confirmed and materially
    /// incomplete output are never a pass.*
    ///
    /// **This is the test that has to fail if the mapping softens**, so the
    /// assertion is [`CheckResult::blocks_green`] and not `status != Pass`. The
    /// tempting mutation is `Warning` — the status that reads like "it ran and
    /// something is worth a caution" — and a status-only assertion would let it
    /// through, because `Warning` is not `Pass` and `CriticalState::from_status`
    /// maps it to `Passed`, where it blocks nothing. Asserting what the product
    /// actually reads (`aggregate_run` reads exactly this method) is the
    /// difference between a test and a test that cannot fail.
    ///
    /// Each case is asserted twice — once on the status the mapping returns and
    /// once on the result it builds — because the two are not the same line: a
    /// `Warning` reaching `to_result` is refused by the arm that exists to
    /// refuse it, so a mutation in `status` alone would show up only in the
    /// first assertion and a mutation in that refusal only in the second.
    #[test]
    fn a_run_that_was_cut_short_never_leaves_a_critical_check_green() {
        let proposal = a_proposal();
        let fingerprint = a_fingerprint();

        let mut cases: Vec<(String, CommandRun)> = Vec::new();
        for case in every_termination() {
            if case == (Termination::Exited { code: Some(0) }) {
                // The one case that is a pass, and it is held out here rather
                // than left out of the sweep: its incomplete twins are added
                // below, which is the "materially incomplete output" half of the
                // clause.
                continue;
            }
            cases.push((termination_name(case).to_owned(), a_run_that_ended(case)));
        }
        for error in every_process_error() {
            cases.push((
                error_name(&error).to_owned(),
                CommandRun::NeverStarted(error),
            ));
        }
        cases.push((
            "exit 0 with standard output cut short by the bound".to_owned(),
            CommandRun::Ran(an_outcome_saying(
                Termination::Exited { code: Some(0) },
                said_more_than_it_kept("the first part of what it said", 4_096),
                said(""),
            )),
        ));
        cases.push((
            "exit 0 with standard error cut short by the bound".to_owned(),
            CommandRun::Ran(an_outcome_saying(
                Termination::Exited { code: Some(0) },
                said(""),
                said_more_than_it_kept("the first part of what it said", 4_096),
            )),
        ));
        cases.push((
            "exit 0 with a stream SURE could not read to the end".to_owned(),
            CommandRun::Ran(an_outcome_saying(
                Termination::Exited { code: Some(0) },
                never_finished("a beginning", "the reader did not finish"),
                said(""),
            )),
        ));

        for (name, run) in cases {
            // The mapping's own answer, asked before the result is built. It has
            // to be here as well as the `blocks_green` assertion below, because
            // `to_result` refuses to believe a status the table never produces —
            // so a cut-short run mapped to `Warning` in `status` alone would come
            // out as an `error` and slip past the assertion that is about the
            // false green. The two assertions fail on different mutations, and
            // one of them is the mutation this test exists for.
            assert!(
                !matches!(run.status(), CheckStatus::Pass | CheckStatus::Warning),
                "{name}: a run SURE did not see finish, or did not see the whole of, is worth \
                 `{}`. It must be `unknown`, `error` or `fail`: a `pass` would be a green on a \
                 run nobody saw end, and a `warning` is read as `CriticalState::Passed` and \
                 blocks nothing",
                run.status().as_str()
            );
            let result = run.to_result(&proposal, &fingerprint);
            assert_ne!(
                result.status,
                CheckStatus::Pass,
                "{name}: a run SURE did not see finish, or did not see the whole of, came back as \
                 a pass"
            );
            assert!(
                result.blocks_green(),
                "{name}: a critical check came back as `{}` and does not block green. A timeout, a \
                 cancellation, a stop that could not be confirmed or output SURE holds only part \
                 of must be `unknown`, `error` or `fail`: `warning` is read as \
                 `CriticalState::Passed`, which is the false green this product exists to prevent",
                result.status.as_str()
            );
            assert!(
                !aggregate(std::slice::from_ref(&result)).is_green(),
                "{name}: the run as a whole came out green from a check that never saw its \
                 command finish"
            );
        }

        // The control, without which everything above would pass for a mapping
        // that never passes anything: the held-out case really is a pass, and a
        // real one does not block.
        let passed = a_run_that_ended(Termination::Exited { code: Some(0) })
            .to_result(&proposal, &fingerprint);
        assert_eq!(
            passed.status,
            CheckStatus::Pass,
            "the control case is no longer a pass: {}",
            passed.reason
        );
        assert!(!passed.blocks_green());
        assert!(aggregate(&[passed]).is_green());
    }

    #[test]
    fn a_non_zero_exit_is_a_failure_of_the_check_and_the_reason_says_which_code() {
        // The other half of the first clause. The code is read into the
        // sentence and never into the status, which is the same rule
        // `runtime_start.rs` follows for the same field — there the status is
        // `fail` whatever the code says, and here every non-zero code is one
        // answer because the check's question is "did this succeed".
        for code in [1, 2, 9_009] {
            let result = a_run_that_ended(Termination::Exited { code: Some(code) })
                .to_result(&a_proposal(), &a_fingerprint());
            assert_eq!(result.status, CheckStatus::Fail, "exit code {code}");
            assert!(result.blocks_green(), "exit code {code}");
            assert!(
                result.reason.contains(&format!("exit code {code}")),
                "exit code {code}: the sentence does not say which code came back: {}",
                result.reason
            );
            assert_eq!(
                aggregate(std::slice::from_ref(&result)).severity,
                AggregateSeverity::NotReady,
                "exit code {code}: a failed critical check must not aggregate to anything gentler"
            );
        }
    }

    #[test]
    fn a_command_the_operating_system_ended_is_not_a_clean_exit() {
        // `None` is what a process the operating system ended with a signal
        // looks like — a Unix fact with no Windows equivalent, modelled as
        // `None` rather than as a fabricated code. It is `fail` and not
        // `unknown` because something *was* observed: the process ended, and not
        // on its own terms. SURE's own stops are `TimedOut` and `Cancelled` and
        // are never this variant, so whatever ended this process was not SURE.
        let result = a_run_that_ended(Termination::Exited { code: None })
            .to_result(&a_proposal(), &a_fingerprint());
        assert_eq!(result.status, CheckStatus::Fail);
        assert!(result.blocks_green());
        assert!(
            result.reason.contains("ended by the operating system"),
            "the sentence must say who ended it: {}",
            result.reason
        );
        assert!(
            !result.reason.contains("exit code 0"),
            "a process the operating system ended must never read as a clean exit: {}",
            result.reason
        );
    }

    #[test]
    fn a_run_cancelled_before_it_started_is_an_error_rather_than_an_observation() {
        // `process::run` really returns this outcome — `Outcome::never_started`
        // is what a request already cancelled comes back as — so this is a
        // reachable answer rather than a defensive arm. Nothing ran, so there is
        // no observation to weigh, and `error` says that where `unknown` would
        // claim SURE has evidence.
        let result = a_run_that_ended(Termination::CancelledBeforeStart)
            .to_result(&a_proposal(), &a_fingerprint());
        assert_eq!(result.status, CheckStatus::Error);
        assert_eq!(result.evidence_class, EvidenceClass::Unknown);
        assert!(result.blocks_green());
        assert!(
            result.reason.contains("so nothing ran"),
            "the sentence must say that nothing ran: {}",
            result.reason
        );
    }

    #[test]
    fn output_sure_holds_only_part_of_turns_a_zero_exit_into_an_unknown() {
        // `CapturedOutput::was_truncated`'s own documentation supplies the
        // reason: *"a reader that treats a truncated stream as the complete
        // output is reading a partial answer as a full one, which is the shape
        // of failure this product exists to prevent."* An exit code is one fact
        // about a run and the streams are the rest of what a check reads, so a
        // run whose output is a beginning and not a whole supports no verdict.
        //
        // The two causes are here together because they are one answer to a
        // reader — bytes SURE chose not to keep, and a stream SURE could not
        // read to the end — while `process::outcome` keeps them apart for the
        // report that has to say why.
        let proposal = a_proposal();
        let fingerprint = a_fingerprint();

        // The control: the same run with both streams read to the end is a pass,
        // so what the cases below measure is the incompleteness and not the
        // shape of the fixture.
        let whole = CommandRun::Ran(an_outcome_saying(
            Termination::Exited { code: Some(0) },
            said("built the thing\n"),
            said(""),
        ))
        .to_result(&proposal, &fingerprint);
        assert_eq!(
            whole.status,
            CheckStatus::Pass,
            "the control is no longer a pass: {}",
            whole.reason
        );

        let cases = [
            (
                "standard output",
                said_more_than_it_kept("the first part of what it said", 4_096),
                said(""),
            ),
            (
                "standard error",
                said(""),
                said_more_than_it_kept("the first part of what it said", 4_096),
            ),
            (
                "standard output",
                never_finished("a beginning", "the reader did not finish"),
                said(""),
            ),
            (
                "standard error",
                said(""),
                never_finished("a beginning", "the reader did not finish"),
            ),
        ];
        for (stream, stdout, stderr) in cases {
            let result = CommandRun::Ran(an_outcome_saying(
                Termination::Exited { code: Some(0) },
                stdout,
                stderr,
            ))
            .to_result(&proposal, &fingerprint);
            assert_eq!(
                result.status,
                CheckStatus::Unknown,
                "{stream}: a zero exit with output SURE holds only part of came back as `{}`",
                result.status.as_str()
            );
            assert!(result.blocks_green(), "{stream}");
            assert!(
                result.reason.contains(stream),
                "{stream}: the sentence does not say which stream is incomplete: {}",
                result.reason
            );
            assert!(
                result.reason.contains("beginning")
                    || result.reason.contains("not read to its end"),
                "{stream}: the sentence does not say what is missing: {}",
                result.reason
            );
        }
    }

    #[test]
    fn a_stop_that_could_not_be_confirmed_is_said_out_loud() {
        // The unconfirmed stop is handled in the sweep above, where it is one of
        // the cases that must never leave a critical check green. What is left
        // for this test is the fact the status cannot carry: `ProcessOnly` means
        // anything the command started may still be running on this machine,
        // with the project's files open or a port bound, and a report that did
        // not say so would leave a person with a process they cannot see.
        for stop in [Stop::WholeTree, Stop::ProcessOnly] {
            for termination in [
                Termination::TimedOut { stopped: stop },
                Termination::Cancelled { stopped: stop },
            ] {
                let run = a_run_that_ended(termination);
                let reason = run.reason();
                assert_eq!(
                    run.status(),
                    CheckStatus::Unknown,
                    "{termination:?}: the stop changes the sentence, not the status"
                );
                match stop {
                    Stop::WholeTree => {
                        assert!(
                            reason.contains("the programs it started"),
                            "{termination:?}: a stop that reached the tree must say so: {reason}"
                        );
                        assert!(
                            !reason.contains("may still be running"),
                            "{termination:?}: nothing may still be running after a whole-tree \
                             stop, and saying so would be a warning about nothing: {reason}"
                        );
                    }
                    Stop::ProcessOnly => {
                        assert!(
                            reason.contains("only the command itself")
                                && reason.contains("may still be running"),
                            "{termination:?}: a stop that reached only the process must say what \
                             it did not reach: {reason}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn a_pass_from_a_command_is_only_built_from_a_class_that_can_carry_one() {
        // The same rule the precomputed path holds, one layer along, asked
        // through the same predicate rather than through a list written here: a
        // run cannot be promoted past the weight its own check claimed. It is
        // not a formality on this path — a proposal that claims a pattern guess
        // while its operation runs a command has two halves that disagree, and
        // the honest report of that is *SURE has evidence that supports no
        // verdict*, never a green.
        let fingerprint = a_fingerprint();
        for &class in EvidenceClass::ALL {
            let result = a_run_that_ended(Termination::Exited { code: Some(0) })
                .to_result(&a_critical_proposal_weighted(class), &fingerprint);
            assert_eq!(
                result.evidence_class, class,
                "{class:?}: the result relabelled the evidence the check claimed"
            );
            if class.can_alone_support_must_fix() {
                assert_eq!(result.status, CheckStatus::Pass, "{class:?}");
                assert!(
                    !result.blocks_green(),
                    "{class:?}: a pass that can carry a verdict must not block green"
                );
            } else {
                assert_eq!(
                    result.status,
                    CheckStatus::Unknown,
                    "{class:?}: a command that exited zero came back as a pass from evidence that \
                     cannot carry one"
                );
                assert!(
                    result.blocks_green(),
                    "{class:?}: a critical check that supports no verdict must not leave a run \
                     green"
                );
                assert!(
                    result.reason.contains("cannot be reported as passed"),
                    "{class:?}: the reason does not say why this is not a pass: {}",
                    result.reason
                );
            }
        }
    }

    #[test]
    fn a_run_that_never_happened_leaves_no_observation_behind() {
        // Every `ProcessError` is one answer for one reason: `process::error`'s
        // module documentation says of all of them that the process did not run.
        // `errored` fixes the class at `EvidenceClass::Unknown`, and
        // `checks::evidence_of` records no evidence for a result of that class —
        // so a check SURE could not perform leaves nothing behind that a later
        // reader could mistake for a measurement.
        let proposal = a_proposal();
        let fingerprint = a_fingerprint();
        for error in every_process_error() {
            let name = error_name(&error);
            let result = CommandRun::NeverStarted(error.clone()).to_result(&proposal, &fingerprint);
            assert_eq!(result.status, CheckStatus::Error, "{name}");
            assert!(result.blocks_green(), "{name}");
            assert_eq!(result.evidence_class, EvidenceClass::Unknown, "{name}");
            assert!(
                result.not_checked_reason.is_none(),
                "{name}: an error means the check was attempted, which a skip means it was not"
            );
            assert!(
                result.reason.contains(&error.to_string()),
                "{name}: the sentence does not carry the error's own words: {}",
                result.reason
            );
        }
    }

    #[test]
    fn a_run_result_carries_the_proposals_own_weight_and_the_fingerprint_it_was_given() {
        let proposal = a_proposal();
        let fingerprint = a_fingerprint();
        let result = a_run_that_ended(Termination::Exited { code: Some(0) })
            .to_result(&proposal, &fingerprint);
        assert_eq!(result.evidence_class, EvidenceClass::ObservedFact);
        assert_eq!(result.severity, Severity::ShouldFixFirst);
        assert!(result.critical);
        assert_eq!(result.project_fingerprint, fingerprint);
        assert_eq!(result.id, *proposal.id());
        assert_eq!(result.title, proposal.title());
    }

    #[test]
    fn the_runners_own_answer_is_what_a_command_run_is_built_from() {
        // `process::run` returns a `Result<Outcome, ProcessError>`, and the
        // conversion is here so that the step from the machinery to the mapping
        // is one call rather than a match every caller writes and keeps right.
        // The accessors are what a caller reads back without matching again.
        let outcome = an_outcome(Termination::Exited { code: Some(0) });
        let ran = CommandRun::from(Ok(outcome.clone()));
        assert_eq!(ran, CommandRun::Ran(outcome.clone()));
        assert_eq!(ran.outcome(), Some(&outcome));
        assert!(ran.error().is_none());

        let error = ProcessError::NotStarted {
            program: OsString::from("npm"),
            working_directory: PathBuf::from(r"C:\project"),
            message: "the system cannot find the file specified".to_owned(),
        };
        let never = CommandRun::from(Err(error.clone()));
        assert_eq!(never, CommandRun::NeverStarted(error.clone()));
        assert!(never.outcome().is_none());
        assert_eq!(never.error(), Some(&error));
    }

    /// A service that answers on `port`, for the fixtures below.
    fn a_service_answering_on(port: u16) -> ServiceCheckSpec {
        let endpoint = Endpoint::loopback(port, "/").expect("`/` is a safe path");
        ServiceCheckSpec::new(
            a_spec(),
            Readiness::Answers { endpoint },
            Duration::from_secs(20),
        )
    }

    /// The authority of an `http://` URL as text: everything before the first
    /// `/` after the scheme. Written out here rather than pulled from a URL
    /// parser so that the test states the rule it is checking — **the authority
    /// ends at the first `/`, so a path that does not start with one is part of
    /// the host** — instead of borrowing a library's agreement with it.
    fn authority_of(url: &str) -> &str {
        let after_scheme = url.strip_prefix("http://").expect("the scheme is http");
        match after_scheme.find('/') {
            Some(slash) => &after_scheme[..slash],
            None => after_scheme,
        }
    }

    /// The host an `http://` URL would actually reach: the authority with any
    /// userinfo and the port taken off.
    ///
    /// This is a second step and not a pedantic one. `http://127.0.0.1:8080@evil.example/`
    /// has the authority `127.0.0.1:8080@evil.example` — which *looks* loopback,
    /// because the loopback address is right there at the front — and the host
    /// `evil.example`, because everything before the `@` is userinfo. **A test
    /// that stopped at the authority would pass on that string**, and the first
    /// version of this helper did exactly that: the assertion failed with
    /// `left: "127.0.0.1:8080@evil.example"`, which is the measured proof that
    /// the authority is not the part that decides where the request goes.
    ///
    /// Splitting the port off the first `:` is enough here because every
    /// [`Endpoint`] in this module is IPv4 loopback; a bracketed IPv6 host would
    /// need more, and this module has no way to build one.
    fn host_of(url: &str) -> &str {
        let authority = authority_of(url);
        let without_userinfo = match authority.rsplit_once('@') {
            Some((_userinfo, host)) => host,
            None => authority,
        };
        match without_userinfo.split_once(':') {
            Some((host, _port)) => host,
            None => without_userinfo,
        }
    }

    #[test]
    fn a_readiness_names_loopback_and_nothing_else() {
        let answers = Readiness::Answers {
            endpoint: Endpoint::loopback(4321, "/health").expect("`/health` is a safe path"),
        };
        assert_eq!(
            answers.loopback_url().as_deref(),
            Some("http://127.0.0.1:4321/health")
        );
        assert_eq!(Readiness::StaysUp.loopback_url(), None);
        assert!(Readiness::StaysUp.endpoint().is_none());
    }

    #[test]
    fn a_browser_check_reads_the_service_it_starts() {
        let check = BrowserCheckSpec::new(
            a_service_answering_on(5173),
            "/post/1",
            "the post has a title",
        )
        .expect("a service on a port and a safe path build a check");
        assert_eq!(check.loopback_url(), "http://127.0.0.1:5173/post/1");
        assert_eq!(authority_of(&check.loopback_url()), "127.0.0.1:5173");
        assert_eq!(check.path(), "/post/1");
        assert_eq!(check.expectation(), "the post has a title");
    }

    #[test]
    fn a_path_that_would_move_the_host_is_refused_rather_than_formatted() {
        // The defect this test exists for, as the string that produced it: what
        // `format!("http://127.0.0.1:{port}{path}")` had for its answer once the
        // path was a free `String`. It *looks* loopback — the address is right
        // there at the front — and it is not: the host is `evil.example`, and
        // the loopback address is userinfo. A check whose entire justification is
        // that it never leaves this machine would have left it.
        let smuggled = format!("http://127.0.0.1:{}{}", 8080, "@evil.example/");
        assert_eq!(host_of(&smuggled), "evil.example");
        assert_ne!(host_of(&smuggled), "127.0.0.1");
        // And the weaker reading really would have missed it, which is why the
        // assertion above is on the host.
        assert_eq!(authority_of(&smuggled), "127.0.0.1:8080@evil.example");

        // And the value that would have produced it cannot be built: the path
        // is refused where it enters, by the same constructor the local probe
        // uses, so no code downstream has a `@evil.example/` to format.
        assert_eq!(
            BrowserCheckSpec::new(
                a_service_answering_on(8080),
                "@evil.example/",
                "the page says something"
            ),
            Err(WorkRefusal::Endpoint(EndpointError::UnsafePath {
                path: "@evil.example/".to_owned()
            }))
        );
    }

    #[test]
    fn every_path_a_check_can_hold_keeps_the_authority_on_loopback() {
        // The control for the test above: a check that *is* built has a host,
        // and it is loopback. Without this, refusing every path would pass the
        // test above and no browser check would ever run — the shape of a fix
        // that hides a defect by removing the feature.
        for path in [
            "/",
            "/post/1",
            "/a/b?c=d",
            "/%2Fencoded",
            "/~user",
            "/@evil.example",
        ] {
            let check = BrowserCheckSpec::new(a_service_answering_on(3000), path, "something")
                .unwrap_or_else(|error| panic!("{path} must build a check: {error}"));
            assert_eq!(
                host_of(&check.loopback_url()),
                "127.0.0.1",
                "{path} moved the host off loopback"
            );
            assert_eq!(
                authority_of(&check.loopback_url()),
                "127.0.0.1:3000",
                "{path} moved the authority off loopback"
            );
            assert_eq!(check.path(), path);
        }
        // `"/@evil.example"` above is the near miss worth naming: with the
        // leading `/` it is a path on loopback that happens to contain an `@`,
        // and without it, it is the host. The character is the same; the `/` is
        // the whole difference.
    }

    #[test]
    fn the_paths_a_request_line_cannot_carry_are_the_paths_a_check_cannot_hold() {
        // Each of these is one of `probe::path_is_safe`'s three refusals or its
        // no-leading-slash rule, reached through this module's own door: a space
        // splits the request line, a CRLF adds a header, a backslash is a
        // separator on this machine and not in the request-target grammar, and
        // no leading `/` is the host confusion above.
        let a_crlf = "/a\r\nHost: evil.example";
        // The request-line hazard, as the string a free-form path would have
        // put on the wire. A request line ends at the first CRLF, so this path
        // does not lengthen the path — **it adds a header**, chosen by whatever
        // produced the string.
        let would_be_request_line = format!("GET {a_crlf} HTTP/1.1");
        assert_eq!(would_be_request_line.lines().count(), 2);
        assert!(
            would_be_request_line
                .lines()
                .nth(1)
                .is_some_and(|line| line.starts_with("Host: evil.example")),
            "the fixture no longer demonstrates a header being added"
        );
        // And that string is not on the wire, because the path never became an
        // endpoint: it is refused at the same door as every other path here.
        for path in ["health", "/a b", "/a\\b", a_crlf, "/\u{e9}", "", "//\r\n"] {
            assert!(
                matches!(
                    BrowserCheckSpec::new(a_service_answering_on(80), path, "something"),
                    Err(WorkRefusal::Endpoint(EndpointError::UnsafePath { .. }))
                ),
                "{path:?} built a browser check, and it must not"
            );
        }
    }

    #[test]
    fn a_browser_check_on_a_service_that_names_no_port_is_refused_by_name() {
        let silent = ServiceCheckSpec::new(a_spec(), Readiness::StaysUp, Duration::from_secs(5));
        assert_eq!(
            BrowserCheckSpec::new(silent, "/", "the page says something"),
            Err(WorkRefusal::ServiceNamesNoPort)
        );
        // A refusal is a value that can be printed, not a dropped `None`.
        assert!(
            WorkRefusal::ServiceNamesNoPort
                .to_string()
                .contains("never says which port"),
            "the refusal must say what was missing"
        );
    }

    #[test]
    fn a_name_that_is_not_there_is_absent_and_not_an_error() {
        let path =
            ProgramPath::from_search_path(a_directory_holding("absent", &[]).into_os_string());
        assert_eq!(path.resolve(OsStr::new("nothing-here")), Resolution::Absent);
        assert_eq!(
            path.resolve(OsStr::new("nothing-here")).program_name(),
            None
        );
    }

    #[test]
    fn a_platform_that_completes_a_bare_name_with_nothing_finds_the_name_itself() {
        // The macOS and Linux table, handed to `resolve_with` on Windows. That
        // is the whole reason `resolve_with` takes a table: the defect this
        // guards was a table that was wrong on the two platforms whose tests
        // could not run there, so a test that only ran on those two would have
        // been the same defect one layer up.
        let directory = a_directory_holding("no completion", &["npm"]);
        let search = ProgramPath::from_search_path(directory.clone().into_os_string());
        assert_eq!(
            search.resolve_with(OsStr::new("npm"), WITHOUT_PATHEXT),
            Resolution::Executable(directory.join("npm")),
            "a program that is on PATH must not be reported as absent just \
             because this platform completes a bare name with nothing"
        );
    }

    // There is deliberately no test here for the other half of the empty
    // completion — that a joined suffix would build the candidate `npm.` rather
    // than `npm` — and the reason it is absent is worth more than the test was.
    // **The fixture cannot be built on Windows.** A file created as `npm.` is
    // stored as `npm`: the Win32 layer strips trailing dots and spaces, so on
    // this machine `directory.join("npm.")` and `directory.join("npm")` name one
    // file, and a directory holding the first is a directory holding the second.
    // Measured rather than assumed: the test that asserted otherwise found
    // `…\trailing dot-6\npm` `Executable` on the first run.
    //
    // So the two implementations are indistinguishable here for *any* fixture,
    // and the distinction exists only on the platform where `npm.` is its own
    // file. What catches a joined suffix there is the test above this comment:
    // on a platform that completes a bare name with nothing, the join produces
    // `npm.`, the branch produces `npm`, and only one of those is the file the
    // fixture put on the path. **The collision the empty suffix guards against
    // is therefore reachable, and reachable nowhere the tests run** — which is
    // the same sentence as the defect it repairs, one layer along.

    #[cfg(windows)]
    #[test]
    fn a_name_with_no_extension_is_completed_the_way_windows_completes_it() {
        let directory = a_directory_holding("completed", &["thing.exe", "npm.cmd"]);
        let path = ProgramPath::from_search_path(directory.clone().into_os_string());

        match path.resolve(OsStr::new("thing")) {
            Resolution::Executable(found) => assert_eq!(found, directory.join("thing.exe")),
            other => panic!("thing.exe is on the path, so it is an executable, not {other:?}"),
        }

        match path.resolve(OsStr::new("npm")) {
            Resolution::InterpreterRequired(found) => {
                assert_eq!(found, directory.join("npm.cmd"));
                assert!(!path.resolve(OsStr::new("npm")).is_startable());
            }
            other => {
                panic!("only npm.cmd is there, so the honest answer is a script and not {other:?}")
            }
        }
    }

    #[cfg(windows)]
    #[test]
    fn a_batch_file_named_with_its_extension_is_the_file_that_was_named() {
        let directory = a_directory_holding("spelled-out", &["thing.cmd"]);
        let path = ProgramPath::from_search_path(directory.clone().into_os_string());
        assert_eq!(
            path.resolve(OsStr::new("thing.cmd")),
            Resolution::InterpreterRequired(directory.join("thing.cmd"))
        );
    }

    #[cfg(windows)]
    #[test]
    fn a_ps1_is_never_a_program_this_build_starts() {
        let directory = a_directory_holding("script", &["deploy.ps1"]);
        let path = ProgramPath::from_search_path(directory.clone().into_os_string());
        match path.resolve(OsStr::new("deploy")) {
            Resolution::InterpreterRequired(found) => {
                assert_eq!(found, directory.join("deploy.ps1"))
            }
            other => panic!("deploy.ps1 is there and is a script, not {other:?}"),
        }
        assert!(!path.resolve(OsStr::new("deploy.ps1")).is_startable());
    }

    #[cfg(windows)]
    #[test]
    fn an_explicit_extension_is_looked_for_by_that_name_and_no_other() {
        let directory = a_directory_holding("explicit", &["thing.exe"]);
        let path = ProgramPath::from_search_path(directory.into_os_string());
        assert_eq!(
            path.resolve(OsStr::new("thing.cmd")),
            Resolution::Absent,
            "a caller that named .cmd asked about .cmd, and completing it with .exe would be \
             answering a different question"
        );
    }

    #[cfg(windows)]
    #[test]
    fn the_executable_wins_when_a_machine_has_both() {
        let directory = a_directory_holding("both", &["thing.bat", "thing.exe"]);
        let path = ProgramPath::from_search_path(directory.clone().into_os_string());
        assert_eq!(
            path.resolve(OsStr::new("thing")),
            Resolution::Executable(directory.join("thing.exe"))
        );
    }

    #[test]
    fn the_directories_are_the_platforms_own_reading_of_the_variable() {
        let first = std::env::temp_dir();
        let second = std::env::temp_dir().join("sure second directory");
        let joined = std::env::join_paths([first.clone(), second.clone()]).unwrap();
        let path = ProgramPath::from_search_path(joined);
        let directories: Vec<PathBuf> = path.directories().collect();
        assert_eq!(directories, vec![first, second]);
    }

    #[test]
    fn a_machine_with_no_path_finds_nothing_rather_than_failing() {
        let path = ProgramPath::from_search_path(OsString::new());
        assert_eq!(path.resolve(OsStr::new("cargo")), Resolution::Absent);
        assert_eq!(path.directories().count(), 0);
    }

    #[cfg(windows)]
    #[test]
    fn an_empty_path_entry_does_not_become_the_current_directory() {
        let directory = a_directory_holding("planted", &["planted.exe"]);
        let planted = directory.join("planted.exe");
        assert!(planted.is_file(), "the fixture is on disk");

        let with_an_empty_entry =
            std::env::join_paths([PathBuf::from(""), directory.clone()]).unwrap();
        let path = ProgramPath::from_search_path(with_an_empty_entry);
        assert_eq!(
            path.directories().count(),
            1,
            "the empty entry means the current directory and is dropped"
        );

        // The one direct way to observe the rule from here: with the fixture's
        // own directory removed, nothing is found even though the empty entry
        // is still in the variable, so the current directory was never read.
        let only_an_empty_entry = ProgramPath::from_search_path(OsString::from(";"));
        assert_eq!(
            only_an_empty_entry.resolve(OsStr::new("planted")),
            Resolution::Absent
        );
    }
}
