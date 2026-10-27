//! The door between a plan and a process.
//!
//! [`crate::planned_work`] carries a check's executable half as named fields, and
//! [`crate::enforce`] decides which of those may run. Neither of them starts
//! anything, and both say so: `CommandSpec` has deliberately no method that turns
//! it into a runner's request, and `AdmittedCommand::new` is private so that the
//! only value carrying a "yes" is one the enforcement produced. This module is the
//! caller those two were written for. It is the first file in the product that can
//! carry a planned command to [`crate::process`], and `tests/spawn_sites.rs` is
//! the census that makes its arrival a deliberate edit rather than a quiet one.
//!
//! # What runs, and what makes that a fact about a type
//!
//! The runner's input is [`AdmittedRun`], and there is no way to build one except
//! [`AdmittedRun::new`], which demands an [`AdmittedCommand`]. That type has a
//! private constructor and is produced by exactly one function, so a check that
//! enforcement did not admit is not *unlikely* to reach the process runner — it is
//! unrepresentable, because there is no value to hand the runner and no way to
//! make one. This is decision 4 of
//! `docs/adr/0014-planned-check-execution-contract.md` stated as a signature
//! rather than as a rule for a reader.
//!
//! Pairing is not a formality either. An admitted command is two things — a
//! program and an argument vector — and so is a [`CommandSpec`], and
//! [`AdmittedRun::new`] refuses unless the check, the program and the arguments
//! all agree. Everything else a spec carries (directory, environment, limits) is
//! not part of what was decided, so it is not part of what is compared; see
//! [`crate::safety::classify`], which is the decision and takes the same two
//! things.
//!
//! # Three kinds of work, one seam, and no test in this file starts a process
//!
//! [`CheckRunner`] is the whole of the machine: a method from an admitted command
//! to a [`CommandRun`], since `P18-T009` a method from an admitted service to the
//! [`CheckResult`] it produced, and since `P18-T010` a method from an admitted
//! browser check to the [`CheckResult`] it produced. [`ProcessRunner`] is the
//! implementation that can start any of them, and it is the only one in this
//! file. Every proof below — that an unadmitted command never arrives, that one
//! check produces one result, that a check which reported nothing becomes an
//! error, that a service gets the environment the plan holds, that a page is
//! opened on the port that answered — is made with a fake that records what it
//! was asked for and answers from a value. **A test that starts a real process is
//! a test that measures this machine rather than this code**, and nothing in this
//! module's acceptance needs one: `tests/process_runner.rs` is where starting a
//! process is the subject, and `tests/runtime_start.rs` is where the window, the
//! question, the look and the stop are.
//!
//! The three methods are on one trait rather than three, and that is the same
//! argument the pipeline's own `runner` field makes: *what may this run start?* is
//! one question with one answer, and three traits would let one run hold three
//! runners that could disagree about it — a fake for commands and the real runner
//! for services, or the other way round.
//!
//! # Exactly one result per scheduled check
//!
//! Rule six of the ADR, in three parts, and this module is where two of them land.
//!
//! - **A check the mode stopped keeps the plan's own stopped result.** Asked
//!   first, of the plan, and then of the enforcement: a check the schedule
//!   decided against is not carried out whatever its operation holds, and a check
//!   the schedule allowed but whose command the mode stopped keeps the result that
//!   command's own refusal carries. Both are `Skipped` and neither can be a pass.
//! - **A check the mode admitted that produced no result becomes an `Error`.** Not
//!   a silence, not a row quietly missing from the run's list, and never a pass.
//!   This is the gap `coverage_summary.rs:75`'s `None => continue` leaves open for
//!   any caller that hands it a set that does not cover the plan: a scheduled check
//!   with no result is a check SURE said it would carry out, and the honest report
//!   of having no observation for it is that SURE's own machinery did not produce
//!   one.
//! - **Two results for one check is an internal error that stops the run**, and so
//!   is the same duplication one step earlier — two commands the enforcement
//!   admitted for one check. There is no honest rule for choosing between two
//!   answers to one question, and inventing one (first wins, least green wins)
//!   would be new run semantics living in a runner.
//!
//! [`crate::aggregation::aggregate_run`] states a rule that looks like the second
//! of those and is not the same one: a set of results that does not cover a check
//! is aggregated as `Unknown` with [`crate::aggregation::NOTHING_CAME_BACK`],
//! because a result *set* that is missing a row is not evidence about why. The two
//! are kept apart on purpose. The runner knows what it was asked to carry out and
//! says so; the aggregator knows only what it was handed, and says only that. The
//! effect of this module's rule is that the aggregator's arm is now rare rather
//! than always — which is what the ADR's consequence note says it should be.
//!
//! # A service check is carried out by the module that already ran one
//!
//! [`CheckOperation::Service`] holds a [`ServiceCheckSpec`], and there is exactly
//! one implementation of what a service check *is* in this tree: the startup
//! window, the one question, the stop on every path, and the verdict table in
//! [`crate::runtime_start`]. So this module's job for a service is pairing and
//! nothing more — the spec the schedule holds, the command the enforcement
//! admitted for that check, and [`StartSmoke::planned`], the constructor
//! `P18-T009` gave that door. A second mapping written here — start, poll, one
//! HTTP call, stop — would be a second answer to *did this service work* that
//! could disagree with the first, and the tests that hold the first are
//! `tests/runtime_start.rs`'s, over real processes.
//!
//! **What this file's tests can hold instead is the wiring**: that a service
//! check's own spec reaches the seam, that the admission is paired by check id
//! and by program and argument vector, and that nothing of the sort happens for a
//! check whose work is not a service. The window, the question and the stop are
//! `runtime_start.rs`'s and are measured there.
//!
//! **The environment is the plan's own, and that is the whole of what this file
//! decides about it.** [`AdmittedService`] carries a [`ServiceCheckSpec`] whose
//! command holds the environment, and `StartSmoke::planned` reads it — so a
//! service check is started with what the plan states rather than with whatever
//! SURE was started with. That is the same rule the command path already follows
//! in [`AdmittedRun::request`], where the spec's environment is the request's;
//! the alternative, a service that inherits SURE's environment because nobody
//! looked, is `service.rs`'s old gap and the accident this clause is about.
//!
//! # A browser check is a service check with something to do while it is up
//!
//! [`CheckOperation::Browser`] holds a [`BrowserCheckSpec`], which holds a
//! [`ServiceCheckSpec`] — and `P18-T010` opened that door by **reusing the
//! service's own lifecycle rather than writing a second one**. The window, the
//! readiness question, the stop on every path and the verdict table are
//! [`crate::runtime_start`]'s and are not restated here; what a browser check adds
//! is one look, taken between the answer and the stop, and
//! [`crate::runtime_start::StartSmoke::run_then`] is the caller's own step that
//! exists for it.
//!
//! **The look is gated on the service answering, and the gate is the answer
//! rather than the verdict.** [`StartSmoke::run_then`] calls the step only when
//! the readiness question came back as an answer — any status, including a 404 —
//! because a project whose readiness path is `/health` and whose page is at
//! `/post/1` is the ordinary shape (see `planned_work.rs`'s own fixture), and a
//! service that answered *something* is a service whose page can be opened. A
//! service that was never reached produces no look at all, which is what clause
//! one of `P18-T010` says.
//!
//! **The stop happens whether the look passed, failed or panicked**, and that is
//! [`crate::runtime_start`]'s property rather than this module's to restate:
//! `run_then` takes the same `?`-free path to the stop that `run` does, and the
//! `Drop` on the service's own stopper covers the panic. What this module decides
//! is only *what to look at and with what*.
//!
//! **The driver is held, not built.** [`ProcessRunner`] holds a
//! [`browser::Driver`] — an alias for the interface, declared in
//! [`crate::browser`] so that this file names a name rather than the adapter —
//! and a runner that was given none answers a browser check with an `Error`
//! saying so. That is deliberate and it is the property to keep: **un-wiring the
//! driver turns a browser check into a failure of SURE's own check, never into a
//! pass and never into a skip.** The file that constructs a driver is
//! `sure-cli/src/check.rs`, the composition root where `sure check` binds every
//! implementation it uses; nothing in this crate builds one.
//!
//! # What this module does not do
//!
//! **It does not decide what may run.** Every "yes" comes from
//! [`Enforcement::admitted`], and a caller holding every command the plan
//! considered has nothing it can do with them here.
//!
//! **It decides no verdict for a browser.** A driver reports what the page did
//! and [`crate::browser::Report::verdict`] says what that is worth; this file
//! calls the second on the first and adds nothing. A browser check whose driver
//! was absent is the one exception, and it is an `Error` for the reason above
//! rather than a verdict about the project.
//!
//! **It builds no command line.** The one translation here is field for field, and
//! an argument holding a space is one argument before it and one argument after it.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fmt;
use std::time::Duration;

use sure_domain::ids::{CheckId, FingerprintId};
use sure_domain::status::CheckResult;

use crate::browser;
use crate::enforce::{AdmittedCommand, Enforcement};
use crate::package_launcher::PackageLaunchers;
use crate::planned_work::{
    BrowserCheckSpec, CheckOperation, CommandRun, CommandSpec, ServiceCheckSpec,
};
use crate::probe;
use crate::process::{self, Cancellation, ProcessRequest};
use crate::runtime_start::{LimitsError, StartSmoke};
use crate::schedule::{CheckSchedule, ScheduledCheck};

/// What SURE says about a check the mode admitted that produced no result.
///
/// **An `Error`, and the reason it is not a silence is the whole of clause two.**
/// A check the mode admitted is a check SURE said it would carry out; a runner
/// that comes back with nothing for it has not observed anything, and the honest
/// report of that is that SURE's own machinery did not produce the observation the
/// plan promised. It is not `Unknown` and it is not a skip: `Unknown` belongs to
/// [`crate::aggregation::NOTHING_CAME_BACK`], where a *set* of results does not
/// cover a check and nothing is known about why, and a skip is a decision somebody
/// made. This is neither — it is an answer SURE owes and does not have.
///
/// A `Warning` would be worse than either: `CriticalState::from_status` maps
/// `Warning` to `Passed`, so a warning on a critical check blocks nothing at all.
const NOTHING_WAS_REPORTED: &str = "SURE admitted this check and the runner reported nothing for \
                                    it, so nothing about it was observed.";

/// The one seam at which admitted work becomes a process.
///
/// **A trait rather than a function**, for one reason that matters and one that
/// follows from it. The reason that matters: an acceptance about *what may run*
/// has to be provable without running anything, and a seam is what lets the proof
/// be made with a value that records what it was asked for. The one that follows:
/// the interface a fake has to satisfy is three methods wide, so a fake cannot
/// agree with the real runner on everything except the thing being tested.
///
/// Every method takes a value only an [`Enforcement`] can produce — [`AdmittedRun`]
/// for a command, [`AdmittedService`] for a service, [`AdmittedBrowser`] for a
/// browser check — which is what makes "work the mode did not admit cannot reach
/// a process" a property of the signature rather than a promise in a comment.
/// None is a defaulted method: an implementation that had not decided what to do
/// with a service or a browser would otherwise compile, and *has not decided* is
/// exactly the state clause one of `P18-T009` and clause one of `P18-T010` are
/// about.
///
/// **The three answers have different shapes on purpose.** A command's run is a
/// [`CommandRun`] because *the process ran, and this is what it said* and *the
/// process never started, and this is why* are two states with one mapping to a
/// result ([`CommandRun::to_result`]). A service's run is already a
/// [`CheckResult`], because [`StartSmoke::run`] produces one: the window, the
/// question and the stop are one indivisible row of a verdict table, and a
/// wrapper type here would only be a place for this module to reshape that table.
/// A browser check's run is a [`CheckResult`] for the same reason and one more:
/// its lifecycle *is* the service's — the same `run_then`, with a look in the
/// middle — so a separate shape for it would be this module claiming to own a
/// lifecycle it deliberately borrowed.
///
/// **[`fmt::Debug`] is a supertrait, and the reason is one field rather than this
/// module.** `Pipeline` holds a `&dyn CheckRunner` — a run is built with the
/// runner it will use, so that a caller answering "what may this run start?" is
/// answering it at the place the run is described — and `Pipeline` prints itself
/// when a test fails, so the runner it holds has to be printable. Nothing about
/// running a command needs this; what needs it is a runner being part of a value a
/// person reads.
pub trait CheckRunner: fmt::Debug {
    /// Carry out one admitted command and report what came of it.
    ///
    /// [`CommandRun`] rather than a `Result`, because the runner's two answers —
    /// *the process ran, and this is what it said* and *the process never started,
    /// and this is why* — are one question about one check, and
    /// [`CommandRun::to_result`] is where the answer is read.
    fn run(&self, work: &AdmittedRun<'_>) -> CommandRun;

    /// Start one admitted service, ask it its one question, stop it, and report
    /// what came of all three.
    ///
    /// **[`CheckResult`] rather than a `Result`, and that is
    /// [`StartSmoke::run`]'s own rule** — every way a service check can go wrong
    /// is a state the check has to report, and a caller that had to handle an
    /// `Err` here would be deciding what to tell somebody about a check that did
    /// not happen. An implementation is expected to route this to
    /// [`StartSmoke::run`], which stops the service on every path.
    fn run_service(&self, work: &AdmittedService<'_>) -> CheckResult;

    /// Start one admitted service, open the page it serves once it answers, stop
    /// the service, and report what came of all three.
    ///
    /// **[`AdmittedService`]'s argument one door along, and the difference is the
    /// one thing a browser check adds**: the service is the same service, and the
    /// look happens between the answer and the stop. An implementation is
    /// expected to route this to
    /// [`StartSmoke::run_then`](crate::runtime_start::StartSmoke::run_then) with
    /// a step that asks its driver, which is what makes the window, the question,
    /// the stop and the verdict table one lifecycle rather than two.
    ///
    /// **A [`CheckResult`] rather than a `Result`**, for [`Self::run_service`]'s
    /// reason: a browser check that could not be carried out is a state the check
    /// has to report, and a caller handling an `Err` here would be deciding what
    /// to say about a check that did not happen.
    fn run_browser(&self, work: &AdmittedBrowser<'_>) -> CheckResult;
}

/// The runner that starts a real process and drives a real browser.
///
/// The only implementation in the product that can, and it is reached from
/// [`run_scheduled_checks`] by whoever the pipeline hands it to.
///
/// **The driver is a field rather than a constructor argument, and a runner
/// without one is a state that exists on purpose.** Four callers in this tree
/// build a runner to prove that a run starts nothing — they cancel the token
/// before the run and never hand it a browser — and a constructor that demanded
/// a driver would make those callers write `with_page_driver` they do not
/// mean, or build one to throw away. [`Self::new`] leaves the field empty and
/// [`Self::with_page_driver`] fills it, and the empty state is *answered*
/// rather than assumed away: see the browser arm of this type's [`CheckRunner`]
/// implementation.
///
/// **It is not `Clone`, and that is new.** A runner could be copied before
/// `P18-T010` because both of its fields were; a boxed driver cannot be, and
/// inventing a way to copy one — a `clone_box` method on the interface, say —
/// would be an interface change made to serve a struct's derive. Nothing in the
/// product copies a runner: a run is built with `&dyn CheckRunner` and the runner
/// outlives it. What the removal does mean is that a caller who wants two runners
/// makes two, which is also the only way to get two different drivers.
pub struct ProcessRunner {
    /// The handle a caller cancels a run through. Held rather than made per call,
    /// so that the caller keeps the other clone and cancelling it reaches every
    /// request the runner makes.
    cancellation: Cancellation,
    /// The driver a browser check is carried out with, or `None` for a run that
    /// was not given one. Held as the interface's own alias rather than as the
    /// adapter, so that this file names what it was handed and not what built it.
    driver: Option<browser::Driver>,
    /// How a package manager installed as a Windows batch shim is started
    /// (npm's own JavaScript entry through `node`), or `None` for a run that
    /// starts exactly what the plan names. See [`crate::package_launcher`].
    launchers: Option<PackageLaunchers>,
}

/// Written by hand because [`browser::Driver`] is a `Box<dyn …>` and a boxed
/// trait object is not `Debug`, and because what a person reading a failed test
/// needs from this field is **whether there is a driver**, not what is inside it.
/// Printing the absence is the whole of the useful answer, and printing
/// `Some(<dyn BrowserDriver>)` would be noise that a reader would learn to skip.
///
/// It is not a convenience: [`CheckRunner`] requires [`fmt::Debug`] because a
/// `Pipeline` holds one and prints itself when a test fails, so a runner that
/// could not be printed could not be handed to a pipeline at all.
impl fmt::Debug for ProcessRunner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProcessRunner")
            .field("cancellation", &self.cancellation)
            .field(
                "driver",
                &match self.driver {
                    Some(_) => "a browser driver",
                    None => "no browser driver",
                },
            )
            .field(
                "launchers",
                &match self.launchers {
                    Some(_) => "package-manager launchers",
                    None => "no package-manager launchers",
                },
            )
            .finish()
    }
}

impl ProcessRunner {
    /// A runner whose runs are cancelled through `cancellation` and which has no
    /// browser driver.
    ///
    /// **A browser check handed to this runner is an `Error` and never a pass**,
    /// which is the honest answer for a run nobody gave the means to carry one
    /// out. [`Self::with_page_driver`] is the way to give it one.
    #[must_use]
    pub fn new(cancellation: Cancellation) -> Self {
        Self {
            cancellation,
            driver: None,
            launchers: None,
        }
    }

    /// The same runner, carrying `driver` for any page it is asked to open.
    ///
    /// The name is the whole of what this file knows about a driver: what the
    /// type is, where it comes from and what it does are [`crate::browser`]'s and
    /// `sure-cli/src/check.rs`'s, and this function only puts it in the field.
    ///
    /// **`with_page_driver` and not `with_browser_…`, and the name is a
    /// decision rather than a style.** `tests/browser_probe.rs` refuses a shipped
    /// file outside the adapter that names the adapter, and it is right to: a
    /// file that spells the module is a file that can construct one and start a
    /// browser. This file must be able to *hold* a driver and must not be able to
    /// *make* one, and the way it says so is by naming the page it opens and the
    /// value it was handed — `browser::Driver`, the alias
    /// [`crate::browser`] declares for exactly this — rather than the module that
    /// builds one. The capability is real and is declared where it belongs:
    /// `sure-cli/src/check.rs` is the composition root that constructs a driver,
    /// and that is the one line a reader should follow.
    #[must_use]
    pub fn with_page_driver(mut self, driver: browser::Driver) -> Self {
        self.driver = Some(driver);
        self
    }

    /// The same runner, translating a package manager installed as a Windows
    /// batch shim into `node` and the JavaScript entry npm ships.
    ///
    /// **Bound at the composition root, like the browser driver.** A runner
    /// without this starts exactly what the plan names; the product path
    /// (`sure-cli/src/check.rs`) gives it the machine's `PATH` so that
    /// `npm run test` is a run rather than a not-found error on Windows. See
    /// [`crate::package_launcher`] for what is translated and what is left
    /// alone.
    #[must_use]
    pub fn with_package_launchers(mut self, launchers: PackageLaunchers) -> Self {
        self.launchers = Some(launchers);
        self
    }

    /// The handle this runner's requests carry.
    #[must_use]
    pub const fn cancellation(&self) -> &Cancellation {
        &self.cancellation
    }
}

impl CheckRunner for ProcessRunner {
    fn run(&self, work: &AdmittedRun<'_>) -> CommandRun {
        // One call, and the conversion is `CommandRun`'s own: `process::run`
        // returns exactly the `Result` that `From` is written for, so the step
        // from the machinery to the check's result is not a reshape written here.
        // The launchers, when bound, resolve a batch shim to the program the
        // shim itself runs; the plan's arguments are passed through unchanged.
        process::run(&work.request_with_launchers(&self.cancellation, self.launchers.as_ref()))
            .into()
    }

    fn run_service(&self, work: &AdmittedService<'_>) -> CheckResult {
        match StartSmoke::planned(
            work.admitted(),
            work.service(),
            work.fingerprint(),
            ONE_EXCHANGE,
        ) {
            // The verdict table is `runtime_start`'s and is not touched here: the
            // window, the question, the stop and the mapping from what happened
            // to a status all belong to that module, and this call is the whole
            // of what `P18-T009` had to add to reach it.
            Ok(smoke) => smoke.run(&self.cancellation),
            // The plan's own numbers cannot be run — a window of zero, or one
            // that cannot close before the command's budget runs out. Nothing was
            // started, and this is an `Error` for the same reason
            // `NOTHING_WAS_REPORTED` is: SURE said it would carry this check out.
            Err(error) => service_refused(work, &error),
        }
    }

    /// The whole of what a browser check costs this runner.
    ///
    /// **The absence is answered first, and it is answered with an `Error`.**
    /// Before `P18-T010` a browser check that reached the run was reported as
    /// *this build has no runner for this*; the sentence changes and the status
    /// does not, because the property that mattered then is the property that
    /// matters now — **a browser check that nothing carries out is a failure of
    /// SURE's own check, never a pass and never a skip.** Un-wiring the driver at
    /// the composition root has to be a run that says so.
    ///
    /// **The look is taken inside the service's own lifecycle**, through
    /// [`StartSmoke::run_then`], and the step comes back `None` on every path
    /// where the service never answered. That is clause one of `P18-T010` written
    /// as a type rather than as a rule: the step is handed *the endpoint that
    /// answered*, and there is nothing to look at when nothing did.
    ///
    /// **The page is opened on the address that answered, and the path is the
    /// plan's.** [`BrowserCheckSpec`] deliberately lets the page's path differ
    /// from the readiness path — a service whose health route is `/health` serves
    /// its pages somewhere else — so the two halves come from two places and both
    /// are the plan's: the host and port from the endpoint SURE has just read a
    /// status line from, the path from the spec. **A browser check never opens an
    /// address SURE did not reach**, which is the difference between this and
    /// trusting a URL a plan carries.
    ///
    /// **The check's result is the page's verdict, and the service's own line is
    /// kept in front of it.** The two answer different questions — *did the
    /// service come up and answer* and *what did its page do* — and neither is
    /// discarded: the page's verdict is the check's status, because the page is
    /// what the check is about, and the service's own sentence stays in the
    /// reason so a reader can see what SURE started, what it asked, and that it
    /// stopped it. A service whose readiness route answers 500 and whose page is
    /// clean is a project whose two answers disagree; the status says what the
    /// page did and the reason line says the rest.
    ///
    /// **When no look happened, the service's own verdict is the check's
    /// result**, and that is not a fallback: nothing about the page was observed,
    /// and the service's own words for why are the only honest answer there is.
    /// [`crate::runtime_start`] produces that result, this file does not reshape
    /// it, and its statuses are the same ones a service check gets.
    fn run_browser(&self, work: &AdmittedBrowser<'_>) -> CheckResult {
        let Some(driver) = self.driver.as_ref() else {
            return no_driver_result(work);
        };
        // Built before anything starts, so that a number a reader can see being
        // wrong is an `Error` about the plan rather than a failed look.
        let limits = match browser::Limits::new(LOOK_BUDGET, LOOK_PROBLEMS) {
            Ok(limits) => limits,
            Err(error) => return browser_refused(work, "the budget for the look", &error),
        };
        let spec = work.browser();
        let page = spec.path();
        match StartSmoke::planned(
            work.admitted(),
            spec.service(),
            work.fingerprint(),
            ONE_EXCHANGE,
        ) {
            Ok(smoke) => {
                let (service, looked) = smoke.run_then(&self.cancellation, |endpoint| {
                    let address = endpoint.address();
                    // The same constructor `BrowserCheckSpec::new` used, so a path
                    // it accepted is a path this accepts; the `Err` arm below is
                    // therefore about a port the readiness question answered on
                    // and not about the path the plan holds.
                    browser::Target::at(address.ip(), address.port(), page).map(|target| {
                        let report = driver.observe(&target, &limits, &self.cancellation);
                        (target, report)
                    })
                });
                match looked {
                    Some(Ok((target, report))) => {
                        let check = work.admitted().command().check();
                        let page_reason = report.reason();
                        let verdict = report.verdict(
                            check.id().clone(),
                            &target,
                            check.severity(),
                            check.critical(),
                            work.fingerprint().clone(),
                        );
                        verdict.with_reason(format!(
                            "{}; and the page it serves: {page_reason}",
                            service.reason
                        ))
                    }
                    // Unreachable in the product: the address is the one the
                    // readiness question was answered from, so it is loopback,
                    // and the path is one `Endpoint::loopback` already accepted
                    // when the plan was built. Written out rather than `expect`ed
                    // because a run does not abort on a state this file cannot
                    // produce, and because an error naming it is how a reader
                    // finds out that it happened after all.
                    Some(Err(error)) => browser_refused(work, "the address of the page", &error),
                    // The service never answered, so there was no page to open:
                    // the service's own result is what happened, whole.
                    None => service,
                }
            }
            Err(error) => browser_refused(work, "the window the service is held to", &error),
        }
    }
}

/// The bounds on the one look a planned browser check is allowed to take.
///
/// **The second budget the plan does not hold, and its argument is
/// [`ONE_EXCHANGE`]'s.** A [`BrowserCheckSpec`] carries the service's window and
/// the command's whole-life deadline; neither bounds the page, and
/// [`browser::Limits`] is a decision rather than a default. The numbers are here,
/// where a reader can disagree with them.
///
/// **Thirty seconds, and it is shaped after the browser rather than after the
/// probe.** [`ONE_EXCHANGE`] is half a second because a request to a process SURE
/// is already watching on loopback either answers at once or has not answered; a
/// page is a browser starting, navigating, running a script and settling, and a
/// budget that only a fast machine could meet would report `unknown` on the
/// machines where a project most needs the check. **It is not a licence to wait**:
/// the number is a ceiling on one look, the run's own cancellation and the
/// service's window both bound it from outside, and a look that runs out reports
/// that it stopped early rather than that the page was clean.
///
/// **Sixty-four problems kept**, because the reason line quotes three of them and
/// counts the rest ([`browser::QUOTED_PROBLEMS`]), and a bound large enough to
/// hold a page that throws in a loop is a bound the report cannot render. The
/// number is the count, not the quote.
const LOOK_BUDGET: Duration = Duration::from_secs(30);
/// See [`LOOK_BUDGET`].
const LOOK_PROBLEMS: usize = 64;

/// The bounds on the one exchange a planned service check is allowed to make.
///
/// **The one budget the plan does not hold.** A [`ServiceCheckSpec`] carries the
/// window and the command's whole-life deadline; neither bounds a request, and
/// [`probe::Limits`] is a decision rather than a default — *"a caller that does
/// not choose a bound has not decided what the check is allowed to cost"* — so
/// the caller is here, in the machinery, and the number is written down where a
/// reader can disagree with it.
///
/// Half a second, because the exchange is a request to a process SURE is watching
/// on loopback and a service that needs longer than that to answer one question
/// has not answered it; 64 KiB, because the answer is a header line and whatever
/// body came with it before the reader stopped, and a check that read more of a
/// project's page than this would be reading the page rather than the fact that
/// it was served.
const ONE_EXCHANGE: probe::Limits = probe::Limits::new(Duration::from_millis(500), 64 * 1024);

/// One scheduled check's command, paired with the admission that lets it run.
///
/// **The only value [`CheckRunner::run`] can be handed**, and it cannot be built
/// without an [`AdmittedCommand`] — a type with a private constructor that exactly
/// one function produces. That is what makes *unadmitted work cannot reach a
/// process* a fact about the type system rather than a rule about how callers
/// ought to behave. [`AdmittedService`] is the same argument for the other door.
///
/// It holds the [`CommandSpec`] as well as the admission because the admission is
/// not the whole of the work: the enforcement decided about a program and an
/// argument vector, and the directory, the environment policy and the deadline
/// live in the spec. Pairing the two is what lets the request be built field for
/// field from the plan's own value, with nothing reconstructed in between.
#[derive(Debug, Clone, Copy)]
pub struct AdmittedRun<'a> {
    admitted: AdmittedCommand<'a>,
    spec: &'a CommandSpec,
}

impl<'a> AdmittedRun<'a> {
    /// Pair a scheduled check's work with the command the enforcement admitted
    /// for it.
    ///
    /// # Errors
    ///
    /// [`AdmissionRefused`] when the two cannot be the same command: when the
    /// check's work is not one command, when the admitted command belongs to a
    /// different check, or when the program or the argument vector differs from
    /// the one the plan holds. **The argument vector is compared element by
    /// element and never compared as text**, because two commands whose rendered
    /// lines are equal are not necessarily the same command and the admission was
    /// a decision about the elements.
    pub fn new(
        scheduled: &'a ScheduledCheck,
        admitted: AdmittedCommand<'a>,
    ) -> Result<Self, AdmissionRefused> {
        let proposal = scheduled.proposal();
        let id = proposal.id();
        let CheckOperation::Command(spec) = scheduled.operation() else {
            return Err(AdmissionRefused::NotOneCommand {
                id: id.clone(),
                work: scheduled.operation().plain_description(),
            });
        };

        let command = admitted.command();
        if command.check().id() != id {
            return Err(AdmissionRefused::ForADifferentCheck {
                id: id.clone(),
                admitted_for: command.check().id().clone(),
            });
        }
        if command.program() != spec.program() || command.arguments() != spec.arguments() {
            return Err(AdmissionRefused::NotTheCommandThatWasAdmitted {
                id: id.clone(),
                planned: display_of(spec),
                admitted: command.display(),
            });
        }

        Ok(Self { admitted, spec })
    }

    /// The check this command belongs to.
    #[must_use]
    pub fn check(&self) -> &'a CheckId {
        self.admitted.command().check().id()
    }

    /// The command as the plan holds it: program, arguments, directory,
    /// environment and limits.
    #[must_use]
    pub const fn command(&self) -> &'a CommandSpec {
        self.spec
    }

    /// The request [`crate::process::run`] is given, built field for field.
    ///
    /// The program, the working directory, the deadline and the output bound are
    /// the spec's own values, handed over unchanged; the argument vector is the
    /// spec's vector, handed over whole. **Nothing here is rendered, joined,
    /// split, quoted or re-parsed** — an argument holding a space is one element
    /// on both sides of this call — and `cancellation` is the only thing this
    /// function adds, because a request requires one and a spec has no business
    /// holding a handle to a caller's decision to stop.
    ///
    /// Public because the translation is the part of this module most likely to be
    /// got subtly wrong, and a test that can hold the request can compare it
    /// against the spec it came from without starting anything.
    #[must_use]
    pub fn request(&self, cancellation: &Cancellation) -> ProcessRequest {
        self.request_with_launchers(cancellation, None)
    }

    /// The same request, with batch-shim package managers translated to the
    /// program the shim runs (`node` and npm's own JavaScript entry).
    ///
    /// **Only the program and the front of the argument vector can change.** The
    /// plan's own arguments follow the entry unchanged, the working directory,
    /// limits and environment are still the spec's, and a runner given no
    /// launchers produces exactly [`Self::request`]. See
    /// [`crate::package_launcher`] for what is and is not translated.
    #[must_use]
    pub fn request_with_launchers(
        &self,
        cancellation: &Cancellation,
        launchers: Option<&crate::package_launcher::PackageLaunchers>,
    ) -> ProcessRequest {
        let mut program: OsString = self.spec.program().to_os_string();
        let mut arguments: Vec<OsString> = self.spec.arguments().to_vec();
        if let Some(launchers) = launchers
            && let Some(launch) =
                launchers.resolve(&program, &arguments, self.spec.working_directory())
        {
            program = launch.program.into_os_string();
            arguments = launch.arguments;
        }
        ProcessRequest::new(
            program,
            self.spec.working_directory(),
            self.spec.limits(),
            cancellation.clone(),
        )
        .with_arguments(arguments)
        .with_environment(self.spec.environment().clone())
    }
}

/// One scheduled check's service, paired with the admission that lets it start.
///
/// **The only value [`CheckRunner::run_service`] can be handed**, and it cannot be
/// built without an [`AdmittedCommand`] for the same reason [`AdmittedRun`] cannot:
/// the type a runner is given is the type the enforcement produced, so *a service
/// the mode did not admit cannot be started* is a fact about the type system
/// rather than a rule for callers.
///
/// It holds the [`ServiceCheckSpec`] as well as the admission for the reason
/// [`AdmittedRun`] does: the admission decided a program and an argument vector,
/// and the window, the readiness, the directory and **the environment** live in
/// the spec. That last one is clause one of `P18-T009` — the environment a service
/// is given is the plan's own field and not a default discovered in the runner.
///
/// The fingerprint travels with it because the result a service produces is built
/// by [`crate::runtime_start`], which needs the fingerprint of the run it belongs
/// to; every other result in this module is built from the schedule's proposal and
/// takes the same value from the caller.
#[derive(Debug, Clone, Copy)]
pub struct AdmittedService<'a> {
    admitted: AdmittedCommand<'a>,
    spec: &'a ServiceCheckSpec,
    fingerprint: &'a FingerprintId,
}

impl<'a> AdmittedService<'a> {
    /// Pair a scheduled check's service with the command the enforcement admitted
    /// for it.
    ///
    /// **The same three refusals [`AdmittedRun::new`] makes, and for the same
    /// reasons** — the work is not the kind this door carries, the admission
    /// belongs to another check, or the admission covers a different command —
    /// plus the same rule about the argument vector: compared element by element
    /// and never as text. What the admission decided about is the *program and the
    /// arguments of the service's own command*, so that is what is compared, and
    /// the refusal names the pair the way a person reads it.
    ///
    /// # Errors
    ///
    /// [`AdmissionRefused`], for the reasons on that type.
    pub fn new(
        scheduled: &'a ScheduledCheck,
        admitted: AdmittedCommand<'a>,
        project_fingerprint: &'a FingerprintId,
    ) -> Result<Self, AdmissionRefused> {
        let proposal = scheduled.proposal();
        let id = proposal.id();
        let CheckOperation::Service(spec) = scheduled.operation() else {
            return Err(AdmissionRefused::NotOneService {
                id: id.clone(),
                work: scheduled.operation().plain_description(),
            });
        };

        let command = admitted.command();
        if command.check().id() != id {
            return Err(AdmissionRefused::ForADifferentCheck {
                id: id.clone(),
                admitted_for: command.check().id().clone(),
            });
        }
        let service_command = spec.command();
        if command.program() != service_command.program()
            || command.arguments() != service_command.arguments()
        {
            return Err(AdmissionRefused::NotTheCommandThatWasAdmitted {
                id: id.clone(),
                planned: display_of(service_command),
                admitted: command.display(),
            });
        }

        Ok(Self {
            admitted,
            spec,
            fingerprint: project_fingerprint,
        })
    }

    /// The check this service belongs to.
    #[must_use]
    pub fn check(&self) -> &'a CheckId {
        self.admitted.command().check().id()
    }

    /// The service as the plan holds it: the command that starts it, what counts
    /// as ready, and the window.
    #[must_use]
    pub const fn service(&self) -> &'a ServiceCheckSpec {
        self.spec
    }

    /// The admission that lets it start, for the one caller that needs to hand it
    /// to [`crate::runtime_start`].
    ///
    /// Public because the seam's own production implementation is in this file and
    /// a caller writing another one needs exactly this — and because an
    /// [`AdmittedCommand`] is a value the enforcement produced, so handing it on
    /// is not a way round the enforcement.
    #[must_use]
    pub const fn admitted(&self) -> AdmittedCommand<'a> {
        self.admitted
    }

    /// The fingerprint of the run this check is part of.
    #[must_use]
    pub const fn fingerprint(&self) -> &'a FingerprintId {
        self.fingerprint
    }
}

/// One scheduled check's browser page and the service under it, paired with the
/// admission that lets that service start.
///
/// **The same argument as [`AdmittedService`], and the same value underneath.**
/// A browser check holds a [`BrowserCheckSpec`], which holds a
/// [`ServiceCheckSpec`], and the command the enforcement decided about is the
/// one that starts that service. So the pairing compares exactly what
/// [`AdmittedService::new`] compares — the check, the program and the argument
/// vector of the service's own command — and what the browser half adds is the
/// page: a path and an expectation, neither of which is a program and neither of
/// which the enforcement has anything to say about.
///
/// **This is why a browser check needs no permission of its own here.** The
/// question the enforcement answers is *may this run start that program*;
/// opening a page on the service that program just answered from adds no process
/// and no address SURE did not already reach. The browser's own permission —
/// [`ActionKind::BrowserProbe`](sure_domain::execution::ActionKind::BrowserProbe)
/// needing `ConnectService` — is decided before a plan exists, by
/// [`crate::browser::absence`], and a check that reached this door has already
/// passed it.
///
/// The fingerprint travels with it for [`AdmittedService`]'s reason: the result
/// is built by [`crate::browser`] and needs the fingerprint of the run it belongs
/// to.
#[derive(Debug, Clone, Copy)]
pub struct AdmittedBrowser<'a> {
    admitted: AdmittedCommand<'a>,
    spec: &'a BrowserCheckSpec,
    fingerprint: &'a FingerprintId,
    /// What this kind of work is, in the words a report uses for it, kept from
    /// the scheduled check so that a result built where the schedule is no longer
    /// in hand can still name what SURE could not do. It is
    /// [`CheckOperation::plain_description`]'s sentence and not a second copy of
    /// it — the copy here would be a sentence that could drift.
    work: &'static str,
}

impl<'a> AdmittedBrowser<'a> {
    /// Pair a scheduled check's page and service with the command the enforcement
    /// admitted for it.
    ///
    /// **The same three refusals the other two doors make, and the same rule
    /// about the argument vector**: the work is not a browser check, the
    /// admission belongs to another check, or the admission covers a different
    /// program or argument vector — compared element by element and never as
    /// text.
    ///
    /// # Errors
    ///
    /// [`AdmissionRefused`], for the reasons on that type.
    pub fn new(
        scheduled: &'a ScheduledCheck,
        admitted: AdmittedCommand<'a>,
        project_fingerprint: &'a FingerprintId,
    ) -> Result<Self, AdmissionRefused> {
        let proposal = scheduled.proposal();
        let id = proposal.id();
        let CheckOperation::Browser(spec) = scheduled.operation() else {
            return Err(AdmissionRefused::NotOneBrowser {
                id: id.clone(),
                work: scheduled.operation().plain_description(),
            });
        };

        let command = admitted.command();
        if command.check().id() != id {
            return Err(AdmissionRefused::ForADifferentCheck {
                id: id.clone(),
                admitted_for: command.check().id().clone(),
            });
        }
        let service_command = spec.service().command();
        if command.program() != service_command.program()
            || command.arguments() != service_command.arguments()
        {
            return Err(AdmissionRefused::NotTheCommandThatWasAdmitted {
                id: id.clone(),
                planned: display_of(service_command),
                admitted: command.display(),
            });
        }

        Ok(Self {
            admitted,
            spec,
            fingerprint: project_fingerprint,
            work: scheduled.operation().plain_description(),
        })
    }

    /// The check this page belongs to.
    #[must_use]
    pub fn check(&self) -> &'a CheckId {
        self.admitted.command().check().id()
    }

    /// What this kind of work is, in the words a report uses for it.
    #[must_use]
    pub const fn work_description(&self) -> &'static str {
        self.work
    }

    /// The page and the service under it, as the plan holds them.
    #[must_use]
    pub const fn browser(&self) -> &'a BrowserCheckSpec {
        self.spec
    }

    /// The admission that lets the service start, for the one caller that needs
    /// to hand it to [`crate::runtime_start`].
    #[must_use]
    pub const fn admitted(&self) -> AdmittedCommand<'a> {
        self.admitted
    }

    /// The fingerprint of the run this check is part of.
    #[must_use]
    pub const fn fingerprint(&self) -> &'a FingerprintId {
        self.fingerprint
    }
}

/// Why an admitted command could not be paired with a scheduled check's work.
///
/// Five variants, and each is refused rather than repaired: three about the kind
/// of work — one per door, because a command, a service and a browser check are
/// paired by three constructors and each has to refuse the others' checks — and
/// two about the admission itself, which all three doors make. Repairing any of
/// them would mean SURE running something the plan did not hold or something
/// nobody admitted, and the second of those is the whole point of the type the
/// pair is built from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmissionRefused {
    /// The check's work is not one command, so there is no command for the
    /// admission to be about.
    NotOneCommand {
        /// The check that was paired.
        id: CheckId,
        /// What the check's work is, in the words a report uses for it.
        work: &'static str,
    },
    /// The check's work is not a service, so there is no service for the
    /// admission to be about.
    NotOneService {
        /// The check that was paired.
        id: CheckId,
        /// What the check's work is, in the words a report uses for it.
        work: &'static str,
    },
    /// The check's work is not a browser check, so there is no page and no
    /// service under it for the admission to be about.
    NotOneBrowser {
        /// The check that was paired.
        id: CheckId,
        /// What the check's work is, in the words a report uses for it.
        work: &'static str,
    },
    /// The admitted command belongs to another check.
    ForADifferentCheck {
        /// The check whose work was handed in.
        id: CheckId,
        /// The check the admitted command actually belongs to.
        admitted_for: CheckId,
    },
    /// The admission covers a different program or a different argument vector.
    NotTheCommandThatWasAdmitted {
        /// The check both commands claim.
        id: CheckId,
        /// The command the plan holds for it, as a person reads it.
        planned: String,
        /// The command the enforcement admitted for it, as a person reads it.
        admitted: String,
    },
}

impl fmt::Display for AdmissionRefused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotOneCommand { id, work } => write!(
                f,
                "the check {id} would be carried out as {work}, and an admission can only be \
                 paired with a check whose work is one command"
            ),
            Self::NotOneService { id, work } => write!(
                f,
                "the check {id} would be carried out as {work}, and an admission can only be \
                 paired with a check whose work is a service"
            ),
            Self::NotOneBrowser { id, work } => write!(
                f,
                "the check {id} would be carried out as {work}, and an admission can only be \
                 paired with a check that opens a page on a service it starts"
            ),
            Self::ForADifferentCheck { id, admitted_for } => write!(
                f,
                "the command the enforcement admitted belongs to the check {admitted_for}, and it \
                 was paired with the check {id}"
            ),
            Self::NotTheCommandThatWasAdmitted {
                id,
                planned,
                admitted,
            } => write!(
                f,
                "the admission covers `{admitted}` and the plan holds `{planned}` for the check \
                 {id}, so the command SURE would start is not the command it decided about"
            ),
        }
    }
}

impl std::error::Error for AdmissionRefused {}

/// A refusal that stops the run.
///
/// Each of these is a run SURE cannot report on honestly, and none is repaired:
/// choosing between two commands, or between two results, would make the run
/// depend on a rule nobody wrote down, and dropping a result the schedule does not
/// hold would be the silent loss this repository treats as worse than an error.
/// [`crate::aggregation::RunRefused`] is the same idea one layer up, about the
/// verdict rather than about the run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunnerRefused {
    /// The enforcement admitted more than one command for one check.
    ///
    /// A check is one command — [`CheckOperation::Command`] holds one spec, and
    /// `ScheduledCheck::plain_description` says "one command, once, under a
    /// deadline" — so a second admitted command is the plan and the enforcement
    /// disagreeing about what the check is. **Refused before anything is carried
    /// out**, so no work starts under a plan this runner has just found
    /// unreadable. A future check that is genuinely several commands needs a
    /// vocabulary for that, and this refusal is the thing that will have to move.
    MoreThanOneCommandForACheck {
        /// The check that was given two commands.
        id: CheckId,
    },
    /// Two results were produced for one check.
    TwoResultsForOneCheck {
        /// The check that was answered twice.
        id: CheckId,
    },
    /// A result was handed in for a check the schedule does not hold.
    ///
    /// Reported rather than absorbed. [`crate::aggregation::RunReport`] can carry
    /// such a result to a caller as an anomaly, because a verdict is computed over
    /// a set; a run's own results cannot, because they are the schedule's list and
    /// nothing else.
    ResultForACheckThatWasNotScheduled {
        /// The check the result claims.
        id: CheckId,
    },
}

impl fmt::Display for RunnerRefused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MoreThanOneCommandForACheck { id } => write!(
                f,
                "the enforcement admitted more than one command for the check {id}, so there is no \
                 one command this check is"
            ),
            Self::TwoResultsForOneCheck { id } => write!(
                f,
                "two results were produced for the check {id}, and a run has one answer for a \
                 check"
            ),
            Self::ResultForACheckThatWasNotScheduled { id } => write!(
                f,
                "a result for the check {id} was handed in, and this schedule does not hold that \
                 check"
            ),
        }
    }
}

impl std::error::Error for RunnerRefused {}

/// What a run produced: one result per scheduled check, in the plan's order.
///
/// **Not a verdict**, and the type says so by being a list of results rather than
/// an aggregate: [`crate::aggregation::RunReport`] is what a verdict is, and it is
/// built from these by [`crate::aggregation::aggregate_run`]. The difference is
/// the one decision 3 of the ADR draws — the plan is metadata and this is the
/// evidence — and a report that could be green while a result cannot is the reason
/// they are two types rather than one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunResults {
    /// One entry per scheduled check, in the schedule's own order. The order is
    /// the schedule's and not this module's, so a report cannot number its rows
    /// differently from the plan they came from.
    results: Vec<CheckResult>,
}

impl RunResults {
    /// Turn what was produced into the run's results, one per scheduled check.
    ///
    /// Public because the two rules it enforces are the acceptance: exactly one
    /// result per scheduled check, and a check that produced nothing is an `Error`
    /// rather than a missing row. `produced` is what the runner (or any caller)
    /// collected; the schedule is what decides the shape of the answer.
    ///
    /// # Errors
    ///
    /// [`RunnerRefused::TwoResultsForOneCheck`] — a duplicate is not resolved by
    /// choosing. [`RunnerRefused::ResultForACheckThatWasNotScheduled`] — a result
    /// that cannot be placed is not dropped.
    pub fn assemble(
        schedule: &CheckSchedule,
        produced: &[CheckResult],
        project_fingerprint: &FingerprintId,
    ) -> Result<Self, RunnerRefused> {
        // Counted before anything is assembled, so a refusal is a statement about
        // the caller's set and not about a half-built run.
        let mut by_id: BTreeMap<&CheckId, &CheckResult> = BTreeMap::new();
        for result in produced {
            if by_id.insert(&result.id, result).is_some() {
                return Err(RunnerRefused::TwoResultsForOneCheck {
                    id: result.id.clone(),
                });
            }
        }
        for id in by_id.keys() {
            if schedule.get(id).is_none() {
                return Err(RunnerRefused::ResultForACheckThatWasNotScheduled {
                    id: (*id).clone(),
                });
            }
        }

        let mut results: Vec<CheckResult> = Vec::with_capacity(schedule.len());
        for scheduled in schedule.checks() {
            let result = match by_id.remove(scheduled.proposal().id()) {
                Some(produced) => produced.clone(),
                // Nothing was produced for this check, and what that means is
                // the whole of what this function is for.
                None => unreported(scheduled, project_fingerprint),
            };
            results.push(result);
        }

        Ok(Self { results })
    }

    /// Every scheduled check and what became of it, in plan order.
    #[must_use]
    pub fn results(&self) -> &[CheckResult] {
        &self.results
    }

    /// The result for one check, if it is one of these.
    ///
    /// Looking one up by identity is how a caller joins a result back to the plan
    /// that proposed it, which is the same thing
    /// [`CheckSchedule::get`] does in the other direction.
    #[must_use]
    pub fn get(&self, id: &CheckId) -> Option<&CheckResult> {
        self.results.iter().find(|result| &result.id == id)
    }

    /// How many results there are, which is how many checks were scheduled.
    #[must_use]
    pub fn len(&self) -> usize {
        self.results.len()
    }

    /// Whether the run has no results at all, which is to say nothing was
    /// scheduled.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.results.is_empty()
    }
}

/// Carry out every scheduled check that may be carried out, and report one result
/// for each.
///
/// This is the runner's whole job. It stops at the first thing it cannot report on
/// honestly — see [`RunnerRefused`] — and otherwise produces exactly one result per
/// scheduled check, in the schedule's order:
///
/// | what the plan says | what the mode says | what the run reports |
/// | --- | --- | --- |
/// | the check will not run | — | the plan's own `Skipped` result with its reason |
/// | it will run | the command was not admitted | the command's own `Skipped` result |
/// | it will run | it was admitted | what the runner reported, through `CommandRun::to_result` |
/// | it will run, as a service | it was admitted | what the runner reported, through `StartSmoke::run` |
/// | it will run, as a page | it was admitted | what the runner reported, through `StartSmoke::run_then` |
/// | it will run | nothing was admitted and nothing was stopped | an `Error` — nothing was observed |
///
/// The page's row is the service's row with a step in the middle, and the status
/// in both is the page's or the service's own rather than one chosen here. **A
/// browser check that no driver could carry out is one more `Error` rather than a
/// row of its own**: the plan says it would run, and SURE having no way to run it
/// is a failure of SURE's check and never a pass.
///
/// Static evidence never reaches a runner at all: a [`CheckOperation::Precomputed`]
/// check is its own observation, and its result is read from the evidence by
/// [`crate::planned_work::PrecomputedEvidence::to_result`], which is the same
/// mapping the command path ends in.
///
/// The three rows that reach a runner differ in the shape of the answer and not in
/// what happens next: a command's [`CommandRun`] is mapped here by
/// [`CommandRun::to_result`], and a service's and a page's results are produced
/// whole by [`crate::runtime_start`] — the table above has one row per kind of
/// work, and only one of them is this module's to map.
///
/// # Errors
///
/// [`RunnerRefused`], for the reasons on that type. Every one of them means the
/// run produced nothing: a refusal is not a partial result set.
#[must_use = "a run's results are the whole point of running it"]
pub fn run_scheduled_checks<R>(
    schedule: &CheckSchedule,
    enforcement: &Enforcement,
    project_fingerprint: &FingerprintId,
    runner: &R,
) -> Result<RunResults, RunnerRefused>
where
    R: CheckRunner + ?Sized,
{
    // The results the mode itself produced, by the check they are about. Keyed
    // rather than searched so that the two loops below read as the two questions
    // they are rather than as a scan inside a loop.
    let stopped: BTreeMap<&CheckId, &CheckResult> = enforcement
        .stopped()
        .iter()
        .map(|result| (&result.id, result))
        .collect();

    // Every command the enforcement admitted, by the check it belongs to — and
    // counted before any work happens, so that a plan this runner cannot read is
    // refused before SURE starts anything at all.
    let mut admitted: BTreeMap<&CheckId, AdmittedCommand<'_>> = BTreeMap::new();
    for command in enforcement.admitted() {
        let id = command.command().check().id();
        if admitted.insert(id, command).is_some() {
            return Err(RunnerRefused::MoreThanOneCommandForACheck { id: id.clone() });
        }
    }

    let mut produced: Vec<CheckResult> = Vec::with_capacity(schedule.len());
    for scheduled in schedule.checks() {
        let id = scheduled.proposal().id();

        // The plan's own answer, and it is asked first: a check the mode stopped
        // keeps the plan's own stopped result and is not carried out, whatever its
        // operation holds. Without this, a precomputed check the plan refused would
        // be reported as one that ran, and `aggregate_run` would record the
        // disagreement.
        if let Some(stopped) = scheduled.not_run(project_fingerprint) {
            produced.push(stopped);
            continue;
        }

        // Then the enforcement's: the plan allowed this check, and the command it
        // holds is one the mode stopped. The reason is the command's own — nothing
        // is made up here — and this branch is what makes *what may run* a question
        // the enforcement answers even when the schedule says yes.
        if let Some(result) = stopped.get(id) {
            produced.push((*result).clone());
            continue;
        }

        if let Some(result) = carry_out(
            scheduled,
            admitted.get(id).copied(),
            project_fingerprint,
            runner,
        ) {
            produced.push(result);
        }
    }

    RunResults::assemble(schedule, &produced, project_fingerprint)
}

/// What carrying out one scheduled check produced, or `None` when it produced
/// nothing.
///
/// **`None` is a real answer and not a failure**: it means SURE has no observation
/// for this check, and what that means for the run is [`RunResults::assemble`]'s
/// rule rather than this function's. It is returned in exactly one situation — the
/// plan holds a command for the check and the enforcement neither admitted nor
/// stopped one — because that is the case where there is nothing to observe and
/// nothing to report *about* the observation.
fn carry_out<R>(
    scheduled: &ScheduledCheck,
    admitted: Option<AdmittedCommand<'_>>,
    project_fingerprint: &FingerprintId,
    runner: &R,
) -> Option<CheckResult>
where
    R: CheckRunner + ?Sized,
{
    match scheduled.operation() {
        // The answer was already observed while the plan was made. There is no
        // process, no admission and no runner between this evidence and the
        // result, which is what `CheckOperation::starts_a_process` means.
        CheckOperation::Precomputed(evidence) => {
            Some(evidence.to_result(scheduled.proposal(), project_fingerprint))
        }
        CheckOperation::Command(_) => {
            // A plan holding a command the enforcement neither admitted nor
            // stopped has nothing to observe, and `None` is that answer; what it
            // means for the run is `RunResults::assemble`'s rule.
            let command = admitted?;
            match AdmittedRun::new(scheduled, command) {
                Ok(work) => {
                    let run = runner.run(&work);
                    Some(run.to_result(scheduled.proposal(), project_fingerprint))
                }
                // The admission does not cover this check's command, so there is
                // nothing SURE may start. An `Error` for this check rather than a
                // refusal of the run: the pairing is a fact about one check, and
                // the run's other checks can still be reported honestly.
                Err(refusal) => Some(refused_result(scheduled, &refusal, project_fingerprint)),
            }
        }
        // A service is the other kind of work that starts something, and it goes
        // to the other method: the admission is about the program and the
        // arguments that start the service, and the window, the question and the
        // stop belong to `runtime_start`, which is the only implementation of
        // what a service check is.
        CheckOperation::Service(_) => {
            // The same answer as the command arm for a plan that holds no
            // admission: nothing was admitted, so nothing was observed.
            let command = admitted?;
            match AdmittedService::new(scheduled, command, project_fingerprint) {
                Ok(work) => Some(runner.run_service(&work)),
                // The admission does not cover this check's service, so there is
                // nothing SURE may start. An `Error`, and the same reasoning as
                // the command arm's.
                Err(refusal) => Some(refused_result(scheduled, &refusal, project_fingerprint)),
            }
        }
        // A browser check is a service check with a page, and it goes to its own
        // door for the reason the service has one: the admission is about the
        // program that starts the service, and the pairing has to refuse a check
        // whose work is not a page as well as one whose command differs. The
        // window, the readiness question, the look and the stop are
        // `runtime_start`'s, reached through `run_browser`.
        //
        // Named rather than swallowed by a wildcard, so that a fifth kind of work
        // is a compile error here instead of a check that quietly produces nothing.
        CheckOperation::Browser(_) => {
            // The same answer as the other two doors for a plan that holds no
            // admission: nothing was admitted, so nothing was observed.
            let command = admitted?;
            match AdmittedBrowser::new(scheduled, command, project_fingerprint) {
                Ok(work) => Some(runner.run_browser(&work)),
                // The admission does not cover this check's service, so there is
                // nothing SURE may start. An `Error`, and the same reasoning as
                // the other two arms'.
                Err(refusal) => Some(refused_result(scheduled, &refusal, project_fingerprint)),
            }
        }
    }
}

/// The result for a scheduled check the runner produced nothing for.
///
/// Two answers, and which one is honest depends on what the plan said. A check the
/// plan refused keeps the plan's own stopped entry, and this is the path that
/// covers a caller that assembled results without asking the schedule what it
/// decided. A check the plan allowed that produced nothing is
/// [`NOTHING_WAS_REPORTED`], which is an `Error`.
///
/// `not_run` returning `None` *is* the question "would this check run?", so this
/// match is the rule rather than a re-derivation of it: a check that may run is
/// one SURE owes a result to, and a check that may not is one whose result the plan
/// already wrote.
fn unreported(scheduled: &ScheduledCheck, project_fingerprint: &FingerprintId) -> CheckResult {
    match scheduled.not_run(project_fingerprint) {
        Some(stopped) => stopped,
        None => {
            let proposal = scheduled.proposal();
            CheckResult::errored(
                proposal.id().clone(),
                proposal.title(),
                proposal.severity(),
                proposal.critical(),
                NOTHING_WAS_REPORTED,
                project_fingerprint.clone(),
            )
        }
    }
}

/// The result for a check whose command the admission does not cover.
///
/// `Error` and never a pass, because nothing was observed: SURE could not start
/// the command the plan holds, so what it has is a reason rather than evidence.
fn refused_result(
    scheduled: &ScheduledCheck,
    refusal: &AdmissionRefused,
    project_fingerprint: &FingerprintId,
) -> CheckResult {
    let proposal = scheduled.proposal();
    CheckResult::errored(
        proposal.id().clone(),
        proposal.title(),
        proposal.severity(),
        proposal.critical(),
        format!("SURE could not run the work this check holds: {refusal}."),
        project_fingerprint.clone(),
    )
}

/// The result for an admitted browser check on a runner that was given no
/// driver.
///
/// **[`CheckOperation::Browser`] arrives here and nothing else**, which makes
/// this the function the un-wiring property lives in. Before `P18-T010` a browser
/// check was answered by *this build has no runner for that kind of work*; the
/// mechanism changed and the answer did not, because the thing being protected is
/// not the sentence. **Deleting the one `.with_page_driver(…)` call at the
/// composition root must produce a run that fails, not a run that passes and not
/// a run that quietly skips**, and a `Skipped` here would be exactly the quiet
/// skip — it reads as a decision somebody made about the project, and nobody
/// decided this.
///
/// The status is `Error` for the same reason [`NOTHING_WAS_REPORTED`] is: the plan
/// says the check would run, so SURE having no way to run it is a failure of
/// SURE's own check. The reason names the work as well as the missing driver,
/// because *what SURE could not do* and *what it could not do it with* are two
/// things a reader needs and this is the only line that carries them.
fn no_driver_result(work: &AdmittedBrowser<'_>) -> CheckResult {
    let check = work.admitted().command().check();
    CheckResult::errored(
        check.id().clone(),
        check.title().to_owned(),
        check.severity(),
        check.critical(),
        format!(
            "SURE was not given a browser driver, so the work this check is — {} — was never \
             carried out and nothing about this check was observed.",
            work.work_description()
        ),
        work.fingerprint().clone(),
    )
}

/// The result for a browser check SURE could not set up.
///
/// `Error` and never a pass, for [`service_refused`]'s reason: nothing was
/// started, so nothing was observed, and a check the plan says would run is one
/// SURE owes an answer to. The identity comes from the admitted command, the same
/// place [`crate::browser::Report::verdict`]'s caller takes it from, so the two
/// paths cannot name one check differently.
///
/// `component` names the part of the plan that could not be used, because the
/// three ways to arrive here are three different facts: a budget this file chose
/// (which would be this file's defect), a window the plan chose, and an address
/// the plan chose. A reader who cannot tell them apart cannot tell which file to
/// look in.
fn browser_refused(
    work: &AdmittedBrowser<'_>,
    component: &str,
    error: &dyn fmt::Display,
) -> CheckResult {
    let check = work.admitted().command().check();
    CheckResult::errored(
        check.id().clone(),
        check.title().to_owned(),
        check.severity(),
        check.critical(),
        format!(
            "SURE could not set this browser check up, so no page was opened and nothing about \
             this check was observed: {component} could not be used ({error})."
        ),
        work.fingerprint().clone(),
    )
}

/// The result for a service check whose plan could not be turned into a run.
///
/// `Error` and never a pass, because nothing was started: the spec's own numbers
/// cannot produce a verdict, and a check SURE said it would carry out is one it
/// owes an answer to. The identity comes from the admitted command — which is the
/// check the enforcement decided about, and the same place [`crate::runtime_start`]
/// takes the identity of the results it produces — so the two paths cannot name
/// one check differently.
fn service_refused(work: &AdmittedService<'_>, error: &LimitsError) -> CheckResult {
    let check = work.admitted().command().check();
    CheckResult::errored(
        check.id().clone(),
        check.title().to_owned(),
        check.severity(),
        check.critical(),
        format!(
            "SURE could not set this service check up, so nothing about it was observed: {error}."
        ),
        work.fingerprint().clone(),
    )
}

/// A command as a person reads it, for a refusal message and for nothing else.
///
/// **This rendering is never turned back into a program and an argument vector.**
/// Splitting a command line into arguments is the act of starting a shell, and the
/// refusal this feeds is a sentence about two commands that were *not* run.
/// `PlannedCommand::display` is the same rendering for the other half of the pair
/// and carries the same note, so the two sides of the sentence are built the same
/// way and neither is parsed back.
fn display_of(spec: &CommandSpec) -> String {
    let mut line = spec.program().to_string_lossy().into_owned();
    for argument in spec.arguments() {
        line.push(' ');
        line.push_str(&argument.to_string_lossy());
    }
    line
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::ffi::OsString;
    use std::path::PathBuf;
    use std::time::{Duration, SystemTime};

    use sure_domain::evidence::EvidenceClass;
    use sure_domain::execution::{ActionKind, ExecutionMode, ExecutionPermissions};
    use sure_domain::severity::Severity;
    use sure_domain::status::{CheckStatus, NotCheckedReason};

    use crate::consent::{PermissionPlan, PlannedCheck};
    use crate::planned_work::{
        BrowserCheckSpec, PlannedWork, PrecomputedEvidence, Readiness, ServiceCheckSpec,
    };
    use crate::probe::Endpoint;
    use crate::process::{CapturedOutput, Outcome, ProcessError, Termination};
    use crate::schedule::{CheckProposal, CheckReason, PlanBuilder};

    /// What one call to a fake runner was asked to run.
    ///
    /// Structured rather than a rendered line, so that the assertion about what
    /// reached the runner is an assertion about the program and the argument
    /// vector — the two things the enforcement decided about — and not about how
    /// they happen to print.
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Asked {
        id: CheckId,
        program: OsString,
        arguments: Vec<OsString>,
    }

    /// What one call to a fake runner was asked to start as a service.
    ///
    /// The spec's own fields rather than a rendered line, and the environment is
    /// in it on purpose: **the environment a service is given is clause one of
    /// `P18-T009`**, and the only place it can be measured without starting a
    /// process is where the plan's value crosses the seam.
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct AskedService {
        id: CheckId,
        program: OsString,
        arguments: Vec<OsString>,
        working_directory: PathBuf,
        environment: crate::process::Environment,
        window: Duration,
        endpoint: Option<Endpoint>,
    }

    /// What one call to a fake runner was asked to open in a browser.
    ///
    /// The spec's own fields rather than a rendered line, for [`AskedService`]'s
    /// reason: **the page's path is deliberately not the readiness path**, so the
    /// two have to be readable apart, and an assertion about a service's endpoint
    /// could not tell a browser check that opened the page from one that opened
    /// the health route.
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct AskedPage {
        id: CheckId,
        program: OsString,
        arguments: Vec<OsString>,
        working_directory: PathBuf,
        environment: crate::process::Environment,
        window: Duration,
        readiness: Option<Endpoint>,
        path: String,
        expectation: String,
    }

    /// A runner with no process behind it.
    ///
    /// It records what it was asked for before it answers, so a test can assert
    /// both halves of the seam: what arrived, and what the result was made of.
    /// **No test in this file starts a process, and that is not a convenience** —
    /// these tests are about what may reach the seam, and a real run would answer a
    /// question about this machine instead.
    ///
    /// One fake for all three methods rather than three, so that "the command
    /// runner was not asked for a page" and "the page runner was not asked for a
    /// command" are assertions about the same value a run was handed.
    #[derive(Debug)]
    struct FakeRunner {
        asked: RefCell<Vec<Asked>>,
        answer: CommandRun,
        services: RefCell<Vec<AskedService>>,
        pages: RefCell<Vec<AskedPage>>,
        verdict: CheckStatus,
        page_verdict: CheckStatus,
    }

    impl FakeRunner {
        /// A runner that reports `answer` for every command and a `Pass` for every
        /// service and every page.
        fn reporting(answer: CommandRun) -> Self {
            Self {
                asked: RefCell::new(Vec::new()),
                answer,
                services: RefCell::new(Vec::new()),
                pages: RefCell::new(Vec::new()),
                verdict: CheckStatus::Pass,
                page_verdict: CheckStatus::Pass,
            }
        }

        /// A runner that reports a clean success for every command.
        fn succeeding() -> Self {
            Self::reporting(CommandRun::Ran(an_outcome(Some(0))))
        }

        /// The same fake, answering services with `verdict` instead of a pass.
        fn answering_services_with(mut self, verdict: CheckStatus) -> Self {
            self.verdict = verdict;
            self
        }

        /// The same fake, answering pages with `verdict` instead of a pass.
        ///
        /// Separate from [`Self::answering_services_with`] on purpose: a fixture
        /// that moved both at once could not show that a page's status is the one
        /// the browser check reports, which is the only thing that distinguishes
        /// the browser door's wiring from the service door's.
        fn answering_pages_with(mut self, verdict: CheckStatus) -> Self {
            self.page_verdict = verdict;
            self
        }

        /// Everything it was asked to run, in the order it was asked.
        fn asked(&self) -> Vec<Asked> {
            self.asked.borrow().clone()
        }

        /// Every service it was asked to start, in the order it was asked.
        fn services(&self) -> Vec<AskedService> {
            self.services.borrow().clone()
        }

        /// Every page it was asked to open, in the order it was asked.
        fn pages(&self) -> Vec<AskedPage> {
            self.pages.borrow().clone()
        }

        /// The result a service run reports, with the identity of the check the
        /// work belongs to.
        ///
        /// Built the way [`crate::runtime_start::StartSmoke::run`] builds one —
        /// identity from the admitted command, class `ObservedFact`, status from
        /// the verdict — because a fake whose result named a check the schedule
        /// does not hold would be refused by [`RunResults::assemble`] and the
        /// refusal would be about this fixture rather than about the runner.
        fn a_service_result(&self, work: &AdmittedService<'_>) -> CheckResult {
            self.a_result(work.admitted(), work.fingerprint(), self.verdict)
        }

        /// The result a browser check reports, built the same way and for the same
        /// reason.
        ///
        /// **One construction for both doors rather than two**, so that the two
        /// cannot drift into reporting a check differently — the identity comes
        /// from the admitted command in both cases, which is where
        /// `runtime_start` and `browser::Report::verdict` take it from too.
        fn a_page_result(&self, work: &AdmittedBrowser<'_>) -> CheckResult {
            self.a_result(work.admitted(), work.fingerprint(), self.page_verdict)
        }

        /// The result a fake run reports for one check in one status.
        fn a_result(
            &self,
            admitted: AdmittedCommand<'_>,
            run_fingerprint: &FingerprintId,
            verdict: CheckStatus,
        ) -> CheckResult {
            let check = admitted.command().check();
            let (id, title) = (check.id().clone(), check.title().to_owned());
            let (severity, critical) = (check.severity(), check.critical());
            let fingerprint = run_fingerprint.clone();
            let class = EvidenceClass::ObservedFact;
            match verdict {
                CheckStatus::Pass => {
                    CheckResult::pass(id, title, severity, critical, class, fingerprint)
                }
                CheckStatus::Fail => {
                    CheckResult::fail(id, title, severity, critical, class, fingerprint)
                }
                CheckStatus::Warning => {
                    CheckResult::warning(id, title, severity, critical, class, fingerprint)
                }
                CheckStatus::Unknown => {
                    CheckResult::unknown(id, title, severity, critical, class, fingerprint)
                }
                CheckStatus::Error => CheckResult::errored(
                    id,
                    title,
                    severity,
                    critical,
                    "this fake's verdict is an error",
                    fingerprint,
                ),
                // Named rather than folded into the arm above, so that a service
                // run reporting `Skipped` — which nothing in the product produces
                // — is a compile error in this file rather than a status quietly
                // mapped to the wrong word.
                CheckStatus::Skipped => CheckResult::not_run(
                    id,
                    title,
                    severity,
                    critical,
                    NotCheckedReason::ExecutionNotAuthorized,
                    fingerprint,
                ),
            }
        }
    }

    impl CheckRunner for FakeRunner {
        fn run(&self, work: &AdmittedRun<'_>) -> CommandRun {
            self.asked.borrow_mut().push(Asked {
                id: work.check().clone(),
                program: work.command().program().to_os_string(),
                arguments: work.command().arguments().to_vec(),
            });
            self.answer.clone()
        }

        fn run_service(&self, work: &AdmittedService<'_>) -> CheckResult {
            let spec = work.service();
            let command = spec.command();
            self.services.borrow_mut().push(AskedService {
                id: work.check().clone(),
                program: command.program().to_os_string(),
                arguments: command.arguments().to_vec(),
                working_directory: command.working_directory().to_path_buf(),
                environment: command.environment().clone(),
                window: spec.window(),
                endpoint: spec.readiness().endpoint().cloned(),
            });
            self.a_service_result(work)
        }

        fn run_browser(&self, work: &AdmittedBrowser<'_>) -> CheckResult {
            let spec = work.browser();
            let service = spec.service();
            let command = service.command();
            self.pages.borrow_mut().push(AskedPage {
                id: work.check().clone(),
                program: command.program().to_os_string(),
                arguments: command.arguments().to_vec(),
                working_directory: command.working_directory().to_path_buf(),
                environment: command.environment().clone(),
                window: service.window(),
                readiness: service.readiness().endpoint().cloned(),
                path: spec.path().to_owned(),
                expectation: spec.expectation().to_owned(),
            });
            self.a_page_result(work)
        }
    }

    /// An outcome the process runner could have reported, built directly rather
    /// than observed: `Outcome`'s constructors are crate-internal, which is what
    /// lets a unit test reach the mapping without a process.
    fn an_outcome(code: Option<i32>) -> Outcome {
        Outcome::new(
            OsString::from("a fake program"),
            Termination::Exited { code },
            CapturedOutput::empty(),
            CapturedOutput::empty(),
            SystemTime::now(),
            Duration::from_millis(1),
        )
    }

    fn check_id(body: &str) -> CheckId {
        CheckId::parse(format!("chk_{body}")).expect("a well-formed check id")
    }

    /// The mode and permissions this file's fixtures are built under.
    ///
    /// `HostConfirmed` with the one grant that lets a declared command run, which
    /// is the pair `tests/aggregation.rs` uses for a run that may execute the
    /// project's code. The same pair is given to the plan and to the permission
    /// plan, because a schedule built under one set of rules and enforced under
    /// another would be a fixture about a state the product cannot be in.
    fn execution() -> (ExecutionMode, ExecutionPermissions) {
        (
            ExecutionMode::HostConfirmed,
            ExecutionPermissions {
                run_project_code: true,
                ..ExecutionPermissions::inspect_only()
            },
        )
    }

    /// A check's proposal, with the operation that would carry it out.
    fn work(body: &str, title: &str, action: ActionKind, operation: CheckOperation) -> PlannedWork {
        PlannedWork::new(
            CheckProposal::new(
                check_id(body),
                title,
                Severity::MustFix,
                true,
                EvidenceClass::DeterministicCheck,
                CheckReason::ProjectWide,
                &[action],
            ),
            operation,
        )
    }

    /// The command this file's fixtures use when they need one the mode admits.
    ///
    /// `python -m pytest` is classified as running code the project controls,
    /// which the grants [`execution`] hands out cover — so a permission plan that
    /// holds it admits it. A fixture that needs a command the mode will **not**
    /// admit uses `frobnicate`, which is a program the classifier does not know:
    /// an unknown program needs a permission nobody can grant, so it is the
    /// shape of a command the mode refuses without SURE having any opinion about
    /// the program itself.
    const ADMITTED_PROGRAM: &str = "python";
    const ADMITTED_ARGUMENTS: [&str; 2] = ["-m", "pytest"];

    /// The operation for a check that runs the admitted command.
    fn runs_the_admitted_command() -> CheckOperation {
        a_command(ADMITTED_PROGRAM, &ADMITTED_ARGUMENTS)
    }

    /// The operation for a check that runs one command.
    fn a_command(program: &str, arguments: &[&str]) -> CheckOperation {
        CheckOperation::Command(
            CommandSpec::new(
                program,
                std::env::temp_dir(),
                crate::process::Environment::inherited(),
                crate::process::Limits::new(Duration::from_secs(30), 64 * 1024, 64 * 1024),
            )
            .with_arguments(arguments.iter().copied()),
        )
    }

    /// The operation for a check whose answer a detector already observed.
    fn observed(detail: &str) -> CheckOperation {
        CheckOperation::Precomputed(PrecomputedEvidence::holds(detail))
    }

    /// The operation for a check that starts a service.
    ///
    /// The command is the admitted one, so that a fixture can hold an admission
    /// for a service check too. [`AdmittedRun::new`] refuses a service by what its
    /// work *is* and refuses a mismatched command by what it *holds*, and a
    /// service fixture whose command was also unadmitted would not tell those two
    /// refusals apart — the mismatch would answer first.
    fn a_service() -> CheckOperation {
        let CheckOperation::Command(spec) = runs_the_admitted_command() else {
            panic!("the fixture builds a command");
        };
        CheckOperation::Service(ServiceCheckSpec::new(
            spec,
            Readiness::StaysUp,
            Duration::from_secs(5),
        ))
    }

    /// The operation for a service whose spec differs from the defaults in every
    /// field a request is built from.
    ///
    /// The program and the arguments are the admitted ones, because those are the
    /// only ones an admission can be paired with. Everything else the spec holds
    /// is free to differ, and this fixture makes every one of them differ — the
    /// directory is not [`std::env::temp_dir`], the environment is not the
    /// inherited one, the process limits are not the ones [`a_command`] uses, the
    /// window is not [`a_service`]'s, and the readiness names an endpoint — so
    /// that the assertions in
    /// `a_service_check_that_is_admitted_reaches_the_service_runner` can only pass
    /// if each value came from this spec and from nowhere else.
    fn a_planned_service() -> CheckOperation {
        let spec = CommandSpec::new(
            ADMITTED_PROGRAM,
            std::env::temp_dir().join("sure-fixture-service"),
            crate::process::Environment::only([
                (OsString::from("PATH"), OsString::from("/fixture/bin")),
                (OsString::from("PORT"), OsString::from("5173")),
            ]),
            crate::process::Limits::new(Duration::from_secs(21), 4096, 8192),
        )
        .with_arguments(ADMITTED_ARGUMENTS);
        CheckOperation::Service(ServiceCheckSpec::new(
            spec,
            Readiness::Answers {
                endpoint: Endpoint::loopback(5173, "/health")
                    .expect("the fixture names a loopback endpoint"),
            },
            Duration::from_secs(7),
        ))
    }

    /// The operation for a check that reads a page a service serves.
    ///
    /// Built from a service that **answers**, because
    /// [`BrowserCheckSpec::new`] refuses a service that only stays up: a service
    /// that names no port has no page for a browser to open. So this fixture
    /// cannot be built from [`a_service`], and the endpoint it does carry is the
    /// one the browser would be sent to.
    fn a_browser() -> CheckOperation {
        let CheckOperation::Service(service) = a_planned_service() else {
            panic!("the fixture builds a service");
        };
        CheckOperation::Browser(
            BrowserCheckSpec::new(service, "/", "the page says the project is up")
                .expect("the fixture's page is well formed"),
        )
    }

    /// The operation for a browser check whose page is **not** its service's
    /// readiness route.
    ///
    /// [`a_browser`] opens `/`, which is what a fixture reaches for first and is
    /// also the one path that could not tell the page apart from the readiness
    /// question if a wiring ever confused them. This one opens `/post/1` on a
    /// service whose readiness is `/health`, which is the shape `planned_work.rs`
    /// says a browser check is for — *a project whose health route is not where
    /// its pages are* — and it is the fixture the wiring assertions use for that
    /// reason.
    fn a_browser_with_its_own_page() -> CheckOperation {
        let CheckOperation::Service(service) = a_planned_service() else {
            panic!("the fixture builds a service");
        };
        CheckOperation::Browser(
            BrowserCheckSpec::new(service, "/post/1", "the post page shows the first post")
                .expect("the fixture's page is well formed"),
        )
    }

    /// A schedule built from these checks, in the plan's own order.
    ///
    /// The order that comes back is the plan's, not this function's — the plan
    /// sorts by what a check would do and how heavily it weighs — so every test
    /// below looks a check up by identity rather than by position.
    fn schedule_of(work: impl IntoIterator<Item = PlannedWork>) -> CheckSchedule {
        let (mode, permissions) = execution();
        let mut builder = PlanBuilder::new(mode, permissions);
        for entry in work {
            builder
                .propose(entry)
                .expect("the fixture's proposals are well formed");
        }
        builder.build()
    }

    /// A schedule holding one browser check, built under the one grant a browser
    /// probe needs.
    ///
    /// [`schedule_of`]'s mode grants the right to run the project's code and not
    /// the right to connect to a service, so a browser check proposed there is
    /// stopped by the plan and never reaches a door — which would make every test
    /// below a test about the plan rather than about the seam. This is the same
    /// builder with `connect_service` added and nothing else changed, which is
    /// the pair `browser_probe.rs` uses for the same reason.
    fn browser_schedule(entry: PlannedWork) -> CheckSchedule {
        let (mode, permissions) = (
            ExecutionMode::HostConfirmed,
            ExecutionPermissions {
                connect_service: true,
                ..ExecutionPermissions::inspect_only()
            },
        );
        let mut builder = PlanBuilder::new(mode, permissions);
        builder
            .propose(entry)
            .expect("the fixture's proposal is well formed");
        builder.build()
    }

    /// A permission plan that holds one command per `(check, program, arguments)`,
    /// decided under [`execution`].
    fn permission_plan(
        fingerprint: &FingerprintId,
        commands: &[(&str, &str, &[&str])],
    ) -> PermissionPlan {
        let (mode, permissions) = execution();
        let mut plan = PermissionPlan::new(mode, fingerprint.clone(), permissions);
        for (body, program, arguments) in commands {
            plan.add(
                PlannedCheck::new(check_id(body), "a check", Severity::MustFix, true),
                *program,
                arguments.iter().copied(),
            );
        }
        plan
    }

    /// The enforcement for a schedule and a permission plan.
    fn enforcement_of(schedule: &CheckSchedule, plan: PermissionPlan) -> Enforcement {
        Enforcement::of("P18-T006's fixture", plan, &schedule.planned_checks())
    }

    /// The status of the result for one check.
    fn status_of(results: &RunResults, body: &str) -> CheckStatus {
        results
            .get(&check_id(body))
            .expect("the run reported nothing for this check")
            .status
    }

    // ---- clause one: exactly one result per scheduled check ------------------

    #[test]
    fn every_scheduled_check_comes_back_with_exactly_one_result() {
        let fingerprint = FingerprintId::generate();
        // Four kinds of check in one plan: one already observed, one that runs an
        // admitted command, one the plan stopped, and one that starts a service.
        // The last two are the ones worth watching: the stopped check has an
        // admission of its own that must not be used, and the service reaches the
        // other half of the seam rather than the command runner.
        let schedule = schedule_of([
            work(
                "observed",
                "a detector read the project",
                ActionKind::ReadFile,
                observed("it is there"),
            ),
            work(
                "runs",
                "the project's tests",
                ActionKind::RunTests,
                a_command("python", &["-m", "pytest"]),
            ),
            work(
                "stopped",
                "a check the mode stopped",
                ActionKind::RunTests,
                a_command("frobnicate", &["--everything"]),
            ),
            work(
                "served",
                "a service that answers",
                ActionKind::LocalProbe,
                a_service(),
            ),
        ]);
        let plan = permission_plan(
            &fingerprint,
            &[
                ("runs", "python", &["-m", "pytest"]),
                ("stopped", "frobnicate", &["--everything"]),
                ("served", ADMITTED_PROGRAM, &ADMITTED_ARGUMENTS),
            ],
        );
        let enforcement = enforcement_of(&schedule, plan);
        let runner = FakeRunner::succeeding();

        let results = run_scheduled_checks(&schedule, &enforcement, &fingerprint, &runner)
            .expect("nothing in this plan is ambiguous");

        assert_eq!(
            results.len(),
            schedule.len(),
            "every scheduled check has one result"
        );
        let reported: Vec<&CheckId> = results.results().iter().map(|result| &result.id).collect();
        let scheduled: Vec<&CheckId> = schedule
            .checks()
            .iter()
            .map(|scheduled| scheduled.proposal().id())
            .collect();
        assert_eq!(
            reported, scheduled,
            "the results are the schedule's checks, in the schedule's own order"
        );
        let mut seen: Vec<&CheckId> = Vec::new();
        for id in &reported {
            assert!(
                !seen.contains(id),
                "{id} was reported twice, which is the duplication this run refuses"
            );
            seen.push(id);
        }
        assert_eq!(
            runner.asked().len(),
            1,
            "exactly one check in this plan reaches the command runner"
        );
        let services = runner.services();
        assert_eq!(
            services.len(),
            1,
            "exactly one check in this plan reaches the service runner, found: {services:?}"
        );
        assert_eq!(
            services[0].id,
            check_id("served"),
            "the service runner is asked for the check that plans a service, and not for the check \
             the plan stopped — a stopped check keeps the plan's own answer"
        );
    }

    #[test]
    fn two_results_for_one_check_stop_the_run() {
        let fingerprint = FingerprintId::generate();
        let schedule = schedule_of([work(
            "observed",
            "a detector read the project",
            ActionKind::ReadFile,
            observed("it is there"),
        )]);
        // Two results that claim the same check. The first is a perfectly good
        // result, which is the point: the refusal is about the duplication and
        // not about anything being wrong with either answer.
        let first = CheckResult::pass(
            check_id("observed"),
            "a detector read the project",
            Severity::MustFix,
            true,
            EvidenceClass::DeterministicCheck,
            fingerprint.clone(),
        );
        let again = CheckResult::errored(
            check_id("observed"),
            "a detector read the project",
            Severity::MustFix,
            true,
            "a second answer to the same question",
            fingerprint.clone(),
        );

        let refused = RunResults::assemble(&schedule, &[first, again], &fingerprint)
            .expect_err("two results for one check cannot be assembled");

        assert_eq!(
            refused,
            RunnerRefused::TwoResultsForOneCheck {
                id: check_id("observed")
            }
        );
    }

    #[test]
    fn two_commands_admitted_for_one_check_stop_the_run_before_anything_runs() {
        let fingerprint = FingerprintId::generate();
        let schedule = schedule_of([work(
            "twice",
            "a check with two commands",
            ActionKind::RunTests,
            a_command("python", &["-m", "pytest"]),
        )]);
        let plan = permission_plan(
            &fingerprint,
            &[
                ("twice", "python", &["-m", "pytest"]),
                ("twice", "python", &["-m", "pytest", "-x"]),
            ],
        );
        let enforcement = enforcement_of(&schedule, plan);
        let runner = FakeRunner::succeeding();

        let refused = run_scheduled_checks(&schedule, &enforcement, &fingerprint, &runner)
            .expect_err("a check that is two commands cannot be carried out");

        assert_eq!(
            refused,
            RunnerRefused::MoreThanOneCommandForACheck {
                id: check_id("twice")
            }
        );
        assert!(
            runner.asked().is_empty(),
            "the refusal happens before any work, so nothing ran under a plan SURE had just found \
             unreadable"
        );
    }

    #[test]
    fn a_result_for_a_check_the_schedule_does_not_hold_is_refused() {
        let fingerprint = FingerprintId::generate();
        let schedule = schedule_of([work(
            "observed",
            "a detector read the project",
            ActionKind::ReadFile,
            observed("it is there"),
        )]);
        let stray = CheckResult::errored(
            check_id("elsewhere"),
            "a check nobody scheduled",
            Severity::MustFix,
            true,
            "a result that cannot be placed",
            fingerprint.clone(),
        );

        let refused = RunResults::assemble(&schedule, &[stray], &fingerprint)
            .expect_err("a result the schedule does not hold cannot be part of its run");

        assert_eq!(
            refused,
            RunnerRefused::ResultForACheckThatWasNotScheduled {
                id: check_id("elsewhere")
            }
        );
    }

    // ---- clause two: an admitted check that reported nothing is an error -----

    #[test]
    fn a_check_the_mode_admitted_that_reported_nothing_becomes_an_error() {
        let fingerprint = FingerprintId::generate();
        // The plan says this check runs one command. The permission plan holds no
        // command for it at all, so the enforcement neither admits one nor stops
        // one — and the runner has nothing to report.
        let schedule = schedule_of([work(
            "unreported",
            "a command nobody planned to run",
            ActionKind::RunTests,
            a_command("python", &["-m", "pytest"]),
        )]);
        assert!(
            schedule.checks()[0].may_run(),
            "the plan allowed this check, which is what makes the missing result a question SURE \
             owes an answer to"
        );
        let enforcement = enforcement_of(&schedule, permission_plan(&fingerprint, &[]));
        let runner = FakeRunner::succeeding();

        let results = run_scheduled_checks(&schedule, &enforcement, &fingerprint, &runner)
            .expect("a missing result is reported rather than refused");

        let result = results
            .get(&check_id("unreported"))
            .expect("the check cannot be dropped out of the run");
        assert_eq!(
            result.status,
            CheckStatus::Error,
            "a check the mode admitted that produced nothing is an error, never a silence"
        );
        assert!(
            result.blocks_green(),
            "a critical check in this state must stop a green verdict"
        );
        assert_eq!(result.reason, NOTHING_WAS_REPORTED);
        assert!(
            runner.asked().is_empty(),
            "nothing was admitted, so the runner was asked nothing"
        );
    }

    #[test]
    fn a_scheduled_check_with_no_result_is_an_error_and_not_a_dropped_row() {
        let fingerprint = FingerprintId::generate();
        let schedule = schedule_of([work(
            "admitted",
            "a check the plan allowed",
            ActionKind::RunTests,
            a_command("python", &["-m", "pytest"]),
        )]);

        let results = RunResults::assemble(&schedule, &[], &fingerprint)
            .expect("an empty result set is assembled rather than refused");

        assert_eq!(results.len(), 1, "the check is a row and not an absence");
        let result = &results.results()[0];
        assert_eq!(result.id, check_id("admitted"));
        assert_eq!(result.status, CheckStatus::Error);
        assert!(result.blocks_green());
        assert_eq!(result.reason, NOTHING_WAS_REPORTED);
    }

    #[test]
    fn a_check_the_plan_stopped_keeps_the_plans_own_stopped_result() {
        let fingerprint = FingerprintId::generate();
        let (mode, permissions) = (
            ExecutionMode::InspectOnly,
            ExecutionPermissions::inspect_only(),
        );
        let mut builder = PlanBuilder::new(mode, permissions);
        builder
            .propose(work(
                "blocked",
                "a check the mode stopped",
                ActionKind::RunTests,
                a_command("python", &["-m", "pytest"]),
            ))
            .expect("the proposal is well formed");
        let schedule = builder.build();
        assert!(
            !schedule.checks()[0].may_run(),
            "the fixture is about a check that will not run"
        );

        let results = RunResults::assemble(&schedule, &[], &fingerprint)
            .expect("a stopped check needs no result from a runner");

        assert_eq!(results.len(), 1);
        let result = &results.results()[0];
        assert_eq!(
            result.status,
            CheckStatus::Skipped,
            "a check the plan stopped keeps the plan's own answer"
        );
        assert_eq!(
            result.not_checked_reason,
            Some(NotCheckedReason::ExecutionNotAuthorized)
        );
    }

    // ---- clause three: an unadmitted command cannot reach the runner ---------

    #[test]
    fn a_command_the_enforcement_did_not_admit_never_reaches_the_runner() {
        let fingerprint = FingerprintId::generate();
        // Both checks may run as far as the *plan* is concerned — their actions
        // need nothing this mode withholds. One of them holds a command the mode
        // will not admit, and that is the whole of the difference.
        let schedule = schedule_of([
            work(
                "admitted",
                "the project's tests",
                ActionKind::RunTests,
                a_command("python", &["-m", "pytest"]),
            ),
            work(
                "unadmitted",
                "a command the mode will not admit",
                ActionKind::ReadFile,
                a_command("frobnicate", &["--everything"]),
            ),
        ]);
        let plan = permission_plan(
            &fingerprint,
            &[
                ("admitted", "python", &["-m", "pytest"]),
                ("unadmitted", "frobnicate", &["--everything"]),
            ],
        );
        let enforcement = enforcement_of(&schedule, plan);
        assert_eq!(
            enforcement.stopped().len(),
            1,
            "the enforcement stopped exactly the command it did not admit"
        );
        let runner = FakeRunner::succeeding();

        let results = run_scheduled_checks(&schedule, &enforcement, &fingerprint, &runner)
            .expect("a stopped command is a result and not a refusal");

        let asked = runner.asked();
        assert_eq!(
            asked.len(),
            1,
            "only the admitted command reached the runner, found: {asked:?}"
        );
        assert_eq!(asked[0].id, check_id("admitted"));
        assert_eq!(asked[0].program, OsString::from("python"));
        assert_eq!(
            asked[0].arguments,
            vec![OsString::from("-m"), OsString::from("pytest")]
        );
        assert_eq!(
            status_of(&results, "unadmitted"),
            CheckStatus::Skipped,
            "the check whose command was not admitted keeps the command's own stopping"
        );
        assert_eq!(status_of(&results, "admitted"), CheckStatus::Pass);
    }

    #[test]
    fn an_admission_cannot_be_paired_with_another_checks_command() {
        let fingerprint = FingerprintId::generate();
        let schedule = schedule_of([
            work(
                "mine",
                "a check that runs a command",
                ActionKind::RunTests,
                runs_the_admitted_command(),
            ),
            work(
                "theirs",
                "another check that runs a command",
                ActionKind::RunTests,
                a_command(ADMITTED_PROGRAM, &["-m", "pytest", "-x"]),
            ),
            work("served", "a service", ActionKind::LocalProbe, a_service()),
        ]);
        let plan = permission_plan(
            &fingerprint,
            &[
                ("mine", ADMITTED_PROGRAM, &ADMITTED_ARGUMENTS),
                ("theirs", ADMITTED_PROGRAM, &ADMITTED_ARGUMENTS),
                ("served", ADMITTED_PROGRAM, &ADMITTED_ARGUMENTS),
            ],
        );
        let enforcement = enforcement_of(&schedule, plan);
        let admitted: BTreeMap<&CheckId, AdmittedCommand<'_>> = enforcement
            .admitted()
            .map(|command| (command.command().check().id(), command))
            .collect();

        // The pair that really is one command.
        let mine = schedule.get(&check_id("mine")).expect("scheduled");
        let work = AdmittedRun::new(mine, admitted[&check_id("mine")])
            .expect("the plan and the enforcement agree about this command");
        assert_eq!(work.check(), &check_id("mine"));
        assert_eq!(work.command().arguments().len(), 2);

        // The same admission, paired with another check's work.
        let theirs = schedule.get(&check_id("theirs")).expect("scheduled");
        let refused = AdmittedRun::new(theirs, admitted[&check_id("mine")])
            .expect_err("an admission is about one check");
        assert_eq!(
            refused,
            AdmissionRefused::ForADifferentCheck {
                id: check_id("theirs"),
                admitted_for: check_id("mine"),
            }
        );

        // An admission paired with work that is not one command at all.
        let served = schedule.get(&check_id("served")).expect("scheduled");
        let refused = AdmittedRun::new(served, admitted[&check_id("served")])
            .expect_err("a service is not one command");
        assert_eq!(
            refused,
            AdmissionRefused::NotOneCommand {
                id: check_id("served"),
                work: "started, asked one question, and stopped",
            }
        );
    }

    #[test]
    fn an_admission_that_covers_a_different_command_is_refused() {
        let fingerprint = FingerprintId::generate();
        let schedule = schedule_of([work(
            "differs",
            "a check whose command and admission disagree",
            ActionKind::RunTests,
            a_command("python", &["-m", "pytest"]),
        )]);
        // The same program, a different argument vector: the case a comparison of
        // rendered command lines would let through.
        let plan = permission_plan(
            &fingerprint,
            &[("differs", "python", &["-m", "pytest", "-x"])],
        );
        let enforcement = enforcement_of(&schedule, plan);
        let admitted = enforcement
            .admitted()
            .next()
            .expect("one command was admitted");
        let scheduled = schedule.get(&check_id("differs")).expect("scheduled");

        let refused = AdmittedRun::new(scheduled, admitted)
            .expect_err("the decision was about a different argument vector");

        match refused {
            AdmissionRefused::NotTheCommandThatWasAdmitted {
                id,
                planned,
                admitted,
            } => {
                assert_eq!(id, check_id("differs"));
                assert_eq!(planned, "python -m pytest");
                assert_eq!(admitted, "python -m pytest -x");
            }
            other => panic!("the refusal names the wrong reason: {other}"),
        }
    }

    #[test]
    fn an_admission_that_does_not_cover_a_checks_command_is_an_error_and_never_a_pass() {
        // The arm above proves the pairing is refused. This one takes the
        // refusal through the run, because **a refusal nothing calls is not a
        // rule**: `carry_out` turns it into a row, and what that row says is the
        // whole of what a user sees when the two halves of SURE's own decision
        // disagree.
        //
        // `pipeline.rs` cannot produce this state today — it builds the schedule
        // and the permission plan from the same walk, so the two agree by
        // construction — and that is a fact about one caller rather than about
        // this function, which takes the schedule and the enforcement as two
        // values. What is asserted here is about the second value: a check whose
        // work the admission does not cover must be an `Error` that blocks green
        // and must not be carried to a runner at all.
        let fingerprint = FingerprintId::generate();
        let schedule = schedule_of([work(
            "differs",
            "a check whose admission does not cover its command",
            ActionKind::RunTests,
            a_command("python", &["-m", "pytest"]),
        )]);
        // The same program, one more argument: the case a comparison of rendered
        // command lines would let through, and the one `P18-T006` chose to refuse.
        let plan = permission_plan(
            &fingerprint,
            &[("differs", "python", &["-m", "pytest", "-x"])],
        );
        let enforcement = enforcement_of(&schedule, plan);
        let runner = FakeRunner::succeeding();

        let results = run_scheduled_checks(&schedule, &enforcement, &fingerprint, &runner)
            .expect("a check and its admission disagreeing is a row, not a refused run");

        let result = results
            .get(&check_id("differs"))
            .expect("the check is a row and not an absence");
        assert_eq!(
            result.status,
            CheckStatus::Error,
            "nothing was observed, so nothing may be reported as an observation: {}",
            result.reason
        );
        assert!(
            result.blocks_green(),
            "a critical check SURE could not carry out has to keep the run out of green"
        );
        assert!(
            result
                .reason
                .contains("could not run the work this check holds"),
            "the row says what happened rather than reporting a status alone: {}",
            result.reason
        );
        assert!(
            result.reason.contains("python -m pytest -x"),
            "and it names the command that was admitted, which is what a reader needs \
             to see the disagreement: {}",
            result.reason
        );
        assert!(
            runner.asked().is_empty(),
            "the refused pairing reached a runner, so the refusal is a sentence rather \
             than a door: {:?}",
            runner.asked()
        );
    }

    // ---- the translation, field for field -----------------------------------

    #[test]
    fn the_request_is_the_spec_field_for_field() {
        let fingerprint = FingerprintId::generate();
        // The program and the arguments are the ones the mode admits, because
        // those are the only ones an admission can be paired with. Everything
        // else the spec holds is free to differ, and this fixture makes them
        // differ so that the assertions below can only pass if each field came
        // from the spec.
        let spec = CommandSpec::new(
            ADMITTED_PROGRAM,
            std::env::temp_dir().join("sure-fixture"),
            crate::process::Environment::inherited()
                .without("CARGO_TARGET_DIR")
                .with("CARGO_TERM_COLOR", "never"),
            crate::process::Limits::new(Duration::from_secs(11), 1024, 2048),
        )
        .with_arguments(ADMITTED_ARGUMENTS);
        let schedule = schedule_of([work(
            "translated",
            "a check whose request is compared against its spec",
            ActionKind::RunTests,
            CheckOperation::Command(spec.clone()),
        )]);
        let plan = permission_plan(
            &fingerprint,
            &[("translated", ADMITTED_PROGRAM, &ADMITTED_ARGUMENTS)],
        );
        let enforcement = enforcement_of(&schedule, plan);
        let admitted = enforcement
            .admitted()
            .next()
            .expect("one command was admitted");
        let scheduled = schedule.get(&check_id("translated")).expect("scheduled");
        let work = AdmittedRun::new(scheduled, admitted).expect("the two agree");

        let request = work.request(&Cancellation::new());

        assert_eq!(request.program(), spec.program());
        assert_eq!(request.arguments(), spec.arguments());
        assert_eq!(request.working_directory(), spec.working_directory());
        assert_eq!(request.limits(), spec.limits());
        assert_eq!(request.environment(), spec.environment());
    }

    #[test]
    fn an_argument_holding_a_space_stays_one_argument() {
        let fingerprint = FingerprintId::generate();
        // Three arguments, two of which no shell-free layer may touch: one holds
        // a space, and one holds a quote. The module flag keeps the classifier
        // reading these as arguments of the operation rather than as the
        // operation, and nothing else about them matters here.
        let spec = CommandSpec::new(
            ADMITTED_PROGRAM,
            std::env::temp_dir(),
            crate::process::Environment::inherited(),
            crate::process::Limits::new(Duration::from_secs(5), 1024, 1024),
        )
        .with_arguments(["tests/a file with spaces", "it's", "a\\b"]);
        let schedule = schedule_of([work(
            "spaces",
            "a check with an argument holding a space",
            ActionKind::RunTests,
            CheckOperation::Command(spec.clone()),
        )]);
        let plan = permission_plan(
            &fingerprint,
            &[(
                "spaces",
                ADMITTED_PROGRAM,
                &["tests/a file with spaces", "it's", "a\\b"],
            )],
        );
        let enforcement = enforcement_of(&schedule, plan);
        let admitted = enforcement
            .admitted()
            .next()
            .expect("one command was admitted");
        let scheduled = schedule.get(&check_id("spaces")).expect("scheduled");
        let work = AdmittedRun::new(scheduled, admitted).expect("the two agree");

        let request = work.request(&Cancellation::new());

        assert_eq!(
            request.arguments().len(),
            3,
            "three arguments went in and three came out: nothing is split and nothing is joined"
        );
        assert_eq!(
            request.arguments(),
            [
                OsString::from("tests/a file with spaces"),
                OsString::from("it's"),
                OsString::from("a\\b"),
            ],
            "each argument arrived as itself, with the space and the quote still inside it"
        );
        assert_eq!(request.arguments(), spec.arguments());
        for argument in request.arguments() {
            let text = argument.to_string_lossy();
            assert!(
                !text.starts_with('"') && !text.starts_with('\''),
                "{text:?} was quoted on the way through, which no layer here may do"
            );
        }
    }

    // ---- what the runner reported, as the check's result ---------------------

    #[test]
    fn a_command_that_ran_and_reported_success_passes_the_check() {
        let fingerprint = FingerprintId::generate();
        let schedule = schedule_of([work(
            "passes",
            "the project's tests",
            ActionKind::RunTests,
            a_command("python", &["-m", "pytest"]),
        )]);
        let plan = permission_plan(&fingerprint, &[("passes", "python", &["-m", "pytest"])]);
        let enforcement = enforcement_of(&schedule, plan);
        let runner = FakeRunner::reporting(CommandRun::Ran(an_outcome(Some(0))));

        let results = run_scheduled_checks(&schedule, &enforcement, &fingerprint, &runner)
            .expect("nothing here is ambiguous");

        assert_eq!(status_of(&results, "passes"), CheckStatus::Pass);
    }

    #[test]
    fn a_command_that_never_started_makes_the_check_an_error() {
        let fingerprint = FingerprintId::generate();
        let schedule = schedule_of([work(
            "missing",
            "a check whose program is not installed",
            ActionKind::RunTests,
            a_command("python", &["-m", "pytest"]),
        )]);
        let plan = permission_plan(&fingerprint, &[("missing", "python", &["-m", "pytest"])]);
        let enforcement = enforcement_of(&schedule, plan);
        let runner = FakeRunner::reporting(CommandRun::NeverStarted(ProcessError::NotStarted {
            program: OsString::from("python"),
            working_directory: std::env::temp_dir(),
            message: "the system cannot find the file specified".to_owned(),
        }));

        let results = run_scheduled_checks(&schedule, &enforcement, &fingerprint, &runner)
            .expect("a command that did not start is a result and not a refusal");

        let result = results.get(&check_id("missing")).expect("reported");
        assert_eq!(result.status, CheckStatus::Error);
        assert!(
            result
                .reason
                .contains("the system cannot find the file specified"),
            "the operating system's own words are what a reader needs: {}",
            result.reason
        );
        assert!(result.blocks_green());
    }

    #[test]
    fn a_browser_check_whose_service_is_admitted_reaches_the_browser_runner() {
        let fingerprint = FingerprintId::generate();
        // **Every field of this check differs from every other fixture's.** The
        // page is `/post/1` while the service's readiness is `/health`, the
        // window is `a_planned_service`'s seven seconds and not `a_service`'s
        // five, the directory is not the temp directory and the environment is
        // not SURE's own. So an assertion below can only pass if the value came
        // from the plan, and the two paths can only pass if the page's path and
        // the readiness path arrived as two different things.
        let schedule = browser_schedule(work(
            "browsed",
            "the project's first post page",
            ActionKind::BrowserProbe,
            a_browser_with_its_own_page(),
        ));
        let plan = permission_plan(
            &fingerprint,
            &[("browsed", ADMITTED_PROGRAM, &ADMITTED_ARGUMENTS)],
        );
        let enforcement = enforcement_of(&schedule, plan);
        let runner = FakeRunner::succeeding();

        let results = run_scheduled_checks(&schedule, &enforcement, &fingerprint, &runner)
            .expect("nothing in this plan is ambiguous");

        let pages = runner.pages();
        assert_eq!(
            pages.len(),
            1,
            "one page reached the browser runner, found: {pages:?}"
        );
        let asked = &pages[0];
        assert_eq!(asked.id, check_id("browsed"), "and it is this check's page");
        assert_eq!(
            asked.path, "/post/1",
            "the page the plan names is the page that would be opened, and it is not the \
             readiness route"
        );
        assert_eq!(
            asked.readiness,
            Some(Endpoint::loopback(5173, "/health").expect("the fixture's endpoint")),
            "the service is held to the question the plan names, which is a different endpoint \
             from the page"
        );
        assert_eq!(
            asked.expectation, "the post page shows the first post",
            "what the observation is for travels with it, because that is what a reader is told \
             the look was looking for"
        );
        assert_eq!(asked.program, OsString::from(ADMITTED_PROGRAM));
        assert_eq!(
            asked.arguments,
            vec![OsString::from("-m"), OsString::from("pytest")],
            "the service's own program and argument vector are what the enforcement admitted"
        );
        assert_eq!(
            asked.working_directory,
            std::env::temp_dir().join("sure-fixture-service"),
            "the directory is the plan's"
        );
        assert_eq!(
            asked.environment,
            crate::process::Environment::only([
                (OsString::from("PATH"), OsString::from("/fixture/bin")),
                (OsString::from("PORT"), OsString::from("5173")),
            ]),
            "**the environment a browser check's service is given is the plan's own field too** \
             — the same rule `P18-T009` holds for a service check, and the browser door is not a \
             way round it"
        );
        assert_eq!(
            asked.window,
            Duration::from_secs(7),
            "the window is the plan's, and it bounds the service rather than the look"
        );
        assert!(
            runner.asked().is_empty(),
            "a browser check is not carried out by the command runner, whatever its service's \
             command is"
        );
        assert!(
            runner.services().is_empty(),
            "**and it is not carried out by the service runner either**: a browser check that \
             reached the service door would run the service, ask it its readiness question and \
             stop it, and no page would ever be opened"
        );
        assert_eq!(
            status_of(&results, "browsed"),
            CheckStatus::Pass,
            "the result is the one the browser runner reported for this check"
        );
    }

    #[test]
    fn a_browser_the_runner_failed_is_not_reported_as_a_pass_by_the_wiring() {
        let fingerprint = FingerprintId::generate();
        // The verdict itself is `browser::Report::status`'s and is measured in
        // `tests/browser_driver.rs` and `tests/browser_probe.rs`, over the real
        // adapter. What this measures is the other half — that the browser door
        // hands back the answer it was given. A wiring that laundered a `Fail`
        // into a `Pass` would be the false green this repository treats as worse
        // than an error, and a fixture whose fake answered a pass could not tell
        // the two apart. The service half is told to pass in the same run, so the
        // failing status can only have come from the page's own door.
        let schedule = browser_schedule(work(
            "browsed",
            "a page that reported a console error",
            ActionKind::BrowserProbe,
            a_browser_with_its_own_page(),
        ));
        let plan = permission_plan(
            &fingerprint,
            &[("browsed", ADMITTED_PROGRAM, &ADMITTED_ARGUMENTS)],
        );
        let enforcement = enforcement_of(&schedule, plan);
        let runner = FakeRunner::succeeding()
            .answering_services_with(CheckStatus::Pass)
            .answering_pages_with(CheckStatus::Fail);

        let results = run_scheduled_checks(&schedule, &enforcement, &fingerprint, &runner)
            .expect("nothing in this plan is ambiguous");

        assert_eq!(
            status_of(&results, "browsed"),
            CheckStatus::Fail,
            "the page's own verdict is the check's verdict, and the wiring did not soften it"
        );
        assert!(
            results
                .get(&check_id("browsed"))
                .expect("reported")
                .blocks_green(),
            "a failing browser check keeps the run out of green"
        );
    }

    // ---- the browser door: the un-wiring property, on the real runner --------

    #[test]
    fn a_browser_check_with_no_driver_is_an_error_and_opens_nothing() {
        let fingerprint = FingerprintId::generate();
        // **The property this file existed to hold before `P18-T010`, held after
        // it.** A browser check used to be answered with *this build has no
        // runner for that kind of work*; the mechanism is a driver now, and the
        // thing being protected is not the sentence. Delete the one
        // `.with_page_driver(…)` call at the composition root and this is what
        // a run must say — an `Error`, never a pass and never a quiet skip.
        //
        // The runner is the **real** [`ProcessRunner`] rather than a fake, because
        // this is the one browser test whose subject is what the product's own
        // implementation does. It starts nothing either way: the token is
        // cancelled before the run, so even a regression that reached
        // `StartSmoke` would be refused by the supervisor before spawning, and the
        // assertion below would catch it because a cancelled run's own sentence is
        // a different one.
        let schedule = browser_schedule(work(
            "browsed",
            "a page this run was given no driver for",
            ActionKind::BrowserProbe,
            a_browser_with_its_own_page(),
        ));
        let plan = permission_plan(
            &fingerprint,
            &[("browsed", ADMITTED_PROGRAM, &ADMITTED_ARGUMENTS)],
        );
        let enforcement = enforcement_of(&schedule, plan);
        let stop = Cancellation::new();
        stop.cancel();
        let runner = ProcessRunner::new(stop);

        let results = run_scheduled_checks(&schedule, &enforcement, &fingerprint, &runner)
            .expect("a kind of work this runner cannot carry out is a result");

        assert_eq!(results.len(), 1, "the check is a row and not an absence");
        let result = results.get(&check_id("browsed")).expect("reported");
        assert_eq!(result.status, CheckStatus::Error);
        assert!(
            result.blocks_green(),
            "a critical browser check that could not be carried out must keep the run out of green"
        );
        assert!(
            result
                .reason
                .contains("SURE was not given a browser driver"),
            "the reason says what was missing: {}",
            result.reason
        );
        assert!(
            result
                .reason
                .contains("a page served on loopback, read by a browser"),
            "and it still names the work SURE could not do, which is the half of the sentence a \
             reader acts on: {}",
            result.reason
        );
        assert!(
            !result.reason.contains("cancelled"),
            "the run was cancelled before it started, and a reason that says so is a reason from \
             a path this check did not take — which would mean the driver check was not the first \
             thing this runner did: {}",
            result.reason
        );
    }

    // ---- the service door: what may reach it, and with what environment ------

    #[test]
    fn a_service_check_that_is_admitted_reaches_the_service_runner() {
        let fingerprint = FingerprintId::generate();
        // Every field of this spec differs from a default: the directory is not
        // the temp directory, the environment is not SURE's own, the window is
        // not the one the other service fixture uses, and the readiness names an
        // endpoint. So an assertion below can only pass if the value came from
        // the plan.
        let schedule = schedule_of([work(
            "served",
            "the project's server",
            ActionKind::LocalProbe,
            a_planned_service(),
        )]);
        let plan = permission_plan(
            &fingerprint,
            &[("served", ADMITTED_PROGRAM, &ADMITTED_ARGUMENTS)],
        );
        let enforcement = enforcement_of(&schedule, plan);
        let runner = FakeRunner::succeeding();

        let results = run_scheduled_checks(&schedule, &enforcement, &fingerprint, &runner)
            .expect("nothing in this plan is ambiguous");

        let services = runner.services();
        assert_eq!(
            services.len(),
            1,
            "one service reached the service runner, found: {services:?}"
        );
        let asked = &services[0];
        assert_eq!(
            asked.id,
            check_id("served"),
            "and it is this check's service"
        );
        assert_eq!(asked.program, OsString::from(ADMITTED_PROGRAM));
        assert_eq!(
            asked.arguments,
            vec![OsString::from("-m"), OsString::from("pytest")],
            "the argument vector arrives as elements, the way the admission decided it"
        );
        assert_eq!(
            asked.working_directory,
            std::env::temp_dir().join("sure-fixture-service"),
            "the directory is the plan's, not one the runner chose"
        );
        assert_eq!(
            asked.environment,
            crate::process::Environment::only([
                (OsString::from("PATH"), OsString::from("/fixture/bin")),
                (OsString::from("PORT"), OsString::from("5173")),
            ]),
            "**the environment a service is given is the plan's own field** — not SURE's own \
             environment, and not a default discovered here"
        );
        assert_eq!(
            asked.window,
            Duration::from_secs(7),
            "the window is the plan's, and it is the window and not the process budget: the \
             fixture's two durations differ"
        );
        assert_eq!(
            asked.endpoint,
            Some(Endpoint::loopback(5173, "/health").expect("the fixture's endpoint")),
            "the question is sent where the plan says it is sent"
        );
        assert!(
            runner.asked().is_empty(),
            "a service is not carried out by the command runner, whatever its command is"
        );
        assert_eq!(
            status_of(&results, "served"),
            CheckStatus::Pass,
            "the result is the one the service runner reported for this check"
        );
    }

    #[test]
    fn a_service_the_runner_failed_is_not_reported_as_a_pass_by_the_wiring() {
        let fingerprint = FingerprintId::generate();
        // The verdict itself is `runtime_start`'s and is measured there, with real
        // processes: a service that ended inside its window fails. What this
        // measures is the other half — that the wiring hands back the answer it
        // was given. A wiring that laundered a `Fail` into a `Pass` would be the
        // false green this repository treats as worse than an error, and a fixture
        // whose fake answered a pass could not tell the two apart.
        let schedule = schedule_of([work(
            "dead",
            "a service that ended during its window",
            ActionKind::LocalProbe,
            a_planned_service(),
        )]);
        let plan = permission_plan(
            &fingerprint,
            &[("dead", ADMITTED_PROGRAM, &ADMITTED_ARGUMENTS)],
        );
        let enforcement = enforcement_of(&schedule, plan);
        let runner = FakeRunner::succeeding().answering_services_with(CheckStatus::Fail);

        let results = run_scheduled_checks(&schedule, &enforcement, &fingerprint, &runner)
            .expect("nothing in this plan is ambiguous");

        let result = results.get(&check_id("dead")).expect("reported");
        assert_eq!(result.id, check_id("dead"), "the result is this check's");
        assert_eq!(
            result.status,
            CheckStatus::Fail,
            "a service the runner reported as failed is a failed check and not a pass"
        );
        assert!(
            result.blocks_green(),
            "the check is critical, so failing it stops a green verdict"
        );
    }

    #[test]
    fn a_service_the_mode_did_not_admit_keeps_the_commands_own_stopping() {
        let fingerprint = FingerprintId::generate();
        // The same shape as the command door's own test: both checks may run as
        // far as the plan is concerned, and one of them holds a program the
        // classifier does not know, which is the whole of the difference.
        let refused = CommandSpec::new(
            "frobnicate",
            std::env::temp_dir(),
            crate::process::Environment::inherited(),
            crate::process::Limits::new(Duration::from_secs(30), 1024, 2048),
        )
        .with_arguments(["--serve"]);
        let schedule = schedule_of([
            work(
                "admitted",
                "the project's server",
                ActionKind::LocalProbe,
                a_planned_service(),
            ),
            work(
                "unadmitted",
                "a service the mode will not start",
                ActionKind::LocalProbe,
                CheckOperation::Service(ServiceCheckSpec::new(
                    refused,
                    Readiness::StaysUp,
                    Duration::from_secs(5),
                )),
            ),
        ]);
        let plan = permission_plan(
            &fingerprint,
            &[
                ("admitted", ADMITTED_PROGRAM, &ADMITTED_ARGUMENTS),
                ("unadmitted", "frobnicate", &["--serve"]),
            ],
        );
        let enforcement = enforcement_of(&schedule, plan);
        assert_eq!(
            enforcement.stopped().len(),
            1,
            "the enforcement stopped exactly the service it did not admit"
        );
        let runner = FakeRunner::succeeding();

        let results = run_scheduled_checks(&schedule, &enforcement, &fingerprint, &runner)
            .expect("a stopped service is a result and not a refusal");

        assert_eq!(
            status_of(&results, "unadmitted"),
            CheckStatus::Skipped,
            "the service whose command was not admitted keeps the command's own stopping"
        );
        assert!(
            results
                .get(&check_id("unadmitted"))
                .expect("reported")
                .not_checked_reason
                .is_some(),
            "and the stopping carries the enforcement's own reason for it; which reason is the \
             command door's question and is asserted there"
        );
        let services = runner.services();
        assert_eq!(
            services.len(),
            1,
            "only the admitted service reached the service runner, found: {services:?}"
        );
        assert_eq!(services[0].id, check_id("admitted"));
        assert_eq!(
            status_of(&results, "admitted"),
            CheckStatus::Pass,
            "and the one that was admitted is the one that was carried out"
        );
    }

    #[test]
    fn a_service_whose_window_cannot_close_is_an_error_and_starts_nothing() {
        let fingerprint = FingerprintId::generate();
        // The window is three times the service's own budget, so the service
        // would be stopped by its deadline before the window ever closed and SURE
        // would never ask its question. `runtime_start` refuses that pairing
        // rather than rounding it, and this door has to turn the refusal into a
        // result rather than into a missing row.
        //
        // This is the one test here that uses the real runner, and it can: the
        // refusal happens **before** anything could start. `StartSmoke::planned`
        // returns the error and `StartSmoke::run` — the one function in that
        // module that starts a process — is never reached. The cancellation handed
        // in is already cancelled as well, so even a regression that got as far as
        // a start would start nothing.
        let endless = CommandSpec::new(
            ADMITTED_PROGRAM,
            std::env::temp_dir(),
            crate::process::Environment::inherited(),
            crate::process::Limits::new(Duration::from_secs(10), 1024, 2048),
        )
        .with_arguments(ADMITTED_ARGUMENTS);
        let schedule = schedule_of([work(
            "endless",
            "a service whose window cannot close",
            ActionKind::LocalProbe,
            CheckOperation::Service(ServiceCheckSpec::new(
                endless,
                Readiness::StaysUp,
                Duration::from_secs(30),
            )),
        )]);
        let plan = permission_plan(
            &fingerprint,
            &[("endless", ADMITTED_PROGRAM, &ADMITTED_ARGUMENTS)],
        );
        let enforcement = enforcement_of(&schedule, plan);
        let admitted = enforcement
            .admitted()
            .next()
            .expect("the fixture's mode admits one command");
        let scheduled = schedule.get(&check_id("endless")).expect("scheduled");
        let service = AdmittedService::new(scheduled, admitted, &fingerprint)
            .expect("the plan and the enforcement agree about this command");
        let stop = Cancellation::new();
        stop.cancel();

        let result = ProcessRunner::new(stop).run_service(&service);

        assert_eq!(
            result.id,
            check_id("endless"),
            "the result is the check's own"
        );
        assert_eq!(
            result.status,
            CheckStatus::Error,
            "a service that could never be asked its question is an error, never a pass"
        );
        assert!(result.blocks_green());
        assert!(
            result.reason.contains("startup window"),
            "the reason is the refusal's own words: {}",
            result.reason
        );
    }

    #[test]
    fn the_service_door_refuses_the_same_three_pairings_the_command_door_does() {
        let fingerprint = FingerprintId::generate();
        let schedule = schedule_of([
            work(
                "mine",
                "a service",
                ActionKind::LocalProbe,
                a_planned_service(),
            ),
            work(
                "theirs",
                "another service",
                ActionKind::LocalProbe,
                a_planned_service(),
            ),
            work(
                "command",
                "a check that runs one command",
                ActionKind::RunTests,
                runs_the_admitted_command(),
            ),
            work(
                "differs",
                "a service whose command and admission disagree",
                ActionKind::LocalProbe,
                a_planned_service(),
            ),
        ]);
        // The last entry is the same program with one more argument: the case a
        // comparison of rendered command lines would let through.
        let plan = permission_plan(
            &fingerprint,
            &[
                ("mine", ADMITTED_PROGRAM, &ADMITTED_ARGUMENTS),
                ("theirs", ADMITTED_PROGRAM, &ADMITTED_ARGUMENTS),
                ("command", ADMITTED_PROGRAM, &ADMITTED_ARGUMENTS),
                ("differs", ADMITTED_PROGRAM, &["-m", "pytest", "-x"]),
            ],
        );
        let enforcement = enforcement_of(&schedule, plan);
        let admitted: BTreeMap<&CheckId, AdmittedCommand<'_>> = enforcement
            .admitted()
            .map(|command| (command.command().check().id(), command))
            .collect();

        // The pairing that really is one service.
        let mine = schedule.get(&check_id("mine")).expect("scheduled");
        let pair = AdmittedService::new(mine, admitted[&check_id("mine")], &fingerprint)
            .expect("the plan and the enforcement agree about this command");
        assert_eq!(pair.check(), &check_id("mine"));
        assert_eq!(pair.service().window(), Duration::from_secs(7));

        // The same admission, paired with another check's service.
        let theirs = schedule.get(&check_id("theirs")).expect("scheduled");
        let refused = AdmittedService::new(theirs, admitted[&check_id("mine")], &fingerprint)
            .expect_err("an admission is about one check");
        assert_eq!(
            refused,
            AdmissionRefused::ForADifferentCheck {
                id: check_id("theirs"),
                admitted_for: check_id("mine"),
            }
        );

        // An admission paired with work that is not a service at all.
        let command = schedule.get(&check_id("command")).expect("scheduled");
        let refused = AdmittedService::new(command, admitted[&check_id("command")], &fingerprint)
            .expect_err("one command once is not a service");
        assert_eq!(
            refused,
            AdmissionRefused::NotOneService {
                id: check_id("command"),
                work: "one command, once, under a deadline",
            }
        );

        // And the same program with a different argument vector.
        let differs = schedule.get(&check_id("differs")).expect("scheduled");
        match AdmittedService::new(differs, admitted[&check_id("differs")], &fingerprint)
            .expect_err("the decision was about a different argument vector")
        {
            AdmissionRefused::NotTheCommandThatWasAdmitted {
                id,
                planned,
                admitted,
            } => {
                assert_eq!(id, check_id("differs"));
                assert_eq!(planned, "python -m pytest");
                assert_eq!(admitted, "python -m pytest -x");
            }
            other => panic!("the refusal names the wrong reason: {other}"),
        }
    }

    #[test]
    fn the_browser_door_refuses_the_same_three_pairings_the_other_doors_do() {
        let fingerprint = FingerprintId::generate();
        let schedule = schedule_of([
            work(
                "mine",
                "a page on my service",
                ActionKind::BrowserProbe,
                a_browser(),
            ),
            work(
                "theirs",
                "a page on another service",
                ActionKind::BrowserProbe,
                a_browser(),
            ),
            work(
                "service",
                "a service with no page",
                ActionKind::LocalProbe,
                a_planned_service(),
            ),
            work(
                "differs",
                "a page whose service's command and admission disagree",
                ActionKind::BrowserProbe,
                a_browser(),
            ),
        ]);
        // The last entry is the same program with one more argument: the case a
        // comparison of rendered command lines would let through, and for a
        // browser check it is the *service's* command that is compared — the page
        // is a path and an expectation, and neither is something the enforcement
        // decided about.
        let plan = permission_plan(
            &fingerprint,
            &[
                ("mine", ADMITTED_PROGRAM, &ADMITTED_ARGUMENTS),
                ("theirs", ADMITTED_PROGRAM, &ADMITTED_ARGUMENTS),
                ("service", ADMITTED_PROGRAM, &ADMITTED_ARGUMENTS),
                ("differs", ADMITTED_PROGRAM, &["-m", "pytest", "-x"]),
            ],
        );
        let enforcement = enforcement_of(&schedule, plan);
        let admitted: BTreeMap<&CheckId, AdmittedCommand<'_>> = enforcement
            .admitted()
            .map(|command| (command.command().check().id(), command))
            .collect();

        // The pairing that really is one browser check.
        let mine = schedule.get(&check_id("mine")).expect("scheduled");
        let pair = AdmittedBrowser::new(mine, admitted[&check_id("mine")], &fingerprint)
            .expect("the plan and the enforcement agree about this service's command");
        assert_eq!(pair.check(), &check_id("mine"));
        assert_eq!(
            pair.browser().path(),
            "/",
            "the page travels with the pair, which is the half the enforcement has no opinion \
             about"
        );
        assert_eq!(
            pair.work_description(),
            "a page served on loopback, read by a browser"
        );

        // The same admission, paired with another check's page.
        let theirs = schedule.get(&check_id("theirs")).expect("scheduled");
        let refused = AdmittedBrowser::new(theirs, admitted[&check_id("mine")], &fingerprint)
            .expect_err("an admission is about one check");
        assert_eq!(
            refused,
            AdmissionRefused::ForADifferentCheck {
                id: check_id("theirs"),
                admitted_for: check_id("mine"),
            }
        );

        // An admission paired with work that opens no page at all — and this is
        // the refusal a browser check needed its own door for. A service and a
        // browser check hold the *same kind of command*, so a door that keyed on
        // the command alone would carry a service out as a page.
        let service = schedule.get(&check_id("service")).expect("scheduled");
        let refused = AdmittedBrowser::new(service, admitted[&check_id("service")], &fingerprint)
            .expect_err("a service is asked one question and no page is opened");
        assert_eq!(
            refused,
            AdmissionRefused::NotOneBrowser {
                id: check_id("service"),
                work: "started, asked one question, and stopped",
            }
        );

        // And the same program with a different argument vector.
        let differs = schedule.get(&check_id("differs")).expect("scheduled");
        match AdmittedBrowser::new(differs, admitted[&check_id("differs")], &fingerprint)
            .expect_err("the decision was about a different argument vector")
        {
            AdmissionRefused::NotTheCommandThatWasAdmitted {
                id,
                planned,
                admitted,
            } => {
                assert_eq!(id, check_id("differs"));
                assert_eq!(planned, "python -m pytest");
                assert_eq!(admitted, "python -m pytest -x");
            }
            other => panic!("the refusal names the wrong reason: {other}"),
        }
    }

    #[test]
    fn a_permission_the_mode_did_not_grant_keeps_a_check_from_the_runner() {
        let fingerprint = FingerprintId::generate();
        // The action needs a permission this mode does not grant, so the plan
        // itself refuses the check: it never reaches a decision about a command.
        let (mode, permissions) = (
            ExecutionMode::InspectOnly,
            ExecutionPermissions::inspect_only(),
        );
        let mut builder = PlanBuilder::new(mode, permissions);
        builder
            .propose(work(
                "networked",
                "a check the mode will not run",
                ActionKind::NetworkAccess,
                a_command("git", &["fetch"]),
            ))
            .expect("the proposal is well formed");
        let schedule = builder.build();
        let plan = permission_plan(&fingerprint, &[("networked", "git", &["fetch"])]);
        let enforcement = enforcement_of(&schedule, plan);
        let runner = FakeRunner::succeeding();

        let results = run_scheduled_checks(&schedule, &enforcement, &fingerprint, &runner)
            .expect("the plan's own refusal is a result and not a failure");

        assert_eq!(status_of(&results, "networked"), CheckStatus::Skipped);
        assert_eq!(
            results
                .get(&check_id("networked"))
                .map(|result| result.not_checked_reason),
            Some(Some(NotCheckedReason::ExecutionNotAuthorized))
        );
        assert!(
            runner.asked().is_empty(),
            "a check the plan refused is not carried out, whatever command it holds"
        );
    }
}
