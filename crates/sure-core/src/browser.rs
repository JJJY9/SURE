//! What SURE asks a browser to do, and the one place a browser's answer becomes
//! a verdict.
//!
//! `P3-T011` acceptance: *"Browser unavailable => skipped/unknown."* /
//! *"Browser automation is isolated from core verdict semantics."*
//!
//! # The seam, and what a driver is not allowed to say
//!
//! [`BrowserDriver`] is the interface. A driver is whatever can drive a real
//! browser — a Playwright installation, a Puppeteer script, something this build
//! has never heard of — and it implements one method, which returns a
//! [`Report`].
//!
//! **A [`Report`] is an [`Absence`] or an [`Observation`], and neither is a
//! verdict.** Neither type contains a [`CheckStatus`], neither contains a
//! [`CheckResult`], and the trait's signature gives a driver no way to return
//! either: the only thing a driver can produce is *what it saw*. The one place a
//! browser's answer becomes a verdict is [`Report::verdict`], and the one place
//! the status behind it is decided is [`Report::status`]. Nothing else in this
//! file returns either type, and `tests/browser_probe.rs` counts that rather
//! than trusting it.
//!
//! ```text
//! BrowserDriver::observe  ->  Report  ->  Report::status      ->  CheckStatus
//!                                 \-->  Report::verdict      ->  CheckResult
//! ```
//!
//! **What this does not claim.** The interface keeps a driver from *spelling* a
//! verdict; it does not keep a driver from being wrong. A driver that reports
//! `complete: true` and no problems has said something false about a page that
//! threw, and nothing here can tell. What is enforced is the direction that
//! matters: **a driver cannot hand SURE a status, so no driver can put a green
//! in a report by asking for one.** The observations are still the driver's to
//! get wrong, and the way SURE finds that out is a second driver, not this
//! module.
//!
//! # Absence is a value, and it is the first acceptance sentence
//!
//! A browser that is not installed is not a failure of the project and not a
//! pass for it. [`Report::absent`] carries an [`Absence`], [`AbsenceReason`] maps
//! one-to-one onto the frozen [`NotCheckedReason`], and **every one of the five
//! reasons is `skipped`** — never a pass, and never a `fail` about code that was
//! never run. The mapping is total and it is checked over
//! [`AbsenceReason::ALL`], because a sixth reason added later that quietly landed
//! on a `pass` is exactly the shape of defect this repository is built against.
//!
//! **A missing browser is not a scope limit, and the difference is what a
//! report does with it.** Four of the five reasons map to a
//! [`NotCheckedReason`] whose
//! [`is_scope_limit`](NotCheckedReason::is_scope_limit) is false, so a *critical*
//! browser check that could not run **blocks green** rather than politely
//! disappearing. That is the deliberate reading of "unavailable => skipped": the
//! check did not happen, and a project whose interface was never looked at is
//! not a project SURE has checked.
//!
//! **The fifth reason is the project switching the check off**, and what that
//! buys is smaller than it sounds. It stops the check *blocking* the run, and it
//! does not make the run green: the frozen [`aggregate`](sure_domain::status::aggregate)
//! keeps an out-of-scope critical check visible, so the run lands on
//! *needs attention* and the report still says the interface was not looked at.
//! A user who wants the browser check off is entitled to say so; they are not
//! entitled to be told their interface was fine.
//!
//! [`absence`] is the part of that SURE decides by itself — the project switched
//! the check off, or the permission to reach a service was never granted — and
//! it is a function here rather than a rule each caller re-implements, because
//! two callers ordering those two questions differently would report two
//! different reasons for one situation.
//!
//! # The false green this module is arranged against
//!
//! **A browser that was stopped early has not seen the whole page, so it has not
//! seen the absence of errors either.** An [`Observation`] carries `complete`,
//! and an incomplete look that reported no problems is
//! [`CheckStatus::Unknown`] — not a pass. It is the distinction
//! [`ProbeOutcome::NoAnswer`](crate::probe::ProbeOutcome::NoAnswer) draws one
//! module over, where a connection that was accepted and said nothing is
//! `Unknown` rather than a pass, and it is the single most likely way for a
//! browser check to lie: every driver that runs out of time reports "no errors
//! found".
//!
//! **A pass here says one narrow thing**: this address was opened, the page
//! reached, and nothing was reported wrong before the look ended. It does not
//! say the interface works, that it looks right, that a user can do anything
//! with it, or that the thing the project claims is present is present. **A
//! title is the line a reader skims**, so the title is exactly
//! `browser probe: <address>` — the words name the instrument and the address
//! names what was looked at, and a test asserts that string exactly rather than
//! asserting the absence of words a later edit could reintroduce.
//!
//! # What is missing, and what arrived
//!
//! **No driver is implemented here, and this module starts no browser.** Finding
//! one, launching it and driving it is the adapter, which is
//! [`crate::browser_driver`]; this module is the interface that adapter
//! implements and the mapping its answers go through. Nothing here builds a
//! [`std::process::Command`], so the file this one names in the spawn census is
//! the adapter's launcher and not this one.
//!
//! **The product builds one since `P18-T010`, and that is the change to read
//! here.** [`Driver`] is the name the runner holds a driver by, and the file
//! that *constructs* one is `sure-cli/src/check.rs` — the composition root,
//! where `sure check` binds every implementation the product uses — which hands
//! a `browser_driver::Browser` to
//! [`ProcessRunner`](crate::planned_check_runner::ProcessRunner). A browser
//! check that reaches the runner now opens a page, so the census rule in
//! `tests/browser_probe.rs` that reads *a shipped file outside the adapter has
//! begun naming it* is answered by that file being outside the tree the rule
//! walks rather than by the absence it used to record.
//!
//! **`support::CEILING` did not move with it, and the reason is not this
//! module's.** The ceiling's reason is the platform argument `P18-T007` wrote
//! beside it, re-read on 2026-10-22: a Node check whose only program on the
//! machine is `npm.cmd` still comes back `InterpreterRequired`, but the product
//! runner now starts the known package-manager shims through their own
//! JavaScript entry (`crate::package_launcher`), so that case is reachable
//! rather than stopped. A Rust project's declared check now completes in the
//! tracked CLI test `finished_declared_check.rs` on all three CI legs, and
//! `docs/adr/0015-support-ceiling-evidence.md`'s amendment records why moving
//! the constant is now a separate open decision rather than a reading this
//! module can take. A new caller is not evidence about which platforms SURE has
//! been shown to run project code on, and the paragraph beside the ceiling is
//! where that argument lives.
//!
//! **The loopback rule is [`Endpoint`]'s**, and it is reused rather than
//! restated — see [`Target`]. A browser will navigate to the internet happily,
//! which is why the subject of a check is a type and not a `String`.

use std::fmt;

use sure_domain::evidence::EvidenceClass;
use sure_domain::execution::{ActionKind, ExecutionDecision, ExecutionMode, ExecutionPermissions};
use sure_domain::ids::{CheckId, FingerprintId};
use sure_domain::severity::Severity;
use sure_domain::status::{CheckResult, CheckStatus, NotCheckedReason};
use sure_domain::variants::variants;

use crate::config::CheckPreference;
use crate::probe::{Endpoint, EndpointError};

/// How many problems a reason line quotes before it stops and counts the rest.
///
/// A page that throws in a loop produces thousands, and a report line is not the
/// place for them. Three is enough for a reader to recognise the failure, and
/// the count of the remainder is carried rather than the remainder itself.
///
/// This is not [`Limits::problems_kept`], which is how many the driver was asked
/// to keep. A driver that kept a hundred problems gets a hundred counted in the
/// reason line and three of them quoted.
pub const QUOTED_PROBLEMS: usize = 3;

/// Whether a response status is one the browser could show the page from.
///
/// **This is the local probe's window, restated.** `ProbeOutcome::status` in
/// `probe.rs` treats 200 to 399 as a pass and everything else the service
/// answered with as a failure, and a browser check that disagreed with it about
/// the same number would be two answers to one question. The two are separate
/// spellings rather than one function — the probe's is a guard on an enum
/// variant and this one is a question about a number a driver reported — so what
/// ties them together is
/// `tests/browser_probe.rs::the_page_status_window_is_the_local_probes_window`,
/// which sweeps every status from 100 to 599 asserting the two agree.
///
/// A `const fn` because the probe's guard is one, and clippy reads
/// `status >= 200 && status < 400` as a hand-written `(200..400).contains` in
/// any other context — the same two comparisons, spelled the same way in both
/// files, is the version a reader can compare.
#[must_use]
pub const fn a_page_could_be_shown(status: u16) -> bool {
    status >= 200 && status < 400
}

/// The local address a browser is asked to open.
///
/// # Why this is not a `String`
///
/// A URL built from a string can name `https://example.com`, and a browser will
/// go there. That would make a browser check an
/// [`ActionKind::ExternalService`](sure_domain::execution::ActionKind::ExternalService)
/// reaching a machine that is not this one, under a permission SURE asked for on
/// the understanding that the target was local.
///
/// So the subject is built from an address and a path, the address must be
/// loopback, and the path must be writable into a request target. **Both rules
/// are [`Endpoint`]'s** — the same constructor the local probe uses — rather
/// than a second copy of them here, because two copies of a refusal rule are two
/// rules the day one of them is changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target(Endpoint);

impl Target {
    /// `127.0.0.1` on `port`, opening `path`.
    ///
    /// # Errors
    ///
    /// [`EndpointError::UnsafePath`] if `path` is not something that may be
    /// written into a request target.
    pub fn local(port: u16, path: impl Into<String>) -> Result<Self, EndpointError> {
        Endpoint::loopback(port, path).map(Self)
    }

    /// `address` on `port`, opening `path`.
    ///
    /// # Errors
    ///
    /// [`EndpointError::NotLoopback`] if `address` is not on this machine, and
    /// [`EndpointError::UnsafePath`] as above.
    pub fn at(
        address: std::net::IpAddr,
        port: u16,
        path: impl Into<String>,
    ) -> Result<Self, EndpointError> {
        Endpoint::at(address, port, path).map(Self)
    }

    /// The address and path, as the endpoint this target opens.
    #[must_use]
    pub const fn endpoint(&self) -> &Endpoint {
        &self.0
    }

    /// The URL a driver navigates to, which is `http://` and cannot be anything
    /// else: the address is loopback and the scheme is not a parameter.
    #[must_use]
    pub fn url(&self) -> String {
        self.0.to_string()
    }
}

impl fmt::Display for Target {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.0)
    }
}

/// What one browser look is allowed to spend.
///
/// The same shape as [`crate::probe::Limits`] and [`crate::process::Limits`] one
/// and two modules over, and for the same reason: a caller that has not chosen a
/// bound has not decided what the check is allowed to cost.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    timeout: std::time::Duration,
    problems_kept: usize,
}

impl Limits {
    /// A look that may spend `timeout` and hold up to `problems_kept` problems.
    ///
    /// # Errors
    ///
    /// [`LimitsError::ZeroTimeout`] if `timeout` is zero, and
    /// [`LimitsError::NoRoomForProblems`] if `problems_kept` is zero.
    ///
    /// **A zero timeout is refused rather than rounded up**, and the reason is
    /// the one [`crate::probe`] gives for the same refusal: a look allowed no
    /// time at all can only come back reporting that it saw nothing, and whether
    /// that reads as *nothing was wrong* or as *nothing was looked at* would
    /// then depend on a driver setting `complete` honestly. Refusing the budget
    /// removes the question instead of relying on the answer to it.
    ///
    /// **A zero problem bound is refused for a smaller reason**: the bound is
    /// what keeps a page that throws in a loop from filling a report, and a
    /// caller asking for none has not asked for a look whose result can be
    /// described.
    pub fn new(timeout: std::time::Duration, problems_kept: usize) -> Result<Self, LimitsError> {
        if timeout.is_zero() {
            return Err(LimitsError::ZeroTimeout);
        }
        if problems_kept == 0 {
            return Err(LimitsError::NoRoomForProblems);
        }
        Ok(Self {
            timeout,
            problems_kept,
        })
    }

    /// The whole-life budget of one look, navigation included.
    #[must_use]
    pub const fn timeout(&self) -> std::time::Duration {
        self.timeout
    }

    /// How many problems the driver is asked to keep.
    #[must_use]
    pub const fn problems_kept(&self) -> usize {
        self.problems_kept
    }
}

/// Why a budget was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitsError {
    /// The look may spend no time.
    ZeroTimeout,
    /// The look may hold no problems.
    NoRoomForProblems,
}

impl fmt::Display for LimitsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroTimeout => formatter.write_str(
                "a browser look with no time at all can only report that it saw nothing, \
                 which is not a result",
            ),
            Self::NoRoomForProblems => formatter.write_str(
                "a browser look that may hold no problems cannot describe a page that has any",
            ),
        }
    }
}

impl std::error::Error for LimitsError {}

/// What a page did that a person would call wrong.
///
/// Every variant is an observation about the page and none is a verdict: a
/// console error in a project that expects it is still a console error, and
/// whether it makes the check fail is [`Report::status`]'s answer rather than
/// the driver's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProblemKind {
    /// The browser reported an error on the console.
    ConsoleError,
    /// An exception escaped to the page's top level.
    RuntimeError,
    /// A request the page made did not complete.
    FailedRequest,
    /// The address was asked for and the page never arrived.
    NavigationFailed,
}

variants!(ProblemKind {
    ConsoleError,
    RuntimeError,
    FailedRequest,
    NavigationFailed
});

impl ProblemKind {
    /// The stable name, as it appears in a reason line.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ConsoleError => "console error",
            Self::RuntimeError => "uncaught error",
            Self::FailedRequest => "failed request",
            Self::NavigationFailed => "could not open",
        }
    }
}

/// One thing the page did, with where it happened.
///
/// `source` and `line` are what makes this checkable by the person reading the
/// report: a message with no location is a claim they cannot go and look at.
/// **`line` is zero when the browser did not say**, and zero is not a line
/// number — it is the absence of one, and it is printed as an absence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Problem {
    /// What kind of thing went wrong.
    pub kind: ProblemKind,
    /// The message, as the browser wrote it.
    pub message: String,
    /// Where it came from: a script URL, a file, or the address itself.
    pub source: String,
    /// The line, or zero when the browser did not report one.
    pub line: u32,
}

impl Problem {
    /// A problem with the location the browser reported.
    #[must_use]
    pub fn new(
        kind: ProblemKind,
        message: impl Into<String>,
        source: impl Into<String>,
        line: u32,
    ) -> Self {
        Self {
            kind,
            message: message.into(),
            source: source.into(),
            line,
        }
    }

    /// One line a report can quote: what, and where.
    #[must_use]
    pub fn describe(&self) -> String {
        let where_it_happened = if self.line == 0 {
            format!("{} (no line reported)", self.source)
        } else {
            format!("{}:{}", self.source, self.line)
        };
        format!(
            "{}: {} — {where_it_happened}",
            self.kind.as_str(),
            self.message
        )
    }
}

/// What a driver saw when it opened the address.
///
/// **This is the whole vocabulary a driver has**, and it holds no verdict. The
/// fields are public because a driver builds this and SURE does not: a
/// constructor here would only be a second spelling of the same struct.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    /// Where the browser ended up, after any redirects. Empty if it never
    /// arrived anywhere.
    pub landing_url: String,
    /// The document title, or empty when there was none.
    pub title: String,
    /// What the HTTP response to the page request was, when the driver knows.
    ///
    /// # Why this is in the interface rather than left out
    ///
    /// **A 404 page renders and reports no errors.** A browser that loads one
    /// has a landing address, a title, an empty problem list and a complete
    /// look — every field that would otherwise add up to a pass, about a page
    /// that was never served. An interface without this field would leave a
    /// driver no way to say so, which means the mapping could not help but
    /// return green, and that is a false green written into a type rather than
    /// made by a mistake.
    ///
    /// **`None` is not a pass either.** A driver that did not report a status
    /// gets [`CheckStatus::Unknown`], for the same reason
    /// [`ProbeOutcome::NoAnswer`](crate::probe::ProbeOutcome::NoAnswer) is not a
    /// pass: a check whose whole content is *the page was opened* has
    /// established nothing when the opening's outcome is unknown. So a driver
    /// cannot reach green by staying silent, and does not have to lie to avoid
    /// it.
    ///
    /// The window this is judged by — 200 to 399 is a successful page load, and
    /// anything else the driver reports is not — is the local probe's, and
    /// `tests/browser_probe.rs` sweeps every status from 100 to 599 asserting the
    /// two agree rather than trusting that they still do.
    pub document_status: Option<u16>,
    /// What went wrong, in the order the browser reported it.
    pub problems: Vec<Problem>,
    /// Whether the look ran to the end of its budget.
    ///
    /// **False means the driver stopped early** — the budget expired, the
    /// browser died, the driver gave up — and the page was therefore not seen in
    /// full. An incomplete look that reported no problems is
    /// [`CheckStatus::Unknown`], because *I stopped looking* is not *there was
    /// nothing to find*.
    pub complete: bool,
}

impl Observation {
    /// Whether a page was reached at all.
    #[must_use]
    pub fn reached_a_page(&self) -> bool {
        !self.landing_url.trim().is_empty()
    }

    /// Everything the driver reported, as a bounded line a report can quote.
    #[must_use]
    pub fn problems_described(&self) -> String {
        let quoted: Vec<String> = self
            .problems
            .iter()
            .take(QUOTED_PROBLEMS)
            .map(Problem::describe)
            .collect();
        let rest = self.problems.len().saturating_sub(QUOTED_PROBLEMS);
        if rest == 0 {
            quoted.join("; ")
        } else {
            format!("{}; and {rest} more", quoted.join("; "))
        }
    }
}

/// Why no browser was driven.
///
/// **Five reasons, and none of them is about the project's code.** A browser
/// SURE could not drive says nothing about whether the interface works, which is
/// why every one of these is `skipped` rather than a `fail`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AbsenceReason {
    /// Nothing on this machine can drive a browser.
    NoDriverInstalled,
    /// A driver is installed and would not start.
    DriverWouldNotStart,
    /// The permission to connect to a service was not granted.
    PermissionNotGranted,
    /// The project switched the check off.
    DisabledByTheProject,
    /// SURE has no way to drive a browser on this operating system.
    UnsupportedPlatform,
}

variants!(AbsenceReason {
    NoDriverInstalled,
    DriverWouldNotStart,
    PermissionNotGranted,
    DisabledByTheProject,
    UnsupportedPlatform
});

impl AbsenceReason {
    /// The frozen reason this maps onto.
    ///
    /// **`NoDriverInstalled`, `DriverWouldNotStart` and `UnsupportedPlatform`
    /// all answer [`ToolUnavailable`](NotCheckedReason::ToolUnavailable), and
    /// that is not a loss of detail.** The domain value is what a report groups
    /// by, and all three are the same group: no way to drive a browser *here*.
    /// The difference survives in [`Absence::plain_explanation`], which is what
    /// the report prints, and in [`Absence::detail`], which is where a reader
    /// looks for the sentence the tool itself produced.
    ///
    /// **`UnsupportedPlatform` is deliberately not `UnsupportedStack`**, and the
    /// reason is what that variant does downstream: the domain defines
    /// `UnsupportedStack` as a scope limit, and a scope limit stops a critical
    /// check blocking the run. *This operating system is not one SURE can drive a
    /// browser on* is not a limit the user chose and not one the project's shape
    /// implies — the domain's own definition of a scope limit is *"that the user
    /// chose or that the project shape implies"*, and neither half holds — so it
    /// is a gap in what SURE could check and a critical check that hit it has to
    /// keep saying so. The user does have a way to stop the browser check
    /// holding their run back, and it is the one that says so out loud:
    /// `checks.browser_probe: never`, which answers
    /// [`DisabledByTheProject`](Self::DisabledByTheProject) and *is* a scope
    /// limit.
    #[must_use]
    pub const fn not_checked_reason(self) -> NotCheckedReason {
        match self {
            Self::NoDriverInstalled | Self::DriverWouldNotStart | Self::UnsupportedPlatform => {
                NotCheckedReason::ToolUnavailable
            }
            Self::PermissionNotGranted => NotCheckedReason::ExecutionNotAuthorized,
            Self::DisabledByTheProject => NotCheckedReason::DisabledByConfiguration,
        }
    }

    /// One sentence, in the product's plain language, for someone who is not a
    /// programmer.
    #[must_use]
    pub const fn plain_explanation(self) -> &'static str {
        match self {
            Self::NoDriverInstalled => {
                "Checking your interface in a real browser needs a browser tool on this computer, \
                 and there is not one."
            }
            Self::DriverWouldNotStart => {
                "The browser tool on this computer would not start, so your interface was not \
                 opened."
            }
            Self::PermissionNotGranted => {
                "You have not allowed SURE to connect to a service, so the browser was not \
                 opened."
            }
            Self::DisabledByTheProject => "This project's settings switch the browser check off.",
            Self::UnsupportedPlatform => {
                "SURE does not know how to open a browser on this kind of computer yet."
            }
        }
    }
}

/// The browser that was not driven, and what said so.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Absence {
    /// Which of the five situations this is.
    pub reason: AbsenceReason,
    /// What produced it, in the words of whatever produced it.
    ///
    /// For a driver that would not start this is the tool's own message, quoted
    /// rather than paraphrased, because SURE did not interpret it.
    pub detail: String,
}

impl Absence {
    /// An absence with the detail that produced it.
    #[must_use]
    pub fn new(reason: AbsenceReason, detail: impl Into<String>) -> Self {
        Self {
            reason,
            detail: detail.into(),
        }
    }

    /// The one line a report prints.
    #[must_use]
    pub fn plain_explanation(&self) -> String {
        if self.detail.trim().is_empty() {
            return self.reason.plain_explanation().to_owned();
        }
        format!("{} ({})", self.reason.plain_explanation(), self.detail)
    }
}

/// What asking a browser produced: an absence, or a look.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Report {
    /// No browser was driven.
    Absent(Absence),
    /// A browser was driven and this is what it saw.
    Observed(Observation),
}

impl Report {
    /// A report that no browser was driven.
    #[must_use]
    pub fn absent(reason: AbsenceReason, detail: impl Into<String>) -> Self {
        Self::Absent(Absence::new(reason, detail))
    }

    /// A report of what a browser saw.
    #[must_use]
    pub fn observed(observation: Observation) -> Self {
        Self::Observed(observation)
    }

    /// The status this report supports, without naming a check first.
    ///
    /// The mapping, in full, and the order of the rows is the rule:
    ///
    /// | report | status | why |
    /// | --- | --- | --- |
    /// | `Absent` | `skipped` | no browser was driven; that is not a fact about the project |
    /// | `Observed` with any problem | `fail` | something concrete was reported |
    /// | `Observed`, no problems, not complete | `unknown` | the look stopped early, so seeing nothing is not evidence of nothing |
    /// | `Observed`, no problems, complete, no page reached | `unknown` | nothing says a page was opened |
    /// | `Observed`, no problems, complete, landed, status 200–399 | `pass` | the page was served and reported nothing wrong |
    /// | `Observed`, no problems, complete, landed, status outside 200–399 | `fail` | the page request was answered and the answer was not a page |
    /// | `Observed`, no problems, complete, landed, no status reported | `unknown` | the opening's outcome is unknown, so nothing about the page was established |
    ///
    /// **The problem row comes before the completeness row on purpose.** A
    /// problem seen during a look that was cut short is a problem that was seen,
    /// and demoting it to `unknown` because the look did not finish would throw
    /// away the one concrete thing the driver came back with.
    ///
    /// **Three of the rows land on `unknown`, and they are one row here and
    /// three in [`Self::reason`].** *The look stopped early*, *nothing says a
    /// page was opened*, and *the driver did not say what came back* are
    /// different facts and they get different sentences; what they have in
    /// common is the thing that matters for a verdict — **none of them is
    /// evidence that nothing was wrong**, so none of them may pass. None is
    /// demoted to a `fail` either: SURE not knowing is not the project being
    /// wrong, and a `fail` is a statement about the project.
    #[must_use]
    pub fn status(&self) -> CheckStatus {
        match self {
            Self::Absent(_) => CheckStatus::Skipped,
            Self::Observed(observation) => {
                if !observation.problems.is_empty() {
                    CheckStatus::Fail
                } else if !observation.complete || !observation.reached_a_page() {
                    CheckStatus::Unknown
                } else {
                    match observation.document_status {
                        Some(status) if a_page_could_be_shown(status) => CheckStatus::Pass,
                        Some(_) => CheckStatus::Fail,
                        None => CheckStatus::Unknown,
                    }
                }
            }
        }
    }

    /// The narrow verdict this report supports.
    ///
    /// The status comes from [`Self::status`] and the reason line from
    /// [`Self::reason`], which run the same rows in the same order; this method
    /// chooses which [`CheckResult`] constructor those two imply and does not
    /// decide a verdict of its own.
    ///
    /// The title names what was observed, so nothing in the report reads as a
    /// claim about the interface: a pass here says *this address was opened,
    /// answered with a status in the 200–399 window, and reported nothing wrong
    /// before the look ended*. It says nothing about whether the interface works,
    /// whether it is usable, whether it looks right, or whether the thing the
    /// project claims is on the page is on the page.
    ///
    /// Every non-skipped row is [`EvidenceClass::ObservedFact`] — SURE asked a
    /// browser to open the address and read what it reported. The skipped row is
    /// [`EvidenceClass::Unknown`] and is not a parameter, because a check that
    /// did not run established nothing and offering a choice would only offer a
    /// way to write that down wrongly.
    #[must_use]
    pub fn verdict(
        &self,
        id: CheckId,
        target: &Target,
        severity: Severity,
        critical: bool,
        fingerprint: FingerprintId,
    ) -> CheckResult {
        let title = format!("browser probe: {}", target.url());
        match self {
            Self::Absent(absence) => CheckResult::not_run(
                id,
                title,
                severity,
                critical,
                absence.reason.not_checked_reason(),
                fingerprint,
            )
            .with_reason(absence.plain_explanation()),
            Self::Observed(_) => {
                let class = EvidenceClass::ObservedFact;
                let reason = self.reason();
                match self.status() {
                    CheckStatus::Pass => {
                        CheckResult::pass(id, title, severity, critical, class, fingerprint)
                            .with_reason(reason)
                    }
                    CheckStatus::Fail => {
                        CheckResult::fail(id, title, severity, critical, class, fingerprint)
                            .with_reason(reason)
                    }
                    CheckStatus::Unknown => {
                        CheckResult::unknown(id, title, severity, critical, class, fingerprint)
                            .with_reason(reason)
                    }
                    // `Absent` is the only route to `Skipped` and it is handled
                    // above, and `Error`/`Warning` are not statuses this mapping
                    // has. They are named rather than swallowed by `_` so that
                    // adding a variant to `CheckStatus` is a compile error in
                    // this file instead of a silent mis-mapping, and they are
                    // sent to `errored` because that is the mapping which
                    // refuses to let anything through as a pass.
                    CheckStatus::Skipped | CheckStatus::Error | CheckStatus::Warning => {
                        CheckResult::errored(id, title, severity, critical, reason, fingerprint)
                    }
                }
            }
        }
    }

    /// One line of plain language: what was seen, in the terms a report can
    /// quote.
    #[must_use]
    pub fn reason(&self) -> String {
        match self {
            Self::Absent(absence) => absence.plain_explanation(),
            Self::Observed(observation) => {
                // The branches below are in the same order as
                // [`Self::status`]'s, on purpose: a reason that explained a
                // different row from the one the verdict came from would be the
                // report contradicting itself in the one place a reader looks
                // first.
                if !observation.problems.is_empty() {
                    return format!(
                        "the page reported {} problem(s): {}",
                        observation.problems.len(),
                        observation.problems_described()
                    );
                }
                if !observation.complete {
                    return "the browser stopped before the page had finished, so seeing no \
                            problems is not evidence that there were none"
                        .to_owned();
                }
                if !observation.reached_a_page() {
                    return "the browser reported no problems and never said which page it \
                            opened, so nothing was established about the page"
                        .to_owned();
                }
                let title = if observation.title.trim().is_empty() {
                    "no title".to_owned()
                } else {
                    format!("title {:?}", observation.title)
                };
                match observation.document_status {
                    Some(status) if a_page_could_be_shown(status) => format!(
                        "{} was opened and answered HTTP {status}, and the page reported no \
                         console errors, no uncaught errors and no failed requests before the \
                         look ended ({title})",
                        observation.landing_url
                    ),
                    Some(status) => format!(
                        "the page request was answered with HTTP {status}, which is not a page \
                         the browser could show"
                    ),
                    None => "the browser reported no problems and did not say what the page \
                            request was answered with, so nothing was established about the page"
                        .to_owned(),
                }
            }
        }
    }
}

/// The interface a browser driver implements.
///
/// **One method, one return type, and no verdict in it.** [`observe`](Self::observe)
/// returns a [`Report`] — an [`Absence`] or an [`Observation`] — and neither
/// carries a [`CheckStatus`]. A driver decides *what the page did*; SURE decides
/// what that is worth, in [`Report::status`], and the two decisions are in
/// different files.
///
/// # What an implementation is expected to do
///
/// Open `target` in a real browser, watch it until `limits` is spent, and report
/// what happened. It must report `complete: false` when the budget ran out
/// before the page settled, and it must not report a page as clean because it
/// stopped looking — an [`Observation`] with no problems and `complete: false`
/// is [`CheckStatus::Unknown`], and a driver that sets `complete: true` to turn
/// that into a pass is the failure mode this interface cannot prevent and this
/// section exists to name.
///
/// It must report [`AbsenceReason::DriverWouldNotStart`] rather than panic when
/// it cannot start, and it must not report it because the *project's* page
/// failed: a page that throws is an [`Observation`] with problems in it.
///
/// # Object safety
///
/// The method takes no generic parameters and returns no `Self`, so
/// `Box<dyn BrowserDriver>` is a driver, which is what a caller holding one from
/// configuration needs.
pub trait BrowserDriver {
    /// Open `target` and report what the page did.
    fn observe(
        &self,
        target: &Target,
        limits: &Limits,
        cancellation: &crate::process::Cancellation,
    ) -> Report;
}

/// A driver a caller holds, named so that the caller does not have to.
///
/// **This is a name, not a mechanism, and it is here for one reason.** The
/// runner that carries a browser check out
/// ([`ProcessRunner`](crate::planned_check_runner::ProcessRunner)) has to hold a
/// driver and hand it a [`Target`], and the file it lives in is one of the
/// shipped files `tests/browser_probe.rs` walks. If it wrote
/// `Box<dyn BrowserDriver>` it would be a second file naming the interface,
/// which that census refuses — not out of tidiness but because *a file that
/// names the interface is a file with an opinion about how a browser is driven*,
/// and the point of the rule is that those opinions stay in one place. The alias
/// lets that file carry what it was handed without deciding what it is.
///
/// **It is not a way round the rule and it is not meant to read like one.** The
/// rule's real subject is a *capability*: since `P18-T010` something in the
/// product does construct a driver and open a page, which is why
/// `sure-cli/src/check.rs` — the composition root, where `sure check` binds
/// every implementation the product uses — is the file that builds a
/// `browser_driver::Browser` and hands it over. Nothing else in the product
/// builds one, and this module builds none.
///
/// The interface's object safety (see [`BrowserDriver`]) is what makes this a
/// type rather than a generic parameter, and a caller that has written its own
/// driver can pass it here exactly as the product's does.
pub type Driver = Box<dyn BrowserDriver>;

/// The reason a browser check is not run here, or `None` if SURE's own rules
/// allow it to run.
///
/// Two questions, and **the order is part of the answer rather than a detail**:
///
/// 1. **Did the project switch the check off?** If it did, that is the reason,
///    whatever the permission state is. A project that turned a check off has
///    not asked for it, and SURE reporting a permission gap for a check nobody
///    requested would be asking the user to grant something that would still not
///    run.
/// 2. **Is the permission granted?** [`ActionKind::BrowserProbe`] needs
///    [`Permission::ConnectService`](sure_domain::execution::Permission::ConnectService),
///    which no execution mode grants by itself — not
///    [`InspectOnly`](ExecutionMode::InspectOnly), and not
///    [`HostConfirmed`](ExecutionMode::HostConfirmed). A browser reaches a
///    service, and the permission for that is its own decision.
///
/// Whether a browser is *installed* is not asked here and cannot be: this
/// function reads configuration, and finding a browser is a search of this
/// machine. A caller that gets `None` here has SURE's own go-ahead and still has
/// to ask a driver, which answers [`AbsenceReason::NoDriverInstalled`] if there
/// is none.
#[must_use]
pub fn absence(
    preference: CheckPreference,
    mode: ExecutionMode,
    permissions: &ExecutionPermissions,
) -> Option<Absence> {
    if preference.disables() {
        return Some(Absence::new(
            AbsenceReason::DisabledByTheProject,
            "checks.browser_probe is never",
        ));
    }
    match sure_domain::execution::decide(ActionKind::BrowserProbe, mode, permissions) {
        ExecutionDecision::Allowed => None,
        ExecutionDecision::NeedsConsent | ExecutionDecision::Denied => Some(Absence::new(
            AbsenceReason::PermissionNotGranted,
            format!(
                "{} mode without the connect_service permission",
                mode.as_str()
            ),
        )),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;
    use sure_domain::ids::{CheckId, FingerprintId};
    use sure_domain::severity::Severity;
    use sure_domain::status::{AggregateSeverity, aggregate};

    /// A driver that returns whatever it was handed, so that the mapping can be
    /// exercised without a browser. It is also the proof that the trait is
    /// object-safe: it is used as a `Box<dyn BrowserDriver>` below.
    struct Stub(Report);

    impl BrowserDriver for Stub {
        fn observe(
            &self,
            _target: &Target,
            _limits: &Limits,
            _cancellation: &crate::process::Cancellation,
        ) -> Report {
            self.0.clone()
        }
    }

    fn a_target() -> Target {
        Target::local(3000, "/").expect("127.0.0.1:3000/ is a loopback target")
    }

    fn a_budget() -> Limits {
        Limits::new(Duration::from_secs(5), 10).expect("five seconds is a budget")
    }

    /// A look that reached a page, was served it, and reported nothing.
    fn a_clean_look() -> Observation {
        Observation {
            landing_url: "http://127.0.0.1:3000/".to_owned(),
            title: "Example".to_owned(),
            document_status: Some(200),
            problems: Vec::new(),
            complete: true,
        }
    }

    fn a_verdict(report: &Report) -> CheckResult {
        report.verdict(
            CheckId::generate(),
            &a_target(),
            Severity::MustFix,
            true,
            FingerprintId::generate(),
        )
    }

    #[test]
    fn a_target_refuses_an_address_that_is_not_on_this_machine() {
        // The refusal is `Endpoint`'s rather than a second copy of it, so this
        // test is really asserting that `Target` has no rule of its own to get
        // wrong: the same address is refused by the local probe.
        let refused = Target::at(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 80, "/");
        assert_eq!(
            refused,
            Err(EndpointError::NotLoopback {
                address: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))
            })
        );
    }

    #[test]
    fn a_target_refuses_a_path_that_would_change_the_request() {
        for path in ["", "index.html", "/a b", "/a\r\nHost: elsewhere", "/a\\b"] {
            assert!(
                Target::local(3000, path).is_err(),
                "{path:?} was accepted as a request target"
            );
        }
        for path in ["/", "/index.html", "/a?b=c", "/#fragment"] {
            assert!(
                Target::local(3000, path).is_ok(),
                "{path:?} was refused as a request target"
            );
        }
    }

    #[test]
    fn the_url_a_driver_is_given_is_http_and_the_address_it_was_built_from() {
        let target = Target::local(3000, "/app").expect("a loopback target");
        assert_eq!(target.url(), "http://127.0.0.1:3000/app");
        assert_eq!(target.to_string(), target.url());
        assert_eq!(target.endpoint().path(), "/app");
        // The scheme is not a parameter, and there is no constructor that takes
        // one: a browser pointed at an `https://` address would be reaching a
        // machine that is not this one.
        assert!(!target.url().contains("https"));
    }

    #[test]
    fn a_budget_of_no_time_or_no_room_is_refused() {
        assert_eq!(
            Limits::new(Duration::ZERO, 1),
            Err(LimitsError::ZeroTimeout)
        );
        assert_eq!(
            Limits::new(Duration::from_secs(1), 0),
            Err(LimitsError::NoRoomForProblems)
        );
        let limits = a_budget();
        assert_eq!(limits.timeout(), Duration::from_secs(5));
        assert_eq!(limits.problems_kept(), 10);
        assert!(!LimitsError::ZeroTimeout.to_string().is_empty());
        assert!(!LimitsError::NoRoomForProblems.to_string().is_empty());
    }

    #[test]
    fn every_absence_reason_is_skipped_and_none_of_them_produced_a_result() {
        // The acceptance sentence, checked over the whole list rather than over
        // the variants someone thought of. A sixth reason added later that
        // landed on `pass` fails here.
        assert_eq!(AbsenceReason::ALL.len(), 5);
        for reason in AbsenceReason::ALL {
            let report = Report::absent(*reason, "");
            assert_eq!(
                report.status(),
                CheckStatus::Skipped,
                "{reason:?} is not skipped"
            );
            let verdict = a_verdict(&report);
            assert_eq!(verdict.status, CheckStatus::Skipped, "{reason:?}");
            assert!(!verdict.status.is_green(), "{reason:?} was green");
            assert!(
                !verdict.status.produced_a_result(),
                "{reason:?} claimed to have checked the project"
            );
            assert_eq!(
                verdict.blocks_green(),
                !reason.not_checked_reason().is_scope_limit(),
                "{reason:?} blocks green if and only if its domain reason is a gap"
            );
        }
    }

    #[test]
    fn a_critical_absence_that_is_not_a_scope_limit_blocks_green() {
        // Four of the five reasons are gaps rather than scope limits, so a
        // critical browser check that could not run keeps the run out of green.
        // The one that does not is the project having switched the check off,
        // which is the user's own decision and not a gap in what SURE checked.
        let blocking: Vec<AbsenceReason> = AbsenceReason::ALL
            .iter()
            .copied()
            .filter(|reason| !reason.not_checked_reason().is_scope_limit())
            .collect();
        assert_eq!(
            blocking,
            vec![
                AbsenceReason::NoDriverInstalled,
                AbsenceReason::DriverWouldNotStart,
                AbsenceReason::PermissionNotGranted,
                AbsenceReason::UnsupportedPlatform,
            ],
            "the split between a gap and a scope limit moved"
        );

        for reason in blocking {
            let verdict = a_verdict(&Report::absent(reason, ""));
            assert!(
                verdict.blocks_green(),
                "{reason:?} is a gap in what was checked and did not block green"
            );
            assert!(!aggregate(&[verdict]).is_green(), "{reason:?}");
        }

        // Switching the check off is not a route to a clean green either, and
        // the two rows of the frozen aggregation it lands on are worth stating
        // because they say different things.
        let switched_off = a_verdict(&Report::absent(AbsenceReason::DisabledByTheProject, ""));
        assert!(!switched_off.blocks_green());

        // On its own: nothing ran at all, which the frozen rule treats as not
        // enough checked rather than as a run that is merely incomplete.
        assert_eq!(
            aggregate(std::slice::from_ref(&switched_off)).severity,
            AggregateSeverity::NotEnoughChecked
        );

        // Beside a check that did run: not blocking, and still not green. The
        // user who switches the browser check off is told their interface was
        // not looked at, which is the truth.
        let something_else_ran = CheckResult::pass(
            CheckId::generate(),
            "read the manifest",
            Severity::ShouldFixFirst,
            true,
            EvidenceClass::DeterministicCheck,
            FingerprintId::generate(),
        );
        let run = aggregate(&[something_else_ran, switched_off]);
        assert_eq!(run.severity, AggregateSeverity::NeedsAttention);
        assert!(!run.is_green());
    }

    #[test]
    fn a_look_that_was_cut_short_is_unknown_rather_than_a_pass() {
        // The false green this module is arranged against: a driver that ran
        // out of time has not seen the whole page, so it has not seen the
        // absence of errors either.
        let cut_short = Observation {
            complete: false,
            ..a_clean_look()
        };
        assert_eq!(
            Report::observed(cut_short.clone()).status(),
            CheckStatus::Unknown
        );
        let verdict = a_verdict(&Report::observed(cut_short));
        assert_eq!(verdict.status, CheckStatus::Unknown);
        assert!(
            verdict.blocks_green(),
            "an incomplete browser check is a critical check that did not pass"
        );
        assert_eq!(verdict.evidence_class, EvidenceClass::ObservedFact);
    }

    #[test]
    fn a_problem_seen_during_a_look_that_was_cut_short_is_still_a_failure() {
        // The other direction, and it is deliberate: a problem that was seen
        // was seen, and demoting it because the look did not finish would throw
        // away the only concrete thing the driver brought back.
        let cut_short_with_a_problem = Observation {
            complete: false,
            problems: vec![Problem::new(
                ProblemKind::ConsoleError,
                "Uncaught TypeError",
                "app.js",
                12,
            )],
            ..a_clean_look()
        };
        assert_eq!(
            Report::observed(cut_short_with_a_problem).status(),
            CheckStatus::Fail
        );
    }

    #[test]
    fn a_page_that_was_never_reached_is_unknown_even_with_nothing_reported() {
        let nowhere = Observation {
            landing_url: String::new(),
            ..a_clean_look()
        };
        assert_eq!(Report::observed(nowhere).status(), CheckStatus::Unknown);

        // Whitespace is not an address.
        let blank = Observation {
            landing_url: "   ".to_owned(),
            ..a_clean_look()
        };
        assert_eq!(Report::observed(blank).status(), CheckStatus::Unknown);
    }

    #[test]
    fn a_page_request_answered_outside_the_window_fails_even_with_no_problems() {
        // A 404 page renders, has a title, reports no console errors and loads
        // completely. Without the status in the interface this would be a pass
        // about a page that was never served.
        for status in [404, 500, 503, 199, 0] {
            let answered = Observation {
                document_status: Some(status),
                ..a_clean_look()
            };
            let report = Report::observed(answered);
            assert_eq!(report.status(), CheckStatus::Fail, "HTTP {status}");
            assert!(report.reason().contains(&status.to_string()));
        }
    }

    #[test]
    fn a_driver_that_did_not_say_what_came_back_cannot_reach_green_by_saying_nothing() {
        // The same technique as `ProbeOutcome::NoAnswer`: staying silent is not
        // an answer, so a driver has no reason to invent a status code.
        let silent = Observation {
            document_status: None,
            ..a_clean_look()
        };
        let report = Report::observed(silent);
        assert_eq!(report.status(), CheckStatus::Unknown);
        assert!(report.reason().contains("did not say"));
    }

    #[test]
    fn a_page_that_was_served_and_reported_nothing_passes_and_the_reason_says_only_that() {
        let report = Report::observed(a_clean_look());
        assert_eq!(report.status(), CheckStatus::Pass);
        let reason = report.reason();
        assert!(reason.contains("http://127.0.0.1:3000/"));
        assert!(reason.contains("HTTP 200"));

        // The title is the whole of what a reader skims, so it is asserted
        // exactly rather than probed for words that a later edit could change.
        let verdict = a_verdict(&report);
        assert_eq!(verdict.title, "browser probe: http://127.0.0.1:3000/");
        assert!(!verdict.title.contains("works"));
        assert!(!verdict.title.contains("correct"));
    }

    #[test]
    fn a_reason_line_quotes_at_most_three_problems_and_counts_the_rest() {
        let problems: Vec<Problem> = (0..7)
            .map(|index| {
                Problem::new(
                    ProblemKind::FailedRequest,
                    format!("request {index} failed"),
                    "api",
                    index + 1,
                )
            })
            .collect();
        let observation = Observation {
            problems,
            ..a_clean_look()
        };
        let reason = Report::observed(observation).reason();
        assert!(reason.contains("7 problem(s)"));
        assert!(reason.contains("and 4 more"));
        assert!(!reason.contains("request 4 failed"), "{reason}");
    }

    #[test]
    fn a_problem_with_no_line_says_so_rather_than_printing_zero() {
        let no_line = Problem::new(ProblemKind::RuntimeError, "boom", "app.js", 0);
        assert!(no_line.describe().contains("no line reported"));
        assert!(!no_line.describe().contains("app.js:0"));
        let with_line = Problem::new(ProblemKind::RuntimeError, "boom", "app.js", 7);
        assert!(with_line.describe().contains("app.js:7"));
    }

    #[test]
    fn every_problem_kind_is_describable() {
        assert_eq!(ProblemKind::ALL.len(), 4);
        for kind in ProblemKind::ALL {
            assert!(!kind.as_str().is_empty());
        }
    }

    #[test]
    fn a_check_the_project_switched_off_is_disabled_by_configuration_whatever_the_permissions_are()
    {
        let mut granted = ExecutionPermissions::inspect_only();
        granted.set(sure_domain::execution::Permission::ConnectService, true);
        assert_eq!(
            absence(
                CheckPreference::Never,
                ExecutionMode::HostConfirmed,
                &granted
            )
            .expect("a check switched off is absent")
            .reason,
            AbsenceReason::DisabledByTheProject
        );
    }

    #[test]
    fn a_browser_probe_without_the_connect_permission_is_not_authorized() {
        // The product's default mode. `ConnectService` is granted by no mode on
        // its own, so this is the answer for every caller that has not asked
        // for it explicitly.
        for mode in [
            ExecutionMode::InspectOnly,
            ExecutionMode::HostConfirmed,
            ExecutionMode::Container,
        ] {
            let absence = absence(
                CheckPreference::Auto,
                mode,
                &ExecutionPermissions::inspect_only(),
            )
            .unwrap_or_else(|| panic!("{mode:?} granted the connect permission on its own"));
            assert_eq!(absence.reason, AbsenceReason::PermissionNotGranted);
            assert!(absence.plain_explanation().contains("connect"));
        }
    }

    #[test]
    fn a_browser_probe_with_the_permission_granted_leaves_the_question_to_a_driver() {
        let mut granted = ExecutionPermissions::inspect_only();
        granted.set(sure_domain::execution::Permission::ConnectService, true);
        assert!(
            absence(
                CheckPreference::Always,
                ExecutionMode::HostConfirmed,
                &granted
            )
            .is_none(),
            "SURE's own rules allow the check, so whether a browser exists is the \
             adapter's question and not this function's"
        );
    }

    #[test]
    fn the_trait_is_a_seam_a_caller_can_hold() {
        // Object safety, and the mapping end to end through the trait rather
        // than through the constructor: a `Box<dyn BrowserDriver>` is a driver,
        // and what it reports goes through the one door.
        let driver: Box<dyn BrowserDriver> = Box::new(Stub(Report::observed(a_clean_look())));
        let report = driver.observe(
            &a_target(),
            &a_budget(),
            &crate::process::Cancellation::default(),
        );
        assert_eq!(report.status(), CheckStatus::Pass);

        let absent: Box<dyn BrowserDriver> = Box::new(Stub(Report::absent(
            AbsenceReason::NoDriverInstalled,
            "no chromium on PATH",
        )));
        let report = absent.observe(
            &a_target(),
            &a_budget(),
            &crate::process::Cancellation::default(),
        );
        assert_eq!(report.status(), CheckStatus::Skipped);
        let verdict = a_verdict(&report);
        assert_eq!(
            verdict.not_checked_reason,
            Some(NotCheckedReason::ToolUnavailable)
        );
        assert_eq!(verdict.evidence_class, EvidenceClass::Unknown);
        assert!(verdict.reason.contains("no chromium on PATH"));
    }
}
